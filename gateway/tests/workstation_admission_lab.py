#!/usr/bin/env python3
"""Real WireGuard + admission HTTP + packet enforcement in disposable namespaces.

FreePBX Custom Services are modelled by firewall_listener_model.php. HTTP and SSH
are TCP test services, not an installed FreePBX/Apache/sshd. No host network changes.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if (os.geteuid() != 0 or len(sys.argv) != 2 or not sys.argv[1].startswith("net:[")
        or os.readlink("/proc/self/ns/net") == sys.argv[1]):
    raise SystemExit("Refusing to run outside a new user/network namespace")
spec = importlib.util.spec_from_file_location("broker", ROOT / "teliphones/support_broker.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


def run(*args, stdin=None):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=20, env=os.environ)
    if result.returncode:
        raise RuntimeError("%s failed: %s" % (args[0], result.stderr))
    return result.stdout.strip()


def check(ok, message):
    if not ok:
        raise AssertionError(message)


def service(address, port, payload):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen()
    servers.append(server)

    def accept():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                return
            with client:
                try:
                    client.sendall(payload)
                except OSError:
                    pass
    threading.Thread(target=accept, daemon=True).start()


with tempfile.TemporaryDirectory(prefix="tlp-admission-") as directory:
    directory = Path(directory)
    os.environ["XTABLES_LOCKFILE"] = str(directory / "xtables.lock")
    broker.ENV = {**broker.ENV, "XTABLES_LOCKFILE": os.environ["XTABLES_LOCKFILE"]}
    broker.STATE = directory / "state"
    broker.STATE.mkdir()
    broker.ENROLLMENT = directory / "enrollment"
    broker.TOOLS["wg"] = [shutil.which("wg")]
    broker.IPTABLES = ["/usr/sbin/iptables-nft"]
    instance = broker.Broker()
    instance.audit = lambda *args: None
    # There is no systemd/sshd in the namespace; only management TCP admission is under test.
    instance.ssh.reconcile = lambda *args, **kwargs: None
    instance.session_server_enabled = True
    client = subprocess.Popen(["unshare", "--net", "sleep", "180"])
    servers = []
    try:
        for _ in range(100):
            if os.readlink("/proc/%d/ns/net" % client.pid) != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.01)
        enter = ["nsenter", "--net=/proc/%d/ns/net" % client.pid]
        run("ip", "link", "set", "lo", "up")
        run(*enter, "ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "wan1")
        run("ip", "link", "set", "wan1", "netns", str(client.pid))
        run("ip", "addr", "add", "198.51.100.1/24", "dev", "wan0")
        run("ip", "link", "set", "wan0", "up")
        run(*enter, "ip", "addr", "add", "198.51.100.2/24", "dev", "wan1")
        run(*enter, "ip", "link", "set", "wan1", "up")

        def ipt(*args):
            return run("iptables-nft", "-w", "5", *args)

        for chain in ("fpbxfirewall", "zone-external", "zone-internal", "zone-other", "fail2ban-PBX-GUI"):
            ipt("-N", chain)
        ipt("-A", "INPUT", "-j", "fail2ban-PBX-GUI")
        ipt("-A", "INPUT", "-j", "fpbxfirewall")
        ipt("-A", "fpbxfirewall", "-i", "lo", "-j", "ACCEPT")
        ipt("-A", "fpbxfirewall", "-j", "zone-external")
        ipt("-A", "fpbxfirewall", "-j", "DROP")

        def listener(ports):
            ports = ([ports] if ports else []) if isinstance(ports, int) else ports
            run("php", str(Path(__file__).with_name("firewall_listener_model.php")), str(broker.STATE),
                ",".join(map(str, ports)) or "0", "/usr/sbin/iptables-nft", sys.argv[1])
        instance.reconcile_listener = listener
        instance.dispatch({"action": "workstation-policy", "state": "open"}, 1000)

        def keypair(name):
            key = run("wg", "genkey")
            path = directory / name
            path.write_text(key)
            path.chmod(0o600)
            return path, run("wg", "pubkey", stdin=key)

        def pair(public, sources=""):
            request = {"schema": "teliphones-pair-request/1", "workstation": "LAB", "public_key": public,
                       "nonce": "n" * 22}
            result = instance.dispatch({"action": "pair", "request": broker.PAIR_REQUEST_PREFIX +
                                        broker.b64url_encode(json.dumps(request).encode()),
                                        "endpoint_host": "198.51.100.1", "listen_port": "51821",
                                        "mode": "temporary", "minutes": "60", "ssh": "0",
                                        "web": "http:8080, https:443", "sources": sources}, 1000)
            return json.loads(broker.b64url_decode(result["pairing_response"].split(":", 1)[1]))

        def tunnel(name, private, response):
            run(*enter, "ip", "link", "add", name, "type", "wireguard")
            run(*enter, "wg", "set", name, "private-key", str(private), "peer", response["pbx_public_key"],
                "endpoint", response["endpoint"], "allowed-ips", response["pbx_address"] + "/32")
            run(*enter, "ip", "addr", "add", response["address"], "dev", name)
            run(*enter, "ip", "link", "set", name, "up")
            run(*enter, "ip", "route", "add", response["pbx_address"] + "/32", "dev", name)

        def probe(address, port, action=None):
            return json.loads(run(*enter, sys.executable, "-c", """
import http.client,json,socket,sys
try:
 if sys.argv[3]:
  c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=2)
  c.request('POST','/workstation/session',json.dumps({'action':sys.argv[3]}))
  r=c.getresponse(); result=json.loads(r.read()); c.close()
 else:
  with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2) as s:
   result=bool(s.recv(256))
except OSError:
 result=False
print(json.dumps(result))
""", address, str(port), action or ""))

        def admitted(address):
            # WireGuard retries handshakes after a short backoff following link/key changes.
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                result = probe(address, 8766, "heartbeat")
                if isinstance(result, dict) and result.get("active"):
                    return True
                time.sleep(0.1)
            return False

        private, public = keypair("workstation.key")
        response = pair(public)
        pbx = response["pbx_address"]
        check(response["gui_url"] == "http://" + pbx + ":8080/admin/", "GUI URL left the private tunnel")
        tunnel("wg0", private, response)
        service(pbx, 8080, b"HTTP/1.0 200 OK\r\n\r\nFreePBX test endpoint")
        service(pbx, 443, b"GUI TCP fixture")
        service(pbx, 22, b"SSH-2.0-test\r\n")
        # A legacy SSH grant tests the real firewall/admission code without starting host systemd services.
        state, _ = instance.workstation_state()
        state["workstations"][0]["ssh"] = True
        instance.save_workstations(state)
        instance.apply_workstations(state)
        check(not probe(pbx, 8080) and not probe(pbx, 22), "WireGuard alone admitted GUI/SSH")
        check(int(run("wg", "show", "tlp-admin", "latest-handshakes").split()[1]) > 0,
              "no authenticated WireGuard handshake")
        check(admitted(pbx), "untrusted-source admission failed")
        check(probe(pbx, 8080) and probe(pbx, 443) and probe(pbx, 22), "admitted private services unavailable")
        check(not probe("198.51.100.1", 8080), "public management was exposed")

        run(*enter, "ip", "addr", "del", "198.51.100.2/24", "dev", "wan1")
        run(*enter, "ip", "addr", "add", "198.51.100.3/24", "dev", "wan1")
        check(admitted(pbx) and probe(pbx, 8080), "unlocked roaming failed")
        check("198.51.100.3:" in run("wg", "show", "tlp-admin", "endpoints"), "WireGuard did not roam")
        run(*enter, "ip", "link", "set", "wg0", "down")
        instance.expire_workstations()
        run(*enter, "ip", "link", "set", "wg0", "up")
        run(*enter, "ip", "route", "replace", pbx + "/32", "dev", "wg0")
        check(admitted(pbx), "temporary loss revoked the grant")

        ipt("-F", "fpbxfirewall")
        ipt("-A", "fpbxfirewall", "-j", "zone-external")
        ipt("-A", "fpbxfirewall", "-j", "DROP")
        ipt("-F", "zone-external")
        instance.expire_workstations()
        check(admitted(pbx) and probe(pbx, 22), "regeneration lost admission")

        expires = instance.active_sessions()[response["workstation_id"]]["expires_at"]
        with patch.object(broker.time, "time", return_value=expires + 1):
            instance.expire_sessions()
            check(not probe(pbx, 8080) and not probe(pbx, 22), "expired lease retained GUI/SSH access")
        check(admitted(pbx), "expired transport lease revoked valid authorisation")
        wrong, _ = keypair("unknown.key")
        run(*enter, "wg", "set", "wg0", "private-key", str(wrong))
        check(not probe(pbx, 8080) and not probe(pbx, 8766, "heartbeat"), "unknown WireGuard key admitted")
        run(*enter, "wg", "set", "wg0", "private-key", str(private))
        check(admitted(pbx), "credential restoration failed")

        locked_key, locked_public = keypair("locked.key")
        locked = pair(locked_public, "198.51.100.2")
        tunnel("wg-lock", locked_key, locked)
        check(not probe(locked["pbx_address"], 8766, "heartbeat"), "locked peer admitted from wrong public IP")
        run(*enter, "ip", "addr", "del", "198.51.100.3/24", "dev", "wan1")
        run(*enter, "ip", "addr", "add", "198.51.100.2/24", "dev", "wan1")
        instance.workstation_session("release", response["address"].split("/")[0])
        check(admitted(locked["pbx_address"]), "locked allowed IP required Trusted")

        instance.dispatch({"action": "unpair", "workstation_id": locked["workstation_id"]}, 1000)
        check(not probe(locked["pbx_address"], 8766, "heartbeat"), "revoked peer retained admission")
        state, _ = instance.workstation_state()
        with patch.object(broker.time, "time", return_value=state["workstations"][0]["expires_at"] + 1):
            instance.expire_workstations()
            check(not probe(pbx, 8080) and not probe(pbx, 8766, "heartbeat"), "expired admin grant retained access")
        check(not instance.link_state() and "fpbxsvc-" not in ipt("-S"), "last expiry retained a listener")
        pair(public)
        check(instance.link_state(), "Open did not allow a new administrator-approved pairing")
        result = instance.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        check(result["ok"] and not instance.link_state() and "fpbxsvc-" not in ipt("-S"),
              "last revocation retained a listener")
        # Closed is still safe and idempotent after the final authorisation expires.
        instance.dispatch({"action": "workstation-policy", "state": "closed"}, 1000)
        check(not instance.link_state() and "fpbxsvc-" not in ipt("-S"), "Closed retained a listener")
        check("zone-trusted" not in ipt("-S"), "lab unexpectedly depended on Trusted")
        print("PASS: real WireGuard untrusted-source admission, private GUI/SSH TCP, roaming, IP lock, unknown-key denial, "
              "pre-admission denial, lease/admin expiry, revocation, reconnection and firewall regeneration")
    finally:
        instance.stop_session_servers()
        if instance.monitor:
            instance.monitor.close()
        for server in servers:
            server.close()
        client.kill()
        client.wait()
