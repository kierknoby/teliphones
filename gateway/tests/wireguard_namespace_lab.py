#!/usr/bin/env python3
"""Run actual WireGuard/nftables/TCP/SSH tests in explicitly disposable namespaces."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT / "teliphones"))

from checker_probe import canonical_json, connect_probe, run_checks, sign, tcp_probe
from engineer_config import render as render_engineer_config
from teliphones_gateway import GatewayService


def command(args: list[str], namespace: str | None = None, *, input_text: str | None = None,
            check: bool = True, timeout: int = 12) -> subprocess.CompletedProcess:
    actual = ["ip", "netns", "exec", namespace, *args] if namespace else args
    result = subprocess.run(actual, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(actual)}: {result.stderr.strip()}")
    return result


def keypair(directory: Path, label: str) -> tuple[Path, str]:
    private = command(["wg", "genkey"]).stdout.strip()
    path = directory / (label + ".key")
    path.write_text(private + "\n", encoding="ascii")
    path.chmod(0o600)
    public = command(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    return path, public


def has_capability(number: int) -> bool:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) & (1 << number))
    except (OSError, ValueError, IndexError):
        return False
    return False


def host_snapshot() -> dict[str, str]:
    paths = (Path("/etc/resolv.conf"), Path("/etc/ssh/sshd_config"))
    hashes = {}
    for path in paths:
        try:
            hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            hashes[str(path)] = "absent"
    return {
        "links": command(["ip", "-o", "link", "show"]).stdout,
        "addresses": command(["ip", "-o", "-4", "address", "show"]).stdout,
        "routes": command(["ip", "-4", "route", "show", "table", "main"]).stdout,
        "rules": command(["ip", "-4", "rule", "show"]).stdout,
        "namespaces": command(["ip", "netns", "list"]).stdout,
        "nft_ruleset": command(["nft", "--stateless", "list", "ruleset"], check=False).stdout,
        "ip_forward": Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip(),
        "file_hashes": json.dumps(hashes, sort_keys=True),
    }


def add_underlay(gateway_ns: str, client_ns: str, bridge: str, gateway_link: str,
                 client_link: str, client_ip: str) -> None:
    command(["ip", "link", "add", gateway_link, "netns", gateway_ns,
             "type", "veth", "peer", "name", client_link, "netns", client_ns])
    command(["ip", "link", "set", gateway_link, "master", bridge], gateway_ns)
    command(["ip", "link", "set", "up", "dev", gateway_link], gateway_ns)
    command(["ip", "address", "add", client_ip, "dev", client_link], client_ns)
    command(["ip", "link", "set", "up", "dev", client_link], client_ns)


def add_public_link(pbx_ns: str, public_ns: str, pbx_link: str, public_link: str,
                    pbx_ip: str, public_ip: str) -> None:
    command(["ip", "link", "add", pbx_link, "netns", pbx_ns,
             "type", "veth", "peer", "name", public_link, "netns", public_ns])
    command(["ip", "address", "add", pbx_ip, "dev", pbx_link], pbx_ns)
    command(["ip", "link", "set", "up", "dev", pbx_link], pbx_ns)
    command(["ip", "address", "add", public_ip, "dev", public_link], public_ns)
    command(["ip", "link", "set", "up", "dev", public_link], public_ns)


def install_client_wireguard(namespace: str, private_file: Path, gateway_public: str,
                             endpoint: str, address: str, routes: list[str], listen_port: int) -> None:
    command(["ip", "link", "add", "dev", "wg0", "type", "wireguard"], namespace)
    command(["wg", "set", "wg0", "private-key", str(private_file), "listen-port", str(listen_port),
             "peer", gateway_public, "endpoint", endpoint, "allowed-ips", ",".join(routes),
             "persistent-keepalive", "3"], namespace)
    command(["ip", "address", "add", address, "dev", "wg0"], namespace)
    command(["ip", "link", "set", "up", "dev", "wg0"], namespace)
    for route in routes:
        command(["ip", "route", "replace", route, "dev", "wg0"], namespace)


def tcp_exchange(namespace: str, host: str, port: int, timeout: float = 2.0) -> str | None:
    script = """import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=float(sys.argv[3]))
s.settimeout(float(sys.argv[3]))
s.sendall(b'teliphones-lab-identify')
print(s.recv(512).decode('ascii','replace'))
s.close()
"""
    result = command(["python3", "-c", script, host, str(port), str(timeout)], namespace,
                     check=False, timeout=int(timeout + 3))
    return result.stdout.strip() if result.returncode == 0 else None


def start_tcp_service(namespace: str, address: str, port: int, identity: str,
                      children: list[subprocess.Popen]) -> None:
    script = """import socket,sys
address,port,identity=sys.argv[1],int(sys.argv[2]),sys.argv[3]
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((address,port)); s.listen(32)
while True:
 c,peer=s.accept()
 try:
  c.recv(1024)
  c.sendall((identity+';source='+peer[0]+';destination='+address).encode('ascii'))
 finally:
  c.close()
"""
    process = subprocess.Popen(["ip", "netns", "exec", namespace, "python3", "-c", script,
                                address, str(port), identity], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               start_new_session=True)
    children.append(process)
    if not wait_for(lambda: process.poll() is None and f"{address}:{port}" in
                    command(["ss", "-H", "-ltn"], namespace, check=False).stdout, seconds=4):
        raise RuntimeError(f"TCP test service failed to listen on {address}:{port}")


def make_ssh_keypair(directory: Path, label: str) -> tuple[Path, str]:
    private = directory / (label + "-ssh")
    command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)])
    private.chmod(0o600)
    return private, Path(str(private) + ".pub").read_text(encoding="ascii").strip()


def start_sshd(namespace: str, address: str, port: int, name: str, key: Path,
               public_key: str, authorised_source: str, directory: Path,
               children: list[subprocess.Popen]) -> tuple[subprocess.Popen, Path]:
    host_key = directory / (name + "-host")
    command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
    host_key.chmod(0o600)
    authorized = directory / (name + "-authorized_keys")
    authorized.write_text(public_key + "\n", encoding="ascii")
    authorized.chmod(0o600)
    config = directory / (name + "-sshd.conf")
    pid_file = directory / (name + "-sshd.pid")
    config.write_text(
        f"Port {port}\nListenAddress {address}\nHostKey {host_key}\nPidFile {pid_file}\n"
        f"AuthorizedKeysFile {authorized}\nPermitRootLogin prohibit-password\n"
        "PubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\n"
        f"KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nAllowUsers root@{authorised_source}\n"
        "AllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\n"
        "GatewayPorts no\nPermitUserEnvironment no\nPrintMotd no\nLogLevel ERROR\n",
        encoding="ascii",
    )
    config.chmod(0o600)
    command(["/usr/sbin/sshd", "-t", "-f", str(config)], namespace)
    process = subprocess.Popen(["ip", "netns", "exec", namespace, "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
    children.append(process)
    if not wait_for(lambda: process.poll() is None and f"{address}:{port}" in
                    command(["ss", "-H", "-ltn"], namespace, check=False).stdout, seconds=4):
        if process.poll() is None:
            try:
                stop_owned_sshd(process, config)
            except Exception:
                stop_owned_process_group(process)
        raise RuntimeError(f"sshd failed to listen on {address}:{port}")
    return process, config


def ssh_command(namespace: str, private_key: Path, host: str, remote_command: str,
                timeout: int = 8) -> subprocess.CompletedProcess:
    return command(["ssh", "-F", "/dev/null", "-i", str(private_key), "-p", "22222",
                    "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
                    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                    f"root@{host}", remote_command], namespace, check=False, timeout=timeout)


def process_start_time(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = stat[stat.rfind(")") + 2:].split()
        return fields[19]
    except (OSError, IndexError):
        return None


def process_tree(pid: int) -> list[tuple[int, str]]:
    start_time = process_start_time(pid)
    if start_time is None:
        return []
    path = Path(f"/proc/{pid}/task/{pid}/children")
    children = path.read_text(encoding="ascii").split() if path.is_file() else []
    result: list[tuple[int, str]] = []
    for child in children:
        result.extend(process_tree(int(child)))
    result.append((pid, start_time))
    return result


def process_alive(pid: int, expected_start_time: str) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = stat[stat.rfind(")") + 2:].split()
        return fields[0] != "Z" and fields[19] == expected_start_time
    except (OSError, IndexError):
        return False


def stop_owned_sshd(process: subprocess.Popen, config: Path) -> bool:
    processes = process_tree(process.pid) if process.poll() is None else []
    commands = []
    for pid, _start_time in processes:
        try:
            commands.append(Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace"))
        except OSError:
            continue
    if processes and not any("sshd" in cmd and str(config) in cmd for cmd in commands):
        raise RuntimeError("refusing to signal a process tree not owned by the lab sshd config")
    for pid, start_time in processes:
        if not process_alive(pid, start_time):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if not wait_for(lambda: all(not process_alive(pid, start_time) for pid, start_time in processes), seconds=3):
        for pid, start_time in processes:
            if process_alive(pid, start_time):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if not wait_for(lambda: all(not process_alive(pid, start_time) for pid, start_time in processes), seconds=3):
            raise RuntimeError("session-owned sshd child survived teardown")
    if process.poll() is None:
        process.wait(timeout=3)
    return True


def stop_owned_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def wait_for(predicate, seconds: float = 8.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        time.sleep(0.1)
    return False


def add_event(events: list[dict[str, Any]], name: str, **fields: Any) -> None:
    events.append({"time": int(time.time()), "test": name, **fields})
    print(f"PASS {name}: {json.dumps(fields, sort_keys=True)}")


def valid_handshake(service: GatewayService, session_id: str) -> bool:
    record = service.store.session(session_id)
    return bool(record and service.handshake_recent(record))


def handshake_timestamp(service: GatewayService, session_id: str) -> int | None:
    record = service.store.session(session_id)
    if not record:
        return None
    output = service.run(["wg", "show", service.interface, "latest-handshakes"], check=False)
    for line in output.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == record["pbx_key"] and fields[1].isdigit():
            return int(fields[1])
    return None


def request_for(session_id: str, remote_id: str, action: str) -> dict[str, Any]:
    return {"protocol": "teliphones-connect/1", "action": action,
            "session_id": session_id, "remote_id": remote_id}


def php_checker_action(action: str, session: dict[str, Any], state_dir: Path,
                       public_key: Path, evidence_file: Path | None = None) -> dict[str, Any]:
    code = r'''require_once $argv[1];
$action=$argv[2];
$stateDir=$argv[3];
$publicKey=file_get_contents($argv[4]);
$session=json_decode(stream_get_contents(STDIN),true);
$checker=new \FreePBX\modules\Teliphones\CheckerEvidence($stateDir,$publicKey);
if($action==="challenge") { echo json_encode($checker->challenge($session),JSON_UNESCAPED_SLASHES); exit(0); }
$evidence=json_decode(file_get_contents($argv[5]),true);
$result=$checker->accept($session,$evidence);
echo json_encode($result,JSON_UNESCAPED_SLASHES);
exit(!empty($result["accepted"])?0:2);'''
    args = ["php", "-r", code, str(ROOT / "teliphones" / "CheckerEvidence.php"), action,
            str(state_dir), str(public_key), str(evidence_file or state_dir / "unused-evidence.json")]
    result = subprocess.run(args, input=json.dumps(session), capture_output=True, text=True, timeout=10, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"PHP Checker {action} failed: {result.stderr.strip()} {result.stdout.strip()}")
    parsed = json.loads(result.stdout)
    if action == "accept" and parsed.get("accepted") is not True:
        raise RuntimeError("PHP CheckerEvidence did not accept the independently probed evidence")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, help="write a new mode-0600 JSON packet-flow report; never overwrites")
    parser.add_argument("--preflight", action="store_true", help="check tools and capabilities without creating namespaces")
    args = parser.parse_args(argv)
    required = ("ip", "wg", "nft", "sysctl", "python3", "ssh", "ssh-keygen", "ss", "openssl", "php")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        print("BLOCKED: missing real integration tools: " + ", ".join(missing))
        return 77
    if not Path("/usr/sbin/sshd").is_file():
        print("BLOCKED: OpenSSH server executable /usr/sbin/sshd is missing")
        return 77
    php_crypto = subprocess.run(["php", "-r", "exit(extension_loaded('openssl') ? 0 : 1);"], check=False)
    if php_crypto.returncode != 0:
        print("BLOCKED: PHP OpenSSL support is required to exercise the module Checker")
        return 77
    if not has_capability(12) or not has_capability(21):
        print("BLOCKED: effective CAP_NET_ADMIN and CAP_SYS_ADMIN are required for isolated namespaces")
        return 77
    if not Path("/sys/module/wireguard").exists():
        print("BLOCKED: the WireGuard kernel module is not loaded")
        return 77
    if args.preflight:
        print("READY: tools, WireGuard module and namespace capabilities are available; no network changes were made")
        return 0
    if os.geteuid() != 0 or os.environ.get("TELIPHONES_LAB_CONFIRM") != "disposable-host":
        print("BLOCKED: full lab requires root on a disposable host and TELIPHONES_LAB_CONFIRM=disposable-host")
        return 77
    if args.evidence and args.evidence.exists():
        print("BLOCKED: evidence path already exists; refusing to overwrite")
        return 77

    suffix = f"{os.getpid() % 100000:05d}"
    namespaces = {label: f"tp-{label}-{suffix}" for label in ("gw", "pba", "pbb", "ena", "enb", "chk", "pub")}
    host_before = host_snapshot()
    events: list[dict[str, Any]] = []
    children: list[subprocess.Popen] = []
    sshd_processes: dict[str, tuple[subprocess.Popen, Path]] = {}
    created: list[str] = []
    failure: Exception | None = None
    host_changed = False
    report: dict[str, Any] = {
        "schema": "teliphones-wireguard-lab-evidence/1",
        "started_at": int(time.time()),
        "host_os": Path("/etc/os-release").read_text(encoding="utf-8").splitlines()[0:4],
        "host_state_before_sha256": hashlib.sha256(json.dumps(host_before, sort_keys=True).encode()).hexdigest(),
        "events": events,
    }
    try:
        for namespace in namespaces.values():
            command(["ip", "netns", "add", namespace])
            created.append(namespace)
            command(["ip", "link", "set", "lo", "up"], namespace)

        command(["ip", "link", "add", "br-underlay", "type", "bridge"], namespaces["gw"])
        command(["ip", "address", "add", "198.18.0.1/24", "dev", "br-underlay"], namespaces["gw"])
        command(["ip", "link", "set", "up", "dev", "br-underlay"], namespaces["gw"])
        underlay = {"pba": "198.18.0.2/24", "pbb": "198.18.0.3/24", "ena": "198.18.0.4/24",
                    "enb": "198.18.0.5/24", "chk": "198.18.0.6/24"}
        for index, (label, client_ip) in enumerate(underlay.items()):
            add_underlay(namespaces["gw"], namespaces[label], "br-underlay", f"g{index}{suffix[-4:]}",
                         "u0", client_ip)
        add_public_link(namespaces["pba"], namespaces["pub"], "pub0", "puba0", "198.19.0.1/30", "198.19.0.2/30")
        add_public_link(namespaces["pbb"], namespaces["pub"], "pub1", "pubb0", "198.19.0.5/30", "198.19.0.6/30")

        with tempfile.TemporaryDirectory(prefix="teliphones-wireguard-lab-") as temporary:
            files = Path(temporary)
            gateway_private, gateway_public = keypair(files, "gateway")
            peer_keys = {label: keypair(files, label) for label in ("pba", "pbb", "ena", "enb", "chk")}
            ssh_keys = {label: make_ssh_keypair(files, label) for label in ("engineer-a", "engineer-b", "wrong-key")}
            checker_private = files / "checker-ecdsa-p256.key"
            command(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(checker_private)])
            checker_private.chmod(0o600)
            checker_public = files / "checker-ecdsa-p256.pub"
            command(["openssl", "pkey", "-in", str(checker_private), "-pubout", "-out", str(checker_public)])

            engineers = {
                "engineer-a": {"wireguard_public_key": peer_keys["ena"][1], "address": "10.77.0.10", "ssh_public_key": ssh_keys["engineer-a"][1]},
                "engineer-b": {"wireguard_public_key": peer_keys["enb"][1], "address": "10.77.0.11", "ssh_public_key": ssh_keys["engineer-b"][1]},
            }
            config = {
                "deployment_mode": "reference-lab", "interface": "wg0", "endpoint": "198.18.0.1:51820",
                "listen_port": 51820, "public_key": gateway_public, "private_key_file": str(gateway_private),
                "support_pool": "10.20.17.0/24", "engineer_pool": "10.77.0.0/24",
                "tls_certificate": "/unused/lab-server.crt", "tls_private_key": "/unused/lab-server.key",
                "client_ca": "/unused/lab-customer-ca.crt",
                "checker": {"wireguard_public_key": peer_keys["chk"][1], "address": "10.77.0.254", "probe_port": 22221},
                "engineers": engineers,
                "customers": {
                    "customer-a": {"certificate_sha256": "a" * 64, "engineers": ["engineer-a"],
                                   "ssh_engineer": "engineer-a", "services": [80, 443, 22222]},
                    "customer-b": {"certificate_sha256": "b" * 64, "engineers": ["engineer-b"],
                                   "ssh_engineer": "engineer-b", "services": [80, 443, 22222]},
                },
            }

            def gateway_runner(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
                return subprocess.run(["ip", "netns", "exec", namespaces["gw"], *args], **kwargs)

            command(["sysctl", "-qw", "net.ipv4.ip_forward=1"], namespaces["gw"])
            gateway = GatewayService(config, files / "gateway-state", runner=gateway_runner)
            gateway.configure_interface()
            command(["ip", "address", "add", "10.20.17.2/32", "dev", "wg0"], namespaces["gw"])
            command(["ip", "address", "add", "10.20.17.6/32", "dev", "wg0"], namespaces["gw"])
            add_event(events, "gateway-configured", interface="wg0", underlay="198.18.0.1/24", ip_forward="namespace-only")

            expiry_a = int(time.time()) + 180
            expiry_b = int(time.time()) + 45
            session_ids = {"customer-a": secrets.token_hex(16), "customer-b": secrets.token_hex(16)}
            session_requests = {
                "customer-a": {"protocol": "teliphones-connect/1", "action": "provision", "session_id": session_ids["customer-a"],
                               "expires_at": expiry_a, "topology": "on-pbx", "pbx_wg_public_key": peer_keys["pba"][1],
                               "pbx_tunnel_address": "10.20.17.1/30", "support_tunnel_address": "10.20.17.2/32"},
                "customer-b": {"protocol": "teliphones-connect/1", "action": "provision", "session_id": session_ids["customer-b"],
                               "expires_at": expiry_b, "topology": "on-pbx", "pbx_wg_public_key": peer_keys["pbb"][1],
                               "pbx_tunnel_address": "10.20.17.5/30", "support_tunnel_address": "10.20.17.6/32"},
            }
            responses = {customer: gateway.provision(customer, request) for customer, request in session_requests.items()}
            add_event(events, "local-authorisation-fixtures", sessions={key: value[:8] for key, value in session_ids.items()},
                      expiry_a=expiry_a, expiry_b=expiry_b, gateway_provisioned=True)

            pbx_routes = {
                "pba": ["10.20.17.2/32", "10.77.0.10/32", "10.77.0.11/32", "10.77.0.254/32", "10.20.17.5/32"],
                "pbb": ["10.20.17.6/32", "10.77.0.10/32", "10.77.0.11/32", "10.77.0.254/32", "10.20.17.1/32"],
            }
            for label, pbx, remote in (("pba", "10.20.17.1/30", responses["customer-a"]),
                                       ("pbb", "10.20.17.5/30", responses["customer-b"])):
                install_client_wireguard(namespaces[label], peer_keys[label][0], remote["peer_public_key"],
                                         remote["peer_endpoint"], pbx, pbx_routes[label], 52000 + (1 if label == "pba" else 2))
            for label, address in (("pba", "10.20.17.1"), ("pbb", "10.20.17.5")):
                for port in (80, 443):
                    start_tcp_service(namespaces[label], address, port, f"{label.upper()}:{port}", children)
            for label, address, peer, port in (("ena", "10.77.0.10/32", "ena", 52003),
                                               ("enb", "10.77.0.11/32", "enb", 52004)):
                install_client_wireguard(namespaces[label], peer_keys[peer][0], gateway_public,
                                         "198.18.0.1:51820", address,
                                         ["10.20.17.1/32", "10.20.17.5/32"], port)
            if tcp_exchange(namespaces["ena"], "10.20.17.1", 80) is not None:
                raise RuntimeError("engineer accessed PBX GUI profile during provisioning")
            add_event(events, "engineer-service-closed-during-provisioning", customer="customer-a")

            for customer, label in (("customer-a", "pba"), ("customer-b", "pbb")):
                session_id = session_ids[customer]
                if not wait_for(lambda sid=session_id: valid_handshake(gateway, sid), seconds=12):
                    raise RuntimeError(f"{customer} did not complete an actual WireGuard handshake")
                response = responses[customer]
                confirmed = gateway.confirm(customer, request_for(session_id, response["remote_id"], "confirm"))
                if confirmed.get("state") != "connected":
                    raise RuntimeError(f"{customer} transport did not enter connected state")
                add_event(events, "customer-wireguard-confirmed", customer=customer, session=session_id[:8],
                          handshake_timestamp=handshake_timestamp(gateway, session_id),
                          pbx_address="10.20.17.1" if label == "pba" else "10.20.17.5")

            checker_grant = gateway.checker_grant()
            checker_config = render_engineer_config(checker_grant, "local-private-key", peer_keys["chk"][1])
            checker_allowed = next(line.partition("=")[2].strip() for line in checker_config.splitlines() if line.startswith("AllowedIPs = "))
            checker_routes = checker_allowed.split(", ")
            if checker_routes != ["10.20.17.1/32", "10.20.17.5/32"]:
                raise RuntimeError("Checker config did not contain exactly the connected customer host routes")
            install_client_wireguard(namespaces["chk"], peer_keys["chk"][0], gateway_public,
                                     "198.18.0.1:51820", checker_grant["checker_address"], checker_routes, 52005)

            probe_server = ROOT / "teliphones" / "checker_probe_server.py"
            challenge_records: dict[str, dict[str, Any]] = {}
            for customer, pbx_label, pbx_ip in (("customer-a", "pba", "10.20.17.1"),
                                                ("customer-b", "pbb", "10.20.17.5")):
                session_for_checker = {"session_id": session_ids[customer], "topology": "on-pbx",
                                       "expires_at": session_requests[customer]["expires_at"]}
                challenge = php_checker_action("challenge", session_for_checker, files / "php-checker-state",
                                               checker_public)
                challenge_file = files / (customer + "-checker-challenge.json")
                challenge_file.write_bytes(canonical_json(challenge) + b"\n")
                challenge_file.chmod(0o600)
                server = subprocess.Popen(["ip", "netns", "exec", namespaces[pbx_label], "python3", str(probe_server),
                                           "--bind", pbx_ip, "--port", "22221", "--challenge", str(challenge_file),
                                           "--session", session_ids[customer]], stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE, start_new_session=True)
                children.append(server)
                if not wait_for(lambda: server.poll() is None and f"{pbx_ip}:22221" in
                                command(["ss", "-H", "-ltn"], namespaces[pbx_label], check=False).stdout, seconds=3):
                    raise RuntimeError(f"{customer} restricted Checker probe failed to start")
                authorized_probe = connect_probe(pbx_ip, 22221, False, None, challenge["nonce"],
                                                 challenge["session_id"], namespaces["chk"])
                negative_probe = tcp_probe(pbx_ip, 22221, namespaces["enb"] if customer == "customer-a" else namespaces["ena"])
                public_ip = "198.19.0.1" if customer == "customer-a" else "198.19.0.5"
                public_probe = tcp_probe(public_ip, 22221, namespaces["pub"], require_wireguard=False)
                evidence = run_checks(challenge, authorized_probe, negative_probe, public_probe)
                evidence["signature"] = sign(evidence, checker_private)
                signature = base64.b64decode(evidence["signature"], validate=True)
                unsigned = {key: value for key, value in evidence.items() if key != "signature"}
                signed_file = files / (customer + "-checker-evidence.json")
                signed_file.write_bytes(canonical_json(unsigned))
                signature_file = files / (customer + "-checker-signature.der")
                signature_file.write_bytes(signature)
                verify = command(["openssl", "dgst", "-sha256", "-verify", str(checker_public), "-signature",
                                  str(signature_file), str(signed_file)], check=False)
                if not authorized_probe["reachable"] or negative_probe["reachable"] or public_probe["reachable"] or verify.returncode != 0:
                    raise RuntimeError(f"{customer} signed Checker positive/negative/public checks failed")
                php_acceptance = php_checker_action("accept", session_for_checker, files / "php-checker-state",
                                                    checker_public, signed_file)
                add_event(events, "checker-probes-signed-and-verified", customer=customer,
                          authorized=authorized_probe["result"], negative_blocked=True, public_blocked=True,
                          openssl_signature_verified=True, module_checker_accepted=php_acceptance["accepted"])
                challenge_records[customer] = challenge
                server.terminate()
                server.wait(timeout=3)

            if tcp_exchange(namespaces["ena"], "10.20.17.1", 80) is not None or tcp_exchange(namespaces["enb"], "10.20.17.5", 443) is not None:
                raise RuntimeError("engineer services opened before TELIPHONES activated signed Checker evidence")
            add_event(events, "engineer-service-closed-after-checker-before-activation")

            for customer in ("customer-a", "customer-b"):
                session_id = session_ids[customer]
                remote_id = responses[customer]["remote_id"]
                activated = gateway.activate(customer, request_for(session_id, remote_id, "activate"))
                if activated.get("state") != "active":
                    raise RuntimeError(f"{customer} did not activate after verified Checker evidence")
                add_event(events, "signed-checker-accepted-gateway-activation", customer=customer,
                          session=session_id[:8], state=activated["state"])

            for engineer_id, label, key_label in (("engineer-a", "ena", "engineer-a"),
                                                  ("engineer-b", "enb", "engineer-b")):
                grant = gateway.engineer_grant(engineer_id)
                private, public = peer_keys[label]
                generated = render_engineer_config(grant, "local-private-key", public)
                authorised_ip = "10.20.17.1/32" if engineer_id == "engineer-a" else "10.20.17.5/32"
                if f"AllowedIPs = {authorised_ip}" not in generated:
                    raise RuntimeError(f"{engineer_id} generated config contains unintended customer routes")
                unauthorized_ip = "10.20.17.5/32" if engineer_id == "engineer-a" else "10.20.17.1/32"
                command(["wg", "set", "wg0", "peer", gateway_public, "allowed-ips", f"{authorised_ip},{unauthorized_ip}"], namespaces[label])
                for route in (authorised_ip, unauthorized_ip):
                    command(["ip", "route", "replace", route, "dev", "wg0"], namespaces[label])
                add_event(events, "engineer-config-rendered", engineer=engineer_id,
                          allowed_ips=authorised_ip, private_key_exported=False,
                          negative_test_route_added=unauthorized_ip)

            if tcp_exchange(namespaces["ena"], "10.20.17.1", 22222) is not None:
                raise RuntimeError("SSH listener was reachable before the customer opened the temporary SSH service")
            add_event(events, "temporary-ssh-listener-closed-until-customer-open")

            for namespace, host, expected in (
                (namespaces["ena"], "10.20.17.1", "PBA:80;source=10.77.0.10;destination=10.20.17.1"),
                (namespaces["ena"], "10.20.17.1", "PBA:443;source=10.77.0.10;destination=10.20.17.1"),
                (namespaces["enb"], "10.20.17.5", "PBB:80;source=10.77.0.11;destination=10.20.17.5"),
                (namespaces["enb"], "10.20.17.5", "PBB:443;source=10.77.0.11;destination=10.20.17.5"),
            ):
                port = 80 if ":80;" in expected else 443
                response = tcp_exchange(namespace, host, port)
                if response != expected:
                    raise RuntimeError(f"actual TCP flow mismatch: expected {expected!r}, got {response!r}")
                add_event(events, "authorized-private-tcp-service", source=expected.split("source=")[1].split(";")[0],
                          destination=host, port=port, listener_response=response)

            for namespace, host, port, label in (
                (namespaces["enb"], "10.20.17.1", 80, "engineer-b-to-pbx-a"),
                (namespaces["ena"], "10.20.17.5", 80, "engineer-a-to-pbx-b"),
                (namespaces["pba"], "10.20.17.5", 80, "customer-a-to-customer-b"),
                (namespaces["pbb"], "10.20.17.1", 80, "customer-b-to-customer-a"),
            ):
                if tcp_exchange(namespace, host, port) is not None:
                    raise RuntimeError(f"unauthorized cross-customer TCP flow succeeded: {label}")
                add_event(events, "unauthorized-tcp-flow-rejected", path=label, destination=host, port=port)

            sshd_a, sshd_config_a = start_sshd(namespaces["pba"], "10.20.17.1", 22222, "pba",
                                               ssh_keys["engineer-a"][0], ssh_keys["engineer-a"][1], "10.77.0.10",
                                               files, children)
            sshd_b, sshd_config_b = start_sshd(namespaces["pbb"], "10.20.17.5", 22222, "pbb",
                                               ssh_keys["engineer-b"][0], ssh_keys["engineer-b"][1], "10.77.0.11",
                                               files, children)
            sshd_processes["pba"] = (sshd_a, sshd_config_a)
            sshd_processes["pbb"] = (sshd_b, sshd_config_b)
            ssh_a = ssh_command(namespaces["ena"], ssh_keys["engineer-a"][0], "10.20.17.1", "printf '%s' \"$SSH_CONNECTION\"")
            if ssh_a.returncode != 0 or not ssh_a.stdout.startswith("10.77.0.10 "):
                raise RuntimeError("authorised engineer A SSH authentication/source check failed")
            add_event(events, "authorized-ssh-authentication", source=ssh_a.stdout.split()[0], destination="10.20.17.1", port=22222)
            ssh_b = ssh_command(namespaces["enb"], ssh_keys["engineer-b"][0], "10.20.17.5", "printf '%s' \"$SSH_CONNECTION\"")
            if ssh_b.returncode != 0 or not ssh_b.stdout.startswith("10.77.0.11 "):
                raise RuntimeError("authorised engineer B SSH authentication/source check failed")
            add_event(events, "authorized-ssh-authentication", source=ssh_b.stdout.split()[0], destination="10.20.17.5", port=22222)
            wrong = ssh_command(namespaces["ena"], ssh_keys["wrong-key"][0], "10.20.17.1", "id")
            if wrong.returncode == 0:
                raise RuntimeError("incorrect SSH key was accepted")
            add_event(events, "incorrect-ssh-key-rejected", destination="10.20.17.1", port=22222)
            for namespace, host, label in ((namespaces["enb"], "10.20.17.1", "engineer-b-to-pbx-a"),
                                           (namespaces["ena"], "10.20.17.5", "engineer-a-to-pbx-b")):
                denied_ssh = ssh_command(namespace, ssh_keys["engineer-a" if namespace == namespaces["ena"] else "engineer-b"][0], host, "id", timeout=5)
                if denied_ssh.returncode == 0:
                    raise RuntimeError(f"unauthorized SSH flow succeeded: {label}")
                add_event(events, "unauthorized-ssh-rejected", path=label, destination=host, port=22222)

            for port in (80, 443, 22222):
                for public_ip in ("198.19.0.1", "198.19.0.5"):
                    if tcp_exchange(namespaces["pub"], public_ip, port) is not None:
                        raise RuntimeError(f"test service was reachable on simulated public address {public_ip}:{port}")
            add_event(events, "simulated-public-management-ports-blocked", addresses=["198.19.0.1", "198.19.0.5"],
                      ports=[80, 443, 22222], binding="PBX tunnel addresses only")

            persistent_ssh_a = subprocess.Popen(
                ["ip", "netns", "exec", namespaces["ena"], "ssh", "-F", "/dev/null", "-i", str(ssh_keys["engineer-a"][0]),
                 "-p", "22222", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "root@10.20.17.1", "printf 'ESTABLISHED\\n'; sleep 120"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            children.append(persistent_ssh_a)
            if persistent_ssh_a.stdout is None or persistent_ssh_a.stdout.readline().strip() != "ESTABLISHED":
                raise RuntimeError("could not establish persistent SSH session for revocation")
            add_event(events, "persistent-ssh-session-established", source="10.77.0.10", destination="10.20.17.1")

            session_a = session_ids["customer-a"]
            local_stop = stop_owned_sshd(sshd_a, sshd_config_a)
            command(["ip", "link", "del", "dev", "wg0"], namespaces["pba"])
            remote_cleanup = gateway.destroy("customer-a", request_for(session_a, responses["customer-a"]["remote_id"], "destroy"))
            if not local_stop or not remote_cleanup.get("destroyed"):
                raise RuntimeError("customer A revocation did not complete local and gateway teardown")
            try:
                persistent_ssh_a.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("established SSH session survived local revocation") from error
            if tcp_exchange(namespaces["ena"], "10.20.17.1", 80) is not None:
                raise RuntimeError("new TCP flow succeeded after revocation")
            if ssh_command(namespaces["ena"], ssh_keys["engineer-a"][0], "10.20.17.1", "id", timeout=4).returncode == 0:
                raise RuntimeError("new SSH connection succeeded after revocation")
            add_event(events, "revocation-terminated-established-ssh-and-new-flows", customer="customer-a",
                      local_sshd_tree_stopped=True, local_wireguard_removed=True, gateway_destroyed=True)

            service_status = gateway.store.session(session_a)
            if not service_status or service_status["state"] != "revoked":
                raise RuntimeError("revoked session was not retained as a gateway tombstone")
            recovered_gateway = GatewayService(config, files / "gateway-state", runner=gateway_runner)
            recovered_gateway.reconcile()
            gateway = recovered_gateway
            if peer_keys["pba"][1] in command(["wg", "show", "wg0", "peers"], namespaces["gw"]).stdout.splitlines():
                raise RuntimeError("gateway reconciliation restored a revoked customer peer")
            add_event(events, "gateway-restart-reconcile-did-not-restore-revoked-peer", customer="customer-a")

            persistent_ssh_b = subprocess.Popen(
                ["ip", "netns", "exec", namespaces["enb"], "ssh", "-F", "/dev/null", "-i", str(ssh_keys["engineer-b"][0]),
                 "-p", "22222", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "root@10.20.17.5", "printf 'EXPIRY-SSH\\n'; sleep 120"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            children.append(persistent_ssh_b)
            if persistent_ssh_b.stdout is None or persistent_ssh_b.stdout.readline().strip() != "EXPIRY-SSH":
                raise RuntimeError("could not establish persistent SSH session for expiry")
            add_event(events, "persistent-ssh-session-established", source="10.77.0.11", destination="10.20.17.5")

            command(["ip", "link", "set", "down", "dev", "wg0"], namespaces["gw"])
            add_event(events, "gateway-wireguard-outage-simulated", customer="customer-b")
            wait_seconds = max(0, expiry_b - int(time.time())) + 1
            time.sleep(wait_seconds)
            tcp_set = command(["nft", "list", "set", "inet", "teliphones", "allowed_tcp"], namespaces["gw"]).stdout
            if "10.77.0.11" in tcp_set or "10.20.17.5" in tcp_set:
                raise RuntimeError("nftables still contained customer B engineer service permissions after expiry")
            if tcp_exchange(namespaces["enb"], "10.20.17.5", 80) is not None:
                raise RuntimeError("gateway firewall still allowed TCP after the absolute expiry timeout")
            local_stop_b = stop_owned_sshd(sshd_b, sshd_config_b)
            if not local_stop_b:
                raise RuntimeError("local expiry did not stop the session-owned SSH process tree")
            try:
                persistent_ssh_b.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("established SSH session survived local expiry while gateway was offline") from error
            command(["ip", "link", "set", "up", "dev", "wg0"], namespaces["gw"])
            command(["ip", "link", "set", "up", "dev", "br-underlay"], namespaces["gw"])
            expired_count = gateway.expire()
            if expired_count != 1:
                raise RuntimeError(f"gateway expiry worker cleaned {expired_count} sessions; expected 1")
            sshd_b_restarted, sshd_b_restarted_config = start_sshd(
                namespaces["pbb"], "10.20.17.5", 22222, "pbb-after-expiry",
                ssh_keys["engineer-b"][0], ssh_keys["engineer-b"][1], "10.77.0.11", files, children)
            sshd_processes["pbb-after-expiry"] = (sshd_b_restarted, sshd_b_restarted_config)
            if ssh_command(namespaces["enb"], ssh_keys["engineer-b"][0], "10.20.17.5", "id", timeout=4).returncode == 0:
                raise RuntimeError("restarted SSH daemon regained expired gateway access")
            stop_owned_sshd(sshd_b_restarted, sshd_b_restarted_config)
            command(["ip", "link", "del", "dev", "wg0"], namespaces["pbb"])
            add_event(events, "absolute-expiry-terminated-ssh-and-removed-gateway-peer", customer="customer-b",
                      expired_sessions=expired_count, firewall_timeout_observed=True, established_ssh_terminated=True,
                      local_teardown_preceded_gateway_recovery=True)
            restarted_gateway = GatewayService(config, files / "gateway-state", runner=gateway_runner)
            restarted_gateway.reconcile()
            if peer_keys["pbb"][1] in command(["wg", "show", "wg0", "peers"], namespaces["gw"]).stdout.splitlines():
                raise RuntimeError("gateway reconciliation restored an expired customer peer")

            for label, namespace in namespaces.items():
                route = command(["ip", "-4", "route", "show", "default"], namespace).stdout
                if route:
                    raise RuntimeError(f"namespace {label} unexpectedly has a default route")
            add_event(events, "namespace-default-routes-preserved", namespaces=list(namespaces))

    except Exception as error:
        failure = error
    finally:
        for process, config in sshd_processes.values():
            if process.poll() is None:
                try:
                    stop_owned_sshd(process, config)
                except Exception as error:
                    failure = failure or error
        for process in children:
            stop_owned_process_group(process)
        for namespace in reversed(created):
            command(["ip", "netns", "del", namespace], check=False)
        try:
            host_after = host_snapshot()
            report["host_state_after_sha256"] = hashlib.sha256(json.dumps(host_after, sort_keys=True).encode()).hexdigest()
            report["host_network_unchanged"] = host_after == host_before
            if host_after != host_before:
                host_changed = True
                print("BLOCKED/FAIL: host networking or protected file state changed during cleanup", file=sys.stderr)
        except Exception as error:
            host_changed = True
            report["host_network_unchanged"] = False
            print(f"BLOCKED/FAIL: could not verify host cleanup: {error}", file=sys.stderr)

    report["events"] = events
    report["finished_at"] = int(time.time())
    report["result"] = "FAILED" if failure or host_changed else "PASS"
    if args.evidence:
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(args.evidence, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as evidence_file:
                json.dump(report, evidence_file, sort_keys=True, indent=2)
                evidence_file.write("\n")
        except OSError as error:
            print(f"Could not write evidence file: {error}", file=sys.stderr)
            return 1
    if failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    if host_changed:
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())