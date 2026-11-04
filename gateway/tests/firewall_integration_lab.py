#!/usr/bin/env python3
"""Real packet test of the FreePBX Firewall integration; called only inside a new user/network namespace.

The PBX side is this namespace, with a veth named tlp-admin (no WireGuard: `wg` may be absent). The
workstation is a nested network namespace. FreePBX Firewall is *simulated* with the hook/zone/final
DROP shape reported from a real FreePBX 17 PBX (INPUT -> the eight observed fail2ban-* hooks, INPUT -> fpbxfirewall
-> zone-external, DROP);
it is not the FreePBX Firewall implementation.
"""
import atexit
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
if (os.geteuid() != 0 or len(sys.argv) != 3 or not sys.argv[1].startswith("net:[")
        or os.readlink("/proc/self/ns/net") == sys.argv[1] or sys.argv[2] not in ("nft", "legacy")):
    raise SystemExit("Refusing to run outside a new user/network namespace.")

spec = importlib.util.spec_from_file_location("broker", ROOT / "teliphones/support_broker.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)
broker.SESSION_LEASE_SECONDS = 3600
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_support_broker import FREEPBX17_FAIL2BAN as BANS, fail2ban_hook  # noqa: E402

BACKEND = sys.argv[2]
IPTABLES = "/usr/sbin/iptables-nft" if BACKEND == "nft" else "/usr/sbin/iptables-legacy"
IP6TABLES = IPTABLES.replace("iptables", "ip6tables")
LOCK_DIRECTORY = tempfile.TemporaryDirectory(prefix="teliphones-xtables-lab-")
atexit.register(LOCK_DIRECTORY.cleanup)
LOCK = os.path.join(LOCK_DIRECTORY.name, "xtables.lock")
broker.IPTABLES = [IPTABLES]
broker.ENV = {**broker.ENV, "XTABLES_LOCKFILE": LOCK}
ENV = {**os.environ, "XTABLES_LOCKFILE": LOCK}
PBX, SSH_PEER, WEB_PEER, STRANGER = "100.70.1.1", "100.70.1.2", "100.70.1.4", "100.70.1.3"
PORTS = (22, 80, 443, 3306, 5038, 5060, broker.ssh.API_PORT, broker.SESSION_CONTROL_PORT, 8443, 22002, 22004)
# Public-side networks: FreePBX drops everything from these by default (external-zone shape).
WAN = (("198.51.100.50", "198.51.100.1"), ("203.0.113.9", "203.0.113.1"))


def run(*arguments, check=True):
    result = subprocess.run(list(arguments), capture_output=True, text=True, check=False, env=ENV)
    if check and result.returncode:
        raise RuntimeError("%s failed: %s%s" % (
            shlex.join(arguments), result.stdout, result.stderr))
    return result.stdout


def ipt(*arguments):
    return run(IPTABLES, "-w", "5", *arguments)


def freepbx(reload_order="normal"):
    """Simulated FreePBX Firewall/Fail2Ban reload: rebuilds only their own chains and INPUT hooks."""
    for line in ipt("-S", "INPUT").splitlines():
        if line.split()[-1] in ["fpbxfirewall", *BANS]:
            ipt("-D", "INPUT", *line.split()[2:])
    for chain in ("fpbxfirewall", "zone-external", "zone-internal", "zone-other", *BANS):
        if run(IPTABLES, "-w", "5", "-S", chain, check=False):
            ipt("-F", chain)
        else:
            ipt("-N", chain)
    for chain in BANS:
        ipt("-A", chain, "-j", "RETURN")
    ipt("-A", "fpbxfirewall", "-i", "lo", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-i", "lan0", "-p", "udp", "-m", "multiport", "--dports", "5060,10000:10010", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-i", "lan0", "-p", "tcp", "-m", "multiport", "--dports", "22,443", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-j", "zone-external")
    ipt("-A", "fpbxfirewall", "-j", "DROP")
    if reload_order == "hook-first":
        ipt("-I", "INPUT", "1", "-j", "fpbxfirewall")
        for chain in BANS:
            # Fail2Ban inserts its hooks at INPUT position 1.
            ipt("-I", "INPUT", "1", *fail2ban_hook(chain))
    else:
        for chain in BANS:
            ipt("-A", "INPUT", *fail2ban_hook(chain))
        ipt("-A", "INPUT", "-j", "fpbxfirewall")
    if listener_port:
        listener_service(listener_port)


def freepbx_snapshot():
    def owned(line):
        rule = broker.iptables_rule(shlex.split(line)[2:])
        return ((rule is not None and rule.get("comment") == broker.INTEGRATION_MARK)
                or "-j fpbxsvc-" in line)
    return [[line for line in ipt("-S", chain).splitlines() if not owned(line)]
            for chain in ("INPUT", "fpbxfirewall", "zone-external", *BANS)] + [ipt("-S").splitlines()[:3]]


def input_targets():
    return [line.split()[-1] for line in ipt("-S", "INPUT").splitlines()[1:]]


def valid_order():
    targets = input_targets()
    rules = ipt("-S", "fpbxfirewall").splitlines()[1:]
    return (broker.INTEGRATION_CHAIN not in targets and targets.count("fpbxfirewall") == 1
            and len(jumps()) == 1 and rules[0] == jumps()[0]
            and all(targets.index(chain) < targets.index("fpbxfirewall") for chain in BANS))


def move_hook(chain, before=None):
    """Simulated reload that reorders one Fail2Ban hook (appended, or placed before `before`)."""
    hook = fail2ban_hook(chain)
    ipt("-D", "INPUT", *hook)
    if before is None:
        ipt("-A", "INPUT", *hook)
    else:
        ipt("-I", "INPUT", str(input_targets().index(before) + 1), *hook)


def listen(port, family=socket.AF_INET):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
    server.listen(16)

    def accept():
        while True:
            connection, _ = server.accept()
            connection.close()
    threading.Thread(target=accept, daemon=True).start()


CLIENT = r"""
import json, socket, sys, threading
results = []
def probe(source, destination, port):
    family = socket.AF_INET6 if ":" in destination else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(0.6)
    try:
        sock.bind((source, 0)); sock.connect((destination, port)); results.append([source, destination, port, True])
    except OSError:
        results.append([source, destination, port, False])
    finally:
        sock.close()
threads = [threading.Thread(target=probe, args=tuple(item)) for item in json.loads(sys.argv[1])]
[thread.start() for thread in threads]; [thread.join() for thread in threads]
print(json.dumps(results))
"""


def reachable(workstation, probes):
    output = run("nsenter", "--net=/proc/%d/ns/net" % workstation.pid, sys.executable, "-c", CLIENT,
                 json.dumps([[source, destination, port] for source, destination, port in probes]))
    return {(source, destination, port): ok for source, destination, port, ok in json.loads(output)}


def open_set(workstation, sources=(SSH_PEER, WEB_PEER, STRANGER)):
    results = reachable(workstation, [(source, PBX, port) for source in sources for port in PORTS])
    return {(source, port) for (source, _, port), ok in results.items() if ok}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def jumps():
    return [line for line in ipt("-S", "fpbxfirewall").splitlines() if "-j " + broker.INTEGRATION_CHAIN in line]


def udp_echo(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", port))
    def echo():
        while True:
            data, address = server.recvfrom(1024)
            server.sendto(data, address)
    threading.Thread(target=echo, daemon=True).start()


def udp_probe(workstation, source, destination, port):
    """One datagram exchange, like a WireGuard handshake initiation/response pair."""
    output = run("nsenter", "--net=/proc/%d/ns/net" % workstation.pid, sys.executable, "-c", r"""
import socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(0.6)
    client.bind((sys.argv[1], 0))
    client.sendto(b"teliphones-wg", (sys.argv[2], int(sys.argv[3])))
    try:
        print("open" if client.recv(64) == b"teliphones-wg" else "other")
    except socket.timeout:
        print("closed")
""", source, destination, str(port))
    return output.strip() == "open"


def check_unrelated(workstation):
    results = reachable(workstation, [("192.0.2.2", "192.0.2.1", port) for port in PORTS])
    check({port for (_, _, port), ok in results.items() if ok} == {22, 443},
          "unrelated management permits/denies changed")
    output = run("nsenter", "--net=/proc/%d/ns/net" % workstation.pid, sys.executable, "-c", r"""
import socket
for port in (5060, 10000):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.bind(("192.0.2.2", 0))
        client.sendto(b"teliphones-lab", ("192.0.2.1", port))
        assert client.recv(1024) == b"teliphones-lab"
print("ok")
""")
    check(output.strip() == "ok", "normal SIP/RTP UDP traffic changed")


def expect_raises(function, message):
    try:
        function()
    except broker.BrokerError:
        return
    raise AssertionError(message)


listener_port = 0


def listener_service(port):
    global listener_port
    ports = [] if port == 0 else (port if isinstance(port, (list, tuple)) else [port])
    run("php", str(Path(__file__).with_name("firewall_listener_model.php")),
        str(broker.STATE), ",".join(str(item) for item in ports) if ports else "0", IPTABLES, sys.argv[1])
    listener_port = ports[0] if ports else 0


workstation = subprocess.Popen(["unshare", "--net", "sleep", "180"])
with tempfile.TemporaryDirectory(prefix=".firewall-lab-", dir=ROOT) as directory:
    broker.STATE = Path(directory)
    instance = broker.Broker()
    instance.audit = lambda *args: None
    instance.reconcile_listener = listener_service
    try:
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", broker.WORKSTATION_IFACE, "type", "veth", "peer", "name", "ws0")
        run("ip", "link", "set", "ws0", "netns", str(workstation.pid))
        run("ip", "address", "add", PBX + "/24", "dev", broker.WORKSTATION_IFACE)
        run("ip", "address", "add", "fd7e::1/64", "dev", broker.WORKSTATION_IFACE, "nodad")
        run("ip", "link", "set", broker.WORKSTATION_IFACE, "up")
        enter = ["nsenter", "--net=/proc/%d/ns/net" % workstation.pid]
        run(*enter, "ip", "link", "set", "lo", "up")
        for address in (SSH_PEER, WEB_PEER, STRANGER):
            run(*enter, "ip", "address", "add", address + "/24", "dev", "ws0")
        run(*enter, "ip", "address", "add", "fd7e::2/64", "dev", "ws0", "nodad")
        run(*enter, "ip", "link", "set", "ws0", "up")
        run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "lan1")
        run("ip", "link", "set", "lan1", "netns", str(workstation.pid))
        run("ip", "address", "add", "192.0.2.1/24", "dev", "lan0")
        run("ip", "link", "set", "lan0", "up")
        run(*enter, "ip", "address", "add", "192.0.2.2/24", "dev", "lan1")
        run(*enter, "ip", "link", "set", "lan1", "up")
        # Public side: a WAN link where the workstation can source traffic from changing, previously
        # unknown addresses, exactly like a roaming TELIPHONES workstation on new public IPs.
        run("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "wan1")
        run("ip", "link", "set", "wan1", "netns", str(workstation.pid))
        for _, gateway in WAN:
            run("ip", "address", "add", gateway + "/24", "dev", "wan0")
        run("ip", "link", "set", "wan0", "up")
        for source, _ in WAN:
            run(*enter, "ip", "address", "add", source + "/24", "dev", "wan1")
        run(*enter, "ip", "link", "set", "wan1", "up")
        for port in PORTS:
            listen(port)
            listen(port, socket.AF_INET6)
        for port in (5060, 10000):
            udp_echo(port)
        udp_echo(51821)

        state = {"subnet": "100.70.1.0/24", "listen_port": 51821, "connection_state": "open",
                 "max_sessions": 2, "workstations": [
            {"id": "a" * 16, "name": "ssh", "public_key": "A" * 42 + "A=", "address": SSH_PEER + "/32", "mode": "persistent", "ssh": True},
            {"id": "b" * 16, "name": "web", "public_key": "B" * 42 + "A=", "address": WEB_PEER + "/32", "mode": "persistent", "ssh": False}]}
        instance.save_workstations(state)
        lease = int(broker.time.time()) + broker.SESSION_LEASE_SECONDS
        instance.save_active_sessions({"a" * 16: {"expires_at": lease}, "b" * 16: {"expires_at": lease}})
        run("nft", "add", "table", "inet", "teliphones_lab_foreign")
        foreign = run("nft", "-j", "list", "table", "inet", "teliphones_lab_foreign")
        ip6_before = run(IP6TABLES, "-w", "5", "-S")
        instance.start_monitor()
        instance.mutate_policy(instance.expected_policy(state), None)

        # The nft table alone restricts web access by interface/destination; WireGuard AllowedIPs normally binds the
        # source. This veth has no cryptokey routing, so the unauthorised source is visible here.
        check(open_set(workstation) == {(source, broker.SESSION_CONTROL_PORT) for source in (SSH_PEER, WEB_PEER)}
              | {(source, port) for source in (SSH_PEER, WEB_PEER) for port in (80, 443)}
              | {(SSH_PEER, 22)},
              "baseline without FreePBX simulation should follow the nft policy only")
        freepbx()
        check(open_set(workstation) == set(), "reproduction: nft ACCEPT must not override the simulated FreePBX DROP")
        check(not udp_probe(workstation, WAN[0][0], WAN[0][1], 51821),
              "reproduction: without integration, FreePBX DROP must block unknown-source WireGuard UDP")
        check_unrelated(workstation)

        instance.firewall_integration(state)
        listener_service([51821, 52022])
        before = freepbx_snapshot()
        output = run(*enter, sys.executable, "-c", r"""
import socket
for port in (5060, 10000):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.3)
        client.bind(("100.70.1.2", 0))
        client.sendto(b"denied", ("100.70.1.1", port))
        try:
            client.recv(1024)
        except socket.timeout:
            continue
        raise AssertionError("SIP/RTP admitted over workstation interface")
print("ok")
""")
        check(output.strip() == "ok", "workstation SIP/RTP restriction changed")

        expected_open = {(SSH_PEER, 80), (SSH_PEER, 443), (SSH_PEER, 22), (WEB_PEER, 80), (WEB_PEER, 443),
                         (SSH_PEER, broker.SESSION_CONTROL_PORT), (WEB_PEER, broker.SESSION_CONTROL_PORT)}
        check(instance.integration["state"] == "active", instance.integration)
        check(open_set(workstation) == expected_open, "integration must open exactly authorised web/SSH flows")
        # The WireGuard listener accepts handshakes from any public address, including a previously
        # unknown one and a changed one, without any per-source configuration (the live regression).
        for source, gateway in WAN:
            check(udp_probe(workstation, source, gateway, 51821),
                  "WireGuard handshake UDP must reach the listener from previously unknown source %s" % source)
        monitor = instance.monitor
        monitor.close()
        instance.monitor = None
        listener_service([51821, 52022])
        udp_echo(52022)
        locked_policy = broker.workstation_policy(
            PBX, [SSH_PEER], web_ports=tuple(entry["port"] for entry in broker.DEFAULT_WEB),
            listener_sources=[{"port": 52022, "sources": [WAN[0][0] + "/32"]}],
            admitted_sources=[SSH_PEER, WEB_PEER], control_sources=[SSH_PEER, WEB_PEER])
        instance.mutate_policy(locked_policy, instance.owned_table())
        check(udp_probe(workstation, WAN[0][0], WAN[0][1], 52022),
              "a source explicitly allowed on a locked listener must reach UDP")
        check(not udp_probe(workstation, WAN[1][0], WAN[1][1], 52022),
              "an unapproved public source must be dropped on a locked listener")
        locked_id, locked_peer = "c" * 16, "100.71.1.2"
        locked_interface = instance.locked_interface({"id": locked_id})
        run("ip", "link", "add", locked_interface, "type", "veth", "peer", "name", "locked-ws0")
        run("ip", "link", "set", "locked-ws0", "netns", str(workstation.pid))
        run("ip", "address", "add", "100.71.1.1/24", "dev", locked_interface)
        run("ip", "link", "set", locked_interface, "up")
        run(*enter, "ip", "address", "add", locked_peer + "/24", "dev", "locked-ws0")
        run(*enter, "ip", "address", "add", "100.71.1.3/24", "dev", "locked-ws0")
        run(*enter, "ip", "link", "set", "locked-ws0", "up")
        dedicated_policy = broker.workstation_policy(
            PBX, [SSH_PEER], web_ports=tuple(entry["port"] for entry in broker.DEFAULT_WEB),
            listener_sources=[{"port": 52022, "sources": [WAN[0][0] + "/32"]}],
            peer_interfaces=[{"interface": locked_interface, "pbx_address": "100.71.1.1",
                              "source": locked_peer, "ssh_port": 22002}],
            admitted_sources=[SSH_PEER, WEB_PEER, locked_peer],
            control_sources=[SSH_PEER, WEB_PEER, locked_peer])
        instance.mutate_policy(dedicated_policy, instance.owned_table())
        locked_state = dict(state)
        locked_state["workstations"] = state["workstations"] + [{
            "id": locked_id, "name": "locked", "public_key": "C" * 42 + "A=",
            "address": locked_peer + "/32", "mode": "persistent", "ssh": True,
            "ssh_public_key": "fixture", "ssh_user": "fixture", "locked": True,
            "subnet": "100.71.1.0/24", "pbx_address": "100.71.1.1", "listener_port": 52022,
        }]
        instance.firewall_integration(locked_state)
        dedicated_access = reachable(workstation, [
            (locked_peer, "100.71.1.1", port) for port in (22, 80, 443, 5038, broker.ssh.API_PORT,
                                                            broker.SESSION_CONTROL_PORT, 22002)])
        check({port for (_, _, port), allowed in dedicated_access.items() if allowed}
              == {80, 443, broker.ssh.API_PORT, broker.SESSION_CONTROL_PORT, 22002},
              "dedicated peer interface must permit web and explicitly authorised managed SSH only: %r; "
              "integration=%r rules=%r" % (dedicated_access, instance.integration,
                                           ipt("-S", broker.INTEGRATION_CHAIN)))
        wrong_peer = reachable(workstation, [
            ("100.71.1.3", "100.71.1.1", port) for port in (80, 443, broker.ssh.API_PORT,
                                                              broker.SESSION_CONTROL_PORT, 22002)])
        check(not any(wrong_peer.values()),
              "dedicated managed SSH and web permits must reject another source on the same interface")
        instance.firewall_integration(state)
        instance.mutate_policy(instance.expected_policy(state), instance.owned_table())
        instance.start_monitor()
        check(not udp_probe(workstation, WAN[0][0], WAN[0][1], 51822), "only the WireGuard listener port may be opened")
        wan_tcp = reachable(workstation, [(WAN[0][0], WAN[0][1], port) for port in PORTS])
        check(not any(wan_tcp.values()), "no TCP service may become reachable from the public side")
        listing = ipt("-S", "INPUT").splitlines()
        check([line.split()[-1] for line in listing[1:]] == BANS + ["fpbxfirewall"], listing)
        check(freepbx_snapshot() == before, "unrelated FreePBX rules or policy were modified")
        stable = ipt("-S")
        for _ in range(5):
            instance.firewall_integration(state)
            check(ipt("-S") == stable and valid_order(), "watchdog/reconcile cycles changed INPUT or duplicated rules")
        check_unrelated(workstation)

        # A remote disconnect changes no PBX authorization. Reconnection must reuse the exact same policy.
        run(*enter, "ip", "link", "set", "ws0", "down")
        instance.firewall_integration(state)
        check(ipt("-S") == stable, "disconnect rewrote firewall authorization")
        run(*enter, "ip", "link", "set", "ws0", "up")
        instance.firewall_integration(state)
        check(ipt("-S") == stable and open_set(workstation) == expected_open,
              "reconnect duplicated rules or changed access")

        # Migrate the exact old intrusive rule without installing any new INPUT rule.
        ipt("-D", "fpbxfirewall", *broker.iptables_arguments(broker.INTEGRATION_JUMP))
        ipt("-I", "INPUT", str(len(BANS) + 1), *broker.iptables_arguments(broker.LEGACY_INTEGRATION_JUMP))
        instance.firewall_integration(state)
        check(valid_order() and freepbx_snapshot() == before, "legacy INPUT migration failed")

        # "active" verifies the owned rules, not reachability through every independent firewall decision.
        early_drop = ("-i", broker.WORKSTATION_IFACE, "-s", WEB_PEER, "-p", "tcp", "--dport", "80", "-j", "DROP")
        ipt("-I", "INPUT", "1", *early_drop)
        instance.firewall_integration(state)
        check(instance.integration["state"] == "active", instance.integration)
        check(open_set(workstation) == expected_open - {(WEB_PEER, 80)}, "an earlier INPUT drop must not be bypassed")
        ipt("-D", "INPUT", *early_drop)

        run("nft", "add", "table", "inet", "teliphones_lab_late")
        run("nft", "add", "chain", "inet", "teliphones_lab_late", "input",
            "{ type filter hook input priority 10; policy accept; }")
        run("nft", "add", "rule", "inet", "teliphones_lab_late", "input",
            "iifname", broker.WORKSTATION_IFACE, "ip", "saddr", WEB_PEER, "tcp", "dport", "443", "drop")
        instance.firewall_integration(state)
        check(instance.integration["state"] == "active", instance.integration)
        check(open_set(workstation) == expected_open - {(WEB_PEER, 443)}, "a separate nftables drop must not be bypassed")
        run("nft", "delete", "table", "inet", "teliphones_lab_late")
        check(open_set(workstation) == expected_open, "removing lab-only blockers must restore the baseline")

        # IPv6 is not integrated and remains dropped by the owned nft policy.
        v6 = reachable(workstation, [("fd7e::2", "fd7e::1", port) for port in PORTS])
        check(not any(v6.values()), "IPv6 through tlp-admin must remain blocked")
        check(run(IP6TABLES, "-w", "5", "-S") == ip6_before, "ip6tables must not be modified")

        # Fail2Ban precedes TELIPHONES: banned authorised peers stay banned (PBX-GUI web jail and sshd jail).
        ipt("-I", "fail2ban-PBX-GUI", "1", "-s", WEB_PEER, "-j", "REJECT")
        ipt("-I", "fail2ban-sshd", "1", "-s", SSH_PEER, "-j", "REJECT")
        check(open_set(workstation) == expected_open - {(WEB_PEER, 80), (WEB_PEER, 443), (SSH_PEER, 22)}, "Fail2Ban ban was bypassed")
        ipt("-D", "fail2ban-PBX-GUI", "-s", WEB_PEER, "-j", "REJECT")
        ipt("-D", "fail2ban-sshd", "-s", SSH_PEER, "-j", "REJECT")

        # Without the owned nft table, integration still opens nothing beyond authorised 80/443/22.
        run("nft", "delete", "table", "inet", broker.WORKSTATION_TABLE)
        check(open_set(workstation) == expected_open, "integration widened access when nft protection was missing")
        check(instance.enforcement_event.wait(3), "nft removal not observed")
        instance.enforcement_event.clear()
        instance.mutate_policy(instance.expected_policy(state), None)

        # Event-driven repair of FreePBX reloads (iptables-nft emits nft events; legacy relies on the periodic check).
        for order in ("flush", "hook-first", "chain-deleted"):
            instance.wake.clear()
            if order in ("flush", "chain-deleted"):
                ipt("-F", "INPUT")
            if order == "chain-deleted":
                for jump in jumps():
                    ipt("-D", "fpbxfirewall", *shlex.split(jump)[2:])
                ipt("-F", broker.INTEGRATION_CHAIN)
                ipt("-X", broker.INTEGRATION_CHAIN)
            freepbx("hook-first" if order == "hook-first" else "normal")
            check(freepbx_snapshot()[1:] == before[1:], "simulated reload changed FreePBX rules")
            check(open_set(workstation, (SSH_PEER,)) == set(), "reload must fall back to FreePBX policy (fail closed)")
            if BACKEND == "nft":
                check(instance.wake.wait(3), "FreePBX iptables-nft reload did not wake the enforcement worker")
            instance.expire_workstations()
            check(instance.integration["state"] == "active" and len(jumps()) == 1,
                  (instance.integration, instance.workstation_error))
            check(valid_order(), input_targets())
            check(open_set(workstation) == expected_open, "reconciliation did not restore exact access")
            check(udp_probe(workstation, WAN[0][0], WAN[0][1], 51821), "reload must restore WireGuard reachability")
            check_unrelated(workstation)

        # Reload that moves an observed Fail2Ban hook after fpbxfirewall: integration is withdrawn (Fail2Ban is never
        # bypassed), then restored at the correct position after Fail2Ban re-inserts its hook at position 1.
        move_hook("fail2ban-PBX-GUI")
        instance.expire_workstations()
        check(instance.integration["state"] == "error" and not jumps() and "fail2ban-PBX-GUI" in instance.integration["message"],
              instance.integration)
        check(open_set(workstation, (SSH_PEER,)) == set(), "withdrawn integration must leave FreePBX policy in force")
        ipt("-D", "INPUT", *fail2ban_hook("fail2ban-PBX-GUI"))
        ipt("-I", "INPUT", "1", *fail2ban_hook("fail2ban-PBX-GUI"))
        instance.expire_workstations()
        check(instance.integration["state"] == "active" and valid_order(), input_targets())
        check(open_set(workstation) == expected_open, "integration not restored after Fail2Ban hook reordering")

        # Fail2Ban can reinsert hooks immediately above fpbxfirewall without bypassing them or moving our jump.
        move_hook("fail2ban-apache-auth", before="fpbxfirewall")
        ipt("-I", "fail2ban-apache-auth", "1", "-s", WEB_PEER, "-j", "REJECT")
        instance.expire_workstations()
        check(valid_order(), input_targets())
        fail2ban_open = open_set(workstation, (WEB_PEER,))
        check(fail2ban_open == {(WEB_PEER, broker.SESSION_CONTROL_PORT)},
              "Fail2Ban must block management services while leaving only the non-management lease-control API: %r" %
              (fail2ban_open,))
        ipt("-D", "fail2ban-apache-auth", "-s", WEB_PEER, "-j", "REJECT")
        freepbx()
        instance.expire_workstations()
        check(valid_order() and freepbx_snapshot() == before, input_targets())
        check(not instance.enforcement_event.is_set(), "iptables reloads must not re-admit peers")

        # Managed pairings keep only their certificate API and dedicated SSH port, not system SSH or another
        # peer's listener. No sshd is started here; certificate authentication has its own isolated SSH suite.
        managed_state = json.loads(json.dumps(state))
        managed_state["workstations"][0]["ssh_public_key"] = "fixture"
        instance.mutate_policy(instance.expected_policy(managed_state), instance.owned_table())
        instance.firewall_integration(managed_state)
        check(open_set(workstation) == expected_open - {(SSH_PEER, 22)}
              | {(SSH_PEER, broker.ssh.API_PORT), (SSH_PEER, 22002)},
              "managed SSH/API scope widened or system SSH admitted")
        check_unrelated(workstation)
        instance.mutate_policy(instance.expected_policy(state), instance.owned_table())

        # SSH removal and revocation take effect immediately.
        state["workstations"][0]["ssh"] = False
        instance.firewall_integration(state)
        check(open_set(workstation) == expected_open - {(SSH_PEER, 22)}, "SSH was not removed")
        state["workstations"] = state["workstations"][1:]
        instance.firewall_integration(state)
        check(open_set(workstation) == {(WEB_PEER, 80), (WEB_PEER, 443),
                                        (WEB_PEER, broker.SESSION_CONTROL_PORT)}, "revoked peer retained access")
        check(udp_probe(workstation, WAN[1][0], WAN[1][1], 51821), "revoking one peer must not close the listener")

        # Management web ports follow configuration on both firewall layers, with no stale permits.
        web_state = json.loads(json.dumps(state))
        web_state["web"] = [{"scheme": "https", "port": 8443}]
        instance.mutate_policy(instance.expected_policy(web_state), instance.owned_table())
        instance.firewall_integration(web_state)
        check(open_set(workstation, (WEB_PEER,)) == {(WEB_PEER, 8443),
                                                     (WEB_PEER, broker.SESSION_CONTROL_PORT)},
              "custom management port not applied or stale ports kept")
        check(udp_probe(workstation, WAN[0][0], WAN[0][1], 51821), "management port change must not affect the listener")
        instance.mutate_policy(instance.expected_policy(state), instance.owned_table())
        instance.firewall_integration(state)
        check(open_set(workstation, (WEB_PEER,)) == {(WEB_PEER, 80), (WEB_PEER, 443),
                                                     (WEB_PEER, broker.SESSION_CONTROL_PORT)},
              "management port restore failed")

        # Unknown hook ordering and missing hooks never produce integration rules.
        move_hook("fail2ban-sshd")
        instance.firewall_integration(state)
        check(instance.integration["state"] == "error" and not jumps(), "integration installed before a Fail2Ban hook")
        ipt("-D", "INPUT", "-j", "fpbxfirewall")
        instance.firewall_integration(state)
        check(instance.integration["state"] == "not-detected" and not jumps(), "integration installed without a FreePBX hook")
        freepbx()
        instance.firewall_integration(state)

        # Teardown removes only TELIPHONES' rules; FreePBX, nft foreign table and ip6tables are preserved.
        instance.teardown_workstations()
        check(not jumps() and broker.INTEGRATION_CHAIN not in ipt("-S"), "integration not removed")
        check(not udp_probe(workstation, WAN[0][0], WAN[0][1], 51821), "teardown must close the WireGuard listener permit")
        check(freepbx_snapshot() == before, "teardown changed FreePBX rules")
        check(run("nft", "-j", "list", "table", "inet", "teliphones_lab_foreign") == foreign, "foreign nft table changed")
        check(run(IP6TABLES, "-w", "5", "-S") == ip6_before, "ip6tables changed")
        check_unrelated(workstation)

        # An unfamiliar namesake chain is never modified or removed.
        ipt("-N", broker.INTEGRATION_CHAIN)
        ipt("-A", broker.INTEGRATION_CHAIN, "-j", "ACCEPT")
        foreign_chain = ipt("-S", broker.INTEGRATION_CHAIN)
        expect_raises(lambda: instance.firewall_integration({**state, "workstations": state["workstations"]}), "unfamiliar chain accepted")
        expect_raises(instance.remove_integration, "unfamiliar chain removed")
        check(ipt("-S", broker.INTEGRATION_CHAIN) == foreign_chain and not jumps(), "unfamiliar chain modified")
        print("PASS (%s): FreePBX DROP reproduced; WireGuard UDP listener reachable from unknown/changed public sources without "
              "whitelisting and closed on teardown; exact per-peer management-web and approved-SSH access with configurable ports; "
              "SIP/AMI/DB/other peers/IPv6 blocked; observed fail2ban-* precedence and reordering; reload repair without duplicates; "
              "revocation; FreePBX/ip6tables/foreign preservation" % BACKEND)
    finally:
        instance.monitor and instance.monitor.close()
        workstation.kill()
        workstation.wait()
