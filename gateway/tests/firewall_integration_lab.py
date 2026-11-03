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
PORTS = (22, 80, 443, 3306, 5038, 5060, broker.ssh.API_PORT, 22002, 22004)


def run(*arguments, check=True):
    return subprocess.run(list(arguments), capture_output=True, text=True, check=check, env=ENV).stdout


def ipt(*arguments):
    return run(IPTABLES, "-w", "5", *arguments)


def freepbx(reload_order="normal"):
    """Simulated FreePBX Firewall/Fail2Ban reload: rebuilds only their own chains and INPUT hooks."""
    for line in ipt("-S", "INPUT").splitlines():
        if line.split()[-1] in ["fpbxfirewall", *BANS]:
            ipt("-D", "INPUT", *line.split()[2:])
    for chain in ("fpbxfirewall", "zone-external", *BANS):
        if run(IPTABLES, "-w", "5", "-S", chain, check=False):
            ipt("-F", chain)
        else:
            ipt("-N", chain)
    for chain in BANS:
        ipt("-A", chain, "-j", "RETURN")
    ipt("-A", "fpbxfirewall", "-i", "lo", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-i", "lan0", "-p", "udp", "-m", "multiport", "--dports", "5060,10000:10010", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-i", "lan0", "-p", "tcp", "-m", "multiport", "--dports", "22,443", "-j", "ACCEPT")
    ipt("-A", "fpbxfirewall", "-i", broker.WORKSTATION_IFACE, "-j", "zone-external")
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


def freepbx_snapshot():
    return [[line for line in ipt("-S", chain).splitlines()
             if broker.iptables_rule(shlex.split(line)[2:]) != broker.INTEGRATION_JUMP]
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


workstation = subprocess.Popen(["unshare", "--net", "sleep", "120"])
with tempfile.TemporaryDirectory(prefix=".firewall-lab-", dir=ROOT) as directory:
    broker.STATE = Path(directory)
    instance = broker.Broker()
    instance.audit = lambda *args: None
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
        for port in PORTS:
            listen(port)
            listen(port, socket.AF_INET6)
        for port in (5060, 10000):
            udp_echo(port)

        state = {"subnet": "100.70.1.0/24", "listen_port": 51821, "workstations": [
            {"id": "a" * 16, "name": "ssh", "public_key": "A" * 42 + "A=", "address": SSH_PEER + "/32", "mode": "persistent", "ssh": True},
            {"id": "b" * 16, "name": "web", "public_key": "B" * 42 + "A=", "address": WEB_PEER + "/32", "mode": "persistent", "ssh": False}]}
        instance.save_workstations(state)
        run("nft", "add", "table", "inet", "teliphones_lab_foreign")
        foreign = run("nft", "-j", "list", "table", "inet", "teliphones_lab_foreign")
        ip6_before = run(IP6TABLES, "-w", "5", "-S")
        instance.start_monitor()
        instance.mutate_policy(instance.expected_policy(state), None)

        # The nft table alone restricts web access by interface/destination; WireGuard AllowedIPs normally binds the
        # source. This veth has no cryptokey routing, so the unauthorised source is visible here.
        check(open_set(workstation) == {(source, port) for source in (SSH_PEER, WEB_PEER, STRANGER) for port in (80, 443)} | {(SSH_PEER, 22)},
              "baseline without FreePBX simulation should follow the nft policy only")
        freepbx()
        before = freepbx_snapshot()
        check(open_set(workstation) == set(), "reproduction: nft ACCEPT must not override the simulated FreePBX DROP")
        check_unrelated(workstation)

        instance.firewall_integration(state)
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

        expected_open = {(SSH_PEER, 80), (SSH_PEER, 443), (SSH_PEER, 22), (WEB_PEER, 80), (WEB_PEER, 443)}
        check(instance.integration["state"] == "active", instance.integration)
        check(open_set(workstation) == expected_open, "integration must open exactly authorised web/SSH flows")
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
        ipt("-I", "INPUT", str(len(BANS) + 1), *broker.iptables_arguments(broker.INTEGRATION_JUMP))
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
            check(instance.integration["state"] == "active" and len(jumps()) == 1, instance.integration)
            check(valid_order(), input_targets())
            check(open_set(workstation) == expected_open, "reconciliation did not restore exact access")
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
        check(open_set(workstation, (WEB_PEER,)) == set(), "Fail2Ban ban bypassed after hook reordering")
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
        check(open_set(workstation) == {(WEB_PEER, 80), (WEB_PEER, 443)}, "revoked peer retained access")

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
        print("PASS (%s): FreePBX DROP reproduced; exact per-peer 80/443 and approved-SSH access; SIP/AMI/DB/other peers/IPv6 blocked; "
              "observed fail2ban-* precedence and reordering; reload repair without duplicates; revocation; FreePBX/ip6tables/foreign preservation" % BACKEND)
    finally:
        instance.monitor and instance.monitor.close()
        workstation.kill()
        workstation.wait()
