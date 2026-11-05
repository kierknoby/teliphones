import importlib.util
import http.client
import json
import os
import shlex
import socket
import threading
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("support_broker", Path(__file__).resolve().parents[2] / "teliphones" / "support_broker.py")
broker_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker_module)


class SupportBrokerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name)
        self.patch = patch.object(broker_module, "STATE", self.state)
        self.patch.start()
        self.broker = broker_module.Broker()
        self.broker.audit = lambda *args: None
        self.broker.readiness = lambda: {"Gateway enrollment": True, "wg": True}
        self.calls = []

    def tearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    def run_work(self, request):
        self.broker.lock.acquire()
        self.broker.running = True
        self.broker.work(request, 1000)

    def test_allowlist_and_inputs(self):
        for request in ({"action": "exec"}, {"action": "revoke", "command": "whoami"},
                        {"action": []}, {"action": {}},
                        {"action": "authorise", "minutes": "60;id"},
                        {"action": "authorise", "minutes": "241"},
                        {"action": "evidence", "evidence": "[]"}):
            with self.assertRaises(broker_module.BrokerError):
                broker_module.validate(request)
        self.assertEqual(broker_module.validate({"action": "authorise", "minutes": "5"}), "authorise")

    def test_missing_dependency_blocks_authorisation(self):
        self.broker.readiness = lambda: {"Gateway enrollment": True, "wg": False}
        self.assertFalse(self.broker.status()["can_authorise"])
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "authorise", "minutes": "5"}, 1000)
        self.assertFalse(self.broker.lock.locked())

    def test_successful_connection_pipeline(self):
        self.broker.cli = lambda action, *args, **kwargs: self.calls.append(action)
        self.run_work({"action": "authorise", "minutes": "5"})
        self.assertEqual(self.calls, ["authorise", "provision", "connect-confirm", "attest", "checker-request"])
        self.assertNotIn("open", self.calls)
        self.assertFalse(self.broker.lock.locked())

    def test_failed_connection_revokes_and_quarantines(self):
        def cli(action, *args, **kwargs):
            self.calls.append(action)
            if action == "provision":
                raise broker_module.BrokerError("gateway unavailable")
        self.broker.cli = cli
        self.run_work({"action": "authorise", "minutes": "5"})
        self.assertEqual(self.calls[-1], "revoke")
        self.assertTrue((self.state / "quarantine.json").exists())
        self.assertFalse(self.broker.status()["can_authorise"])

    def test_signed_evidence_then_open(self):
        (self.state / "session.json").write_text(json.dumps({"state": "locally_verified", "expires_at": 9999999999}))
        self.broker.cli = lambda action, *args, **kwargs: self.calls.append((action, args))
        self.run_work({"action": "evidence", "evidence": '{"signature":"signed"}'})
        self.assertEqual([call[0] for call in self.calls], ["checker-accept", "open"])
        self.assertFalse((self.state / "web-checker-evidence.json").exists())

    def test_expired_session_does_not_open(self):
        (self.state / "session.json").write_text('{"state":"locally_verified","expires_at":1}')
        self.broker.cli = lambda action, *args, **kwargs: self.calls.append(action)
        self.run_work({"action": "evidence", "evidence": "{}"})
        self.assertNotIn("open", self.calls)
        self.assertIn("revoke", self.calls)

    def test_cleanup_failure_keeps_quarantine_and_is_retryable(self):
        self.broker.cli = lambda *args, **kwargs: (_ for _ in ()).throw(broker_module.BrokerError("cleanup failed"))
        self.broker.cleanup(1000)
        self.assertTrue((self.state / "quarantine.json").exists())
        self.broker.cli = lambda *args, **kwargs: None
        self.broker.cleanup(1000)
        self.assertTrue((self.state / "quarantine.json").exists())

    def test_revocation_cancels_and_blocks_new_jobs(self):
        self.broker.lock.acquire()
        try:
            response = self.broker.dispatch({"action": "revoke"}, 1000)
            self.assertTrue(response["ok"])
            self.assertTrue(self.broker.cancel.is_set())
            self.assertTrue(self.broker.revoking)
            self.assertFalse(self.broker.status()["can_authorise"])
        finally:
            self.broker.cli = lambda *args, **kwargs: None
            self.broker.lock.release()
        # Wait for the bounded mock revocation without polling the real service.
        with self.broker.lock:
            pass

    def test_missing_and_invalid_state(self):
        self.assertEqual(broker_module.read_json(self.state / "missing"), {})
        (self.state / "session.json").write_text("broken")
        with self.assertRaises(broker_module.BrokerError):
            self.broker.status()

    def test_expired_ready_session_never_reports_connected(self):
        (self.state / "session.json").write_text('{"state":"ready","expires_at":1}')
        result = self.broker.status()
        self.assertFalse(result["access_verified"])
        self.assertIn("expired", result["phase"])

    def test_ready_session_requires_adapter_and_checker_state(self):
        (self.state / "session.json").write_text('{"state":"ready","session_id":"session","expires_at":9999999999}')
        self.assertFalse(self.broker.status()["access_verified"])
        (self.state / "adapter.json").write_text('{"session_id":"session","support_ready":true}')
        (self.state / "checker.json").write_text('{"session_id":"session","accepted":true}')
        self.assertTrue(self.broker.status()["access_verified"])

    def test_fixed_dependency_command_requires_explicit_action(self):
        self.broker.command = lambda arguments, **kwargs: self.calls.append(arguments)
        self.broker.readiness = lambda: {"Gateway enrollment": True, "WireGuard wg": bool(self.calls)}
        self.run_work({"action": "dependencies"})
        self.assertEqual(self.calls, [["/usr/bin/apt-get", "-y", "--no-install-recommends", "install", "wireguard-tools"]])

    def wait_for_operation(self):
        # Mocked operations are bounded; acquiring the lock waits for the worker thread to finish.
        with self.broker.lock:
            pass
        for _ in range(100):
            if self.broker.operation["state"] != "running":
                return self.broker.operation
            broker_module.time.sleep(0.01)
        self.fail("operation did not finish")

    def test_started_operation_is_reported_running_then_verified_success(self):
        release = broker_module.threading.Event()
        stages = []
        def command(arguments, **kwargs):
            stages.append(self.broker.status()["operation"]["stage"])
            release.wait(2)
            self.calls.append(arguments)
        self.broker.command = command
        self.broker.readiness = lambda: {"Gateway enrollment": True, "WireGuard wg": bool(self.calls)}
        response = self.broker.dispatch({"action": "dependencies"}, 1000)
        self.assertTrue(response["ok"])
        self.assertEqual(response["message"], "TELIPHONES operation started. Monitoring progress automatically…")
        self.assertNotIn("Refresh", response["message"])
        operation = self.broker.status()["operation"]
        self.assertEqual((operation["id"], operation["action"], operation["state"]), (response["operation_id"], "dependencies", "running"))
        self.assertIsNone(operation["finished_at"])
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "configure"}, 1000)
        release.set()
        operation = self.wait_for_operation()
        self.assertEqual(stages, ["Installing WireGuard tools"])
        self.assertEqual(operation["state"], "succeeded")
        self.assertIn("verified", operation["message"])
        self.assertIsInstance(self.broker.status()["server_time"], int)

    def test_dependency_success_requires_verified_wg(self):
        self.broker.command = lambda arguments, **kwargs: self.calls.append(arguments)
        self.broker.readiness = lambda: {"Gateway enrollment": True, "WireGuard wg": False}
        self.broker.dispatch({"action": "dependencies"}, 1000)
        operation = self.wait_for_operation()
        self.assertEqual(operation["state"], "failed")
        self.assertIn("could not be verified", operation["message"])

    def test_failed_dependency_installation_is_reported_and_retryable(self):
        def command(arguments, **kwargs):
            raise broker_module.BrokerError("TELIPHONES operation failed: install.")
        self.broker.command = command
        self.broker.readiness = lambda: {"Gateway enrollment": True, "WireGuard wg": False}
        self.broker.dispatch({"action": "dependencies"}, 1000)
        operation = self.wait_for_operation()
        self.assertEqual((operation["state"], operation["message"]), ("failed", "TELIPHONES operation failed: install."))
        self.assertFalse(self.broker.lock.locked())
        self.assertFalse((self.state / "quarantine.json").exists())
        self.assertTrue(self.broker.dispatch({"action": "dependencies"}, 1000)["ok"])
        self.wait_for_operation()

    def test_installed_dependency_is_not_reinstalled(self):
        self.broker.readiness = lambda: {"Gateway enrollment": True, "WireGuard wg": True}
        self.broker.command = lambda arguments, **kwargs: self.calls.append(arguments)
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "dependencies"}, 1000)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.broker.lock.locked())
        self.assertIsNone(self.broker.status()["operation"])

    def test_connection_stages_and_failure_cleanup_are_reported(self):
        stages = []
        def cli(action, *args, **kwargs):
            stages.append(self.broker.operation["stage"])
            self.calls.append(action)
            if action == "connect-confirm":
                raise broker_module.BrokerError("handshake failed")
        self.broker.cli = cli
        self.broker.cancel.set()  # stop the bounded connect-confirm retry immediately
        operation_id = self.broker.begin("authorise", "Authorising remote support")
        self.broker.lock.acquire()
        self.broker.running = True
        self.broker.work({"action": "authorise", "minutes": "5"}, 1000, operation_id)
        self.assertEqual(stages, ["Authorising remote support", "Provisioning WireGuard connection",
                                  "Establishing WireGuard connection", "Cleaning up after failure"])
        self.assertEqual(self.broker.operation["state"], "failed")
        self.assertEqual(self.broker.operation["message"], "handshake failed")
        self.assertTrue((self.state / "quarantine.json").exists())

    def test_cleanup_failure_is_included_in_operation_failure(self):
        def cli(action, *args, **kwargs):
            raise broker_module.BrokerError("revoke failed" if action == "revoke" else "authorise failed")
        self.broker.cli = cli
        operation_id = self.broker.begin("authorise", "Authorising remote support")
        self.broker.lock.acquire()
        self.broker.running = True
        self.broker.work({"action": "authorise", "minutes": "5"}, 1000, operation_id)
        self.assertEqual(self.broker.operation["message"], "authorise failed Cleanup also failed: revoke failed")

    def test_revocation_is_monitored_and_supersedes_interrupted_operation(self):
        self.broker.cli = lambda *args, **kwargs: self.calls.append(args[0])
        interrupted = self.broker.begin("authorise", "Authorising remote support")
        self.broker.lock.acquire()
        self.broker.running = True
        response = self.broker.dispatch({"action": "revoke"}, 1000)
        self.assertEqual(response["message"], "Revocation started. Monitoring progress automatically…")
        self.assertEqual(self.broker.status()["operation"]["stage"], "Cancelling the running operation")
        self.broker.finish(interrupted, False, "Operation interrupted")
        self.assertEqual(self.broker.operation["state"], "running")
        self.broker.running = False
        self.broker.lock.release()
        operation = self.wait_for_operation()
        self.assertEqual((operation["id"], operation["action"], operation["state"]), (response["operation_id"], "revoke", "succeeded"))
        self.assertIn("revoke", self.calls)

    def test_failed_revocation_is_not_reported_successful(self):
        self.broker.cli = lambda *args, **kwargs: (_ for _ in ()).throw(broker_module.BrokerError("cleanup failed"))
        self.broker.dispatch({"action": "revoke"}, 1000)
        operation = self.wait_for_operation()
        self.assertEqual(operation["state"], "failed")
        self.assertIn("cleanup failed", operation["message"])
        self.assertTrue((self.state / "quarantine.json").exists())

    def test_status_reports_live_monitoring_protocol_matching_gui(self):
        status = self.broker.status()
        self.assertEqual(status["component_version"], "0.6.1")
        self.assertEqual(status["protocol"], 12)
        self.assertEqual(status["protocol"], broker_module.PROTOCOL)
        self.assertIn("operation", status)
        self.assertIsInstance(status["server_time"], int)
        web_support = (Path(broker_module.__file__).parent / "WebSupport.php").read_text()
        self.assertIn("public const DIAGNOSTICS_PROTOCOL = 4;", web_support)
        self.assertIn("public const SSH_PROTOCOL = 5;", web_support)
        self.assertIn("public const POLICY_PROTOCOL = 8;", web_support)
        self.assertIn("public const LOCKED_SSH_PROTOCOL = 9;", web_support)
        self.assertIn("public const BAN_PROTOCOL = 10;", web_support)
        self.assertIn("public const SESSION_PROTOCOL = 11;", web_support)
        self.assertIn("public const WORKSTATION_MANAGEMENT_PROTOCOL = %d;" % broker_module.PROTOCOL, web_support)

    def test_status_never_starts_an_operation(self):
        self.broker.command = lambda arguments, **kwargs: self.calls.append(arguments)
        self.broker.cli = lambda *args, **kwargs: self.calls.append(args)
        for _ in range(3):
            self.assertTrue(self.broker.dispatch({"action": "status"}, 1000)["ok"])
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.broker.operation)
        self.assertFalse(self.broker.lock.locked())

    def test_socket_rejects_other_service_accounts(self):
        self.assertTrue(broker_module.permitted_peer(1000, 1000))
        self.assertFalse(broker_module.permitted_peer(1001, 1000))
        self.assertFalse(broker_module.permitted_peer(0, 1000))
        self.assertFalse(broker_module.permitted_peer(0, 0))

    def test_interruption_terminates_child_before_cleanup(self):
        class Process:
            pid = 123
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0
        self.broker.cancel.set()
        with patch.object(broker_module.subprocess, "Popen", return_value=Process()), patch.object(broker_module.os, "killpg") as kill:
            with self.assertRaises(broker_module.BrokerError):
                self.broker.command(["/usr/sbin/fwconsole", "teliphones", "provision"])
            kill.assert_called_once_with(123, broker_module.signal.SIGTERM)

    def test_existing_active_session_refuses_second_authorisation(self):
        (self.state / "session.json").write_text('{"state":"authorised","expires_at":9999999999}')
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "authorise", "minutes": "5"}, 1000)
        self.assertFalse(self.broker.lock.locked())

    def test_enrollment_rejects_insecure_or_command_shaped_urls(self):
        request = {"action": "configure", "url": "http://gateway.test",
                   "certificate": "cert", "private_key": "key", "ca": "ca", "checker_key": "checker"}
        with self.assertRaises(broker_module.BrokerError):
            broker_module.validate(request)
        request["url"] = 'https://gateway.test"\nCOMMAND=id'
        with self.assertRaises(broker_module.BrokerError):
            broker_module.validate(request)


if __name__ == "__main__":
    unittest.main()


def pair_request(public_key="A" * 42 + "E=", name="ADMIN-PC (alice)", nonce="n" * 22, **extra):
    body = {"schema": "teliphones-pair-request/1", "workstation": name, "public_key": public_key, "nonce": nonce, **extra}
    return broker_module.PAIR_REQUEST_PREFIX + broker_module.b64url_encode(json.dumps(body).encode())


def decode_response(code):
    prefix = broker_module.PAIR_RESPONSE_V2 if code.startswith(broker_module.PAIR_RESPONSE_V2) else broker_module.PAIR_RESPONSE_PREFIX
    assert code.startswith(prefix)
    return json.loads(broker_module.b64url_decode(code[len(prefix):]))


# Fail2Ban INPUT chains observed on the FreePBX 17 test installation.
FREEPBX17_FAIL2BAN = ["fail2ban-sshd", "fail2ban-SIP", "fail2ban-BadBots", "fail2ban-api",
                      "fail2ban-SSH", "fail2ban-apache-auth", "fail2ban-recidive", "fail2ban-PBX-GUI"]


def fail2ban_hook(name):
    """iptables -S shape of a Fail2Ban INPUT hook (port-limited jails use multiport, others are all-ports)."""
    ports = {"fail2ban-sshd": "22", "fail2ban-SSH": "22", "fail2ban-apache-auth": "80,443",
             "fail2ban-BadBots": "80,443", "fail2ban-PBX-GUI": "80,443"}
    if name in ports:
        return ["-p", "tcp", "-m", "multiport", "--dports", ports[name], "-j", name]
    return ["-j", name]


class FakeNetwork:
    """Stateful stand-in for ip/wg/nft. Records every command; real kernel behaviour is not exercised."""

    def __init__(self):
        self.calls = []
        self.devices = {}
        self.ruleset = None
        self.fail = None
        self.handshakes = {}
        self.endpoints = {}
        self.table = None
        self.process = None
        self.silent = False
        self.next_handle = 1
        # Simulated iptables filter table (None: no iptables). Rule token lists use iptables -S syntax.
        self.filter = None

    @property
    def link(self):
        return broker_module.WORKSTATION_IFACE in self.devices

    @link.setter
    def link(self, value):
        if value:
            self.devices.setdefault(broker_module.WORKSTATION_IFACE, {"up": False, "peers": {}})
        else:
            self.devices.pop(broker_module.WORKSTATION_IFACE, None)

    @property
    def up(self):
        return self.devices.get(broker_module.WORKSTATION_IFACE, {}).get("up", False)

    @up.setter
    def up(self, value):
        if self.link:
            self.devices[broker_module.WORKSTATION_IFACE]["up"] = value

    @property
    def peers(self):
        return self.devices.get(broker_module.WORKSTATION_IFACE, {}).get("peers", {})

    def freepbx(self, fail2ban=None):
        """FreePBX Firewall-shaped hooks only; not the FreePBX implementation. Default Fail2Ban hooks are the
        INPUT chain names observed on the FreePBX 17 test installation."""
        fail2ban = FREEPBX17_FAIL2BAN if fail2ban is None else fail2ban
        self.filter = {"INPUT": [fail2ban_hook(name) for name in fail2ban] + [["-j", "fpbxfirewall"]], "FORWARD": [], "OUTPUT": [],
                       "fpbxfirewall": [["-i", "lo", "-j", "ACCEPT"], ["-j", "DROP"]]}
        self.filter.update({name: [["-j", "RETURN"]] for name in fail2ban})
        return self

    def iptables(self, rest):
        if rest == ["--version"]:
            return "iptables v1.8.9 (nf_tables)\n"
        assert rest[:2] == ["-w", "5"], rest
        table, operation, chain, rule = self.filter, rest[2], (rest[3] if len(rest) > 3 else None), rest[4:]
        if operation == "-S":
            return "\n".join(["-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT"]
                             + ["-N " + name for name in table if name not in ("INPUT", "FORWARD", "OUTPUT")]
                             + ["-A %s %s" % (name, shlex.join(item)) for name in table for item in table[name]]) + "\n"
        failed = broker_module.BrokerError("Workstation network operation failed: iptables")
        if operation == "-N":
            if chain in table:
                raise failed
            table[chain] = []
        elif operation == "-F":
            table[chain] = []
        elif operation == "-X":
            if table.get(chain) or any(chain in item for rules in table.values() for item in rules):
                raise failed
            table.pop(chain)
        elif operation == "-A":
            table[chain].append(rule)
        elif operation == "-I":
            table[chain].insert(int(rule[0]) - 1, rule[1:])
        elif operation == "-D":
            if rule not in table[chain]:
                raise failed
            table[chain].remove(rule)
        return ""

    def emit(self, events):
        if self.process and self.process.poll() is None and not self.silent:
            self.process.writer.write(json.dumps({"nftables": events}) + "\n")
            self.process.writer.flush()

    def run(self, arguments, stdin=None, check=True, stream=False):
        name, rest = arguments[0], arguments[1:]
        self.calls.append((name, tuple(rest)))
        if self.fail and self.fail(name, rest):
            if check:
                raise broker_module.BrokerError("Workstation network operation failed: " + name)
            return None
        if stream:
            self.process = FakeMonitorProcess()
            return self.process
        if name == "iptables":
            return self.iptables(list(rest))
        if name == "ip" and rest == ["-j", "link", "show"]:
            return json.dumps([{"ifname": interface, "flags": ["UP"] if device["up"] else []}
                               for interface, device in self.devices.items()])
        if name == "ip" and rest[:2] == ["link", "show"]:
            interface = rest[-1]
            return "" if interface in self.devices else None
        if name == "ip" and rest[:2] == ["link", "add"]:
            interface = rest[rest.index("dev") + 1]
            self.devices[interface] = {"up": False, "peers": {}}
        if name == "ip" and rest[:2] == ["link", "del"]:
            interface = rest[rest.index("dev") + 1]
            self.devices.pop(interface, None)
        if name == "ip" and rest[:2] == ["link", "set"]:
            interface = rest[rest.index("dev") + 1]
            if interface in self.devices:
                self.devices[interface]["up"] = "up" in rest
        if name == "ip" and rest[:2] == ["-4", "-o"]:
            return "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        if name == "ip" and rest[:2] == ["-4", "route"]:
            return "default via 192.168.1.1 dev eth0\n192.168.1.0/24 dev eth0 proto kernel\n"
        if name == "wg" and rest == ["genkey"]:
            return "k" * 43 + "=\n"
        if name == "wg" and rest == ["pubkey"]:
            return "P" * 42 + "A=\n"
        if name == "wg" and rest[0] == "show":
            interface = rest[1]
            peers = self.devices.get(interface, {}).get("peers", {})
            if rest[2] == "peers":
                return "\n".join(peers)
            if rest[2] == "latest-handshakes":
                return "\n".join("%s\t%d" % (key, self.handshakes.get(key, 0)) for key in peers)
            if rest[2] == "endpoints":
                return "\n".join("%s\t%s" % (key, self.endpoints.get(key, "(none)")) for key in peers)
            if rest[2] == "transfer":
                return "\n".join("%s\t0\t0" % key for key in peers)
        if name == "wg" and rest[:1] == ["set"] and "peer" in rest:
            interface = rest[1]
            peers = self.devices.setdefault(interface, {"up": False, "peers": {}})["peers"]
            key = rest[rest.index("peer") + 1]
            if "remove" in rest:
                peers.pop(key, None)
            else:
                peers[key] = rest[rest.index("allowed-ips") + 1]
        if name == "nft" and rest == ["-j", "-f", "-"]:
            commands = json.loads(stdin)["nftables"]
            notifications = []
            for command in commands:
                action, entry = next(iter(command.items()))
                kind, value = next(iter(entry.items()))
                if action == "delete":
                    if self.table:
                        notifications.append({"delete": {"table": self.table["nftables"][0]["table"]}})
                    self.table, self.ruleset = None, None
                else:
                    if kind == "table":
                        self.table = {"nftables": []}
                    value = {**value, "handle": self.next_handle}
                    self.next_handle += 1
                    self.table["nftables"].append({kind: value})
                    notifications.append({"add": {kind: value}})
            if self.table:
                rules = [entry["rule"] for entry in self.table["nftables"] if "rule" in entry]
                shared_rule = next((entry for entry in rules if entry["chain"] == "input"
                                    and any(expr.get("match", {}).get("right") == broker_module.WORKSTATION_IFACE
                                            for expr in entry["expr"])), None)
                if shared_rule is None:
                    shared_rule = next(entry for entry in rules if entry["chain"] == "input"
                                       and any(expr.get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "daddr"}}
                                               for expr in entry["expr"]))
                pbx = next(expr["match"]["right"] for expr in shared_rule["expr"]
                           if expr.get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "daddr"}})
                sources = [entry["expr"][1]["match"]["right"] for entry in rules
                           if any(expr.get("match", {}).get("right") == 22 for expr in entry["expr"])]

                def matched(rule, protocol, field):
                    return [expr["match"]["right"] for expr in rule.get("expr", []) if "match" in expr
                            and expr["match"].get("left") == {"payload": {"protocol": protocol, "field": field}}]
                web_ports = [matched(rule, "tcp", "dport")[0] for rule in rules
                             if rule["chain"] == "input" and {"accept": None} in rule["expr"]
                             and matched(rule, "tcp", "dport") and matched(rule, "ip", "saddr")
                             and matched(rule, "tcp", "dport")[0] not in (
                                 22, broker_module.SESSION_CONTROL_PORT, broker_module.ssh.API_PORT)
                             and not 22000 <= matched(rule, "tcp", "dport")[0] <= 22999]
                self.ruleset = broker_module.workstation_ruleset(pbx, sources, sorted(set(web_ports)))
            self.emit(notifications)
        if name == "nft" and rest == ["-j", "list", "tables"]:
            return json.dumps({"nftables": [entry for entry in self.table["nftables"] if "table" in entry] if self.table else []})
        if name == "nft" and rest == ["-j", "list", "table", "inet", broker_module.WORKSTATION_TABLE]:
            return json.dumps(self.table)
        return ""


class FakeMonitorProcess:
    def __init__(self):
        read, write = os.pipe()
        self.stdout = os.fdopen(read)
        self.writer = os.fdopen(write, "w")
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0
        self.writer.close()

    def wait(self, timeout=None):
        return self.returncode


class WorkstationPairingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name) / "state"
        self.enrollment = Path(self.directory.name) / "etc"
        self.state.mkdir()
        self.patches = [patch.object(broker_module, "STATE", self.state), patch.object(broker_module, "ENROLLMENT", self.enrollment)]
        for item in self.patches:
            item.start()
        self.broker = broker_module.Broker()
        self.broker.audit = lambda *args: None
        self.broker.readiness = lambda: {"Gateway enrollment": True, "wg": True}
        self.net = FakeNetwork()
        self.broker.run = self.net.run
        self.broker.tool = lambda name: name
        self.broker.iptables_tool = lambda: "iptables" if self.net.filter is not None else None
        self.ssh_reconcile = patch.object(self.broker.ssh, "reconcile")
        self.ssh_reconcile.start()
        self.broker.save_workstations({"subnet": None, "listen_port": None, "web": broker_module.DEFAULT_WEB,
                                       "connection_state": "open", "workstations": []})

    def tearDown(self):
        if self.broker.monitor:
            self.broker.monitor.close()
        for item in self.patches:
            item.stop()
        self.ssh_reconcile.stop()
        self.directory.cleanup()

    def pair(self, mode="persistent", ssh="0", minutes="60", port="51821", web=None, sources=None, **request_options):
        if not (self.state / "workstations.json").exists():
            self.broker.save_workstations({"subnet": None, "listen_port": None, "web": broker_module.DEFAULT_WEB,
                                           "connection_state": "open", "workstations": []})
        pairing_request = pair_request(**request_options)
        if ssh == "1":
            pairing = broker_module.parse_pair_request(pairing_request)
            pairing.update(schema="teliphones-pair-request/2",
                           ssh_public_key="ssh-ed25519 " + base64.b64encode(
                               b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode())
            pairing_request = broker_module.PAIR_REQUEST_V2 + broker_module.b64url_encode(json.dumps(pairing).encode())
        request = {"action": "pair", "request": pairing_request, "endpoint_host": "pbx.example.net",
                   "listen_port": port, "mode": mode, "minutes": minutes, "ssh": ssh}
        if web is not None:
            request["web"] = web
        if sources is not None:
            request["sources"] = sources
        if ssh == "1":
            request["ssh_user"] = "root"
            ssh_public = "ssh-ed25519 " + base64.b64encode(
                b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
            with patch.object(self.broker.ssh, "initialise", return_value=ssh_public), \
                    patch.object(self.broker.ssh, "host_key", return_value=ssh_public), \
                    patch.object(self.broker.ssh, "account_policy", return_value={}), \
                    patch.object(self.broker.ssh, "reconcile"):
                result = self.broker.dispatch(request, 1000)
        else:
            result = self.broker.dispatch(request, 1000)
        return result, decode_response(result["pairing_response"])

    def open_session(self, response):
        state, _ = self.broker.workstation_state()
        item = next(entry for entry in state["workstations"] if entry["id"] == response["workstation_id"])
        ssh_key = "ssh-ed25519 " + base64.b64encode(
            b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
        with patch.object(self.broker.ssh, "host_key", return_value=ssh_key), \
                patch.object(self.broker.ssh, "initialise", return_value=ssh_key):
            return self.broker.workstation_session("heartbeat", item["address"].split("/")[0])

    def test_pairing_inputs_are_strictly_validated(self):
        good = {"action": "pair", "request": pair_request(), "endpoint_host": "pbx.example.net", "listen_port": "51821",
                "mode": "temporary", "minutes": "60", "ssh": "0"}
        self.assertEqual(broker_module.validate(good), "pair")
        self.assertEqual(broker_module.validate({**good, "mode": "persistent", "minutes": "0"}), "pair")
        for change in ({"request": "TELIPHONES-PAIR-REQUEST-1:!!"}, {"request": pair_request(extra="x")},
                       {"request": pair_request(public_key="not-a-key")}, {"request": pair_request(public_key="A" * 43 + "=")},
                       {"request": pair_request(name="<script>")}, {"request": pair_request(nonce="short")},
                       {"endpoint_host": "pbx.example.net;id"}, {"endpoint_host": "127.0.0.1"}, {"endpoint_host": "1.2.3"},
                       {"listen_port": "80"}, {"listen_port": "70000"}, {"mode": "forever"}, {"ssh": "yes"},
                       {"minutes": "5"}, {"minutes": "1441"}, {"command": "id"}):
            with self.assertRaises(broker_module.BrokerError, msg=str(change)):
                broker_module.validate({**good, **change})
        for workstation_id in ("all", "0123456789abcdef"):
            self.assertEqual(broker_module.validate({"action": "unpair", "workstation_id": workstation_id}), "unpair")
        for workstation_id in ("ALL", "0123", "../x", 1):
            with self.assertRaises(broker_module.BrokerError):
                broker_module.validate({"action": "unpair", "workstation_id": workstation_id})

    def test_locked_source_validation_and_dns_failure_fail_closed(self):
        self.assertEqual(broker_module.parse_source_restrictions("198.51.100.7, 2001:db8::1/128, PBX.Example.NET."),
                         ["198.51.100.7/32", "2001:db8::1/128", "pbx.example.net"])
        self.assertEqual(broker_module.parse_wireguard_endpoint("198.51.100.24:51821"),
                         {"address": "198.51.100.24", "port": 51821})
        self.assertEqual(broker_module.parse_wireguard_endpoint("[2001:db8::24]:51821"),
                         {"address": "2001:db8::24", "port": 51821})
        for value in ("(none)", "example.net:51821", "2001:db8::24:51821", "198.51.100.24:0", "[::1]:65536"):
            self.assertIsNone(broker_module.parse_wireguard_endpoint(value))

        def resolver(host, *args):
            if host == "good.example.net":
                return [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("203.0.113.12", 0))]
            raise OSError("DNS unavailable")

        resolved, failed = broker_module.resolve_source_restrictions(
            ["203.0.113.0/24", "good.example.net", "lost.example.net"], resolver)
        self.assertEqual(resolved, ["203.0.113.0/24", "203.0.113.12/32"])
        self.assertEqual(failed, ["lost.example.net"])
        with self.assertRaises(broker_module.BrokerError):
            broker_module.parse_source_restrictions("0.0.0.0/0")

    def test_locked_domain_refresh_replaces_expired_addresses_and_fails_closed(self):
        cache, calls = {}, []
        current = ["203.0.113.12"]
        def resolver(host, *args):
            calls.append(host)
            if not current:
                raise OSError("DNS unavailable")
            return [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", (address, 0)) for address in current]

        first, _ = broker_module.resolve_source_restrictions(
            ["pbx.example.net"], resolver, cache, now=100)
        cached, _ = broker_module.resolve_source_restrictions(
            ["pbx.example.net"], resolver, cache, now=399)
        self.assertEqual(first, ["203.0.113.12/32"])
        self.assertEqual(cached, first)
        self.assertEqual(calls, ["pbx.example.net"])

        current[:] = ["198.51.100.23"]
        refreshed, _ = broker_module.resolve_source_restrictions(
            ["pbx.example.net"], resolver, cache, now=401)
        self.assertEqual(refreshed, ["198.51.100.23/32"])
        current.clear()
        failed, unresolved = broker_module.resolve_source_restrictions(
            ["pbx.example.net"], resolver, cache, now=702)
        self.assertEqual((failed, unresolved), ([], ["pbx.example.net"]))

    def test_locked_pair_uses_dedicated_interface_port_and_authenticated_peer(self):
        _, response = self.pair(sources="198.51.100.24")
        state = broker_module.read_json(self.state / "workstations.json")
        item = state["workstations"][0]
        interface = self.broker.locked_interface(item)
        self.assertTrue(item["locked"])
        self.assertNotEqual(response["endpoint"].rsplit(":", 1)[1], "51821")
        self.assertEqual(response["endpoint"].rsplit(":", 1)[1], str(item["listener_port"]))
        self.assertEqual(response["address"], item["address"])
        self.assertEqual(response["pbx_address"], item["pbx_address"])
        self.assertNotIn(item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])
        self.assertEqual(self.net.devices[interface]["peers"], {item["public_key"]: item["address"]})
        rules = [entry["rule"] for entry in self.net.table["nftables"] if "rule" in entry]
        source_rule = next(rule for rule in rules if rule["chain"] == "input"
                           and any(expr.get("match", {}).get("right") == "198.51.100.24"
                                   for expr in rule["expr"]))
        blocked_rule = next(rule for rule in rules if rule["chain"] == "input"
                            and {"drop": None} in rule["expr"]
                            and any(expr.get("match", {}).get("right") == item["listener_port"]
                                    for expr in rule["expr"]))
        self.assertEqual(source_rule["expr"][-1], {"accept": None})
        self.assertEqual(blocked_rule["expr"][-1], {"drop": None})

    def test_pairing_another_workstation_does_not_take_existing_listener_down(self):
        _, first = self.pair()
        first_id = first["workstation_id"]
        first_key = next(item["public_key"] for item in self.broker.workstation_state()[0]["workstations"]
                         if item["id"] == first_id)
        self.net.calls = []
        self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        self.assertTrue(self.net.devices[broker_module.WORKSTATION_IFACE]["up"])
        self.assertIn(first_key, self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])
        self.assertFalse(any(name == "ip" and rest[:3] == ("link", "set", "down")
                             for name, rest in self.net.calls))

    def test_post_pair_lock_to_current_uses_recent_authenticated_endpoint(self):
        _, response = self.pair()
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.net.handshakes[item["public_key"]] = int(broker_module.time.time())
        self.net.endpoints[item["public_key"]] = "[2001:db8::24]:51821"
        result = self.broker.dispatch({"action": "workstation-manage", "workstation_id": item["id"],
                                       "state": "lock", "sources": "current"}, 1000)
        managed, _ = self.broker.workstation_state()
        locked = managed["workstations"][0]
        self.assertEqual(result["workstation"]["id"], item["id"])
        self.assertTrue(locked["locked"])
        self.assertEqual(locked["sources"], ["2001:db8::24/128"])
        self.assertEqual(locked["public_key"], item["public_key"])
        self.assertIn(item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])
        self.assertTrue(locked["migration"]["locked"] is False)
        migration = self.broker.workstation_session(
            "heartbeat", response["address"].split("/")[0], response["pbx_address"])
        self.assertFalse(migration["active"])
        self.broker.workstation_session(
            "heartbeat", locked["address"].split("/")[0], locked["pbx_address"])
        self.assertNotIn(item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])
        self.assertTrue(self.net.devices[self.broker.locked_interface(locked)]["up"])
        self.assertTrue(self.net.devices[broker_module.WORKSTATION_IFACE]["up"])

    def test_authenticated_workstation_can_self_restrict_to_its_verified_public_source(self):
        _, response = self.pair()
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.net.handshakes[item["public_key"]] = int(broker_module.time.time())
        self.net.endpoints[item["public_key"]] = "198.51.100.24:53123"
        result = self.broker.workstation_session(
            "lock-current", item["address"].split("/")[0],
            str(broker_module.ipaddress.IPv4Network(state["subnet"])[1]))
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertEqual(result["workstation_change_status"], "applied")
        self.assertTrue(item["locked"])
        self.assertEqual(item["sources"], ["198.51.100.24/32"])
        self.assertEqual(self.broker.active_sessions(), {})

    def test_post_pair_source_update_and_unlock_preserve_identity(self):
        _, response = self.pair(sources="198.51.100.24")
        original_key = response["workstation_public_key"]
        workstation_id = response["workstation_id"]
        updated = self.broker.dispatch({"action": "workstation-manage", "workstation_id": workstation_id,
                                        "state": "lock", "sources": "2001:db8::24/64, office.example.net"}, 1000)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertEqual(item["public_key"], original_key)
        self.assertEqual(updated["workstation"]["sources"], ["2001:db8::/64", "office.example.net"])
        with patch.object(self.broker, "apply_workstations", wraps=self.broker.apply_workstations) as apply:
            result = self.broker.dispatch({"action": "workstation-manage", "workstation_id": workstation_id,
                                           "state": "unlock", "sources": ""}, 1000)
            self.assertTrue(apply.call_args.kwargs["preserve_unrelated"])
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertFalse(item["locked"])
        self.assertEqual(item["public_key"], original_key)
        self.assertNotIn("sources", item)
        self.assertNotIn("listener_port", item)
        self.assertEqual(result["workstation"]["id"], workstation_id)
        self.assertTrue(self.net.devices[broker_module.WORKSTATION_IFACE]["up"])

    def test_listener_migration_is_control_only_until_same_identity_acknowledges(self):
        self.broker.configure_workstation_limit({"maximum": "2"}, 1000)
        _, first = self.pair(public_key="A" * 42 + "E=", nonce="a" * 22)
        _, unrelated = self.pair(public_key="B" * 42 + "E=", nonce="b" * 22)
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        unrelated_item = next(item for item in state["workstations"] if item["id"] == unrelated["workstation_id"])
        original_source = first_item["address"].split("/")[0]
        original_pbx = str(broker_module.ipaddress.IPv4Network(state["subnet"])[1])
        self.open_session(first)
        self.open_session(unrelated)
        original_key = first_item["public_key"]

        self.broker.dispatch({"action": "workstation-manage", "workstation_id": first_item["id"],
                              "state": "lock", "sources": "198.51.100.24"}, 1000)
        self.broker.restore_workstations()
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        offer = self.broker.workstation_session("heartbeat", original_source, original_pbx)
        self.assertFalse(offer["active"])
        self.assertEqual(offer["migration"]["workstation_id"], first_item["id"])
        self.assertEqual(offer["migration"]["workstation_public_key"], original_key)
        self.assertEqual(set(self.broker.active_sessions()), {unrelated_item["id"]})
        rules = [entry["rule"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry]
        self.assertFalse(any(rule["expr"][-1] == {"accept": None}
                             and any(expr.get("match", {}).get("right") in (80, 443) for expr in rule["expr"])
                             and any(expr.get("match", {}).get("right") == original_source for expr in rule["expr"])
                             for rule in rules))
        control_rules = broker_module.integration_rules(
            original_pbx, state["workstations"], migration_controls=[{
                "address": original_source + "/32",
                "pbx_address": original_pbx,
                "interface": broker_module.WORKSTATION_IFACE,
            }])
        self.assertTrue(any(rule.get("dport") == str(broker_module.SESSION_CONTROL_PORT)
                            and rule.get("s") == original_source + "/32" for rule in control_rules))
        locked_source = first_item["address"].split("/")[0]
        self.broker.workstation_session("heartbeat", locked_source, first_item["pbx_address"])
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        self.assertNotIn("migration", first_item)
        self.assertEqual(first_item["public_key"], original_key)
        self.assertIn(unrelated_item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])
        self.assertEqual(set(self.broker.active_sessions()), {first_item["id"], unrelated_item["id"]})

        old_locked_address = first_item["address"].split("/")[0]
        old_locked_pbx = first_item["pbx_address"]
        self.broker.dispatch({"action": "workstation-manage", "workstation_id": first_item["id"],
                              "state": "unlock", "sources": ""}, 1000)
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        offer = self.broker.workstation_session("heartbeat", old_locked_address, old_locked_pbx)
        self.assertFalse(offer["active"])
        self.assertEqual(offer["migration"]["workstation_public_key"], original_key)
        self.broker.workstation_session("heartbeat", first_item["address"].split("/")[0], first_item["pbx_address"])
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        self.assertNotIn("migration", first_item)
        self.assertNotIn(self.broker.locked_interface(first_item), self.net.devices)
        self.assertIn(unrelated_item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])

    def test_post_pair_ssh_elevation_requires_admission_and_explicit_admin_decision(self):
        _, response = self.pair()
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        request_key = "ssh-ed25519 " + base64.b64encode(
            b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
        with self.assertRaisesRegex(broker_module.BrokerError, "admitted administrative session"):
            self.broker.workstation_session("ssh-request", item["address"].split("/")[0],
                                            str(broker_module.ipaddress.IPv4Network(state["subnet"])[1]), request_key)
        self.open_session(response)
        pending = self.broker.workstation_session("ssh-request", item["address"].split("/")[0],
                                                  str(broker_module.ipaddress.IPv4Network(state["subnet"])[1]), request_key)
        self.assertEqual(pending["ssh_request_status"], "pending")
        status = self.broker.workstation_status()
        self.assertTrue(status["items"][0]["ssh_request_pending"])
        self.assertFalse(status["items"][0]["ssh"])
        self.assertTrue(status["ssh_accounts"])
        with patch.object(self.broker.ssh, "account_policy", return_value={}), \
                patch.object(self.broker.ssh, "reconcile"):
            approved = self.broker.dispatch({"action": "workstation-ssh-approve",
                                             "workstation_id": item["id"], "ssh_user": "root"}, 1000)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertTrue(approved["ok"])
        self.assertTrue(item["ssh"])
        self.assertEqual(item["ssh_user"], "root")
        self.assertEqual(item["ssh_public_key"], request_key)
        self.assertNotIn("ssh_request", item)
        with patch.object(self.broker.ssh, "reconcile"):
            revoked = self.broker.dispatch({"action": "workstation-ssh-revoke",
                                            "workstation_id": item["id"]}, 1000)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertTrue(revoked["ok"])
        self.assertFalse(item["ssh"])
        self.assertNotIn("ssh_public_key", item)
        self.assertIn(item["public_key"], self.net.devices[broker_module.WORKSTATION_IFACE]["peers"])

    def test_windows_unlock_request_requires_admin_approval_and_rejection_preserves_restrictions(self):
        _, response = self.pair(sources="198.51.100.24")
        self.open_session(response)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        source = item["address"].split("/")[0]
        pending = self.broker.workstation_session("unlock-request", source, item["pbx_address"])
        self.assertEqual(pending["unlock_request_status"], "pending")
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertTrue(item["locked"])
        self.assertTrue(item["unlock_request"])
        self.assertIn(item["id"], self.broker.active_sessions())
        rejected = self.broker.dispatch({"action": "workstation-unlock-reject",
                                         "workstation_id": item["id"]}, 1000)
        state, _ = self.broker.workstation_state()
        self.assertTrue(rejected["ok"])
        self.assertTrue(state["workstations"][0]["locked"])
        self.assertNotIn("unlock_request", state["workstations"][0])

    def test_admin_approved_windows_unlock_starts_identity_preserving_migration(self):
        _, response = self.pair(sources="198.51.100.24")
        self.open_session(response)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        source = item["address"].split("/")[0]
        self.broker.workstation_session("unlock-request", source, item["pbx_address"])
        approved = self.broker.dispatch({"action": "workstation-unlock-approve",
                                         "workstation_id": item["id"]}, 1000)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertTrue(approved["ok"])
        self.assertFalse(item["locked"])
        self.assertTrue(item.get("migration"))
        self.assertTrue(item["migration"]["locked"])
        self.assertNotIn("unlock_request", item)
        self.assertNotIn(item["id"], self.broker.active_sessions())

    def test_windows_allowed_list_change_requires_admin_approval_before_policy_migration(self):
        _, response = self.pair()
        self.open_session(response)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        source = item["address"].split("/")[0]
        pending = self.broker.workstation_session("sources-request", source, response["pbx_address"],
                                                  "198.51.100.24, 2001:db8::24/128, example.org")
        self.assertEqual(pending["sources_request_status"], "pending")
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertFalse(item["locked"])
        self.assertNotIn("migration", item)
        self.assertEqual(item["sources_request"]["sources"],
                         ["198.51.100.24/32", "2001:db8::24/128", "example.org"])
        approved = self.broker.dispatch({"action": "workstation-sources-approve",
                                         "workstation_id": item["id"]}, 1000)
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        self.assertTrue(approved["ok"])
        self.assertTrue(item["locked"])
        self.assertEqual(item["sources"], ["198.51.100.24/32", "2001:db8::24/128", "example.org"])
        self.assertTrue(item.get("migration"))
        self.assertNotIn("sources_request", item)
        self.assertNotIn(item["id"], self.broker.active_sessions())

    def test_locked_workstation_managed_ssh_is_scoped_to_its_dedicated_interface(self):
        _, response = self.pair(sources="198.51.100.24", ssh="1")
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        interface = self.broker.locked_interface(item)
        rules = [entry["rule"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry]
        self.assertFalse(any(rule["expr"][-1] == {"accept": None}
                             and any(expression.get("match", {}).get("right") in (80, 443, 8765, 22002)
                                     for expression in rule["expr"]) for rule in rules))
        self.open_session(response)
        rules = [entry["rule"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry]
        allowed = [rule for rule in rules if rule["chain"] == "input" and rule["expr"][-1] == {"accept": None}
                   and any(expression == {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                                                       "right": interface}} for expression in rule["expr"])]
        allowed_ports = {expression["match"]["right"] for rule in allowed for expression in rule["expr"]
                         if expression.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}}
        self.assertEqual(allowed_ports, {80, 443, broker_module.SESSION_CONTROL_PORT,
                                         broker_module.ssh.API_PORT, broker_module.ssh.port(item)})
        self.assertTrue(response["ssh"])
        self.assertEqual(response["ssh_port"], broker_module.ssh.port(item))
        self.assertTrue(item["locked"])
        self.assertTrue(item["ssh"])

    def test_manual_ban_blocks_listener_source_without_disrupting_tunnels(self):
        self.pair(sources="198.51.100.24")
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        interface = self.broker.locked_interface(item)
        self.net.calls = []
        updated = self.broker.configure_ban({"action": "workstation-ban", "source": "198.51.100.24",
                                             "reason": "temporary incident", "hours": "1"}, 1000)
        self.assertEqual(len(updated["bans"]), 1)
        self.assertTrue(self.net.devices[interface]["up"])
        self.assertFalse(any(name == "ip" and "down" in rest for name, rest in self.net.calls))
        rules = [entry["rule"] for entry in self.net.table["nftables"] if "rule" in entry and entry["rule"]["chain"] == "input"]
        banned = next(index for index, rule in enumerate(rules)
                      if rule["expr"][-1] == {"drop": None}
                      and {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                     "right": "198.51.100.24"}} in rule["expr"])
        allowed = next(index for index, rule in enumerate(rules)
                       if rule["expr"][-1] == {"accept": None}
                       and {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                      "right": "198.51.100.24"}} in rule["expr"])
        self.assertLess(banned, allowed, "an explicit ban must precede the Locked listener allow rule")
        self.assertEqual(self.broker.workstation_status()["bans"][0]["active"], True)
        self.broker.configure_ban({"action": "workstation-unban", "ban_id": updated["bans"][0]["id"]}, 1000)
        self.assertTrue(self.net.devices[interface]["up"])
        self.assertFalse(any(entry["rule"]["expr"][-1] == {"drop": None}
                             and any(expr.get("match", {}).get("right") == "198.51.100.24"
                                      for expr in entry["rule"]["expr"])
                             for entry in self.net.table["nftables"] if "rule" in entry))

    def test_workstation_session_admission_is_atomic_and_peer_bound(self):
        _, first = self.pair()
        _, second = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        first_state, _ = self.broker.workstation_state()
        first_item = next(item for item in first_state["workstations"] if item["id"] == first["workstation_id"])
        second_item = next(item for item in first_state["workstations"] if item["id"] == second["workstation_id"])
        barrier = broker_module.threading.Barrier(3)
        outcomes = []
        outcome_lock = broker_module.threading.Lock()

        def acquire(source):
            barrier.wait()
            try:
                self.broker.workstation_session("heartbeat", source)
                result = "admitted"
            except broker_module.BrokerError as error:
                result = str(error)
            with outcome_lock:
                outcomes.append(result)

        workers = [broker_module.threading.Thread(target=acquire, args=(item["address"].split("/")[0],))
                   for item in (first_item, second_item)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=5)

        self.assertEqual(outcomes.count("admitted"), 1)
        self.assertTrue(any("Session limit reached: 1 of 1" in result for result in outcomes))
        sessions = self.broker.active_sessions()
        self.assertEqual(len(sessions), 1)
        state, _ = self.broker.workstation_state()
        active_id = next(iter(sessions))
        active_source = next(item["address"].split("/")[0] for item in state["workstations"] if item["id"] == active_id)
        inactive_source = next(item["address"].split("/")[0] for item in state["workstations"] if item["id"] != active_id)
        rules = [entry["rule"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry]
        admitted_sources = {expression["match"]["right"] for rule in rules if rule["expr"][-1] == {"accept": None}
                            for expression in rule["expr"]
                            if expression.get("match", {}).get("left") == {"payload": {"protocol": "ip", "field": "saddr"}}
                            and any(part.get("match", {}).get("right") in (80, 443) for part in rule["expr"])}
        self.assertIn(active_source, admitted_sources)
        self.assertNotIn(inactive_source, admitted_sources)

    def test_release_expiry_and_restart_recover_capacity(self):
        _, first = self.pair()
        _, second = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        state, _ = self.broker.workstation_state()
        first_item = next(item for item in state["workstations"] if item["id"] == first["workstation_id"])
        second_item = next(item for item in state["workstations"] if item["id"] == second["workstation_id"])
        first_source = first_item["address"].split("/")[0]
        second_source = second_item["address"].split("/")[0]
        admitted = self.broker.workstation_session("heartbeat", first_source)
        self.assertEqual(admitted["active"], True)
        self.assertEqual(admitted["policy"]["locked"], False)
        self.assertEqual(admitted["policy"]["sources"], [])
        self.assertFalse(admitted["policy"]["ssh_approved"])
        with self.assertRaisesRegex(broker_module.BrokerError, "Session limit reached"):
            self.broker.workstation_session("heartbeat", second_source)
        self.broker.workstation_session("release", first_source)
        self.broker.workstation_session("heartbeat", second_source)
        self.assertEqual(list(self.broker.active_sessions()), [second["workstation_id"]])

        leases = self.broker.active_sessions()
        leases[second["workstation_id"]]["expires_at"] = int(broker_module.time.time()) - 1
        self.broker.save_active_sessions(leases)
        self.broker.expire_sessions()
        self.assertEqual(self.broker.active_sessions(), {})
        self.broker.workstation_session("heartbeat", first_source)
        self.broker.save_active_sessions({})
        state, _ = self.broker.workstation_state()
        rules = [entry["rule"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry]
        self.assertFalse(any(rule["expr"][-1] == {"accept": None}
                             and any(expression.get("match", {}).get("right") in (80, 443)
                                     for expression in rule["expr"]) for rule in rules))

    def test_locked_session_reports_effective_policy_and_dns_failure(self):
        _, response = self.pair(sources="198.51.100.24, office.example.net")
        state, _ = self.broker.workstation_state()
        item = next(entry for entry in state["workstations"] if entry["id"] == response["workstation_id"])
        self.broker.source_cache["office.example.net"] = (broker_module.time.monotonic() + 60, [])
        status = self.broker.workstation_session("heartbeat", item["address"].split("/")[0])
        self.assertTrue(status["policy"]["locked"])
        self.assertEqual(status["policy"]["sources"], ["198.51.100.24/32", "office.example.net"])
        self.assertEqual(status["policy"]["effective_source_count"], 1)
        self.assertEqual(status["policy"]["source_resolution_failures"], ["office.example.net"])
        self.assertEqual(status["policy"]["listener_port"], item["listener_port"])

    def test_session_limit_setting_is_validated_and_persisted(self):
        for maximum in ("0", "129", "1.5", 1, "001"):
            with self.assertRaises(broker_module.BrokerError):
                broker_module.validate({"action": "workstation-limit", "maximum": maximum})
        _, response = self.pair()
        self.assertEqual(self.broker.dispatch({"action": "workstation-limit", "maximum": "2"}, 1000)["ok"], True)
        self.open_session(response)
        _, second = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        self.open_session(second)
        status = self.broker.workstation_status()
        self.assertEqual(status["max_sessions"], 2)
        self.assertEqual(status["connected_workstations"], 2)
        with self.assertRaisesRegex(broker_module.BrokerError, "cannot be lower"):
            self.broker.configure_workstation_limit({"maximum": "1"}, 1000)

    def test_session_admission_fails_when_firewall_order_is_unsafe(self):
        _, response = self.pair()
        state, _ = self.broker.workstation_state()
        item = next(entry for entry in state["workstations"] if entry["id"] == response["workstation_id"])
        self.broker.integration["state"] = "error"
        with self.assertRaisesRegex(broker_module.BrokerError, "integration is unsafe"):
            self.broker.workstation_session("heartbeat", item["address"].split("/")[0])
        self.assertEqual(self.broker.active_sessions(), {})

    def test_http_session_controller_authenticates_kernel_source_and_enforces_capacity(self):
        state = {"connection_state": "open", "subnet": "127.0.0.0/24", "max_sessions": 1,
                 "workstations": [{"id": "a" * 16, "address": "127.0.0.2/32"},
                                  {"id": "b" * 16, "address": "127.0.0.3/32"}]}
        self.broker.workstation_state = lambda: (state, False)
        self.broker.reconcile_policy_only = lambda current: None
        self.broker.integration["state"] = "active"
        with broker_module.socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with patch.object(broker_module, "SESSION_CONTROL_PORT", port):
            self.broker.session_server_enabled = True
            self.broker.reconcile_session_servers(state)

            def post(source, action="heartbeat", extra=None):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", port, timeout=3, source_address=(source, 0))
                try:
                    body = json.dumps({"action": action, **(extra or {})})
                    connection.request("POST", "/workstation/session", body,
                                       {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    connection.close()

            try:
                status, admitted = post("127.0.0.2")
                self.assertEqual(status, 200)
                self.assertEqual(admitted["connected_workstations"], 1)
                status, refused = post("127.0.0.3")
                self.assertEqual(status, 409)
                self.assertIn("Session limit reached: 1 of 1", refused["error"])
                status, renewed = post("127.0.0.2")
                self.assertEqual(status, 200)
                self.assertEqual(renewed["connected_workstations"], 1)
                status, request = post("127.0.0.2", "sources-request",
                                       {"sources": "198.51.100.24, example.org"})
                self.assertEqual(status, 200)
                self.assertEqual(request["sources_request_status"], "pending")
                status, released = post("127.0.0.2", "release")
                self.assertEqual(status, 200)
                self.assertEqual(released["connected_workstations"], 0)
            finally:
                self.broker.stop_session_servers()

    def test_expired_manual_ban_is_removed_without_restarting_workstation_interfaces(self):
        self.pair(sources="198.51.100.24")
        state = self.broker.configure_ban({"action": "workstation-ban", "source": "198.51.100.24",
                                           "reason": "temporary", "hours": "1"}, 1000)
        state["bans"][0]["expires_at"] = int(broker_module.time.time()) - 1
        self.broker.save_workstations(state)
        self.net.calls = []

        self.broker.expire_workstations()

        self.assertTrue(self.net.devices[broker_module.WORKSTATION_IFACE]["up"])
        self.assertFalse(any(name == "ip" and "down" in rest for name, rest in self.net.calls))
        self.assertFalse(any(entry["rule"]["expr"][-1] == {"drop": None}
                             and any(expr.get("match", {}).get("right") == "198.51.100.24"
                                      for expr in entry["rule"]["expr"])
                             for entry in self.net.table["nftables"] if "rule" in entry))

    def test_connection_state_defaults_and_migrates_existing_roster(self):
        (self.state / "workstations.json").unlink()
        state, changed = self.broker.workstation_state()
        self.assertEqual(state["connection_state"], "closed")
        self.assertTrue(changed)
        self.pair()
        saved = broker_module.read_json(self.state / "workstations.json")
        saved.pop("connection_state")
        broker_module.atomic(self.state / "workstations.json", json.dumps(saved))
        migrated, changed = self.broker.workstation_state()
        self.assertEqual(migrated["connection_state"], "open")
        self.assertTrue(changed)

    def test_closed_retains_pairings_and_open_restores_them(self):
        _, response = self.pair()
        before, _ = self.broker.workstation_state()
        self.broker.configure_workstation_policy({"state": "closed"}, 1000)
        closed, _ = self.broker.workstation_state()
        self.assertEqual(closed["connection_state"], "closed")
        self.assertEqual([item["id"] for item in closed["workstations"]], [response["workstation_id"]])
        self.assertIsNone(self.broker.link_state())
        self.broker.configure_workstation_policy({"state": "open"}, 1000)
        opened, _ = self.broker.workstation_state()
        self.assertEqual(opened["connection_state"], "open")
        self.assertEqual(opened["workstations"], before["workstations"])
        self.assertIn("UP", self.broker.link_state()["flags"])

    def test_frozen_preserves_existing_pairings_and_rejects_new_ones(self):
        self.pair()
        self.broker.configure_workstation_policy({"state": "frozen"}, 1000)
        state, _ = self.broker.workstation_state()
        self.assertEqual(state["connection_state"], "frozen")
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "pair", "request": pair_request(public_key="C" * 42 + "E=", nonce="n" * 22),
                                  "endpoint_host": "pbx.example.net", "listen_port": "51821", "mode": "persistent",
                                  "minutes": "60", "ssh": "0"}, 1000)

    def test_web_only_pairing_cannot_be_granted_ssh(self):
        with self.assertRaisesRegex(broker_module.BrokerError, "did not include SSH capability"):
            self.broker.dispatch({"action": "pair", "request": pair_request(), "endpoint_host": "pbx.example.net",
                                  "listen_port": "51821", "mode": "persistent", "minutes": "60", "ssh": "1"}, 1000)

    def test_managed_ssh_has_explicit_account_and_no_system_ssh_permission(self):
        blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))
        key = "ssh-ed25519 " + base64.b64encode(blob).decode()
        request = broker_module.parse_pair_request(pair_request())
        request.update(schema="teliphones-pair-request/2", ssh_public_key=key)
        code = broker_module.PAIR_REQUEST_V2 + broker_module.b64url_encode(json.dumps(request).encode())
        action = {"action": "pair", "request": code, "endpoint_host": "pbx.example.net", "listen_port": "51821",
                  "mode": "temporary", "minutes": "60", "ssh": "1"}
        for user in ("", "-root", "root\n"):
            with self.assertRaises(broker_module.BrokerError):
                broker_module.validate({**action, "ssh_user": user})
        with patch.object(self.broker.ssh, "initialise", return_value=key), \
                patch.object(self.broker.ssh, "host_key", return_value=key), \
                patch.object(self.broker.ssh, "account_policy", return_value={}), \
                patch.object(self.broker.ssh, "reconcile") as reconcile:
            response = self.broker.dispatch({**action, "ssh_user": "root"}, 1000)
            self.assertTrue(response["ok"])
            encoded = response["pairing_response"].removeprefix(broker_module.PAIR_RESPONSE_V2)
            paired = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            self.assertEqual(paired["ssh_user"], "root")
            self.assertEqual(paired["ssh_port"], 22002)
            self.assertEqual(paired["ssh_api_port"], 8765)
            self.assertEqual(paired["ssh_ca_key"], key)
            self.assertEqual(reconcile.call_args[0][0]["workstations"][0]["ssh_public_key"], key)
            self.open_session(decode_response(response["pairing_response"]))
            ports = [match["match"]["right"] for entry in self.net.table["nftables"] if "rule" in entry
                     for match in entry["rule"]["expr"]
                     if match.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}]
            self.assertIn(8765, ports)
            self.assertIn(22002, ports)
            self.assertNotIn(22, ports)
            with patch.object(self.broker.ssh, "reconcile", side_effect=broker_module.ssh.SshError("cleanup not verified")):
                with self.assertRaisesRegex(broker_module.BrokerError, "cleanup"):
                    self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
            self.assertEqual(len(broker_module.read_json(self.state / "workstations.json")["workstations"]), 1)

    def test_pairing_applies_port_policy_before_admitting_the_peer(self):
        result, response = self.pair(ssh="1")
        self.assertTrue(result["ok"])
        self.assertEqual(response["nonce"], "n" * 22)
        self.assertEqual(response["workstation_public_key"], "A" * 42 + "E=")
        self.assertEqual(response["pbx_public_key"], "P" * 42 + "A=")
        self.assertEqual(response["endpoint"], "pbx.example.net:51821")
        self.assertEqual(response["mode"], "persistent")
        self.assertIsNone(response["expires_at"])
        self.assertTrue(response["ssh"])
        network = broker_module.ipaddress.IPv4Network(json.loads((self.state / "workstations.json").read_text())["subnet"])
        self.assertTrue(network.subnet_of(broker_module.WORKSTATION_POOL) and not network.overlaps(broker_module.WORKSTATION_EXCLUDED))
        self.assertEqual(response["pbx_address"], str(network[1]))
        self.assertEqual(response["address"], str(network[2]) + "/32")
        self.assertEqual(response["gui_url"], "http://" + str(network[1]) + "/admin/")
        policy = next(index for index, call in enumerate(self.net.calls) if call[0] == "nft")
        admitted = next(index for index, call in enumerate(self.net.calls) if call[0] == "wg" and "allowed-ips" in call[1])
        self.assertLess(policy, admitted)
        self.assertEqual(self.net.peers, {"A" * 42 + "E=": response["address"]})
        state, _ = self.broker.workstation_state()
        tcp_ports = [match["match"]["right"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry
                     for match in entry["rule"]["expr"]
                     if match.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}]
        self.assertNotIn(80, tcp_ports)
        self.open_session(response)
        tcp_ports = [match["match"]["right"] for entry in self.broker.expected_policy(state)["nftables"] if "rule" in entry
                     for match in entry["rule"]["expr"]
                     if match.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}]
        self.assertIn(22000 + int(response["address"].split(".")[-1].split("/")[0]), tcp_ports)
        self.assertNotIn(22, tcp_ports)
        self.assertIn(str(network[2]), json.dumps(self.broker.expected_policy(state)))
        self.assertNotIn("PrivateKey", (self.state / "workstations.json").read_text())
        self.assertNotIn("k" * 43, (self.state / "workstations.json").read_text())
        self.assertEqual((self.enrollment / "workstation-wg.key").stat().st_mode & 0o077, 0)

    def test_ruleset_limits_workstations_to_pbx_gui_and_approved_ssh(self):
        ruleset = broker_module.workstation_ruleset("100.70.1.1", [])
        self.assertIn('iifname "tlp-admin" ip daddr 100.70.1.1 tcp dport { 80, 443 } accept', ruleset)
        self.assertNotIn("dport 22", ruleset)
        self.assertIn('        iifname "tlp-admin" drop', ruleset)
        self.assertIn('        oifname "tlp-admin" drop', ruleset)
        self.assertTrue(ruleset.startswith("table inet teliphones_workstations {"))
        self.assertIn("chain " + broker_module.WORKSTATION_OWNER_CHAIN + " { }", ruleset)
        self.assertNotIn("comment", ruleset)
        policy = broker_module.workstation_policy("100.70.1.1", [])
        self.assertNotIn("comment", policy["nftables"][0]["table"])
        self.assertEqual(policy["nftables"][1]["chain"], {
            "family": "inet", "table": broker_module.WORKSTATION_TABLE, "name": broker_module.WORKSTATION_OWNER_CHAIN
        })
        self.assertNotIn("delete table", ruleset)
        ruleset = broker_module.workstation_ruleset("100.70.1.1", ["100.70.1.3", "100.70.1.2"])
        self.assertIn("ip saddr { 100.70.1.2, 100.70.1.3 } ip daddr 100.70.1.1 tcp dport 22 accept", ruleset)
        self.assertLess(ruleset.index("dport 22 accept"), ruleset.index('iifname "tlp-admin" drop'))

    def test_temporary_pairing_expires_and_open_listener_remains(self):
        _, response = self.pair(mode="temporary", minutes="15")
        self.assertGreater(response["expires_at"], broker_module.time.time() + 14 * 60)
        self.assertTrue(self.net.link)
        state = json.loads((self.state / "workstations.json").read_text())
        state["workstations"][0]["expires_at"] = 1
        (self.state / "workstations.json").write_text(json.dumps(state))
        self.broker.expire_workstations()
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertIsNotNone(self.net.ruleset)
        self.assertEqual(self.broker.status()["workstations"]["items"], [])
        expired = self.broker.diagnostics.read("ws-" + response["workstation_id"])
        self.assertIn("pairing.expired", [item["event"] for item in expired])

    def test_repairing_same_key_keeps_address_and_port_is_fixed(self):
        _, first = self.pair(mode="temporary")
        _, second = self.pair(mode="persistent")
        self.assertEqual(first["address"], second["address"])
        self.assertEqual(first["workstation_id"], second["workstation_id"])
        self.assertEqual(len(self.broker.status()["workstations"]["items"]), 1)
        with self.assertRaises(broker_module.BrokerError):
            self.pair(port="51822", public_key="B" * 42 + "E=")
        _, other = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        self.assertNotEqual(other["address"], first["address"])

    def test_revocation_removes_peer_and_keeps_open_listener(self):
        _, first = self.pair()
        _, second = self.pair(public_key="B" * 42 + "E=", ssh="1")
        result = self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.assertTrue(result["ok"])
        self.assertEqual(set(self.net.peers), {"B" * 42 + "E="})
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertIsNotNone(self.net.ruleset)
        self.broker.configure_workstation_policy({"state": "closed"}, 1000)
        self.assertFalse(self.net.link)

    def test_revocation_holds_even_when_network_update_fails(self):
        _, first = self.pair()
        self.pair(public_key="B" * 42 + "E=")
        self.net.fail = lambda name, rest: name == "nft" and rest == ["-j", "-f", "-"]
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertNotIn("A" * 42 + "E=", self.net.peers)
        self.assertIn(first["workstation_id"], [item["id"] for item in json.loads((self.state / "workstations.json").read_text())["workstations"]])

    def test_failed_interface_deletion_disables_traffic_and_preserves_firewall(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "ip" and rest[:2] == ["link", "del"]
        with self.assertRaisesRegex(broker_module.BrokerError, "disabled"):
            self.broker.configure_workstation_policy({"state": "closed"}, 1000)
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertIsNotNone(self.net.ruleset)
        self.assertEqual(self.broker.workstation_state()[0]["connection_state"], "open")
        self.net.fail = None
        self.broker.configure_workstation_policy({"state": "closed"}, 1000)
        self.assertFalse(self.net.link)

    def test_failed_firewall_cleanup_is_not_reported_as_success(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "nft" and rest == ["-j", "-f", "-"]
        with self.assertRaisesRegex(broker_module.BrokerError, "cleanup"):
            self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertIsNotNone(self.net.ruleset)

    def test_failed_pairing_fails_closed_and_restores_previous_state(self):
        self.net.fail = lambda name, rest: name == "wg" and "allowed-ips" in rest
        with self.assertRaisesRegex(broker_module.BrokerError, "removed"):
            self.pair()
        self.assertTrue(self.net.link)
        self.assertTrue(self.net.up)
        self.assertIsNotNone(self.net.ruleset)
        self.assertEqual(self.broker.status()["workstations"]["items"], [])

    def test_failed_new_pairing_restores_existing_workstations(self):
        _, first = self.pair()
        self.net.fail = lambda name, rest: name == "wg" and "allowed-ips" in rest and "B" * 42 + "E=" in rest
        with self.assertRaises(broker_module.BrokerError):
            self.pair(public_key="B" * 42 + "E=")
        self.assertEqual(self.net.peers, {"A" * 42 + "E=": first["address"]})
        self.assertEqual([item["id"] for item in self.broker.status()["workstations"]["items"]], [first["workstation_id"]])

    def test_status_reports_workstations_without_keys(self):
        self.pair(mode="temporary", ssh="1")
        status = self.broker.status()["workstations"]
        self.assertEqual(set(status), {"ready", "requirements", "error", "listen_port", "web", "gui_url", "connection_state",
                                       "firewall_integration", "pbx_address", "items", "ssh_ready", "ssh_error", "bans",
                                       "max_sessions", "connected_workstations", "ssh_accounts", "session_control_port"})
        self.assertEqual(status["firewall_integration"]["state"], "not-detected")
        self.assertEqual([(entry["scheme"], entry["port"]) for entry in status["web"]], [("http", 80), ("https", 443)])
        self.assertEqual(status["gui_url"], "http://" + status["pbx_address"] + "/admin/")
        item = status["items"][0]
        self.assertEqual(set(item), {"id", "name", "address", "mode", "ssh", "created_at", "expires_at", "fingerprint", "last_handshake",
                                     "ssh_user", "ssh_port", "ssh_managed", "locked", "sources", "effective_sources",
                                     "source_resolution_failures", "listener_port", "verified_endpoint",
                                     "migration_pending", "migration_generation", "ssh_request_pending",
                                     "unlock_request_pending", "sources_request_pending", "requested_sources",
                                     "session_active", "session_expires_at"})
        self.assertTrue(item["fingerprint"].startswith("SHA256:"))
        self.assertEqual(item["last_handshake"], 0)
        self.assertIsNone(item["verified_endpoint"])
        self.assertNotIn("A" * 42, json.dumps(status))

    def test_handshake_status_is_read_only_and_does_not_claim_reachability(self):
        self.pair()
        self.net.handshakes["A" * 42 + "E="] = 1790000000
        self.net.endpoints["A" * 42 + "E="] = "[2001:db8::24]:51821"
        self.net.calls = []
        status = self.broker.status()
        self.assertEqual(status["protocol"], broker_module.PROTOCOL)
        self.assertEqual(status["workstations"]["items"][0]["last_handshake"], 1790000000)
        self.assertEqual(status["workstations"]["items"][0]["verified_endpoint"],
                         {"address": "2001:db8::24", "port": 51821})
        self.assertEqual(self.net.calls, [("wg", ("show", broker_module.WORKSTATION_IFACE, "latest-handshakes")),
                                          ("wg", ("show", broker_module.WORKSTATION_IFACE, "endpoints")),
                                          ("wg", ("show", broker_module.WORKSTATION_IFACE, "transfer"))])
        self.assertNotIn("A" * 42, json.dumps(status))
        diagnostic_id = "ws-" + status["workstations"]["items"][0]["id"]
        events = self.broker.diagnostics.read(diagnostic_id)
        observations = [item for item in events if item["event"] == "peer.observation"]
        self.assertTrue(observations)
        self.assertEqual(observations[-1]["data"]["handshake_at"], 1790000000)
        self.assertNotIn("disconnected", json.dumps(events).lower())
        self.assertEqual({item["diagnostic_id"] for item in events}, {diagnostic_id})
        exported = self.broker.dispatch({"action": "diagnostics", "diagnostic_id": diagnostic_id}, 1000)
        self.assertEqual(exported["component_version"], "0.6.1")
        self.assertEqual(exported["diagnostic_id"], diagnostic_id)
        self.assertFalse(any("public_key" in item or "token" in json.dumps(item).lower() for item in exported["events"]))

    def test_pairing_diagnostics_capture_server_lifecycle_and_filtering(self):
        _, response = self.pair(mode="temporary")
        diagnostic_id = "ws-" + response["workstation_id"]
        self.broker.workstation_status()
        events = self.broker.diagnostics.read(diagnostic_id)
        names = [event["event"] for event in events]
        self.assertIn("pairing.approved", names)
        self.assertIn("interface.established", names)
        self.assertIn("peer.admitted", names)
        self.assertIn("peer.observation", names)
        self.assertTrue(all(event["source"] == "pbx" and event["component_version"] == "0.6.1" for event in events))
        self.broker.dispatch({"action": "unpair", "workstation_id": response["workstation_id"]}, 1000)
        events = self.broker.diagnostics.read(diagnostic_id)
        self.assertEqual(events[-1]["event"], "pairing.revoked")
        self.assertEqual(self.broker.diagnostics.read("ws-ffffffffffffffff"), [])

    def test_diagnostics_action_rejects_invalid_identifiers_and_extra_fields(self):
        for request in ({"action": "diagnostics", "diagnostic_id": "0123456789abcdef"},
                        {"action": "diagnostics", "diagnostic_id": "ws-../../"},
                        {"action": "diagnostics", "diagnostic_id": "ws-0123456789abcdef", "path": "/etc/shadow"}):
            with self.assertRaises(broker_module.BrokerError):
                broker_module.validate(request)

    def test_traffic_counters_are_logged_as_throttled_summaries(self):
        _, response = self.pair()
        state, _ = self.broker.workstation_state()
        item = state["workstations"][0]
        with patch.object(broker_module.time, "monotonic", side_effect=[100, 120, 399, 401]):
            self.broker.observe_workstations(state, {item["public_key"]: 0}, {item["public_key"]: (0, 0)})
            self.broker.observe_workstations(state, {item["public_key"]: 0}, {item["public_key"]: (10, 0)})
            self.broker.observe_workstations(state, {item["public_key"]: 0}, {item["public_key"]: (10, 0)})
            self.broker.observe_workstations(state, {item["public_key"]: 0}, {item["public_key"]: (10, 0)})
        events = [event for event in self.broker.diagnostics.read("ws-" + response["workstation_id"])
                  if event["event"] == "peer.observation"]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["data"]["rx_bytes"], 10)

    def test_diagnostic_log_rotates_retains_and_limits_export(self):
        logger = broker_module.DiagnosticLog(self.state / "test-diagnostics")
        self.assertEqual(logger.MAX_FILE_BYTES, 1024 * 1024)
        logger.MAX_FILE_BYTES = 500
        diagnostic_id = "ws-0123456789abcdef"
        for index in range(20):
            logger.record(diagnostic_id, "peer.observation", handshake_at=index, rx_bytes=index, tx_bytes=index)
        files = [logger.directory / name for name in logger.FILES if (logger.directory / name).exists()]
        self.assertLessEqual(len(files), 3)
        self.assertTrue(all(path.stat().st_size <= 500 for path in files))
        self.assertGreaterEqual(len(files), 2)
        active = logger.directory / "events.jsonl"
        lines = active.read_text().splitlines()
        record = json.loads(lines[0])
        record["unix_time"] = int(broker_module.time.time() - logger.RETENTION_SECONDS - 1)
        lines[0] = json.dumps(record, separators=(",", ":"), sort_keys=True)
        active.write_text("\n".join(lines) + "\n")
        logger.read(diagnostic_id)
        self.assertTrue(all(json.loads(line)["unix_time"] >= broker_module.time.time() - logger.RETENTION_SECONDS
                            for line in active.read_text().splitlines()))

    def test_diagnostic_log_concurrent_writes_and_field_redaction(self):
        logger = broker_module.DiagnosticLog(self.state / "concurrent-diagnostics")
        diagnostic_id = "ws-0123456789abcdef"
        writers = [threading.Thread(target=lambda base=base: [
            logger.record(diagnostic_id, "peer.observation", handshake_at=base + index, rx_bytes=index, tx_bytes=index)
            for index in range(50)]) for base in range(8)]
        for writer in writers:
            writer.start()
        for writer in writers:
            writer.join()
        active = logger.directory / "events.jsonl"
        records = [json.loads(line) for line in active.read_text().splitlines()]
        self.assertEqual(len(records), 400)
        with self.assertRaises(ValueError):
            logger.record(diagnostic_id, "peer.observation", handshake_at=0, rx_bytes=0, tx_bytes=0,
                          private_key="private-secret")
        self.assertNotIn("private-secret", active.read_text())

    def test_diagnostic_storage_failure_does_not_block_revocation(self):
        _, response = self.pair()
        self.broker.diagnostics.record = lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk unavailable"))
        with patch.object(broker_module.LOGGER, "warning") as warning:
            result = self.broker.dispatch({"action": "unpair", "workstation_id": response["workstation_id"]}, 1000)
        self.assertTrue(result["ok"])
        self.assertTrue(self.net.link)
        self.assertTrue(warning.called)

    def test_diagnostic_storage_failure_does_not_block_expiry_cleanup(self):
        _, response = self.pair(mode="temporary")
        state = json.loads((self.state / "workstations.json").read_text())
        state["workstations"][0]["expires_at"] = 1
        (self.state / "workstations.json").write_text(json.dumps(state))
        self.broker.diagnostics.record = lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk unavailable"))
        with patch.object(broker_module.LOGGER, "warning") as warning:
            self.broker.expire_workstations()
        self.assertTrue(self.net.link)
        self.assertEqual(self.broker.status()["workstations"]["items"], [])
        self.assertTrue(warning.called)

    def test_handshake_query_failure_reports_unverified_status(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "wg" and "latest-handshakes" in rest
        status = self.broker.status()["workstations"]
        self.assertIsNone(status["items"][0]["last_handshake"])
        self.assertIn("could not be read", status["error"])
        self.assertTrue(self.net.link)

    def test_disabled_teliphones_refuses_pairing(self):
        (self.state / "disabled").write_text("")
        with self.assertRaises(broker_module.BrokerError):
            self.pair()
        self.assertEqual(self.net.calls, [])

    def test_disabled_teliphones_removes_workstation_access_and_prevents_restore(self):
        self.pair()
        (self.state / "disabled").write_text("")
        self.broker.expire_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.net.ruleset)
        self.broker.restore_workstations()
        self.assertFalse(self.net.link)
        self.assertFalse(self.broker.workstation_status()["ready"])

    def test_broker_restart_restores_only_unexpired_pairings(self):
        self.pair(mode="temporary")
        self.pair(public_key="B" * 42 + "E=", mode="persistent")
        state = json.loads((self.state / "workstations.json").read_text())
        state["workstations"][0]["expires_at"] = 1
        (self.state / "workstations.json").write_text(json.dumps(state))
        self.broker.teardown_workstations()
        self.broker.monitor.close()
        restarted = broker_module.Broker()
        restarted.audit, restarted.run, restarted.tool = self.broker.audit, self.net.run, self.broker.tool
        restarted.iptables_tool = self.broker.iptables_tool
        restarted.restore_workstations()
        self.assertEqual(set(self.net.peers), {"B" * 42 + "E="})
        self.assertTrue(self.net.link)
        restarted.monitor.close()
