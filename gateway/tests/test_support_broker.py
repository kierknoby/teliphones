import importlib.util
import json
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
        self.assertEqual(status["protocol"], broker_module.PROTOCOL)
        self.assertIn("operation", status)
        self.assertIsInstance(status["server_time"], int)
        web_support = (Path(broker_module.__file__).parent / "WebSupport.php").read_text()
        self.assertIn("public const BROKER_PROTOCOL = %d;" % broker_module.PROTOCOL, web_support)

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
    assert code.startswith(broker_module.PAIR_RESPONSE_PREFIX)
    return json.loads(broker_module.b64url_decode(code[len(broker_module.PAIR_RESPONSE_PREFIX):]))


class FakeNetwork:
    """Stateful stand-in for ip/wg/nft. Records every command; real kernel behaviour is not exercised."""

    def __init__(self):
        self.calls = []
        self.link = False
        self.up = False
        self.peers = {}
        self.ruleset = None
        self.fail = None
        self.handshakes = {}

    def run(self, arguments, stdin=None, check=True):
        name, rest = arguments[0], arguments[1:]
        self.calls.append((name, tuple(rest)))
        if self.fail and self.fail(name, rest):
            if check:
                raise broker_module.BrokerError("Workstation network operation failed: " + name)
            return None
        if name == "ip" and rest[:2] == ["link", "show"]:
            return "" if self.link else None
        if name == "ip" and rest[:2] == ["link", "add"]:
            self.link = True
        if name == "ip" and rest[:2] == ["link", "del"]:
            self.link, self.up, self.peers = False, False, {}
        if name == "ip" and rest[:2] == ["link", "set"]:
            self.up = "up" in rest
        if name == "ip" and rest[:2] == ["-4", "-o"]:
            return "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        if name == "ip" and rest[:2] == ["-4", "route"]:
            return "default via 192.168.1.1 dev eth0\n192.168.1.0/24 dev eth0 proto kernel\n"
        if name == "wg" and rest == ["genkey"]:
            return "k" * 43 + "=\n"
        if name == "wg" and rest == ["pubkey"]:
            return "P" * 42 + "A=\n"
        if name == "wg" and rest[:3] == ["show", broker_module.WORKSTATION_IFACE, "peers"]:
            return "\n".join(self.peers)
        if name == "wg" and rest == ["show", broker_module.WORKSTATION_IFACE, "latest-handshakes"]:
            return "\n".join("%s\t%d" % (key, self.handshakes.get(key, 0)) for key in self.peers)
        if name == "wg" and rest[:1] == ["set"] and "peer" in rest:
            key = rest[rest.index("peer") + 1]
            if "remove" in rest:
                self.peers.pop(key, None)
            else:
                self.peers[key] = rest[rest.index("allowed-ips") + 1]
        if name == "nft" and rest == ["-f", "-"]:
            self.ruleset = stdin
        if name == "nft" and rest[:1] == ["delete"]:
            self.ruleset = None
        if name == "nft" and rest[:1] == ["list"]:
            return self.ruleset
        return ""


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

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.directory.cleanup()

    def pair(self, mode="persistent", ssh="0", minutes="60", port="51821", **request_options):
        result = self.broker.dispatch({"action": "pair", "request": pair_request(**request_options), "endpoint_host": "pbx.example.net",
                                       "listen_port": port, "mode": mode, "minutes": minutes, "ssh": ssh}, 1000)
        return result, decode_response(result["pairing_response"])

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
        self.assertIn("tcp dport 22 accept", self.net.ruleset)
        self.assertIn(str(network[2]), self.net.ruleset)
        self.assertNotIn("PrivateKey", (self.state / "workstations.json").read_text())
        self.assertNotIn("k" * 43, (self.state / "workstations.json").read_text())
        self.assertEqual((self.enrollment / "workstation-wg.key").stat().st_mode & 0o077, 0)

    def test_ruleset_limits_workstations_to_pbx_gui_and_approved_ssh(self):
        ruleset = broker_module.workstation_ruleset("100.70.1.1", [])
        self.assertIn('iifname "tlp-admin" ip daddr 100.70.1.1 tcp dport { 80, 443 } accept', ruleset)
        self.assertNotIn("dport 22", ruleset)
        self.assertIn('        iifname "tlp-admin" drop', ruleset)
        self.assertIn('        oifname "tlp-admin" drop', ruleset)
        self.assertTrue(ruleset.startswith("add table inet teliphones_workstations\ndelete table inet teliphones_workstations\n"))
        ruleset = broker_module.workstation_ruleset("100.70.1.1", ["100.70.1.3", "100.70.1.2"])
        self.assertIn("ip saddr { 100.70.1.2, 100.70.1.3 } ip daddr 100.70.1.1 tcp dport 22 accept", ruleset)
        self.assertLess(ruleset.index("dport 22 accept"), ruleset.index('iifname "tlp-admin" drop'))

    def test_temporary_pairing_expires_and_last_expiry_removes_interface(self):
        _, response = self.pair(mode="temporary", minutes="15")
        self.assertGreater(response["expires_at"], broker_module.time.time() + 14 * 60)
        self.assertTrue(self.net.link)
        state = json.loads((self.state / "workstations.json").read_text())
        state["workstations"][0]["expires_at"] = 1
        (self.state / "workstations.json").write_text(json.dumps(state))
        self.broker.expire_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.net.ruleset)
        self.assertEqual(self.broker.status()["workstations"]["items"], [])

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

    def test_revocation_removes_peer_and_last_revocation_removes_interface(self):
        _, first = self.pair()
        _, second = self.pair(public_key="B" * 42 + "E=", ssh="1")
        result = self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.assertTrue(result["ok"])
        self.assertEqual(set(self.net.peers), {"B" * 42 + "E="})
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        self.assertFalse(self.net.link)
        self.assertEqual(self.net.peers, {})
        self.assertIsNone(self.net.ruleset)

    def test_revocation_holds_even_when_network_update_fails(self):
        _, first = self.pair()
        self.pair(public_key="B" * 42 + "E=")
        self.net.fail = lambda name, rest: name == "nft" and rest == ["-f", "-"]
        with self.assertRaises(broker_module.BrokerError):
            self.broker.dispatch({"action": "unpair", "workstation_id": first["workstation_id"]}, 1000)
        self.assertFalse(self.net.link)
        self.assertNotIn(first["workstation_id"], [item["id"] for item in json.loads((self.state / "workstations.json").read_text())["workstations"]])

    def test_failed_interface_deletion_disables_traffic_and_preserves_firewall(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "ip" and rest[:2] == ["link", "del"]
        with self.assertRaisesRegex(broker_module.BrokerError, "disabled"):
            self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        self.assertTrue(self.net.link)
        self.assertFalse(self.net.up)
        self.assertIsNotNone(self.net.ruleset)
        self.assertIn("could not be confirmed", self.broker.workstation_error)
        self.net.fail = None
        self.assertTrue(self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)["ok"])
        self.assertFalse(self.net.link)

    def test_failed_firewall_cleanup_is_not_reported_as_success(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "nft" and rest[:1] == ["delete"]
        with self.assertRaisesRegex(broker_module.BrokerError, "cleanup"):
            self.broker.dispatch({"action": "unpair", "workstation_id": "all"}, 1000)
        self.assertFalse(self.net.link)
        self.assertIsNotNone(self.net.ruleset)

    def test_failed_pairing_fails_closed_and_restores_previous_state(self):
        self.net.fail = lambda name, rest: name == "wg" and "allowed-ips" in rest
        with self.assertRaisesRegex(broker_module.BrokerError, "removed"):
            self.pair()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.net.ruleset)
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
        self.assertEqual(set(status), {"ready", "requirements", "error", "listen_port", "pbx_address", "items"})
        item = status["items"][0]
        self.assertEqual(set(item), {"id", "name", "address", "mode", "ssh", "created_at", "expires_at", "fingerprint", "last_handshake"})
        self.assertTrue(item["fingerprint"].startswith("SHA256:"))
        self.assertEqual(item["last_handshake"], 0)
        self.assertNotIn("A" * 42, json.dumps(status))

    def test_handshake_status_is_read_only_and_does_not_claim_reachability(self):
        self.pair()
        self.net.handshakes["A" * 42 + "E="] = 1790000000
        self.net.calls = []
        status = self.broker.status()
        self.assertEqual(status["protocol"], 3)
        self.assertEqual(status["workstations"]["items"][0]["last_handshake"], 1790000000)
        self.assertEqual(self.net.calls, [("wg", ("show", broker_module.WORKSTATION_IFACE, "latest-handshakes"))])
        self.assertNotIn("A" * 42, json.dumps(status))

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
        restarted = broker_module.Broker()
        restarted.audit, restarted.run, restarted.tool = self.broker.audit, self.net.run, self.broker.tool
        restarted.restore_workstations()
        self.assertEqual(set(self.net.peers), {"B" * 42 + "E="})
        self.assertTrue(self.net.link)
