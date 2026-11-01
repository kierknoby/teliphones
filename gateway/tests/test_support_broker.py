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
