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
        self.run_work({"action": "dependencies"})
        self.assertEqual(self.calls, [["/usr/bin/apt-get", "-y", "--no-install-recommends", "install", "wireguard-tools"]])

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
