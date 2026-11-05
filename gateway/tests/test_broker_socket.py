"""Actual PHP/Unix-socket framing with modelled broker network operations, not a live PBX."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import test_support_broker as helpers

broker = helpers.broker_module
MODULE = Path(broker.__file__).parent


@unittest.skipUnless(shutil.which("php"), "PHP is required for the Unix-socket integration")
class BrokerSocketTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown

    def request(self):
        return {"action": "pair", "request": helpers.pair_request(), "endpoint_host": "pbx.example.net",
                "listen_port": "51821", "mode": "persistent", "minutes": "60", "ssh": "0"}

    def php(self, request, handler=None):
        path = Path(self.directory.name) / "broker.sock"
        errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            server.settimeout(10)

            def serve():
                try:
                    connection, _ = server.accept()
                    if handler is None:
                        broker.handle_connection(self.broker, connection, os.getuid())
                    else:
                        with connection:
                            handler(connection)
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                source = ('require $argv[1]; $client = new \\FreePBX\\modules\\Teliphones\\WebSupport($argv[2]);'
                          ' echo json_encode($client->request(json_decode($argv[3], true)), JSON_THROW_ON_ERROR);')
                process = subprocess.run(["php", "-r", source, str(MODULE / "WebSupport.php"), str(path),
                                          json.dumps(request)], env={**os.environ, "XDEBUG_MODE": "off"},
                                         capture_output=True, text=True, timeout=20)
            finally:
                thread.join(10)
                path.unlink()
            self.assertFalse(thread.is_alive(), "Socket handler must finish")
            if errors:
                raise errors[0]
            self.assertEqual(process.returncode, 0, process.stderr)
            return json.loads(process.stdout)

    @staticmethod
    def read_request(connection):
        data = bytearray()
        while b"\n" not in data:
            part = connection.recv(4096)
            if not part:
                raise AssertionError("No complete PHP request")
            data.extend(part)
        return json.loads(data)

    def test_pairing_crosses_five_second_boundary_without_admitting_before_verification(self):
        original = self.broker.run
        checked = []

        def run(arguments, **kwargs):
            if arguments[:3] == [broker.FWCONSOLE, "teliphones", "listener"] and not checked:
                self.broker.request_context.progress["stage"] = "Verifying FreePBX listener rules"
                # Model the real asynchronous FreePBX-rule convergence beyond PHP's old 5 s deadline.
                self.assertFalse(self.net.up)
                threading.Event().wait(6)
                self.assertFalse(self.net.up)
                checked.append(True)
            return original(arguments, **kwargs)

        self.broker.run = run
        start = time.monotonic()
        response = self.php(self.request())
        self.assertGreaterEqual(time.monotonic() - start, 6)
        self.assertTrue(checked)
        self.assertTrue(response["ok"], response)
        decoded = helpers.decode_response(response["pairing_response"])
        self.assertEqual(decoded["workstation_public_key"], broker.parse_pair_request(self.request()["request"])["public_key"])
        self.assertTrue(self.net.up)
        self.assertTrue(self.net.peers)
        self.assertEqual(self.broker.monitor.pending, [])
        state, _ = self.broker.workstation_state()
        self.assertTrue(broker.policy_equal(self.broker.owned_table(), self.broker.expected_policy(state)))

    def test_pairing_failure_after_progress_reports_real_error_and_retains_fail_closed_cleanup(self):
        original = self.broker.reconcile_listener

        def listener(ports):
            if ports:
                self.broker.request_context.progress["stage"] = "Verifying FreePBX listener rules"
                threading.Event().wait(6)
                raise broker.BrokerError("FreePBX generated listener rules have not converged; reconciliation will retry.")
            return original(ports)

        self.broker.reconcile_listener = listener
        response = self.php(self.request())
        self.assertFalse(response["ok"])
        self.assertIn("FreePBX generated listener rules have not converged", response["error"])
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertEqual(self.broker.monitor.pending, [])

    def test_real_command_timeout_survives_pairing_cleanup_and_rollback(self):
        original = self.broker.run

        def run(arguments, **kwargs):
            if arguments[:3] == [broker.FWCONSOLE, "teliphones", "listener"] and arguments[-1] != "0":
                with patch.object(broker.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                        arguments, 60, stderr="PRIVATE-KEY-FIXTURE")):
                    return broker.Broker.run(self.broker, arguments, **kwargs)
            return original(arguments, **kwargs)

        self.broker.run = run
        with self.assertLogs(broker.LOGGER, level="ERROR") as captured:
            response = self.php(self.request())
        self.assertFalse(response["ok"])
        self.assertIn("FreePBX listener verification timed out after 60 seconds", response["error"])
        self.assertIn("TimeoutExpired", str(captured.output))
        self.assertNotIn("PRIVATE-KEY-FIXTURE", json.dumps(response) + str(captured.output))
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertEqual(self.broker.monitor.pending, [])

    def test_missing_and_malformed_frames_are_distinguished_without_echoing_contents(self):
        for payload, expected in [
            (b"", "closed or failed to read"),
            (b'{"ok":true', "closed or failed to read"),
            (b"PRIVATE-KEY-FIXTURE\n", "not a JSON object"),
            (b'{"progress":"PRIVATE-KEY-FIXTURE"}\n', "invalid progress framing"),
            (b'{"progress":"Verifying FreePBX listener rules"}\n', "closed or failed to read"),
            (b'[]\n', "missing its success/failure"),
            (b'{"ok":"true"}\n', "missing its success/failure"),
            (b"x" * 131072, "exceeded the 128 KiB limit"),
        ]:
            with self.subTest(expected=expected):
                def send(connection):
                    self.read_request(connection)
                    if payload:
                        connection.sendall(payload)
                response = self.php(self.request(), send)
                self.assertFalse(response["ok"])
                self.assertIn(expected, response["error"])
                self.assertNotIn("PRIVATE-KEY-FIXTURE", json.dumps(response))

    def test_socket_inactivity_is_not_reported_as_invalid_json(self):
        def stalled(connection):
            self.read_request(connection)
            threading.Event().wait(6)
        response = self.php(self.request(), stalled)
        self.assertFalse(response["ok"])
        self.assertIn("timed out after five seconds without progress", response["error"])
        self.assertIn("outcome is unconfirmed", response["error"])
        self.assertEqual(self.net.peers, {})

    def test_fragmented_progress_and_final_response_are_read_completely(self):
        def send(connection):
            request = self.read_request(connection)
            self.assertIs(request.pop("progress"), True)
            self.assertEqual(request, self.request())
            for chunk in [b'{"pro', b'gress":"Verifying FreePBX listener rules"}\n',
                          b'{"ok":false,', b'"error":"Confirmed listener failure."}\n']:
                connection.sendall(chunk)
        response = self.php(self.request(), send)
        self.assertEqual(response, {"ok": False, "error": "Confirmed listener failure."})

    def test_older_root_helper_returns_update_instruction_not_invalid_response(self):
        def send(connection):
            request = self.read_request(connection)
            with self.assertRaises(broker.BrokerError):
                broker.validate(request)  # Old helpers passed the transport field straight into validation.
            connection.sendall(b'{"ok":false,"error":"Unexpected TELIPHONES input."}\n')
        response = self.php(self.request(), send)
        self.assertFalse(response["ok"])
        self.assertIn("Rerun Complete Installation", response["error"])
        self.assertEqual(self.net.peers, {})

    def test_process_timeout_unexpected_exception_and_serialization_failure_return_safe_json(self):
        for error in [subprocess.TimeoutExpired(["wg", "PRIVATE-KEY-FIXTURE"], 20, stderr="SECRET"),
                      TypeError("PRIVATE-KEY-FIXTURE"), broker.ssh.SshError("PRIVATE-KEY-FIXTURE"),
                      OSError(13, "PRIVATE-KEY-FIXTURE")]:
            with self.subTest(error=type(error).__name__), patch.object(self.broker, "dispatch", side_effect=error):
                with self.assertLogs(broker.LOGGER, level="ERROR") as captured:
                    response = self.php(self.request())
                self.assertFalse(response["ok"])
                self.assertNotIn("PRIVATE-KEY-FIXTURE", json.dumps(response) + str(captured.output))
                self.assertNotIn("SECRET", json.dumps(response) + str(captured.output))
                self.assertIn(type(error).__name__, str(captured.output))
        with patch.object(self.broker, "dispatch", return_value={"ok": True, "result": object()}):
            with self.assertLogs(broker.LOGGER, level="ERROR"):
                response = self.php(self.request())
            self.assertFalse(response["ok"])
            self.assertIn("TypeError", response["error"])

    def test_legacy_socket_client_still_gets_exactly_one_response(self):
        client, server = socket.socketpair()
        with client:
            client.sendall(json.dumps({"action": "status"}).encode() + b"\n")
            thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
            thread.start()
            data = bytearray()
            while True:
                part = client.recv(4096)
                if not part:
                    break
                data.extend(part)
            thread.join(5)
        self.assertEqual(data.count(b"\n"), 1)
        response = json.loads(data)
        self.assertTrue(response["ok"])
        self.assertEqual(response["status"]["protocol"], 12)

    def test_legacy_five_second_reader_times_out_while_verified_pairing_completes(self):
        original = self.broker.reconcile_listener
        checked = threading.Event()

        def listener(ports):
            if ports:
                self.assertFalse(self.net.up)
                checked.set()
                threading.Event().wait(6)
            return original(ports)

        self.broker.reconcile_listener = listener
        client, server = socket.socketpair()
        with client:
            client.settimeout(5)  # Exact deadline used by the previous PHP reader, without progress opt-in.
            client.sendall(json.dumps(self.request()).encode() + b"\n")
            thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
            thread.start()
            try:
                self.assertTrue(checked.wait(1))
                with self.assertRaises(socket.timeout):
                    client.recv(131073)
                self.assertFalse(self.net.up)
                response = json.loads(client.recv(131073))
                self.assertTrue(response["ok"], response)
                self.assertTrue(self.net.up)
            finally:
                thread.join(10)

    def test_disconnected_client_does_not_interrupt_or_repeat_verified_pairing(self):
        entered, release = threading.Event(), threading.Event()
        original = self.broker.reconcile_listener
        calls = []

        def listener(ports):
            if ports:
                calls.append(ports)
                entered.set()
                if not release.wait(5):
                    raise AssertionError("Test did not release listener verification")
            return original(ports)

        self.broker.reconcile_listener = listener
        client, server = socket.socketpair()
        client.sendall(json.dumps({**self.request(), "progress": True}).encode() + b"\n")
        thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertFalse(self.net.up)
            self.assertTrue(client.recv(4096))
            client.close()
            with self.assertLogs(broker.LOGGER, level="ERROR"):
                thread.join(3)  # Next progress send observes the closed peer, not a transaction cancellation.
            self.assertFalse(thread.is_alive())
            self.assertFalse(self.net.up)
        finally:
            client.close()
            release.set()
        # Acquiring the actual pairing lock synchronizes with completion of the continuing worker.
        with self.broker.wslock:
            state, _ = self.broker.workstation_state()
            self.assertEqual(len(state["workstations"]), 1)
            self.assertTrue(self.net.up)
            self.assertEqual(len(calls), 1)
            self.assertEqual(self.broker.monitor.pending, [])

    def test_progress_flag_is_pair_only_and_boolean(self):
        for request in [{"action": "status", "progress": True}, {**self.request(), "progress": "true"}]:
            with self.subTest(request=request["action"]), patch.object(self.broker, "dispatch") as dispatch:
                client, server = socket.socketpair()
                with client:
                    client.sendall(json.dumps(request).encode() + b"\n")
                    thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
                    thread.start()
                    response = json.loads(client.recv(4096))
                    thread.join(5)
                self.assertFalse(response["ok"])
                self.assertIn("Progress framing is available only", response["error"])
                dispatch.assert_not_called()

    def test_untrusted_peer_cannot_enable_progress_or_dispatch(self):
        client, server = socket.socketpair()
        with client, patch.object(self.broker, "dispatch") as dispatch:
            client.sendall(json.dumps({**self.request(), "progress": True}).encode() + b"\n")
            # Different UID; peer checking happens before accepting transport options or dispatching.
            thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid() + 1))
            thread.start()
            response = json.loads(client.recv(4096))
            thread.join(5)
            self.assertFalse(response["ok"])
            self.assertIn("Only the configured FreePBX web service account", response["error"])
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
