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

    def php(self, request, handler=None, page=False):
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
                command = (["php", str(MODULE / "tests/pairing-page.php"), str(path), json.dumps(request)] if page
                           else ["php", "-r", source, str(MODULE / "WebSupport.php"), str(path), json.dumps(request)])
                process = subprocess.run(command, env={**os.environ, "XDEBUG_MODE": "off"},
                                         capture_output=True, text=True, timeout=20)
            finally:
                thread.join(10)
                path.unlink()
            self.assertFalse(thread.is_alive(), "Socket handler must finish")
            if errors:
                raise errors[0]
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            if page:
                self.assertNotIn(request["request"], result["html"], "Pairing material must not be redisplayed")
                return result["notice"]
            return result

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

    @unittest.skipUnless(shutil.which("node"), "Node is required to execute the actual form script")
    def test_rendered_web_only_form_submits_through_php_page_and_actual_broker(self):
        result = subprocess.run(["node", str(MODULE / "tests/pairing-form.test.js"), "--post"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        post = json.loads(result.stdout)
        self.assertEqual(post["ssh"], "0")
        with self.assertRaisesRegex(broker.BrokerError, "Complete workstation pairing details"):
            broker.validate({key: value for key, value in post.items() if key not in ("token", "ssh")})
        response = self.php(post, page=True)
        self.assertTrue(response["ok"], response)
        decoded = helpers.decode_response(response["pairing_response"])
        self.assertFalse(decoded["ssh"])
        self.assertEqual(decoded["workstation_public_key"], broker.parse_pair_request(post["request"])["public_key"])
        self.assertTrue(self.net.up)
        state, _ = self.broker.workstation_state()
        self.assertEqual(len(state["workstations"]), 1)
        self.assertTrue(broker.policy_equal(self.broker.owned_table(), self.broker.expected_policy(state)))
        self.assertEqual(self.broker.monitor.pending, [])

        for field, value, message in [
                ("request", "TELIPHONES-PAIR-REQUEST-1:not-valid-json", "pairing request"),
                ("request", broker.PAIR_REQUEST_PREFIX + broker.b64url_encode(b'{}'), "malformed or incomplete"),
                ("listen_port", "70000", "WireGuard UDP port"),
                ("endpoint_host", "https://pbx.example.net", "hostname")]:
            with self.subTest(field=field, value=value):
                rejected = self.php({**post, field: value}, page=True)
                self.assertFalse(rejected["ok"], rejected)
                self.assertIn(message, rejected["error"])
                state, _ = self.broker.workstation_state()
                self.assertEqual(len(state["workstations"]), 1, "Rejected input must not mutate existing pairing")

    def test_pairing_failure_after_progress_reports_real_error_and_retains_fail_closed_cleanup(self):
        original = self.broker.reconcile_listener

        def listener(ports):
            if ports:
                self.broker.request_context.progress["stage"] = "Verifying FreePBX listener rules"
                threading.Event().wait(6)
                raise broker.BrokerError(
                    "FreePBX generated listener rules have not converged; reconciliation will retry. "
                    "fpbxsvc-newlistener UDP 52800: UDP ACCEPT missing; zone-external jump missing; "
                    "zone-internal jump missing; zone-other jump missing")
            return original(ports)

        self.broker.reconcile_listener = listener
        response = self.php(self.request())
        self.assertFalse(response["ok"])
        self.assertIn("FreePBX generated listener rules have not converged", response["error"])
        self.assertIn("fpbxsvc-newlistener UDP 52800: UDP ACCEPT missing", response["error"])
        self.assertIn("zone-other jump missing", response["error"])
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

    def test_original_listener_failure_and_cleanup_mismatch_both_reach_php(self):
        original = self.broker.run
        chain = "fpbxsvc-50dc73725c3e4073"

        def run(arguments, **kwargs):
            if arguments[:3] == [broker.FWCONSOLE, "teliphones", "listener"]:
                removing = arguments[-1] == "--listen-port=0"
                detail = (chain + " removal: service rules remain (1); zone-external jump remains"
                          if removing else chain + " UDP 51821: zone-other jump missing")
                failure = "FreePBX generated listener rules have not converged; reconciliation will retry. " + detail
                result = subprocess.CompletedProcess(arguments, 1, "PRIVATE-KEY-FIXTURE", failure)
                with patch.object(broker.subprocess, "run", return_value=result):
                    return broker.Broker.run(self.broker, arguments, **kwargs)
            return original(arguments, **kwargs)

        self.broker.run = run
        with self.assertLogs(broker.LOGGER, level="ERROR") as captured:
            response = self.php(self.request())
        self.assertFalse(response["ok"])
        self.assertIn("Initiating failure:", response["error"])
        self.assertIn("Listener admission ports=51821 exit=1", response["error"])
        self.assertIn("UDP 51821: zone-other jump missing", response["error"])
        self.assertIn("Workstation cleanup could not be confirmed", response["error"])
        self.assertIn("Listener removal ports=0 exit=1", response["error"])
        self.assertIn("removal: service rules remain (1)", response["error"])
        logs = "\n".join(captured.output)
        self.assertIn("listener admission failed", logs)
        self.assertIn("listener removal failed", logs)
        self.assertNotIn("PRIVATE-KEY-FIXTURE", json.dumps(response) + logs)
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertTrue(self.broker.workstation_cleanup_failed)
        self.assertTrue((self.state / "workstation-recovery.json").exists())
        self.broker.run = original
        self.broker.expire_workstations()
        state, _ = self.broker.workstation_state()
        self.assertEqual(state["workstations"], [])
        self.assertEqual(state["connection_state"], "open")
        self.assertEqual(self.net.peers, {})
        self.assertEqual(self.broker.workstation_error, "")

    def test_background_cannot_recreate_open_listener_during_pairing_cleanup(self):
        state, _ = self.broker.workstation_state()
        state.update(subnet="100.70.1.0/24", listen_port=51821)
        self.broker.apply_workstations(state)
        self.broker.save_workstations(state)
        original = self.broker.reconcile_listener
        calls, errors, contenders = [], [], []
        attempted = threading.Event()
        failed = []
        background = []

        def reconcile():
            acquired = self.broker.wslock.acquire(blocking=False)
            contenders.append(acquired)
            if acquired:
                self.broker.wslock.release()
            attempted.set()
            try:
                self.broker.expire_workstations()
            except Exception as error:
                errors.append(error)

        def listener(ports):
            calls.append((threading.current_thread().name, ports))
            if ports and not failed:
                failed.append(True)
                raise broker.BrokerError("Listener admission fixture failed")
            if ports == 0:
                self.assertFalse(self.net.up)
                worker = threading.Thread(target=reconcile, name="background-listener")
                background.append(worker)
                worker.start()
                self.assertTrue(attempted.wait(5), "Background must contend for the held policy lock")
                self.assertEqual(contenders, [False])
                self.assertFalse(any(name == "background-listener" for name, _ in calls))
            return original(ports)

        self.broker.reconcile_listener = listener
        try:
            with self.assertRaisesRegex(broker.BrokerError, "Listener admission fixture failed"):
                self.broker.dispatch(self.request(), os.getuid())
        finally:
            for worker in background:
                worker.join(5)
                self.assertFalse(worker.is_alive(), "Reconciliation must finish after rollback releases the lock")
        self.assertEqual(errors, [])
        self.assertEqual([ports for name, ports in calls if name != "background-listener"],
                         [[51821], 0, [51821]])
        self.assertEqual(calls[-1], ("background-listener", [51821]))
        state, _ = self.broker.workstation_state()
        self.assertEqual(state["connection_state"], "open")
        self.assertEqual(state["workstations"], [])
        self.assertEqual(self.net.peers, {})
        self.assertFalse(self.broker.workstation_cleanup_failed)
        self.assertEqual(self.broker.workstation_error, "")
        self.broker.reconcile_listener = original
        response = self.php(self.request())
        self.assertTrue(response["ok"], response)
        self.assertTrue(self.net.peers)

    def test_listener_output_whitelist_never_echoes_arbitrary_stderr(self):
        for output in ("PRIVATE-KEY-FIXTURE", "Listener reconciliation failed: TOKEN-FIXTURE",
                       "FreePBX generated listener rules have not converged; reconciliation will retry. TOKEN-FIXTURE"):
            self.assertIn("withheld", broker.listener_failure_output(output))
        self.assertEqual(broker.listener_failure_output(" \n"), "empty")
        self.assertIn("withheld", broker.listener_failure_output(b"PRIVATE-KEY-FIXTURE"))

    def test_listener_policy_restoration_failure_retains_initiating_error(self):
        original = self.broker.reconcile_listener
        failures = []

        def listener(ports):
            if ports:
                failures.append(True)
                raise broker.BrokerError("Admission fixture failed" if len(failures) == 1
                                        else "Policy restoration fixture failed")
            return original(ports)

        self.broker.reconcile_listener = listener
        response = self.php(self.request())
        self.assertFalse(response["ok"])
        self.assertIn("Initiating failure:", response["error"])
        self.assertIn("Admission fixture failed", response["error"])
        self.assertIn("Pairing rollback failed", response["error"])
        self.assertIn("Policy restoration fixture failed", response["error"])
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertEqual(self.broker.workstation_state()[0]["workstations"], [])

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

    def test_revocation_crosses_five_seconds_and_persists_retrievable_outcome(self):
        response = self.broker.dispatch(self.request(), os.getuid())
        identifier = helpers.decode_response(response["pairing_response"])["workstation_id"]
        original = self.broker.reconcile_listener

        def delayed(ports):
            operation = self.broker.revocation_status()
            self.assertEqual(operation["state"], "running")
            self.assertTrue(operation["stage"])
            threading.Event().wait(6)
            return original(ports)

        with patch.object(self.broker, "reconcile_listener", side_effect=delayed):
            response = self.php({"action": "unpair", "workstation_id": identifier})
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["outcome"], "complete")
        self.assertEqual(self.net.peers, {})
        with patch.object(self.broker, "workstation_status", return_value={}):
            status = self.php({"action": "status"})["status"]["workstation_revocation"]
        self.assertEqual(status["id"], response["operation_id"])
        self.assertEqual(status["outcome"], "complete")

    def test_revocation_progress_while_waiting_for_workstation_lock(self):
        self.broker.dispatch(self.request(), os.getuid())
        held = threading.Event()
        release = threading.Event()

        def lock():
            with self.broker.wslock:
                held.set()
                release.wait(10)

        worker = threading.Thread(target=lock)
        worker.start()
        self.assertTrue(held.wait(5))
        client, server = socket.socketpair()
        thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
        try:
            with client:
                client.settimeout(4)
                client.sendall(b'{"action":"unpair","workstation_id":"all","progress":true}\n')
                thread.start()
                frame = json.loads(client.recv(4096))
                self.assertEqual(frame, {"progress": "Waiting for workstation policy lock"})
                release.set()
                data = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                self.assertTrue(json.loads(data.splitlines()[-1])["ok"])
        finally:
            release.set()
            worker.join(5)
            if thread.ident:
                thread.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(thread.is_alive())

    def test_browser_disconnect_does_not_cancel_revocation_and_status_recovers_result(self):
        self.broker.dispatch(self.request(), os.getuid())
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()
        original = self.broker.unpair

        def delayed(request, uid):
            entered.set()
            self.assertTrue(release.wait(10))
            try:
                return original(request, uid)
            finally:
                completed.set()

        client, server = socket.socketpair()
        thread = threading.Thread(target=broker.handle_connection, args=(self.broker, server, os.getuid()))
        with patch.object(self.broker, "unpair", side_effect=delayed):
            try:
                client.sendall(b'{"action":"unpair","workstation_id":"all","progress":true}\n')
                thread.start()
                self.assertTrue(entered.wait(5))
                client.close()
                thread.join(4)
                self.assertFalse(thread.is_alive(), "Transport may exit while the accepted operation continues")
                release.set()
                self.assertTrue(completed.wait(5))
                with self.broker.wslock:
                    pass
            finally:
                release.set()
                client.close()
                if thread.ident:
                    thread.join(5)
        with patch.object(self.broker, "workstation_status", return_value={}):
            status = self.php({"action": "status"})["status"]["workstation_revocation"]
        self.assertEqual(status["action"], "unpair")
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(status["outcome"], "complete")
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
