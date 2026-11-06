"""Workstation public-address changes (WireGuard roaming) with the actual broker policy and admission code."""
import copy
import json
import re
import threading
import time
import unittest
from unittest.mock import patch

import test_support_broker as helpers

broker = helpers.broker_module


class RoamingTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    pair = helpers.WorkstationPairingTests.pair
    open_session = helpers.WorkstationPairingTests.open_session

    def roam(self, response, endpoint):
        key = response["workstation_public_key"]
        self.net.endpoints[key] = endpoint
        self.net.handshakes[key] = int(time.time())

    def firewall_writes(self):
        return [call for call in self.net.calls if call[0] in ("nft", "iptables", "ip6tables", broker.FWCONSOLE)
                and not any(word in ("list", "-S", "-L", "monitor") for word in call[1])]

    def test_unrestricted_gui_only_admission_survives_public_address_change(self):
        _, response = self.pair()
        address = response["address"].split("/")[0]
        self.roam(response, "203.0.113.10:50000")
        self.assertTrue(self.open_session(response)["active"])
        table = copy.deepcopy(self.net.table)
        peers = copy.deepcopy(self.net.peers)
        policy = json.dumps(table, sort_keys=True)
        self.assertNotIn("203.0.113.10", policy)
        self.net.calls.clear()
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        baseline = self.firewall_writes()
        self.assertFalse([call for call in baseline if call[0] == "nft"])

        # Network change during an active session: only the outer endpoint and handshake change.
        self.roam(response, "198.51.100.77:61000")
        self.net.calls.clear()
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        self.assertEqual(self.firewall_writes(), baseline)
        self.assertEqual(self.net.table, table)
        self.assertEqual(self.net.peers, peers)
        lease = self.open_session(response)
        self.assertTrue(lease["active"])
        self.assertEqual(self.net.table, table)
        self.assertNotIn("198.51.100.77", json.dumps(self.net.table, sort_keys=True))
        self.assertIn(response["workstation_id"], self.broker.active_sessions())

        # Network change before reconnection: release, move, then admit from the new address.
        self.broker.workstation_session("release", address)
        self.assertNotIn(response["workstation_id"], self.broker.active_sessions())
        self.roam(response, "[2001:db8::77]:62000")
        self.assertTrue(self.open_session(response)["active"])
        self.assertTrue(broker.policy_equal(self.net.table, table))
        self.assertNotIn("2001:db8::77", json.dumps(self.net.table, sort_keys=True))
        self.assertTrue(broker.policy_equal(self.net.table,
                                            self.broker.expected_policy(self.broker.workstation_state()[0])))

    def test_lost_handshake_does_not_revoke_or_block_admission_once_tunnel_returns(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        self.assertTrue(self.open_session(response)["active"])
        table = copy.deepcopy(self.net.table)
        # No handshake for longer than the Windows freshness threshold (the outer path is down).
        self.net.handshakes[response["workstation_public_key"]] = int(time.time()) - 600
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        self.assertEqual(self.net.table, table)
        self.assertIn(response["workstation_public_key"], self.net.peers)
        state, _ = self.broker.workstation_state()
        self.assertTrue(any(item["id"] == response["workstation_id"] for item in state["workstations"]))
        # WireGuard re-handshakes from the new network; the existing pairing is admitted without re-pairing.
        self.roam(response, "198.51.100.77:61000")
        self.assertTrue(self.open_session(response)["active"])


    def events(self, response, event=None):
        records = self.broker.diagnostics.read("ws-" + response["workstation_id"])
        return [record for record in records if event is None or record["event"] == event]

    def request(self, response, action="heartbeat", attempt="0123456789abcdef", delivered=True):
        """One session-controller request through the same path the HTTP handler uses."""
        state, _ = self.broker.workstation_state()
        item = next(entry for entry in state["workstations"] if entry["id"] == response["workstation_id"])
        with patch.object(self.broker.ssh, "host_key", return_value=None), \
                patch.object(self.broker.ssh, "initialise", return_value=None):
            status, body, trace = self.broker.session_request(action, item["address"].split("/")[0], attempt=attempt)
        self.broker.record_session_request(trace, delivered)
        return status, body, trace

    def test_admission_outcomes_are_recorded_with_timing_and_correlation_but_no_addresses(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        status, body, trace = self.request(response)
        self.assertEqual((status, body["ok"], trace["result"]), (200, True, "admitted"))
        [admitted] = self.events(response, "session.request")
        self.assertEqual(admitted["data"]["result"], "admitted")
        self.assertEqual(admitted["data"]["attempt"], "0123456789abcdef")
        self.assertTrue(admitted["data"]["delivered"])
        self.assertIsInstance(admitted["data"]["processing_ms"], int)
        self.assertTrue(admitted["timestamp_utc"].endswith("Z"))
        # Fast renewals are not recorded, so seven days of retention is not consumed by a 2-second heartbeat.
        self.request(response)
        self.assertEqual(len(self.events(response, "session.request")), 1)
        # An answer Windows never received is the PBX-admitted/Windows-timeout split; it is always recorded.
        self.roam(response, "198.51.100.77:61000")
        self.request(response, delivered=False)
        undelivered = self.events(response, "session.request")[-1]["data"]
        self.assertEqual((undelivered["result"], undelivered["delivered"]), ("renewed", False))
        # Only a random 16-hex attempt id is accepted; anything else is dropped rather than stored.
        _, _, trace = self.request(response, attempt="../../etc/passwd", delivered=False)
        self.assertIsNone(trace["attempt"])
        self.assertIsNone(self.events(response, "session.request")[-1]["data"]["attempt"])
        recorded = json.dumps(self.events(response))
        for secret in ("203.0.113.10", "198.51.100.77", response["workstation_public_key"]):
            self.assertNotIn(secret, recorded)

    def test_workstation_lock_contention_is_recorded_and_reporting_reads_do_not_hold_it(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        self.request(response)
        held = threading.Event()
        release = threading.Event()

        def background():
            with self.broker.wslock:
                held.set()
                release.wait(5)

        worker = threading.Thread(target=background)
        worker.start()
        held.wait(5)
        threading.Timer(2.2, release.set).start()
        _, body, trace = self.request(response)
        worker.join()
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(trace["lock_wait_ms"], 2000)
        slow = self.events(response, "session.request")[-1]["data"]
        self.assertEqual(slow["result"], "renewed")
        self.assertGreaterEqual(slow["lock_wait_ms"], 2000)

        observed = []
        original = self.broker.verified_workstation_source

        def verified(item):
            probe = threading.Thread(target=lambda: observed.append(self.broker.wslock.acquire(timeout=1)
                                                                     and (self.broker.wslock.release() or True)))
            probe.start()
            probe.join()
            return original(item)

        with patch.object(self.broker, "verified_workstation_source", side_effect=verified):
            _, body, _ = self.request(response)
        self.assertEqual(observed, [True])
        self.assertEqual(body["policy"]["current_source"], "203.0.113.10/32")

    def test_reconnect_from_new_address_at_limit_is_the_same_workstation_and_limits_still_apply(self):
        _, first = self.pair()
        _, second = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22)
        state, _ = self.broker.workstation_state()
        self.assertEqual(state["max_sessions"], 1)
        self.roam(first, "203.0.113.10:50000")
        self.assertEqual(self.request(first)[2]["result"], "admitted")
        # Windows closed without releasing (crash or forced exit), the network changed, and TELIPHONES relaunched
        # before the lease expired: the same workstation identity renews rather than counting twice.
        self.roam(first, "198.51.100.77:61000")
        status, body, trace = self.request(first, attempt="fedcba9876543210")
        self.assertEqual((status, trace["result"], body["connected_workstations"]), (200, "renewed", 1))
        # A genuinely different workstation is still refused at the limit, with the reason recorded for it.
        self.roam(second, "192.0.2.5:40000")
        status, body, trace = self.request(second)
        self.assertEqual((status, trace["reason"]), (409, "session-limit"))
        self.assertIn("Session limit reached", body["error"])
        self.assertEqual(self.events(second, "session.request")[-1]["data"]["reason"], "session-limit")
        # Repeated identical refusals within a minute are not re-recorded.
        self.request(second)
        self.assertEqual(len(self.events(second, "session.request")), 1)
        self.assertEqual(self.broker.dispatch({"action": "workstation-limit", "maximum": "2"}, 1000)["ok"], True)
        self.assertEqual(self.request(second)[2]["result"], "admitted")
        self.assertEqual(self.broker.workstation_status()["connected_workstations"], 2)
        self.assertEqual(self.request(first, action="release")[2]["result"], "released")
        self.assertEqual(self.broker.workstation_status()["connected_workstations"], 1)

    def test_broker_restart_clears_leases_and_keeps_evidence_and_the_pairing(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        self.request(response)
        before = self.events(response)
        # A restart starts with no leases, exactly as main() does, and a fresh diagnostics instance.
        restarted = broker.Broker()
        restarted.audit = self.broker.audit
        restarted.run = self.net.run
        restarted.tool = self.broker.tool
        restarted.iptables_tool = self.broker.iptables_tool
        restarted.save_active_sessions({})
        self.assertEqual(restarted.diagnostics.read("ws-" + response["workstation_id"]), before)
        self.broker = restarted
        with patch.object(self.broker.ssh, "reconcile"):
            self.roam(response, "198.51.100.77:61000")
            status, body, trace = self.request(response)
        self.assertEqual((status, trace["result"]), (200, "admitted"))
        self.assertEqual(len(self.events(response, "session.request")), 2)

    def test_unexpected_controller_failure_answers_and_is_recorded(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        with patch.object(self.broker, "reconcile_policy_only", side_effect=RuntimeError("unexpected")), \
                self.assertLogs(broker.LOGGER, "ERROR"):
            status, body, trace = self.request(response)
        self.assertEqual((status, body["ok"], trace["result"]), (500, False, "failed"))
        self.assertIn("PBX session controller failed", body["error"])
        self.assertNotIn("unexpected", body["error"])
        self.assertEqual(self.events(response, "session.request")[-1]["data"]["result"], "failed")

    def test_background_reconciliation_failure_and_recovery_are_recorded(self):
        _, response = self.pair()
        self.roam(response, "203.0.113.10:50000")
        self.request(response)
        self.broker.workstation_retry_at = 0
        with patch.object(self.broker, "reconcile_integration", side_effect=broker.BrokerError("injected")), \
                self.assertLogs(broker.LOGGER, "WARNING"):
            self.broker.expire_workstations()
        failed = self.events(response, "reconcile.background")[-1]["data"]
        self.assertEqual((failed["result"], failed["retry_seconds"]), ("failed", 5))
        self.broker.workstation_retry_at = 0
        self.broker.workstation_retry_policy = None
        self.broker.expire_workstations()
        self.assertEqual(self.events(response, "reconcile.background")[-1]["data"]["result"], "recovered")
        # The pairing survives and the same workstation is admitted again without re-pairing.
        self.assertEqual(self.request(response)[0], 200)

    def test_controller_listener_state_is_recorded(self):
        _, response = self.pair()
        self.broker.session_server_enabled = True
        with patch.object(broker, "ThreadingHTTPServer", side_effect=OSError("address unavailable")):
            with self.assertRaises(OSError):
                self.broker.reconcile_session_servers()
        self.assertEqual(self.events(response, "controller.state")[-1]["data"]["state"], "failed")

        class Server:
            def __init__(self, address, handler):
                self.server_address = address

            def serve_forever(self):
                return None

            def shutdown(self):
                return None

            def server_close(self):
                return None

        with patch.object(broker, "ThreadingHTTPServer", Server):
            self.broker.reconcile_session_servers()
        self.assertEqual(self.events(response, "controller.state")[-1]["data"]["state"], "listening")
        self.broker.session_servers.clear()

    def test_pbx_gui_sanitiser_mirrors_every_broker_diagnostic_event(self):
        source = (helpers.Path(__file__).resolve().parents[2] / "teliphones" / "WebSupport.php").read_text()
        body = source[source.index("function sanitiseDiagnostics"):source.index("$events = [];", source.index("function sanitiseDiagnostics"))]
        parts = re.split(r"'([a-z]+\.[a-z]+)' => ", body)
        php = dict(zip(parts[1::2], parts[2::2]))
        self.assertEqual(set(php), set(broker.DiagnosticLog.EVENT_FIELDS))
        for event, fields in broker.DiagnosticLog.EVENT_FIELDS.items():
            self.assertEqual(set(re.findall(r"'([a-z_]+)' =>", php[event])), set(fields), event)

if __name__ == "__main__":
    unittest.main()
