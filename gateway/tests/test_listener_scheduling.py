"""Production scheduling with modelled FreePBX generation; no live PBX changes."""
import json
import unittest
from unittest.mock import patch

import test_support_broker as helpers

broker = helpers.broker_module


class ListenerSchedulingTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown

    def test_open_without_authorisations_keeps_listener_closed(self):
        self.net.freepbx()
        self.broker.configure_workstation_policy({"state": "open"}, 1000)
        before = [call for call in self.net.calls if call[0] == broker.FWCONSOLE]
        for _ in range(100):
            self.broker.expire_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.net.table)
        self.assertEqual(self.broker.workstation_state()[0]["connection_state"], "open")
        self.assertEqual([call for call in self.net.calls if call[0] == broker.FWCONSOLE], before)

    def open_paired(self):
        self.net.freepbx()
        self.commands = []
        self.generated = {}
        self.fail_listener = False
        self.fail_ports = None
        original = self.broker.run

        def run(arguments, **kwargs):
            if arguments[:3] == [broker.FWCONSOLE, "teliphones", "listener"]:
                ports = arguments[-1].split("=", 1)[1]
                self.commands.append(ports)
                if self.fail_listener or ports == self.fail_ports:
                    raise broker.BrokerError("FreePBX listener fixture failed")
                for chain in self.generated.values():
                    self.net.filter.pop(chain, None)
                    for zone in ("external", "internal", "other"):
                        self.net.filter["zone-" + zone] = [
                            rule for rule in self.net.filter.get("zone-" + zone, [])
                            if rule != ["-j", chain]]
                self.generated = {}
                services = {}
                for port in [] if ports == "0" else ports.split(","):
                    identifier = ("%016x" % int(port)) + "0" * 16
                    chain = "fpbxsvc-" + identifier[:16]
                    self.generated[port] = chain
                    services[port] = {"id": identifier, "name": "TELIPHONES WireGuard listener (managed) fixture"}
                    self.net.filter[chain] = [("-p udp -m udp --dport %s -j ACCEPT" % port).split()]
                    for zone in ("external", "internal", "other"):
                        self.net.filter.setdefault("zone-" + zone, []).append(["-j", chain])
                journal = self.state / "firewall-listener.json"
                if services:
                    snapshot = self.net.iptables(["-w", "5", "-S"])
                    digest = broker.hashlib.sha256((snapshot + "\0" + snapshot).encode()).hexdigest()
                    broker.atomic(journal, json.dumps({"services": services, "verified_rules_sha256": digest}))
                else:
                    journal.unlink(missing_ok=True)
                if self.broker.monitor:
                    self.broker.monitor.event({"add": {"rule": {
                        "family": "ip", "table": "filter", "chain": "zone-external"}}})
                return ""
            return original(arguments, **kwargs)

        self.broker.run = run
        helpers.WorkstationPairingTests.pair(self)
        self.expected_peers = dict(self.net.peers)
        self.expected_workstations = self.broker.workstation_state()[0]["workstations"]
        self.assertEqual(self.commands, ["51821"])

    def test_idle_authorised_listener_does_not_spawn_listener_on_periodic_or_self_events(self):
        self.open_paired()
        for _ in range(240):
            self.broker.expire_workstations()
        self.assertEqual(self.commands, ["51821"], "One hour of 15-second ticks must not reload FreePBX")
        for _ in range(100):
            self.broker.monitor.event({"add": {"rule": {
                "family": "ip", "table": "filter", "chain": "zone-external"}}})
        self.broker.expire_workstations()
        self.assertEqual(self.commands, ["51821"], "Repeated notifications must not invoke an unchanged listener")
        self.assertEqual(self.broker.workstation_state()[0]["workstations"], self.expected_workstations)
        self.assertEqual(self.net.peers, self.expected_peers)

    def test_real_rule_change_repairs_once_then_becomes_idle(self):
        self.open_paired()
        chain = self.generated["51821"]
        self.net.filter["zone-other"].remove(["-j", chain])
        self.broker.monitor.event({"delete": {"rule": {
            "family": "ip", "table": "filter", "chain": "zone-other"}}})
        self.broker.expire_workstations()
        self.assertEqual(self.commands, ["51821", "51821"])
        for _ in range(20):
            self.broker.expire_workstations()
        self.assertEqual(len(self.commands), 2)

    def test_successful_freepbx_notification_feedback_reaches_quiescence(self):
        self.open_paired()
        cycles = 0
        while self.broker.wake.is_set() and cycles < 20:
            self.broker.wake.clear()
            self.broker.expire_workstations()
            cycles += 1
        self.assertLess(cycles, 20, "Listener success must not perpetually re-wake its own worker")
        self.assertFalse(self.broker.wake.is_set())
        self.assertEqual(self.commands, ["51821"])

    def test_failed_listener_is_rate_limited_under_event_storm_and_recovers(self):
        self.open_paired()
        self.net.filter[self.generated["51821"]] = []
        self.fail_listener = True
        clock = [100.0]
        with patch.object(broker.time, "monotonic", side_effect=lambda: clock[0]):
            self.broker.expire_workstations()
            initial = len(self.commands)
            self.assertFalse(self.net.up)
            for _ in range(100):
                self.broker.wake.set()
                self.broker.expire_workstations()
            self.assertEqual(len(self.commands), initial)
            for delay in (5, 10, 20, 40, 60, 60):
                clock[0] += delay - 0.1
                self.broker.expire_workstations()
                self.assertEqual(len(self.commands), initial)
                clock[0] += 0.1
                self.broker.expire_workstations()
                # Admission failure is followed by at most one cleanup attempt.
                self.assertLessEqual(len(self.commands) - initial, 2)
                self.assertGreater(len(self.commands), initial)
                initial = len(self.commands)
                self.assertFalse(self.net.up)
            self.fail_listener = False
            clock[0] += 60
            self.broker.expire_workstations()
            self.assertTrue(self.net.up)
            self.assertEqual(self.net.peers, self.expected_peers)
            self.assertEqual(self.broker.workstation_error, "")
            initial = len(self.commands)
            for _ in range(20):
                self.broker.expire_workstations()
            self.assertEqual(len(self.commands), initial)

    def test_changed_authoritative_policy_is_not_blocked_by_retry_backoff(self):
        self.open_paired()
        self.net.filter[self.generated["51821"]] = []
        with patch.object(broker.time, "monotonic", return_value=100):
            self.fail_listener = True
            self.broker.expire_workstations()
            self.fail_listener = False
            self.broker.dispatch({"action": "workstation-policy", "state": "closed"}, 1000)
            self.broker.expire_workstations()
        self.assertEqual(self.commands[-1], "0")
        self.assertFalse(self.net.up)
        self.assertEqual(self.generated, {})

    def test_external_owned_nft_change_still_fails_closed_and_recovers(self):
        self.open_paired()
        self.net.table = None
        self.broker.monitor.event({"delete": {"table": {
            "family": "inet", "name": broker.WORKSTATION_TABLE}}})
        self.broker.expire_workstations()
        self.assertTrue(broker.policy_equal(self.broker.owned_table(),
                                           self.broker.expected_policy(self.broker.workstation_state()[0])))
        self.assertEqual(self.net.peers, self.expected_peers)

    def test_acknowledged_own_nft_events_do_not_request_reconciliation(self):
        self.open_paired()
        self.broker.wake.clear()
        self.broker.enforcement_event.clear()
        value = {"family": "inet", "table": broker.WORKSTATION_TABLE, "name": "input"}
        event = {"add": {"chain": value}}
        signature = self.broker.monitor.signature("add", "chain", value)
        for _ in range(100):
            self.broker.monitor.expect([signature])
            self.broker.monitor.event(event)
            self.broker.monitor.wait()
        self.assertFalse(self.broker.wake.is_set())
        self.assertFalse(self.broker.enforcement_event.is_set())
        self.broker.expire_workstations()
        self.assertEqual(self.commands, ["51821"])

    def test_late_owned_notifications_with_exact_readback_do_not_reapply(self):
        self.open_paired()
        for _ in range(100):
            self.broker.monitor.event({"add": {"chain": {
                "family": "inet", "table": broker.WORKSTATION_TABLE, "name": "input"}}})
            self.broker.expire_workstations()
        self.assertEqual(self.commands, ["51821"])
        self.assertEqual(self.broker.monitor.pending, [])

    def test_failed_dedicated_pairing_restores_shared_policy_without_port_oscillation(self):
        self.open_paired()
        self.fail_ports = "51821,58490"
        request = {"action": "pair", "request": helpers.pair_request(), "endpoint_host": "pbx.example.net",
                   "listen_port": "51821", "mode": "persistent", "minutes": "60", "ssh": "0",
                   "sources": "198.51.100.10"}
        with patch.object(self.broker, "locked_listener_port", return_value=58490):
            with self.assertRaisesRegex(broker.BrokerError, "listener fixture failed"):
                self.broker.dispatch(request, 1000)
        self.assertEqual(self.commands, ["51821", "51821,58490", "51821"])
        self.assertEqual(self.broker.workstation_state()[0]["workstations"], self.expected_workstations)
        self.assertEqual(self.net.peers, self.expected_peers)
        self.assertEqual(set(self.generated), {"51821"})
        for _ in range(60):
            self.broker.expire_workstations()
        self.assertEqual(len(self.commands), 3, "Restored shared policy must stay stable after failed Locked pairing")
        self.fail_ports = None
        response = self.broker.dispatch(request, 1000)
        self.assertTrue(response["ok"])
        self.assertEqual(len(self.broker.workstation_state()[0]["workstations"]), 1)

    def test_readback_rejects_stale_ownership_and_wrong_or_forbidden_rules(self):
        self.open_paired()
        self.assertTrue(self.broker.listener_rules_current([51821]))
        self.assertFalse(self.broker.listener_rules_current([51821, 58490]))
        self.assertFalse(self.broker.listener_rules_current([]))
        chain = self.generated["51821"]
        self.net.filter["zone-trusted"] = [["-j", chain]]
        self.assertFalse(self.broker.listener_rules_current([51821]))
        self.net.filter["zone-trusted"] = []
        self.net.filter[chain].append(["-j", "ACCEPT"])
        self.assertFalse(self.broker.listener_rules_current([51821]))
        self.net.filter[chain].pop()
        self.net.filter[chain][0][5] = "58490"
        self.assertFalse(self.broker.listener_rules_current([51821]))
        self.broker.teardown_workstations()
        self.assertFalse((self.state / "firewall-listener.json").exists())
        self.assertEqual(self.net.peers, {})


if __name__ == "__main__":
    unittest.main()
