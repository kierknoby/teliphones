"""Regression coverage for actual policy identity, monitoring and recoverable teardown."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_support_broker as helpers

broker = helpers.broker_module


class EnforcementTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    pair = helpers.WorkstationPairingTests.pair

    def saved(self):
        return (self.state / "workstations.json").read_bytes()

    def mutations(self):
        return [call for call in self.net.calls if call == ("nft", ("-j", "-f", "-"))]

    def test_complete_rule_and_chain_shape_is_compared(self):
        expected = broker.workstation_policy("100.70.1.1", ["100.70.1.2"])
        variants = []
        for index, entry in enumerate(expected["nftables"]):
            removed = copy.deepcopy(expected)
            removed["nftables"].pop(index)
            variants.append(removed)
            for key in next(iter(entry.values())):
                altered = copy.deepcopy(expected)
                next(iter(altered["nftables"][index].values()))[key] = "unexpected"
                variants.append(altered)
        extra_rule = copy.deepcopy(expected)
        extra_rule["nftables"].append(copy.deepcopy(extra_rule["nftables"][2]))
        variants.append(extra_rule)
        reversed_rules = copy.deepcopy(expected)
        reversed_rules["nftables"][2:4] = reversed(reversed_rules["nftables"][2:4])
        variants.append(reversed_rules)
        extra_expression = copy.deepcopy(expected)
        extra_expression["nftables"][2]["rule"]["expr"].insert(0, {"counter": {"packets": 0, "bytes": 0}})
        variants.append(extra_expression)
        for changed in variants:
            with self.subTest(changed=changed):
                try:
                    self.assertFalse(broker.policy_equal(changed, expected))
                except (broker.BrokerError, KeyError, TypeError):
                    pass

    def test_only_handles_metadata_and_chain_enumeration_are_ignored(self):
        expected = broker.workstation_policy("100.70.1.1", [])
        actual = copy.deepcopy(expected)
        for entry in actual["nftables"]:
            next(iter(entry.values()))["handle"] = 123
        actual["nftables"].insert(0, {"metainfo": {"version": "test"}})
        chains = [entry for entry in actual["nftables"] if "chain" in entry]
        actual["nftables"] = [entry for entry in actual["nftables"] if "chain" not in entry] + list(reversed(chains))
        self.assertTrue(broker.policy_equal(actual, expected))
        for extra in ({"set": {}}, {"map": {}}, {"flowtable": {}}, {"unknown": {}}):
            with self.assertRaises(broker.BrokerError):
                broker.policy_equal({"nftables": actual["nftables"] + [extra]}, expected)

    def test_unfamiliar_name_is_not_updated_or_deleted(self):
        self.pair()
        self.net.table["nftables"][0]["table"]["comment"] = "somebody else"
        original, saved = copy.deepcopy(self.net.table), self.saved()
        self.net.calls = []
        for operation in (lambda: self.pair(), self.broker.teardown_workstations,
                          self.broker.uninstall_workstations):
            with self.assertRaisesRegex(broker.BrokerError, "Unfamiliar|ownership"):
                operation()
            self.assertEqual(self.net.table, original)
            self.assertEqual(self.saved(), saved)
            self.assertEqual(self.mutations(), [])
            self.assertFalse(self.net.up)

    def test_legacy_markerless_table_is_unfamiliar(self):
        self.pair()
        del self.net.table["nftables"][0]["table"]["comment"]
        self.net.calls = []
        with self.assertRaisesRegex(broker.BrokerError, "Unfamiliar"):
            self.broker.teardown_workstations()
        self.assertEqual(self.mutations(), [])

    def test_upgrade_legacy_table_preserves_pairings_and_key_with_access_disabled(self):
        self.pair(mode="persistent", ssh="1")
        self.pair(mode="temporary", public_key="B" * 42 + "E=", nonce="m" * 22)
        saved = self.saved()
        key = (self.enrollment / "workstation-wg.key").read_bytes()
        del self.net.table["nftables"][0]["table"]["comment"]
        legacy = copy.deepcopy(self.net.table)
        self.net.calls = []
        self.broker.restore_workstations()
        self.assertFalse(self.net.up)
        self.assertEqual(self.saved(), saved)
        self.assertEqual((self.enrollment / "workstation-wg.key").read_bytes(), key)
        self.assertEqual(self.net.table, legacy)
        self.assertEqual(self.mutations(), [])
        self.assertIn("Unfamiliar", self.broker.workstation_error)
        # Simulate the operator removing only the positively identified legacy table.
        self.net.table = None
        self.broker.restore_workstations()
        self.assertTrue(self.net.up)
        self.assertEqual(self.saved(), saved)
        self.assertEqual((self.enrollment / "workstation-wg.key").read_bytes(), key)
        self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(json.loads(saved))))

    def test_update_disables_and_verifies_before_firewall_or_peer_changes(self):
        self.pair()
        self.net.calls = []
        self.pair(public_key="B" * 42 + "E=", ssh="1")
        down = self.net.calls.index(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)))
        verify = self.net.calls.index(("ip", ("-j", "link", "show")), down)
        mutation = self.net.calls.index(("nft", ("-j", "-f", "-")))
        self.assertLess(down, verify)
        self.assertLess(verify, mutation)

    def test_failed_down_and_delete_preserve_all_recovery_information(self):
        self.pair()
        original, saved = copy.deepcopy(self.net.table), self.saved()
        key = (self.enrollment / "workstation-wg.key").read_bytes()
        self.net.calls = []
        self.net.fail = lambda name, rest: name == "ip" and (rest[:3] == ["link", "set", "down"] or rest[:2] == ["link", "del"])
        with self.assertRaisesRegex(broker.BrokerError, "retaining|confirmed"):
            self.broker.uninstall_workstations()
        self.assertEqual(self.net.table, original)
        self.assertEqual(self.saved(), saved)
        self.assertEqual((self.enrollment / "workstation-wg.key").read_bytes(), key)
        self.assertEqual(self.mutations(), [])

    def test_successful_down_is_not_enough_for_uninstall_to_destroy_state(self):
        self.pair()
        saved = self.saved()
        self.net.fail = lambda name, rest: name == "ip" and rest[:2] == ["link", "del"]
        with self.assertRaises(broker.BrokerError):
            self.broker.uninstall_workstations()
        self.assertFalse(self.net.up)
        self.assertEqual(self.saved(), saved)
        self.assertTrue((self.enrollment / "workstation-wg.key").exists())
        self.assertIsNotNone(self.net.table)

    def test_successful_uninstall_uses_common_verified_teardown(self):
        self.pair()
        self.broker.uninstall_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.net.table)
        self.assertFalse((self.state / "workstations.json").exists())
        self.assertFalse((self.enrollment / "workstation-wg.key").exists())

    def test_uninstall_nft_failure_preserves_key_and_state(self):
        self.pair()
        saved = self.saved()
        self.net.fail = lambda name, rest: name == "nft" and rest == ["-j", "-f", "-"]
        with self.assertRaises(broker.BrokerError):
            self.broker.uninstall_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNotNone(self.net.table)
        self.assertEqual(self.saved(), saved)
        self.assertTrue((self.enrollment / "workstation-wg.key").exists())

    def test_failed_inventory_is_never_treated_as_absence(self):
        for tool, rest in (("ip", ["-j", "link", "show"]), ("nft", ["-j", "list", "tables"])):
            with self.subTest(tool=tool):
                self.net.fail = None
                if not (self.state / "workstations.json").exists():
                    self.pair()
                saved = self.saved()
                self.net.fail = lambda name, args: name == tool and args == rest
                with self.assertRaises(broker.BrokerError):
                    self.broker.uninstall_workstations()
                self.assertEqual(self.saved(), saved)
                self.assertIsNotNone(self.net.table)
        self.net.fail = None

    def test_missing_tools_prevent_unverified_teardown(self):
        self.pair()
        saved = self.saved()
        real = self.broker.tool
        for missing in ("ip", "nft"):
            self.broker.tool = lambda name: (_ for _ in ()).throw(broker.BrokerError("missing tool")) if name == missing else real(name)
            with self.assertRaises(broker.BrokerError):
                self.broker.uninstall_workstations()
            self.assertEqual(self.saved(), saved)
            self.assertTrue((self.enrollment / "workstation-wg.key").exists())
        self.broker.tool = real

    def test_periodic_fallback_repairs_missing_policy_for_both_modes(self):
        for mode in ("persistent", "temporary"):
            with self.subTest(mode=mode):
                self.pair(mode=mode)
                saved = self.saved()
                self.net.table, self.net.ruleset = None, None
                self.broker.expire_workstations()
                self.assertTrue(self.net.up)
                self.assertEqual(self.saved(), saved)
                state, _ = self.broker.workstation_state()
                self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(state)))

    def test_periodic_fallback_repairs_altered_rule(self):
        self.pair()
        self.net.table["nftables"][2]["rule"]["expr"][-1] = {"drop": None}
        self.broker.expire_workstations()
        state, _ = self.broker.workstation_state()
        self.assertTrue(self.net.up)
        self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(state)))

    def test_altered_marker_is_not_repaired_and_access_is_disabled(self):
        self.pair()
        self.net.table["nftables"][0]["table"]["comment"] = "foreign"
        self.net.calls = []
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertEqual(self.mutations(), [])
        self.assertIn("Unfamiliar", self.broker.workstation_error)
        self.assertFalse(self.broker.workstation_status()["ready"])

    def test_temporary_flush_then_restore_still_triggers_disable_and_reverify(self):
        self.pair()
        original = copy.deepcopy(self.net.table)
        self.net.table = None
        self.net.emit([{"delete": {"table": original["nftables"][0]["table"]}}])
        self.net.table = original
        self.assertTrue(self.broker.enforcement_event.wait(1))
        self.net.calls = []
        self.broker.expire_workstations()
        self.assertIn(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)), self.net.calls)
        self.assertTrue(self.net.up)
        self.assertFalse(self.broker.enforcement_event.is_set())

    def test_own_events_do_not_produce_repair_loops(self):
        self.pair()
        self.assertFalse(self.broker.enforcement_event.is_set())
        self.net.calls = []
        for _ in range(3):
            self.broker.expire_workstations()
        self.assertEqual(self.mutations(), [])
        self.assertNotIn(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)), self.net.calls)

    def test_foreign_table_events_do_not_trigger_repairs(self):
        self.pair()
        self.broker.monitor.event({"delete": {"table": {"family": "inet", "name": "freepbx"}}})
        self.broker.monitor.event({"delete": {"table": {"family": "ip", "name": broker.WORKSTATION_TABLE}}})
        self.assertFalse(self.broker.enforcement_event.is_set())

    def test_monitor_death_is_reported_and_disables_without_destroying_state(self):
        self.pair()
        saved, original = self.saved(), copy.deepcopy(self.net.table)
        self.net.process.terminate()
        self.assertTrue(self.broker.enforcement_event.wait(1))
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertIn("monitor", self.broker.workstation_status()["error"])
        self.assertFalse(self.broker.workstation_status()["ready"])
        self.assertEqual(self.saved(), saved)
        self.assertEqual(self.net.table, original)

    def test_failed_monitor_registration_never_admits_peer(self):
        self.net.silent = True
        with patch.object(broker.NftMonitor, "wait", side_effect=broker.BrokerError("registration failed")):
            with self.assertRaises(broker.BrokerError):
                self.pair()
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})

    def test_monitor_is_started_before_any_admission(self):
        self.pair()
        monitor = self.net.calls.index(("nft", ("-j", "monitor", "ruleset")))
        mutation = self.net.calls.index(("nft", ("-j", "-f", "-")))
        peer = next(index for index, call in enumerate(self.net.calls) if call[0] == "wg" and "allowed-ips" in call[1])
        self.assertLess(monitor, mutation)
        self.assertLess(mutation, peer)
        self.assertEqual(self.broker.monitor.pending, [])

    def test_bad_firewall_readback_never_admits_peers(self):
        original = self.net.run
        def altered(arguments, **kwargs):
            output = original(arguments, **kwargs)
            if arguments[1:] == ["-j", "list", "table", "inet", broker.WORKSTATION_TABLE] and self.net.table:
                value = json.loads(output)
                value["nftables"][2]["rule"]["expr"][-1] = {"accept": {"unexpected": True}}
                return json.dumps(value)
            return output
        self.broker.run = altered
        with self.assertRaises(broker.BrokerError):
            self.pair()
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})

    def test_corrupt_state_on_periodic_check_disables_access(self):
        self.pair()
        (self.state / "workstations.json").write_text("invalid")
        # The service worker catches this and disables; restore must do so as well.
        self.broker.restore_workstations()
        self.assertFalse(self.net.up)
        self.assertEqual((self.state / "workstations.json").read_text(), "invalid")

    def test_monitor_malformed_output_disables_and_reports_failure(self):
        self.pair()
        self.net.process.writer.write("not JSON\n")
        self.net.process.writer.flush()
        self.assertTrue(self.broker.enforcement_event.wait(1))
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertFalse(self.broker.workstation_status()["ready"])

    def test_raw_monitor_events_are_supported(self):
        self.pair()
        self.net.process.writer.write(json.dumps({"delete": {"table": self.net.table["nftables"][0]["table"]}}) + "\n")
        self.net.process.writer.flush()
        self.assertTrue(self.broker.enforcement_event.wait(1))

    def test_dead_reader_is_not_reported_as_healthy_process(self):
        self.pair()
        with patch.object(self.broker.monitor.thread, "is_alive", return_value=False):
            self.broker.expire_workstations()
            self.assertFalse(self.net.up)
            self.assertIn("monitor", self.broker.workstation_status()["error"])

    def test_delayed_subscription_requires_successful_observed_retry(self):
        original_wait = broker.NftMonitor.wait
        attempts = []
        self.net.silent = True
        def delayed(monitor):
            attempts.append(True)
            if len(attempts) == 1:
                self.net.silent = False
                raise broker.BrokerError("not subscribed yet")
            return original_wait(monitor)
        with patch.object(broker.NftMonitor, "wait", delayed):
            self.pair()
        self.assertEqual(len(attempts), 2)
        self.assertTrue(self.net.up)
        self.assertEqual(self.broker.monitor.pending, [])

    def test_temporary_peer_event_repair_does_not_extend_expiry(self):
        self.pair(mode="temporary")
        saved = self.saved()
        self.broker.monitor.event({"delete": {"table": self.net.table["nftables"][0]["table"]}})
        self.broker.expire_workstations()
        self.assertEqual(self.saved(), saved)
        self.assertTrue(self.net.up)

    def test_success_exit_code_for_down_is_independently_verified(self):
        self.pair()
        saved, original_table = self.saved(), copy.deepcopy(self.net.table)
        original_run = self.net.run
        def ignore_down(arguments, **kwargs):
            if arguments[1:4] == ["link", "set", "down"]:
                return ""
            return original_run(arguments, **kwargs)
        self.broker.run = ignore_down
        self.net.fail = lambda name, rest: name == "ip" and rest[:2] == ["link", "del"]
        with self.assertRaises(broker.BrokerError):
            self.broker.uninstall_workstations()
        self.assertTrue(self.net.up)
        self.assertEqual(self.net.table, original_table)
        self.assertEqual(self.saved(), saved)

    def test_malformed_inventory_is_not_table_absence(self):
        self.pair()
        saved, original_table = self.saved(), copy.deepcopy(self.net.table)
        original_run = self.net.run
        def invalid_inventory(arguments, **kwargs):
            if arguments[1:] == ["-j", "list", "tables"]:
                return '{"nftables":[{"unexpected":{}}]}'
            return original_run(arguments, **kwargs)
        self.broker.run = invalid_inventory
        with self.assertRaises(broker.BrokerError):
            self.broker.uninstall_workstations()
        self.assertEqual(self.net.table, original_table)
        self.assertEqual(self.saved(), saved)

    def test_failed_new_pairing_cleanup_retains_old_and_attempted_states(self):
        self.pair()
        saved = self.saved()
        self.net.fail = lambda name, rest: (name == "wg" and "allowed-ips" in rest and "B" * 42 + "E=" in rest) or (name == "ip" and rest[:2] == ["link", "del"])
        with self.assertRaises(broker.BrokerError):
            self.pair(public_key="B" * 42 + "E=")
        self.assertEqual(self.saved(), saved)
        attempted = json.loads((self.state / "workstation-recovery.json").read_text())
        self.assertEqual(len(attempted["workstations"]), 2)
        self.assertFalse(self.net.up)
        self.assertIsNotNone(self.net.table)
        self.assertTrue((self.enrollment / "workstation-wg.key").exists())


class NamespaceTests(unittest.TestCase):
    def test_real_nft_json_monitor_and_teardown_in_private_namespace(self):
        if not all(shutil.which(tool) for tool in ("unshare", "nft", "ip")):
            self.skipTest("unshare/nft/ip unavailable; no host network mutation attempted")
        probe = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"], capture_output=True, text=True)
        if probe.returncode:
            self.skipTest("user/network namespace capability unavailable: " + probe.stderr.strip())
        script = Path(__file__).with_name("workstation_namespace_lab.py")
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable, str(script), os.readlink("/proc/self/ns/net")],
                                capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wireguard_namespace_prerequisites(self):
        if not shutil.which("wg"):
            self.skipTest("wg unavailable; real WireGuard admission/traffic tests not run (no packages installed)")
        # This is only a prerequisite check, not a substitute for the separate traffic lab.
        self.assertTrue(shutil.which("ip"))
