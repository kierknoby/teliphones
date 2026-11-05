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
        first_rule = next(index for index, item in enumerate(extra_rule["nftables"]) if "rule" in item)
        extra_rule["nftables"].append(copy.deepcopy(extra_rule["nftables"][first_rule]))
        variants.append(extra_rule)
        reversed_rules = copy.deepcopy(expected)
        first_rule = next(index for index, item in enumerate(reversed_rules["nftables"]) if "rule" in item)
        reversed_rules["nftables"][first_rule:first_rule + 2] = reversed(reversed_rules["nftables"][first_rule:first_rule + 2])
        variants.append(reversed_rules)
        extra_expression = copy.deepcopy(expected)
        first_rule = next(item for item in extra_expression["nftables"] if "rule" in item)
        first_rule["rule"]["expr"].insert(0, {"counter": {"packets": 0, "bytes": 0}})
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
        for index, operation in enumerate((lambda: self.pair(), self.broker.teardown_workstations,
                                           self.broker.uninstall_workstations)):
            with self.assertRaisesRegex(broker.BrokerError, "Unfamiliar|ownership|Unexpected"):
                operation()
            self.assertEqual(self.net.table, original)
            self.assertEqual(self.saved(), saved)
            self.assertEqual(self.mutations(), [])
            self.assertEqual(self.net.up, index == 0)

    def test_hookless_owner_chain_is_visible_without_table_comments(self):
        self.pair()
        self.assertNotIn("comment", self.net.table["nftables"][0]["table"])
        self.assertEqual(self.net.table["nftables"][1]["chain"]["name"], broker.WORKSTATION_OWNER_CHAIN)
        self.assertEqual(set(self.net.table["nftables"][1]["chain"]), {"family", "table", "name", "handle"})
        self.assertTrue(broker.policy_equal(self.broker.owned_table(), self.broker.expected_policy(
            json.loads(self.saved()))))

    def legacy_policy(self, include_comment=False):
        state = json.loads(self.saved())
        sources = [item["address"].split("/")[0] for item in state["workstations"] if item.get("ssh") is True]
        legacy = broker.workstation_policy(str(broker.ipaddress.IPv4Network(state["subnet"])[1]), sources)
        legacy["nftables"] = [
            item for item in legacy["nftables"]
            if "chain" not in item or item["chain"].get("name") != broker.WORKSTATION_OWNER_CHAIN
        ]
        if include_comment:
            legacy["nftables"][0]["table"]["comment"] = broker.WORKSTATION_OWNER
        for item in legacy["nftables"]:
            value = next(iter(item.values()))
            value["handle"] = self.net.next_handle
            self.net.next_handle += 1
        return legacy

    def test_upgrade_legacy_table_preserves_pairings_and_key_with_access_disabled(self):
        self.pair(mode="persistent", ssh="1")
        self.pair(mode="temporary", public_key="B" * 42 + "E=", nonce="m" * 22)
        saved = self.saved()
        key = (self.enrollment / "workstation-wg.key").read_bytes()
        self.net.table = self.legacy_policy()
        legacy = copy.deepcopy(self.net.table)
        self.net.calls = []
        self.broker.restore_workstations()
        self.assertTrue(self.net.up)
        self.assertEqual(self.saved(), saved)
        self.assertEqual((self.enrollment / "workstation-wg.key").read_bytes(), key)
        self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(json.loads(saved))))
        self.assertNotEqual(self.net.table, legacy)
        self.assertTrue(any("nft" == call[0] and call[1] == ("-j", "-f", "-") for call in self.net.calls))
        self.assertEqual(self.net.table["nftables"][0]["table"].get("comment"), None)
        self.assertEqual(self.net.table["nftables"][1]["chain"]["name"], broker.WORKSTATION_OWNER_CHAIN)

    def test_legacy_policy_with_old_table_comment_migrates_after_verified_down(self):
        self.pair(mode="persistent", ssh="1")
        self.net.table = self.legacy_policy(include_comment=True)
        self.net.calls = []
        self.broker.restore_workstations()
        self.assertTrue(self.net.up)
        self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(json.loads(self.saved()))))
        self.assertEqual(self.net.table["nftables"][0]["table"].get("comment"), None)
        down = self.net.calls.index(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)))
        mutation = self.net.calls.index(("nft", ("-j", "-f", "-")))
        self.assertLess(down, mutation)

    def test_legacy_migration_refuses_when_interface_cannot_be_proved_down(self):
        self.pair()
        self.net.table = self.legacy_policy()
        self.net.calls = []
        with self.assertRaisesRegex(broker.BrokerError, "cannot be migrated while the tunnel is up"):
            self.broker.validate_owned_table(self.net.table)
        self.assertEqual(self.mutations(), [])
        self.assertTrue(self.net.up)

    def test_legacy_migration_refuses_unmatched_or_unfamiliar_policy(self):
        self.pair(mode="persistent", ssh="1")
        invalid = self.legacy_policy()
        invalid["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
        self.net.table = invalid
        self.net.up = False
        self.net.calls = []
        with self.assertRaisesRegex(broker.BrokerError, "does not exactly match"):
            self.broker.owned_table()
        self.assertEqual(self.mutations(), [])
        changed_comment = self.legacy_policy(include_comment=True)
        changed_comment["nftables"][0]["table"]["comment"] = "foreign owner"
        self.net.table = changed_comment
        with self.assertRaisesRegex(broker.BrokerError, "Unexpected workstation table comment"):
            self.broker.owned_table()

    def test_owner_chain_must_be_unique_hookless_and_ruleless(self):
        self.pair()
        original = copy.deepcopy(self.net.table)
        for mutate in (
            lambda chain: chain.update({"type": "filter", "hook": "input", "prio": 10, "policy": "accept"}),
            lambda chain: chain.update({"comment": "untrusted"}),
        ):
            actual = copy.deepcopy(original)
            mutate(actual["nftables"][1]["chain"])
            self.net.table = actual
            with self.assertRaisesRegex(broker.BrokerError, "ownership chain"):
                self.broker.owned_table()
        actual = copy.deepcopy(original)
        actual["nftables"].append(copy.deepcopy(actual["nftables"][1]))
        self.net.table = actual
        with self.assertRaisesRegex(broker.BrokerError, "ownership chain"):
            self.broker.owned_table()
        actual = copy.deepcopy(original)
        actual["nftables"].append({"rule": {"family": "inet", "table": broker.WORKSTATION_TABLE,
                                             "chain": broker.WORKSTATION_OWNER_CHAIN, "expr": [{"accept": None}]}})
        self.net.table = actual
        with self.assertRaisesRegex(broker.BrokerError, "ownership chain"):
            self.broker.owned_table()

    def test_restart_revalidates_owner_chain_and_revocation_retains_open_listener(self):
        _, response = self.pair(mode="persistent", ssh="1")
        restarted = broker.Broker()
        self.addCleanup(lambda: restarted.monitor.close() if restarted.monitor is not None else None)
        restarted.audit = lambda *args: None
        restarted.run = self.net.run
        restarted.tool = lambda name: name
        restarted.iptables_tool = self.broker.iptables_tool
        restarted.ssh.reconcile = lambda *args: None
        restarted.restore_workstations()
        self.assertTrue(self.net.up)
        self.assertTrue(broker.policy_equal(self.net.table, restarted.expected_policy(
            json.loads(self.saved()))))
        self.assertEqual(self.net.table["nftables"][1]["chain"]["name"], broker.WORKSTATION_OWNER_CHAIN)
        with patch.object(broker, "STATE", self.state), patch.object(broker, "ENROLLMENT", self.enrollment):
            restarted.dispatch({"action": "unpair", "workstation_id": response["workstation_id"]}, 1000)
        state = json.loads(self.saved())
        self.assertEqual(self.net.peers, {})
        self.assertTrue(self.net.up)
        self.assertTrue(broker.policy_equal(self.net.table, restarted.expected_policy(state)))

    def test_pairing_addition_preserves_existing_listener_and_firewall_policy(self):
        _, first = self.pair()
        self.net.calls = []
        self.pair(public_key="B" * 42 + "E=", ssh="1")
        self.assertTrue(self.net.up)
        self.assertIn(first["workstation_id"], {item["id"] for item in json.loads(self.saved())["workstations"]})
        self.assertFalse(any(name == "ip" and rest[:3] == ("link", "set", "down")
                             for name, rest in self.net.calls))

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

    def test_expiry_worker_restores_missing_locked_interface(self):
        _, response = self.pair(sources="198.51.100.24")
        state = json.loads((self.state / "workstations.json").read_text())
        item = state["workstations"][0]
        interface = self.broker.locked_interface(item)
        del self.net.devices[interface]
        self.net.calls = []
        self.broker.expire_workstations()
        self.assertTrue(self.net.devices[interface]["up"])
        self.assertEqual(self.net.devices[interface]["peers"], {item["public_key"]: item["address"]})
        self.assertIn((broker.FWCONSOLE, ("teliphones", "listener",
                                          "--listen-port=51821," + str(item["listener_port"]))), self.net.calls)

    def test_teardown_removes_orphaned_dedicated_listener_interfaces(self):
        self.net.devices["tlpw" + "a" * 11] = {"up": False, "peers": {}}
        self.broker.teardown_workstations()
        self.assertNotIn("tlpw" + "a" * 11, self.net.devices)

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
        first_rule = next(item for item in self.net.table["nftables"] if "rule" in item)
        first_rule["rule"]["expr"][-1] = {"drop": None}
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
        self.assertIn("Unexpected", self.broker.workstation_error)
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
                next(item for item in value["nftables"] if "rule" in item)["rule"]["expr"][-1] = {"accept": {"unexpected": True}}
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

    def drop_monitor_events(self, dropped):
        original = self.net.emit
        self.net.emit = lambda events: original([event for event in events if not dropped(event)])
        return original

    def test_udp_rules_match_the_form_nft_reports_back(self):
        policy = broker.workstation_policy(
            "100.70.1.1", [], (), (80, 443), [{"port": 52001, "sources": ["203.0.113.7", "2001:db8::/32"]}], [],
            [{"port": 51821, "source": "192.0.2.9"}])
        udp = [item["rule"]["expr"] for item in policy["nftables"] if "rule" in item
               and any(expression.get("match", {}).get("left", {}).get("payload", {}).get("protocol") == "udp"
                       for expression in item["rule"]["expr"])]
        self.assertGreaterEqual(len(udp), 3)
        for expressions in udp:
            # nft omits the implicit l4proto dependency from monitor events and listings, so it can never be acknowledged.
            self.assertNotIn({"meta": {"key": "l4proto"}}, [expression.get("match", {}).get("left") for expression in expressions])

    def test_unacknowledged_transaction_is_read_back_released_cleaned_up_and_recovers(self):
        restore = self.drop_monitor_events(lambda event: "rule" in event.get("add", {}))
        with self.assertRaises(broker.BrokerError) as raised:
            self.pair()
        message = str(raised.exception)
        self.assertIn("Workstation access could not be applied and was removed", message)
        self.assertIn("not acknowledged by the nft monitor", message)
        self.assertIn("add rule", message)
        self.assertIn("Firewall readback: the TELIPHONES table matches the requested policy", message)
        self.assertNotIn("100.70.", message)
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertEqual(self.broker.monitor.pending, [])
        self.assertFalse(self.broker.workstation_cleanup_failed)
        self.assertIsNone(self.broker.owned_table())
        self.assertNotIn("cleanup could not be confirmed", self.broker.workstation_status()["error"])
        self.net.emit = restore
        self.pair()
        self.assertTrue(self.net.up)
        self.assertNotEqual(self.net.peers, {})
        self.assertEqual(self.broker.monitor.pending, [])
        self.assertEqual(self.broker.workstation_status()["error"], "")

    def test_unreadable_state_after_unacknowledged_transaction_stays_latched_until_read_back(self):
        restore = self.drop_monitor_events(lambda event: "rule" in event.get("add", {}))
        original_owned = self.broker.owned_table
        readable = []
        def owned_table():
            if not readable and self.broker.monitor.pending:
                raise broker.BrokerError("Workstation network operation failed: nft")
            return original_owned()
        self.broker.owned_table = owned_table
        with self.assertRaises(broker.BrokerError) as raised:
            self.pair()
        # Unreadable state cannot be released, so cleanup also cannot be confirmed; the cause names the readback failure.
        self.assertIn("Workstation cleanup could not be confirmed", str(raised.exception))
        self.assertIn("could not be read back after an unacknowledged nft transaction", str(raised.exception.__cause__))
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})
        self.assertNotEqual(self.broker.monitor.pending, [])
        self.assertTrue(self.broker.workstation_cleanup_failed)
        readable.append(True)
        self.net.emit = restore
        self.pair()
        self.assertTrue(self.net.up)
        self.assertEqual(self.broker.monitor.pending, [])
        self.assertFalse(self.broker.workstation_cleanup_failed)

    def test_unacknowledged_teardown_reports_readback_and_keeps_access_disabled(self):
        self.pair()
        restore = self.drop_monitor_events(lambda event: "table" in event.get("delete", {}))
        with self.assertRaises(broker.BrokerError) as raised:
            self.broker.teardown_workstations()
        self.assertIn("Firewall readback: the TELIPHONES table is absent", str(raised.exception))
        self.assertFalse(self.net.up)
        self.assertEqual(self.broker.monitor.pending, [])
        self.net.emit = restore
        self.broker.teardown_workstations()
        self.assertIsNone(self.broker.owned_table())

    def test_monitor_errors_name_the_actual_condition(self):
        self.pair()
        self.broker.monitor.pending = [("add", "rule", {"family": "inet", "table": broker.WORKSTATION_TABLE, "chain": "input"})]
        with self.assertRaisesRegex(broker.BrokerError, r"unacknowledged earlier transaction \(add rule input x1\)"):
            self.broker.monitor.expect([])
        self.broker.monitor.pending = []
        self.net.process.terminate()
        self.broker.monitor.thread.join(2)
        with self.assertRaisesRegex(broker.BrokerError, "nft monitor is unavailable: "):
            self.broker.monitor.expect([])

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
        self.assertFalse((self.state / "workstation-recovery.json").exists())
        self.assertTrue(self.net.up)
        self.assertEqual(len(self.net.devices[broker.WORKSTATION_IFACE]["peers"]), 1)
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
