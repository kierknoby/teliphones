"""FreePBX Firewall (iptables) integration: ordering, exact scope, idempotence, reconciliation and failure handling.

Unit tests use a simulated iptables filter table with FreePBX Firewall-shaped hooks (not FreePBX itself).
NamespaceIntegrationTests run real packets through real nft and iptables in disposable namespaces.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_support_broker as helpers

broker = helpers.broker_module
MARK = broker.INTEGRATION_MARK
CHAIN = broker.INTEGRATION_CHAIN
JUMP = broker.iptables_arguments(broker.INTEGRATION_JUMP)
LEGACY_JUMP = broker.iptables_arguments(broker.LEGACY_INTEGRATION_JUMP)
DEFAULT_WEB = [dict(entry) for entry in broker.DEFAULT_WEB]
BANS = helpers.FREEPBX17_FAIL2BAN
EXPECTED = BANS + ["fpbxfirewall"]
BASELINE = BANS + ["fpbxfirewall"]


class IntegrationTests(unittest.TestCase):
    setUp_base = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    pair = helpers.WorkstationPairingTests.pair
    open_session = helpers.WorkstationPairingTests.open_session

    def setUp(self):
        self.setUp_base()
        self.net.freepbx()
        original = self.net.iptables
        def guarded(rest):
            if rest[:2] == ["-w", "5"] and rest[2] in ("-F", "-X"):
                self.assertEqual(rest[3:], [CHAIN], "broker must never flush/delete a foreign chain")
            if rest[:3] == ["-w", "5", "-I"]:
                self.assertEqual(rest[3], "fpbxfirewall", "broker must never insert INPUT rules")
            return original(rest)
        self.net.iptables = guarded

    def rules(self):
        return [broker.iptables_rule(rule) for rule in self.net.filter.get(CHAIN, [])]

    def accepted(self):
        return {(rule["s"], rule["dport"]) for rule in self.rules() if rule and rule["j"] == "ACCEPT" and "s" in rule}

    def input_targets(self):
        return [broker.iptables_target(rule) for rule in self.net.filter["INPUT"]]

    def assert_placement(self):
        self.assertNotIn(CHAIN, self.input_targets())
        self.assertEqual(self.net.filter["fpbxfirewall"][0], JUMP)
        self.assertEqual(self.net.filter["fpbxfirewall"].count(JUMP), 1)

    def watchdog_reset(self):
        # Model only the reported above-hook check, not FreePBX's full implementation.
        inputs = self.net.filter["INPUT"]
        hook = inputs.index(["-j", "fpbxfirewall"])
        if any(jump in inputs[:hook] for jump in (JUMP, LEGACY_JUMP)):
            self.net.freepbx()
            return True
        return False

    def baseline_input(self):
        return [helpers.fail2ban_hook(name) for name in BANS] + [["-j", "fpbxfirewall"]]

    def move_after_hook(self, target):
        rules = self.net.filter["INPUT"]
        rule = next(item for item in rules if broker.iptables_target(item) == target)
        rules.remove(rule)
        rules.append(rule)

    def unpair(self, workstation_id):
        return self.broker.dispatch({"action": "unpair", "workstation_id": workstation_id}, 1000)

    def test_pairing_installs_exact_rules_inside_freepbx_after_fail2ban(self):
        _, response = self.pair()
        self.assertEqual(self.input_targets(), EXPECTED)
        self.assert_placement()
        pbx = response["pbx_address"] + "/32"
        self.assertEqual(self.rules(), [
            {"s": response["address"], "d": pbx, "i": broker.WORKSTATION_IFACE, "p": "tcp", "dport": "80", "comment": MARK, "j": "ACCEPT"},
            {"s": response["address"], "d": pbx, "i": broker.WORKSTATION_IFACE, "p": "tcp", "dport": "443", "comment": MARK, "j": "ACCEPT"},
            {"s": response["address"], "d": pbx, "i": broker.WORKSTATION_IFACE, "p": "tcp", "dport": "8766", "comment": MARK, "j": "ACCEPT"},
            {"comment": MARK, "j": "RETURN"}])
        status = self.broker.status()["workstations"]["firewall_integration"]
        self.assertEqual((status["state"], status["backend"], status["hook"], status["chain"]), ("active", "nf_tables", "fpbxfirewall", CHAIN))
        self.assertEqual(self.net.filter["fpbxfirewall"][1:], [["-i", "lo", "-j", "ACCEPT"], ["-j", "DROP"]])
        self.assertEqual(self.net.filter["INPUT"][:len(BANS)], [helpers.fail2ban_hook(name) for name in BANS])
        for name in BANS:
            self.assertEqual(self.net.filter[name], [["-j", "RETURN"]])

    def test_nft_is_verified_before_integration_and_link_up_follows(self):
        self.pair()
        calls = self.net.calls
        insert = calls.index(("iptables", ("-w", "5", "-I", "fpbxfirewall", "1", *JUMP)))
        last_nft_check = max(index for index, call in enumerate(calls[:insert]) if call[0] == "nft" and call[1][:2] == ("-j", "list"))
        mutation = max(index for index, call in enumerate(calls[:insert]) if call == ("nft", ("-j", "-f", "-")))
        self.assertLess(mutation, last_nft_check)
        self.assertGreater(calls.index(("ip", ("link", "set", "up", "dev", broker.WORKSTATION_IFACE))), insert)

    def test_ssh_only_for_explicitly_authorised_peer(self):
        _, web = self.pair()
        _, ssh = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22, ssh="1")
        managed_port = str(22000 + int(ssh["address"].split(".")[-1].split("/")[0]))
        self.assertEqual(self.accepted(), {(web["address"], "80"), (web["address"], "443"),
                                           (web["address"], "8766"),
                                           (ssh["address"], "80"), (ssh["address"], "443"),
                                           (ssh["address"], "8766"),
                                           (ssh["address"], "8765"), (ssh["address"], managed_port)})
        for rule in self.rules()[:-1]:
            self.assertTrue(rule["s"].endswith("/32") and rule["d"] == web["pbx_address"] + "/32" and rule["i"] == broker.WORKSTATION_IFACE)
            self.assertIn(rule["dport"], {"80", "443", "8765", "8766", managed_port})

    def test_reconnection_and_repairing_do_not_duplicate_rules(self):
        self.pair(mode="temporary")
        before = json.dumps(self.net.filter)
        self.pair(mode="temporary")
        self.broker.restore_workstations()
        self.broker.expire_workstations()
        self.assertEqual(json.dumps(self.net.filter), before)
        self.assert_placement()

    def test_firewall_reload_is_repaired_without_rebouncing_peers(self):
        self.pair()
        for reload in ("flush", "jump-last", "chain-flushed", "fail2ban-restart", "rule-between", "fail2ban-between"):
            rules = self.net.filter["fpbxfirewall"]
            if reload == "flush":
                self.net.freepbx()
            elif reload == "jump-last":
                rules.append(rules.pop(rules.index(JUMP)))
            elif reload == "chain-flushed":
                self.net.filter[CHAIN] = []
            elif reload == "fail2ban-restart":
                # Fail2Ban re-inserts its hooks at INPUT position 1 on restart.
                inputs = self.net.filter["INPUT"]
                hooks = [item for item in inputs if broker.is_fail2ban_hook(broker.iptables_target(item))]
                self.net.filter["INPUT"] = list(reversed(hooks)) + [item for item in inputs if item not in hooks]
            elif reload == "rule-between":
                rules.insert(0, ["-i", "lo", "-j", "ACCEPT"])
            else:
                hook = helpers.fail2ban_hook("fail2ban-PBX-GUI")
                inputs = self.net.filter["INPUT"]
                inputs.remove(hook)
                inputs.insert(inputs.index(["-j", "fpbxfirewall"]), hook)
            self.net.calls = []
            self.broker.expire_workstations()
            targets = self.input_targets()
            self.assert_placement()
            self.assertTrue(all(targets.index(name) < targets.index("fpbxfirewall") for name in BANS), reload)
            self.assertEqual(len(self.rules()), 4)
            self.assertTrue(self.net.up)
            self.assertNotIn(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)), self.net.calls)
            self.assertEqual(self.broker.integration["state"], "active")

    def test_revocation_and_expiry_remove_peer_rules_but_keep_open_listener(self):
        _, first = self.pair(mode="temporary")
        _, second = self.pair(public_key="B" * 42 + "E=", nonce="m" * 22, ssh="1")
        self.unpair(second["workstation_id"])
        self.assertEqual(self.accepted(), {(first["address"], "80"), (first["address"], "443"),
                                           (first["address"], "8766")})
        state = json.loads((self.state / "workstations.json").read_text())
        state["workstations"][0]["expires_at"] = int(time.time()) - 1
        (self.state / "workstations.json").write_text(json.dumps(state))
        self.broker.expire_workstations()
        self.assertEqual(self.accepted(), set())
        self.assertIn(CHAIN, self.net.filter)
        self.assertTrue(self.net.up)

    def test_complete_chain_deletion_is_repaired_without_monitor_event(self):
        self.pair()
        self.net.filter["INPUT"] = self.baseline_input()
        self.net.filter["fpbxfirewall"].remove(JUMP)
        del self.net.filter[CHAIN]
        self.broker.wake.clear()
        self.broker.enforcement_event.clear()
        self.net.calls = []
        self.broker.expire_workstations()
        self.assertEqual(self.input_targets(), EXPECTED)
        self.assertEqual(len(self.rules()), 4)
        self.assertEqual(self.broker.integration["state"], "active")
        self.assertNotIn(("ip", ("link", "set", "down", "dev", broker.WORKSTATION_IFACE)), self.net.calls)

    def test_temporarily_missing_freepbx_hook_withdraws_then_restores_integration(self):
        _, response = self.pair()
        self.net.filter["INPUT"].remove(["-j", "fpbxfirewall"])
        self.broker.expire_workstations()
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.broker.integration["state"], "not-detected")
        self.assertTrue(self.net.up)
        self.net.filter["INPUT"].append(["-j", "fpbxfirewall"])
        self.broker.expire_workstations()
        self.assertEqual(self.input_targets(), EXPECTED)
        self.assertEqual(self.accepted(), {(response["address"], "80"), (response["address"], "443"),
                                           (response["address"], "8766")})
        self.assertEqual(self.broker.integration["state"], "active")

    def test_last_revocation_keeps_open_listener_and_shutdown_removes_integration(self):
        self.pair()
        self.unpair("all")
        self.assertTrue(self.net.up)
        self.assertEqual(self.accepted(), set())
        self.assertIn(CHAIN, self.net.filter)
        self.pair(nonce="m" * 22)
        self.broker.teardown_workstations()
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.input_targets(), BASELINE)
        self.pair(nonce="n" * 22)
        self.broker.uninstall_workstations()
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertFalse((self.state / "workstations.json").exists())

    def test_uninstall_retains_recovery_state_when_integration_removal_fails(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "iptables" and "-X" in rest
        with self.assertRaisesRegex(broker.BrokerError, "integration cleanup is incomplete"):
            self.broker.uninstall_workstations()
        self.assertFalse(self.net.link)
        self.assertTrue((self.state / "workstations.json").exists())
        self.assertTrue((self.enrollment / "workstation-wg.key").exists())
        # Owned nft cleanup is not skipped because of the iptables failure.
        self.assertIsNone(self.net.table)

    def test_failed_insert_removes_integration_and_reports_diagnostic(self):
        self.net.fail = lambda name, rest: name == "iptables" and "-I" in rest
        self.pair()
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertTrue(self.net.up)
        status = self.broker.status()["workstations"]["firewall_integration"]
        self.assertEqual(status["state"], "error")
        self.assertIn("may now drop WireGuard handshakes and tunnel HTTP/HTTPS", status["message"])

    def test_unverifiable_integration_cleanup_fails_closed(self):
        self.net.fail = lambda name, rest: name == "iptables" and ("-I" in rest or "-X" in rest)
        with self.assertRaises(broker.BrokerError):
            self.pair()
        self.assertFalse(self.net.up)
        self.assertTrue((self.state / "workstation-recovery.json").exists())

    def test_periodic_cleanup_failure_disables_interface(self):
        self.pair()
        self.net.filter["INPUT"] = self.baseline_input()
        self.net.filter["fpbxfirewall"].remove(JUMP)
        self.net.fail = lambda name, rest: name == "iptables" and ("-I" in rest or "-X" in rest)
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertIn("could not be verified or removed", self.broker.workstation_error)

    def test_watchdog_cycles_leave_input_and_unrelated_rules_unchanged(self):
        self.net.filter["FORWARD"] = [["-i", "eth0", "-j", "DROP"]]
        self.net.filter["OUTPUT"] = [["-p", "udp", "--dport", "5060", "-j", "ACCEPT"]]
        original = json.loads(json.dumps(self.net.filter))
        self.pair()
        for _ in range(10):
            self.assertFalse(self.watchdog_reset())
            self.broker.expire_workstations()
            self.assertEqual(self.net.filter["INPUT"], original["INPUT"])
            self.assertEqual(self.net.filter["fpbxfirewall"][1:], original["fpbxfirewall"])
        self.net.calls = []
        self.broker.expire_workstations()
        mutations = [call for call in self.net.calls if call[0] == "iptables"
                     and call[1] != ("--version",) and call[1][2] != "-S"]
        self.assertEqual(mutations, [])
        self.broker.teardown_workstations()
        self.assertEqual(self.net.filter, original)

    def test_watchdog_model_reproduces_legacy_reset_but_not_corrected_placement(self):
        self.pair()
        self.net.filter["fpbxfirewall"].remove(JUMP)
        self.net.filter["INPUT"].insert(len(BANS), LEGACY_JUMP[:])
        self.assertTrue(self.watchdog_reset())
        self.broker.expire_workstations()
        self.assertFalse(self.watchdog_reset())
        self.assert_placement()

    def test_legacy_input_jumps_migrate_and_never_return_after_rebuild(self):
        self.pair()
        self.net.filter["fpbxfirewall"].remove(JUMP)
        self.net.filter["INPUT"][len(BANS):len(BANS)] = [LEGACY_JUMP, LEGACY_JUMP]
        self.broker.expire_workstations()
        self.assert_placement()
        self.assertEqual(self.input_targets(), BASELINE)
        for _ in range(3):
            self.net.freepbx()
            before_input = json.loads(json.dumps(self.net.filter["INPUT"]))
            self.broker.expire_workstations()
            self.assert_placement()
            self.assertEqual(self.net.filter["INPUT"], before_input)
        self.broker.teardown_workstations()
        self.assertNotIn(CHAIN, self.net.filter)

    def test_cleanup_removes_both_legacy_and_current_duplicate_jumps(self):
        self.pair()
        self.net.filter["INPUT"].insert(len(BANS), LEGACY_JUMP[:])
        self.net.filter["fpbxfirewall"].append(JUMP[:])
        self.broker.teardown_workstations()
        self.assertEqual(self.input_targets(), BASELINE)
        self.assertEqual(self.net.filter["fpbxfirewall"], [["-i", "lo", "-j", "ACCEPT"], ["-j", "DROP"]])
        self.assertNotIn(CHAIN, self.net.filter)

    def test_broker_restart_restores_exact_policy_without_extending_expiry(self):
        self.pair(mode="temporary")
        saved = (self.state / "workstations.json").read_text()
        replacement = broker.Broker()
        replacement.run = self.net.run
        replacement.tool = self.broker.tool
        replacement.iptables_tool = self.broker.iptables_tool
        replacement.audit = lambda *args: None
        try:
            replacement.restore_workstations()
            self.assertEqual(replacement.integration["state"], "active")
            self.assertEqual((self.state / "workstations.json").read_text(), saved)
            self.assert_placement()
            replacement.teardown_workstations()
        finally:
            if replacement.monitor:
                replacement.monitor.close()

    def test_rebuild_during_insert_withdraws_without_input_repair_loop(self):
        original = self.net.iptables
        def racing(rest):
            result = original(rest)
            if rest[2:4] == ["-I", "fpbxfirewall"]:
                self.net.freepbx()
            return result
        self.net.iptables = racing
        self.pair()
        self.assertEqual(self.input_targets(), BASELINE)
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.broker.integration["state"], "error")
        self.net.iptables = original
        self.broker.expire_workstations()
        self.assert_placement()

    def test_listing_failure_is_not_treated_as_absence(self):
        self.pair()
        self.net.fail = lambda name, rest: name == "iptables" and "-S" in rest
        with self.assertRaises(broker.BrokerError):
            self.broker.teardown_workstations()
        self.assertTrue((self.state / "workstations.json").exists())

    def test_unfamiliar_chain_and_references_are_never_modified(self):
        for change in ({CHAIN: [["-j", "ACCEPT"]]},
                       {CHAIN: [], "fpbxfirewall": [["-j", CHAIN]]},
                       {CHAIN: [], "FORWARD": [JUMP]},
                       {CHAIN: [], "INPUT": [["-i", "eth0", "-m", "comment", "--comment", MARK, "-j", CHAIN], ["-j", "fpbxfirewall"]]},
                       {CHAIN: [["-s", "0.0.0.0/0", "-m", "conntrack", "--ctstate", "NEW", "-m", "comment", "--comment", MARK, "-j", "ACCEPT"]]}):
            self.net.freepbx()
            self.net.filter.update(json.loads(json.dumps(change)))
            snapshot = json.dumps(self.net.filter)
            with self.assertRaises(broker.BrokerError):
                self.pair()
            self.assertEqual(json.dumps(self.net.filter), snapshot)
            self.assertFalse(self.net.up)

    def test_missing_hook_and_iptables_install_nothing(self):
        self.net.filter["INPUT"] = self.baseline_input()[:-1]
        self.pair()
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.broker.integration["state"], "not-detected")
        self.assertTrue(self.net.up)
        self.net.filter = None
        self.pair(nonce="m" * 22)
        self.assertIn("not installed", self.broker.integration["message"])

    def test_fail2ban_prefixes_are_recognised_case_insensitively(self):
        for name in BANS + ["f2b-sshd", "F2B-asterisk", "Fail2Ban-Custom", "FAIL2BAN-x"]:
            self.assertTrue(broker.is_fail2ban_hook(name), name)
        for name in ("fpbxfirewall", "fail2bannish", "xf2b-sshd", "f2b", "fail2ban", "zone-external", None, CHAIN):
            self.assertFalse(broker.is_fail2ban_hook(name), name)

    def test_upstream_and_mixed_fail2ban_layouts(self):
        for layout in (["f2b-sshd"], ["f2b-sshd", "fail2ban-SIP", "F2B-Custom", "Fail2Ban-PBX-GUI"], []):
            self.net.freepbx(layout)
            self.pair(nonce=("%s" % len(layout)) * 22)
            self.assertEqual(self.input_targets(), layout + ["fpbxfirewall"], layout)
            self.assert_placement()
            self.assertEqual(self.broker.integration["state"], "active")
            self.broker.teardown_workstations()

    def test_each_observed_fail2ban_chain_after_freepbx_hook_is_refused(self):
        for name in BANS + ["f2b-sshd", "F2B-Mixed"]:
            self.net.freepbx(BANS + ["f2b-sshd", "F2B-Mixed"])
            self.move_after_hook(name)
            snapshot = json.dumps(self.net.filter)
            self.pair(nonce="m" * 22)
            self.assertEqual(json.dumps(self.net.filter), snapshot, name)
            self.assertEqual(self.broker.integration["state"], "error", name)
            self.assertIn(name, self.broker.integration["message"])
            self.assertIn("Fail2Ban is not bypassed", self.broker.integration["message"])
            self.broker.teardown_workstations()

    def test_reload_moving_fail2ban_after_hook_removes_then_restores_integration(self):
        self.pair()
        self.move_after_hook("fail2ban-PBX-GUI")
        self.broker.expire_workstations()
        self.assertNotIn(CHAIN, self.input_targets())
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.broker.integration["state"], "error")
        self.assertIn("fail2ban-PBX-GUI", self.broker.status()["workstations"]["firewall_integration"]["message"])
        # Still nft-protected; only FreePBX Firewall decides, so Fail2Ban is never bypassed.
        self.assertTrue(self.net.up)
        # Fail2Ban restart re-inserts its hook at position 1: integration returns at the correct position.
        rules = self.net.filter["INPUT"]
        rules.insert(0, rules.pop())
        self.broker.expire_workstations()
        self.assert_placement()
        self.assertEqual(self.broker.integration["state"], "active")

    def test_fail2ban_hook_inserted_during_integration_fails_safe(self):
        original = self.net.iptables

        def racing(rest):
            if rest[2:4] == ["-I", "fpbxfirewall"]:
                # A Fail2Ban hook is appended just before the FreePBX hook between inspection and insertion.
                rules = self.net.filter["INPUT"]
                rules.append(["-j", "fail2ban-late"])
                self.net.filter.setdefault("fail2ban-late", [["-j", "RETURN"]])
            return original(rest)
        self.net.iptables = racing
        self.pair()
        self.assertNotIn(CHAIN, self.input_targets())
        self.assertNotIn(CHAIN, self.net.filter)
        self.assertEqual(self.broker.integration["state"], "error")
        self.assertTrue(self.net.up)

    def test_iptables_reload_events_wake_without_readmission(self):
        self.pair()
        self.broker.wake.clear()
        self.net.emit([{"add": {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 9, "expr": []}}}])
        self.assertTrue(self.broker.wake.wait(1))
        self.assertFalse(self.broker.enforcement_event.is_set())

    def test_rule_parser_rejects_unrecognised_options(self):
        for tokens in (["!", "-s", "1.2.3.4/32", "-j", "ACCEPT"], ["-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"],
                       ["-s", "1.2.3.4/32", "-s", "5.6.7.8/32", "-j", "ACCEPT"], ["-j"]):
            self.assertIsNone(broker.iptables_rule(tokens))
        self.assertEqual(broker.iptables_rule(broker.iptables_arguments(broker.INTEGRATION_JUMP)), broker.INTEGRATION_JUMP)
        with self.assertRaises(broker.BrokerError):
            broker.integration_rules("100.70.1.1", [{"address": "100.70.1.0/24", "ssh": False}], DEFAULT_WEB)

    def test_wireguard_listener_accepts_unknown_sources_without_whitelisting(self):
        """Regression: the public WireGuard handshake permit must exist and never name a source address."""
        self.pair()
        self.assertIn((broker.FWCONSOLE, ("teliphones", "listener", "--listen-port=51821")), self.net.calls)
        self.assertFalse(any(rule.get("p") == "udp" for rule in self.rules()))
        # Every source-scoped rule is a tunnel peer; no public address is ever whitelisted.
        for rule in self.rules():
            self.assertTrue(rule is not None)
            if "s" in rule:
                self.assertTrue(broker.ipaddress.IPv4Network(rule["s"]).subnet_of(broker.WORKSTATION_POOL), rule)

    def test_custom_listen_port_and_stale_udp_permits_are_reconciled(self):
        self.pair(port="51899")
        self.assertIn((broker.FWCONSOLE, ("teliphones", "listener", "--listen-port=51899")), self.net.calls)
        self.net.calls = []
        self.broker.expire_workstations()
        self.assertIn((broker.FWCONSOLE, ("teliphones", "listener", "--listen-port=51899")), self.net.calls)
        self.assertEqual(self.broker.integration["state"], "active")
        # Open mode keeps the listener available for a future pairing, with no peer permits.
        self.unpair("all")
        self.assertIn((broker.FWCONSOLE, ("teliphones", "listener", "--listen-port=51899")), self.net.calls)
        self.assertIn(CHAIN, self.net.filter)
        self.assertEqual(self.accepted(), set())
        self.assertTrue(self.net.up)

    def test_management_web_services_follow_configuration_without_stale_rules(self):
        _, response = self.pair(web="https:8443")
        self.open_session(response)
        self.assertEqual(response["gui_url"], "https://" + response["pbx_address"] + ":8443/admin/")
        self.assertEqual(self.accepted(), {(response["address"], "8443"), (response["address"], "8766")})
        self.assertIn("tcp dport { 8443 } accept", self.net.ruleset)
        # Changing the management ports while the workstation stays paired reconciles both
        # firewall layers and leaves no stale permits.
        result = self.broker.dispatch({"action": "web", "web": "http:80, https:443"}, 1000)
        self.assertTrue(result["ok"])
        self.assertEqual(self.accepted(), {(response["address"], "80"), (response["address"], "443"),
                                           (response["address"], "8766")})
        self.assertNotIn("8443", json.dumps(self.net.filter))
        self.assertIn("tcp dport { 80, 443 } accept", self.net.ruleset)
        self.assertNotIn("8443", self.net.ruleset)
        self.assert_placement()
        status = self.broker.status()["workstations"]
        self.assertEqual([(entry["scheme"], entry["port"]) for entry in status["web"]], [("http", 80), ("https", 443)])
        self.assertEqual(status["gui_url"], "http://" + response["pbx_address"] + "/admin/")
        # The saved pairing keeps working after a broker restart with the new ports.
        replacement = broker.Broker()
        replacement.run = self.net.run
        replacement.tool = self.broker.tool
        replacement.iptables_tool = self.broker.iptables_tool
        replacement.audit = lambda *args: None
        try:
            replacement.restore_workstations()
            self.assertEqual(replacement.integration["state"], "active")
            self.assertEqual(self.accepted(), {(response["address"], "80"), (response["address"], "443"),
                                               (response["address"], "8766")})
        finally:
            if replacement.monitor:
                replacement.monitor.close()

    def test_web_action_inputs_are_strictly_validated(self):
        for value in ("", "ftp:80", "http:0", "http:65536", "https:08", "http:80,http:80", "http", ":443",
                      "http:22", "https:8765", "https:22002",
                      "http:80,https:443,http:81,https:444,http:82", 443):
            with self.assertRaises(broker.BrokerError, msg=str(value)):
                broker.validate({"action": "web", "web": value})
        self.assertEqual(broker.validate({"action": "web", "web": "HTTPS:8443"}), "web")
        self.assertEqual(broker.parse_web("HTTPS:8443, http:80"),
                         [{"scheme": "https", "port": 8443}, {"scheme": "http", "port": 80}])

    def test_listener_transient_failure_recovers_disabled_interface(self):
        self.pair()
        self.net.fail = lambda name, rest: name == broker.FWCONSOLE
        self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertTrue(self.broker.workstation_error)
        self.net.fail = None
        self.broker.expire_workstations()
        self.assertTrue(self.net.up)
        self.assertFalse(self.broker.workstation_error)
        self.assert_placement()

    def test_listener_removal_failure_does_not_skip_other_teardown(self):
        self.pair()
        self.net.fail = lambda name, rest: name == broker.FWCONSOLE
        with self.assertRaises(broker.BrokerError):
            self.broker.teardown_workstations()
        self.assertFalse(self.net.link)
        self.assertIsNone(self.broker.owned_table())
        self.assertNotIn(CHAIN, self.net.filter)
        self.net.fail = None
        self.broker.teardown_workstations()

    def test_web_persistence_failure_restores_active_permissions(self):
        self.pair()
        before, _ = self.broker.workstation_state()
        with patch.object(self.broker, "save_workstations", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.broker.configure_web({"web": "https:8443"}, 1000)
        after, _ = self.broker.workstation_state()
        self.assertEqual(after, before)
        self.assertEqual({port for _, port in self.accepted()}, {"80", "443", "8766"})
        self.assertNotIn("8443", self.net.ruleset)
        self.assertTrue(self.net.up)

    def test_both_custom_web_ports_and_actual_listener_binding(self):
        _, response = self.pair(web="http:8080, https:8443")
        self.open_session(response)
        self.assertEqual(response["gui_url"], "http://" + response["pbx_address"] + ":8080/admin/")
        self.assertEqual({port for _, port in self.accepted()}, {"8080", "8443", "8766"})
        self.assertIn("tcp dport { 8080, 8443 } accept", self.net.ruleset)
        address = response["pbx_address"]
        exact = broker.socket.inet_aton(address)[::-1].hex().upper()
        for bound, expected in ((exact, True), ("00000000", True), ("0100007F", False)):
            tcp4 = "header\n0: %s:20FB 00000000:0000 0A\n" % bound  # TCP 8443
            with patch.object(broker.Path, "read_text", side_effect=[tcp4, "header\n"]):
                self.assertEqual(broker.web_listening(8443, address), expected)
        with patch.object(broker.Path, "read_text", side_effect=OSError("unreadable")):
            self.assertIsNone(broker.web_listening(8443, address))


class NamespaceIntegrationTests(unittest.TestCase):
    def run_lab(self, backend):
        binary = {"nft": "iptables-nft", "legacy": "iptables-legacy"}[backend]
        if not all(shutil.which(tool) for tool in ("unshare", "nsenter", "nft", "ip", "php", binary)):
            self.skipTest("unshare/nsenter/nft/ip/%s unavailable; no host network mutation attempted" % binary)
        probe = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"], capture_output=True, text=True)
        if probe.returncode:
            self.skipTest("user/network namespace capability unavailable: " + probe.stderr.strip())
        script = Path(__file__).with_name("firewall_integration_lab.py")
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable, str(script),
                                 os.readlink("/proc/self/ns/net"), backend],
                                capture_output=True, text=True, timeout=180, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if result.returncode and backend == "legacy" and "can't initialize iptables table" in result.stderr:
            self.skipTest("legacy iptables kernel support unavailable in namespace")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS (%s)" % backend, result.stdout)

    def test_real_packets_iptables_nft_backend(self):
        self.run_lab("nft")

    def test_real_packets_iptables_legacy_backend(self):
        self.run_lab("legacy")
