"""Durable revocation with actual broker policy and isolated network/service models."""
import json
import os
import stat
import threading
import types
import unittest
from unittest.mock import Mock, patch

import test_support_broker as helpers

broker = helpers.broker_module


class RevocationTests(unittest.TestCase):
    setUp = helpers.WorkstationPairingTests.setUp
    tearDown = helpers.WorkstationPairingTests.tearDown
    pair = helpers.WorkstationPairingTests.pair
    open_session = helpers.WorkstationPairingTests.open_session

    def revoke(self, identifier="all"):
        return self.broker.dispatch({"action": "unpair", "workstation_id": identifier}, 1000)

    def restart(self):
        restarted = broker.Broker()
        restarted.audit = Mock()
        restarted.run = self.net.run
        restarted.tool = lambda name: name
        restarted.iptables_tool = self.broker.iptables_tool
        restarted.ssh.reconcile = Mock()
        self.addCleanup(lambda: restarted.monitor.close() if restarted.monitor else None)
        restarted.restore_workstations()
        return restarted

    def assert_rejected(self, response, instance=None):
        instance = instance or self.broker
        with self.assertRaisesRegex(broker.BrokerError, "not an approved workstation"):
            instance.workstation_session("heartbeat", response["address"].split("/")[0])
        with self.assertRaisesRegex(broker.ssh.SshError, "not authorised"):
            instance.ssh.authorised(response["workstation_id"], response["address"].split("/")[0])

    def test_listener_failure_cannot_restore_revoked_peer_or_admission(self):
        _, revoked = self.pair()
        self.open_session(revoked)
        original = self.broker.run

        def fail(arguments, **kwargs):
            if arguments[:3] == [broker.FWCONSOLE, "teliphones", "listener"]:
                raise broker.BrokerError("Injected listener failure")
            return original(arguments, **kwargs)

        with patch.object(self.broker, "run", side_effect=fail):
            result = self.revoke()
            self.assertTrue(result["ok"])
            self.assertEqual(result["outcome"], "housekeeping")
            self.assertIn("confirmed", result["message"])
            self.assertEqual(self.net.peers, {})
            self.assertEqual(self.broker.active_sessions(), {})
            self.broker.workstation_retry_at = 0
            self.broker.expire_workstations()
            self.assertEqual(self.net.peers, {})
        self.assert_rejected(revoked)
        self.assert_rejected(revoked, self.restart())
        self.assertEqual(self.net.peers, {})

    def test_unchanged_shared_listener_is_not_reconciled(self):
        _, revoked = self.pair()
        _, other = self.pair(public_key="B" * 42 + "E=")
        self.open_session(other)
        with patch.object(self.broker, "listener_rules_current", return_value=True), \
                patch.object(self.broker, "reconcile_listener", side_effect=AssertionError("Unchanged listener")):
            result = self.revoke(revoked["workstation_id"])
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(set(self.net.peers), {other["workstation_public_key"]})
        self.assertTrue(self.net.up)
        self.assertIn(other["workstation_id"], self.broker.active_sessions())
        self.assertTrue(broker.policy_equal(self.net.table, self.broker.expected_policy(self.broker.workstation_state()[0])))

    def test_listener_failure_does_not_skip_ssh_termination_or_other_peer(self):
        _, revoked = self.pair(ssh="1")
        _, other = self.pair(public_key="B" * 42 + "E=")
        with patch.object(self.broker, "reconcile_listener", side_effect=broker.BrokerError("Listener failure")), \
                patch.object(self.broker.ssh, "reconcile") as ssh:
            result = self.revoke(revoked["workstation_id"])
        self.assertEqual(result["outcome"], "housekeeping")
        ssh.assert_called_once()
        self.assertEqual(ssh.call_args.kwargs, {"start": False})
        self.assertNotIn(revoked["workstation_id"], [item["id"] for item in ssh.call_args.args[0]["workstations"]])
        self.assertEqual(set(self.net.peers), {other["workstation_public_key"]})
        self.assertTrue(self.net.up)

    def test_listener_failure_follows_actual_verified_ssh_unit_termination(self):
        _, revoked = self.pair(ssh="1")
        identifier = revoked["workstation_id"]
        authority = self.broker.ssh
        authority.active.add(identifier)
        stopped = types.SimpleNamespace(returncode=0, stdout=
                                        "ActiveState=inactive\nMainPID=0\nControlPID=0\nLoadState=loaded\n")
        unit = authority.unit(identifier)
        original_reconcile = broker.ssh.Authority.reconcile

        def verify_ssh(state, start=True):
            return original_reconcile(authority, state, start=start)

        def fail_listener(ports):
            self.assertNotIn(identifier, authority.active)
            raise broker.BrokerError("Listener failure")

        with patch.object(authority, "reconcile", side_effect=verify_ssh), \
                patch.object(broker.ssh, "run", return_value=unit + " loaded active running\n"), \
                patch.object(broker.ssh.subprocess, "run", return_value=stopped) as systemctl, \
                patch.object(self.broker, "reconcile_listener", side_effect=fail_listener):
            result = self.revoke()
        self.assertEqual(result["outcome"], "housekeeping")
        self.assertIn(["/usr/bin/systemctl", "stop", unit], [call.args[0] for call in systemctl.call_args_list])
        self.assertTrue(any("show" in call.args[0] for call in systemctl.call_args_list))
        self.assert_rejected(revoked)

    def test_combined_nft_and_peer_removal_failure_is_unconfirmed_and_contained(self):
        _, revoked = self.pair()
        self.open_session(revoked)
        self.net.fail = lambda name, rest: ((name == "nft" and rest == ["-j", "-f", "-"])
                                           or (name == "wg" and rest[-1:] == ["remove"]))
        result = self.revoke()
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "unconfirmed")
        self.assertIn("removal remains unconfirmed", result["error"])
        self.assertIn(revoked["workstation_public_key"], self.net.peers)
        self.assertFalse(self.net.up)
        self.assert_rejected(revoked)
        self.net.fail = None
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        self.broker.expire_workstations()
        self.assertEqual(self.net.peers, {})
        self.assert_rejected(revoked, self.restart())

    def test_failed_containment_is_never_claimed_verified(self):
        self.pair()
        self.net.fail = lambda name, rest: ((name == "nft" and rest == ["-j", "-f", "-"])
                                           or (name == "wg" and rest[-1:] == ["remove"])
                                           or (name == "ip" and rest[:2] in (["link", "set"], ["link", "del"])))
        result = self.revoke()
        self.assertFalse(result["ok"])
        self.assertIn("containment is also unconfirmed", result["error"])
        self.assertTrue(self.net.up)

    def test_successful_command_without_effective_peer_removal_is_rejected(self):
        self.pair()
        original = self.broker.run

        def ineffective(arguments, **kwargs):
            if arguments[0] == "wg" and arguments[-1] == "remove":
                return ""
            return original(arguments, **kwargs)

        with patch.object(self.broker, "run", side_effect=ineffective):
            result = self.revoke()
        self.assertFalse(result["ok"])
        self.assertFalse(self.net.up)

    def test_successful_nft_command_without_matching_readback_is_rejected(self):
        _, revoked = self.pair()
        self.open_session(revoked)
        with patch.object(self.broker, "mutate_policy"):
            result = self.revoke()
        self.assertFalse(result["ok"])
        self.assertFalse(self.net.up)

    def test_crash_after_journal_before_authority_cleanup_survives_restart(self):
        _, revoked = self.pair()
        saved = (self.state / "workstations.json").read_bytes()
        with patch.object(self.broker, "reconcile_revocations", side_effect=SystemExit("crash boundary")):
            with self.assertRaises(SystemExit):
                self.revoke()
        self.assertEqual((self.state / "workstations.json").read_bytes(), saved)
        self.assertEqual(self.broker.workstation_state()[0]["workstations"], [])
        self.assert_rejected(revoked)
        restarted = self.restart()
        self.assert_rejected(revoked, restarted)
        self.assertEqual(self.net.peers, {})
        self.assertNotEqual(restarted.revocations()["operation"]["state"], "running")

    def test_crash_after_peer_removal_before_final_result_survives_restart(self):
        _, revoked = self.pair()
        original = self.broker.save_revocations
        calls = []

        def crash(journal):
            calls.append(True)
            if len(calls) == 2:
                raise SystemExit("before outcome persistence")
            return original(journal)

        with patch.object(self.broker, "save_revocations", side_effect=crash):
            with self.assertRaises(SystemExit):
                self.revoke()
        self.assertEqual(self.net.peers, {})
        self.assert_rejected(revoked, self.restart())

    def test_journal_persistence_failure_prevents_success_and_contains(self):
        self.pair()
        with patch.object(self.broker, "save_revocations", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(broker.BrokerError, "Durable.*could not be confirmed"):
                self.revoke()
        self.assertFalse(self.net.up)
        with self.assertRaisesRegex(broker.BrokerError, "requires verified recovery"):
            self.broker.apply_workstations(self.broker.workstation_state()[0])

    def test_authority_persistence_failure_does_not_undo_journal(self):
        _, revoked = self.pair()
        with patch.object(self.broker, "save_workstations", side_effect=OSError("disk failure")):
            result = self.revoke()
        self.assertFalse(result["ok"])
        self.assert_rejected(revoked)
        self.assert_rejected(revoked, self.restart())

    def test_outcome_persistence_failure_retains_pending_security_decision(self):
        _, revoked = self.pair()
        original = self.broker.save_revocations
        calls = []

        def fail_final(journal):
            calls.append(True)
            if len(calls) == 2:
                raise OSError("outcome failure")
            return original(journal)

        with patch.object(self.broker, "save_revocations", side_effect=fail_final):
            with self.assertRaisesRegex(broker.BrokerError, "outcome persistence failed"):
                self.revoke()
        self.assertFalse(self.net.up)
        self.assert_rejected(revoked, self.restart())

    def test_journal_is_private_fsynced_and_contains_no_credentials(self):
        self.pair(ssh="1")
        original = broker.os.fsync
        syncs = []

        def sync(fd):
            syncs.append(os.fstat(fd).st_mode)
            return original(fd)

        with patch.object(broker.os, "fsync", side_effect=sync):
            self.revoke()
        self.assertTrue(any(stat.S_ISDIR(mode) for mode in syncs))
        self.assertTrue(any(stat.S_ISREG(mode) for mode in syncs))
        path = self.state / "workstation-revocations.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        record = next(iter(json.loads(path.read_text())["records"].values()))
        self.assertEqual(set(record), {"public_key", "dedicated", "outcome", "revoked_at", "administrator_uid"})

    def test_revoked_identity_cannot_be_paired_or_applied_from_stale_state(self):
        self.pair()
        stale = self.broker.workstation_state()[0]
        self.revoke()
        with self.assertRaisesRegex(broker.BrokerError, "identity was revoked"):
            self.pair()
        with self.assertRaisesRegex(broker.BrokerError, "revoked workstation authority"):
            self.broker.apply_workstations(stale, preserve_unrelated=True)
        with self.assertRaisesRegex(broker.BrokerError, "revoked workstation authority"):
            self.broker.save_workstations(stale)

    def test_reconciliation_contends_for_lock_and_cannot_restore_authority(self):
        _, revoked = self.pair()
        entered, attempted = threading.Event(), threading.Event()
        workers, errors = [], []
        original = self.broker.save_revocations

        def background():
            attempted.set()
            try:
                self.broker.expire_workstations()
            except Exception as error:
                errors.append(error)

        def save(journal):
            original(journal)
            if not entered.is_set():
                entered.set()
                worker = threading.Thread(target=background)
                workers.append(worker)
                worker.start()
                self.assertTrue(attempted.wait(5))
                self.assertTrue(worker.is_alive())

        with patch.object(self.broker, "save_revocations", side_effect=save):
            self.assertTrue(self.revoke()["ok"])
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.net.peers, {})
        self.assert_rejected(revoked)

    def test_dedicated_interface_removed_without_affecting_other_peer(self):
        _, revoked = self.pair(sources="198.51.100.10")
        _, other = self.pair(public_key="B" * 42 + "E=")
        interface = self.broker.locked_interface({"id": revoked["workstation_id"]})
        result = self.revoke(revoked["workstation_id"])
        self.assertTrue(result["ok"])
        self.assertNotIn(interface, self.net.devices)
        self.assertEqual(set(self.net.peers), {other["workstation_public_key"]})
        self.assertTrue(self.net.up)

    def test_empty_revoke_all_verifies_and_removes_unexpected_peers(self):
        self.pair()
        self.revoke()
        self.net.peers["A" * 42 + "E="] = "100.70.1.2/32"
        result = self.revoke()
        self.assertTrue(result["ok"])
        self.assertEqual(self.net.peers, {})

    def test_revoke_all_before_first_pairing_has_verified_empty_boundary(self):
        result = self.revoke()
        self.assertTrue(result["ok"])
        self.assertFalse(self.net.up)
        self.assertEqual(self.net.peers, {})

    def test_directory_fsync_failure_does_not_acknowledge_durable_revocation(self):
        _, revoked = self.pair()
        original = broker.os.fsync

        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync failure")
            return original(fd)

        with patch.object(broker.os, "fsync", side_effect=fail):
            with self.assertRaisesRegex(broker.BrokerError, "Durable.*could not be confirmed"):
                self.revoke()
        self.assertFalse(self.net.up)
        self.assert_rejected(revoked)
        self.assert_rejected(revoked, self.restart())

    def test_outcome_directory_fsync_failure_cannot_display_complete(self):
        self.pair()
        original = broker.os.fsync
        directories = []

        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directories.append(fd)
                if len(directories) == 2:
                    raise OSError("outcome directory sync failure")
            return original(fd)

        with patch.object(broker.os, "fsync", side_effect=fail):
            with self.assertRaisesRegex(broker.BrokerError, "outcome persistence failed"):
                self.revoke()
        self.assertEqual(self.broker.revocation_status()["outcome"], "unconfirmed")
        self.assertEqual(self.broker.revocation_status()["state"], "failed")

    def test_invalid_or_empty_journal_prevents_restoration(self):
        self.pair()
        for value in ("{}", '{"records":{}}', '{"records":{"invalid":{}}}', "not JSON"):
            (self.state / "workstation-revocations.json").write_text(value)
            restarted = self.restart()
            self.assertFalse(self.net.up)
            self.assertTrue(restarted.workstation_error)
            with self.assertRaises(broker.BrokerError):
                restarted.workstation_state()

    def test_missing_policy_during_cleanup_is_unconfirmed_and_contained(self):
        _, revoked = self.pair()
        with patch.object(self.broker, "workstation_state", side_effect=[
                self.broker.workstation_state(), broker.BrokerError("Unreadable saved policy")]):
            with self.assertRaisesRegex(broker.BrokerError, "removal remains unconfirmed"):
                self.revoke()
        self.assertFalse(self.net.up)
        self.assertEqual(self.broker.revocations()["operation"]["state"], "failed")
        self.assert_rejected(revoked, self.restart())

    def test_housekeeping_retry_obeys_backoff(self):
        self.pair()
        with patch.object(self.broker, "reconcile_listener", side_effect=broker.BrokerError("Listener failure")) as listener, \
                patch.object(broker.time, "monotonic", return_value=100):
            self.assertEqual(self.revoke()["outcome"], "housekeeping")
            for _ in range(100):
                self.broker.expire_workstations()
            self.assertEqual(listener.call_count, 1)
        self.broker.workstation_retry_at = 0
        self.broker.expire_workstations()
        self.assertEqual(self.broker.revocations()["operation"]["outcome"], "complete")

    def test_housekeeping_backoff_never_defers_enforcement_failure_containment(self):
        _, revoked = self.pair()
        self.pair(public_key="B" * 42 + "E=")
        with patch.object(self.broker, "reconcile_listener", side_effect=broker.BrokerError("Listener failure")):
            self.assertEqual(self.revoke(revoked["workstation_id"])["outcome"], "housekeeping")
            self.assertTrue(self.net.up)
            self.net.table = None
            self.broker.monitor.event({"delete": {"table": {
                "family": "inet", "name": broker.WORKSTATION_TABLE}}})
            self.net.fail = lambda name, rest: name == "nft" and rest == ["-j", "-f", "-"]
            self.broker.expire_workstations()
        self.assertFalse(self.net.up)
        self.assertEqual(self.broker.revocations()["operation"]["outcome"], "unconfirmed")

    def test_concurrent_pairing_and_management_cannot_override_revocation(self):
        _, revoked = self.pair()
        ready, release = threading.Event(), threading.Event()
        original = self.broker.save_revocations
        results = []

        def pause(journal):
            original(journal)
            if not ready.is_set():
                ready.set()
                self.assertTrue(release.wait(5))

        def revoke():
            results.append(self.revoke())

        workers = []
        with patch.object(self.broker, "save_revocations", side_effect=pause):
            revoker = threading.Thread(target=revoke)
            revoker.start()
            try:
                self.assertTrue(ready.wait(5))
                for action in ({"action": "workstation-manage", "workstation_id": revoked["workstation_id"],
                                "state": "lock", "sources": "198.51.100.10"},
                               {"action": "pair", "request": helpers.pair_request(), "endpoint_host": "pbx.example.net",
                                "listen_port": "51821", "mode": "persistent", "minutes": "60", "ssh": "0"}):
                    def attempt(request=action):
                        try:
                            self.broker.dispatch(request, 1000)
                            results.append("unexpected success")
                        except broker.BrokerError:
                            results.append("rejected")
                    worker = threading.Thread(target=attempt)
                    worker.start()
                    workers.append(worker)
                release.set()
            finally:
                release.set()
                revoker.join(10)
                for worker in workers:
                    worker.join(10)
        self.assertFalse(revoker.is_alive())
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(results.count("rejected"), 2)
        self.assertNotIn("unexpected success", results)
        self.assertEqual(self.net.peers, {})


if __name__ == "__main__":
    unittest.main()
