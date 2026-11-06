"""Workstation public-address changes (WireGuard roaming) with the actual broker policy and admission code."""
import copy
import json
import time
import unittest

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


if __name__ == "__main__":
    unittest.main()
