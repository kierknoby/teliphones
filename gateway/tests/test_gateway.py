import base64
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from teliphones_gateway import GatewayError, GatewayService, SessionStore, tunnel_pair, validate_config


def key(seed: int) -> str:
    return base64.b64encode(bytes((seed + index) % 256 for index in range(32))).decode("ascii")


def config() -> dict:
    return {
        "deployment_mode": "reference-lab",
        "interface": "wg-teliphones",
        "endpoint": "gateway.invalid:51820",
        "listen_port": 51820,
        "public_key": key(1),
        "private_key_file": "/unused/in-unit-test",
        "support_pool": "10.20.17.0/24",
        "engineer_pool": "10.77.0.0/24",
        "tls_certificate": "/unused/server.crt",
        "tls_private_key": "/unused/server.key",
        "client_ca": "/unused/client-ca.crt",
        "customers": {
            "customer-a": {
                "certificate_sha256": "a" * 64,
                "engineers": ["engineer-a"],
                "ssh_engineer": "engineer-a",
                "services": [80, 443, 22222],
            },
            "customer-b": {
                "certificate_sha256": "b" * 64,
                "engineers": ["engineer-b"],
                "ssh_engineer": "engineer-b",
                "services": [80, 443, 22222],
            },
        },
        "engineers": {
            "engineer-a": {
                "wireguard_public_key": key(33),
                "address": "10.77.0.10",
                "ssh_public_key": "ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test-a",
            },
            "engineer-b": {
                "wireguard_public_key": key(65),
                "address": "10.77.0.11",
                "ssh_public_key": "ssh-ed25519 QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC test-b",
            },
        },
        "checker": {
            "wireguard_public_key": key(129),
            "address": "10.77.0.254",
            "probe_port": 22221,
        },
    }


def record(session_id: str, subnet: str, customer_id: str = "customer-a") -> dict:
    engineer_id = "engineer-a" if customer_id == "customer-a" else "engineer-b"
    return {
        "session_id": session_id,
        "remote_id": session_id,
        "customer_id": customer_id,
        "pbx_key": key(97),
        "pbx_address": "10.20.17.1",
        "gateway_address": "10.20.17.2",
        "subnet": subnet,
        "engineer_ids": f'["{engineer_id}"]',
        "ssh_key": config()["engineers"][engineer_id]["ssh_public_key"],
        "expires_at": 2000,
        "state": "provisioning",
        "created_at": 1000,
    }


class AddressPolicyTests(unittest.TestCase):
    def test_valid_session_pair(self):
        pbx, gateway, subnet = tunnel_pair("10.20.17.1/30", "10.20.17.2/32", "10.20.17.0/24")
        self.assertEqual(str(pbx.ip), "10.20.17.1")
        self.assertEqual(str(gateway.ip), "10.20.17.2")
        self.assertEqual(str(subnet), "10.20.17.0/30")

    def test_rejects_outside_or_reserved_addresses(self):
        for pbx, peer in (
            ("10.20.18.1/30", "10.20.18.2/32"),
            ("10.20.17.0/30", "10.20.17.2/32"),
            ("10.20.17.1/30", "10.20.17.3/32"),
            ("10.20.17.1/30", "10.20.18.2/32"),
        ):
            with self.subTest(pbx=pbx, peer=peer), self.assertRaises(GatewayError):
                tunnel_pair(pbx, peer, "10.20.17.0/24")

    def test_config_requires_explicit_pinned_identities(self):
        valid = config()
        validate_config(valid)
        invalid = config()
        invalid["customers"]["customer-a"]["certificate_sha256"] = "not-a-fingerprint"
        with self.assertRaises(ValueError):
            validate_config(invalid)


class DurableStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SessionStore(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_control_request_nonce_cannot_be_replayed(self):
        request_id = "d" * 64
        self.store.consume_request(request_id, 1500, now=1500)
        with self.assertRaises(GatewayError) as caught:
            self.store.consume_request(request_id, 1500, now=1500)
        self.assertEqual(caught.exception.code, "request-replayed")

    def test_stale_control_request_is_rejected(self):
        with self.assertRaises(GatewayError) as caught:
            self.store.consume_request("e" * 64, 1000, now=2000)
        self.assertEqual(caught.exception.code, "request-freshness-invalid")

    def test_expired_session_is_due_but_address_remains_reserved_until_cleanup(self):
        session = record("1" * 32, "10.20.17.0/30")
        self.store.reserve(session)
        self.store.connected(session["session_id"])
        self.store.activate(session["session_id"])
        self.assertEqual(len(self.store.due(now=2000)), 1)
        self.assertTrue(self.store.overlapping(tunnel_pair("10.20.17.1/30", "10.20.17.2/32", "10.20.17.0/24")[2]))
        self.store.close(session["session_id"], "expired")
        self.assertTrue(self.store.overlapping(tunnel_pair("10.20.17.1/30", "10.20.17.2/32", "10.20.17.0/24")[2]))
        self.store.finalize_cleanup(session["session_id"])
        self.assertFalse(self.store.overlapping(tunnel_pair("10.20.17.5/30", "10.20.17.6/32", "10.20.17.0/24")[2]))

    def test_closed_session_identifier_is_a_tombstone(self):
        session = record("2" * 32, "10.20.17.0/30")
        self.store.reserve(session)
        self.store.close(session["session_id"], "customer-revoked")
        with self.assertRaises(GatewayError) as caught:
            self.store.reserve(session)
        self.assertEqual(caught.exception.code, "session-id-already-used")

    def test_engineer_grant_contains_only_mapped_active_customers(self):
        service = GatewayService(config(), Path(self.temporary.name) / "service-state")
        session = record("3" * 32, "10.20.17.0/30")
        session["expires_at"] = int(time.time()) + 600
        service.store.reserve(session)
        service.store.connected(session["session_id"])
        service.store.activate(session["session_id"])
        other = record("4" * 32, "10.20.17.4/30", "customer-b")
        other["expires_at"] = int(time.time()) + 600
        service.store.reserve(other)
        service.store.connected(other["session_id"])
        service.store.activate("4" * 32)
        probe_only = record("5" * 32, "10.20.17.8/30")
        probe_only["expires_at"] = int(time.time()) + 600
        service.store.reserve(probe_only)
        service.store.connected(probe_only["session_id"])
        grant = service.engineer_grant("engineer-a")
        self.assertEqual([item["session_id"] for item in grant["sessions"]], ["3" * 32])
        checker_grant = service.checker_grant()
        self.assertEqual([item["session_id"] for item in checker_grant["sessions"]], ["5" * 32])

    def test_gateway_response_names_the_enrolled_ssh_engineer(self):
        service = GatewayService(config(), Path(self.temporary.name) / "response-state")
        session = record("6" * 32, "10.20.17.0/30")
        response = service.response(session, ["10.77.0.10/32"])
        self.assertEqual(response["ssh_engineer_address"], "10.77.0.10/32")
        self.assertEqual(response["ssh_public_key"], config()["engineers"]["engineer-a"]["ssh_public_key"])

    def test_existing_nft_table_must_match_exact_reference_policy(self):
        service = GatewayService(config(), Path(self.temporary.name) / "firewall-state")
        rules = [
            'iifname "wg-teliphones" oifname "wg-teliphones" ip saddr . ip daddr . tcp dport @allowed_probe accept',
            'iifname "wg-teliphones" oifname "wg-teliphones" ct state established,related ip saddr . ip daddr . tcp sport @allowed_probe_reverse accept',
            'iifname "wg-teliphones" oifname "wg-teliphones" ip saddr . ip daddr . tcp dport @allowed_tcp accept',
            'iifname "wg-teliphones" oifname "wg-teliphones" ct state established,related ip saddr . ip daddr . tcp sport @allowed_reverse accept',
            'iifname "wg-teliphones" drop',
            'oifname "wg-teliphones" drop',
        ]
        table = '''table inet teliphones {
     set allowed_tcp {
      type ipv4_addr . ipv4_addr . inet_service
      flags timeout
      timeout 4h
     }
     set allowed_reverse {
      type ipv4_addr . ipv4_addr . inet_service
      flags timeout
      timeout 4h
     }
     set allowed_probe {
      type ipv4_addr . ipv4_addr . inet_service
      flags timeout
      timeout 5m
     }
     set allowed_probe_reverse {
      type ipv4_addr . ipv4_addr . inet_service
      flags timeout
      timeout 5m
     }
 chain forward {
  type filter hook forward priority -10; policy accept;
''' + "\n".join("  " + rule for rule in rules) + '''
 }
 chain input {
  type filter hook input priority -10; policy accept;
  iifname "wg-teliphones" drop
 }
}'''
        self.assertTrue(service.firewall_table_valid(table))
        self.assertFalse(service.firewall_table_valid(table.replace('iifname "wg-teliphones" drop', 'iifname "wg-teliphones" accept', 1)))
        self.assertFalse(service.firewall_table_valid(table.replace('chain input {', 'chain input {\n  iifname "wg-teliphones" accept', 1)))
        self.assertFalse(service.firewall_table_valid(table.replace("timeout 5m", "timeout 4h", 1)))


if __name__ == "__main__":
    unittest.main(verbosity=2)