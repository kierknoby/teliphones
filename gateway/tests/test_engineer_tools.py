import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checker_probe import connect_probe, run_checks, tcp_probe
from engineer_config import render
from test_gateway import config


class EngineerConfigTests(unittest.TestCase):
    def test_config_has_only_current_authorized_host_routes(self):
        cfg = config()
        grant = {
            "schema": "teliphones-engineer-grant/1",
            "engineer_address": "10.77.0.10/32",
            "engineer_public_key": cfg["engineers"]["engineer-a"]["wireguard_public_key"],
            "gateway_public_key": cfg["public_key"],
            "endpoint": cfg["endpoint"],
            "sessions": [
                {"pbx_address": "10.20.17.1", "expires_at": int(time.time()) + 600},
                {"pbx_address": "10.20.17.5", "expires_at": int(time.time()) - 1},
            ],
        }
        text = render(grant, "engineer-private", grant["engineer_public_key"])
        self.assertIn("AllowedIPs = 10.20.17.1/32", text)
        self.assertNotIn("10.20.17.5/32", text)
        self.assertNotIn("0.0.0.0/0", text)

    def test_mismatched_engineer_key_is_rejected(self):
        grant = {
            "schema": "teliphones-engineer-grant/1",
            "engineer_address": "10.77.0.10/32",
            "engineer_public_key": "registered-key",
            "gateway_public_key": config()["public_key"],
            "endpoint": "gateway.invalid:51820",
            "sessions": [{"pbx_address": "10.20.17.1", "expires_at": int(time.time()) + 60}],
        }
        with self.assertRaises(ValueError):
            render(grant, "unrelated-private-key", "wrong-public-key")

    def test_checker_config_is_limited_to_connected_probe_routes(self):
        cfg = config()
        grant = {
            "schema": "teliphones-checker-grant/1",
            "checker_address": "10.77.0.254/32",
            "checker_public_key": cfg["checker"]["wireguard_public_key"],
            "gateway_public_key": cfg["public_key"],
            "endpoint": cfg["endpoint"],
            "sessions": [{"pbx_address": "10.20.17.1", "probe_port": 22221, "expires_at": int(time.time()) + 600}],
        }
        text = render(grant, "checker-private", grant["checker_public_key"])
        self.assertIn("AllowedIPs = 10.20.17.1/32", text)
        self.assertNotIn("0.0.0.0/0", text)


class CheckerEvidenceTests(unittest.TestCase):
    def test_observations_reflect_real_probe_outcomes(self):
        challenge = {"protocol": "teliphones-checker/1", "session_id": "a" * 32, "topology": "on-pbx", "nonce": "n" * 48}
        evidence = run_checks(
            challenge,
            {"reachable": True, "result": {"tls": "verified", "http_status": 302}},
            {"reachable": False, "result": None},
            {"reachable": False, "result": None},
        )
        self.assertEqual(evidence["nonce"], challenge["nonce"])
        self.assertEqual(evidence["observations"]["authorised_source"]["support_service"], "reachable")
        self.assertEqual(evidence["observations"]["negative_source"]["support_service"], "blocked")
        self.assertEqual(evidence["observations"]["public_address"]["support_service"], "blocked")

    def test_probe_requires_exact_session_and_nonce_echo(self):
        class ProbeHandler(BaseHTTPRequestHandler):
            expected_nonce = "n" * 48
            expected_session = "a" * 32

            def do_HEAD(self):
                if self.path != "/teliphones-checker/1":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(204)
                self.send_header("X-TELIPHONES-Session", self.expected_session)
                self.send_header("X-TELIPHONES-Challenge", self.expected_nonce)
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            positive = connect_probe("127.0.0.1", server.server_port, False, None, "n" * 48, "a" * 32)
            self.assertTrue(positive["reachable"])
            self.assertTrue(tcp_probe("127.0.0.1", server.server_port)["reachable"])
            negative = connect_probe("127.0.0.1", server.server_port, False, None, "wrong-nonce", "a" * 32)
            self.assertFalse(negative["reachable"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        self.assertFalse(tcp_probe("127.0.0.1", server.server_port)["reachable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)