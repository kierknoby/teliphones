import json
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checker_probe import connect_probe, run_checks, sign, tcp_probe
from wireguard_namespace_lab import php_checker_action


class PhpCheckerBridgeTests(unittest.TestCase):
    def test_module_accepts_signed_evidence_from_real_local_probe(self):
        with tempfile.TemporaryDirectory(prefix="teliphones-php-checker-test-") as temporary:
            directory = Path(temporary)
            private_key = directory / "checker.key"
            public_key = directory / "checker.pub"
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)], check=True)
            private_key.chmod(0o600)
            subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True)

            session = {"session_id": secrets.token_hex(16), "topology": "on-pbx", "expires_at": int(time.time()) + 240}
            challenge = php_checker_action("challenge", session, directory / "state", public_key)

            class Handler(BaseHTTPRequestHandler):
                nonce = challenge["nonce"]
                session_id = session["session_id"]

                def do_HEAD(self):
                    if self.path != "/teliphones-checker/1" or self.headers.get("X-TELIPHONES-Challenge") != self.nonce:
                        self.send_response(403)
                        self.end_headers()
                        return
                    self.send_response(204)
                    self.send_header("X-TELIPHONES-Session", self.session_id)
                    self.send_header("X-TELIPHONES-Challenge", self.nonce)
                    self.end_headers()

                def log_message(self, _format, *_args):
                    return

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                authorized = connect_probe("127.0.0.1", server.server_port, False, None,
                                           challenge["nonce"], session["session_id"])
                with socket.socket() as blocked:
                    blocked.bind(("127.0.0.1", 0))
                    blocked_port = blocked.getsockname()[1]
                negative = tcp_probe("127.0.0.1", blocked_port)
                with socket.socket() as public_blocked:
                    public_blocked.bind(("127.0.0.1", 0))
                    public_port = public_blocked.getsockname()[1]
                public = tcp_probe("127.0.0.1", public_port)
                evidence = run_checks(challenge, authorized, negative, public)
                evidence["signature"] = sign(evidence, private_key)
                evidence_file = directory / "evidence.json"
                evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
                result = php_checker_action("accept", session, directory / "state", public_key, evidence_file)
                self.assertTrue(authorized["reachable"])
                self.assertFalse(negative["reachable"])
                self.assertFalse(public["reachable"])
                self.assertTrue(result["accepted"])
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)