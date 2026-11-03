#!/usr/bin/env python3
"""Portable client contracts; Linux broker admission is tested separately."""

import base64
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
TOOL = sys.argv.pop(1) if len(sys.argv) > 1 else os.environ["TELIPHONES_CONTRACT_TOOL"]


class PortableImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ("fcntl", "pwd", "grp", "support_broker", "broker_tests"):
            raise ImportError("Portable client contracts must not import " + fullname)
        return None


sys.meta_path.insert(0, PortableImports())


def encoded(prefix, value):
    return prefix + base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def tool(*args, stdin=None):
    return subprocess.run([TOOL, *args], input=stdin, text=True, capture_output=True, timeout=10)


class ClientContracts(unittest.TestCase):
    def setUp(self):
        self.key = base64.b64encode(hashlib.sha256(b"workstation").digest()).decode()
        self.pbx_key = base64.b64encode(hashlib.sha256(b"pbx").digest()).decode()
        self.private = base64.b64encode(hashlib.sha256(b"private").digest()).decode()
        self.nonce = base64.urlsafe_b64encode(bytes(range(16))).decode().rstrip("=")
        self.now = int(time.time())
        self.response = {
            "schema": "teliphones-pair-response/1", "nonce": self.nonce,
            "workstation_id": "0123456789abcdef", "workstation_public_key": self.key,
            "address": "100.70.1.2/32", "pbx_address": "100.70.1.1",
            "pbx_name": "PBX", "pbx_public_key": self.pbx_key,
            "endpoint": "pbx.example.net:51821", "mode": "temporary",
            "expires_at": self.now + 3600, "ssh": False,
            "gui_url": "http://100.70.1.1/admin/",
        }

    def response_code(self, **changes):
        return encoded("TELIPHONES-PAIR-RESPONSE-1:", {**self.response, **changes})

    def test_pair_request_schema_and_binding(self):
        result = tool("request", "ADMIN-PC (Office)", self.key, self.nonce)
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix, body = result.stdout.strip().split(":", 1)
        self.assertEqual(prefix, "TELIPHONES-PAIR-REQUEST-1")
        request = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        self.assertEqual(request, {"schema": "teliphones-pair-request/1",
                                  "workstation": "ADMIN-PC (Office)",
                                  "public_key": self.key, "nonce": self.nonce})
        for name, key, nonce in (("-invalid", self.key, self.nonce),
                                 ("ADMIN-PC", "invalid", self.nonce),
                                 ("ADMIN-PC", self.key, "invalid")):
            with self.subTest(name=name, key=key, nonce=nonce):
                self.assertNotEqual(tool("request", name, key, nonce).returncode, 0)

    def test_response_profile_and_administrator_tunnel(self):
        for mode, expiry in (("temporary", self.now + 3600), ("persistent", None)):
            with self.subTest(mode=mode):
                code = self.response_code(mode=mode, expires_at=expiry)
                result = tool("response", code, self.nonce, self.key)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(),
                                 f"0123456789abcdef 100.70.1.2/32 100.70.1.1 pbx.example.net:51821 {mode} {expiry or 0} nossh")
                rendered = tool("administrator", code, self.nonce, self.key, self.private)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                self.assertEqual(rendered.stdout.strip(),
                                 f"[Interface]\nPrivateKey = {self.private}\nAddress = 100.70.1.2/32\n\n"
                                 f"[Peer]\nPublicKey = {self.pbx_key}\nEndpoint = pbx.example.net:51821\n"
                                 "AllowedIPs = 100.70.1.1/32\nPersistentKeepalive = 25")

    def test_response_rejects_wrong_binding_or_unsafe_routes(self):
        for code, nonce, key in (
            (self.response_code(), "abcdefghijklmnopqrstuv", self.key),
            (self.response_code(), self.nonce, self.pbx_key),
            (self.response_code(address="0.0.0.0/0"), self.nonce, self.key),
            (self.response_code(pbx_address="127.0.0.1"), self.nonce, self.key),
            (self.response_code(mode="unrestricted"), self.nonce, self.key),
        ):
            with self.subTest(code=code, nonce=nonce, key=key):
                self.assertNotEqual(tool("response", code, nonce, key).returncode, 0)

    def test_fingerprints_match_sha256(self):
        for key in (self.key, self.pbx_key):
            expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key)).digest()).decode()[:16]
            result = tool("fingerprint", key)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def test_support_tunnel_matches_portable_gateway_renderer(self):
        spec = importlib.util.spec_from_file_location("engineer_config", ROOT / "gateway/engineer_config.py")
        engineer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engineer)
        grant = {
            "schema": "teliphones-engineer-grant/1", "engineer_id": "engineer-a",
            "engineer_address": "10.99.0.2/32", "engineer_public_key": self.key,
            "gateway_public_key": self.pbx_key, "endpoint": "gateway.example.net:51820",
            "sessions": [{"session_id": "session-1", "pbx_address": "10.20.4.2",
                          "expires_at": self.now + 3600}],
        }
        rendered = tool("support", self.private, "session-1", str(self.now), stdin=json.dumps(grant))
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual(rendered.stdout.strip(), engineer.render(grant, self.private, self.key).strip())
        self.assertNotEqual(tool("support", self.private, "unauthorised", str(self.now),
                                 stdin=json.dumps(grant)).returncode, 0)
        self.assertNotEqual(tool("support", self.private, "session-1", str(self.now + 3601),
                                 stdin=json.dumps(grant)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
