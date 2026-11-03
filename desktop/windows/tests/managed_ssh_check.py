"""Verify the portable client against actual OpenSSH certificate encodings."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


TOOL = sys.argv.pop(1)


class ManagedSshContract(unittest.TestCase):
    def test_real_certificate_bindings(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("OpenSSH is unavailable; no dependencies downloaded")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("ca", "host", "client", "session", "wrong"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(root / name)], check=True)
                if os.name != "nt":
                    os.chmod(root / name, 0o600)
            key = lambda name: (root / (name + ".pub")).read_text().strip()
            now = int(time.time())
            expiry = now + 120
            workstation = "0123456789abcdef"
            session_id = "0123456789abcdef0123456789abcdef"
            principal = "tlp-eph-" + workstation + "-" + hashlib.sha256(key("client").encode()).hexdigest()[:16]
            wg = base64.b64encode(bytes(range(1, 33))).decode()
            nonce = "abcdefghijklmnopqrstuv"
            response = {"schema": "teliphones-pair-response/2", "nonce": nonce, "workstation_id": workstation,
                        "workstation_public_key": wg, "address": "100.70.1.2/32", "pbx_address": "100.70.1.1",
                        "pbx_name": "PBX", "pbx_public_key": wg, "endpoint": "pbx.example.net:51821",
                        "mode": "temporary", "expires_at": now + 300, "ssh": True, "gui_url": "http://100.70.1.1/admin/",
                        "ssh_user": "administrator", "ssh_host_key": key("host"), "ssh_ca_key": key("ca"),
                        "ssh_port": 22002, "ssh_api_port": 8765}

            def sign(identity=principal, source="100.70.1.2/32"):
                date = lambda stamp: time.strftime("%Y%m%d%H%M%SZ", time.gmtime(stamp))
                subprocess.run(["ssh-keygen", "-q", "-s", str(root / "ca"), "-I", "ws-" + workstation + "/" + session_id,
                                "-n", identity, "-V", date(now) + ":" + date(expiry), "-O", "clear", "-O", "permit-pty",
                                "-O", "source-address=" + source, str(root / "session.pub")], check=True)
                return (root / "session-cert.pub").read_text()

            def check(certificate, fields=None, public=None, at=now, until=expiry, session=None, identity=session_id):
                payload = base64.urlsafe_b64encode(json.dumps({**response, **(fields or {})}).encode()).decode().rstrip("=")
                return subprocess.run([TOOL, "certificate", "TELIPHONES-PAIR-RESPONSE-2:" + payload, nonce, wg,
                                       public or key("client"), identity, session or key("session"), str(at), str(until)],
                                      input=certificate, text=True, capture_output=True)

            certificate = sign()
            inspected = subprocess.run(["ssh-keygen", "-L", "-f", str(root / "session-cert.pub")], capture_output=True)
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            result = check(certificate)
            self.assertEqual(result.returncode, 0, result.stderr)
            for fields in ({"ssh_ca_key": key("wrong")}, {"ssh_port": 22}, {"ssh_user": "-root"},
                           {"ssh_api_port": 80}, {"expires_at": now + 30}, {"ssh": False}):
                with self.subTest(fields=fields):
                    self.assertNotEqual(check(certificate, fields).returncode, 0)
            self.assertNotEqual(check(certificate, public=key("wrong")).returncode, 0)
            self.assertNotEqual(check(certificate, session=key("wrong")).returncode, 0)
            self.assertNotEqual(check(certificate, session=key("client")).returncode, 0,
                                "the persistent pairing identity must never be the certificate subject")
            self.assertNotEqual(check(certificate, identity="f" * 32).returncode, 0)
            self.assertNotEqual(check(certificate, identity="invalid").returncode, 0)
            self.assertNotEqual(check(certificate, at=expiry).returncode, 0)
            self.assertNotEqual(check(certificate, until=expiry + 1).returncode, 0)
            self.assertNotEqual(check(sign(identity="other")).returncode, 0)
            self.assertNotEqual(check(sign(source="100.70.1.3/32")).returncode, 0)
            self.assertEqual(check(certificate, at=now - 15).returncode, 0, "bounded clock skew must not break valid pairing")
            self.assertNotEqual(check(certificate, at=now - 31).returncode, 0)
            expiry = now + 300
            self.assertEqual(check(sign(), until=expiry).returncode, 0, "exact five-minute certificate must be accepted")
            expiry = now + 301
            self.assertNotEqual(check(sign(), fields={"expires_at": now + 1000}, until=expiry).returncode, 0,
                                "a certificate exceeding five minutes must be rejected")
            # Binding validation is not cryptographic; OpenSSH must reject a tampered signature separately.
            raw = certificate.split()
            blob = bytearray(base64.b64decode(raw[1]))
            blob[-1] ^= 1
            raw[1] = base64.b64encode(blob).decode()
            (root / "tampered.pub").write_text(" ".join(raw) + "\n")
            self.assertEqual(check(" ".join(raw) + "\n").returncode, 0,
                             "the portable parser checks bindings, not the digital signature")
            verified = subprocess.run(["ssh-keygen", "-L", "-f", str(root / "tampered.pub")], capture_output=True)
            self.assertNotEqual(verified.returncode, 0)


if __name__ == "__main__":
    unittest.main()
