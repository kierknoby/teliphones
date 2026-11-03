"""Use real OpenSSH to verify the production Ed25519 and SSHSIG implementation."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest

TOOL = sys.argv.pop(1)


class CryptoTests(unittest.TestCase):
    def test_agent_signing_restricted_to_bound_ssh_authentication(self):
        def field(value):
            return struct.pack(">I", len(value)) + value

        def message(user=b"approved", method=b"publickey", certificate=b"\1\2\3",
                    host=b"\4\5\6", service=b"ssh-connection", kind=50, suffix=b""):
            result = (field(b"x" * 32) + bytes([kind]) + field(user) + field(service) +
                      field(method) + b"\1" + field(b"ssh-ed25519-cert-v01@openssh.com") + field(certificate))
            if method == b"publickey-hostbound-v00@openssh.com":
                result += field(host)
            return result + suffix

        cases = [
            (True, message()),
            (True, message(method=b"publickey-hostbound-v00@openssh.com")),
            (False, message(user=b"root")),
            (False, message(service=b"other")),
            (False, message(kind=49)),
            (False, message(method=b"arbitrary-signature")),
            (False, message(certificate=b"another session")),
            (False, message(method=b"publickey-hostbound-v00@openssh.com", host=b"untrusted")),
            (False, message(suffix=b"\0")),
            (False, message()[:-1]),
            (False, b"arbitrary data"),
        ]
        for accepted, value in cases:
            with self.subTest(message=value, accepted=accepted):
                result = subprocess.run([TOOL, "authentication"],
                                        input=json.dumps({"message": base64.b64encode(value).decode()}),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_destroyed_key_cannot_sign_or_export(self):
        subprocess.run([TOOL, "lifetime"], check=True, capture_output=True)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH required; no download attempted")
    def test_identity_migration_signature_and_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("identity", "ca", "wrong"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(root / name)], check=True)
                if os.name != "nt":
                    (root / name).chmod(0o600)
            identity = subprocess.run([TOOL, "identity"], input=(root / "identity").read_text(),
                                      capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(identity, (root / "identity.pub").read_text().strip())
            signed = json.loads(subprocess.run([TOOL, "signature"], text=True, capture_output=True, check=True).stdout)
            (root / "allowed").write_text("workstation " + signed["public"] + "\n")
            (root / "signature").write_text(signed["signature"])
            verify = ["ssh-keygen", "-Y", "verify", "-f", str(root / "allowed"), "-I", "workstation",
                      "-n", "teliphones-ssh", "-s", str(root / "signature")]
            self.assertEqual(subprocess.run(verify, input="test challenge", text=True, capture_output=True).returncode, 0)
            self.assertNotEqual(subprocess.run(verify, input="substituted challenge", text=True, capture_output=True).returncode, 0)
            subprocess.run(["ssh-keygen", "-q", "-s", str(root / "ca"), "-I", "test", "-n", "workstation",
                            "-V", "-1m:+5m", str(root / "identity.pub")], check=True)
            certificate = (root / "identity-cert.pub").read_text()

            def check(cert, ca):
                return subprocess.run([TOOL, "certificate"], input=json.dumps({"certificate": cert, "ca": ca}),
                                      text=True, capture_output=True)

            ca = (root / "ca.pub").read_text().strip()
            self.assertEqual(check(certificate, ca).returncode, 0)
            self.assertNotEqual(check(certificate, (root / "wrong.pub").read_text().strip()).returncode, 0)
            fields = certificate.split()
            raw = bytearray(base64.b64decode(fields[1]))
            raw[-1] ^= 1
            fields[1] = base64.b64encode(raw).decode()
            self.assertNotEqual(check(" ".join(fields), ca).returncode, 0)


if __name__ == "__main__":
    unittest.main()
