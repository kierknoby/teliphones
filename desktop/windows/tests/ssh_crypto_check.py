"""Use real OpenSSH to verify the production Ed25519 and SSHSIG implementation."""
import base64
import contextlib
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import socket
import sys
import tempfile
import threading
import time
import unittest

TOOL = sys.argv.pop(1)


def field(value):
    return struct.pack(">I", len(value)) + value


def key_blob(line):
    return base64.b64decode(line.split()[1])


@contextlib.contextmanager
def agent_session(root, user="approved"):
    process = subprocess.Popen([TOOL, "agent"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        public = process.stdout.readline().strip()
        if not public.startswith("ssh-ed25519 "):
            raise RuntimeError("Agent tool did not publish its public identity.")
        (root / "identity.pub").write_text(public + "\n", encoding="ascii")
        if os.name != "nt":
            (root / "identity.pub").chmod(0o600)
        subprocess.run(["ssh-keygen", "-q", "-s", str(root / "ca"), "-I", "agent-test",
                        "-n", user, "-V", "-1m:+5m", str(root / "identity.pub")], check=True)
        if os.name != "nt":
            (root / "identity-cert.pub").chmod(0o600)
        certificate = (root / "identity-cert.pub").read_text().strip()
        host = (root / "host.pub").read_text().strip()
        process.stdin.write(json.dumps({"certificate": certificate, "ca": (root / "ca.pub").read_text().strip(),
                                       "user": user, "host": host}) + "\n")
        process.stdin.flush()
        yield process, public, certificate, host
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        finally:
            process.stdout.close()
            process.stderr.close()


def agent_request(process, request):
    process.stdin.write(base64.b64encode(request).decode() + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("Agent protocol rejected request: " + process.stderr.read())
    response = json.loads(line)
    return base64.b64decode(response["reply"]), response["destroyed"]


def generate_keys(root):
    for name in ("ca", "host"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(root / name)], check=True)
        if os.name != "nt":
            (root / name).chmod(0o600)


class CryptoTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH required; no download attempted")
    def test_agent_certificate_identity_signing_and_destruction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generate_keys(root)
            for method in (b"publickey", b"publickey-hostbound-v00@openssh.com"):
                with self.subTest(method=method), agent_session(root) as (agent, public, cert, host):
                    identities, destroyed = agent_request(agent, b"\13")
                    self.assertEqual(identities, b"\14" + struct.pack(">I", 1) +
                                     field(key_blob(cert)) + field(b"TELIPHONES session"))
                    self.assertFalse(destroyed)
                    for forbidden in (15, 17, 18, 19, 20, 27):
                        self.assertEqual(agent_request(agent, bytes([forbidden])), (b"\5", False))
                    message = (field(b"x" * 32) + b"\62" + field(b"approved") + field(b"ssh-connection") +
                               field(method) + b"\1" + field(b"ssh-ed25519-cert-v01@openssh.com") + field(key_blob(cert)))
                    if method != b"publickey":
                        message += field(key_blob(host))
                    request = b"\15" + field(key_blob(cert)) + field(message) + struct.pack(">I", 0)
                    reply, destroyed = agent_request(agent, request)
                    self.assertTrue(destroyed)
                    self.assertEqual(reply[0], 14)
                    self.assertEqual(agent_request(agent, request), (b"\5", True))
                    self.assertEqual(agent_request(agent, b"\13"), (b"\5", True))
            for mutation in ("wrong-key", "raw-key", "wrong-certificate", "wrong-user", "wrong-host", "flags"):
                with self.subTest(mutation=mutation), agent_session(root) as (agent, public, cert, host):
                    message = (field(b"x" * 32) + b"\62" + field(b"other" if mutation == "wrong-user" else b"approved") +
                               field(b"ssh-connection") + field(b"publickey-hostbound-v00@openssh.com") + b"\1" +
                               field(b"ssh-ed25519-cert-v01@openssh.com") +
                               field(b"other" if mutation == "wrong-certificate" else key_blob(cert)) +
                               field(b"other" if mutation == "wrong-host" else key_blob(host)))
                    key = key_blob(public) if mutation == "raw-key" else b"other" if mutation == "wrong-key" else key_blob(cert)
                    request = b"\15" + field(key) + field(message) + struct.pack(">I", mutation == "flags")
                    with self.assertRaisesRegex(RuntimeError, "Agent protocol rejected request"):
                        agent_request(agent, request)
                    self.assertNotEqual(agent.wait(timeout=5), 0)

    @unittest.skipUnless(os.name != "nt" and shutil.which("sshd") and shutil.which("ssh") and shutil.which("ssh-keygen"),
                         "Local Unix OpenSSH integration requires sshd/ssh/keygen; Windows uses the native named-pipe suite")
    def test_agent_real_openssh_certificate_authentication(self):
        for selection in ("old-fixture", "old-production", "corrected"):
            with self.subTest(selection=selection):
                self.check_agent_openssh(selection)

    def check_agent_openssh(self, selection):
        with tempfile.TemporaryDirectory(prefix="tlp-agent-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            generate_keys(root)
            with agent_session(root, getpass.getuser()) as (agent, public, certificate, host):
                (root / "known_hosts").write_text("fixture " + host + "\n", encoding="ascii")
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0))
                    port = reserve.getsockname()[1]
                config = root / "sshd_config"
                config.write_text(
                    f"Port {port}\nListenAddress 127.0.0.1\nHostKey {root / 'host'}\nPidFile {root / 'pid'}\n"
                    f"TrustedUserCAKeys {root / 'ca.pub'}\nAuthorizedKeysFile none\n"
                    "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nLogLevel DEBUG2\n")
                client = root / "config"
                identity = root / ("identity-cert.pub" if selection == "corrected" else "identity.pub")
                certificate_file = "none" if selection == "corrected" else str(root / "identity-cert.pub")
                algorithms = ("PubkeyAcceptedKeyTypes ssh-ed25519-cert-v01@openssh.com\n"
                              if selection != "old-fixture" else "")
                client.write_text(
                    f"Host *\nHostName 127.0.0.1\nPort {port}\nUser {getpass.getuser()}\nHostKeyAlias fixture\n"
                    f"IdentityAgent {root / 'agent'}\nIdentityFile {identity}\n"
                    f"CertificateFile {certificate_file}\nUserKnownHostsFile {root / 'known_hosts'}\n"
                    "GlobalKnownHostsFile /dev/null\nIdentitiesOnly yes\nBatchMode yes\nStrictHostKeyChecking yes\n"
                    "HostKeyAlgorithms ssh-ed25519\n" + algorithms +
                    "PreferredAuthentications publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
                requests, errors = [], []
                with socket.socket(socket.AF_UNIX) as listener, (root / "sshd.log").open("w+") as log:
                    listener.bind(str(root / "agent"))
                    listener.listen()
                    listener.settimeout(10)

                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection:
                                connection.settimeout(10)

                                def receive(size):
                                    data = b""
                                    while len(data) < size:
                                        chunk = connection.recv(size - len(data))
                                        if not chunk:
                                            raise EOFError("OpenSSH agent connection closed.")
                                        data += chunk
                                    return data

                                while True:
                                    try:
                                        size = struct.unpack(">I", receive(4))[0]
                                    except EOFError:
                                        break
                                    if not 0 < size <= 16384:
                                        raise ValueError("Invalid OpenSSH agent frame.")
                                    request = receive(size)
                                    requests.append(request[0])
                                    reply, _ = agent_request(agent, request)
                                    connection.sendall(field(reply))
                        except Exception as error:
                            errors.append(str(error))

                    server = subprocess.Popen([shutil.which("sshd"), "-D", "-e", "-f", str(config)], stderr=log)
                    worker = threading.Thread(target=serve)
                    worker.start()
                    try:
                        for _ in range(50):
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                    break
                            except ConnectionRefusedError:
                                if server.poll() is not None:
                                    break
                                time.sleep(0.05)
                        result = subprocess.run(["ssh", "-vvv", "-F", str(client), "fixture",
                                                 "printf TELIPHONES_AGENT_LOGIN_OK"], capture_output=True, timeout=15)
                        worker.join(timeout=12)
                        log.flush()
                        log.seek(0)
                        diagnostics = result.stderr.decode(errors="replace") + "\n" + log.read() + "\n" + "\n".join(errors)
                        self.assertFalse(errors, errors)
                        self.assertIn(11, requests)
                        self.assertIn("Server accepts key:", diagnostics)
                        if selection == "corrected":
                            self.assertEqual(result.returncode, 0, diagnostics)
                            self.assertEqual(result.stdout, b"TELIPHONES_AGENT_LOGIN_OK", diagnostics)
                            self.assertNotIn("Load key", diagnostics)
                            self.assertIn(13, requests)
                            self.assertEqual(agent_request(agent, b"\13"), (b"\5", True))
                        else:
                            self.assertNotEqual(result.returncode, 0, diagnostics)
                            self.assertIn("Permission denied (publickey)", diagnostics)
                            self.assertNotIn(13, requests, diagnostics)
                            self.assertFalse(agent_request(agent, b"\13")[1], diagnostics)
                            if selection == "old-fixture":
                                self.assertIn(f'Load key "{identity}": ', diagnostics)
                                self.assertIn(f'using private key "{identity}" for certificate', diagnostics)
                            else:
                                self.assertIn("corresponding algorithm not in PubkeyAcceptedAlgorithms", diagnostics)
                    finally:
                        server.terminate()
                        server.wait(timeout=5)
                        worker.join(timeout=12)

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
