"""Genuine Windows named-pipe agent/OpenSSH tests; never use a real PBX."""
import base64
import ctypes
import json
import hashlib
import http.server
import os
import queue
import shutil
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HOST = Path(sys.argv.pop(1)).resolve()
OPENSSH = Path(os.environ["SystemRoot"]) / "System32/OpenSSH"
SSH = OPENSSH / "ssh.exe"
SSHD = OPENSSH / "sshd.exe"
KEYGEN = OPENSSH / "ssh-keygen.exe"

def kernel32():
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
    return kernel

def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, text=True, timeout=20, **kwargs).stdout


def line(process, timeout=40):
    results = queue.Queue()

    def read():
        try:
            results.put(process.stdout.readline())
        except Exception as error:
            results.put(error)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        result = results.get(timeout=timeout)
    except queue.Empty:
        process.kill()
        process.wait(timeout=10)
        reader.join(timeout=5)
        raise TimeoutError("Native SSH harness did not produce its next protocol line.")
    reader.join(timeout=5)
    if isinstance(result, Exception):
        raise result
    return result.strip()


def quoted(path):
    return '"' + str(path).replace("\\", "/").replace('"', '\\"') + '"'


def alive(pid):
    kernel = kernel32()
    process = kernel.OpenProcess(0x100000, False, pid)
    if not process:
        return False
    try:
        return kernel.WaitForSingleObject(ctypes.c_void_p(process), 0) == 258
    finally:
        kernel.CloseHandle(ctypes.c_void_p(process))


class WindowsSshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "nt":
            raise RuntimeError("This harness must run natively on Windows.")
        for path in (HOST, SSH, SSHD, KEYGEN):
            if not path.is_file():
                raise RuntimeError(f"Native prerequisite missing: {path}. No Unix substitute or silent skip is permitted.")
        print(subprocess.run([str(SSH), "-V"], capture_output=True, text=True).stderr.strip())
        cls.temporary = tempfile.TemporaryDirectory(prefix="TELIPHONES-native-ssh-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.user = os.environ["USERNAME"].lower()
        cls.sid = json.loads(run(["powershell.exe", "-NoProfile", "-Command",
                                 "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json"]))
        run(["icacls.exe", cls.root, "/inheritance:r", "/grant:r", f"*{cls.sid}:(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)"])
        for name in ("ca", "host"):
            run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", cls.root / name])
        cls.ca = (cls.root / "ca.pub").read_text().strip()
        cls.host = (cls.root / "host.pub").read_text().strip()
        cls.principal = "teliphones-native-test"
        (cls.root / "principals").write_text(cls.principal + "\n")
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 22001))
            cls.port = 22001
        cls.config = cls.root / "sshd_config"
        cls.config.write_text(
            f"Port {cls.port}\nListenAddress 127.0.0.1\nHostKey {quoted(cls.root / 'host')}\n"
            f"PidFile {quoted(cls.root / 'sshd.pid')}\nAllowUsers {cls.user}\n"
            f"TrustedUserCAKeys {quoted(cls.root / 'ca.pub')}\nAuthorizedPrincipalsFile {quoted(cls.root / 'principals')}\n"
            "AuthorizedKeysFile none\nPubkeyAuthentication yes\nAuthenticationMethods publickey\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
            "AllowAgentForwarding no\nAllowTcpForwarding no\nPermitTunnel no\nLogLevel DEBUG2\n"
        )
        run([SSHD, "-t", "-f", cls.config])
        cls.server_log = open(cls.root / "sshd-test.log", "w", encoding="utf-8")
        cls.addClassCleanup(cls.server_log.close)
        cls.server = subprocess.Popen([str(SSHD), "-D", "-e", "-f", str(cls.config)],
                                      stdout=cls.server_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop, cls.server)
        for _ in range(100):
            if cls.server.poll() is not None:
                cls.server_log.flush()
                raise RuntimeError("Native fixture sshd exited: " + (cls.root / "sshd-test.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Native fixture sshd never became responsive.")

    def start(self, command="echo TELIPHONES_LOGIN_OK", expired=False, wrong_host=False, tamper=False, cert_from=None, crash=False):
        token = secrets.token_hex(16)
        root = self.root / token
        root.mkdir()
        host = subprocess.Popen([str(HOST)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        self.addCleanup(lambda: self.stop(host))
        public = line(host)
        self.assertTrue(public.startswith("ssh-ed25519 "), public)
        (root / "identity.pub").write_text(public + "\n")
        run([KEYGEN, "-q", "-s", self.root / "ca", "-I", token, "-n", self.principal,
             "-V", "-10m:-5m" if expired else "-1m:+5m", "-O", "clear",
             "-O", "source-address=127.0.0.1", root / "identity.pub"])
        cert = (root / "identity-cert.pub").read_text().strip()
        if cert_from:
            cert = cert_from
        if tamper:
            fields = cert.split()
            raw = bytearray(base64.b64decode(fields[1]))
            raw[-1] ^= 1
            fields[1] = base64.b64encode(raw).decode()
            cert = " ".join(fields)
        (root / "certificate.pub").write_text(cert + "\n")
        (root / "known_hosts").write_text("fixture " + (self.ca if wrong_host else self.host) + "\n")
        pipe = r"\\.\pipe\TELIPHONES-native-" + token
        # Backslashes must survive OpenSSH's configuration parser.
        agent = '"' + pipe.replace("\\", "\\\\") + '"'
        config = root / "config"
        config.write_text(
            f"Host *\nHostName 127.0.0.1\nPort {self.port}\nUser {self.user}\nHostKeyAlias fixture\n"
            f"IdentityAgent {agent}\nIdentityFile {quoted(root / 'identity.pub')}\n"
            f"CertificateFile {quoted(root / 'certificate.pub')}\nUserKnownHostsFile {quoted(root / 'known_hosts')}\n"
            "GlobalKnownHostsFile NUL\nStrictHostKeyChecking yes\nUpdateHostKeys no\n"
            "IdentitiesOnly yes\nBatchMode yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PreferredAuthentications publickey\nConnectTimeout 5\nControlMaster no\nControlPath none\n"
        )
        params = {"pipe": pipe, "certificate": cert, "ca": self.ca, "host": self.host,
                  "user": self.user, "ssh": str(SSH), "config": str(config), "command": command, "crash": crash}
        host.stdin.write(json.dumps(params) + "\n")
        host.stdin.flush()
        if tamper:
            return host, root, pipe, None, cert
        pid = line(host)
        self.assertTrue(pid.startswith("SSH_PID="), pid + host.stderr.read() if host.poll() is not None else pid)
        self.assertEqual(line(host), "PIPE_READY")
        return host, root, pipe, int(pid.split("=")[1]), cert

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    def go(self, host):
        host.stdin.write("go\n")
        host.stdin.flush()

    def test_native_login_destroys_key_and_creates_no_private_key_files(self):
        host, root, _, _, _ = self.start()
        self.go(host)
        output, error = host.communicate(timeout=30)
        self.assertEqual(host.returncode, 0, output + error)
        self.assertIn("TELIPHONES_LOGIN_OK", output)
        self.assertIn("KEY_DESTROYED=1", output)
        for file in root.iterdir():
            self.assertNotIn(b"PRIVATE KEY", file.read_bytes())
        self.assertEqual({p.name for p in root.iterdir()},
                         {"identity.pub", "identity-cert.pub", "certificate.pub", "known_hosts", "config"})

    def test_other_process_cannot_enumerate_or_use_agent(self):
        host, _, pipe, _, _ = self.start()
        kernel = kernel32()
        handle = kernel.CreateFileW(pipe, 0xC0000000, 0, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            count = ctypes.c_ulong()
            packet = struct.pack(">IB", 1, 11)
            kernel.WriteFile(ctypes.c_void_p(handle), packet, len(packet), ctypes.byref(count), None)
            output = ctypes.create_string_buffer(4)
            result = kernel.ReadFile(ctypes.c_void_p(handle), output, 4, ctypes.byref(count), None)
            self.assertFalse(result and count.value, "An unrelated process enumerated session credentials.")
        finally:
            kernel.CloseHandle(ctypes.c_void_p(handle))
        self.go(host)
        output, error = host.communicate(timeout=30)
        self.assertEqual(host.returncode, 0, output + error)

    def test_new_process_handles_cannot_read_memory_or_duplicate_credentials(self):
        host, _, _, pid, _ = self.start()
        kernel = kernel32()
        for target in (host.pid, pid):
            for rights in (0x10, 0x20, 0x40, 0x2):  # VM_READ, VM_WRITE, DUP_HANDLE, CREATE_THREAD
                handle = kernel.OpenProcess(rights, False, target)
                if handle:
                    kernel.CloseHandle(handle)
                self.assertFalse(handle, f"An unrelated process obtained sensitive rights {rights} to {target}")
        self.go(host)
        output, error = host.communicate(timeout=30)
        self.assertEqual(host.returncode, 0, output + error)

    def test_concurrent_sessions_and_wrong_certificate(self):
        first, _, _, _, cert = self.start()
        second, _, _, _, other = self.start()
        self.assertNotEqual(cert, other)
        self.go(first)
        self.go(second)
        for host in (first, second):
            output, error = host.communicate(timeout=30)
            self.assertEqual(host.returncode, 0, output + error)
        mismatched, _, _, _, _ = self.start(cert_from=cert)
        self.go(mismatched)
        mismatched.communicate(timeout=30)
        self.assertNotEqual(mismatched.returncode, 0)

    def test_expired_cert_and_wrong_host_fail_without_password_fallback(self):
        for fields in ({"expired": True}, {"wrong_host": True}, {"tamper": True}):
            with self.subTest(fields=fields):
                host, _, _, _, _ = self.start(**fields)
                if not fields.get("tamper"):
                    self.go(host)
                output, error = host.communicate(timeout=30)
                self.assertNotEqual(host.returncode, 0, output + error)

    def test_controller_crash_kills_owned_ssh_only(self):
        unrelated, _, _, unrelated_pid, _ = self.start(command="ping -n 40 127.0.0.1")
        owned, _, _, pid, _ = self.start(command="ping -n 40 127.0.0.1")
        self.go(unrelated)
        self.go(owned)
        time.sleep(3)
        self.assertTrue(alive(pid))
        self.assertTrue(alive(unrelated_pid))
        owned.kill()
        owned.wait(timeout=10)
        for _ in range(100):
            if not alive(pid):
                break
            time.sleep(0.05)
        self.assertFalse(alive(pid), "Controller crash orphaned its SSH process.")
        self.assertTrue(alive(unrelated_pid), "Controller crash killed an unrelated session.")

    def test_ssh_crash_ends_agent_and_prevents_reuse(self):
        host, _, pipe, _, _ = self.start(command="ping -n 40 127.0.0.1", crash=True)
        self.go(host)
        host.communicate(timeout=15)
        self.assertNotEqual(host.returncode, 0)
        kernel = kernel32()
        self.assertFalse(kernel.WaitNamedPipeW(pipe, 100), "Destroyed agent endpoint survived its owner.")

    def test_production_dpapi_identity_certificate_api_console_and_disconnect(self):
        self.production()

    def test_production_certificate_refusal_cleans_identity_without_launch(self):
        self.production(denied=True)

    def test_production_local_authorisation_expiry_ends_owned_session(self):
        self.production(expiring=True)

    def production(self, denied=False, expiring=False):
        log_offset = (self.root / "sshd-test.log").stat().st_size
        profile = secrets.token_hex(8)
        identity_path = Path(os.environ["LOCALAPPDATA"]) / "TELIPHONES/SSH" / (profile + ".dpapi")
        runtime = identity_path.parent / profile
        self.assertFalse(identity_path.exists())
        self.assertFalse(runtime.exists())
        self.addCleanup(lambda: identity_path.unlink(missing_ok=True))
        self.addCleanup(lambda: shutil.rmtree(runtime) if runtime.exists() else None)
        host = subprocess.Popen([str(HOST), "--production", profile], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        self.addCleanup(lambda: self.stop(host))
        identity = line(host)
        self.assertTrue(identity.startswith("ssh-ed25519 "), identity)
        principal = "tlp-eph-" + profile + "-" + hashlib.sha256(identity.encode()).hexdigest()[:16]
        (self.root / "principals").write_text(principal + "\n")
        nonce = secrets.token_hex(32)
        observed = []
        errors = []
        fixture = self
        deadline = int(time.time()) + 15 if expiring else 0

        class Issuer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def answer(self, body):
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self.answer({"schema": "teliphones-ssh-challenge/1", "workstation_id": profile,
                             "challenge": nonce, "expires_at": int(time.time()) + 30})

            def do_POST(self):
                try:
                    value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    fixture.assertEqual(set(value), {"schema", "workstation_id", "challenge", "session_id", "ssh_public_key", "signature"})
                    fixture.assertEqual(value["schema"], "teliphones-ssh-request/2")
                    fixture.assertEqual(value["workstation_id"], profile)
                    fixture.assertEqual(value["challenge"], nonce)
                    fixture.assertNotEqual(value["ssh_public_key"], identity)
                    fixture.assertNotIn("PRIVATE KEY", json.dumps(value))
                    root = fixture.root / ("production-" + value["session_id"])
                    root.mkdir()
                    (root / "allowed").write_text(profile + " " + identity + "\n")
                    (root / "signature").write_text(value["signature"])
                    message = ("TELIPHONES-SSH-REQUEST-2\n" + profile + "\n" + nonce + "\n" +
                               value["session_id"] + "\n" + value["ssh_public_key"] + "\n")
                    run([KEYGEN, "-Y", "verify", "-I", profile, "-n", "teliphones-ssh", "-f", root / "allowed",
                         "-s", root / "signature"], input=message)
                    if denied:
                        self.send_error(403)
                        return
                    (root / "session.pub").write_text(value["ssh_public_key"] + "\n")
                    now = int(time.time())
                    until = min(now + 120, deadline) if deadline else now + 120
                    stamp = lambda value: time.strftime("%Y%m%d%H%M%SZ", time.gmtime(value))
                    run([KEYGEN, "-q", "-s", fixture.root / "ca", "-I", "ws-" + profile + "/" + value["session_id"],
                         "-n", principal, "-V", stamp(now) + ":" + stamp(until), "-O", "clear", "-O", "permit-pty",
                         "-O", "source-address=127.0.0.1/32", root / "session.pub"])
                    observed.append(value["ssh_public_key"])
                    self.answer({"schema": "teliphones-ssh-certificate/2", "workstation_id": profile,
                                 "session_id": value["session_id"], "ssh_public_key": value["ssh_public_key"],
                                 "certificate": (root / "session-cert.pub").read_text().strip(), "expires_at": until,
                                 "ssh_user": fixture.user, "ssh_host_key": fixture.host, "ssh_ca_key": fixture.ca, "ssh_port": 22001})
                except Exception as error:
                    errors.append(str(error))
                    self.send_error(403)

        endpoint = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), Issuer)
        worker = threading.Thread(target=endpoint.serve_forever)
        worker.start()
        try:
            host.stdin.write(json.dumps({"user": self.user, "host": self.host, "ca": self.ca,
                                        "expires_at": deadline}) + "\n")
            host.stdin.flush()
            if denied:
                output, error = host.communicate(timeout=30)
                self.assertNotEqual(host.returncode, 0)
                self.assertIn("HTTP 403", error)
                self.assertNotIn("PRODUCTION_STARTED", output)
                self.assertFalse(identity_path.exists())
                self.assertFalse(runtime.exists())
                self.assertFalse(errors, errors)
                return
            self.assertEqual(line(host), "PRODUCTION_STARTED")
            for _ in range(100):
                self.server_log.flush()
                tail = (self.root / "sshd-test.log").read_bytes()[log_offset:].decode(errors="replace")
                if "Accepted publickey" in tail and "ws-" + profile + "/" in tail:
                    break
                time.sleep(0.1)
            else:
                self.fail("Production provider did not produce an authenticated native SSH login.")
            self.assertTrue(observed, errors)
            encrypted = identity_path.read_bytes()
            self.assertNotIn(b"PRIVATE KEY", encrypted)
            for file in runtime.rglob("*"):
                if file.is_file():
                    self.assertIn(file.name, {"identity.pub", "certificate.pub", "known_hosts", "config"})
                    self.assertNotIn(b"PRIVATE KEY", file.read_bytes())
            host.stdin.write("wait-expiry\n" if expiring else "close\n")
            host.stdin.flush()
            output, error = host.communicate(timeout=30)
            self.assertEqual(host.returncode, 0, output + error + "\n".join(errors))
            self.assertIn("PRODUCTION_CLOSED", output)
            self.assertIn("IDENTITY_RETAINED", output)
            if expiring:
                self.assertIn("PRODUCTION_EXPIRED", output)
            self.assertFalse(identity_path.exists())
            self.assertFalse(runtime.exists())
        finally:
            endpoint.shutdown()
            endpoint.server_close()
            worker.join(timeout=10)
            (self.root / "principals").write_text(self.principal + "\n")


if __name__ == "__main__":
    unittest.main()
