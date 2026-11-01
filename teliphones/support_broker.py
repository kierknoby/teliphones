#!/usr/bin/python3
"""Restricted local GUI-to-root bridge; no browser-selected commands or paths."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

STATE = Path("/var/lib/teliphones")
ENROLLMENT = Path("/etc/teliphones")
SOCKET = "/run/teliphones/control.sock"
# Version of the broker status contract; 2 adds operation records and server_time for live GUI monitoring.
PROTOCOL = 2
FWCONSOLE = "/usr/sbin/fwconsole"
ACTIONS = {"status", "authorise", "revoke", "dependencies", "evidence", "configure"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}


class BrokerError(Exception):
    pass


def read_json(path):
    try:
        with path.open() as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BrokerError("Invalid TELIPHONES state; support must be revoked.")
        return value
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as error:
        raise BrokerError("TELIPHONES state is inaccessible or invalid; inspect quarantine.") from error


def atomic(path, value, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=path.name + ".broker-tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def validate(request):
    if not isinstance(request, dict) or not isinstance(request.get("action"), str) or request["action"] not in ACTIONS:
        raise BrokerError("Unsupported TELIPHONES operation.")
    action = request["action"]
    fields = {
        "status": set(), "revoke": set(), "dependencies": set(),
        "authorise": {"minutes"}, "evidence": {"evidence"},
        "configure": {"url", "certificate", "private_key", "ca", "checker_key"},
    }[action]
    if set(request) - fields - {"action"}:
        raise BrokerError("Unexpected TELIPHONES input.")
    if action == "authorise":
        if not isinstance(request.get("minutes"), str) or not re.fullmatch(r"[0-9]{1,3}", request["minutes"]) or not 5 <= int(request["minutes"]) <= 240:
            raise BrokerError("Duration must be between 5 and 240 minutes.")
    if action == "evidence":
        if not isinstance(request.get("evidence"), str) or len(request["evidence"]) > 32768:
            raise BrokerError("Signed Checker evidence is required (maximum 32 KiB).")
        try:
            if not isinstance(json.loads(request["evidence"]), dict):
                raise ValueError()
        except ValueError as error:
            raise BrokerError("Checker evidence must be a JSON object.") from error
    if action == "configure":
        if any(not isinstance(request.get(field), str) or not 1 <= len(request[field]) <= 16384 for field in fields):
            raise BrokerError("Complete, bounded gateway and Checker enrollment is required.")
        url = urlsplit(request["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/") or any(c in request["url"] for c in '\r\n"'):
            raise BrokerError("Gateway URL must be an HTTPS origin without credentials, paths or query.")
    return action


def permitted_peer(uid, web_uid):
    return uid == web_uid and web_uid != 0


class Broker:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.phase = "Disconnected"
        self.error = ""
        self.running = False
        self.revoking = False
        # Progress of the most recent web operation, reported read-only through "status".
        self.operation = None

    def begin(self, action, stage):
        self.operation = {"id": uuid.uuid4().hex, "action": action, "state": "running", "stage": stage,
                          "message": "", "started_at": int(time.time()), "finished_at": None}
        return self.operation["id"]

    def stage(self, operation_id, stage):
        if operation_id is not None and self.operation and self.operation["id"] == operation_id:
            self.operation["stage"] = stage

    def finish(self, operation_id, succeeded, message):
        # A superseded operation (for example, cancelled by revocation) never overwrites the newer record.
        if operation_id is not None and self.operation and self.operation["id"] == operation_id:
            self.operation.update({"state": "succeeded" if succeeded else "failed", "stage": "",
                                   "message": message, "finished_at": int(time.time())})

    def audit(self, action, uid, result):
        with open("/var/log/teliphones-web.log", "a") as handle:
            handle.write(json.dumps({"time": int(time.time()), "peer_uid": uid, "action": action, "result": result}) + "\n")

    def command(self, arguments, timeout=45, cancellable=True):
        with subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=ENV, start_new_session=True) as process:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if (cancellable and self.cancel.is_set()) or time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    raise BrokerError("Operation interrupted or timed out; local revocation and cleanup required.")
                time.sleep(0.1)
            if process.returncode:
                raise BrokerError("TELIPHONES operation failed: " + arguments[2] + ". Inspect TELIPHONES audit and quarantine; no success is assumed.")

    def cli(self, action, *options, cancellable=True):
        allowed = {"authorise", "provision", "connect-confirm", "attest", "checker-request", "checker-accept", "open", "revoke", "reconcile"}
        if action not in allowed:
            raise BrokerError("Invalid broker command.")
        self.command([FWCONSOLE, "teliphones", action, *options], cancellable=cancellable)

    def readiness(self):
        paths = {
            "WireGuard wg": ["/usr/bin/wg", "/usr/sbin/wg"],
            "iproute2": ["/usr/sbin/ip"], "Temporary SSH server": ["/usr/sbin/sshd", "/usr/bin/sshd"],
            "SSH key generation": ["/usr/bin/ssh-keygen"], "systemd-run": ["/usr/bin/systemd-run"],
            "systemctl": ["/usr/bin/systemctl"], "Checker Python": ["/usr/bin/python3"],
            "FreePBX Console": [FWCONSOLE],
        }
        result = {name: any(os.access(path, os.X_OK) for path in choices) for name, choices in paths.items()}
        result["Gateway enrollment"] = all(path.is_file() and os.access(path, os.R_OK) for path in
                                           [Path("/etc/teliphones-connect.conf"), ENROLLMENT / "connect-client.crt",
                                            ENROLLMENT / "connect-client.key", ENROLLMENT / "connect-ca.crt"])
        if result["Gateway enrollment"]:
            config = Path("/etc/teliphones-connect.conf").read_text()
            result["Gateway enrollment"] = re.search(r'^CONNECT_URL="https://[^"\r\n]+"$', config, re.MULTILINE) is not None
        result["Checker trusted public key"] = (ENROLLMENT / "checker-ecdsa-p256.pub").is_file()
        try:
            check = subprocess.run(["/usr/bin/php", "-r",
                                    "exit(extension_loaded('curl')&&extension_loaded('openssl')&&extension_loaded('json')"
                                    "&&function_exists('posix_geteuid')&&function_exists('posix_kill')"
                                    "&&function_exists('posix_getpwnam')&&function_exists('exec')?0:1);"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, env=ENV)
            result["Required PHP functions / extensions"] = check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            result["Required PHP functions / extensions"] = False
        return result

    def status(self):
        session = read_json(STATE / "session.json")
        remote = read_json(STATE / "connect.json")
        readiness = self.readiness()
        enabled = not (STATE / "disabled").exists()
        quarantine = (STATE / "quarantine.json").exists()
        phase = self.phase if self.running or self.revoking else {
            "ready": "Connected", "locally_verified": "Connecting",
            "verified": "Connecting", "peer_configured": "Connecting",
            "connected": "Connecting", "authorised": "Authorising",
        }.get(session.get("state"), "Disconnected")
        if quarantine:
            phase = "Verification failed / quarantined"
        elif session and int(session.get("expires_at", 0)) <= time.time():
            phase = "Revoking (session expired; cleanup not yet confirmed)"
        elif not session and not self.running and not self.revoking:
            phase = "Not configured" if not readiness["Gateway enrollment"] else ("Ready" if all(readiness.values()) and enabled else "Missing dependency")
        if session.get("state") == "ready" and phase == "Connected":
            adapter = read_json(STATE / "adapter.json")
            checker = read_json(STATE / "checker.json")
            if (adapter.get("session_id") != session.get("session_id") or not adapter.get("support_ready")
                    or checker.get("session_id") != session.get("session_id") or not checker.get("accepted")):
                phase = "Verification failed / access not confirmed"
        fingerprint = None
        key = remote.get("ssh_public_key", "").split()
        if len(key) >= 2:
            try:
                fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key[1], validate=True)).digest()).decode().rstrip("=")
            except ValueError:
                fingerprint = "Invalid gateway SSH identity"
        return {"protocol": PROTOCOL, "phase": phase, "readiness": readiness, "enabled": enabled,
                "operation": dict(self.operation) if self.operation else None, "server_time": int(time.time()),
                "can_authorise": all(readiness.values()) and enabled and not session and not quarantine and not self.running and not self.revoking,
                "session": {key: session[key] for key in ("session_id", "state", "expires_at") if key in session},
                "access_verified": phase == "Connected",
                "engineer": fingerprint, "challenge": read_json(STATE / "checker-challenge.json") if session.get("state") == "locally_verified" else None}

    def configure(self, request):
        if read_json(STATE / "session.json") or read_json(STATE / "connect.json"):
            raise BrokerError("Revoke the existing session before changing enrollment.")
        ENROLLMENT.mkdir(mode=0o700, exist_ok=True)
        if ENROLLMENT.is_symlink() or ENROLLMENT.stat().st_uid != 0:
            raise BrokerError("Enrollment directory is not root-owned.")
        # Validate in a root-only staging directory; never echo credential values.
        with tempfile.TemporaryDirectory(dir=ENROLLMENT) as directory:
            stage = Path(directory)
            names = {"certificate": "connect-client.crt", "private_key": "connect-client.key",
                     "ca": "connect-ca.crt", "checker_key": "checker-ecdsa-p256.pub"}
            for field, name in names.items():
                atomic(stage / name, request[field])
            for name in ("connect-client.crt", "connect-ca.crt"):
                self.command(["/usr/bin/openssl", "x509", "-in", str(stage / name), "-checkend", "0", "-noout"])
            self.command(["/usr/bin/openssl", "pkey", "-in", str(stage / "connect-client.key"), "-check", "-noout"])
            certificate_key = subprocess.run(["/usr/bin/openssl", "x509", "-in", str(stage / "connect-client.crt"), "-pubkey", "-noout"],
                                             capture_output=True, timeout=5, env=ENV)
            private_public_key = subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(stage / "connect-client.key"), "-pubout"],
                                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=ENV)
            if certificate_key.returncode or private_public_key.returncode or certificate_key.stdout != private_public_key.stdout:
                raise BrokerError("Customer certificate and private key do not match.")
            key_check = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-in", str(stage / "checker-ecdsa-p256.pub"), "-text", "-noout"],
                                       capture_output=True, timeout=5, env=ENV)
            if key_check.returncode or b"prime256v1" not in key_check.stdout:
                raise BrokerError("Checker key must be an ECDSA P-256 public key.")
            for name in names.values():
                os.replace(stage / name, ENROLLMENT / name)
        atomic(Path("/etc/teliphones-connect.conf"),
               'CONNECT_URL="' + request["url"].rstrip("/") + '"\n'
               'CLIENT_CERT=/etc/teliphones/connect-client.crt\nCLIENT_KEY=/etc/teliphones/connect-client.key\nCA_CERT=/etc/teliphones/connect-ca.crt\n')

    def work(self, request, uid, operation_id=None):
        action = request["action"]
        stage = lambda text: self.stage(operation_id, text)
        try:
            if action == "authorise":
                self.phase = "Authorising"
                stage("Authorising remote support")
                self.cli("authorise", "--minutes=" + request["minutes"], "--topology=on-pbx")
                self.phase = "Connecting"
                stage("Provisioning WireGuard connection")
                self.cli("provision")
                stage("Establishing WireGuard connection")
                deadline = time.monotonic() + 60
                while True:
                    try:
                        self.cli("connect-confirm")
                        break
                    except BrokerError:
                        if self.cancel.is_set() or time.monotonic() >= deadline:
                            raise
                        self.cancel.wait(2)
                stage("Verifying the connection locally")
                self.cli("attest")
                stage("Requesting Checker challenge")
                self.cli("checker-request")
                message = "Remote support authorised and the WireGuard connection verified locally. Submit independent Checker evidence to open access."
            elif action == "evidence":
                session = read_json(STATE / "session.json")
                if session.get("state") != "locally_verified" or int(session.get("expires_at", 0)) <= time.time():
                    raise BrokerError("No current verified session is awaiting Checker evidence.")
                evidence = STATE / "web-checker-evidence.json"
                atomic(evidence, request["evidence"])
                try:
                    stage("Verifying Checker evidence")
                    self.cli("checker-accept", "--evidence-file=" + str(evidence))
                    stage("Opening approved access")
                    self.cli("open")
                    message = "Checker evidence accepted and approved access opened."
                finally:
                    if evidence.exists():
                        evidence.unlink()
            elif action == "dependencies":
                if read_json(STATE / "session.json"):
                    raise BrokerError("Revoke support before installing dependencies.")
                stage("Installing WireGuard tools")
                self.command(["/usr/bin/apt-get", "-y", "--no-install-recommends", "install", "wireguard-tools"], timeout=300, cancellable=False)
                stage("Checking WireGuard tools")
                if self.readiness().get("WireGuard wg") is not True:
                    raise BrokerError("wireguard-tools installation finished, but the wg executable could not be verified.")
                message = "WireGuard tools installed; the wg executable was verified."
            elif action == "configure":
                stage("Validating gateway enrollment")
                self.configure(request)
                message = "Gateway enrollment validated and saved."
            self.audit(action, uid, "completed")
            self.finish(operation_id, True, message)
        except (BrokerError, OSError, ValueError, subprocess.TimeoutExpired) as error:
            self.error = str(error) if isinstance(error, BrokerError) else "TELIPHONES operation failed; inspect broker service logs."
            self.audit(action, uid, "failed")
            failure = self.error
            if action in ("authorise", "evidence"):
                stage("Cleaning up after failure")
                self.cleanup(uid, quarantine=True)
                if self.error != failure:
                    failure += " Cleanup also failed: " + self.error
            self.finish(operation_id, False, failure)
        finally:
            self.running = False
            self.lock.release()

    def cleanup(self, uid, quarantine=False):
        self.phase = "Revoking"
        try:
            self.cli("revoke", cancellable=False)
            self.phase = "Disconnected"
            self.audit("revoke", uid, "completed")
        except (BrokerError, OSError) as error:
            quarantine = True
            self.error = str(error)
            self.audit("revoke", uid, "cleanup-failed")
        if quarantine:
            atomic(STATE / "quarantine.json", json.dumps({"reason": "web-operation-or-cleanup-failed", "time": int(time.time())}))

    def dispatch(self, request, uid):
        action = validate(request)
        if action == "status":
            return {"ok": True, "status": self.status(), "error": self.error}
        if action == "revoke":
            self.cancel.set()
            self.revoking = True
            self.phase = "Revoking"
            revocation = self.begin("revoke", "Cancelling the running operation" if self.running else "Revoking remote support")
            def revoke():
                with self.lock:
                    self.running = True
                    self.stage(revocation, "Revoking remote support")
                    try:
                        self.error = ""
                        self.cleanup(uid)
                        if self.error:
                            self.finish(revocation, False, self.error + " TELIPHONES remains quarantined; revocation may be retried.")
                        else:
                            self.finish(revocation, True, "Remote support revoked and local cleanup confirmed.")
                    finally:
                        self.running = False
                        self.revoking = False
            threading.Thread(target=revoke, daemon=True).start()
            return {"ok": True, "operation_id": revocation, "message": "Revocation started. Monitoring progress automatically…"}
        if not self.lock.acquire(blocking=False):
            raise BrokerError("A TELIPHONES operation is already running. Revocation remains available.")
        try:
            if self.revoking:
                raise BrokerError("Revocation is in progress.")
            if action == "dependencies" and self.readiness().get("WireGuard wg") is True:
                raise BrokerError("WireGuard tools are already installed.")
            if action == "authorise" and not self.status()["can_authorise"]:
                raise BrokerError("TELIPHONES is not ready, already active, disabled or quarantined.")
            self.cancel.clear()
            self.running = True
            self.error = ""
            self.audit(action, uid, "approved")
            operation_id = self.begin(action, {"authorise": "Authorising remote support", "evidence": "Verifying Checker evidence",
                                               "dependencies": "Installing WireGuard tools", "configure": "Validating gateway enrollment"}[action])
            threading.Thread(target=self.work, args=(request, uid, operation_id), daemon=True).start()
        except Exception:
            self.lock.release()
            raise
        return {"ok": True, "operation_id": operation_id, "message": "TELIPHONES operation started. Monitoring progress automatically…"}


def serve():
    if os.geteuid() != 0:
        raise SystemExit("TELIPHONES broker requires a root Module Admin bootstrap.")
    os.umask(0o077)
    user = pwd.getpwnam("asterisk")
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise SystemExit("TELIPHONES state directory must be root-owned and private.")
    broker = Broker()
    # Interrupted broker jobs never resume/open access implicitly.
    broker.cleanup(0, quarantine=(STATE / "session.json").exists() or (STATE / "connect.json").exists())
    Path("/run/teliphones").mkdir(mode=0o750, exist_ok=True)
    if Path("/run/teliphones").is_symlink() or Path("/run/teliphones").stat().st_uid != 0:
        raise SystemExit("TELIPHONES socket directory must be root-owned.")
    os.chown("/run/teliphones", 0, user.pw_gid)
    os.chmod("/run/teliphones", 0o750)
    if os.path.lexists(SOCKET):
        os.unlink(SOCKET)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET)
    os.chown(SOCKET, 0, user.pw_gid)
    os.chmod(SOCKET, 0o660)
    server.listen(8)

    def handle(connection):
        with connection:
            connection.settimeout(5)
            uid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            try:
                if not permitted_peer(uid, user.pw_uid):
                    raise BrokerError("Only the configured FreePBX web service account may contact this broker.")
                data = bytearray()
                while b"\n" not in data and len(data) <= 100000:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > 100000 or b"\n" not in data:
                    raise BrokerError("Invalid or oversized request.")
                response = broker.dispatch(json.loads(data.split(b"\n", 1)[0]), uid)
            except (BrokerError, ValueError, OSError) as error:
                response = {"ok": False, "error": str(error) if isinstance(error, BrokerError) else "TELIPHONES request failed."}
            connection.sendall(json.dumps(response).encode() + b"\n")

    while True:
        connection, _ = server.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


if __name__ == "__main__":
    serve()
