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
import traceback
import unittest
import xml.etree.ElementTree as ET

HOST = Path(sys.argv.pop(1)).resolve()
OPENSSH = Path(os.environ["SystemRoot"]) / "System32/OpenSSH"
SSH = OPENSSH / "ssh.exe"
SSHD = OPENSSH / "sshd.exe"
KEYGEN = OPENSSH / "ssh-keygen.exe"
SYSTEM_SID = "S-1-5-18"
ADMIN_SID = "S-1-5-32-544"

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


def pipe_io(handle, data, writing):
    from ctypes import wintypes

    class Overlapped(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]

    kernel = kernel32()
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                         ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
    kernel.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    operation = Overlapped()
    operation.hEvent = kernel.CreateEventW(None, True, False, None)
    if not operation.hEvent:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = wintypes.DWORD()
        action = kernel.WriteFile if writing else kernel.ReadFile
        ok = action(handle, data, len(data), ctypes.byref(count), ctypes.byref(operation))
        if not ok and ctypes.get_last_error() == 997:
            if kernel.WaitForSingleObject(operation.hEvent, 5000) != 0:
                kernel.CancelIoEx(handle, ctypes.byref(operation))
                kernel.GetOverlappedResult(handle, ctypes.byref(operation), ctypes.byref(count), True)
                raise TimeoutError("Unrelated-process agent probe did not complete within five seconds.")
            ok = kernel.GetOverlappedResult(handle, ctypes.byref(operation), ctypes.byref(count), False)
        return bool(ok), count.value
    finally:
        kernel.CloseHandle(operation.hEvent)

def run(args, **kwargs):
    command = [str(x) for x in args]
    if command[0].lower() in ("icacls.exe", "schtasks.exe", "whoami.exe"):
        command[0] = str(Path(os.environ["SystemRoot"]) / "System32" / command[0])
    encoding = kwargs.pop("encoding", "utf-8")
    if isinstance(kwargs.get("input"), str):
        # SSHSIG verifies exact bytes; Windows text-mode stdin rewrites LF to CRLF.
        kwargs["input"] = kwargs["input"].encode("utf-8")
    try:
        result = subprocess.run(command, capture_output=True, timeout=30, **kwargs)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Native fixture command {subprocess.list2cmdline(command)} timed out "
                           f"(no exit code):\nstdout:\n{error.stdout!r}\nstderr:\n{error.stderr!r}") from error
    except OSError as error:
        raise RuntimeError(f"Native fixture command {subprocess.list2cmdline(command)} could not launch; "
                           f"expected successful process creation; actual Win32={getattr(error, 'winerror', None)}, "
                           f"errno={error.errno}: {error}") from error
    output = result.stdout.decode(encoding, errors="replace")
    error_output = result.stderr.decode(encoding, errors="replace")
    if result.returncode:
        raise RuntimeError(f"Native fixture command {subprocess.list2cmdline(command)} failed "
                           f"(expected exit 0; actual exit {result.returncode}):\nstdout:\n{output}\nstderr:\n{error_output}")
    return output


def verify_security(observed, owner, sids, inheritance=0, task=False):
    expected = {"owner": owner, "protected": True, "sids": sorted(sids),
                "inheritance": inheritance, "full_control": True}
    if task:
        expected.update(principal=SYSTEM_SID, logon_type=5, run_level=1)
    print("ACL expected: " + json.dumps(expected), flush=True)
    print("ACL observed: " + json.dumps(observed), flush=True)
    rules = observed["rules"]
    valid = (observed["owner"] == owner and observed["protected"] is True
             and len(rules) == len(sids) and {rule["sid"] for rule in rules} == set(sids))
    for rule in rules:
        valid = valid and (rule["allow"] is True and rule["inherited"] is False
                           and rule["mask"] in ((0x10000000, 0x1F01FF) if task else (0x1F01FF,))
                           and rule["inheritance"] == inheritance and rule["propagation"] == 0
                           and rule["unsupported_flags"] == 0)
    if not valid:
        raise AssertionError("Fixture security descriptor does not match the exact restricted policy.")
    if task and (observed["principal"] != SYSTEM_SID
                 or observed["logon_type"] != 5 or observed["run_level"] != 1):
        raise AssertionError("Fixture task does not use a highest-privilege SYSTEM service-account token.")


def security_state(kind, path, user_sid=None):
    command = [HOST, "--security", kind, path]
    if user_sid:
        command.append(user_sid)
    return json.loads(run(command, encoding="utf-8"))


def secure_path(path, owner, sids, directory=False, remove_sid=None):
    print(f"Securing fixture path: {path}", flush=True)
    print(f"Expected owner={owner}; protected=True; full-control SIDs={sids}; directory={directory}", flush=True)
    # ICACLS /setowner is a separate command form, not a /grant modifier.
    commands = [
        ["icacls.exe", path, "/grant:r",
         *["*" + sid + (":(OI)(CI)(F)" if directory else ":(F)") for sid in sids]],
        ["icacls.exe", path, "/setowner", "*" + owner],
        ["icacls.exe", path, "/inheritance:r"],
    ]
    if remove_sid and remove_sid not in sids:
        commands.append(["icacls.exe", path, "/remove:g", "*" + remove_sid])
    try:
        for command in commands:
            print("ACL operation: " + subprocess.list2cmdline([str(x) for x in command]), flush=True)
            run(command)
    except Exception as operation_error:
        print("ACL state after failed operation:", flush=True)
        try:
            print(json.dumps(security_state("File", path)), flush=True)
        except Exception as descriptor_error:
            raise RuntimeError(f"ACL operation failed: {operation_error}\n"
                               f"Descriptor inspection also failed: {descriptor_error}") from operation_error
        raise
    verify_security(security_state("File", path), owner, sids, 3 if directory else 0)


def native_acl_regression(root, sid):
    """Exercise the real descriptor reader against deliberately invalid file ACLs."""
    path = root / "acl-negative-probe"
    path.write_text("public fixture permission probe\n", encoding="ascii")
    sids = [sid, SYSTEM_SID, ADMIN_SID]
    secure_path(path, sid, sids)
    cases = (
        ("unexpected SID", ["/grant:r", "*S-1-1-0:(R)"], ["/remove:g", "*S-1-1-0"]),
        ("wrong owner", ["/setowner", "*" + ADMIN_SID], ["/setowner", "*" + sid]),
        ("unprotected/inherited DACL", ["/inheritance:e"], ["/inheritance:r"]),
        ("insufficient access mask", ["/grant:r", "*" + sid + ":(R)"], ["/grant:r", "*" + sid + ":(F)"]),
        ("deny ACE", ["/deny", "*S-1-1-0:(WD)"], ["/remove:d", "*S-1-1-0"]),
    )
    try:
        for label, change, restore in cases:
            print("Native ACL negative probe: " + label, flush=True)
            run(["icacls.exe", path, *change])
            try:
                try:
                    verify_security(security_state("File", path), sid, sids)
                except AssertionError:
                    print("Rejected actual invalid ACL as required: " + label, flush=True)
                else:
                    raise RuntimeError("Security verification accepted actual invalid ACL: " + label)
            finally:
                run(["icacls.exe", path, *restore])
            verify_security(security_state("File", path), sid, sids)
    finally:
        path.unlink()


def disable_debug_privilege():
    from ctypes import wintypes

    class Luid(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class Privileges(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", Luid), ("Attributes", wintypes.DWORD)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Luid)]
    advapi.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(Privileges),
                                           wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    kernel = kernel32()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        privileges = Privileges()
        privileges.PrivilegeCount = 1
        if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(privileges.Luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        ctypes.set_last_error(0)
        if not advapi.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() not in (0, 1300):  # A non-admin token may not have this privilege.
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)


def task_xml(program, arguments):
    ns = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", ns)
    task = ET.Element(f"{{{ns}}}Task", version="1.2")

    def element(parent, name, text=None, **attributes):
        child = ET.SubElement(parent, f"{{{ns}}}{name}", attributes)
        child.text = text
        return child

    principal = element(element(task, "Principals"), "Principal", id="System")
    element(principal, "UserId", "S-1-5-18")
    element(principal, "LogonType", "ServiceAccount")
    element(principal, "RunLevel", "HighestAvailable")
    settings = element(task, "Settings")
    element(settings, "ExecutionTimeLimit", "PT10M")
    element(settings, "AllowStartOnDemand", "true")
    element(settings, "DisallowStartIfOnBatteries", "false")
    element(settings, "StopIfGoingOnBatteries", "false")
    action = element(element(task, "Actions", Context="System"), "Exec")
    element(action, "Command", str(program))
    element(action, "Arguments", subprocess.list2cmdline([str(arg) for arg in arguments]))
    return ET.tostring(task, encoding="utf-16", xml_declaration=True)


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
    if not result:
        output, error = process.communicate(timeout=10)
        raise RuntimeError(f"Native SSH protocol ended before its next line; expected protocol response; "
                           f"actual process exit={process.returncode}\nstdout:\n{output}\nstderr:\n{error}")
    return result.strip()


def quoted(path):
    return '"' + str(path).replace("\\", "/").replace('"', '\\"') + '"'


def alive(pid):
    kernel = kernel32()
    process = kernel.OpenProcess(0x100000, False, pid)
    if not process:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: no such PID.
            return False
        raise ctypes.WinError(error)
    try:
        return kernel.WaitForSingleObject(ctypes.c_void_p(process), 0) == 258
    finally:
        kernel.CloseHandle(ctypes.c_void_p(process))


def fixture_task_state(task):
    return security_state("TaskState", task)


def wait_server_exit(pid_file):
    if not pid_file.exists():
        return
    pid = int(pid_file.read_text())
    for _ in range(100):
        if not alive(pid):
            return
        time.sleep(0.1)
    raise RuntimeError(f"Fixture server PID {pid} survived ten seconds after owned task shutdown.")


def cleanup_interrupted_fixture():
    descriptor = Path(os.environ["STARTUP_DIAGNOSTICS"]) / "native-fixture.json"
    if not descriptor.exists():
        return
    state = json.loads(descriptor.read_text(encoding="utf-8"))
    root = Path(state["root"]).resolve()
    task = state["task"]
    token = task.removeprefix("TELIPHONES-sshd-test-")
    if (root.parent != Path(os.environ["RUNNER_TEMP"]).resolve()
            or not root.name.startswith("TELIPHONES-native-ssh-")
            or not task.startswith("TELIPHONES-sshd-test-")
            or len(token) != 16 or any(c not in "0123456789abcdef" for c in token)):
        raise RuntimeError("Interrupted-fixture descriptor is not an owned test path/task.")
    if root.exists():
        (root / "stop-server").touch()
        for _ in range(100):
            if (root / "server.pid.stopped").exists():
                break
            time.sleep(0.1)
    task_state = fixture_task_state(task)
    if task_state is not None:
        # End only this uniquely recorded task, never production services/process names.
        if task_state in (2, 4):  # Queued or running; ready tasks have no automatic trigger.
            run(["schtasks.exe", "/End", "/TN", task])
        run(["schtasks.exe", "/Delete", "/TN", task, "/F"])
    if fixture_task_state(task) is not None:
        raise RuntimeError("Interrupted fixture scheduled task survived deletion.")
    wait_server_exit(root / "server.pid")
    if root.exists():
        shutil.rmtree(root)
    with socket.socket() as probe:
        probe.settimeout(0.2)
        if probe.connect_ex(("127.0.0.1", 22001)) == 0:
            raise RuntimeError("Interrupted fixture loopback listener remains open.")
    if root.exists():
        raise RuntimeError("Interrupted fixture temporary directory survived removal.")
    descriptor.unlink()
    print("Interrupted fixture cleanup verified: task absent, server stopped, listener closed, files removed.", flush=True)


class WindowsSshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "nt":
            raise RuntimeError("This harness must run natively on Windows.")
        for path in (HOST, SSH, SSHD, KEYGEN):
            if not path.is_file():
                raise RuntimeError(f"Native prerequisite missing: {path}. No Unix substitute or silent skip is permitted.")
        print(subprocess.run([str(SSH), "-V"], capture_output=True, text=True).stderr.strip())
        disable_debug_privilege()
        print("Fixture test-process identity/privileges:\n" + run(["whoami.exe", "/all"]), flush=True)
        print("Installed ICACLS command syntax:\n" + run(["icacls.exe", "/?"]), flush=True)
        cls.root = Path(tempfile.mkdtemp(prefix="TELIPHONES-native-ssh-", dir=os.environ.get("RUNNER_TEMP")))
        cls.addClassCleanup(cls.remove_temporary)
        cls.task = "TELIPHONES-sshd-test-" + secrets.token_hex(8)
        if os.environ.get("STARTUP_DIAGNOSTICS") and os.environ.get("RUNNER_TEMP"):
            (Path(os.environ["STARTUP_DIAGNOSTICS"]) / "native-fixture.json").write_text(
                json.dumps({"root": str(cls.root), "task": cls.task}), encoding="utf-8")
        identity = json.loads(run([HOST, "--security", "Identity"], encoding="utf-8"))
        print("Actual fixture token identity: " + json.dumps(identity), flush=True)
        if not identity["elevated"] or not identity["local_account"]:
            raise RuntimeError("Expected elevated local-account token for SYSTEM task/native Windows SSH login; "
                               "actual: " + json.dumps(identity))
        cls.user = identity["user"].lower()
        cls.sid = identity["sid"]
        secure_path(cls.root, cls.sid, [cls.sid, SYSTEM_SID, ADMIN_SID], directory=True)
        for name in ("ca", "host"):
            run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", cls.root / name])
        secure_path(cls.root / "host", SYSTEM_SID, [SYSTEM_SID, ADMIN_SID], remove_sid=cls.sid)
        secure_path(cls.root / "ca", cls.sid, [cls.sid, SYSTEM_SID, ADMIN_SID])
        message = cls.root / "feature-probe"
        message.write_bytes(b"TELIPHONES Windows SSHSIG compatibility\n")
        run([KEYGEN, "-Y", "sign", "-f", cls.root / "ca", "-n", "teliphones-preflight", message])
        (cls.root / "feature-allowed").write_text("preflight " + (cls.root / "ca.pub").read_text(), encoding="ascii")
        run([KEYGEN, "-Y", "verify", "-I", "preflight", "-n", "teliphones-preflight",
             "-f", cls.root / "feature-allowed", "-s", cls.root / "feature-probe.sig"],
            input=message.read_bytes())
        cls.ca = (cls.root / "ca.pub").read_text().strip()
        cls.host = (cls.root / "host.pub").read_text().strip()
        cls.principal = "teliphones-native-test"
        (cls.root / "principals").write_text(cls.principal + "\n")
        with socket.socket() as reserve:
            reserve.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            reserve.bind(("127.0.0.1", 22001))
            cls.port = 22001
        with socket.socket() as reserve:
            reserve.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            reserve.bind(("127.0.0.1", 8765))
        cls.config = cls.root / "sshd_config"
        cls.config.write_text(
            f"Port {cls.port}\nListenAddress 127.0.0.1\nHostKey {quoted(cls.root / 'host')}\n"
            f"PidFile {quoted(cls.root / 'sshd.pid')}\nAllowUsers {cls.user}\n"
            f"TrustedUserCAKeys {quoted(cls.root / 'ca.pub')}\nAuthorizedPrincipalsFile {quoted(cls.root / 'principals')}\n"
            "AuthorizedKeysFile none\nPubkeyAuthentication yes\nAuthenticationMethods publickey\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
            "AllowAgentForwarding no\nAllowTcpForwarding no\nPermitTunnel no\nLogLevel DEBUG2\n"
            "StrictModes yes\n",
            encoding="utf-8")
        for path in (cls.config, cls.root / "ca.pub", cls.root / "host.pub", cls.root / "principals"):
            secure_path(path, cls.sid, [cls.sid, SYSTEM_SID, ADMIN_SID])
        run([SSHD, "-t", "-f", cls.config])
        effective = run([SSHD, "-T", "-f", cls.config])
        if "listenaddress 127.0.0.1:" not in effective.lower() or "passwordauthentication no" not in effective.lower():
            raise RuntimeError("Fixture sshd effective configuration is not loopback-only certificate authentication.")
        cls.stop_file = cls.root / "stop-server"
        cls.server_pid = cls.root / "server.pid"
        xml = cls.root / "server-task.xml"
        xml.write_bytes(task_xml(HOST, ["--fixture-server", SSHD, cls.config, cls.root / "sshd-test.log",
                                        cls.stop_file, cls.server_pid]))
        secure_path(xml, cls.sid, [cls.sid, SYSTEM_SID, ADMIN_SID])
        run(["schtasks.exe", "/Create", "/TN", cls.task, "/XML", xml, "/RU", "SYSTEM"])
        cls.addClassCleanup(cls.stop_server)
        cls.server_requested = False
        verify_security(security_state("Task", cls.task, cls.sid), ADMIN_SID,
                        [cls.sid, SYSTEM_SID, ADMIN_SID], task=True)
        cls.server_requested = True
        run(["schtasks.exe", "/Run", "/TN", cls.task])
        for _ in range(300):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1) as connection:
                    connection.settimeout(2)
                    with connection.makefile("rb") as stream:
                        banner = stream.readline(256)
                    if not banner.startswith(b"SSH-2.0-"):
                        raise RuntimeError(f"Fixture loopback endpoint returned an invalid SSH banner: {banner!r}")
                    if not cls.server_pid.exists() or not alive(int(cls.server_pid.read_text())):
                        raise RuntimeError("Fixture listener has no live owned server PID.")
                    print(f"Fixture loopback listener ready: 127.0.0.1:{cls.port}", flush=True)
                    break
            except OSError:
                time.sleep(0.1)
        else:
            log = cls.root / "sshd-test.log"
            raise RuntimeError("SYSTEM fixture sshd never became responsive:\n"
                               + run(["schtasks.exe", "/Query", "/TN", cls.task, "/V", "/FO", "LIST"])
                               + (log.read_text(errors="replace") if log.exists() else "No server log produced."))

    @classmethod
    def remove_temporary(cls):
        if getattr(cls, "task", None) and fixture_task_state(cls.task) is not None:
            raise RuntimeError("Preserving fixture directory for recovery: scheduled task remains.")
        wait_server_exit(cls.root / "server.pid")
        shutil.rmtree(cls.root)
        if cls.root.exists():
            raise RuntimeError("Fixture temporary directory survived cleanup: " + str(cls.root))
        print("Fixture cleanup verified: temporary directory removed.", flush=True)

    @classmethod
    def stop_server(cls):
        stopped = Path(str(cls.server_pid) + ".stopped")
        graceful = False
        try:
            cls.stop_file.touch()
            if cls.server_requested:
                for _ in range(100):
                    if stopped.exists() and cls.server_pid.exists() and not alive(int(cls.server_pid.read_text())):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("SYSTEM fixture did not confirm zero Job processes before timeout; forcing owned task shutdown.")
            if cls.server_pid.exists() and alive(int(cls.server_pid.read_text())):
                raise RuntimeError("Fixture sshd survived stop/Job cleanup.")
            with socket.socket() as probe:
                probe.settimeout(0.2)
                if probe.connect_ex(("127.0.0.1", cls.port)) == 0:
                    raise RuntimeError("Fixture listener remains open after teardown.")
            print("Fixture cleanup verified: owned server stopped, zero-Job-process acknowledgement checked, listener closed."
                  if cls.server_requested else "Fixture cleanup: server launch was never requested.", flush=True)
            graceful = True
        finally:
            log = cls.root / "sshd-test.log"
            diagnostics = os.environ.get("STARTUP_DIAGNOSTICS")
            try:
                if log.exists():
                    print("Fixture OpenSSH/wrapper diagnostics:\n" + log.read_text(errors="replace"), flush=True)
                    if diagnostics:
                        shutil.copyfile(log, Path(diagnostics) / "native-sshd-test.log")
            finally:
                if not graceful and fixture_task_state(cls.task) in (2, 4):
                    run(["schtasks.exe", "/End", "/TN", cls.task])
                    wait_server_exit(cls.server_pid)
                run(["schtasks.exe", "/Delete", "/TN", cls.task, "/F"])
                # Only Task Scheduler's precise not-found HRESULT proves absence.
                if fixture_task_state(cls.task) is not None:
                    raise RuntimeError("Fixture scheduled task survived deletion.")
                print("Fixture cleanup verified: scheduled task deleted.", flush=True)

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
        handle = kernel.CreateFileW(pipe, 0xC0000000, 0, None, 3, 0x40000000, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            packet = struct.pack(">IB", 1, 11)
            written, _ = pipe_io(handle, packet, True)
            if written:
                output = ctypes.create_string_buffer(4)
                result, count = pipe_io(handle, output, False)
                self.assertFalse(result and count, "An unrelated process enumerated session credentials.")
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
        self.addCleanup(lambda: (self.root / "principals").write_text(self.principal + "\n"))
        nonce = secrets.token_hex(32)
        observed = []
        errors = []
        fixture = self
        deadline = int(time.time()) + 30 if expiring else 0

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
            output, error = host.communicate(timeout=60 if expiring else 30)
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


def fixture_preflight():
    failures = []
    try:
        WindowsSshTests.setUpClass()
        native_acl_regression(WindowsSshTests.root, WindowsSshTests.sid)
    except Exception as error:
        failures.append(error)
    finally:
        WindowsSshTests.doClassCleanups()
        failures.extend(error.with_traceback(trace)
                        for _, error, trace in WindowsSshTests.tearDown_exceptions)
    if failures:
        details = "\n".join("".join(traceback.format_exception(type(error), error, error.__traceback__))
                            for error in failures)
        raise RuntimeError("Actual Windows SSH fixture preflight/cleanup failed:\n" + details) from failures[0]
    print("FIXTURE PREFLIGHT PASS: real ACLs, host keys, config, SYSTEM task, loopback sshd, shutdown and cleanup.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--cleanup-only"]:
        cleanup_interrupted_fixture()
    elif sys.argv[1:] == ["--fixture-preflight"]:
        fixture_preflight()
    else:
        unittest.main()
