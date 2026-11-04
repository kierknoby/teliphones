"""Launch the real TELIPHONES.exe, verify its main window is usable, then close it cleanly.

Failures report the exit status, Windows Error Reporting fault records and, when a debugger is
available, a symbolised stack from a local minidump. Dumps are deleted after analysis and never
copied to CI artifacts.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IDC_OPEN_SSH = 1010
WM_NULL = 0x0000
WM_CLOSE = 0x0010
WM_GETTEXT = 0x000D
SMTO_BLOCK = 0x0001
SMTO_ABORTIFHUNG = 0x0002
NTSTATUS_NAMES = {
    0xC0000005: "access violation",
    0xC0000374: "heap corruption",
    0xC0000409: "stack buffer overrun / fail-fast",
    0xC00000FD: "stack overflow",
    0xC0000135: "DLL not found",
    0xC0000139: "entry point not found",
    0xC0000142: "DLL initialisation failed",
    0x80000003: "breakpoint",
}
LOCAL_DUMPS_KEY = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\TELIPHONES.exe"
MAX_TEXT = 400


class SmokeFailure(Exception):
    pass


def describe_exit_code(code):
    code &= 0xFFFFFFFF
    name = NTSTATUS_NAMES.get(code)
    text = f"{code} (0x{code:08X})"
    if name:
        return f"{text}: {name}"
    if code >= 0xC0000000:
        return f"{text}: unhandled NTSTATUS error"
    return text


def is_crash_exit_code(code):
    code &= 0xFFFFFFFF
    return code >= 0xC0000000 or code == 0x80000003


def bounded(text, limit=MAX_TEXT):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def diagnostic_records(directory):
    records = set()
    if not directory.is_dir():
        return records
    for path in sorted(directory.glob("events-*.jsonl")):
        try:
            records.update(line for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        except OSError:
            continue
    return records


def new_application_events(before, after):
    """Return (event, severity) pairs for application-level records written during the run."""
    events = []
    for line in sorted(after - before):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("session") == "application":
            events.append((record.get("utc", ""), record.get("event", ""), record.get("severity", "")))
    return [(event, severity) for _, event, severity in sorted(events)]


def fault_events_for(executable_name, since_seconds, wevtutil="wevtutil"):
    milliseconds = max(1000, int(since_seconds * 1000))
    query = ("*[System[(Provider[@Name='Application Error'] or Provider[@Name='Application Hang'] or "
             f"Provider[@Name='Windows Error Reporting']) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]")
    try:
        result = subprocess.run([wevtutil, "qe", "Application", "/q:" + query, "/f:text", "/rd:true", "/c:10"],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return [f"Event Log query unavailable: {error}"]
    blocks = [block.strip() for block in result.stdout.split("Event[") if executable_name.lower() in block.lower()]
    return ["Event[" + block[:4000] for block in blocks[:3]]


class Windows:
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.wintypes = wintypes
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user32.EnumWindows.argtypes = [self.enum_proc, wintypes.LPARAM]
        self.user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self.user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
        self.user32.GetDlgItem.restype = wintypes.HWND
        self.user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
                                                    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
        self.user32.SendMessageTimeoutW.restype = ctypes.c_size_t
        self.user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        self.user32.EnumChildWindows.argtypes = [wintypes.HWND, self.enum_proc, wintypes.LPARAM]
        for name in ("IsWindowVisible", "IsWindowEnabled", "IsHungAppWindow", "IsWindow"):
            getattr(self.user32, name).argtypes = [wintypes.HWND]

    def top_level_windows(self, pid):
        found = []

        def callback(hwnd, _):
            owner = self.wintypes.DWORD()
            self.user32.GetWindowThreadProcessId(hwnd, self.ctypes.byref(owner))
            if owner.value == pid and self.user32.IsWindowVisible(hwnd):
                found.append(hwnd)
            return True

        self.user32.EnumWindows(self.enum_proc(callback), 0)
        return found

    def class_name(self, hwnd):
        buffer = self.ctypes.create_unicode_buffer(256)
        self.user32.GetClassNameW(hwnd, buffer, len(buffer))
        return buffer.value

    def text(self, hwnd, timeout_ms=2000):
        buffer = self.ctypes.create_unicode_buffer(1024)
        result = self.ctypes.c_size_t()
        address = self.ctypes.cast(buffer, self.ctypes.c_void_p).value
        if not self.user32.SendMessageTimeoutW(hwnd, WM_GETTEXT, len(buffer), address,
                                               SMTO_BLOCK | SMTO_ABORTIFHUNG, timeout_ms, self.ctypes.byref(result)):
            raise SmokeFailure(f"Window did not answer WM_GETTEXT within {timeout_ms} ms "
                               f"(Win32 {self.ctypes.get_last_error()}).")
        return buffer.value

    def ping(self, hwnd, timeout_ms=5000):
        result = self.ctypes.c_size_t()
        started = time.monotonic()
        if not self.user32.SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_BLOCK | SMTO_ABORTIFHUNG, timeout_ms,
                                               self.ctypes.byref(result)):
            raise SmokeFailure(f"Main window did not process WM_NULL within {timeout_ms} ms "
                               f"(Win32 {self.ctypes.get_last_error()}); the UI thread is unresponsive.")
        return (time.monotonic() - started) * 1000

    def describe(self, hwnd):
        parts = [f"class={self.class_name(hwnd)}", f"title={bounded(self.text(hwnd))!r}",
                 f"enabled={bool(self.user32.IsWindowEnabled(hwnd))}"]
        statics = []

        def callback(child, _):
            if self.class_name(child) == "Static":
                value = self.text(child)
                if value.strip():
                    statics.append(bounded(value))
            return True

        self.user32.EnumChildWindows(hwnd, self.enum_proc(callback), 0)
        if statics:
            parts.append("static text=" + " | ".join(statics[:3]))
        return "; ".join(parts)


def configure_local_dumps(dump_dir):
    import winreg
    dump_dir.mkdir(parents=True, exist_ok=True)
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, LOCAL_DUMPS_KEY, 0, winreg.KEY_SET_VALUE)
    with key:
        winreg.SetValueEx(key, "DumpFolder", 0, winreg.REG_EXPAND_SZ, str(dump_dir))
        winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "DumpCount", 0, winreg.REG_DWORD, 2)


def remove_local_dumps():
    import winreg
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, LOCAL_DUMPS_KEY)
    except OSError:
        pass


def find_cdb():
    roots = [os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), os.environ.get("ProgramFiles", r"C:\Program Files")]
    for root in roots:
        candidate = Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"
        if candidate.is_file():
            return candidate
    found = shutil.which("cdb.exe")
    return Path(found) if found else None


def analyse_dumps(dump_dir, symbols):
    if not dump_dir or not dump_dir.is_dir():
        return ["Local crash dumps were not enabled."]
    dumps = []
    for _ in range(60):
        dumps = sorted(dump_dir.glob("*.dmp"))
        if dumps:
            break
        time.sleep(0.5)
    if not dumps:
        return ["No local crash dump was written."]
    lines = []
    try:
        cdb = find_cdb()
        if not cdb:
            return [f"A crash dump was captured but cdb.exe is unavailable; match the fault offset with {symbols}\\TELIPHONES.pdb."]
        try:
            result = subprocess.run([str(cdb), "-z", str(dumps[-1]), "-y", str(symbols), "-i", str(symbols), "-lines",
                                     "-c", ".ecxr;kn 25;q"], capture_output=True, text=True, timeout=180)
            output = result.stdout.splitlines()
            start = next((i for i, value in enumerate(output) if ".ecxr" in value), 0)
            lines = ["Symbolised crash stack (local PDB only):"] + output[start:start + 60]
        except (OSError, subprocess.TimeoutExpired) as error:
            lines = [f"Crash dump analysis failed: {error}"]
    finally:
        shutil.rmtree(dump_dir, ignore_errors=True)
    return lines


def crash_report(executable, process, started, dump_dir):
    report = [f"Process exit code: {describe_exit_code(process.returncode)}"]
    events = []
    for _ in range(20):
        events = fault_events_for(executable.name, time.time() - started + 5)
        if any("Application Error" in event or "Application Hang" in event for event in events):
            break
        time.sleep(0.5)
    report += events or ["No Application Error event mentions " + executable.name + "."]
    report += analyse_dumps(dump_dir, executable.parent)
    return "\n".join(report)


def run(executable, dump_dir, startup_timeout, responsive_seconds, close_timeout):
    if sys.platform != "win32":
        raise SmokeFailure("The TELIPHONES GUI startup smoke test requires Windows.")
    windows = Windows()
    diagnostics = Path(os.environ["LOCALAPPDATA"]) / "TELIPHONES" / "Diagnostics"
    before = diagnostic_records(diagnostics)
    if dump_dir:
        configure_local_dumps(dump_dir)
    started = time.time()
    process = subprocess.Popen([str(executable)], cwd=str(executable.parent))
    try:
        main = None
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline and main is None:
            if process.poll() is not None:
                raise SmokeFailure("TELIPHONES exited before its main window appeared.\n" +
                                   crash_report(executable, process, started, dump_dir))
            for hwnd in windows.top_level_windows(process.pid):
                if windows.class_name(hwnd) == "#32770" and windows.text(hwnd).startswith("TELIPHONES "):
                    main = hwnd
                    break
            if main is None:
                time.sleep(0.1)
        if main is None:
            visible = [windows.describe(hwnd) for hwnd in windows.top_level_windows(process.pid)]
            raise SmokeFailure(f"TELIPHONES main window did not appear within {startup_timeout} s. "
                               f"Visible windows: {visible or 'none'}")
        print(f"Main window available after {time.time() - started:.2f} s: {windows.describe(main)}", flush=True)

        latencies = []
        deadline = time.monotonic() + responsive_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise SmokeFailure("TELIPHONES exited while idle at its main window.\n" +
                                   crash_report(executable, process, started, dump_dir))
            latencies.append(windows.ping(main))
            others = [hwnd for hwnd in windows.top_level_windows(process.pid) if hwnd != main]
            if others or not windows.user32.IsWindowEnabled(main):
                raise SmokeFailure("TELIPHONES opened an unexpected modal window at startup: " +
                                   "; ".join(windows.describe(hwnd) for hwnd in others) +
                                   f"; main enabled={bool(windows.user32.IsWindowEnabled(main))}")
            if windows.user32.IsHungAppWindow(main):
                raise SmokeFailure("Windows reports the TELIPHONES main window as hung.")
            time.sleep(0.25)
        print(f"Main window answered {len(latencies)} WM_NULL probes over {responsive_seconds} s "
              f"(max {max(latencies):.1f} ms).", flush=True)

        open_ssh = windows.user32.GetDlgItem(main, IDC_OPEN_SSH)
        if not open_ssh:
            raise SmokeFailure("The Open SSH control is missing from the main window.")
        label = windows.text(open_ssh)
        if label != "Open SSH" or windows.user32.IsWindowEnabled(open_ssh):
            raise SmokeFailure(f"Idle Open SSH control state is wrong: label={label!r}, "
                               f"enabled={bool(windows.user32.IsWindowEnabled(open_ssh))}")
        print("Idle button state verified: 'Open SSH' disabled with no active connection.", flush=True)

        if not windows.user32.PostMessageW(main, WM_CLOSE, 0, 0):
            raise SmokeFailure(f"Unable to request TELIPHONES shutdown (Win32 {windows.ctypes.get_last_error()}).")
        try:
            process.wait(timeout=close_timeout)
        except subprocess.TimeoutExpired:
            visible = [windows.describe(hwnd) for hwnd in windows.top_level_windows(process.pid)]
            raise SmokeFailure(f"TELIPHONES did not exit within {close_timeout} s of WM_CLOSE. Visible windows: {visible}")
        if is_crash_exit_code(process.returncode):
            raise SmokeFailure("TELIPHONES crashed during shutdown.\n" + crash_report(executable, process, started, dump_dir))
        events = new_application_events(before, diagnostic_records(diagnostics))
        names = [event for event, _ in events]
        if "startup" not in names or "shutdown" not in names:
            raise SmokeFailure(f"TELIPHONES did not record a complete startup/shutdown lifecycle: {events}")
        print(f"TELIPHONES closed cleanly: exit {describe_exit_code(process.returncode)}; "
              f"application diagnostic events {names}.", flush=True)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if dump_dir:
            remove_local_dumps()
            shutil.rmtree(dump_dir, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--local-dumps", action="store_true",
                        help="Temporarily enable WER local minidumps (requires administrator rights).")
    parser.add_argument("--startup-timeout", type=float, default=30)
    parser.add_argument("--responsive-seconds", type=float, default=6)
    parser.add_argument("--close-timeout", type=float, default=20)
    args = parser.parse_args(argv)
    executable = args.executable.resolve()
    if not executable.is_file():
        print(f"TELIPHONES executable not found: {executable}", file=sys.stderr)
        return 2
    dump_dir = Path(tempfile.mkdtemp(prefix="TELIPHONES-dumps-")) if args.local_dumps else None
    try:
        run(executable, dump_dir, args.startup_timeout, args.responsive_seconds, args.close_timeout)
    except SmokeFailure as error:
        print("TELIPHONES GUI startup smoke test FAILED:\n" + str(error), file=sys.stderr, flush=True)
        return 1
    print("TELIPHONES GUI startup smoke test passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
