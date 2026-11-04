"""Exercise the real TELIPHONES.exe first-run experience, main window and relaunch in an isolated profile.

Existing TELIPHONES user data is moved aside so the application sees a genuinely new Windows profile.
The first launch must show the first-run wizard, which is completed through its visible buttons (never
the WireGuard installer, Add my PBX or Remote Support). The main window must then be responsive with
Open SSH disabled, and close cleanly. A second launch must skip the completed wizard. The test profile
is removed and the original data restored afterwards.

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

IDOK = 1
IDC_OPEN_SSH = 1010
IDC_APPS_HEADING = 1300
IDC_MESSAGE_TEXT = 1415
WM_NULL = 0x0000
WM_CLOSE = 0x0010
WM_GETTEXT = 0x000D
WM_COMMAND = 0x0111
BN_CLICKED = 0
APP_FOLDER = "TELIPHONES"
PROFILE_BACKUP_SUFFIX = ".smoke-test-backup"
FOLDERID_LOCAL_APP_DATA = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"
FOLDERID_ROAMING_APP_DATA = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"
WELCOME_TITLE = "Welcome to TELIPHONES"
# (heading, IDOK label) for each first-run step, as set by CAppSettingsDlg::ShowStep.
WIZARD_STEPS = (("Step 1: Applications", "Save & Next"),
                ("Step 2: Secure connectivity", "Continue"),
                ("Step 3: Get started", "Finish"))
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


def is_main_window_title(title):
    return title.startswith("TELIPHONES ") and title != "TELIPHONES Settings"


def first_run_preferences(text):
    """Validate preferences.json written by the wizard and return its non-secret application choices."""
    try:
        preferences = json.loads(text)
    except ValueError as error:
        raise SmokeFailure(f"The first-run wizard wrote unreadable preferences: {error}") from None
    if not isinstance(preferences, dict) or preferences.get("setup") != "completed":
        setup = preferences.get("setup") if isinstance(preferences, dict) else None
        raise SmokeFailure(f"The first-run wizard did not record completed setup (setup={setup!r}).")
    browser, terminal = preferences.get("browser"), preferences.get("terminal")
    if not isinstance(browser, str) or not browser or not isinstance(terminal, str):
        raise SmokeFailure(f"The first-run wizard saved invalid application choices: browser={browser!r}, terminal={terminal!r}.")
    return {"browser": browser, "terminal": terminal or "(none)"}


class IsolatedProfile:
    """Move existing TELIPHONES user data aside so the application starts with a new profile, then restore it.

    Only folders that were confirmed isolated are removed afterwards; original data is never deleted.
    """

    def __init__(self, roots):
        self.folders = [Path(root) / APP_FOLDER for root in roots]
        self.isolated = []
        self.moved = []

    @staticmethod
    def backup_for(folder):
        return folder.with_name(folder.name + PROFILE_BACKUP_SUFFIX)

    def __enter__(self):
        for folder in self.folders:
            backup = self.backup_for(folder)
            if backup.exists() or backup.is_symlink():
                raise SmokeFailure(f"An earlier smoke-test profile backup remains at {backup}. Restore it to {folder} "
                                   "manually before rerunning; it will not be overwritten.")
        try:
            for folder in self.folders:
                if folder.exists() or folder.is_symlink():
                    os.replace(folder, self.backup_for(folder))
                    self.moved.append(folder)
                self.isolated.append(folder)
        except OSError as error:
            problems = self.restore()
            raise SmokeFailure(f"Unable to isolate the TELIPHONES profile: {error}" +
                               "".join("\n" + problem for problem in problems)) from None
        print("Isolated TELIPHONES profile: " + "; ".join(
            f"{folder} ({'existing data moved aside' if folder in self.moved else 'absent'})" for folder in self.folders),
            flush=True)
        return self

    def restore(self):
        problems = []
        for folder in list(self.isolated):
            try:
                if folder.exists() or folder.is_symlink():
                    shutil.rmtree(folder)
            except OSError as error:
                problems.append(f"Could not remove the test profile {folder}: {error}")
                continue
            self.isolated.remove(folder)
            if folder in self.moved:
                try:
                    os.replace(self.backup_for(folder), folder)
                    self.moved.remove(folder)
                except OSError as error:
                    problems.append(f"Could not restore {folder} from {self.backup_for(folder)}: {error}")
        return problems

    def __exit__(self, exc_type, exc, traceback):
        problems = self.restore()
        if problems:
            message = "TELIPHONES profile restoration failed:\n" + "\n".join(problems)
            if exc_type is None:
                raise SmokeFailure(message)
            print(message, file=sys.stderr, flush=True)
        return False


def running_instances(image="TELIPHONES.exe"):
    try:
        result = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(f"Unable to check for running {image} instances: {error}") from None
    return [line for line in result.stdout.splitlines() if line.lower().startswith(f'"{image.lower()}"')]


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
        self.ole32 = ctypes.WinDLL("ole32")
        self.ole32.CLSIDFromString.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
        self.ole32.CLSIDFromString.restype = ctypes.c_long
        self.ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        self.shell32 = ctypes.WinDLL("shell32")
        self.shell32.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                                                      ctypes.POINTER(ctypes.c_void_p)]
        self.shell32.SHGetKnownFolderPath.restype = ctypes.c_long

    def known_folder(self, folder_id):
        """Resolve a folder exactly as TELIPHONES does (SHGetKnownFolderPath), not from environment variables."""
        guid = (self.ctypes.c_ubyte * 16)()
        if self.ole32.CLSIDFromString(folder_id, self.ctypes.byref(guid)) != 0:
            raise SmokeFailure(f"Invalid known folder identifier {folder_id}.")
        path = self.ctypes.c_void_p()
        result = self.shell32.SHGetKnownFolderPath(self.ctypes.byref(guid), 0, None, self.ctypes.byref(path))
        try:
            if result != 0:
                raise SmokeFailure(f"SHGetKnownFolderPath({folder_id}) failed: HRESULT 0x{result & 0xFFFFFFFF:08X}.")
            return Path(self.ctypes.wstring_at(path.value))
        finally:
            if path.value:
                self.ole32.CoTaskMemFree(path)

    def control(self, dialog, control_id):
        hwnd = self.user32.GetDlgItem(dialog, control_id)
        if not hwnd:
            raise SmokeFailure(f"Control {control_id} is missing from {self.describe(dialog)}.")
        return hwnd

    def control_text(self, dialog, control_id):
        return self.text(self.control(dialog, control_id))

    def click(self, dialog, control_id):
        """Press a button the way the dialog receives a user click, refusing hidden or disabled buttons."""
        button = self.control(dialog, control_id)
        if not self.user32.IsWindowVisible(button) or not self.user32.IsWindowEnabled(button):
            raise SmokeFailure(f"Button {self.text(button)!r} is not available to the user: "
                               f"visible={bool(self.user32.IsWindowVisible(button))}, "
                               f"enabled={bool(self.user32.IsWindowEnabled(button))}.")
        # Posted rather than sent so a validation message box cannot block the test thread.
        if not self.user32.PostMessageW(dialog, WM_COMMAND, (BN_CLICKED << 16) | control_id, button):
            raise SmokeFailure(f"Unable to press {self.text(button)!r} (Win32 {self.ctypes.get_last_error()}).")

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
        message = self.user32.GetDlgItem(hwnd, IDC_MESSAGE_TEXT)
        if message:
            parts.append("message=" + bounded(self.text(message)))
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


class Launch:
    """One TELIPHONES process; every wait checks for an early exit and reports crashes."""

    def __init__(self, windows, executable, dump_dir, label):
        self.windows = windows
        self.executable = executable
        self.dump_dir = dump_dir
        self.label = label
        self.started = time.time()
        self.process = subprocess.Popen([str(executable)], cwd=str(executable.parent))

    def fail(self, message):
        raise SmokeFailure(f"{self.label}: {message}")

    def check_alive(self, stage):
        if self.process.poll() is not None:
            self.fail(f"TELIPHONES exited during {stage}.\n" +
                      crash_report(self.executable, self.process, self.started, self.dump_dir))

    def visible(self):
        return self.windows.top_level_windows(self.process.pid)

    def describe_visible(self):
        return [self.windows.describe(hwnd) for hwnd in self.visible()] or "none"

    def dialog(self, predicate):
        for hwnd in self.visible():
            if self.windows.class_name(hwnd) == "#32770" and predicate(self.windows.text(hwnd)):
                return hwnd
        return None

    def wait(self, stage, timeout, probe):
        deadline = time.monotonic() + timeout
        while True:
            self.check_alive(stage)
            result = probe()
            if result:
                return result
            if time.monotonic() >= deadline:
                self.fail(f"timed out after {timeout} s waiting for {stage}. Visible windows: {self.describe_visible()}")
            time.sleep(0.1)

    def reject_unexpected(self, stage, expected):
        others = [hwnd for hwnd in self.visible() if hwnd not in expected]
        if others:
            self.fail(f"unexpected window during {stage}: " + "; ".join(self.windows.describe(hwnd) for hwnd in others))

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)


def read_preferences(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise SmokeFailure(f"TELIPHONES preferences are unavailable at {path}: {error}") from None


def complete_first_run(launch, timeout, preferences_file):
    windows = launch.windows
    wizard = launch.wait("the first-run wizard", timeout, lambda: launch.dialog(lambda title: title == WELCOME_TITLE))
    print(f"{launch.label}: first-run wizard shown after {time.time() - launch.started:.2f} s: "
          f"{windows.describe(wizard)}", flush=True)
    saved = None
    for heading, action in WIZARD_STEPS:
        stage = f"wizard step {heading!r}"

        def reached():
            launch.reject_unexpected(stage, {wizard, launch.dialog(is_main_window_title)})
            if not windows.user32.IsWindow(wizard):
                launch.fail(f"the wizard closed before {stage}.")
            return (windows.control_text(wizard, IDC_APPS_HEADING), windows.control_text(wizard, IDOK)) == (heading, action)

        launch.wait(stage, timeout, reached)
        if heading == WIZARD_STEPS[1][0]:
            saved = first_run_preferences(read_preferences(preferences_file))
            print(f"{launch.label}: step 1 validated and saved the detected applications: {saved}.", flush=True)
        print(f"{launch.label}: {heading}: pressing {action!r}.", flush=True)
        windows.click(wizard, IDOK)

    def closed():
        launch.reject_unexpected("wizard completion", {wizard, launch.dialog(is_main_window_title)})
        main = launch.dialog(is_main_window_title)
        if windows.user32.IsWindow(wizard) and windows.user32.IsWindowVisible(wizard):
            return None
        return main if main and windows.user32.IsWindowEnabled(main) else None

    main = launch.wait("the main window after completing the wizard", timeout, closed)
    print(f"{launch.label}: wizard completed after {time.time() - launch.started:.2f} s.", flush=True)
    return main, saved


def wait_for_main_without_wizard(launch, timeout):
    def ready():
        if launch.dialog(lambda title: title == WELCOME_TITLE):
            launch.fail("the completed first-run wizard was shown again: " + str(launch.describe_visible()))
        return launch.dialog(is_main_window_title)

    main = launch.wait("the main window", timeout, ready)
    print(f"{launch.label}: main window available after {time.time() - launch.started:.2f} s without the wizard.",
          flush=True)
    return main


def verify_main_window(launch, main, responsive_seconds):
    windows = launch.windows
    print(f"{launch.label}: main window: {windows.describe(main)}", flush=True)
    latencies = []
    deadline = time.monotonic() + responsive_seconds
    while time.monotonic() < deadline:
        launch.check_alive("idle operation at the main window")
        latencies.append(windows.ping(main))
        launch.reject_unexpected("idle operation at the main window", {main})
        if not windows.user32.IsWindowEnabled(main):
            launch.fail("the main window is disabled while idle.")
        if windows.user32.IsHungAppWindow(main):
            launch.fail("Windows reports the TELIPHONES main window as hung.")
        time.sleep(0.25)
    print(f"{launch.label}: main window answered {len(latencies)} WM_NULL probes over {responsive_seconds} s "
          f"(max {max(latencies):.1f} ms).", flush=True)

    open_ssh = windows.control(main, IDC_OPEN_SSH)
    label = windows.text(open_ssh)
    if label != "Open SSH" or windows.user32.IsWindowEnabled(open_ssh):
        launch.fail(f"idle Open SSH control state is wrong: label={label!r}, "
                    f"enabled={bool(windows.user32.IsWindowEnabled(open_ssh))}")
    print(f"{launch.label}: 'Open SSH' is disabled with no active connection.", flush=True)


def close_cleanly(launch, main, close_timeout, diagnostics, before):
    windows = launch.windows
    if not windows.user32.PostMessageW(main, WM_CLOSE, 0, 0):
        launch.fail(f"unable to request shutdown (Win32 {windows.ctypes.get_last_error()}).")
    try:
        launch.process.wait(timeout=close_timeout)
    except subprocess.TimeoutExpired:
        launch.fail(f"TELIPHONES did not exit within {close_timeout} s of WM_CLOSE. "
                    f"Visible windows: {launch.describe_visible()}")
    if is_crash_exit_code(launch.process.returncode):
        launch.fail("TELIPHONES crashed during shutdown.\n" +
                    crash_report(launch.executable, launch.process, launch.started, launch.dump_dir))
    after = diagnostic_records(diagnostics)
    events = new_application_events(before, after)
    names = [event for event, _ in events]
    if "startup" not in names or "shutdown" not in names:
        launch.fail(f"TELIPHONES did not record a complete startup/shutdown lifecycle: {events}")
    print(f"{launch.label}: closed cleanly: exit {describe_exit_code(launch.process.returncode)}; "
          f"application diagnostic events {names}.", flush=True)
    return after


def run(executable, dump_dir, startup_timeout, responsive_seconds, close_timeout):
    if sys.platform != "win32":
        raise SmokeFailure("The TELIPHONES GUI startup smoke test requires Windows.")
    windows = Windows()
    if running_instances():
        raise SmokeFailure("Close the running TELIPHONES instance first; the smoke test needs an isolated profile.")
    local = windows.known_folder(FOLDERID_LOCAL_APP_DATA)
    roaming = windows.known_folder(FOLDERID_ROAMING_APP_DATA)
    diagnostics = local / APP_FOLDER / "Diagnostics"
    preferences_file = local / APP_FOLDER / "preferences.json"
    with IsolatedProfile([local, roaming]):
        if dump_dir:
            configure_local_dumps(dump_dir)
        records = set()
        launch = None
        try:
            launch = Launch(windows, executable, dump_dir, "First launch (new profile)")
            main, saved = complete_first_run(launch, startup_timeout, preferences_file)
            verify_main_window(launch, main, responsive_seconds)
            records = close_cleanly(launch, main, close_timeout, diagnostics, records)

            launch = Launch(windows, executable, dump_dir, "Second launch (completed setup)")
            main = wait_for_main_without_wizard(launch, startup_timeout)
            verify_main_window(launch, main, responsive_seconds)
            close_cleanly(launch, main, close_timeout, diagnostics, records)
            if first_run_preferences(read_preferences(preferences_file)) != saved:
                raise SmokeFailure("The second launch changed the application choices saved by the first-run wizard.")
        except SmokeFailure as error:
            events = new_application_events(set(), diagnostic_records(diagnostics))
            raise SmokeFailure(f"{error}\nApplication lifecycle events in the test profile: {events or 'none'}") from None
        finally:
            if launch:
                launch.stop()
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
