"""Check native build inputs without requiring Visual Studio or third-party packages."""

from pathlib import Path, PureWindowsPath
import importlib.util
import copy
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
NS = {"ms": "http://schemas.microsoft.com/developer/msbuild/2003"}


def project(name):
    return ET.parse(ROOT / name).getroot()


class BuildLayoutTests(unittest.TestCase):
    @patch("builtins.print")
    def test_fixture_acl_operations_and_descriptor_verification(self, _print):
        spec = importlib.util.spec_from_file_location("fixture_acl", ROOT / "tests/ssh_native_check.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), patch.object(sys, "argv", ["fixture", "host.exe"]):
            spec.loader.exec_module(module)
        sids = ["S-1-5-18", "S-1-5-32-544"]
        descriptor = {"owner": sids[0], "protected": True, "rules": [
            {"sid": sid, "allow": True, "inherited": False, "mask": 0x1F01FF,
             "inheritance": 0, "propagation": 0, "unsupported_flags": 0} for sid in sids]}
        with patch.object(module, "run") as run, patch.object(module, "security_state", return_value=descriptor):
            module.secure_path("D:/fixture/host", sids[0], sids)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands, [
                [module.HOST, "--security", "RestrictFile", "D:/fixture/host", "host"],
                ["icacls.exe", "D:/fixture/host", "/setowner", "*S-1-5-18"]])
        for field, value in (("owner", "S-1-1-0"), ("protected", False)):
            invalid = {**descriptor, field: value}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                module.verify_security(invalid, sids[0], sids)
        for field, value in (("sid", "S-1-1-0"), ("mask", 0x120089), ("inherited", True),
                             ("allow", False), ("inheritance", 3), ("propagation", 1), ("unsupported_flags", 64)):
            invalid = copy.deepcopy(descriptor)
            invalid["rules"][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                module.verify_security(invalid, sids[0], sids)
        task = {**descriptor, "principal": "S-1-5-18", "logon_type": 5, "run_level": 1}
        module.verify_security(task, sids[0], sids, task=True)
        with self.assertRaises(AssertionError):
            module.verify_security({**task, "logon_type": 3}, sids[0], sids, task=True)
        runner_sid = "S-1-5-21-1-2-3-1001"
        baseline = copy.deepcopy(descriptor)
        baseline["owner"] = runner_sid
        baseline["rules"].append({**baseline["rules"][0], "sid": runner_sid})
        invalid = copy.deepcopy(baseline)
        invalid["rules"].append({**invalid["rules"][0], "sid": "S-1-1-0"})
        observations = [baseline, invalid, baseline]
        for field in ("extra", "owner", "protected", "mask", "deny"):
            observed = copy.deepcopy(invalid if field in ("extra", "deny") else baseline)
            if field == "owner":
                observed["owner"] = sids[1]
            elif field == "protected":
                observed["protected"] = False
            elif field == "mask":
                observed["rules"][0]["mask"] = 0x120089
            elif field == "deny":
                observed["rules"][-1]["allow"] = False
            observations.extend((observed, baseline))
        with tempfile.TemporaryDirectory() as root, patch.object(module, "run"), \
                patch.object(module, "security_state", side_effect=observations) as inspected:
            module.native_acl_regression(Path(root), runner_sid)
            self.assertEqual(inspected.call_count, 13)
            self.assertFalse((Path(root) / "acl-negative-probe").exists())
        with tempfile.TemporaryDirectory() as root, patch.object(module, "run"), \
                patch.object(module, "security_state", return_value=baseline), \
                self.assertRaisesRegex(RuntimeError, "requires an actual explicit Everyone ACE"):
            module.native_acl_regression(Path(root), runner_sid)
        with tempfile.TemporaryDirectory() as root, patch.object(module, "run"), \
                patch.object(module, "security_state", side_effect=[baseline, invalid, baseline, baseline]), \
                self.assertRaisesRegex(RuntimeError, "accepted actual invalid ACL"):
            module.native_acl_regression(Path(root), runner_sid)
        with patch.object(module, "run") as run, patch.object(module, "security_state", return_value=baseline):
            module.secure_path("D:/fixture/ca.pub", runner_sid, [*sids, runner_sid])
            self.assertEqual(run.call_args_list[0].args[0],
                             [module.HOST, "--security", "RestrictFile", "D:/fixture/ca.pub", "file"])
            directory = copy.deepcopy(baseline)
            for rule in directory["rules"]:
                rule["inheritance"] = 3
            with patch.object(module, "security_state", return_value=directory):
                module.secure_path("D:/fixture", runner_sid, [*sids, runner_sid], directory=True)
            self.assertEqual(run.call_args_list[2].args[0],
                             [module.HOST, "--security", "RestrictFile", "D:/fixture", "directory"])
        cls = module.WindowsSshTests
        with patch.object(module, "native_acl_regression"), patch("builtins.print"), \
                patch.object(cls, "root", Path("fixture"), create=True), patch.object(cls, "sid", sids[0], create=True), \
                patch.object(cls, "setUpClass") as setup, patch.object(cls, "doClassCleanups") as cleanup, \
                patch.object(cls, "tearDown_exceptions", [], create=True):
            module.fixture_preflight()
            setup.assert_called_once()
            cleanup.assert_called_once()
            with patch.object(cls, "setUpClass"), patch.object(cls, "doClassCleanups"), \
                    patch.object(cls, "tearDown_exceptions", [(RuntimeError, RuntimeError("cleanup failed"), None)], create=True), \
                    self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                module.fixture_preflight()
            with tempfile.TemporaryDirectory() as parent:
                cls.root = Path(parent) / "owned-fixture"
                cls.root.mkdir()
                cls.task = "TELIPHONES-sshd-test-0123456789abcdef"
                with patch.object(module, "fixture_task_state", return_value=4), \
                        self.assertRaisesRegex(RuntimeError, "Preserving fixture directory"):
                    cls.remove_temporary()
                self.assertTrue(cls.root.is_dir())
                pid_file = cls.root / "server.pid"
                pid_file.write_text("123", encoding="ascii")
                with patch.object(module, "alive", side_effect=[True, False]) as alive, \
                        patch.object(module.time, "sleep") as sleep:
                    module.wait_server_exit(pid_file)
                    self.assertEqual(alive.call_count, 2)
                    sleep.assert_called_once_with(0.1)
                with patch.object(module, "fixture_task_state", return_value=None), \
                        patch.object(module, "alive", return_value=False):
                    cls.remove_temporary()
                self.assertFalse(cls.root.exists())
        with patch.object(cls, "setUpClass", side_effect=RuntimeError("setup operation failed")), \
                patch.object(cls, "doClassCleanups") as cleanup, \
                patch.object(cls, "tearDown_exceptions", [], create=True), \
                self.assertRaisesRegex(RuntimeError, "setup operation failed"):
            module.fixture_preflight()
        cleanup.assert_called_once()

    def test_native_security_has_no_powershell_module_dependency(self):
        fixture = (ROOT / "tests/ssh_native_check.py").read_text(encoding="utf-8")
        for dependency in ("powershell.exe", "Get-Acl", "Get-ScheduledTask", "PSModulePath"):
            self.assertNotIn(dependency, fixture)
        native = (ROOT / "tests/fixture_security.cpp").read_text(encoding="utf-8")
        for api in ("GetNamedSecurityInfoW", "GetSecurityDescriptorOwner", "GetSecurityDescriptorDacl",
                    "GetSecurityDescriptorControl", "GetAce", "GetSecurityDescriptor",
                    "SE_DACL_PROTECTED", "TASK_DONT_ADD_PRINCIPAL_ACE", "TokenElevation",
                    "GetVolumeInformationW", "FS_PERSISTENT_ACLS", "SetNamedSecurityInfoW",
                    "DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION"):
            self.assertIn(api, native)
        self.assertIn("HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)", native)
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("tests/fixture_security.cpp", cmake)
        self.assertIn("oleaut32 taskschd", cmake)
        self.assertFalse((ROOT / "tests/fixture_security.ps1").exists())

    def test_native_fixture_signature_transport_preserves_exact_bytes(self):
        spec = importlib.util.spec_from_file_location("fixture_transport", ROOT / "tests/ssh_native_check.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), patch.object(sys, "argv", ["fixture", "host.exe"]):
            spec.loader.exec_module(module)
        message = "TELIPHONES-SSH-REQUEST-2\nworkstation\nchallenge\nsession\npublic-key\n"
        result = subprocess.CompletedProcess(["keygen"], 0, b"verified\r\n", b"")
        with patch.object(module.subprocess, "run", return_value=result) as process:
            self.assertEqual(module.run(["keygen"], input=message), "verified\r\n")
            self.assertEqual(process.call_args.kwargs["input"], message.encode("utf-8"))
            self.assertNotIn("text", process.call_args.kwargs)
            self.assertNotIn("encoding", process.call_args.kwargs)
        with patch.object(module, "run", return_value='{"owner":"S-1-5-18"}') as process:
            self.assertEqual(module.security_state("File", "D:/a b/key")["owner"], "S-1-5-18")
            self.assertEqual(process.call_args.args[0], [module.HOST, "--security", "File", "D:/a b/key"])

    def test_powershell_diagnostics_compare_isolated_discovery_environments(self):
        spec = importlib.util.spec_from_file_location("ps_environment", ROOT / "tests/powershell_environment_check.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for module_path_key in ("PSModulePath", "PSMODULEPATH", None):
            with self.subTest(module_path_key=module_path_key):
                environment = {"SystemRoot": "C:/Windows", "PATH": "C:/Windows/System32"}
                if module_path_key is not None:
                    environment.update({module_path_key: "C:/PowerShell7/Modules", "PSHOME": "C:/PowerShell7"})
                expected_parent = environment.copy()
                expected_isolated = {key: value for key, value in environment.items()
                                     if key.casefold() not in ("psmodulepath", "pshome")}
                results = [subprocess.CompletedProcess([], 1, "loader exception details", ""),
                           subprocess.CompletedProcess([], 0, "Microsoft.PowerShell.Security loaded", "")]
                # Windows os.environ.copy() uppercases keys; use an exact mapping,
                # not the host's case-normalising environment implementation.
                with patch.object(module.os, "environ", environment), patch.object(module.os, "name", "nt"), \
                        patch.object(module, "Path", PureWindowsPath), \
                        patch.object(module.subprocess, "run", side_effect=results) as process, \
                        patch("builtins.print") as output:
                    module.main()
                    self.assertEqual(process.call_count, 2)
                    first, second = process.call_args_list
                    self.assertEqual(first.kwargs["env"], expected_parent)
                    self.assertEqual(second.kwargs["env"], expected_isolated)
                    self.assertIsNot(first.kwargs["env"], environment)
                    self.assertIsNot(second.kwargs["env"], environment)
                    self.assertEqual(environment, expected_parent)
                    self.assertIn("System32\\WindowsPowerShell\\v1.0\\powershell.exe", first.args[0][0])
                    self.assertEqual(first.args[0], second.args[0])
                    self.assertTrue(any("loader exception details" in str(call) for call in output.call_args_list))

    def test_contract_stdout_rejects_windows_double_translation(self):
        spec = importlib.util.spec_from_file_location("portable_contract", ROOT / "tests/contract_check.py")
        module = importlib.util.module_from_spec(spec)
        importers = sys.meta_path[:]
        try:
            with patch.object(sys, "argv", ["contract_check.py", "contract_tool"]):
                spec.loader.exec_module(module)
        finally:
            sys.meta_path[:] = importers
        renderer = b"[Interface]\r\nAddress = 100.70.1.2/32\r\n\r\n[Peer]\r\n"
        windows_text_stdout = renderer.replace(b"\n", b"\r\n")
        for mode in ("administrator", "support"):
            for output, accepted in ((renderer, True), (windows_text_stdout, False),
                                     (renderer.replace(b"\r\n", b"\n"), False)):
                with self.subTest(mode=mode, output=output):
                    result = subprocess.CompletedProcess(["contract_tool", mode], 0, output, b"")
                    with patch.object(module.subprocess, "run", return_value=result) as process:
                        if accepted:
                            self.assertEqual(module.tool(mode).stdout, renderer.decode().replace("\r\n", "\n"))
                        else:
                            with self.assertRaisesRegex(AssertionError, "must preserve renderer CRLF bytes"):
                                module.tool(mode)
                        self.assertNotIn("text", process.call_args.kwargs)
        helper = (ROOT / "tests/contract_tool.cpp").read_text(encoding="utf-8")
        self.assertIn("_setmode(_fileno(stdout), _O_BINARY)", helper)

    def test_workflow_independent_suites_preserve_failures_and_diagnostics(self):
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text(encoding="utf-8")
        steps = {match.group(1): match.group(2) for match in
                 re.finditer(r"      - name: ([^\n]+)\n(.*?)(?=\n      - name: |\Z)", workflow, re.DOTALL)}
        ctest = steps["Run all portable CTests with complete diagnostics"]
        native = steps["Run native Windows OpenSSH integration independently"]
        for step in (ctest, native):
            self.assertIn("!cancelled()", step)
            self.assertIn("steps.native_build.outcome == 'success'", step)
            self.assertIn("steps.openssh.outcome == 'success'", step)
            self.assertIn("if ($LASTEXITCODE -ne 0) { throw", step)
            self.assertIn("Tee-Object", step)
        self.assertIn("steps.native_preflight.outcome == 'success'", native)
        self.assertIn("steps.fixture_preflight.outcome == 'success'", native)
        fixture = steps["Preflight actual isolated Windows SSH fixture"]
        self.assertIn("--fixture-preflight", fixture)
        self.assertIn("!cancelled()", fixture)
        self.assertNotIn("contract", fixture)
        self.assertNotIn("contract", native)
        self.assertNotIn("steps.native_preflight", ctest)
        self.assertIn("--verbose --output-on-failure --no-tests=error --output-junit", ctest)
        self.assertNotIn("continue-on-error", workflow)
        self.assertIn("if: always()", steps["Upload startup diagnostics on failure"])
        self.assertNotIn("if:", steps["Prepare application artifact"])
        for name in ("Run native Windows core and diagnostics regression tests",
                     "Run native appearance, layout and Connection Health window tests",
                     "Verify real x64 native executable and runtime dependencies",
                     "Smoke-test executable loading without UAC or networking"):
            self.assertIn("!cancelled() && steps.application_build.outcome == 'success'", steps[name])

    def test_native_task_definition_preserves_windows_paths(self):
        spec = importlib.util.spec_from_file_location("native_fixture", ROOT / "tests/ssh_native_check.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), patch.object(sys, "argv", ["fixture", "host.exe"]):
            spec.loader.exec_module(module)
        args = ["--fixture-server", "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
                "D:\\test directory\\config", "D:\\test directory\\log", "stop", "pid"]
        xml = ET.fromstring(module.task_xml("D:\\test directory\\host.exe", args))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(xml.findtext("t:Principals/t:Principal/t:UserId", namespaces=ns), "S-1-5-18")
        self.assertIsNone(xml.find("t:Principals/t:Principal/t:LogonType", ns))
        self.assertEqual(xml.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=ns), "HighestAvailable")
        self.assertEqual(xml.find("t:Principals/t:Principal", ns).get("id"), "System")
        self.assertEqual(xml.find("t:Actions", ns).get("Context"), "System")
        self.assertIsNone(xml.find("t:Triggers", ns))
        self.assertEqual(xml.get("version"), "1.2")
        self.assertEqual(xml.findtext("t:Actions/t:Exec/t:Command", namespaces=ns), "D:\\test directory\\host.exe")
        self.assertEqual(xml.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns), subprocess.list2cmdline(args))
        self.assertEqual(xml.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=ns), "PT10M")
        self.assertEqual(xml.findtext("t:Settings/t:AllowStartOnDemand", namespaces=ns), "true")
        fixture = (ROOT / "tests/ssh_native_check.py").read_text(encoding="utf-8")
        self.assertIn('run(["schtasks.exe", "/Create", "/TN", cls.task, "/XML", xml, "/RU", "SYSTEM"])', fixture)
        self.assertLess(fixture.index('security_state("Task", cls.task, cls.sid)'),
                        fixture.index('run(["schtasks.exe", "/Run", "/TN", cls.task])'))
        self.assertEqual(len([name for name in dir(module.WindowsSshTests) if name.startswith("test_")]), 10)

    def test_ctest_platform_boundary_and_native_ssh_gate(self):
        stubbed = ("project", "set_target_properties", "add_library", "add_executable",
                   "target_compile_options", "target_include_directories", "target_link_libraries",
                   "target_compile_definitions", "enable_testing")
        script = "\n".join(f"macro({name})\nendmacro()" for name in stubbed)
        script += """
macro(find_package)
    if("${ARGV0}" STREQUAL "Python3")
        set(Python3_FOUND TRUE)
        set(Python3_EXECUTABLE python)
    endif()
endmacro()
function(add_test)
    message(STATUS "REGISTERED=${ARGV1}")
endfunction()
"""
        portable = {"core_tests", "session_diagnostics", "build_layout", "contract_check",
                    "managed_ssh_check", "ssh_crypto_check"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registration.cmake"
            for platform in ("Windows", "Linux"):
                path.write_text(script + f'\nset(CMAKE_SYSTEM_NAME {platform})\n'
                                f'set(WIN32 {"TRUE" if platform == "Windows" else "FALSE"})\n'
                                f'include("{(ROOT / "CMakeLists.txt").as_posix()}")\n', encoding="utf-8")
                result = subprocess.run(["cmake", "-P", str(path)], text=True,
                                        capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                registered = re.findall(r"REGISTERED=(\w+)", result.stdout)
                expected = portable | ({"broker_contract_check"} if platform == "Linux" else set())
                self.assertEqual(set(registered), expected)
                self.assertEqual(len(registered), len(expected))
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text(encoding="utf-8")
        self.assertIn("tests/provision_openssh.ps1", workflow)
        self.assertLess(workflow.index("tests/provision_openssh.ps1"),
                        workflow.index("ctest --test-dir"))
        self.assertLess(workflow.index("tests/provision_openssh.ps1"),
                        workflow.index("Restore declared static OpenSSL"))
        self.assertLess(workflow.index("ssh_native_host.exe --preflight"),
                        workflow.index("ctest --test-dir"))
        self.assertIn("python desktop/windows/tests/ssh_native_check.py", workflow)
        self.assertIn("throw 'Native Windows named-pipe/OpenSSH integration failed.'", workflow)

    def test_native_ssh_provisioning_and_isolated_system_fixture(self):
        provision = (ROOT / "tests/provision_openssh.ps1").read_text(encoding="utf-8")
        for required in ("Get-WindowsCapability -Online", "Add-WindowsCapability -Online -Name $name",
                         "OpenSSH.Client~~~~0.0.1.0", "OpenSSH.Server~~~~0.0.1.0",
                         "$verified.State -ne 'Installed'", "$result.RestartNeeded",
                         "@('ssh.exe', 'ssh-keygen.exe', 'sshd.exe')", "$env:GITHUB_PATH",
                         "Get-FileHash", "$LASTEXITCODE", "$global:LASTEXITCODE = 0"):
            self.assertIn(required, provision)
        for forbidden in ("Start-Service", "Set-Service", "Invoke-WebRequest", "winget", "choco"):
            self.assertNotIn(forbidden, provision)
        native = (ROOT / "tests/ssh_native_check.py").read_text(encoding="utf-8")
        for required in ("disable_debug_privilege()", "SO_EXCLUSIVEADDRUSE", "StrictModes yes",
                         '"/RU", "SYSTEM"', '"S-1-5-18"', '"schtasks.exe", "/Create"',
                         '"schtasks.exe", "/Run"', '"schtasks.exe", "/Delete"', "cls.stop_file.touch()",
                         'KEYGEN, "-Y", "verify"', 'SSHD, "-T"', '"/setowner", "*" + owner',
                         "Unrelated-process agent probe did not complete within five seconds"):
            self.assertIn(required, native)
        host = (ROOT / "tests/ssh_native_host.cpp").read_text(encoding="utf-8")
        for required in ("WinLocalSystemSid", "CryptProtectData", "CryptUnprotectData",
                         "fixtureServer(argv)", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
                         "accounting.ActiveProcesses == 0", "TerminateJobObject", 'L".stopped"'):
            self.assertIn(required, host)
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("target_compile_definitions(teliphones_fixture_core PRIVATE TELIPHONES_SSH_LOOPBACK_FIXTURE)", cmake)
        self.assertNotIn("TELIPHONES_SSH_LOOPBACK_FIXTURE", (ROOT / "TELIPHONES.vcxproj").read_text())
        self.assertIn("ssh_native_host PRIVATE teliphones_fixture_crypto", cmake)
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text(encoding="utf-8")
        self.assertIn("if: always() && env.STARTUP_DIAGNOSTICS != ''", workflow)
        self.assertIn("ssh_native_host.exe --cleanup-only", workflow)

    def test_windows_version_is_consistent_and_embedded(self):
        header = (ROOT / "src/app/Version.h").read_text()
        parts = []
        for component in ("MAJOR", "MINOR", "PATCH", "BUILD"):
            match = re.search(rf"^#define TELIPHONES_VERSION_{component}\s+(\d+)\s*$", header, re.MULTILINE)
            self.assertIsNotNone(match, component)
            value = int(match.group(1))
            self.assertTrue(0 <= value <= 65535, component)
            parts.append(value)
        base = ".".join(map(str, parts[:3]))
        product = base
        numeric = ".".join(map(str, parts))
        self.assertEqual(product, "0.7.0")
        self.assertEqual(numeric, "0.7.0.0")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"# TELIPHONES {product} for Windows", readme)
        self.assertIn(f"**{numeric}**", readme)
        self.assertIn(f"Windows **{product}**", (ROOT.parents[1] / "README.md").read_text(encoding="utf-8"))
        self.assertIn(f"## {product} — Unreleased", changelog)
        self.assertEqual(re.findall(r"^## (\d+\.\d+\.\d+) ", changelog, re.MULTILINE)[0], product)
        self.assertIn(f"**{numeric}**", changelog)
        self.assertIn("Windows 0.7.0 introduces managed My PBXs SSH certificates", readme)
        self.assertIn(
            "Windows 0.7.0 introduces managed My PBXs SSH certificates",
            " ".join(changelog.split()),
        )
        self.assertIn("FreePBX module version is independent and is **0.4.0**", changelog)
        registered = {
            item.attrib["Include"].replace("\\", "/")
            for item in project("TELIPHONES.vcxproj").findall("ms:ItemGroup/ms:ClInclude", NS)
        }
        self.assertIn("src/app/Version.h", registered)
        rc = (ROOT / "src/app/TELIPHONES.rc").read_text()
        self.assertIn('#include "Version.h"', rc)
        self.assertEqual(len(re.findall(r"^\s*VS_VERSION_INFO VERSIONINFO", rc, re.MULTILINE)), 1)
        for declaration in (
            "FILEVERSION TELIPHONES_VERSION_NUMERIC",
            "PRODUCTVERSION TELIPHONES_VERSION_NUMERIC",
            'VALUE "FileVersion", TELIPHONES_VERSION_FILE_STRING',
            'VALUE "ProductVersion", TELIPHONES_VERSION_STRING',
            'VALUE "OriginalFilename", "TELIPHONES.exe',
            "FILEFLAGS VS_FF_PRERELEASE",
            'VALUE "Translation", 0x0809, 1200',
        ):
            self.assertIn(declaration, rc)
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        self.assertIn('#include "Version.h"', main)
        self.assertIn('SetWindowText(Widen("TELIPHONES " TELIPHONES_VERSION_STRING)', main)
        installer = (ROOT / "src/platform/WireGuardInstaller.cpp").read_text()
        self.assertIn('#include "../app/Version.h"', installer)
        self.assertIn('Widen("TELIPHONES/" TELIPHONES_VERSION_STRING)', installer)
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text()
        self.assertIn("$expectedProductVersion = $parts[0..2] -join '.'", workflow)
        for check in (
            "GetVersionInfo($exe)", "$version.IsPreRelease", "$version.FileVersion",
            "$version.ProductVersion", "$fixedFileVersion", "$fixedProductVersion",
            "build-info.json", "sourceRevision = $env:GITHUB_SHA", "runId = $env:GITHUB_RUN_ID",
            "Get-FileHash", "desktop/windows/build/artifact/CHANGELOG.md",
        ):
            self.assertIn(check, workflow)

    def test_product_disclaimers_and_licence_packaging(self):
        source = (ROOT / "src/app/AppSettingsDlg.cpp").read_text()
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        self.assertIn('"Saved connections", IDC_PBX_HEADING', resource)
        self.assertNotIn('"My PBXs & Remote Support"', resource)
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text()
        self.assertIn('#include "Version.h"', source)
        self.assertIn("ON_BN_CLICKED(IDC_APPS_ABOUT, &CAppSettingsDlg::OnAbout)", source)
        self.assertIn('"About...", IDC_APPS_ABOUT', resource)
        self.assertIn('"TELIPHONES " TELIPHONES_VERSION_STRING " for Windows is licensed under GPLv3.', source)
        self.assertIn("TELIPHONES is a UK registered trademark.", source)
        self.assertIn("does not grant trademark rights", source)
        layout = (ROOT / "src/app/DesktopLayout.cpp").read_text()
        self.assertIn("SetDlgItemText(IDC_PRODUCT_FOOTER", layout)
        self.assertIn('"TELIPHONES " TELIPHONES_VERSION_STRING " for Windows is licensed under GPLv3.', layout)
        self.assertIn("move(Find(IDC_PRODUCT_FOOTER), fixed.disclaimer)", layout)
        self.assertIn('SS_CENTER | SS_CENTERIMAGE | SS_ENDELLIPSIS', resource)
        self.assertNotIn('"TELIPHONES is a UK registered trademark.\\r\\n"', layout)
        self.assertIn("desktop/windows/build/artifact/LICENSE", workflow)
        module = ET.parse(ROOT.parents[1] / "teliphones/module.xml").getroot()
        self.assertEqual(module.findtext("version"), "0.4.0")
        for path, statement in (
            (ROOT / "README.md", "TELIPHONES 0.7.0 for Windows is licensed under GPLv3."),
            (ROOT.parents[1] / "teliphones/README.md", "TELIPHONES 0.4.0 for FreePBX is licensed under GPLv3."),
        ):
            text = path.read_text()
            self.assertIn(statement, text)
            self.assertIn("TELIPHONES is a UK registered trademark.", text)
            self.assertIn("does not grant trademark rights", text)

    def test_application_compiles_every_native_source(self):
        app = project("TELIPHONES.vcxproj")
        compiled = {
            item.attrib["Include"].replace("\\", "/")
            for item in app.findall("ms:ItemGroup/ms:ClCompile", NS)
        }
        expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.cpp")}
        helper_main = "src/platform/SshConsoleMain.cpp"
        self.assertEqual(compiled, expected - {helper_main})
        helper = project("SshConsole.vcxproj")
        self.assertIn(helper_main, {item.attrib["Include"].replace("\\", "/")
                                   for item in helper.findall("ms:ItemGroup/ms:ClCompile", NS)})
        self.assertIn("SshConsole.vcxproj", {item.attrib["Include"]
                                          for item in project("TELIPHONES.vcxproj").findall("ms:ItemGroup/ms:ProjectReference", NS)})
        project_headers = {
            item.attrib["Include"].replace("\\", "/")
            for item in app.findall("ms:ItemGroup/ms:ClInclude", NS)
        }
        self.assertIn("src/app/ConnectionHealthDlg.h", project_headers)
        self.assertIn("src/core/ConnectionHealth.h", project_headers)
        self.assertIn("src/app/ConnectionHealthDlg.cpp", compiled)
        self.assertIn("src/core/ConnectionHealth.cpp", compiled)

    def test_pairing_ssh_capability_is_opt_in(self):
        source = (ROOT / "src/app/PairDlg.cpp").read_text()
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        self.assertIn("CheckDlgButton(IDC_PAIR_SSH_CAPABILITY, BST_UNCHECKED);", source)
        self.assertIn("tlp::CreatePairRequest(", source)
        self.assertIn("IsDlgButtonChecked(IDC_PAIR_SSH_CAPABILITY) == BST_CHECKED", source)
        self.assertIn("[this]() { return tlp::win::GenerateWorkstationSshIdentity(profile); }", source)
        self.assertNotIn("RequireEphemeralSshProvider", source)
        self.assertIn("pairing.ssh && sshPublicKey_.empty()", source)
        self.assertIn("if (sshKeyRequested_) {", source)
        self.assertIn('IDC_PAIR_SSH_CAPABILITY, "Button", BS_AUTOCHECKBOX', resource)

    def test_managed_ssh_has_no_file_or_shared_agent_fallback(self):
        source = (ROOT / "src/platform/Ssh.cpp").read_text()
        services = (ROOT / "src/platform/Services.cpp").read_text()
        apps = (ROOT / "src/platform/Applications.cpp").read_text()
        for forbidden in ("WriteNewFile(", "ReadSmallFile(", "RunProcess(", "WinHttp", "ssh-keygen", "CryptUnprotectData(",
                          "CreateProcess", "IdentityAgent", "ssh-add", "PrepareManagedSsh"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("LoadSshPrivateKey(", services)
        self.assertNotIn("SaveSshPrivateKey(", services)
        launch = apps[apps.index("void OpenSsh("):]
        self.assertLess(launch.index("StartManagedSsh(profile, preferences)"), launch.index("SshTargetFor("))
        session = (ROOT / "src/platform/SshSession.cpp").read_text()
        agent = (ROOT / "src/platform/SshAgent.cpp").read_text()
        for required in ("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "AssignProcessToJobObject", "IsProcessInJob",
                         "CRYPTPROTECT_UI_FORBIDDEN", "teliphones-ssh-request/2", "VerifySshCertificateSignature"):
            self.assertIn(required, session)
        for required in ("GetNamedPipeClientProcessId", "GetProcessId(client_)", "key_->destroy()",
                         "ValidateSshAuthentication", "PIPE_REJECT_REMOTE_CLIENTS", "FILE_FLAG_FIRST_PIPE_INSTANCE"):
            self.assertIn(required, agent)
        helper = session[session.index("int RunSshConsole("):]
        self.assertLess(helper.index("ProtectSshProcess(GetCurrentProcess(), true)"), helper.index("CreateProcessW("))
        solution = (ROOT / "TELIPHONES.sln").read_text()
        self.assertIn('"TELIPHONES-SSH", "SshConsole.vcxproj"', solution)
        for configuration in ("Debug", "Release"):
            self.assertIn(f"{{FF47881E-AB14-4F8C-9212-15AAB265FA09}}.{configuration}|x64.Build.0", solution)
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        self.assertIn("tlp::win::CloseManagedSsh(managedSshProfile)", main)
        action = main[main.index("void CMainDlg::OnOpenSsh()"):main.index("void CMainDlg::OnTimer(")]
        self.assertLess(action.index("RequireManagedSsh(profile)"), action.index("tlp::ResolveApp("))

    def test_connection_health_popout_and_integrated_panel_are_wired(self):
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        self.assertRegex(resource, r"IDD_CONNECTION_HEALTH DIALOGEX 0, 0, 360, 240")
        for control in ("IDC_HEALTH_STATE", "IDC_HEALTH_AUTH", "IDC_HEALTH_GRAPH", "IDC_HEALTH_WARNING",
                        "IDC_HEALTH_HISTORY", "IDC_HEALTH_TOPMOST", "IDC_HEALTH_THRESHOLDS",
                        "IDC_HEALTH_INLINE_TEXT", "IDC_HEALTH_INLINE_GRAPH", "IDC_HEALTH_INLINE_HISTORY",
                        "IDC_SESSION_LOG", "IDC_SESSION_LOG_TEXT", "IDC_SESSION_LOG_EXPORT"):
            self.assertIn(control, resource)
        dialog = (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text()
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        self.assertIn("width - limitsDlu.Width() - rightMarginDlu.right", dialog)
        for source in (dialog, main):
            self.assertIn("DrawConnectionHealthGraph(", source)
        self.assertIn("ConnectionHealthSummary(display)", main)
        self.assertIn("healthDialog_.UpdateSnapshot(display)", main)
        self.assertIn('const bool showingActive = selected && active_ && selected->id == active_->profileId', main)
        self.assertIn("ShowWindow(SW_HIDE)", dialog)

    def test_diagnostics_sources_tests_and_export_are_registered(self):
        compiled = {
            item.attrib["Include"].replace("\\", "/")
            for item in project("SessionDiagnosticsTests.vcxproj").findall("ms:ItemGroup/ms:ClCompile", NS)
        }
        self.assertIn("tests/session_diagnostics_tests.cpp", compiled)
        self.assertIn("src/core/SessionDiagnostics.cpp", compiled)
        solution = (ROOT / "TELIPHONES.sln").read_text()
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text()
        self.assertIn("SessionDiagnosticsTests.vcxproj", solution)
        self.assertIn("SessionDiagnosticsTests.exe", workflow)
        cmake = (ROOT / "CMakeLists.txt").read_text()
        self.assertIn("add_test(NAME session_diagnostics", cmake)
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        self.assertIn("ReadSessionEvents", main)
        self.assertIn('"ws-" +', main)
        self.assertIn('"support-" +', main)
        viewer = (ROOT / "src/app/SessionLogDlg.cpp").read_text()
        self.assertIn("CFileDialog", viewer)
        self.assertIn("contents_.data() + offset", viewer)

    def test_connection_durations_share_snapshot_without_duplicate_countdowns(self):
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        dialog = (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text()
        monitor = (ROOT / "src/core/Monitor.cpp").read_text()
        self.assertIn("healthDialog_.UpdateSnapshot(display)", main)
        self.assertIn("ConnectionHealthSummary(display)", main)
        for field in ("ConnectedDurationText", "HealthyDurationText"):
            self.assertIn(f"tlp::{field}(snapshot)", dialog)
            self.assertIn(f"tlp::{field}(snapshot_)", dialog)
        self.assertIn("tlp::AuthorizationRemainingText(snapshot)", dialog)
        self.assertNotIn("state +=", main)
        self.assertNotIn("authorization still has", main)
        self.assertNotIn("FormatRemaining", monitor)
        self.assertIn('decision.summary = "Connected";', monitor)

    def test_responsive_desktop_layout_and_native_interactions_are_registered(self):
        source = (ROOT / "src/app/DesktopLayout.cpp").read_text()
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        block = resource.split("IDD_MAIN DIALOGEX", 1)[1].split("END", 1)[0]
        self.assertIn("WS_THICKFRAME", block)
        self.assertIn("WS_MAXIMIZEBOX", block)
        for feature in ("WS_EX_CONTROLPARENT", "WM_VSCROLL", "WM_MOUSEWHEEL", "RevealFocus",
                        "SetScrollInfo", "GetSystemMetricsForDpi", "1050", "620"):
            self.assertIn(feature, source)
        self.assertIn("WM_DPICHANGED", main)
        self.assertIn("history_.find(selected->id)", main)
        native = (ROOT / "tests/health_window_tests.cpp").read_text()
        for feature in ("1024", "1366", "1920", "96, 120, 144, 192",
                        "critical actions stay inside client area", "scrolled content is keyboard reachable",
                        "wheel scroll remains bounded", "Until revoked", "Expired"):
            self.assertIn(feature, native)
        app_sources = [node.get("Include") for node in project("HealthWindowTests.vcxproj").findall("ms:ItemGroup/ms:ClCompile", NS)]
        self.assertIn("src\\app\\DesktopLayout.cpp", app_sources)

    def test_modeless_health_window_has_explicit_owner_and_native_lifecycle_tests(self):
        source = (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text()
        header = (ROOT / "src/app/ConnectionHealthDlg.h").read_text()
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        block = resource.split("IDD_CONNECTION_HEALTH DIALOGEX", 1)[1].split("END", 1)[0]
        self.assertIn("WS_EX_APPWINDOW", block)
        self.assertNotIn("WS_EX_TOOLWINDOW", block)
        self.assertIn("WS_THICKFRAME", block)
        self.assertIn("CWnd* owner_", header)
        self.assertIn("Create(IDD_CONNECTION_HEALTH, owner_)", source)
        self.assertNotIn("GetParent())", source)
        self.assertIn("if (GetSafeHwnd()) return true;", source)
        self.assertIn("EnsureVisiblePosition();", source)
        self.assertIn("ShowWindow(IsIconic() ? SW_RESTORE : SW_SHOW)", source)
        self.assertIn("MonitorFromWindow(owner_->GetSafeHwnd(), MONITOR_DEFAULTTONEAREST)", source)
        self.assertIn("tlp::FitHealthWindow(", source)
        self.assertIn("SetForegroundWindow();", source)
        self.assertNotIn("EndDialog", source)
        self.assertNotIn("PostQuitMessage", source)
        self.assertNotIn("DoModal()", source.split("bool CConnectionHealthDlg::CreateMonitor()", 1)[1].split(
            "void CConnectionHealthDlg::UpdateSnapshot", 1)[0])
        project_file = ROOT / "HealthWindowTests.vcxproj"
        ET.parse(project_file)
        native_tests = (ROOT / "tests/health_window_tests.cpp").read_text()
        for scenario in ("main window remains visible and enabled", "explicit main-window owner",
                         "repeat opening reuses one window", "close leaves main usable",
                         "reopen restores minimized window", "safe recreation after destruction",
                         "hidden monitoring update does not reopen window"):
            self.assertIn(scenario, native_tests)
        self.assertIn("HealthWindowTests.vcxproj", (ROOT / "TELIPHONES.sln").read_text())
        self.assertIn("HealthWindowTests.exe", (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text())

    def test_project_inputs_exist(self):
        for name in ("TELIPHONES.vcxproj", "TeliphonesCoreTests.vcxproj", "SessionDiagnosticsTests.vcxproj"):
            with self.subTest(project=name):
                for group in project(name).findall("ms:ItemGroup", NS):
                    for item in group:
                        include = item.get("Include")
                        if include is not None and not item.tag.endswith("ProjectConfiguration"):
                            self.assertTrue((ROOT / include.replace("\\", "/")).is_file(), include)

    def test_release_uses_native_static_runtime_and_x64(self):
        app = project("TELIPHONES.vcxproj")
        release = "'$(Configuration)|$(Platform)'=='Release|x64'"
        groups = app.findall("ms:PropertyGroup", NS)
        config = next(group for group in groups if group.get("Condition") == release)
        self.assertEqual(config.findtext("ms:UseOfMfc", namespaces=NS), "Static")
        self.assertEqual(config.findtext("ms:PlatformToolset", namespaces=NS), "v143")
        for name in ("TELIPHONES.vcxproj", "TeliphonesCoreTests.vcxproj", "SessionDiagnosticsTests.vcxproj"):
            root = project(name)
            definitions = root.findall("ms:ItemDefinitionGroup", NS)
            release_definitions = next(group for group in definitions if group.get("Condition") == release)
            self.assertEqual(release_definitions.findtext("ms:ClCompile/ms:RuntimeLibrary", namespaces=NS), "MultiThreaded")
            self.assertIn("stdcpp17", [node.text for node in root.findall(".//ms:LanguageStandard", NS)])
            self.assertIn("MachineX64", [node.text for node in root.findall(".//ms:TargetMachine", NS)])
            self.assertIn("Sync", [node.text for node in root.findall(".//ms:ExceptionHandling", NS)])
            self.assertEqual(root.findtext(".//ms:OutDir", namespaces=NS), "$(SolutionDir)build\\$(Configuration)\\")
            self.assertIsNone(root.find(".//ms:CLRSupport", NS))
        for deps in app.findall(".//ms:AdditionalDependencies", NS):
            for library in ("uuid.lib", "shell32.lib", "comdlg32.lib", "advapi32.lib", "winhttp.lib", "wintrust.lib", "crypt32.lib", "bcrypt.lib", "iphlpapi.lib"):
                self.assertIn(library, deps.text.split(";"))

    def test_application_sdk_header_order(self):
        layout = (ROOT / "src/app/DesktopLayout.cpp").read_text()
        self.assertIn("#include <stdexcept>", layout)
        self.assertIn('throw std::runtime_error("A required TELIPHONES layout control is missing.")', layout)
        self.assertNotIn("tlp::Error", layout)
        applications = (ROOT / "src/platform/Applications.cpp").read_text()
        win = (ROOT / "src/platform/Win.h").read_text()
        self.assertIn("#include <windows.h>", win)
        self.assertLess(applications.index('#include "Win.h"'), applications.index("#include <shellapi.h>"))
        settings = (ROOT / "src/app/AppSettingsDlg.cpp").read_text()
        self.assertLess(settings.index('#include "AppSettingsDlg.h"'), settings.index("#include <commdlg.h>"))
        installer = (ROOT / "src/platform/WireGuardInstaller.cpp").read_text()
        for header in ("shellapi.h", "winhttp.h", "wintrust.h"):
            self.assertLess(installer.index('#include "Win.h"'), installer.index(f"#include <{header}>"))

    def test_central_appearance_and_native_regressions_are_wired(self):
        source = (ROOT / "src/app/Appearance.cpp").read_text()
        settings = (ROOT / "src/app/AppSettingsDlg.cpp").read_text()
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        for name in ("MainDlg", "AppSettingsDlg", "PairDlg", "SupportDlg", "ConnectionHealthDlg", "SessionLogDlg"):
            header = (ROOT / f"src/app/{name}.h").read_text()
            implementation = (ROOT / f"src/app/{name}.cpp").read_text()
            self.assertIn("public CAppearanceDialog", header)
            self.assertIn("CAppearanceDialog::OnInitDialog()", implementation)
        self.assertIn("IDC_APPEARANCE", resource)
        for choice in ("System (follow Windows)", "Light", "Dark"):
            self.assertIn(f'L"{choice}"', settings)
        for required in ("ColorValuesChanged", "PostMessageW(target", "SPI_GETHIGHCONTRAST",
                         "WM_SETTINGCHANGE", "WM_SYSCOLORCHANGE", "WM_THEMECHANGED",
                         "DrawComboItem", "PaintScrollbars", "WM_NCDESTROY",
                         "const bool visible = IsWindowVisible(root)"):
            self.assertIn(required, source)
        for private_api in ("AllowDarkModeForWindow", "SetPreferredAppMode", "DarkMode_Explorer", "MAKEINTRESOURCEA"):
            self.assertNotIn(private_api, source)
        self.assertNotIn("RGB(", (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text())
        self.assertIn("tlp::ui::Colours()", (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text())
        for name in ("TELIPHONES.vcxproj", "HealthWindowTests.vcxproj"):
            native = project(name)
            self.assertIn("src\\app\\Appearance.cpp", [node.get("Include") for node in native.findall(".//ms:ClCompile", NS)])
            for dependencies in native.findall(".//ms:AdditionalDependencies", NS):
                for library in ("uxtheme.lib", "dwmapi.lib", "windowsapp.lib"):
                    self.assertIn(library, dependencies.text.split(";"))
        app = (ROOT / "TELIPHONES.vcxproj").read_text()
        self.assertNotIn("TELIPHONES_APPEARANCE_TESTING", app)
        self.assertIn("TELIPHONES_APPEARANCE_TESTING", (ROOT / "HealthWindowTests.vcxproj").read_text())
        tests = (ROOT / "tests/health_window_tests.cpp").read_text()
        for scenario in ("SimulateSystemAppearance", "GraphAppearanceTests",
                         "theme switch never reopens hidden windows", "every currently open application dialog follows theme",
                         "96, 120, 144, 192", "WM_CTLCOLORDLG"):
            self.assertIn(scenario, tests)
        workflow = (ROOT.parents[1] / ".github/workflows/windows-build.yml").read_text()
        self.assertIn("cppwinrt\\winrt\\Windows.UI.ViewManagement.h", workflow)
        self.assertIn("cppwinrt\\winrt\\Windows.UI.h", workflow)
        self.assertIn("cppwinrt\\winrt\\Windows.Foundation.h", workflow)

    def test_appearance_review_regressions_are_registered(self):
        source = (ROOT / "src/app/Appearance.cpp").read_text()
        tests = (ROOT / "tests/health_window_tests.cpp").read_text()
        for header in ("winrt/Windows.UI.h", "winrt/Windows.Foundation.h", "cwctype", "utility"):
            self.assertIn(f"#include <{header}>", source)
        for case in ("owner-drawn menu supports unique keyboard mnemonic",
                     "duplicate menu mnemonics cycle to next match",
                     "menu mnemonics skip disabled items and escaped ampersands",
                     "high contrast updates both dropdown item and selection heights after font changes",
                     "long PBX name never paints into the adjacent column"):
            self.assertIn(case, tests)
        self.assertIn("WM_MENUCHAR", source)
        self.assertIn("WM_DPICHANGED_AFTERPARENT", source)
        self.assertIn("Header_GetItemRect(header, column, &cell)", source)
        self.assertNotIn("ListView_GetSubItemRect", source)
        self.assertIn("CB_SETITEMHEIGHT, static_cast<WPARAM>(-1)", source)
        self.assertLess(source.index("message == WM_SETFONT"), source.index("if (manager.highContrast_)"))
        health = (ROOT / "src/app/ConnectionHealthDlg.cpp").read_text()
        self.assertIn("Download: solid / Upload: dashed", health)
        self.assertIn("Latency: line / Jitter: dots", health)

    def test_captioned_windows_keep_native_frame_theming(self):
        source = (ROOT / "src/app/Appearance.cpp").read_text()
        self.assertIn("const bool nativeFrame = (style & WS_CAPTION) == WS_CAPTION;", source)
        self.assertIn("const bool nativeTheme = highContrast_ || nativeFrame;", source)
        self.assertIn('SetWindowTheme(window, nativeTheme ? nullptr : L"", nativeTheme ? nullptr : L"");', source)
        self.assertIn("DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE", source)

    def test_combo_selection_uses_shared_bounded_renderer(self):
        source = (ROOT / "src/app/Appearance.cpp").read_text()
        self.assertIn("selection.rcItem = info.rcItem;", source)
        self.assertIn("DrawComboItem(WM_DRAWITEM, reinterpret_cast<LPARAM>(&selection));", source)
        self.assertIn("const bool selected = !closedField", source)
        self.assertIn("&& !hideFocus", source)
        self.assertNotIn("DrawFocusRect(dc, &label)", source)
        tests = (ROOT / "tests/health_window_tests.cpp").read_text()
        self.assertIn("closed combo owner-draw preserves surface and respects hidden focus cues", tests)

    def test_installer_is_fixed_verified_and_does_not_change_profiles(self):
        source = (ROOT / "src/platform/WireGuardInstaller.cpp").read_text()
        for required in (
            'L"download.wireguard.com"', 'L"/windows-client/wireguard-amd64-1.1.1.msi"',
            "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242",
            'L"WireGuard LLC"', "WINHTTP_FLAG_SECURE", "WINHTTP_OPTION_REDIRECT_POLICY_NEVER",
            "WTD_REVOKE_WHOLECHAIN", "WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT", "WINTRUST_ACTION_GENERIC_VERIFY_V2",
            "FILE_SHARE_READ", "CREATE_NEW", 'L"runas"', '"/norestart"', '"DO_NOT_LAUNCH=1"',
            "GetNativeSystemInfo", "PROCESSOR_ARCHITECTURE_AMD64", "CoInitializeEx",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SECURITY_FLAG_IGNORE", "WINHTTP_OPTION_SECURITY_FLAGS", "SaveProfiles(", "SavePreferences(",
            "RemoveTunnel(", "InstallTunnel(", "TerminateProcess(", "system(",
        ):
            self.assertNotIn(forbidden, source)
        main = (ROOT / "src/app/MainDlg.cpp").read_text()
        self.assertIn("RefreshWireGuard();", main)
        self.assertIn("if (saved) storedPreferences_ = dialog.preferences;", main)
        settings_return = main[main.index("bool CMainDlg::ShowAppSettings("):main.index("void CMainDlg::OnSettings()")]
        self.assertLess(settings_return.index("dialog.DoModal()"), settings_return.index("RefreshWireGuard();"))
        refresh = main[main.index("void CMainDlg::RefreshWireGuard()"):main.index("void CMainDlg::RemoveStaleTunnels()")]
        self.assertIn("UpdateButtons();", refresh)
        self.assertIn("bool usable = wireguard_.installed && wireguard_.trusted;", main)
        dialog = (ROOT / "src/app/AppSettingsDlg.cpp").read_text()
        self.assertIn("void CAppSettingsDlg::OnInstallWireGuard()", dialog)
        self.assertNotIn("InstallWireGuard(", dialog[:dialog.index("void CAppSettingsDlg::OnInstallWireGuard()")])
        for heading in ("Step 1: Applications", "Step 2: Secure connectivity", "Step 3: Get started"):
            self.assertIn(heading, dialog)

    def test_resources_and_manifest_are_wired_once(self):
        resource_dir = ROOT / "src" / "app"
        header = (resource_dir / "resource.h").read_text()
        declared = set(re.findall(r"^#define\s+(ID[CD]_[A-Z0-9_]+)\s+", header, re.MULTILINE))
        used = set()
        for path in resource_dir.iterdir():
            if path.suffix in (".cpp", ".h", ".rc"):
                used.update(re.findall(r"\bID[CD]_[A-Z0-9_]+\b", path.read_text()))
        self.assertEqual(used - declared - {"IDC_ARROW"}, set())
        rc = (resource_dir / "TELIPHONES.rc").read_text()
        for name in ("IDD_MAIN", "IDD_PAIR", "IDD_SUPPORT", "IDD_APP_SETTINGS", "IDD_CONNECTION_HEALTH", "IDD_HEALTH_LIMITS", "IDD_SESSION_LOG"):
            self.assertRegex(rc, rf"\b{name}\s+DIALOGEX\b")
        for name in ("IDC_CONNECTION_HEALTH", "IDC_HEALTH_GRAPH", "IDC_HEALTH_HISTORY", "IDC_HEALTH_TOPMOST",
                     "IDC_HEALTH_THRESHOLDS", "IDC_HEALTH_LIMIT_LATENCY", "IDC_HEALTH_LIMIT_JITTER", "IDC_HEALTH_LIMIT_FAILURES"):
            self.assertIn(name, header)
        health_source = (resource_dir / "ConnectionHealthDlg.cpp").read_text()
        main_source = (resource_dir / "MainDlg.cpp").read_text()
        self.assertIn("ON_WM_DRAWITEM()", health_source)
        self.assertIn("SetWindowPos(preferences_.alwaysOnTop", health_source)
        self.assertIn("tlp::win::SaveHealthPreferences(preferences)", main_source)
        self.assertIn("std::thread([window, generation", main_source)
        self.assertIn("MeasureTcpProbe(address, 443, 1200)", main_source)
        self.assertIn("ReadWireGuardCounters(wgExecutable, tunnelName, peerPublicKey)", main_source)
        self.assertIn("The Connection Health monitor will keep checking; existing terminal windows are not closed.", main_source)
        self.assertIn("probes are not packet loss", health_source)
        self.assertIn("congestion not measured", health_source)
        self.assertNotIn("RT_MANIFEST", rc)
        app = project("TELIPHONES.vcxproj")
        manifests = app.findall(".//ms:AdditionalManifestFiles", NS)
        self.assertEqual(len(manifests), 1)
        self.assertIn("src\\app\\TELIPHONES.manifest", manifests[0].text)
        manifest = ET.parse(resource_dir / "TELIPHONES.manifest")
        privileges = manifest.find(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel")
        self.assertEqual(privileges.get("level"), "asInvoker")
        self.assertEqual(privileges.get("uiAccess"), "false")

    def test_manifest_identities_match_x64_and_preserve_visual_styles(self):
        ns = {"asm": "urn:schemas-microsoft-com:asm.v1"}
        manifest = ET.parse(ROOT / "src/app/TELIPHONES.manifest").getroot()
        identity = manifest.find("asm:assemblyIdentity", ns)
        self.assertEqual(identity.get("processorArchitecture"), "amd64")
        self.assertEqual(identity.get("type"), "win32")
        controls = manifest.findall("asm:dependency/asm:dependentAssembly/asm:assemblyIdentity", ns)
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0].attrib, {
            "type": "win32",
            "name": "Microsoft.Windows.Common-Controls",
            "version": "6.0.0.0",
            "processorArchitecture": "amd64",
            "publicKeyToken": "6595b64144ccf1df",
            "language": "*",
        })
        dpi = manifest.find(".//{http://schemas.microsoft.com/SMI/2016/WindowsSettings}dpiAwareness")
        self.assertEqual(dpi.text, "PerMonitorV2")

    def test_custom_manifest_is_the_only_dpi_configuration_source(self):
        app = project("TELIPHONES.vcxproj")
        settings = app.findall(".//ms:Manifest/ms:EnableDpiAwareness", NS)
        self.assertEqual(len(settings), 1)
        self.assertEqual(settings[0].text, "false")
        manifest = ET.parse(ROOT / "src/app/TELIPHONES.manifest").getroot()
        for name, namespace, value in (
            ("dpiAware", "http://schemas.microsoft.com/SMI/2005/WindowsSettings", "true/pm"),
            ("dpiAwareness", "http://schemas.microsoft.com/SMI/2016/WindowsSettings", "PerMonitorV2"),
        ):
            with self.subTest(declaration=name):
                declarations = [
                    node for node in manifest.iter()
                    if node.tag.rsplit("}", 1)[-1] == name
                ]
                self.assertEqual(len(declarations), 1)
                self.assertEqual(declarations[0].tag, f"{{{namespace}}}{name}")
                self.assertEqual(declarations[0].text, value)


if __name__ == "__main__":
    unittest.main()
