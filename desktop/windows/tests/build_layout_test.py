"""Check native build inputs without requiring Visual Studio or third-party packages."""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
NS = {"ms": "http://schemas.microsoft.com/developer/msbuild/2003"}


def project(name):
    return ET.parse(ROOT / name).getroot()


class BuildLayoutTests(unittest.TestCase):
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
        self.assertEqual(product, "0.5.1")
        self.assertEqual(numeric, "0.5.1.0")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"# TELIPHONES {product} for Windows", readme)
        self.assertIn(f"**{numeric}**", readme)
        self.assertIn(f"Windows **{product}**", (ROOT.parents[1] / "README.md").read_text(encoding="utf-8"))
        self.assertIn(f"## {product} — Unreleased", changelog)
        self.assertEqual(re.findall(r"^## (\d+\.\d+\.\d+) ", changelog, re.MULTILINE)[0], product)
        self.assertIn(f"**{numeric}**", changelog)
        self.assertIn("0.6.0 is reserved for the upcoming fully automated SSH authentication functionality", readme)
        self.assertIn(
            "0.6.0 is reserved for the upcoming fully automated SSH authentication functionality",
            " ".join(changelog.split()),
        )
        self.assertIn("FreePBX module version is independent and remains **0.3.2**", changelog)
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

    def test_application_compiles_every_native_source(self):
        app = project("TELIPHONES.vcxproj")
        compiled = {
            item.attrib["Include"].replace("\\", "/")
            for item in app.findall("ms:ItemGroup/ms:ClCompile", NS)
        }
        expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.cpp")}
        self.assertEqual(compiled, expected)
        project_headers = {
            item.attrib["Include"].replace("\\", "/")
            for item in app.findall("ms:ItemGroup/ms:ClInclude", NS)
        }
        self.assertIn("src/app/ConnectionHealthDlg.h", project_headers)
        self.assertIn("src/core/ConnectionHealth.h", project_headers)
        self.assertIn("src/app/ConnectionHealthDlg.cpp", compiled)
        self.assertIn("src/core/ConnectionHealth.cpp", compiled)

    def test_connection_health_popout_and_integrated_panel_are_wired(self):
        resource = (ROOT / "src/app/TELIPHONES.rc").read_text()
        self.assertRegex(resource, r"IDD_CONNECTION_HEALTH DIALOGEX 0, 0, 490, 350")
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
        self.assertIn("ConnectionHealthSummary(healthSnapshot_)", main)
        self.assertIn("healthDialog_.UpdateSnapshot(healthSnapshot_)", main)
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
        self.assertIn("healthDialog_.UpdateSnapshot(healthSnapshot_)", main)
        self.assertIn("ConnectionHealthSummary(healthSnapshot_)", main)
        for field in ("ConnectedDurationText", "HealthyDurationText"):
            self.assertIn(f"tlp::{field}(snapshot)", dialog)
            self.assertIn(f"tlp::{field}(snapshot_)", dialog)
        self.assertIn("tlp::AuthorizationRemainingText(snapshot)", dialog)
        self.assertNotIn("state +=", main)
        self.assertNotIn("authorization still has", main)
        self.assertNotIn("FormatRemaining", monitor)
        self.assertIn('decision.summary = "Connected";', monitor)

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
        applications = (ROOT / "src/platform/Applications.cpp").read_text()
        win = (ROOT / "src/platform/Win.h").read_text()
        self.assertIn("#include <windows.h>", win)
        self.assertLess(applications.index('#include "Win.h"'), applications.index("#include <shellapi.h>"))
        settings = (ROOT / "src/app/AppSettingsDlg.cpp").read_text()
        self.assertLess(settings.index('#include "AppSettingsDlg.h"'), settings.index("#include <commdlg.h>"))
        installer = (ROOT / "src/platform/WireGuardInstaller.cpp").read_text()
        for header in ("shellapi.h", "winhttp.h", "wintrust.h"):
            self.assertLess(installer.index('#include "Win.h"'), installer.index(f"#include <{header}>"))

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
        self.assertEqual(used - declared, set())
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
