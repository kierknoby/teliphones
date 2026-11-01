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
    def test_application_compiles_every_native_source(self):
        app = project("TELIPHONES.vcxproj")
        compiled = {
            item.attrib["Include"].replace("\\", "/")
            for item in app.findall("ms:ItemGroup/ms:ClCompile", NS)
        }
        expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.cpp")}
        self.assertEqual(compiled, expected)

    def test_project_inputs_exist(self):
        for name in ("TELIPHONES.vcxproj", "TeliphonesCoreTests.vcxproj"):
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
        for name in ("TELIPHONES.vcxproj", "TeliphonesCoreTests.vcxproj"):
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
            self.assertIn("uuid.lib", deps.text.split(";"))

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
        for name in ("IDD_MAIN", "IDD_PAIR", "IDD_SUPPORT"):
            self.assertRegex(rc, rf"\b{name}\s+DIALOGEX\b")
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
