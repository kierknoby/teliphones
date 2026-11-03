"""Validate the current module-only Module Admin package against source."""

from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "teliphones"
VERSION = ET.parse(MODULE / "module.xml").findtext("version")
PACKAGE = ROOT / ("TELIPHONES-%s.tgz" % VERSION)


def included(path):
    parts = path.relative_to(MODULE).parts
    return not any(part.startswith(".") or part in ("tests", "__pycache__") for part in parts) and path.suffix not in (".pyc", ".pyo")


class PackageTests(unittest.TestCase):
    def test_archive_extracts_and_matches_module_source(self):
        expected = {
            "teliphones/" + path.relative_to(MODULE).as_posix(): path
            for path in MODULE.rglob("*") if path.is_file() and included(path)
        }
        with tarfile.open(PACKAGE, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(len({member.name for member in members}), len(members), "Duplicate archive paths")
            for member in members:
                path = PurePosixPath(member.name)
                self.assertFalse(path.is_absolute() or ".." in path.parts)
                self.assertEqual(path.parts[0], "teliphones")
                self.assertTrue(member.isdir() or member.isfile(), "Links/special files must not be packaged")
                self.assertEqual(member.mode & 0o022, 0, "Package must not be group/other writable")
            self.assertEqual({member.name for member in members if member.isfile()}, set(expected))
            with tempfile.TemporaryDirectory() as directory:
                archive.extractall(directory, filter="data")
                for name, source in expected.items():
                    self.assertEqual((Path(directory) / name).read_bytes(), source.read_bytes(), name)
                metadata = ET.parse(Path(directory) / "teliphones/module.xml").getroot()
                self.assertEqual(metadata.findtext("version"), "0.4.0")
                self.assertEqual(metadata.findtext("rawname"), "teliphones")
                self.assertEqual(metadata.findtext("category"), "Connectivity")
                for name in ("WebSupport.php", "views/support.php", "views/disclaimer.php", "support_broker.py", "ssh_authority.py", "assets/js/teliphones.js", "install.php"):
                    self.assertIn("teliphones/" + name, expected)
                self.assertIn("def pair(", (Path(directory) / "teliphones/support_broker.py").read_text())
                self.assertIn("Windows workstations", (Path(directory) / "teliphones/views/support.php").read_text())
                broker = (Path(directory) / "teliphones/support_broker.py").read_text()
                for feature in ("TELIPHONES workstation enforcement v1", 'WORKSTATION_OWNER_CHAIN = "teliphones_owner_v1"',
                                "def start_monitor(", "def uninstall_workstations(", "def policy_equal(",
                                "TELIPHONES workstation integration v1", 'FREEPBX_HOOK = "fpbxfirewall"',
                                'FAIL2BAN_PREFIXES = ("fail2ban-", "f2b-")', "def reconcile_integration(",
                                "class DiagnosticLog", "PROTOCOL = 5"):
                    self.assertIn(feature, broker)
                bootstrap = (Path(directory) / "teliphones/BrokerBootstrap.php").read_text()
                self.assertIn("copy($moduleDir . '/support_broker.py', $brokerFile)", bootstrap)
                self.assertIn("'restart teliphones-broker.service'", bootstrap)
                self.assertIn("Previous broker files restored", bootstrap)
                self.assertIn("BrokerBootstrap::", (Path(directory) / "teliphones/uninstall.php").read_text())


if __name__ == "__main__":
    unittest.main()
