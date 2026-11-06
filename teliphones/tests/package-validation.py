"""Validate the current module-only Module Admin package against source."""

from pathlib import Path, PurePosixPath
import ast
import hashlib
import runpy
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "teliphones"
VERSION = ET.parse(MODULE / "module.xml").findtext("version")
PACKAGE = ROOT / ("TELIPHONES-%s.tgz" % VERSION)


def included(path):
    parts = path.relative_to(MODULE).parts
    return not any(part.startswith(".") or part in ("tests", "__pycache__") for part in parts) and path.suffix not in (".pyc", ".pyo")


class SourceVersionTests(unittest.TestCase):
    def test_authoritative_versions(self):
        self.assertEqual(VERSION, "0.6.5")
        tree = ast.parse((MODULE / "support_broker.py").read_text())
        versions = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets)]
        self.assertEqual(versions, ["0.6.5"], "The broker patch version identifies the revocation security corrections")
        self.assertIn("BROKER_VERSION = '%s';" % versions[0], (MODULE / "WebSupport.php").read_text())
        self.assertIn("TELIPHONES 0.6.5 requires broker version 0.6.5, broker protocol 12",
                      (MODULE / "BrokerBootstrap.php").read_text())
        self.assertIn("## 0.6.5, durable workstation revocation", (MODULE / "docs/CHANGELOG.md").read_text())
        self.assertIn("durable workstation revocation", (MODULE / "BrokerBootstrap.php").read_text())


class PackageTests(unittest.TestCase):
    def test_archive_checksum(self):
        self.assertTrue(PACKAGE.exists(), "Build the current installation archive before package validation")
        digest = hashlib.sha256(PACKAGE.read_bytes()).hexdigest()
        self.assertEqual(Path(str(PACKAGE) + ".sha256").read_text(), "%s  %s\n" % (digest, PACKAGE.name))

    @unittest.skipUnless((ROOT / "TELIPHONES-0.4.0.tgz").exists(),
                         "The historical 0.4.0 archive is not present in the repository")
    def test_previous_0_4_0_package_remains_identifiable_and_unchanged(self):
        previous = ROOT / "TELIPHONES-0.4.0.tgz"
        self.assertEqual(hashlib.sha256(previous.read_bytes()).hexdigest(),
                         "f67dfaaf4cd78564c1599efe2e227580c751a1a40f59c9e4a6c3f08f418af670")
        with tarfile.open(previous, "r:gz") as archive:
            self.assertEqual(ET.fromstring(archive.extractfile("teliphones/module.xml").read()).findtext("version"),
                             "0.4.0")
            source = archive.extractfile("teliphones/support_broker.py").read().decode()
            self.assertIn('VERSION = "0.4.0"', source)
            self.assertIn('self.ipt(iptables, "-I", "INPUT",', source)

    @unittest.skipUnless((ROOT / "TELIPHONES-0.4.1.tgz").exists(),
                         "The historical 0.4.1 archive is not present in the repository")
    def test_previous_0_4_1_package_remains_identifiable_and_unchanged(self):
        previous = ROOT / "TELIPHONES-0.4.1.tgz"
        self.assertEqual(hashlib.sha256(previous.read_bytes()).hexdigest(),
                         "d4b867af617b05c4b306137e4db31e8c2708acc1751295ad9b6f928eaff20800")
        with tarfile.open(previous, "r:gz") as archive:
            self.assertEqual(ET.fromstring(archive.extractfile("teliphones/module.xml").read()).findtext("version"),
                             "0.4.1")
            source = archive.extractfile("teliphones/support_broker.py").read().decode()
            self.assertIn('VERSION = "0.4.1"', source)
            # 0.4.1 corrected the jump placement but still lacked the WireGuard listener permit.
            self.assertIn('self.ipt(iptables, "-I", FREEPBX_HOOK, "1"', source)
            self.assertNotIn("def integration_jumps(", source)

    @unittest.skipUnless((ROOT / "TELIPHONES-0.6.0.tgz").exists(),
                         "The historical 0.6.0 archive is not present in the repository")
    def test_previous_0_6_0_package_and_broker_remain_unchanged(self):
        previous = ROOT / "TELIPHONES-0.6.0.tgz"
        digest = hashlib.sha256(previous.read_bytes()).hexdigest()
        self.assertEqual(digest, "11b69c0f78b8152279bc2a035107536331ae4bfce62627d8a448e6c232fcf0e9")
        self.assertEqual(Path(str(previous) + ".sha256").read_text(), "%s  %s\n" % (digest, previous.name))
        with tarfile.open(previous, "r:gz") as archive:
            metadata = ET.fromstring(archive.extractfile("teliphones/module.xml").read())
            self.assertEqual(metadata.findtext("version"), "0.6.0")
            broker = archive.extractfile("teliphones/support_broker.py").read().decode()
            self.assertIn('VERSION = "0.6.0"', broker)
            self.assertIn("PROTOCOL = 12", broker)

    @unittest.skipUnless((ROOT / "TELIPHONES-0.6.1.tgz").exists(),
                         "The previous 0.6.1 archive is not present in the repository")
    def test_previous_0_6_1_package_remains_unchanged(self):
        previous = ROOT / "TELIPHONES-0.6.1.tgz"
        digest = hashlib.sha256(previous.read_bytes()).hexdigest()
        self.assertEqual(digest, "1dfcd18318f6efc73615df19cfc3a03728ec904a4c7f35197873b382722f7d7a")
        self.assertEqual(Path(str(previous) + ".sha256").read_text(), "%s  %s\n" % (digest, previous.name))
        with tarfile.open(previous, "r:gz") as archive:
            metadata = ET.fromstring(archive.extractfile("teliphones/module.xml").read())
            self.assertEqual(metadata.findtext("version"), "0.6.1")
            broker = archive.extractfile("teliphones/support_broker.py").read().decode()
            self.assertIn('VERSION = "0.6.0"', broker)
            self.assertIn("PROTOCOL = 12", broker)

    @unittest.skipUnless((ROOT / "TELIPHONES-0.6.2.tgz").exists(),
                         "The previous 0.6.2 archive is not present in the repository")
    def test_previous_0_6_2_package_remains_unchanged(self):
        previous = ROOT / "TELIPHONES-0.6.2.tgz"
        digest = hashlib.sha256(previous.read_bytes()).hexdigest()
        self.assertEqual(digest, "5b1ef90abc1c02f08f5fed7222f16be2709dd4c98bf15d2d3716bcbf8c2ee53e")
        self.assertEqual(Path(str(previous) + ".sha256").read_text(), "%s  %s\n" % (digest, previous.name))
        with tarfile.open(previous, "r:gz") as archive:
            self.assertEqual(ET.fromstring(archive.extractfile("teliphones/module.xml").read()).findtext("version"),
                             "0.6.2")
            source = archive.extractfile("teliphones/support_broker.py").read().decode()
            self.assertIn('VERSION = "0.6.1"', source)
            self.assertIn("PROTOCOL = 12", source)

    @unittest.skipUnless((ROOT / "TELIPHONES-0.6.3.tgz").exists(),
                         "The historical 0.6.3 archive is not present in the repository")
    def test_previous_0_6_3_package_remains_unchanged(self):
        previous = ROOT / "TELIPHONES-0.6.3.tgz"
        digest = hashlib.sha256(previous.read_bytes()).hexdigest()
        self.assertEqual(digest, "46c851197ae5e3bd70a48fb90a18bb39918d4f7774c0a8c76b6fcd4f8c4abf27")
        self.assertEqual(Path(str(previous) + ".sha256").read_text(), "%s  %s\n" % (digest, previous.name))
        with tarfile.open(previous, "r:gz") as archive:
            self.assertEqual(ET.fromstring(archive.extractfile("teliphones/module.xml").read()).findtext("version"),
                             "0.6.3")
            self.assertIn('VERSION = "0.6.2"', archive.extractfile("teliphones/support_broker.py").read().decode())

    def test_packaged_firewall_migrates_legacy_input_and_survives_rebuild(self):
        self.assertTrue(PACKAGE.exists(), "Build the current installation archive before package validation")
        sys.path.insert(0, str(ROOT / "gateway/tests"))
        try:
            from test_support_broker import FakeNetwork, FREEPBX17_FAIL2BAN, fail2ban_hook
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as directory, tarfile.open(PACKAGE, "r:gz") as archive:
            archive.extractall(directory, filter="data")
            namespace = runpy.run_path(str(Path(directory) / "teliphones/support_broker.py"))
            instance = namespace["Broker"]()
            network = FakeNetwork().freepbx()
            instance.run = network.run
            instance.iptables_tool = lambda: "iptables"
            state = {"subnet": "100.70.1.0/24", "listen_port": 51821, "workstations": [
                {"address": "100.70.1.2/32", "ssh": True, "ssh_public_key": "fixture"}]}
            chain = namespace["INTEGRATION_CHAIN"]
            jumps = [namespace["iptables_arguments"](namespace["INTEGRATION_JUMP"])]
            baseline = [fail2ban_hook(name) for name in FREEPBX17_FAIL2BAN] + [["-j", "fpbxfirewall"]]
            network.filter[chain] = []
            # Model a legacy 0.4.0 intrusive INPUT jump awaiting migration.
            network.filter["INPUT"].insert(len(FREEPBX17_FAIL2BAN), jumps[0][:])
            for _ in range(2):
                instance.firewall_integration(state)
                self.assertEqual(network.filter["INPUT"], baseline)
                self.assertEqual(network.filter["fpbxfirewall"][:1], jumps)
                for jump in jumps:
                    self.assertEqual(network.filter["fpbxfirewall"].count(jump), 1)
                rules = [namespace["iptables_rule"](rule) for rule in network.filter[chain]]
                self.assertEqual({rule["dport"] for rule in rules if rule["j"] == "ACCEPT" and rule.get("p") == "tcp"},
                                 {"80", "443", "8765", "8766", "22002"})
                self.assertEqual([rule["dport"] for rule in rules if rule["j"] == "ACCEPT" and rule.get("p") == "udp"],
                                 [])
                stable = network.filter.copy()
                with patch.object(instance, "ipt", wraps=instance.ipt) as ipt:
                    instance.firewall_integration(state)
                    self.assertTrue(all(call.args[1] == "-S" for call in ipt.call_args_list))
                self.assertEqual(network.filter, stable)
                network.freepbx()
            instance.remove_integration()
            self.assertEqual(network.filter["INPUT"], baseline)
            self.assertNotIn(chain, network.filter)

    def test_archive_extracts_and_matches_module_source(self):
        self.assertTrue(PACKAGE.exists(), "Build the current installation archive before package validation")
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
                self.assertEqual(metadata.findtext("version"), VERSION)
                self.assertEqual(metadata.findtext("rawname"), "teliphones")
                self.assertEqual(metadata.findtext("category"), "Connectivity")
                self.assertEqual(metadata.findtext("depends/version"), "17.0.1")
                self.assertEqual(metadata.findtext("supported/version"), "17.0")
                for name in ("WebSupport.php", "views/support.php", "views/disclaimer.php", "support_broker.py", "ssh_authority.py", "assets/js/teliphones.js", "install.php"):
                    self.assertIn("teliphones/" + name, expected)
                self.assertIn("def pair(", (Path(directory) / "teliphones/support_broker.py").read_text())
                self.assertIn("Windows Workstation Access", (Path(directory) / "teliphones/views/support.php").read_text())
                broker = (Path(directory) / "teliphones/support_broker.py").read_text()
                for feature in ("TELIPHONES workstation enforcement v1", 'WORKSTATION_OWNER_CHAIN = "teliphones_owner_v1"',
                                "def start_monitor(", "def uninstall_workstations(", "def policy_equal(",
                                "TELIPHONES workstation integration v1", 'FREEPBX_HOOK = "fpbxfirewall"',
                                'FAIL2BAN_PREFIXES = ("fail2ban-", "f2b-")', "def reconcile_integration(",
                                "class DiagnosticLog", "PROTOCOL = 12", "def reconcile_listener(", "def parse_web(",
                                "workstation-revocations.json", "def reconcile_revocations(",
                                "def revocation_status(", "revocation_persistence_failed"):
                    self.assertIn(feature, broker)
                self.assertIn('VERSION = "0.6.5"', broker)
                for feature in ("def listener_failure_output(", "listener_operation", "Initiating failure:",
                                "listener_failure_output(result.stderr)", "def listener_rules_current(",
                                "background_listener_check", "workstation_retry_at",
                                "min(60, max(5, self.workstation_retry_delay * 2))"):
                    self.assertIn(feature, broker)
                listener = (Path(directory) / "teliphones/FirewallListener.php").read_text()
                for feature in ("function rulesMismatch(", "UDP ACCEPT missing", " jump missing",
                                "service rules remain", "($port === 0 ? 'removal'"):
                    self.assertIn(feature, listener)
                form = (Path(directory) / "teliphones/views/support.php").read_text()
                self.assertIn('name="ssh" value="0"', form)
                self.assertIn('id="teliphones-pair-web-only"', form)
                for feature in ("def socket_response(", "def handle_connection(", 'done.wait(1)',
                                '"progress": progress["stage"]', "except subprocess.TimeoutExpired"):
                    self.assertIn(feature, broker)
                web = (Path(directory) / "teliphones/WebSupport.php").read_text()
                self.assertIn("stream_set_timeout($socket, 5)", web)
                self.assertIn("$streaming = in_array($request['action'] ?? null, ['pair', 'unpair'], true);", web)
                self.assertIn("if ($streaming) $request['progress'] = true;", web)
                bootstrap = (Path(directory) / "teliphones/BrokerBootstrap.php").read_text()
                self.assertIn("copy($moduleDir . '/support_broker.py', $brokerFile)", bootstrap)
                self.assertIn("'restart teliphones-broker.service'", bootstrap)
                self.assertIn("Previous broker files restored", bootstrap)
                self.assertIn("BrokerBootstrap::", (Path(directory) / "teliphones/uninstall.php").read_text())


if __name__ == "__main__":
    unittest.main()
