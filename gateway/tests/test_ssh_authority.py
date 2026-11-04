import base64
import importlib.util
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("ssh_authority_unit", Path(__file__).resolve().parents[2] / "teliphones/ssh_authority.py")
ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh)
PUBLIC = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
EPHEMERAL = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(reversed(range(32)))).decode()
OTHER_EPHEMERAL = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes([1] * 32)).decode()


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.item = {"id": "0123456789abcdef", "ssh": True, "ssh_user": "root", "ssh_public_key": PUBLIC,
                     "address": "100.70.1.2/32", "expires_at": int(time.time()) + 60}
        self.state = {"subnet": "100.70.1.0/24", "workstations": [self.item]}
        self.authority = ssh.Authority(Path(self.temporary.name) / "authority",
                                       lambda: (self.state, False), threading.RLock(), lambda *args, **kwargs: None)

    def test_strict_keys_and_unit_identity(self):
        self.assertEqual(ssh.public_key(PUBLIC), PUBLIC)
        for value in (PUBLIC + " comment", "ssh-ed25519 AAAA", "ssh-rsa AAAA", [], None):
            with self.assertRaises(ssh.SshError):
                ssh.public_key(value)
        for value in ("all", "../sshd", "sshd.service", "0" * 17):
            with self.assertRaises(ssh.SshError):
                self.authority.unit(value)
        self.assertNotEqual(self.authority.principal(self.item),
                            self.authority.principal({**self.item, "ssh_public_key": PUBLIC[:-4] + "AQEB"}))

    def test_locked_ssh_interface_is_derived_from_pairing_identity(self):
        interface = self.authority.item_interface({**self.item, "locked": True})
        self.assertEqual(interface, "tlpw" + ssh.hashlib.sha256(self.item["id"].encode()).hexdigest()[:11])
        with self.assertRaisesRegex(ssh.SshError, "does not match"):
            self.authority.item_interface({**self.item, "locked": True, "interface": "tlp-admin"})

    def test_authorisation_requires_ssh_identity_source_and_deadline(self):
        for identity, source in ((self.item["id"], "10.0.0.2"), ("f" * 16, "100.70.1.2")):
            with self.assertRaises(ssh.SshError):
                self.authority.challenge(identity, source)
        self.item["ssh"] = False
        with self.assertRaises(ssh.SshError):
            self.authority.challenge(self.item["id"], "100.70.1.2")
        self.item["ssh"] = True
        self.item["expires_at"] = int(time.time()) - 1
        with self.assertRaises(ssh.SshError):
            self.authority.challenge(self.item["id"], "100.70.1.2")

    def test_account_policy_preserves_existing_restrictions_and_explicit_root(self):
        baseline = {"pubkeyauthentication": "yes", "authenticationmethods": "publickey", "usedns": "no",
                    "permitrootlogin": "no", "permittty": "yes", "usepam": "yes",
                    "pubkeyacceptedalgorithms": "ssh-ed25519-cert-v01@openssh.com",
                    "casignaturealgorithms": "ssh-ed25519"}
        account = types.SimpleNamespace(pw_uid=20001, pw_shell="/bin/sh")
        self.item["ssh_user"] = "tlptest"

        def output(changes=None):
            return "\n".join(name + " " + value for name, value in {**baseline, **(changes or {})}.items())

        with patch.object(ssh.pwd, "getpwnam", return_value=account), patch.object(ssh.os, "access", return_value=True):
            with patch.object(ssh, "run", return_value=output()):
                self.assertEqual(self.authority.account_policy(self.item, "100.70.1.1")["permitrootlogin"], "no")
            for name, value in (("authenticationmethods", "publickey,password"), ("forcecommand", "/bin/false"),
                                ("allowusers", "other"), ("denygroups", "restricted"), ("usedns", "yes"),
                                ("chrootdirectory", "/restricted"), ("permittty", "no"),
                                ("authorizedkeyscommand", "/usr/bin/false"),
                                ("authorizedprincipalsfile", "/etc/ssh/restricted_principals"),
                                ("pamservicename", "custom"), ("usepam", "unsupported"),
                                ("pubkeyacceptedalgorithms", "ssh-rsa"), ("casignaturealgorithms", "rsa-sha2-512")):
                with self.subTest(directive=name), patch.object(ssh, "run", return_value=output({name: value})):
                    with self.assertRaises(ssh.SshError):
                        self.authority.account_policy(self.item, "100.70.1.1")
            account.pw_uid = 0
            with self.assertRaisesRegex(ssh.SshError, "UID-zero aliases"):
                self.authority.account_policy(self.item, "100.70.1.1")
            self.item["ssh_user"] = "root"
            with patch.object(ssh, "run", return_value=output()):
                with self.assertRaisesRegex(ssh.SshError, "root public-key login"):
                    self.authority.account_policy(self.item, "100.70.1.1")
            with patch.object(ssh, "run", return_value=output({"permitrootlogin": "prohibit-password"})):
                self.assertEqual(self.authority.account_policy(self.item, "100.70.1.1")["permitrootlogin"], "prohibit-password")
            self.item["ssh_user"] = ""
            with self.assertRaisesRegex(ssh.SshError, "explicitly authorised"):
                self.authority.account_policy(self.item, "100.70.1.1")

    def test_listener_context_match_policy_is_rejected(self):
        account = types.SimpleNamespace(pw_uid=20001, pw_shell="/bin/sh")
        self.item["ssh_user"] = "tlptest"
        baseline = "pubkeyauthentication yes\nusepam no\n"
        with patch.object(ssh.pwd, "getpwnam", return_value=account), patch.object(ssh.os, "access", return_value=True), \
                patch.object(ssh, "run", side_effect=[baseline, baseline + "forcecommand /bin/false\n"]) as runner:
            with self.assertRaisesRegex(ssh.SshError, "managed local port"):
                self.authority.account_policy(self.item, "100.70.1.1")
        self.assertIn("lport=22", runner.call_args_list[0].args[0][-1])
        self.assertIn("lport=22002", runner.call_args_list[1].args[0][-1])

    def test_challenges_are_bounded_and_one_use_even_on_bad_signature(self):
        challenge = self.authority.challenge(self.item["id"], "100.70.1.2")
        self.assertEqual(len(challenge["challenge"]), 64)
        self.assertLessEqual(challenge["expires_at"], int(time.time()) + 30)
        request = {"schema": "teliphones-ssh-request/2", "workstation_id": self.item["id"],
                   "challenge": challenge["challenge"], "signature": "bad signature",
                   "session_id": "a" * 32, "ssh_public_key": EPHEMERAL}
        with patch.object(ssh, "run", side_effect=ssh.SshError("signature rejected")):
            with self.assertRaisesRegex(ssh.SshError, "signature rejected"):
                self.authority.issue(request, "100.70.1.2")
        with self.assertRaisesRegex(ssh.SshError, "already used"):
            self.authority.issue(request, "100.70.1.2")

    def test_only_ephemeral_exact_requests_are_accepted(self):
        challenge = self.authority.challenge(self.item["id"], "100.70.1.2")
        request = {"schema": "teliphones-ssh-request/2", "workstation_id": self.item["id"],
                   "challenge": challenge["challenge"], "signature": "signature",
                   "session_id": "b" * 32, "ssh_public_key": EPHEMERAL}
        for change in ({"schema": "teliphones-ssh-request/1"}, {"session_id": "../identity"},
                       {"ssh_public_key": EPHEMERAL + " comment"}, {"private_key": "must not be accepted"}):
            with self.subTest(change=change), self.assertRaises(ssh.SshError):
                self.authority.issue({**request, **change}, "100.70.1.2")
        with self.assertRaisesRegex(ssh.SshError, "persistent workstation identity"):
            self.authority.issue({**request, "ssh_public_key": PUBLIC}, "100.70.1.2")

    def test_session_and_public_key_cannot_receive_multiple_live_certificates(self):
        for identifier, key in (("c" * 32, OTHER_EPHEMERAL), ("d" * 32, EPHEMERAL)):
            self.authority.sessions = {"c" * 32: (EPHEMERAL, int(time.time()) + 60)}
            challenge = self.authority.challenge(self.item["id"], "100.70.1.2")
            request = {"schema": "teliphones-ssh-request/2", "workstation_id": self.item["id"],
                       "challenge": challenge["challenge"], "signature": "signature",
                       "session_id": identifier, "ssh_public_key": key}
            with self.assertRaises(ssh.SshError), patch.object(ssh, "run") as runner:
                self.authority.issue(request, "100.70.1.2")
            runner.assert_not_called()

    def test_expired_owned_units_are_stopped_even_with_unfiltered_state(self):
        self.item["expires_at"] = int(time.time()) - 1
        self.authority.active.add(self.item["id"])
        with patch.object(ssh, "run", return_value=self.authority.unit(self.item["id"]) + " loaded active running\n"), \
                patch.object(self.authority, "stop") as stop, patch.object(self.authority, "start") as start:
            self.authority.reconcile(self.state)
        stop.assert_called_once_with(self.item["id"], "revoked")
        start.assert_not_called()

    def test_unit_properties_bound_owned_sessions_and_lifetime(self):
        self.authority.configuration = lambda *_: Path(self.temporary.name) / "sshd_config"
        with patch.object(ssh.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout="inactive\n")), \
                patch.object(ssh, "run", return_value="active\n") as runner:
            self.authority.start(self.item, "100.70.1.1")
        start = runner.call_args_list[0].args[0]
        for value in ("--property=KillMode=control-group", "--property=SendSIGKILL=yes",
                      "--property=Type=notify", "--property=BindsTo=teliphones-broker.service"):
            self.assertIn(value, start)
        self.assertTrue(any(value.startswith("--property=RuntimeMaxSec=") for value in start))
        self.assertNotIn("sshd.service", start)

    def test_unverified_stop_does_not_forget_ownership(self):
        self.authority.active.add(self.item["id"])
        unsafe = types.SimpleNamespace(returncode=0, stdout="ActiveState=active\nMainPID=42\nControlPID=0\nLoadState=loaded\n")
        with patch.object(ssh.subprocess, "run", return_value=unsafe):
            with self.assertRaises(ssh.SshError):
                self.authority.stop(self.item["id"], "revoked")
        self.assertIn(self.item["id"], self.authority.active)
        stopped = types.SimpleNamespace(returncode=0, stdout="ActiveState=inactive\nMainPID=0\nControlPID=0\nLoadState=loaded\n")
        with patch.object(ssh.subprocess, "run", return_value=stopped):
            self.authority.stop(self.item["id"], "revoked")
        self.assertNotIn(self.item["id"], self.authority.active)

    def test_helper_errors_do_not_echo_sensitive_output(self):
        result = types.SimpleNamespace(returncode=1, stdout="sensitive", stderr="private key material")
        with patch.object(ssh.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ssh.SshError, "^SSH helper failed: ssh-keygen$"):
                ssh.run(["/usr/bin/ssh-keygen"])


if __name__ == "__main__":
    unittest.main()
