"""Real OpenSSH in private mount/PID/network namespaces; never changes host SSH/accounts.

The test supervisor substitutes process-tree teardown for unavailable systemd.
It does NOT certify production systemd/cgroup behaviour.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[2] / "teliphones" / "ssh_authority.py"
spec = importlib.util.spec_from_file_location("ssh_integration_authority", MODULE)
ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh)


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode:
        raise AssertionError("Isolated helper failed: " + repr(args) + "\n" + result.stderr[-4000:] + result.stdout[-4000:])
    return result.stdout


def descendants(parent):
    result = {parent}
    while True:
        before = len(result)
        for path in Path("/proc").glob("[0-9]*/status"):
            try:
                values = dict(line.split(":", 1) for line in path.read_text().splitlines() if ":" in line)
                if int(values["PPid"]) in result:
                    result.add(int(values["Pid"]))
            except (FileNotFoundError, ProcessLookupError):
                continue
        if len(result) == before:
            return result


class NamespaceTests(unittest.TestCase):
    def test_isolated_ssh(self):
        if not Path("/usr/sbin/sshd").is_file() or not shutil.which("unshare") or not shutil.which("ip"):
            self.skipTest("sshd, iproute2 and Linux namespaces are required; no dependencies downloaded")
        probe = subprocess.run(["sudo", "-n", "unshare", "--mount", "--net", "--pid", "--fork", "true"],
                               capture_output=True, timeout=10)
        if probe.returncode:
            self.skipTest("Privileged isolated namespaces are unavailable; host services will not be used")
        result = subprocess.run(["sudo", "-n", "unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc",
                                 "/usr/bin/python3", "-B", str(Path(__file__).resolve()), "--isolated"],
                                text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ISOLATED SSH INTEGRATION PASS", result.stdout)
        print(result.stdout.strip())


def isolated():
    command(["mount", "--make-rprivate", "/"])
    command(["mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", "/tmp"])
    with tempfile.TemporaryDirectory(prefix="teliphones-ssh-integration-") as directory:
        base = Path(directory)
        base.chmod(0o755)
        etc = base / "etc"
        (etc / "ssh").mkdir(parents=True)
        (etc / "teliphones" / "ssh").mkdir(parents=True, mode=0o700)
        (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\nsshd:x:65534:65534:sshd:/:/usr/sbin/nologin\n"
                                    "tlptest:x:20001:20001:test:/:/bin/sh\nother:x:20002:20002:test:/:/bin/sh\n")
        (etc / "group").write_text("root:x:0:\nsshd:x:65534:\ntlptest:x:20001:\nother:x:20002:\n")
        (etc / "shadow").write_text("root::19000:0:99999:7:::\ntlptest::19000:0:99999:7:::\nother::19000:0:99999:7:::\n")
        (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nshadow: files\nhosts: files\n")
        (etc / "ssh" / "sshd_config").write_text("UsePAM no\nPermitRootLogin no\n")
        etc.chmod(0o755)
        for name in ("passwd", "group", "nsswitch.conf"):
            (etc / name).chmod(0o644)
        command(["mount", "--bind", str(etc), "/etc"])
        command(["mount", "-t", "tmpfs", "tmpfs", "/run"])
        Path("/run/sshd").mkdir(mode=0o755)
        command(["ip", "link", "set", "lo", "up"])
        command(["ip", "netns", "add", "tlp-test-client"])
        for server, client, server_ip, client_ip in (("tlp-admin", "ws", "100.70.1.1/24", "100.70.1.2/24"),
                                                     ("public", "uplink", "10.0.0.1/24", "10.0.0.2/24")):
            command(["ip", "link", "add", server, "type", "veth", "peer", "name", client])
            command(["ip", "link", "set", client, "netns", "tlp-test-client"])
            command(["ip", "addr", "add", server_ip, "dev", server])
            command(["ip", "link", "set", server, "up"])
            command(["ip", "netns", "exec", "tlp-test-client", "ip", "addr", "add", client_ip, "dev", client])
            command(["ip", "netns", "exec", "tlp-test-client", "ip", "link", "set", client, "up"])
        command(["ip", "netns", "exec", "tlp-test-client", "ip", "link", "set", "lo", "up"])

        def key(name):
            path = base / name
            command(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path)])
            path.chmod(0o600)
            return path

        host = key("host")
        shutil.copyfile(host, "/etc/ssh/ssh_host_ed25519_key")
        Path("/etc/ssh/ssh_host_ed25519_key").chmod(0o600)
        identity = key("client")
        wrong_key = key("wrong")
        session_key = key("session")
        other_session_key = key("session-other")
        item = {"id": "0123456789abcdef", "ssh": True, "ssh_user": "tlptest",
                "ssh_public_key": ssh.public_key((base / "client.pub").read_text().strip()),
                "address": "100.70.1.2/32", "expires_at": int(time.time()) + 90}
        state = {"subnet": "100.70.1.0/24", "workstations": [item]}
        events = []
        authority = ssh.Authority("/etc/teliphones/ssh", lambda: (state, False), threading.RLock(),
                                  lambda *args, **kwargs: events.append((args, kwargs)))
        authority.prerequisites = lambda: None
        authority.initialise()
        config = authority.configuration(item, "100.70.1.1")
        system_policy = Path("/etc/ssh/sshd_config")
        original_policy = system_policy.read_text()
        original_managed = config.read_text()
        try:
            for local_port in (22, ssh.port(item)):
                system_policy.write_text(original_policy + "\nMatch LocalPort " + str(local_port) + "\n    ForceCommand /bin/false\n")
                try:
                    authority.configuration(item, "100.70.1.1")
                    raise AssertionError("Listener-context system SSH restriction was bypassed")
                except ssh.SshError as error:
                    assert "managed local port" in str(error), str(error)
                assert config.read_text() == original_managed
            system_policy.write_text(original_policy + "\nMatch User tlptest\n    ForceCommand /bin/false\n")
            try:
                authority.configuration(item, "100.70.1.1")
                raise AssertionError("Forced-command system account restriction was bypassed")
            except ssh.SshError as error:
                assert "forced-command" in str(error), str(error)
        finally:
            system_policy.write_text(original_policy)
        config.write_text(original_managed.replace("ForceCommand none\n", "ForceCommand /bin/false\n"))
        try:
            authority.validate_configuration(config, item, "100.70.1.1", authority.account_policy(item, "100.70.1.1"))
            raise AssertionError("Altered generated policy was accepted")
        except ssh.SshError as error:
            assert "effective account/source/local-port" in str(error), str(error)
        finally:
            config.write_text(original_managed)
        principal_file = config.parent / "principals"
        ca_before = (authority.directory / "ca").read_bytes()
        identity_before = identity.read_bytes()
        principal_file.write_text("unknown-principal\n")
        with patch.object(authority, "stop") as stop:
            try:
                authority.configuration(item, "100.70.1.1")
                raise AssertionError("Unknown trust file was silently migrated")
            except ssh.SshError as error:
                assert "differs from its owned configuration" in str(error), str(error)
            stop.assert_not_called()
        assert principal_file.read_text() == "unknown-principal\n"
        principal_file.write_text(authority.legacy_principal(item) + "\n")
        with patch.object(authority, "stop", side_effect=ssh.SshError("modelled stop failure")):
            try:
                authority.configuration(item, "100.70.1.1")
                raise AssertionError("Principal migration ignored unverified session cleanup")
            except ssh.SshError as error:
                assert "modelled stop failure" in str(error), str(error)
        assert principal_file.read_text() == authority.legacy_principal(item) + "\n"
        with patch.object(authority, "stop") as stop:
            authority.configuration(item, "100.70.1.1")
            stop.assert_called_once_with(item["id"], "ephemeral-credential-upgrade")
        assert principal_file.read_text() == authority.principal(item) + "\n"
        assert (authority.directory / "ca").read_bytes() == ca_before and identity.read_bytes() == identity_before
        notification = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify_path = str(base / "notify")
        notification.bind(notify_path)
        notification.settimeout(10)
        listener = subprocess.Popen(["/usr/bin/python3", "-B", "-I", str(MODULE), "--listen", str(config),
                                     "100.70.1.1", str(ssh.port(item)), "100.70.1.2", "tlp-admin"],
                                    env={**os.environ, "NOTIFY_SOCKET": notify_path}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        held = None
        unrelated = None
        unrelated_listener = None
        try:
            assert notification.recv(64) == b"READY=1"
            authority.start_api("100.70.1.1")
            http_script = ("import http.client,json,sys; c=http.client.HTTPConnection('100.70.1.1',8765,timeout=1,"
                           "source_address=('100.70.1.2',0)); c.request(sys.argv[1],sys.argv[2],sys.stdin.read(),"
                           "{'Content-Type':'application/json'}); r=c.getresponse(); raw=r.read(); "
                           "assert r.status==200,raw; print(raw.decode())")
            http_args = ["ip", "netns", "exec", "tlp-test-client", "/usr/bin/python3", "-c", http_script]
            challenge_path = "/ssh/challenge?workstation_id=" + item["id"]
            challenge = json.loads(command(http_args + ["GET", challenge_path], input=""))

            def signed_request(challenge, session, session_id, signer=identity):
                session_public = ssh.public_key(Path(str(session) + ".pub").read_text().strip())
                message = ("TELIPHONES-SSH-REQUEST-2\n" + item["id"] + "\n" + challenge["challenge"] + "\n" +
                           session_id + "\n" + session_public + "\n")
                signature = command(["/usr/bin/ssh-keygen", "-Y", "sign", "-n", ssh.NAMESPACE, "-f", str(signer)], input=message)
                return {"schema": "teliphones-ssh-request/2", "workstation_id": item["id"],
                        "challenge": challenge["challenge"], "session_id": session_id,
                        "ssh_public_key": session_public, "signature": signature}

            request = signed_request(challenge, session_key, "1" * 32)
            issued = json.loads(command(http_args + ["POST", "/ssh/certificate"], input=json.dumps(request)))
            assert issued["session_id"] == request["session_id"] and issued["ssh_public_key"] == request["ssh_public_key"]
            assert issued["ssh_public_key"] != item["ssh_public_key"]
            assert "PRIVATE KEY" not in json.dumps(request)
            try:
                authority.issue(request, "100.70.1.2")
                raise AssertionError("Replayed SSH challenge accepted")
            except ssh.SshError:
                pass
            (base / "certificate.pub").write_text(issued["certificate"] + "\n")
            known = base / "known_hosts"
            known.write_text("[100.70.1.1]:" + str(ssh.port(item)) + " " + authority.host_key() + "\n")
            args = ["ip", "netns", "exec", "tlp-test-client", "/usr/bin/ssh", "-F", "/dev/null",
                    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                    "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known),
                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=2",
                    "-o", "CertificateFile=" + str(base / "certificate.pub"), "-i", str(session_key),
                    "-p", str(ssh.port(item)), "tlptest@100.70.1.1"]
            assert command(args + ["id -un"]).strip() == "tlptest"
            second = authority.issue(signed_request(authority.challenge(item["id"], "100.70.1.2"),
                                                    other_session_key, "2" * 32), "100.70.1.2")
            (base / "second-certificate.pub").write_text(second["certificate"] + "\n")
            other_args = args.copy()
            other_args[other_args.index(str(session_key))] = str(other_session_key)
            assert subprocess.run(other_args + ["true"], capture_output=True, timeout=10).returncode != 0, \
                "A session authenticated using a different session's certificate"
            other_args[other_args.index("CertificateFile=" + str(base / "certificate.pub"))] = "CertificateFile=" + str(base / "second-certificate.pub")
            assert command(other_args + ["id -un"]).strip() == "tlptest"
            persistent_args = args.copy()
            persistent_args[persistent_args.index(str(session_key))] = str(identity)
            assert subprocess.run(persistent_args + ["true"], capture_output=True, timeout=10).returncode != 0
            legacy_principal = authority.legacy_principal(item)
            command(["/usr/bin/ssh-keygen", "-q", "-s", str(authority.directory / "ca"),
                     "-I", "ws-" + item["id"], "-n", legacy_principal, "-V", "-1m:+5m",
                     "-O", "clear", "-O", "permit-pty", "-O", "source-address=" + item["address"], str(identity) + ".pub"])
            persistent_args[persistent_args.index("CertificateFile=" + str(base / "certificate.pub"))] = "CertificateFile=" + str(base / "client-cert.pub")
            assert subprocess.run(persistent_args + ["true"], capture_output=True, timeout=10).returncode != 0, \
                "A pre-correction persistent-identity certificate authenticated"
            certificate = issued["certificate"].split()
            tampered_blob = bytearray(base64.b64decode(certificate[1]))
            tampered_blob[-1] ^= 1
            certificate[1] = base64.b64encode(tampered_blob).decode()
            (base / "certificate.pub").write_text(" ".join(certificate) + "\n")
            assert subprocess.run(args + ["true"], capture_output=True, timeout=10).returncode != 0, \
                "The real SSH server accepted a certificate with a tampered digital signature"
            (base / "certificate.pub").write_text(issued["certificate"] + "\n")
            wrong_user = args.copy()
            wrong_user[-1] = "root@100.70.1.1"
            assert subprocess.run(wrong_user + ["true"], capture_output=True, timeout=10).returncode != 0
            wrong_user[-1] = "other@100.70.1.1"
            assert subprocess.run(wrong_user + ["true"], capture_output=True, timeout=10).returncode != 0
            wrong_args = args.copy()
            wrong_args[wrong_args.index(str(session_key))] = str(wrong_key)
            assert subprocess.run(wrong_args + ["true"], capture_output=True, timeout=10).returncode != 0
            original_known = known.read_text()
            known.write_text("[100.70.1.1]:" + str(ssh.port(item)) + " " + ssh.public_key((base / "wrong.pub").read_text().strip()) + "\n")
            assert subprocess.run(args + ["true"], capture_output=True, timeout=10).returncode != 0
            known.write_text(original_known)
            for user in ("root", "doesnotexist"):
                try:
                    authority.account_policy({**item, "ssh_user": user}, "100.70.1.1")
                    raise AssertionError("Restricted account was accepted")
                except ssh.SshError:
                    pass
            # Wrong key possession must fail even when source address and WG identity match.
            bad = authority.challenge(item["id"], "100.70.1.2")
            try:
                authority.issue(signed_request(bad, key("unauthorised-session"), "3" * 32, wrong_key), "100.70.1.2")
                raise AssertionError("Unpaired SSH key received a certificate")
            except ssh.SshError:
                pass
            substituted_public = ssh.public_key(Path(str(key("substituted")) + ".pub").read_text().strip())
            for field, value in (("ssh_public_key", substituted_public), ("session_id", "f" * 32)):
                altered = signed_request(authority.challenge(item["id"], "100.70.1.2"), key("altered-" + field), "4" * 32)
                try:
                    authority.issue({**altered, field: value}, "100.70.1.2")
                    raise AssertionError("Workstation signature did not bind the ephemeral " + field)
                except ssh.SshError:
                    pass
            for candidate_key, candidate_id in ((session_key, "6" * 32), (key("duplicate-session"), "1" * 32)):
                candidate = signed_request(authority.challenge(item["id"], "100.70.1.2"), candidate_key, candidate_id)
                try:
                    authority.issue(candidate, "100.70.1.2")
                    raise AssertionError("A live session key or identity was reused")
                except ssh.SshError as error:
                    assert "only one live certificate" in str(error), str(error)
            # A public-interface route to the exact WG address must not reach either listener.
            command(["ip", "netns", "exec", "tlp-test-client", "ip", "route", "add", "100.70.1.1/32", "via", "10.0.0.1"])
            assert subprocess.run(args[:-1] + ["-b", "100.70.1.2", args[-1], "true"], capture_output=True, timeout=10).returncode != 0
            assert subprocess.run(http_args + ["GET", challenge_path], input="", text=True, capture_output=True, timeout=10).returncode != 0
            command(["ip", "netns", "exec", "tlp-test-client", "ip", "route", "del", "100.70.1.1/32"])
            # New logins reject genuinely expired OpenSSH certificates (not just JSON expiry).
            expiry_challenge = authority.challenge(item["id"], "100.70.1.2")
            expiring_key = key("expiring")
            expiry_request = signed_request(expiry_challenge, expiring_key, "5" * 32)
            item["expires_at"] = int(time.time()) + 2
            expired = authority.issue(expiry_request, "100.70.1.2")
            (base / "certificate.pub").write_text(expired["certificate"] + "\n")
            expired_args = args.copy()
            expired_args[expired_args.index(str(session_key))] = str(expiring_key)
            time.sleep(2.1)
            assert subprocess.run(expired_args + ["true"], capture_output=True, timeout=10).returncode != 0
            try:
                authority.challenge(item["id"], "100.70.1.2")
                raise AssertionError("Expired authorisation received a challenge")
            except ssh.SshError:
                pass
            item["expires_at"] = int(time.time()) + 90
            (base / "certificate.pub").write_text(issued["certificate"] + "\n")
            # Existing interactive processes must actually disappear, not merely lose network reachability.
            held = subprocess.Popen(args + ["echo SESSION_READY; exec sleep 90"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert held.stdout.readline().strip() == "SESSION_READY"
            session_key.unlink()
            assert subprocess.run(args + ["true"], capture_output=True, timeout=10).returncode != 0, \
                "A keyless client reused the remaining public certificate"
            assert held.poll() is None, "Deleting a key must not be mistaken for terminating an authenticated session"
            system_config = base / "system_sshd_config"
            system_config.write_text(config.read_text().replace("Port 22002\n", "Port 2222\n").replace("sshd.pid", "system_sshd.pid"))
            unrelated_listener = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(system_config)],
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            known.write_text(original_known + "[100.70.1.1]:2222 " + authority.host_key() + "\n")
            other_args = args.copy()
            other_args[other_args.index(str(session_key))] = str(other_session_key)
            other_args[other_args.index("CertificateFile=" + str(base / "certificate.pub"))] = "CertificateFile=" + str(base / "second-certificate.pub")
            other_args[other_args.index(str(ssh.port(item)))] = "2222"
            time.sleep(0.1)
            unrelated = subprocess.Popen(other_args + ["echo OTHER_READY; read line; echo OTHER_ALIVE; exec sleep 90"],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert unrelated.stdout.readline().strip() == "OTHER_READY"
            revoked_request = signed_request(authority.challenge(item["id"], "100.70.1.2"), key("revoked-session"), "7" * 32)
            state["workstations"] = []
            try:
                authority.challenge(item["id"], "100.70.1.2")
                raise AssertionError("Revoked workstation received a challenge")
            except ssh.SshError:
                pass
            try:
                authority.issue(revoked_request, "100.70.1.2")
                raise AssertionError("Revocation allowed issuance for a previously authenticated challenge")
            except ssh.SshError:
                pass
            owned = descendants(listener.pid)
            for pid in sorted(owned, reverse=True):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            held.wait(timeout=10)
            assert held.returncode != 0 and unrelated.poll() is None
            revoked_args = args.copy()
            revoked_args[revoked_args.index(str(session_key))] = str(other_session_key)
            revoked_args[revoked_args.index("CertificateFile=" + str(base / "certificate.pub"))] = "CertificateFile=" + str(base / "second-certificate.pub")
            assert subprocess.run(revoked_args + ["true"], capture_output=True, timeout=10).returncode != 0
            unrelated.stdin.write("check\n")
            unrelated.stdin.flush()
            assert unrelated.stdout.readline().strip() == "OTHER_ALIVE"
            print("ISOLATED SSH INTEGRATION PASS: distinct ephemeral certificate subjects and session isolation; persistent-identity certificate denied; public-key/session binding; deleted-key login denied without terminating existing login; real certificate login; tampered certificate signature; restrictive Match policy; generated effective policy; wrong account/key/host pin; replay; wrong-interface rejection; certificate expiry; expired/revoked issuance rejected; owned session termination; unrelated authenticated SSH session retained. Linux tmpfs test credentials only; not Windows memory-agent validation. systemd/cgroup supervision is substituted, not certified.")
        finally:
            if authority.server:
                authority.server.shutdown()
                authority.server.server_close()
            for pid in sorted(descendants(listener.pid), reverse=True):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            listener.wait(timeout=10)
            if sys.exc_info()[0] is not None:
                print(listener.stderr.read().decode()[-4000:], file=sys.stderr)
            for process in (held, unrelated):
                if process and process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
            if unrelated_listener:
                for pid in sorted(descendants(unrelated_listener.pid), reverse=True):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                unrelated_listener.wait(timeout=10)
            notification.close()
            command(["ip", "netns", "del", "tlp-test-client"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--isolated"]:
        isolated()
    else:
        unittest.main()
