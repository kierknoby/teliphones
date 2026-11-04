"""My PBXs SSH authority. Never used by Remote Support or the system SSH listener."""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
import threading
import time
import sys
from urllib.parse import parse_qs, urlsplit


API_PORT = 8765
SSH_PORT_BASE = 22000
CERT_SECONDS = 300
NAMESPACE = "teliphones-ssh"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root"}


class SshError(Exception):
    pass


def public_key(value):
    if not isinstance(value, str) or len(value) > 256:
        raise SshError("An OpenSSH Ed25519 public key is required.")
    parts = value.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise SshError("Only a bare Ed25519 public key is accepted.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError as error:
        raise SshError("Invalid SSH public-key encoding.") from error
    expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
    if len(raw) != 51 or not raw.startswith(expected):
        raise SshError("Invalid SSH public-key structure.")
    return " ".join(parts)


def managed(item):
    return item.get("ssh") is True and bool(item.get("ssh_public_key"))


def port(item):
    return SSH_PORT_BASE + int(ipaddress.IPv4Interface(item["address"]).ip) % 256


def existing_accounts():
    accounts = []
    for account in pwd.getpwall():
        if (re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", account.pw_name) is None
                or (account.pw_uid == 0 and account.pw_name != "root")
                or not account.pw_shell.startswith("/")
                or Path(account.pw_shell).name in ("nologin", "false")
                or not os.access(account.pw_shell, os.X_OK)):
            continue
        accounts.append(account.pw_name)
    return sorted(set(accounts))


def run(arguments, data=None):
    result = subprocess.run(arguments, input=data, text=True, capture_output=True,
                            timeout=15, env=ENV, check=False)
    if result.returncode:
        # Helpers may print public certificates or authentication material: never forward output.
        raise SshError("SSH helper failed: " + Path(arguments[0]).name)
    return result.stdout


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SshError("SSH authority directory ownership or permissions are unsafe.")


def write(path, content):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


class Authority:
    def __init__(self, directory, state, lock, diagnostic, interface="tlp-admin"):
        self.directory = Path(directory)
        self.state = state
        self.lock = lock
        self.diagnostic = diagnostic
        self.interface = interface
        self.challenges = {}
        self.sessions = {}
        self.servers = {}
        self.server = None
        self.server_address = None
        self.active = set()

    def item_interface(self, item):
        interface = self.interface
        if item.get("locked") is True:
            identifier = item.get("id")
            if not isinstance(identifier, str) or re.fullmatch(r"[a-f0-9]{16}", identifier) is None:
                raise SshError("Invalid Locked workstation identity.")
            interface = "tlpw" + hashlib.sha256(identifier.encode()).hexdigest()[:11]
        if item.get("interface") is not None and item["interface"] != interface:
            raise SshError("Managed SSH interface does not match the workstation's authenticated pairing.")
        if not isinstance(interface, str) or (interface != "tlp-admin" and re.fullmatch(r"tlpw[a-f0-9]{11}", interface) is None):
            raise SshError("Invalid managed SSH tunnel interface.")
        return interface

    def prerequisites(self):
        for binary in ("/usr/bin/ssh-keygen", "/usr/sbin/sshd", "/usr/bin/systemd-run", "/usr/bin/systemctl"):
            if not os.access(binary, os.X_OK):
                raise SshError("Managed SSH requires " + binary)
        if not Path("/run/systemd/system").is_dir():
            raise SshError("Managed SSH requires a running systemd service manager.")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise SshError("Managed SSH requires unified cgroup v2 for verified session cleanup.")

    def initialise(self):
        self.prerequisites()
        private_directory(self.directory)
        ca = self.directory / "ca"
        if not ca.exists():
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                generated = Path(temporary) / "ca"
                run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(generated)])
                generated.chmod(0o600)
                os.replace(generated, ca)
        info = ca.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise SshError("SSH CA must be a private root-owned regular file.")
        return public_key(run(["/usr/bin/ssh-keygen", "-y", "-f", str(ca)]).strip())

    def host_key(self):
        path = Path("/etc/ssh/ssh_host_ed25519_key")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise SshError("A root-owned Ed25519 SSH host key is required.")
        return public_key(" ".join(run(["/usr/bin/ssh-keygen", "-y", "-f", str(path)]).split()[:2]))

    @staticmethod
    def effective_policy(user, source, pbx, local_port, config=None):
        arguments = ["/usr/sbin/sshd", "-T"]
        if config is not None:
            arguments += ["-f", str(config)]
        arguments += ["-C", "user=%s,host=%s,addr=%s,laddr=%s,lport=%d" %
                      (user, source, source, pbx, local_port)]
        policy = {}
        for line in run(arguments).splitlines():
            name, _, value = line.partition(" ")
            policy[name] = value
        return policy

    def account_policy(self, item, pbx):
        user = item.get("ssh_user", "")
        if not isinstance(user, str) or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) is None:
            raise SshError("An existing Linux account must be explicitly authorised.")
        try:
            account = pwd.getpwnam(user)
        except KeyError as error:
            raise SshError("The authorised Linux account does not exist.") from error
        if account.pw_uid == 0 and user != "root":
            raise SshError("UID-zero aliases cannot receive managed SSH access.")
        if not os.access(account.pw_shell, os.X_OK) or Path(account.pw_shell).name in ("nologin", "false"):
            raise SshError("The authorised account has no permitted interactive shell.")
        source = str(ipaddress.IPv4Interface(item["address"]).ip)
        policy = self.effective_policy(user, source, pbx, 22)
        listener_policy = self.effective_policy(user, source, pbx, port(item))
        if policy != listener_policy:
            raise SshError("System SSH policy differs at the managed local port; listener-context Match policies are unsupported.")
        if policy.get("pubkeyauthentication") != "yes" or policy.get("authenticationmethods") not in ("any", "publickey"):
            raise SshError("Existing SSH policy does not permit certificate-only public-key authentication.")
        if policy.get("usedns") != "no":
            raise SshError("DNS-dependent SSH Match policies are not supported for managed account approval.")
        if policy.get("usepam") not in ("yes", "no") or policy.get("pamservicename", "sshd") != "sshd":
            raise SshError("Unsupported SSH PAM configuration; managed SSH requires the same sshd PAM service.")
        if user == "root" and policy.get("permitrootlogin") not in ("yes", "without-password", "prohibit-password"):
            raise SshError("Existing SSH policy does not permit an interactive root public-key login.")
        if policy.get("forcecommand", "none") != "none":
            raise SshError("A forced-command account cannot be used for an interactive managed shell.")
        if (policy.get("chrootdirectory", "none") != "none" or policy.get("permittty") != "yes"
                or policy.get("pubkeyauthoptions", "none") != "none"
                or policy.get("authorizedkeyscommand", "none") != "none"
                or policy.get("authorizedprincipalscommand", "none") != "none"
                or policy.get("authorizedprincipalsfile", "none") != "none"):
            raise SshError("Existing SSH account restrictions are not supported for managed interactive access.")
        if "ssh-ed25519-cert-v01@openssh.com" not in policy.get("pubkeyacceptedalgorithms", "").split(","):
            raise SshError("Existing SSH policy does not accept Ed25519 user certificates.")
        if "ssh-ed25519" not in policy.get("casignaturealgorithms", "").split(","):
            raise SshError("Existing SSH policy does not accept an Ed25519 certificate authority.")
        # Do not silently reinterpret group patterns, PAM stacks or nonstandard key policies.
        for name in ("allowusers", "denyusers", "allowgroups", "denygroups"):
            if policy.get(name):
                raise SshError("Existing SSH account restrictions require an explicit supported policy; " + name + " is configured.")
        return policy

    def validate_configuration(self, config, item, pbx, policy):
        source = str(ipaddress.IPv4Interface(item["address"]).ip)
        effective = self.effective_policy(item["ssh_user"], source, pbx, port(item), config)
        expected = {
            "port": str(port(item)), "listenaddress": pbx + ":" + str(port(item)),
            "allowusers": item["ssh_user"], "pubkeyauthentication": "yes", "authenticationmethods": "publickey",
            "passwordauthentication": "no", "kbdinteractiveauthentication": "no", "permitemptypasswords": "no",
            "authorizedkeysfile": "none", "authorizedprincipalsfile": "none",
            "authorizedprincipalscommand": "/usr/bin/cat " + str(config.parent / "principals"),
            "authorizedprincipalscommanduser": "root",
            "trustedusercakeys": str(config.parent / "ca.pub"),
            "hostkey": "/etc/ssh/ssh_host_ed25519_key", "strictmodes": "yes",
            "disableforwarding": "yes", "permittunnel": "no", "permituserrc": "no", "permituserenvironment": "no",
            "forcecommand": "none", "chrootdirectory": "none", "permittty": "yes",
            "maxsessions": "1", "pubkeyauthoptions": "none",
        }
        for directive in ("permitrootlogin", "usepam", "pubkeyacceptedalgorithms", "casignaturealgorithms", "revokedkeys"):
            expected[directive] = policy.get(directive, "none")
        if any(effective.get(name) != value for name, value in expected.items()):
            raise SshError("Generated managed SSH policy failed effective account/source/local-port validation.")

    @staticmethod
    def unit(identifier):
        if re.fullmatch(r"[a-f0-9]{16}", identifier) is None:
            raise SshError("Invalid SSH workstation identity.")
        return "teliphones-ssh-" + identifier + ".service"

    def configuration(self, item, pbx):
        self.initialise()
        self.host_key()
        policy = self.account_policy(item, pbx)
        directory = self.directory / item["id"]
        private_directory(directory)
        principal = self.principal(item)
        principal_file = directory / "principals"
        ca_file = directory / "ca.pub"
        upgrade_principal = False
        for target, content in ((principal_file, principal + "\n"), (ca_file, self.initialise() + "\n")):
            if target.exists():
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise SshError("Managed SSH trust file ownership or permissions are unsafe.")
                previous = target.read_text()
                if target == principal_file and previous == self.legacy_principal(item) + "\n":
                    upgrade_principal = True
                elif previous != content:
                    raise SshError("Managed SSH trust file differs from its owned configuration.")
            else:
                write(target, content)
        config = (
            "Port %d\nListenAddress %s\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
            "PidFile %s\nAllowUsers %s\nPubkeyAuthentication yes\nAuthenticationMethods publickey\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
            "AuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile none\n"
            "AuthorizedPrincipalsCommand /usr/bin/cat %s\nAuthorizedPrincipalsCommandUser root\n"
            "PermitRootLogin %s\nUsePAM %s\nStrictModes yes\n"
            "DisableForwarding yes\nPermitTunnel no\nPermitUserRC no\nPermitUserEnvironment no\n"
            "PermitTTY yes\nForceCommand none\n"
            "LogLevel VERBOSE\nLoginGraceTime 20\nMaxAuthTries 2\nMaxSessions 1\n"
            "ClientAliveInterval 15\nClientAliveCountMax 2\n"
        ) % (port(item), item.get("pbx_address", pbx), directory / "sshd.pid", item["ssh_user"], ca_file, principal_file,
             policy.get("permitrootlogin", "no"), policy.get("usepam", "yes"))
        for directive in ("pubkeyacceptedalgorithms", "casignaturealgorithms", "revokedkeys"):
            value = policy.get(directive)
            if value and value != "none":
                if "\n" in value or "\r" in value:
                    raise SshError("Invalid effective SSH policy value.")
                config += directive + " " + value + "\n"
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(config)
        try:
            run(["/usr/sbin/sshd", "-t", "-f", str(temporary)])
            self.validate_configuration(temporary, item, pbx, policy)
            if upgrade_principal:
                self.stop(item["id"], "ephemeral-credential-upgrade")
                with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
                    replacement = Path(stream.name)
                    stream.write(principal + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.replace(replacement, principal_file)
                finally:
                    replacement.unlink(missing_ok=True)
            os.replace(temporary, directory / "sshd_config")
        finally:
            temporary.unlink(missing_ok=True)
        return directory / "sshd_config"

    def stop(self, identifier, reason):
        unit = self.unit(identifier)
        stopped = subprocess.run(["/usr/bin/systemctl", "stop", unit], text=True, capture_output=True,
                                 timeout=15, env=ENV, check=False)
        result = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState,MainPID,ControlPID,LoadState"],
                                text=True, capture_output=True, timeout=15, env=ENV, check=False)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if (values.get("ActiveState") not in ("inactive", "failed") or values.get("MainPID") != "0"
                or values.get("ControlPID") != "0" or values.get("LoadState") not in ("loaded", "not-found")
                or (stopped.returncode != 0 and values.get("LoadState") != "not-found")):
            raise SshError("Managed SSH service state could not be verified.")
        group = Path("/sys/fs/cgroup/system.slice") / unit
        if group.exists():
            events = dict(line.split() for line in (group / "cgroup.events").read_text().splitlines())
            if events.get("populated") != "0":
                raise SshError("Managed SSH cgroup still contains session processes.")
        self.active.discard(identifier)
        self.diagnostic("ws-" + identifier, "ssh.terminated", reason=reason)

    def start(self, item, pbx):
        endpoint = item.get("pbx_address", pbx)
        interface = self.item_interface(item)
        config = self.configuration(item, endpoint)
        unit = self.unit(item["id"])
        # These units are uniquely owned by the broker and never share system SSH processes.
        state = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"],
                               capture_output=True, text=True, timeout=10, env=ENV, check=False)
        if state.returncode == 0 and state.stdout.strip() == "active":
            self.active.add(item["id"])
            return
        args = ["/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + unit,
                "--property=Type=notify", "--property=NotifyAccess=main", "--property=TimeoutStartSec=10",
                "--property=KillMode=control-group",
                "--property=TimeoutStopSec=5", "--property=SendSIGKILL=yes",
                "--property=BindsTo=teliphones-broker.service", "--property=After=teliphones-broker.service",
                "--property=Restart=no"]
        if item.get("expires_at") is not None:
            remaining = item["expires_at"] - int(time.time())
            if remaining <= 0:
                raise SshError("SSH authorisation has expired.")
            args.append("--property=RuntimeMaxSec=" + str(remaining))
        run(args + ["/usr/bin/python3", "-I", str(Path(__file__).resolve()), "--listen",
                    str(config), endpoint, str(port(item)), str(ipaddress.IPv4Interface(item["address"]).ip), interface])
        status = run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"]).strip()
        if status != "active":
            raise SshError("Managed SSH listener failed to start.")
        self.active.add(item["id"])

    def reconcile(self, state):
        now = int(time.time())
        items = {item["id"]: item for item in state.get("workstations", []) if managed(item)
                 and (item.get("expires_at") is None or item["expires_at"] > now)}
        if items or self.active or self.directory.exists():
            units = run(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager",
                         "teliphones-ssh-*.service"])
            for line in units.splitlines():
                name = line.split()[0]
                found = re.fullmatch(r"teliphones-ssh-([a-f0-9]{16})\.service", name)
                if found is None:
                    raise SshError("Unexpected owned SSH service inventory.")
                self.active.add(found[1])
        for identifier in sorted(self.active - items.keys()):
            self.stop(identifier, "revoked")
        if not items:
            for server in self.servers.values():
                server.shutdown()
                server.server_close()
            self.servers.clear()
            self.server = None
            self.server_address = None
            return
        pbx = str(ipaddress.IPv4Network(state["subnet"])[1])
        for item in items.values():
            self.start(item, pbx)
        endpoints = {(self.item_interface(item), item.get("pbx_address", pbx)) for item in items.values()}
        for binding in set(self.servers) - endpoints:
            server = self.servers.pop(binding)
            server.shutdown()
            server.server_close()
        for interface, address in sorted(endpoints):
            if (interface, address) not in self.servers:
                self.servers[(interface, address)] = self.start_api(address, interface)
        self.server = next(iter(self.servers.values()), None)
        self.server_address = next(iter(self.servers), (None, None))[1]

    def authorised(self, identifier, peer):
        state, _ = self.state()
        now = int(time.time())
        item = next((entry for entry in state.get("workstations", [])
                     if entry["id"] == identifier and managed(entry)), None)
        if not item or str(ipaddress.IPv4Interface(item["address"]).ip) != peer:
            raise SshError("This workstation is not authorised for managed SSH.")
        if item.get("expires_at") is not None and item["expires_at"] <= now:
            raise SshError("SSH authorisation has expired.")
        return item, str(ipaddress.IPv4Network(state["subnet"])[1])

    def destroy(self):
        self.reconcile({"workstations": []})
        if not self.directory.exists():
            return
        private_directory(self.directory)
        for path in self.directory.iterdir():
            if re.fullmatch(r"[a-f0-9]{16}", path.name):
                private_directory(path)
                for child in path.iterdir():
                    if child.name not in ("principals", "ca.pub", "sshd_config"):
                        raise SshError("Unexpected SSH recovery artifact; retaining authority files.")
                    info = child.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                        raise SshError("Unsafe SSH recovery artifact; retaining authority files.")
                for child in path.iterdir():
                    child.unlink()
                path.rmdir()
            elif path.name not in ("ca", "ca.pub"):
                raise SshError("Unknown SSH authority artifact; retaining recovery files.")
        for name in ("ca", "ca.pub"):
            path = self.directory / name
            if path.exists():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise SshError("Unsafe SSH authority file; refusing removal.")
                path.unlink()
        self.directory.rmdir()

    @staticmethod
    def legacy_principal(item):
        digest = hashlib.sha256(public_key(item["ssh_public_key"]).encode()).hexdigest()[:16]
        return "tlp-" + item["id"] + "-" + digest

    @classmethod
    def principal(cls, item):
        return cls.legacy_principal(item).replace("tlp-", "tlp-eph-", 1)

    def challenge(self, identifier, peer):
        with self.lock:
            self.authorised(identifier, peer)
            now = int(time.time())
            self.challenges = {key: value for key, value in self.challenges.items() if value[2] > now}
            if len(self.challenges) >= 512:
                raise SshError("SSH challenge capacity reached; retry later.")
            nonce = secrets.token_hex(32)
            self.challenges[identifier] = (nonce, peer, now + 30)
            return {"schema": "teliphones-ssh-challenge/1", "workstation_id": identifier,
                    "challenge": nonce, "expires_at": now + 30}

    def issue(self, request, peer):
        if not isinstance(request, dict) or set(request) != {
                "schema", "workstation_id", "challenge", "session_id", "ssh_public_key", "signature"}:
            raise SshError("Invalid SSH certificate request.")
        identifier = request["workstation_id"]
        if request["schema"] != "teliphones-ssh-request/2" or not isinstance(identifier, str):
            raise SshError("Unsupported SSH certificate request.")
        session_id = request["session_id"]
        if not isinstance(session_id, str) or re.fullmatch(r"[a-f0-9]{32}", session_id) is None:
            raise SshError("An ephemeral SSH session identity is required.")
        session_key = public_key(request["ssh_public_key"])
        if request["ssh_public_key"] != session_key:
            raise SshError("The ephemeral SSH public key must use canonical encoding.")
        signature = request["signature"]
        if not isinstance(signature, str) or len(signature) > 4096:
            raise SshError("Invalid SSH signature.")
        with self.lock:
            item, pbx = self.authorised(identifier, peer)
            expected = self.challenges.pop(identifier, None)
            if not expected or expected[0] != request["challenge"] or expected[1] != peer or expected[2] <= int(time.time()):
                raise SshError("SSH challenge expired, was already used, or belongs to another workstation.")
            if session_key == public_key(item["ssh_public_key"]):
                raise SshError("The persistent workstation identity cannot be used as an SSH session key.")
            now = int(time.time())
            self.sessions = {key: value for key, value in self.sessions.items() if value[1] > now}
            if session_id in self.sessions or any(value[0] == session_key for value in self.sessions.values()):
                raise SshError("An ephemeral SSH key and session identity may receive only one live certificate.")
            if len(self.sessions) >= 512:
                raise SshError("SSH certificate capacity reached; retry after existing certificates expire.")
            private_directory(self.directory)
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                directory = Path(temporary)
                write(directory / "allowed", identifier + " " + public_key(item["ssh_public_key"]) + "\n")
                write(directory / "signature", signature)
                message = ("TELIPHONES-SSH-REQUEST-2\n" + identifier + "\n" + expected[0] + "\n" +
                           session_id + "\n" + session_key + "\n")
                run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(directory / "allowed"),
                     "-I", identifier, "-n", NAMESPACE, "-s", str(directory / "signature")], message)
                write(directory / "client.pub", session_key + "\n")
                now = int(time.time())
                expiry = min(now + CERT_SECONDS, item.get("expires_at") or now + CERT_SECONDS)
                if expiry <= now:
                    raise SshError("SSH authorisation expired during certificate authentication.")
                serial = secrets.randbits(63)
                date = lambda stamp: time.strftime("%Y%m%d%H%M%SZ", time.gmtime(stamp))
                run(["/usr/bin/ssh-keygen", "-q", "-s", str(self.directory / "ca"),
                     "-I", "ws-" + identifier + "/" + session_id, "-z", str(serial), "-n", self.principal(item),
                     "-V", date(now) + ":" + date(expiry), "-O", "clear", "-O", "permit-pty",
                     "-O", "source-address=" + item["address"], str(directory / "client.pub")])
                certificate = " ".join((directory / "client-cert.pub").read_text().split()[:2])
            if int(time.time()) >= expiry:
                raise SshError("SSH authorisation or certificate expired during issuance.")
            self.sessions[session_id] = (session_key, expiry)
            self.diagnostic("ws-" + identifier, "ssh.certificate", expires_at=expiry, serial=serial)
            return {"schema": "teliphones-ssh-certificate/2", "workstation_id": identifier,
                    "session_id": session_id, "ssh_public_key": session_key,
                    "certificate": certificate, "expires_at": expiry, "ssh_user": item["ssh_user"],
                    "ssh_host_key": self.host_key(), "ssh_ca_key": self.initialise(), "ssh_port": port(item)}

    def start_api(self, address, interface=None):
        interface = interface or self.interface
        if interface != "tlp-admin" and re.fullmatch(r"tlpw[a-f0-9]{11}", interface) is None:
            raise SshError("Invalid managed SSH API interface.")
        authority = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # No HTTP request/signature material in logs.

            def answer(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                try:
                    if len(self.path) > 128:
                        raise SshError("SSH challenge path is too long.")
                    path = urlsplit(self.path)
                    query = parse_qs(path.query, strict_parsing=True)
                    if path.path != "/ssh/challenge" or set(query) != {"workstation_id"} or len(query["workstation_id"]) != 1:
                        raise SshError("Invalid SSH endpoint.")
                    self.answer(200, authority.challenge(query["workstation_id"][0], self.client_address[0]))
                except (SshError, ValueError) as error:
                    self.answer(403, {"ok": False, "error": str(error)})

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if self.path != "/ssh/certificate" or not 1 <= length <= 8192 or self.headers.get("Transfer-Encoding"):
                        raise SshError("Invalid SSH endpoint payload.")
                    self.connection.settimeout(5)
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise SshError("Incomplete SSH endpoint payload.")
                    self.answer(200, authority.issue(json.loads(body), self.client_address[0]))
                except (SshError, ValueError, UnicodeError) as error:
                    self.answer(403, {"ok": False, "error": str(error)})
                except (OSError, subprocess.SubprocessError):
                    self.answer(503, {"ok": False, "error": "SSH certificate helper unavailable."})

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 8
            slots = threading.BoundedSemaphore(32)

            def server_bind(self):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
                socketserver.TCPServer.server_bind(self)
                self.server_name = address
                self.server_port = API_PORT

            def get_request(self):
                connection, peer = super().get_request()
                connection.settimeout(5)
                return connection, peer

            def process_request(self, connection, peer):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(connection)
                    return
                try:
                    super().process_request(connection, peer)
                except (OSError, RuntimeError):
                    self.slots.release()
                    raise

            def process_request_thread(self, connection, peer):
                try:
                    super().process_request_thread(connection, peer)
                finally:
                    self.slots.release()

        server = Server((address, API_PORT), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.server = server
        self.server_address = address
        return server


def listener(config, address, listen_port, peer, interface):
    """systemd-owned inetd-style sshd children; the listener itself is device-bound."""
    if os.geteuid() != 0:
        raise SshError("The managed SSH listener must run as root.")
    path = Path(config)
    if (path.parent.parent != Path("/etc/teliphones/ssh") or path.name != "sshd_config"
            or re.fullmatch(r"[a-f0-9]{16}", path.parent.name) is None):
        raise SshError("Unexpected managed SSH configuration path.")
    for protected in (path, path.parent, path.parent.parent):
        info = protected.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise SshError("Unsafe managed SSH listener configuration.")
    address = str(ipaddress.IPv4Address(address))
    peer = str(ipaddress.IPv4Address(peer))
    if not SSH_PORT_BASE <= listen_port <= SSH_PORT_BASE + 255:
        raise SshError("Invalid managed SSH listen port.")
    children = []
    if interface != "tlp-admin" and re.fullmatch(r"tlpw[a-f0-9]{11}", interface) is None:
        raise SshError("Invalid managed SSH tunnel interface.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        server.bind((address, listen_port))
        server.listen(8)
        server.settimeout(1)
        notify = os.environ.get("NOTIFY_SOCKET")
        if not notify:
            raise SshError("The SSH listener must be supervised by systemd.")
        if notify.startswith("@"):
            notify = "\0" + notify[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
            notification.connect(notify)
            notification.sendall(b"READY=1")
        while True:
            children = [child for child in children if child.poll() is None]
            try:
                connection, source = server.accept()
            except socket.timeout:
                continue
            with connection:
                if source[0] != peer or len(children) >= 16:
                    continue
                children.append(subprocess.Popen(["/usr/sbin/sshd", "-i", "-e", "-f", str(path)],
                                                 stdin=connection, stdout=connection, env=ENV))


if __name__ == "__main__":
    if len(sys.argv) != 7 or sys.argv[1] != "--listen":
        raise SystemExit("Only the root-owned managed SSH service may invoke this helper.")
    listener(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6])
