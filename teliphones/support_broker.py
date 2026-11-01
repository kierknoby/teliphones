#!/usr/bin/python3
"""Restricted local GUI-to-root bridge; no browser-selected commands or paths."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

STATE = Path("/var/lib/teliphones")
ENROLLMENT = Path("/etc/teliphones")
SOCKET = "/run/teliphones/control.sock"
# Version of the broker status contract; 2 adds operation records and server_time for live GUI monitoring;
# 3 adds administrator-owned workstation pairing (pair/unpair and the "workstations" status block).
PROTOCOL = 3
FWCONSOLE = "/usr/sbin/fwconsole"
ACTIONS = {"status", "authorise", "revoke", "dependencies", "evidence", "configure", "pair", "unpair"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
# Administrator-owned workstation pairing (TELIPHONES Windows application). Separate from the support interface.
WORKSTATION_IFACE = "tlp-admin"
WORKSTATION_TABLE = "teliphones_workstations"
WORKSTATION_POOL = ipaddress.IPv4Network("100.64.0.0/10")
WORKSTATION_EXCLUDED = ipaddress.IPv4Network("100.100.0.0/16")
PAIR_REQUEST_PREFIX = "TELIPHONES-PAIR-REQUEST-1:"
PAIR_RESPONSE_PREFIX = "TELIPHONES-PAIR-RESPONSE-1:"
WG_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=")
WORKSTATION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}")
HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
TOOLS = {"wg": ["/usr/bin/wg", "/usr/sbin/wg"], "ip": ["/usr/sbin/ip", "/sbin/ip"], "nft": ["/usr/sbin/nft", "/sbin/nft"]}


class BrokerError(Exception):
    pass


def read_json(path):
    try:
        with path.open() as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BrokerError("Invalid TELIPHONES state; support must be revoked.")
        return value
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as error:
        raise BrokerError("TELIPHONES state is inaccessible or invalid; inspect quarantine.") from error


def atomic(path, value, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=path.name + ".broker-tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def validate(request):
    if not isinstance(request, dict) or not isinstance(request.get("action"), str) or request["action"] not in ACTIONS:
        raise BrokerError("Unsupported TELIPHONES operation.")
    action = request["action"]
    fields = {
        "status": set(), "revoke": set(), "dependencies": set(),
        "authorise": {"minutes"}, "evidence": {"evidence"},
        "configure": {"url", "certificate", "private_key", "ca", "checker_key"},
        "pair": {"request", "endpoint_host", "listen_port", "mode", "minutes", "ssh"}, "unpair": {"workstation_id"},
    }[action]
    if set(request) - fields - {"action"}:
        raise BrokerError("Unexpected TELIPHONES input.")
    if action == "authorise":
        if not isinstance(request.get("minutes"), str) or not re.fullmatch(r"[0-9]{1,3}", request["minutes"]) or not 5 <= int(request["minutes"]) <= 240:
            raise BrokerError("Duration must be between 5 and 240 minutes.")
    if action == "evidence":
        if not isinstance(request.get("evidence"), str) or len(request["evidence"]) > 32768:
            raise BrokerError("Signed Checker evidence is required (maximum 32 KiB).")
        try:
            if not isinstance(json.loads(request["evidence"]), dict):
                raise ValueError()
        except ValueError as error:
            raise BrokerError("Checker evidence must be a JSON object.") from error
    if action == "configure":
        if any(not isinstance(request.get(field), str) or not 1 <= len(request[field]) <= 16384 for field in fields):
            raise BrokerError("Complete, bounded gateway and Checker enrollment is required.")
        url = urlsplit(request["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/") or any(c in request["url"] for c in '\r\n"'):
            raise BrokerError("Gateway URL must be an HTTPS origin without credentials, paths or query.")
    if action == "pair":
        if any(not isinstance(request.get(field), str) for field in ("request", "endpoint_host", "listen_port", "mode", "ssh")):
            raise BrokerError("Complete workstation pairing details are required.")
        parse_pair_request(request["request"])
        endpoint_host(request["endpoint_host"])
        if not re.fullmatch(r"[0-9]{4,5}", request["listen_port"]) or not 1024 <= int(request["listen_port"]) <= 65535:
            raise BrokerError("The WireGuard UDP port must be between 1024 and 65535.")
        if request["mode"] not in ("temporary", "persistent") or request["ssh"] not in ("0", "1"):
            raise BrokerError("Choose temporary or persistent pairing, and whether SSH is permitted.")
        if request["mode"] == "temporary" and (not isinstance(request.get("minutes"), str) or not re.fullmatch(r"[0-9]{2,4}", request["minutes"])
                                               or not 15 <= int(request["minutes"]) <= 1440):
            raise BrokerError("Temporary pairing must last between 15 and 1440 minutes.")
    if action == "unpair":
        if not isinstance(request.get("workstation_id"), str) or not re.fullmatch(r"[a-f0-9]{16}|all", request["workstation_id"]):
            raise BrokerError("Unknown workstation.")
    return action


def b64url_decode(text):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,4000}", text):
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_pair_request(code):
    """Parse the workstation-generated request; it carries only a public key, a name and a nonce."""
    try:
        code = code.strip()
        if not code.startswith(PAIR_REQUEST_PREFIX) or len(code) > 4096:
            raise ValueError("prefix")
        value = json.loads(b64url_decode(code[len(PAIR_REQUEST_PREFIX):]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise BrokerError("The pairing request is not a TELIPHONES workstation pairing request.") from error
    if (not isinstance(value, dict) or set(value) != {"schema", "workstation", "public_key", "nonce"}
            or value["schema"] != "teliphones-pair-request/1"
            or not isinstance(value["workstation"], str) or not WORKSTATION_NAME.fullmatch(value["workstation"])
            or not isinstance(value["public_key"], str) or not WG_PUBLIC_KEY.fullmatch(value["public_key"])
            or base64.b64decode(value["public_key"]) == bytes(32)
            or not isinstance(value["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{22}", value["nonce"])):
        raise BrokerError("The pairing request is malformed or incomplete.")
    return value


def endpoint_host(host):
    host = host.strip()
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise BrokerError("The public WireGuard address must be reachable by the workstation.")
        return "[" + str(address) + "]" if address.version == 6 else str(address)
    except ValueError:
        if HOSTNAME.fullmatch(host) and not re.fullmatch(r"[0-9.]+", host):
            return host.lower()
    raise BrokerError("Enter the PBX public hostname or IP address that the workstation will use for WireGuard.")


def key_fingerprint(public_key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public_key)).digest()).decode().rstrip("=")[:16]


def workstation_ruleset(pbx_address, ssh_sources):
    """nftables policy for tlp-admin: PBX GUI (80/443) for every paired workstation, SSH only where approved,
    no forwarding into other networks. Applied atomically and before any peer is added."""
    lines = ["add table inet " + WORKSTATION_TABLE, "delete table inet " + WORKSTATION_TABLE,
             "table inet " + WORKSTATION_TABLE + " {",
             "    chain input {", "        type filter hook input priority -10; policy accept;",
             '        iifname "%s" ip daddr %s tcp dport { 80, 443 } accept' % (WORKSTATION_IFACE, pbx_address)]
    if ssh_sources:
        lines.append('        iifname "%s" ip saddr { %s } ip daddr %s tcp dport 22 accept' % (WORKSTATION_IFACE, ", ".join(sorted(ssh_sources)), pbx_address))
    lines += ['        iifname "%s" ip daddr %s icmp type echo-request accept' % (WORKSTATION_IFACE, pbx_address),
              '        iifname "%s" drop' % WORKSTATION_IFACE, "    }",
              "    chain forward {", "        type filter hook forward priority -10; policy accept;",
              '        iifname "%s" drop' % WORKSTATION_IFACE, '        oifname "%s" drop' % WORKSTATION_IFACE, "    }", "}"]
    return "\n".join(lines) + "\n"


def permitted_peer(uid, web_uid):
    return uid == web_uid and web_uid != 0


class Broker:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.phase = "Disconnected"
        self.error = ""
        self.running = False
        self.revoking = False
        # Progress of the most recent web operation, reported read-only through "status".
        self.operation = None
        # Workstation pairing is independent of support sessions and serialised separately.
        self.wslock = threading.Lock()
        self.workstation_error = ""

    def begin(self, action, stage):
        self.operation = {"id": uuid.uuid4().hex, "action": action, "state": "running", "stage": stage,
                          "message": "", "started_at": int(time.time()), "finished_at": None}
        return self.operation["id"]

    def stage(self, operation_id, stage):
        if operation_id is not None and self.operation and self.operation["id"] == operation_id:
            self.operation["stage"] = stage

    def finish(self, operation_id, succeeded, message):
        # A superseded operation (for example, cancelled by revocation) never overwrites the newer record.
        if operation_id is not None and self.operation and self.operation["id"] == operation_id:
            self.operation.update({"state": "succeeded" if succeeded else "failed", "stage": "",
                                   "message": message, "finished_at": int(time.time())})

    def audit(self, action, uid, result):
        with open("/var/log/teliphones-web.log", "a") as handle:
            handle.write(json.dumps({"time": int(time.time()), "peer_uid": uid, "action": action, "result": result}) + "\n")

    def command(self, arguments, timeout=45, cancellable=True):
        with subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=ENV, start_new_session=True) as process:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if (cancellable and self.cancel.is_set()) or time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    raise BrokerError("Operation interrupted or timed out; local revocation and cleanup required.")
                time.sleep(0.1)
            if process.returncode:
                raise BrokerError("TELIPHONES operation failed: " + arguments[2] + ". Inspect TELIPHONES audit and quarantine; no success is assumed.")

    def cli(self, action, *options, cancellable=True):
        allowed = {"authorise", "provision", "connect-confirm", "attest", "checker-request", "checker-accept", "open", "revoke", "reconcile"}
        if action not in allowed:
            raise BrokerError("Invalid broker command.")
        self.command([FWCONSOLE, "teliphones", action, *options], cancellable=cancellable)

    def readiness(self):
        paths = {
            "WireGuard wg": ["/usr/bin/wg", "/usr/sbin/wg"],
            "iproute2": ["/usr/sbin/ip"], "Temporary SSH server": ["/usr/sbin/sshd", "/usr/bin/sshd"],
            "SSH key generation": ["/usr/bin/ssh-keygen"], "systemd-run": ["/usr/bin/systemd-run"],
            "systemctl": ["/usr/bin/systemctl"], "Checker Python": ["/usr/bin/python3"],
            "FreePBX Console": [FWCONSOLE],
        }
        result = {name: any(os.access(path, os.X_OK) for path in choices) for name, choices in paths.items()}
        result["Gateway enrollment"] = all(path.is_file() and os.access(path, os.R_OK) for path in
                                           [Path("/etc/teliphones-connect.conf"), ENROLLMENT / "connect-client.crt",
                                            ENROLLMENT / "connect-client.key", ENROLLMENT / "connect-ca.crt"])
        if result["Gateway enrollment"]:
            config = Path("/etc/teliphones-connect.conf").read_text()
            result["Gateway enrollment"] = re.search(r'^CONNECT_URL="https://[^"\r\n]+"$', config, re.MULTILINE) is not None
        result["Checker trusted public key"] = (ENROLLMENT / "checker-ecdsa-p256.pub").is_file()
        try:
            check = subprocess.run(["/usr/bin/php", "-r",
                                    "exit(extension_loaded('curl')&&extension_loaded('openssl')&&extension_loaded('json')"
                                    "&&function_exists('posix_geteuid')&&function_exists('posix_kill')"
                                    "&&function_exists('posix_getpwnam')&&function_exists('exec')?0:1);"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, env=ENV)
            result["Required PHP functions / extensions"] = check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            result["Required PHP functions / extensions"] = False
        return result

    def status(self):
        session = read_json(STATE / "session.json")
        remote = read_json(STATE / "connect.json")
        readiness = self.readiness()
        enabled = not (STATE / "disabled").exists()
        quarantine = (STATE / "quarantine.json").exists()
        phase = self.phase if self.running or self.revoking else {
            "ready": "Connected", "locally_verified": "Connecting",
            "verified": "Connecting", "peer_configured": "Connecting",
            "connected": "Connecting", "authorised": "Authorising",
        }.get(session.get("state"), "Disconnected")
        if quarantine:
            phase = "Verification failed / quarantined"
        elif session and int(session.get("expires_at", 0)) <= time.time():
            phase = "Revoking (session expired; cleanup not yet confirmed)"
        elif not session and not self.running and not self.revoking:
            phase = "Not configured" if not readiness["Gateway enrollment"] else ("Ready" if all(readiness.values()) and enabled else "Missing dependency")
        if session.get("state") == "ready" and phase == "Connected":
            adapter = read_json(STATE / "adapter.json")
            checker = read_json(STATE / "checker.json")
            if (adapter.get("session_id") != session.get("session_id") or not adapter.get("support_ready")
                    or checker.get("session_id") != session.get("session_id") or not checker.get("accepted")):
                phase = "Verification failed / access not confirmed"
        fingerprint = None
        key = remote.get("ssh_public_key", "").split()
        if len(key) >= 2:
            try:
                fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key[1], validate=True)).digest()).decode().rstrip("=")
            except ValueError:
                fingerprint = "Invalid gateway SSH identity"
        return {"protocol": PROTOCOL, "phase": phase, "readiness": readiness, "enabled": enabled,
                "operation": dict(self.operation) if self.operation else None, "server_time": int(time.time()),
                "can_authorise": all(readiness.values()) and enabled and not session and not quarantine and not self.running and not self.revoking,
                "session": {key: session[key] for key in ("session_id", "state", "expires_at") if key in session},
                "access_verified": phase == "Connected",
                "engineer": fingerprint, "challenge": read_json(STATE / "checker-challenge.json") if session.get("state") == "locally_verified" else None,
                "workstations": self.workstation_status()}

    # ----- Administrator-owned workstation pairing -----

    def tool(self, name):
        for path in TOOLS[name]:
            if os.access(path, os.X_OK):
                return path
        raise BrokerError("Workstation pairing requires %s, which is not installed." % {"wg": "WireGuard tools (wg)", "ip": "iproute2 (ip)", "nft": "nftables (nft)"}[name])

    def run(self, arguments, stdin=None, check=True):
        result = subprocess.run(arguments, input=stdin, capture_output=True, text=True, timeout=20, env=ENV)
        if result.returncode and check:
            raise BrokerError("Workstation network operation failed: " + os.path.basename(arguments[0]) + " " + arguments[1] + ".")
        return result.stdout if result.returncode == 0 else None

    def workstation_state(self):
        """Load the pairing state and drop expired temporary pairings. Returns (state, changed)."""
        state = read_json(STATE / "workstations.json")
        items = state.get("workstations") if isinstance(state.get("workstations"), list) else []
        now = int(time.time())
        valid = [item for item in items if isinstance(item, dict) and WG_PUBLIC_KEY.fullmatch(str(item.get("public_key", "")))
                 and (item.get("mode") == "persistent" or (isinstance(item.get("expires_at"), int) and item["expires_at"] > now))]
        state = {"subnet": state.get("subnet") if isinstance(state.get("subnet"), str) else None,
                 "listen_port": state.get("listen_port") if isinstance(state.get("listen_port"), int) else None,
                 "workstations": valid}
        return state, len(valid) != len(items)

    def save_workstations(self, state):
        atomic(STATE / "workstations.json", json.dumps(state, indent=2, sort_keys=True))

    def choose_subnet(self):
        used = []
        for arguments in ([self.tool("ip"), "-4", "-o", "address", "show"], [self.tool("ip"), "-4", "route", "show", "table", "all"]):
            for token in (self.run(arguments) or "").split():
                try:
                    used.append(ipaddress.IPv4Network(token, strict=False))
                except ValueError:
                    pass
        candidates = [net for net in WORKSTATION_POOL.subnets(new_prefix=24) if not net.overlaps(WORKSTATION_EXCLUDED)]
        for _ in range(64):
            candidate = secrets.choice(candidates)
            if not any(candidate.overlaps(net) for net in used if net.prefixlen > 0):
                return str(candidate)
        raise BrokerError("No unused private address range is available for workstation pairing.")

    def server_public_key(self):
        path = ENROLLMENT / "workstation-wg.key"
        ENROLLMENT.mkdir(mode=0o700, exist_ok=True)
        if not path.exists():
            atomic(path, self.run([self.tool("wg"), "genkey"]).strip() + "\n")
        if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
            raise BrokerError("The workstation WireGuard key must be a private, root-owned file.")
        public = self.run([self.tool("wg"), "pubkey"], stdin=path.read_text()).strip()
        if not WG_PUBLIC_KEY.fullmatch(public):
            raise BrokerError("The PBX workstation WireGuard identity could not be derived.")
        return public

    def teardown_workstations(self):
        for name in ("ip", "nft"):
            try:
                self.tool(name)
            except BrokerError:
                continue
            if name == "ip":
                self.run([self.tool("ip"), "link", "del", "dev", WORKSTATION_IFACE], check=False)
            else:
                self.run([self.tool("nft"), "delete", "table", "inet", WORKSTATION_TABLE], check=False)

    def apply_workstations(self, state):
        """Make the kernel match the state. Fails closed: any error removes all workstation access."""
        try:
            if not state["workstations"]:
                self.teardown_workstations()
                self.workstation_error = ""
                return
            network = ipaddress.IPv4Network(state["subnet"])
            pbx = str(network[1])
            wg, ip = self.tool("wg"), self.tool("ip")
            # Port policy first, so no peer is ever reachable without it.
            self.run([self.tool("nft"), "-f", "-"], stdin=workstation_ruleset(pbx, [item["address"].split("/")[0] for item in state["workstations"] if item.get("ssh") is True]))
            if self.run([ip, "link", "show", "dev", WORKSTATION_IFACE], check=False) is None:
                self.run([ip, "link", "add", "dev", WORKSTATION_IFACE, "type", "wireguard"])
            self.server_public_key()
            self.run([wg, "set", WORKSTATION_IFACE, "listen-port", str(state["listen_port"]), "private-key", str(ENROLLMENT / "workstation-wg.key")])
            self.run([ip, "address", "replace", pbx + "/" + str(network.prefixlen), "dev", WORKSTATION_IFACE])
            wanted = {item["public_key"]: item["address"] for item in state["workstations"]}
            for peer in (self.run([wg, "show", WORKSTATION_IFACE, "peers"]) or "").split():
                if peer not in wanted:
                    self.run([wg, "set", WORKSTATION_IFACE, "peer", peer, "remove"])
            for key, address in wanted.items():
                self.run([wg, "set", WORKSTATION_IFACE, "peer", key, "allowed-ips", address])
            self.run([ip, "link", "set", "up", "dev", WORKSTATION_IFACE])
            self.workstation_error = ""
        except (BrokerError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            self.teardown_workstations()
            self.workstation_error = "Workstation access could not be applied and was removed: " + (str(error) if isinstance(error, BrokerError) else "network configuration failed.")
            raise BrokerError(self.workstation_error) from error

    def restore_workstations(self):
        """Broker start: re-create persistent and unexpired temporary pairings, failing closed."""
        with self.wslock:
            state, changed = self.workstation_state()
            if changed:
                self.save_workstations(state)
            try:
                self.apply_workstations(state)
            except BrokerError:
                pass

    def expire_workstations(self):
        with self.wslock:
            state, changed = self.workstation_state()
            if changed:
                self.save_workstations(state)
                self.audit("workstation-expired", 0, "completed")
                try:
                    self.apply_workstations(state)
                except BrokerError:
                    pass

    def pair(self, request, uid):
        if (STATE / "disabled").exists():
            raise BrokerError("TELIPHONES is disabled; workstation pairing is unavailable.")
        pairing = parse_pair_request(request["request"])
        host, port = endpoint_host(request["endpoint_host"]), int(request["listen_port"])
        for name in TOOLS:
            self.tool(name)
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        if state["workstations"] and state["listen_port"] != port:
            raise BrokerError("Paired workstations already use UDP port %d. Use the same port, or revoke all workstations first." % state["listen_port"])
        if not state["workstations"] or not state["subnet"]:
            state["subnet"] = self.choose_subnet()
        state["listen_port"] = port
        network = ipaddress.IPv4Network(state["subnet"])
        existing = next((item for item in state["workstations"] if item["public_key"] == pairing["public_key"]), None)
        if existing:
            state["workstations"].remove(existing)
            address = existing["address"]
        else:
            taken = {item["address"] for item in state["workstations"]}
            free = [str(host_address) + "/32" for host_address in list(network.hosts())[1:] if str(host_address) + "/32" not in taken]
            if not free:
                raise BrokerError("No workstation addresses remain; revoke unused workstations first.")
            address = free[0]
        now = int(time.time())
        entry = {"id": existing["id"] if existing else secrets.token_hex(8), "name": pairing["workstation"], "public_key": pairing["public_key"],
                 "address": address, "mode": request["mode"], "ssh": request["ssh"] == "1", "created_at": now,
                 "expires_at": now + int(request["minutes"]) * 60 if request["mode"] == "temporary" else None}
        state["workstations"].append(entry)
        self.save_workstations(state)
        try:
            self.apply_workstations(state)
            pbx_public = self.server_public_key()
        except BrokerError:
            self.save_workstations(previous)
            try:
                self.apply_workstations(previous)
            except BrokerError:
                pass
            raise
        self.audit("pair", uid, "completed")
        pbx_address = str(network[1])
        response = {"schema": "teliphones-pair-response/1", "nonce": pairing["nonce"], "workstation_id": entry["id"],
                    "workstation_public_key": entry["public_key"], "address": address, "pbx_address": pbx_address,
                    "pbx_name": re.sub(r"[^A-Za-z0-9._-]", "", socket.gethostname())[:64] or "FreePBX",
                    "pbx_public_key": pbx_public, "endpoint": host + ":" + str(port), "mode": entry["mode"],
                    "expires_at": entry["expires_at"], "ssh": entry["ssh"], "gui_url": "http://" + pbx_address + "/admin/"}
        return PAIR_RESPONSE_PREFIX + b64url_encode(json.dumps(response, separators=(",", ":"), sort_keys=True).encode()), entry

    def unpair(self, request, uid):
        state, _ = self.workstation_state()
        before = len(state["workstations"])
        state["workstations"] = [] if request["workstation_id"] == "all" else [item for item in state["workstations"] if item["id"] != request["workstation_id"]]
        if len(state["workstations"]) == before and request["workstation_id"] != "all":
            raise BrokerError("Unknown workstation; it may already have been revoked or expired.")
        self.save_workstations(state)
        try:
            self.apply_workstations(state)
        except BrokerError:
            # apply_workstations has already removed all workstation access, so revocation still holds.
            pass
        self.audit("unpair", uid, "completed")

    def workstation_status(self):
        state, _ = self.workstation_state()
        requirements = {name: any(os.access(path, os.X_OK) for path in paths) for name, paths in TOOLS.items()}
        return {"ready": all(requirements.values()), "requirements": requirements, "error": self.workstation_error,
                "listen_port": state["listen_port"],
                "pbx_address": str(ipaddress.IPv4Network(state["subnet"])[1]) if state["subnet"] and state["workstations"] else None,
                "items": [{"id": item["id"], "name": item["name"], "address": item["address"], "mode": item["mode"],
                           "ssh": item.get("ssh") is True, "created_at": item.get("created_at"), "expires_at": item.get("expires_at"),
                           "fingerprint": key_fingerprint(item["public_key"])} for item in state["workstations"]]}

    def configure(self, request):
        if read_json(STATE / "session.json") or read_json(STATE / "connect.json"):
            raise BrokerError("Revoke the existing session before changing enrollment.")
        ENROLLMENT.mkdir(mode=0o700, exist_ok=True)
        if ENROLLMENT.is_symlink() or ENROLLMENT.stat().st_uid != 0:
            raise BrokerError("Enrollment directory is not root-owned.")
        # Validate in a root-only staging directory; never echo credential values.
        with tempfile.TemporaryDirectory(dir=ENROLLMENT) as directory:
            stage = Path(directory)
            names = {"certificate": "connect-client.crt", "private_key": "connect-client.key",
                     "ca": "connect-ca.crt", "checker_key": "checker-ecdsa-p256.pub"}
            for field, name in names.items():
                atomic(stage / name, request[field])
            for name in ("connect-client.crt", "connect-ca.crt"):
                self.command(["/usr/bin/openssl", "x509", "-in", str(stage / name), "-checkend", "0", "-noout"])
            self.command(["/usr/bin/openssl", "pkey", "-in", str(stage / "connect-client.key"), "-check", "-noout"])
            certificate_key = subprocess.run(["/usr/bin/openssl", "x509", "-in", str(stage / "connect-client.crt"), "-pubkey", "-noout"],
                                             capture_output=True, timeout=5, env=ENV)
            private_public_key = subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(stage / "connect-client.key"), "-pubout"],
                                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=ENV)
            if certificate_key.returncode or private_public_key.returncode or certificate_key.stdout != private_public_key.stdout:
                raise BrokerError("Customer certificate and private key do not match.")
            key_check = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-in", str(stage / "checker-ecdsa-p256.pub"), "-text", "-noout"],
                                       capture_output=True, timeout=5, env=ENV)
            if key_check.returncode or b"prime256v1" not in key_check.stdout:
                raise BrokerError("Checker key must be an ECDSA P-256 public key.")
            for name in names.values():
                os.replace(stage / name, ENROLLMENT / name)
        atomic(Path("/etc/teliphones-connect.conf"),
               'CONNECT_URL="' + request["url"].rstrip("/") + '"\n'
               'CLIENT_CERT=/etc/teliphones/connect-client.crt\nCLIENT_KEY=/etc/teliphones/connect-client.key\nCA_CERT=/etc/teliphones/connect-ca.crt\n')

    def work(self, request, uid, operation_id=None):
        action = request["action"]
        stage = lambda text: self.stage(operation_id, text)
        try:
            if action == "authorise":
                self.phase = "Authorising"
                stage("Authorising remote support")
                self.cli("authorise", "--minutes=" + request["minutes"], "--topology=on-pbx")
                self.phase = "Connecting"
                stage("Provisioning WireGuard connection")
                self.cli("provision")
                stage("Establishing WireGuard connection")
                deadline = time.monotonic() + 60
                while True:
                    try:
                        self.cli("connect-confirm")
                        break
                    except BrokerError:
                        if self.cancel.is_set() or time.monotonic() >= deadline:
                            raise
                        self.cancel.wait(2)
                stage("Verifying the connection locally")
                self.cli("attest")
                stage("Requesting Checker challenge")
                self.cli("checker-request")
                message = "Remote support authorised and the WireGuard connection verified locally. Submit independent Checker evidence to open access."
            elif action == "evidence":
                session = read_json(STATE / "session.json")
                if session.get("state") != "locally_verified" or int(session.get("expires_at", 0)) <= time.time():
                    raise BrokerError("No current verified session is awaiting Checker evidence.")
                evidence = STATE / "web-checker-evidence.json"
                atomic(evidence, request["evidence"])
                try:
                    stage("Verifying Checker evidence")
                    self.cli("checker-accept", "--evidence-file=" + str(evidence))
                    stage("Opening approved access")
                    self.cli("open")
                    message = "Checker evidence accepted and approved access opened."
                finally:
                    if evidence.exists():
                        evidence.unlink()
            elif action == "dependencies":
                if read_json(STATE / "session.json"):
                    raise BrokerError("Revoke support before installing dependencies.")
                stage("Installing WireGuard tools")
                self.command(["/usr/bin/apt-get", "-y", "--no-install-recommends", "install", "wireguard-tools"], timeout=300, cancellable=False)
                stage("Checking WireGuard tools")
                if self.readiness().get("WireGuard wg") is not True:
                    raise BrokerError("wireguard-tools installation finished, but the wg executable could not be verified.")
                message = "WireGuard tools installed; the wg executable was verified."
            elif action == "configure":
                stage("Validating gateway enrollment")
                self.configure(request)
                message = "Gateway enrollment validated and saved."
            self.audit(action, uid, "completed")
            self.finish(operation_id, True, message)
        except (BrokerError, OSError, ValueError, subprocess.TimeoutExpired) as error:
            self.error = str(error) if isinstance(error, BrokerError) else "TELIPHONES operation failed; inspect broker service logs."
            self.audit(action, uid, "failed")
            failure = self.error
            if action in ("authorise", "evidence"):
                stage("Cleaning up after failure")
                self.cleanup(uid, quarantine=True)
                if self.error != failure:
                    failure += " Cleanup also failed: " + self.error
            self.finish(operation_id, False, failure)
        finally:
            self.running = False
            self.lock.release()

    def cleanup(self, uid, quarantine=False):
        self.phase = "Revoking"
        try:
            self.cli("revoke", cancellable=False)
            self.phase = "Disconnected"
            self.audit("revoke", uid, "completed")
        except (BrokerError, OSError) as error:
            quarantine = True
            self.error = str(error)
            self.audit("revoke", uid, "cleanup-failed")
        if quarantine:
            atomic(STATE / "quarantine.json", json.dumps({"reason": "web-operation-or-cleanup-failed", "time": int(time.time())}))

    def dispatch(self, request, uid):
        action = validate(request)
        if action == "status":
            return {"ok": True, "status": self.status(), "error": self.error}
        if action == "pair":
            with self.wslock:
                code, entry = self.pair(request, uid)
            return {"ok": True, "pairing_response": code,
                    "message": "Workstation '%s' paired. Paste the pairing response into the TELIPHONES Windows application." % entry["name"]}
        if action == "unpair":
            with self.wslock:
                self.unpair(request, uid)
            return {"ok": True, "message": "Workstation access revoked." if request["workstation_id"] != "all" else "All workstation access revoked."}
        if action == "revoke":
            self.cancel.set()
            self.revoking = True
            self.phase = "Revoking"
            revocation = self.begin("revoke", "Cancelling the running operation" if self.running else "Revoking remote support")
            def revoke():
                with self.lock:
                    self.running = True
                    self.stage(revocation, "Revoking remote support")
                    try:
                        self.error = ""
                        self.cleanup(uid)
                        if self.error:
                            self.finish(revocation, False, self.error + " TELIPHONES remains quarantined; revocation may be retried.")
                        else:
                            self.finish(revocation, True, "Remote support revoked and local cleanup confirmed.")
                    finally:
                        self.running = False
                        self.revoking = False
            threading.Thread(target=revoke, daemon=True).start()
            return {"ok": True, "operation_id": revocation, "message": "Revocation started. Monitoring progress automatically…"}
        if not self.lock.acquire(blocking=False):
            raise BrokerError("A TELIPHONES operation is already running. Revocation remains available.")
        try:
            if self.revoking:
                raise BrokerError("Revocation is in progress.")
            if action == "dependencies" and self.readiness().get("WireGuard wg") is True:
                raise BrokerError("WireGuard tools are already installed.")
            if action == "authorise" and not self.status()["can_authorise"]:
                raise BrokerError("TELIPHONES is not ready, already active, disabled or quarantined.")
            self.cancel.clear()
            self.running = True
            self.error = ""
            self.audit(action, uid, "approved")
            operation_id = self.begin(action, {"authorise": "Authorising remote support", "evidence": "Verifying Checker evidence",
                                               "dependencies": "Installing WireGuard tools", "configure": "Validating gateway enrollment"}[action])
            threading.Thread(target=self.work, args=(request, uid, operation_id), daemon=True).start()
        except Exception:
            self.lock.release()
            raise
        return {"ok": True, "operation_id": operation_id, "message": "TELIPHONES operation started. Monitoring progress automatically…"}


def serve():
    if os.geteuid() != 0:
        raise SystemExit("TELIPHONES broker requires a root Module Admin bootstrap.")
    os.umask(0o077)
    user = pwd.getpwnam("asterisk")
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise SystemExit("TELIPHONES state directory must be root-owned and private.")
    broker = Broker()
    # Interrupted broker jobs never resume/open access implicitly.
    broker.cleanup(0, quarantine=(STATE / "session.json").exists() or (STATE / "connect.json").exists())
    # Workstation access exists only while the broker runs and can enforce expiry.
    broker.restore_workstations()

    def stop(signum, frame):
        broker.teardown_workstations()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)

    def expiry():
        while True:
            time.sleep(15)
            try:
                broker.expire_workstations()
            except Exception:
                broker.teardown_workstations()
    threading.Thread(target=expiry, daemon=True).start()
    Path("/run/teliphones").mkdir(mode=0o750, exist_ok=True)
    if Path("/run/teliphones").is_symlink() or Path("/run/teliphones").stat().st_uid != 0:
        raise SystemExit("TELIPHONES socket directory must be root-owned.")
    os.chown("/run/teliphones", 0, user.pw_gid)
    os.chmod("/run/teliphones", 0o750)
    if os.path.lexists(SOCKET):
        os.unlink(SOCKET)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET)
    os.chown(SOCKET, 0, user.pw_gid)
    os.chmod(SOCKET, 0o660)
    server.listen(8)

    def handle(connection):
        with connection:
            connection.settimeout(5)
            uid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            try:
                if not permitted_peer(uid, user.pw_uid):
                    raise BrokerError("Only the configured FreePBX web service account may contact this broker.")
                data = bytearray()
                while b"\n" not in data and len(data) <= 100000:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > 100000 or b"\n" not in data:
                    raise BrokerError("Invalid or oversized request.")
                response = broker.dispatch(json.loads(data.split(b"\n", 1)[0]), uid)
            except (BrokerError, ValueError, OSError) as error:
                response = {"ok": False, "error": str(error) if isinstance(error, BrokerError) else "TELIPHONES request failed."}
            connection.sendall(json.dumps(response).encode() + b"\n")

    while True:
        connection, _ = server.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


if __name__ == "__main__":
    serve()
