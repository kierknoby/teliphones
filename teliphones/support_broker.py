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
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import sys
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
WORKSTATION_OWNER = "TELIPHONES workstation enforcement v1"
WORKSTATION_POOL = ipaddress.IPv4Network("100.64.0.0/10")
WORKSTATION_EXCLUDED = ipaddress.IPv4Network("100.100.0.0/16")
PAIR_REQUEST_PREFIX = "TELIPHONES-PAIR-REQUEST-1:"
PAIR_RESPONSE_PREFIX = "TELIPHONES-PAIR-RESPONSE-1:"
WG_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=")
WORKSTATION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}")
HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
TOOLS = {"wg": ["/usr/bin/wg", "/usr/sbin/wg"], "ip": ["/usr/sbin/ip", "/sbin/ip"], "nft": ["/usr/sbin/nft", "/sbin/nft"]}
# FreePBX Firewall integration. An nft ACCEPT in TELIPHONES' own table is not final: FreePBX Firewall's
# separate iptables INPUT processing can still drop the packet. A broker-owned chain, jumped to from INPUT
# immediately before the FreePBX hook (and after Fail2Ban hooks), accepts only exact authorised flows;
# everything else returns to normal FreePBX processing. FreePBX's own chains are never modified.
IPTABLES = ["/usr/sbin/iptables", "/sbin/iptables"]
FREEPBX_HOOK = "fpbxfirewall"
# Fail2Ban hook chains: "fail2ban-<jail>" (FreePBX 17, e.g. fail2ban-SIP, fail2ban-PBX-GUI) and "f2b-<jail>"
# (upstream default). Prefixes are matched case-insensitively so no Fail2Ban hook can be overlooked.
FAIL2BAN_PREFIXES = ("fail2ban-", "f2b-")
INTEGRATION_CHAIN = "teliphones-ws"
INTEGRATION_MARK = "TELIPHONES workstation integration v1"
INTEGRATION_JUMP = {"i": WORKSTATION_IFACE, "comment": INTEGRATION_MARK, "j": INTEGRATION_CHAIN}


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
    """Human-readable policy illustration; enforcement uses workstation_policy JSON."""
    lines = ["table inet " + WORKSTATION_TABLE + " {",
             '    comment "%s";' % WORKSTATION_OWNER,
             "    chain input {", "        type filter hook input priority -10; policy accept;",
             '        iifname "%s" ip daddr %s tcp dport { 80, 443 } accept' % (WORKSTATION_IFACE, pbx_address)]
    if ssh_sources:
        lines.append('        iifname "%s" ip saddr { %s } ip daddr %s tcp dport 22 accept' % (WORKSTATION_IFACE, ", ".join(sorted(ssh_sources)), pbx_address))
    lines += ['        iifname "%s" ip daddr %s icmp type echo-request accept' % (WORKSTATION_IFACE, pbx_address),
              '        iifname "%s" drop' % WORKSTATION_IFACE, "    }",
              "    chain forward {", "        type filter hook forward priority -10; policy accept;",
              '        iifname "%s" drop' % WORKSTATION_IFACE, '        oifname "%s" drop' % WORKSTATION_IFACE, "    }", "}"]
    return "\n".join(lines) + "\n"


def workstation_policy(pbx_address, ssh_sources):
    """Offline expected nft JSON, deliberately without sets, counters or implicit expressions."""
    family = {"family": "inet", "table": WORKSTATION_TABLE}
    objects = [{"table": {"family": "inet", "name": WORKSTATION_TABLE, "comment": WORKSTATION_OWNER}}]

    def match(left, right):
        return {"match": {"op": "==", "left": left, "right": right}}

    def meta(key):
        return {"meta": {"key": key}}

    def payload(protocol, field):
        return {"payload": {"protocol": protocol, "field": field}}

    def rule(chain, expressions):
        objects.append({"rule": {**family, "chain": chain, "expr": expressions}})

    incoming = match(meta("iifname"), WORKSTATION_IFACE)
    destination = match(payload("ip", "daddr"), str(ipaddress.IPv4Address(pbx_address)))
    objects.append({"chain": {**family, "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}})
    for port in (80, 443):
        rule("input", [incoming, destination, match(payload("tcp", "dport"), port), {"accept": None}])
    for source in sorted(set(ssh_sources)):
        rule("input", [incoming, match(payload("ip", "saddr"), str(ipaddress.IPv4Address(source))),
                       destination, match(payload("tcp", "dport"), 22), {"accept": None}])
    rule("input", [incoming, destination, match(payload("icmp", "type"), "echo-request"), {"accept": None}])
    rule("input", [incoming, {"drop": None}])
    objects.append({"chain": {**family, "name": "forward", "type": "filter", "hook": "forward", "prio": -10, "policy": "accept"}})
    rule("forward", [incoming, {"drop": None}])
    rule("forward", [match(meta("oifname"), WORKSTATION_IFACE), {"drop": None}])
    return {"nftables": objects}


def iptables_rule(tokens):
    """Canonical form of the only match options TELIPHONES writes; anything else is not recognised (None)."""
    options = {"-s": "s", "-d": "d", "-i": "i", "-p": "p", "--dport": "dport", "--comment": "comment", "-j": "j"}
    rule, index = {}, 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-m" and index + 1 < len(tokens) and tokens[index + 1] in ("tcp", "comment"):
            index += 2
            continue
        if token not in options or index + 1 >= len(tokens) or options[token] in rule:
            return None
        rule[options[token]] = tokens[index + 1]
        index += 2
    return rule


def iptables_target(tokens):
    target = None
    for index, token in enumerate(tokens[:-1]):
        if token in ("-j", "-g"):
            target = tokens[index + 1]
    return target


def is_fail2ban_hook(target):
    return isinstance(target, str) and target.lower().startswith(FAIL2BAN_PREFIXES)


def integration_placement_valid(hooks, bans, jumps):
    """Exactly one jump, immediately before the first FreePBX hook, after every Fail2Ban hook."""
    return (len(jumps) == 1 and bool(hooks) and jumps[0] == hooks[0] - 1
            and all(index < jumps[0] for index in bans))


def iptables_arguments(rule):
    arguments = []
    for option, key in (("-s", "s"), ("-d", "d"), ("-i", "i"), ("-p", "p")):
        if key in rule:
            arguments += [option, rule[key]]
    if "dport" in rule:
        arguments += ["-m", "tcp", "--dport", rule["dport"]]
    return arguments + ["-m", "comment", "--comment", rule["comment"], "-j", rule["j"]]


def integration_rules(pbx_address, workstations):
    """Exact per-peer ACCEPTs: TCP 80/443, plus 22 only for SSH-approved peers. Nothing else is trusted."""
    pbx = str(ipaddress.IPv4Address(pbx_address)) + "/32"
    rules = []
    for item in sorted(workstations, key=lambda entry: ipaddress.IPv4Network(entry["address"])):
        source = ipaddress.IPv4Network(item["address"])
        if source.prefixlen != 32:
            raise BrokerError("Workstation integration requires a single-address peer.")
        for port in (80, 443, 22) if item.get("ssh") is True else (80, 443):
            rules.append({"s": str(source), "d": pbx, "i": WORKSTATION_IFACE, "p": "tcp", "dport": str(port),
                          "comment": INTEGRATION_MARK, "j": "ACCEPT"})
    rules.append({"comment": INTEGRATION_MARK, "j": "RETURN"})
    return rules


def nft_objects(document):
    """Ignore only kernel-assigned object handles and nft's envelope metadata.

    Everything else (including extra objects, expressions, policies and rule order)
    participates in equality. Unsupported JSON fails closed rather than guessing.
    """
    if not isinstance(document, dict) or set(document) != {"nftables"} or not isinstance(document["nftables"], list):
        raise BrokerError("Invalid nftables JSON.")
    objects = []
    for entry in document["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise BrokerError("Invalid nftables object.")
        kind, value = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if kind not in ("table", "chain", "rule") or not isinstance(value, dict):
            raise BrokerError("Unexpected workstation firewall object.")
        identity = {"table": ("family", "name"), "chain": ("family", "table", "name"), "rule": ("family", "table", "chain")}[kind]
        if any(not isinstance(value.get(key), str) for key in identity) or (kind == "rule" and not isinstance(value.get("expr"), list)):
            raise BrokerError("Invalid workstation firewall identity or expressions.")
        objects.append({kind: {key: item for key, item in value.items() if key != "handle"}})
    return objects


def policy_equal(actual, expected):
    # nft emits each chain followed by its rules; keep rule order, but not chain enumeration order.
    def canonical(document):
        objects = nft_objects(document)
        tables = [item["table"] for item in objects if "table" in item]
        chains = [item["chain"] for item in objects if "chain" in item]
        rules = [item["rule"] for item in objects if "rule" in item]
        return [tables, sorted(chains, key=lambda item: item["name"]),
                {name: [rule for rule in rules if rule["chain"] == name] for name in sorted({rule["chain"] for rule in rules})}]
    return json.dumps(canonical(actual), sort_keys=True) == json.dumps(canonical(expected), sort_keys=True)


class NftMonitor:
    """One local netlink event stream. Own transactions are acknowledged before admission."""
    def __init__(self, broker):
        self.broker = broker
        self.condition = threading.Condition()
        self.pending = []
        self.failed = ""
        self.process = broker.run([broker.tool("nft"), "-j", "monitor", "ruleset"], stream=True)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def alive(self):
        return not self.failed and self.process.poll() is None and self.thread.is_alive()

    def expect(self, events):
        with self.condition:
            if not self.alive() or self.pending:
                raise BrokerError("Workstation nft monitor is unavailable or has an unacknowledged transaction.")
            self.pending = events[:]

    def wait(self):
        with self.condition:
            if not self.condition.wait_for(lambda: not self.pending or not self.alive(), timeout=3) or not self.alive():
                raise BrokerError("Workstation nft monitor registration/transaction could not be verified.")

    @staticmethod
    def signature(action, kind, value):
        if action == "create":
            action = "add"
        # Delete notifications may contain only identity and handle.
        if action == "delete":
            value = {key: value[key] for key in ("family", "name", "table", "chain") if key in value}
        else:
            value = {key: item for key, item in value.items() if key != "handle"}
        return action, kind, value

    def event(self, event):
        if not isinstance(event, dict) or len(event) != 1:
            raise BrokerError("Invalid nft monitor event.")
        action, content = next(iter(event.items()))
        if action == "metainfo":
            return
        if not isinstance(content, dict) or len(content) != 1:
            raise BrokerError("Invalid nft monitor operation.")
        kind, value = next(iter(content.items()))
        if not isinstance(value, dict):
            raise BrokerError("Invalid nft monitor value.")
        if value.get("family") == "ip" and (value.get("table") if kind != "table" else value.get("name")) == "filter":
            # iptables-nft change (for example a FreePBX Firewall reload): re-check integration only.
            self.broker.wake.set()
            return
        if value.get("family") != "inet" or (value.get("table") if kind != "table" else value.get("name")) != WORKSTATION_TABLE:
            return
        signature = self.signature(action, kind, value)
        with self.condition:
            if signature in self.pending:
                # The kernel may announce all chains before any rules, not command order.
                self.pending.remove(signature)
                self.condition.notify_all()
                return
        self.broker.enforcement_event.set()
        self.broker.wake.set()

    def read(self):
        try:
            for line in self.process.stdout:
                document = json.loads(line)
                if not isinstance(document, dict):
                    raise BrokerError("Invalid nft monitor envelope.")
                events = document.get("nftables", [document])
                if not isinstance(events, list):
                    raise BrokerError("Invalid nft monitor envelope.")
                for event in events:
                    self.event(event)
            raise BrokerError("Workstation nft monitor stopped.")
        except Exception as error:
            with self.condition:
                self.failed = str(error)
                self.condition.notify_all()
            self.broker.enforcement_event.set()
            self.broker.wake.set()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        self.process.stdout.close()


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
        self.wslock = threading.RLock()
        self.workstation_error = ""
        self.monitor = None
        self.enforcement_event = threading.Event()
        # Wakes the enforcement worker; enforcement_event alone means the owned nft policy must be re-applied.
        self.wake = threading.Event()
        self.integration = {"state": "inactive", "message": "", "backend": None}
        self.workstation_cleanup_failed = False

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

    def run(self, arguments, stdin=None, check=True, stream=False):
        if stream:
            return subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, env=ENV)
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

    def link_state(self):
        links = json.loads(self.run([self.tool("ip"), "-j", "link", "show"]))
        if not isinstance(links, list) or any(not isinstance(link, dict) or not isinstance(link.get("ifname"), str)
                                              or not isinstance(link.get("flags"), list) for link in links):
            raise BrokerError("Workstation interface inventory could not be verified.")
        matches = [link for link in links if link.get("ifname") == WORKSTATION_IFACE]
        if len(matches) > 1:
            raise BrokerError("Ambiguous workstation interface.")
        return matches[0] if matches else None

    def disable_workstations(self):
        if self.link_state() is not None:
            self.run([self.tool("ip"), "link", "set", "down", "dev", WORKSTATION_IFACE], check=False)
            link = self.link_state()
            if link is not None and "UP" in link["flags"]:
                # Deletion is a second way to stop traffic, never permission to remove policy on failure.
                self.run([self.tool("ip"), "link", "del", "dev", WORKSTATION_IFACE], check=False)
                if self.link_state() is not None:
                    raise BrokerError("Workstation interface could not be disabled or removed; retaining firewall and recovery state.")

    def owned_table(self):
        nft = self.tool("nft")
        # A failed query is not evidence that the table is absent.
        inventory = json.loads(self.run([nft, "-j", "list", "tables"]))
        if not isinstance(inventory, dict) or not isinstance(inventory.get("nftables"), list):
            raise BrokerError("Workstation firewall inventory could not be verified.")
        tables = []
        for item in inventory["nftables"]:
            if not isinstance(item, dict) or len(item) != 1:
                raise BrokerError("Invalid nftables table inventory.")
            if "metainfo" in item:
                continue
            table = item.get("table")
            if not isinstance(table, dict) or not isinstance(table.get("family"), str) or not isinstance(table.get("name"), str):
                raise BrokerError("Invalid nftables table identity.")
            tables.append(table)
        if not any(table["family"] == "inet" and table["name"] == WORKSTATION_TABLE for table in tables):
            return None
        document = json.loads(self.run([nft, "-j", "list", "table", "inet", WORKSTATION_TABLE]))
        if (not isinstance(document, dict) or not isinstance(document.get("nftables"), list)
                or any(not isinstance(item, dict) or len(item) != 1 for item in document["nftables"])):
            raise BrokerError("Invalid workstation table JSON.")
        tables = [item["table"] for item in document["nftables"] if "table" in item]
        if any(not isinstance(table, dict) for table in tables):
            raise BrokerError("Invalid workstation table identity.")
        if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != WORKSTATION_TABLE or tables[0].get("comment") != WORKSTATION_OWNER:
            raise BrokerError("Unfamiliar inet teliphones_workstations table: ownership marker missing/changed; it will not be modified.")
        return document

    def expected_policy(self, state):
        network = ipaddress.IPv4Network(state["subnet"])
        if not network.subnet_of(WORKSTATION_POOL) or network.prefixlen != 24 or network.overlaps(WORKSTATION_EXCLUDED):
            raise BrokerError("Invalid workstation subnet.")
        return workstation_policy(str(network[1]), [item["address"].split("/")[0] for item in state["workstations"] if item.get("ssh") is True])

    def start_monitor(self):
        if self.monitor is None:
            self.monitor = NftMonitor(self)
        if not self.monitor.alive():
            raise BrokerError("Workstation nft monitor is unavailable; restart the broker after repairing nftables.")

    # ----- FreePBX Firewall (iptables) integration -----

    def iptables_tool(self):
        return next((path for path in IPTABLES if os.access(path, os.X_OK)), None)

    def ipt(self, iptables, *arguments):
        try:
            return self.run([iptables, "-w", "5", *arguments])
        except BrokerError:
            raise BrokerError("FreePBX Firewall integration command failed: iptables %s." % arguments[0]) from None

    def integration_inventory(self, iptables):
        """Parse the filter table. A failed or unparseable listing is never evidence of absence."""
        chains, rules = {"INPUT", "FORWARD", "OUTPUT"}, []
        try:
            lines = [shlex.split(line) for line in self.ipt(iptables, "-S").splitlines() if line.strip()]
        except ValueError:
            raise BrokerError("The iptables filter table could not be parsed.") from None
        for tokens in lines:
            if tokens[0] == "-P" and len(tokens) == 3:
                continue
            if tokens[0] == "-N" and len(tokens) == 2:
                chains.add(tokens[1])
            elif tokens[0] == "-A" and len(tokens) >= 2:
                rules.append((tokens[1], tokens[2:]))
            else:
                raise BrokerError("Unexpected iptables filter table listing.")
        for chain, tokens in rules:
            if chain == INTEGRATION_CHAIN:
                rule = iptables_rule(tokens)
                if rule is None or rule.get("comment") != INTEGRATION_MARK:
                    raise BrokerError("Unfamiliar iptables chain %s (rule without TELIPHONES marker); it will not be modified." % INTEGRATION_CHAIN)
            elif iptables_target(tokens) == INTEGRATION_CHAIN and (chain != "INPUT" or iptables_rule(tokens) != INTEGRATION_JUMP):
                raise BrokerError("Unexpected reference to iptables chain %s from %s; it will not be modified." % (INTEGRATION_CHAIN, chain))
        return chains, rules

    @staticmethod
    def integration_positions(rules):
        targets = [iptables_target(tokens) for chain, tokens in rules if chain == "INPUT"]
        return ([index for index, target in enumerate(targets) if target == FREEPBX_HOOK],
                [index for index, target in enumerate(targets) if is_fail2ban_hook(target)],
                [index for index, target in enumerate(targets) if target == INTEGRATION_CHAIN])

    def integration_backend(self, iptables):
        version = self.run([iptables, "--version"], check=False) or ""
        return "nf_tables" if "nf_tables" in version else ("legacy" if "legacy" in version else None)

    def integration_status(self, state, message, backend=None):
        self.integration = {"state": state, "message": message, "backend": backend}

    def firewall_integration(self, state):
        """Idempotently install/verify the exact integration. Caller must have verified the nft policy first."""
        iptables = self.iptables_tool()
        if iptables is None:
            self.integration_status("not-detected", "iptables is not installed, so no FreePBX Firewall hook is present; no integration rules were installed.")
            return
        backend = self.integration_backend(iptables)
        chains, rules = self.integration_inventory(iptables)
        hooks, bans, _ = self.integration_positions(rules)
        if not hooks:
            self.remove_integration()
            self.integration_status("not-detected", "No iptables INPUT jump to %s (FreePBX Firewall) was found; no integration rules were installed. "
                                    "If FreePBX Firewall is enabled and tunnel traffic is dropped, report this." % FREEPBX_HOOK, backend)
            return
        if bans and max(bans) > hooks[0]:
            # Never bypass Fail2Ban: without a position after every Fail2Ban hook, install nothing.
            targets = [iptables_target(tokens) for chain, tokens in rules if chain == "INPUT"]
            late = sorted({targets[index] for index in bans if index > hooks[0]})
            self.remove_integration()
            self.integration_status("error", "Fail2Ban INPUT hook(s) %s follow the FreePBX Firewall hook (%s), so no position both after Fail2Ban "
                                    "and before FreePBX Firewall exists; integration was not installed (Fail2Ban is not bypassed) and FreePBX "
                                    "Firewall may drop tunnel traffic. Check with: iptables -S INPUT" % (", ".join(late)[:200], FREEPBX_HOOK), backend)
            return
        network = ipaddress.IPv4Network(state["subnet"])
        expected = integration_rules(str(network[1]), state["workstations"])
        for item in state["workstations"]:
            if not ipaddress.IPv4Network(item["address"]).subnet_of(network):
                raise BrokerError("Workstation address is outside the workstation subnet.")
        if INTEGRATION_CHAIN not in chains:
            self.ipt(iptables, "-N", INTEGRATION_CHAIN)
        current = [iptables_rule(tokens) for chain, tokens in rules if chain == INTEGRATION_CHAIN]
        if current != expected:
            # With the jump present, a flushed chain simply returns to FreePBX processing (never more permissive).
            self.ipt(iptables, "-F", INTEGRATION_CHAIN)
            for rule in expected:
                self.ipt(iptables, "-A", INTEGRATION_CHAIN, *iptables_arguments(rule))
        hooks, bans, jumps = self.integration_positions(rules)
        if not integration_placement_valid(hooks, bans, jumps):
            for _ in jumps:
                self.ipt(iptables, "-D", "INPUT", *iptables_arguments(INTEGRATION_JUMP))
            hooks, bans, jumps = self.integration_positions(self.integration_inventory(iptables)[1])
            if jumps or not hooks or (bans and max(bans) > hooks[0]):
                raise BrokerError("FreePBX Firewall INPUT hooks changed during integration.")
            self.ipt(iptables, "-I", "INPUT", str(hooks[0] + 1), *iptables_arguments(INTEGRATION_JUMP))
        chains, rules = self.integration_inventory(iptables)
        hooks, bans, jumps = self.integration_positions(rules)
        if ([iptables_rule(tokens) for chain, tokens in rules if chain == INTEGRATION_CHAIN] != expected
                or not integration_placement_valid(hooks, bans, jumps)):
            raise BrokerError("FreePBX Firewall integration could not be verified after update.")
        self.integration_status("active", "Authorised workstation peers may reach TCP 80/443%s on the PBX tunnel address before %s; "
                                "all other tunnel traffic returns to FreePBX Firewall." % (
                                    " (and TCP 22 for SSH-approved peers)" if any(item.get("ssh") is True for item in state["workstations"]) else "",
                                    FREEPBX_HOOK), backend)

    def remove_integration(self):
        iptables = self.iptables_tool()
        if iptables is None:
            self.integration_status("inactive", "")
            return
        chains, rules = self.integration_inventory(iptables)
        for _ in self.integration_positions(rules)[2]:
            self.ipt(iptables, "-D", "INPUT", *iptables_arguments(INTEGRATION_JUMP))
        if INTEGRATION_CHAIN in chains:
            self.ipt(iptables, "-F", INTEGRATION_CHAIN)
            self.ipt(iptables, "-X", INTEGRATION_CHAIN)
        chains, rules = self.integration_inventory(iptables)
        if INTEGRATION_CHAIN in chains or self.integration_positions(rules)[2]:
            raise BrokerError("FreePBX Firewall integration rules could not be removed.")
        self.integration_status("inactive", "")

    def reconcile_integration(self, state):
        """Integration failure removes TELIPHONES' iptables rules (FreePBX then decides); unverifiable removal fails closed."""
        try:
            self.firewall_integration(state)
        except (BrokerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            reason = str(error) if isinstance(error, BrokerError) else "integration command failed."
            try:
                self.remove_integration()
            except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                self.integration_status("error", "FreePBX Firewall integration could not be verified or removed: " + reason)
                raise BrokerError("FreePBX Firewall integration could not be verified or removed: " + str(cleanup_error)) from error
            self.integration_status("error", "FreePBX Firewall integration failed and was removed; WireGuard handshakes may succeed while "
                                    "FreePBX Firewall drops HTTP/HTTPS: " + reason)

    def mutate_policy(self, expected, existing, registration_retry=True):
        nft = self.tool("nft")
        commands, events = [], []
        if existing is not None:
            identity = {"family": "inet", "name": WORKSTATION_TABLE}
            table = next(entry["table"] for entry in existing["nftables"] if "table" in entry)
            if table.get("family") != "inet" or table.get("name") != WORKSTATION_TABLE or table.get("comment") != WORKSTATION_OWNER:
                raise BrokerError("Unfamiliar workstation table; refusing mutation.")
            handle = table.get("handle")
            if type(handle) is not int or handle <= 0:
                raise BrokerError("Workstation table identity handle could not be verified; refusing deletion.")
            # Delete the inspected kernel object, not a possibly-replaced namesake.
            commands.append({"delete": {"table": {"family": "inet", "handle": handle}}})
            events.append(NftMonitor.signature("delete", "table", identity))
        if expected is not None:
            for entry in expected["nftables"]:
                kind, value = next(iter(entry.items()))
                # "create" (unlike "add") refuses a namesake appearing after inventory.
                commands.append({"create" if kind == "table" else "add": entry})
                events.append(NftMonitor.signature("add", kind, value))
        if not commands:
            return
        monitored = self.monitor is not None and self.monitor.alive()
        if monitored:
            self.monitor.expect(events)
        try:
            self.run([nft, "-j", "-f", "-"], stdin=json.dumps({"nftables": commands}))
        except (BrokerError, OSError, subprocess.SubprocessError):
            if monitored:
                with self.monitor.condition:
                    self.monitor.pending = []
            raise
        if monitored:
            try:
                self.monitor.wait()
            except BrokerError:
                if expected is None or not registration_retry or not self.monitor.alive():
                    raise
                # Popen is not subscription readiness. With the interface still down,
                # retry once and require a complete observed transaction before admission.
                with self.monitor.condition:
                    self.monitor.pending = []
                self.mutate_policy(expected, self.owned_table(), registration_retry=False)

    def teardown_workstations(self):
        """Shared by revoke, failure, shutdown and the trusted uninstall entry point."""
        self.disable_workstations()
        if self.link_state() is not None:
            self.run([self.tool("ip"), "link", "del", "dev", WORKSTATION_IFACE], check=False)
            if self.link_state() is not None:
                raise BrokerError("Workstation interface could not be removed and was disabled; retaining firewall and recovery state.")
        # With the interface gone the integration rules are inert; still remove them, but never let an
        # iptables failure skip owned nft cleanup. Either failure is reported and keeps recovery state.
        try:
            self.remove_integration()
            integration_error = None
        except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
            integration_error = error
        existing = self.owned_table()
        self.mutate_policy(None, existing)
        if self.owned_table() is not None:
            raise BrokerError("Workstation interface was removed, but firewall cleanup is incomplete; retaining recovery state.")
        if integration_error is not None:
            raise BrokerError("Workstation interface was removed, but FreePBX Firewall integration cleanup is incomplete: "
                              + (str(integration_error) if isinstance(integration_error, BrokerError) else "iptables failed."))

    def uninstall_workstations(self):
        with self.wslock:
            self.teardown_workstations()
            # Never remove either recovery file until link and owned-table absence are proven.
            for path in (STATE / "workstations.json", STATE / "workstation-recovery.json", ENROLLMENT / "workstation-wg.key"):
                path.unlink(missing_ok=True)

    def apply_workstations(self, state):
        """Disable before any change, verify the entire policy, then admit peers."""
        self.workstation_cleanup_failed = False
        try:
            self.disable_workstations()
            if not state["workstations"] or (STATE / "disabled").exists():
                self.teardown_workstations()
                self.workstation_error = ""
                return
            self.start_monitor()
            network = ipaddress.IPv4Network(state["subnet"])
            pbx = str(network[1])
            wg, ip = self.tool("wg"), self.tool("ip")
            expected = self.expected_policy(state)
            existing = self.owned_table()
            # Even an already-correct policy needs an acknowledged initial transaction:
            # this proves monitor subscription before the first admission.
            self.mutate_policy(expected, existing)
            if not policy_equal(self.owned_table(), expected):
                raise BrokerError("Workstation firewall differs from the complete expected policy.")
            if self.link_state() is None:
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
            if not self.monitor.alive() or not policy_equal(self.owned_table(), expected):
                raise BrokerError("Workstation enforcement could not be verified before admission.")
            # Only after the nft restrictions are verified may the narrower FreePBX Firewall ACCEPTs be added.
            self.reconcile_integration(state)
            self.run([ip, "link", "set", "up", "dev", WORKSTATION_IFACE])
            self.workstation_error = ""
        except (BrokerError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            try:
                self.teardown_workstations()
            except (BrokerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as cleanup_error:
                self.workstation_cleanup_failed = True
                self.workstation_error = "Workstation cleanup could not be confirmed: " + (str(cleanup_error) if isinstance(cleanup_error, BrokerError) else "network operation failed.")
                raise BrokerError(self.workstation_error) from error
            self.workstation_error = "Workstation access could not be applied and was removed: " + (str(error) if isinstance(error, BrokerError) else "network configuration failed.")
            raise BrokerError(self.workstation_error) from error

    def restore_workstations(self):
        """Broker start: re-create persistent and unexpired temporary pairings, failing closed."""
        with self.wslock:
            try:
                state, changed = self.workstation_state()
                self.apply_workstations(state)
                if changed:
                    self.save_workstations(state)
            except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
                self.workstation_error = str(error)
                try:
                    self.disable_workstations()
                except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error += " Cleanup unverified: " + str(cleanup_error)

    def expire_workstations(self):
        with self.wslock:
            event = self.enforcement_event.is_set()
            if event:
                self.enforcement_event.clear()
            state, changed = self.workstation_state()
            try:
                if state["workstations"]:
                    if self.monitor is None or not self.monitor.alive():
                        raise BrokerError("Workstation nft monitor is unavailable; access disabled. Restart the broker.")
                    actual = self.owned_table()
                    try:
                        matches = actual is not None and policy_equal(actual, self.expected_policy(state))
                    except (BrokerError, KeyError, TypeError):
                        matches = False
                    if not matches:
                        event = True
                if changed or event or (STATE / "disabled").exists():
                    self.apply_workstations(state)
                    if changed:
                        self.save_workstations(state)
                        self.audit("workstation-expired", 0, "completed")
                elif state["workstations"]:
                    link = self.link_state()
                    if link is not None and "UP" in link["flags"]:
                        # Repairs a FreePBX Firewall reload without re-admitting peers; a no-op when already exact.
                        self.reconcile_integration(state)
            except (BrokerError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                self.workstation_error = str(error)
                try:
                    self.disable_workstations()
                except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error += " Cleanup could not be confirmed: " + str(cleanup_error)

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
        try:
            self.apply_workstations(state)
            pbx_public = self.server_public_key()
            self.save_workstations(state)
        except BrokerError:
            if self.workstation_cleanup_failed:
                atomic(STATE / "workstation-recovery.json", json.dumps(state, indent=2, sort_keys=True))
                raise
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
        self.apply_workstations(state)
        self.save_workstations(state)
        self.audit("unpair", uid, "completed")

    def workstation_status(self):
        state, _ = self.workstation_state()
        requirements = {name: any(os.access(path, os.X_OK) for path in paths) for name, paths in TOOLS.items()}
        handshakes = {}
        error = self.workstation_error
        if (self.monitor is not None and not self.monitor.alive()) or (state["workstations"] and self.monitor is None):
            error = error or "Workstation nft monitor unavailable; access is being disabled. Restart the broker after repair."
        if state["workstations"] and not error:
            try:
                output = self.run([self.tool("wg"), "show", WORKSTATION_IFACE, "latest-handshakes"])
                for line in output.splitlines():
                    key, timestamp = line.split()
                    if not WG_PUBLIC_KEY.fullmatch(key) or not timestamp.isdigit():
                        raise ValueError("Invalid WireGuard handshake status.")
                    handshakes[key] = int(timestamp)
            except (BrokerError, OSError, ValueError, subprocess.SubprocessError):
                error = "Workstation connection status could not be read. Check the broker and tlp-admin interface; pairing is not proof of connectivity."
        return {"ready": all(requirements.values()) and not error and not (STATE / "disabled").exists(), "requirements": requirements, "error": error,
                "listen_port": state["listen_port"],
                "firewall_integration": {"state": self.integration["state"] if state["workstations"] else "inactive",
                                         "message": self.integration["message"] if state["workstations"] else "",
                                         "backend": self.integration["backend"], "hook": FREEPBX_HOOK, "chain": INTEGRATION_CHAIN},
                "pbx_address": str(ipaddress.IPv4Network(state["subnet"])[1]) if state["subnet"] and state["workstations"] else None,
                "items": [{"id": item["id"], "name": item["name"], "address": item["address"], "mode": item["mode"],
                           "ssh": item.get("ssh") is True, "created_at": item.get("created_at"), "expires_at": item.get("expires_at"),
                           "last_handshake": handshakes.get(item["public_key"]),
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
    def stop(signum, frame):
        with broker.wslock:
            broker.teardown_workstations()
        if broker.monitor is not None:
            broker.monitor.close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        broker.disable_workstations()
    except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
        broker.workstation_error = "Initial workstation shutdown unverified: " + str(error)
    # Interrupted broker jobs never resume/open access implicitly.
    broker.cleanup(0, quarantine=(STATE / "session.json").exists() or (STATE / "connect.json").exists())
    # Workstation access exists only while the broker runs and can enforce expiry.
    try:
        broker.start_monitor()
    except (BrokerError, OSError):
        broker.workstation_error = "Workstation nft monitor unavailable; pairing cannot be admitted."
    broker.restore_workstations()

    def expiry():
        while True:
            broker.wake.wait(15)
            broker.wake.clear()
            try:
                broker.expire_workstations()
            except Exception as error:
                broker.workstation_error = "Workstation enforcement worker failed: " + str(error)
                if broker.monitor is not None:
                    broker.monitor.failed = broker.workstation_error
                try:
                    broker.disable_workstations()
                except Exception as cleanup_error:
                    broker.workstation_error += " Cleanup unverified: " + str(cleanup_error)
                return
            # A dead stream sets the event once; do not spin indefinitely on failure.
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
    if sys.argv[1:] == ["--uninstall-workstations"]:
        if os.geteuid() != 0:
            raise SystemExit("Workstation uninstall requires root.")
        try:
            Broker().uninstall_workstations()
        except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
            raise SystemExit("Workstation uninstall incomplete; recovery state retained: " + str(error))
    elif len(sys.argv) != 1:
        raise SystemExit("Unsupported broker arguments.")
    else:
        serve()
