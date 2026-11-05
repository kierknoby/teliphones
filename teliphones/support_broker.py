#!/usr/bin/python3
"""Restricted local GUI-to-root bridge; no browser-selected commands or paths."""
import base64
import datetime
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import sys
from urllib.parse import urlsplit
import importlib.util

_ssh_spec = importlib.util.spec_from_file_location("teliphones_ssh", Path(__file__).with_name("ssh_authority.py"))
ssh = importlib.util.module_from_spec(_ssh_spec)
_ssh_spec.loader.exec_module(ssh)

STATE = Path("/var/lib/teliphones")
ENROLLMENT = Path("/etc/teliphones")
SOCKET = "/run/teliphones/control.sock"
# Protocol 11 adds PBX-enforced workstation session leases and management gating.
# Protocol 12 adds post-pair workstation policy management.
PROTOCOL = 12
VERSION = "0.6.1"
SESSION_CONTROL_PORT = 8766
SESSION_LEASE_SECONDS = 30
FWCONSOLE = "/usr/sbin/fwconsole"
ACTIONS = {"status", "authorise", "revoke", "dependencies", "evidence", "configure", "pair", "unpair", "web",
           "workstation-policy", "workstation-manage", "workstation-ban", "workstation-unban", "workstation-limit",
           "workstation-ssh-approve", "workstation-ssh-reject",
           "workstation-ssh-revoke", "workstation-unlock-approve", "workstation-unlock-reject",
           "workstation-sources-approve", "workstation-sources-reject",
           "diagnostics"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
# Administrator-owned workstation pairing (TELIPHONES Windows application). Separate from the support interface.
WORKSTATION_IFACE = "tlp-admin"
WORKSTATION_TABLE = "teliphones_workstations"
WORKSTATION_OWNER = "TELIPHONES workstation enforcement v1"
WORKSTATION_OWNER_CHAIN = "teliphones_owner_v1"
WORKSTATION_POOL = ipaddress.IPv4Network("100.64.0.0/10")
WORKSTATION_EXCLUDED = ipaddress.IPv4Network("100.100.0.0/16")
PAIR_REQUEST_PREFIX = "TELIPHONES-PAIR-REQUEST-1:"
PAIR_RESPONSE_PREFIX = "TELIPHONES-PAIR-RESPONSE-1:"
PAIR_REQUEST_V2 = "TELIPHONES-PAIR-REQUEST-2:"
PAIR_RESPONSE_V2 = "TELIPHONES-PAIR-RESPONSE-2:"
WG_PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=")
WORKSTATION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}")
HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
LISTENER_PORT_RANGE = range(52000, 61000)
TOOLS = {"wg": ["/usr/bin/wg", "/usr/sbin/wg"], "ip": ["/usr/sbin/ip", "/sbin/ip"], "nft": ["/usr/sbin/nft", "/sbin/nft"]}
# FreePBX Firewall integration. An nft ACCEPT in TELIPHONES' own table is not final: FreePBX Firewall's
# separate iptables INPUT processing can still drop the packet. FreePBX polices rules above its INPUT hook.
# Put only our marked jump inside fpbxfirewall, after INPUT's Fail2Ban hooks. Every ACCEPT rule in
# the owned chain is scoped to an exact TELIPHONES interface, peer address, PBX address and port.
# The public UDP listener is a persistent FreePBX Custom Service, not a second raw ACCEPT.
# Everything not explicitly authorised returns to the existing FreePBX rules.
IPTABLES = ["/usr/sbin/iptables", "/sbin/iptables"]
FREEPBX_HOOK = "fpbxfirewall"
# Fail2Ban hook chains: "fail2ban-<jail>" (FreePBX 17, e.g. fail2ban-SIP, fail2ban-PBX-GUI) and "f2b-<jail>"
# (upstream default). Prefixes are matched case-insensitively so no Fail2Ban hook can be overlooked.
FAIL2BAN_PREFIXES = ("fail2ban-", "f2b-")
INTEGRATION_CHAIN = "teliphones-ws"
INTEGRATION_MARK = "TELIPHONES workstation integration v1"
INTEGRATION_JUMP = {"comment": INTEGRATION_MARK, "j": INTEGRATION_CHAIN}
LEGACY_INTEGRATION_JUMP = {"i": WORKSTATION_IFACE, **INTEGRATION_JUMP}
# Management web services reachable by authorised peers; the first entry forms the workstation GUI URL.
# The default preserves standard FreePBX HTTP/HTTPS installations.
DEFAULT_WEB = ({"scheme": "http", "port": 80}, {"scheme": "https", "port": 443})
MAX_WEB_SERVICES = 4
DIAGNOSTIC_ID = re.compile(r"ws-[a-f0-9]{16}")
LOGGER = logging.getLogger("teliphones.broker")


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


class DiagnosticLog:
    MAX_FILE_BYTES = 1024 * 1024
    RETAINED_FILES = 3
    RETENTION_SECONDS = 7 * 24 * 60 * 60
    MAX_RETURNED_EVENTS = 200
    FILES = ("events.jsonl", "events.1.jsonl", "events.2.jsonl")
    EVENT_FIELDS = {
        "ssh.certificate": {"expires_at": ("int", None), "serial": ("int", None)},
        "ssh.terminated": {"reason": ("enum", ("revoked", "shutdown", "rotation"))},
        "pairing.approved": {"mode": ("enum", ("temporary", "persistent")), "expires_at": ("nullable_int", None),
                             "renewed": ("bool", None)},
        "pairing.revoked": {"reason": ("enum", ("administrator",))},
        "pairing.expired": {"reason": ("enum", ("deadline",))},
        "peer.admitted": {"access": ("enum", ("web", "web+ssh"))},
        "peer.observation": {"handshake_at": ("int", None), "rx_bytes": ("int", None), "tx_bytes": ("int", None)},
        "interface.established": {"listen_port": ("int", None)},
        "interface.removed": {},
        "firewall.integration": {"state": ("enum", ("inactive", "active", "not-detected", "error")),
                                 "backend": ("nullable_enum", ("nf_tables", "legacy"))},
        "broker.error": {"category": ("enum", ("workstation-enforcement", "firewall-integration",
                                                "telemetry-unavailable", "cleanup-unverified"))},
    }

    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock_path = self.directory / "events.lock"

    @staticmethod
    def _valid_private_file(path, fd=None):
        info = os.fstat(fd) if fd is not None else path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o077 == 0)

    def _open_lock(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise OSError("Diagnostics directory is not private and trusted.")
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if not self._valid_private_file(self.lock_path, fd):
            os.close(fd)
            raise OSError("Diagnostics lock file is not private and trusted.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @staticmethod
    def _event_data(event, fields):
        specification = DiagnosticLog.EVENT_FIELDS.get(event)
        if specification is None or set(fields) - set(specification):
            raise ValueError("Unsupported diagnostic event.")
        clean = {}
        for name, value in fields.items():
            kind, allowed = specification[name]
            if kind == "enum" and value in allowed:
                clean[name] = value
            elif kind == "nullable_enum" and (value is None or value in allowed):
                clean[name] = value
            elif kind == "bool" and isinstance(value, bool):
                clean[name] = value
            elif kind == "int" and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                clean[name] = value
            elif kind == "nullable_int" and (value is None or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)):
                clean[name] = value
            else:
                raise ValueError("Invalid diagnostic event field.")
        return clean

    @staticmethod
    def _timestamp(value):
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _trusted_existing(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        try:
            if not self._valid_private_file(path, fd):
                raise OSError("Diagnostics file is not private and trusted.")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _prune_locked(self, now):
        cutoff = int(now - self.RETENTION_SECONDS)
        for name in self.FILES:
            path = self.directory / name
            try:
                fd = self._trusted_existing(path)
                if fd is None:
                    continue
                try:
                    stale = now - os.fstat(fd).st_mtime > self.RETENTION_SECONDS
                    if not stale:
                        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                            lines = handle.readlines()
                finally:
                    os.close(fd)
                if stale:
                    path.unlink()
                    continue
                retained = []
                changed = False
                for line in lines:
                    try:
                        record = json.loads(line)
                        valid = (isinstance(record, dict) and isinstance(record.get("unix_time"), int)
                                 and not isinstance(record.get("unix_time"), bool) and record["unix_time"] >= cutoff)
                    except (ValueError, TypeError):
                        valid = False
                    if valid and len(line) <= 4096:
                        retained.append(line)
                    else:
                        changed = True
                if changed:
                    if retained:
                        atomic(path, "".join(retained), 0o600)
                    else:
                        path.unlink()
            except FileNotFoundError:
                pass

    def _rotate_locked(self):
        oldest = self.directory / self.FILES[-1]
        try:
            oldest.unlink()
        except FileNotFoundError:
            pass
        for index in range(len(self.FILES) - 2, -1, -1):
            source = self.directory / self.FILES[index]
            target = self.directory / self.FILES[index + 1]
            try:
                source.lstat()
            except FileNotFoundError:
                continue
            fd = self._trusted_existing(source)
            os.close(fd)
            os.replace(source, target)

    def record(self, diagnostic_id, event, **fields):
        if not isinstance(diagnostic_id, str) or DIAGNOSTIC_ID.fullmatch(diagnostic_id) is None:
            return
        now = time.time()
        clean = self._event_data(event, fields)
        line = json.dumps({"component_version": VERSION, "timestamp_utc": self._timestamp(now), "unix_time": int(now),
                           "diagnostic_id": diagnostic_id, "source": "pbx", "event": event, "data": clean},
                          separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
        if len(line) > 4096:
            raise ValueError("Diagnostic record exceeds its bound.")
        lock_fd = self._open_lock()
        try:
            self._prune_locked(now)
            active = self.directory / self.FILES[0]
            fd = self._trusted_existing(active)
            size = os.fstat(fd).st_size if fd is not None else 0
            if fd is not None:
                os.close(fd)
            if size + len(line) > self.MAX_FILE_BYTES:
                self._rotate_locked()
            fd = os.open(active, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                if not self._valid_private_file(active, fd) or os.fstat(fd).st_size + len(line) > self.MAX_FILE_BYTES:
                    raise OSError("Diagnostics file failed its size or permission check.")
                offset = 0
                while offset < len(line):
                    offset += os.write(fd, line[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def read(self, diagnostic_id, now=None):
        if not isinstance(diagnostic_id, str) or DIAGNOSTIC_ID.fullmatch(diagnostic_id) is None:
            raise BrokerError("Invalid diagnostic session identifier.")
        now = time.time() if now is None else now
        lock_fd = self._open_lock()
        try:
            self._prune_locked(now)
            events = []
            for name in reversed(self.FILES):
                fd = self._trusted_existing(self.directory / name)
                if fd is None:
                    continue
                try:
                    with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                        for line in handle:
                            if len(line) > 4096:
                                continue
                            try:
                                record = json.loads(line)
                            except (ValueError, TypeError):
                                continue
                            if (isinstance(record, dict) and record.get("diagnostic_id") == diagnostic_id
                                    and record.get("source") == "pbx"
                                    and isinstance(record.get("unix_time"), int)
                                    and not isinstance(record.get("unix_time"), bool)
                                    and record["unix_time"] >= int(now - self.RETENTION_SECONDS)
                                    and record.get("event") in self.EVENT_FIELDS):
                                events.append(record)
                finally:
                    os.close(fd)
            events.sort(key=lambda item: item.get("unix_time", 0))
            return events[-self.MAX_RETURNED_EVENTS:]
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def validate(request):
    if not isinstance(request, dict) or not isinstance(request.get("action"), str) or request["action"] not in ACTIONS:
        raise BrokerError("Unsupported TELIPHONES operation.")
    action = request["action"]
    fields = {
        "status": set(), "revoke": set(), "dependencies": set(),
        "authorise": {"minutes"}, "evidence": {"evidence"},
        "configure": {"url", "certificate", "private_key", "ca", "checker_key"},
        "pair": {"request", "endpoint_host", "listen_port", "mode", "minutes", "ssh", "ssh_user", "web", "sources"}, "unpair": {"workstation_id"},
        "web": {"web"}, "workstation-policy": {"state"},
        "workstation-manage": {"workstation_id", "state", "sources"},
        "workstation-ban": {"source", "reason", "hours"}, "workstation-unban": {"ban_id"},
        "workstation-limit": {"maximum"},
        "workstation-ssh-approve": {"workstation_id", "ssh_user"},
        "workstation-ssh-reject": {"workstation_id"},
        "workstation-ssh-revoke": {"workstation_id"},
        "workstation-unlock-approve": {"workstation_id"},
        "workstation-unlock-reject": {"workstation_id"},
        "workstation-sources-approve": {"workstation_id"},
        "workstation-sources-reject": {"workstation_id"},
        "diagnostics": {"diagnostic_id"},
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
        if request["request"].strip().startswith(PAIR_REQUEST_V2) and request["ssh"] == "1":
            if not isinstance(request.get("ssh_user"), str) or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", request["ssh_user"]) is None:
                raise BrokerError("Explicitly select the existing Linux account authorised for this workstation.")
        endpoint_host(request["endpoint_host"])
        if not re.fullmatch(r"[0-9]{4,5}", request["listen_port"]) or not 1024 <= int(request["listen_port"]) <= 65535:
            raise BrokerError("The WireGuard UDP port must be between 1024 and 65535.")
        if request["mode"] not in ("temporary", "persistent") or request["ssh"] not in ("0", "1"):
            raise BrokerError("Choose temporary or persistent pairing, and whether SSH is permitted.")
        if request["mode"] == "temporary" and (not isinstance(request.get("minutes"), str) or not re.fullmatch(r"[0-9]{2,4}", request["minutes"])
                                               or not 15 <= int(request["minutes"]) <= 1440):
            raise BrokerError("Temporary pairing must last between 15 and 1440 minutes.")
        if "web" in request:
            if not isinstance(request["web"], str):
                raise BrokerError("Management web services must be supplied as text.")
            if request["web"].strip():
                parse_web(request["web"])
        if "sources" in request:
            if not isinstance(request["sources"], str):
                raise BrokerError("Approved workstation sources must be supplied as text.")
            parse_source_restrictions(request["sources"])
    if action == "web":
        if not isinstance(request.get("web"), str):
            raise BrokerError("Complete management web service details are required.")
        parse_web(request["web"])
    if action == "workstation-policy" and request.get("state") not in ("open", "closed", "frozen"):
        raise BrokerError("Choose Open, Closed or Frozen workstation access.")
    if action == "workstation-manage":
        if (not isinstance(request.get("workstation_id"), str)
                or re.fullmatch(r"[a-f0-9]{16}", request["workstation_id"]) is None
                or request.get("state") not in ("lock", "unlock")
                or not isinstance(request.get("sources"), str)):
            raise BrokerError("Choose a paired workstation and a valid Lock or Unlock action.")
        if request["state"] == "lock" and request["sources"] != "current":
            parse_source_restrictions(request["sources"])
        if request["state"] == "unlock" and request["sources"]:
            raise BrokerError("Unlocking a workstation does not accept source restrictions.")
    if action == "workstation-limit" and (
            not isinstance(request.get("maximum"), str)
            or not re.fullmatch(r"[1-9][0-9]{0,2}", request["maximum"])
            or not 1 <= int(request["maximum"]) <= 128):
        raise BrokerError("The simultaneous workstation limit must be between 1 and 128.")
    if action == "workstation-ban":
        if (not isinstance(request.get("source"), str) or not isinstance(request.get("reason"), str)
                or not isinstance(request.get("hours"), str) or len(request["reason"]) > 160
                or not request["reason"].strip()
                or request["hours"] not in ("never", "1", "24", "168", "720", "8760")):
            raise BrokerError("Enter a manual IP/CIDR ban, a reason of at most 160 characters, and a valid expiry.")
        try:
            network = ipaddress.ip_network(request["source"].strip(), strict=False)
        except ValueError as error:
            raise BrokerError("Bans must be numeric IPv4/IPv6 addresses or CIDR ranges.") from error
        if network.is_unspecified or network.is_multicast:
            raise BrokerError("An unspecified or multicast network cannot be banned.")
    if action == "workstation-unban" and (
            not isinstance(request.get("ban_id"), str) or re.fullmatch(r"[a-f0-9]{16}", request["ban_id"]) is None):
        raise BrokerError("Unknown TELIPHONES ban.")
    if action == "unpair":
        if not isinstance(request.get("workstation_id"), str) or not re.fullmatch(r"[a-f0-9]{16}|all", request["workstation_id"]):
            raise BrokerError("Unknown workstation.")
    if action in ("workstation-ssh-approve", "workstation-ssh-reject", "workstation-ssh-revoke") and (
            not isinstance(request.get("workstation_id"), str)
            or re.fullmatch(r"[a-f0-9]{16}", request["workstation_id"]) is None):
        raise BrokerError("Choose a valid paired workstation SSH request.")
    if action == "workstation-ssh-approve" and (
            not isinstance(request.get("ssh_user"), str)
            or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", request["ssh_user"]) is None):
        raise BrokerError("Explicitly select the existing Linux account authorised for this workstation.")
    if action == "diagnostics" and (not isinstance(request.get("diagnostic_id"), str)
                                    or DIAGNOSTIC_ID.fullmatch(request["diagnostic_id"]) is None):
        raise BrokerError("Invalid diagnostic session identifier.")
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
        version = 2 if code.startswith(PAIR_REQUEST_V2) else 1
        prefix = PAIR_REQUEST_V2 if version == 2 else PAIR_REQUEST_PREFIX
        if not code.startswith(prefix) or len(code) > 4096:
            raise ValueError("prefix")
        value = json.loads(b64url_decode(code[len(prefix):]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise BrokerError("The pairing request is not a TELIPHONES workstation pairing request.") from error
    if (not isinstance(value, dict) or set(value) != ({"schema", "workstation", "public_key", "nonce"} | ({"ssh_public_key"} if version == 2 else set()))
            or value["schema"] != "teliphones-pair-request/" + str(version)
            or not isinstance(value["workstation"], str) or not WORKSTATION_NAME.fullmatch(value["workstation"])
            or not isinstance(value["public_key"], str) or not WG_PUBLIC_KEY.fullmatch(value["public_key"])
            or base64.b64decode(value["public_key"]) == bytes(32)
            or not isinstance(value["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{22}", value["nonce"])):
        raise BrokerError("The pairing request is malformed or incomplete.")
    if version == 2:
        try:
            value["ssh_public_key"] = ssh.public_key(value["ssh_public_key"])
        except ssh.SshError as error:
            raise BrokerError(str(error)) from error
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


def parse_wireguard_endpoint(value):
    """Parse only a numeric endpoint observed by WireGuard after peer authentication."""
    if not isinstance(value, str) or value == "(none)":
        return None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value[closing + 1:closing + 2] != ":":
            return None
        host, port = value[1:closing], value[closing + 2:]
    else:
        host, separator, port = value.rpartition(":")
        if not separator or ":" in host:
            return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    return {"address": address.compressed, "port": int(port)}


def key_fingerprint(public_key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public_key)).digest()).decode().rstrip("=")[:16]


def parse_web(value):
    """Comma-separated "scheme:port" management web services, e.g. "https:8443" or "http:80, https:443".

    The first entry forms the GUI URL given to the Windows application at pairing.
    """
    if not isinstance(value, str) or not value.strip():
        raise BrokerError("Enter the management web services as scheme:port entries, for example https:8443.")
    entries = []
    for token in value.split(","):
        scheme, _, port = token.strip().lower().partition(":")
        if scheme not in ("http", "https") or not re.fullmatch(r"[1-9][0-9]{0,4}", port) or not 1 <= int(port) <= 65535:
            raise BrokerError("Management web services must be comma-separated scheme:port entries (http or https, port 1-65535).")
        if int(port) in (22, ssh.API_PORT) or ssh.SSH_PORT_BASE <= int(port) <= ssh.SSH_PORT_BASE + 255:
            raise BrokerError("A management web service must not use a TELIPHONES SSH or certificate API port.")
        if int(port) in [entry["port"] for entry in entries]:
            raise BrokerError("Each management web service port may be listed only once.")
        entries.append({"scheme": scheme, "port": int(port)})
    if len(entries) > MAX_WEB_SERVICES:
        raise BrokerError("At most %d management web services may be authorised." % MAX_WEB_SERVICES)
    return entries


def parse_source_restrictions(value):
    """Canonical IP/CIDR and hostname restrictions for one workstation listener."""
    if not isinstance(value, str) or len(value) > 2048:
        raise BrokerError("Approved workstation sources must be at most 2048 characters.")
    if not value.strip():
        return []
    entries, seen = [], set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            raise BrokerError("Remove empty entries from the approved-source list.")
        try:
            source = str(ipaddress.ip_network(token, strict=False))
            parsed = ipaddress.ip_network(source)
            if (parsed.prefixlen == 0 or parsed.network_address.is_unspecified
                    or parsed.network_address.is_multicast or parsed.network_address.is_loopback):
                raise BrokerError("Approved sources cannot be a default route or unspecified, multicast or loopback range.")
        except ValueError:
            hostname = token.rstrip(".").lower()
            if not HOSTNAME.fullmatch(hostname) or re.fullmatch(r"[0-9.]+", hostname):
                raise BrokerError("Approved sources must be IPv4/IPv6 addresses, CIDR ranges or DNS hostnames.")
            source = hostname
        if source not in seen:
            entries.append(source)
            seen.add(source)
    if len(entries) > 32:
        raise BrokerError("At most 32 approved source entries are supported per workstation.")
    return entries


def resolve_source_restrictions(entries, resolver=None, cache=None, now=None):
    """Resolve domains without ever replacing a failed domain with a wildcard."""
    resolver = resolver or socket.getaddrinfo
    now = time.monotonic() if now is None else now
    resolved, failed = set(), []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            cached = cache.get(entry) if cache is not None else None
            if cached is not None and cached[0] > now:
                resolved.update(cached[1])
                if not cached[1]:
                    failed.append(entry)
                continue
            try:
                answers = resolver(entry, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
                addresses = {str(ipaddress.ip_address(answer[4][0].split("%", 1)[0])) for answer in answers}
                if not addresses:
                    raise OSError("no address records")
                values = sorted(str(ipaddress.ip_network(address + ("/32" if ":" not in address else "/128"), strict=False))
                                for address in addresses)
                resolved.update(values)
                if cache is not None:
                    cache[entry] = (now + 300, values)
            except (OSError, ValueError, IndexError):
                failed.append(entry)
                if cache is not None:
                    cache[entry] = (now + 60, [])
        else:
            resolved.add(str(network))
    return sorted(resolved, key=lambda source: (ipaddress.ip_network(source).version,
                                                 int(ipaddress.ip_network(source).network_address),
                                                 ipaddress.ip_network(source).prefixlen)), failed


def normalise_web(value):
    """Only missing legacy state gets defaults; malformed stored permissions fail closed."""
    if value is None:
        return [dict(entry) for entry in DEFAULT_WEB]
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, dict) or set(item) != {"scheme", "port"}
                   or item["scheme"] not in ("http", "https") or type(item["port"]) is not int for item in value)):
        raise BrokerError("Invalid stored management web services.")
    return parse_web(web_text(value))


def web_text(web):
    return ", ".join("%s:%d" % (entry["scheme"], entry["port"]) for entry in web)


def gui_url(web, pbx_address):
    """GUI address for the Windows application: the first configured management web service."""
    primary = web[0]
    default = 80 if primary["scheme"] == "http" else 443
    return "%s://%s%s/admin/" % (primary["scheme"], pbx_address,
                                 "" if primary["port"] == default else ":%d" % primary["port"])


def web_listening(port, pbx_address=None):
    """Whether a local TCP listener covers the PBX tunnel address for this port (wildcard or exact bind).

    A firewall permit alone is not reachability; the management service must also listen on an address
    the tunnel peers reach. Returns True, False, or None when /proc/net/tcp* cannot be read.
    """
    try:
        hex_port = "%04X" % int(port)
        mapped = None
        wanted4 = {"00000000"}
        if pbx_address:
            little_endian = socket.inet_aton(pbx_address)[::-1].hex().upper()
            wanted4.add(little_endian)
            mapped = "0000000000000000FFFF0000" + little_endian
        # An IPv6 wildcard may be v6-only; do not report IPv4 reachability on that evidence.
        wanted6 = {mapped} if mapped else set()
        for path, wanted in ((Path("/proc/net/tcp"), wanted4), (Path("/proc/net/tcp6"), wanted6)):
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                local, _, local_port = fields[1].partition(":")
                if fields[3] == "0A" and local_port == hex_port and local in wanted:
                    return True
    except (OSError, ValueError, IndexError):
        return None
    return False


def workstation_ruleset(pbx_address, ssh_sources, web_ports=(80, 443)):
    """Human-readable policy illustration; enforcement uses workstation_policy JSON."""
    lines = ["table inet " + WORKSTATION_TABLE + " {",
             "    chain " + WORKSTATION_OWNER_CHAIN + " { }",
             "    chain input {", "        type filter hook input priority 10; policy accept;"]
    if web_ports:
        lines.append('        iifname "%s" ip daddr %s tcp dport { %s } accept' % (
            WORKSTATION_IFACE, pbx_address, ", ".join(str(port) for port in web_ports)))
    if ssh_sources:
        lines.append('        iifname "%s" ip saddr { %s } ip daddr %s tcp dport 22 accept' % (WORKSTATION_IFACE, ", ".join(sorted(ssh_sources)), pbx_address))
    lines += ['        iifname "%s" ip daddr %s icmp type echo-request accept' % (WORKSTATION_IFACE, pbx_address),
              '        iifname "%s" drop' % WORKSTATION_IFACE, "    }",
              "    chain forward {", "        type filter hook forward priority -10; policy accept;",
              '        iifname "%s" drop' % WORKSTATION_IFACE, '        oifname "%s" drop' % WORKSTATION_IFACE, "    }", "}"]
    return "\n".join(lines) + "\n"


def workstation_policy(pbx_address, ssh_sources, managed_sources=(), web_ports=(80, 443), listener_sources=(),
                       peer_interfaces=(), banned_sources=(), admitted_sources=(), control_sources=()):
    """Offline expected nft JSON, deliberately without sets, counters or implicit expressions.

    Rules must use the form nft reports back: for example "udp dport" without "meta l4proto udp", which
    nft adds as the implicit protocol dependency and omits from listings and monitor events.
    """
    family = {"family": "inet", "table": WORKSTATION_TABLE}
    # nftables 1.0.6 accepts table comments in JSON but drops them from kernel state.
    # A hookless, ruleless chain remains visible and verifiable on that version.
    objects = [{"table": {"family": "inet", "name": WORKSTATION_TABLE}},
               {"chain": {**family, "name": WORKSTATION_OWNER_CHAIN}}]

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
    objects.append({"chain": {**family, "name": "input", "type": "filter", "hook": "input", "prio": 10, "policy": "accept"}})
    objects.append({"chain": {**family, "name": "forward", "type": "filter", "hook": "forward", "prio": -10, "policy": "accept"}})
    for ban in sorted(banned_sources, key=lambda item: (int(item["port"]), item["source"])):
        port = ban["port"]
        if type(port) is not int or not 1024 <= port <= 65535:
            raise BrokerError("Invalid TELIPHONES banned-list listener port.")
        network_source = ipaddress.ip_network(ban["source"], strict=False)
        address_family = "ip" if network_source.version == 4 else "ip6"
        source_match = (str(network_source.network_address) if network_source.prefixlen == network_source.max_prefixlen
                        else {"prefix": {"addr": str(network_source.network_address), "len": network_source.prefixlen}})
        rule("input", [match(payload("udp", "dport"), port),
                       match(payload(address_family, "saddr"), source_match), {"drop": None}])
    for listener in sorted(listener_sources, key=lambda item: int(item["port"])):
        port = int(listener["port"])
        if not 1024 <= port <= 65535:
            raise BrokerError("Invalid locked workstation listener port.")
        for source in listener["sources"]:
            network_source = ipaddress.ip_network(source, strict=False)
            address_family = "ip" if network_source.version == 4 else "ip6"
            source_match = (str(network_source.network_address) if network_source.prefixlen == network_source.max_prefixlen
                            else {"prefix": {"addr": str(network_source.network_address), "len": network_source.prefixlen}})
            rule("input", [match(payload("udp", "dport"), port),
                           match(payload(address_family, "saddr"), source_match), {"accept": None}])
        rule("input", [match(payload("udp", "dport"), port), {"drop": None}])
    for peer in sorted(peer_interfaces, key=lambda item: item["interface"]):
        interface = peer["interface"]
        peer_pbx = str(ipaddress.IPv4Address(peer["pbx_address"]))
        peer_incoming = match(meta("iifname"), interface)
        peer_destination = match(payload("ip", "daddr"), peer_pbx)
        peer_source = str(ipaddress.IPv4Address(peer["source"]))
        rule("input", [peer_incoming, match(payload("ip", "saddr"), peer_source), peer_destination,
                       match(payload("tcp", "dport"), SESSION_CONTROL_PORT), {"accept": None}])
        if peer_source in admitted_sources:
            for port in web_ports:
                rule("input", [peer_incoming, match(payload("ip", "saddr"), peer_source), peer_destination,
                               match(payload("tcp", "dport"), port), {"accept": None}])
        if type(peer.get("ssh_port")) is int:
            for ssh_destination in (ssh.API_PORT, peer["ssh_port"]):
                rule("input", [{"match": {"op": "!=", "left": meta("iifname"), "right": interface}},
                               peer_destination, match(payload("tcp", "dport"), ssh_destination), {"drop": None}])
                if peer_source in admitted_sources:
                    rule("input", [peer_incoming, match(payload("ip", "saddr"), peer_source), peer_destination,
                                   match(payload("tcp", "dport"), ssh_destination), {"accept": None}])
        rule("input", [peer_incoming, peer_destination, match(payload("icmp", "type"), "echo-request"), {"accept": None}])
        rule("input", [peer_incoming, {"drop": None}])
        rule("forward", [peer_incoming, {"drop": None}])
        rule("forward", [match(meta("oifname"), interface), {"drop": None}])
    for source, ssh_port in managed_sources:
        if source not in admitted_sources:
            continue
        for ssh_destination in (ssh.API_PORT, ssh_port):
            # A local address is not an interface boundary on Linux (weak host model).
            rule("input", [{"match": {"op": "!=", "left": meta("iifname"), "right": WORKSTATION_IFACE}},
                           destination, match(payload("tcp", "dport"), ssh_destination), {"drop": None}])
            rule("input", [incoming, match(payload("ip", "saddr"), str(ipaddress.IPv4Address(source))),
                           destination, match(payload("tcp", "dport"), ssh_destination), {"accept": None}])
    for source in sorted(set(control_sources)):
        rule("input", [incoming, match(payload("ip", "saddr"), str(ipaddress.IPv4Address(source))),
                       destination, match(payload("tcp", "dport"), SESSION_CONTROL_PORT), {"accept": None}])
    for source in sorted(set(admitted_sources)):
        for port in web_ports:
            rule("input", [incoming, match(payload("ip", "saddr"), str(ipaddress.IPv4Address(source))),
                           destination, match(payload("tcp", "dport"), port), {"accept": None}])
    for source in sorted(set(ssh_sources) & set(admitted_sources)):
        rule("input", [incoming, match(payload("ip", "saddr"), str(ipaddress.IPv4Address(source))),
                       destination, match(payload("tcp", "dport"), 22), {"accept": None}])
    rule("input", [incoming, destination, match(payload("icmp", "type"), "echo-request"), {"accept": None}])
    rule("input", [incoming, {"drop": None}])
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
    """One interface jump inside FreePBX, after INPUT's Fail2Ban hooks."""
    return jumps == [0] and bool(hooks) and all(index < hooks[0] for index in bans)


def iptables_arguments(rule):
    arguments = []
    for option, key in (("-s", "s"), ("-d", "d"), ("-i", "i"), ("-p", "p")):
        if key in rule:
            arguments += [option, rule[key]]
    if "dport" in rule:
        arguments += ["-m", "tcp", "--dport", rule["dport"]]
    return arguments + ["-m", "comment", "--comment", rule["comment"], "-j", rule["j"]]


def integration_rules(pbx_address, workstations, web=DEFAULT_WEB, migration_controls=()):
    """Per-peer management TCP and explicitly approved SSH; no public services."""
    web_ports = tuple(entry["port"] for entry in web)
    rules = []
    for item in sorted(workstations, key=lambda entry: ipaddress.IPv4Network(entry["address"])):
        source = ipaddress.IPv4Network(item["address"])
        if source.prefixlen != 32:
            raise BrokerError("Workstation integration requires a single-address peer.")
        pbx = str(ipaddress.IPv4Address(item.get("pbx_address", pbx_address))) + "/32"
        interface = item.get("interface", WORKSTATION_IFACE)
        ports = (*web_ports, SESSION_CONTROL_PORT,
                 *((ssh.API_PORT, ssh.port(item)) if ssh.managed(item) else ((22,) if item.get("ssh") is True else ())))
        for protocol_port in ports:
            rules.append({"s": str(source), "d": pbx, "i": interface, "p": "tcp", "dport": str(protocol_port),
                          "comment": INTEGRATION_MARK, "j": "ACCEPT"})
    for item in migration_controls:
        source = ipaddress.IPv4Network(item["address"])
        if source.prefixlen != 32:
            raise BrokerError("Workstation migration requires a single-address peer.")
        pbx = str(ipaddress.IPv4Address(item["pbx_address"])) + "/32"
        interface = item["interface"]
        rules.append({"s": str(source), "d": pbx, "i": interface, "p": "tcp",
                      "dport": str(SESSION_CONTROL_PORT), "comment": INTEGRATION_MARK, "j": "ACCEPT"})
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
        self.expected_count = 0
        self.failed = ""
        self.process = broker.run([broker.tool("nft"), "-j", "monitor", "ruleset"], stream=True)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def alive(self):
        return not self.failed and self.process.poll() is None and self.thread.is_alive()

    def unavailable_reason(self):
        if self.failed:
            return self.failed
        if self.process.poll() is not None:
            return "nft monitor exited with status %s." % self.process.returncode
        return "nft monitor reader stopped."

    @staticmethod
    def describe(signatures):
        """Bounded, address-free summary of outstanding events, for example "add rule input x4"."""
        counts = {}
        for action, kind, value in signatures:
            label = " ".join(filter(None, (action, kind, value.get("chain") if kind == "rule" else value.get("name"))))
            counts[label] = counts.get(label, 0) + 1
        return ", ".join("%s x%d" % item for item in sorted(counts.items())[:8]) + ("; ..." if len(counts) > 8 else "")

    def expect(self, events):
        with self.condition:
            if not self.alive():
                raise BrokerError("Workstation nft monitor is unavailable: " + self.unavailable_reason())
            if self.pending:
                raise BrokerError("Workstation nft monitor still has an unacknowledged earlier transaction (%s) whose "
                                  "firewall result could not be read back." % self.describe(self.pending))
            self.pending = events[:]
            self.expected_count = len(events)

    def wait(self):
        with self.condition:
            if not self.condition.wait_for(lambda: not self.pending or not self.alive(), timeout=3) or not self.alive():
                if not self.alive():
                    raise BrokerError("Workstation nft monitor stopped during a transaction: " + self.unavailable_reason())
                raise BrokerError("Workstation nft transaction was not acknowledged by the nft monitor: %d of %d events "
                                  "outstanding after 3 s (%s)." % (len(self.pending), self.expected_count,
                                                                     self.describe(self.pending)))

    def release(self):
        """Forget an unacknowledged transaction; callers must first read back kernel state. Late events then count as external changes."""
        with self.condition:
            self.pending = []
            self.condition.notify_all()

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
        self.lease_wake = threading.Event()
        self.session_server_enabled = False
        self.session_servers = {}
        # Wakes the enforcement worker; enforcement_event alone means the owned nft policy must be re-applied.
        self.wake = threading.Event()
        self.integration = {"state": "inactive", "message": "", "backend": None}
        self.source_cache = {}
        self.workstation_cleanup_failed = False
        self.diagnostics = DiagnosticLog(STATE / "diagnostics")
        self.diagnostic_active_peers = set()
        self.diagnostic_interface_up = False
        self.diagnostic_observations = {}
        self.diagnostic_telemetry_error = False
        self.ssh = ssh.Authority(ENROLLMENT / "ssh", self.workstation_state, self.wslock, self.diagnostic)

    def diagnostic(self, diagnostic_id, event, **fields):
        try:
            self.diagnostics.record(diagnostic_id, event, **fields)
        except Exception:
            # Diagnostics must never alter firewall enforcement or access decisions.
            LOGGER.warning("TELIPHONES diagnostic write failed", exc_info=True)

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
        return {"protocol": PROTOCOL, "component_version": VERSION, "phase": phase, "readiness": readiness, "enabled": enabled,
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
        listener = arguments[:3] == [FWCONSOLE, "teliphones", "listener"]
        result = subprocess.run(arguments, input=stdin, capture_output=True, text=True, timeout=60 if listener else 20, env=ENV)
        if result.returncode and check:
            detail = (" " + (result.stdout or result.stderr).strip()[-500:]) if listener or os.path.basename(arguments[0]) == "nft" else ""
            raise BrokerError("Workstation network operation failed: " + os.path.basename(arguments[0]) + " " + arguments[1] + "." + detail)
        return result.stdout if result.returncode == 0 else None

    def workstation_state(self):
        """Load the pairing state and drop expired temporary pairings. Returns (state, changed)."""
        stored = read_json(STATE / "workstations.json")
        items = stored.get("workstations") if isinstance(stored.get("workstations"), list) else []
        now = int(time.time())
        valid = []
        for item in items:
            if (not isinstance(item, dict) or not WG_PUBLIC_KEY.fullmatch(str(item.get("public_key", "")))
                    or (item.get("mode") != "persistent"
                        and not (isinstance(item.get("expires_at"), int) and item["expires_at"] > now))):
                continue
            item = dict(item)
            item.setdefault("locked", False)
            if type(item["locked"]) is not bool:
                raise BrokerError("Invalid saved workstation source-lock state.")
            if item["locked"]:
                sources = item.get("sources")
                if not isinstance(sources, list) or not sources or parse_source_restrictions(", ".join(sources)) != sources:
                    raise BrokerError("Invalid saved workstation source restrictions; access remains unavailable.")

                for field in ("subnet", "pbx_address", "listener_port"):
                    if field not in item:
                        raise BrokerError("Incomplete saved dedicated workstation listener; access remains unavailable.")
            migration = item.get("migration")
            if migration is not None:
                required = {"id", "locked", "address", "pbx_address"}
                if (not isinstance(migration, dict) or not required.issubset(migration)
                        or not isinstance(migration["id"], str)
                        or re.fullmatch(r"[a-f0-9]{32}", migration["id"]) is None
                        or type(migration["locked"]) is not bool
                        or not isinstance(migration["address"], str)
                        or not isinstance(migration["pbx_address"], str)):
                    raise BrokerError("Invalid pending workstation configuration migration; access remains unavailable.")
                old_address = migration["address"].split("/")[0]
                try:
                    if (ipaddress.ip_address(old_address).version != 4
                            or ipaddress.ip_address(migration["pbx_address"]).version != 4):
                        raise ValueError()
                except ValueError as error:
                    raise BrokerError("Invalid pending workstation migration address; access remains unavailable.")
                if migration["locked"]:
                    if (not isinstance(migration.get("sources"), list) or not migration["sources"]
                            or type(migration.get("listener_port")) is not int
                            or not isinstance(migration.get("subnet"), str)):
                        raise BrokerError("Incomplete pending dedicated-listener migration; access remains unavailable.")
            ssh_request = item.get("ssh_request")
            if ssh_request is not None:
                try:
                    if (not isinstance(ssh_request, dict)
                            or set(ssh_request) != {"public_key", "created_at"}
                            or ssh.public_key(ssh_request["public_key"]) != ssh_request["public_key"]
                            or type(ssh_request["created_at"]) is not int or ssh_request["created_at"] <= 0):
                        raise ValueError()
                except (KeyError, TypeError, ssh.SshError) as error:
                    raise BrokerError("Invalid pending workstation SSH request; it cannot be approved.") from error
            unlock_request = item.get("unlock_request")
            if unlock_request is not None and (
                    not isinstance(unlock_request, dict)
                    or set(unlock_request) != {"created_at"}
                    or type(unlock_request["created_at"]) is not int
                    or unlock_request["created_at"] <= 0):
                raise BrokerError("Invalid pending workstation unlock request.")
            sources_request = item.get("sources_request")
            if sources_request is not None:
                try:
                    if (not isinstance(sources_request, dict)
                            or set(sources_request) != {"sources", "created_at"}
                            or not isinstance(sources_request["sources"], list)
                            or not sources_request["sources"]
                            or parse_source_restrictions(", ".join(sources_request["sources"])) != sources_request["sources"]
                            or type(sources_request["created_at"]) is not int
                            or sources_request["created_at"] <= 0):
                        raise ValueError()
                except (KeyError, TypeError, ValueError, BrokerError) as error:
                    raise BrokerError("Invalid pending workstation source-list request.") from error
            valid.append(item)
        bans = stored.get("bans", [])
        if not isinstance(bans, list) or len(bans) > 256:
            raise BrokerError("Invalid saved TELIPHONES banned list.")
        safe_bans = []
        seen_ban_ids = set()
        for ban in bans:
            if (not isinstance(ban, dict) or not isinstance(ban.get("id"), str)
                    or re.fullmatch(r"[a-f0-9]{16}", ban["id"]) is None or ban["id"] in seen_ban_ids
                    or not isinstance(ban.get("source"), str) or not isinstance(ban.get("reason"), str)
                    or len(ban["reason"]) > 160
                    or (ban.get("expires_at") is not None
                        and (type(ban["expires_at"]) is not int or ban["expires_at"] <= 0))):
                raise BrokerError("Invalid saved TELIPHONES ban; listener policy remains unavailable.")
            try:
                source = str(ipaddress.ip_network(ban["source"], strict=False))
            except ValueError as error:
                raise BrokerError("Invalid saved TELIPHONES ban; listener policy remains unavailable.") from error
            if source != ban["source"]:
                raise BrokerError("Non-canonical saved TELIPHONES ban; listener policy remains unavailable.")
            seen_ban_ids.add(ban["id"])
            safe_bans.append({"id": ban["id"], "source": source, "reason": ban["reason"],
                              "expires_at": ban.get("expires_at")})
        mode = stored.get("connection_state")
        if mode is None:
            mode = "open" if valid else "closed"
        if mode not in ("open", "closed", "frozen"):
            raise BrokerError("Invalid saved workstation connection state; access remains unavailable.")
        state = {"subnet": stored.get("subnet") if isinstance(stored.get("subnet"), str) else None,
                 "listen_port": stored.get("listen_port") if isinstance(stored.get("listen_port"), int) else None,
                 "web": normalise_web(stored.get("web")),
                 "connection_state": mode,
                 "max_sessions": stored.get("max_sessions", 1),
                 "workstations": valid,
                 "bans": safe_bans}
        if type(state["max_sessions"]) is not int or not 1 <= state["max_sessions"] <= 128:
            raise BrokerError("Invalid maximum simultaneous workstation setting.")
        changed = (len(valid) != len(items) or stored.get("connection_state") != mode
                   or stored.get("max_sessions") != state["max_sessions"]
                   or (mode != "closed" and (state["subnet"] is None or state["listen_port"] is None)))
        return state, changed

    def save_workstations(self, state):
        atomic(STATE / "workstations.json", json.dumps(state, indent=2, sort_keys=True))

    def active_sessions(self):
        stored = read_json(STATE / "active-sessions.json")
        sessions = stored.get("sessions", {})
        if not isinstance(sessions, dict) or len(sessions) > 1024:
            raise BrokerError("Invalid active workstation session ledger; management access remains blocked.")
        clean = {}
        for workstation_id, lease in sessions.items():
            if (not isinstance(workstation_id, str) or re.fullmatch(r"[a-f0-9]{16}", workstation_id) is None
                    or not isinstance(lease, dict) or type(lease.get("expires_at")) is not int
                    or lease["expires_at"] <= 0):
                raise BrokerError("Invalid active workstation session lease; management access remains blocked.")
            if lease["expires_at"] > int(time.time()):
                clean[workstation_id] = {"expires_at": lease["expires_at"]}
        return clean

    def save_active_sessions(self, sessions):
        atomic(STATE / "active-sessions.json", json.dumps({"sessions": sessions}, sort_keys=True))

    def choose_subnet(self, reserved=()):
        used = []
        for value in reserved:
            try:
                used.append(ipaddress.IPv4Network(value))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
                raise BrokerError("Invalid reserved workstation tunnel subnet.")
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

    @staticmethod
    def locked_interface(item):
        return "tlpw" + hashlib.sha256(item["id"].encode()).hexdigest()[:11]

    def locked_listener_port(self, item, workstations, shared_port):
        occupied = {shared_port}
        occupied.update(entry.get("listener_port") for entry in workstations
                        if isinstance(entry.get("listener_port"), int))
        start = int(hashlib.sha256(item["id"].encode()).hexdigest()[:8], 16) % len(LISTENER_PORT_RANGE)
        for offset in range(len(LISTENER_PORT_RANGE)):
            candidate = LISTENER_PORT_RANGE[(start + offset) % len(LISTENER_PORT_RANGE)]
            if candidate in occupied:
                continue
            sockets = []
            try:
                for family, address in ((socket.AF_INET, ("0.0.0.0", candidate)),
                                        (socket.AF_INET6, ("::", candidate, 0, 0))):
                    probe = socket.socket(family, socket.SOCK_DGRAM)
                    sockets.append(probe)
                    if family == socket.AF_INET6:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    probe.bind(address)
                return candidate
            except OSError:
                continue
            finally:
                for probe in sockets:
                    probe.close()
        raise BrokerError("No dedicated WireGuard listener UDP ports remain.")

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

    def link_state(self, interface=WORKSTATION_IFACE):
        links = json.loads(self.run([self.tool("ip"), "-j", "link", "show"]))
        if not isinstance(links, list) or any(not isinstance(link, dict) or not isinstance(link.get("ifname"), str)
                                              or not isinstance(link.get("flags"), list) for link in links):
            raise BrokerError("Workstation interface inventory could not be verified.")
        matches = [link for link in links if link.get("ifname") == interface]
        if len(matches) > 1:
            raise BrokerError("Ambiguous workstation interface.")
        return matches[0] if matches else None

    def disable_workstations(self):
        interfaces = [WORKSTATION_IFACE]
        state_error = None
        try:
            state = read_json(STATE / "workstations.json")
            interfaces.extend(self.locked_interface(item) for item in state.get("workstations", [])
                              if isinstance(item, dict) and re.fullmatch(r"[a-f0-9]{16}", str(item.get("id", "")))
                              and item.get("locked") is True)
        except BrokerError as error:
            state_error = error
        links = json.loads(self.run([self.tool("ip"), "-j", "link", "show"]))
        interfaces.extend(link["ifname"] for link in links if isinstance(link, dict)
                          and re.fullmatch(r"tlpw[a-f0-9]{11}", str(link.get("ifname", ""))))
        for interface in interfaces:
            if self.link_state(interface) is None:
                continue
            self.run([self.tool("ip"), "link", "set", "down", "dev", interface], check=False)
            link = self.link_state(interface)
            if link is not None and "UP" in link["flags"]:
                # Deletion is a second way to stop traffic, never permission to remove policy on failure.
                self.run([self.tool("ip"), "link", "del", "dev", interface], check=False)
                if self.link_state(interface) is not None:
                    raise BrokerError("Workstation interface could not be disabled or removed; retaining firewall and recovery state.")
        if state_error is not None:
            raise state_error

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
        return self.validate_owned_table(document)

    def validate_owned_table(self, document):
        if (not isinstance(document, dict) or not isinstance(document.get("nftables"), list)
                or any(not isinstance(item, dict) or len(item) != 1 for item in document["nftables"])):
            raise BrokerError("Invalid workstation table JSON.")
        tables = [item["table"] for item in document["nftables"] if "table" in item]
        if any(not isinstance(table, dict) for table in tables):
            raise BrokerError("Invalid workstation table identity.")
        if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != WORKSTATION_TABLE:
            raise BrokerError("Unfamiliar inet teliphones_workstations table; it will not be modified.")
        if tables[0].get("comment") not in (None, WORKSTATION_OWNER):
            raise BrokerError("Unexpected workstation table comment; refusing modification.")
        owner_chains = [item["chain"] for item in document["nftables"]
                        if "chain" in item and isinstance(item["chain"], dict)
                        and item["chain"].get("name") == WORKSTATION_OWNER_CHAIN]
        if owner_chains:
            if (len(owner_chains) != 1
                    or set(owner_chains[0]) - {"family", "table", "name", "handle"}
                    or any(owner_chains[0].get(key) != value for key, value in
                           (("family", "inet"), ("table", WORKSTATION_TABLE),
                            ("name", WORKSTATION_OWNER_CHAIN)))
                    or any(item.get("rule", {}).get("chain") == WORKSTATION_OWNER_CHAIN
                           for item in document["nftables"] if isinstance(item, dict))):
                raise BrokerError("Workstation ownership chain has unexpected configuration; refusing modification.")
            return document

        # One-time migration from the 0.3.0 table comment, which nftables 1.0.6
        # drops when returning kernel state. Reconstruct only the exact old policy
        # using the root-owned subnet and SSH-source matches before adopting it.
        persisted = read_json(STATE / "workstations.json")
        try:
            network = ipaddress.IPv4Network(persisted.get("subnet"))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError) as error:
            raise BrokerError("Legacy workstation table cannot be matched to saved TELIPHONES state; refusing migration.") from error
        self.expected_policy({"subnet": str(network), "workstations": []})
        ssh_sources = set()
        for item in document["nftables"]:
            rule = item.get("rule")
            if not isinstance(rule, dict):
                continue
            for expression in rule.get("expr", []):
                if (isinstance(expression, dict) and isinstance(expression.get("match"), dict)
                        and expression["match"].get("left") == {"payload": {"protocol": "ip", "field": "saddr"}}):
                    try:
                        source = ipaddress.IPv4Address(expression["match"].get("right"))
                    except (ipaddress.AddressValueError, TypeError) as error:
                        raise BrokerError("Legacy workstation source is invalid; refusing migration.") from error
                    if source not in network:
                        raise BrokerError("Legacy workstation source is outside the saved subnet; refusing migration.")
                    ssh_sources.add(str(source))
        expected = workstation_policy(str(network[1]), sorted(ssh_sources))
        legacy = {"nftables": [item for item in expected["nftables"]
                               if "chain" not in item or item["chain"].get("name") != WORKSTATION_OWNER_CHAIN]}
        if tables[0].get("comment") == WORKSTATION_OWNER:
            legacy["nftables"][0] = {"table": {**legacy["nftables"][0]["table"],
                                               "comment": WORKSTATION_OWNER}}
        if not policy_equal(document, legacy):
            raise BrokerError("Unmarked workstation table does not exactly match the saved TELIPHONES policy; refusing migration.")
        link = self.link_state()
        if link is not None and "UP" in link["flags"]:
            raise BrokerError("Legacy workstation table cannot be migrated while the tunnel is up; refusing modification.")
        return document

    def expected_policy(self, state, include_expired_bans=False):
        network = ipaddress.IPv4Network(state["subnet"])
        if not network.subnet_of(WORKSTATION_POOL) or network.prefixlen != 24 or network.overlaps(WORKSTATION_EXCLUDED):
            raise BrokerError("Invalid workstation subnet.")
        listener_sources = []
        peer_interfaces = []
        banned_sources = []
        active_sessions = self.active_sessions()
        active_ids = {item["id"] for item in state["workstations"]} & set(active_sessions)
        admitted_sources = {item["address"].split("/")[0] for item in state["workstations"]
                            if item["id"] in active_ids and not item.get("migration")}
        control_sources = {item["address"].split("/")[0] for item in state["workstations"]}
        reserved_subnets = [network]
        shared_listener_port = state.get("listen_port")
        listener_ports = {shared_listener_port} if type(shared_listener_port) is int else set()
        for item in state["workstations"]:
            migration = item.get("migration")
            if migration:
                old_source = migration["address"].split("/")[0]
                control_sources.add(old_source)
                if migration["locked"] and not item.get("locked"):
                    old_subnet = ipaddress.IPv4Network(migration["subnet"])
                    if (old_subnet.prefixlen != 24 or not old_subnet.subnet_of(WORKSTATION_POOL)
                            or old_subnet.overlaps(WORKSTATION_EXCLUDED)
                            or migration["pbx_address"] != str(old_subnet[1])
                            or migration["address"] != str(old_subnet[2]) + "/32"
                            or type(migration.get("listener_port")) is not int
                            or not LISTENER_PORT_RANGE.start <= migration["listener_port"] < LISTENER_PORT_RANGE.stop
                            or not migration.get("sources")):
                        raise BrokerError("Invalid retired dedicated listener during workstation migration.")
                    old_sources, _ = resolve_source_restrictions(migration["sources"], cache=self.source_cache)
                    listener_sources.append({"port": migration["listener_port"], "sources": old_sources})
                    peer_interfaces.append({"interface": "tlpw" + hashlib.sha256(item["id"].encode()).hexdigest()[:11],
                                             "pbx_address": migration["pbx_address"], "source": old_source})
            if not item.get("locked"):
                continue
            station_network = ipaddress.IPv4Network(item["subnet"])
            if (station_network.prefixlen != 24 or not station_network.subnet_of(WORKSTATION_POOL)
                    or station_network.overlaps(WORKSTATION_EXCLUDED)
                    or any(station_network.overlaps(other) for other in reserved_subnets)
                    or item["pbx_address"] != str(station_network[1])
                    or item["address"] != str(station_network[2]) + "/32"
                    or type(item["listener_port"]) is not int
                    or not LISTENER_PORT_RANGE.start <= item["listener_port"] < LISTENER_PORT_RANGE.stop
                    or item["listener_port"] in listener_ports
                    or not item["sources"]):
                raise BrokerError("Invalid dedicated listener assignment for a Locked workstation.")
            reserved_subnets.append(station_network)
            listener_ports.add(item["listener_port"])
            sources, _ = resolve_source_restrictions(item["sources"], cache=self.source_cache)
            listener_sources.append({"port": item["listener_port"], "sources": sources})
            peer = {"interface": self.locked_interface(item), "pbx_address": item["pbx_address"],
                    "source": item["address"].split("/")[0]}
            if ssh.managed(item):
                peer.update(source=item["address"].split("/")[0], ssh_port=ssh.port(item))
            peer_interfaces.append(peer)
        if state.get("connection_state") != "closed" and not (STATE / "disabled").exists():
            active_ports = set()
            if type(shared_listener_port) is int:
                active_ports.add(shared_listener_port)
            active_ports.update(item["listener_port"] for item in state["workstations"] if item.get("locked"))
            now = int(time.time())
            for ban in state.get("bans", []):
                if include_expired_bans or ban.get("expires_at") is None or ban["expires_at"] > now:
                    banned_sources.extend({"port": port, "source": ban["source"]}
                                          for port in active_ports)
        return workstation_policy(str(network[1]),
                                  [item["address"].split("/")[0] for item in state["workstations"] if item.get("ssh") is True and not ssh.managed(item)],
                                  [(item["address"].split("/")[0], ssh.port(item)) for item in state["workstations"]
                                   if ssh.managed(item) and not item.get("locked")],
                                  tuple(entry["port"] for entry in normalise_web(state.get("web"))),
                                  listener_sources, peer_interfaces, banned_sources,
                                  admitted_sources=admitted_sources, control_sources=control_sources)

    def reconcile_policy_only(self, state):
        if state["connection_state"] == "closed" or (STATE / "disabled").exists():
            return
        self.start_monitor()
        expected = self.expected_policy(state)
        self.mutate_policy(expected, self.owned_table())
        if not policy_equal(self.owned_table(), expected):
            raise BrokerError("TELIPHONES listener policy did not reconcile to the complete expected firewall state.")

    def workstation_session(self, action, source, destination=None, ssh_public_key=None):
        try:
            address = str(ipaddress.ip_address(source))
        except ValueError as error:
            raise BrokerError("Workstation session request has an invalid tunnel source.") from error
        with self.wslock:
            state, _ = self.workstation_state()
            item = next((entry for entry in state["workstations"] if entry["address"].split("/")[0] == address), None)
            migration_item = next((entry for entry in state["workstations"]
                                   if entry.get("migration", {}).get("address", "").split("/")[0] == address
                                   and (destination is None or entry["migration"]["pbx_address"] == destination)), None)
            migration_source = migration_item is not None and (
                item is None or destination == migration_item["migration"]["pbx_address"])
            if migration_source:
                item = migration_item
            if item is None:
                item = migration_item
                migration_source = item is not None
            if item is None:
                raise BrokerError("This authenticated WireGuard peer is not an approved workstation.")
            if state["connection_state"] == "closed" or (STATE / "disabled").exists():
                raise BrokerError("PBX Closed: workstation access is unavailable.")
            if self.integration.get("state") == "error":
                raise BrokerError("FreePBX Firewall integration is unsafe; a management session cannot be admitted.")
            migration = item.get("migration")
            if action == "lock-current":
                if migration_source or migration:
                    raise BrokerError("Lock to Current IP is unavailable while listener migration is pending.")
                updated = self.manage_workstation({"workstation_id": item["id"],
                                                   "state": "lock", "sources": "current"}, 0)
                return {"workstation_change_status": "applied",
                        "migration_pending": updated["migration_pending"]}
            if action == "unlock-request":
                if migration_source or migration:
                    raise BrokerError("Unlock requests are unavailable while listener migration is pending.")
                if item["id"] not in self.active_sessions():
                    raise BrokerError("A PBX-admitted administrative session is required to request an unlock.")
                if not item.get("locked"):
                    return {"unlock_request_status": "applied"}
                if not item.get("unlock_request"):
                    item["unlock_request"] = {"created_at": int(time.time())}
                    self.save_workstations(state)
                return {"unlock_request_status": "pending"}
            if action == "sources-request":
                if migration_source or migration:
                    raise BrokerError("Allowed List changes are unavailable while listener migration is pending.")
                if item["id"] not in self.active_sessions():
                    raise BrokerError("A PBX-admitted administrative session is required to request an Allowed List change.")
                if not isinstance(ssh_public_key, str):
                    raise BrokerError("The requested Allowed List must be supplied.")
                requested_sources = parse_source_restrictions(ssh_public_key)
                if not requested_sources:
                    raise BrokerError("Enter at least one permitted IP address, CIDR range or DNS name.")
                item["sources_request"] = {"sources": requested_sources, "created_at": int(time.time())}
                self.save_workstations(state)
                return {"sources_request_status": "pending"}
            if action == "ssh-request":
                if migration_source or migration:
                    raise BrokerError("SSH elevation requests are unavailable while listener migration is pending.")
                if item["id"] not in self.active_sessions():
                    raise BrokerError("A PBX-admitted administrative session is required to request SSH access.")
                if ssh.managed(item):
                    return {"ssh_request_status": "applied"}
                try:
                    requested_key = ssh.public_key(ssh_public_key)
                except (ssh.SshError, TypeError, AttributeError) as error:
                    raise BrokerError("A valid workstation SSH public key is required.") from error
                if item.get("ssh_request", {}).get("public_key") != requested_key:
                    item["ssh_request"] = {"public_key": requested_key, "created_at": int(time.time())}
                    self.save_workstations(state)
                return {"ssh_request_status": "pending"}
            if migration and migration_source and action == "heartbeat":
                return {"active": False, "expires_at": None,
                        "connected_workstations": len(self.active_sessions()),
                        "max_sessions": state["max_sessions"],
                        "migration": {"workstation_id": item["id"],
                                      "workstation_public_key": item["public_key"],
                                      "pbx_public_key": self.server_public_key(),
                                      "address": item["address"],
                                      "pbx_address": item["pbx_address"],
                                      "listener_port": item.get("listener_port", state["listen_port"]),
                                      "gui_url": gui_url(state["web"], item["pbx_address"]),
                                      "ssh_port": ssh.port(item) if ssh.managed(item) else 0,
                                      "ssh_api_port": ssh.API_PORT if ssh.managed(item) else 0,
                                      "generation": migration["id"]}}
            if migration and action == "heartbeat":
                previous = json.loads(json.dumps(state))
                item.pop("migration", None)
                try:
                    self.apply_workstations(state, preserve_unrelated=True)
                    self.save_workstations(state)
                except (BrokerError, OSError, subprocess.SubprocessError) as error:
                    try:
                        self.apply_workstations(previous, preserve_unrelated=True)
                        self.save_workstations(previous)
                    except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                        self.workstation_error = "Workstation migration acknowledgement failed; both old and new management paths remain blocked: " + str(rollback_error)
                    raise BrokerError("The new workstation listener could not be acknowledged safely; the migration remains pending.") from error
            previous = self.active_sessions()
            current = {key: value for key, value in previous.items()
                       if any(entry["id"] == key for entry in state["workstations"])}
            if action == "release":
                current.pop(item["id"], None)
            elif action == "heartbeat":
                if item["id"] not in current and len(current) >= state["max_sessions"]:
                    raise BrokerError("Session limit reached: %d of %d workstation connections are active." %
                                      (len(current), state["max_sessions"]))
                current[item["id"]] = {"expires_at": int(time.time()) + SESSION_LEASE_SECONDS}
            else:
                raise BrokerError("Unsupported workstation session operation.")
            self.save_active_sessions(current)
            try:
                self.reconcile_policy_only(state)
            except (BrokerError, OSError, subprocess.SubprocessError) as error:
                self.save_active_sessions(previous)
                try:
                    self.disable_workstations()
                except (BrokerError, OSError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error = "Session firewall update failed and workstation shutdown is unverified: " + str(cleanup_error)
                raise BrokerError("Workstation session firewall could not be verified; access was disabled.") from error
            self.lease_wake.set()
            response = {"active": action == "heartbeat", "expires_at": current.get(item["id"], {}).get("expires_at"),
                        "connected_workstations": len(current), "max_sessions": state["max_sessions"]}
            if action == "heartbeat":
                try:
                    current_source = self.verified_workstation_source(item) \
                        if isinstance(item.get("public_key"), str) else None
                except (BrokerError, OSError, subprocess.SubprocessError):
                    current_source = None
                effective, failed = resolve_source_restrictions(item.get("sources", []), cache=self.source_cache) \
                    if item.get("locked") else ([], [])
                response["policy"] = {"locked": item.get("locked") is True,
                                      "sources": item.get("sources", []),
                                      "effective_source_count": len(effective),
                                      "source_resolution_failures": failed,
                                      "current_source": current_source,
                                      "ssh_approved": item.get("ssh") is True,
                                      "ssh_request_pending": bool(item.get("ssh_request")),
                                      "unlock_request_pending": bool(item.get("unlock_request")),
                                      "sources_request_pending": bool(item.get("sources_request")),
                                      "requested_sources": item.get("sources_request", {}).get("sources", []),
                                      "connection_state": state["connection_state"],
                                      "listener_port": item.get("listener_port", state.get("listen_port", 51821))}
                if ssh.managed(item):
                    response["policy"]["ssh_configuration"] = {
                        "ssh_user": item["ssh_user"], "ssh_public_key": item["ssh_public_key"],
                        "ssh_host_key": self.ssh.host_key(), "ssh_ca_key": self.ssh.initialise(),
                        "ssh_port": ssh.port(item), "ssh_api_port": ssh.API_PORT}
            return response

    def reconcile_session_servers(self, state=None):
        if not self.session_server_enabled:
            return
        if state is None:
            state, _ = self.workstation_state()
        wanted = set()
        if state["connection_state"] != "closed" and not (STATE / "disabled").exists():
            for item in state["workstations"]:
                wanted.add(item["pbx_address"] if item.get("locked")
                           else str(ipaddress.IPv4Network(state["subnet"])[1]))
                if item.get("migration"):
                    wanted.add(item["migration"]["pbx_address"])
        for address in set(self.session_servers) - wanted:
            server, thread = self.session_servers.pop(address)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        for address in wanted - set(self.session_servers):
            broker = self

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.path != "/workstation/session":
                        self.send_error(404)
                        return
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        if not 1 <= length <= 4096:
                            raise BrokerError("Invalid workstation session request.")
                        request = json.loads(self.rfile.read(length))
                        if (not isinstance(request, dict)
                                or set(request) != ({"action", "ssh_public_key"} if request.get("action") == "ssh-request"
                                                    else {"action", "sources"} if request.get("action") == "sources-request"
                                                    else {"action"})):
                            raise BrokerError("Invalid workstation session request.")
                        result = broker.workstation_session(request["action"], self.client_address[0],
                                                            self.server.server_address[0],
                                                            request.get("ssh_public_key", request.get("sources")))
                        response = {"ok": True, **result}
                        status = 200
                    except (BrokerError, ValueError, TypeError) as error:
                        response = {"ok": False, "error": str(error) if isinstance(error, BrokerError)
                                    else "Invalid workstation session request."}
                        status = 409
                    payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, format, *args):
                    return

            server = ThreadingHTTPServer((address, SESSION_CONTROL_PORT), Handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.session_servers[address] = (server, thread)

    def stop_session_servers(self):
        self.session_server_enabled = False
        for address, (server, thread) in list(self.session_servers.items()):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.session_servers.pop(address, None)

    def configure_workstation_limit(self, request, uid):
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        state["max_sessions"] = int(request["maximum"])
        active = self.active_sessions()
        if len(active) > state["max_sessions"]:
            raise BrokerError("The maximum cannot be lower than the %d currently active workstation session(s)." % len(active))
        try:
            self.save_workstations(state)
        except (BrokerError, OSError) as error:
            try:
                self.save_workstations(previous)
            except (BrokerError, OSError) as rollback_error:
                self.workstation_error = "Session limit could not be saved or rolled back: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        self.audit("workstation-limit", uid, "completed")
        return state["max_sessions"]

    def expire_sessions(self):
        with self.wslock:
            state, _ = self.workstation_state()
            previous = self.active_sessions()
            workstation_ids = {item["id"] for item in state["workstations"]}
            current = {key: value for key, value in previous.items()
                       if key in workstation_ids and value["expires_at"] > int(time.time())}
            if current == previous:
                return
            self.save_active_sessions(current)
            try:
                self.reconcile_policy_only(state)
            except (BrokerError, OSError, subprocess.SubprocessError) as error:
                try:
                    self.disable_workstations()
                except (BrokerError, OSError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error = "Expired session cleanup failed and workstation shutdown is unverified: " + str(cleanup_error)
                raise BrokerError("Expired workstation sessions could not be removed from the firewall.") from error

    def configure_ban(self, request, uid):
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        if request["action"] == "workstation-ban":
            network = str(ipaddress.ip_network(request["source"].strip(), strict=False))
            if any(item["source"] == network and (item["expires_at"] is None or item["expires_at"] > int(time.time()))
                   for item in state["bans"]):
                raise BrokerError("That source already has an active TELIPHONES ban.")
            hours = None if request["hours"] == "never" else int(request["hours"])
            state["bans"].append({"id": secrets.token_hex(8), "source": network,
                                  "reason": request["reason"].strip(),
                                  "expires_at": int(time.time()) + hours * 3600 if hours is not None else None})
        else:
            state["bans"] = [item for item in state["bans"] if item["id"] != request["ban_id"]]
            if len(state["bans"]) == len(previous["bans"]):
                raise BrokerError("Unknown TELIPHONES ban; it may already have been removed.")
        try:
            self.reconcile_policy_only(state)
            self.save_workstations(state)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            try:
                self.reconcile_policy_only(previous)
            except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                self.workstation_error = "Banned-list change failed and firewall rollback could not be verified: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        self.audit(request["action"], uid, "completed")
        return state

    def verified_workstation_source(self, item):
        interface = self.locked_interface(item) if item.get("locked") else WORKSTATION_IFACE
        key = item["public_key"]
        handshakes = (self.run([self.tool("wg"), "show", interface, "latest-handshakes"]) or "").splitlines()
        endpoints = (self.run([self.tool("wg"), "show", interface, "endpoints"]) or "").splitlines()
        handshake = next((line.split()[1] for line in handshakes
                          if len(line.split()) == 2 and line.split()[0] == key), None)
        endpoint = next((line.split(maxsplit=1)[1] for line in endpoints
                         if len(line.split(maxsplit=1)) == 2 and line.split(maxsplit=1)[0] == key), None)
        if handshake is None or not handshake.isdigit() or int(handshake) <= 0 or int(time.time()) - int(handshake) > 180:
            raise BrokerError("Lock to Current IP requires a verified WireGuard handshake within the last three minutes.")
        observed = parse_wireguard_endpoint(endpoint or "")
        if observed is None:
            raise BrokerError("The workstation's authenticated public source could not be verified.")
        address = ipaddress.ip_address(observed["address"])
        return str(address) + ("/32" if address.version == 4 else "/128")

    def manage_workstation(self, request, uid):
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        item = next((entry for entry in state["workstations"] if entry["id"] == request["workstation_id"]), None)
        if item is None:
            raise BrokerError("Unknown workstation; it may already have been revoked or expired.")
        initial_locked = item.get("locked") is True
        if item.get("migration") and request["state"] != ("lock" if initial_locked else "unlock"):
            raise BrokerError("A listener migration is already pending; wait for the existing Windows profile to acknowledge it before changing listener mode.")
        initial_config = {"locked": initial_locked, "address": item["address"],
                          "pbx_address": item["pbx_address"] if initial_locked
                          else str(ipaddress.IPv4Network(state["subnet"])[1])}
        if initial_locked:
            initial_config.update(sources=item["sources"], subnet=item["subnet"],
                                  listener_port=item["listener_port"])

        if request["state"] == "lock":
            sources = [self.verified_workstation_source(item)] if request["sources"] == "current" else \
                parse_source_restrictions(request["sources"])
            if not sources:
                raise BrokerError("Enter at least one permitted IP address, CIDR range or DNS name.")
            if item.get("locked"):
                item["sources"] = sources
            else:
                network = ipaddress.IPv4Network(state["subnet"])
                reserved = [str(network)] + [entry["subnet"] for entry in state["workstations"]
                                              if entry.get("locked")]
                subnet = self.choose_subnet(reserved)
                station_network = ipaddress.IPv4Network(subnet)
                listener_port = self.locked_listener_port(item, state["workstations"], state["listen_port"])
                item.update(locked=True, sources=sources, subnet=subnet,
                            pbx_address=str(station_network[1]),
                            address=str(station_network[2]) + "/32",
                            listener_port=listener_port)
        else:
            if item.get("locked"):
                network = ipaddress.IPv4Network(state["subnet"])
                taken = {entry["address"] for entry in state["workstations"]
                         if entry["id"] != item["id"] and not entry.get("locked")}
                address = next((str(host) + "/32" for host in list(network.hosts())[1:]
                                if str(host) + "/32" not in taken), None)
                if address is None:
                    raise BrokerError("No shared-listener workstation addresses remain; revoke unused pairings first.")
                item["address"] = address
                item["pbx_address"] = str(network[1])
                for field in ("sources", "subnet", "listener_port"):
                    item.pop(field, None)
                item["locked"] = False

        if initial_locked != (item.get("locked") is True):
            migration = item.get("migration")
            if migration is None:
                item["migration"] = {"id": secrets.token_hex(16), **initial_config}
        item.pop("unlock_request", None)
        item.pop("sources_request", None)

        if item.get("migration"):
            # Persist the transition and revoke its old management lease before
            # changing peers. A restart can therefore only restore a
            # control-channel-only old path until the same key arrives at the
            # new address.
            self.save_workstations(state)
            sessions = self.active_sessions()
            sessions.pop(item["id"], None)
            self.save_active_sessions(sessions)
            try:
                self.reconcile_policy_only(state)
            except (BrokerError, OSError, subprocess.SubprocessError) as error:
                old_interface = self.locked_interface(item) if initial_locked else WORKSTATION_IFACE
                if self.link_state(old_interface) is not None:
                    self.run([self.tool("wg"), "set", old_interface, "peer", item["public_key"], "remove"],
                             check=False)
                self.workstation_error = "Workstation migration could not install its restricted firewall; the affected peer was disconnected: " + str(error)
                raise BrokerError(self.workstation_error) from error

        try:
            self.apply_workstations(state, preserve_unrelated=True)
            self.save_workstations(state)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            try:
                if item.get("migration"):
                    self.save_workstations(state)
                else:
                    self.apply_workstations(previous, preserve_unrelated=True)
                    self.save_workstations(previous)
            except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                self.workstation_error = "Workstation policy update and rollback failed; affected access remains blocked: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        self.audit("workstation-manage", uid, "completed")
        return {"id": item["id"], "locked": item.get("locked") is True,
                "sources": item.get("sources", []),
                "migration_pending": bool(item.get("migration")),
                "migration_generation": item.get("migration", {}).get("id"),
                "listener_port": item.get("listener_port", state["listen_port"]),
                "address": item["address"], "pbx_address": item["pbx_address"]}

    def manage_workstation_ssh(self, request, uid, operation):
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        item = next((entry for entry in state["workstations"] if entry["id"] == request["workstation_id"]), None)
        if item is None:
            raise BrokerError("Unknown workstation; SSH access was not changed.")
        if operation == "revoke":
            if not ssh.managed(item):
                raise BrokerError("This workstation has no managed SSH authorisation to revoke.")
            item["ssh"] = False
            for field in ("ssh_public_key", "ssh_user"):
                item.pop(field, None)
            item.pop("ssh_request", None)
        elif not item.get("ssh_request"):
            raise BrokerError("There is no pending SSH elevation request for that workstation.")
        elif operation == "approve":
            pending = item["ssh_request"]
            item.update(ssh=True, ssh_public_key=pending["public_key"], ssh_user=request["ssh_user"])
            try:
                self.ssh.account_policy(item, item.get("pbx_address", str(ipaddress.IPv4Network(state["subnet"])[1])))
            except (ssh.SshError, OSError, subprocess.SubprocessError) as error:
                raise BrokerError("The selected existing Linux account cannot receive managed SSH access: " + str(error)) from error
            item.pop("ssh_request", None)
        else:
            item.pop("ssh_request", None)
        try:
            self.apply_workstations(state, preserve_unrelated=True)
            self.save_workstations(state)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            try:
                self.apply_workstations(previous, preserve_unrelated=True)
                self.save_workstations(previous)
            except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                self.workstation_error = "SSH elevation change and rollback failed; workstation recovery is required: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        self.audit("workstation-ssh-" + operation, uid, "completed")
        return item

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
            elif iptables_target(tokens) == INTEGRATION_CHAIN and (
                    (chain == "INPUT" and iptables_rule(tokens) not in (INTEGRATION_JUMP, LEGACY_INTEGRATION_JUMP))
                    or (chain == FREEPBX_HOOK and iptables_rule(tokens) != INTEGRATION_JUMP)
                    or chain not in ("INPUT", FREEPBX_HOOK)):
                raise BrokerError("Unexpected reference to iptables chain %s from %s; it will not be modified." % (INTEGRATION_CHAIN, chain))
        return chains, rules

    @staticmethod
    def integration_positions(rules):
        targets = [iptables_target(tokens) for chain, tokens in rules if chain == "INPUT"]
        firewall_targets = [iptables_target(tokens) for chain, tokens in rules if chain == FREEPBX_HOOK]
        return ([index for index, target in enumerate(targets) if target == FREEPBX_HOOK],
                [index for index, target in enumerate(targets) if is_fail2ban_hook(target)],
                [index for index, target in enumerate(firewall_targets) if target == INTEGRATION_CHAIN])

    def remove_integration_jumps(self, iptables, rules, parents=("INPUT", FREEPBX_HOOK)):
        # Inventory has validated every reference, including legacy 0.4.0 INPUT jumps.
        for chain, tokens in rules:
            if chain in parents and iptables_target(tokens) == INTEGRATION_CHAIN:
                self.ipt(iptables, "-D", chain, *tokens)

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
        # Withdraw the intrusive legacy hook before doing anything that might fail or return early.
        self.remove_integration_jumps(iptables, rules, parents=("INPUT",))
        if any(chain == "INPUT" and iptables_target(tokens) == INTEGRATION_CHAIN for chain, tokens in rules):
            chains, rules = self.integration_inventory(iptables)
        hooks, bans, _ = self.integration_positions(rules)
        if not hooks:
            self.remove_integration()
            self.integration_status("not-detected", "No iptables INPUT jump to %s (FreePBX Firewall) was found; no integration rules were installed. "
                                    "If FreePBX Firewall is enabled and tunnel traffic is dropped, report this." % FREEPBX_HOOK, backend)
            return
        if bans and max(bans) > hooks[0]:
            # Entry to fpbxfirewall must follow every Fail2Ban hook.
            targets = [iptables_target(tokens) for chain, tokens in rules if chain == "INPUT"]
            late = sorted({targets[index] for index in bans if index > hooks[0]})
            self.remove_integration()
            self.integration_status("error", "Fail2Ban INPUT hook(s) %s follow the FreePBX Firewall hook (%s), so no position both after Fail2Ban "
                                    "and inside FreePBX Firewall exists; integration was not installed (Fail2Ban is not bypassed) and FreePBX "
                                    "Firewall may drop tunnel traffic. Check with: iptables -S INPUT" % (", ".join(late)[:200], FREEPBX_HOOK), backend)
            return
        network = ipaddress.IPv4Network(state["subnet"])
        web = normalise_web(state.get("web"))
        integrated_workstations = []
        for item in state["workstations"]:
            integrated = dict(item)
            if item.get("locked"):
                integrated["interface"] = self.locked_interface(item)
                integrated["pbx_address"] = item["pbx_address"]
            integrated_workstations.append(integrated)
        migration_controls = []
        for item in state["workstations"]:
            migration = item.get("migration")
            if not migration:
                continue
            migration_controls.append({
                "address": migration["address"],
                "pbx_address": migration["pbx_address"],
                "interface": self.locked_interface(item) if migration.get("locked") else WORKSTATION_IFACE,
            })
        expected = integration_rules(str(network[1]), integrated_workstations, web, migration_controls)
        for item in state["workstations"]:
            if item.get("locked"):
                station_network = ipaddress.IPv4Network(item["subnet"])
                if (station_network.prefixlen != 24 or not station_network.subnet_of(WORKSTATION_POOL)
                        or station_network.overlaps(network)
                        or not ipaddress.IPv4Network(item["address"]).subnet_of(station_network)
                        or item.get("pbx_address") != str(station_network[1])):
                    raise BrokerError("Locked workstation address is outside its dedicated tunnel subnet.")
            elif not ipaddress.IPv4Network(item["address"]).subnet_of(network):
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
            self.remove_integration_jumps(iptables, rules, parents=(FREEPBX_HOOK,))
            hooks, bans, jumps = self.integration_positions(self.integration_inventory(iptables)[1])
            if jumps or not hooks or (bans and max(bans) > hooks[0]):
                raise BrokerError("FreePBX Firewall INPUT hooks changed during integration.")
            self.ipt(iptables, "-I", FREEPBX_HOOK, "1", *iptables_arguments(INTEGRATION_JUMP))
        chains, rules = self.integration_inventory(iptables)
        hooks, bans, jumps = self.integration_positions(rules)
        if ([iptables_rule(tokens) for chain, tokens in rules if chain == INTEGRATION_CHAIN] != expected
                or not integration_placement_valid(hooks, bans, jumps)
                or any(chain == "INPUT" and iptables_target(tokens) == INTEGRATION_CHAIN for chain, tokens in rules)):
            raise BrokerError("FreePBX Firewall integration could not be verified after update.")
        web_ports = "/".join(str(entry["port"]) for entry in web)
        self.integration_status("active", "Paired peers may reach TCP %s (session control) and configured management services %s%s "
                                "on their PBX tunnel address inside %s; nftables permits management only while a broker lease is active, "
                                "and all other traffic returns to FreePBX Firewall." % (
                                    SESSION_CONTROL_PORT,
                                    web_ports,
                                    " (and explicitly approved per-peer SSH services)" if any(item.get("ssh") is True for item in state["workstations"]) else "",
                                    FREEPBX_HOOK), backend)

    def reconcile_listener(self, ports):
        if isinstance(ports, int):
            ports = [] if ports == 0 else [ports]
        if not isinstance(ports, (list, tuple)) or any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
            raise BrokerError("Invalid managed WireGuard listener port set.")
        values = sorted(set(ports))
        value = ",".join(str(port) for port in values) if values else "0"
        self.run([FWCONSOLE, "teliphones", "listener", "--listen-port=" + value])

    def remove_integration(self):
        iptables = self.iptables_tool()
        if iptables is None:
            self.integration_status("inactive", "")
            return
        chains, rules = self.integration_inventory(iptables)
        self.remove_integration_jumps(iptables, rules)
        if INTEGRATION_CHAIN in chains:
            self.ipt(iptables, "-F", INTEGRATION_CHAIN)
            self.ipt(iptables, "-X", INTEGRATION_CHAIN)
        chains, rules = self.integration_inventory(iptables)
        if INTEGRATION_CHAIN in chains or any(iptables_target(tokens) == INTEGRATION_CHAIN for _, tokens in rules):
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
            self.integration_status("error", "FreePBX Firewall integration failed and was removed; FreePBX Firewall may now drop "
                                    "WireGuard handshakes and tunnel HTTP/HTTPS until integration is restored: " + reason)

    def mutate_policy(self, expected, existing, registration_retry=True):
        nft = self.tool("nft")
        commands, events = [], []
        if existing is not None:
            identity = {"family": "inet", "name": WORKSTATION_TABLE}
            self.validate_owned_table(existing)
            table = next(entry["table"] for entry in existing["nftables"] if "table" in entry)
            if table.get("family") != "inet" or table.get("name") != WORKSTATION_TABLE:
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
            if self.monitor.pending:
                # A transaction whose result could not be read back earlier; release it only after a successful readback.
                self.readback_unacknowledged(expected)
            self.monitor.expect(events)
        try:
            self.run([nft, "-j", "-f", "-"], stdin=json.dumps({"nftables": commands}))
        except (BrokerError, OSError, subprocess.SubprocessError):
            if monitored:
                # A timed-out nft may still have committed; the kernel state is read back before release.
                self.readback_unacknowledged(expected)
            raise
        if monitored:
            try:
                self.monitor.wait()
            except BrokerError as error:
                if not self.monitor.alive():
                    raise
                if expected is None or not registration_retry:
                    raise BrokerError(str(error) + " Firewall readback: " + self.readback_unacknowledged(expected)[0]
                                      + "; workstation access was not admitted.") from error
                # Popen is not subscription readiness. With the interface still down,
                # retry once and require a complete observed transaction before admission.
                self.mutate_policy(expected, self.readback_unacknowledged(expected)[1], registration_retry=False)

    def readback_unacknowledged(self, expected):
        """Read the owned kernel table before releasing an unacknowledged transaction; unreadable state stays latched."""
        try:
            actual = self.owned_table()
        except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
            raise BrokerError("Workstation firewall state could not be read back after an unacknowledged nft transaction; "
                              "access remains disabled: " + (str(error) if isinstance(error, BrokerError) else "nft list failed.")) from error
        if actual is None:
            readback = "the TELIPHONES table is absent"
        elif expected is None:
            readback = "the TELIPHONES table is still present"
        else:
            try:
                matches = policy_equal(actual, expected)
            except BrokerError:
                matches = False
            readback = "the TELIPHONES table %s the requested policy" % ("matches" if matches else "differs from")
        self.monitor.release()
        return readback, actual

    def teardown_workstations(self, state=None):
        """Shared by revoke, failure, shutdown and the trusted uninstall entry point."""
        if state is None:
            try:
                state, _ = self.workstation_state()
            except BrokerError:
                self.disable_workstations()
                raise
        interfaces = {WORKSTATION_IFACE: self.link_state() is not None}
        interfaces.update({self.locked_interface(item): self.link_state(self.locked_interface(item)) is not None
                           for item in state["workstations"]
                           if item.get("locked") or item.get("migration", {}).get("locked")})
        links = json.loads(self.run([self.tool("ip"), "-j", "link", "show"]))
        for link in links:
            interface = link.get("ifname", "") if isinstance(link, dict) else ""
            if re.fullmatch(r"tlpw[a-f0-9]{11}", interface):
                interfaces[interface] = True
        self.disable_workstations()
        listener_error = None
        try:
            self.reconcile_listener(0)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            listener_error = error
        try:
            self.ssh.reconcile({"workstations": []})
        except (ssh.SshError, OSError, subprocess.SubprocessError) as error:
            raise BrokerError("Managed SSH cleanup could not be verified; retaining recovery state: " + str(error)) from error
        for interface, present in interfaces.items():
            if present:
                self.run([self.tool("ip"), "link", "del", "dev", interface], check=False)
                if self.link_state(interface) is not None:
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
        if listener_error is not None:
            raise BrokerError("Workstation access removed, but listener cleanup requires retry: " + str(listener_error))
        if any(interfaces.values()):
            for diagnostic_id in self.diagnostic_active_peers:
                self.diagnostic(diagnostic_id, "interface.removed")
            self.diagnostic_active_peers.clear()
            self.diagnostic_interface_up = False

    def uninstall_workstations(self):
        with self.wslock:
            self.teardown_workstations()
            try:
                self.ssh.destroy()
            except (ssh.SshError, OSError, subprocess.SubprocessError) as error:
                raise BrokerError("Managed SSH removal could not be verified; retaining recovery state: " + str(error)) from error
            # Never remove either recovery file until link and owned-table absence are proven.
            for path in (STATE / "workstations.json", STATE / "workstation-recovery.json", ENROLLMENT / "workstation-wg.key"):
                path.unlink(missing_ok=True)

    def apply_workstations(self, state, preserve_unrelated=False):
        """Disable before any change, verify the entire policy, then admit peers."""
        has_pending_migration = any(item.get("migration") for item in state.get("workstations", []))
        if (preserve_unrelated or has_pending_migration) and state["connection_state"] != "closed" and not (STATE / "disabled").exists():
            saved = read_json(STATE / "workstations.json")
            if saved.get("workstations"):
                return self.apply_workstations_preserving(state)
        self.workstation_cleanup_failed = False
        previous = read_json(STATE / "workstations.json")
        workstation_ids = {"ws-" + item["id"] for item in state.get("workstations", [])
                           if isinstance(item, dict) and re.fullmatch(r"[a-f0-9]{16}", str(item.get("id", "")))}
        try:
            self.disable_workstations()
            if state["connection_state"] == "closed" or (STATE / "disabled").exists():
                self.teardown_workstations(state)
                self.reconcile_session_servers(state)
                self.workstation_error = ""
                return
            if state["subnet"] is None:
                state["subnet"] = self.choose_subnet()
            if state["listen_port"] is None:
                state["listen_port"] = 51821
            interfaces = {WORKSTATION_IFACE: self.link_state() is not None}
            interfaces.update({self.locked_interface(item): self.link_state(self.locked_interface(item)) is not None
                               for item in state["workstations"] if item.get("locked")})
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
            wanted = {item["public_key"]: item["address"] for item in state["workstations"] if not item.get("locked")}
            for peer in (self.run([wg, "show", WORKSTATION_IFACE, "peers"]) or "").split():
                if peer not in wanted:
                    self.run([wg, "set", WORKSTATION_IFACE, "peer", peer, "remove"])
            for key, address in wanted.items():
                self.run([wg, "set", WORKSTATION_IFACE, "peer", key, "allowed-ips", address])
            listener_ports = [state["listen_port"]]
            for item in state["workstations"]:
                if not item.get("locked"):
                    continue
                interface = self.locked_interface(item)
                station_network = ipaddress.IPv4Network(item["subnet"])
                if self.link_state(interface) is None:
                    self.run([ip, "link", "add", "dev", interface, "type", "wireguard"])
                self.run([wg, "set", interface, "listen-port", str(item["listener_port"]),
                          "private-key", str(ENROLLMENT / "workstation-wg.key")])
                self.run([ip, "address", "replace", str(station_network[1]) + "/" + str(station_network.prefixlen),
                          "dev", interface])
                station_peers = (self.run([wg, "show", interface, "peers"]) or "").split()
                for peer in station_peers:
                    if peer != item["public_key"]:
                        self.run([wg, "set", interface, "peer", peer, "remove"])
                self.run([wg, "set", interface, "peer", item["public_key"], "allowed-ips", item["address"]])
                listener_ports.append(item["listener_port"])
            if not self.monitor.alive() or not policy_equal(self.owned_table(), expected):
                raise BrokerError("Workstation enforcement could not be verified before admission.")
            # Only after the nft restrictions are verified may the narrower FreePBX Firewall ACCEPTs be added.
            previous_integration = dict(self.integration)
            self.reconcile_integration(state)
            self.reconcile_listener(listener_ports)
            active_interfaces = {self.locked_interface(item) for item in state["workstations"] if item.get("locked")}
            for old_item in previous.get("workstations", []):
                if not isinstance(old_item, dict):
                    continue
                old_locked = old_item.get("locked") or old_item.get("migration", {}).get("locked")
                if old_locked:
                    old_interface = self.locked_interface(old_item)
                    if old_interface not in active_interfaces and self.link_state(old_interface) is not None:
                        self.run([ip, "link", "del", "dev", old_interface], check=False)
                        if self.link_state(old_interface) is not None:
                            raise BrokerError("A retired dedicated workstation interface could not be removed.")
            self.ssh.reconcile(state)
            self.run([ip, "link", "set", "up", "dev", WORKSTATION_IFACE])
            for item in state["workstations"]:
                if item.get("locked"):
                    self.run([ip, "link", "set", "up", "dev", self.locked_interface(item)])
            for interface, present in interfaces.items():
                if not present:
                    self.diagnostic_interface_up = True
                    for diagnostic_id in workstation_ids:
                        self.diagnostic(diagnostic_id, "interface.established", listen_port=state["listen_port"])
            if self.integration != previous_integration:
                for diagnostic_id in workstation_ids:
                    self.diagnostic(diagnostic_id, "firewall.integration", state=self.integration["state"],
                                    backend=self.integration["backend"] if self.integration["backend"] in ("nf_tables", "legacy") else None)
            active_ids = set()
            for item in state["workstations"]:
                diagnostic_id = "ws-" + item["id"]
                active_ids.add(diagnostic_id)
                if diagnostic_id not in self.diagnostic_active_peers:
                    self.diagnostic(diagnostic_id, "peer.admitted", access="web+ssh" if item.get("ssh") is True else "web")
            self.diagnostic_active_peers = active_ids
            self.reconcile_session_servers(state)
            self.workstation_error = ""
        except (BrokerError, ssh.SshError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            category = "firewall-integration" if self.integration.get("state") == "error" else "workstation-enforcement"
            for diagnostic_id in workstation_ids:
                self.diagnostic(diagnostic_id, "broker.error", category=category)
            try:
                self.teardown_workstations(state)
            except (BrokerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as cleanup_error:
                self.workstation_cleanup_failed = True
                self.workstation_error = "Workstation cleanup could not be confirmed: " + (str(cleanup_error) if isinstance(cleanup_error, BrokerError) else "network operation failed.")
                raise BrokerError(self.workstation_error) from error
            self.workstation_error = "Workstation access could not be applied and was removed: " + (str(error) if isinstance(error, BrokerError) else "network configuration failed.")
            raise BrokerError(self.workstation_error) from error

    def apply_workstations_preserving(self, state):
        """Reconcile peer and policy changes without taking unrelated interfaces down."""
        previous = read_json(STATE / "workstations.json")
        previous_sessions = self.active_sessions()
        previous_by_id = {item["id"]: item for item in previous.get("workstations", []) if isinstance(item, dict)}
        current_by_id = {item["id"]: item for item in state.get("workstations", [])}
        changed_ids = {
            workstation_id for workstation_id in set(previous_by_id) | set(current_by_id)
            if previous_by_id.get(workstation_id, {}).get("locked") != current_by_id.get(workstation_id, {}).get("locked")
            or previous_by_id.get(workstation_id, {}).get("sources") != current_by_id.get(workstation_id, {}).get("sources")
        }
        sessions = {key: value for key, value in previous_sessions.items()
                    if key in current_by_id and key not in changed_ids}
        self.save_active_sessions(sessions)
        established = set()
        try:
            if state["subnet"] is None:
                state["subnet"] = self.choose_subnet()
            if state["listen_port"] is None:
                state["listen_port"] = 51821
            self.start_monitor()
            expected = self.expected_policy(state)
            self.mutate_policy(expected, self.owned_table())
            if not policy_equal(self.owned_table(), expected):
                raise BrokerError("Workstation firewall differs from the complete expected policy.")

            ip, wg = self.tool("ip"), self.tool("wg")
            if self.link_state() is None:
                self.run([ip, "link", "add", "dev", WORKSTATION_IFACE, "type", "wireguard"])
                established.add(WORKSTATION_IFACE)
            self.server_public_key()
            self.run([wg, "set", WORKSTATION_IFACE, "listen-port", str(state["listen_port"]),
                      "private-key", str(ENROLLMENT / "workstation-wg.key")])
            shared_network = ipaddress.IPv4Network(state["subnet"])
            self.run([ip, "address", "replace", str(shared_network[1]) + "/" + str(shared_network.prefixlen),
                      "dev", WORKSTATION_IFACE])

            shared_peers = {}
            for item in state["workstations"]:
                routes = []
                if not item.get("locked"):
                    routes.append(item["address"])
                migration = item.get("migration")
                if migration and not migration.get("locked"):
                    routes.append(migration["address"])
                if routes:
                    shared_peers[item["public_key"]] = ",".join(sorted(set(routes)))
            for peer in (self.run([wg, "show", WORKSTATION_IFACE, "peers"]) or "").split():
                if peer not in shared_peers:
                    self.run([wg, "set", WORKSTATION_IFACE, "peer", peer, "remove"])
            for key, address in shared_peers.items():
                self.run([wg, "set", WORKSTATION_IFACE, "peer", key, "allowed-ips", address])

            desired_interfaces = set()
            listener_ports = [state["listen_port"]]
            for item in state["workstations"]:
                configurations = []
                if item.get("locked"):
                    configurations.append(item)
                migration = item.get("migration")
                if migration and migration.get("locked") and (
                        not item.get("locked") or migration["listener_port"] != item.get("listener_port")):
                    configurations.append({"id": item["id"], "subnet": migration["subnet"],
                                           "pbx_address": migration["pbx_address"],
                                           "address": migration["address"],
                                           "listener_port": migration["listener_port"]})
                for configuration in configurations:
                    interface = self.locked_interface(configuration)
                    desired_interfaces.add(interface)
                    subnet = ipaddress.IPv4Network(configuration["subnet"])
                    if self.link_state(interface) is None:
                        self.run([ip, "link", "add", "dev", interface, "type", "wireguard"])
                        established.add(interface)
                    self.run([wg, "set", interface, "listen-port", str(configuration["listener_port"]),
                              "private-key", str(ENROLLMENT / "workstation-wg.key")])
                    self.run([ip, "address", "replace", str(subnet[1]) + "/" + str(subnet.prefixlen), "dev", interface])
                    peers = (self.run([wg, "show", interface, "peers"]) or "").split()
                    for peer in peers:
                        if peer != item["public_key"]:
                            self.run([wg, "set", interface, "peer", peer, "remove"])
                    self.run([wg, "set", interface, "peer", item["public_key"],
                              "allowed-ips", configuration["address"]])
                    listener_ports.append(configuration["listener_port"])

            for old_item in previous.get("workstations", []):
                if not isinstance(old_item, dict):
                    continue
                if old_item.get("locked") or old_item.get("migration", {}).get("locked"):
                    interface = self.locked_interface(old_item)
                    if interface not in desired_interfaces and self.link_state(interface) is not None:
                        self.run([ip, "link", "del", "dev", interface])
                        if self.link_state(interface) is not None:
                            raise BrokerError("A retired dedicated workstation interface could not be removed.")

            if not self.monitor.alive() or not policy_equal(self.owned_table(), expected):
                raise BrokerError("Workstation enforcement could not be verified before admission.")
            self.reconcile_integration(state)
            self.reconcile_listener(listener_ports)
            self.ssh.reconcile(state)
            self.run([ip, "link", "set", "up", "dev", WORKSTATION_IFACE])
            for interface in desired_interfaces:
                self.run([ip, "link", "set", "up", "dev", interface])
            self.reconcile_session_servers(state)
            for interface in established:
                self.diagnostic_interface_up = True
                for item in state["workstations"]:
                    self.diagnostic("ws-" + item["id"], "interface.established", listen_port=
                                    item.get("listener_port", state["listen_port"]))
            self.workstation_error = ""
        except (BrokerError, ssh.SshError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            # Revoke only identities whose policy changed; unrelated interfaces and
            # leases remain untouched if an update cannot be verified.
            affected = set(changed_ids) | (set(previous_by_id) - set(current_by_id))
            for workstation_id in affected:
                old_item = previous_by_id.get(workstation_id, {})
                new_item = current_by_id.get(workstation_id, {})
                for item in (old_item, new_item):
                    key = item.get("public_key")
                    if not isinstance(key, str):
                        continue
                    for interface in (WORKSTATION_IFACE,
                                      self.locked_interface(item) if item.get("locked") else None):
                        if interface is not None and self.link_state(interface) is not None:
                            self.run([self.tool("wg"), "set", interface, "peer", key, "remove"], check=False)
            self.workstation_error = "Workstation policy update could not be verified; affected access was removed and cleanup requires retry: " + (
                str(error) if isinstance(error, BrokerError) else "network configuration failed.")
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
            self.expire_sessions()
            event = self.enforcement_event.is_set()
            if event:
                self.enforcement_event.clear()
            stored = read_json(STATE / "workstations.json")
            now = int(time.time())
            expired_ids = ["ws-" + item["id"] for item in stored.get("workstations", [])
                           if isinstance(item, dict) and re.fullmatch(r"[a-f0-9]{16}", str(item.get("id", "")))
                           and item.get("mode") != "persistent" and isinstance(item.get("expires_at"), int)
                           and item["expires_at"] <= now]
            try:
                state, changed = self.workstation_state()
                active = state["connection_state"] != "closed" and not (STATE / "disabled").exists()
                if active:
                    if self.monitor is None or not self.monitor.alive():
                        raise BrokerError("Workstation nft monitor is unavailable; access disabled. Restart the broker.")
                    actual = self.owned_table()
                    try:
                        matches = actual is not None and policy_equal(actual, self.expected_policy(state))
                        matches_with_expired_bans = actual is not None and policy_equal(
                            actual, self.expected_policy(state, include_expired_bans=True))
                    except (BrokerError, KeyError, TypeError):
                        matches = matches_with_expired_bans = False
                    if not matches:
                        if matches_with_expired_bans:
                            self.reconcile_policy_only(state)
                        else:
                            event = True
                interfaces = [WORKSTATION_IFACE] + [self.locked_interface(item) for item in state["workstations"]
                                                    if item.get("locked")]
                links_ready = active and all(
                    (link := self.link_state(interface)) is not None and "UP" in link["flags"]
                    for interface in interfaces)
                if changed or event or (STATE / "disabled").exists() or (
                        active and not links_ready):
                    self.apply_workstations(state)
                    if changed:
                        self.save_workstations(state)
                        self.audit("workstation-expired", 0, "completed")
                        for diagnostic_id in expired_ids:
                            self.diagnostic_observations.pop(diagnostic_id, None)
                            self.diagnostic(diagnostic_id, "pairing.expired", reason="deadline")
                elif active and links_ready:
                    # Repairs a FreePBX Firewall reload without re-admitting peers; a no-op when already exact.
                    self.reconcile_integration(state)
                    self.reconcile_listener([state["listen_port"]] + [item["listener_port"] for item in state["workstations"]
                                                                      if item.get("locked")])
                    if any(ssh.managed(item) for item in state["workstations"]):
                        self.ssh.reconcile(state)
            except (BrokerError, ssh.SshError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                self.workstation_error = str(error)
                try:
                    self.disable_workstations()
                    self.ssh.reconcile({"workstations": []})
                except (BrokerError, ssh.SshError, OSError, ValueError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error += " Cleanup could not be confirmed: " + str(cleanup_error)

    def pair(self, request, uid):
        if (STATE / "disabled").exists():
            raise BrokerError("TELIPHONES is disabled; workstation pairing is unavailable.")
        pairing = parse_pair_request(request["request"])
        state, _ = self.workstation_state()
        existing = next((item for item in state["workstations"] if item["public_key"] == pairing["public_key"]), None)
        if state["connection_state"] == "frozen" and existing is None:
            raise BrokerError("New workstation pairings are suspended while TELIPHONES is Frozen.")
        if pairing["schema"] != "teliphones-pair-request/2" and request["ssh"] == "1":
            raise BrokerError("This pairing request did not include SSH capability; request SSH from the Windows application first.")
        host, port = endpoint_host(request["endpoint_host"]), int(request["listen_port"])
        requested_sources = parse_source_restrictions(request.get("sources", ""))
        for name in TOOLS:
            self.tool(name)
        stored = read_json(STATE / "workstations.json")
        now = int(time.time())
        expired_ids = ["ws-" + item["id"] for item in stored.get("workstations", [])
                       if isinstance(item, dict) and re.fullmatch(r"[a-f0-9]{16}", str(item.get("id", "")))
                       and item.get("mode") != "persistent" and isinstance(item.get("expires_at"), int)
                       and item["expires_at"] <= now]
        previous = json.loads(json.dumps(state))
        if state["workstations"] and state["listen_port"] != port:
            raise BrokerError("Paired workstations already use UDP port %d. Use the same port, or revoke all workstations first." % state["listen_port"])
        if not state["workstations"] or not state["subnet"]:
            state["subnet"] = self.choose_subnet()
        state["listen_port"] = port
        if isinstance(request.get("web"), str) and request["web"].strip():
            state["web"] = parse_web(request["web"])
        existing = next((item for item in state["workstations"] if item["public_key"] == pairing["public_key"]), None)
        if existing and existing.get("locked") and not requested_sources:
            requested_sources = existing["sources"]
        locked = bool(requested_sources)
        if pairing["schema"] == "teliphones-pair-request/2" and request["ssh"] == "1":
            try:
                self.ssh.initialise()
                self.ssh.host_key()
            except (ssh.SshError, OSError, subprocess.SubprocessError) as error:
                raise BrokerError("Managed SSH is unavailable: " + str(error)) from error
        network = ipaddress.IPv4Network(state["subnet"])
        if existing:
            state["workstations"].remove(existing)
        if locked:
            if existing and existing.get("locked"):
                station_subnet = existing["subnet"]
                station_port = existing["listener_port"]
            else:
                reserved = [str(network)]
                reserved.extend(item["subnet"] for item in state["workstations"] if item.get("locked"))
                station_subnet = self.choose_subnet(reserved)
                station_port = self.locked_listener_port({"id": existing["id"] if existing else secrets.token_hex(8)},
                                                         state["workstations"], port)
            station_network = ipaddress.IPv4Network(station_subnet)
            address = str(station_network[2]) + "/32"
            pbx_address = str(station_network[1])
        elif existing and not existing.get("locked"):
            address = existing["address"]
            station_subnet = None
            station_port = None
            pbx_address = str(network[1])
        else:
            taken = {item["address"] for item in state["workstations"]}
            free = [str(host_address) + "/32" for host_address in list(network.hosts())[1:] if str(host_address) + "/32" not in taken]
            if not free:
                raise BrokerError("No workstation addresses remain; revoke unused workstations first.")
            address = free[0]
            station_subnet = None
            station_port = None
            pbx_address = str(network[1])
        now = int(time.time())
        workstation_id = existing["id"] if existing and pairing["schema"] == "teliphones-pair-request/1" else secrets.token_hex(8)
        entry = {"id": workstation_id,
                 "name": pairing["workstation"], "public_key": pairing["public_key"],
                 "address": address, "mode": request["mode"], "ssh": request["ssh"] == "1", "created_at": now,
                 "expires_at": now + int(request["minutes"]) * 60 if request["mode"] == "temporary" else None,
                 "locked": locked}
        if locked:
            entry.update(sources=requested_sources, subnet=station_subnet, pbx_address=pbx_address,
                         listener_port=station_port)
        if pairing["schema"] == "teliphones-pair-request/2" and entry["ssh"]:
            entry.update(ssh_public_key=pairing["ssh_public_key"], ssh_user=request["ssh_user"])
            try:
                self.ssh.account_policy(entry, entry.get("pbx_address", str(network[1])))
                if existing and existing["id"] in self.ssh.active:
                    self.ssh.stop(existing["id"], "rotation")
            except (ssh.SshError, OSError, subprocess.SubprocessError) as error:
                raise BrokerError("Managed SSH account authorisation failed: " + str(error)) from error
        state["workstations"].append(entry)
        try:
            self.apply_workstations(state, preserve_unrelated=True)
            pbx_public = self.server_public_key()
            self.save_workstations(state)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            if self.workstation_cleanup_failed:
                atomic(STATE / "workstation-recovery.json", json.dumps(state, indent=2, sort_keys=True))
                raise
            try:
                self.apply_workstations(previous, preserve_unrelated=bool(previous.get("workstations")))
            except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                self.workstation_error = "Pairing rollback failed; affected access remains blocked and recovery requires retry: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        for diagnostic_id in expired_ids:
            self.diagnostic(diagnostic_id, "pairing.expired", reason="deadline")
        diagnostic_id = "ws-" + entry["id"]
        self.diagnostic_observations.pop(diagnostic_id, None)
        self.diagnostic(diagnostic_id, "pairing.approved", mode=entry["mode"], expires_at=entry["expires_at"],
                        renewed=existing is not None)
        self.audit("pair", uid, "completed")
        response = {"schema": "teliphones-pair-response/1", "nonce": pairing["nonce"], "workstation_id": entry["id"],
                    "workstation_public_key": entry["public_key"], "address": address, "pbx_address": pbx_address,
                    "pbx_name": re.sub(r"[^A-Za-z0-9._-]", "", socket.gethostname())[:64] or "FreePBX",
                    "pbx_public_key": pbx_public, "endpoint": host + ":" + str(entry["listener_port"] if locked else port), "mode": entry["mode"],
                    "expires_at": entry["expires_at"], "ssh": entry["ssh"], "gui_url": gui_url(state["web"], pbx_address)}
        prefix = PAIR_RESPONSE_PREFIX
        if pairing["schema"] == "teliphones-pair-request/2":
            prefix = PAIR_RESPONSE_V2
            response.update(schema="teliphones-pair-response/2", ssh_user=entry.get("ssh_user", ""),
                            ssh_host_key=self.ssh.host_key() if ssh.managed(entry) else "",
                            ssh_ca_key=self.ssh.initialise() if ssh.managed(entry) else "",
                            ssh_port=ssh.port(entry) if ssh.managed(entry) else 0,
                            ssh_api_port=ssh.API_PORT if ssh.managed(entry) else 0)
        return prefix + b64url_encode(json.dumps(response, separators=(",", ":"), sort_keys=True).encode()), entry

    def unpair(self, request, uid):
        state, _ = self.workstation_state()
        revoked_ids = ["ws-" + item["id"] for item in state["workstations"]
                       if request["workstation_id"] == "all" or item["id"] == request["workstation_id"]]
        before = len(state["workstations"])
        state["workstations"] = [] if request["workstation_id"] == "all" else [item for item in state["workstations"] if item["id"] != request["workstation_id"]]
        if len(state["workstations"]) == before and request["workstation_id"] != "all":
            raise BrokerError("Unknown workstation; it may already have been revoked or expired.")
        self.apply_workstations(state, preserve_unrelated=True)
        self.save_workstations(state)
        sessions = self.active_sessions()
        sessions = {key: value for key, value in sessions.items()
                    if key not in {identifier[3:] for identifier in revoked_ids}}
        self.save_active_sessions(sessions)
        self.reconcile_session_servers(state)
        for diagnostic_id in revoked_ids:
            self.diagnostic_observations.pop(diagnostic_id, None)
            self.diagnostic(diagnostic_id, "pairing.revoked", reason="administrator")
        self.audit("unpair", uid, "completed")

    def configure_web(self, request, uid):
        """Replace the management web services and reconcile both firewall layers; no stale permits remain."""
        state, _ = self.workstation_state()
        web = parse_web(request["web"])
        previous = json.loads(json.dumps(state))
        state["web"] = web
        if state["workstations"]:
            try:
                self.apply_workstations(state, preserve_unrelated=True)
                self.save_workstations(state)
            except (BrokerError, OSError, subprocess.SubprocessError) as error:
                if self.workstation_cleanup_failed:
                    atomic(STATE / "workstation-recovery.json", json.dumps(state, indent=2, sort_keys=True))
                    raise
                try:
                    self.apply_workstations(previous)
                except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                    self.disable_workstations()
                    self.workstation_error = "Management update rollback failed: " + str(rollback_error)
                    raise BrokerError(self.workstation_error) from error
                raise
        else:
            self.save_workstations(state)
        self.audit("web", uid, "completed")
        return web

    def configure_workstation_policy(self, request, uid):
        state, _ = self.workstation_state()
        previous = json.loads(json.dumps(state))
        previous_sessions = self.active_sessions()
        state["connection_state"] = request["state"]
        if state["connection_state"] == "closed":
            self.save_active_sessions({})
        if state["connection_state"] != "closed":
            if state["subnet"] is None:
                state["subnet"] = self.choose_subnet()
            if state["listen_port"] is None:
                state["listen_port"] = 51821
        try:
            self.save_workstations(state)
            self.apply_workstations(state, preserve_unrelated=True)
        except (BrokerError, OSError, subprocess.SubprocessError) as error:
            try:
                self.save_active_sessions(previous_sessions)
                self.apply_workstations(previous)
                self.save_workstations(previous)
            except (BrokerError, OSError, subprocess.SubprocessError) as rollback_error:
                try:
                    self.disable_workstations()
                except (BrokerError, OSError, subprocess.SubprocessError) as cleanup_error:
                    self.workstation_error = "Connection policy change and rollback failed; cleanup is unverified: " + str(cleanup_error)
                    raise BrokerError(self.workstation_error) from error
                self.workstation_error = "Connection policy change failed and was rolled back: " + str(rollback_error)
                raise BrokerError(self.workstation_error) from error
            raise
        self.audit("workstation-policy", uid, "completed")
        return state["connection_state"]

    def observe_workstations(self, state, handshakes, transfers):
        now = time.monotonic()
        for item in state["workstations"]:
            key = item["public_key"]
            diagnostic_id = "ws-" + item["id"]
            handshake = handshakes.get(key, 0)
            rx_bytes, tx_bytes = transfers.get(key, (0, 0))
            previous = self.diagnostic_observations.get(diagnostic_id)
            changed_handshake = previous is None or handshake != previous[0]
            traffic_summary_due = (previous is None or ((rx_bytes, tx_bytes) != previous[1:3]
                                   and now - previous[3] >= 300))
            if changed_handshake or traffic_summary_due:
                self.diagnostic(diagnostic_id, "peer.observation", handshake_at=handshake,
                                rx_bytes=rx_bytes, tx_bytes=tx_bytes)
                self.diagnostic_observations[diagnostic_id] = (handshake, rx_bytes, tx_bytes, now)

    def workstation_status(self):
        state, _ = self.workstation_state()
        leases = self.active_sessions()
        paired_ids = {item["id"] for item in state["workstations"]}
        leases = {key: value for key, value in leases.items() if key in paired_ids}
        if state["connection_state"] == "closed" or (STATE / "disabled").exists():
            leases = {}
        requirements = {name: any(os.access(path, os.X_OK) for path in paths) for name, paths in TOOLS.items()}
        handshakes = {}
        endpoints = {}
        error = self.workstation_error
        active = state["connection_state"] != "closed" and not (STATE / "disabled").exists()
        if (self.monitor is not None and not self.monitor.alive()) or (active and self.monitor is None):
            error = error or "Workstation nft monitor unavailable; access is being disabled. Restart the broker after repair."
        if active and not error:
            try:
                for interface in [WORKSTATION_IFACE] + [self.locked_interface(item) for item in state["workstations"]
                                                         if item.get("locked")]:
                    output = self.run([self.tool("wg"), "show", interface, "latest-handshakes"])
                    for line in output.splitlines():
                        key, timestamp = line.split()
                        if not WG_PUBLIC_KEY.fullmatch(key) or not timestamp.isdigit():
                            raise ValueError("Invalid WireGuard handshake status.")
                        handshakes[key] = int(timestamp)
                    output = self.run([self.tool("wg"), "show", interface, "endpoints"])
                    for line in output.splitlines():
                        fields = line.split(maxsplit=1)
                        if len(fields) != 2 or not WG_PUBLIC_KEY.fullmatch(fields[0]):
                            raise ValueError("Invalid WireGuard endpoint status.")
                        endpoint = parse_wireguard_endpoint(fields[1])
                        if endpoint is not None:
                            endpoints[fields[0]] = endpoint
                transfers = {}
                try:
                    for interface in [WORKSTATION_IFACE] + [self.locked_interface(item) for item in state["workstations"]
                                                             if item.get("locked")]:
                        output = self.run([self.tool("wg"), "show", interface, "transfer"])
                        for line in output.splitlines():
                            key, rx_bytes, tx_bytes = line.split()
                            if WG_PUBLIC_KEY.fullmatch(key) and rx_bytes.isdigit() and tx_bytes.isdigit():
                                transfers[key] = (int(rx_bytes), int(tx_bytes))
                except (BrokerError, OSError, ValueError, subprocess.SubprocessError):
                    transfers = {}
                self.observe_workstations(state, handshakes, transfers)
                self.diagnostic_telemetry_error = False
            except (BrokerError, OSError, ValueError, subprocess.SubprocessError):
                error = "Workstation connection status could not be read. Check the broker and tlp-admin interface; pairing is not proof of connectivity."
                if not self.diagnostic_telemetry_error:
                    for item in state["workstations"]:
                        self.diagnostic("ws-" + item["id"], "broker.error", category="telemetry-unavailable")
                self.diagnostic_telemetry_error = True
        ssh_error = ""
        try:
            self.ssh.prerequisites()
            self.ssh.host_key()
        except (ssh.SshError, OSError, subprocess.SubprocessError) as failure:
            ssh_error = str(failure)
        pbx_address = str(ipaddress.IPv4Network(state["subnet"])[1]) if state["subnet"] and state["workstations"] else None
        source_status = {}
        for item in state["workstations"]:
            if item.get("locked"):
                effective, failed = resolve_source_restrictions(item["sources"], cache=self.source_cache)
                source_status[item["id"]] = {"effective": effective, "failed": failed}
        return {"ready": all(requirements.values()) and not error and not (STATE / "disabled").exists(), "requirements": requirements, "error": error,
                "ssh_ready": not ssh_error, "ssh_error": ssh_error,
                "connection_state": state["connection_state"],
                "max_sessions": state["max_sessions"],
                "connected_workstations": len(leases),
                "ssh_accounts": ssh.existing_accounts(),
                "session_control_port": SESSION_CONTROL_PORT,
                "bans": [{"id": ban["id"], "source": ban["source"], "reason": ban["reason"],
                          "expires_at": ban["expires_at"],
                          "active": ban["expires_at"] is None or ban["expires_at"] > int(time.time())}
                         for ban in state["bans"]],
                "listen_port": state["listen_port"],
                "web": [{"scheme": entry["scheme"], "port": entry["port"],
                         "listening": web_listening(entry["port"], pbx_address)} for entry in state["web"]],
                "gui_url": gui_url(state["web"], pbx_address) if pbx_address else None,
                "firewall_integration": {"state": self.integration["state"] if state["workstations"] else "inactive",
                                         "message": self.integration["message"] if state["workstations"] else "",
                                         "backend": self.integration["backend"], "hook": FREEPBX_HOOK, "chain": INTEGRATION_CHAIN},
                "pbx_address": pbx_address,
                "items": [{"id": item["id"], "name": item["name"], "address": item["address"], "mode": item["mode"],
                           "ssh": item.get("ssh") is True, "ssh_managed": ssh.managed(item),
                           "ssh_user": item.get("ssh_user", ""), "ssh_port": ssh.port(item) if ssh.managed(item) else 0,
                           "created_at": item.get("created_at"), "expires_at": item.get("expires_at"),
                           "locked": item.get("locked") is True,
                           "ssh_request_pending": bool(item.get("ssh_request")),
                           "unlock_request_pending": bool(item.get("unlock_request")),
                           "sources_request_pending": bool(item.get("sources_request")),
                           "requested_sources": item.get("sources_request", {}).get("sources", []),
                           "sources": item.get("sources", []),
                           "effective_sources": source_status.get(item["id"], {}).get("effective", []),
                           "source_resolution_failures": source_status.get(item["id"], {}).get("failed", []),
                           "listener_port": item.get("listener_port", state["listen_port"]),
                           "migration_pending": bool(item.get("migration")),
                           "migration_generation": item.get("migration", {}).get("id"),
                           "verified_endpoint": endpoints.get(item["public_key"]) if handshakes.get(item["public_key"], 0) > 0 else None,
                           "last_handshake": handshakes.get(item["public_key"]),
                           "session_active": item["id"] in leases,
                           "session_expires_at": leases[item["id"]]["expires_at"] if item["id"] in leases else None,
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
        if action == "diagnostics":
            try:
                events = self.diagnostics.read(request["diagnostic_id"])
            except (OSError, ValueError, TypeError) as error:
                LOGGER.warning("TELIPHONES diagnostic export failed", exc_info=True)
                raise BrokerError("Workstation diagnostics are temporarily unavailable.") from error
            return {"ok": True, "component_version": VERSION, "diagnostic_id": request["diagnostic_id"],
                    "exported_at": DiagnosticLog._timestamp(time.time()), "events": events}
        if action == "pair":
            with self.wslock:
                code, entry = self.pair(request, uid)
            return {"ok": True, "pairing_response": code,
                    "message": "Workstation '%s' paired. Paste the pairing response into the TELIPHONES Windows application." % entry["name"]}
        if action == "unpair":
            with self.wslock:
                self.unpair(request, uid)
            return {"ok": True, "message": "Workstation access revoked." if request["workstation_id"] != "all" else "All workstation access revoked."}
        if action == "web":
            with self.wslock:
                web = self.configure_web(request, uid)
            return {"ok": True, "message": "Management web services set to %s. Workstation firewall permissions were "
                    "reconciled; already-paired workstations keep their saved GUI address until re-paired." % web_text(web)}
        if action == "workstation-policy":
            with self.wslock:
                state = self.configure_workstation_policy(request, uid)
            return {"ok": True, "message": "TELIPHONES workstation access is now %s." % state.capitalize()}
        if action == "workstation-manage":
            with self.wslock:
                updated = self.manage_workstation(request, uid)
            return {"ok": True, "workstation": updated,
                    "message": "Workstation policy updated. The workstation keeps its identity; its tunnel must reconnect to the assigned listener."}
        if action in ("workstation-ssh-approve", "workstation-ssh-reject", "workstation-ssh-revoke"):
            ssh_operation = {"workstation-ssh-approve": "approve", "workstation-ssh-reject": "reject",
                             "workstation-ssh-revoke": "revoke"}[action]
            with self.wslock:
                item = self.manage_workstation_ssh(request, uid, ssh_operation)
            return {"ok": True, "workstation": {"id": item["id"], "ssh": item.get("ssh") is True},
                    "message": {"approve": "Managed SSH elevation approved for the explicitly selected account.",
                                "reject": "SSH elevation request rejected; existing web access is unchanged.",
                                "revoke": "Managed SSH access revoked; existing web access is unchanged."}[ssh_operation]}
        if action in ("workstation-unlock-approve", "workstation-unlock-reject"):
            with self.wslock:
                state, _ = self.workstation_state()
                item = next((entry for entry in state["workstations"]
                                        if entry["id"] == request["workstation_id"]), None)
                if item is None or not item.get("unlock_request"):
                                raise BrokerError("There is no pending unlock request for this workstation.")
                if action == "workstation-unlock-approve":
                                if item.get("migration"):
                                    if item["migration"].get("locked"):
                                        raise BrokerError("A different listener migration is pending; finish it before approving unlock.")
                                    item.pop("unlock_request", None)
                                    self.save_workstations(state)
                                    updated = item
                                else:
                                    updated = self.manage_workstation(
                                        {"workstation_id": item["id"], "state": "unlock", "sources": ""}, uid)
                                    state, _ = self.workstation_state()
                                    approved = next(entry for entry in state["workstations"] if entry["id"] == item["id"])
                                    approved.pop("unlock_request", None)
                                    self.save_workstations(state)
                                message = "Workstation unlock approved; the existing identity will receive its updated tunnel configuration."
                else:
                                item.pop("unlock_request", None)
                                self.save_workstations(state)
                                updated = item
                                message = "Workstation unlock request rejected; existing restrictions remain in force."
            return {"ok": True, "workstation": {"id": updated["id"], "locked": updated.get("locked") is True},
                                "message": message}
        if action in ("workstation-sources-approve", "workstation-sources-reject"):
            with self.wslock:
                state, _ = self.workstation_state()
                item = next((entry for entry in state["workstations"]
                                        if entry["id"] == request["workstation_id"]), None)
                if item is None or not item.get("sources_request"):
                                raise BrokerError("There is no pending Allowed List request for this workstation.")
                if action == "workstation-sources-approve":
                                if item.get("migration"):
                                    raise BrokerError("A listener migration is pending; finish it before approving Allowed List changes.")
                                approved_sources = ", ".join(item["sources_request"]["sources"])
                                updated = self.manage_workstation(
                                    {"workstation_id": item["id"], "state": "lock", "sources": approved_sources}, uid)
                                message = "Allowed List request approved and enforced for this workstation."
                else:
                                item.pop("sources_request", None)
                                self.save_workstations(state)
                                updated = item
                                message = "Allowed List request rejected; existing restrictions remain in force."
            return {"ok": True, "workstation": {"id": updated["id"], "locked": updated.get("locked") is True},
                                "message": message}
        if action == "workstation-limit":
            with self.wslock:
                maximum = self.configure_workstation_limit(request, uid)
            return {"ok": True, "message": "Maximum simultaneous workstation connections set to %d." % maximum}
        if action in ("workstation-ban", "workstation-unban"):
            with self.wslock:
                state = self.configure_ban(request, uid)
            return {"ok": True, "message": "TELIPHONES ban list updated.",
                    "bans": state["bans"]}
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
        broker.stop_session_servers()
        with broker.wslock:
            broker.teardown_workstations()
        if broker.monitor is not None:
            broker.monitor.close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        broker.disable_workstations()
        with broker.wslock:
            broker.ssh.reconcile({"workstations": []})
    except (BrokerError, OSError, ValueError, subprocess.SubprocessError) as error:
        broker.workstation_error = "Initial workstation shutdown unverified: " + str(error)
    # Interrupted broker jobs never resume/open access implicitly.
    broker.cleanup(0, quarantine=(STATE / "session.json").exists() or (STATE / "connect.json").exists())
    # Workstation access exists only while the broker runs and can enforce expiry.
    try:
        broker.start_monitor()
    except (BrokerError, OSError):
        broker.workstation_error = "Workstation nft monitor unavailable; pairing cannot be admitted."
    broker.save_active_sessions({})
    broker.restore_workstations()
    broker.session_server_enabled = True
    try:
        broker.reconcile_session_servers()
    except (OSError, BrokerError) as error:
        broker.workstation_error = "Private workstation session-control listener could not start: " + str(error)
        broker.disable_workstations()

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

    def lease_expiry():
        while True:
            broker.lease_wake.wait(1)
            broker.lease_wake.clear()
            try:
                broker.expire_sessions()
            except (BrokerError, OSError, subprocess.SubprocessError) as error:
                broker.workstation_error = "Workstation session lease enforcement failed: " + str(error)
                try:
                    broker.disable_workstations()
                except (BrokerError, OSError, subprocess.SubprocessError) as cleanup_error:
                    broker.workstation_error += " Cleanup unverified: " + str(cleanup_error)
                return
    threading.Thread(target=lease_expiry, daemon=True).start()
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
