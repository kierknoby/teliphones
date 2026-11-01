#!/usr/bin/env python3
"""Provider-neutral TELIPHONES reference Connect gateway for disposable Linux labs."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import signal
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


PROTOCOL = "teliphones-connect/1"
TABLE = "teliphones"
DEFAULT_SERVICES = (80, 443, 22222)
SESSION_ID = re.compile(r"^[a-f0-9]{32}$")
REQUEST_ID = re.compile(r"^[a-f0-9]{64}$")
WG_INTERFACE = re.compile(r"^[a-zA-Z0-9_=.-]{1,15}$")


class GatewayError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def valid_wireguard_key(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        import base64

        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == 32 and any(decoded)


def tunnel_pair(pbx_cidr: Any, gateway_cidr: Any, pool: str) -> tuple[ipaddress.IPv4Interface, ipaddress.IPv4Interface, ipaddress.IPv4Network]:
    try:
        pbx = ipaddress.IPv4Interface(pbx_cidr)
        gateway = ipaddress.IPv4Interface(gateway_cidr)
        allowed_pool = ipaddress.IPv4Network(pool, strict=False)
    except (TypeError, ValueError) as error:
        raise GatewayError(400, "address-invalid") from error
    if pbx.network.prefixlen not in (30, 31) or gateway.network.prefixlen != 32:
        raise GatewayError(400, "address-prefix-invalid")
    if pbx.ip not in pbx.network or gateway.ip not in pbx.network or pbx.ip == gateway.ip:
        raise GatewayError(400, "address-pair-invalid")
    if pbx.network != ipaddress.IPv4Network((pbx.ip, pbx.network.prefixlen), strict=False):
        raise GatewayError(400, "address-pair-invalid")
    if not pbx.network.subnet_of(allowed_pool) or not gateway.ip.is_private:
        raise GatewayError(400, "address-outside-pool")
    if pbx.network.prefixlen == 30 and ({pbx.ip, gateway.ip} & {pbx.network.network_address, pbx.network.broadcast_address}):
        raise GatewayError(400, "address-reserved")
    return pbx, gateway, pbx.network


def validate_config(config: dict[str, Any]) -> None:
    if config.get("deployment_mode") not in ("reference-lab", "provisioned"):
        raise ValueError("deployment_mode must explicitly be reference-lab or provisioned")
    interface = config.get("interface", "wg-teliphones")
    if not WG_INTERFACE.fullmatch(str(interface)):
        raise ValueError("invalid WireGuard interface name")
    if not isinstance(config.get("endpoint"), str) or not re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):[1-9][0-9]{0,4}", config["endpoint"]):
        raise ValueError("endpoint must be a configured host:port")
    if not valid_wireguard_key(config.get("public_key")):
        raise ValueError("public_key is not a WireGuard public key")
    if not isinstance(config.get("private_key_file"), str):
        raise ValueError("private_key_file is required")
    if not isinstance(config.get("support_pool"), str):
        raise ValueError("support_pool is required")
    ipaddress.IPv4Network(config["support_pool"], strict=False)
    if not isinstance(config.get("engineer_pool"), str):
        raise ValueError("engineer_pool is required")
    ipaddress.IPv4Network(config["engineer_pool"], strict=False)
    if ipaddress.IPv4Network(config["support_pool"], strict=False).overlaps(ipaddress.IPv4Network(config["engineer_pool"], strict=False)):
        raise ValueError("support and engineer address pools must be disjoint")
    if not isinstance(config.get("customers"), dict) or not config["customers"]:
        raise ValueError("an explicit customer certificate enrollment map is required")
    if not isinstance(config.get("engineers"), dict) or not config["engineers"]:
        raise ValueError("an explicit engineer public-key enrollment map is required")
    certs: set[str] = set()
    addresses: set[str] = set()
    wg_keys: set[str] = set()
    for customer_id, customer in config["customers"].items():
        fingerprint = str(customer.get("certificate_sha256", "")).lower()
        if not re.fullmatch(r"[a-f0-9]{64}", fingerprint) or fingerprint in certs:
            raise ValueError(f"invalid or duplicate mTLS certificate pin for {customer_id}")
        certs.add(fingerprint)
        engineers = customer.get("engineers")
        if not isinstance(engineers, list) or not engineers or any(item not in config["engineers"] for item in engineers):
            raise ValueError(f"customer {customer_id} needs explicitly enrolled engineer identities")
        if customer.get("ssh_engineer") not in engineers:
            raise ValueError(f"customer {customer_id} needs an ssh_engineer from its engineer allow-list")
    for engineer_id, engineer in config["engineers"].items():
        if not valid_wireguard_key(engineer.get("wireguard_public_key")):
            raise ValueError(f"invalid WireGuard public key for engineer {engineer_id}")
        if engineer["wireguard_public_key"] in wg_keys:
            raise ValueError("engineer WireGuard keys must identify separate people")
        wg_keys.add(engineer["wireguard_public_key"])
        address = ipaddress.IPv4Address(engineer.get("address", "0.0.0.0"))
        if address in addresses or address not in ipaddress.IPv4Network(config["engineer_pool"], strict=False):
            raise ValueError(f"invalid or duplicate tunnel address for engineer {engineer_id}")
        addresses.add(str(address))
        if not re.match(r"^(ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: .*)?$", str(engineer.get("ssh_public_key", ""))):
            raise ValueError(f"invalid SSH public key for engineer {engineer_id}")
    checker = config.get("checker")
    if not isinstance(checker, dict) or not valid_wireguard_key(checker.get("wireguard_public_key")):
        raise ValueError("a dedicated Checker WireGuard identity is required")
    checker_address = ipaddress.IPv4Address(checker.get("address", "0.0.0.0"))
    if checker_address not in ipaddress.IPv4Network(config["engineer_pool"], strict=False) or str(checker_address) in addresses:
        raise ValueError("Checker address must be unique and inside the engineer pool")
    if checker["wireguard_public_key"] in wg_keys:
        raise ValueError("Checker must have an identity separate from every engineer")
    if not isinstance(checker.get("probe_port"), int) or checker["probe_port"] not in range(1024, 65536):
        raise ValueError("Checker probe port must be an unprivileged TCP port")
    for name in ("tls_certificate", "tls_private_key", "client_ca"):
        if not isinstance(config.get(name), str) or not config[name]:
            raise ValueError(f"{name} is required for authenticated Connect API access")


class SessionStore:
    """Durable session authority, replay ledger and append-only lifecycle audit."""

    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        self.database = directory / "gateway.sqlite3"
        self.audit_file = directory / "audit.jsonl"
        self.lock = threading.RLock()
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY, remote_id TEXT UNIQUE NOT NULL, customer_id TEXT NOT NULL,
                pbx_key TEXT NOT NULL, pbx_address TEXT NOT NULL, gateway_address TEXT NOT NULL,
                subnet TEXT NOT NULL, engineer_ids TEXT NOT NULL, ssh_key TEXT NOT NULL,
                expires_at INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL,
                closed_at INTEGER, close_reason TEXT, cleanup_complete INTEGER NOT NULL DEFAULT 0)""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
            if "cleanup_complete" not in columns:
                db.execute("ALTER TABLE sessions ADD COLUMN cleanup_complete INTEGER NOT NULL DEFAULT 0")
            db.execute("CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, seen_at INTEGER NOT NULL)")
        os.chmod(self.database, 0o600)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10, isolation_level="IMMEDIATE")
        db.row_factory = sqlite3.Row
        return db

    @contextlib.contextmanager
    def connection(self):
        db = self.connect()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def consume_request(self, request_id: str, timestamp: int, now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if not REQUEST_ID.fullmatch(request_id) or abs(current - timestamp) > 300:
            raise GatewayError(400, "request-freshness-invalid")
        with self.lock, self.connection() as db:
            try:
                db.execute("INSERT INTO requests(request_id, seen_at) VALUES (?, ?)", (request_id, current))
            except sqlite3.IntegrityError as error:
                raise GatewayError(409, "request-replayed") from error
            db.execute("DELETE FROM requests WHERE seen_at < ?", (current - 86400,))

    def session(self, session_id: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
            return dict(row) if row else None

    def active(self, now: int | None = None) -> list[dict[str, Any]]:
        current = int(time.time()) if now is None else now
        with self.connection() as db:
            rows = db.execute("SELECT * FROM sessions WHERE state IN ('connected','active') AND expires_at>?", (current,)).fetchall()
            return [dict(row) for row in rows]

    def due(self, now: int | None = None) -> list[dict[str, Any]]:
        current = int(time.time()) if now is None else now
        with self.connection() as db:
            rows = db.execute("SELECT * FROM sessions WHERE state IN ('connected','active') AND expires_at<=?", (current,)).fetchall()
            return [dict(row) for row in rows]

    def overlapping(self, subnet: ipaddress.IPv4Network, excluding: str | None = None) -> bool:
        with self.connection() as db:
            rows = db.execute("SELECT session_id,subnet FROM sessions WHERE cleanup_complete=0").fetchall()
        return any(row["session_id"] != excluding and subnet.overlaps(ipaddress.IPv4Network(row["subnet"])) for row in rows)

    def key_used(self, public_key: str) -> bool:
        with self.connection() as db:
            return db.execute("SELECT 1 FROM sessions WHERE pbx_key=? LIMIT 1", (public_key,)).fetchone() is not None

    def reserve(self, record: dict[str, Any]) -> None:
        with self.lock, self.connection() as db:
            existing = db.execute("SELECT * FROM sessions WHERE session_id=?", (record["session_id"],)).fetchone()
            if existing:
                old = dict(existing)
                same = all(old[key] == record[key] for key in ("customer_id", "pbx_key", "pbx_address", "gateway_address", "subnet", "engineer_ids", "ssh_key", "expires_at"))
                if same and old["state"] == "active":
                    return
                if same and old["state"] == "provisioning":
                    return
                raise GatewayError(409, "session-id-already-used")
            db.execute("""INSERT INTO sessions(session_id,remote_id,customer_id,pbx_key,pbx_address,gateway_address,subnet,
                engineer_ids,ssh_key,expires_at,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                tuple(record[key] for key in ("session_id", "remote_id", "customer_id", "pbx_key", "pbx_address", "gateway_address", "subnet", "engineer_ids", "ssh_key", "expires_at", "state", "created_at")))

    def activate(self, session_id: str) -> None:
        with self.lock, self.connection() as db:
            db.execute("UPDATE sessions SET state='active' WHERE session_id=? AND state='connected'", (session_id,))

    def connected(self, session_id: str) -> None:
        with self.lock, self.connection() as db:
            db.execute("UPDATE sessions SET state='connected' WHERE session_id=? AND state='provisioning'", (session_id,))

    def set_state(self, session_id: str, state: str) -> None:
        if state not in ("provisioning", "connected", "active"):
            raise ValueError("invalid gateway session state")
        with self.lock, self.connection() as db:
            db.execute("UPDATE sessions SET state=? WHERE session_id=?", (state, session_id))

    def finalize_cleanup(self, session_id: str) -> None:
        with self.lock, self.connection() as db:
            db.execute("UPDATE sessions SET cleanup_complete=1 WHERE session_id=?", (session_id,))

    def close(self, session_id: str, reason: str) -> dict[str, Any] | None:
        with self.lock, self.connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
            if not row:
                return None
            record = dict(row)
            if record["state"] not in ("revoked", "expired", "failed"):
                db.execute("UPDATE sessions SET state=?, closed_at=?, close_reason=? WHERE session_id=?",
                       ("expired" if reason == "expired" else "revoked", int(time.time()), reason, session_id))
            return record

    def event(self, event: str, **fields: Any) -> None:
        record = {"time": int(time.time()), "event": event, **fields}
        fd = os.open(self.audit_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, canonical_json(record) + b"\n")
        finally:
            os.close(fd)


class GatewayService:
    def __init__(self, config: dict[str, Any], state_dir: Path, runner=None):
        validate_config(config)
        self.config = config
        self.interface = config.get("interface", "wg-teliphones")
        self.store = SessionStore(state_dir)
        self.runner = runner or subprocess.run
        self.lock = threading.RLock()

    def run(self, args: list[str], input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
        try:
            result = self.runner(args, input=input_text, text=True, capture_output=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            if check:
                raise GatewayError(503, "gateway-tool-failed") from error
            return subprocess.CompletedProcess(args, 127, "", str(error))
        if check and result.returncode != 0:
            raise GatewayError(503, "gateway-tool-failed")
        return result

    def configure_interface(self) -> None:
        private_file = Path(self.config["private_key_file"])
        stat = private_file.lstat()
        if not private_file.is_file() or private_file.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o077:
            raise GatewayError(500, "gateway-private-key-permissions-invalid")
        show = self.run(["wg", "show", self.interface], check=False)
        if show.returncode != 0:
            self.run(["ip", "link", "add", "dev", self.interface, "type", "wireguard"])
        self.run(["wg", "set", self.interface, "private-key", str(private_file), "listen-port", str(int(self.config["listen_port"]))])
        self.run(["ip", "link", "set", "up", "dev", self.interface])
        current_public = self.run(["wg", "show", self.interface, "public-key"]).stdout.strip()
        if current_public != self.config["public_key"]:
            raise GatewayError(500, "gateway-public-key-mismatch")
        try:
            forwarding = self.run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
        except GatewayError as error:
            raise GatewayError(500, "gateway-forwarding-state-unavailable") from error
        if forwarding != "1":
            raise GatewayError(500, "gateway-forwarding-not-explicitly-enabled")
        self.ensure_firewall()
        self.assert_engineer_pool_free()
        peers = list(self.config["engineers"].values()) + [self.config["checker"]]
        for peer in peers:
            address = str(ipaddress.IPv4Address(peer["address"])) + "/32"
            self.run(["wg", "set", self.interface, "peer", peer["wireguard_public_key"], "allowed-ips", address])
            self.run(["ip", "route", "replace", address, "dev", self.interface])

    def ensure_firewall(self) -> None:
        table = self.run(["nft", "list", "table", "inet", TABLE], check=False)
        if table.returncode == 0:
            if not self.firewall_table_valid(table.stdout):
                raise GatewayError(500, "gateway-nft-table-conflict")
            return
        rules = f'''table inet {TABLE} {{
 set allowed_tcp {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; timeout 4h; }}
 set allowed_reverse {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; timeout 4h; }}
 set allowed_probe {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; timeout 5m; }}
 set allowed_probe_reverse {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; timeout 5m; }}
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "{self.interface}" oifname "{self.interface}" ip saddr . ip daddr . tcp dport @allowed_probe accept
  iifname "{self.interface}" oifname "{self.interface}" ct state established,related ip saddr . ip daddr . tcp sport @allowed_probe_reverse accept
  iifname "{self.interface}" oifname "{self.interface}" ip saddr . ip daddr . tcp dport @allowed_tcp accept
  iifname "{self.interface}" oifname "{self.interface}" ct state established,related ip saddr . ip daddr . tcp sport @allowed_reverse accept
    iifname "{self.interface}" drop
    oifname "{self.interface}" drop
 }}
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "{self.interface}" drop
 }}
}}'''
        self.run(["nft", "-f", "-"], rules)

    def firewall_table_valid(self, output: str) -> bool:
        expected = {
            "forward": sorted([
                f'iifname "{self.interface}" oifname "{self.interface}" ip saddr . ip daddr . tcp dport @allowed_probe accept',
                f'iifname "{self.interface}" oifname "{self.interface}" ct state established,related ip saddr . ip daddr . tcp sport @allowed_probe_reverse accept',
                f'iifname "{self.interface}" oifname "{self.interface}" ip saddr . ip daddr . tcp dport @allowed_tcp accept',
                f'iifname "{self.interface}" oifname "{self.interface}" ct state established,related ip saddr . ip daddr . tcp sport @allowed_reverse accept',
                f'iifname "{self.interface}" drop',
                f'oifname "{self.interface}" drop',
            ]),
            "input": [f'iifname "{self.interface}" drop'],
        }
        chain_rules: dict[str, list[str]] = {}
        active_chain: str | None = None
        active_set: str | None = None
        chain_names: set[str] = set()
        set_names: set[str] = set()
        set_definitions: dict[str, list[str]] = {}
        for line in output.splitlines():
            stripped = line.strip()
            chain_match = re.fullmatch(r"chain\s+([a-zA-Z0-9_-]+)\s*\{", stripped)
            set_match = re.fullmatch(r"set\s+([a-zA-Z0-9_-]+)\s*\{", stripped)
            if chain_match:
                active_chain = chain_match.group(1)
                chain_names.add(active_chain)
                chain_rules[active_chain] = []
                continue
            if set_match:
                active_set = set_match.group(1)
                set_names.add(active_set)
                set_definitions[active_set] = []
                continue
            if stripped == "}":
                active_chain = None
                active_set = None
                continue
            if active_set and stripped and not stripped.startswith("elements"):
                set_definitions[active_set].append(stripped.rstrip(";"))
            if active_chain and stripped and not stripped.startswith(("type ", "policy ")):
                chain_rules[active_chain].append(stripped)
        expected_sets = {
            "allowed_tcp": ["type ipv4_addr . ipv4_addr . inet_service", "flags timeout", "timeout 4h"],
            "allowed_reverse": ["type ipv4_addr . ipv4_addr . inet_service", "flags timeout", "timeout 4h"],
            "allowed_probe": ["type ipv4_addr . ipv4_addr . inet_service", "flags timeout", "timeout 5m"],
            "allowed_probe_reverse": ["type ipv4_addr . ipv4_addr . inet_service", "flags timeout", "timeout 5m"],
        }
        return (
            chain_names == set(expected)
            and set_names == set(expected_sets)
            and all(set_definitions.get(name) == definition for name, definition in expected_sets.items())
            and sorted(chain_rules.get("forward", [])) == expected["forward"]
            and chain_rules.get("input", []) == expected["input"]
            and all(name in output for name in ("hook forward", "hook input", "policy accept"))
        )

    def allowed_engineers(self, customer_id: str) -> tuple[list[str], str]:
        customer = self.config["customers"].get(customer_id)
        if not customer:
            raise GatewayError(403, "customer-identity-not-enrolled")
        engineers = customer["engineers"]
        ssh_engineer = customer["ssh_engineer"]
        if ssh_engineer not in engineers:
            raise GatewayError(403, "ssh-engineer-not-enrolled")
        return engineers, self.config["engineers"][ssh_engineer]["ssh_public_key"]

    def provision(self, customer_id: str, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL or request.get("action") != "provision":
            raise GatewayError(400, "connect-protocol-invalid")
        self.expire()
        session_id = str(request.get("session_id", ""))
        if not SESSION_ID.fullmatch(session_id):
            raise GatewayError(400, "session-id-invalid")
        now = int(time.time())
        expires = request.get("expires_at")
        if not isinstance(expires, int) or expires <= now or expires > now + 240 * 60:
            raise GatewayError(400, "session-expiry-invalid")
        if request.get("topology") != "on-pbx":
            raise GatewayError(400, "topology-not-supported")
        if not valid_wireguard_key(request.get("pbx_wg_public_key")):
            raise GatewayError(400, "customer-wireguard-key-invalid")
        pbx, gateway, subnet = tunnel_pair(request.get("pbx_tunnel_address"), request.get("support_tunnel_address"), self.config["support_pool"])
        engineers, ssh_key = self.allowed_engineers(customer_id)
        engineer_ips = [str(ipaddress.IPv4Address(self.config["engineers"][engineer]["address"])) + "/32" for engineer in engineers]
        existing = self.store.session(session_id)
        if existing and existing["state"] in ("provisioning", "connected", "active"):
            if existing["customer_id"] != customer_id or existing["pbx_key"] != request["pbx_wg_public_key"] or existing["expires_at"] != expires:
                raise GatewayError(409, "session-identity-conflict")
            return self.response(existing, engineer_ips)
        if existing:
            raise GatewayError(409, "session-id-already-used")
        if self.store.overlapping(subnet, excluding=session_id):
            raise GatewayError(409, "tunnel-subnet-collision")
        if self.store.key_used(request["pbx_wg_public_key"]):
            raise GatewayError(409, "customer-wireguard-key-reused")
        self.assert_gateway_pool_free(subnet)
        remote_id = secrets.token_hex(16)
        record = {
            "session_id": session_id, "remote_id": remote_id, "customer_id": customer_id,
            "pbx_key": request["pbx_wg_public_key"], "pbx_address": str(pbx.ip),
            "gateway_address": str(gateway.ip), "subnet": str(subnet),
            "engineer_ids": json.dumps(engineers), "ssh_key": ssh_key,
            "expires_at": expires, "state": "provisioning", "created_at": now,
        }
        with self.lock:
            self.store.reserve(record)
            try:
                self.run(["ip", "address", "add", str(gateway.ip) + "/32", "dev", self.interface])
                self.run(["ip", "route", "replace", str(pbx.ip) + "/32", "dev", self.interface])
                self.run(["wg", "set", self.interface, "peer", request["pbx_wg_public_key"], "allowed-ips", str(pbx.ip) + "/32"])
            except Exception:
                self.store.close(session_id, "provision-failed")
                if self.remove_peer(record):
                    self.store.finalize_cleanup(session_id)
                self.sync_firewall(best_effort=True)
                self.store.event("provision-failed", session_id=session_id, customer_id=customer_id)
                raise
        self.store.event("session-provisioned", session_id=session_id, customer_id=customer_id, expires_at=expires)
        active = self.store.session(session_id)
        return self.response(active, engineer_ips)

    def response(self, record: dict[str, Any], engineer_ips: list[str]) -> dict[str, Any]:
        return {
            "protocol": PROTOCOL,
            "session_id": record["session_id"],
            "remote_id": record["remote_id"],
            "expires_at": int(record["expires_at"]),
            "peer_public_key": self.config["public_key"],
            "peer_endpoint": self.config["endpoint"],
            "gateway_address": record["gateway_address"] + "/32",
            "engineer_addresses": engineer_ips,
            "checker_addresses": [str(ipaddress.IPv4Address(self.config["checker"]["address"])) + "/32"],
            "ssh_public_key": record["ssh_key"],
            "ssh_engineer_address": str(ipaddress.IPv4Address(self.config["engineers"][self.config["customers"][record["customer_id"]]["ssh_engineer"]]["address"])) + "/32",
            "state": record["state"],
            "reference_only": self.config["deployment_mode"] == "reference-lab",
        }

    def handshake_recent(self, record: dict[str, Any]) -> bool:
        output = self.run(["wg", "show", self.interface, "latest-handshakes"], check=False)
        if output.returncode != 0:
            return False
        now = int(time.time())
        for line in output.stdout.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == record["pbx_key"]:
                try:
                    timestamp = int(fields[1])
                except ValueError:
                    return False
                return timestamp > 0 and 0 <= now - timestamp <= 90
        return False

    def confirm(self, customer_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return self.transition(customer_id, request, "confirm", "connected")

    def activate(self, customer_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return self.transition(customer_id, request, "activate", "active")

    def transition(self, customer_id: str, request: dict[str, Any], action: str, target_state: str) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL or request.get("action") != action:
            raise GatewayError(400, "connect-protocol-invalid")
        session_id = str(request.get("session_id", ""))
        if not SESSION_ID.fullmatch(session_id):
            raise GatewayError(400, "session-id-invalid")
        with self.lock:
            record = self.store.session(session_id)
            if not record or record["customer_id"] != customer_id or request.get("remote_id") != record["remote_id"]:
                raise GatewayError(403, "session-identity-mismatch")
            if record["expires_at"] <= int(time.time()) or record["state"] in ("revoked", "expired", "failed"):
                raise GatewayError(410, "session-not-current")
            if record["state"] == target_state:
                if not self.handshake_recent(record):
                    raise GatewayError(425, "wireguard-handshake-not-current")
                return {"protocol": PROTOCOL, "session_id": session_id, "state": target_state}
            expected = "provisioning" if target_state == "connected" else "connected"
            if record["state"] != expected:
                raise GatewayError(409, "session-transition-invalid")
            if not self.handshake_recent(record):
                raise GatewayError(425, "wireguard-handshake-not-current")
            if target_state == "connected":
                self.store.connected(session_id)
            else:
                self.store.activate(session_id)
            try:
                self.sync_firewall()
            except Exception:
                self.store.set_state(session_id, expected)
                self.sync_firewall(best_effort=True)
                raise
            self.store.event("session-state", session_id=session_id, customer_id=customer_id, state=target_state)
        return {"protocol": PROTOCOL, "session_id": session_id, "state": target_state}

    def assert_gateway_pool_free(self, subnet: ipaddress.IPv4Network) -> None:
        routes = self.run(["ip", "-4", "route", "show", "table", "main"], check=False)
        addresses = self.run(["ip", "-o", "-4", "address", "show"], check=False)
        if routes.returncode != 0 or addresses.returncode != 0:
            raise GatewayError(503, "gateway-network-state-unavailable")
        for line in routes.stdout.splitlines():
            parts = line.split()
            destination = parts[0] if parts else ""
            device_index = parts.index("dev") if "dev" in parts else -1
            device = parts[device_index + 1] if device_index >= 0 and device_index + 1 < len(parts) else ""
            if destination == "default" or device == self.interface:
                continue
            try:
                network = ipaddress.IPv4Network(destination if "/" in destination else destination + "/32", strict=False)
            except ValueError:
                continue
            if subnet.overlaps(network):
                raise GatewayError(409, "gateway-address-collision")
        for line in addresses.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[1].rstrip(":") == self.interface or parts[2] != "inet":
                continue
            try:
                address = ipaddress.IPv4Interface(parts[3]).network
            except ValueError:
                continue
            if subnet.overlaps(address):
                raise GatewayError(409, "gateway-address-collision")

    def assert_engineer_pool_free(self) -> None:
        pool = ipaddress.IPv4Network(self.config["engineer_pool"], strict=False)
        routes = self.run(["ip", "-4", "route", "show", "table", "main"], check=False)
        addresses = self.run(["ip", "-o", "-4", "address", "show"], check=False)
        if routes.returncode != 0 or addresses.returncode != 0:
            raise GatewayError(503, "gateway-network-state-unavailable")
        for line in routes.stdout.splitlines():
            parts = line.split()
            if not parts or parts[0] == "default":
                continue
            device_index = parts.index("dev") if "dev" in parts else -1
            device = parts[device_index + 1] if device_index >= 0 and device_index + 1 < len(parts) else ""
            if device == self.interface:
                continue
            try:
                network = ipaddress.IPv4Network(parts[0] if "/" in parts[0] else parts[0] + "/32", strict=False)
            except ValueError:
                continue
            if pool.overlaps(network):
                raise GatewayError(409, "engineer-address-collision")
        for line in addresses.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[1].rstrip(":") == self.interface or parts[2] != "inet":
                continue
            try:
                network = ipaddress.IPv4Interface(parts[3]).network
            except ValueError:
                continue
            if pool.overlaps(network):
                raise GatewayError(409, "engineer-address-collision")

    def destroy(self, customer_id: str, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL or request.get("action") != "destroy":
            raise GatewayError(400, "connect-protocol-invalid")
        session_id = str(request.get("session_id", ""))
        if not SESSION_ID.fullmatch(session_id):
            raise GatewayError(400, "session-id-invalid")
        with self.lock:
            record = self.store.session(session_id)
            if not record:
                return {"protocol": PROTOCOL, "session_id": session_id, "destroyed": True}
            if record["customer_id"] != customer_id or request.get("remote_id") != record["remote_id"]:
                raise GatewayError(403, "session-identity-mismatch")
            self.store.close(session_id, "customer-revoked")
            firewall_clean = True
            try:
                self.sync_firewall()
            except GatewayError:
                firewall_clean = False
            removed = self.remove_peer(record)
            if removed and firewall_clean:
                self.store.finalize_cleanup(session_id)
            if not removed or not firewall_clean:
                self.store.event("cleanup-failed", session_id=session_id, customer_id=customer_id)
                raise GatewayError(503, "session-cleanup-pending")
        self.store.event("session-revoked", session_id=session_id, customer_id=customer_id)
        return {"protocol": PROTOCOL, "session_id": session_id, "destroyed": True}

    def remove_peer(self, record: dict[str, Any]) -> bool:
        peers = self.run(["wg", "show", self.interface, "peers"], check=False)
        if peers.returncode != 0:
            return False
        peer_removed = True
        if record["pbx_key"] in peers.stdout.splitlines():
            peer_removed = self.run(["wg", "set", self.interface, "peer", record["pbx_key"], "remove"], check=False).returncode == 0
        addresses = self.run(["ip", "-o", "-4", "address", "show", "dev", self.interface], check=False)
        if addresses.returncode != 0:
            return False
        expected = record["gateway_address"] + "/32"
        address_removed = True
        if re.search(r"\binet\s+" + re.escape(expected) + r"\b", addresses.stdout):
            address_removed = self.run(["ip", "address", "del", expected, "dev", self.interface], check=False).returncode == 0
        route = self.run(["ip", "route", "del", record["pbx_address"] + "/32", "dev", self.interface], check=False)
        route_removed = route.returncode == 0 or "No such process" in route.stderr or "No such file" in route.stderr
        return peer_removed and address_removed and route_removed

    def sync_firewall(self, best_effort: bool = False) -> None:
        tcp: dict[tuple[str, str, int], int] = {}
        reverse: dict[tuple[str, str, int], int] = {}
        probe: dict[tuple[str, str, int], int] = {}
        probe_reverse: dict[tuple[str, str, int], int] = {}
        for session in self.store.active():
            if session["state"] == "connected":
                checker_ip = str(ipaddress.IPv4Address(self.config["checker"]["address"]))
                port = int(self.config["checker"]["probe_port"])
                probe[(checker_ip, session["pbx_address"], port)] = min(session["expires_at"], int(time.time()) + 300)
                probe_reverse[(session["pbx_address"], checker_ip, port)] = min(session["expires_at"], int(time.time()) + 300)
                continue
            if session["state"] != "active":
                continue
            customer = self.config["customers"].get(session["customer_id"], {})
            for engineer_id in json.loads(session["engineer_ids"]):
                engineer_ip = str(ipaddress.IPv4Address(self.config["engineers"][engineer_id]["address"]))
                for port in customer.get("services", DEFAULT_SERVICES):
                    if not isinstance(port, int) or not 1 <= port <= 65535:
                        raise GatewayError(500, "invalid-support-profile")
                    tcp[(engineer_ip, session["pbx_address"], port)] = max(session["expires_at"], tcp.get((engineer_ip, session["pbx_address"], port), 0))
                    reverse[(session["pbx_address"], engineer_ip, port)] = max(session["expires_at"], reverse.get((session["pbx_address"], engineer_ip, port), 0))
        names = ("allowed_tcp", "allowed_reverse", "allowed_probe", "allowed_probe_reverse")
        statements = [f"flush set inet {TABLE} {name}" for name in names]
        for name, items in (("allowed_tcp", tcp), ("allowed_reverse", reverse), ("allowed_probe", probe), ("allowed_probe_reverse", probe_reverse)):
            if items:
                now = int(time.time())
                elements = ", ".join(f"{src} . {dst} . {port} timeout {max(1, expiry - now)}s" for (src, dst, port), expiry in sorted(items.items()))
                statements.append(f"add element inet {TABLE} {name} {{ {elements} }}")
        result = self.run(["nft", "-f", "-"], "\n".join(statements) + "\n", check=not best_effort)
        if result.returncode != 0 and not best_effort:
            raise GatewayError(503, "firewall-update-failed")

    def expire(self) -> int:
        expired = self.store.due()
        closed = 0
        for record in expired:
            with self.lock:
                self.store.close(record["session_id"], "expired")
                firewall_clean = True
                try:
                    self.sync_firewall()
                except GatewayError:
                    firewall_clean = False
                finally:
                    peer_clean = self.remove_peer(record)
                if not firewall_clean or not peer_clean:
                    self.store.event("cleanup-failed", session_id=record["session_id"], customer_id=record["customer_id"])
                    continue
                self.store.finalize_cleanup(record["session_id"])
            self.store.event("session-expired", session_id=record["session_id"], customer_id=record["customer_id"])
            closed += 1
        return closed

    def reconcile(self) -> None:
        self.configure_interface()
        with self.store.connection() as db:
            rows = db.execute("SELECT * FROM sessions WHERE cleanup_complete=0").fetchall()
        for row in rows:
            record = dict(row)
            if record["state"] in ("connected", "active") and record["expires_at"] > int(time.time()):
                self.run(["ip", "address", "add", record["gateway_address"] + "/32", "dev", self.interface], check=False)
                self.run(["ip", "route", "replace", record["pbx_address"] + "/32", "dev", self.interface])
                self.run(["wg", "set", self.interface, "peer", record["pbx_key"], "allowed-ips", record["pbx_address"] + "/32"])
            else:
                self.store.close(record["session_id"], "reconcile-incomplete-or-expired")
                if self.remove_peer(record):
                    self.store.finalize_cleanup(record["session_id"])
                else:
                    self.store.event("cleanup-failed", session_id=record["session_id"], customer_id=record["customer_id"])
        self.sync_firewall()
        self.expire()

    def engineer_grant(self, engineer_id: str) -> dict[str, Any]:
        engineer = self.config["engineers"].get(engineer_id)
        if not engineer:
            raise GatewayError(404, "engineer-not-enrolled")
        sessions = []
        for session in self.store.active():
            if session["state"] == "active" and engineer_id in json.loads(session["engineer_ids"]):
                sessions.append({"session_id": session["session_id"], "pbx_address": session["pbx_address"], "expires_at": session["expires_at"]})
        return {"schema": "teliphones-engineer-grant/1", "engineer_id": engineer_id,
                "engineer_address": str(ipaddress.IPv4Address(engineer["address"])) + "/32",
            "engineer_public_key": engineer["wireguard_public_key"],
                "gateway_public_key": self.config["public_key"], "endpoint": self.config["endpoint"],
                "sessions": sessions}

    def checker_grant(self) -> dict[str, Any]:
        checker = self.config["checker"]
        sessions = []
        for session in self.store.active():
            if session["state"] == "connected":
                sessions.append({"session_id": session["session_id"], "pbx_address": session["pbx_address"],
                                 "probe_port": checker["probe_port"], "expires_at": session["expires_at"]})
        return {"schema": "teliphones-checker-grant/1",
                "checker_address": str(ipaddress.IPv4Address(checker["address"])) + "/32",
                "checker_public_key": checker["wireguard_public_key"],
                "gateway_public_key": self.config["public_key"], "endpoint": self.config["endpoint"],
                "sessions": sessions}


class APIHandler(http.server.BaseHTTPRequestHandler):
    server: "GatewayHTTPServer"

    def do_POST(self) -> None:
        try:
            identity = self.authenticated_customer()
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 65536:
                raise GatewayError(413, "request-size-invalid")
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise GatewayError(400, "request-invalid")
            self.server.service.store.consume_request(str(request.get("request_id", "")), int(request.get("request_timestamp", 0)))
            if self.path == "/v1/support-sessions":
                result = self.server.service.provision(identity, request)
            elif self.path == "/v1/support-sessions/confirm":
                result = self.server.service.confirm(identity, request)
            elif self.path == "/v1/support-sessions/activate":
                result = self.server.service.activate(identity, request)
            elif self.path == "/v1/support-sessions/destroy":
                result = self.server.service.destroy(identity, request)
            else:
                raise GatewayError(404, "endpoint-not-found")
            self.respond(200, result)
        except GatewayError as error:
            self.respond(error.status, {"error": error.code})
        except (ValueError, json.JSONDecodeError):
            self.respond(400, {"error": "request-invalid"})
        except Exception:
            self.server.service.store.event("api-internal-error")
            self.respond(500, {"error": "gateway-internal-error"})

    def authenticated_customer(self) -> str:
        certificate = self.connection.getpeercert(binary_form=True)
        if not certificate:
            raise GatewayError(401, "client-certificate-required")
        fingerprint = hashlib.sha256(certificate).hexdigest()
        for customer_id, customer in self.server.service.config["customers"].items():
            if secrets.compare_digest(fingerprint, customer["certificate_sha256"].lower()):
                return customer_id
        raise GatewayError(403, "client-certificate-not-enrolled")

    def respond(self, status: int, value: dict[str, Any]) -> None:
        body = canonical_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class GatewayHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: GatewayService, context: ssl.SSLContext):
        super().__init__(address, APIHandler)
        self.service = service
        self.socket = context.wrap_socket(self.socket, server_side=True)


def load_config(path: Path) -> dict[str, Any]:
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ValueError("gateway config must be a root-owned regular file not writable by group or others")
    config = json.loads(path.read_text(encoding="utf-8"))
    validate_config(config)
    return config


def serve(config: dict[str, Any], state_dir: Path) -> None:
    service = GatewayService(config, state_dir)
    service.reconcile()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(config["tls_certificate"], config["tls_private_key"])
    context.load_verify_locations(config["client_ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    host = config.get("api_bind", "127.0.0.1")
    port = int(config.get("api_port", 9443))
    server = GatewayHTTPServer((host, port), service, context)
    stop = threading.Event()

    def expire_loop() -> None:
        while not stop.wait(1):
            try:
                service.expire()
            except Exception:
                service.store.event("expiry-reconcile-failed")

    worker = threading.Thread(target=expire_loop, daemon=True)
    worker.start()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        stop.set()
        server.server_close()
        worker.join(timeout=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/teliphones-gateway.json")
    parser.add_argument("--state-dir", default="/var/lib/teliphones-gateway")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("serve")
    subparsers.add_parser("reconcile")
    grant = subparsers.add_parser("engineer-grant")
    grant.add_argument("engineer_id")
    subparsers.add_parser("checker-grant")
    args = parser.parse_args(argv)
    try:
        config = load_config(Path(args.config))
        service = GatewayService(config, Path(args.state_dir))
        if args.action == "serve":
            serve(config, Path(args.state_dir))
        elif args.action == "reconcile":
            service.reconcile()
        elif args.action == "engineer-grant":
            print(json.dumps(service.engineer_grant(args.engineer_id), indent=2))
        elif args.action == "checker-grant":
            print(json.dumps(service.checker_grant(), indent=2))
        return 0
    except (GatewayError, OSError, ValueError, sqlite3.Error) as error:
        print(f"teliphones-gateway: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())