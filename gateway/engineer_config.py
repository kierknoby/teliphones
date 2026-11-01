#!/usr/bin/env python3
"""Render a least-route WireGuard client config on the engineer's own workstation."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def read_private_key(path: Path) -> str:
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("WireGuard private-key file must be a regular, user-owned file with mode 0600 or stricter")
    value = path.read_text(encoding="ascii").strip()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid WireGuard private key") from error
    if len(decoded) != 32 or not any(decoded):
        raise ValueError("invalid WireGuard private key")
    return value


def render(grant: dict[str, Any], private_key: str, public_key: str) -> str:
    schema = grant.get("schema")
    if schema == "teliphones-engineer-grant/1":
        address_field, key_field = "engineer_address", "engineer_public_key"
    elif schema == "teliphones-checker-grant/1":
        address_field, key_field = "checker_address", "checker_public_key"
    else:
        raise ValueError("unsupported peer grant schema")
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", str(grant.get("gateway_public_key", ""))):
        raise ValueError("invalid gateway WireGuard public key")
    if grant.get(key_field) != public_key:
        raise ValueError("private key does not match the enrolled peer identity")
    address = ipaddress.IPv4Interface(grant.get(address_field, ""))
    endpoint = grant.get("endpoint", "")
    if not isinstance(endpoint, str) or not re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):[1-9][0-9]{0,4}", endpoint):
        raise ValueError("invalid configured gateway endpoint")
    sessions = grant.get("sessions")
    if not isinstance(sessions, list):
        raise ValueError("grant sessions must be a list")
    routes = sorted({str(ipaddress.IPv4Address(item["pbx_address"])) + "/32" for item in sessions if int(item["expires_at"]) > time.time()})
    if not routes:
        raise ValueError("no current customer authorisations are available")
    allowed = ", ".join(routes)
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {address}\n\n"
        "[Peer]\n"
        f"PublicKey = {grant['gateway_public_key']}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed}\n"
        "PersistentKeepalive = 25\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grant", required=True, type=Path, help="gateway-issued JSON grant; contains no private keys")
    parser.add_argument("--private-key-file", required=True, type=Path, help="local engineer private key, never uploaded")
    parser.add_argument("--output", required=True, type=Path, help="new configuration path; existing files are not overwritten")
    args = parser.parse_args(argv)
    try:
        grant = json.loads(args.grant.read_text(encoding="utf-8"))
        private_key = read_private_key(args.private_key_file)
        result = subprocess.run(["wg", "pubkey"], input=private_key + "\n", text=True, capture_output=True, timeout=5, check=True)
        config = render(grant, private_key, result.stdout.strip())
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(args.output, flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(config)
            output.flush()
            os.fsync(output.fileno())
        print(f"Created {args.output} with routes for {len(grant['sessions'])} active authorised session(s).")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"engineer-config: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())