#!/usr/bin/env python3
"""Read-only TELIPHONES Checker challenge responder for a private WireGuard address."""

from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path


SESSION_ID = re.compile(r"^[a-f0-9]{32}$")


def load_challenge(path: Path, expected_session: str) -> dict:
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_mode & 0o022:
        raise ValueError("unsafe challenge file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != "teliphones-checker/1" or value.get("session_id") != expected_session:
        raise ValueError("challenge does not belong to this session")
    if not SESSION_ID.fullmatch(expected_session) or int(value.get("expires_at", 0)) <= int(time.time()):
        raise ValueError("challenge expired or invalid")
    if not re.fullmatch(r"[a-f0-9]{48}", str(value.get("nonce", ""))):
        raise ValueError("challenge nonce invalid")
    return value


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    challenge_file: Path
    session_id: str

    def do_HEAD(self) -> None:
        if self.path != "/teliphones-checker/1":
            self.send_error(404)
            return
        try:
            challenge = load_challenge(self.challenge_file, self.session_id)
            supplied = self.headers.get("X-TELIPHONES-Challenge", "")
            if not __import__("hmac").compare_digest(supplied, challenge["nonce"]):
                self.send_error(403)
                return
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-TELIPHONES-Session", self.session_id)
            self.send_header("X-TELIPHONES-Challenge", challenge["nonce"])
            self.end_headers()
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(410)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--session", required=True)
    args = parser.parse_args(argv)
    try:
        ipaddress.IPv4Address(args.bind)
        if not SESSION_ID.fullmatch(args.session) or not 1024 <= args.port <= 65535:
            raise ValueError("invalid listener binding")
        ProbeHandler.challenge_file = args.challenge
        ProbeHandler.session_id = args.session
        server = http.server.ThreadingHTTPServer((args.bind, args.port), ProbeHandler)
        server.timeout = 1
        while True:
            load_challenge(args.challenge, args.session)
            server.handle_request()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"checker-probe-server: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())