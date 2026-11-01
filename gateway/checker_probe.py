#!/usr/bin/env python3
"""Independent, signed positive/negative TCP and HTTPS checks for a TELIPHONES challenge."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def connect_probe(host: str, port: int, tls: bool, server_name: str | None, nonce: str, session_id: str, namespace: str | None = None) -> dict[str, Any]:
    code = r'''import json,socket,ssl,sys
host,port,tls,name,nonce,session=sys.argv[1],int(sys.argv[2]),sys.argv[3]=="1",sys.argv[4],sys.argv[5],sys.argv[6]
sock=socket.create_connection((host,port),timeout=4)
result={"tcp":"reachable","tls":"not-tested","http_status":None}
if tls:
 context=ssl.create_default_context()
 sock=context.wrap_socket(sock,server_hostname=name or host)
 result["tls"]="verified"
request=("HEAD /teliphones-checker/1 HTTP/1.1\r\nHost: "+(name or host)+"\r\nX-TELIPHONES-Challenge: "+nonce+"\r\nConnection: close\r\n\r\n").encode("ascii")
sock.sendall(request)
response=b""
while b"\r\n\r\n" not in response and len(response)<4096:
 chunk=sock.recv(1024)
 if not chunk: break
 response+=chunk
head=response.split(b"\r\n\r\n",1)[0].decode("ascii","replace").split("\r\n")
line=head[0] if head else ""
parts=line.split()
if len(parts)<2 or not parts[1].isdigit(): raise RuntimeError("invalid HTTP response")
result["http_status"]=int(parts[1])
headers={}
for header in head[1:]:
 if ":" in header:
  name,value=header.split(":",1); headers[name.strip().lower()]=value.strip()
if result["http_status"]!=204 or headers.get("x-teliphones-session")!=session or headers.get("x-teliphones-challenge")!=nonce:
 raise RuntimeError("restricted Checker challenge response mismatch")
sock.close()
print(json.dumps(result,separators=(",",":")))'''
    if namespace:
        route = subprocess.run(["ip", "netns", "exec", namespace, "ip", "route", "get", host], capture_output=True, text=True, timeout=4)
        if route.returncode != 0 or "dev wg0" not in route.stdout:
            raise ValueError(f"Checker identity {namespace} has no assigned WireGuard route to {host}")
    command = ["python3", "-c", code, host, str(port), "1" if tls else "0", server_name or "", nonce, session_id]
    if namespace:
        command = ["ip", "netns", "exec", namespace, *command]
    try:
        response = subprocess.run(command, capture_output=True, text=True, timeout=8, check=True)
        return {"reachable": True, "result": json.loads(response.stdout)}
    except subprocess.CalledProcessError:
        return {"reachable": False, "result": None}
    except subprocess.TimeoutExpired:
        return {"reachable": False, "result": None}


def tcp_probe(host: str, port: int, namespace: str | None = None, require_wireguard: bool = True) -> dict[str, Any]:
    code = "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=4); s.close()"
    command = ["python3", "-c", code, host, str(port)]
    if namespace:
        route = subprocess.run(["ip", "netns", "exec", namespace, "ip", "route", "get", host], capture_output=True, text=True, timeout=4)
        if route.returncode != 0 or (require_wireguard and "dev wg0" not in route.stdout):
            raise ValueError(f"Checker identity {namespace} has no assigned WireGuard route to {host}")
        command = ["ip", "netns", "exec", namespace, *command]
    try:
        subprocess.run(command, capture_output=True, text=True, timeout=6, check=True)
        return {"reachable": True, "result": {"tcp": "reachable"}}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return {"reachable": False, "result": None}


def sign(evidence: dict[str, Any], private_key: Path) -> str:
    info = private_key.lstat()
    if private_key.is_symlink() or not private_key.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Checker signing key must be a regular, user-owned file with mode 0600 or stricter")
    description = subprocess.run(["openssl", "pkey", "-in", str(private_key), "-text", "-noout"], capture_output=True, text=True, check=True, timeout=10)
    if "ASN1 OID: prime256v1" not in description.stdout:
        raise ValueError("Checker evidence key must be ECDSA P-256")
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key)], input=canonical_json(evidence), capture_output=True, check=True, timeout=10)
    return base64.b64encode(result.stdout).decode("ascii")


def run_checks(challenge: dict[str, Any], authorized: dict[str, Any], negative: dict[str, Any], public: dict[str, Any]) -> dict[str, Any]:
    observations = {
        "authorised_source": {"support_service": "reachable" if authorized["reachable"] else "blocked", "probe": authorized["result"]},
        "negative_source": {"support_service": "reachable" if negative["reachable"] else "blocked"},
        "public_address": {"support_service": "reachable" if public["reachable"] else "blocked"},
        "unexpected_services": [],
    }
    return {
        "protocol": "teliphones-checker/1",
        "session_id": challenge["session_id"],
        "topology": challenge["topology"],
        "nonce": challenge["nonce"],
        "observed_at": int(time.time()),
        "observations": observations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--private-host", required=True)
    parser.add_argument("--private-port", required=True, type=int)
    parser.add_argument("--tls", action="store_true", help="require normal certificate-chain validation for the positive probe")
    parser.add_argument("--server-name")
    parser.add_argument("--authorized-netns", required=True)
    parser.add_argument("--negative-netns", required=True)
    parser.add_argument("--public-host", required=True)
    parser.add_argument("--public-port", required=True, type=int)
    parser.add_argument("--private-key", required=True, type=Path, help="independent Checker ECDSA P-256 signing key")
    args = parser.parse_args(argv)
    try:
        challenge = json.loads(args.challenge.read_text(encoding="utf-8"))
        if challenge.get("protocol") != "teliphones-checker/1" or int(challenge["expires_at"]) <= int(time.time()):
            raise ValueError("Checker challenge is invalid or expired")
        ipaddress.IPv4Address(args.private_host)
        ipaddress.IPv4Address(args.public_host)
        authorized = connect_probe(args.private_host, args.private_port, args.tls, args.server_name, challenge["nonce"], challenge["session_id"], args.authorized_netns)
        negative = tcp_probe(args.private_host, args.private_port, args.negative_netns)
        public = tcp_probe(args.public_host, args.public_port)
        evidence = run_checks(challenge, authorized, negative, public)
        evidence["signature"] = sign(evidence, args.private_key)
        print(json.dumps(evidence, sort_keys=True, indent=2))
        passed = authorized["reachable"] and not negative["reachable"] and not public["reachable"]
        return 0 if passed else 2
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"checker-probe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())