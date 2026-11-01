#!/usr/bin/env python3
"""Cross-check the desktop C++ core against the real TELIPHONES broker and gateway client renderer."""

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TELIPHONES_CONTRACT_TOOL", "")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tool(*args, stdin=None):
    result = subprocess.run([TOOL, *args], input=stdin, text=True, capture_output=True, timeout=10)
    return result.returncode, result.stdout.strip() if result.returncode == 0 else result.stderr.strip()


def main():
    if not TOOL:
        print("usage: contract_check.py <path-to-contract_tool>")
        return 2
    broker = load("support_broker", ROOT / "teliphones" / "support_broker.py")
    engineer = load("engineer_config", ROOT / "gateway" / "engineer_config.py")
    key = base64.b64encode(hashlib.sha256(b"workstation").digest()).decode()
    pbx_key = base64.b64encode(hashlib.sha256(b"pbx").digest()).decode()
    private = base64.b64encode(hashlib.sha256(b"private").digest()).decode()
    nonce = broker.b64url_encode(os.urandom(16))
    failures = []

    status, request = tool("request", "ADMIN-PC (Office)", key, nonce)
    parsed = broker.parse_pair_request(request) if status == 0 else None
    if not parsed or parsed["public_key"] != key or parsed["nonce"] != nonce or parsed["workstation"] != "ADMIN-PC (Office)":
        failures.append("broker did not accept the C++ pairing request: %s" % request)

    # Same construction as Broker.pair() in support_broker.py.
    response = {"schema": "teliphones-pair-response/1", "nonce": nonce, "workstation_id": "0123456789abcdef", "workstation_public_key": key,
                "address": "100.83.17.2/32", "pbx_address": "100.83.17.1", "pbx_name": "freepbx", "pbx_public_key": pbx_key,
                "endpoint": broker.endpoint_host("PBX.Example.NET") + ":51821", "mode": "temporary", "expires_at": 2000000000, "ssh": True,
                "gui_url": "http://100.83.17.1/admin/"}
    code = broker.PAIR_RESPONSE_PREFIX + broker.b64url_encode(json.dumps(response, separators=(",", ":"), sort_keys=True).encode())
    status, output = tool("response", code, nonce, key)
    if status != 0 or output != "0123456789abcdef 100.83.17.2/32 100.83.17.1 pbx.example.net:51821 temporary 2000000000 ssh":
        failures.append("C++ core rejected a broker pairing response: %s" % output)
    persistent = dict(response, mode="persistent", expires_at=None, ssh=False)
    code = broker.PAIR_RESPONSE_PREFIX + broker.b64url_encode(json.dumps(persistent, separators=(",", ":"), sort_keys=True).encode())
    if tool("response", code, nonce, key)[1].split()[-3:] != ["persistent", "0", "nossh"]:
        failures.append("C++ core misread a persistent broker pairing response")
    if tool("response", code, broker.b64url_encode(os.urandom(16)), key)[0] == 0:
        failures.append("C++ core accepted a response bound to another nonce")

    for public in (key, pbx_key):
        if tool("fingerprint", public)[1] != broker.key_fingerprint(public):
            failures.append("fingerprint differs from the broker for %s" % public)

    now = int(time.time())
    grant = {"schema": "teliphones-engineer-grant/1", "engineer_id": "engineer-a", "engineer_address": "10.99.0.2/32", "engineer_public_key": key,
             "gateway_public_key": pbx_key, "endpoint": "gateway.example.net:51820",
             "sessions": [{"session_id": "session-1", "pbx_address": "10.20.4.2", "expires_at": now + 3600}]}
    expected = engineer.render(grant, private, key)
    status, rendered = tool("support", private, "session-1", str(now), stdin=json.dumps(grant))
    if status != 0 or rendered.replace("\r\n", "\n").strip() != expected.strip():
        failures.append("Remote Support tunnel differs from gateway/engineer_config.py:\n%s\n---\n%s" % (rendered, expected))

    if failures:
        print("Desktop contract checks: FAIL")
        for failure in failures:
            print(" -", failure)
        return 1
    print("Desktop contract checks: PASS (broker accepts C++ requests, C++ accepts broker responses, fingerprints and engineer config match)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
