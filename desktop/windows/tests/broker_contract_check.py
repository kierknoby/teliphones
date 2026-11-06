#!/usr/bin/env python3
"""Linux integration: cross-check the C++ core against the real broker and gateway renderer."""

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

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
        print("usage: broker_contract_check.py <path-to-contract_tool>")
        return 2
    broker_tests = load("broker_tests", ROOT / "gateway" / "tests" / "test_support_broker.py")
    broker = broker_tests.broker_module
    engineer = load("engineer_config", ROOT / "gateway" / "engineer_config.py")
    key = base64.b64encode(hashlib.sha256(b"workstation").digest()).decode()
    pbx_key = base64.b64encode(hashlib.sha256(b"pbx").digest()).decode()
    private = base64.b64encode(hashlib.sha256(b"private").digest()).decode()
    ssh_key = "ssh-ed25519 " + base64.b64encode(
        b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
    nonce = broker.b64url_encode(os.urandom(16))
    failures = []

    status, request = tool("request", "ADMIN-PC (Office)", key, nonce)
    parsed = broker.parse_pair_request(request) if status == 0 else None
    if not parsed or parsed["public_key"] != key or parsed["nonce"] != nonce or parsed["workstation"] != "ADMIN-PC (Office)":
        failures.append("broker did not accept the C++ pairing request: %s" % request)

    # Execute the real broker approval/revocation and C++ import/store/render logic.
    # Only privileged OS/network calls are doubled; no response schema is invented here.
    with tempfile.TemporaryDirectory() as directory:
        state, enrollment = Path(directory) / "state", Path(directory) / "enrollment"
        state.mkdir(mode=0o700)
        network = broker_tests.FakeNetwork()
        with patch.object(broker, "STATE", state), patch.object(broker, "ENROLLMENT", enrollment):
            instance = broker.Broker()
            instance.run, instance.tool = network.run, lambda name: name
            instance.audit = lambda *args: None
            instance.save_workstations({"subnet": None, "listen_port": None, "web": broker.DEFAULT_WEB,
                                        "connection_state": "open", "workstations": []})
            instance.ssh.reconcile = lambda *args, **kwargs: None
            revoked = []
            for mode, ssh in (("temporary", "1"), ("persistent", "0")):
                # Revocation is durable: each pairing below uses a distinct identity, as a reinstalled workstation would.
                ws_key = key if not revoked else base64.b64encode(hashlib.sha256(mode.encode()).digest()).decode()
                pairing_request = request if ws_key == key else tool("request", "ADMIN-PC (Office)", ws_key, nonce)[1]
                if ssh == "1":
                    status, pairing_request = tool("request2", "ADMIN-PC (Office)", ws_key, nonce, ssh_key)
                    if status != 0:
                        failures.append("C++ core could not create an SSH-capable pairing request: %s" % pairing_request)
                        continue
                    instance.ssh.initialise = lambda: ssh_key
                    instance.ssh.host_key = lambda: ssh_key
                    instance.ssh.account_policy = lambda *args: {}
                approval = {"action": "pair", "request": pairing_request, "endpoint_host": "PBX.Example.NET",
                            "listen_port": "51821", "mode": mode, "minutes": "60", "ssh": ssh}
                if ssh == "1":
                    approval["ssh_user"] = "root"
                reply = instance.dispatch(approval, 1000)
                code = reply["pairing_response"]
                response = broker_tests.decode_response(code)
                expected = "%s %s %s pbx.example.net:51821 %s %s %s" % (
                    response["workstation_id"], response["address"], response["pbx_address"], mode,
                    response["expires_at"] or 0, "ssh" if ssh == "1" else "nossh")
                status, output = tool("response", code, nonce, ws_key, *([ssh_key] if ssh == "1" else []))
                if status != 0 or output != expected:
                    failures.append("C++ core rejected real %s broker response: %s (response %s)" %
                                    (mode, output, json.dumps(response, sort_keys=True)))
                status, rendered = tool("administrator", code, nonce, ws_key,
                                        *([ssh_key] if ssh == "1" else []), private)
                expected_config = ("[Interface]\nPrivateKey = %s\nAddress = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\n"
                                   "AllowedIPs = %s/32\nPersistentKeepalive = 25" %
                                   (private, response["address"], response["pbx_public_key"], response["endpoint"], response["pbx_address"]))
                if status != 0 or rendered.replace("\r\n", "\n") != expected_config:
                    failures.append("C++ saved profile/tunnel differs from actual broker admission: %s" % rendered)
                state_now, _ = instance.workstation_state()
                if network.peers.get(ws_key) != response["address"] or not broker.policy_equal(
                        network.table, instance.expected_policy(state_now)):
                    failures.append("Broker peer/firewall differs from the returned pairing permissions")
                if tool("response", code, broker.b64url_encode(os.urandom(16)), ws_key)[0] == 0:
                    failures.append("C++ core accepted a response bound to another nonce")
                if tool("response", code, nonce, pbx_key)[0] == 0:
                    failures.append("C++ core accepted a response bound to another workstation key")
                instance.dispatch({"action": "unpair", "workstation_id": response["workstation_id"]}, 1000)
                state_now, _ = instance.workstation_state()
                if network.peers or not network.link or not broker.policy_equal(
                        network.table, instance.expected_policy(state_now)):
                    failures.append("Open-mode revocation did not retain an empty listener with the expected policy")
                revoked.append(pairing_request)
            try:
                instance.dispatch({"action": "pair", "request": revoked[0], "endpoint_host": "PBX.Example.NET",
                                   "listen_port": "51821", "mode": "persistent", "minutes": "60", "ssh": "0"}, 1000)
                failures.append("Broker re-admitted a revoked workstation identity")
            except broker.BrokerError as error:
                if "revoked" not in str(error):
                    failures.append("Revoked identity was refused for an unexpected reason: %s" % error)

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
    print("Desktop contract checks: PASS (real broker approval/revocation, C++ request/import/profile/tunnel compatibility, fingerprints and support config; OS networking doubled)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
