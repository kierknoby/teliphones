#!/usr/bin/env python3
"""Called only by the regression test inside an isolated user/network namespace."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[2]
if os.geteuid() != 0 or len(sys.argv) != 2 or not sys.argv[1].startswith("net:[") or os.readlink("/proc/self/ns/net") == sys.argv[1]:
    raise SystemExit("Refusing to run outside a new user/network namespace.")

spec = importlib.util.spec_from_file_location("broker", ROOT / "teliphones/support_broker.py")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


def nft(*arguments, value=None):
    return subprocess.run(["/usr/sbin/nft", *arguments], input=json.dumps(value) if value else None,
                          capture_output=True, text=True, check=True).stdout


with tempfile.TemporaryDirectory(prefix=".workstation-lab-", dir=ROOT) as directory:
    broker.STATE = Path(directory)
    instance = broker.Broker()
    instance.audit = lambda *args: None
    nft("add", "table", "inet", "teliphones_lab_foreign")
    foreign = nft("-j", "list", "table", "inet", "teliphones_lab_foreign")
    instance.start_monitor()
    try:
        expected = broker.workstation_policy("100.70.1.1", ["100.70.1.2", "100.70.1.3"])
        instance.mutate_policy(expected, None)
        assert broker.policy_equal(instance.owned_table(), expected)
        assert not instance.monitor.pending
        assert not instance.enforcement_event.is_set(), "own mutations triggered enforcement"
        subprocess.run(["/usr/sbin/ip", "link", "add", "tlp-admin", "type", "dummy"], check=True)
        subprocess.run(["/usr/sbin/ip", "link", "set", "tlp-admin", "up"], check=True)
        nft("flush", "table", "inet", broker.WORKSTATION_TABLE)
        assert instance.enforcement_event.wait(3), "external rule removal was not observed"
        assert not broker.policy_equal(instance.owned_table(), expected)
        instance.disable_workstations()
        assert "UP" not in instance.link_state()["flags"]
        instance.enforcement_event.clear()
        instance.mutate_policy(expected, instance.owned_table())
        assert broker.policy_equal(instance.owned_table(), expected)
        instance.teardown_workstations()
        assert instance.link_state() is None and instance.owned_table() is None
        assert nft("-j", "list", "table", "inet", "teliphones_lab_foreign") == foreign

        # A foreign namesake created between inventory and transaction must survive.
        instance.mutate_policy(expected, None)
        inspected = instance.owned_table()
        nft("delete", "table", "inet", broker.WORKSTATION_TABLE)
        nft("-j", "-f", "-", value={"nftables": [{"create": {"table": {
            "family": "inet", "name": broker.WORKSTATION_TABLE, "comment": "namespace test foreign owner"}}}]})
        try:
            instance.mutate_policy(None, inspected)
            raise AssertionError("deletion of a stale inspected handle succeeded")
        except broker.BrokerError:
            pass
        assert "namespace test foreign owner" in nft("-j", "list", "table", "inet", broker.WORKSTATION_TABLE)
        try:
            instance.mutate_policy(expected, None)
            raise AssertionError("exclusive table creation accepted an unfamiliar namesake")
        except broker.BrokerError:
            pass
        assert "namespace test foreign owner" in nft("-j", "list", "table", "inet", broker.WORKSTATION_TABLE)
        try:
            instance.teardown_workstations()
            raise AssertionError("unfamiliar namesake was not refused")
        except broker.BrokerError:
            pass
        assert "namespace test foreign owner" in nft("-j", "list", "table", "inet", broker.WORKSTATION_TABLE)
        assert nft("-j", "list", "table", "inet", "teliphones_lab_foreign") == foreign
        print("PASS: real nft JSON roundtrip, event subscription, external flush detection, interface down/delete, own-event filtering, isolated-table preservation and stale-handle refusal")
    finally:
        instance.monitor.close()
