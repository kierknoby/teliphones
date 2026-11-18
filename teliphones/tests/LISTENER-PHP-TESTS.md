# TELIPHONES listener PHP regression bundle

This test-only bundle validates persistent FreePBX Custom Service ownership,
multi-listener reconciliation, asynchronous FreePBX rule generation,
regeneration recovery, last-listener removal, and an interface-specific INPUT
jump. It does not contact FreePBX, modify iptables, or contain runtime state.

Run from the extracted bundle root with PHP 8.2+:

```bash
php teliphones/tests/run-listener-regressions.php
```

Expected result: both fixtures print `PASS`, followed by `TELIPHONES listener
PHP regressions: PASS` and exit status zero. A failure is a source-validation
blocker; it is not evidence that a live PBX was tested.

The listener fixture uses the FreePBX 17 generated layout:
`INPUT -> fpbxfirewall -> fpbxinterfaces -> zone-external -> fpbxsvc-*`.
It exercises the reported development-PBX service identifier and FreePBX 17
structure, including preceding Fail2Ban `RETURN` chains and unrelated UDP
multiport hooks. It rejects preceding listener-port UDP drops, NEW-UDP drops,
universal UDP drops, a terminal intermediary chain, broad source restrictions,
and a broad listener-port ACCEPT that bypasses the managed service. It can
require named public interfaces as test input. These are structural integration
checks, not a general iptables interpreter or proof of end-to-end packet
reachability. The complete 162-rule diagnostic snapshot is not present in this
bundle; the fixture contains the reported listener-relevant rules only.
