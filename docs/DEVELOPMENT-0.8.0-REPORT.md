# TELIPHONES 0.8.0 development verification report

Prepared 16 November 2026. Baseline: `83f0a78ff9e2b2b3e53b5df220ccbb0b7f3acc71`.
Changes remain uncommitted. No commit, push, tag, signature, publication,
installation, service restart or privileged networking experiment was performed.
No external search was performed.

## Version and implementation

Module/root broker **0.8.0** is justified by material changes to authority,
reconciliation and firewall admission. Protocol **12**, Windows **0.8.5** and
file version **0.8.5.0** remain unchanged. Pairing identities and original expiry
are preserved. See the [complete implementation and acceptance procedure](../teliphones/docs/DEVELOPMENT-0.8.0.md).

Corrected defects include rollback of Closed and SSH grant removal after cleanup
failure; foreground listener waits retaining the authority lock; stale listener
completion and queued heartbeat admission; unreachable-rule false positives;
unbounded controller workers and body-read lifetime; and disagreement between
the README upgrade procedure and the tested/displayed bootstrap instruction.

Restriction intent is durable before external work. Listener writers are
serialised, cancellation targets process groups, generations fence completion,
and shutdown cancels before cleanup. IPv4/IPv6 public listener paths and exact
NEW/ESTABLISHED management paths require conservative verification. Unknown or
blocked integration denies admission. Expiring iptables permits and terminal
tunnel drops supplement the native nftables gate; running-broker clock regression
withdraws leases. Controller admission remains available before management leases.

## Evidence boundary and remaining limitations

The original unknown-public-IP FreePBX 17 requirement is **unverified**. No local
upstream Firewall source or live API/ruleset evidence establishes the supported
production integration contract. The conservative interpreter may refuse legitimate
FreePBX classifiers, extra native hooks or non-filter policies. This candidate is
not suitable for deployment or a production release on the evidence available.

The Python firewall tests model command/kernel state; loopback tests exercise HTTP,
not WireGuard. Neither proves independent kernel cutoff or real GUI/SSH connectivity.
Both deadline mechanisms use wall time; a suspended broker plus backwards clock
step remains a limitation. Real shutdown timing under load, helper descendant
cleanup, cgroup/session termination, PHP ownership directory durability, upgrade,
uninstall, reboot and live reload recovery still require disposable-host evidence.
Privileged simultaneous removal/bypass of both filtering guards has no guaranteed
zero-exposure window. Network lease expiry does not itself kill running SSH commands.
Windows native validation and the reported embedded SSH console crash remain open.

Documentation updated: root/module/Windows guides, changelog, architecture,
security, diagnostics, pairing, testing, upgrade instructions, website version and
evidence references. Historical changelog records and Windows versions are retained.
The new packaged development notes contain the precise, unexecuted disposable-PBX
acceptance procedure, including IPv6, changing public IPs, delayed generation,
lease/gate-loss packet tests, slow clients, revocation and unrelated services.

## Verification results

All executed final checks passed. Earlier fixture/version/documentation failures
were corrected and rerun; no final environmental failure remains. PHP 8.4.27 was
already available through a temporary wrapper outside the repository; its PATH and
PHPRC were supplied to child processes. Nothing was installed. Python is 3.13.5;
Node is 20.19.2. The PHP bridge uses temporary keys and local loopback endpoints.

| Check | Exact result |
|---|---|
| Safe broker/gateway regression selection | 262 run, 262 passed, no skips, 50.410 seconds |
| Final firewall/security selection after conservative failed-inventory refusal | 57 run, 57 passed, no skips, 10.064 seconds; includes one new test, so 263 distinct Python cases across these selections |
| PHP checker bridge | 1 run, 1 passed, 0.760 seconds |
| PHP module regression runner | PASS: 14 top-level PHP scripts, 20 page scenarios, 3 JavaScript scripts; includes README/GUI upgrade equality and IPv6/earlier-rule regressions |
| Documentation links after package creation | 5 run, 5 passed, no skips |
| Website Node tests | 5 run, 5 passed, no skips |
| Package validator | 10 run: 4 passed, 6 skipped because historical archives are absent; no failures |
| Python syntax | 12 changed/relevant files parsed successfully |
| PHP syntax | All 37 module PHP files passed lint |
| Git whitespace | `git diff --check` passed |
| Deterministic package rebuild and checksum | Byte-for-byte identical rebuild; SHA-256 sidecar verified |

The 262-test selection was followed by the final 57-test targeted run because
review found that a failed non-filter-table inventory must return unknown instead
of treating missing output as an empty policy. The broader selection is not
represented as having included that last additional test. No privileged namespace
class was included. Modelled failures intentionally emit containment/backoff
messages; these are expected regression output, not live host operations.

Reproduce the safe Python selection from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B - <<'PYTEST'
import sys, unittest
sys.path.insert(0, 'gateway/tests')
names = [
    'test_support_broker.SupportBrokerTests',
    'test_support_broker.WorkstationPairingTests',
    'test_concurrency.ListenerConcurrencyTests',
    'test_listener_scheduling.ListenerSchedulingTests',
    'test_firewall_integration.IntegrationTests',
    'test_workstation_enforcement.EnforcementTests',
    'test_workstation_revocation.RevocationTests',
    'test_workstation_roaming.RoamingTests',
    'test_ssh_authority.AuthorityTests',
    'test_gateway.AddressPolicyTests',
    'test_gateway.DurableStateTests',
    'test_engineer_tools.EngineerConfigTests',
    'test_engineer_tools.CheckerEvidenceTests',
    'test_security_generation.SecurityGenerationTests',
]
result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromNames(names))
sys.exit(not result.wasSuccessful())
PYTEST
```

The same command on final source now selects 263 tests. The final targeted command
used only `test_firewall_integration.IntegrationTests` and
`test_security_generation.SecurityGenerationTests`. Other executed commands:

```bash
PATH=/tmp/teliphones-test-tools/bin:$PATH php teliphones/tests/run.php
PATH=/tmp/teliphones-test-tools/bin:$PATH PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s gateway/tests -p test_php_checker_bridge.py
PYTHONDONTWRITEBYTECODE=1 python3 -B teliphones/tests/documentation-links.py
node --test website/tests/*.test.js
PYTHONDONTWRITEBYTECODE=1 python3 -B teliphones/tests/package-validation.py
git diff --check
```

Logs for this local session are outside the repository under
`/tmp/teliphones-080-{python-final,affected-final,php-final,bridge,website,package-final}.log`.
They are ephemeral; counts above are the preservation record. Safe tests use
production functions and simulated command output, plus loopback HTTP and a real
unprivileged helper/descendant cancellation test. They do not substitute for the
unexecuted disposable-PBX procedure.

## Package

The deterministic packaging command was:

```bash
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' --exclude='*/.*' --exclude='*/tests' \
  --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
  -czf TELIPHONES-0.8.0.tgz teliphones
sha256sum TELIPHONES-0.8.0.tgz > TELIPHONES-0.8.0.tgz.sha256
```

Archive/source equality, metadata, protocol, installed resources, archive path/type
safety, non-writable group/other modes, development/sensitive exclusions and checksum
passed the validator. A second build in `/tmp` compared byte-for-byte equal.
Only after successful replacement validation were the 0.7.0 archive and checksum
removed. Historical source/changelog records remain in Git history.


- Archive: [TELIPHONES-0.8.0.tgz](../TELIPHONES-0.8.0.tgz), **232,792 bytes**, 38 regular files.
- Checksum: [SHA-256 sidecar](../TELIPHONES-0.8.0.tgz.sha256).
- SHA-256: `36d5fccfa02ed357f6c401dfb58973c655087f1af4752151337d20072fc33635`.

## Preservation assessment and complete working-tree status

Suitable for a **local development preservation commit after review**, explicitly
labelled unaccepted and with the limitations above. No commit was made. It is not
ready for deployment or production release. No Windows binary was built. Existing
valid pairing compatibility is model-tested, not demonstrated by a live upgrade.
The complete final `git status --short` is:

```
 M README.md
 D TELIPHONES-0.7.0.tgz
 D TELIPHONES-0.7.0.tgz.sha256
 M desktop/windows/CHANGELOG.md
 M desktop/windows/README.md
 M desktop/windows/tests/WINDOWS-READINESS.md
 M docs/ARCHITECTURE.md
 M docs/FREEPBX-FIREWALL-DIAGNOSTICS.md
 M docs/SECURITY.md
 M docs/SSH-KEY-MANAGEMENT-PROPOSAL.md
 M gateway/tests/test_concurrency.py
 M gateway/tests/test_firewall_integration.py
 M gateway/tests/test_listener_scheduling.py
 M gateway/tests/test_support_broker.py
 M gateway/tests/test_workstation_revocation.py
 M gateway/tests/test_workstation_roaming.py
 M teliphones/BrokerBootstrap.php
 M teliphones/FirewallListener.php
 M teliphones/README.md
 M teliphones/WebSupport.php
 M teliphones/docs/CHANGELOG.md
 M teliphones/docs/CONNECTIVITY-REGRESSION.md
 M teliphones/docs/TESTING.md
 M teliphones/docs/WORKSTATION-PAIRING.md
 M teliphones/module.xml
 M teliphones/support_broker.py
 M teliphones/tests/admin-layout.php
 M teliphones/tests/broker-upgrade.php
 M teliphones/tests/firewall-listener-generation.php
 M teliphones/tests/firewall-listener.php
 M teliphones/tests/live-status.php
 M teliphones/tests/module-menu.php
 M teliphones/tests/package-validation.py
 M teliphones/tests/web-page.php
 M teliphones/tests/web-support.php
 M teliphones/tests/workstation-pairing.php
 M website/about/index.html
 M website/docs/getting-started/index.html
 M website/docs/index.html
 M website/docs/troubleshooting/index.html
 M website/downloads/index.html
 M website/faq/index.html
 M website/freepbx/index.html
 M website/index.html
 M website/roadmap/index.html
 M website/security/index.html
 M website/tests/site-content.test.js
 M website/windows/index.html
?? TELIPHONES-0.8.0.tgz
?? TELIPHONES-0.8.0.tgz.sha256
?? docs/DEVELOPMENT-0.8.0-REPORT.md
?? gateway/tests/test_security_generation.py
?? teliphones/docs/DEVELOPMENT-0.8.0.md
```
