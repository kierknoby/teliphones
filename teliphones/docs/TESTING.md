# TELIPHONES testing

## Windows 0.8.3 source review and package boundary

Windows 0.8.3 is independently versioned; module 0.6.5 and root broker 0.6.5
retain protocol 12. The local 0.6.5 archive and checksum match current source;
the obsolete root-level 0.6.4 pair was removed. Historical archives **do not
match current module source** and must not be rebuilt or described as containing
the new revocation security corrections. No publication or deployment is claimed.
Source version checks run without an archive; exact package validation requires
a separately prepared reviewed archive and checksum.

Run source version consistency independently from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/package-validation.py SourceVersionTests
```

The complete package validator still requires the current archive and checksum
and fails when they are missing; it is not replaced by this source-only check.

Offline documentation and site validation, from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/documentation-links.py
node --test website/tests/*.test.js
```

The site is static HTML/CSS/JavaScript; no generator/build installation is
needed. Local links, assets, fragments and source version references are checked
without accessing external URLs. For native Windows version resources, MFC
pairing behaviour, startup smoke and portable Release checks, use the
`desktop/windows/tests/WINDOWS-READINESS.md` reference in the source repository.
Linux checks do not substitute for Windows execution.

## 0.6.5 revocation security, reliability and version validation

Run the PHP/Node and gateway suites below, then run
`PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/package-validation.py`
after building `TELIPHONES-0.6.5.tgz` using the root README procedure.
The package validator checks exact module-source equality, module 0.6.5,
root broker 0.6.5, compatibility declarations, protocol 12, Windows exclusion
and preservation of available historical archives. PHP tests verify the
metadata-derived `TELIPHONES 0.6.5` heading and reject brokers through 0.6.4 even when
it reports protocol 12.

During the earlier 0.6.3 preparation the isolated real-nft namespace lab passed 10/10
working-tree runs and 10/10 runs using the unchanged `2c67adc` broker source
loaded in memory. Each run used a fresh network namespace; the host firewall
was untouched. The previous investigation had one own-event-filtering assertion
failure followed by successful isolated reruns. There was no recurrence in this
sample, including the baseline, but the intermittent condition is not diagnosed
or excluded by these results. Do not remove or weaken its assertion.

## 0.6.2 nftables acknowledgement and recovery

The broker tests include regressions for canonical UDP rule serialisation,
unacknowledged monitor events, kernel-state readback before pending-event
release, fail-closed behaviour when readback is unavailable, verified cleanup,
recovery and a subsequent pairing attempt. PHP tests verify that an old
protocol-12 broker is reported as outdated and that pairing readiness errors
are not misreported as missing networking tools.

Run the suites from the repository root:

```bash
XDEBUG_MODE=off php teliphones/tests/run.php
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s gateway/tests
sudo -n env PYTHONDONTWRITEBYTECODE=1 unshare -n \
  python3 gateway/tests/workstation_namespace_lab.py "$(readlink /proc/self/ns/net)"
```

The real-nft namespace lab passed with nftables 1.0.9 in this development
environment. It does not change the host firewall. Debian 12's nftables 1.0.6
and a live FreePBX 17 system were not available, so neither is certified by
these results. Keep that live-PBX check as a release gate.

## Workstation enforcement regression coverage

`teliphones/tests/pairing-form.test.js` renders the actual PHP page, executes its
inline pairing script with modelled DOM controls, serializes successful named
controls, and submits them through the page POST handler. It covers the web-only
disabled-SSH-select regression, exactly one explicit SSH access value, managed
SSH selection, no-JavaScript web-only submission, field-specific missing/type
errors, CSRF, escaping and retention of bounded non-sensitive values. Pairing
requests and SSH approval are not redisplayed after failure.
The corresponding gateway socket regression submits the generated POST through
the same PHP page and actual broker socket, verifies completed web-only pairing
against modelled firewall/WireGuard state, and checks that malformed requests,
ports and endpoints cannot mutate existing pairings. This is not a browser
engine or live FreePBX test. The form correction changes module PHP/templates,
not the broker; the preserved 0.6.3 archive remains unchanged and does not
contain those subsequent source edits. The form changes were included in 0.6.4
and remain in current 0.6.5 source.

The listener PHP regressions replay the observed UDP 51821/zone rule shape
through the production predicate and test admission, removal, missing/differing
rules, forbidden zones, ownership retention and sanitised timeout diagnostics.
Concurrent broker tests use events and real threads to demonstrate that the
background worker cannot acquire `wslock` during pairing cleanup. They verify
Open/zero-peer rollback, subsequent reconciliation, no unauthorised peers,
recovery and separate initiating/cleanup/restoration errors through the actual
PHP socket path. FreePBX API and network operations remain modelled here;
FreePBX's asynchronous generator is not exercised.
Use the [live acceptance checklist](../README.md#064-development-server-acceptance)
before asserting that pairing or connectivity is fixed.

`gateway/tests/test_listener_scheduling.py` models FreePBX journal/kernel
generation while executing the real broker and nft monitor event handling.
The initial reproduction produced 241 listener commands over 240 idle ticks
(one simulated hour). The corrected source expects just the initial command:
zero further listener commands for stable periodic checks or repeated filter
notifications. A simulated successful FreePBX command emits a filter event;
the worker must reach quiescence rather than spawn another command. Tests also
cover acknowledged own events, late owned events with full fail-closed
reverification, stale/mismatched ownership, wrong rules/zones, dedicated port
58490 admission failure and restoration to shared port 51821, and failures under
notification storms. A mocked monotonic clock verifies retry delays of
5/10/20/40/60 seconds, capped at 60, recovery and immediate explicit policy
changes. No sleeps substitute for assertions, and no live FreePBX generator
or single-vCPU CPU measurement is represented by these modelled counts.

`gateway/tests/test_broker_socket.py` runs the real PHP client against real
Unix sockets and the production broker request handler, with modelled network
commands. It reproduces the old five-second read timeout during a six-second
listener verification, verifies final success and failure after progress frames,
and checks that new workstation admission waits for verification. It also covers
peer authorisation, legacy single-response clients, invalid progress options,
fragmented/malformed/oversized replies, inactivity, older-helper rejection,
sanitised exception/serialisation errors, and transaction completion without
re-dispatch after a client disconnect. PHP is required for this integration
class; a missing interpreter produces an explicit skip.

These tests do not execute real FreePBX listener convergence, web-server/proxy
request deadlines, installed broker upgrades or live workstation pairing.
Those remain live-PBX validation requirements. The local 0.6.5 archive is
validated against current source; historical archives predate these corrections.

From the repository root, run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s gateway/tests -v` and `php teliphones/tests/run.php`. The new enforcement cases exercise complete JSON-policy tampering, ownership conflicts, verified disable/delete failures, recovery-file retention, both pairing lifetimes, transient external flush/restore events, monitor startup/death and own-event filtering. PHP covers trusted-helper ancestry, refusal of legacy/web-owned helpers, verified service stopping and abort-on-failure ordering. The existing portable C++ contract tests reuse the updated Python fake network; Windows sources are unchanged.

When `unshare`, `ip`, `nft` and user/network namespaces are usable, Python automatically runs `gateway/tests/workstation_namespace_lab.py` inside a fresh isolated namespace. It checks actual kernel JSON equivalence, real monitor framing/registration, external flush detection, interface disable/delete, foreign-table preservation and stale-handle deletion refusal. All network mutations stay in that child namespace. It does not touch the host firewall or require packages. The current workspace passed this nft/dummy-interface lab; `wg` is absent, so real WireGuard admission/traffic tests are explicitly skipped. This is not an installed FreePBX/Windows or FreePBX Firewall reload test. No local FreePBX hooks were available to inspect. Monitor recovery does not prove zero packet exposure during external flushes; the [documented race and latency limitations](WORKSTATION-PAIRING.md#enforcement-integrity-and-exposure-limits) apply.

`gateway/tests/test_firewall_integration.py` covers the FreePBX Firewall integration chain. It runs simulated broker tests against a fake iptables layout that covers ordering, exact rules, SSH scope, reconnection, reload repair, revocation, expiry, shutdown, uninstall, failure handling and refusal of unfamiliar chains. It also runs `gateway/tests/firewall_integration_lab.py` in a fresh user/network namespace for both the iptables `nf_tables` and `legacy` backends (legacy uses a private `XTABLES_LOCKFILE`). The lab sends real TCP packets over a veth `tlp-admin` through a **simulated** FreePBX layout: a `fpbxfirewall` hook, `zone-external` and final DROP, plus INPUT hooks for the eight `fail2ban-*` chains observed on the FreePBX 17 test PBX. Regression coverage now includes hookless nftables ownership, exact 0.3.0 policy migration with the interface down, refusal of altered policies, broker restart, revocation and recovery. The simulated tests also cover upstream `f2b-*` and mixed-case names, Fail2Ban hooks moved after `fpbxfirewall` or between the jump and the hook by reloads, Fail2Ban restarts, and a hook inserted concurrently with integration. It checks that only TCP 80/443 (and 22 when approved) are admitted. SIP, AMI, MySQL and IPv6 remain blocked. It also checks that Fail2Ban bans remain effective, reload repair, revocation and teardown preservation. This is not a real FreePBX Firewall or WireGuard test. The operator separately reports that the nftables ownership correction was tested on the real FreePBX 17 test PBX; the packaged repository build still requires a reviewed upgrade/bootstrap and retest.

### 0.4.1 firewall correction

The jump now lives inside `fpbxfirewall`, not above its INPUT hook. Focused command:
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s gateway/tests -p test_firewall_integration.py -v`.
Coverage includes a model of the journal's above-hook watchdog condition, repeated
stable reconciliations with no writes, duplicate legacy INPUT migration, concurrent
and complete rebuilds, broker restarts without extending temporary deadlines,
reconnection, expiry/revocation, shutdown/uninstall and cleanup failures.
The packet lab verifies that existing rules and policies survive, both backend
implementations enforce exact peer/interface/destination/service scope, and earlier
Fail2Ban or independent nft drops still win. Managed SSH/API ports are scoped to
their peer and system SSH is not granted to managed pairings. A separate LAN veth
tests permitted SIP UDP 5060, RTP UDP 10000 and management TCP 22/443, plus
unchanged denied management ports, before integration, after rebuilds and after
teardown. Workstation SIP/RTP stays denied.

The tests do not run FreePBX's actual watchdog. With Custom Rules **disabled** and
FreePBX Firewall/Fail2Ban **enabled**, real-PBX validation must observe multiple
41-second watchdog intervals (at least five minutes), deliberate approved firewall
reload/restart cycles, Windows 0.7.0 connect/disconnect/reconnect, certificate SSH
and revocation, PBX/broker restarts and uninstall. Compare INPUT and unrelated
rules/counters and exercise a real SIP call with RTP and unrelated management
sessions throughout. Check for absence of TELIPHONES-related invading-rule/reset
messages, not just an `active` integration status. The root-owned installed broker
must match reviewed source. The review package `TELIPHONES-0.4.1.tgz` contains
this correction. `TELIPHONES-0.4.0.tgz` remains unchanged and contains the old
intrusive INPUT placement. Rerun the documented root bootstrap after upgrading:
module installation alone does not prove that the separately installed broker
was updated. Windows remains 0.7.0.

Local validation of this correction **at packaging, before the later
documentation-only overhaul**:

- Gateway/broker suite: 148 tests run, 147 passed, one skipped because `wg` is
  unavailable. Both real-packet iptables backend labs and isolated OpenSSH
  certificate/session tests passed. The SSH lab substitutes process supervision
  for systemd/cgroups and does not validate the Windows memory agent.
- Module PHP/JavaScript suite and documentation link tests passed.
- Portable Windows CMake build and all seven CTest cases passed.
- `git diff --check` passed.
- Package/source equality, corrected archived firewall behaviour, authoritative
  module/broker/web version consistency and preservation of the older 0.4.0
  archive are checked by `teliphones/tests/package-validation.py`.
  The 0.4.1 SHA-256 sidecar identifies the exact package contents.
  No release is published and nothing is deployed.

The `TELIPHONES-0.4.1.tgz` Module Admin package includes the corrected code.
Run `PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/package-validation.py -v`
from the repository root. Tests, Windows sources, caches and runtime state are
excluded. **The archive is preserved unchanged during the documentation review.**
Source documentation now differs, including the newly separated changelog, so
the full archive/source file-set/byte-equality test is expected to fail.
Version/checksum, corrected archived firewall behaviour and old-package identity
checks remain independently useful. Do not ignore a non-documentation difference.
Before any later distribution, explicitly approve packaging and rerun the full
validator; do not describe the preserved archive as containing this new guide.

### Documentation review validation

After reorganising the guides, local rechecks passed:

- module PHP/JavaScript suite, including exact README/GUI root-bootstrap and
  upgrade-note consistency;
- all five documentation-link tests, including module-only source boundaries
  and extraction of the preserved archive;
- all 36 Windows source/layout tests and all seven portable CTest cases;
- broker suite: 148 run, 147 passed, one skipped (`wg` unavailable);
- local Markdown fence/table/heading checks and `git diff --check`.

Package validation is **3/4 passing**: versions/checksum, corrected archived
firewall behaviour and unchanged older-package identity pass; full current
source equality fails as expected for documentation. An independent comparison
of every packaged/source file confirms **only** the module README, testing
guide, pairing contract and new changelog differ. All packaged non-documentation
source remains byte-identical.

Both archive hashes and product versions are unchanged in this documentation
phase: FreePBX 0.4.1, Windows 0.7.0. No native Windows test or GitHub-rendered
visual review was performed locally; reported native results remain attributed
as below. No new release, deployment or archive rebuild is implied.

### Native and live evidence

The operator now reports successful Windows Actions builds, all **ten** native
OpenSSH integration tests passing, authenticated Windows 0.7.0 SSH into a
FreePBX 17 / Debian 12 test PBX with module 0.4.0, and automatic owned-terminal
closure on disconnect. Run URLs, commit/build hashes and raw logs were not
supplied and were not retrieved. This is a meaningful initial interoperability
milestone, not evidence of full server-side revocation, authorisation expiry,
empty cgroups, real 0.4.1 watchdog stability or production readiness.
The source repository's `docs/SECURITY.md`, section **Verification evidence**,
is the central evidence register; the manual gates above still apply.

### Genuine screenshots to capture

No product screenshots are currently supplied; none should be fabricated from
source, tests or a planned interface. Capture only real disposable-system UI,
with versions and build provenance recorded separately:

1. **Windows main window:** one approved connected My PBXs profile, reachable
   Connection Health, distinct connection/authorisation durations and enabled
   FreePBX/SSH actions. Capture a temporary pairing and **Until revoked** example.
2. **Windows settings:** Applications/Connectivity and Appearance in System,
   Light and Dark. Include one high-contrast and narrow/high-DPI example only
   after real visual inspection; injected test DPI is not a screenshot.
3. **Authenticated SSH:** the actual current built-in managed console and
   observed owned-session closure on disconnect. Earlier external-terminal
   screenshots are historical, not evidence of the current integrated console.
4. **FreePBX workstation approval:** SSH opt-in with a deliberately selected
   test account, permission/lifetime controls, integration status and diagnostics.
5. **FreePBX readiness/upgrade:** module 0.6.5 and separately refreshed broker
   0.6.5/protocol 12, including the form and listener diagnostic corrections;
   an older capture does not establish those corrections.

Use synthetic names and harmless commands. Redact keys, pairing strings,
certificates, grants, credentials, customer names, usernames, hostnames,
endpoints, operational addresses and unrelated sessions. Do not capture clipboard
contents or privileged prompts. A screenshot demonstrates UI state, not firewall
enforcement, authentication guarantees or successful server-side cleanup.

0.4.1 is an operational correction to the installed/tested 0.4.0 build, prepared
for review and testing on a **disposable FreePBX 17 / Debian 12 PBX**. It is not a
production-readiness claim. The workstation diagnostics regression cases exercise server-side session filtering, admin/CSRF checks, secret-free allowlisted events, rotation, retention, concurrent writers and lifecycle correlation. They are local simulations; no live PBX was contacted.

For workstation pairing, start with [install, pair and connect](../README.md#windows-workstations-install-pair-and-connect); for remote support use the [browser workflow](../README.md#remote-support-browser-workflow). The CLI steps below remain platform recovery and direct integration tests, not required browser operations. Local regression tests use framework stubs and mocked privileged broker calls; they do not prove real systemd, apt, SSH or FreePBX administrator permissions.

The first objective is to prove TELIPHONES independently of any hosted integration. Test the local module with a disposable WireGuard peer, manual Checker evidence and a throw-away Console SSH key. Only after that passes should Connect, Checker and Console implementations be integrated.

## Invariant

> **Connect creates. Checker observes. Console consumes. TELIPHONES decides.**

At no point may an external component authorise support, extend the local grant, override expiry, revive a revoked session or make TELIPHONES READY by itself.

## 1. Clean-machine baseline

Before installing or authorising TELIPHONES, record:

```bash
ip -4 addr
ip -4 route
ss -lntup
systemctl list-units --type=service --all
find /var/lib/teliphones /etc/teliphones* -maxdepth 3 -ls 2>/dev/null
```

Keep this output. After revoke, expiry and uninstall, compare the PBX with the baseline. TELIPHONES must not leave a support listener, `wg-teliphones`, ephemeral keys or session credentials behind.

## 2. Installation and preflight

Install the module through the normal FreePBX module workflow, then run:

```bash
fwconsole teliphones check
fwconsole teliphones status
```

Confirm the module is enabled but support is off. A read-only page/status request must not create authority. Explicit full-administrator, CSRF-protected approval is required for privileged broker actions.

### Windows pairing validation

Run the documented Windows pairing steps with a genuinely reachable UDP endpoint. Test temporary web-only and explicitly persistent web-plus-SSH approval. Compare fingerprints; verify only the PBX `/32` is routed and ordinary credentials remain necessary. Check the last-handshake table, **Disconnect**, individual **Revoke**, persistent removal and automatic expiry. A revoked saved profile must not regain access without fresh approval. Confirm a protocol-2 or malformed protocol-3 broker displays **Root broker update required** and refuses pairing server-side while the existing remote support workflow remains available.

Portable CTest executes the actual Python broker approval/revocation with only OS network calls doubled, and feeds its generated responses into the actual C++ parser, profile serialisation/reload and tunnel renderer. It covers temporary/persistent expiry, SSH scope, request key/nonce binding and reference-gateway support configuration; this is not a real tunnel or Windows Credential Manager/systemd test.

Run a management command as a non-root user. It must be refused.

## 3. Local authority

```bash
fwconsole teliphones authorise --minutes=5 --topology=on-pbx
fwconsole teliphones status
fwconsole teliphones connect-request
```

Expected:

- a new random session ID;
- an absolute expiry approximately five minutes ahead;
- a fresh PBX WireGuard public key;
- support **not READY**;
- no temporary sshd listening;
- only session-scoped TELIPHONES state created.

Try durations below 5 and above 240 minutes. Both must be rejected.

## 4. On-PBX Connect path

Use a disposable WireGuard peer. The default test allocation is PBX `10.20.17.1/30`, peer `10.20.17.2/32`. The `/24` preferred pool must never be installed wholesale.

Supply only the peer's public key and endpoint:

```bash
fwconsole teliphones peer --peer-key='...' --peer-endpoint='host:port'
```

Verify:

```bash
ip -4 addr show dev wg-teliphones
ip -4 route show dev wg-teliphones
wg show wg-teliphones
```

Expected: AllowedIPs is exactly the session peer `/32`; no default route, DNS, forwarding, NAT or unrelated interface is changed.

Repeat with a proposed private subnet that overlaps an existing route. Authorisation must refuse the proposal rather than modify the customer's routing.

## 5. PBX-local verification

```bash
fwconsole teliphones attest
fwconsole teliphones status
```

TELIPHONES checks only PBX-local invariants. It must not perform external reachability probing. On success, support remains closed pending Checker evidence.

Break the local peer/address/route deliberately and repeat. Mandatory verification failure must quarantine the attempt, tear down locally owned support state and require a fresh root authorisation.

## 6. Checker gate

Create a fresh challenge:

```bash
fwconsole teliphones checker-request > /root/teliphones-checker-request.json
```

The checked-in JSON files are unsigned fixtures and are not accepted by TELIPHONES. Use the independent Checker private key to create evidence for the current challenge, then sign the canonical evidence as specified in `CHECKER-CONTRACT.md`. Install only its matching public key at `/etc/teliphones/checker-ecdsa-p256.pub` using a trusted local process. Do not copy the Checker private key to the PBX.

The accepted evidence must demonstrate:

- the support service is reachable from the authorised source;
- the same service is blocked from the negative-control source;
- the support service is blocked at the public address;
- no unexpected service was observed.

Import it:

```bash
fwconsole teliphones checker-accept --evidence-file=/root/checker-evidence.json
```

Then test rejection for wrong session, wrong topology, wrong nonce, stale challenge, failed authorised source, failed negative control, public exposure and unexpected services. Reusing consumed or stale evidence must not create a new READY session.

Run the local isolated regression checks from the module directory with:

```bash
php tests/run.php
```

These tests exercise local JSON/signature policy and route calculations only. They are not FreePBX installation, WireGuard, systemd, firewall or gateway integration tests.

## Reference gateway

The separate Linux reference gateway and its operator configuration are documented in `../../gateway/README.md`. Run its policy and state tests without network privileges:

```bash
cd /path/to/teliphones/gateway
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The real network-namespace harness requires a disposable Linux host with `ip`, `wg`, `nft`, Python and root. It also requires explicit `TELIPHONES_LAB_CONFIRM=disposable-host`:

```bash
sudo env TELIPHONES_LAB_CONFIRM=disposable-host \
	PYTHONDONTWRITEBYTECODE=1 python3 tests/wireguard_namespace_lab.py
```

Do not run the harness on a production host. It checks engineer/PBX reachability and isolation, active flow revocation, firewall-element expiry and route preservation. It does not test the FreePBX Firewall, GUI/SSH on an installed PBX or gateway-process crash recovery. In the current development container `wg` is unavailable, so real WireGuard tests were not run.

## 7. Console gate

Before accepted Checker evidence, this must fail:

```bash
fwconsole teliphones open --ssh-key='ssh-ed25519 AAAA... teliphones-test'
```

After local verification and accepted Checker evidence, generate a throw-away Ed25519 Console key and run the same command with its public key.

Verify the dedicated sshd:

- listens only on the private On-PBX session address and port 22222;
- permits the session public key only;
- rejects password and keyboard-interactive authentication;
- rejects TCP forwarding, agent forwarding, X11, tunnels and gateway ports;
- has not modified the system sshd configuration.

`fwconsole teliphones console-handoff` must be unavailable before READY and available afterwards.

## 8. Revocation, disable and expiry

During a live test run each case independently:

```bash
fwconsole teliphones revoke
fwconsole teliphones disable
```

Also allow a five-minute session to expire naturally.

For every case, local authority must disappear first even if an external Connect destroy request fails. TELIPHONES must attempt all local cleanup stages rather than abandoning cleanup after one failure.

Confirm the dedicated sshd is gone, `wg-teliphones` is gone, Checker material is invalidated and ephemeral key/session files are removed.

`disable` must survive reboot and refuse new authorisations until root runs `fwconsole teliphones enable`.

## 9. Reboot and interrupted-state tests

Reboot during an active but not-yet-READY grant. The original absolute expiry must not move.

Reboot after Console access has opened. TELIPHONES may reconstruct a still-valid On-PBX network path, but privileged SSH must **not** silently reopen. Fresh verification is required.

Kill or interrupt the process during authorise, peer setup, Checker handling, open and revoke. Reconciliation must fail closed. If TELIPHONES cannot guarantee the original expiry or local state, it must remove support authority rather than invent a replacement grant.

## 10. Uninstall

Uninstall while no session exists, then repeat while a disposable session is active.

Confirm the temporary sshd is stopped before its PID/config/key files are removed, `wg-teliphones` is absent, the reconcile service is disabled/removed and no ephemeral support credential remains.

Configuration/enrolment retention should be reviewed deliberately before production packaging; no retained file may itself grant support access.

## 11. External integrations

Only after the manual path passes should the three real integrations be introduced, one at a time:

1. **Connect** — create the requested private path and return only contract-defined session material.
2. **Checker** — independently observe the path and return fresh session-bound evidence.
3. **Console** — consume the final temporary handoff after TELIPHONES reaches READY.

A failure in one integration must never weaken the other gates.

## Stop conditions

Stop testing immediately if TELIPHONES creates public root access, changes the PBX default route/DNS/unrelated networking, extends an expiry after reboot, accepts mismatched/replayed Checker evidence, reopens SSH automatically after reboot, or leaves privileged access behind after revoke/disable/expiry/uninstall.

## Baseline evidence command

Before the first authorisation, capture:

```bash
fwconsole teliphones baseline > /root/teliphones-before.json
```

After revoke (and again after uninstall where practical), capture the same command to a different file and compare the `system` sections. Timestamp and TELIPHONES session metadata naturally change. Unexpected persistent interfaces, routes, rules or listeners are a stop condition. The baseline command is observational only and deliberately excludes secrets and configuration-file contents.
