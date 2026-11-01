# TELIPHONES 0.1.2 testing

0.1.2 is a development milestone for testing on a **disposable FreePBX 17 / Debian 12 PBX**. Do not begin on a production PBX.

For the administrator-operated browser workflow, start with the [module README](../README.md#browser-support-workflow-012). The CLI steps below remain platform recovery and direct integration tests, not required browser operations. Local regression tests use framework stubs and mocked privileged broker calls; they do not prove real systemd, apt, SSH or FreePBX administrator permissions.

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

Confirm the module is enabled but support is off. Confirm the GUI is observational: it must not be able to create privileged authority.

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
