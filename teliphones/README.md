# TELIPHONES 0.0.1 for FreePBX 17

TELIPHONES (`teliphones`) provides temporary, root-authorised support access for FreePBX 17. It manages the local lifecycle of a support session, including authorisation, absolute expiry, temporary network and SSH state, verification and revocation.

The module separates external support functions into three integration contracts: **Connect** creates the temporary communications path, **Checker** independently observes that path, and **Console** consumes approved access. TELIPHONES remains the local authority for the session.

## ⚠️ Not Currently Suitable for Production

TELIPHONES 0.0.1 is an initial testing release.

It has not yet completed live installation, end-to-end integration, failure-recovery or adversarial security testing on FreePBX 17.

**Do not install TELIPHONES 0.0.1 on a production PBX.**

Testing should be performed only on a disposable FreePBX 17 system where unexpected network, SSH or service behaviour can be investigated without affecting live communications.

The security controls documented below describe the behaviour TELIPHONES is designed to enforce. They should not be treated as validated security guarantees until the corresponding live tests have been completed.

## Release Status

TELIPHONES 0.0.1 is the current testing release for FreePBX 17.

The complete executable local implementation currently targets the **On-PBX** topology. On-net and Off-net are defined integration topologies and require external Connect implementations.

0.0.1 is intended for development, review and controlled testing rather than production deployment.

## Compatibility

Primary target: FreePBX 17 on Debian 12. Installation and end-to-end compatibility have not yet been validated on that platform. No compatibility claim is made for FreePBX 16 or PBXact.

FreePBX 16 is not currently supported.

## Requirements

For local 0.0.1 testing:

- FreePBX 17 on Debian 12
- root access for installation and support authorisation
- systemd transient-unit support
- WireGuard userspace tools and kernel support for On-PBX testing
- OpenSSH server components for temporary On-PBX SSH testing
- PHP OpenSSL support and an independently provisioned Checker ECDSA P-256 public key for signed Checker evidence

A complete end-to-end support workflow additionally requires implementations of the three published TELIPHONES integration contracts:

- **Connect**
- **Checker**
- **Console**

These are integration interfaces, not dependencies on FreePBX UK services. Initial authority, status, baseline, expiry and revoke testing can be performed before live external integrations are connected.

## Support Topologies

TELIPHONES defines three topology names.

### On-PBX

The private support connection terminates directly on the FreePBX server.

This is the locally implemented topology in 0.0.1. TELIPHONES creates an ephemeral WireGuard interface named `wg-teliphones`.

For FreePBX 17, the preferred private allocation pool is `10.20.17.0/24`. This is an allocation pool, not a route. Each session uses only the address space required for that connection.

Before accepting proposed addressing, TELIPHONES checks it against existing IPv4 addresses and routes. A collision causes the proposal to be rejected. TELIPHONES does not change the default route, DNS, forwarding, NAT or unrelated network configuration to make a proposed allocation fit.

### On-net

The private connection terminates elsewhere on the customer's local network.

The external Connect implementation is responsible for providing this path. TELIPHONES does not configure the customer's LAN to create it.

### Off-net

The private connection terminates outside the customer's network and may cross the public Internet.

The external Connect implementation is responsible for providing this path. TELIPHONES does not make the public network itself the privileged support endpoint.

## Authority and Session Lifecycle

Installing or enabling TELIPHONES does not authorise support access.

A support session requires explicit local root authorisation and has a fixed absolute expiry. External integrations cannot create, extend or replace that authority.

The intended successful sequence is:

1. Root authorises a temporary session.
2. Connect creates the required path.
3. TELIPHONES verifies PBX-local state.
4. Checker performs independent external observations.
5. TELIPHONES evaluates and accepts the Checker evidence.
6. TELIPHONES permits the temporary support service to open.
7. Console receives the approved handoff.
8. The session remains subject to its original absolute expiry.

In short:

`ROOT AUTHORISE → CONNECT → LOCAL VERIFY → CHECKER → CONSOLE → READY`

A reboot does not reset or extend the original expiry. If a grant remains valid after reboot, TELIPHONES can reconcile the still-valid session state, but the privileged temporary SSH service is not silently reopened.

Disabling TELIPHONES revokes active local access and prevents new grants until the module is enabled again.

## Connect

Connect creates the communications path for an authorised session.

TELIPHONES uses the versioned `teliphones-connect/1` contract. Connect returns a proposal or session material; it does not return an authorisation. TELIPHONES validates the returned information before using it.

For On-PBX, the PBX WireGuard private key is generated locally and does not leave the PBX.

Connect cannot create root authority, extend the grant, override local verification, provide Checker approval or authorise Console access.

TELIPHONES does not require a proprietary Connect service. The standalone open-source reference gateway in `gateway/` implements the On-PBX flow for disposable Linux testing; other operators can implement the published contract and provide their own network.

## Local Verification

TELIPHONES verifies state that can be established from the PBX itself.

For an On-PBX session this can include current authorisation, session identity, absolute expiry, expected WireGuard state, configured peer, local addressing, relevant routes and temporary support-service state.

Local verification does not attempt to establish whether a service is externally reachable or externally blocked. Those observations belong to Checker.

A mandatory local verification failure prevents the session from proceeding.

## Checker

Checker performs independent external observations of the path created by Connect.

TELIPHONES uses the versioned `teliphones-checker/1` contract. TELIPHONES generates a session-bound challenge containing a nonce and validity period. Checker returns observations associated with that challenge rather than a trusted `safe` verdict.

The contract supports observations including:

- expected support-service reachability from an authorised source;
- expected rejection from a negative-control source;
- public-address support-service exposure;
- unexpected service exposure.

TELIPHONES evaluates the returned evidence. Evidence is bound to the session, topology, nonce and challenge validity period. Accepted challenges cannot be reused; stale, mismatched and replayed evidence is rejected.

The repository includes an independent Checker probe tool for the reference gateway. A production deployment must provide and separately operate its own Checker signer and public-key enrollment process.

## Console

Console consumes an approved support session.

TELIPHONES uses the versioned `teliphones-console/1` handoff. A Console handoff is not available until the required local verification and Checker stages have completed.

Console does not create or extend root authority and cannot authorise itself.

The repository does not include an engineer portal. Console remains a provider-neutral handoff contract; engineers use standard WireGuard, browser and SSH clients.

## Temporary SSH Service

The On-PBX implementation uses a dedicated temporary sshd rather than repurposing the PBX's normal SSH listener.

The temporary service binds to the TELIPHONES private session address and currently uses port `22222`. Authentication uses session-specific public-key material and restricts the expected root connection to the session peer.

The temporary sshd disables:

- password authentication;
- keyboard-interactive authentication;
- TCP forwarding;
- agent forwarding;
- X11 forwarding;
- SSH tunnelling;
- gateway ports;
- user environment processing;
- PAM authentication.

Expiry, revoke and disable stop the temporary service and remove its session access material. A reboot does not automatically reopen it.

## Expiry and Revocation

A session has an absolute expiry established when root authorises it. Expiry is not recalculated from reboot time or from the time an external component connects.

When a session is revoked or expires, TELIPHONES attempts all local cleanup stages even if one stage reports a failure. Local cleanup includes stopping the temporary sshd, removing temporary SSH authorisation, destroying local `wg-teliphones` state and removing session material before depending on external cleanup.

Remote infrastructure should independently enforce the same session expiry so that remote session resources do not remain indefinitely if the PBX becomes unavailable.

## Installing

TELIPHONES is a community module and is not currently listed in the FreePBX online module repository.

Do not use:

```text
fwconsole ma installlocal teliphones
```

Use `fwconsole ma install teliphones` with the method below.

### Option 1: Install from an unpacked module directory

Place the `teliphones` directory in `/var/www/html/admin/modules/`, then:

```text
cd /var/www/html/admin/modules/teliphones
fwconsole ma install teliphones
cd
fwconsole chown
fwconsole reload
```

Check the installation:

```text
fwconsole ma list | grep -i teliphones
fwconsole teliphones check
```

For 0.0.1, perform this only on a disposable FreePBX 17 test system.

A repository installation option can be documented when a public TELIPHONES repository and supported branch structure are published.

## Updating TELIPHONES

Update TELIPHONES in place. Do not uninstall the module first for a normal source update.

After replacing or updating the module source:

```text
cd /var/www/html/admin/modules/teliphones
fwconsole ma install teliphones
cd
fwconsole chown
fwconsole reload
```

Confirm the installed version:

```text
fwconsole ma list | grep -i teliphones
```

Then rerun:

```text
fwconsole teliphones check
```

If an update appears incomplete, verify both the source `module.xml` version and the version reported by Module Admin before troubleshooting runtime behaviour.

## Command Line

TELIPHONES provides the following root-controlled CLI actions:

```text
fwconsole teliphones status
fwconsole teliphones baseline
fwconsole teliphones authorise
fwconsole teliphones connect-request
fwconsole teliphones provision
fwconsole teliphones peer
fwconsole teliphones attest
fwconsole teliphones checker-request
fwconsole teliphones checker-accept
fwconsole teliphones open
fwconsole teliphones console-handoff
fwconsole teliphones revoke
fwconsole teliphones check
fwconsole teliphones enable
fwconsole teliphones disable
fwconsole teliphones reconcile
```

Common options include `--minutes`, `--topology`, `--peer-key`, `--peer-endpoint`, `--pbx-address`, `--peer-address`, `--evidence-file` and `--ssh-key` where required by the action.

For example, authorise a 15-minute On-PBX test session with:

```text
fwconsole teliphones authorise --minutes=15 --topology=on-pbx
```

See `docs/INTEGRATION.md` and `docs/TESTING.md` before attempting the complete Connect, Checker and Console sequence.

## Baseline

`fwconsole teliphones baseline` provides a read-only, sanitised snapshot for before-and-after testing.

The current `teliphones-baseline/1` output includes capture time, hostname, sanitised TELIPHONES state, network interfaces and addresses, IPv4 main-table routes, IPv4 routing rules, listening TCP and UDP sockets, and details of `wg-teliphones` when present.

It deliberately excludes private keys, credentials, arbitrary configuration-file contents and unrelated process environments.

A typical test is:

```text
fwconsole teliphones baseline > /root/teliphones-before.json
```

Perform the TELIPHONES test, then:

```text
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

Timestamp and session metadata will naturally differ. The purpose is to identify unexpected persistent system changes.

## Security Model

TELIPHONES is designed so that no single external integration can establish privileged support access by itself.

The authority boundaries are:

- local root creates the grant;
- Connect creates the path;
- TELIPHONES verifies PBX-local state;
- Checker independently observes external behaviour;
- TELIPHONES evaluates Checker evidence;
- Console consumes access only after approval.

The current FreePBX page is status-only. A FreePBX web session cannot create a root grant, and no GUI request/approval workflow or duration selector is implemented yet. Root authorisation is available only through the local `fwconsole` command.

For On-PBX, TELIPHONES also avoids using the normal PBX SSH listener as its temporary support service. Temporary network and authentication material is scoped to the support session and removed during local cleanup.

These are design properties of 0.0.1. They require live and adversarial testing before they should be treated as validated security guarantees.

## Current Limitations

TELIPHONES 0.0.1 is an initial testing release. Current limitations include:

- live FreePBX 17 installation validation is pending;
- end-to-end integration testing is pending;
- adversarial security testing is pending;
- On-PBX is the first locally implemented topology;
- On-net and Off-net require external Connect implementations;
- a standalone reference gateway and engineer/Checker tools now exist, but real WireGuard traffic and end-to-end customer isolation have not yet been demonstrated;
- the Checker contract now requires a locally pinned ECDSA public key, but no production Checker signer is included;
- GUI authorisation, live countdown, engineer presence, PJSIP/RTP diagnostics and FreePBX Firewall integration are not implemented;
- expiry, SSH cgroup teardown and route policy have local code-level checks but still require disposable FreePBX 17/systemd/WireGuard integration tests;
- reboot and failure-recovery behaviour still require live validation;
- FreePBX menu rendering, permissions and navigation have only metadata-level checks in this workspace;
- Firewall-enabled GUI/SSH/PJSIP reachability is unknown and no firewall policy is changed;
- temporary SSH uses root with session-specific public-key authentication; a narrower support account/privilege model remains unresolved;
- the module is not suitable for production use at this stage.

## Reference Gateway

The standalone `gateway/` directory contains a provider-neutral reference Connect service, engineer/Checker config tools, policy tests and an opt-in Linux namespace lab. It is not part of the FreePBX module package and is not deployed. Read `gateway/README.md` before preparing a dedicated disposable gateway. Its sample config contains placeholders, not credentials or infrastructure endpoints. The current development host lacks `wg`, so real WireGuard traffic, GUI access and SSH access through the gateway have not been demonstrated.

## Validation

Run the local regression suite from the module directory:

```bash
php tests/run.php
```

It covers module XML/page-auth metadata, synthetic Linux route coverage, tunnel address collision policy and signed Checker policy. It does not install FreePBX, create a WireGuard interface, start systemd units, test a FreePBX Firewall, or contact a support gateway.

The first live test should deliberately avoid external integration and prove that the local authority lifecycle returns the PBX to its starting state.

Run:

```text
fwconsole teliphones check
fwconsole teliphones baseline > /root/teliphones-before.json
fwconsole teliphones status
fwconsole teliphones authorise --minutes=15 --topology=on-pbx
fwconsole teliphones status
fwconsole teliphones revoke
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

Only after the local lifecycle passes should testing proceed to Connect, Checker and Console.

The wider test programme includes expiry, reboot, collision refusal, WireGuard teardown, dedicated sshd binding and hardening, Connect failure, Checker negative control, public-exposure detection, stale or replayed evidence, Console gating, process interruption, disable during an active session, uninstall cleanup and reinstall behaviour.

Stop testing immediately if TELIPHONES exposes privileged root access publicly, changes the default route or DNS unexpectedly, modifies unrelated networking, extends an expired grant, accepts replayed Checker evidence, silently reopens privileged SSH after reboot or leaves privileged access behind after cleanup.

See `docs/TESTING.md` for the complete test programme.

## Documentation

Further documentation is provided under `docs/`:

- `INTEGRATION.md` — how the three integrations join TELIPHONES;
- `INTEGRATIONS.md` — integration overview;
- `CONNECT-CONTRACT.md` — Connect contract;
- `CHECKER-CONTRACT.md` — Checker contract;
- `CONSOLE-CONTRACT.md` — Console contract;
- `TOPOLOGIES.md` — On-PBX, On-net and Off-net definitions;
- `TESTING.md` — staged validation programme;
- `gateway/README.md` — standalone reference gateway and disposable integration testing.

The published contracts allow operators to implement Connect, Checker and Console independently, without shared managed services.

## Uninstalling

Revoke any active session before uninstalling:

```text
fwconsole teliphones revoke
```

Then uninstall the module:

```text
fwconsole ma uninstall teliphones --force
fwconsole chown
fwconsole reload
```

If the source directory remains after the module has been uninstalled and you no longer require it, remove `/var/www/html/admin/modules/teliphones` separately.

Testing should verify that uninstall leaves no `wg-teliphones` interface, temporary sshd or established SSH child, TELIPHONES session key material, active session state or TELIPHONES expiry job. If gateway cleanup fails, the module deliberately retains its local Connect cleanup record and logs the failure; remote expiry is still required.

## Support and Feedback

TELIPHONES is maintained by FreePBX UK.

For installation help, testing feedback, troubleshooting or general support, contact FreePBX UK:

https://freepbx.uk/support/

When requesting support during the 0.0.1 testing phase, include the following where relevant:

- FreePBX version;
- Debian version;
- TELIPHONES version;
- the topology being tested;
- the TELIPHONES action that failed;
- the relevant command output;
- whether Connect, Checker or Console was involved;
- a sanitised before-and-after baseline where appropriate.

Do not include private keys, credentials or other session secrets in support reports.

## Licence

GPLv3+. See LICENSE.

## AI-Assisted Contributions and Disclosure

This module has been developed with AI assistance for code generation, review, testing, and documentation. From 26 August 2026, generative AI assistance must be disclosed in every commit containing AI-assisted changes:

```text
Assisted-by: AGENT_NAME:MODEL_VERSION
```

For example: `Assisted-by: GitHub-Copilot:gpt-5.6-sol`

The human contributor remains solely responsible for the contribution. AI tools must not be listed as co-authors.

## Author

[@kierknoby](https://github.com/kierknoby), Kieran Knowles-Byrne // [FreePBX UK](https://github.com/freepbxUK)

## Release History

### 0.0.1, initial testing release, 26 September 2026

Released by `@kierknoby, Kieran Knowles-Byrne // FreePBX UK`.

Initial TELIPHONES testing release for FreePBX 17. This release establishes the local authority model, the initial On-PBX implementation and the Connect, Checker and Console integration boundaries for controlled testing.

#### Local authority

- Adds root-controlled temporary support authorisation with an absolute expiry.
- Adds persistent enable and disable state.
- Adds immediate local revoke.
- Adds reboot reconciliation without extending the original grant.
- Prevents the temporary privileged SSH service from automatically reopening after reboot.

#### On-PBX

- Adds the initial On-PBX topology.
- Creates an ephemeral `wg-teliphones` WireGuard interface.
- Generates the PBX WireGuard private key locally.
- Validates proposed addressing against existing PBX addresses and routes.
- Does not alter the default route, DNS, forwarding, NAT or unrelated network configuration to resolve an allocation conflict.
- Adds a dedicated temporary sshd using session-specific public-key authentication.

#### Integrations

- Defines the `teliphones-connect/1` Connect contract.
- Defines the `teliphones-checker/1` Checker contract.
- Defines the `teliphones-console/1` Console handoff.
- Separates PBX-local verification from external Checker observations.
- Adds session-, topology-, nonce- and time-bound Checker evidence with replay protection.

#### Testing

- Adds `fwconsole teliphones check`.
- Adds `fwconsole teliphones baseline` with the `teliphones-baseline/1` schema.
- Adds staged local, Connect, Checker and Console testing documentation.
- Adds explicit expiry, reboot, revoke, cleanup and failure-testing requirements.
