# TELIPHONES

**Private, administrator-approved access to FreePBX, from the workstation you use every day.**

TELIPHONES pairs a Windows workstation with your FreePBX server over a narrowly
restricted WireGuard tunnel. Open the FreePBX GUI in your preferred browser or,
when explicitly approved, use temporary SSH certificates for an existing Linux
account. Keep access decisions on the PBX rather than distributing permanent
administrator SSH credentials.

Independent administrators get a repeatable way to reach their own PBXs. MSPs
and support engineers have a separate, customer-authorised **Remote Support**
workflow for bounded support windows.

| Component | Current version | Start here |
|---|---|---|
| FreePBX module / root broker | **0.6.4** / **0.6.3**, protocol 12 (local experimental package) | [Install](teliphones/README.md#installing-the-module) · [Upgrade](teliphones/README.md#updating-teliphones) |
| Windows application | **0.8.3** (file version 0.8.3.0; native build pending) | [Download and requirements](desktop/windows/README.md#requirements-and-download) · [Pair a PBX](desktop/windows/README.md#pair-an-administrator-workstation) |
| Reference gateway and Checker probe | Optional laboratory infrastructure | [Integration guide](teliphones/docs/INTEGRATION.md) · [Gateway](gateway/README.md) |

FreePBX module **0.6.4**, root broker **0.6.3** and Windows **0.8.3** are
independently versioned; the broker protocol remains 12. The module/broker
update includes the web-only `ssh=0` form correction, field-specific validation
and safe-value retention. Listener diagnostics distinguish admission/removal
and preserve initiating errors through cleanup and policy restoration.
Progress is never pairing success; firewall verification
and single-dispatch behaviour remain unchanged. Upgrade the module in place and
rerun the root bootstrap so the separately installed broker is refreshed;
pairings and their identities are preserved.
Windows **0.8.3** replaces the incompatible text-UAPI activation with the
official WireGuardNT adapter API, preserving memory-only keys; native build
and live acceptance are pending. It is distinct from the failing development
version 0.8.2 and retains
its corrected pairing dialogue: select name/access, generate and copy the request, then validate and
save FreePBX's response. Name/access changes invalidate stale requests; approved
SSH accounts are response-derived. It retains 0.8.0's password protection, PBX
policy requests, listener migration and post-pair SSH elevation.
The Windows application is not included in the Module Admin package.

The local `TELIPHONES-0.6.4.tgz` includes these corrections and broker 0.6.3.
The preserved `TELIPHONES-0.6.3.tgz` and its checksum are unchanged; that archive
contains broker 0.6.2 and predates the form and listener diagnostic corrections.
The initiating live listener convergence failure remains unconfirmed. Regression
tests do not establish successful Debian 12 / FreePBX 17 pairing or connectivity.
The later operator-confirmed CPU overload came from repeated listener commands
in installed broker 0.6.2. The rebuilt pending 0.6.3 broker gates background
commands on owned kernel readback and adds bounded failure backoff. Keep the
development broker stopped until this replacement is reviewed; use the
[controlled startup/CPU and live acceptance procedure](teliphones/README.md#064-development-server-acceptance).
No Windows 0.8.3 executable has been built here or published. Native execution
and artefact creation are blocked pending a Windows runner; check exact build
provenance, not the target version alone. See the
[controlled Windows upgrade procedure](desktop/windows/README.md#upgrade-the-development-workstation-after-native-validation).

> [!WARNING]
> **Experimental; not currently suitable for production PBXs.** Gateway,
> FreePBX and portable Windows-core regressions pass locally. Native Windows
> compilation, MFC/service lifecycle and live FreePBX session, migration,
> firewall, password-protection and SSH acceptance have not been performed
> here. Historical operator reports do not validate the current source.
> See [verification evidence](docs/SECURITY.md#verification-evidence).

> [!IMPORTANT]
> **Upgrading from 0.4.0?** Version 0.4.1 corrects the TELIPHONES firewall rule
> placement that FreePBX reported as intrusive, coinciding with repeated firewall
> resets and intermittent connectivity. Upgrade the module **and repeat the
> root broker bootstrap**, even if protocol 5 is already reported.
> [Follow the upgrade procedure](teliphones/README.md#updating-teliphones).
> Do not disable FreePBX Firewall or enable Custom Rules as a workaround.

The historical 0.5.0 test package manages the public WireGuard listener through
a persistent FreePBX Custom Service and supports configured management ports.
The historical 0.6.0 source adds Open/Closed/Frozen state, atomic session leases,
authenticated policy requests and identity-preserving listener migration. The
0.6.2 nftables regression is exercised with real nftables in an isolated
namespace; Debian 12 / FreePBX 17 and a live PBX were not available for
validation. See the [investigation and validation limits](teliphones/docs/CONNECTIVITY-REGRESSION.md).

## Find your route

- **Administrators:** [FreePBX administration guide](teliphones/README.md) and
  [Windows application guide](desktop/windows/README.md).
- **MSPs and engineers:** [Remote Support workflow](teliphones/README.md#remote-support-browser-workflow)
  and [Connect, Checker and Console integration](teliphones/docs/INTEGRATION.md).
- **Developers and reviewers:** [Architecture](docs/ARCHITECTURE.md),
  [security model](docs/SECURITY.md), [testing programme](teliphones/docs/TESTING.md)
  and [Windows build/test reference](desktop/windows/tests/WINDOWS-READINESS.md#developer-builds-and-testing).
- **Diagnosing a problem:** [PBX troubleshooting](teliphones/README.md#troubleshooting),
  [Windows troubleshooting](desktop/windows/README.md#troubleshooting) and
  [read-only firewall diagnostics](docs/FREEPBX-FIREWALL-DIAGNOSTICS.md).

## Two workflows, two kinds of authority

| | My PBXs | Remote Support |
|---|---|---|
| For | Administrators connecting their own Windows workstations | Customers granting an enrolled engineer a support window |
| Approval | Full FreePBX administrator pairs one workstation over HTTPS | Customer/root authorises each support session |
| Lifetime | Temporary: 60, 240, 480 or 1440 minutes; or persistent until revoked | Always temporary: 5–240 minutes |
| Connection | Direct WireGuard to the PBX; no external service | Separately operated Connect, Checker and Console integrations |
| SSH | Explicit existing-account approval, ephemeral certificates and isolated per-workstation listener | Separate key-only temporary support service on port 22222 |
| Current evidence | Initial live tunnel/authenticated SSH and client disconnect reported; lifecycle validation incomplete | Implemented contracts and laboratory tests; not validated end to end |

### My PBXs: your workstation, your PBX

1. **Request:** in Windows, choose **Add my PBX...** and generate a pairing
   request. GUI-only access is the default; opt in to SSH before generating
   the request if needed.
2. **Approve:** a full FreePBX administrator pastes the request into
   **Connectivity > TELIPHONES > Windows workstations**, sets the period and
   explicitly approves an existing account if granting managed SSH.
3. **Pair:** paste the bound response back into the waiting Windows dialogue and
   save the connection. Private keys stay on their originating device.
4. **Connect:** approve Windows tunnel setup, open FreePBX and sign in normally.
   The unreleased Windows source includes an experimental built-in VT console
   on the approved managed SSH path, using the approved account, pinned host/CA
   keys and a fresh session certificate. Portable VT tests pass; the native
   MFC/ConPTY integration and real SSH behaviour remain unverified.
5. **Disconnect or revoke:** disconnecting closes the local connection, not its
   authorisation. To remove authority, **Revoke** on the PBX. Deleting a Windows
   profile is not PBX-side revocation.

Only the PBX's tunnel address (`/32`) is routed through WireGuard; the PBX does
not forward workstation traffic to other networks. Web access uses TCP 80/443.
New SSH-approved pairings receive only their dedicated SSH port and certificate
API, not the normal system SSH listener. Legacy network permissions are preserved.

Follow the [complete pairing instructions](teliphones/README.md#windows-workstations-install-pair-and-connect).

### Remote Support: a customer-approved window

> **Connect creates. Checker observes. Console consumes. TELIPHONES decides.**

The PBX creates the grant and absolute expiry. Connect proposes the path;
Checker returns independently signed, session-bound observations. TELIPHONES
verifies both before opening support access. Console consumes that approved
access; none of these roles can authorise itself or extend the window.

On-PBX is implemented. On-net and Off-net are contracts requiring external
implementations. The repository supplies a reference Connect gateway and Checker
probe for disposable labs, not hosted services or a production engineer portal.
Remote Support uses `wg-teliphones`, separate from My PBXs' `tlp-admin`.

[Operate Remote Support](teliphones/README.md#remote-support-browser-workflow) ·
[Integration contracts](teliphones/docs/INTEGRATIONS.md) ·
[Topologies](teliphones/docs/TOPOLOGIES.md)

## Get started on a disposable test system

1. **Check the platform:** FreePBX 17 on Debian 12, root console access, HTTPS,
   WireGuard kernel support, `wg`, `ip`, `nft`, iptables and systemd.
   See [PBX requirements](teliphones/README.md#requirements).
2. **Verify and install** `TELIPHONES-0.6.4.tgz` through Module Admin:

   ```bash
   sha256sum -c TELIPHONES-0.6.4.tgz.sha256
   ```

3. **Complete the root bootstrap** using the
   [authoritative procedure](teliphones/README.md#complete-installation-on-freepbx-17).
   Repeat it after upgrades and verify the separately installed files.
   Keep an independent root/console route open.
4. **Prepare Windows:** obtain a verified successful build, keep
   `TELIPHONES.exe` and `TELIPHONES-SSH.exe` together, and follow the
   [first-launch/WireGuard guide](desktop/windows/README.md#secure-connectivity-and-wireguard-installation).
5. **Permit the WireGuard UDP endpoint**, default 51821, through the necessary
   router and firewall policy. Then pair, connect and verify the private route.
   Do not publish managed SSH or certificate API ports.

TELIPHONES is installed manually, not through the FreePBX online module
repository. The optional gateway is unnecessary for My PBXs.

## Security boundaries, in plain language

- **Approval is not just a tunnel.** WireGuard authenticates the peer; managed
  SSH also requires the paired identity, an approved account, a fresh certificate
  and pinned host/CA verification. FreePBX web sign-in remains required.
- **The web page is not root.** It sends allow-listed requests to a root-owned
  broker, which verifies the FreePBX service account. Installing the module
  alone grants no remote access.
- **Do not distribute session private keys.** Windows keeps the permanent SSH
  identity encrypted with DPAPI and session signing keys in memory. The owned
  agent signs once for its SSH process. This does not promise physical erasure
  of every OS/library copy or defence against a compromised administrator/OS.
- **Closing a terminal is not server-side revocation.** Client disconnect
  closes owned processes; PBX revocation and pairing expiry must separately
  stop the owned server sessions. Full real systemd/cgroup validation is pending.
- **TELIPHONES complements FreePBX Firewall.** Version 0.4.1 uses one marked,
  marked jump inside `fpbxfirewall`; its exact per-peer ACCEPT rules remain
  interface-scoped and preserve unrelated policy.
  Custom Rules need not be enabled. Real watchdog/rebuild compatibility is not
  yet established.

TELIPHONES **does not automatically close public management ports** or replace
router/host policy. Verify the private route before restricting your existing
administration route. Required public SIP/RTP traffic is separate from GUI/SSH
access. A reachable WireGuard UDP endpoint, sometimes with port forwarding, is
still required: no relay or universal NAT traversal is implemented.

External privileged firewall changes can create an exposure window before
detection. A Fail2Ban hook moved after `fpbxfirewall` can be bypassed for approved
flows until integration is withdrawn. There is no guaranteed recovery deadline
or zero-exposure claim. Read the [security limitations](docs/SECURITY.md#known-limitations).

## Working, experimental and planned

| Area | Evidence and remaining work |
|---|---|
| Windows build and managed SSH | Operator reports successful Actions builds and **10/10 native SSH tests**; initial authenticated SSH into FreePBX 17 and terminal closure on disconnect observed |
| Module 0.4.1 firewall correction | Local unit/model and real-packet namespace tests on both iptables backends; real FreePBX watchdog, rebuild and upgrade validation outstanding |
| Revocation, expiry and recovery | Automated failure/SSH tests exist; complete live PBX server-side session termination, cgroups, reboot and recovery remain outstanding |
| GUI, appearance, onboarding and connection health | Implemented; initial use does not certify every terminal, display scale, installer or reconnection case |
| Remote Support | Contracts and lab implementation; complete deployed workflow remains unverified |
| Integrated TELIPHONES SSH console | Experimental libvterm/ConPTY implementation in source; portable VT tests pass; native Windows build and real SSH validation remain outstanding |
| PuTTY for managed My PBXs SSH | Not supported; a development objective only if certificate authentication, key isolation and termination guarantees can be preserved |

The operator-reported results supplied with this documentation review are not
accompanied by a run URL, commit/build hash or raw logs here. They are attributed
as reports, not claimed as independently re-executed results. See the
[evidence record](docs/SECURITY.md#verification-evidence) and
[current PBX acceptance checklist](teliphones/README.md#current-verification-status).

## Documentation and repository

| Resource | Purpose |
|---|---|
| [FreePBX guide](teliphones/README.md) | Install, upgrade, pair, operate, diagnose and uninstall |
| [Windows guide](desktop/windows/README.md) | Download, first launch, connection health, terminals, settings and recovery |
| [Architecture](docs/ARCHITECTURE.md) | Trust boundaries, interfaces, firewall layering and runtime state |
| [Security](docs/SECURITY.md) | Authentication, lifecycle, evidence, limitations and private reporting |
| [Firewall diagnostics](docs/FREEPBX-FIREWALL-DIAGNOSTICS.md) | Incident trace, read-only collection and 0.4.1 acceptance criteria |
| [Managed SSH design](docs/SSH-KEY-MANAGEMENT-PROPOSAL.md) | Certificate protocol, key inventory, process ownership and historical proposal |
| [Pairing contract](teliphones/docs/WORKSTATION-PAIRING.md) | Versioned pairing, restrictions, reconciliation and verified cleanup |
| [Testing programme](teliphones/docs/TESTING.md) | Local commands and staged disposable-PBX validation |
| [Windows build/readiness reference](desktop/windows/tests/WINDOWS-READINESS.md) | Build tools, CI, manifests, fixtures and historical debugging evidence |
| [Module history](teliphones/docs/CHANGELOG.md) · [Windows history](desktop/windows/CHANGELOG.md) | Separate version histories |
| [Rendezvous design](docs/RENDEZVOUS.md) | Future direct-first/relay contracts, not implemented connectivity |

Source is organised as `teliphones/` (module and broker), `desktop/windows/`
(native C++17 Win32/MFC client), `gateway/` (optional lab tools and broker tests),
`docs/` (project design) and `.github/workflows/` (build validation).
The module-only archive excludes Windows, gateway, root project docs and tests.

### Building and testing

From the repository root, with existing dependencies:

```bash
cd teliphones && XDEBUG_MODE=off php tests/run.php
cd ../gateway && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Portable Windows checks, native build instructions and the distinction between
test registration and execution are in the
[build reference](desktop/windows/tests/WINDOWS-READINESS.md#developer-builds-and-testing).
The [package validator](teliphones/tests/package-validation.py) checks exact
archive/source equality. Documentation edits after packaging deliberately make
that equality fail; they do not justify rewriting a preserved archive.

Build the module-only 0.6.4 archive from the repository root using the existing
package exclusions, then validate the exact contents and checksum:

```bash
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' --exclude='*/.*' --exclude='*/tests' \
  --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
  -czf TELIPHONES-0.6.4.tgz teliphones
  sha256sum TELIPHONES-0.6.4.tgz > TELIPHONES-0.6.4.tgz.sha256
PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/package-validation.py
```

Do not rebuild the preserved 0.6.3 or historical archives. The 0.6.4 package
contains the 0.6.3 root broker and protocol 12; no Windows or gateway sources
are included.

## Contributing

Use British English and keep My PBXs, Remote Support, pairing, connection and
revocation distinct. Run the relevant tests; never weaken a security control to
make a test pass. Do not include credentials, private keys or operational
pairing/grant data in issues, logs or commits. Follow the
[AI disclosure policy](teliphones/README.md#ai-assisted-contributions-and-disclosure).

## Support

Maintained by [FreePBX UK](https://github.com/freepbxUK). See
[support and feedback](teliphones/README.md#support-and-feedback) for useful,
sanitised evidence. Report suspected security issues privately through
[FreePBX UK support](https://freepbx.uk/support/), not a public issue.

## Licence

**TELIPHONES is a UK registered trademark.**

TELIPHONES 0.7.0 for Windows is licensed under GPLv3.
TELIPHONES 0.4.1 for FreePBX is licensed under GPLv3.
These are the product footer statements. The software grant is **GPL version 3
or, at your option, any later version (GPL-3.0-or-later)**; the module metadata
declares `GPLv3+`. See [LICENSE](LICENSE). Software licensing does not grant
trademark rights. Windows distributions also include the OpenSSL licence.

## Author

[@kierknoby](https://github.com/kierknoby), Kieran Knowles-Byrne // [FreePBX UK](https://github.com/freepbxUK)
