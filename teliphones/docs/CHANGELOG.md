# FreePBX module change history

[Administration guide](../README.md) | [Current verification status](../README.md#current-verification-status)

Historical entries describe their versions at the time, not current behaviour
or current test status. Windows has an independent history in the source
repository. The current report is native SSH 10/10 and initial live
authentication/client disconnect success; complete server lifecycle and real
0.4.1 firewall validation remain outstanding.


Entries for 0.0.2 to 0.2.1 are summarised from the repository history. Release dates are recorded only where they were previously published.

## 0.5.0, local test package (not production-certified)

- Manage the public WireGuard UDP listener through FreePBX's persistent Custom
  Service API, with journalled ownership, interrupted-operation recovery and
  read-only generated-rule verification. Preserve INPUT/Fail2Ban ordering.
- Add approved HTTP/HTTPS management ports in both tunnel enforcement layers;
  preserve the configured URL in updated Windows profiles and Connection Health.
- Restore historical-package integrity tests and retain the locally validated
  installation archive/checksum. Real FreePBX roaming, watchdog, Apache and
  systemd lifecycle validation remain outstanding.
- Minor module/broker increment for the management-port feature, protocol 6.
  Windows keeps its unreleased 0.7.0 target; custom-port support requires an
  updated build. Package checksums distinguish this test build.

## 0.4.1, FreePBX Firewall coexistence correction

- Patch increment because 0.4.0 was already installed and tested on a real
  FreePBX server and this serious operational correction must be identifiable.
  Windows remains independently versioned at 0.7.0; no Windows application code
  changes are included.
- Move the marked workstation jump from above
  FreePBX's INPUT hook into `fpbxfirewall`, preserving Fail2Ban and exact peer
  restrictions without Custom Rules. Remove legacy jumps during migration and
  cleanup; never flush or replace unrelated rules. The reported approximately
  41-second "invading rule" reset loop is covered by a modeled watchdog test,
  not by real FreePBX execution. Local real-packet tests cover both iptables
  backends, unchanged unrelated SIP/RTP/management traffic and lifecycle repair.
  Real-PBX 0.4.1 watchdog, rebuild and certificate SSH retesting remain pending;
  initial live SSH success was reported against 0.4.0.
- Package as `TELIPHONES-0.4.1.tgz`, including both root broker helpers and all
  module components. Package/source equality and version consistency passed
  when the archive was built. Later documentation edits are not repackaged;
  full byte equality must be restored before future distribution.
  The SHA-256 sidecar identifies the exact archive contents; retain it with the
  package. Preserve `TELIPHONES-0.4.0.tgz` unchanged as the older version.
- Rerun the documented root broker bootstrap after upgrading, even if the old
  broker already reports protocol 5. Verify helper equality and service restart.
  Building this review package does not publish a release or deploy anything.

## 0.4.0, managed My PBXs SSH (installed test build)

- Installed and tested on a real FreePBX 17 / Debian 12 server; the firewall
  reset defect found during that testing is corrected in 0.4.1.
- Add version-2 pairing with an explicitly approved existing Linux account,
  pinned host/CA keys and independent workstation SSH keys.
- Add a paired-key-authenticated, WireGuard-device-bound certificate API and
  isolated, per-workstation SSH listeners. Keep system SSH and Remote Support
  unchanged. Short certificates never extend the original pairing deadline.
- Require request/2 signatures to bind a distinct ephemeral public key and fresh
  session ID; reject old reusable-subject issuance and duplicate live credentials.
  Migrate recognised old principals only after verified owned-session termination,
  preserving CA, host identity and enrolled workstations.
- Add owned systemd/cgroup teardown and expiry bounds; retain recovery state
  whenever cleanup cannot be verified.
- Reject system SSH policy differences between port 22 and the managed listener,
  and verify the generated effective policy at the actual account/source/port.
- Update the shared protocol-5/two-helper bootstrap guidance, expected states
  and failure recovery; do not touch the normal SSH service.
- Add real isolated OpenSSH authentication, restriction, expiry and termination
  tests. Native Windows and real systemd/FreePBX lifecycle validation remain
  outstanding. Windows now has a session-isolated memory agent, protected
  permanent identity signing and owned console helper implemented in source;
  the former plaintext session-key export path remains removed. This is
  not a complete or production-ready SSH release.
- Build TELIPHONES-0.4.0.tgz; retain both products' independent histories.

## 0.3.5, disclaimer footer presentation (unreleased)

- Centre the disclaimer on one regular-weight line with spacing above and below.
  Narrow pages can scroll the line horizontally instead of wrapping.
- Package as TELIPHONES-0.3.5.tgz; retain the existing licence and trademark distinction.

## 0.3.4, disclaimer footer placement (unreleased)

- Move the version-derived trademark and licence disclaimer below all module GUI
  controls in a dedicated footer. No broker, authorisation or network-policy changes.
- Package the correction as TELIPHONES-0.3.4.tgz.

## 0.3.3, trademark and licence disclaimer (unreleased)

- Display the UK registered trademark statement and the FreePBX-specific GPLv3
  statement in both module GUI views, deriving the displayed version from module.xml.
- Distinguish software licensing from trademark rights; preserve the existing
  GPLv3-or-later grant and all broker, WireGuard and authorisation behavior.
- Package the updated module as TELIPHONES-0.3.3.tgz. The unchanged broker
  implementation continues to identify its component version as 0.3.2, protocol 4.

## 0.3.2, workstation diagnostics (unreleased)

- Adds a pairing-lifetime diagnostic ID (`ws-` plus the existing workstation ID) and bounded PBX-side event records for administrator pairing decisions, server-observed peer/interface/firewall lifecycle, and compact WireGuard handshake/traffic observations.
- Adds protocol 4 diagnostics retrieval and JSON export through the authenticated, CSRF-checked FreePBX AJAX handler; only full FreePBX administrators can read logs.
- Rotates private broker logs at 1 MiB per file, retains at most three files for seven days, and filters exported events by diagnostic ID. Event fields are allowlisted; keys, pairing tokens and request bodies are excluded.
- The PBX does not claim to observe Windows-local attempts or treat an idle peer as disconnected. No firewall, WireGuard access policy, pairing protocol or SSH authentication behavior changes.
- Regression tests are local simulations. No live PBX deployment or FreePBX runtime test is claimed.

## 0.3.1, nftables ownership compatibility (unreleased)

- Replaces reliance on nftables table comments with the exact hookless, ruleless `teliphones_owner_v1` chain, which remains visible in Debian 12 nftables 1.0.6 JSON readback.
- Safely migrates only an exact known 0.3.0 policy while the verified workstation interface is down. Unknown or altered rules remain untouched.
- Keeps broker protocol 3; rerunning the root bootstrap is required to copy and restart the separately installed broker.
- The operator reports successful testing of the ownership correction on the FreePBX 17 test PBX. The repository's automated packet tests still use a simulated FreePBX Firewall.

## 0.3.0, development milestone (unreleased)

Not yet released. This package is for manual installation and testing on a disposable FreePBX 17 PBX only; see [current verification status](../README.md#current-verification-status). It is the milestone that introduces FreePBX Firewall integration and enhanced workstation connectivity enforcement. It builds on the 0.2.0 workstation pairing and the 0.2.1 firewall enforcement corrections, which are preserved.

### FreePBX Firewall integration

The INPUT placement below is historical and is superseded by the 0.4.1
firewall correction described above.

- Adds a broker-owned, marker-validated iptables chain, `teliphones-ws`. One INPUT jump is placed immediately before the `fpbxfirewall` hook. FreePBX Firewall chains, zones, trusted networks, settings and services are not modified.
- Admits only TCP 80/443 from each paired workstation address (`/32`) to the PBX tunnel address. TCP 22 is added only for explicitly SSH-approved workstations. Everything else returns to FreePBX Firewall.
- Installs integration only after the owned nftables policy has been verified, and before `tlp-admin` is brought up. Unverifiable cleanup disables workstation access.
- Refuses to modify an unfamiliar `teliphones-ws` chain or unexpected references to it.

### Fail2Ban compatibility

- Recognises `fail2ban-*` (FreePBX 17) and `f2b-*` (upstream) INPUT hooks, ignoring case.
- Requires the TELIPHONES jump to follow every Fail2Ban hook. If a Fail2Ban hook follows `fpbxfirewall`, the integration is withdrawn and reported rather than bypassing Fail2Ban.

### Automatic reconciliation

- Restores missing, duplicated or misplaced integration after firewall reloads or Fail2Ban restarts, without duplicating rules or reconnecting peers. With the iptables `nf_tables` backend this happens on nft monitor events; with `legacy` it happens on the approximately 15-second periodic check.
- Removes integration on revocation, expiry, broker shutdown and uninstall. Uninstall retains recovery state if removal fails.

### Diagnostics

- **Windows workstations** shows the integration state (active, not installed, failed or not reported by an outdated broker) and the iptables backend.
- Warns when a workstation's WireGuard handshake succeeded but FreePBX Firewall integration is inactive.

### Windows application

- Adds a first-run **Welcome to TELIPHONES** dialog and a **Settings...** dialog for the default browser and SSH terminal. Only installed applications are offered. Preferences are stored locally for each Windows user and are never sent to the PBX.
- **Open FreePBX** uses the Windows default browser, Chrome, Edge, Firefox, Brave or Vivaldi.
- **Open SSH** uses Windows PowerShell, PowerShell 7, Windows Terminal, Command Prompt or PuTTY, with validated, separately passed arguments. It is enabled only after the PBX has answered through the tunnel.
- A missing selected application is reported, and is never silently replaced.
- These features are covered by simulated core tests only; they have not been validated on Windows.

### Testing

- Adds simulated broker tests and real-packet namespace tests for both iptables backends. They use the Fail2Ban chain names observed on the FreePBX 17 test installation, including hook reordering. None of these tests use the real FreePBX Firewall, WireGuard or Windows.

### Documentation

- Reorganises the project documentation, adding a project overview, an architecture guide, a security guide and this module guide.

## 0.2.1, firewall enforcement and lifecycle security

- Verifies the complete owned nftables policy before admitting workstation peers, and monitors it for external changes, with a periodic fallback.
- Disables workstation connectivity when enforcement is missing or altered, and restores verified restrictions before readmitting peers.
- Originally identified `inet teliphones_workstations` with a table comment; nftables 1.0.6 does not preserve that marker in JSON readback. The 0.3.1 ownership chain and constrained migration supersede that mechanism.
- Makes uninstallation verify interface removal before removing firewall protection, and retain recovery information on failure.
- Preserves workstation pairing data on upgrade.

## 0.2.0, Windows workstation pairing

- Adds administrator-approved Windows workstation pairing with temporary or persistent access, direct WireGuard connectivity and per-workstation SSH permission.
- Adds individual and bulk revocation, and handshake status.
- Requires broker protocol 3 and verifies the workstation capability contract.
- Accompanies the experimental native Windows application.

## 0.1.3, live status monitoring

- Adds automatic, authenticated status polling with progress indicators, verified outcomes and duplicate-submission prevention.
- Adds broker protocol detection, outdated-broker warnings and copy-and-paste root bootstrap instructions.
- Prevents redundant WireGuard tools installation.

## 0.1.2, FreePBX 17 administrator authentication

- Separates FreePBX access validation from session and permission checks. Accepts permission-bearing session objects and scalar session usernames, and no longer requires a particular `FREEPBX_IS_AUTH` value.
- Preserves restricted-user refusal and CSRF protection.
- GUI operation was confirmed on FreePBX 17.

## 0.1.0, browser-based remote support

- Adds GUI-based support authorisation, session monitoring and revocation through a restricted privileged broker.
- Adds approved WireGuard tools installation, secure gateway enrolment, signed Checker verification, temporary SSH access and automatic expiry and cleanup.

## 0.0.2, FreePBX 17 compatibility

- Corrects the BMO implementation and lifecycle methods.
- Resolves a Symfony Console method collision that prevented `fwconsole reload` and `fwconsole chown`.
- Implements `doConfigPageInit` and corrects GUI state handling.
- Module installation and GUI operation were tested on Debian 12 / FreePBX 17.

## 0.0.1, initial testing release, 26 September 2026

Released by `@kierknoby, Kieran Knowles-Byrne // FreePBX UK`.

Initial TELIPHONES testing release for FreePBX 17. This release establishes the local authority model, the initial On-PBX implementation and the Connect, Checker and Console integration boundaries for controlled testing.

### Local authority

- Adds root-controlled temporary support authorisation with an absolute expiry.
- Adds persistent enable and disable state.
- Adds immediate local revoke.
- Adds reboot reconciliation without extending the original grant.
- Prevents the temporary privileged SSH service from automatically reopening after reboot.

### On-PBX

- Adds the initial On-PBX topology.
- Creates an ephemeral `wg-teliphones` WireGuard interface.
- Generates the PBX WireGuard private key locally.
- Validates proposed addressing against existing PBX addresses and routes.
- Does not alter the default route, DNS, forwarding, NAT or unrelated network configuration to resolve an allocation conflict.
- Adds a dedicated temporary sshd using session-specific public-key authentication.

### Integrations

- Defines the `teliphones-connect/1` Connect contract.
- Defines the `teliphones-checker/1` Checker contract.
- Defines the `teliphones-console/1` Console handoff.
- Separates PBX-local verification from external Checker observations.
- Adds session-, topology-, nonce- and time-bound Checker evidence with replay protection.

### Testing

- Adds `fwconsole teliphones check`.
- Adds `fwconsole teliphones baseline` with the `teliphones-baseline/1` schema.
- Adds staged local, Connect, Checker and Console testing documentation.
- Adds explicit expiry, reboot, revoke, cleanup and failure-testing requirements.
