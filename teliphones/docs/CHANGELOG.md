# FreePBX module change history

[Administration guide](../README.md) | [Current verification status](../README.md#current-verification-status)

Historical entries describe their versions at the time, not current behaviour
or current test status. Windows has an independent history in the source
repository. Portable Linux validation is current for the broker, FreePBX module and
Windows core. Native Windows compilation/UI integration and live FreePBX
session, migration, firewall and SSH acceptance remain outstanding.

## 0.6.7, admission diagnostics and responsiveness (unreleased source)

- Advance the FreePBX module and root broker independently to **0.6.7**,
  retaining protocol **12** and Windows **0.8.5**. Module Admin does not
  necessarily refresh the separately installed root broker; repeat the root
  bootstrap after upgrading the module.
- Persist correlated workstation session-controller outcomes in the existing
  bounded diagnostic history: admission/refusal/failure, reason, lock wait and
  processing time, response delivery and a random per-attempt identifier.
  Fast successful lease renewals are omitted. Histories remain size- and
  age-bounded; endpoint addresses, credentials, keys and pairing responses are
  not recorded.
- Record controller listener state and slow, failed and recovered background
  workstation reconciliation. A failed reconciliation still disables
  workstation access until a later successful retry; it is now visible in the
  persistent administrator diagnostics rather than only the system journal.
- Move source verification and DNS resolution for the admission status report
  outside the workstation lock. Unexpected session-controller exceptions now
  receive a generic error response rather than silently dropping the request.
  A request that the PBX admitted but Windows did not receive can be identified
  by matching the `ws-` diagnostic ID and attempt ID on both sides.
- Keep leases keyed to the authenticated workstation identity: a public source
  change does not consume another simultaneous-session slot. This does not
  establish that endpoint roaming or a complete network-change/reconnect
  succeeds on Windows or a live PBX.
- Add broker regressions for delivery, sanitisation, lock contention, source
  changes, admission limits, restart recovery, listener state and reconciliation
  failure/recovery. The FreePBX administrator diagnostics view and export
  validate and display the new event types.
- Native Windows validation and live FreePBX 17 / Debian 12 admission,
  roaming, firewall and end-to-end recovery acceptance remain outstanding.
  This is development source preparation, not a release or deployment claim.

## 0.6.6, firewall reconciliation feedback-loop correction (previous development target)

- Advance the FreePBX module and root broker to **0.6.6**, retaining protocol
  **12** and independently versioned Windows **0.8.3**. Brokers through 0.6.5
  are reported as outdated because the correction is in the root broker.
- Fix workstation session admission timing out (Windows error 12002) and
  sustained broker CPU use. Replacing the owned nft table cascades kernel rule
  and chain deletion events that were misread as external tampering, so each
  heartbeat restarted a self-sustaining loop of interface shutdown and policy
  replacement while holding the workstation lock. The inspected rules and
  chains are now acknowledged as part of the broker's own transaction, and an
  already-exact policy is not rewritten on lease renewal. Unpredicted changes
  still trigger enforcement.
- Model the kernel deletion cascade in the network fake and add regressions for
  unrestricted GUI-only admission, own-table replacement versus external
  changes, and bounded read-only work under repeated firewall events. The
  isolated real-nft namespace lab asserts that the broker's own table
  replacement and teardown do not trigger enforcement.
- Source changes after the 0.6.6 archive was built are not yet packaged: the
  later 0.6.7 package contains those changes; the historical 0.6.6 archive is
  preserved unchanged.
- Build the local module-only 0.6.6 archive and SHA-256 sidecar from current
  source, replacing the superseded root-level 0.6.5 pair. Live FreePBX 17 /
  Debian 12 session-admission and idle-CPU acceptance remain outstanding; no
  publication, release, live installation or deployment is claimed.

## 0.6.5, durable workstation revocation and reliability (superseded local test package, not published)

- Advance the FreePBX module and root broker to **0.6.5**, retaining protocol
  **12** and independently versioned Windows **0.8.3**. Module metadata drives
  the GUI heading; broker status and diagnostic events report the new broker
  version. Reject earlier brokers even when they report protocol 12.
- Durably persist revocation before fallible network cleanup using a private
  journal with file and directory fsync. Public identity tombstones override
  saved pairing state, restart recovery, heartbeat admission and SSH authority.
  Revoked identities require a newly generated workstation identity to pair again.
- Verify WireGuard peer/interface removal, owned nft policy, session admission
  and managed SSH termination. Report unconfirmed removal, confirmed removal
  with pending housekeeping, and complete cleanup separately. Apply verified
  fail-closed containment when targeted enforcement cannot be confirmed.
- Decouple access removal from unchanged shared-listener reconciliation.
  Preserve unrelated authorised peers where safe and retain cleanup ownership
  without restoring revoked authority or editing FreePBX-generated chains.
- Extend bounded progress framing to revocation, preserve accepted operations
  after browser disconnection, and expose the persisted latest outcome with the
  explicit **Revoke workstation access** label.
- Add failure-injection, crash/persistence, restart, concurrency, slow-operation,
  disconnected-browser, SSH termination and GUI regressions. Local real nft and
  isolated OpenSSH checks do not certify live FreePBX generation or production
  systemd/cgroup supervision. Build the local module-only 0.6.5 archive and
  SHA-256 sidecar from current source, replacing the obsolete root-level 0.6.4
  pair. No publication, release, live installation or deployment is claimed.
- Upgrade the module in place and rerun the trusted root bootstrap with tunnels
  disconnected and no active support session. Preserve revocation journals;
  older broker binaries do not understand these new security decisions.

## 0.6.4, pairing form and listener diagnostics (local test package, not published)

- Include the web-only pairing form correction developed after the preserved
  0.6.3 archive: submit exactly one explicit `ssh=0`, report field-specific
  validation errors and retain bounded non-sensitive values after failure.
  Pairing payloads and SSH approval are cleared rather than redisplayed.
- Identify listener admission versus removal, requested ports and exit status.
  Report the owned chain and exact rule/zone mismatch at verification timeout.
  Retain separately sanitised stdout/stderr and the initiating error when
  cleanup or policy restoration also fails. Unrecognised command output is
  explicitly withheld; raw keys, payloads, comments and tokens are not echoed.
- Preserve ownership checks, firewall verification, retry deadlines and
  fail-closed workstation access. Pairing, cleanup and policy restoration remain
  serialised against the background worker; no speculative lifecycle fix is
  included. The initiating live FreePBX convergence failure is not established.
- Correct the subsequently reported broker 0.6.2 CPU/spawn loop, also present
  in the initial pending 0.6.3 source: the background worker invoked the costly
  FreePBX listener command on every tick/wakeup, including its own generated
  `ip filter` notifications. Before a background command, compare the exact
  desired port set, owned journal and generated service/zone rules read-only.
  Correct state now needs no `fwconsole` process. Explicit pairing and cleanup
  still use the trusted PHP helper; unmatched owned-nft events still disable
  and reverify enforcement, including a transient flush followed by restoration.
- Back off failed background transactions by 5, 10, 20, 40 then at most 60
  seconds after cleanup, coalescing notifications without bypassing the retry
  deadline. Reassert disabled access during cooldown; a changed authoritative
  policy can be applied immediately. Success resets retry state. This is a
  bounded retry rate, not a finite limit that abandons recovery.
- New simulated scheduling tests count listener commands over 240 idle ticks,
  notification storms, successful self-notification feedback and failures.
  They cover dedicated-listener rollback, ownership/readback rejection, retry
  deadlines and recovery. No live CPU measurement or PBX acceptance of this
  correction has yet been performed. Keep the affected development broker
  stopped until the replacement package is reviewed.
- Module **0.6.4** requires independently versioned root broker **0.6.3**,
  even when an older broker reports protocol **12**. Windows remains **0.8.1**.
  Upgrade in place, then repeat the trusted root bootstrap with Windows tunnels
  disconnected and no active support session. Do not uninstall or clear state.
- Local PHP/JavaScript, broker and package regressions cover form submission,
  lock contention, Open policy with zero peers, cleanup, restoration, recovery
  and sanitised diagnostics. Networking/FreePBX operations are modelled except
  where individual test output explicitly identifies isolated kernel/SSH tests.
  Debian 12 / FreePBX 17 upgrade, pairing, WireGuard traffic, approved management
  access, reconnect and final cleanup still require live acceptance.
  Regression success is not a connectivity fix or production certification.

## 0.6.3, pairing transport patch (local package, not published)

**Historical packaging boundary; subsequently included in 0.6.4:** the
web-only form now submits exactly one explicit `ssh=0` when its SSH select is
disabled. PHP reports field-specific missing/type errors and retains bounded
non-sensitive values; pairing material/SSH approval are cleared. Actual page/POST
and Unix-socket regressions pass locally. The preserved archive predates this
correction; that form correction alone required no broker implementation change.
Windows is now independently prepared as 0.8.1; entries below retain the
original component versions at packaging.

- Replace the five-second synchronous pairing response deadline with opt-in,
  non-secret progress frames and a five-second inactivity timeout. Only the
  final verified response is success; pairing is dispatched once, and loss of
  its response does not interrupt verified enforcement or cleanup.
- Serialize broker operation and response-encoding failures into valid JSON
  errors. Report safe exception categories, stages and source locations without
  recording requests, credentials or subprocess contents. Preserve initiating
  command timeout errors through cleanup and rollback.
- Distinguish socket inactivity, early closure, malformed/oversized replies and
  invalid progress framing from an explicit broker operation failure. An
  unconfirmed outcome requires refreshing status before retrying.
- Require independently versioned root broker 0.6.2 for module 0.6.3, including
  when an older broker reports protocol 12. Keep protocol 12 and Windows 0.8.0
  unchanged. Rerun the documented root bootstrap after the Module Admin upgrade.
  The GUI heading continues to use authoritative module metadata.
- Retain nftables acknowledgement, readback-gated recovery, workstation
  authorisation, SSH protections and fail-closed enforcement. No GUI layout
  change is included.
- Add real PHP/Unix-socket regressions with modelled network commands. The
  isolated real-nft lab passed 10/10 runs on this source and 10/10 against the
  unchanged pre-transport baseline. The earlier intermittent own-event-filtering
  failure was not reproduced; these runs do not prove it cannot recur.
  Live FreePBX 17 / Debian 12 pairing, installed upgrades and web-server/proxy
  request deadlines remain unvalidated. This is a local test package, not a
  published or production-certified release.

## 0.6.2, workstation firewall recovery patch (local package, not published)

- Correct nftables policy serialization so UDP port matches use the same
  canonical form reported by kernel listings and monitor events. This allows
  the broker to verify Banned List and Locked/Allowed List listener rules.
- On an unacknowledged transaction, read back the TELIPHONES kernel table
  before releasing pending monitor events. If readback fails, retain the
  pending transaction and keep workstation access disabled. Cleanup and the
  next pairing attempt recover only after verified kernel state and an observed
  transaction; no firewall verification is bypassed.
- Restore workstation pairing after recoverable acknowledgement failures and
  report missing tools separately from broker readiness errors.
- Increment the FreePBX module to 0.6.2 and the independently identified root
  broker to 0.6.1. Keep broker protocol 12 and Windows 0.8.0 unchanged. The GUI
  refuses workstation pairing until it sees broker 0.6.1; after Module Admin
  upgrade, rerun the documented root bootstrap without uninstalling or clearing
  pairings.
- Gateway regression suite and real-nft isolated namespace lab pass locally.
  The lab uses nftables 1.0.9; Debian 12's nftables 1.0.6 and a live FreePBX
  17 host were not available for this validation. This is not a production
  certification.


Entries for 0.0.2 to 0.2.1 are summarised from the repository history. Release dates are recorded only where they were previously published.

## 0.6.1, administration interface patch (local package, not published)

- Group existing controls into lightweight FreePBX-style readiness, support,
  workstation access, paired-workstation and security panels. Make policy,
  session capacity and per-workstation permissions easier to scan.
- Keep blockers and security warnings visible; move technical explanations
  into expandable help. Distinguish configuration gaps from platform failures.
- Keep diagnostics and pairing compact with native expandable panels; split
  the unchanged pairing form into five visual groups. Reveal collapsed
  validation errors and reopen server-rejected pairing/enrollment forms.
- Add scoped responsive spacing, readable status badges and a keyboard-focusable
  horizontal workstation-table region without removing management actions.
- Retain broker 0.6.0, protocol 12, state formats and installation logic.
  Upgrade 0.6.0 through Module Admin without uninstalling or clearing pairings;
  an operational protocol 12 broker does not need updating.
- Local PHP/template, JavaScript and package checks cover the patch.
  Browser rendering and a live FreePBX 17 upgrade remain unverified.

## 0.6.0, local development target (not production-certified)

- Add persistent Open, Closed and Frozen workstation connection states.
  Closed tears down network access without deleting pairings; Frozen blocks
  enrolment of new WireGuard identities while retaining existing authority.
  Existing installations with valid pairings migrate to Open; a new install
  defaults to Closed.
- Reject SSH approval for web-only pairing requests. Show SSH authorization
  choices only when the request supports them.
- Protocol 7 carries the connection-state policy. State is persisted before
  enforcement so a broker restart after interruption converges on the
  administrator's selected policy.
- Protocol 8 adds dedicated WireGuard listeners and source restrictions for
  Locked pairings. Unlocked workstations retain the shared listener, and the
  Locked peer is removed from that shared roster.
- Protocol 9 permits explicitly approved managed SSH for Locked pairings by
  binding the certificate API and SSH listener to the workstation's dedicated
  tunnel interface and address. Local isolated packet tests verify the
  interface-scoped SSH ports; live PBX and native Windows acceptance remain
  outstanding.
- Protocol 10 adds a manually managed IP/CIDR Banned list on the TELIPHONES
  listener ports only. It is persisted with workstation policy, applied before
  listener accepts and expires through firewall-only reconciliation. Focused
  broker tests cover ordering, expiry and avoiding tunnel-interface restarts;
  live nftables/FreePBX validation remains outstanding.
- Protocol 11 adds atomic PBX-enforced active-session leases and heartbeats,
  defaulting to one workstation. The owned firewall policy grants management
  access only to admitted peer addresses; expired or removed leases reconcile
  without treating WireGuard handshake timestamps as active sessions.
- Protocol 12 adds post-pair lock/unlock and source-list management. Current-IP
  locking uses the broker-observed recent WireGuard endpoint; failed policy
  updates revoke the affected peer without taking unrelated workstation
  interfaces down. Windows receives the effective source list, current
  verified public source, DNS failures and capacity, and can request source-list
  changes or unlocks. Relaxing changes remain pending until explicit FreePBX
  administrator approval. Listener migrations deliver the updated profile
  over the authenticated existing tunnel, restrict the old tunnel to session
  control, and retire it after acknowledgement on the new tunnel.
- Protocol 12 also permits web-only workstations to request SSH after pairing.
  FreePBX explicitly approves/rejects the request and selects an existing Linux
  account; SSH revocation preserves web access. Short-lived managed SSH
  certificates remain identity-bound.
- Increment the module independently to 0.6.0 for the new server policy.
  Gateway, FreePBX and portable Windows suites pass; live FreePBX and native
  Windows validation remain outstanding.

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
