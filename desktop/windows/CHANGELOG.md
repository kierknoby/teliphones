# TELIPHONES for Windows: change history

This is the Windows application's history, not the FreePBX module release list.
No Windows release is declared published by this document. Earlier development
builds lacked embedded file/product versions and cannot be assigned reliable
version numbers retrospectively.

## 0.8.4 — Unreleased development target

Windows file/product version: **0.8.4.0** / **0.8.4**. Independent source targets:
FreePBX module **0.6.6**, root broker **0.6.6**, protocol **12** (unchanged).
Patch increment: corrects the tunnel lifecycle of the 0.8.3 workstation build,
which left `WireGuardTunnel$TELIPHONES-*` stuck in `START_PENDING` (stop refused
with Windows error 1052, `wireguard.exe` surviving termination) until reboot.

The tunnel mechanism is unchanged: the official WireGuard service owns the
adapter and WireGuardNT only applies the key after that service is Running, so
the stall preceded any TELIPHONES activation. Its underlying cause remains
unconfirmed and requires native diagnostics. Corrected lifecycle defects:

- Failures report their original stage and Windows error together with the
  cleanup outcome, instead of a generic "could not be removed safely".
- Cleanup checks the official uninstall and waits for the service to be absent.
  A service stuck in `START_PENDING` is recovered by terminating its own
  process only after its SCM binary path (`wireguard.exe /tunnelservice` and
  this tunnel's configuration) and process image prove ownership; the PID is
  re-read to exclude reuse. Other WireGuard tunnels are never changed.
- The adapter must be released and the bootstrap configuration deleted before
  cleanup is reported complete; any residual service state, surviving process,
  unverified ownership, adapter or file is reported specifically.
- A machine-wide per-tunnel lock prevents overlapping elevated connect and
  cleanup operations. Each connection first removes and verifies any earlier
  instance; a residual instance blocks reuse instead of conflicting with it.
- The application waits longer than the helper's worst case (compile-time
  checked) and never terminates a running helper or starts competing cleanup.
- Non-elevated removal escalates immediately for `START_PENDING`.
- Closing TELIPHONES after a failed removal offers an explicit, logged exit.

A process that survives termination (a thread blocked in kernel mode) cannot be
recovered from user mode; TELIPHONES reports it and a Windows restart remains
required. Adds portable result/ownership/budget tests and native SCM tests for
a real stuck `START_PENDING` service and per-tunnel locking. Native compilation
and these native tests have not run in the Linux workspace.

Further corrections before release (version unchanged):

- Reconnect after a normal disconnect no longer reports a residual adapter.
  The 0.8.4 adapter check matched any interface row with the tunnel's name,
  including rows Windows had already marked not present, and treated a failed
  interface enumeration as absent. Adapter state is now classified by
  interface status (an enumeration failure is unverified, never absent), and
  Disconnect itself verifies that the active adapter was released.
- Saved connections always load. Startup previously removed SSH runtime files
  inside the profile-loading step, so one leftover directory reported "Saved
  connections could not be loaded". Cleanup now runs per profile after loading
  and reports failures without blocking the application.
- SSH runtime cleanup knows every file an attempt writes, including the client
  diagnostic `ssh.log` that a crashed session leaves behind. It still deletes
  only known names, never recursively, and names any remaining path. Session
  teardown that cannot be verified remains a failure.
- The runtime-cleanup regression fixture now uses native path separators, so
  its exact-path assertions also work on Windows. Locked-log coverage verifies
  that loaded profiles and the adjacent DPAPI identity survive a failed cleanup.
  Cleanup warnings are accepted by the diagnostics event allowlist instead of
  generating an additional startup error.
- Disconnect no longer fails after the tunnel is removed merely because
  temporary SSH files remain; they are reported and retried at the next start.
- Console exceptions (dialog initialisation, font creation, disconnect) no
  longer escape window procedures and terminate TELIPHONES. After the console
  closes, its owned SSH session is verified closed.
- Closing TELIPHONES tears down every owned resource independently: the managed
  SSH sessions of all profiles, the active tunnel and SSH runtime files. Any
  remaining resource is named, and the user chooses whether to exit or keep
  TELIPHONES open and retry.
- Startup errors are shown after the main window appears. They were previously
  owned by the still-hidden main window, with no taskbar button, so the process
  could appear to run without a usable window.
- Starting TELIPHONES while it is already running brings the existing window
  forward. If that process has no window, the message gives its process ID and
  the recovery steps. TELIPHONES never ends the other process.
- "Admission unavailable" is classified by the WireGuard handshake read in the
  same check. It no longer claims the tunnel is authenticated when no
  handshake has completed within 180 seconds; the message then names the
  outer UDP path and the PBX endpoint. With a recent handshake, it
  distinguishes a controller that cannot be reached from one that accepted
  the request but did not answer. Connection Health, the handshake age and
  traffic counters keep updating while admission fails. Admission failures and
  recoveries are recorded in the session log. The existing monitor continues
  retrying admission; no new retry loop or longer timeout was added.

Adds portable classification, adapter-release and runtime-cleanup tests, a
native disconnect/immediate-reconnect integration check and a native console
crash/locked-file recovery test. The specific trigger of the reported console
crash is not confirmed from code; Windows Error Reporting data is required.

## 0.8.3 — Previous development target

Windows file/product version: **0.8.3.0** / **0.8.3**. Independent source targets:
FreePBX module **0.6.6**, root broker **0.6.6**, protocol **12**.
The PBX security version update does not change Windows 0.8.3 functionality.
Increment Windows only because 0.8.2 is already tested on the workstation and
still fails; this correction must be distinguishable from that executable.

Official WireGuard for Windows 1.1.1 source confirms that the WireGuardNT
tunnel service does not create the protected text-UAPI pipe introduced by
`c8840f9` in 0.8.0. The 0.8.2 pipe-readiness retries could not fix this
architecture mismatch. Remove that path and its simulated-pipe tests.

Use the published WireGuardNT 1.1 DLL/header pinned by the official 1.1.1 build.
Restore and package the unmodified AMD64 DLL and binary licence. Before loading,
verify the compiled-in DLL hash, copy to a restrictive Program Files directory,
then lock/reverify and load the absolute path with system-only dependency search.
Open the existing service-owned adapter, set only `HAS_PRIVATE_KEY`, preserve
peers/interface settings, close the opened handle and wipe the temporary structure.
Retain bootstrap-only disk configuration, PID-bound local key delivery, SCM
readiness and cleanup on genuine failure. Report dependency, adapter or update
failures distinctly; a missing peer handshake is not a startup failure.

Add native ABI/wipe/failure tests and an isolated CI gate using the official
1.1.1 tunnel service and real driver. It checks enrolled-key readback, peer/
endpoint/allowed-IP/listen-port preservation, no initial handshake or text pipe,
continued service operation and failed-activation cleanup. Native compilation
and this real integration are not executable in the Linux workspace. Live
workstation handshake and approved PBX access remain required before claiming
connectivity restored. No binary has been built or deployed here.

## 0.8.2 — Previous development target

Subsequent operator testing confirmed error 1460: this pipe-based correction
did not restore connectivity. The historical implementation description below
is superseded by the verified 0.8.3 architecture correction.

Windows file/product version: **0.8.2.0** / **0.8.2**. Compatible source targets:
FreePBX module **0.6.4**, root broker **0.6.3**, protocol **12**.
Increment the Windows patch version because 0.8.1 is already installed on the
development workstation. Resource metadata, captions, About and dependency
manifest identify the correction independently of that executable. FreePBX
versions and packages are unchanged. No native 0.8.2 build or application
artefact exists yet; execution is blocked pending a Windows runner.

Correct a Windows tunnel activation race introduced with the 0.8.0 memory-only
key provisioning: `WaitNamedPipe` does not wait for a pipe that does not yet
exist, even after SCM reports Running. Retry only transient pipe availability
errors within a bounded deadline while checking service state. Preserve
bootstrap-only configuration, protected IPC, PID-bound helper key delivery
and removal on genuine failure. Distinguish service, control-pipe and
key-activation failures instead of suggesting an unproven VPN/address conflict.
Add a native SCM/named-pipe regression to the Windows Release CTests.
Linux portable checks do not prove the observed workstation failure fixed;
native and live WireGuard acceptance remain required.

## 0.8.1 — Previous development target

Windows file/product version: **0.8.1.0** / **0.8.1**.
The operator confirms this version is installed on the development workstation;
that does not declare a public release or validate the pending 0.8.2 correction.

The pairing dialogue groups **Request access** before **Complete pairing**:
choose the workstation name and access before generating/copying the request,
then paste the PBX response and save. Changing name/access invalidates unused
request identities and stale responses. Copy requires successful generation;
Save requires a current validated response. Approved SSH accounts are read-only,
response-derived and shown only for approved SSH. The existing v1 web-only/v2
SSH-capability protocol and independent FreePBX versions remain unchanged.
Portable Release tests cover protocol bindings and source layout; native MFC
regressions are registered but require Windows execution.

Correct native dialogue fixtures to replace multiline response text through
the edit-control path, which emits `EN_CHANGE`, rather than `WM_SETTEXT`, which
does not. Cover web-only Save without an SSH account, invalid/request-mismatched
responses, explicit SSH denial and missing/invalid response-derived accounts.
Web + SSH selection now requires explicit PBX SSH approval before Save; a
web-only reply requires a new Web Access request instead of a silent downgrade.

The generated response is request-bound, not independently signed as an
envelope: its provenance relies on the trusted, administrator-approved HTTPS
exchange. SSH certificates are separately signature-verified at session launch.
No pairing schema or cryptographic trust check was changed.

## 0.8.0 — Previous unreleased development target

Windows file version: **0.8.0.0**. FreePBX module version at preparation: **0.6.3**.
Windows 0.8.0 adds explicit pairing access selection, post-pair policy requests,
identity-preserving migration, SSH elevation and an experimental built-in
managed SSH console with a libvterm screen model and ConPTY resize path.
Earlier operator reports include eleven native SSH integrations and first-run
startup smoke passing, without independently fetched matching logs.
They do not validate subsequent 0.8.1 source changes.
The FreePBX policy and Windows client changes are independently versioned.
No Windows release or build is declared by this entry.

- Replace the SSH opt-in checkbox with an explicit Web access / Web + SSH
  access choice. Continue to omit SSH identity generation for web-only requests.
- Display whether SSH was authorised in saved-profile details.
- Replace successful clipboard-copy dialogues with short-lived inline feedback.
- Display the PBX-applied policy, source list, DNS failures, verified public
  source and actual/max admitted session count. Lock to the PBX-verified
  current IP; request Allowed List changes or unlocking through the authenticated
  session channel, with relaxing changes pending FreePBX approval.
- Apply authenticated listener migration to the saved profile while preserving
  its WireGuard identity. Keep management blocked until admission on the new
  tunnel, and retire the old path only after the PBX acknowledges the migration.
- Generate and persist a protected workstation SSH identity when requesting
  post-pair SSH; apply the account and pinned SSH configuration only after the
  PBX has explicitly approved the request.
- Open managed My PBXs SSH in the built-in TELIPHONES window using the existing
  certificate, pinned host key, isolated agent and owned process job. Add a
  libvterm-backed VT screen, UTF-8 input/output, keyboard/clipboard handling,
  scrollback and a ConPTY path that propagates terminal resizing. Portable
  emulator tests pass; the native MFC/ConPTY and live SSH paths still require
  Windows verification.
- Use temporary confirmation before changing the PBX's listener to Closed.
- Add optional per-connection Connect Password Protection using the existing
  OpenSSL Argon2id provider and AES-256-GCM inside Credential Manager/DPAPI.
  Settings enable/change/disable requires current-password authentication;
  protected Connect always decrypts the credential, regardless of preferences.
- Keep enrolled WireGuard keys off staging/installed configuration files:
  use a public bootstrap identity and PID-bound, local-only UAC-helper IPC
  followed by WireGuard's administrator-only control pipe. Stored configs
  cannot restore the enrolled identity. Preserve DPAPI-only credential mode
  when protection is disabled; no weaker KDF fallback.
- Add portable authentication/tampering, independent-vector and bootstrap
  regressions. New native password/UAC/WireGuard behaviour remains unverified
  until tested on Windows; no dependency was fetched or installed locally.
- Local portable-core tests can validate shared code; native MFC/Win32 UI
  validation requires Windows and has not been performed in this environment.

## 0.7.0 — Previous unreleased development target

Windows file version: **0.7.0.0**. FreePBX module version: **0.4.1**.
The FreePBX-only firewall correction advances the installed/tested module from
0.4.0 to 0.4.1. Windows remains 0.7.0 because no application code changes are
made; this note does not declare a new Windows build or release.
**Evidence reported at the 0.7.0 development stage:** successful Windows Actions builds,
**all ten native OpenSSH integration tests passing**, authenticated Windows
SSH into FreePBX 17 with module 0.4.0, and owned-terminal closure on disconnect.
Run identifiers and raw logs were not supplied here. Complete PBX-side
revocation/expiry/cgroups, reboot/recovery, the all-terminal matrix and real
module 0.4.1 firewall stability remain outstanding. See the
[evidence register](../../docs/SECURITY.md#verification-evidence).

- Correct certificate identity selection: select the certificate directly from
  the isolated memory agent without permitting raw-key authentication or private
  key files. Exercise the shared production protocol with genuine local OpenSSH;
  the subsequent reported Windows run passes nine of ten native tests. Tolerate
  fingerprint rejection only for the deliberately corrupted certificate, and
  require signature rejection and verified key destruction before SSH launch.
  That remaining diagnostic fix is included in the subsequently reported
  ten-of-ten result; the nine-of-ten observation is retained as history.
  Require authenticated readiness
  before crash tests and retain per-client diagnostics. Preserve the unreleased
  0.7.0 target; this is not a new Windows release/distribution. FreePBX was 0.4.0
  for that Windows correction and is now independently updated to 0.4.1.
- Remove the previous DPAPI SSH key save/decrypt and plaintext runtime-key export
  paths. Preserve existing permanent encrypted identities and authorisations.
- Implement Ed25519 session keys in memory using static OpenSSL, with locked seed
  pages and no session-key export API. The per-session named-pipe agent accepts
  only its owned Windows OpenSSH process and signs one account/certificate-bound
  authentication request before destroying the key.
- Restore SSH-capable pairing with a separately DPAPI-protected permanent identity,
  request/2 certificate issuance, independent Ed25519 certificate signature
  verification, pinned host keys and automatic terminal launching.
- Add the TELIPHONES-SSH console helper and non-inheritable kill-on-close Jobs;
  app/helper/SSH exit, disconnect and authorisation expiry end owned sessions.
  Bound uncompleted authentication to 30 seconds; never use the shared agent.
- Keep GUI-only pairing independent of OpenSSH; SSH capability is an unchecked,
  explicit request before generation and still requires PBX approval.
- Name certificate binding validation separately from OpenSSH signature checks;
  test actual rejection of signature tampering without claiming the parser is cryptographic.
- Add the server-side request/2 contract: the permanent paired identity signs a
  challenge, fresh session ID and distinct disposable public key. Reject the old
  reusable-subject issuance contract and duplicate live session IDs/public keys.
- Bind portable certificate checks to the ephemeral subject and session ID,
  pinned CA, principal, source and expiry; test real Linux OpenSSH session isolation.
- Pin the PBX host key and certificate authority from administrator-approved
  pairing; never fall back to passwords, default SSH configuration or host prompts.
- Preserve Remote Support, appearance, layout and the centred licence footer.
- Add native Windows OpenSSH login, process/agent access, concurrent sessions,
  controller/SSH crash, expiry and production DPAPI/API/console/disconnect tests
  to Actions. An earlier reported run executed all ten with seven failures;
  subsequent reports progressed through nine-of-ten to ten-of-ten passing.
  The terminal/reboot matrix and real systemd/FreePBX termination still require
  validation. No physical
  memory/pagefile/SSD-erasure guarantee or production security sign-off is made.

## 0.6.5 — Previous development version (not released)

Windows file version: **0.6.5.0**. FreePBX module version: **0.3.5**.
Native MSVC/MFC compilation and visual validation remain pending.

- Rename the profile-list heading to "Saved connections".
- Balance the footer text spacing between the action buttons and bottom edge
  without increasing the allocated space or moving the buttons.

## 0.6.4 — Previous development version (not released)

Windows file version: **0.6.4.0**. FreePBX module version: **0.3.5**.
Native MSVC/MFC compilation and visual validation remain pending.

- Centre the main-window disclaimer on one regular-weight line with vertical
  spacing. Narrow windows use end ellipsis rather than wrapping; Settings > About
  retains the complete notice.

## 0.6.3 — Previous development version (not released)

Windows file version: **0.6.3.0**. FreePBX module version: **0.3.4**.
Native MSVC/MFC compilation and visual validation remain pending.

- Display the version-derived trademark and GPLv3 statements in a fixed main-window
  footer below the action buttons, with DPI scaling and narrow-window wrapping.
- Retain Settings > About and the existing appearance, layout and connection behaviour.

## 0.6.2 — Previous development version (not released)

Windows file version: **0.6.2.0**. FreePBX module version: **0.3.3**.
Native MSVC/MFC compilation and visual validation of this patch remain pending.

- Use the same selection renderer for full dropdown repainting and native
  owner-draw notifications, with the native selection-field bounds. Remove
  conflicting text/focus rectangles that could appear as overlay boxes.
- Keep closed selection fields on the normal surface colour, clip item drawing
  to its bounds and inset keyboard focus cues while respecting Windows' hidden
  focus state. Dropdown-list selection highlighting remains intact.
- Add native rendering regression cases and update version consistency checks.
  Preserve the 0.6.1 native caption-frame correction and existing layout.
- Add Settings > About with the UK registered trademark statement and Windows
  GPLv3 statement derived from Version.h. Include the disclaimer in the distributed
  README and the existing GPL licence text in the ZIP; no trademark rights are granted.

## 0.6.1 — Previous development version (not released)

Windows file version: **0.6.1.0**. FreePBX module version: **0.3.2**.
Native MSVC/MFC compilation and interactive validation of this patch are pending.

- Preserve native Windows visual styles on captioned windows instead of disabling
  their frame theming when applying client-control colours. Windows retains
  ownership of title bars and minimize/maximize/close buttons; the documented
  DWM dark-title-bar preference remains in use.
- Add a source regression guard for native caption-frame theming. This does not
  establish visual correctness or resolve the separate Chrome download warning.

## 0.6.0 — Previous development version (not released)

Windows file version: **0.6.0.0**. FreePBX module version: **0.3.2**.
Native MSVC/MFC compilation and visual validation remain pending.

- Add Settings > Appearance: System (default), Light and Dark, persisted with the
  existing per-user preferences. Preview changes immediately in all open dialogues;
  Save retains them and Cancel restores the previously saved appearance.
- Follow live Windows application colour changes through the supported WinRT
  UISettings event, marshalled to the UI thread, without touching connection state.
- Centralize application dialogue, list/header, selection, button, checkbox, combo,
  edit, menu, border, scrollbar, message and graph rendering. The main window,
  pairing, Remote Support, Settings, thresholds, health pop-out and Session Log
  share the same palette. Hidden monitors stay hidden when themes change.
- Respect Windows high contrast with native control rendering/system colours;
  retain keyboard behaviour, focus cues and native accessibility roles. OS-owned
  file pickers, title-bar/system decorations on older Windows and security prompts
  remain controlled by Windows rather than private/undocumented dark-mode APIs.
- Add portable preference/policy/contrast tests and native open-dialogue, live
  simulated notification, control/graph pixel, hidden-window and DPI-input tests.
  Simulations do not constitute interactive Windows visual validation.
- Pre-build appearance review: preserve owner-drawn menu mnemonics (including
  duplicates, disabled entries and escaped ampersands), clip PBX text to actual
  header column bounds, update dropdown/selection heights after font/DPI changes
  even in high contrast, and repaint themed scrollbar frames after native
  keyboard/paint/tracking updates. Graph legends describe line/marker patterns
  rather than colours that change with accessibility settings.

## 0.5.2 — Previous development version (not released)

Windows file version: **0.5.2.0**. FreePBX module version: **0.3.2**.
No new native Windows build or live measurements have been validated locally.

- Replace the tall main dialogue with a landscape two-column native layout and
  responsive DPI-aware resizing. The PBX management list and connection/health
  panels use available space; a fixed wrapping action bar keeps connection controls
  accessible, with a vertical scroll viewport, scrollbar, mouse wheel and focus
  reveal when the work area is too small.
- Replace vertically stacked health graphs with selectable latency/jitter,
  upload/download traffic, and failures/interruption plots. Fix traffic graph
  rendering so ordinary two-second probes do not break six-second counter samples.
- Preserve per-profile health history for disconnected review, alongside pairing,
  Remote Support, WireGuard, SSH and session diagnostics behaviour.
- Add native MFC layout, scrolling, command-routing, graph and DPI-input tests to
  the Actions build. Actual Windows rendering/scaling remains to be validated.

## 0.5.1 — Previous development version (not released)

Windows file version: **0.5.1.0**. FreePBX module version: **0.3.2**.

- Correct UTC/monotonic clock separation for authorisation expiry and handshake
  age. Persistent authorisation displays Until revoked; absent evidence is Unknown.
- Integrate health measurements and a shared graph into the main window, retaining
  an independent resizable pop-out and persisted preferences.
- Show current TCP latency, recent jitter and actual interval traffic rates.
  Separate connected duration, authorisation expiry and continuously healthy time.
- Report WireGuard CLI failures and use Windows IP Helper tunnel interface byte
  counters when peer telemetry is unavailable, without fabricating handshake data.
- Add bounded local diagnostics with native viewing/export and correlation to
  administrator-only PBX logs; preserve SSH and profile separation.
- Correct modeless pop-out ownership/visibility, restore minimized windows, recover
  invalid geometry and expose the monitor in the task switcher.
- Add native MFC window lifecycle tests. A successful Actions/MSVC run was not
  verified before the subsequent 0.5.2 interface redesign.

## 0.5.0 — Previous development version (not released)

Windows application version **0.5.0**, independent of the FreePBX module,
which remains **0.3.1**. Windows file version: **0.5.0.0**. This version has
not been published as a release and is not production-ready.

### Added

- Opt-in installation of the official WireGuard x64 MSI using Windows Installer
  and normal UAC, with HTTPS, pinned SHA-256, Authenticode and publisher checks.
- Three-step onboarding: Applications, Secure connectivity, Get started.
- Settings Connectivity section, installation progress, deferral, retry and
  post-install verification without restarting TELIPHONES.
- Compact (approximately 320 x 220 pixels) native Connection Health pop-out
  with local PBX TCP probes, WireGuard peer byte counters and handshake age,
  latency/jitter history, configurable health thresholds, and persistent
  window/history preferences. Reachability warnings are separate from
  authorisation expiry and do not close existing SSH windows.
- Embedded file/product version metadata, a visible version in the main window,
  and build validation of the version information.

### Preserved

- Browser and SSH terminal preferences, local profiles, existing WireGuard
  installations and tunnel configuration.
- The existing PBX pairing, permissions and connection contracts.

### Validation status

The operator reports that the previous 0.4.0 development build runs on a
Windows office PC, establishes a WireGuard tunnel to the FreePBX 17 test PBX
and launches PuTTY, which reaches the SSH server. Web access still requires
disabling FreePBX Firewall in that test, and SSH public-key authentication has
not completed. Disabling the firewall is not an acceptable solution;
compatibility remains unresolved.

Portable tests and source/build-layout checks are available locally; they are
not native MSVC/MFC compilation. Installer/UAC behaviour, the full UI/lifecycle
matrix, firewall-enabled web access and authenticated SSH still require
validation. This operator test is not a published release or proof of production
readiness. A successful Actions build is not an end-to-end installation test.

## 0.4.0 — Previous development version (not released)

This was the prior unreleased Windows development version. The operator tested
that build's WireGuard tunnel and PuTTY connectivity on a Windows office PC.
It did not include the Connection Health monitor, and it was never published
as a release.

## Earlier development — no dependable Windows version identifiers

These are source-history milestones, **not published Windows releases**:

| Source revision | Changes |
|---|---|
| `31ab8e1` | Corrected SDK header ordering for `ShellExecuteW`, explicitly included common-dialogue declarations and strengthened build-layout checks. |
| `c80619e` | Added browser and SSH terminal preferences, first-run application setup and persistent user settings as part of the 0.3.0 milestone. |
| `2c8bb22` | Added Windows workstation pairing and direct WireGuard PBX access with administrator-controlled SSH. |
| `3f451f1` | Corrected duplicate DPI manifest declarations and added regression checks. |
| `54e1dba` | Corrected amd64 SideBySide identities and expanded native executable/manifest diagnostics. |

## Versioning policy

- [Version.h](src/app/Version.h) is the authoritative Windows version definition.
- Use plain numerical application versions: the current product/display version
  is `0.6.0` and the Windows fixed numeric file/product version is `0.6.0.0`.
  Do not add development suffixes or change the version for individual
  development builds. Actions records the Git commit SHA, run identity and
  executable SHA-256 alongside the version to distinguish build provenance.
- Keep the window title, executable metadata, README and current changelog entry
  consistent. Automated checks reject mismatches.
- The FreePBX module version is independent and is **0.4.1**. The manifest's
  fixed assembly identity is not a release version and must not be bumped merely
  to change the product version.
- An application version does not imply publication or production readiness.
  Keep the entry marked Unreleased until an actual release. The executable's
  prerelease flag reflects this unreleased status without changing its numerical
  version; publication requires an explicit release decision and updates to
  the changelog, resource flags and validation.
- New features increment the minor version; bug fixes increment the patch version.
  Preserve previous version history when advancing either.
- Windows 0.7.0 introduces managed My PBXs SSH certificates. The 0.6.x history
  remains unchanged; the new functionality is not retrospectively part of 0.6.0.
