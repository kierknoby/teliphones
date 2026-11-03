# TELIPHONES for Windows: change history

This is the Windows application's history, not the FreePBX module release list.
No Windows release is declared published by this document. Earlier development
builds lacked embedded file/product versions and cannot be assigned reliable
version numbers retrospectively.

## 0.6.5 — Unreleased

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
- Retain Settings > About and the existing appearance, layout and connection behavior.

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
  existing per-user preferences. Preview changes immediately in all open dialogs;
  Save retains them and Cancel restores the previously saved appearance.
- Follow live Windows application colour changes through the supported WinRT
  UISettings event, marshalled to the UI thread, without touching connection state.
- Centralize application dialog, list/header, selection, button, checkbox, combo,
  edit, menu, border, scrollbar, message and graph rendering. The main window,
  pairing, Remote Support, Settings, thresholds, health pop-out and Session Log
  share the same palette. Hidden monitors stay hidden when themes change.
- Respect Windows high contrast with native control rendering/system colours;
  retain keyboard behavior, focus cues and native accessibility roles. OS-owned
  file pickers, title-bar/system decorations on older Windows and security prompts
  remain controlled by Windows rather than private/undocumented dark-mode APIs.
- Add portable preference/policy/contrast tests and native open-dialog, live
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

- Replace the tall main dialog with a landscape two-column native layout and
  responsive DPI-aware resizing. The PBX management list and connection/health
  panels use available space; a fixed wrapping action bar keeps connection controls
  accessible, with a vertical scroll viewport, scrollbar, mouse wheel and focus
  reveal when the work area is too small.
- Replace vertically stacked health graphs with selectable latency/jitter,
  upload/download traffic, and failures/interruption plots. Fix traffic graph
  rendering so ordinary two-second probes do not break six-second counter samples.
- Preserve per-profile health history for disconnected review, alongside pairing,
  Remote Support, WireGuard, SSH and session diagnostics behavior.
- Add native MFC layout, scrolling, command-routing, graph and DPI-input tests to
  the Actions build. Actual Windows rendering/scaling remains to be validated.

## 0.5.1 — Previous development version (not released)

Windows file version: **0.5.1.0**. FreePBX module version: **0.3.2**.

- Correct UTC/monotonic clock separation for authorization expiry and handshake
  age. Persistent authorization displays Until revoked; absent evidence is Unknown.
- Integrate health measurements and a shared graph into the main window, retaining
  an independent resizable pop-out and persisted preferences.
- Show current TCP latency, recent jitter and actual interval traffic rates.
  Separate connected duration, authorization expiry and continuously healthy time.
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
  authorization expiry and do not close existing SSH windows.
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
| `31ab8e1` | Corrected SDK header ordering for `ShellExecuteW`, explicitly included common-dialog declarations and strengthened build-layout checks. |
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
- The FreePBX module version is independent and is **0.3.5**. The manifest's
  fixed assembly identity is not a release version and must not be bumped merely
  to change the product version.
- An application version does not imply publication or production readiness.
  Keep the entry marked Unreleased until an actual release. The executable's
  prerelease flag reflects this unreleased status without changing its numerical
  version; publication requires an explicit release decision and updates to
  the changelog, resource flags and validation.
- New features increment the minor version; bug fixes increment the patch version.
  Preserve previous version history when advancing either.
- Windows 0.7.0 is reserved for the upcoming fully automated SSH
  authentication functionality. That functionality is not part of 0.6.0.
