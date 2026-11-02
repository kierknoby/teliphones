# TELIPHONES for Windows: change history

This is the Windows application's history, not the FreePBX module release list.
No Windows release is declared published by this document. Earlier development
builds lacked embedded file/product versions and cannot be assigned reliable
version numbers retrospectively.

## 0.4.0 — Unreleased

First explicitly identified Windows application version, independent of the
FreePBX module, which remains **0.3.0**. Windows file version: **0.4.0.0**.
This version has not been published as a release and is not production-ready.

### Added

- Opt-in installation of the official WireGuard x64 MSI using Windows Installer
  and normal UAC, with HTTPS, pinned SHA-256, Authenticode and publisher checks.
- Three-step onboarding: Applications, Secure connectivity, Get started.
- Settings Connectivity section, installation progress, deferral, retry and
  post-install verification without restarting TELIPHONES.
- Embedded file/product version metadata, a visible version in the main window,
  and build validation of the version information.

### Preserved

- Browser and SSH terminal preferences, local profiles, existing WireGuard
  installations and tunnel configuration.
- The existing PBX pairing, permissions and connection contracts.

### Validation status

Portable tests and source/build-layout checks are available locally. Native
MSVC/MFC compilation, installer/UAC behaviour, UI layout and actual PBX
connectivity require Windows testing. A successful Actions build is not an
end-to-end installation or connectivity test.

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
  is `0.4.0` and the Windows fixed numeric file/product version is `0.4.0.0`.
  Do not add development suffixes or change the version for individual
  development builds. Actions records the Git commit SHA, run identity and
  executable SHA-256 alongside the version to distinguish build provenance.
- Keep the window title, executable metadata, README and current changelog entry
  consistent. Automated checks reject mismatches.
- The FreePBX module version is independent and remains **0.3.0**. The manifest's
  fixed assembly identity is not a release version and must not be bumped merely
  to change the product version.
- An application version does not imply publication or production readiness.
  Keep the entry marked Unreleased until an actual release. The executable's
  prerelease flag reflects this unreleased status without changing its numerical
  version; publication requires an explicit release decision and updates to
  the changelog, resource flags and validation.
