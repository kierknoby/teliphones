# Windows developer builds, testing and readiness

Targets: TELIPHONES for Windows **0.8.0**, TELIPHONES for FreePBX **0.6.1**.
The FreePBX connection-state policy and Windows pairing/clipboard UX are
independently versioned; neither entry declares a published release.

## Current evidence

### Encoding object collision and embedded-console authentication fix

The MFC project assigns libvterm's `encoding.c` the object filename
`$(IntDir)libvterm_encoding.obj`, distinct from the default `Encoding.obj`
produced by the application's `Encoding.cpp`. The project-layout suite expands
the current explicit and wildcard source lists for every Visual Studio project
and checks object paths case-insensitively in Debug and Release. Its negative
control removes this override and reproduces the encoding collision.

The reported embedded-console failure was not a rejected SSH login: the client
authenticated, opened an interactive session and displayed a prompt. The
controller was trying to read the OpenSSH `-E` diagnostic file while the client
still held it open; Windows returned file-not-found before creation and a
sharing violation while the writer was active. Seeing the marker only after
the client exited did not provide a usable live signal.

The embedded console now enables a fixed companion-helper `LocalCommand`.
OpenSSH executes it only after successful authentication; it signals a
per-session named event whose ACL is limited to SYSTEM and the current user.
The controller reads this event rather than opening the live log, so a failed
or unconfirmed authentication remains unauthenticated. The diagnostic file is
retained for post-exit evidence, when its writer has closed. LocalCommand stays
disabled for non-embedded sessions. The existing native test still requires
the real command result through the production input path, checks input byte
counts, exercises resize and disconnect, and now corroborates the signalled
state with OpenSSH's diagnostic marker after teardown. A Windows run remains
necessary to validate the native signal and input/resize path.

The generated OpenSSH configuration lives in the active attempt directory
below the profile's SSH runtime directory and is removed when the owned session
ends. The production integration test inspects its non-secret LocalCommand
settings only after the interactive session is confirmed and before teardown.

Connect Password Protection's portable positive path has been verified in this
Codespace using the locally available OpenSSL 3.5.8 Argon2id provider: the
independent interoperability vector, authenticated encryption/decryption,
wrong-password rejection, envelope tampering checks and bootstrap-config
checks passed. A separate system-OpenSSL 3.0.13 run verified fail-closed
behavior when Argon2id is absent. No dependency was fetched or installed.
First-use Set Password / Skip This Time / Skip Permanently, Settings > Security
controls, existing-password checks and the credential-removal/re-pair recovery
flow are implemented in source. This does **not** validate the native MFC,
Credential Manager, DPAPI, UAC, named-pipe or WireGuard UAPI path. Before
release, test enable/change/remove/cancel/wrong password, first Connect,
tampered credential envelopes, cleanup refusal, UAC cancellation (including
another administrator account), key-pipe PID/remote-client rejection, UAPI
failure and helper crash. Inspect staging/installed configs for absence of the
enrolled key; restart the stored service and verify it cannot handshake as the
enrolled workstation until another successful password-authenticated Connect.
Verify DPAPI-only profiles still connect and protected keys cannot unlock on a
no-Argon2 build.

Broker-managed session leases, authenticated listener migration,
identity-preserving Windows profile updates, Allowed List/unlock approval
requests and post-pair SSH elevation are covered by portable gateway and core
regressions. The Linux CTest suite passed 9/9; the gateway suite passed 184
tests and the FreePBX suite passed. These checks do not compile the MFC
application or validate Windows Credential Manager, DPAPI, UAC, the WireGuard
service lifecycle, or actual migration/reconnect. Native Windows and live
FreePBX Firewall/session/SSH acceptance remain outstanding.

The operator reports successful Windows Actions builds, **all ten native
OpenSSH integration tests passing**, authenticated Windows-to-FreePBX 17 SSH
and automatic owned-terminal closure on disconnect. No run URL, commit/build
hash or raw logs were supplied with this update; no remote logs were fetched.
Earlier nine-of-ten and seven-failure records below are historical.

These are initial native/live milestones, not complete server-side revocation,
expiry, systemd/cgroup, reboot or recovery evidence. Real module 0.4.1 firewall
watchdog validation, the full terminal/display matrix and production readiness
remain outstanding. See the [evidence register](../../../docs/SECURITY.md#verification-evidence).

The current source registers eight Windows CTests (nine on Linux) and eleven
native SSH integration methods. The operator report above predates the latest
native console test; the current-source Windows build and test suite have not
been run in this workspace.

## Developer builds and testing

This section preserves the detailed build and test reference formerly in the Windows README. Commands below run from `desktop/windows/`. Test registration describes coverage, not execution evidence; see [verification evidence](../../../docs/SECURITY.md#verification-evidence) for the current results and remaining gates.


- Windows 10/11 x64.
- Visual Studio 2022 with the **Desktop development with C++** workload, Windows 10/11 SDK, and the optional **C++ MFC for latest v143 build tools (x86 & x64)** component.
- Static OpenSSL 3 Crypto, declared in `vcpkg.json`, for maintained Ed25519 generation/signing/verification. Set `VCPKG_INSTALLATION_ROOT` to an existing vcpkg installation; `build.ps1` restores the manifest's `x64-windows-static` dependency. For direct MSBuild, restore it first from this directory or supply `OpenSslRoot`. No dependencies were downloaded during local implementation.
- WireGuard for Windows is required for pairing and connections. TELIPHONES can retrieve and verify the official installer after you choose **Install WireGuard**, then ask for administrator approval through UAC. Existing verified installations are reused unchanged. WireGuard is not bundled.
- GUI-only My PBXs pairing requires no OpenSSH. **FreePBX Web Access** is selected by default; **FreePBX Web + SSH Access** enrols the separate persistent workstation identity, encrypted with user DPAPI. Open SSH requires the Windows system OpenSSH Client and PowerShell, PowerShell 7, Windows Terminal or Command Prompt; PuTTY is not supported for managed certificates. Remote Support keeps its separate workflow.

Open `TELIPHONES.sln` in Visual Studio, select **x64**, then build. Or run `build.ps1` in a Visual Studio 2022 Developer PowerShell:

```powershell
.\build.ps1 -Configuration Release -Platform x64
```

The application and portable tests are written to `build\Release\`. Run `build\Release\TeliphonesCoreTests.exe` and `build\Release\SessionDiagnosticsTests.exe` for the core and diagnostic-storage regressions. The portable tests and broker contracts can also be run on Linux with CMake:

```sh
cmake -S . -B build/core
cmake --build build/core
ctest --test-dir build/core --output-on-failure
```

### Reproducible native Windows build and validation

Run from the repository root in an x64 Visual Studio 2022 Developer PowerShell.
The machine needs the v143 toolset, Windows SDK, static MFC, Python, CMake,
OpenSSH Client/Server and the repository's declared static OpenSSL dependency.
If the OpenSSL manifest is not already restored, the `vcpkg install` command
below can access external package sources; obtain approval before running it
when that would fetch dependencies.

```powershell
$env:VCPKG_INSTALLATION_ROOT = 'C:\path\to\existing\vcpkg'
Push-Location desktop/windows
try {
    & "$env:VCPKG_INSTALLATION_ROOT\vcpkg.exe" install --triplet x64-windows-static --disable-metrics
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL restore failed.' }
} finally {
    Pop-Location
}

msbuild desktop/windows/TELIPHONES.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64 /verbosity:minimal
if ($LASTEXITCODE -ne 0) { throw 'Visual Studio solution build failed.' }

& desktop/windows/build/Release/TeliphonesCoreTests.exe
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }
& desktop/windows/build/Release/SessionDiagnosticsTests.exe
if ($LASTEXITCODE -ne 0) { throw 'Session diagnostics tests failed.' }
& desktop/windows/build/Release/HealthWindowTests.exe
if ($LASTEXITCODE -ne 0) { throw 'MFC window tests failed.' }
```

For native SSH/ConPTY process and PTY tests, use an elevated disposable
Windows 10/11 machine. The OpenSSH provisioning script uses Windows capability
servicing and may change installed system capabilities. The fixture creates a
temporary SYSTEM task and loopback-only SSH server; it does not use a production
PBX or change the global sshd service.
The native Release configuration enables interprocedural optimization so MSVC
compiles with `/GL` and links with `/LTCG` for the tested native targets.

```powershell
.\desktop\windows\tests\provision_openssh.ps1
$toolchain = Join-Path $env:VCPKG_INSTALLATION_ROOT 'scripts\buildsystems\vcpkg.cmake'
$installed = Join-Path (Get-Location) 'desktop\windows\vcpkg_installed'
cmake -S desktop/windows -B desktop/windows/build/ssh-native -A x64 `
  "-DCMAKE_TOOLCHAIN_FILE=$toolchain" "-DVCPKG_INSTALLED_DIR=$installed" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON
if ($LASTEXITCODE -ne 0) { throw 'Native SSH CMake configuration failed.' }
cmake --build desktop/windows/build/ssh-native --config Release
if ($LASTEXITCODE -ne 0) { throw 'Native SSH host build failed.' }
& desktop/windows/build/ssh-native/Release/ssh_native_host.exe --preflight
if ($LASTEXITCODE -ne 0) { throw 'Native security preflight failed.' }
ctest --test-dir desktop/windows/build/ssh-native -C Release --verbose --output-on-failure --no-tests=error
if ($LASTEXITCODE -ne 0) { throw 'Native CTest suite failed.' }
python -u desktop/windows/tests/ssh_native_check.py desktop/windows/build/ssh-native/Release/ssh_native_host.exe --fixture-preflight
if ($LASTEXITCODE -ne 0) { throw 'Native SSH fixture preflight failed.' }
python -u desktop/windows/tests/ssh_native_check.py desktop/windows/build/ssh-native/Release/ssh_native_host.exe -v
if ($LASTEXITCODE -ne 0) { throw 'Native SSH integration tests failed.' }
```

After a fixture interruption, run its exact recorded cleanup command before
reusing the test host:

```powershell
python desktop/windows/tests/ssh_native_check.py desktop/windows/build/ssh-native/Release/ssh_native_host.exe --cleanup-only
```

The automated PTY test does not replace manual GUI validation. On Windows,
connect only to a disposable authorised PBX and exercise cursor/colour
rendering, `top`, `nano`/`vim`, UTF-8 input/output, window resize, clipboard,
Alt+F4, reconnect, disconnect, password protection and revocation.

### GitHub Actions build and download

The [Windows build workflow](../../../.github/workflows/windows-build.yml) builds the existing Visual Studio solution in **Release x64** on a GitHub-hosted `windows-2022` runner. It runs automatically when changes under `desktop/windows/` or the workflow itself are pushed. It can also be run from **Actions > Windows build > Run workflow** once the workflow is available on the repository's default branch.

The workflow discovers Visual Studio 2022 with `vswhere`, verifies the installed x64 MSVC tools, static Unicode MFC libraries and Windows SDK, and reports the selected versions. If anything is missing, it fails with the missing component or file path; it does not install Visual Studio components, drivers or other dependencies.

The workflow runs standard-library Python project/resource layout checks, explicitly provisions missing official Windows OpenSSH Client and Server capabilities using Windows servicing, restores static OpenSSL, and builds the application and its `TELIPHONES-SSH.exe` console helper. Capability state is re-queried, reboot requirements rejected and actual executable loading checked; versions/hashes and servicing failures are reported. The Windows OpenSSH directory is placed first on PATH. No alternate package is downloaded if servicing fails.

It also builds the production cryptographic/agent/session code with CMake, performs native DPAPI/locked-memory/pipe/Job preflight and runs real OpenSSH tests. The loopback-only server uses a unique temporary SYSTEM scheduled task and kill-on-close Job for Windows logon-token support, not the global sshd service. Generated test keys/configuration and all owned processes are cleaned up, including an always-run interrupted-fixture recovery step. A separate test-only core permits exactly the loopback fixture source; the application and production core tests retain their non-loopback policy. Successful native credential-provider/OpenSSH validation is still required; portable success alone is insufficient. Existing core, diagnostics, PE/manifest and malformed tunnel-helper checks remain. This is not an interactive GUI or WireGuard integration test. See the [complete execution-order and sixteen-test readiness audit](#historical-investigations) for dependencies, cleanup and remaining native/systemd validation.

Windows CTest runs `connect_protection`, `terminal_emulator`, `core_tests`,
`session_diagnostics`, `build_layout`, `contract_check`, `managed_ssh_check`
and `ssh_crypto_check`. The portable
`contract_check` verifies client pairing schemas, response/key/nonce binding,
profile/tunnel rendering, route rejection, fingerprints and parity with the
gateway's portable Remote Support renderer without importing the root broker.
Linux additionally runs `broker_contract_check`, preserving the complete real
broker approval/revocation and peer/firewall contract tests with privileged OS
operations doubled. The broker imports Linux-only `fcntl` and `pwd`; it is not
loaded in Windows tests. Python is required by CMake so these checks cannot
silently disappear.

After CTest, Windows runs all eleven tests in `ssh_native_check.py`: actual
OpenSSH login/key destruction/public-only runtime files, unrelated-process agent
denial, process-memory/handle restrictions, concurrent-session isolation and wrong
certificates, expiry/wrong host/tampering, controller crash, SSH crash, production
DPAPI/certificate API/console/disconnect, certificate refusal and local
authorisation expiry. The workflow fails on native test failure; it does not
replace those checks with the portable suite. Real FreePBX/systemd and reboot
validation remain separate outstanding requirements.

Portable CTest and native SSH integration are separate steps. If CTest fails,
native SSH tests still execute when their build, OpenSSH and Win32 preflight
prerequisites and the real isolated-fixture preflight succeeded. That preflight
uses the integration fixture itself: complete SID-based protected DACL replacement
and separate owner assignment,
native Win32/Task Scheduler read-back of file/task security descriptors, actual
negative ACL probes, generated keys/configuration, a
temporary SYSTEM task, real loopback SSH banner and verified shutdown/removal.
It preserves all ten authentication/security tests; it does not replace them.
Actual Windows ACL/task execution remains unverified locally. Independent window, executable and startup checks also
continue after test failures when their build succeeded. Any required failure
still fails the job and prevents application artifact publication. Full verbose
CTest/unittest output, CTest JUnit and native SSH logs are retained in the
diagnostics artifact on success or failure. The [readiness audit](#historical-investigations)
records the reproduced three-assertion CRT output defect and its helper-only fix.
The fixture no longer invokes PowerShell for ACL, identity or task inspection.
A separate diagnostic step records inherited versus reset Windows PowerShell
module discovery; its loader results are not used as security-test results.

The x64 manifest uses explicit `amd64` application and Common Controls version 6 identities. The workflow extracts and prints the actual embedded manifest, validates it using the SDK's `mt.exe`, and requires exactly one matching Common Controls dependency after linker manifest merging. It preserves `asInvoker`, `uiAccess="false"` and the DPI settings. The project disables automatic DPI manifest generation so the custom manifest is the sole source: exactly one legacy `dpiAware` (`true/pm`) and one modern `dpiAwareness` (`PerMonitorV2`) declaration, checked in the embedded manifest by Actions. The startup smoke test must launch both malformed helper invocations and receive exit code 2 (argument rejection before elevation/networking); a loader error or timeout fails the run.

If startup fails with an incorrect side-by-side configuration, the workflow prints the `sxstrace` activation trace and recent Windows Application **SideBySide** events. Download **TELIPHONES-Windows-startup-diagnostics** from that failed run for the extracted manifest, DLL import list, startup error and available trace/event files. Diagnostic-tool failures are reported and do not bypass the executable startup test. The application artifact is uploaded only after all validation succeeds. A manifest correction is not Windows-validated until a new run passes the real smoke test.

Download **TELIPHONES-Windows-x64** only from a successful run. It contains `TELIPHONES.exe`, the required adjacent `TELIPHONES-SSH.exe`, this README, the changelog, `LICENSE`, `OpenSSL-LICENSE.txt` and `build-info.json`; no keys, profiles or runtime configurations are included. Keep both executables together. OpenSSL is statically linked, not a separately installed DLL. Build information records the source/Actions provenance and hashes of both executables. Existing embedded-version/prerelease checks remain. Artefacts are retained for 14 days; the workflow creates no release and deploys nothing. No new native artifact has been validated locally.

Extract the artifact and run `TELIPHONES.exe` on Windows 10/11 x64. Release builds statically link MFC and the MSVC C/C++ runtime (`/MT`), so no separate Visual C++ Redistributable or MFC DLL is expected; Windows system DLLs remain required. No .NET runtime is used. The application offers [WireGuard installation](../README.md#secure-connectivity-and-wireguard-installation) if needed. OpenSSH-backed terminals require the Windows system OpenSSH Client; only Remote Support supports PuTTY. Unsigned test executables may trigger Windows SmartScreen; the workflow does not code-sign them.


## Test coverage and manual validation


The C++ core tests and contract tests check parsing, key/request binding, grant binding, narrow host routes, tunnel rendering, command construction, connection monitor behavior, and parity with the broker/gateway contracts. They also simulate health threshold persistence, WireGuard counter parsing, latency/jitter/rate calculations, stable/degraded/unstable/disconnected/unknown transitions, bounded 60-second/5-minute history, and recovery after measurement interruptions. These are deterministic model tests, not live WireGuard measurements. They also simulate browser and terminal preferences: first-run save, skip and cancel; detection-driven choices and defaults; saving, restoring and changing preferences; missing and mismatched applications; and the exact command line for each supported browser and terminal, including paths with spaces and rejection of unsafe arguments. They do not execute Win32 APIs, so registry detection, the dialogs and real application launches are untested on Linux.

The build-layout checks also verify SDK header ordering (`Win.h`, which includes `windows.h`, before `shellapi.h`), the Settings dialog's explicit `commdlg.h` include, and the required shell, file-dialog and registry libraries in both native build configurations. These are source checks, not a substitute for compiling and linking with MSVC, MFC and the Windows SDK.

Appearance regressions cover all three persisted modes, legacy preferences,
strict invalid-value rejection, simulated system/high-contrast policy and measured
palette contrast (4.5:1 normal/status/selection text; 3:1 graph series and disabled
text). `HealthWindowTests.exe` additionally exercises real MFC dialog resources,
buttons, dropdowns, menus, message response codes, hidden pop-outs and graph pixel
output with 96/120/144/192 DPI font/layout inputs. Its system/accessibility change
events are simulated through the same UI-thread notification handler, without
activating the real WinRT event provider in the test executable. It does not
change Windows settings and is not an interactive visual or real DPI-transition
test. Actions builds and runs it; no native appearance validation has been
performed in the Linux workspace.

The pre-build review also adds native regressions for owner-drawn menu mnemonics
(including duplicate/disabled/escaped entries), PBX column text clipping and
high-contrast combo item/selection sizing after font changes. Scrollbar frames are
repainted after native keyboard, paint and tracking updates. Graph legends name
line/marker patterns so they remain accurate in high contrast. These native tests
are registered for Actions; their individual results have not been independently
audited from the supplied aggregate build/SSH report.

Portable installer tests simulate existing/missing/untrusted installations, approval and deferral, successful installation, UAC refusal, MSI cancellation, download/verification/launch errors, success followed by failed detection, restart requests, cleanup failures and retry. Native source checks guard the official source/hash, verification policy, project dependencies, onboarding wiring and the absence of profile/tunnel mutation. They do **not** execute WinHTTP, Authenticode, UAC or MSI, and do not prove a successful live Windows installation.

The following require real Windows and a disposable FreePBX/gateway environment:

1. Build the Visual Studio solution with the selected Visual Studio/MFC components.
2. Install and signature-check the expected WireGuard for Windows distribution; verify `wg.exe` availability and CLI behavior.
3. Approve a UAC prompt and validate tunnel service installation, ACLs, start, stop, and removal, including cancellation and an over-the-shoulder administrator account.
4. Verify Credential Manager persistence, profile file permissions, multiple profiles, and cleanup.
5. Pair with a disposable FreePBX 17 system, test HTTP/HTTPS redirection, selected UDP forwarding and FreePBX Firewall behavior, and confirm the PBX's interface and peer are removed on revocation/expiry.
6. Test Remote Support only with an explicitly enrolled test engineer key, a current grant and an authorised disposable session. Confirm gateway policy blocks access after expiry/revocation.
7. Test direct connectivity across representative NAT/firewall configurations. No universal NAT traversal or relay is implemented.
8. Test application preferences:
   - Check the welcome dialog's Save, Skip and Cancel.
   - Confirm detection of each installed browser and terminal, including per-user and 32-bit installs.
   - Use **Locate...** with a portable PuTTY.
   - Confirm preferences persist across a restart and an update.
   - Confirm **Open FreePBX** works with each browser.
   - Confirm Remote Support **Open SSH** works with each terminal. Confirm managed My PBXs works with each OpenSSH-backed terminal and the adjacent console helper, including profile paths with spaces/Unicode; PuTTY must fail explicitly.
   - Uninstall or rename a selected application and confirm the error and recovery choices.
   - Confirm Open SSH stays unavailable without SSH approval.
9. On disposable fresh Windows 10/11 x64 machines, test the complete installer UI with a standard user and a separate administrator account, cancellation/UAC refusal, blocked downloads and revocation servers, unexpected signatures/hashes, post-install detection, retries, safe temporary-file cleanup and connection controls becoming available. Repeat with WireGuard already installed and confirm profiles, preferences and pre-existing tunnels remain unchanged. No live Windows installer validation has been performed locally.
10. With a disposable PBX and Windows workstation, verify the Connection Health dialog's resize, position/topmost/history/threshold persistence, sampling responsiveness, measured WireGuard counters/handshake age, disconnected/recovery states, network changes, and temporary authorization expiry. Compare displayed rates and TCP measurements with local Windows/WireGuard observations. Confirm an existing SSH terminal remains open during degradation and that no stale PBX address is probed. Linux tests only simulate the health algorithms; they do not establish native UI responsiveness or real Windows telemetry behavior.
11. Compare the integrated and pop-out graphs at both history lengths; test persistent Until revoked and temporary UTC expiry with a fresh workstation uptime. As a standard user, verify exact-interface IP byte counters and the actual WireGuard CLI diagnostic reason. Export both sides' logs, check matching `ws-` identifiers and clock differences, exercise concurrent instances/rotation/retention, and verify another Windows user and a non-administrator FreePBX session cannot read them. Access-control/GUI tests here are not a substitute for this native/live exercise.
12. On Windows 10 and 11, test System/Light/Dark at 100%, 125%, 150% and 200%
    scaling on 1024x768, 1366x768 and 1920x1080 work areas, including moving between
    differently scaled monitors. Open Settings, pairing, Remote Support, thresholds,
    Session Log and the pop-out together; switch Windows' **application** theme in
    System mode and verify immediate updates, no white flashes, readable controls,
    selected PBX rows, disabled actions, dropdown lists, scrolling and all graph
    modes. Repeat with high contrast enabled/disabled and keyboard-only navigation.
    Save/restart to verify persistence; Cancel to verify preview rollback. Repeat
    while connected/disconnected and with temporary, expired and persistent access:
    theme changes must leave connection timers, authorisation, monitoring, history,
    SSH windows and tunnel state unchanged. This manual matrix is still pending.

No Windows executable is included in the module package. The operator reports
successful Actions builds, all ten native SSH tests and an initial authenticated
Windows SSH session into FreePBX 17, with owned-terminal closure on disconnect.
The complete UAC, Credential Manager, WireGuard lifecycle, display and
server-side revocation/expiry matrix is not established by that report.
The Linux workspace has no MSVC, MFC or Windows SDK; its tests do not prove
native compilation. Existing Actions artefacts remain subject to retention.

## WireGuard installer verification


TELIPHONES uses the built-in **Windows Installer**, not a shell script or an assumed WinGet configuration:

1. Only the explicit **Install WireGuard** button starts retrieval.
2. WinHTTP retrieves the fixed official x64 MSI over HTTPS, using normal Windows certificate validation and proxy discovery. Redirects are refused. Downloads have time and size limits.
3. The file is placed in a new, randomly named directory under `%LOCALAPPDATA%\TELIPHONES\Installer-*`, with a protected ACL for the current user, SYSTEM and administrator read access. Existing files are never reused.
4. TELIPHONES checks the pinned SHA-256, then uses `WinVerifyTrust` to verify Authenticode trust and certificate revocation, and checks that both the signer's common name and organisation are **WireGuard LLC**. Verification failure prevents execution; revocation-service access may be required.
5. The verified file stays locked against writes/deletion while the system `msiexec.exe` is launched with the normal UAC `runas` mechanism. The MSI uses basic Windows Installer progress and cancellation UI, `DO_NOT_LAUNCH=1` and `/norestart`. TELIPHONES also shows retrieval, verification and installation stages without freezing the dialog.
6. After Windows Installer exits, TELIPHONES checks again for `wireguard.exe` and `wg.exe` and verifies their signatures using the existing detection path. An exit code of zero is not sufficient. The readiness indicator and connection controls refresh without restarting TELIPHONES. A requested Windows restart is reported, not performed automatically.
7. Normal completion, cancellation and failure all attempt targeted file and directory cleanup. Cleanup failures are reported. Abrupt process termination or Windows shutdown may leave a private installer directory; TELIPHONES does not recursively remove unrelated files or sweep other installations.

The reviewed package is **WireGuard for Windows 1.1.1, x64**:

- Official MSI: `https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi`
- SHA-256: `7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242`
- Expected Authenticode publisher common name and organisation: `WireGuard LLC`

Historical source checks, not repeated during this documentation review: the [official installation page](https://www.wireguard.com/install/), [WireGuard enterprise installation guidance](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md), the [Microsoft WinGet x64 installer manifest](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/w/WireGuard/WireGuard/1.1.1/WireGuard.WireGuard.installer.yaml) and [Windows Installer command-line documentation](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options). The official MSI was downloaded for read-only inspection: its hash matched the manifest and its embedded signer certificate named WireGuard LLC. This was **not** Windows Authenticode trust validation or an installation test.

The fixed package avoids silently following an unreviewed newer release. If it is withdrawn, changes hash or fails signature verification, installation stops until the application is updated with a reviewed package. Integrated installation requires native Intel/AMD x64 Windows; it refuses an emulated x64 application on ARM64. TELIPHONES does not update, uninstall or repair an existing installation, change existing WireGuard tunnels, synchronise profiles or change PBX pairing. No WireGuard installer or binary is redistributed in TELIPHONES.


## Native appearance implementation


**Settings > Appearance** offers **System (follow Windows)**, **Light** and
**Dark**. System is the default, including when reading older preferences.
Changes preview immediately in the main window and all open TELIPHONES dialogs,
including pairing, Remote Support, Settings, thresholds, Session Log and the
Connection Health pop-out. **Save** persists the choice; **Cancel** restores the
previously saved choice. Welcome's **Save & Next** and **Skip** retain it too.

The shared native renderer covers backgrounds, text, disabled controls, lists and
selection, headers, buttons, checkboxes, dropdowns, menus, borders, scrollbars and
graph series. Theme switching does not recreate connection objects, clear history,
stop monitoring, restart a tunnel or change authorisation. Closed/hidden monitors
stay closed/hidden and use the latest appearance when reopened.

System uses the supported Windows Runtime `UISettings.ColorValuesChanged` event
and reads Windows' application foreground colour; notifications are marshalled
to the UI thread. Windows accessibility/high-contrast colours override every
appearance preference, with native control rendering (owner-drawn dropdown items
and graphs use the same system palette). Keyboard/focus and standard control
accessibility roles are retained; graph line patterns and textual state labels
do not rely on colour alone. Metrics/spacing follow the existing DPI-aware layout.
No private dark-mode ordinals, external services or third-party UI libraries are
used. Windows-owned file pickers, UAC, credential prompts and unsupported older
Windows title-bar decorations remain OS-rendered; TELIPHONES does not attempt to
override security/system UI. The documented dark title-bar attribute is optional
on older Windows 10 builds.

New dialogs must derive from `CAppearanceDialog`; runtime-created content windows
enrol through `tlp::ui::ThemeWindow`. Rendering and environment notifications live
in `src/app/Appearance.cpp`, with portable preferences/palettes in
`src/core/Appearance.h`. New features advance the minor Windows version; fixes
advance the patch version. Windows 0.7.0 introduces managed My PBXs SSH certificates.
The credential provider is implemented in source; native integration success is now operator-reported; the complete display and lifecycle matrix remains pending. Provider errors fail closed rather than using plaintext session-key files.


## Connection Health implementation and measurements


The main window starts at approximately **1050 x 620 logical pixels**, scaled for the current DPI and clamped to the monitor work area. The left column contains the profile list, pairing/removal, Remote Support/grant actions and selected-profile details. The right contains connection status, distinct connected/authorization/healthy durations, measurements, the live graph, **Pop Out** and **View Session Log**. The list and graph grow with the window. Under narrow/high-DPI work areas the columns stack in a vertically scrollable viewport, with scrollbar, mouse wheel and automatic keyboard-focus reveal. **Connect**, **Disconnect**, **Open FreePBX**, **Open SSH**, **Settings** and **Close** remain in a fixed wrapping action bar outside that viewport. Read-only details and diagnostic guidance can also be scrolled/copied rather than being silently truncated. The main window does not restore stale saved geometry; each launch is positioned within the current work area, and DPI transitions relayout controls and fonts.

The main window shows the selected PBX's health, current TCP latency, recent jitter, application probe failures, upload/download rates, handshake freshness and continuously healthy duration. A plot selector switches between **Latency & jitter**, **Upload / download** and **Failures & interruptions**, using one compact plot instead of vertically stacked graphs. Axes and traffic rates auto-scale; unavailable observations are gaps rather than zero latency. History can be 60 seconds or five minutes. **Pop Out** opens a separate compact resizable monitor using the same samples and plot choices. Recent bounded history for each profile remains available in either display after disconnecting, until application exit or profile removal; no stale history initiates probes or restores authorization. Closing the pop-out never stops sampling. **Always on Top**, pop-out position, history length and thresholds persist locally; restarting the application starts fresh measurements.

The monitor is a separate modeless window explicitly owned by the main TELIPHONES window, which stays visible and enabled. It has a task-switcher/taskbar entry. Opening it again reuses the same window and restores it if minimised; Close, Escape and Enter hide only the monitor. Every opening checks its position against the current display work area, clamps partial/off-screen geometry and falls back to the main window's monitor after a display is removed. Native MFC tests are registered in Actions, but the reported SSH 10/10 result alone does not establish their detailed results or visual correctness.

Native tests now exercise the layout adapter at 1024/1366/1920 display sizes, reduced work-area heights, minimum/large windows and 96/120/144/192 DPI layout inputs, including command forwarding, Tab focus, wheel/scrollbar bounds and pop-out lifecycle. Injected DPI inputs are not changes to the runner's display scaling. Manual inspection at actual 100%, 125%, 150% and 200% Windows scaling, multi-monitor DPI transitions and real connected/expired/persistent sessions remains required. No visual correctness or successful MSVC/MFC compilation is claimed from the Linux tests.

The monitor samples every two seconds when the UI is active; WireGuard counters/handshake are queried every six seconds to keep process and CPU overhead low. Its TCP connection-establishment time to the currently authorised PBX's tunnel address on port 443 (with port 80 as a fallback) is labelled **TCP RTT**; it is not ICMP ping. Probe success/failure percentages and consecutive failures are application-level TCP checks. A failed TCP application probe is **not** a measurement of network packet loss. It never probes an old pairing address, an Internet service, the SSH port, or any host other than the active profile's PBX.

Transmit/receive rates use actual interval byte-counter deltas, not an estimate of bandwidth. The preferred source is `wg.exe show <active tunnel> transfer`; handshake age uses `latest-handshakes`. These WireGuard Windows management reads can require administrator permission independently of PBX traffic. If unavailable, the Windows IP Helper `GetIfTable2` API reads the exact active tunnel interface alias's IP-byte counters, labelled separately from WireGuard peer transport counters. No service/pipe ACLs are widened and no automatic elevation is introduced. Handshake remains **Unknown** when its source is inaccessible. Diagnostics preserve the command stage, exit code and sanitized error, or the specific interface lookup failure. A source change resets rate baselines rather than mixing incompatible counters.

Stable requires five consistent successful checks. Defaults warn at 300 ms current TCP latency or 100 ms recent jitter; **Limits...** allows 200/300/500 ms latency, 50/100/200 ms jitter and 2/3/4 consecutive failures before Unstable. Five consecutive failures or a known stopped tunnel produce Disconnected health, but application-probe failures do not remove the WireGuard tunnel. Expired authorization does remove it. Unknown local measurements are not failures. A handshake older than 180 seconds is a freshness warning, not proof an idle peer disconnected. No packet loss, total available bandwidth, network saturation or guaranteed SSH command safety is claimed.

Authorization remaining time is displayed separately from reachability: for example, an unexpired pairing can still have 44 minutes remaining while the PBX is disconnected or no longer answering. A degraded connection disables starting a new SSH session until TELIPHONES verifies the PBX again. Health warnings do not close existing terminal windows or automatically remove the tunnel; authorization expiry continues to use the existing disconnect behavior. Recovery is observed through subsequent successful checks.

Persistent authorization displays **Until revoked**. Temporary expiry and WireGuard handshake timestamps use UTC, while graph history, intervals and healthy duration use a monotonic clock. Mixing Unix expiry with Windows uptime caused the previous enormous remaining-time display; it is no longer used.

The main panel and pop-out share three separate values: **Connected for** starts at zero on the first successful PBX reachability check and uses monotonic elapsed time; **Authorisation remaining** uses the original UTC expiry (or **Until revoked**); **Connection health** shows the independent continuously healthy duration, beginning only when Stable is established. Brief failed checks reset healthy time but keep the connected timer running. Declared connection loss (three consecutive failed checks), a stopped tunnel or expiry stops connected time; subsequent successful recovery starts it at zero. Manual disconnect/reconnect also starts a fresh duration without renewing authorization. Missing fresh measurements do not display an advancing connected duration.


## Historical investigations

The records below describe earlier failures and fixes. They are retained for diagnosis, not as the current readiness verdict.

### Deliberately corrupted certificate diagnostic

The subsequent user-reported Windows run passes nine of ten native tests. Its
remaining error is fingerprint diagnostics treating `ssh-keygen -l` rejection
of the deliberately corrupted certificate as a fixture failure. No remote logs
were fetched. The earlier seven-failure investigation below is historical.

Only the designated tampered `certificate.pub` may return fingerprint exit 1/255
without aborting the test. The complete command/exit/stdout/stderr is printed as
an expected diagnostic rejection. Valid identity/certificate failures, missing
files, configuration inspection failures, other exit codes, process launch
errors and timeouts still fail. A fingerprint that succeeds on a different
OpenSSH version is also diagnostic-only; the signature rejection remains the
mandatory security assertion.
The installed local OpenSSH reports exit 255 for an invalid public-key file;
controlled regressions cover both 1 and 255 rather than assuming a single
cross-version rejection code.

The native host verifies the certificate before creating an agent or SSH child.
On verification rejection it explicitly destroys the disposable key, verifies
that signing and public-key access both fail, reports
`AUTHENTICATION_REJECTED_BEFORE_SSH` and `KEY_DESTROYED=1`, and rethrows the
original verification error. The negative subtest requires that exact signature
failure, both markers, no login output, no child/pipe-ready publication and no
remaining pipe. Password/interactive fallback stays disabled in the config;
no client is launched on this path, so no password exchange is possible.
This tests fail-closed rejection before authentication, not a server-side
authentication attempt; certificate verification must not be bypassed to force
a connection.

Local regression coverage exercises the real OpenSSH fingerprint rejection and
the narrowly scoped handling, plus unexpected failures through controlled mocks.
All ten native tests remain present. Production sources, ACLs, Task Scheduler
and signing/authentication rules are unchanged. The revised native host's
execution still requires Windows. Windows remains 0.7.0 (test-only correction);
FreePBX remains 0.4.0 (module untouched). Existing build provenance is unchanged.

### Seven native authentication/process failures

The earlier user-reported Windows run executes all ten native tests: three pass
and seven fail. Four positive fixture tests report `Load key "identity.pub":
invalid format`, publickey refusal and `KEY_DESTROYED=0`; two production tests
cannot establish authentication, and controller-crash fails a liveness assertion.
Complete Windows client/server transcripts were not supplied or fetched.

Local genuine OpenSSH 9.6 reproduces the shared selection defect, using a
disposable loopback sshd, generated CA/host keys and the same agent protocol:

1. The memory agent enumerates an Ed25519 **certificate**, while the old
   `IdentityFile` selects the raw `identity.pub` and `CertificateFile` separately
   selects the certificate. OpenSSH accepts the certificate offer but searches
   for its signer through the raw identity. It does not associate that identity
   with the certificate-only agent entry. It instead tries to load the
   public-only file as a private key. No agent signing request is made; the
   private seed has not been consumed, explaining `KEY_DESTROYED=0`.
   The local Linux loader reports `error in libcrypto`; the supplied Windows
   loader reports `invalid format`. Neither is evidence of malformed public
   key/certificate encoding: both are the wrong private-key loader being invoked.
2. Advertising the raw identity is not a sufficient production fix. With the
   production certificate-only `PubkeyAcceptedKeyTypes` policy, genuine OpenSSH
   filters out the raw identity (`corresponding algorithm not in
   PubkeyAcceptedAlgorithms`) before signer selection. This separately reproduced
   failure must not be "fixed" by allowing raw-key authentication.

Both configs now use `IdentityFile certificate.pub` and `CertificateFile none`.
The latter prevents a second, separately loaded certificate candidate; it does
not disable certificates. The identity itself is the exact certificate exposed
by the agent. `identity.pub` remains a public subject/audit artifact, never a
private-key fallback. Certificate-only algorithms, `IdentitiesOnly`, strict host
verification and no password/shared-agent fallback remain enforced.

The agent request/reply logic is moved without relaxing its policy into the
portable production `SshAgentProtocol`, called by the existing process-bound
named-pipe transport. Its signer selector is still the exact certificate blob,
not the raw public key. It checks zero flags and the exact userauth
user/service/certificate (and pinned host for hostbound requests), creates one
Ed25519 signature, then destroys the seed. Enumeration/re-signing fail after
destruction; import/removal/export/extension operations remain unsupported.
Named-pipe PID/retained-handle checks, DACLs, DPAPI, locks and owned Jobs are
unchanged.

The portable regression drives that actual C++ dispatcher, not a Python signing
substitute. It verifies enumeration, normal/hostbound signing, destruction,
re-use rejection and wrong key/certificate/user/host/flags rejection. A real
local OpenSSH client/server login with the production certificate-only policy
succeeds using this dispatcher and no session private-key file. Unix sockets
adapt only the transport: this does **not** validate Windows named pipes,
Windows OpenSSH, DPAPI, console helper or Jobs.
The same real-OpenSSH regression also runs both old configurations, requiring
certificate-offer acceptance followed by authentication failure, no signing
request and a still-unconsumed key. Only the corrected selection may log in.

Both crash tests now require a remote authenticated readiness marker before
testing process death. The SSH-crash test also requires `KEY_DESTROYED=1`,
preventing an authentication failure from masquerading as a successful crash
test. The controller-crash test still requires both children alive, owned child
termination and unrelated child survival. An explicit post-login crash command
replaces the fixed two-second timer; `ssh -n` prevents the client from consuming
the test controller's stdin protocol.

Native tests record effective identity/certificate/agent configuration and
public fingerprints. Direct clients and the test-built production helper use
`-vvv -E` logs outside the public-runtime directories, avoiding verbose-stderr
pipe blockage. Client/server tails and issuer errors accompany production
authentication failure; full client logs are copied to the existing diagnostics
artifact before cleanup. No private seeds/keys/signature requests are logged.
Production binaries do not include the test helper's log-path environment hook.
All ten test methods, working ACL/Task Scheduler code, independent CI suite
execution and mandatory failure outcomes are retained.

Windows remains **0.7.0**: this corrects production code within that explicitly
unreleased development target, not a correction to released software or a new
distribution/checkpoint. FreePBX remains **0.4.0** because its code/contracts are
unchanged. Existing build-info source SHA, Actions run/attempt and executable
hash provenance remain intact. Native Windows execution of the correction and
all ten tests is still required; no passing Windows result is claimed.

This audit describes executable provisioning and tests, not a successful Windows
run. The reported failure established that the selected `windows-2022` runner
lacked `System32/OpenSSH/sshd.exe`. Checking that file without provisioning it
was insufficient. The previous Unix broker import failure is separately fixed:
Windows executes portable client contracts; Linux retains full broker contracts.

### Execution order and prerequisites

| Stage | Dependency / source | Verification and failure handling |
|---|---|---|
| Checkout | Existing GitHub checkout action | No persisted Git credentials |
| Toolchain | Runner Visual Studio 2022, v143, static MFC, Windows SDK | Existing `vswhere` discovery and exact header/library/tool checks; no VS downloads |
| Project/layout checks | Runner Python and CMake | Explicit Python requirement; CMake script-mode tests check both platform registrations and provisioning order |
| PowerShell discovery diagnostics | Exact System32 Windows PowerShell executable, separate from fixture/security tests | Record selected discovery variables and child edition/module paths; compare inherited versus PSModulePath/PSHOME-reset module loads; full exception/exit output in powershell-environment.log; not an ACL verification or success substitute |
| OpenSSH provisioning | Elevated x64 runner, Windows DISM capability servicing, Task Scheduler | Enumerate `Get-WindowsCapability -Online` OpenSSH entries; install missing official Client/Server capabilities with `Add-WindowsCapability`; re-query Installed state and reject RestartNeeded |
| OpenSSH executable validation | Windows capability output in `%SystemRoot%\System32\OpenSSH` | Verify all three files, versions and SHA256; execute ssh version and sshd/keygen usage probes; validate exit codes AND output; export exact directory through GITHUB_PATH |
| OpenSSL restore | Runner's existing vcpkg; existing declared OpenSSL manifest | Static x64 restore, checked exit codes, versions logged; explicitly verify headers, Release/Debug crypto libraries and distributable copyright file |
| MSBuild | Verified VS tools and restored static crypto | Build GUI, console helper, native core/diagnostics and MFC window tests; existing failures remain fatal |
| Native CMake build | Runner CMake/Python/compiler, same vcpkg toolchain | Compile production core plus isolated loopback fixture core, crypto and agent/session test host |
| Win32 preflight | DPAPI, BCrypt/OpenSSL, VirtualAlloc/VirtualLock, local pipes, Jobs, process permissions | Actual native operations: locked seed/sign/destroy, user DPAPI round-trip, restrictive pipe creation, suspended child, Job assignment/process DACL/termination |
| CTest | Dependencies listed below | All six Windows tests remain enabled; verbose output, JUnit and full stdout/stderr log retained; failure does not suppress independent native SSH integration |
| Real fixture preflight | Same Python/C++ fixture, ICACLS, native Win32 security APIs, Task Scheduler COM and actual OpenSSH server | Complete protected DACL replacement plus separate owner assignment; inspect exact file/task descriptors; reject and repair real deliberately invalid file ACLs; generated keys/config, SYSTEM task, live server PID/SSH banner; verified teardown; no mocked replacement |
| Native SSH integration | Windows OpenSSH, elevated task registration, current local Windows account, loopback ports | Actual SSHSIG sign/verify feature probe, generated Ed25519 host/CA, strict host key ACL, `sshd -t` and effective `sshd -T`; real authenticated login is mandatory |
| Always-run cleanup | Python and uniquely recorded fixture task/path | Stop marker, verified zero-Job-process acknowledgement, exact task deletion; recovery for interrupted harness; no service-name/process-name killing |
| Remaining native tests | Existing MFC tests, dumpbin, mt.exe, loader | Window tests, actual PE/version/manifest/import checks and helper startup tests retained |
| Distribution | Both executables plus static OpenSSL copyright and GPL licence | Existing packaging and executable hashes unchanged; upload only after successful validation |

Builds and test suites are separate Actions steps with explicit prerequisite
outcome checks and `!cancelled()`. A failed contract suite does not prevent native
SSH integration when OpenSSH provisioning, native compilation, Win32 preflight
and actual fixture preflight succeeded. Portable CTest does not depend on either preflight success, so it still
collects its own results. MFC window, PE/manifest and startup suites also run after
other test failures if the application build succeeded. Both standalone core and
diagnostics executables are attempted even if the first fails.

No step uses `continue-on-error`: failures remain job failures. Application
packaging/upload retain the default successful-job condition. Diagnostics upload
runs on success or failure, collecting `ctest-results.xml`, `ctest-output.log`,
`powershell-environment.log`, `native-fixture-preflight.log`, `native-ssh-output.log` and the existing native/startup logs in
`TELIPHONES-Windows-startup-diagnostics`. Verbose unittest names, unlimited contract
diffs and raw transport-byte errors identify exact assertions in the same run.

`provision_openssh.ps1` does not start/enable the global sshd or ssh-agent service,
change public firewall rules or edit production SSH configuration. Official
capability servicing may retrieve its payload through Windows servicing; this is
the requested capability installation, not an alternate download mechanism.
No external searches/downloads were performed in the local development session.

If servicing fails, logs include the specific exception/HRESULT and available
DISM/CBS tails. A reboot requirement or an executable that cannot load is a failure,
not an assumed successful install. No unapproved ZIP/package fallback exists.
If the runner cannot install the official capability, an alternative requires
approval for an exact, version-pinned official Microsoft Win32-OpenSSH distribution
URL and an independently trusted expected SHA256. No version/hash is invented.

Capability presence does not establish feature compatibility: the installed
`ssh-keygen` must actually sign/verify SSHSIG and sign Ed25519 certificates; CTest
and native login reject unsupported behaviour. Actual versions/hashes are logged
on each runner, not assumed from the mutable runner label.

### Native fixture ACL failure and preflight

The supplied Windows traceback is an actual setup failure: ICACLS exit **87**,
`Invalid parameter "/setowner"`, before any native test ran. The host-key command
combined `/inheritance:r /grant:r ... /setowner ...`; `/setowner` is a separate
ICACLS command form, not a grant option. This is a fixture defect, not an SSH
provider defect.

The later confirmed `ca.pub` failure exposed a separate construction defect:
`icacls /grant:r` replaces grants **only for the specified SIDs**, not the whole
DACL. `/inheritance:r` removes inherited ACEs, not an existing explicit Everyone
read ACE. `/setowner` does not remove grants either. The supplied observation
establishes that Everyone survived; it does not by itself establish which
key-generation/runtime operation originally created that ACE.

The fixture now uses `SetNamedSecurityInfoW` to install a complete, protected
allowlist DACL, replacing all existing explicit and inherited entries in one
operation. The intended trusted grants are present immediately; no empty/null
DACL or permissive intermediate state is installed. Ownership remains a separate
checked `icacls /setowner` invocation, followed by independent descriptor readback.
SID-based policy is read back through native Windows APIs in
`fixture_security.cpp`, checking owner, protected DACL, exact allowed identities,
full-control masks, inheritance, propagation and unexpected flags. Unsupported
ACE forms and unexpected ACEs fail the fixture. The former PowerShell script has
been removed; the fixture does not spawn PowerShell.

- Temporary root: current user owner; current user, SYSTEM and Administrators
  have explicit inheritable full control.
- Host private key: SYSTEM owner; only SYSTEM and Administrators have explicit,
  noninherited full control; any explicit runner-user grant is removed.
- CA private/public key, host public key, principals, configuration and task XML:
  current user owner; only current user, SYSTEM and Administrators, protected
  noninherited file grants. These are disposable fixture keys, not product
  session private keys; fixture files are removed on teardown.
- Task Scheduler security: Administrators owner; protected DACL allowing only
  SYSTEM, Administrators and the runner user; actual SYSTEM SID, service-account
  logon type and highest run level verified after task registration.

#### SYSTEM task XML registration correction

The supplied Server 2022 failure identifies the exact invalid XML element:
`LogonType:ServiceAccount`. `TASK_LOGON_SERVICE_ACCOUNT` (numeric value 5) is a
supported Task Scheduler COM logon type, but `ServiceAccount` is **not** a valid
lexical value of the task XML schema's `LogonType`. The scheduler rejects the XML
before task execution; this is unrelated to the now-working ACL implementation.

The generated XML omits `LogonType`, retains `UserId` `S-1-5-18`,
`HighestAvailable`, matching principal/action context and no automatic triggers.
Existing `schtasks /Create /TN <unique-name> /XML <fixture.xml> /RU SYSTEM`
registration supplies the supported passwordless SYSTEM service-account choice.
There is no need to change the working COM descriptor helper or rewrite task
registration. Runtime COM readback still **requires** SYSTEM SID, logon type 5,
highest run level and the exact restrictive task DACL before `/Run` is allowed.
Omission of the XML element does not relax that assertion.

Subsequent `/Run`, diagnostic `/Query`, exact-task `/End`/`/Delete`, native
state/absence queries, SYSTEM-wrapper identity, kill-on-close Job, PID/banner
readiness and verified teardown are unchanged. These do not supply XML
`LogonType` values. Regression tests verify the emitted XML, `/RU SYSTEM`
registration, inspection-before-launch ordering and all ten native methods.
Local XML tests do not establish native registration success: actual Server 2022
registration, SYSTEM execution and the ten SSH tests remain Windows validation
requirements. Windows stays 0.7.0 (test-only correction); FreePBX stays 0.4.0
(module unchanged). No distribution is created.

#### Identification readiness probe and bounded diagnostics

The reported run starts SYSTEM sshd and binds port 22001 but repeatedly fails
during identification. The old readiness probe never sent a client
identification: it waited two seconds for a server line, then closed the socket
on timeout. Its broad `except OSError` also retried established-connection resets
and timeouts up to 300 times, potentially producing minutes of self-generated
pre-auth disconnect logs and hiding the first useful error.

The corrected probe sends `SSH-2.0-TELIPHONES_fixture_probe` with CRLF before
reading the server identification. Reading is bounded to 255 bytes and three
seconds; EOF, reset, timeout and invalid identification fail immediately after
the first established connection. Only connection refusal while the server is
binding is retried: at most ten TCP attempts within a 15-second startup window.
The controlled SYSTEM task must report running and its published server PID must
be present in a successful process snapshot before connecting. Both are checked
again after identification responds. Identification
success deliberately closes **before** key exchange/authentication and labels
that disconnect as expected; it is not evidence of authenticated login.

Failure output identifies the stage, sent/received identification bytes and
actual socket error (including Win32/errno where available). Startup failures
and teardown print only the last 30 log lines, read from at most 8 KiB; the full
server log is still copied into the existing diagnostic artifact. No retry loop
can silently turn an established-connection protocol failure into success.

Local regression tests cover send-before-read ordering, fragmented valid banner,
EOF/reset/timeout, invalid/oversized banner, refusal retry exhaustion, deadline,
dead PID, immediate nonretryable connect failure and no retry after identification
failure. A real local loopback peer waiting for client identification reproduced
the old receive-only timeout/disconnect; the revised probe exchanged
identifications on one connection. This demonstrates probe behaviour, **not**
that the reported Windows sshd waits for client identification. Without that
run's full logs or an authorised Windows runtime, its exact initial socket error
and whether later key exchange/authentication succeeds remain unverified. The
new diagnostics expose a genuine server-side failure rather than retrying it.
All ten actual Windows SSH tests, ACLs, Task Scheduler registration, authentication
policy and process ownership/cleanup remain unchanged.

#### SYSTEM process access-denied correction

The supplied `alive(pid)` failure is `OpenProcess(SYNCHRONIZE, FALSE, pid)`
returning Win32 5, not a TCP or SSH failure. `SYNCHRONIZE` is `0x00100000`,
required by the subsequent process-handle wait. SYSTEM-owned sshd's process DACL
does not grant that access to the runner in the reported environment; elevation
alone does not bypass process DACLs, and the harness intentionally disables debug
privilege. The supplied output does not identify the exact process DACL, but it
does establish that this requested access was denied. Access denial is never
interpreted as liveness.

Readiness now uses the existing restricted Task Scheduler COM query to require
`TASK_STATE_RUNNING` (4), the SYSTEM wrapper's protected PID publication and a
Toolhelp `TH32CS_SNAPPROCESS` inventory containing that PID, plus the bounded SSH
identification exchange. Queued tasks may wait within the existing deadline;
missing/disabled/ready/unknown tasks fail. State/PID checks repeat after the
response. No `OpenProcess` is requested on SYSTEM sshd; no process DACL or token
privilege is changed. Process snapshots require no per-process SYNCHRONIZE,
query, VM-read or debug rights. Snapshot creation/enumeration errors propagate;
only successful enumeration ending with `ERROR_NO_MORE_FILES` proves absence.

Normal, failed-start and interrupted cleanup use the same inventory instead of
reintroducing the denied `OpenProcess`. Normal shutdown still requires the
SYSTEM wrapper's exact zero-Job-process acknowledgement, absent server PID,
closed listener, deleted task and removed fixture directory. Forced cleanup
retains the owned-task termination/kill-on-close Job and bounded server-absence
check; an inventory/query error cannot make cleanup succeed. The existing
`alive` helper remains for the same-user SSH child crash-isolation tests, where
process-handle rights are intentionally part of those tests.

Local mocks exercise inventory match/absence, snapshot/enumeration denial,
running/queued/stopped task states, stopping during identification, successful
readiness despite a forbidden OpenProcess helper, and verified cleanup without
calling that helper. These do not establish native Windows interoperability.
All ten SSH methods, security-descriptor code, Task Scheduler registration,
authentication and production provider are preserved. Windows 0.7.0 remains the
unreleased target for a test-only fix; FreePBX 0.4.0 is unchanged because module
code is untouched. Actual Windows execution remains required.

`--fixture-preflight` calls the **same** `setUpClass` and class cleanups used by
the ten native tests. It checks generated Ed25519 host keys, SSHSIG support,
`sshd -t/-T`, the protected task, real SYSTEM wrapper and loopback SSH banner with
a live recorded server PID. Actual negative ACL probes separately change owner,
add an unauthorised SID, enable inheritance, reduce access rights and add a deny
ACE; every observed invalid descriptor must be rejected, then restored and
re-verified. A repair probe also seeds a real explicit Everyone read ACE, confirms
the strict checker rejects it, reapplies the complete DACL and verifies exact
SID/mask/flags/owner state. Both generated public keys are secured before first
use; generated certificate files receive the same complete replacement/readback.
Private host/CA keys, root, config, principals and task XML use the shared
constructor; host private-key access stays restricted to SYSTEM/Administrators.
Success requires acknowledged zero Job processes,
closed listener, absent scheduled task and removed temporary directory. Setup
and cleanup errors are both reported. It does not claim an authenticated login:
that remains mandatory in the unchanged ten-test integration suite.

Diagnostics include ICACLS's installed `/?` help, exact failing
argv/exit code/stdout/stderr, expected/observed ACLs and SDDL, `whoami /all`, and
OpenSSH/wrapper logs. No private-key contents or private protocol input are logged.
The C++ test host uses Unicode command-line input rather than treating Windows
ANSI argv as UTF-8. SYSTEM-wrapper failures are written to the fixture log,
because a scheduled task has no attached console. Failed shutdown does not
silently erase evidence of a still-running server/task; interrupted recovery
uses `ITaskFolder::GetTask` and accepts only `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`
as proof that a task is absent. Access-denied/RPC/service failures remain errors.

Local policy/command-construction/cleanup-error unit tests use mocks and do **not**
validate Windows ACL semantics. This Linux workspace has no PowerShell or Windows
runtime: the separate native fixture preflight, actual ICACLS commands, task
descriptors, Unicode test-host build and all ten native SSH tests remain
unexecuted locally. Runtime ICACLS help plus descriptor checks provide the
on-runner syntax and permission validation; no external searches were used.

#### Latest PowerShell loader failure: evidence and correction

The supplied error, `Get-Acl: Microsoft.PowerShell.Security could not be loaded`,
establishes a module/command-loader failure **before** descriptor inspection. It
does not establish an invalid file owner or ACL. The full loader exception,
inherited module paths and exact module manifest selected on that runner are
not available locally; no remote GitHub access was performed.

The workflow's parent shell is PowerShell 7 (`pwsh`), whereas the old fixture
spawned Windows PowerShell (`powershell.exe`) without sanitising its inherited
environment. `-NoProfile` does not clear `PSModulePath` or other environment
variables. Cross-edition module/assembly discovery is therefore a concrete
fragile dependency, but **not a proven explanation for that specific run**.
Missing/damaged inbox modules or other assembly-loading errors cannot be ruled
out from the single supplied message.

The diagnostic-only probes are isolated child processes, not a workaround in
the fixture. They record only named PowerShell discovery variables, edition,
module manifest paths, exit codes and complete loader exceptions, comparing
inherited versus reset discovery variables. Even if these probes cannot load
the module, the native security checks still run independently. A later runner
cannot retroactively prove the original runner's exact condition.

Discovery tests use an explicit environment mapping, covering `PSModulePath`
present, absent and Windows-style uppercase `PSMODULEPATH`. They compare the
complete inherited/reset child environments and verify the parent is unchanged.
Reset removal is case-insensitive because Windows `os.environ.copy()` produces
uppercase keys; optional discovery variables are not assumed to exist.

The actual correction removes **all** PowerShell calls from the SSH harness:

- `GetNamedSecurityInfoW`, `GetSecurityDescriptorOwner/Control/Dacl`, `GetAce`,
  SID conversion and SDDL serialization inspect real file security; the filesystem
  must advertise persistent ACL support. No localised CLI output is parsed.
- Task Scheduler COM sets and reads back the protected task descriptor and
  resolves principal names to SIDs; its actual SYSTEM SID, service-account logon
  and highest run level are required.
- Token/account APIs return the runner SID, elevation and actual local account
  name instead of trusting `USERNAME` or a PowerShell identity query.
- Task-state/absence inspection uses COM, including interrupted cleanup; it no
  longer imports the ScheduledTasks PowerShell module.
- Errors identify the API, numeric Win32 code or HRESULT, expected result and
  actual result. Descriptor mismatch errors include expected policy and observed
  descriptor. The SYSTEM wrapper captures errors at the failing API rather than
  reporting a later, potentially stale `GetLastError`.

The audit also identified a separate **fixture-only byte transport defect**:
Python `subprocess.run(text=True, input=...)` rewrites LF to CRLF on Windows.
The production certificate-request signature covers LF-delimited bytes, so the
old mock issuer could verify different bytes from those signed by the native
provider. The fixture now sends SSHSIG input as explicit UTF-8 bytes and writes
the feature probe using exact bytes. Production cryptography is unchanged.
Local transport tests verify no text-mode stdin translation; native signature
verification/login remains a required Windows result.

#### Complete fixture dependency audit

| Phase / operation | Essential dependency and handling |
|---|---|
| Before tests: tools | Official client/server/keygen provisioning and executable checks remain before dependent stages; static OpenSSL is restored and compiled; native host links SDK `taskschd`, `ole32`, `oleaut32` and `advapi32`, no added runtime package |
| Before tests: services/modules | Task Scheduler/RPC is essential and checked by provisioning plus actual native COM connection/task registration. No global sshd/ssh-agent service is started. PowerShell DISM remains only in the existing official-capability provisioning stage, not fixture verification or teardown |
| Before tests: privileges/account | Provisioning requires elevated x64; native identity query additionally verifies an elevated local-account token. SYSTEM is needed for Windows sshd logon tokens; task principal/run level/permissions are checked. Python disables debug privilege before process-isolation tests |
| Before tests: filesystem | Unique temporary path, exact SID allowlists, protected ACLs, host SYSTEM ownership, explicit CA/config/task permissions; filesystem persistent-ACL capability checked. Negative ACL probes must reject actual invalid permissions |
| Before tests: server | Generated test-only CA/host keys; public-key-only auth, pinned host, no password/interactive fallback, forwarding disabled, StrictModes enabled; `sshd -t/-T`, exclusive port availability, actual live PID/banner. No production config/firewall changes |
| During tests: API issuer | Loopback HTTP server with authenticated SSHSIG request, exact-byte verification, distinct public subject/session/principal and short-lived generated certificate; rejects invalid/denied requests; issuer thread/socket stopped in finally |
| During tests: isolation | Actual Windows named pipe and exact client PID enforcement; real process access probes, locked Ed25519 key, DPAPI, Windows SSH client/helper, anonymous kill-on-close Jobs; concurrent sessions and unexpected termination exercised, not mocked |
| During tests: paths/encoding | Native host uses `wmain`, UTF-8 protocol and UTF-16 Win32/COM APIs; Python uses argument arrays, XML task serialization and quoted OpenSSH paths. Task operations restricted to the generated fixture namespace |
| After tests: ownership/termination | Stop marker, SYSTEM wrapper kill-on-close Job, zero-active-process acknowledgement, bounded PID wait, closed loopback listener, exact task deletion and absence query; retain failure if any mandatory check fails |
| After failure/interruption | Cleanup registered immediately, recovery descriptor recorded before sensitive setup; created-but-unstarted tasks cleaned; always-run recovery ends only the recorded task and removes only its validated temporary path. No name-based process killing or production service changes |

All six Windows CTests and all ten native methods remain registered/enabled.
Unittest continues after individual test failures. Independent portable, native,
window, PE and startup results are collected using existing outcome gates;
mandatory failures remain job failures and prevent packaging/publication.
Fixture setup/preflight failure cannot be labelled an authenticated SSH test pass.

Local validation for this correction: CMake build and all seven Linux CTests
passed, including 30 project/fixture regression tests; gateway Python ran 142
tests with 141 passed and one skipped for missing WireGuard tooling. PHP,
JavaScript, documentation and module packaging regressions passed. A genuine
local OpenSSH SSHSIG probe (with Linux mode-0600 test key) accepted the exact
LF-delimited payload and rejected its CRLF-mutated equivalent. This is evidence
for byte binding, not Windows execution. The new native Win32/COM component,
real negative ACL probes, runner module probes, SYSTEM task and all ten native
SSH tests have **not** been compiled/executed in this Linux workspace. No
disposable Windows runtime, Windows SDK/compiler or authorised remote Windows
execution environment is available here; no dependencies were downloaded.

### All six Windows CTests

| Test | Runtime dependencies / provisioning | Windows behaviour and cleanup |
|---|---|---|
| `core_tests` | Compiled production portable core | No Unix imports/network; deterministic schemas/routes/commands; production loopback policy rejection explicitly retained |
| `session_diagnostics` | Win32 token/ACL/file/mutex/process APIs | Existing Windows-specific implementation; temporary stores and child handles; no POSIX execution on Windows |
| `build_layout` | Python stdlib, CMake, repository source/project files | UTF-8 for new fixtures; temporary CMake script removed; checks test registration, provisioning, isolated task XML/path quoting and all ten native methods |
| `contract_check` | Python stdlib, contract_tool, portable gateway renderer | Unix import guard; five real client schema/binding/tunnel/fingerprint/denial checks; no broker/root/network dependencies |
| `managed_ssh_check` | Official ssh-keygen, contract_tool | Generated temporary CA/keys/certs; POSIX chmod guarded; actual certificate-binding boundaries/tamper rejection; files removed by TemporaryDirectory |
| `ssh_crypto_check` | Static OpenSSL crypto tool and official ssh-keygen | Native Ed25519 lifetime/export denial, constrained userauth, SSHSIG/certificate verification and identity migration; generated fixtures removed |

The workflow provisions OpenSSH before these tests, so their existing
OpenSSH-unavailable skips cannot be used to obtain success in this workflow.
Linux additionally runs `broker_contract_check`; privileged OS/network calls in
that contract test are doubled, not represented as a native Windows result.

#### Three contract assertions: locally reproduced Windows CRT behaviour

The supplied Actions summary says five tests ran with three failures; the actual
Windows assertion tracebacks were not available locally and no remote access was
performed. The following are the **local reproduction results**, not invented
values attributed to that Actions run.

Running the uncorrected five-test suite with the real local C++ contract tool and
the Windows CRT text-stdout rule (insert CR before each LF), followed by Python's
universal-newline decoding, reproduces exactly five tests / three failures:

| Test / subtest | Failing assertion | Expected | Reproduced actual |
|---|---|---|---|
| `test_response_profile_and_administrator_tunnel`, `mode='temporary'` | Rendered administrator configuration equals the expected complete configuration | `[Interface]\nPrivateKey = ...\nAddress = 100.70.1.2/32\n\n[Peer]\n...` | `[Interface]\n\nPrivateKey = ...\n\nAddress = 100.70.1.2/32\n\n\n\n[Peer]\n\n...` |
| `test_response_profile_and_administrator_tunnel`, `mode='persistent'` | Same configuration assertion, independent persistent response/profile round-trip | Same administrator configuration as temporary mode | Same doubled line breaks as temporary mode |
| `test_support_tunnel_matches_portable_gateway_renderer` | Rendered support configuration equals `engineer.render(...)` | `[Interface]\nPrivateKey = ...\nAddress = 10.99.0.2/32\n\n[Peer]\n...` | `[Interface]\n\nPrivateKey = ...\n\nAddress = 10.99.0.2/32\n\n\n\n[Peer]\n\n...` |

Keys, endpoints, routes and keepalive fields are identical in the reproduction;
only line termination differs. The administrator expected endpoint/routes are
`pbx.example.net:51821` / `100.70.1.1/32`; support uses
`gateway.example.net:51820` / `10.20.4.2/32`. All use keepalive 25. Ellipses in the
table omit unchanged synthetic fixture keys and fields, not unknown observed data.

Root cause for all three: production `RenderTunnel` intentionally returns CRLF
bytes. The test-only `contract_tool` printed those bytes through Windows CRT text
stdout, producing CRCRLF; Python `text=True` converted CRCRLF into two newlines.
The one-line request/response/fingerprint assertions strip their final newline
and were unaffected, explaining the exact failure count.

Correction: set only the Windows contract helper's stdout to `_O_BINARY`, checking
the result, before writing any output. Production tunnel rendering, files,
authentication and route validation are unchanged. The Python contract adapter
now captures bytes first, rejects CRCRLF/lone newline corruption, decodes UTF-8
explicitly and converts valid CRLF to LF for the existing Python comparison.
It does NOT collapse blank lines or strip rendered configurations to hide errors;
the complete expected output includes its final newline.

Regression coverage rejects the exact simulated CRT corruption for both
administrator and support output, accepts unchanged renderer CRLF, and rejects
LF-only transport. Actual helper bytes are checked during all three rendered
configuration assertions on both platforms. This local byte-level reproduction
does not execute MSVC or establish actual Windows/OpenSSH success; the next native
run must confirm the fix and expose any distinct assertions in its full logs.

### Native fixture: account, configuration and lifetime

Foreground sshd running as the ordinary runner account is not an adequate
Windows logon-token environment. The harness registers a unique demand-start
SYSTEM task (`schtasks /Create /RU SYSTEM`) running the **test host**, not the
product. Its wrapper verifies the SYSTEM SID, starts sshd suspended in an
anonymous non-inheritable kill-on-close Job, then resumes it. The listener,
privilege-separated descendants and remote test commands share that Job.

The scheduled task and wrapper each have a ten-minute bound. Normal cleanup
signals a stop file, terminates the owned Job, verifies zero remaining processes,
writes an acknowledgement and removes the task. Class cleanup runs after fixture
setup failure as well as success. An always-run workflow step handles an
interrupted Python harness using a validated exact task name and temporary path.
Only fixture metadata/logs go to diagnostics, never generated CA/private keys.
The disposable runner remains the ultimate boundary for job cancellation/reboot.

The harness uses a protected temporary directory under RUNNER_TEMP (or the user
temp directory for manual runs), user/SYSTEM/Administrators ACLs, and explicitly
SYSTEM-owned host key with no broad read permissions. It never uses the global
host keys/config or `administrators_authorized_keys`. The server allows only the
current local runner account, CA/certificate authentication, no password/keyboard
interactive/agent/TCP forwarding, and binds only `127.0.0.1:22001`. The mock issuer
binds only `127.0.0.1:8765`. Both fixed contract ports are checked for collisions;
no machine firewall rules, routes or network adapters are changed.

The current provider's production route policy rejects loopback workstation
addresses. Previously the production-path fixture used `127.0.0.1/32` anyway and
would fail before requesting its certificate. The native host now links a
**separate test-only core**, compiled with `TELIPHONES_SSH_LOOPBACK_FIXTURE`, which
permits exactly that fixture source in managed-pairing validation. The application,
production core CTests and crypto tool do NOT define it. The underlying route
parser is unchanged and production rejection has an explicit regression test.
All certificate signature, subject, account, source, principal, lifetime and host
checks remain active against the exact loopback fixture values. This exception is
not shipped, is not generalised to arbitrary addresses and does not prove a real
FreePBX/WireGuard deployment. The existing test-only console executable override
also remains: real application companion packaging is validated separately.

SeDebugPrivilege is explicitly disabled in the Python probe token so tests of
ordinary process-DACL isolation do not accidentally measure an administrative
debug bypass. Privileged/debugger resistance is not a product guarantee.
Unrelated-process agent I/O is overlapped and bounded rather than an unbounded
synchronous read. Authentication/crash failures still fail the test.

### All ten native SSH tests

All rows require the common fixture above, real Windows client/server and compiled
production crypto/agent/session code. Dependencies are verified on the runner;
their presence/success has not been observed locally.

| Test | Additional dependencies / assertions | Success and failure teardown |
|---|---|---|
| `test_native_login_destroys_key_and_creates_no_private_key_files` | Actual certificate login and remote echo; one-signature key destruction; only public session artifacts | Host/agent/SSH Job closes; test files removed with fixture |
| `test_other_process_cannot_enumerate_or_use_agent` | ctypes Win32 overlapped pipe I/O, exact connecting PID enforcement | Bounded five-second probe, I/O cancellation and event/pipe close; host cleanup |
| `test_new_process_handles_cannot_read_memory_or_duplicate_credentials` | Disabled debug privilege; OpenProcess denied VM_READ/VM_WRITE/DUP_HANDLE/CREATE_THREAD | Every acquired probe handle closed; host cleanup |
| `test_concurrent_sessions_and_wrong_certificate` | Two distinct live keys/certificates and independently owned Jobs; mismatched certificate rejected | Per-host cleanup, server Job ultimately reaps remote commands |
| `test_expired_cert_and_wrong_host_fail_without_password_fallback` | Real expired certificate, wrong pinned host and cryptographically tampered certificate | Nonzero results mandatory, no fallback; each owned host stopped |
| `test_controller_crash_kills_owned_ssh_only` | Long-running remote ping, forced exact controller PID termination; unrelated login survives | Per-controller Job; unrelated host cleanup; fixture Job reaps server-side commands |
| `test_ssh_crash_ends_agent_and_prevents_reuse` | Exact owned SSH handle forcibly terminated; agent pipe disappears | Host cleanup; fixture process-tree teardown |
| `test_production_dpapi_identity_certificate_api_console_and_disconnect` | User DPAPI/LOCALAPPDATA; cmd.exe; WinHTTP; Python HTTP issuer verifies SSHSIG and correct public subject; PTY login | CloseManagedSsh, public artifacts removed, permanent identity survives session then explicit test deletion; issuer stopped |
| `test_production_certificate_refusal_cleans_identity_without_launch` | Same authenticated issuer returns 403 after verifying request | No terminal/session; test-owned DPAPI identity removed; principal restored and HTTP server stopped |
| `test_production_local_authorisation_expiry_ends_owned_session` | Real login plus fixed local authorisation deadline; bounded wait accommodates expiry | Owned SSH/helper/agent end; identity retention checked before test deletion |

The issuer's HTTP errors retain exception details in the failing test output;
sshd logs and task status make fixture startup failures actionable. Those logs
contain public fingerprints/session metadata, not private-key material.

### Remaining validation gates

- Official capability servicing, its installed version/features, PowerShell
  execution, SYSTEM task/logon privileges, MSVC test-host compilation and all
  native behaviour above require an actual new Actions run. They are NOT
  validated by Linux syntax/source tests.
- No assertion that Windows tests cover actual FreePBX/systemd revocation:
  server-enforced existing-session expiry/revocation, workstation removal, broker
  failure, cgroup cleanup and unrelated administrators still need a disposable
  real FreePBX 17/systemd target. Linux namespace OpenSSH tests substitute
  process-tree supervision, not real systemd.
- Windows reboot/hibernation, terminal matrix, real WireGuard interruptions,
  production GUI-to-PBX flow and distribution smoke tests still need target
  execution. No physical erasure guarantee for memory/pagefiles/dumps/SSDs.
- No native test was disabled or replaced with a successful stub. The audit's
  source/layout/XML tests are safeguards, not proof of Windows interoperability.
