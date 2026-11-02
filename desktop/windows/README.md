# TELIPHONES 0.4.0 for Windows (experimental)

The native Windows client is under active development and versioned independently of the FreePBX module, which remains **0.3.0**. The current unreleased Windows version is **0.4.0**, shown in the main window title and embedded product version, with Windows file version **0.4.0.0**. Individual development builds retain this application version and are identified by their Git commit SHA and Actions build provenance. See the [Windows change history and versioning policy](CHANGELOG.md). The manifest's `assemblyIdentity` version is a fixed side-by-side identity, not the release number. Earlier executables have compiled and launched in user-run Windows testing; this iteration still requires native build and installation validation, and genuine PBX tunnel/service integration still needs testing. It is a compact C++17 Win32/MFC application, not a .NET application. It has two profile types:

- **My PBX** pairs a workstation with a PBX using an approval in the PBX's TELIPHONES page. Persistent pairing remains revocable from that page. Temporary pairings expire on the PBX.
- **Remote Support** keeps a locally generated engineer key and imports an operator-issued `teliphones-engineer-grant/1` JSON file. The grant must name that exact engineer public key.

Both use WireGuard for Windows and the existing TELIPHONES PBX/gateway contracts. TELIPHONES does not create SSH accounts, expose ordinary PBX ports to the Internet, bundle WireGuard, or provide a relay. Direct WireGuard requires the configured PBX/gateway UDP endpoint to be reachable; restrictive NAT/firewalls can prevent it.

## Requirements and build

- Windows 10/11 x64.
- Visual Studio 2022 with the **Desktop development with C++** workload, Windows 10/11 SDK, and the optional **C++ MFC for latest v143 build tools (x86 & x64)** component.
- WireGuard for Windows is required for pairing and connections. TELIPHONES can retrieve and verify the official installer after you choose **Install WireGuard**, then ask for administrator approval through UAC. Existing verified installations are reused unchanged. WireGuard is not bundled.
- Windows OpenSSH Client is needed for **Open SSH** with Windows PowerShell, PowerShell 7, Windows Terminal or Command Prompt. PuTTY uses its own SSH implementation and does not need it.

Open `TELIPHONES.sln` in Visual Studio, select **x64**, then build. Or run `build.ps1` in a Visual Studio 2022 Developer PowerShell:

```powershell
.\build.ps1 -Configuration Release -Platform x64
```

The application and portable core tests are written to `build\Release\`. Run `build\Release\TeliphonesCoreTests.exe` to execute the core regression tests. The portable core and broker-contract tests can also be run on Linux with CMake:

```sh
cmake -S . -B /tmp/teliphones-windows-core
cmake --build /tmp/teliphones-windows-core
ctest --test-dir /tmp/teliphones-windows-core --output-on-failure
```

### GitHub Actions build and download

The [Windows build workflow](../../.github/workflows/windows-build.yml) builds the existing Visual Studio solution in **Release x64** on a GitHub-hosted `windows-2022` runner. It runs automatically when changes under `desktop/windows/` or the workflow itself are pushed. It can also be run from **Actions > Windows build > Run workflow** once the workflow is available on the repository's default branch.

The workflow discovers Visual Studio 2022 with `vswhere`, verifies the installed x64 MSVC tools, static Unicode MFC libraries and Windows SDK, and reports the selected versions. If anything is missing, it fails with the missing component or file path; it does not install Visual Studio components, drivers or other dependencies.

The workflow runs standard-library Python project/resource layout checks before building. After a successful MSVC build, it runs `TeliphonesCoreTests.exe`, checks that `TELIPHONES.exe` is an AMD64 Windows GUI PE executable without a .NET CLR header, verifies its embedded manifest and runtime imports, and launches malformed tunnel-helper requests to verify that the real executable loads and rejects them without UAC, networking or tunnel installation. This is not an interactive GUI or WireGuard integration test. The Python broker-contract tests are Linux-only because the root broker imports `pwd`; they are not run in this Windows job.

The x64 manifest uses explicit `amd64` application and Common Controls version 6 identities. The workflow extracts and prints the actual embedded manifest, validates it using the SDK's `mt.exe`, and requires exactly one matching Common Controls dependency after linker manifest merging. It preserves `asInvoker`, `uiAccess="false"` and the DPI settings. The project disables automatic DPI manifest generation so the custom manifest is the sole source: exactly one legacy `dpiAware` (`true/pm`) and one modern `dpiAwareness` (`PerMonitorV2`) declaration, checked in the embedded manifest by Actions. The startup smoke test must launch both malformed helper invocations and receive exit code 2 (argument rejection before elevation/networking); a loader error or timeout fails the run.

If startup fails with an incorrect side-by-side configuration, the workflow prints the `sxstrace` activation trace and recent Windows Application **SideBySide** events. Download **TELIPHONES-Windows-startup-diagnostics** from that failed run for the extracted manifest, DLL import list, startup error and available trace/event files. Diagnostic-tool failures are reported and do not bypass the executable startup test. The application artifact is uploaded only after all validation succeeds. A manifest correction is not Windows-validated until a new run passes the real smoke test.

Download **TELIPHONES-Windows-x64** from the successful run's **Artifacts** section. It contains `TELIPHONES.exe`, this README, the Windows changelog and `build-info.json`, not source archives, test binaries, keys, profiles, caches or tunnel configurations. The build information records the embedded product/file version, source commit, Actions run/attempt and executable SHA-256. The workflow checks both textual and fixed numeric executable versions against `Version.h` and requires the prerelease flag before publishing the artefact. The version is also visible in **Properties > Details** on the executable and in the main window title. Artefacts are retained for 14 days. It creates no GitHub Release and deploys nothing.

Extract the artifact and run `TELIPHONES.exe` on Windows 10/11 x64. Release builds statically link MFC and the MSVC C/C++ runtime (`/MT`), so no separate Visual C++ Redistributable or MFC DLL is expected; Windows system DLLs remain required. No .NET runtime is used. The application offers [WireGuard installation](#secure-connectivity-and-wireguard-installation) if needed. **Open SSH** requires Windows OpenSSH Client unless PuTTY is selected. An unsigned test executable may trigger Windows SmartScreen; the workflow does not code-sign it.

## Secure connectivity and WireGuard installation

On first launch, **Welcome to TELIPHONES** guides you through three steps:

1. **Applications:** select your browser and SSH terminal. **Save & Next** saves the preferences immediately; **Skip** saves the defaults.
2. **Secure connectivity:** an existing verified WireGuard installation is shown as installed and needs no changes. Otherwise, TELIPHONES explains **WireGuard is required** and offers **Install WireGuard** or **Not Now**.
3. **Get started:** choose **Add my PBX** or **Remote Support**, or **Finish** to explore the application. Pairing and connections require verified WireGuard; Settings and saved-profile management do not.

**Not Now** never downloads or installs software. Reopen **Settings... > Connectivity** whenever you are ready. The welcome wizard is not repeated once application preferences have been saved or skipped, even if installation was deferred. Closing a later step does not undo the preferences saved in Step 1.

The **Connectivity** section displays **WireGuard for Windows**, with **Installed**, **Not installed** or **Installation failed** status and verification details. **Check Again** refreshes detection, including when an administrator installed WireGuard independently. **Install WireGuard** is available when it is missing, and can be retried after cancellation or failure.

### Installation mechanism and verification

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

Sources checked with explicit approval: the [official installation page](https://www.wireguard.com/install/), [WireGuard enterprise installation guidance](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md), the [Microsoft WinGet x64 installer manifest](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/w/WireGuard/WireGuard/1.1.1/WireGuard.WireGuard.installer.yaml) and [Windows Installer command-line documentation](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options). The official MSI was downloaded for read-only inspection: its hash matched the manifest and its embedded signer certificate named WireGuard LLC. This was **not** Windows Authenticode trust validation or an installation test.

The fixed package avoids silently following an unreviewed newer release. If it is withdrawn, changes hash or fails signature verification, installation stops until the application is updated with a reviewed package. Integrated installation requires native Intel/AMD x64 Windows; it refuses an emulated x64 application on ARM64. TELIPHONES does not update, uninstall or repair an existing installation, change existing WireGuard tunnels, synchronise profiles or change PBX pairing. No WireGuard installer or binary is redistributed in TELIPHONES.

### Cancellation and recovery

- **Not Now:** continue with non-connection functions; return to Settings later.
- **UAC declined / installer Cancel:** status explains cancellation; **Install WireGuard** retries.
- **Download, proxy, signature or publisher failure:** nothing unverified is executed; fix the reported network/policy issue and retry. Never bypass certificate checks.
- **Installer returns success but detection fails:** TELIPHONES reports failure and keeps connections disabled. Choose **Check Again**; restart Windows only if Windows Installer requested it.
- **Existing files cannot be verified or only part of WireGuard is present:** TELIPHONES will not overwrite them automatically. The failure is reported for administrator investigation.

During installation the dialog cannot be closed until the worker finishes; cancel an active MSI in its Windows Installer window. TELIPHONES does not kill a running installer or delete its input while it is in use.

## Pair an administrator workstation

1. Install `TELIPHONES-0.3.0.tgz` through FreePBX Module Admin and complete its [documented root broker bootstrap](../../teliphones/README.md#complete-installation-on-freepbx-17). After upgrading the module, rerun the bootstrap with no active support session and Windows tunnels disconnected so the separately installed broker is current. The module validates protocol 3 and the actual workstation status contract; a stale 0.1.3 broker cannot pass by only reporting a version.
2. In TELIPHONES for Windows, select **Add my PBX...**, enter a workstation name, and choose **Generate request**. Copy the request.
3. In the PBX web interface, open **Connectivity > TELIPHONES > Windows workstations**, paste the request, provide the PBX's externally reachable WireGuard hostname/IP and UDP port, select temporary or persistent access, and explicitly choose whether SSH is allowed. The pairing operation requires HTTPS.
4. Click **Copy pairing response**, paste it into the still-open Windows pairing dialog, enter an existing authorised Linux account only if SSH was approved, and click **Save connection**. The client verifies the response nonce and workstation public key before saving it.
5. Select the saved profile and click **Connect**. Windows requests administrative approval to install/start the individual tunnel service. Use **Open FreePBX** through the tunnel to open the PBX in your [preferred browser](#browser-and-ssh-terminal-preferences). **Open SSH** is offered only after the PBX has answered through the tunnel (the status shows **Connected**), and only when the PBX administrator approved SSH and an SSH account was supplied; it opens your preferred SSH terminal. Click **Disconnect** to stop/remove the tunnel service.
6. To revoke access, use **Revoke** in the PBX's Windows workstations table. Persistent pairings do not expire automatically. Removing the local profile deletes its local private key but does **not** revoke the PBX-side pairing.

The PBX's WireGuard UDP listener must be reachable from the workstation. The pairing firewall rules restrict the paired peer to the PBX web interface and optionally SSH; they do not enable forwarding. From 0.3.0, the PBX also maintains a narrowly scoped `teliphones-ws` iptables chain so FreePBX Firewall does not drop that permitted traffic; this has not yet been verified on a real PBX. If the handshake succeeds but FreePBX does not load, check the FreePBX Firewall integration status in **Windows workstations**. Review the FreePBX Firewall and router policy for the selected UDP port. The client does not alter network routes beyond the per-PBX host route.

## Remote Support profiles

1. Select **Remote Support...** and generate an engineer key. The private key is saved in Windows Credential Manager for the current Windows user; send only the displayed public key to the gateway operator.
2. The operator must enroll that public key using their trusted gateway provisioning process and issue a current grant through the reference gateway's `engineer-grant` operator command. Deliver the grant JSON over a trusted channel.
3. Select **Import grant...** to import the grant. The application rejects a grant issued for a different public key.
4. Select an unexpired authorised session and connect. The generated tunnel routes only to that session's PBX `/32`; SSH uses the existing gateway contract on TCP port `22222`.
5. The gateway remains the authority for access. A grant does not itself authorise or extend a customer session.

The reference gateway is optional infrastructure and must be separately deployed and operated. It is experimental and is not included with the Windows application.

## Browser and SSH terminal preferences

TELIPHONES opens the FreePBX interface and SSH sessions with applications you choose. The same preferences apply to every saved PBX connection, including PBXs paired later.

### First run

The first time TELIPHONES starts for a Windows user, a **Welcome to TELIPHONES** dialog asks for:

- **Default Browser**: the Windows default browser, plus whichever of Google Chrome, Microsoft Edge, Mozilla Firefox, Brave and Vivaldi are installed.
- **Default SSH Terminal**: whichever of Windows PowerShell, PowerShell 7, Windows Terminal, PuTTY and Command Prompt are installed.

Only applications found on the computer are listed. Google Chrome is preselected when installed, otherwise the Windows default browser. Windows PowerShell is preselected when installed, otherwise Command Prompt, otherwise the first terminal found.

- **Save & Next** stores your choices and advances to secure connectivity.
- **Skip** stores the preselected defaults and advances to secure connectivity. Change them later in Settings.
- **Cancel** in Step 1 stores nothing, and the welcome dialog appears again at the next start. Closing later steps preserves the saved preferences.

### Settings

Choose **Settings...** in the main window at any time. Its **Applications** section has the same **Default Browser** and **Default SSH Terminal** lists and the same storage. Changes take effect when you click **Save**. Use **Locate...** to choose an application that was not detected, for example a portable copy of PuTTY. Only the supported program files (`chrome.exe`, `msedge.exe`, `firefox.exe`, `brave.exe`, `vivaldi.exe`, `powershell.exe`, `pwsh.exe`, `wt.exe`, `putty.exe` and `cmd.exe`) on a local drive are accepted.

Detection uses the Windows registrations for installed applications (App Paths and registered browsers) and standard Windows folders, rather than fixed installation paths.

### How applications are launched

| Selection | What TELIPHONES runs |
|---|---|
| Windows default browser | The PBX address through the Windows registered URL handler, as in earlier releases |
| Chrome, Edge, Firefox, Brave, Vivaldi | The detected browser executable, with the PBX address as its only argument |
| Windows PowerShell / PowerShell 7 | A new PowerShell window running the Windows OpenSSH client, with every argument as a PowerShell literal |
| Windows Terminal | A new Windows Terminal tab running the Windows OpenSSH client |
| Command Prompt | A new Command Prompt window running the Windows OpenSSH client |
| PuTTY | PuTTY with `-ssh`, the tunnel address, the approved SSH port (`-P`), the user name (`-l`) and a per-PBX `-loghost` name for host-key checking |

The FreePBX address is unchanged: `http://<PBX tunnel address>/admin/`. TELIPHONES opens only that address, built from the validated tunnel address. SSH always targets the PBX tunnel address and approved port: the administrator's Linux account on port 22 for **My PBX**, or `root` on the support SSH service at port `22222` for Remote Support. TELIPHONES validates the user name, address, port and host-key alias before launching any terminal, passes them as separate arguments, and refuses characters that a shell could interpret.

Earlier builds opened the Windows default browser and ran `ssh.exe` directly in a new console window.

### Security

Choosing a terminal never grants SSH access. **Open SSH** still requires an active connection that the PBX has answered, SSH approval in the pairing (or the Remote Support grant), and an SSH account. TELIPHONES creates no SSH users, passwords or keys. The OpenSSH-based terminals use your existing OpenSSH credentials. PuTTY uses its own credentials and settings, for example Pageant or a `.ppk` key, and keeps its own host-key cache.

### When an application is missing

If a selected browser or terminal has been uninstalled or moved, TELIPHONES says so and never silently launches a different application.

- For a missing browser, choose **Yes** to switch to the Windows default browser, **No** to choose another in Settings, or **Cancel**.
- For a missing terminal, choose **OK** to choose another in Settings.

A missing selection stays visible in Settings, marked **(not found)**, until you replace it. If the Windows OpenSSH Client is not installed, Settings and **Open SSH** explain how to add it, or you can choose PuTTY.

### Where preferences are stored

Preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` for the current Windows user, in a strictly validated format. They survive application and Windows restarts and TELIPHONES updates. They are kept local rather than roaming because executable locations differ between computers. They are never stored in the FreePBX module or sent to a PBX or gateway. If the file cannot be read, TELIPHONES reports this and leaves it unchanged; saving from Settings replaces it.

## Local data and permissions

- Profiles contain public pairing/grant data and are stored in the user's roaming application-data directory.
- Browser and SSH terminal preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` and contain only application choices and paths.
- WireGuard private keys are stored separately in Windows Credential Manager and are not written into the profile file or copied into the gateway grant.
- Tunnel configuration is staged in a user-restricted local directory, revalidated by an elevated helper, then placed under `%ProgramFiles%\TELIPHONES\Tunnels` with a restrictive ACL.
- Each tunnel is demand-started. The helper grants the current Windows user only the service rights needed to query, stop and remove that TELIPHONES tunnel; it does not grant permission to start or reconfigure it.
- UAC approval is required for tunnel installation. Declining it cancels the connection.
- Only one connection is active at a time. The app probes the PBX through the tunnel, displays session expiry, and requests disconnection on expiry or detected loss of PBX reachability. Normal application exit requests disconnection.
- Revocation detection is based on reachability checks, not a server-pushed revocation channel. A revoked but otherwise reachable/established flow may not be detected instantaneously; verify teardown behavior in the supported PBX/gateway environment before relying on it.

## Test plan and limitations

The C++ core tests and contract tests check parsing, key/request binding, grant binding, narrow host routes, tunnel rendering, command construction, connection monitor behavior, and parity with the broker/gateway contracts. They also simulate browser and terminal preferences: first-run save, skip and cancel; detection-driven choices and defaults; saving, restoring and changing preferences; missing and mismatched applications; and the exact command line for each supported browser and terminal, including paths with spaces and rejection of unsafe arguments. They do not execute Win32 APIs, so registry detection, the dialogs and real application launches are untested on Linux.

The build-layout checks also verify SDK header ordering (`Win.h`, which includes `windows.h`, before `shellapi.h`), the Settings dialog's explicit `commdlg.h` include, and the required shell, file-dialog and registry libraries in both native build configurations. These are source checks, not a substitute for compiling and linking with MSVC, MFC and the Windows SDK.

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
   - Confirm **Open SSH** works with each terminal, including a user profile path containing spaces.
   - Uninstall or rename a selected application and confirm the error and recovery choices.
   - Confirm Open SSH stays unavailable without SSH approval.
9. On disposable fresh Windows 10/11 x64 machines, test the complete installer UI with a standard user and a separate administrator account, cancellation/UAC refusal, blocked downloads and revocation servers, unexpected signatures/hashes, post-install detection, retries, safe temporary-file cleanup and connection controls becoming available. Repeat with WireGuard already installed and confirm profiles, preferences and pre-existing tunnels remain unchanged. No live Windows installer validation has been performed locally.

No Windows executable is included in the module package. The existing executable has compiled and launched in user-run Windows testing and is available from the successful Actions artifact. The local Linux development environment does not have MSVC, MFC, or a Windows SDK. UAC, Credential Manager, WireGuard driver/service behavior, visual layout and real PBX connectivity still require interactive Windows/disposable-PBX testing.
