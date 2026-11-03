# TELIPHONES 0.6.4 for Windows (experimental)

**TELIPHONES is a UK registered trademark.**

**TELIPHONES 0.6.4 for Windows is licensed under GPLv3.**

GPLv3 licensing applies to the software and does not grant trademark rights.
The main window displays both statements in a fixed footer beneath the connection
controls, also available in Settings > About, using the application version
definition. The footer is a centred, regular-weight single line with vertical
padding and stays outside the scrolling content. Narrow windows use end ellipsis;
the complete wording remains in Settings > About. The existing GPLv3-or-later software licence grant is unchanged;
see LICENSE in the distributed application ZIP for the full licence text.

The native Windows client is under active development and versioned independently of the FreePBX module, now **0.3.5**. The current unreleased Windows version is **0.6.4**, shown in the main window title and embedded product version, with Windows file version **0.6.4.0**. This patch corrects conflicting dropdown selection/focus painting while preserving native Windows caption-frame theming and the 0.6.0 appearance feature; it does not implement SSH authentication or establish that Chrome's download warning is resolved. Windows **0.7.0 is reserved for the upcoming fully automated SSH authentication functionality**. Individual builds are identified by Git commit SHA and Actions provenance. See the [Windows change history and versioning policy](CHANGELOG.md). The manifest's `assemblyIdentity` is a fixed side-by-side identity, not the release number. Earlier operator tests of 0.4.0 established a WireGuard tunnel and reached SSH using PuTTY; they do not validate this new version or its monitor. The native C++17 Win32/MFC application has two independent profile types:

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

The application and portable tests are written to `build\Release\`. Run `build\Release\TeliphonesCoreTests.exe` and `build\Release\SessionDiagnosticsTests.exe` for the core and diagnostic-storage regressions. The portable tests and broker contracts can also be run on Linux with CMake:

```sh
cmake -S . -B /tmp/teliphones-windows-core
cmake --build /tmp/teliphones-windows-core
ctest --test-dir /tmp/teliphones-windows-core --output-on-failure
```

### GitHub Actions build and download

The [Windows build workflow](../../.github/workflows/windows-build.yml) builds the existing Visual Studio solution in **Release x64** on a GitHub-hosted `windows-2022` runner. It runs automatically when changes under `desktop/windows/` or the workflow itself are pushed. It can also be run from **Actions > Windows build > Run workflow** once the workflow is available on the repository's default branch.

The workflow discovers Visual Studio 2022 with `vswhere`, verifies the installed x64 MSVC tools, static Unicode MFC libraries and Windows SDK, and reports the selected versions. If anything is missing, it fails with the missing component or file path; it does not install Visual Studio components, drivers or other dependencies.

The workflow runs standard-library Python project/resource layout checks before building. After a successful MSVC build, it runs `TeliphonesCoreTests.exe` and `SessionDiagnosticsTests.exe`, checks that `TELIPHONES.exe` is an AMD64 Windows GUI PE executable without a .NET CLR header, verifies its embedded manifest and runtime imports, and launches malformed tunnel-helper requests to verify that the real executable loads and rejects them without UAC, networking or tunnel installation. This is not an interactive GUI or WireGuard integration test. The Python broker-contract tests are Linux-only because the root broker imports `pwd`; they are not run in this Windows job.

The x64 manifest uses explicit `amd64` application and Common Controls version 6 identities. The workflow extracts and prints the actual embedded manifest, validates it using the SDK's `mt.exe`, and requires exactly one matching Common Controls dependency after linker manifest merging. It preserves `asInvoker`, `uiAccess="false"` and the DPI settings. The project disables automatic DPI manifest generation so the custom manifest is the sole source: exactly one legacy `dpiAware` (`true/pm`) and one modern `dpiAwareness` (`PerMonitorV2`) declaration, checked in the embedded manifest by Actions. The startup smoke test must launch both malformed helper invocations and receive exit code 2 (argument rejection before elevation/networking); a loader error or timeout fails the run.

If startup fails with an incorrect side-by-side configuration, the workflow prints the `sxstrace` activation trace and recent Windows Application **SideBySide** events. Download **TELIPHONES-Windows-startup-diagnostics** from that failed run for the extracted manifest, DLL import list, startup error and available trace/event files. Diagnostic-tool failures are reported and do not bypass the executable startup test. The application artifact is uploaded only after all validation succeeds. A manifest correction is not Windows-validated until a new run passes the real smoke test.

Download **TELIPHONES-Windows-x64** from the successful run's **Artifacts** section. It contains `TELIPHONES.exe`, this README, the Windows changelog, `LICENSE` and `build-info.json`, not source archives, test binaries, keys, profiles, caches or tunnel configurations. The build information records the embedded product/file version, source commit, Actions run/attempt and executable SHA-256. The workflow checks both textual and fixed numeric executable versions against `Version.h` and requires the prerelease flag before publishing the artefact. The version is also visible in **Properties > Details** on the executable and in the main window title. Artefacts are retained for 14 days. It creates no GitHub Release and deploys nothing.

Extract the artifact and run `TELIPHONES.exe` on Windows 10/11 x64. Release builds statically link MFC and the MSVC C/C++ runtime (`/MT`), so no separate Visual C++ Redistributable or MFC DLL is expected; Windows system DLLs remain required. No .NET runtime is used. The application offers [WireGuard installation](#secure-connectivity-and-wireguard-installation) if needed. **Open SSH** requires Windows OpenSSH Client unless PuTTY is selected. An unsigned test executable may trigger Windows SmartScreen; the workflow does not code-sign it.

## Appearance

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
advance the patch version. Windows 0.7.0 is reserved for the upcoming fully automated SSH authentication functionality.

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

1. Install `TELIPHONES-0.3.5.tgz` through FreePBX Module Admin and complete its [documented root broker bootstrap](../../teliphones/README.md#complete-installation-on-freepbx-17). After upgrading the module, rerun the bootstrap with no active support session and Windows tunnels disconnected so the separately installed broker is current. A module upgrade alone does not replace the privileged broker.
2. In TELIPHONES for Windows, select **Add my PBX...**, enter a workstation name, and choose **Generate request**. Copy the request.
3. In the PBX web interface, open **Connectivity > TELIPHONES > Windows workstations**, paste the request, provide the PBX's externally reachable WireGuard hostname/IP and UDP port, select temporary or persistent access, and explicitly choose whether SSH is allowed. The pairing operation requires HTTPS.
4. Click **Copy pairing response**, paste it into the still-open Windows pairing dialog, enter an existing authorised Linux account only if SSH was approved, and click **Save connection**. The client verifies the response nonce and workstation public key before saving it.
5. Select the saved profile and click **Connect**. Windows requests administrative approval to install/start the individual tunnel service. The **Connection Health...** control reports whether the authorised PBX is responding separately from the pairing's remaining authorisation time. Use **Open FreePBX** through the tunnel to open the PBX in your [preferred browser](#browser-and-ssh-terminal-preferences). **Open SSH** is offered only after the PBX has answered through the tunnel (the status shows **Connected**), and only when the PBX administrator approved SSH and an SSH account was supplied; it opens your preferred SSH terminal. Click **Disconnect** to stop/remove the tunnel service.
6. To revoke access, use **Revoke** in the PBX's Windows workstations table. Persistent pairings do not expire automatically. Removing the local profile deletes its local private key but does **not** revoke the PBX-side pairing.

The PBX's WireGuard UDP listener must be reachable from the workstation. The pairing firewall rules restrict the paired peer to the PBX web interface and optionally SSH; they do not enable forwarding. From 0.3.0, the PBX also maintains a narrowly scoped `teliphones-ws` iptables chain so FreePBX Firewall does not drop that permitted traffic; this has not yet been verified on a real PBX. If the handshake succeeds but FreePBX does not load, check the FreePBX Firewall integration status in **Windows workstations**. Review the FreePBX Firewall and router policy for the selected UDP port. The client does not alter network routes beyond the per-PBX host route.

## Connection Health

The main window starts at approximately **1050 x 620 logical pixels**, scaled for the current DPI and clamped to the monitor work area. The left column contains the profile list, pairing/removal, Remote Support/grant actions and selected-profile details. The right contains connection status, distinct connected/authorization/healthy durations, measurements, the live graph, **Pop Out** and **View Session Log**. The list and graph grow with the window. Under narrow/high-DPI work areas the columns stack in a vertically scrollable viewport, with scrollbar, mouse wheel and automatic keyboard-focus reveal. **Connect**, **Disconnect**, **Open FreePBX**, **Open SSH**, **Settings** and **Close** remain in a fixed wrapping action bar outside that viewport. Read-only details and diagnostic guidance can also be scrolled/copied rather than being silently truncated. The main window does not restore stale saved geometry; each launch is positioned within the current work area, and DPI transitions relayout controls and fonts.

The main window shows the selected PBX's health, current TCP latency, recent jitter, application probe failures, upload/download rates, handshake freshness and continuously healthy duration. A plot selector switches between **Latency & jitter**, **Upload / download** and **Failures & interruptions**, using one compact plot instead of vertically stacked graphs. Axes and traffic rates auto-scale; unavailable observations are gaps rather than zero latency. History can be 60 seconds or five minutes. **Pop Out** opens a separate compact resizable monitor using the same samples and plot choices. Recent bounded history for each profile remains available in either display after disconnecting, until application exit or profile removal; no stale history initiates probes or restores authorization. Closing the pop-out never stops sampling. **Always on Top**, pop-out position, history length and thresholds persist locally; restarting the application starts fresh measurements.

The monitor is a separate modeless window explicitly owned by the main TELIPHONES window, which stays visible and enabled. It has a task-switcher/taskbar entry. Opening it again reuses the same window and restores it if minimized; Close, Escape and Enter hide only the monitor. Every opening checks its position against the current display work area, clamps partial/off-screen geometry and falls back to the main window's monitor after a display is removed. Native MFC lifecycle tests are built and run by Actions, but remain unverified until that Windows build succeeds; portable positioning tests do not validate actual window behavior.

Native tests now exercise the layout adapter at 1024/1366/1920 display sizes, reduced work-area heights, minimum/large windows and 96/120/144/192 DPI layout inputs, including command forwarding, Tab focus, wheel/scrollbar bounds and pop-out lifecycle. Injected DPI inputs are not changes to the runner's display scaling. Manual inspection at actual 100%, 125%, 150% and 200% Windows scaling, multi-monitor DPI transitions and real connected/expired/persistent sessions remains required. No visual correctness or successful MSVC/MFC compilation is claimed from the Linux tests.

The monitor samples every two seconds when the UI is active; WireGuard counters/handshake are queried every six seconds to keep process and CPU overhead low. Its TCP connection-establishment time to the currently authorised PBX's tunnel address on port 443 (with port 80 as a fallback) is labelled **TCP RTT**; it is not ICMP ping. Probe success/failure percentages and consecutive failures are application-level TCP checks. A failed TCP application probe is **not** a measurement of network packet loss. It never probes an old pairing address, an Internet service, the SSH port, or any host other than the active profile's PBX.

Transmit/receive rates use actual interval byte-counter deltas, not an estimate of bandwidth. The preferred source is `wg.exe show <active tunnel> transfer`; handshake age uses `latest-handshakes`. These WireGuard Windows management reads can require administrator permission independently of PBX traffic. If unavailable, the Windows IP Helper `GetIfTable2` API reads the exact active tunnel interface alias's IP-byte counters, labelled separately from WireGuard peer transport counters. No service/pipe ACLs are widened and no automatic elevation is introduced. Handshake remains **Unknown** when its source is inaccessible. Diagnostics preserve the command stage, exit code and sanitized error, or the specific interface lookup failure. A source change resets rate baselines rather than mixing incompatible counters.

Stable requires five consistent successful checks. Defaults warn at 300 ms current TCP latency or 100 ms recent jitter; **Limits...** allows 200/300/500 ms latency, 50/100/200 ms jitter and 2/3/4 consecutive failures before Unstable. Five consecutive failures or a known stopped tunnel produce Disconnected health, but application-probe failures do not remove the WireGuard tunnel. Expired authorization does remove it. Unknown local measurements are not failures. A handshake older than 180 seconds is a freshness warning, not proof an idle peer disconnected. No packet loss, total available bandwidth, network saturation or guaranteed SSH command safety is claimed.

Authorization remaining time is displayed separately from reachability: for example, an unexpired pairing can still have 44 minutes remaining while the PBX is disconnected or no longer answering. A degraded connection disables starting a new SSH session until TELIPHONES verifies the PBX again. Health warnings do not close existing terminal windows or automatically remove the tunnel; authorization expiry continues to use the existing disconnect behavior. Recovery is observed through subsequent successful checks.

Persistent authorization displays **Until revoked**. Temporary expiry and WireGuard handshake timestamps use UTC, while graph history, intervals and healthy duration use a monotonic clock. Mixing Unix expiry with Windows uptime caused the previous enormous remaining-time display; it is no longer used.

The main panel and pop-out share three separate values: **Connected for** starts at zero on the first successful PBX reachability check and uses monotonic elapsed time; **Authorisation remaining** uses the original UTC expiry (or **Until revoked**); **Connection health** shows the independent continuously healthy duration, beginning only when Stable is established. Brief failed checks reset healthy time but keep the connected timer running. Declared connection loss (three consecutive failed checks), a stopped tunnel or expiry stops connected time; subsequent successful recovery starts it at zero. Manual disconnect/reconnect also starts a fresh duration without renewing authorization. Missing fresh measurements do not display an advancing connected duration.

### Session diagnostics

**View Session Log** shows the selected pairing's sanitized local timeline and exports the same text through a native Save dialog. Logs live under `%LOCALAPPDATA%\TELIPHONES\Diagnostics` with a protected current-user/SYSTEM directory. Storage rotates at 1 MiB per file, retains three files total and removes records older than seven days on access. Cross-process locking protects writes/rotation; failures are reported rather than silently ignored. Shutdown closes logging without a persistent logging worker.

Events include startup/shutdown, local pairing changes, manual connection attempts, service establishment/removal, health/probe/telemetry transitions, errors and minute summaries. Deterioration events retain recent bounded measurements. Logs never dump profiles, tunnel configurations, passwords or key material; detail sanitization also applies before viewing/export.

For **My PBXs**, both ends use `ws-<workstation_id>` as a non-secret pairing-lifetime diagnostic identifier. Each Windows connection has a separate local attempt identifier, since the current pairing protocol does not notify the broker of application button presses. The PBX records only its own peer/interface/authorization/firewall observations, never a fictional client connect or failure. Compare UTC timelines allowing for clock skew, aided by local monotonic elapsed milliseconds. **Remote Support** uses separate local `support-<profile_id>` identifiers, not these PBX workstation logs.

The FreePBX full-administrator interface provides the corresponding bounded broker diagnostics. Export each side to compare events; insufficient evidence remains explicitly inconclusive. The diagnostics do not grant SSH access or transmit logs to a telemetry service.

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

If PuTTY reports **No supported authentication methods available (server sent: publickey)**, it has reached an SSH server that requires public-key authentication; the selected account has not authenticated with an accepted key. TELIPHONES currently neither generates/enrols SSH keys nor passes a managed identity file to the terminal. Its Credential Manager keys are for WireGuard, not SSH. Do not enable password fallback or copy server private keys to resolve this. A separate workstation SSH key-management workflow is proposed for review, not implemented in 0.6.0; fully automated SSH authentication is reserved for Windows 0.7.0.

### When an application is missing

If a selected browser or terminal has been uninstalled or moved, TELIPHONES says so and never silently launches a different application.

- For a missing browser, choose **Yes** to switch to the Windows default browser, **No** to choose another in Settings, or **Cancel**.
- For a missing terminal, choose **OK** to choose another in Settings.

A missing selection stays visible in Settings, marked **(not found)**, until you replace it. If the Windows OpenSSH Client is not installed, Settings and **Open SSH** explain how to add it, or you can choose PuTTY.

### Where preferences are stored

Preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` for the current Windows user, in a strictly validated format. They survive application and Windows restarts and TELIPHONES updates. They are kept local rather than roaming because executable locations differ between computers. They are never stored in the FreePBX module or sent to a PBX or gateway. If the file cannot be read, TELIPHONES reports this and leaves it unchanged; saving from Settings replaces it.

## Local data and permissions

- Profiles contain public pairing/grant data and are stored in the user's roaming application-data directory.
- Browser, SSH terminal and appearance preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` and contain only application choices, paths and appearance mode.
- WireGuard private keys are stored separately in Windows Credential Manager and are not written into the profile file or copied into the gateway grant.
- Tunnel configuration is staged in a user-restricted local directory, revalidated by an elevated helper, then placed under `%ProgramFiles%\TELIPHONES\Tunnels` with a restrictive ACL.
- Each tunnel is demand-started. The helper grants the current Windows user only the service rights needed to query, stop and remove that TELIPHONES tunnel; it does not grant permission to start or reconfigure it.
- UAC approval is required for tunnel installation. Declining it cancels the connection.
- Only one connection is active at a time. The app probes the PBX through the tunnel and displays session expiry separately from reachability. Authorization expiry disconnects the tunnel; detected loss of PBX reachability warns and disables new SSH launches, but does not automatically remove the tunnel or close existing terminal windows. Normal application exit requests disconnection.
- Revocation detection is based on reachability checks, not a server-pushed revocation channel. A revoked but otherwise reachable/established flow may not be detected instantaneously; verify teardown behavior in the supported PBX/gateway environment before relying on it.

## Test plan and limitations

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
are registered for Actions but their Windows results remain pending.

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

No Windows executable is included in the module package. The existing executable has compiled and launched in user-run Windows testing and is available from the successful Actions artifact. The local Linux development environment does not have MSVC, MFC, or a Windows SDK; local tests do not establish native compilation. The operator's 0.4.0 tunnel/PuTTY result does not complete UAC, Credential Manager, WireGuard lifecycle, visual layout, firewall-enabled web access or authenticated SSH validation.
