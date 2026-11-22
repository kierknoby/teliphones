# TELIPHONES 0.10.0 for Windows (experimental)

Current 0.8.0 authority, firewall and lease changes: [implementation and acceptance](../../teliphones/docs/DEVELOPMENT-0.8.0.md).
Unknown-public-IP FreePBX 17 connectivity remains unverified. Historical evidence
below does not validate this development candidate.

**TELIPHONES is a UK registered trademark.**

**TELIPHONES 0.10.0 for Windows is licensed under GPLv3.**

Reach your PBX privately, open FreePBX in your preferred browser and start an
approved SSH session without distributing permanent administrator SSH credentials.
This guide covers installing and using the Windows application. The
[FreePBX administration guide](../../teliphones/README.md) covers server setup.

Windows **0.10.0** (file version **0.10.0.0**) is independent of FreePBX
module/root broker **0.9.0.1**, protocol **12**. The matching 0.9.0.1 module
archive is a local maintenance package, not a release or
production approval. The checksum-verified historical 0.6.7 archive is at the
repository root and does not contain these newer changes.
Native Windows compilation and dialog interaction remain release blockers. The
new v3 pairing response can populate the editable HTTPS hostname only when the
PBX administrator has explicitly configured it; the broker does not inspect
certificate SANs or infer the name from the WireGuard endpoint. If absent,
confirm the exact DNS name with the administrator. Windows retains normal
certificate validation. Permanent authority has no expiry deadline, but it
does not bypass the short renewable active-session lease.
Windows 0.10.0 bounds tunnel establishment, authentication and controller admission;
allows Disconnect and Close during Connect; and persists exact tunnel ownership
for safe next-launch recovery. Its elevated cleanup can remove a residual
adapter through Windows Configuration Manager only after the current interface
GUID and PnP instance match the protected ownership record. It also retains
route-aware admission-failure reporting, local network-change detection and
correlation with PBX-side session diagnostics from 0.8.5, the earlier service
lifecycle corrections and SSH recovery, and 0.8.3's official
WireGuardNT 1.1 adapter-API activation with memory-only keys. It retains 0.8.1's pairing dialogue order, stale-request handling, Copy/Save
   availability and response-derived approved SSH account display, and the 0.8.0 source
   features: password protection, listener migration, PBX policy/status, Allowed
   List and unlock requests, and post-pair SSH elevation. The experimental
   built-in SSH console is disabled on the active Open SSH path; managed SSH uses
   the selected external OpenSSH-backed terminal. Earlier reports of the console
   closing TELIPHONES are historical and do not establish a current external
   terminal defect. Public-IP roaming and the 0.10.0 changes still require native
   and live-system acceptance. This version is unreleased, not a published download.
The [version definition](src/app/Version.h), not the manifest assembly identity,
defines the application version.

**Secure management GUI:** TELIPHONES preserves the PBX-configured primary service
order. HTTP primary pairings fail closed; TELIPHONES does not reorder services,
rewrite pairings, or change firewall permissions. A PBX administrator must
explicitly approve configuring certificate-valid HTTPS as primary, then the
operator must explicitly pair again. For HTTPS, enter the certificate DNS
hostname during pairing or configure it later using **HTTPS Hostname...** on
the saved administrator profile, based on information supplied or confirmed by
the PBX administrator. A v3 response automatically populates the editable
hostname field when the PBX has an explicitly configured hostname; if the
response contains `null`, confirm the exact DNS name with the administrator.
The hostname is not inferred from the WireGuard endpoint. TELIPHONES launches
the selected supported Chromium browser (Microsoft Edge, Google Chrome or Brave)
with a unique isolated profile, maps only that explicit hostname
to the paired WireGuard IPv4, blocks other DNS hostnames in that profile, disables
proxy use, and leaves normal TLS certificate validation enabled. It launches only
after verifying the tunnel service, route selection and a fresh management TCP
probe; the owned browser process job is closed when disconnect is requested or the
monitor observes tunnel loss. This is a scoped resolver/profile and process
lifecycle measure, **not universal network confinement**: IP-literal access,
redirect behavior, browser/OS networking and races while the tunnel disappears
are not proven blocked. Do not rely on it as a general egress firewall. The public
WireGuard endpoint is never treated as a TLS hostname, and certificate errors are
not bypassed. Native Windows/browser acceptance is still required.

> [!WARNING]
> **Experimental, not production-ready.** Conflicting historical operator reports
> state that eleven and ten native OpenSSH integration tests passed. A successful
> first-run startup smoke, authenticated SSH into a FreePBX 17 test server and
> automatic closure of the owned terminal when TELIPHONES disconnects were also
> reported. Complete server-side revocation,
> authorisation expiry, systemd/cgroup lifecycle, reconnection and failure
> recovery still need live validation. The experimental embedded SSH console is
> disabled on the active managed SSH path; those reports do not establish a
> current external-terminal defect or acceptance of the external SSH workflow.
> These supplied reports lack matching run/build identifiers and raw logs; they
> do not establish which test count is accurate, validate current 0.10.0 source or
> establish a matching binary. See
> [verification status](#verification-status).

## Choose your workflow

- **My PBXs:** pair your own workstation with a full administrator's approval
  on the PBX. Choose temporary or persistent access. Open FreePBX normally;
  managed SSH additionally requires explicit approval of an existing account.
- **Remote Support:** use a separately enrolled engineer identity and import
  an operator-issued grant. This is a customer-authorised support window, not
  workstation pairing, and still needs end-to-end validation.

Both use separately installed WireGuard for Windows tunnel services.
TELIPHONES bundles the pinned official WireGuardNT API DLL, not the WireGuard
application or installer. It does not create SSH accounts, supply hosted support
infrastructure or provide a relay.

## In this guide

- [Requirements and download](#requirements-and-download)
- [First launch and WireGuard](#secure-connectivity-and-wireguard-installation)
- [Pair, connect and open FreePBX](#pair-an-administrator-workstation)
- [Open an authorised SSH session](#open-an-authorised-ssh-session)
- [Connection Health and session diagnostics](#connection-health)
- [Disconnect, remove or revoke](#disconnect-remove-or-revoke)
- [Settings, applications and appearance](#browser-and-ssh-terminal-preferences)
- [Remote Support profiles](#remote-support-profiles)
- [Troubleshooting](#troubleshooting)
- [Security](#security) · [Verification status](#verification-status)
- [Developer builds and testing](#developer-builds-and-testing) · [Licence](#licence)

## Secure Administration Without Exposing Your PBX

The private route lets administrators restrict public GUI/SSH access policies;
TELIPHONES **does not replace FreePBX Firewall or automatically close those
services to the internet**. The PBX administrator must configure and verify the
router, host and FreePBX Firewall restrictions, testing the tunnel before
restricting an existing administration route. Required public telephony traffic
(such as SIP and RTP) is separate from private management access.

A reachable WireGuard UDP endpoint is still required and may need port
forwarding. There is no universal NAT traversal or relay connectivity.
Reducing public management exposure reduces attack surface, not every security
risk. See the [current security limitations](#security).

## Requirements and download

- **Windows 10/11 x64**, with administrator approval available for tunnel setup.
  The integrated WireGuard installer requires native Intel/AMD x64, not x64
  emulation on ARM64.
- **WireGuard for Windows.** Reuse a verified installation or explicitly choose
  **Install WireGuard** during first launch. It is not bundled.
- **For managed SSH only:** Windows system OpenSSH Client and Windows PowerShell,
  PowerShell 7, Windows Terminal or Command Prompt. GUI-only pairing needs no
  OpenSSH. PuTTY cannot authenticate My PBXs managed certificates.
- **A prepared PBX:** FreePBX 17 / Debian 12, current module and root broker,
  HTTPS for pairing and a reachable WireGuard UDP endpoint.

### Download an existing build

**No matching successful CI run or downloadable 0.10.0 build can be verified from
this checkout; functional/native acceptance is outstanding.** Earlier Windows
CI builds completed for 0.9.0. The artifact from run `43980149884` (artifact
`14281389786`) is blocked by Chrome as “Dangerous download blocked”; the cause
is unresolved. Do not bypass browser or operating-system protection, and do not
substitute an older run for the current source.

The Windows Actions workflow defines a **TELIPHONES-Windows-x64** artifact, but
that workflow configuration is not evidence that a 0.10.0 run succeeded or that
an artifact is currently available. Any artifact's existence would not establish
functional acceptance or safe public download availability. No public release or
direct public download is claimed.
Extract the ZIP and keep **`TELIPHONES.exe`, `TELIPHONES-SSH.exe` and
`wireguard.dll` together**.
It also contains this guide, the changelog, licences and `build-info.json`,
which records source/run provenance and executable hashes, not user data.
Technical links in the bundled guide refer to the source checkout; developer
references and PBX documentation are not included in the application ZIP.

Run `TELIPHONES.exe`. No .NET runtime or separate MFC/Visual C++ runtime is
expected for the static Release build. Windows system components remain required.
Test executables are unsigned and may trigger SmartScreen; verify their trusted
source rather than disabling Windows protections. For source builds, see
[developer builds and testing](tests/WINDOWS-READINESS.md#developer-builds-and-testing).

### Upgrade the development workstation after native validation

Do not upgrade to 0.10.0 until the exact
build passes native Release compilation, the complete CTests (including
`tunnel_startup_native` with its stuck
`START_PENDING` and per-tunnel lock cases, and `wireguard_nt_unit`),
the actual official service/driver integration gate, application tests and
startup smoke. CI artifact availability does not establish that these
acceptance checks have passed. The existing build produces a portable
application bundle, not an MSI installer. The workflow's bundle directory is
`desktop/windows/build/artifact`; its Actions artefact name is
**TELIPHONES-Windows-x64**.

1. Disconnect in the previous installation and close TELIPHONES and its owned SSH console. Retain
   the old application directory for rollback; do not delete profiles,
   Credential Manager entries or application data.
   If a `WireGuardTunnel$TELIPHONES-*` service remains (for example stuck in
   `START_PENDING`), record the read-only diagnostics in
   [Troubleshooting](#troubleshooting). Do not assume cleanup or network roaming
   succeeded unless the application confirms it.
2. Extract the validated bundle into a separate **TELIPHONES-0.10.0** directory.
   Keep both executables, `wireguard.dll`, licences and `build-info.json` together.
3. Before launch, in PowerShell in that directory, check:

   ```powershell
   $info = Get-Content .\build-info.json -Raw | ConvertFrom-Json
   $version = [Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path .\TELIPHONES.exe).Path)
   if ($version.ProductVersion -ne '0.10.0' -or $version.FileVersion -ne '0.10.0.0') { throw 'Wrong executable version' }
   if ($info.productVersion -ne '0.10.0' -or $info.fileVersion -ne '0.10.0.0') { throw 'Wrong build metadata' }
   if ((Get-FileHash .\TELIPHONES.exe -Algorithm SHA256).Hash -ine $info.sha256) { throw 'Application hash mismatch' }
   if ((Get-FileHash .\TELIPHONES-SSH.exe -Algorithm SHA256).Hash -ine $info.sshHelperSha256) { throw 'SSH helper hash mismatch' }
   if ((Get-FileHash .\wireguard.dll -Algorithm SHA256).Hash -ine $info.wireGuardNtSha256) { throw 'WireGuardNT hash mismatch' }
   ```

4. Launch the new executable, confirm **0.10.0** in About and reuse the saved
   profile without re-pairing. Perform one controlled Connect and retain the
   WireGuard log plus any stage-specific error. Confirm sustained service
   operation, eventual handshake, approved PBX access and disconnect/reconnect.
   A Running service alone is not proof of connectivity. If activation fails,
   confirm cleanup and stop; do not repeat connection attempts blindly.

## Secure connectivity and WireGuard installation

On first launch, **Welcome to TELIPHONES** guides you through three steps:

1. **Applications:** select your browser and SSH terminal. **Save & Next** saves the preferences immediately; **Skip** saves the defaults.
2. **Secure connectivity:** an existing verified WireGuard installation is shown as installed and needs no changes. Otherwise, TELIPHONES explains **WireGuard is required** and offers **Install WireGuard** or **Not Now**.
3. **Get started:** choose **Add my PBX** or **Remote Support**, or **Finish** to explore the application. Pairing and connections require verified WireGuard; Settings and saved-profile management do not.

**Not Now** never downloads or installs software. Reopen **Settings... > Connectivity** whenever you are ready. The welcome wizard is not repeated once application preferences have been saved or skipped, even if installation was deferred. Closing a later step does not undo the preferences saved in Step 1.

The **Connectivity** section displays **WireGuard for Windows**, with **Installed**, **Not installed** or **Installation failed** status and verification details. **Check Again** refreshes detection, including when an administrator installed WireGuard independently. **Install WireGuard** is available when it is missing, and can be retried after cancellation or failure.

The installer downloads only a reviewed official x64 MSI after explicit approval, checks its pinned hash and Authenticode publisher, and uses normal Windows Installer/UAC. It rechecks the installed files before enabling connections. No verification bypass or automatic restart is offered. [Technical verification reference](tests/WINDOWS-READINESS.md#wireguard-installer-verification).

### Cancellation and recovery

- **Not Now:** continue with non-connection functions; return to Settings later.
- **UAC declined / installer Cancel:** status explains cancellation; **Install WireGuard** retries.
- **Download, proxy, signature or publisher failure:** nothing unverified is executed; fix the reported network/policy issue and retry. Never bypass certificate checks.
- **Installer returns success but detection fails:** TELIPHONES reports failure and keeps connections disabled. Choose **Check Again**; restart Windows only if Windows Installer requested it.
- **Existing files cannot be verified or only part of WireGuard is present:** TELIPHONES will not overwrite them automatically. The failure is reported for administrator investigation.

During installation the dialogue cannot be closed until the worker finishes; cancel an active MSI in its Windows Installer window. TELIPHONES does not kill a running installer or delete its input while it is in use.

## Pair an administrator workstation

Older package and broker details are historical context only. This 0.10.0
candidate is not live-accepted or approved for production use; no matching
successful Windows CI run or downloadable artifact can be verified from this
checkout, and functional/native acceptance remains outstanding. A CI artifact
would not by itself be an accepted upgrade. The historical 0.6.7
archive predates these changes. After an
authorized controlled-development installation or upgrade, complete the
[root broker bootstrap](../../teliphones/README.md#complete-installation-on-freepbx-17)
with no active support session and workstation tunnels disconnected. Verify
   that the broker reports version 0.9.0.1 and protocol 12; an operational socket
alone does not confirm the required broker version.

1. Select **Add my PBX...** and enter the workstation name under **Pair my PBX >
   Request access**.
2. Select **FreePBX Web Access** (default, no SSH identity/OpenSSH dependency)
   or **FreePBX Web + SSH Access** before generating. The latter enrols a
   separate DPAPI-protected permanent identity for certificate requests, never
   the disposable session certificate subject. Requesting SSH grants nothing.
3. Select **Generate request**, then **Copy request**. Copy is unavailable until
   generation succeeds. Changing name/access clears the stale request/response
   and unused identities and requires regeneration, retaining the name.
4. A full administrator opens **Connectivity > TELIPHONES > Pair a Workstation**
   over trusted HTTPS.
5. Paste the request and complete endpoint hostname/IP, UDP port, source policy
   and lifetime. Under **SSH approval**, leave **FreePBX Web Access only**, or
   explicitly approve **FreePBX Web + SSH Access** for an SSH-capable request and
   select an existing Linux account. Root is never implicit. An SSH-capable
   request may receive web-only approval from the PBX, but Windows will not save
   it with **Web + SSH Access** selected. Obtain explicit SSH approval or generate
   a new **Web Access** request; access is never silently downgraded.
6. Wait for the final pairing result and copy the response produced by FreePBX.
   Progress means liveness, never successful approval.
7. Paste the response under Windows **Complete pairing**. Validation supplies
   the approved SSH account automatically, read-only and hidden for web-only
   approval.
8. Select **Save connection** when enabled. Save requires a response bound to
   the current request and revalidates addresses, endpoint, expiry, account and
   pinned host/CA keys. Invalid, old or mismatched responses remain rejected.

Pairing v1/v2 requests and response envelopes remain supported for existing
clients and saved connections. The current Windows client uses v3 and the broker
returns v3 only for a v3 request; its response is bound to the request nonce and
workstation public key. The response envelope is not independently signed:
trusted administrator HTTPS supplies its provenance. SSH session certificates
are separately signature-verified.

After saving, select the profile and **Connect**, approving tunnel setup. Wait
for Connection Health to confirm that the PBX is reachable.
Tunnel setup confirms the Windows service within a bounded deadline, then
opens its existing WireGuardNT adapter and applies only the memory-only
enrolled private key. The official service does not expose a text-UAPI pipe;
0.8.0-0.8.2 incorrectly required one. No handshake is required for startup.
Actual service, dependency, adapter-access or key-activation failure still
removes the tunnel; the error identifies the stage and available Windows error
number, without including key material. No VPN/address conflict is inferred.
The native startup regression and live WireGuard validation remain outstanding;
see [Windows readiness](tests/WINDOWS-READINESS.md#wireguard-startup-regression).

Select **Open FreePBX** and sign in with normal FreePBX credentials. For HTTPS
management, pairing automatically fills the administrator-approved certificate
DNS name from a valid v3 response. If it was absent, enter the name supplied or
confirmed by the PBX administrator in the pairing field or later using
**HTTPS Hostname...**. The selected supported Edge, Chrome or Brave profile resolves that name to the paired
tunnel IPv4, uses no proxy, and validates the certificate normally. HTTP primary
management is intentionally refused. Redirect destinations and alternate
IP-literal access are not universally confined; if the tunnel is lost, the owned
browser job is closed when detected. Never disable certificate checks to work
around a mismatch.

The client adds only the PBX's host route; ordinary workstation traffic does not
use the tunnel. The PBX does not forward the workstation onto other networks.
If a handshake succeeds but FreePBX does not load, check the module's firewall
integration status and the [upgrade guidance](../../teliphones/README.md#updating-teliphones).
After pairing, the main window shows the PBX-applied Open/Closed/Frozen and
Locked/Unlocked policy, resolved sources and DNS failures, verified public
source, and active/maximum session capacity. **Lock to Current IP** uses the
PBX-verified recent WireGuard source. A source-list change or **Request Unlock**
is sent through the admitted control channel and remains pending until explicit
FreePBX administrator approval. Changing listener mode triggers an
identity-bound migration: the old path is control-only, the same WireGuard
identity receives and saves the new profile, and the old path is retired after
the new tunnel acknowledges it. Disconnect and reconnect if automatic migration
is interrupted; do not delete the saved identity or import a replacement pairing
unless the PBX administrator explicitly revokes it.

The corrected internal firewall jump and end-to-end migration still need
real-PBX validation.

## Open an authorised SSH session

1. Pair with SSH opt-in and explicit approval of an existing account, or select
   **Request SSH** after a web-only pairing.
2. For a post-pair request, connect and wait for PBX admission. FreePBX shows the
   pending request; a full administrator explicitly selects an existing Linux
   account and approves it. No account is selected automatically and no root
   default is implied. Rejection leaves web access unchanged.
3. Connect and wait for verified PBX reachability.
4. Select **Open SSH**. TELIPHONES requests a certificate for a fresh in-memory
   session key, checks certificate/host bindings and opens the selected external
   OpenSSH terminal over the admitted WireGuard connection. The approved account
   and port come from the pairing; there is no manual password or
   fingerprint-acceptance fallback.
5. The Custom Console is disabled and is not launched by **Open SSH**. Use a
   selected external terminal instead.
6. Close the external terminal independently, or **Disconnect** to close owned
   managed SSH processes and remove the tunnel. The session signing key is
   destroyed earlier, immediately after its single authentication signature.

| Terminal | Managed My PBXs SSH | Remote Support |
|---|---|---|
| Built-in TELIPHONES console | Disabled pending independent native validation | Not used |
| Windows PowerShell / PowerShell 7 / Windows Terminal / Command Prompt | Supported launch options | Supported launch options |
| PuTTY | Not used for managed certificates | Supported by the separate workflow |

The built-in console uses the existing managed certificate, pinned host key,
isolated agent and kill-on-close SSH job. Its source includes a libvterm screen
model, MFC renderer and ConPTY-backed OpenSSH path with resize propagation.
Portable terminal tests pass, but the MFC/ConPTY integration, full-screen
applications and real SSH behaviour have not been verified on Windows here.

## Disconnect, remove or revoke

| Action | Effect |
|---|---|
| **Disconnect** | Cancels an in-progress connection, closes owned managed SSH processes, and removes the exact owned service and adapter; pairing remains authorised |
| Close TELIPHONES normally | Signals cancellation and starts owned-resource cleanup. The window closes within five seconds; unresolved state is retained for recovery at the next launch and does not revoke the PBX pairing |
| **Remove** a Windows profile | Removes local profile/secrets, not PBX-side authority or a guarantee of physical erasure |
| **Revoke** in FreePBX | Withdraws PBX authorisation; successful server-side cleanup must be verified |
| Temporary pairing expires | Original deadline applies; reconnecting does not renew authorisation |

Persistent pairings show **Until revoked**. Disconnect/terminal closure observed
on the client is not proof of server-side revocation, authorisation expiry or
empty cgroups. Revoke on the PBX before deleting an unwanted local profile.
There is no server-pushed revocation channel; client reachability checks alone
are not a complete revocation test.

Connection stages have independent deadlines: up to 90 seconds for local
establishment, then 30 seconds for authentication and 30 seconds for controller
admission. A deadline cancels the operation, stops automatic retries and starts
cleanup. **Cleanup incomplete** means the owned resources were not verified
absent. **Recovery required** means TELIPHONES retained the protected ownership
record and will offer the same narrow cleanup path at the next launch.

## Connection Health

The main window shows the selected PBX's reachability and recent measurements.
Choose **Latency & jitter**, **Upload / download** or **Failures & interruptions**
in the graph. Use **Pop Out** for a compact resizable monitor; closing it does
not stop sampling. **Always on Top**, position, thresholds and history length
are saved locally. Recent bounded history remains after disconnect until exit
or profile removal; restarting starts fresh measurements.

| Display | Meaning |
|---|---|
| **Connected for** | Elapsed time since confirmed PBX reachability, not VPN service uptime; resets after declared loss or reconnect |
| **Authorisation remaining** | Original PBX UTC expiry, or **Until revoked**; reconnecting never renews it |
| **Connection health** | Independent continuously healthy duration; failed checks reset it |
| **TCP RTT** and jitter | Application TCP timing to the approved management URL's port (HTTP 80 / HTTPS 443 if omitted); not ICMP ping, network packet loss, HTTP or TLS validation |
| Upload/download | Actual counter deltas, labelled by source: WireGuard peer transport or exact-interface IP bytes; not available bandwidth |
| Handshake age | WireGuard freshness; older than 180 seconds warns, but does not prove an idle peer disconnected |

Unknown measurements are not zero or failures. Sampling is every two seconds
while the UI is active; WireGuard counters/handshake are queried every six
seconds. Standard-user WireGuard queries may be denied; the IP Helper counter
fallback does not widen permissions or invent handshake data.

Stable needs five consistent successful checks. Default warnings are 300 ms
latency, 100 ms recent jitter or consecutive probe failures; **Limits...**
changes thresholds. Five failed probes or a known stopped tunnel produce
Disconnected health; the separate connected-duration timer stops after three
failed checks. Degradation disables new SSH launches, but an HTTP probe failure
alone does **not** close existing terminals or remove the tunnel. Authorisation
expiry disconnects; a stopped/absent tunnel closes owned managed SSH.

Small/high-DPI work areas stack and scroll content while keeping the action bar
available. Use scrollbars, the mouse wheel or keyboard focus to reveal details.
The [implementation and measurement reference](tests/WINDOWS-READINESS.md#connection-health-implementation-and-measurements)
preserves timing, telemetry, window-lifecycle and manual display-test detail.

### Session diagnostics

**View Session Log** shows the selected pairing's sanitised local timeline and exports the same text through a native Save dialogue. Logs live under `%LOCALAPPDATA%\TELIPHONES\Diagnostics` with a protected current-user/SYSTEM directory. Storage rotates at 1 MiB per file, retains three files total and removes records older than seven days on access. Cross-process locking protects writes/rotation; failures are reported rather than silently ignored. Shutdown closes logging without a persistent logging worker.

Events include startup/shutdown, local pairing changes, manual connection attempts, service establishment/removal, health/probe/telemetry transitions, errors and minute summaries. Deterioration events retain recent bounded measurements. Logs never dump profiles, tunnel configurations, passwords or key material; detail sanitisation also applies before viewing/export.

For **My PBXs**, both ends use `ws-<workstation_id>` as a non-secret pairing-lifetime diagnostic identifier. Each Windows connection has a separate attempt identifier; session-controller requests carry it to correlate client attempts with broker request handling. This does not claim the PBX observed a local button press or a WireGuard event. The PBX records only its own peer/interface/authorisation/firewall observations. Compare UTC timelines allowing for clock skew, aided by local monotonic elapsed milliseconds. **Remote Support** uses separate local `support-<profile_id>` identifiers, not these PBX workstation logs.

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

The first time TELIPHONES starts for a Windows user, a **Welcome to TELIPHONES** dialogue asks for:

- **Default Browser**: the Windows default browser, plus installed Google Chrome, Microsoft Edge and Brave for secure HTTPS management.
- **Default SSH Terminal**: whichever of Windows PowerShell, PowerShell 7, Windows Terminal, PuTTY and Command Prompt are installed. Managed My PBXs SSH uses the selected OpenSSH-backed terminal; the Custom Console is disabled.

The Windows default browser is always listed; Google Chrome, Microsoft Edge and Brave appear when installed. Google Chrome is preselected when installed, otherwise the Windows default browser. Windows PowerShell is preselected when installed, otherwise Command Prompt, otherwise the first terminal found.

- **Save & Next** stores your choices and advances to secure connectivity.
- **Skip** stores the preselected defaults and advances to secure connectivity. Change them later in Settings.
- **Cancel** in Step 1 stores nothing, and the welcome dialogue appears again at the next start. Closing later steps preserves the saved preferences.

### Settings

Choose **Settings...** in the main window at any time. Its **Applications** section has the same **Default Browser** and **Default SSH Terminal** lists and the same storage. Changes take effect when you click **Save**. Use **Locate...** to choose an application that was not detected, for example a portable copy of PuTTY. Secure HTTPS management supports Edge, Chrome and Brave; Firefox and Vivaldi are not offered because TELIPHONES does not provide the isolated secure-management launch mode for them. Supported program files (`chrome.exe`, `msedge.exe`, `brave.exe`, `powershell.exe`, `pwsh.exe`, `wt.exe`, `putty.exe` and `cmd.exe`) on a local drive are accepted.

Detection uses the Windows registrations for installed applications (App Paths and registered browsers) and standard Windows folders, rather than fixed installation paths.

### Appearance

Choose **Settings > Appearance > System (follow Windows)**, **Light** or
**Dark**. System is the default. Changes preview across open TELIPHONES windows;
**Save** persists them and **Cancel** restores the saved choice. Changing themes
does not restart tunnels, clear history or alter authorisation.

Windows accessibility/high-contrast colours override the preference. Graph line
patterns and text labels do not rely on colour alone. Windows-owned file
pickers, UAC and credential prompts remain OS-rendered; title-bar support varies
by Windows version. See the [native appearance reference](tests/WINDOWS-READINESS.md#native-appearance-implementation)
for renderer, accessibility and new-dialogue implementation details.

### How applications are launched

| Selection | What TELIPHONES runs |
|---|---|
| Windows default browser | The PBX address through the Windows registered URL handler, as in earlier releases |
| Chrome, Edge, Brave | For secure HTTPS management, the selected detected executable runs with an isolated profile, scoped hostname resolver mapping and normal TLS validation; HTTP does not silently fall back to another browser |
| Windows PowerShell / PowerShell 7 / Windows Terminal / Command Prompt | The selected external terminal runs managed My PBXs SSH or the separate Remote Support workflow |
| PuTTY (Remote Support only) | PuTTY with `-ssh`, the tunnel address, the approved SSH port (`-P`), the user name (`-l`) and a per-PBX `-loghost` name for host-key checking; not managed My PBXs certificate authentication |

The FreePBX address uses the approved HTTP/HTTPS scheme and management port
on `<PBX tunnel address>/admin/`, not a hardcoded HTTP default. Managed My PBXs
uses the approved account and dedicated port, the app-controlled helper and
short-lived certificate path; the helper never holds a private key.
Remote Support retains port `22222` and its separate terminal/credential workflow.

Earlier builds opened the Windows default browser and ran `ssh.exe` directly in a new console window.

### When an application is missing

If a selected browser or terminal has been uninstalled or moved, TELIPHONES says so and never silently launches a different application.

- For a missing browser, choose **Yes** to switch to the Windows default browser, **No** to choose another in Settings, or **Cancel**.
- For a missing terminal, choose **OK** to choose another in Settings.

A missing selection stays visible in Settings, marked **(not found)**, until replaced. Remote Support can use PuTTY without OpenSSH. Managed My PBXs requires Windows OpenSSH; missing prerequisites produce an explicit error, never a fallback.

### Where preferences are stored

Preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` for the current Windows user, in a strictly validated format. They survive application and Windows restarts and TELIPHONES updates. They are kept local rather than roaming because executable locations differ between computers. They are never stored in the FreePBX module or sent to a PBX or gateway. If the file cannot be read, TELIPHONES reports this and leaves it unchanged; saving from Settings replaces it.

## Security


Choosing a terminal never grants SSH access. SSH-capable pairing creates a permanent workstation Ed25519 identity encrypted with user DPAPI; existing encrypted OpenSSH-format identities can be read in memory without changing their public key or approval. Each Open SSH creates a different, non-exportable session seed in a dedicated `VirtualAlloc`/`VirtualLock` page. OpenSSL temporarily imports it for Ed25519 operations. No session private key is written to a file, command line, log or request, or added to the system agent. Public certificates, public keys, pinned known_hosts and an isolated configuration are the only runtime files.

The permanent identity signs the request/2 challenge, session ID and public key. Response bindings are checked structurally and OpenSSL independently verifies the Ed25519 certificate signature against the pinned CA. The private named-pipe agent accepts only the live, retained handle/PID of its owned Windows OpenSSH child. It rejects key import/export and arbitrary signing: only one userauth signature for the exact account/certificate (and pinned host for hostbound requests) is allowed, then the seed is cleared and released. Strict host-key checking and certificate-only authentication are mandatory; there is no password, shared-agent or host-prompt fallback.

The app alone retains each non-inheritable kill-on-close Job handle. The console helper must join that Job before it can create its suspended SSH child; the app checks image, membership and process identity before allowing execution/signing. SSH/helper exit, disconnect or authorisation expiry terminate the owned Job and destroy the agent; failed/incomplete authentication is bounded to 30 seconds. The Connection Health probe also closes managed SSH when it observes the tunnel stopped or absent, including an external WireGuard stop; an HTTP probe failure alone does not close terminals. App termination or restart closes its handles and cannot restore a session key. Remote server termination ends the SSH child independently of the Windows UI. Runtime file deletion is cleanup, not credential destruction.

Process DACLs restrict new memory-reading, thread-creation and handle-duplication access; agent pipes are user/SYSTEM-only, reject remote clients and enforce client PID ownership. These controls are not protection against administrators/debug privileges, a compromised OS, tampered binaries, malicious code already inside the app or previously obtained privileged handles. Logical signing-capability destruction is not guaranteed physical erasure of OpenSSL/OS copies, paging files, crash dumps or SSD blocks. Legacy plaintext exposure still requires explicit PBX revocation/re-pairing.

**Evidence boundary:** operator reports conflict: one reports eleven native
OpenSSH integrations passing and another reports ten. Neither supplied a
matching run URL, commit/build identifier or raw log, so neither count can be
independently reconciled with the current source. The twelve methods currently
registered in the readiness documentation are not evidence that twelve ran or
passed. Report these as unverified historical reports, not current 0.10.0
validation.
The all-terminal/Unicode-path, Windows reboot and real FreePBX/systemd
revocation/expiry/rollback matrix remains outstanding. The loopback issuer is a
fixture, not FreePBX; local expiry is not proof of server-side termination.
See the [material inventory and outstanding gates](../../docs/SSH-KEY-MANAGEMENT-PROPOSAL.md).
Remote Support remains separate.

## Local data and permissions

### Optional Connect Password Protection

On an unprotected **Connect**, TELIPHONES offers to set a local password for
that saved connection. Choose **Set Password**, **Skip This Time** or
**Skip Permanently**; cancelling stops the connection attempt. The permanent
choice is saved with that workstation profile. With the connection selected,
use **Settings > Security** to enable, change or remove protection, or choose
**Lock Now** to disconnect and release the active workstation session. Changing
or removing protection requires the current password. Every protected
**Connect** requires it again; it is not cached, logged or sent to the PBX.

The password wraps the WireGuard private key using **Argon2id v1.3**
(64 MiB, three passes, one lane) and **AES-256-GCM**, with fresh random
16-byte salt/12-byte nonce and a 16-byte authentication tag. The version and
credential target are authenticated. The envelope remains inside Credential
Manager/DPAPI; there is no parallel plaintext credential or password hash.
Credential format, not a profile/preferences flag, requires authenticated
decryption. Unknown/damaged formats and wrong passwords fail closed.
OpenSSL's established Argon2id provider (3.2+) must be available; older/no-Argon2
builds keep DPAPI-only mode and cannot unlock protected keys. There is no KDF
substitute or recovery/reset bypass.

Enabling first removes the old service and legacy staged/installed configuration;
cleanup failure prevents enabling. New staging and installed `.conf` files
contain only a **public, non-enrolled bootstrap identity**, never the enrolled
private key. The UAC helper rejects old plaintext-key configs. After startup,
the real key passes through a random, local-only, helper-PID-bound pipe and
the official WireGuardNT adapter configuration API, only in memory. Restarting a stored
configuration cannot restore the enrolled identity, including after a crash.
This lifecycle applies in DPAPI-only mode too.

Forgotten passwords require PBX revocation and re-pairing (Remote Support:
re-enrol a new engineer key and obtain a new grant). Removing a profile does not
revoke it remotely. Protection does not lock an already running tunnel, encrypt
public profiles or the separate DPAPI SSH identity, protect against an
administrator/compromised OS or in-process malware, or erase earlier backups,
crash dumps, paging/SSD remnants or configurations copied before enabling.
Use revocation/re-pairing if previous key exposure is possible.

The first-use choice, Settings controls and removal/re-pair recovery flow are
implemented in source. Forgotten-password recovery does not decrypt or reset
the protected key: remove the local profile and inaccessible credential,
revoke the old peer in FreePBX, then pair a new identity.

Portable tests cover successful authenticated decryption, independent
Argon2id/AES interoperability, wrong-password and tampering rejection,
missing-provider refusal and secret-free bootstrap rendering. Native MFC,
Credential Manager, DPAPI, UAC, Windows service and WireGuardNT API behaviour
still need Windows validation; portable success is not that evidence.

### Storage

- Profiles contain public pairing/grant data and are stored in the user's roaming application-data directory.
- Browser, SSH terminal and appearance preferences are stored in `%LOCALAPPDATA%\TELIPHONES\preferences.json` and contain only application choices, paths and appearance mode.
- WireGuard private keys are stored separately in Windows Credential Manager and are not written into the profile file or copied into the gateway grant.
- Public-bootstrap-only tunnel configuration is staged in a user-restricted local directory, revalidated by an elevated helper, then placed under `%ProgramFiles%\TELIPHONES\Tunnels` with a restrictive ACL. The enrolled WireGuard key is injected only in memory after service startup.
- Each tunnel is demand-started. The helper grants the current Windows user only the service rights needed to query, stop and remove that TELIPHONES tunnel; it does not grant permission to start or reconfigure it.
- UAC approval is required for tunnel installation. Declining it cancels the connection.
- Only one connection is active at a time. The app probes the PBX through the tunnel and displays session expiry separately from reachability. Authorisation expiry disconnects the tunnel; detected loss of PBX reachability warns and disables new SSH launches, but does not automatically remove the tunnel or close existing terminal windows. Normal application exit requests disconnection.
- Revocation detection is based on reachability checks, not a server-pushed revocation channel. A revoked but otherwise reachable/established flow may not be detected instantaneously; verify teardown behaviour in the supported PBX/gateway environment before relying on it.

## Troubleshooting

| Symptom | Safe next step |
|---|---|
| WireGuard missing, unverified or installation cancelled | Use **Settings... > Connectivity > Check Again** or retry **Install WireGuard**; investigate signature/proxy errors, never bypass them |
| No WireGuard handshake | Check approved pairing, endpoint DNS/IP and router/host UDP policy; a relay is not provided |
| Handshake but FreePBX unreachable | Check **Connection Health**, the PBX's **FreePBX Firewall integration** status and the [module troubleshooting guide](../../teliphones/README.md#troubleshooting); confirm the installed broker version and helper contents match the authorized module package |
| **Open SSH** unavailable or rejected | Confirm explicit SSH approval, the approved account, Windows system OpenSSH and the selected external terminal. Managed My PBXs requires an OpenSSH-backed terminal; PuTTY remains available for the separate Remote Support workflow. |
| Host/CA/certificate mismatch | Stop and investigate; re-pair only after verifying the PBX identity through a trusted channel, never accept an unverified key |
| Browser/terminal missing | Choose a supported installed application in Settings; no silent substitution occurs |
| Connect or Disconnect reports **Cleanup incomplete** | Choose **Disconnect** again or close and relaunch TELIPHONES to approve recovery. TELIPHONES uses the protected ownership record and removes an adapter only after its current alias, interface GUID and PnP instance all match. It never asks you to use Device Manager, `pnputil` or an administrator shell. Export the session log if recovery remains unresolved |
| Startup reports **Recovery required** | Approve the offered cleanup. If Windows still refuses the exact owned service or adapter, TELIPHONES preserves the record and remains closable; collect the session log and controlled Windows test evidence before changing the device manually |
| Startup or Disconnect reports **Temporary SSH files could not be removed** | Saved connections are still loaded and the SSH session has ended. The message names the remaining path under `%LOCALAPPDATA%\TELIPHONES\SSH`; these files hold no private keys. Close any program holding that file (for example an editor viewing `ssh.log`); TELIPHONES retries at the next disconnect or start. A file TELIPHONES did not create is left for inspection, never deleted |
| TELIPHONES closes unexpectedly while opening SSH | The Custom Console is disabled. Preserve the session diagnostic export, Event Viewer **Windows Logs > Application** event 1000 (Application Error), and any Windows Error Reporting entry for `TELIPHONES.exe` (exception code and faulting module). A failed external terminal launch must report an error without closing TELIPHONES or tearing down its tunnel. |
| Starting TELIPHONES reports it **is already running … but it has no open window** | The earlier process is still closing connections or showing an error. Wait and start again. If it stays without a window, end that process ID in Task Manager. The next start removes any tunnel or temporary SSH files it left; saved connections, credentials and pairings are not affected |
| **Admission unavailable** and the diagnostic says the handshake could not be read | Whether the tunnel is authenticated is unknown; do not infer an authentication failure or success. Export **View Session Log** and compare it with the PBX diagnostic view. Check approved endpoint DNS and UDP reachability, then inspect `wg show tlp-admin latest-handshakes endpoints` on the PBX (a Locked workstation uses its dedicated interface) |
| **Admission unavailable** after the handshake was read | A recent handshake alone does not prove that tunnel routing, TCP 8766, or admission works. Use the diagnostic's last confirmed stage and attempt identifier; compare **View Session Log** with the PBX's bounded diagnostics. On the PBX, check `ss -ltnp 'sport = :8766'`, `fwconsole teliphones status`, and `journalctl -u teliphones-broker --since -30min`. The diagnostics distinguish controller transport/timeouts from a broker admission rejection when that evidence is available |
| Expired or revoked pairing | Obtain a new PBX approval; reconnecting or editing a local profile cannot renew authority |
| Display or pop-out problem | Record Windows version, scaling, monitor layout and theme; compare with the [manual validation matrix](tests/WINDOWS-READINESS.md#test-coverage-and-manual-validation) |

Use **View Session Log** to copy/export selected-profile client diagnostics.
PBX observations are separate in FreePBX. Review and redact diagnostics before
sharing: no private keys, pairing requests/responses, certificates, credentials,
customer identities or routable endpoints. Include application/module versions,
`build-info.json` provenance, timing and exact sanitised errors. Do not publish
customer data in an issue.

## Verification status

The FreePBX module/root broker source target is 0.9.0.1, protocol 12, and
unreleased. Its local maintenance archive is available for controlled testing;
the historical 0.6.7
archive was intentionally removed from this checkout and predates the proposed
changes. Earlier Windows CI builds completed for 0.9.0; no matching successful
0.10.0 run or downloadable artifact can be verified from this checkout, and
native and functional acceptance is outstanding. The artifact from run
`43980149884` (artifact `14281389786`)
is blocked by Chrome as “Dangerous download blocked”; the cause is unresolved.
The experimental embedded SSH console remains disabled on the active managed
SSH path. Historical reports of that console closing TELIPHONES do not establish
a current external-terminal defect. Historical
native test-count reports are not interchangeable or independently reproduced:
an earlier report said eleven SSH integration tests, a later report said ten,
and current readiness documents twelve registered integration methods. No
matching run URL, commit/build identifier or logs were supplied to reconcile
these counts; registration is not evidence of execution.

The Windows portable core and cryptographic tests have passed in prior local
validation, including
identity-bound migration parsing and the Argon2id positive-path provider tests
when available. This is not a native Windows build: this Linux environment
cannot compile or exercise the MFC application, Windows Credential Manager,
DPAPI, UAC, service/helper lifecycle, or actual WireGuard reconnect path.
Historical operator reports for 0.7.0 are not evidence for the current 0.10.0
changes.

Live FreePBX session admission, listener migration, source restrictions,
FreePBX Firewall coexistence, SSH approval/revocation, reboot and recovery
remain to be verified on a disposable PBX. The full terminal/Unicode-path and
display matrix and Remote Support end-to-end testing also remain outstanding.
The [central evidence register](../../docs/SECURITY.md#verification-evidence)
separates reports, local tests and intended controls. See also the
[historical native failures and fixes](tests/WINDOWS-READINESS.md#historical-investigations).

## Developer builds and testing

The complete [build reference](tests/WINDOWS-READINESS.md#developer-builds-and-testing) and [test coverage/manual validation matrix](tests/WINDOWS-READINESS.md#test-coverage-and-manual-validation) preserve the technical detail outside the operating workflow.

The Windows app statically builds the vendored libvterm 0.3.3 sources from
[`third_party/libvterm`](third_party/libvterm); its MIT licence is included
there. The portable `terminal_emulator` CTest target exercises the screen
model and keyboard protocol without requiring a Windows SDK or remote PBX.

The declared [WireGuardNT dependency](wireguard-nt.json) pins the official 1.1
archive used by WireGuard for Windows 1.1.1, including hashes for its AMD64 DLL,
matching header and licence. Run `./restore-wireguard-nt.ps1` before native
MSBuild/CMake (also called by `build.ps1` and CI); `-ArchivePath` accepts a
previously downloaded archive, and `-CheckOnly` never downloads.
Only the documented DLL API is used. The helper verifies the bundled DLL's
compiled-in hash before copying it into the protected
`%ProgramFiles%\TELIPHONES\WireGuardNT-1.1` directory. It locks and verifies
that copy before loading by absolute path with system-only dependency lookup.
No PATH/current-directory DLL search or extraction from `wireguard.exe` is used.
The installed official service still creates/owns the adapter; TELIPHONES only
opens it. Closing that opened handle does not remove the service's adapter.
The zeroed 80-byte interface update sets only `HAS_PRIVATE_KEY`, with zero
peers and no replacement/listen-port flags. Temporary key structures are wiped.

## Licence

The software grant is **GPL version 3 or, at your option, any later version
(GPL-3.0-or-later)**; see [LICENSE](../../LICENSE), also included in the Windows
ZIP. The footer's "licensed under GPLv3" statement is shorthand, not a narrower
grant. Software licensing does not grant trademark rights. The main window
shows the product and trademark statements in its fixed footer; full wording
is also in **Settings > About**. Narrow windows may show an ellipsis.
The Windows ZIP includes the OpenSSL, vendored libvterm and official prebuilt
WireGuardNT licences. The WireGuardNT DLL is distributed unmodified under its
own included binary licence, not under TELIPHONES' software grant.
