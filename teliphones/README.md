# TELIPHONES for FreePBX 17: module guide

This guide covers installing, configuring, operating, maintaining and troubleshooting the TELIPHONES FreePBX module (`teliphones`, version 0.3.1). For an introduction to the project, its architecture and its security model, see the project overview (`README.md`), `docs/ARCHITECTURE.md` and `docs/SECURITY.md` at the root of the TELIPHONES source repository; these are not included in the module package.

> [!WARNING]
> **Not currently suitable for production.** TELIPHONES 0.3.1 is an unreleased development correction for controlled testing on a **disposable** Debian 12 / FreePBX 17 system. Its nftables ownership-marker correction was separately tested by the operator on the FreePBX 17 PBX; repository regression tests are simulations/isolated namespace tests, not a repeat of that live test. See [Known limitations](#known-limitations) and [Outstanding 0.3.1 verification](#outstanding-031-verification).

## Contents

1. [What the module provides](#what-the-module-provides)
2. [Requirements](#requirements)
3. [Installing the module](#installing-the-module)
4. [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) (root broker bootstrap)
5. [Updating TELIPHONES](#updating-teliphones)
6. [Windows workstations: install, pair and connect](#windows-workstations-install-pair-and-connect)
7. [Remote Support: browser workflow](#remote-support-browser-workflow)
8. [Command line reference](#command-line-reference)
9. [Baseline snapshots](#baseline-snapshots)
10. [Troubleshooting](#troubleshooting)
11. [Uninstalling](#uninstalling)
12. [Known limitations](#known-limitations)
13. [Testing](#testing)
14. [Further documentation](#further-documentation)
15. [Support and feedback](#support-and-feedback)
16. [Licence, AI disclosure and author](#licence)
17. [Release History](#release-history)

## What the module provides

The module adds **Connectivity > TELIPHONES** to FreePBX and the `fwconsole teliphones` command. The page has four areas:

| Area | Purpose |
|---|---|
| **System readiness** | Broker state and prerequisites, including **Approve installation of WireGuard tools** |
| **Remote support** and **Active session** | Authorise, monitor and revoke a temporary support session, and submit Checker evidence |
| **Secure gateway enrollment** | Store gateway, certificate and Checker trust material for Remote Support |
| **Windows workstations** | Pair, list, diagnose and revoke administrator workstations |

Privileged work is carried out by a separate root-owned broker, which must be installed once from a root shell (see [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17)) and refreshed after every upgrade.

The two workflows are independent:

- **Windows workstations** ("My PBX" in the Windows application) give an administrator's own workstation direct WireGuard access to this PBX's web interface, and SSH if approved. No external services are involved.
- **Remote Support** grants an MSP temporary, independently verified access through the Connect, Checker and Console contracts.

## Requirements

### PBX

| Requirement | Notes |
|---|---|
| FreePBX 17 on Debian 12 | The only supported platform. FreePBX 16 is not supported. |
| Root shell access | Needed for the one-time broker bootstrap after each installation or upgrade |
| `systemd`, `/usr/bin/python3`, `/usr/bin/systemctl` | Used by the broker and its units |
| FreePBX `asterisk` account | The web server must run as `asterisk`; the broker accepts only this account |
| HTTPS for the FreePBX administration interface | Required for workstation pairing and gateway enrolment |
| `wireguard-tools` (`wg`) and kernel WireGuard support | Can be installed from the GUI after explicit approval |
| `iproute2` (`ip`) | Normally present on Debian 12 |
| `nftables` userspace package (`nft`) | Required for workstation pairing. TELIPHONES uses isolated nftables rules to restrict workstation access. Only the `nft` command is needed; `nftables.service` does **not** need to be enabled, and TELIPHONES never enables it. TELIPHONES does not install this package. |
| `iptables` | Used for the FreePBX Firewall integration; either the `nf_tables` or `legacy` backend |
| A reachable WireGuard UDP port | Default `51821`, reachable from workstations through the router, host firewall and FreePBX Firewall |

The root broker installs packages only when an administrator explicitly approves WireGuard tools, and then installs only `wireguard-tools` from Debian's configured repositories. Any other missing prerequisite must be installed by the platform administrator.

### Windows workstations

- Windows 10 or 11, x64.
- The official WireGuard for Windows, installed separately by a Windows administrator.
- The TELIPHONES Windows application (`TELIPHONES.exe`), built from `desktop/windows/` in the TELIPHONES source repository, or downloaded from a successful GitHub Actions build. It is not included in the module package.
- Windows OpenSSH Client, if you use **Open SSH** with Windows PowerShell, PowerShell 7, Windows Terminal or Command Prompt. PuTTY does not need it.

### Remote Support (additionally)

- OpenSSH server components on the PBX for the temporary support service.
- PHP OpenSSL support.
- A Connect implementation, such as the separately deployed reference gateway (`gateway/` in the TELIPHONES source repository), implementing the [Connect contract](docs/CONNECT-CONTRACT.md), with a customer client certificate.
- An independent Checker with an ECDSA P-256 signing key.
- A Console or engineer process using standard WireGuard and SSH clients.

No Connect, Checker or Console service is supplied or hosted by FreePBX UK.

## Installing the module

TELIPHONES is a community module and is not listed in the FreePBX online module repository.

### Install through Module Admin (recommended)

1. Obtain `TELIPHONES-0.3.1.tgz` and its SHA-256 checksum from a trusted source, then verify the archive:

   ```bash
   sha256sum TELIPHONES-0.3.1.tgz
   ```

2. In FreePBX, open **Admin > Module Admin**, choose **Upload modules**, and upload the archive.
3. Install TELIPHONES, then apply the configuration.
4. Continue with [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17).

Module Admin runs as the web service account. If the root broker cannot be installed at this stage, installation still finishes without error, so ordinary FreePBX operation is unaffected. **Connectivity > TELIPHONES** then shows **TELIPHONES Installation Incomplete**.

### Install from an unpacked module directory

Place the `teliphones` directory in `/var/www/html/admin/modules/`, then run the following as root:

```bash
cd /var/www/html/admin/modules/teliphones
fwconsole ma install teliphones
cd
fwconsole chown
fwconsole reload
```

Use `fwconsole ma install teliphones`. Do **not** use `fwconsole ma installlocal teliphones`.

Check the installation:

```bash
fwconsole ma list | grep -i teliphones
fwconsole teliphones check
```

## Complete Installation on FreePBX 17

FreePBX Module Admin installs the TELIPHONES FreePBX module, but the privileged broker requires a **one-time root bootstrap**, repeated after every upgrade.

**Why this is necessary.** The broker performs operations that the web application must never perform itself: creating WireGuard interfaces, managing firewall rules and running systemd services. It must therefore be installed as root-owned files and a systemd service. Module Admin runs as the web service account, which cannot create these. TELIPHONES deliberately provides no web-based route to root privileges; the bootstrap is the only way the broker is installed.

Run the procedure below **from an existing root shell** on the PBX (for example, log in as root on the console or run `su -` first), using a **trusted, verified TELIPHONES installation**, for example one uploaded from a package whose checksum you have confirmed. Do not prefix it with `sudo` or run it from an unprivileged shell; it stops before making any change if it is not running as root. Copy and paste it unchanged. **Connectivity > TELIPHONES** shows the same commands with a **Copy Commands** button. This sequence was verified on Debian 12 / FreePBX 17:

```bash
(
set -eu

SRC=/var/www/html/admin/modules/teliphones
DEST=/root/teliphones-bootstrap

test "$(id -u)" -eq 0
test -f "$SRC/install.php"
test -f "$SRC/support_broker.py"

mkdir -p "$DEST"
cp -a "$SRC"/. "$DEST"/

chown -R root:root "$DEST"
chmod -R go-w "$DEST"

php -r 'define("FREEPBX_IS_AUTH", true); require "/root/teliphones-bootstrap/install.php";'

systemctl is-active teliphones-broker.service

for i in $(seq 1 30); do
    test -S /run/teliphones/control.sock && break
    sleep 1
done

test -S /run/teliphones/control.sock

echo "TELIPHONES broker is ready."
)
```

What it does:

- Confirms it is running as root and that the installed module contains `install.php` and `support_broker.py`.
- Copies the module into `/root/teliphones-bootstrap`, makes the copy root-owned and removes group and other write access. The installer then runs from this root-owned staging copy, so root never executes files directly from the web-service-owned module directory, which the web service account could modify.
- Runs the module's own `install.php` as root. This installs the root-owned broker at `/usr/local/lib/teliphones-broker/support_broker.py`, registers and starts `teliphones-broker.service` (and `teliphones-reconcile.service`), and makes `/var/lib/teliphones`, `/etc/teliphones.conf` and `/etc/teliphones-connect.conf` root-owned and private.
- Confirms the service is active and waits up to 30 seconds for the control socket `/run/teliphones/control.sock`.

It does **not** authorise a remote support session or install packages. Broker startup revokes interrupted support sessions. Existing workstation access is disabled, and its owned policy is revalidated before valid saved pairings are restored. Unrelated SSH, firewall and network policies are not changed.

Success ends with `active` followed by `TELIPHONES broker is ready.`. If that final line is not printed, the preceding check failed; see [Broker not installed or not running](#broker-not-installed-or-not-running). After successful installation, refresh **Connectivity > TELIPHONES**. The broker is reported as operational only after the page has received a valid status reply.

> [!IMPORTANT]
> **Do not run the bootstrap during an active support session.** It restarts the broker, and broker startup revokes any interrupted session and quarantines TELIPHONES. If you are unsure, check first as root with `fwconsole teliphones status`. Disconnect Windows workstation tunnels before running it.

### Verify the broker

```bash
systemctl status teliphones-broker.service --no-pager -l
ls -l /run/teliphones/control.sock
```

On success, `systemctl status` shows `Loaded: loaded (/etc/systemd/system/teliphones-broker.service; enabled; ...)` and `Active: active (running)`, and `ls -l` shows a socket line beginning `srw-rw----`, owned by `root asterisk`.

## Updating TELIPHONES

Update TELIPHONES in place. Do not uninstall the module first: uninstalling removes workstation pairings.

1. Confirm, as root, that no support session is active: `fwconsole teliphones status`.
2. Disconnect Windows workstation tunnels.
3. Upload and install the new archive through **Admin > Module Admin**. For an unpacked directory, use the commands in [Install from an unpacked module directory](#install-from-an-unpacked-module-directory).
4. Rerun [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) from a root shell.
5. Refresh **Connectivity > TELIPHONES** and confirm that **Root broker update required** is no longer shown. The installed version is reported by `fwconsole ma list | grep -i teliphones`.

### After upgrading TELIPHONES

A Module Admin upgrade updates the FreePBX module files but does not necessarily update the separately installed, root-owned broker (`/usr/local/lib/teliphones-broker/support_broker.py`), because Module Admin runs as the web service account. After every TELIPHONES upgrade, confirm that no support session is active (as root: `fwconsole teliphones status`), then rerun the root bootstrap procedure from an existing root shell and refresh Connectivity > TELIPHONES. TELIPHONES 0.3.1 keeps broker protocol 3 and adds a hookless nftables ownership chain that remains visible when Debian 12 nftables 1.0.6 drops table comments. Module Admin does not update the root-owned broker automatically; until the bootstrap copies and restarts the corrected broker, existing firewall ownership may not be recognised. Disconnect Windows tunnels before the bootstrap; valid pairings are restored when the broker restarts, without extending temporary expiry.

The 0.2.1 and 0.3.0 security/firewall changes, and the 0.3.1 nftables ownership correction, require rerunning this bootstrap even when an older broker already reports protocol 3; that number alone does not distinguish the implementation. Confirm the installed broker file and restart using the documented bootstrap rather than relying on protocol status alone.

### Upgrading from 0.2.0 or 0.2.1

- Saved pairings, their addresses, permissions and original deadlines, and the PBX's workstation key are preserved.
- Expired temporary pairings are not restored.
- An unmarked table is migrated only when its complete contents exactly match the known 0.3.0 TELIPHONES policy reconstructed against root-owned saved state, and the interface is verified down. Unknown or altered tables remain untouched and workstation access stays disabled. See [upgrading from 0.3.0](docs/WORKSTATION-PAIRING.md#upgrading-from-030). Never flush the host ruleset to bypass a conflict.

## Windows workstations: install, pair and connect

This workflow pairs an administrator's own Windows workstation with this PBX. A paired workstation can reach the FreePBX web interface through WireGuard, and the PBX's existing SSH service if that is explicitly approved. It does not require the reference gateway, Checker or any external service.

**Key concepts**

- **Pairing** is the PBX's approval of one workstation key. It is created once, and it remains valid until it expires (temporary) or is revoked (persistent).
- **Connection** is the tunnel the workstation brings up when it needs access. Connecting and disconnecting do not change the pairing.
- **Revocation** removes the pairing on the PBX. It is the only way to remove a workstation's authority; deleting the Windows profile does not.

### Before you begin

- The broker is operational and current: **Windows workstations** is visible, and **Root broker update required** is not shown.
- `wg`, `ip` and `nft` are available. If any are missing, **Windows workstations** lists them. **Approve installation of WireGuard tools** installs `wg`; `iproute2` and `nftables` must be installed by a root administrator.
- You are signed in to FreePBX as a full administrator **over HTTPS**.
- The PBX's WireGuard UDP port (default `51821`) is reachable from the workstation. If the PBX is behind NAT, the external UDP port must forward to the same PBX listener port. Permit this port through the router, host firewall and FreePBX Firewall as required; TELIPHONES does not change these policies. Do **not** publish TCP 22, 80 or 443 for this purpose.

### 1. Prepare the workstation

1. Install the official WireGuard for Windows, with Windows administrator approval.
2. Run `TELIPHONES.exe`. The top of the window reports whether WireGuard for Windows was found.

### 2. Generate a pairing request

1. Select **Add my PBX...**.
2. Enter a workstation name and select **Generate request**.
3. Select **Copy request**. Note the key fingerprint shown beside it.

Keep the **Pair my PBX** dialog open. The response will be bound to this request and to the key that has just been generated.

### 3. Approve the pairing on the PBX

1. In **Connectivity > TELIPHONES > Windows workstations**, expand **Pair a workstation**.
2. Paste the request into **Pairing request from the Windows application**.
3. Enter the **PBX public hostname or IP address** that the workstation uses to reach WireGuard, and the **WireGuard UDP port on the PBX**. All pairings on a PBX share one port. To change it, revoke all workstations first.
4. Choose the access period:
   - **Temporary**, with a **Temporary pairing duration** of 60, 240, 480 or 1440 minutes; or
   - **Persistent trusted workstation (until revoked)**.
5. Choose **SSH access through the tunnel**. Leave **Not permitted** unless SSH is genuinely required. Otherwise, select **Permit SSH (TCP 22) with existing PBX credentials**.
6. Select **Pair workstation**. Compare the key fingerprint shown on the PBX with the one shown in the Windows dialog. They must match.

### 4. Complete pairing on Windows

1. On the PBX, select **Copy pairing response**.
2. Paste the response into the waiting Windows dialog.
3. If SSH was approved, enter the existing Linux account you will use; otherwise leave it blank.
4. Select **Save connection**.

Pairing creates no SSH account, root password or SSH key.

### 5. Connect and open FreePBX

1. Select the saved connection and select **Connect**.
2. Approve the Windows UAC prompt, which installs the TELIPHONES tunnel service for this PBX.
3. Wait until the application reports that the PBX is reachable.
4. Select **Open FreePBX**. This opens `http://<PBX tunnel address>/admin/` inside the encrypted WireGuard tunnel, in the browser chosen in the Windows application (see [browser and SSH terminal preferences](#browser-and-ssh-terminal-preferences)). Sign in with your existing FreePBX credentials; FreePBX authentication is never bypassed.

The workstation routes only the PBX's tunnel address (`/32`); other traffic does not use the tunnel. Only one TELIPHONES connection is active at a time.

### 6. Use SSH (only when approved)

SSH through the tunnel reaches the PBX's existing SSH service on TCP 22, with its existing accounts and authentication policy. TELIPHONES does not change SSH configuration.

- **Open SSH** becomes available once the PBX has answered through the tunnel. It opens your preferred SSH terminal against the PBX tunnel address on port 22, using the account saved with the profile.
  - Windows PowerShell, PowerShell 7, Windows Terminal and Command Prompt run the Windows OpenSSH Client. If it is missing, install **OpenSSH Client** from **Settings > System > Optional features**.
  - PuTTY is opened directly with the address, port and account, and uses its own credentials, such as Pageant or a `.ppk` key.
- **Another SSH client:** while connected, connect to the PBX tunnel address shown in the profile on port 22, with your existing PBX credentials.

The operator reports that PuTTY reaches the real PBX SSH server, which requires public-key authentication; successful SSH authentication has not been completed. See [Outstanding 0.3.1 verification](#outstanding-031-verification). A separate SSH key-management proposal remains repository documentation and is not included in this module package. Choosing a terminal never grants SSH access.

#### Browser and SSH terminal preferences

On first start, the Windows application shows **Welcome to TELIPHONES**. It offers the browsers and SSH terminals found on the workstation:

- **Browsers:** the Windows default browser, Google Chrome, Microsoft Edge, Mozilla Firefox, Brave and Vivaldi.
- **SSH terminals:** Windows PowerShell, PowerShell 7, Windows Terminal, PuTTY and Command Prompt.

You can save your choices, skip and keep the defaults, or cancel. Change them later with **Settings...**. The preferences apply to every saved PBX. They are stored only for the Windows user on that workstation, and are never sent to the PBX or stored in this module. If a selected application is uninstalled or moved, the application reports it and offers another choice rather than silently launching something else. Full details are in the Windows application README (`desktop/windows/README.md` in the source repository).

Workstations that were not approved for SSH cannot reach TCP 22; the connection simply times out. To grant SSH later, revoke the pairing and pair again from a new request, with SSH permitted.

### 7. Disconnect

Select **Disconnect** to stop and remove the Windows tunnel service. Closing the application normally also requests disconnection. The pairing remains valid, so you can connect again later without a new approval.

### 8. Revoke access

1. In **Windows workstations**, select **Revoke** for the workstation, or **Revoke all workstations** when several are listed.
2. Confirm that the page reports success. Revocation removes temporary and persistent authority alike.
3. After verified revocation, the Windows profile cannot reconnect without a fresh approval. You may then remove it with **Remove** in the Windows application.

If cleanup fails, the page reports an error and keeps **Revoke all workstations** available for retry, even if no pairing remains listed. Do not treat a failed operation as a revocation. If the interface cannot be deleted, the broker disables it and keeps the restrictive firewall rules, rather than opening its traffic. If a retry also fails, inspect the broker as root (see [Troubleshooting](#troubleshooting)).

Windows detects revocation by losing reachability to the PBX. There is no server-pushed revocation, so the client may take a short time to notice. The PBX is authoritative.

### Reading the workstation table

| Column | Meaning |
|---|---|
| **Access** | **Web interface only**, or **Web interface and SSH** |
| **Pairing** | **Persistent (until revoked)**, or **Temporary, expires** at a UTC time |
| **WireGuard status** | **Authorised; no handshake yet**, the time of the **Last handshake** (UTC), or **Not verified (status unavailable)** |

Above the table, TELIPHONES reports the FreePBX Firewall integration state:

| Message | Meaning |
|---|---|
| **FreePBX Firewall integration active (iptables nf_tables)** or **(iptables legacy)** | Approved web and SSH traffic is admitted ahead of FreePBX Firewall |
| **FreePBX Firewall integration not installed.** | No FreePBX Firewall hook (`fpbxfirewall`) was found in `INPUT`, so no integration is installed |
| **FreePBX Firewall integration failed.** | The integration could not be placed safely, for example because of Fail2Ban ordering; the message names the cause |
| *The running root broker does not report FreePBX Firewall integration...* | The running broker is outdated or its capability response is incomplete; rerun the root bootstrap |

A row showing **Handshake succeeded, but FreePBX Firewall integration is not active** means that WireGuard is working, but FreePBX Firewall may drop web and SSH traffic. See [The handshake succeeds but FreePBX does not load](#the-handshake-succeeds-but-freepbx-does-not-load).

A handshake time shows that WireGuard has worked; it does not prove that the web interface or SSH is currently reachable. Refresh the page for a new snapshot. Temporary expiry and enforcement are reconciled approximately every 15 seconds.

For the pairing protocol, enforcement design and firewall integration details, see the [workstation pairing contract](docs/WORKSTATION-PAIRING.md).

## Remote Support: browser workflow

Remote Support grants an MSP engineer temporary, independently verified access to this PBX. It uses its own interface (`wg-teliphones`), the `10.20.17.0/24` allocation pool and a temporary SSH service on port `22222`, entirely separately from workstation pairing. The executable local implementation targets the **On-PBX** topology.

> **Connect creates. Checker observes. Console consumes. TELIPHONES decides.**

Remote Support has not been validated end to end on a real PBX.

### 1. Enrol the gateway

Expand **Secure gateway enrollment** over HTTPS, then enter:

- the HTTPS gateway origin;
- the customer mTLS client certificate and private key;
- the CA certificate;
- the independent Checker's ECDSA P-256 public key.

Save the enrolment. The broker stores this material at fixed, root-only paths and never returns it to the browser. Enrolment is refused while a session is active. The gateway itself must be deployed and operated separately; see the [Connect contract](docs/CONNECT-CONTRACT.md) and, for the reference implementation, `gateway/README.md` in the TELIPHONES source repository.

### 2. Authorise a session

Choose a **Duration (minutes)** of 5, 15, 30, 60, 120 or 240, then select **Authorise Remote Support**. The broker authorises the session locally, with an absolute expiry, and then:

1. provisions the path through Connect;
2. confirms an authenticated WireGuard handshake;
3. verifies local state;
4. issues a Checker challenge.

Progress is shown automatically (see [Live status updates](#live-status-updates)).

### 3. Submit Checker evidence

Give the displayed challenge to the independent Checker. Paste its signed JSON into **Signed Checker evidence JSON**, then select **Verify evidence and open approved access**. When the signature and policy checks succeed, TELIPHONES:

1. activates the gateway's engineer access;
2. opens the temporary SSH service, which accepts only the enrolled engineer's session-bound key from its tunnel address.

The engineer identity shown is the SHA-256 fingerprint of the gateway-enrolled SSH key, not proof that the engineer is present.

The reference gateway has no automatic Checker service, so evidence delivery is a deliberate browser step. A session cannot become ready without it.

### 4. Session access

The engineer connects with standard WireGuard and SSH clients to the PBX's session address on port `22222`. The temporary `sshd` is separate from the PBX's normal SSH service. It accepts only session-specific public keys, and it disables password, keyboard-interactive and PAM authentication, forwarding, tunnelling and user environment processing.

### 5. Expiry and revocation

- The session ends at its absolute expiry, which is enforced by a systemd timer independently of the broker and browser. Reboots do not extend it, and they do not reopen the SSH service.
- **Revoke Remote Support** is available at any time, including during running operations. It removes local access first and then requests gateway cleanup.
- Failed or interrupted operations revoke local authority and **quarantine** the module. Quarantine cannot be cleared from the GUI.
- If the broker is unavailable, revoke as root with `fwconsole teliphones revoke`.

### Live status updates

After an action starts, the page reports `TELIPHONES operation started. Monitoring progress automatically…` and updates itself without reloading, so the selected duration and unsaved form values are kept. While an operation runs, a spinner and the broker's current stage appear beside the affected item:

- the **WireGuard wg** readiness row, for dependency installation (for example "Installing WireGuard tools…", then "Checking WireGuard tools…");
- the enrolment rows, for gateway enrolment;
- the session state, for authorisation, connection, Checker verification, revocation and background cleanup after expiry.

Stages are reported as named steps; no percentage is estimated. Success is shown only after the broker has verified the result. For example, WireGuard installation succeeds only once the broker detects `wg`; the button is then disabled and relabelled **WireGuard tools installed**. Failures are shown as **✕** with the broker's message, and the action becomes available again where retrying is safe.

The page polls the read-only `ajax.php?module=teliphones&command=status` endpoint about every two seconds, only while an operation or cleanup is in progress. Requests never overlap, and polling stops when the operation finishes or the page is closed. Operations that exceed their expected duration show `This operation is taking longer than expected. TELIPHONES is continuing to check its status.` A failure to retrieve status is reported separately and retried with back-off; it is not reported as an operation failure. Monitoring pauses after 15 minutes, and **Resume monitoring** restarts it. If AJAX is unavailable, the buttons fall back to ordinary form submission, and **Refresh session status** remains available.

### Administrator access checks

Every page load, status request and action requires a FreePBX administrator with full access. The administrator is resolved from the server-side FreePBX session: the framework-provided `$ampuser`, the session object, or an `ampuser` constructed from a scalar session username. Access is granted only when `checkSection('*')` returns `true` or `1`. Restricted users, missing or malformed sessions and unavailable permission APIs are refused. Actions also require a valid CSRF token and an allow-listed action.

`defined('FREEPBX_IS_AUTH')` prevents direct script access; its value is not treated as a credential. Authentication and permission errors are reported separately from broker availability. These conventions were taken from working FreePBX modules and tested with framework stubs. Delegated-user refusal still needs confirming on a real FreePBX 17 system.

### Support topologies

| Topology | Status |
|---|---|
| **On-PBX** (`on-pbx`): the support tunnel terminates on the PBX | Implemented |
| **On-net** (`on-net`): terminates elsewhere on the customer network | Contract only; requires an external Connect implementation |
| **Off-net** (`off-net`): terminates outside the customer network | Contract only; requires an external Connect implementation |

TELIPHONES checks proposed addressing against existing addresses and routes, and refuses collisions. It never changes the default route, DNS, forwarding or NAT to make a proposal fit. See [Topologies](docs/TOPOLOGIES.md), the [integration guide](docs/INTEGRATION.md) and the [contracts overview](docs/INTEGRATIONS.md).

## Command line reference

`fwconsole teliphones` runs as root. The GUI is the normal interface; the command line is for recovery, diagnostics and direct integration testing.

| Command | Purpose |
|---|---|
| `fwconsole teliphones status` | Show TELIPHONES and support-session state |
| `fwconsole teliphones check` | Check prerequisites |
| `fwconsole teliphones baseline` | Print a read-only, sanitised system snapshot (see [Baseline snapshots](#baseline-snapshots)) |
| `fwconsole teliphones authorise --minutes=N --topology=T` | Authorise a support session for 5–240 minutes (default 60; topology default `on-pbx`) |
| `fwconsole teliphones connect-request` | Print the `teliphones-connect/1` request |
| `fwconsole teliphones provision` | Send the Connect request to the enrolled gateway |
| `fwconsole teliphones connect-confirm` | Confirm the path after a fresh WireGuard handshake |
| `fwconsole teliphones peer --peer-key=K --peer-endpoint=H:P` | Configure a support peer directly, for local testing |
| `fwconsole teliphones attest` | Verify PBX-local session state |
| `fwconsole teliphones checker-request` | Print the Checker challenge |
| `fwconsole teliphones checker-accept --evidence-file=F` | Validate signed Checker evidence |
| `fwconsole teliphones open [--ssh-key=KEY]` | Open the temporary support SSH service (the key defaults to the one supplied by Connect) |
| `fwconsole teliphones console-handoff` | Print the `teliphones-console/1` handoff |
| `fwconsole teliphones revoke` | Revoke the support session immediately (emergency revocation) |
| `fwconsole teliphones enable` / `disable` | Enable or disable TELIPHONES. Disabling revokes support access and removes workstation network access. |
| `fwconsole teliphones reconcile` | Reconcile support authority (run at boot by `teliphones-reconcile.service`) |

`authorise` also accepts `--pbx-address` and `--peer-address` for On-PBX addressing proposals from Connect. Workstation pairing and revocation are performed in the GUI. Read the [integration guide](docs/INTEGRATION.md) and [testing programme](docs/TESTING.md) before attempting the complete Connect, Checker and Console sequence from the command line.

## Baseline snapshots

`fwconsole teliphones baseline` prints a read-only, sanitised `teliphones-baseline/1` JSON snapshot. It includes the capture time, hostname, sanitised TELIPHONES state, interfaces and addresses, IPv4 main-table routes and rules, listening TCP and UDP sockets, and `wg-teliphones` details when present. It excludes private keys, credentials, configuration-file contents and unrelated process environments.

Use it to find unexpected persistent changes:

```bash
fwconsole teliphones baseline > /root/teliphones-before.json
# perform the test
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

Timestamps and session metadata will naturally differ.

## Troubleshooting

> [!IMPORTANT]
> Never disable FreePBX Firewall, add `tlp-admin` to a trusted zone, trust the workstation subnet, flush the firewall ruleset, weaken SSH configuration, or change the broker socket or state-directory permissions to make TELIPHONES work. These actions remove protections that TELIPHONES is designed to preserve. The broker deliberately accepts only the FreePBX `asterisk` account.

The diagnostic commands below are read-only and must be run as root.

### Broker not installed or not running

The GUI reports the condition with read-only checks: **TELIPHONES Installation Incomplete**, a stopped service, a missing control socket, or an unverified broker state. Expand **Verify the broker and troubleshoot** for guidance.

- **Service missing** (`Unit teliphones-broker.service could not be found`): the bootstrap has not completed. Rerun [the procedure](#complete-installation-on-freepbx-17) from a root shell and read its output. It requires `/usr/bin/python3`, `/usr/bin/systemctl` and the FreePBX `asterisk` account (check with `id asterisk`).
- **Failed startup** (`Active: failed`, or repeated restarts): read `journalctl -u teliphones-broker.service -n 50 --no-pager`. If it reports that the state directory must be root-owned and private, rerun the procedure, which restores the ownership of `/var/lib/teliphones`.
- **Socket missing while the service is active:** check the same log, then run `systemctl restart teliphones-broker.service`, which recreates the socket. Do not do this during an active support session. If the socket exists but the page still cannot reach the broker, confirm that the web server runs as `asterisk` with `ps -C apache2 -o user= | sort -u`.

While the broker is unavailable, every broker action is disabled and refused. If a support session may be active, revoke it as root with `fwconsole teliphones revoke`.

### Root broker update required

The installed broker is older than the module. Rerun the root bootstrap, as described in [Updating TELIPHONES](#updating-teliphones).

### Pairing is refused

| Message or symptom | Action |
|---|---|
| *Workstations may only be paired over HTTPS.* | Open the FreePBX administration interface using `https://` |
| *Workstation pairing requires WireGuard tools, iproute2 and nftables on the PBX. Missing: ...* | Approve WireGuard tools in the GUI, or ask a root administrator to install `iproute2` or the `nftables` package. The `nftables` service does not need to be enabled. |
| *TELIPHONES is disabled.* | Enable it as root with `fwconsole teliphones enable` |
| *Paired workstations already use UDP port ...* | Use the same port, or revoke all workstations first |
| *No workstation addresses remain* | Revoke unused workstations |
| The Windows application rejects the response | Pair again from the same, still-open request dialog. A response is valid only for the request that produced it. |

### No WireGuard handshake

If the table shows **Authorised; no handshake yet**:

- confirm that the Windows application is connected, and that the UAC prompt was approved;
- confirm that the hostname or IP address and the UDP port in the pairing are reachable from the workstation's network;
- check NAT port forwarding: the external UDP port must reach the same PBX listener port;
- confirm that the router, host firewall and FreePBX Firewall permit the WireGuard UDP port. TELIPHONES does not configure these, and no relay or NAT traversal is provided;
- check the handshake on the PBX: `wg show tlp-admin latest-handshakes`.

### The handshake succeeds but FreePBX does not load

1. Check the integration message above the **Windows workstations** table.
2. If the broker does not report the integration, rerun the root bootstrap.
3. Inspect the integration, read-only:

   ```bash
   iptables -S INPUT
   iptables -S teliphones-ws
   iptables -L teliphones-ws -v -n -x
   nft list table inet teliphones_workstations
   ```

   In `iptables -S INPUT`, expect exactly one rule containing `TELIPHONES workstation integration v1`. It should appear after every `fail2ban-*` or `f2b-*` rule, and immediately before the first `-j fpbxfirewall` rule. The packet counters in `teliphones-ws` show whether workstation traffic is reaching it.
4. Confirm that the web server is listening: `ss -ltn '( sport = :80 or sport = :443 )'`.
5. Check the broker log: `journalctl -u teliphones-broker.service -n 50 --no-pager`.

If the counters do not increase while a browser connects, the traffic is not reaching the integration. Collect the output above for a [support request](#support-and-feedback). Do not add trusted zones or networks in FreePBX Firewall.

### FreePBX Firewall integration failed: Fail2Ban ordering

If a Fail2Ban hook appears **after** `fpbxfirewall` in `INPUT`, there is no position that is both after Fail2Ban and before FreePBX Firewall. TELIPHONES then withdraws its integration rather than bypass Fail2Ban, and names the affected chains. Tunnel web traffic is dropped by FreePBX Firewall until the order is corrected. Restarting Fail2Ban normally reinserts its hooks at the top of `INPUT`, after which TELIPHONES restores the integration automatically. Do not edit or remove Fail2Ban or FreePBX Firewall rules by hand.

### Firewall ownership conflict

If TELIPHONES reports an unfamiliar `inet teliphones_workstations` table or `teliphones-ws` chain, it will not change it and workstation access stays disabled. The 0.3.1 broker safely migrates only the exact known 0.3.0 nft policy while `tlp-admin` is down. If migration is refused, preserve the saved pairing/key data and obtain administrator review; do not flush the ruleset or remove unrelated tables. See [firewall ownership and migration](docs/WORKSTATION-PAIRING.md#enforcement-integrity-and-exposure-limits).

### SSH does not connect

- Check the **Access** column: it must read **Web interface and SSH**. Otherwise, TCP 22 is blocked by design.
- **Open SSH** stays unavailable until the PBX has answered through the tunnel and the status shows the connection as connected.
- Windows PowerShell, PowerShell 7, Windows Terminal and Command Prompt need Windows OpenSSH Client. Install it from **Settings > System > Optional features**, or choose PuTTY in the Windows application's **Settings...**.
- If the application reports that your selected SSH terminal could not be found, choose another in **Settings...**.
- Use an existing account that the PBX's SSH configuration permits. TELIPHONES does not create accounts or change `sshd` settings.
- Fail2Ban may have banned the workstation's tunnel address after failed sign-in attempts. TELIPHONES does not bypass Fail2Ban.

### Windows application

- **WireGuard for Windows not found:** install the official WireGuard for Windows with administrator approval.
- **Connection cancelled:** the UAC prompt was declined; connect again and approve it.
- **SmartScreen warning:** test builds are not code-signed.

The pairing exchange is described in the [workstation pairing contract](docs/WORKSTATION-PAIRING.md). Build and usage details for the application are in `desktop/windows/README.md` in the TELIPHONES source repository.

### Remote Support is quarantined

A failed or interrupted support operation revokes access and quarantines TELIPHONES. Quarantine cannot be cleared from the GUI. Review `/var/log/teliphones.log` and the broker journal, then contact [support](#support-and-feedback) with sanitised output.

## Uninstalling

Uninstalling removes workstation pairings and TELIPHONES' firewall objects. It must run as root.

1. Disconnect Windows workstations.
2. Revoke any active support session:

   ```bash
   fwconsole teliphones revoke
   ```

3. Uninstall the module:

   ```bash
   fwconsole ma uninstall teliphones --force
   fwconsole chown
   fwconsole reload
   ```

4. If the source directory remains and is no longer needed, remove `/var/www/html/admin/modules/teliphones` separately.

The uninstaller stops and verifies the broker service, then uses only the trusted, installed, root-owned broker helper, never Python from the module directory. It disables workstation connections before removing any firewall protection, and verifies that `tlp-admin` has been deleted before deleting the owned table, key or pairing state. Any failure aborts uninstallation, reports the error and retains the information needed for recovery. Repair the tools or the root broker and retry; do not delete state by hand. Brokers older than 0.2.1 must first be updated with the root bootstrap. Unfamiliar table conflicts require investigation, not automatic deletion. See [verified uninstall and recovery](docs/WORKSTATION-PAIRING.md#verified-uninstall-and-recovery).

After uninstalling, verify that no `tlp-admin` or `wg-teliphones` interface remains. Also check that no temporary `sshd` or SSH child process, session key material, active session state or TELIPHONES expiry job remains, and that the `teliphones-ws` chain and its `INPUT` jump are absent. If gateway cleanup fails, the module deliberately retains its local Connect cleanup record and logs the failure; remote expiry is still required.

## Known limitations

- **Experimental status.** End-to-end, failure-recovery and adversarial security testing on a real PBX is incomplete.
- **External firewall flushes.** TELIPHONES detects and repairs external firewall changes, but cannot prevent them. A flush can briefly expose an active tunnel before detection; a transient removal can pass traffic even if the rules are restored before detection. This is **not** fail-closed or zero-exposure protection. See [enforcement integrity and exposure limits](docs/WORKSTATION-PAIRING.md#enforcement-integrity-and-exposure-limits).
- **Fail2Ban ordering gap.** A Fail2Ban hook inserted between the TELIPHONES jump and `fpbxfirewall` can be bypassed by approved workstation traffic until reconciliation. Reconciliation is prompt with the iptables `nf_tables` backend, and takes up to about 15 seconds with `legacy`.
- **Assumed FreePBX hook names.** `fpbxfirewall`, `fail2ban-*` and `f2b-*` come from the reported FreePBX 17 test installation and upstream defaults, not FreePBX source. Fail2Ban hooks reached through other chains, and Fail2Ban nftables tables, are not inspected.
- **IPv4 only.** Workstation connectivity and the firewall integration are IPv4-only; `ip6tables` is not modified.
- **Direct connectivity only.** No relay or NAT traversal; the PBX's WireGuard UDP port must be reachable.
- **No revocation push.** Windows detects revocation through lost reachability.
- **Remote Support.** Only On-PBX is implemented. Support-session reachability with FreePBX Firewall enabled is unknown, and no support firewall policy is changed. The temporary SSH service uses root with session-specific keys. No production Checker signer or Console is included.
- **Framework checks.** FreePBX menu rendering, permissions and navigation have only metadata-level automated checks.

The project-wide security model and its complete list of known limitations are in `docs/SECURITY.md` in the TELIPHONES source repository.

### Outstanding 0.3.1 verification

The operator reports that the 0.3.1 nftables ownership correction was installed and tested on the Debian 12 / FreePBX 17 test PBX. Repository tests below use simulated FreePBX/Fail2Ban rules in isolated namespaces and do not repeat that exact test or establish production readiness. Remaining validation includes:

- repeated live verification of broker restart, migration, `iptables -S INPUT` ordering and `teliphones-ws` counters;
- repeated Windows WireGuard connection and reconnection tests;
- FreePBX Firewall restart and reload compatibility;
- Fail2Ban enforcement during firewall-rule reordering;
- SSH access through PuTTY when explicitly authorised, and refusal when it is not authorised;
- confirmation that unauthorised PBX services remain inaccessible through the tunnel, including SIP, AMI, databases, and SSH for workstations not approved for it.
- Windows validation of the browser and SSH terminal preferences: application detection, the welcome and Settings dialogs, and launching each supported browser and terminal.

## Testing

### Automated tests

From the module directory:

```bash
php tests/run.php
```

This runs the PHP and JavaScript module tests: metadata, page authentication, GUI rendering, bootstrap consistency, route and collision policy, Checker evidence and pairing validation. The broker, firewall integration and gateway tests are written in Python:

```bash
cd ../gateway && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

These tests use framework stubs, simulated system commands and, where permitted, real packets in disposable network namespaces with a **simulated** FreePBX Firewall layout. They do not install FreePBX, use a real FreePBX Firewall, start systemd units or contact a gateway.

### Disposable PBX test procedure

On a disposable FreePBX 17 system only:

1. Install the module and complete the root bootstrap. Confirm that a delegated (non-full) administrator cannot open the page. Stop the broker service to check the **stopped** guidance, then start it again.
2. Approve WireGuard tools, and confirm that the readiness row updates without a refresh.
3. Pair a Windows workstation, then connect, open FreePBX, disconnect and reconnect it repeatedly. Check `iptables -S INPUT` ordering and the `teliphones-ws` counters.
4. Reload and restart FreePBX Firewall and restart Fail2Ban while connected. Confirm that access is restored and that bans remain effective.
5. With SSH approved, connect using **Open SSH** and PuTTY. Without approval, confirm that TCP 22 is refused.
6. Confirm that SIP, AMI, database and other services are unreachable through the tunnel.
7. Revoke the workstation while it is connected, and let a temporary pairing expire. Confirm that access ends.
8. For Remote Support, first prove the local lifecycle with no external integrations:

   ```bash
   fwconsole teliphones check
   fwconsole teliphones baseline > /root/teliphones-before.json
   fwconsole teliphones authorise --minutes=15 --topology=on-pbx
   fwconsole teliphones status
   fwconsole teliphones revoke
   fwconsole teliphones baseline > /root/teliphones-after.json
   diff -u /root/teliphones-before.json /root/teliphones-after.json
   ```

   Only then integrate Connect, Checker and Console.

Stop testing immediately if TELIPHONES exposes privileged access publicly, changes the default route or DNS, modifies unrelated networking, extends an expired grant, accepts replayed Checker evidence, silently reopens privileged SSH after a reboot, or leaves access behind after cleanup. The complete programme is in [Testing](docs/TESTING.md).

## Further documentation

| Document | Contents |
|---|---|
| [docs/WORKSTATION-PAIRING.md](docs/WORKSTATION-PAIRING.md) | Pairing contract, enforcement integrity, FreePBX Firewall integration, upgrading and verified uninstall |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Step-by-step Connect, Checker and Console integration |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | Overview of the integration contracts and their order |
| [docs/CONNECT-CONTRACT.md](docs/CONNECT-CONTRACT.md) | `teliphones-connect/1` |
| [docs/CHECKER-CONTRACT.md](docs/CHECKER-CONTRACT.md) | `teliphones-checker/1` |
| [docs/CONSOLE-CONTRACT.md](docs/CONSOLE-CONTRACT.md) | `teliphones-console/1` |
| [docs/TOPOLOGIES.md](docs/TOPOLOGIES.md) | On-PBX, On-net and Off-net |
| [docs/TESTING.md](docs/TESTING.md) | Regression coverage and the staged test programme |
Every link above is bundled with the module. The following project documents are maintained only in the TELIPHONES source repository and are not included in the Module Admin package:

| Source repository path | Contents |
|---|---|
| `README.md` | Project overview, workflows, quick start and development status |
| `docs/ARCHITECTURE.md` | Project-wide architecture |
| `docs/SECURITY.md` | Security model, assurance levels and known limitations |
| `docs/RENDEZVOUS.md` | Future rendezvous and relay design (not implemented) |
| `desktop/windows/README.md` | Windows application build and usage |
| `gateway/README.md` | Reference Connect gateway |

## Support and feedback

TELIPHONES is maintained by FreePBX UK. For installation help, testing feedback or troubleshooting, contact FreePBX UK:

https://freepbx.uk/support/

Where relevant, include:

- the FreePBX, Debian and TELIPHONES versions;
- the workflow (Windows workstations or Remote Support) and, for Remote Support, the topology;
- the action that failed, and the message shown;
- relevant command output, such as the integration diagnostics or the broker journal;
- whether Connect, Checker or Console was involved;
- a sanitised before-and-after baseline, where appropriate.

Never include private keys, credentials, pairing requests or responses, gateway grants or other session secrets. Report suspected security vulnerabilities privately through FreePBX UK support, rather than in a public issue.

## Licence

GPLv3+. See [LICENSE](LICENSE).

## AI-Assisted Contributions and Disclosure

This module has been developed with AI assistance for code generation, review, testing and documentation. Generative AI assistance must be disclosed in every commit containing AI-assisted changes:

```text
Assisted-by: AGENT_NAME:MODEL_VERSION
```

For example: `Assisted-by: GitHub-Copilot:gpt-6.1-sol`

The human contributor remains solely responsible for the contribution. AI tools must not be listed as co-authors.

## Author

[@kierknoby](https://github.com/kierknoby), Kieran Knowles-Byrne // [FreePBX UK](https://github.com/freepbxUK)

## Release History

Entries for 0.0.2 to 0.2.1 are summarised from the repository history. Release dates are recorded only where they were previously published.

### 0.3.1, nftables ownership compatibility (unreleased)

- Replaces reliance on nftables table comments with the exact hookless, ruleless `teliphones_owner_v1` chain, which remains visible in Debian 12 nftables 1.0.6 JSON readback.
- Safely migrates only an exact known 0.3.0 policy while the verified workstation interface is down. Unknown or altered rules remain untouched.
- Keeps broker protocol 3; rerunning the root bootstrap is required to copy and restart the separately installed broker.
- The operator reports successful testing of the ownership correction on the FreePBX 17 test PBX. The repository's automated packet tests still use a simulated FreePBX Firewall.

### 0.3.0, development milestone (unreleased)

Not yet released. This package is for manual installation and testing on a disposable FreePBX 17 PBX only; see [outstanding 0.3.1 verification](#outstanding-031-verification). It is the milestone that introduces FreePBX Firewall integration and enhanced workstation connectivity enforcement. It builds on the 0.2.0 workstation pairing and the 0.2.1 firewall enforcement corrections, which are preserved.

#### FreePBX Firewall integration

- Adds a broker-owned, marker-validated iptables chain, `teliphones-ws`. One INPUT jump is placed immediately before the `fpbxfirewall` hook. FreePBX Firewall chains, zones, trusted networks, settings and services are not modified.
- Admits only TCP 80/443 from each paired workstation address (`/32`) to the PBX tunnel address. TCP 22 is added only for explicitly SSH-approved workstations. Everything else returns to FreePBX Firewall.
- Installs integration only after the owned nftables policy has been verified, and before `tlp-admin` is brought up. Unverifiable cleanup disables workstation access.
- Refuses to modify an unfamiliar `teliphones-ws` chain or unexpected references to it.

#### Fail2Ban compatibility

- Recognises `fail2ban-*` (FreePBX 17) and `f2b-*` (upstream) INPUT hooks, ignoring case.
- Requires the TELIPHONES jump to follow every Fail2Ban hook. If a Fail2Ban hook follows `fpbxfirewall`, the integration is withdrawn and reported rather than bypassing Fail2Ban.

#### Automatic reconciliation

- Restores missing, duplicated or misplaced integration after firewall reloads or Fail2Ban restarts, without duplicating rules or reconnecting peers. With the iptables `nf_tables` backend this happens on nft monitor events; with `legacy` it happens on the approximately 15-second periodic check.
- Removes integration on revocation, expiry, broker shutdown and uninstall. Uninstall retains recovery state if removal fails.

#### Diagnostics

- **Windows workstations** shows the integration state (active, not installed, failed or not reported by an outdated broker) and the iptables backend.
- Warns when a workstation's WireGuard handshake succeeded but FreePBX Firewall integration is inactive.

#### Windows application

- Adds a first-run **Welcome to TELIPHONES** dialog and a **Settings...** dialog for the default browser and SSH terminal. Only installed applications are offered. Preferences are stored locally for each Windows user and are never sent to the PBX.
- **Open FreePBX** uses the Windows default browser, Chrome, Edge, Firefox, Brave or Vivaldi.
- **Open SSH** uses Windows PowerShell, PowerShell 7, Windows Terminal, Command Prompt or PuTTY, with validated, separately passed arguments. It is enabled only after the PBX has answered through the tunnel.
- A missing selected application is reported, and is never silently replaced.
- These features are covered by simulated core tests only; they have not been validated on Windows.

#### Testing

- Adds simulated broker tests and real-packet namespace tests for both iptables backends. They use the Fail2Ban chain names observed on the FreePBX 17 test installation, including hook reordering. None of these tests use the real FreePBX Firewall, WireGuard or Windows.

#### Documentation

- Reorganises the project documentation, adding a project overview, an architecture guide, a security guide and this module guide.

### 0.2.1, firewall enforcement and lifecycle security

- Verifies the complete owned nftables policy before admitting workstation peers, and monitors it for external changes, with a periodic fallback.
- Disables workstation connectivity when enforcement is missing or altered, and restores verified restrictions before readmitting peers.
- Originally identified `inet teliphones_workstations` with a table comment; nftables 1.0.6 does not preserve that marker in JSON readback. The 0.3.1 ownership chain and constrained migration supersede that mechanism.
- Makes uninstallation verify interface removal before removing firewall protection, and retain recovery information on failure.
- Preserves workstation pairing data on upgrade.

### 0.2.0, Windows workstation pairing

- Adds administrator-approved Windows workstation pairing with temporary or persistent access, direct WireGuard connectivity and per-workstation SSH permission.
- Adds individual and bulk revocation, and handshake status.
- Requires broker protocol 3 and verifies the workstation capability contract.
- Accompanies the experimental native Windows application.

### 0.1.3, live status monitoring

- Adds automatic, authenticated status polling with progress indicators, verified outcomes and duplicate-submission prevention.
- Adds broker protocol detection, outdated-broker warnings and copy-and-paste root bootstrap instructions.
- Prevents redundant WireGuard tools installation.

### 0.1.2, FreePBX 17 administrator authentication

- Separates FreePBX access validation from session and permission checks. Accepts permission-bearing session objects and scalar session usernames, and no longer requires a particular `FREEPBX_IS_AUTH` value.
- Preserves restricted-user refusal and CSRF protection.
- GUI operation was confirmed on FreePBX 17.

### 0.1.0, browser-based remote support

- Adds GUI-based support authorisation, session monitoring and revocation through a restricted privileged broker.
- Adds approved WireGuard tools installation, secure gateway enrolment, signed Checker verification, temporary SSH access and automatic expiry and cleanup.

### 0.0.2, FreePBX 17 compatibility

- Corrects the BMO implementation and lifecycle methods.
- Resolves a Symfony Console method collision that prevented `fwconsole reload` and `fwconsole chown`.
- Implements `doConfigPageInit` and corrects GUI state handling.
- Module installation and GUI operation were tested on Debian 12 / FreePBX 17.

### 0.0.1, initial testing release, 26 September 2026

Released by `@kierknoby, Kieran Knowles-Byrne // FreePBX UK`.

Initial TELIPHONES testing release for FreePBX 17. This release establishes the local authority model, the initial On-PBX implementation and the Connect, Checker and Console integration boundaries for controlled testing.

#### Local authority

- Adds root-controlled temporary support authorisation with an absolute expiry.
- Adds persistent enable and disable state.
- Adds immediate local revoke.
- Adds reboot reconciliation without extending the original grant.
- Prevents the temporary privileged SSH service from automatically reopening after reboot.

#### On-PBX

- Adds the initial On-PBX topology.
- Creates an ephemeral `wg-teliphones` WireGuard interface.
- Generates the PBX WireGuard private key locally.
- Validates proposed addressing against existing PBX addresses and routes.
- Does not alter the default route, DNS, forwarding, NAT or unrelated network configuration to resolve an allocation conflict.
- Adds a dedicated temporary sshd using session-specific public-key authentication.

#### Integrations

- Defines the `teliphones-connect/1` Connect contract.
- Defines the `teliphones-checker/1` Checker contract.
- Defines the `teliphones-console/1` Console handoff.
- Separates PBX-local verification from external Checker observations.
- Adds session-, topology-, nonce- and time-bound Checker evidence with replay protection.

#### Testing

- Adds `fwconsole teliphones check`.
- Adds `fwconsole teliphones baseline` with the `teliphones-baseline/1` schema.
- Adds staged local, Connect, Checker and Console testing documentation.
- Adds explicit expiry, reboot, revoke, cleanup and failure-testing requirements.
