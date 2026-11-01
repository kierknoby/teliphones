# TELIPHONES 0.2.0 for FreePBX 17

## Complete Installation on FreePBX 17

FreePBX Module Admin installs the TELIPHONES FreePBX module, but the current implementation may require a **one-time root bootstrap** for its privileged broker. Module Admin runs the installer as the web service account, which cannot create root-owned files or systemd services. In that case the installer logs the condition and finishes without error, so ordinary FreePBX operations are unaffected, and Connectivity > TELIPHONES shows **TELIPHONES Installation Incomplete** with these same commands.

Run the procedure below **from an existing root shell** on the PBX (for example, log in as root on the console or run `su -` first), using a **trusted, verified TELIPHONES installation**, for example one uploaded from a package whose checksum you have confirmed. Do not prefix it with `sudo` or run it from an unprivileged shell; it stops before making any change if it is not running as root. Copy and paste it unchanged. This sequence was verified on Debian 12 / FreePBX 17:

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
- Copies the module into `/root/teliphones-bootstrap`, makes the copy root-owned and removes group/other write access. The installer then runs from this root-owned staging copy, so the root bootstrap does not execute files directly from the web-service-owned module directory, which the web service account could modify during installation.
- Runs the module's own `install.php` as root. This installs the root-owned broker at `/usr/local/lib/teliphones-broker/support_broker.py`, registers and starts `teliphones-broker.service` (and `teliphones-reconcile.service`), and makes `/var/lib/teliphones`, `/etc/teliphones.conf` and `/etc/teliphones-connect.conf` root-owned and private.
- Confirms the service is active and waits up to 30 seconds for the control socket `/run/teliphones/control.sock`.

It does **not** authorise a remote support session, install packages, or change SSH, firewall, network interfaces or routing. Success ends with `active` followed by `TELIPHONES broker is ready.`; if that final line is not printed, the preceding check failed. After successful installation, refresh Connectivity > TELIPHONES; the broker is reported as operational only after the page has received a valid status reply.

**Do not run the bootstrap during an active support session.** It restarts the broker, and broker startup revokes any interrupted session and quarantines TELIPHONES. If unsure, check first as root with `fwconsole teliphones status`.

### After upgrading TELIPHONES

A Module Admin upgrade updates the FreePBX module files but does not necessarily update the separately installed, root-owned broker (`/usr/local/lib/teliphones-broker/support_broker.py`), because Module Admin runs as the web service account. After every TELIPHONES upgrade, confirm that no support session is active (as root: `fwconsole teliphones status`), then rerun the root bootstrap procedure from an existing root shell and refresh Connectivity > TELIPHONES. TELIPHONES 0.2.0 requires broker protocol 3 with valid workstation pairing status for Windows workstation operations and automatic monitoring; the 0.1.3 package supplied protocol 2. Until the broker is updated, the page reports **Root broker update required**, workstation operations are refused, and remote support actions fall back to ordinary page submission without automatic progress updates. Disconnect Windows tunnels before the bootstrap; valid pairings are restored when the broker restarts, without extending temporary expiry.

### Verify the broker

```bash
systemctl status teliphones-broker.service --no-pager -l
ls -l /run/teliphones/control.sock
```

Successful results: `systemctl status` shows `Loaded: loaded (/etc/systemd/system/teliphones-broker.service; enabled; ...)` and `Active: active (running)`; `ls -l` shows a socket line beginning `srw-rw----` owned by `root asterisk`.

### Troubleshooting

- **Service missing** (`Unit teliphones-broker.service could not be found`): the bootstrap has not completed. Re-run the procedure from a root shell and read its output. It requires `/usr/bin/python3`, `/usr/bin/systemctl` and the FreePBX `asterisk` account (`id asterisk`).
- **Failed startup** (`Active: failed`, or repeated restarts): read `journalctl -u teliphones-broker.service -n 50 --no-pager`. If it reports that the state directory must be root-owned and private, re-run the procedure, which restores root ownership of `/var/lib/teliphones`.
- **Socket missing** while the service is active: check the same log, then run `systemctl restart teliphones-broker.service` (not during an active support session), which recreates the socket. If the socket exists but the page still cannot reach the broker, confirm the web server runs as `asterisk` with `ps -C apache2 -o user= | sort -u`.

Do not change the socket's ownership or mode, the state directory permissions, or any security control to make the page work: the broker deliberately accepts only the FreePBX `asterisk` account. If a support session may be active while the broker is unavailable, revoke it as root with `fwconsole teliphones revoke`.

## Windows workstations: install, pair and connect

1. Verify the supplied SHA-256 and upload `TELIPHONES-0.2.0.tgz` through **Admin > Module Admin**, then install/update TELIPHONES in place. This module-only package does not contain the Windows executable; retain the existing tested Windows application.
2. With no active support session and Windows tunnels disconnected, rerun [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) from an existing root shell. Open **Connectivity > TELIPHONES** as a full administrator over HTTPS. **Windows workstations** must be visible and **Root broker update required** must no longer appear. Pairing requires `wg`, `ip` and `nft` plus kernel WireGuard support. The existing **Approve installation of WireGuard tools** action installs `wg`; if iproute2 or nftables is missing, a root administrator must supply those system prerequisites separately.
3. Install the official WireGuard for Windows separately with administrator approval. In the existing TELIPHONES Windows application choose **Add my PBX...**, enter a workstation name, choose **Generate request**, then **Copy request**. Keep this dialog open: the response is bound to this request and locally stored key.
4. In **Windows workstations**, expand **Pair a workstation** and paste the request. Enter the PBX's genuinely reachable WireGuard hostname/IP and UDP port (default `51821`). The external UDP port must forward to that same PBX listener port. Permit the listener through the router, host firewall and FreePBX Firewall as required; TELIPHONES does not configure these policies. Do not publish TCP 22, 80 or 443 as part of this pairing.
5. Select **Temporary** and a duration, or explicitly select **Persistent trusted workstation (until revoked)**. Pairing approves the PBX web interface; leave SSH **Not permitted** unless it is needed, then independently select **Permit SSH (TCP 22) with existing PBX credentials**. Click **Pair workstation** and compare the displayed key fingerprint with the Windows request dialog.
6. Click **Copy pairing response** and paste it into the still-open Windows dialog. If SSH was approved, enter the authorised existing Linux account; otherwise leave it blank. Click **Save connection**. No SSH account, root password or SSH key is created or granted by pairing.
7. Select the saved connection and click **Connect**. Approve the Windows tunnel-service UAC request. Wait for a genuine handshake/reachability result, then use **Open FreePBX** or, only if approved, **Open SSH**. The client routes only this PBX's `/32`. Sign in with existing credentials. The response currently opens `http://<paired-PBX-address>/admin/` inside WireGuard; it does not disable or bypass FreePBX authentication.
8. Click **Disconnect** to stop/remove the Windows tunnel service. To remove PBX authority, open **Windows workstations** and click that workstation's **Revoke** (or **Revoke all workstations** when multiple are listed). This removes temporary or persistent pairing authority. If cleanup fails, the page reports an error and exposes **Revoke all workstations** for retry even if no pairing remains listed; do not treat a failed operation as verified revocation. If interface deletion fails, the broker attempts to disable it and retains the restrictive firewall instead of opening its traffic. Inspect the broker as root if retry fails. Removing the local Windows profile alone does not revoke the PBX peer. After verified PBX revocation the saved profile cannot reconnect without a fresh PBX approval.

The table reports pairing permissions/expiry and the last WireGuard handshake, not a fabricated connected state. A handshake timestamp does not prove present GUI/SSH reachability; refresh the page for a fresh workstation snapshot. A missing handshake can mean a disconnected workstation, incorrect endpoint, firewall/NAT limitation or unavailable kernel WireGuard. Temporary expiry is reconciled by the broker approximately every 15 seconds. PBX-side revocation removes access during the revoke operation; Windows detects lost reachability through its existing polling, not server push. Perform the first real Windows/PBX traffic test on the disposable test system before claiming end-to-end connectivity. Direct **My PBX** pairing does not require the reference gateway or Checker; **Remote Support** retains its separate, time-limited engineer, Connect and independent Checker requirements.

## Browser support workflow (0.2.0)

Connectivity > TELIPHONES provides administrator-only enrollment, dependency approval, authorisation, session status, signed Checker evidence submission and revocation. The established `defined('FREEPBX_IS_AUTH')` guard prevents direct script access; the constant's value is not an authentication credential. Administrator identity comes from the server-side `AMP_user` session and administrator context. Resolution prefers the framework-provided `$ampuser`, otherwise uses the session object or constructs the available `ampuser` class from a scalar session username. Full access requires `checkSection('*')` to return boolean `true` or integer `1`; arbitrary truthy strings, missing/malformed sessions, restricted users and unavailable permission APIs fail closed. The same gate precedes every GET and privileged POST, and POST actions still require CSRF validation. Successful authorization proceeds to broker readiness; authentication/permission errors are distinct from broker availability errors.

The 0.1.1 correction addressed the 0.1.0 assumption that `AMP_user` was always a permission-bearing object and permission results were always boolean. The 0.1.2 correction removes the unsupported boolean/integer-value requirement on `FREEPBX_IS_AUTH`. The guard and scalar/object session conventions were supplied from working FreePBX modules; those modules and the FreePBX framework source are not installed in this workspace. Local tests reproduce non-boolean constant values and verify the resolver and controller with doubles, not genuine framework compatibility. The `ampuser` constructor and wildcard full-administrator permission semantics still require disposable FreePBX 17 validation.

The GUI distinguishes, using only read-only checks (unit-file presence, a fixed `systemctl is-active teliphones-broker.service` query with no shell or request input, and socket presence): root broker not installed (**TELIPHONES Installation Incomplete**, with the procedure from [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) and a **Copy Commands** button); service installed but stopped; service running but control socket unavailable; broker state not verified; and broker operational (only after the socket returned a valid status). Installation and troubleshooting guidance is not shown once the broker is operational. While the broker is unavailable, every broker action is disabled in the page and refused server-side; administrator authentication, permission and CSRF checks are unchanged. With an operational broker, missing WireGuard tools and other missing dependencies are reported separately. A failed action is shown once as an emphasised, operation-specific error beneath the system warning. While the broker is unavailable, revocation is **not** reported as performed; the page shows the emergency root command `fwconsole teliphones revoke`. Expiry remains enforced by PBX systemd timers independently of the broker and browser. The broker accepts only the `asterisk` UID over a group-restricted Unix socket; the web application is the trusted administrator authentication boundary. Like existing root `fwconsole` services, this relies on the integrity of the FreePBX application/module code. Do not grant untrusted code execution to the FreePBX service account.

The broker installs **only wireguard-tools**, only after an administrator presses the approval button, using Debian's already configured apt repositories. It never installs packages merely on page load. Other missing platform dependencies require the platform administrator, and the root broker requires the one-time root bootstrap in [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17); there is no web privilege-escalation workaround.

Enroll an HTTPS gateway origin, customer mTLS certificate/private key, CA certificate and independent Checker ECDSA P-256 public key through the HTTPS GUI. The broker stores these at fixed root-only paths; it does not return their contents. Deploy the separate reference gateway with real keys, customer certificate enrollment, engineer identities, address pools and isolation policy as described in `../gateway/README.md`. No gateway is deployed or bundled in the module.

Select a duration and press **Authorise Remote Support**. The broker runs existing authorisation, provisioning, authenticated handshake confirmation, local attestation and Checker challenge stages. Progress is shown automatically (see [Live status updates](#live-status-updates)). Give the displayed challenge to the independent Checker and paste its signed JSON evidence into the page. Successful signature/policy checks activate the gateway and open only the enrolled engineer's session-bound SSH key/source on the dedicated WireGuard listener. The engineer identity shown is the SHA256 fingerprint of that gateway-enrolled SSH key, not a claim of live engineer presence.

### Live status updates

After an action starts, the page reports `TELIPHONES operation started. Monitoring progress automatically…` and updates itself without reloading, so the selected duration and unsaved form values are kept. While an operation runs, a small spinner and the broker's current stage appear beside the affected item: the **WireGuard wg** readiness row for dependency installation (for example "Installing WireGuard tools…", then "Checking WireGuard tools…"), the enrollment rows for gateway enrollment, the session state for authorisation, connection, Checker verification and revocation, and the session state for background cleanup after expiry. Stages are reported as named steps; no percentage is estimated. Success is shown only after the broker has verified the result. For example, WireGuard installation succeeds only once the broker detects the `wg` executable, after which the install button is disabled and relabelled **WireGuard tools installed**. Failures are shown as **✕** results with the broker's message, and the action becomes available again where retrying is safe.

The page polls a read-only status endpoint (`ajax.php?module=teliphones&command=status`) about every two seconds, only while an operation or background cleanup is in progress. It never overlaps requests and stops when the operation finishes or the page is closed. A running operation is detected and monitored again after navigating away and back. Operations that exceed their expected duration show `This operation is taking longer than expected. TELIPHONES is continuing to check its status.` A failure to retrieve status is reported separately and retried with back-off; it is not reported as an operation failure. Monitoring pauses after 15 minutes with a **Resume monitoring** button.

The status endpoint requires the same full-administrator check as the page, issues only the broker's `status` request, and returns an allowlisted, credential-free subset. Actions use the `command=action` endpoint, which requires POST, the same administrator check, the CSRF token and the action allowlist, and is refused server-side while the broker is unavailable. The broker allows one operation at a time and refuses to reinstall WireGuard tools that are already present. If the AJAX endpoint is unavailable, the buttons fall back to the ordinary form POST and **Refresh session status** remains available.

The reference gateway has **no automatic signed Checker service**, so evidence delivery remains an explicit browser step. A connection cannot become support-ready without it. Failed/interrupted connection or evidence operations revoke local authority and quarantine the module. Broker restart revokes interrupted sessions rather than silently reopening SSH. Revoke is available during running operations and cancels them before retrying the existing local-first teardown. GUI quarantine clearance is intentionally unavailable.

### Disposable PBX test procedure

1. Upload `TELIPHONES-0.2.0.tgz` through Module Admin and install/update in place.
2. Open Connectivity > TELIPHONES as a full administrator; confirm a delegated user cannot access it. If the page reports **Root broker not installed**, confirm all broker actions are disabled and that submitting them is refused, then follow [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) from a root shell and refresh; the broker must then show as operational. Also stop the service to confirm the **stopped** guidance and recovery.
3. Approve WireGuard tools installation and confirm that the **WireGuard wg** row shows a spinner, then the verified result, without refreshing; the install button must then be disabled. Check all prerequisites; missing components must keep authorisation disabled.
4. Deploy/enroll the external gateway and independent Checker; save their enrollment material over HTTPS. Never reuse production keys.
5. Authorise a five-minute session and watch the session state progress without refreshing, submit independently signed evidence, and test the engineer's public-key-only SSH at the PBX WireGuard address:22222 and gateway-approved web scope. Confirm unauthorised engineer/Checker/public sources and password login are rejected.
6. Revoke while connected and during connection. Confirm SSH shell descendants, tunnel routes and ephemeral credentials disappear. Repeat revocation. Test browser closure, expiry, broker restart and gateway outage; cleanup failure must show quarantine, not success.

Local mock tests do not validate actual FreePBX permissions, FreePBX `ajax.php` routing or module asset serving, root Module Admin execution, apt repository availability, systemd cgroup teardown or real WireGuard/SSH traffic. No privileged operation was performed on a live PBX from this workspace.

TELIPHONES (`teliphones`) provides temporary, root-authorised support access for FreePBX 17. It manages the local lifecycle of a support session, including authorisation, absolute expiry, temporary network and SSH state, verification and revocation.

The module separates external support functions into three integration contracts: **Connect** creates the temporary communications path, **Checker** independently observes that path, and **Console** consumes approved access. TELIPHONES remains the local authority for the session.

## ⚠️ Not Currently Suitable for Production

TELIPHONES 0.2.0 integrates administrator-approved Windows workstations and direct WireGuard PBX access alongside the 0.1.3 live-status remote support workflow, preserving earlier authentication and FreePBX 17 compatibility corrections.

The earlier module installation/bootstrap has been tested on FreePBX 17, but 0.2.0 workstation pairing has not completed live installation, end-to-end traffic, failure-recovery or adversarial security testing.

**Do not install TELIPHONES 0.2.0 on a production PBX.**

Testing should be performed only on a disposable FreePBX 17 system where unexpected network, SSH or service behaviour can be investigated without affecting live communications.

The security controls documented below describe the behaviour TELIPHONES is designed to enforce. They should not be treated as validated security guarantees until the corresponding live tests have been completed.

## Release Status

TELIPHONES 0.2.0 is the current repository development milestone for FreePBX 17. The native Windows executable has successfully compiled and launched in user-run Windows testing; the complete workstation-to-PBX network flow still requires real integration testing.

The complete executable local implementation currently targets the **On-PBX** topology. On-net and Off-net are defined integration topologies and require external Connect implementations.

0.2.0 is intended for development, review and controlled testing rather than production deployment.

## Compatibility

Primary target: FreePBX 17 on Debian 12. Earlier module installation and root bootstrap were verified there; 0.2.0 workstation pairing and end-to-end compatibility remain unvalidated on a real PBX. No compatibility claim is made for FreePBX 16 or PBXact.

FreePBX 16 is not currently supported.

## Requirements

For local 0.2.0 testing:

- FreePBX 17 on Debian 12
- root access for installation and support authorisation
- systemd transient-unit support
- WireGuard userspace tools and kernel support for On-PBX testing
- OpenSSH server components for temporary On-PBX SSH testing
- PHP OpenSSL support and an independently provisioned Checker ECDSA P-256 public key for signed Checker evidence

A complete end-to-end support workflow additionally requires implementations of the three published TELIPHONES integration contracts:

- **Connect**
- **Checker**
- **Console**

These are integration interfaces, not dependencies on FreePBX UK services. Initial authority, status, baseline, expiry and revoke testing can be performed before live external integrations are connected.

## Support Topologies

TELIPHONES defines three topology names.

### On-PBX

The private support connection terminates directly on the FreePBX server.

This is the locally implemented support topology in 0.2.0. TELIPHONES creates an ephemeral WireGuard interface named `wg-teliphones`; administrator workstation pairing uses the separate `tlp-admin` interface.

For FreePBX 17, the preferred private allocation pool is `10.20.17.0/24`. This is an allocation pool, not a route. Each session uses only the address space required for that connection.

Before accepting proposed addressing, TELIPHONES checks it against existing IPv4 addresses and routes. A collision causes the proposal to be rejected. TELIPHONES does not change the default route, DNS, forwarding, NAT or unrelated network configuration to make a proposed allocation fit.

### On-net

The private connection terminates elsewhere on the customer's local network.

The external Connect implementation is responsible for providing this path. TELIPHONES does not configure the customer's LAN to create it.

### Off-net

The private connection terminates outside the customer's network and may cross the public Internet.

The external Connect implementation is responsible for providing this path. TELIPHONES does not make the public network itself the privileged support endpoint.

## Authority and Session Lifecycle

Installing or enabling TELIPHONES does not authorise support access.

A support session requires explicit local root authorisation and has a fixed absolute expiry. External integrations cannot create, extend or replace that authority.

The intended successful sequence is:

1. Root authorises a temporary session.
2. Connect creates the required path.
3. TELIPHONES verifies PBX-local state.
4. Checker performs independent external observations.
5. TELIPHONES evaluates and accepts the Checker evidence.
6. TELIPHONES permits the temporary support service to open.
7. Console receives the approved handoff.
8. The session remains subject to its original absolute expiry.

In short:

`ROOT AUTHORISE → CONNECT → LOCAL VERIFY → CHECKER → CONSOLE → READY`

A reboot does not reset or extend the original expiry. If a grant remains valid after reboot, TELIPHONES can reconcile the still-valid session state, but the privileged temporary SSH service is not silently reopened.

Disabling TELIPHONES revokes active local support access and prevents new grants until the module is enabled again. The broker also removes workstation network access on its approximately 15-second reconciliation cycle and refuses to restore it while disabled. Pairing metadata is retained; re-enabling followed by broker restart or fresh approved pairing reapplies still-valid entries without extending temporary expiry.

## Connect

Connect creates the communications path for an authorised session.

TELIPHONES uses the versioned `teliphones-connect/1` contract. Connect returns a proposal or session material; it does not return an authorisation. TELIPHONES validates the returned information before using it.

For On-PBX, the PBX WireGuard private key is generated locally and does not leave the PBX.

Connect cannot create root authority, extend the grant, override local verification, provide Checker approval or authorise Console access.

TELIPHONES does not require a proprietary Connect service. The standalone open-source reference gateway in `gateway/` implements the On-PBX flow for disposable Linux testing; other operators can implement the published contract and provide their own network.

## Local Verification

TELIPHONES verifies state that can be established from the PBX itself.

For an On-PBX session this can include current authorisation, session identity, absolute expiry, expected WireGuard state, configured peer, local addressing, relevant routes and temporary support-service state.

Local verification does not attempt to establish whether a service is externally reachable or externally blocked. Those observations belong to Checker.

A mandatory local verification failure prevents the session from proceeding.

## Checker

Checker performs independent external observations of the path created by Connect.

TELIPHONES uses the versioned `teliphones-checker/1` contract. TELIPHONES generates a session-bound challenge containing a nonce and validity period. Checker returns observations associated with that challenge rather than a trusted `safe` verdict.

The contract supports observations including:

- expected support-service reachability from an authorised source;
- expected rejection from a negative-control source;
- public-address support-service exposure;
- unexpected service exposure.

TELIPHONES evaluates the returned evidence. Evidence is bound to the session, topology, nonce and challenge validity period. Accepted challenges cannot be reused; stale, mismatched and replayed evidence is rejected.

The repository includes an independent Checker probe tool for the reference gateway. A production deployment must provide and separately operate its own Checker signer and public-key enrollment process.

## Console

Console consumes an approved support session.

TELIPHONES uses the versioned `teliphones-console/1` handoff. A Console handoff is not available until the required local verification and Checker stages have completed.

Console does not create or extend root authority and cannot authorise itself.

The repository does not include an engineer portal. Console remains a provider-neutral handoff contract; engineers use standard WireGuard, browser and SSH clients.

## Temporary SSH Service

The On-PBX implementation uses a dedicated temporary sshd rather than repurposing the PBX's normal SSH listener.

The temporary service binds to the TELIPHONES private session address and currently uses port `22222`. Authentication uses session-specific public-key material and restricts the expected root connection to the session peer.

The temporary sshd disables:

- password authentication;
- keyboard-interactive authentication;
- TCP forwarding;
- agent forwarding;
- X11 forwarding;
- SSH tunnelling;
- gateway ports;
- user environment processing;
- PAM authentication.

Expiry, revoke and disable stop the temporary service and remove its session access material. A reboot does not automatically reopen it.

## Expiry and Revocation

A session has an absolute expiry established when root authorises it. Expiry is not recalculated from reboot time or from the time an external component connects.

When a session is revoked or expires, TELIPHONES attempts all local cleanup stages even if one stage reports a failure. Local cleanup includes stopping the temporary sshd, removing temporary SSH authorisation, destroying local `wg-teliphones` state and removing session material before depending on external cleanup.

Remote infrastructure should independently enforce the same session expiry so that remote session resources do not remain indefinitely if the PBX becomes unavailable.

## Installing

TELIPHONES is a community module and is not currently listed in the FreePBX online module repository.

Do not use:

```text
fwconsole ma installlocal teliphones
```

Use `fwconsole ma install teliphones` with the method below.

### Option 1: Install from an unpacked module directory

Place the `teliphones` directory in `/var/www/html/admin/modules/`, then:

```text
cd /var/www/html/admin/modules/teliphones
fwconsole ma install teliphones
cd
fwconsole chown
fwconsole reload
```

Check the installation:

```text
fwconsole ma list | grep -i teliphones
fwconsole teliphones check
```

For 0.2.0, perform this only on a disposable FreePBX 17 test system.

A repository installation option can be documented when a public TELIPHONES repository and supported branch structure are published.

## Updating TELIPHONES

Update TELIPHONES in place. Do not uninstall the module first for a normal source update.

After replacing or updating the module source:

```text
cd /var/www/html/admin/modules/teliphones
fwconsole ma install teliphones
cd
fwconsole chown
fwconsole reload
```

Confirm the installed version:

```text
fwconsole ma list | grep -i teliphones
```

Then rerun:

```text
fwconsole teliphones check
```

If an update appears incomplete, verify both the source `module.xml` version and the version reported by Module Admin before troubleshooting runtime behaviour.

## Command Line

TELIPHONES provides the following root-controlled CLI actions:

```text
fwconsole teliphones status
fwconsole teliphones baseline
fwconsole teliphones authorise
fwconsole teliphones connect-request
fwconsole teliphones provision
fwconsole teliphones peer
fwconsole teliphones attest
fwconsole teliphones checker-request
fwconsole teliphones checker-accept
fwconsole teliphones open
fwconsole teliphones console-handoff
fwconsole teliphones revoke
fwconsole teliphones check
fwconsole teliphones enable
fwconsole teliphones disable
fwconsole teliphones reconcile
```

Common options include `--minutes`, `--topology`, `--peer-key`, `--peer-endpoint`, `--pbx-address`, `--peer-address`, `--evidence-file` and `--ssh-key` where required by the action.

For example, authorise a 15-minute On-PBX test session with:

```text
fwconsole teliphones authorise --minutes=15 --topology=on-pbx
```

See `docs/INTEGRATION.md` and `docs/TESTING.md` before attempting the complete Connect, Checker and Console sequence.

## Baseline

`fwconsole teliphones baseline` provides a read-only, sanitised snapshot for before-and-after testing.

The current `teliphones-baseline/1` output includes capture time, hostname, sanitised TELIPHONES state, network interfaces and addresses, IPv4 main-table routes, IPv4 routing rules, listening TCP and UDP sockets, and details of `wg-teliphones` when present.

It deliberately excludes private keys, credentials, arbitrary configuration-file contents and unrelated process environments.

A typical test is:

```text
fwconsole teliphones baseline > /root/teliphones-before.json
```

Perform the TELIPHONES test, then:

```text
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

Timestamp and session metadata will naturally differ. The purpose is to identify unexpected persistent system changes.

## Security Model

TELIPHONES is designed so that no single external integration can establish privileged support access by itself.

The authority boundaries are:

- local root creates the grant;
- Connect creates the path;
- TELIPHONES verifies PBX-local state;
- Checker independently observes external behaviour;
- TELIPHONES evaluates Checker evidence;
- Console consumes access only after approval.

The FreePBX page now offers an administrator-approved workflow through the restricted root broker. The web process does not itself perform privileged network or SSH operations. The existing root CLI remains available for platform recovery. See the browser workflow section above for the precise trust boundary and bootstrap limitations.

For On-PBX, TELIPHONES also avoids using the normal PBX SSH listener as its temporary support service. Temporary network and authentication material is scoped to the support session and removed during local cleanup.

These are design properties of 0.2.0. They require live and adversarial testing before they should be treated as validated security guarantees.

## Current Limitations

TELIPHONES 0.2.0 is a development milestone, and current limitations include:

- live FreePBX 17 installation validation is pending;
- end-to-end integration testing is pending;
- adversarial security testing is pending;
- On-PBX is the first locally implemented topology;
- On-net and Off-net require external Connect implementations;
- a standalone reference gateway and engineer/Checker tools now exist, but real WireGuard traffic and end-to-end customer isolation have not yet been demonstrated;
- the Checker contract now requires a locally pinned ECDSA public key, but no production Checker signer is included;
- Module Admin installation and the root broker bootstrap (broker running, control socket present with the expected permissions) have been verified on a Debian 12 / FreePBX 17 test PBX; the GUI support workflow beyond that still needs disposable PBX validation; live countdown, engineer presence, PJSIP/RTP diagnostics and FreePBX Firewall integration are not implemented;
- expiry, SSH cgroup teardown and route policy have local code-level checks but still require disposable FreePBX 17/systemd/WireGuard integration tests;
- reboot and failure-recovery behaviour still require live validation;
- FreePBX menu rendering, permissions and navigation have only metadata-level checks in this workspace;
- Firewall-enabled GUI/SSH/PJSIP reachability is unknown and no firewall policy is changed;
- temporary SSH uses root with session-specific public-key authentication; a narrower support account/privilege model remains unresolved;
- the module is not suitable for production use at this stage.

## Reference Gateway

The standalone `gateway/` directory contains a provider-neutral reference Connect service, engineer/Checker config tools, policy tests and an opt-in Linux namespace lab. It is not part of the FreePBX module package and is not deployed. Read `gateway/README.md` before preparing a dedicated disposable gateway. Its sample config contains placeholders, not credentials or infrastructure endpoints. The current development host lacks `wg`, so real WireGuard traffic, GUI access and SSH access through the gateway have not been demonstrated.

## Validation

Run the local regression suite from the module directory:

```bash
php tests/run.php
```

It covers module XML/page-auth metadata, synthetic Linux route coverage, tunnel address collision policy and signed Checker policy. It does not install FreePBX, create a WireGuard interface, start systemd units, test a FreePBX Firewall, or contact a support gateway.

The first live test should deliberately avoid external integration and prove that the local authority lifecycle returns the PBX to its starting state.

Run:

```text
fwconsole teliphones check
fwconsole teliphones baseline > /root/teliphones-before.json
fwconsole teliphones status
fwconsole teliphones authorise --minutes=15 --topology=on-pbx
fwconsole teliphones status
fwconsole teliphones revoke
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

Only after the local lifecycle passes should testing proceed to Connect, Checker and Console.

The wider test programme includes expiry, reboot, collision refusal, WireGuard teardown, dedicated sshd binding and hardening, Connect failure, Checker negative control, public-exposure detection, stale or replayed evidence, Console gating, process interruption, disable during an active session, uninstall cleanup and reinstall behaviour.

Stop testing immediately if TELIPHONES exposes privileged root access publicly, changes the default route or DNS unexpectedly, modifies unrelated networking, extends an expired grant, accepts replayed Checker evidence, silently reopens privileged SSH after reboot or leaves privileged access behind after cleanup.

See `docs/TESTING.md` for the complete test programme.

## Documentation

Further documentation is provided under `docs/`:

- `INTEGRATION.md` — how the three integrations join TELIPHONES;
- `INTEGRATIONS.md` — integration overview;
- `CONNECT-CONTRACT.md` — Connect contract;
- `CHECKER-CONTRACT.md` — Checker contract;
- `CONSOLE-CONTRACT.md` — Console contract;
- `TOPOLOGIES.md` — On-PBX, On-net and Off-net definitions;
- `TESTING.md` — staged validation programme;
- `gateway/README.md` — standalone reference gateway and disposable integration testing.

The published contracts allow operators to implement Connect, Checker and Console independently, without shared managed services.

## Uninstalling

Revoke any active session before uninstalling:

```text
fwconsole teliphones revoke
```

Then uninstall the module:

```text
fwconsole ma uninstall teliphones --force
fwconsole chown
fwconsole reload
```

If the source directory remains after the module has been uninstalled and you no longer require it, remove `/var/www/html/admin/modules/teliphones` separately.

Testing should verify that uninstall leaves no `wg-teliphones` interface, temporary sshd or established SSH child, TELIPHONES session key material, active session state or TELIPHONES expiry job. If gateway cleanup fails, the module deliberately retains its local Connect cleanup record and logs the failure; remote expiry is still required.

## Support and Feedback

TELIPHONES is maintained by FreePBX UK.

For installation help, testing feedback, troubleshooting or general support, contact FreePBX UK:

https://freepbx.uk/support/

When requesting support during the 0.2.0 testing phase, include the following where relevant:

- FreePBX version;
- Debian version;
- TELIPHONES version;
- the topology being tested;
- the TELIPHONES action that failed;
- the relevant command output;
- whether Connect, Checker or Console was involved;
- a sanitised before-and-after baseline where appropriate.

Do not include private keys, credentials or other session secrets in support reports.

## Licence

GPLv3+. See LICENSE.

## AI-Assisted Contributions and Disclosure

This module has been developed with AI assistance for code generation, review, testing, and documentation. From 26 August 2026, generative AI assistance must be disclosed in every commit containing AI-assisted changes:

```text
Assisted-by: AGENT_NAME:MODEL_VERSION
```

For example: `Assisted-by: GitHub-Copilot:gpt-5.6-sol`

The human contributor remains solely responsible for the contribution. AI tools must not be listed as co-authors.

## Author

[@kierknoby](https://github.com/kierknoby), Kieran Knowles-Byrne // [FreePBX UK](https://github.com/freepbxUK)

## Experimental Windows desktop client

The native C++17 Win32/MFC client is under [`../desktop/windows/`](../desktop/windows/README.md). It supports administrator-owned workstation pairing and imported, customer-authorised Remote Support grants. It uses the official WireGuard for Windows installation and requires explicit Windows administrator approval for tunnel service setup. The client has compiled and launched in user-run Windows testing; this Linux development environment cannot validate Win32 APIs or real Windows/PBX traffic.

Administrator workstation pairing is separate from MSP session authorization. It is explicitly approved and revocable in **Connectivity > TELIPHONES > Windows workstations**. Persistent pairing lasts until revoked; temporary pairing expires on the PBX. Revoke a workstation on the PBX before deleting its local Windows profile. See [the workstation pairing contract](docs/WORKSTATION-PAIRING.md).

Direct WireGuard requires the PBX's configured UDP endpoint to be reachable. TELIPHONES does not configure router forwarding, promise universal NAT traversal, or provide a relay. The reference Linux gateway remains optional and experimental.

## Release History

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
