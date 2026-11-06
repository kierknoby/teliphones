# TELIPHONES for FreePBX 17: module guide

Current source targets module **0.6.6**, root broker **0.6.6**, protocol **12**;
Windows remains independently **0.8.3**. Both PBX components advance to identify
the firewall feedback-loop correction that restores workstation session
admission and idle broker CPU, on top of 0.6.5's durable workstation revocation,
verified removal and reliability corrections.
The protocol is unchanged, but older broker patch versions are not sufficient.
The local 0.6.6 module archive and SHA-256 sidecar include current source.
The superseded root-level 0.6.5 archive/checksum were removed; older packages lack
the session-admission and CPU correction. No release, live installation or deployment is claimed.
The module retains the web-only `ssh=0` form correction, bounded safe-value
retention and listener diagnostics. Live FreePBX 17 / Debian 12 acceptance
and native Windows 0.8.3 validation remain separate gates.

### Workstation revocation recovery (unreleased source)

Revocation first synchronously persists a root-only, fsynced
`workstation-revocations.json` journal, including directory fsync. Its public
identity tombstones override saved pairings, restart recovery, session admission
and SSH certificate authorisation. It stores public WireGuard identity, derived
interface ownership, revocation outcome and operation metadata, not credentials
or source restrictions. A revoked identity must be replaced with a newly
generated workstation identity before pairing again.

The broker verifies peer removal, its owned nft policy, managed SSH termination
and session admission separately from FreePBX listener housekeeping. Unconfirmed
removal triggers workstation-wide interface/SSH containment; failure to verify
that containment is explicitly reported and requires independent root recovery.
Other authorised workstations remain connected when targeted removal succeeds.
FreePBX-generated service chains remain owned exclusively by FreePBX.

The GUI's **Revoke workstation access** result distinguishes unconfirmed removal,
confirmed removal with pending housekeeping, and complete cleanup. Refreshing
status retrieves the persisted latest revocation result after a disconnected
browser or broker restart. Progress frames keep the existing five-second
inactivity bound while accepted cleanup continues independently of the browser.
Do not delete the revocation journal or restore an older copy to resolve errors:
that would discard security decisions. Live FreePBX 17 / Debian 12 validation
of these unreleased corrections is still required. Module and broker now identify
this source as 0.6.6; Windows remains 0.8.3.

**Review before installation:** the operator confirmed a listener subprocess
CPU overload in installed broker 0.6.2 and deliberately stopped it. Keep it
stopped until the replacement is reviewed. The initial pending 0.6.3 source
shared that defect; current source gates background commands on
owned listener readback and backs off failures. No live CPU or connectivity
success is claimed. Follow the controlled observation procedure below.

Approve private access to your PBX from the FreePBX interface. TELIPHONES
**0.6.6** pairs Windows workstations over WireGuard, with web access and,
when explicitly approved, temporary SSH certificates for an existing account.
This is the authoritative guide to installing, upgrading and operating the
FreePBX module and its separately installed root broker.

**TELIPHONES is a UK registered trademark.**

**TELIPHONES 0.6.6 for FreePBX is licensed under GPLv3.**

The software grant is GPL version 3 or later; the product footer uses the
GPLv3 wording above. Software licensing does not grant trademark rights.
See [Licence](#licence).

> [!WARNING]
> **Experimental; not currently suitable for production.** Local gateway,
> FreePBX and portable Windows-core regressions pass. Native Windows compilation,
> MFC/Windows service integration and live FreePBX session-admission, migration,
> firewall, password-protection and SSH acceptance have not been performed in
> this environment. Use a disposable system and retain an independent
> root/console route. See [current verification status](#current-verification-status).

> [!IMPORTANT]
> **0.4.x and 0.5.0 installations need the 0.6.0 upgrade and root broker refresh.**
> FreePBX reported TELIPHONES' 0.4.0 rule above its INPUT hook as intrusive and
> repeatedly rebuilt iptables, approximately every 41 seconds in the observed
> incident, coinciding with intermittent connectivity. Version 0.4.1 moved the
> marked jump inside `fpbxfirewall`, which ended the resets but exposed a
> missing permission: no earlier version permitted the inbound WireGuard
> listener (UDP, default 51821) through FreePBX Firewall. This is consistent with
> blocked handshakes, but packet capture alone cannot identify the dropping rule.
> Earlier successes could have depended on trusted networks, existing services,
> reset windows or established UDP tracking; none is confirmed. Version 0.5.0
> registers the shared and any dedicated listener ports as persistent FreePBX
> Custom Services, leaving generated UDP rules to FreePBX. Unlocked workstations
> may roam without public-IP allowlists; optional Locked pairings use dedicated
> interfaces and source-specific IP/CIDR/domain rules. WireGuard cryptography
> authenticates each peer. Version 0.6.0 adds persisted Open, Closed and Frozen
> states, atomic session leases, post-pair policy requests and identity-preserving
> listener migration. Local regressions pass, but live watchdog and native
> Windows validation remain outstanding. Uploading the new module alone does not prove that the
> installed root broker changed. [Repeat the root bootstrap and verify
> its files/version](#updating-teliphones), even if protocol 6 is already shown.
> **Do not disable FreePBX Firewall or enable Custom Rules as a workaround.**

## Secure Administration Without Exposing Your PBX

With independently versioned **Windows 0.8.3**, administrators use **My PBXs**
to connect their own paired workstations. **Remote Support** is a separate,
customer-authorised, time-limited workflow for enrolled MSP engineers.
Neither replaces normal FreePBX sign-in or creates Linux accounts.

TELIPHONES does not automatically close public management ports or replace
FreePBX Firewall. Verify the private route before restricting your existing
administration route. While workstations are paired, the root broker permits
the WireGuard UDP listener through the PBX host firewall (FreePBX Firewall
integration); router/NAT port forwarding may still be necessary. SIP/RTP requirements are
separate from private GUI/SSH access. No relay or universal NAT traversal is
provided.

## Contents

[Secure Administration Without Exposing Your PBX](#secure-administration-without-exposing-your-pbx)

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
    and [Current verification status](#current-verification-status)
13. [Testing](#testing)
14. [Further documentation](#further-documentation)
15. [Support and feedback](#support-and-feedback)
16. [Licence, AI disclosure and author](#licence)
17. [Release History](#release-history) (complete, separately linked changelog)

## What the module provides

The module adds **Connectivity > TELIPHONES** to FreePBX and the `fwconsole teliphones` command. The page has four areas:

| Area | Purpose |
|---|---|
| **System readiness** | Broker state and prerequisites, including **Approve installation of WireGuard tools** |
| **Remote support** and **Active session** | Authorise, monitor and revoke a temporary support session, and submit Checker evidence |
| **Secure gateway enrolment** | Store gateway, certificate and Checker trust material for Remote Support |
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
| A reachable WireGuard UDP port | Default `51821`. The broker's FreePBX Firewall integration permits it through the PBX host firewall while workstations are paired; it must still be reachable through the router/NAT |

The root broker installs packages only when an administrator explicitly approves WireGuard tools, and then installs only `wireguard-tools` from Debian's configured repositories. Any other missing prerequisite must be installed by the platform administrator.

### Windows workstations

- Windows 10 or 11, x64.
- The official WireGuard for Windows, installed with Windows administrator
  approval, either independently or through the application's explicit
  **Install WireGuard** flow.
- The TELIPHONES Windows application (`TELIPHONES.exe`), built from `desktop/windows/` in the TELIPHONES source repository, or downloaded from a successful GitHub Actions build. It is not included in the module package.
- Windows system OpenSSH Client for managed **My PBXs Open SSH**, hosted in
  Windows PowerShell, PowerShell 7, Windows Terminal or Command Prompt.
  PuTTY is supported only by the separate Remote Support workflow, not managed
  My PBXs certificates.

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

1. Obtain `TELIPHONES-0.6.6.tgz` and its SHA-256 checksum from a trusted source, then verify the archive:

   ```bash
   sha256sum -c TELIPHONES-0.6.6.tgz.sha256
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
test -f "$SRC/ssh_authority.py"
test -f "$SRC/FirewallListener.php"

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

**0.6.5 or earlier to 0.6.6:** review and verify `TELIPHONES-0.6.6.tgz` against its supplied
`TELIPHONES-0.6.6.tgz.sha256` with `sha256sum -c TELIPHONES-0.6.6.tgz.sha256`,
then upload that archive through **Admin > Module Admin > Upload Modules** as
an in-place upgrade. Do not uninstall the module or delete workstation
configuration. Then rerun the root bootstrap above: 0.6.6 includes root broker
0.6.6, with the nftables feedback-loop correction for session admission and CPU use,
durable revocation, verified removal, containment and retrievable outcomes,
alongside the module's web-only form correction, while preserving
nftables verification and protocol 12. Module Admin does not necessarily
replace the separately installed root-owned broker. The module reports an
outdated broker version and refuses workstation pairing until the current
broker status is confirmed.

The root-broker procedure is required for every 0.6.6 upgrade and older or
incomplete installations:

1. Confirm, as root, that no support session is active: `fwconsole teliphones status`.
2. Disconnect Windows workstation tunnels.
3. Upload and install the new archive through **Admin > Module Admin**. For an unpacked directory, use the commands in [Install from an unpacked module directory](#install-from-an-unpacked-module-directory).
4. Rerun [Complete Installation on FreePBX 17](#complete-installation-on-freepbx-17) from a root shell.
5. Refresh **Connectivity > TELIPHONES** and confirm that **Root broker update required** is no longer shown. The installed version is reported by `fwconsole ma list | grep -i teliphones`.

### 0.6.6 development-server acceptance

<a id="064-development-server-acceptance"></a>

This checklist is for the administrator to execute after the in-place Module
Admin upgrade and the root bootstrap above. It has **not** been executed against
the development PBX during package preparation. Keep an independent root/console
route, leave FreePBX Firewall enabled and do not flush rules or clear recovery
state. The upgrade/bootstrap intentionally refreshes and restarts the broker;
do not perform it during an active support session.

**Additional startup gate after the reported CPU overload:** keep the existing
development broker stopped until this rebuilt package is reviewed. After review,
verify the new checksum, upgrade Module Admin in place and use the existing
root bootstrap above; it starts the replacement broker as part of installation.
Do not first restart the old broker to collect evidence. Keep an independent
root shell open so the replacement can be stopped immediately if the overload
returns. Record its start time, module/helper hashes and version before testing.

Before any pairing, leave the authoritative Open/zero-workstation policy
unchanged and allow the single startup reconciliation to finish. From one
root shell observe CPU with `vmstat 1 60` (ignore its first, since-boot sample).
In a second root shell sample the broker's listener children for two minutes:

```bash
broker_pid=$(systemctl show teliphones-broker.service -p MainPID --value)
test "$broker_pid" -gt 0
for sample in $(seq 1 120); do
    date -Is
    ps -eo pid=,ppid=,pcpu=,args= |
      awk -v parent="$broker_pid" '$2 == parent && /fwconsole teliphones listener/ {print}'
    sleep 1
done
```

Stable state must not continuously spawn listener processes; after initial
generation, periodic checks and unchanged notifications require **no additional
listener commands**. CPU should return close to the stopped-broker idle baseline,
accounting for other PBX work. Sampling can miss short-lived processes; retain
journal failures/backoff messages too, and use existing process-execution
auditing if already available rather than installing monitoring tools.
Repeated changing listener PIDs, high sustained CPU, readiness errors or
continuous retries fail this gate. Stop the replacement with
`systemctl stop teliphones-broker.service` if it overloads the server, retain
diagnostics and do not proceed with pairing.

1. **Identity and readiness:** confirm the GUI heading is `TELIPHONES 0.6.6`,
   all three installed helpers match the module using the `cmp` commands below,
   the service started after bootstrap, and live status reports component
   `0.6.6`, protocol `12`, workstation readiness and all required tools. A
   socket or active service alone is insufficient. From the existing root shell,
   request only non-secret status fields as the permitted service account:

   ```bash
   runuser -u asterisk -- php -r '
   require "/var/www/html/admin/modules/teliphones/WebSupport.php";
   $r = (new \FreePBX\modules\Teliphones\WebSupport())->request(["action"=>"status"]);
   if (($r["ok"] ?? false) !== true) { fwrite(STDERR, "Broker status failed\n"); exit(1); }
   $s = $r["status"];
   $w = $s["workstations"] ?? [];
   echo json_encode(["component_version"=>$s["component_version"] ?? null,
     "protocol"=>$s["protocol"] ?? null, "enabled"=>$s["enabled"] ?? null,
     "ready"=>$w["ready"] ?? null, "requirements"=>$w["requirements"] ?? null,
     "error"=>$w["error"] ?? null, "firewall_integration"=>$w["firewall_integration"] ?? null],
     JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
   '
   ```

2. **Firewall:** set the intended Open policy through the GUI when authorised.
   Check its reported integration state and read-only kernel/API evidence:
   one owned UDP listener service with the configured port and exact
   external/internal/other jumps, no TELIPHONES INPUT jump, and only the
   marker-owned integration jump inside `fpbxfirewall`. Preserve unrelated rules.
   FreePBX generates service rules asynchronously; inspect the actual state,
   not just the saved Custom Service.
3. **Pairing:** in Windows 0.8.3 select name/access before generation. Generate
   and copy the request into **Connectivity > TELIPHONES > Pair a Workstation**.
   Test web-only first: complete the form and approve it without an SSH account.
   Copy the PBX response into Windows and validate/save it. Do not retain or
   share pairing strings. If SSH is tested separately, explicitly approve an
   existing permitted account; requested access is not authorisation.
4. **WireGuard:** connect and confirm a current handshake and admitted session,
   not just a saved pairing or an Up interface. Check the expected endpoint,
   dedicated listener if Locked, assigned addresses and routing without
   disclosing private keys. With the unrestricted web-only workstation
   connected for several heartbeat intervals, repeat the CPU sample above: the
   session must stay admitted, the WireGuard interface must not cycle down and
   broker CPU must remain near idle.
5. **Management access:** open FreePBX through the approved tunnel URL and
   configured management ports; confirm normal FreePBX authentication is still
   required. Web-only must not obtain SSH. If separately approved, verify the
   managed SSH session and its response-derived account.
6. **Disconnect/reconnect:** disconnect, confirm session/management access and
   owned managed SSH stop, then reconnect and repeat approved access checks.
   Record failures rather than treating a handshake as application success.
7. **Removal:** revoke the test workstation and confirm its peer/session and
   authorised management access disappear. Open policy can legitimately retain
   the shared listener with zero peers. When authorised, set Closed to exercise
   complete listener/interface/owned-rule cleanup; verify unrelated firewall
   rules remain and ownership recovery is not discarded on failure.
8. **Genuine Firewall change/recovery:** only with separate operational approval
   and the independent root route retained, perform a normal FreePBX Firewall
   configuration change or regeneration. Do not disable/flush the firewall or
   alter unrelated rules to simulate success. Confirm generated listener and
   integration state is checked/restored, approved connectivity recovers and
   the worker returns to idle. Correct listener rules require no new helper
   command; missing/differing owned rules require a bounded repair followed by
   idle. Failed repairs must leave access blocked and use logged
   5/10/20/40/60-second retry backoff rather than continuous subprocess creation.
   Repeat disconnection and removal checks after recovery.

On failure, record UTC time, action and policy, the new full GUI error and
`journalctl -u teliphones-broker.service --since '-10 minutes' --no-pager -o short-iso`.
Listener errors must distinguish admission ports from removal, identify the
owned chain and final rule/zone mismatch, and retain the initiating error if
cleanup/restoration also fails. Capture matching read-only listener API, ownership
IDs/ports and `iptables -w 1 -t filter -S` evidence at that time; sanitise unrelated
addresses and never share complete workstation state, keys or pairing payloads.
Unknown subprocess output is explicitly withheld rather than echoed.
Report a different/withheld error as evidence; do not assume convergence was
the initiating failure. See the source repository's firewall diagnostics runbook.
Do not declare connectivity fixed until the complete sequence succeeds.

### After upgrading TELIPHONES

A Module Admin upgrade updates the FreePBX module files but does not necessarily update the separately installed, root-owned broker. TELIPHONES 0.6.6 requires broker version 0.6.6, broker protocol 12 and both `/usr/local/lib/teliphones-broker/support_broker.py` and `/usr/local/lib/teliphones-broker/ssh_authority.py`; an older broker or a missing SSH helper cannot provide the current durable workstation revocation, verified access removal, persisted operation outcomes, pairing transport and error-handling corrections, nftables transaction acknowledgement, safe workstation cleanup recovery, managed SSH, connection-state policy, source-locked pairing, post-pair workstation policy, identity-preserving listener migration, Windows policy requests, post-pair SSH elevation, manual listener bans or enforced workstation session limits. Confirm that no support session is active (as root: `fwconsole teliphones status`), disconnect Windows tunnels and expect existing TELIPHONES-managed SSH sessions to terminate, then rerun the root bootstrap from an existing root shell. The bootstrap retains the previous helper files and broker unit, validates the installed helpers, and enables and restarts `teliphones-broker.service`. Verify that service is active, `/run/teliphones/control.sock` exists, and the refreshed Connectivity > TELIPHONES page reports broker version 0.6.6, protocol 12 and managed SSH readiness. On failure, rollback attempts to restore prior files and the previous enabled/active state; an incomplete rollback is an error requiring recovery from the existing root shell. Do not restart, reconfigure or disable the normal system SSH service or change administrator accounts. Valid pairings retain their original deadlines and cryptographic identities during listener migration.

Protocol 5 identifies the certificate endpoint and managed SSH contract shared
by 0.4.0 and 0.4.1; it does not identify the firewall correction.
Protocol 4 identifies older diagnostics support only. A matching module version
does not establish that either root-owned helper was upgraded. Preserve an
independent administrator/root shell until service, socket and readiness checks
succeed. If rollback reports incomplete recovery, retain all recovery artefacts
and repair the TELIPHONES installation from that shell rather than removing the
module or changing the normal SSH service. Actual Debian 12 / FreePBX 17
systemd upgrade, failure recovery and uninstall validation remains a release gate.

For current 0.6.6 corrections, rerun the bootstrap even if protocol 12
was already reported. It copies all three current module helpers into the
separately installed root-owned broker directory and restarts the service.
Afterward, compare the installed files to the module files from a root shell:

```bash
cmp /var/www/html/admin/modules/teliphones/support_broker.py /usr/local/lib/teliphones-broker/support_broker.py
cmp /var/www/html/admin/modules/teliphones/ssh_authority.py /usr/local/lib/teliphones-broker/ssh_authority.py
cmp /var/www/html/admin/modules/teliphones/FirewallListener.php /usr/local/lib/teliphones-broker/FirewallListener.php
grep '^VERSION = ' /usr/local/lib/teliphones-broker/support_broker.py
systemctl show teliphones-broker.service -p ActiveState -p MainPID -p ExecMainStartTimestamp
```

All three `cmp` commands must succeed and the installed broker must declare `0.6.6`.
Confirm the process started after bootstrap, then verify no TELIPHONES jump
remains in INPUT and exactly one marked jump exists inside
`fpbxfirewall`. Verify that every TELIPHONES ACCEPT rule in the owned chain
is scoped to the expected interface, peer and PBX addresses. Verify the managed UDP Custom Service and its
generated zone rule separately; FreePBX applies service changes asynchronously.
Keep the independent root shell open throughout these checks.

### Upgrading from 0.2.0 or 0.2.1

- Saved pairings, their addresses, permissions and original deadlines, and the PBX's workstation key are preserved.
- Expired temporary pairings are not restored.
- An unmarked table is migrated only when its complete contents exactly match the known 0.3.0 TELIPHONES policy reconstructed against root-owned saved state, and the interface is verified down. Unknown or altered tables remain untouched and workstation access stays disabled. See [upgrading from 0.3.0](docs/WORKSTATION-PAIRING.md#upgrading-from-030). Never flush the host ruleset to bypass a conflict.

## Windows workstations: install, pair and connect

This workflow pairs an administrator's own Windows workstation with this PBX.
A web-only pairing needs WireGuard, not Windows OpenSSH. For automatic SSH,
select **FreePBX Web + SSH Access** in Windows before generating
the request, then explicitly approve an existing account on the PBX. New SSH
pairings use an isolated managed listener, never the ordinary system SSH port.
It does not require the reference gateway, Checker or any external service.

**Key concepts**

- **Pairing** is the PBX's approval of one workstation key. It is created once, and it remains valid until it expires (temporary) or is revoked (persistent).
- **Connection** is the tunnel the workstation brings up when it needs access. Connecting and disconnecting do not change the pairing.
- **Revocation** removes the pairing on the PBX. It is the only way to remove a workstation's authority; deleting the Windows profile does not.

### Before you begin

- The broker is operational and current: **Windows workstations** is visible, and **Root broker update required** is not shown.
- `wg`, `ip` and `nft` are available. If any are missing, **Windows workstations** lists them. **Approve installation of WireGuard tools** installs `wg`; `iproute2` and `nftables` must be installed by a root administrator.
- You are signed in to FreePBX as a full administrator **over HTTPS**.
- The PBX's WireGuard UDP port (default `51821`) is reachable from the workstation. If the PBX is behind NAT, the external UDP port must forward to the same PBX listener port and the router must permit it; TELIPHONES does not configure routers. The broker permits shared and dedicated listener ports through FreePBX Firewall. Unlocked workstations may connect from any public address; a Locked pairing is restricted to its administrator-approved IPv4/IPv6 addresses, CIDRs or domains on a dedicated listener. Do **not** publish TCP 22, 80 or 443 for this purpose.

### 1. Prepare the workstation

1. Install the official WireGuard for Windows, with Windows administrator approval.
2. Run `TELIPHONES.exe`. The top of the window reports whether WireGuard for Windows was found.

### 2. Generate a pairing request

1. Select **Add my PBX...**.
2. In **Request access**, enter a workstation name and select **FreePBX Web
   Access** or **FreePBX Web + SSH Access** before **Generate request**.
   Web-only is the default and creates no SSH identity.
3. Select **Generate request**, then **Copy request**. Note the fingerprint.
   Changing name or access invalidates the previous request/response and requires
   regeneration; the workstation name is retained.

Keep the **Pair my PBX** dialogue open. The response will be bound to this request and to the key that has just been generated.

### 3. Approve the pairing on the PBX

1. In **Connectivity > TELIPHONES > Windows workstations**, expand **Pair a workstation**.
2. Paste the request into **Pairing request from the Windows application**.
3. Enter the **PBX public hostname or IP address** that the workstation uses to reach WireGuard, and the **shared WireGuard UDP port on the PBX**. Unlocked pairings use this port. If you enter one or more sources in **Lock this workstation to approved IPs/domains**, the broker allocates a dedicated port/interface for that workstation and includes the port in its pairing response. The administrator/router must permit and, where applicable, forward each dedicated UDP port as well as the shared listener.
4. Choose the access period:
   - **Temporary**, with a **Temporary pairing duration** of 60, 240, 480 or 1440 minutes; or
   - **Persistent trusted workstation (until revoked)**.
5. Under **SSH approval**, leave **FreePBX Web Access only** for web-only access.
   A valid SSH-capable request reveals **FreePBX Web + SSH Access** and requires
   explicitly selecting an existing Linux account; there is no default account
   or implicit root. Requesting SSH in Windows does not itself approve it.
   For a Locked pairing, the managed SSH listener and certificate API bind to
   its dedicated interface/address with firewall permits scoped to that peer.
6. Select **Pair workstation**. Compare the key fingerprint shown on the PBX with the one shown in the Windows dialogue. They must match.

### 4. Complete pairing on Windows

1. On the PBX, select **Copy pairing response**.
2. Paste the response into **Complete pairing** in the waiting Windows dialogue.
3. If SSH was approved, the validated response supplies its account automatically;
   the display is read-only and hidden for web-only approval.
4. **Save connection** enables only for a response bound to the current request
   and is revalidated when clicked. Invalid or old responses cannot be saved.

Pairing creates no SSH account or password. The SSH-capable server contract enrols a permanent workstation authentication public key, separate from disposable session keys, and pins the PBX's Ed25519 host key and certificate authority. Neither private key belongs in a pairing or certificate request. Existing saved identities remain preserved and can be imported from their encrypted DPAPI store in memory.

### 5. Connect and open FreePBX

1. Select the saved connection and select **Connect**.
2. Approve the Windows UAC prompt, which installs the TELIPHONES tunnel service for this PBX.
3. Wait until the application reports that the PBX is reachable.
4. Select **Open FreePBX**. This opens the approved HTTP/HTTPS scheme, port and
   `/admin/` path on the PBX tunnel address in the preferred browser (see
   [browser and SSH terminal preferences](#browser-and-ssh-terminal-preferences)).
   Sign in with existing FreePBX credentials; authentication is never bypassed.

The workstation routes only the PBX's tunnel address (`/32`); other traffic does not use the tunnel. Only one TELIPHONES connection is active at a time.

### 6. Use SSH (only when approved)

New managed pairings use a separate listener at `22000 + workstation address's last octet`, never the system SSH listener. The certificate API is TCP 8765. Both are bound to the exact WireGuard address **and device**; firewall rules admit only authorised peer/service combinations. Do not publish these ports or forward them from the Internet. Ordinary system SSH, accounts and unrelated sessions are untouched.

- Select **Open SSH** once Connection Health confirms the PBX is reachable.
  Windows requests a fresh certificate automatically and opens the approved
  account in the chosen OpenSSH-backed terminal. The operator reports successful
  authenticated access to FreePBX 17 and automatic terminal closure on disconnect;
  that does not prove complete PBX-side revocation or expiry.
- Windows uses in-memory session keys, signed certificate requests, certificate
  signature verification, strict pinned host checks and an owned console/SSH
  lifecycle. Its private agent signs once for the owned SSH process and destroys
  the session key; no plaintext session private-key file or shared agent is used.
  Provider errors fail closed.
- The server's request/2 API verifies the permanent paired identity's signature over a one-use challenge, fresh session ID and distinct ephemeral public key, then issues a certificate lasting at most five minutes (capped by pairing expiry). It refuses the persistent identity as certificate subject and rejects old request/1 issuance. Only public key material is sent to the server. Pinned host/CA verification is mandatory.
- Existing legacy pairing network permissions are preserved, but Windows requires re-pairing for automated SSH. It never silently falls back to existing passwords, keys or host-key prompts.

Managed SSH requires OpenSSH tools, a working root systemd manager and unified cgroup v2. Each workstation listener has its own service with `KillMode=control-group`; temporary authorisations additionally use `RuntimeMaxSec`. The implementation stops only owned units and verifies empty cgroups before discarding state. Recognised legacy principal migration requires a verified owned-unit stop before enabling the new ephemeral principal; old persistent-key certificates are rejected without destroying permanent identities. Unsupported account, multi-factor and forced-command policies fail closed rather than being weakened. Real systemd/cgroup termination, upgrade, rollback and uninstall validation remains mandatory; Linux namespace tests substitute service supervision. Certificate expiry prevents new authentication, not termination of an established session: that depends on the pairing lifetime and owned service controls. See [managed pairing and lifecycle details](docs/WORKSTATION-PAIRING.md#version-2-managed-my-pbxs-ssh).

#### Browser and SSH terminal preferences

On first start, the Windows application shows **Welcome to TELIPHONES**. It offers the browsers and SSH terminals found on the workstation:

- **Browsers:** the Windows default browser, Google Chrome, Microsoft Edge, Mozilla Firefox, Brave and Vivaldi.
- **Managed My PBXs SSH:** Windows PowerShell, PowerShell 7, Windows Terminal
  and Command Prompt, all using Windows OpenSSH.
- **Remote Support SSH:** the separate launch path also supports PuTTY.
  Selecting PuTTY in Settings does not enable managed certificate authentication.

A native integrated TELIPHONES SSH terminal, inspired by my-console usability,
is **planned**, not implemented. External terminal choice remains an objective;
PuTTY compatibility for managed SSH is a development objective only if it can
preserve certificate authentication, key isolation and session termination.

You can save your choices, skip and keep the defaults, or cancel. Change them later with **Settings...**. The preferences apply to every saved PBX. They are stored only for the Windows user on that workstation, and are never sent to the PBX or stored in this module. If a selected application is uninstalled or moved, the application reports it and offers another choice rather than silently launching something else. Full details are in the Windows application README (`desktop/windows/README.md` in the source repository).

Workstations not approved for SSH receive no certificate and cannot reach any managed SSH listener. To grant SSH later, revoke and pair again with explicit account approval.

### 7. Disconnect

Select **Disconnect** to close owned managed SSH processes and stop/remove the
Windows tunnel service. Closing the application normally also requests
disconnection. Terminal closure on disconnect has been operator-observed;
it is not PBX-side revocation. The pairing remains valid, so you can connect
again later without a new approval.

### 8. Revoke access

1. In **Windows workstations**, select **Revoke** for the workstation, or **Revoke all workstations** when several are listed.
2. Confirm that the page reports success. Revocation removes temporary and persistent authority alike.
3. After verified revocation, the Windows profile cannot reconnect without a fresh approval. You may then remove it with **Remove** in the Windows application.

If cleanup fails, the page reports an error and keeps **Revoke all workstations** available for retry, even if no pairing remains listed. Do not treat a failed operation as a revocation. If the interface cannot be deleted, the broker disables it and keeps the restrictive firewall rules, rather than opening its traffic. If a retry also fails, inspect the broker as root (see [Troubleshooting](#troubleshooting)).

Windows detects revocation by losing reachability to the PBX. There is no server-pushed revocation, so the client may take a short time to notice. The PBX is authoritative.

### Reading the workstation table

| Column | Meaning |
|---|---|
| **Access** | **Web interface only**, **Web interface and managed SSH** with the approved account, or legacy SSH permissions |
| **Pairing** | **Persistent (until revoked)**, or **Temporary, expires** at a UTC time |
| **WireGuard status** | **Authorised; no handshake yet**, the time of the **Last handshake** (UTC), or **Not verified (status unavailable)** |

Above the table, TELIPHONES reports the FreePBX Firewall integration state:

| Message | Meaning |
|---|---|
| **FreePBX Firewall integration active (iptables nf_tables)** or **(iptables legacy)** | The narrow marked jump and owned chain were last verified inside `fpbxfirewall`; this is not a reachability probe |
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

Expand **Secure gateway enrolment** over HTTPS, then enter:

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
| Pairing reports the root broker's failed readiness condition although the tools are installed | Read the broker error on the page. For an outdated broker version, follow [Updating TELIPHONES](#updating-teliphones) and rerun the root bootstrap; protocol 12 alone does not prove that broker 0.6.6 is installed. |
| *TELIPHONES is disabled.* | Enable it as root with `fwconsole teliphones enable` |
| *Paired workstations already use UDP port ...* | Use the same port, or revoke all workstations first |
| *No workstation addresses remain* | Revoke unused workstations |
| The Windows application rejects the response | Pair again from the same, still-open request dialogue. A response is valid only for the request that produced it. |

An **Operational** broker and verified control socket establish that a status
request succeeded, not that a pairing transaction completed. Pairing may spend
more than five seconds verifying generated FreePBX listener rules. The PHP
client requests non-secret progress frames over the authenticated Unix socket
and retains its five-second *inactivity* deadline; only the final verified
response constitutes success. Legacy socket clients still receive one final
JSON response, and broker protocol remains 12.

If the response times out, closes early, is malformed or exceeds its size limit,
the GUI reports that condition rather than suggesting missing tools. An
interrupted response does not cancel or repeat the broker transaction: refresh
the workstation list before retrying, because the outcome is unconfirmed.
Request-boundary failures identify the operation stage and a safe error category;
`journalctl -u teliphones-broker.service -n 50 --no-pager` provides the exception
class and source location without recording request or command contents.
Keep journal excerpts private and redact existing sensitive records before sharing.

After a failed pairing submission, bounded hostname, port, management-service,
duration and source-restriction values are retained for correction. The Windows
pairing request is deliberately cleared, and SSH approval must be selected again
explicitly after repasting it. A web-only request still submits an explicit
`ssh=0` even when its SSH approval select is disabled; missing or non-text
required fields are identified by label before the pairing is dispatched.
Malformed Windows request contents remain subject to broker validation.

Module 0.6.6 requires root broker 0.6.6 for these corrections. Refresh **both**
the module PHP and the root-owned helpers through the reviewed
[root bootstrap](#complete-installation-on-freepbx-17). Protocol 12 alone cannot
distinguish the earlier broker; use the version and installed-file comparisons
in [Updating TELIPHONES](#updating-teliphones).
An older helper rejects the optional progress request before dispatch and the GUI
instructs the administrator to refresh it; it does not retry the mutation.

### No WireGuard handshake

If the table shows **Authorised; no handshake yet**:

- confirm that the Windows application is connected, and that the UAC prompt was approved;
- confirm that the hostname or IP address and the UDP port in the pairing are reachable from the workstation's network;
- check NAT port forwarding: the external UDP port must reach the same PBX listener port;
- confirm that the router/NAT permits and forwards the WireGuard UDP port (no relay or NAT traversal is provided). On the PBX, inspect the managed WireGuard UDP Custom Service and follow the generated service rule through FreePBX's zone chains. The tunnel integration's **active** status alone does not establish public UDP reachability;
- check the handshake on the PBX: `wg show tlp-admin latest-handshakes`.

### The handshake succeeds but FreePBX does not load

1. Check the integration message above the **Windows workstations** table.
2. If the broker does not report the integration, rerun the root bootstrap.
3. Inspect the integration, read-only:

   ```bash
   iptables -S INPUT
   iptables -S fpbxfirewall
   iptables -S teliphones-ws
   iptables -L teliphones-ws -v -n -x
   nft list table inet teliphones_workstations
   ```

   In `iptables -S INPUT`, expect no TELIPHONES jump. Every `fail2ban-*` or `f2b-*` hook must precede the first `-j fpbxfirewall` rule. The first rule inside `fpbxfirewall` should be the single marked `-i tlp-admin` jump to `teliphones-ws`. Its counters show whether workstation traffic is reaching it.
4. Confirm that the web server is listening: `ss -ltn '( sport = :80 or sport = :443 )'`.
5. Check the broker log: `journalctl -u teliphones-broker.service -n 50 --no-pager`.

If the counters do not increase while a browser connects, the traffic is not reaching the integration. Collect the output above for a [support request](#support-and-feedback). Do not add trusted zones or networks in FreePBX Firewall.

### FreePBX Firewall integration failed: Fail2Ban ordering

If a Fail2Ban hook appears **after** `fpbxfirewall` in `INPUT`, the internal exception would precede that ban. TELIPHONES withdraws its integration rather than bypass Fail2Ban, and names the affected chains. Tunnel web traffic is dropped by FreePBX Firewall until the order is corrected. Restarting Fail2Ban normally reinserts its hooks at the top of `INPUT`, after which TELIPHONES restores the integration automatically. Do not edit or remove Fail2Ban or FreePBX Firewall rules by hand.

### Firewall ownership conflict

If TELIPHONES reports an unfamiliar `inet teliphones_workstations` table or `teliphones-ws` chain, it will not change it and workstation access stays disabled. The 0.3.1 broker safely migrates only the exact known 0.3.0 nft policy while `tlp-admin` is down. If migration is refused, preserve the saved pairing/key data and obtain administrator review; do not flush the ruleset or remove unrelated tables. See [firewall ownership and migration](docs/WORKSTATION-PAIRING.md#enforcement-integrity-and-exposure-limits).

### SSH does not connect

- Check the **Access** column: new pairings must show **Web interface and managed SSH** with the explicitly approved account. Check managed SSH readiness and the root broker; do not open public TCP ports to work around an error. Legacy pairings require re-pairing for automated SSH.
- **Open SSH** stays unavailable until the PBX has answered through the tunnel and the status shows the connection as connected.
- Windows PowerShell, PowerShell 7, Windows Terminal and Command Prompt need
  Windows OpenSSH Client. Install the Windows optional feature if missing.
  PuTTY is not an alternative for managed My PBXs certificates; it is supported
  only by the separate Remote Support workflow.
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

After uninstalling, verify that no `tlp-admin` or `wg-teliphones` interface remains. Also check that no temporary `sshd` or SSH child process, session key material, active session state or TELIPHONES expiry job remains, and that `teliphones-ws` and its marked jumps in `fpbxfirewall` and legacy `INPUT` are absent. If gateway cleanup fails, the module deliberately retains its local Connect cleanup record and logs the failure; remote expiry is still required.

## Known limitations

- **Experimental status.** End-to-end, failure-recovery and adversarial security testing on a real PBX is incomplete.
- **External firewall flushes.** TELIPHONES detects and repairs external firewall changes, but cannot prevent them. A flush can briefly expose an active tunnel before detection; a transient removal can pass traffic even if the rules are restored before detection. This is **not** fail-closed or zero-exposure protection. See [enforcement integrity and exposure limits](docs/WORKSTATION-PAIRING.md#enforcement-integrity-and-exposure-limits).
- **Fail2Ban ordering gap.** A Fail2Ban INPUT hook externally moved after `fpbxfirewall` can be bypassed by approved workstation traffic until reconciliation withdraws integration. Hooks inserted before `fpbxfirewall` stay ahead of the internal TELIPHONES jump without repair. Reconciliation has no guaranteed deadline.
- **Assumed FreePBX hook names.** `fpbxfirewall`, `fail2ban-*` and `f2b-*` come from the reported FreePBX 17 test installation and upstream defaults, not FreePBX source. Fail2Ban hooks reached through other chains, and Fail2Ban nftables tables, are not inspected.
- **IPv4 only.** Workstation connectivity and the firewall integration are IPv4-only; `ip6tables` is not modified.
- **Direct connectivity only.** No relay or NAT traversal; the PBX's WireGuard UDP port must be reachable through the router/NAT. The broker opens only the PBX host firewall.
- **No revocation push.** Windows detects revocation through lost reachability.
- **Remote Support.** Only On-PBX is implemented. Support-session reachability with FreePBX Firewall enabled is unknown, and no support firewall policy is changed. The temporary SSH service uses root with session-specific keys. No production Checker signer or Console is included.
- **Framework checks.** Menu metadata, permissions, page POST handling and
  templates have modelled regression checks; they do not execute genuine
  FreePBX navigation or browser rendering.

The project-wide security model and its complete list of known limitations are in `docs/SECURITY.md` in the TELIPHONES source repository.

### Current verification status

| Evidence | What it establishes |
|---|---|
| Earlier Windows 0.8.1 source evidence | Pairing dialogue state/access/response improvements and portable Release 9/9 plus 48 layout contracts passed at that time; not native validation of current Windows 0.8.3 |
| Current PHP/Node and gateway regressions | 0.6.6 baseline: 253 Python tests run, 252 passed, one unavailable-WireGuard skip; full module suite passed. Includes crash/persistence, restart, concurrent revocation, heartbeat rejection, slow/disconnected transport, GUI results, unrestricted GUI-only admission and bounded idle firewall-event handling; the real-nft namespace lab confirms own table replacement is not misread as tampering. FreePBX operations remain modelled, not live FreePBX |
| Later operator-reported eleven native SSH integrations and first-run startup smoke passing | Earlier native milestone, not matching 0.8.1 execution or complete live lifecycle assurance |
| Current 0.6.6 package | Module 0.6.6, broker 0.6.6 and protocol 12; exact source and checksum validation, including the feedback-loop correction, durable revocation and verified removal. Not a published release |
| Older packages | Superseded root-level 0.6.5 archive/checksum removed; historical packages lack the session-admission and CPU correction |
| Operator-reported successful Windows Actions builds and all ten native OpenSSH tests passing | Native build/integration milestone; no run URL, build hash or raw logs supplied with this documentation review |
| Operator-reported authenticated Windows 0.7.0 SSH into FreePBX 17 with module 0.4.0, and terminal closure on disconnect | Initial real interoperability and client-side process closure, not complete server-side revocation or expiry |
| Local module, broker, OpenSSH and packet tests | Automated contract/failure coverage; both iptables backends with simulated FreePBX rules; service supervision substituted for real systemd/cgroups |
| Module 0.4.1 firewall placement correction and 0.5.0 WireGuard listener/management-port corrections | Local regressions only (simulated FreePBX rules and namespace packet labs); real-PBX watchdog, rebuild and upgrade validation outstanding |

Historical ownership testing belongs in the [module changelog](docs/CHANGELOG.md).
The current acceptance programme still requires:

- representative older-module-to-0.6.6 upgrade, repeated root bootstrap and installed-helper
  verification while preserving an independent administration route;
- live confirmation that a paired workstation establishes new WireGuard
  handshakes from previously unknown public addresses with FreePBX Firewall
  enabled, before and after workstation public IP changes;
- at least five minutes of real watchdog observation, plus approved FreePBX
  Firewall reload/restart tests: no TELIPHONES-related invading-rule/reset loop,
  unchanged INPUT ordering and unrelated rules, one internal marked jump;
- repeated Windows connect/disconnect/reconnect, broker/PBX/Windows restarts,
  migration, interrupted operations and failed cleanup recovery;
- Fail2Ban enforcement during firewall-rule reordering;
- complete PBX-side revocation and temporary authorisation expiry, including
  active-session termination and empty owned cgroups, with unrelated SSH
  sessions preserved;
- denied certificate requests/accounts and services for unauthorised peers;
  no SIP/RTP/AMI/database/forwarding access over the workstation tunnel;
- ordinary SIP calls with bidirectional RTP and unrelated management traffic
  remaining unaffected during connection, rebuild, revocation and uninstall;
- the complete OpenSSH-backed terminal/browser/installer/display-scale matrix;
  PuTTY is a Remote Support test, not a managed My PBXs certificate test;
- Remote Support end-to-end testing with separately operated infrastructure.

The source repository's `docs/SECURITY.md` records the evidence boundary;
`docs/FREEPBX-FIREWALL-DIAGNOSTICS.md` gives the read-only collection and full
real-PBX acceptance checklist. No production-readiness claim follows from the
initial successful connection.

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
3. Pair a Windows workstation, then connect, open FreePBX, disconnect and reconnect it repeatedly. Check `iptables -S INPUT` ordering, the internal `fpbxfirewall` jump and the `teliphones-ws` counters.
4. Reload and restart FreePBX Firewall and restart Fail2Ban while connected. Confirm that access is restored and that bans remain effective.
5. With managed SSH approved, use **Open SSH** and an OpenSSH-backed terminal. Test wrong keys/accounts, expiry, revocation and active-session termination while an unrelated system SSH session remains alive. Without SSH approval, issuance and managed SSH must be refused. PuTTY is not supported for managed certificates.
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
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Complete FreePBX module history, separate from Windows |

Every link above is bundled with the module. The following project documents are maintained only in the TELIPHONES source repository and are not included in the Module Admin package:

| Source repository path | Contents |
|---|---|
| `README.md` | Project overview, workflows, quick start and development status |
| `docs/ARCHITECTURE.md` | Project-wide architecture |
| `docs/SECURITY.md` | Security model, assurance levels and known limitations |
| `docs/RENDEZVOUS.md` | Future rendezvous and relay design (not implemented) |
| `desktop/windows/README.md` | Windows installation and everyday usage |
| `desktop/windows/tests/WINDOWS-READINESS.md` | Detailed native build/CI reference, manual matrix and historical investigations |
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

TELIPHONES is a UK registered trademark.

TELIPHONES 0.6.6 for FreePBX is licensed under GPLv3.

The software grant is **GPL version 3 or, at your option, any later version
(GPL-3.0-or-later)**, expressed as `GPLv3+` in module metadata. The product
footer statement above is shorthand, not a narrower grant. Software licensing
does not grant trademark rights. See [LICENSE](LICENSE).

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

The complete [FreePBX module change history](docs/CHANGELOG.md) is bundled with the module. Version 0.6.6 corrects the nftables monitor feedback loop that blocked workstation session admission (Windows error 12002) and kept the broker busy, retaining 0.6.5's durable workstation revocation, verified removal, containment and retrievable operation outcomes and earlier pairing and listener reliability corrections. It requires root broker 0.6.6 with protocol 12. Windows remains independently versioned at 0.8.3 with no functionality changes. The local 0.6.6 archive and checksum include this source; no release or deployment is claimed.

The administration page groups System Readiness, Remote Support, Windows
Workstation Access, Paired Workstations and Security & Access Restrictions.
Technical dependency and firewall explanations are expandable; missing
requirements and security warnings remain visible. Diagnostics and Pair a
Workstation use native, keyboard-operable expandable panels. Pairing retains
one form with five visual groups, not a wizard. Invalid fields reveal their
containing panel; server-rejected pairing/enrolment forms reopen on reload.
Styles and panel events are scoped to TELIPHONES. Layout/control regressions
and JavaScript behaviour are tested locally, but no browser engine is
available here: desktop/narrow FreePBX rendering, keyboard interaction and a
live 0.6.6 upgrade must still be checked in FreePBX 17.

### Non-standard management ports

Use **Windows workstations > Management web services**, for example
`https:8443` or `http:8080, https:8443`. The first entry supplies the paired
Windows URL. Both firewall layers replace obsolete management-port permissions.
Re-pair saved Windows profiles after a URL change. Pairing suggests the current
direct server port if it is not already configured; reverse proxies need an
explicit backend-listener override. This does not reconfigure Apache: verify
that it listens on the wildcard or tunnel address, and validate HTTP, TLS and
redirects from an authorised peer. A listening socket alone is not proof.

The [historical root-cause report and read-only live-PBX verification procedure](docs/CONNECTIVITY-REGRESSION.md)
describe confirmed evidence, hypotheses and outstanding release gates.
Do not install an earlier review archive expecting these source changes.
The local 0.6.6 archive/checksum represent current module source. The obsolete
root-level 0.6.5 pair was removed; the unrelated website ZIP and checksum are
unchanged. Historical release references are not download availability claims.
Older packages lack the session-admission and CPU correction. Verify exact
archive/source equality before distribution.
No publication, live installation
or production readiness is claimed.

The root bootstrap also installs and retains `FirewallListener.php` alongside
the Python helpers; the root-only listener action uses that protected copy.
It journals service ownership before creation or port updates and checks the
generated IPv4 service/zone rules read-only before reporting convergence.
FreePBX still owns all public UDP rules. Transient errors disable tunnel access,
retain recovery information and retry on the broker's next reconciliation.
Shutdown/uninstall can wait up to 90 seconds for verified cleanup.
An interrupted removal never discards its ownership record before verification.
Upgrade rollback restores the installed helper files and service unit; matching
module/broker downgrade, asynchronous Firewall recovery and systemd behaviour
still require disposable-PBX tests. Do not downgrade one component alone.

Use an updated Windows 0.8.3 build from this source for custom management URLs
and Connection Health. Health probes the approved URL's TCP port, including
8080/8443; it does not validate HTTP contents, redirects or TLS certificates.
