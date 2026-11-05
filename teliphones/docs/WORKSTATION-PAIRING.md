# TELIPHONES 0.6.4 workstation pairing and connection policy

The current broker is protocol 12. It enforces a default maximum of one
simultaneous admitted workstation with atomic lease admission, authenticated
heartbeats, expiry and restart recovery. A WireGuard handshake only proves
tunnel authentication; it does not grant management access. The PBX firewall
admits management traffic only for an active session lease.

## Current Windows-to-FreePBX sequence

Source targets: Windows **0.8.1**, module **0.6.4**, broker **0.6.3**, protocol
**12**. These component versions are independent. The local 0.6.4 module
archive includes the web-only form correction and listener diagnostics; the
preserved 0.6.3 archive predates both. Neither the new package nor regression
tests prove live pairing. Repeat root bootstrap after Module Admin and follow
the [0.6.4 live acceptance checklist](../README.md#064-development-server-acceptance).

1. Enter the workstation name in Windows **Pair my PBX > Request access**.
2. Select **FreePBX Web Access** or **FreePBX Web + SSH Access**, before generation.
3. Choose **Generate request**, then **Copy request**.
4. Open **Connectivity > TELIPHONES > Pair a Workstation** over trusted HTTPS
   as a full FreePBX administrator.
5. Complete request, endpoint, UDP port, source policy and lifetime. Under
   **SSH approval**, explicitly authorise an existing account only when required
   and the request supports SSH; otherwise approve web-only.
6. Wait for final success and copy the response; progress is liveness, not success.
7. Paste under Windows **Complete pairing**.
8. Validate and **Save connection**. The approved SSH account is response-derived,
   read-only and hidden for web-only approval. Clicking Save revalidates.

   With **Web + SSH Access** selected, Save additionally requires explicit valid
   SSH approval and its response-derived account. A web-only approval cannot
   satisfy that selection; obtain SSH approval or generate a new Web Access
   request. The protocol parser still understands web-only replies independently
   of the dialogue's selected-access policy.

Web-only uses request v1 without an SSH identity; v2 adds an independent SSH
public key. Requested SSH is not approved SSH. Name/access changes invalidate
the pending request, response and unused identities and require regeneration,
retaining the name. Copy needs a generated current request; Save needs a valid
request-bound response. The envelope is not independently signed: provenance
relies on the trusted administrator HTTPS exchange, distinct from verified
SSH certificate signatures. No schema change was needed for the dialogue.

## Persistent connection state

The FreePBX workstation page can set the broker policy to **Open**, **Closed**
or **Frozen**. Open admits new pairings and allows approved peers to connect.
Closed removes the workstation interface and listener while retaining every
pairing and its original expiry. Frozen keeps existing pairings available but
rejects enrolment of new WireGuard identities. Changing state does not extend
temporary approvals. A new installation defaults to Closed; an older
installation with valid saved pairings migrates to Open to preserve access.

The broker persists a requested state before applying it, so startup reconciles
the chosen policy after interruption. A failed operation is reported rather
than presented as successful. The page labels paired workstations as having a
closed listener while Closed is selected; handshake history is not treated as
proof of current connectivity.

Locked pairings use a dedicated WireGuard interface, tunnel subnet and UDP
listener port. The peer key is removed from the shared listener roster before
the dedicated peer is admitted. The broker installs source-specific UDP
accepts followed by a drop for all other sources on that port; IPv4, IPv6,
CIDR and DNS names are supported. DNS failures contribute no allowed address,
and resolved addresses are cached briefly before reconciliation. The owned
nft policy also restricts traffic entering the dedicated interface to its PBX
web services. Open pairings continue to use the shared listener.

The FreePBX page reports configured and resolved sources, DNS failures,
verified public endpoints, session occupancy and pending requests. Administrators
can add, edit and remove IPv4/IPv6/CIDR/DNS sources, Lock and Unlock existing
workstations, and lock to a recently verified WireGuard public source.

Windows displays the effective policy and may request an Allowed List change
or Unlock over its authenticated session-control channel. These requests do
not change the effective policy until a FreePBX administrator explicitly
approves them. Windows can self-restrict with Lock to Current IP; that source
is derived from a recent PBX-verified handshake, not client-supplied input.
When listener configuration changes, the broker revokes the management lease,
keeps the previous tunnel path only for the session-control port, and delivers
an identity-bound migration over the authenticated tunnel. Windows preserves
its WireGuard identity, saves the new profile and reconnects. The old path is
retired only after acknowledgement on the new tunnel. A disconnected or
interrupted client cannot use its stale listener for management access; the
migration state is persisted across broker restarts.

An existing web-only Windows workstation can request SSH elevation after
pairing. FreePBX explicitly approves or rejects the request, and the approving
administrator selects an existing Linux account; there is no implicit root
selection. Managed SSH uses short-lived certificates. Rejection or revocation
does not revoke the workstation's web access.

Portable gateway and Windows-core regressions cover admission, migration,
policy requests and post-pair SSH. Native Windows compilation/UI integration
and live FreePBX/WireGuard/firewall acceptance remain outstanding; these local
results are not production certification.

## Protocol 10: manual TELIPHONES listener bans

The FreePBX page can add or remove manual IPv4/IPv6 address or CIDR bans with
a reason and optional expiry. The broker applies each ban to the shared and
dedicated TELIPHONES UDP listener ports in its owned nftables policy, before
source-specific listener accepts. It does not modify Fail2Ban or other
FreePBX firewall services. Expiry is reconciled by the broker without
restarting the WireGuard interfaces. A ban can block an administrator or
multiple workstations sharing a public address; check the source and recovery
route before applying it. This is not an automatic intrusion-prevention
system.

## Protocol 8: dedicated source-restricted listeners

Broker protocol **8** adds dedicated source-restricted listeners while
preserving protocol 7's persisted Open/Closed/Frozen policy and
server-side enforcement that SSH permission requires an SSH-capable pairing
request. Updated Windows builds expose a web-only or web-plus-SSH request
choice, show explicit SSH authorisation status, and use temporary inline
clipboard feedback instead of success dialogues. Module and Windows versions
are independent; the current development targets are FreePBX **0.6.4**,
root broker **0.6.3**, protocol **12** and Windows **0.8.1**.

When a pairing is Locked, an approved managed SSH listener and its short-lived
certificate API bind to the dedicated `tlpw...` interface and tunnel address.
FreePBX Firewall integration and the owned nft policy allow these SSH ports
only for that workstation identity; the shared listener does not receive its
peer key. Protocol 12 additionally supports post-pair SSH elevation and
authenticated Windows source-list and unlock requests with explicit FreePBX
approval.

Broker protocol **9** adds this dedicated-interface SSH binding. A protocol-8
broker can enforce the Locked web-only tunnel but cannot safely approve SSH
for it; the FreePBX page refuses that combination until the broker is upgraded.
Protocol 10 adds manual listener bans. Protocol 11 adds PBX-enforced
simultaneous-session admission; protocol 12 adds post-pair policy requests,
identity-preserving listener migration and SSH elevation.

## Version 2: managed My PBXs SSH

Broker protocol **5** adds managed SSH alongside the preserved version-1 contract
below. **Windows 0.7.0 implements a session-isolated memory agent.** The operator
reports successful Windows builds, ten native OpenSSH integration tests passing,
initial authenticated SSH into FreePBX 17 with module 0.4.0, and terminal closure
on disconnect. These reports do not establish complete PBX-side revocation,
expiry or cgroup cleanup, or real 0.4.1 firewall stability. No run identifiers or
raw logs were supplied here. The old plaintext session-key path remains removed.
GUI-only pairing is available without OpenSSH.
The preserved SSH-capable pairing contract uses `TELIPHONES-PAIR-REQUEST-2:` and schema
`teliphones-pair-request/2`: the existing four fields plus `ssh_public_key`, a
canonical Ed25519 OpenSSH public key. An HTTPS/CSRF-authenticated full
administrator must explicitly provide `ssh_user` when granting SSH.
GUI-only pairing defaults to the version-1 request without generating SSH keys or
requiring Windows OpenSSH. The Windows client refuses SSH approval for a web-only
request rather than falling back to legacy credentials. Existing SSH pairing
identities and authorisations are retained, not used as disposable session keys.

The matching `TELIPHONES-PAIR-RESPONSE-2:` carries schema
`teliphones-pair-response/2`, all version-1 response fields plus `ssh_user`,
`ssh_host_key`, `ssh_ca_key`, integer `ssh_port` and integer `ssh_api_port`.
Web-only responses use empty strings and zero ports. Managed ports are TCP 8765
for certificate issuance and `22000 + workstation IPv4 last octet` for SSH.
Both listeners bind the WireGuard address and device; firewall integration grants
only that workstation's required ports, never ordinary TCP 22 for new pairings.

`GET /ssh/challenge?workstation_id=<16hex>` returns schema
`teliphones-ssh-challenge/1`, workstation_id, a 64-hex challenge and Unix
expires_at (30 seconds). `POST /ssh/certificate` accepts exactly schema
`teliphones-ssh-request/2`, workstation_id, challenge, session_id, ssh_public_key
and SSHSIG signature. `session_id` is 32 lowercase hex characters; `ssh_public_key`
is a canonical Ed25519 **ephemeral session** public key distinct from the
persistent enrolled SSH identity. No private-key field is accepted.
The signed bytes are
`TELIPHONES-SSH-REQUEST-2\n<id>\n<challenge>\n<session_id>\n<ssh_public_key>\n`;
the OpenSSH signature namespace is `teliphones-ssh`. Challenges are bounded,
one-use and source/identity-bound. The enrolled SSH key must verify the signature.
WireGuard membership alone is never sufficient. Old request/1 issuance is
rejected. A bounded in-memory ledger rejects duplicate live session IDs or public
keys; it is not a durable uniqueness ledger across broker restarts.

Success has schema `teliphones-ssh-certificate/2`, workstation_id, session_id,
ssh_public_key, certificate, expires_at, ssh_user, ssh_host_key, ssh_ca_key and
ssh_port. Certificates bind the **session** public key, source `/32` and principal
`tlp-eph-<id>-<first16hex SHA256(canonical enrolled identity public-key string)>`,
with key ID `ws-<id>/<session_id>`, PTY permission only and validity capped at 300
seconds and the original pairing expiry. The portable client parser checks these
bindings structurally; the separate production OpenSSL verifier checks the
certificate's digital signature before launching Windows OpenSSH. The Windows
client signs once through its process-bound memory agent and immediately destroys
the session key; no reusable-key preflight is performed. Initial native
interoperability is operator-reported; genuine Linux OpenSSH also rejects
tampered signatures in local namespace tests.
Errors are explicit JSON `{ok:false,error:string}`.

Recognised legacy principal files migrate only after new configuration validation
and verified owned-unit termination. The changed principal rejects previously
issued persistent-identity certificates without destroying CA, host or workstation
identity. Unknown trust files fail closed. Actual systemd migration remains a
disposable-host validation gate.

Each listener has a separately owned systemd/cgroup service. Revocation and
expiry kill only that service's sessions and verify cleanup before dropping
recovery metadata. A certificate's expiry prevents new logins; established
sessions are bounded by the pairing's administrator-approved lifetime.
Unsupported existing account/root/multi-factor/forced-command policies fail
closed. System SSH configuration and unrelated sessions are untouched.
The system policy must be identical when evaluated at port 22 and the actual
managed port for the approved user, source and PBX address; context-dependent
differences fail closed. Generated configuration is checked with `sshd -T` at
the actual managed port before installation. Owned CA/principal trust replaces
ordinary authorised keys, while supported root/PAM/algorithm/revoked-key policy
is retained. Custom PAM service names and external principal restrictions are
unsupported. Actual PAM/account and service lifecycle behaviour is a test-host
release gate, not established by these checks.

Version-1 pairings retain their original network permissions. New Windows
requires explicit SSH-capable pairing before adding managed SSH; host/CA rotation
also requires re-pairing.
PuTTY is unsupported for managed My PBXs certificates. Remote Support is
independent and unchanged. Missing SSH prerequisites do not block web-only PBX
pairing. The complete terminal/reboot matrix and real systemd/FreePBX lifecycle
validation remain outstanding; namespace tests substitute the service supervisor. Linux tmpfs test
keys are not evidence of memory-backed Windows credentials or native lifecycle
destruction. The full key inventory and outstanding gates are in
`docs/SSH-KEY-MANAGEMENT-PROPOSAL.md` at the source repository root; that document
is not included in the module-only package.

## Preserved version-1 contract

This section records the original v1 contract and historical lifecycle;
current source additionally requires module 0.6.4 / broker 0.6.3 / protocol 12,
management leases, dedicated Locked interfaces and identity-preserving updates.
The older protocol minima and full-interface rebuild description below are not
the current broker compatibility/admission policy.

Workstation pairing is for an administrator's own Windows workstation. It is separate from the customer-authorised Remote Support session workflow. The FreePBX module and root broker remain authoritative for peer enrolment, allowed traffic, expiry and revocation.

The module requires broker status protocol 3 and a well-formed `workstations` block with boolean readiness/tool requirements and an items array. A protocol number alone is not sufficient. Workstation diagnostics require broker protocol 4. The packaged 0.1.3 broker used protocol 2; rerun the documented root bootstrap after Module Admin upgrade. Pairing and revocation are refused before dispatch when capability status is missing or malformed; missing tools or module disablement block new pairing, not revocation.

## User flow

1. The Windows application generates a WireGuard key pair locally and a random 128-bit nonce. It displays the public key fingerprint and a `TELIPHONES-PAIR-REQUEST-1:` request. The private key stays in Windows Credential Manager.
2. A full FreePBX administrator opens **Connectivity > TELIPHONES > Windows workstations** over HTTPS, submits the request, specifies the public WireGuard endpoint host and UDP port, chooses temporary or persistent access, and explicitly enables or denies SSH.
3. The PBX validates the request and its current dependencies, then returns a `TELIPHONES-PAIR-RESPONSE-1:` value. The administrator copies it to the workstation application.
4. The application validates the exact response schema, nonce, workstation public key, PBX address/key, endpoint, access mode, expiry and GUI address before saving the profile.
5. The workstation configures only the PBX host route. The PBX-side broker installs the peer, its workstation-specific interface and firewall policy.

## Request and response binding

The request carries schema `teliphones-pair-request/1`, workstation name, WireGuard public key and nonce. It carries no private key, credential or session secret.

The response schema is `teliphones-pair-response/1`. It must echo the request nonce and workstation public key. The client rejects unknown or missing fields, invalid key/address/endpoint values, addresses outside the broker's `100.64.0.0/10` workstation allocation, a PBX address that is not `.1` in the same `/24`, a mismatched GUI URL, and an invalid expiry. Temporary responses carry a positive absolute expiry; persistent responses carry `null`.

The response is a copyable enrolment artefact, not proof that arbitrary access is safe. Treat it as sensitive operational data; do not post it publicly. It contains public keys and network metadata, never a private key.

## Access and revocation

- Workstation web access is limited to the paired PBX's approved management ports (default TCP 80/443).
- New managed SSH access uses the workstation-specific SSH listener and certificate API; it does not grant ordinary system SSH TCP 22.
- The workstation interface is not forwarded to other networks.
- Temporary pairing expires at its PBX-side deadline. Persistent pairing remains until revoked.
- The broker's approximately 15-second reconciliation loop also removes workstation network access while TELIPHONES is disabled, and startup cannot restore access while disabled. Pairing metadata is retained; after re-enabling, a broker restart or fresh approved pairing reapplies valid entries without extending expiry.
- An administrator can revoke one workstation or all workstations in the FreePBX TELIPHONES page. Removing a local Windows profile only deletes the local key; it does not revoke the PBX peer.
- Every update first disables `tlp-admin` and verifies that it is down or absent, before changing rules or peers. Cleanup additionally verifies interface deletion before removing the owned table. Failed disable/deletion preserves the remaining rules, key and pairing metadata, and is reported as an error, never successful revocation. **Revoke all workstations** remains available for retry. A failed revocation is incomplete; retained entries may be restored after a broker restart.
- Windows disconnection after revocation is detected through tunnel service and PBX reachability monitoring. There is no server-pushed Windows revocation channel in this version, so instantaneous client-side disconnect is not guaranteed. The PBX-side broker/firewall remains authoritative for access.
- The GUI displays the last WireGuard handshake from a fixed read-only `wg show tlp-admin latest-handshakes` query, without peer keys. Zero means no handshake; an unavailable query is explicitly unverified. A past handshake is not proof of current GUI/SSH reachability. Workstation status is a page-load snapshot, separate from remote support operation polling.
- Each pairing has a non-secret diagnostic ID `ws-` plus its existing 16-hex workstation ID. It is pairing-lifetime, not a connection-attempt ID. The administrator-only **Workstation diagnostics** panel accepts this ID, filters the PBX log to that pairing, and exports a bounded JSON record. Events are UTC-stamped PBX observations of pairing decisions, server-side peer/interface/firewall state, and compact handshake/traffic snapshots; idle peers are not called disconnected, and no Windows-side failures are fabricated. The workstation side records its own local attempts separately.
- Diagnostic records are kept in a root-owned private directory under `/var/lib/teliphones`, rotated at 1 MiB per file with three files total and seven-day retention. The broker exposes only whitelisted event fields through the FreePBX authenticated, CSRF-checked AJAX handler. No keys, pairing tokens, or request payloads are exported.

## Upgrading from 0.2.0

This also applies when upgrading from 0.2.1. Install the current module and rerun the root bootstrap before relying on the separately installed broker.

Install the current test package `TELIPHONES-0.6.4.tgz` through Module Admin, then rerun the documented root bootstrap with no active support session and Windows tunnels disconnected. Installation does not delete `workstations.json`, `workstation-recovery.json` or `workstation-wg.key`. Valid pairings keep their identities, keys and original deadlines; a required listener migration is authenticated and coordinated rather than requiring re-pairing.

Module Admin does not necessarily replace the root-owned broker. Module 0.6.4
requires broker 0.6.3 even if an earlier helper reports protocol 12. The bootstrap
copies the packaged helpers and restarts the service; confirm the component
version and compare installed files as described in
[Updating TELIPHONES](../README.md#updating-teliphones).

Pairing remains synchronous and single-dispatch. Its authenticated Unix-socket
request opts into non-secret progress frames while firewall/listener verification
finishes, retaining PHP's five-second inactivity deadline. Progress cannot grant
access or supply a pairing response; only the final verified result can do so.
An interrupted or malformed reply leaves the outcome unconfirmed: refresh the
workstation list before retrying rather than automatically repeating a mutation.
Safe stage/error diagnostics distinguish transport problems from operation
failures and retain command timeout causes through verified cleanup. Real
PHP/socket tests use modelled network commands, not live FreePBX pairing; the
installed upgrade, listener convergence and web-server/proxy deadlines remain
live-PBX validation gates.

The bootstrap copies the current broker into its protected root-owned installation and restarts it. Protocol 3 was already used in 0.2.0: an operational socket or protocol number alone does **not** prove these security corrections are installed. Rerunning the bootstrap is mandatory even if no update warning appears.

An unmarked legacy table is migrated only when its complete nft JSON exactly matches the known 0.3.0 policy reconstructed against the root-owned saved subnet and SSH source rules, its optional old table comment is absent or exactly expected, and `tlp-admin` has been verified down. The broker then replaces the inspected table atomically with the current policy and hookless owner chain. It does not infer ownership from a name or add a marker to an unknown policy. Unknown or altered tables remain untouched, saved pairings and the PBX key are retained, and access stays disabled for administrator investigation. Do not flush rules, remove unrelated tables or clear pairing data. Expired temporary pairings are not revived.

## Upgrading from 0.3.0

The 0.3.1 broker adds the hookless `teliphones_owner_v1` chain because Debian 12 nftables 1.0.6 drops table comments from kernel JSON readback. The operator reports that this ownership correction was tested successfully on the actual FreePBX 17 test PBX. The repository code still needs to be installed and verified on that PBX through the normal upgrade/bootstrap procedure; this document does not claim that deployment has occurred.

Install the current test package `TELIPHONES-0.6.4.tgz`, confirm there is no active support session, disconnect Windows tunnels, then rerun [Complete Installation on FreePBX 17](../README.md#complete-installation-on-freepbx-17) from an existing root shell. The 0.3.1 ownership correction originally kept protocol 3; protocol 12 alone likewise does not prove the installed helper's version or contents. On restart, the broker verifies the tunnel is down, safely migrates only the exact known 0.3.0 policy, restores current policy from saved state and readmits valid, unexpired pairings. Pairing identities, addresses, SSH permissions, deadlines and the PBX WireGuard key are preserved. If exact ownership cannot be established, migration is refused and recovery data remains intact.

## Upgrading from 0.3.1

The historical 0.3.2 change added bounded diagnostics and protocol 4 without
changing firewall permissions or pairing protocol. For a current upgrade,
use the reviewed 0.6.4 test package, disconnect workstation tunnels, confirm no active support session,
and rerun the root bootstrap. Preserve pairing state and the WireGuard key.
Managed SSH originally required protocol 5; current module 0.6.4 requires broker
0.6.3/protocol 12 and all three protected helpers even if an older broker reports
protocol 12. Protocol 4 identifies historical diagnostics support only.
Follow [current upgrade verification](../README.md#updating-teliphones).

## Network requirements

Unlocked workstations connect through the shared PBX WireGuard UDP endpoint.
Each Locked workstation uses a broker-managed dedicated UDP listener and a
source allowlist enforced at that listener. The broker reconciles the shared
and dedicated ports as FreePBX Custom Services; FreePBX owns generated zone
rules and applies updates asynchronously. The selected UDP ports must also be
reachable through any router/NAT. TELIPHONES does not configure routers,
provide a relay or universal NAT traversal, or change Reject zones, blacklists
or Fail2Ban.

The `nft` CLI is essential; enabling or running `nftables.service` is **not** required. Missing tools require platform-administrator repair. Apart from the owned Custom Service, its marked tunnel jump inside `fpbxfirewall`, and removal of the exact legacy INPUT jump, TELIPHONES does not change unrelated firewall services, tables or policies.

Management web services are configurable as `scheme:port` entries, for example
`https:8443`. Both enforcement layers replace obsolete permissions, and updated
Windows builds preserve the approved scheme and port. Re-pair saved profiles
after a URL change. Apache must actually listen on the tunnel/wildcard address;
firewall permission is not proof of HTTP/TLS reachability. See the
[investigation, ownership model and live verification procedure](CONNECTIVITY-REGRESSION.md).

## Enforcement integrity and exposure limits

The current managed table is `inet teliphones_workstations` and contains the exact hookless, ruleless chain `teliphones_owner_v1`. This kernel-visible object is the ownership marker; unlike table comments, it survives nftables 1.0.6 JSON readback. Table comments are not relied upon. An unfamiliar owner chain or unmarked namesake is **never** overwritten or deleted. The only exception is a one-time migration when the entire table exactly matches the known 0.3.0 policy, its optional table comment is absent or exact, the subnet and SSH sources reconcile to root-owned saved state, and the interface is verified down. All other unmarked tables require administrator investigation.

Expected JSON is generated offline from the approved PBX address and SSH sources. The broker compares the actual `nft -j list table` output with the complete expected table, both base chains (type, hooks, priority and policy), ordered rules and every expression. Only kernel handles, envelope metadata and chain enumeration order are ignored. Extra rules/objects or changed destinations, interfaces, protocols, ports, verdicts or ownership fail validation. The same JSON is submitted atomically, read back and checked before peer admission. Exclusive table creation refuses a newly appearing namesake; deletion uses the inspected table handle so a replacement table is not deleted by name.

A local `nft -j monitor ruleset` stream observes external mutations, including a flush followed by restoration between periodic checks. Registration is proven by acknowledging the broker's own complete initial transaction before admission, not merely by starting a process. Expected event signatures use nft's canonical output: for example, `udp dport` is emitted without an explicit `meta l4proto udp` match because nft treats the protocol match as an implicit dependency. A mismatch cannot be acknowledged and must not be hidden by weakening verification.

If a transaction is not acknowledged, the broker reads back the owned kernel table before releasing its pending event signatures. A successful readback records whether the table is absent, matches the requested policy or differs from it; a failed readback keeps the pending state latched and workstation access disabled. Pairing is admitted only after a fully observed transaction and a complete policy readback. Cleanup verifies that the interface and table are removed. A recoverable failure can then be retried by the regular reconciliation worker or a subsequent pairing attempt; it never clears recovery state or pending events based only on a command exit status. Monitor errors and pairing refusals distinguish missing system tools from actual broker/readiness errors and include a bounded, address-free summary of outstanding event types.

Expected own-event signatures are consumed without launching repair loops; unrelated-table events are ignored. External events wake the serialized enforcement worker; it disables the interface and revalidates/reapplies the policy. Approximately 15-second periodic validation is a fallback for both persistent and temporary pairings, including idle persistent peers. Stream death, malformed output or an enforcement-worker failure reports an error and attempts verified interface disablement; admission then requires broker repair/restart. Saved temporary deadlines are never extended.

**This is detection and recovery, not atomic protection against another privileged firewall manager.** External flushes/removals can expose an already-up interface until the local event is delivered and processed (or the periodic fallback runs). A transient removal can pass traffic even if rules are restored before detection. There is also a verification/admission race with concurrent external changes, and no detection-latency guarantee under load, process suspension or resource failure. Failed interface shutdown may leave access active and needs immediate operator intervention. Do not describe this as truly fail-closed or zero-exposure protection against external flushes.

## FreePBX Firewall integration

An accept verdict in TELIPHONES' nftables table is final only for that base chain. A later independent hook can still drop the packet. On a real Debian 12 / FreePBX 17 PBX with FreePBX Firewall enabled, WireGuard handshakes succeeded and TCP SYNs reached `tlp-admin`. FreePBX Firewall classified the interface as `zone-external`, and its final DROP counters increased. TELIPHONES' nft policy was not sufficient to admit traffic.

The broker uses the existing FreePBX Firewall chain rather than trusting an
interface zone or adding workstation subnets to trusted networks. A single
marked jump is placed inside `fpbxfirewall`; the jump itself is not interface
filtered so it can serve both the shared and dedicated listeners. Every
TELIPHONES ACCEPT rule inside the owned chain is instead scoped to the exact
WireGuard interface, authenticated peer tunnel address, PBX tunnel address,
protocol and port. The chain returns for all other traffic.

The old integration inserted its jump above `fpbxfirewall` in INPUT. During Windows 0.7.0 / module 0.4.0 testing, the PBX journal identified that exact rule as invading and repeatedly reset iptables, approximately every 41 seconds. Broker reconciliation restored the very rule that FreePBX rejected, creating competing management loops.

The corrected root broker maintains a dedicated chain, `teliphones-ws`, in the iptables filter table selected by `/usr/sbin/iptables`. That command's backend is reported as `nf_tables` or `legacy` in the GUI. One marked jump is placed **inside `fpbxfirewall`, at position 1**, not above its INPUT hook:

```
-A fpbxfirewall -m comment --comment "TELIPHONES workstation integration v1" -j teliphones-ws
```

INPUT is left in FreePBX's order. Every direct INPUT Fail2Ban hook must precede entry to `fpbxfirewall`. Fail2Ban hooks are recognised by the case-insensitive prefixes `fail2ban-` and `f2b-`. The FreePBX 17 test installation uses `fail2ban-sshd`, `fail2ban-SIP`, `fail2ban-BadBots`, `fail2ban-api`, `fail2ban-SSH`, `fail2ban-apache-auth`, `fail2ban-recidive` and `fail2ban-PBX-GUI`; upstream Fail2Ban uses `f2b-<jail>`. Banned addresses therefore remain effective for shared and dedicated peers. Each rule in the owned chain carries the same marker:

```
-A teliphones-ws -s <workstation>/32 -d <PBX tunnel address>/32 -i <exact WG interface> -p tcp -m tcp --dport 80  ... -j ACCEPT
-A teliphones-ws -s <workstation>/32 -d <PBX tunnel address>/32 -i <exact WG interface> -p tcp -m tcp --dport 443 ... -j ACCEPT
-A teliphones-ws -s <SSH-approved workstation>/32 ... --dport 22 ... -j ACCEPT
-A teliphones-ws ... -j RETURN
```

Only active, unexpired paired addresses are listed. Shared peers use `tlp-admin`; Locked peers use their dedicated `tlpw...` interface and PBX tunnel address. Legacy SSH-approved pairings retain TCP 22; managed certificate SSH pairings instead receive TCP 8765 and their own dedicated SSH port, never system TCP 22. Certificate authentication, account approval, device binding and certificate lifetimes are unchanged. The owned chain returns for traffic not matching an exact ACCEPT rule, including SIP/RTP, AMI, databases, other ports and other sources; FreePBX Firewall then applies its normal policy. The owned nft table independently blocks unapproved tunnel traffic. IPv6 tunnel traffic is not integrated, and `ip6tables` is not modified.

Lifecycle and safeguards:

- The complete nft policy is verified before the integration is installed. Integration is installed before `tlp-admin` is brought up.
- Updates are idempotent. The owned chain is rebuilt only if its parsed rules differ. The jump is moved only if it is missing, duplicated or not first inside `fpbxfirewall`. Every change is read back and verified. A flushed chain or missing jump falls back to FreePBX's policy. Stable checks perform no firewall writes.
- Migration first deletes every exact marked legacy INPUT jump, including duplicates. It never inserts an INPUT rule. Cleanup understands both old and new locations, including after a broker restart or interrupted migration.
- Revocation, expiry, disablement, broker shutdown and uninstall remove the jump and chain after the interface is disabled or removed. An iptables cleanup failure is reported and keeps recovery state, but it does not skip owned nft cleanup.
- FreePBX Firewall reloads are repaired without bringing peers down. With the `nf_tables` backend, the existing nft monitor wakes the broker on `ip filter` changes. With `legacy`, repair relies on the approximately 15-second periodic check. Until repair, tunnel traffic is dropped by FreePBX Firewall; the exposure is not widened.
- Any rule in `teliphones-ws` without the marker, an unrecognised match, or a reference other than the exact marked jump from INPUT (legacy cleanup only) or `fpbxfirewall` is treated as unfamiliar. It is never modified or deleted, and workstation access is not admitted.
- No INPUT jump to `fpbxfirewall` results in status `not-detected`, and no integration rules are installed. If any Fail2Ban jump follows the FreePBX hook, the internal exception would precede that ban. TELIPHONES then removes its integration and reports status `error`, naming the offending Fail2Ban chains. Tunnel traffic is left to FreePBX Firewall, and Fail2Ban is never intentionally bypassed. The integration is restored automatically when the ordering is corrected, for example when Fail2Ban restarts and re-inserts its hooks at INPUT position 1.
- A rebuild can flush `fpbxfirewall` and remove its owned jump. Reconciliation restores only that jump and, if needed, its own chain. It does not repair or reorder FreePBX's INPUT rules. Every placement is read back. If a hook changes concurrently and the result is invalid, the integration is withdrawn and reported as an error.
- If installation or verification fails, TELIPHONES removes its rules and reports `error`. Peers stay nft-protected, but FreePBX Firewall may drop their HTTP/HTTPS. If removal cannot be verified, workstation access is disabled and recovery state is retained.

The only edit inside a FreePBX chain is insertion/deletion of TELIPHONES' exact marked jump. No unrelated rule is flushed, replaced, deleted or reordered. Only the marker-validated `teliphones-ws` chain may be flushed/deleted. Zones, interface assignments, trusted networks, settings, policies and services are unchanged. Custom Rules need not be enabled. TELIPHONES never flushes, restarts, disables or reconfigures FreePBX Firewall.

Diagnostics: **Windows workstations** shows integration status as active, not installed, failed or unreported. An unreported status means the running broker predates this integration and the root bootstrap must be rerun. When a workstation has a recent handshake but integration is not active, its row warns that FreePBX Firewall may drop HTTP/HTTPS. Read-only root checks are:

```
iptables -S INPUT
iptables -S fpbxfirewall
iptables -S teliphones-ws
iptables -L teliphones-ws -v -n -x
```

Increasing counters on the ACCEPT rules show that integration is matching tunnel traffic.

Limitations: the hook name `fpbxfirewall` and the `fail2ban-*` chain names come from the reported FreePBX 17 installation. `f2b-*` follows the upstream Fail2Ban default. None was verified against FreePBX Firewall or Fail2Ban source. Fail2Ban hooks reached only through other chains, rather than directly from INPUT, and Fail2Ban using its own nftables tables are not inspected. A separate nftables Fail2Ban table still applies independently because an iptables accept does not override it. A Fail2Ban hook externally moved after `fpbxfirewall` can be bypassed by approved traffic until reconciliation withdraws integration. Hooks reinserted above `fpbxfirewall` cannot be bypassed by this jump. Monitor events wake reconciliation on `nf_tables`; `legacy` uses the approximately 15-second periodic fallback. Neither has a guaranteed repair deadline. FreePBX source is absent locally and no external searches were used. Tests model the reported above-hook watchdog condition; they do not prove every FreePBX self-check. Real watchdog stability, actual rebuilds, systemd lifecycle and Windows 0.7.0 certificate SSH still require PBX validation; see the source repository's `docs/FREEPBX-FIREWALL-DIAGNOSTICS.md`.

## Verified uninstall and recovery

Uninstall requires root, stops the broker service and independently verifies inactive/failed state with zero main/control PIDs. It then invokes only the installed, root-owned, non-symlink broker below trusted non-writable ancestors, with isolated Python (`-I`) and a bounded timeout. Older helpers without the verified teardown entry point are refused before execution; web-owned module Python is never executed as root.

The helper shares the broker's verified teardown implementation. It removes the link before the owned rules and deletes the workstation key/state only after both absences are confirmed. A missing tool, unfamiliar table, query/disable/delete failure or helper timeout aborts uninstall and retains recovery information and the installed helper. Failed new pairing cleanup also retains its attempted public pairing metadata in root-private `workstation-recovery.json` alongside the previous saved state. Do not delete these files to hide an error; repair tools/ownership or the root broker, inspect the interface and retry. Support/gateway cleanup failures also abort artefact removal. A non-root Module Admin uninstall is refused rather than silently deleting metadata around live access.

For protocol and implementation details, see `teliphones/support_broker.py`, `teliphones/WebSupport.php`, `desktop/windows/src/core/Pairing.cpp`, and `desktop/windows/README.md`.
