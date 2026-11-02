# TELIPHONES 0.3.0 workstation pairing contract

Workstation pairing is for an administrator's own Windows workstation. It is separate from the customer-authorised Remote Support session workflow. The FreePBX module and root broker remain authoritative for peer enrollment, allowed traffic, expiry and revocation.

The module requires broker status protocol 3 and a well-formed `workstations` block with boolean readiness/tool requirements and an items array. A protocol number alone is not sufficient. The packaged 0.1.3 broker used protocol 2; rerun the documented root bootstrap after Module Admin upgrade. Pairing and revocation are refused before dispatch when capability status is missing or malformed; missing tools or module disablement block new pairing, not revocation.

## User flow

1. The Windows application generates a WireGuard key pair locally and a random 128-bit nonce. It displays the public key fingerprint and a `TELIPHONES-PAIR-REQUEST-1:` request. The private key stays in Windows Credential Manager.
2. A full FreePBX administrator opens **Connectivity > TELIPHONES > Windows workstations** over HTTPS, submits the request, specifies the public WireGuard endpoint host and UDP port, chooses temporary or persistent access, and explicitly enables or denies SSH.
3. The PBX validates the request and its current dependencies, then returns a `TELIPHONES-PAIR-RESPONSE-1:` value. The administrator copies it to the workstation application.
4. The application validates the exact response schema, nonce, workstation public key, PBX address/key, endpoint, access mode, expiry and GUI address before saving the profile.
5. The workstation configures only the PBX host route. The PBX-side broker installs the peer, its workstation-specific interface and firewall policy.

## Request and response binding

The request carries schema `teliphones-pair-request/1`, workstation name, WireGuard public key and nonce. It carries no private key, credential or session secret.

The response schema is `teliphones-pair-response/1`. It must echo the request nonce and workstation public key. The client rejects unknown or missing fields, invalid key/address/endpoint values, addresses outside the broker's `100.64.0.0/10` workstation allocation, a PBX address that is not `.1` in the same `/24`, a mismatched GUI URL, and an invalid expiry. Temporary responses carry a positive absolute expiry; persistent responses carry `null`.

The response is a copyable enrollment artifact, not proof that arbitrary access is safe. Treat it as sensitive operational data; do not post it publicly. It contains public keys and network metadata, never a private key.

## Access and revocation

- Workstation web access is limited to the paired PBX's TCP ports 80 and 443.
- SSH TCP 22 is included only when the administrator explicitly selects it.
- The workstation interface is not forwarded to other networks.
- Temporary pairing expires at its PBX-side deadline. Persistent pairing remains until revoked.
- The broker's approximately 15-second reconciliation loop also removes workstation network access while TELIPHONES is disabled, and startup cannot restore access while disabled. Pairing metadata is retained; after re-enabling, a broker restart or fresh approved pairing reapplies valid entries without extending expiry.
- An administrator can revoke one workstation or all workstations in the FreePBX TELIPHONES page. Removing a local Windows profile only deletes the local key; it does not revoke the PBX peer.
- Every update first disables `tlp-admin` and verifies that it is down or absent, before changing rules or peers. Cleanup additionally verifies interface deletion before removing the owned table. Failed disable/deletion preserves the remaining rules, key and pairing metadata, and is reported as an error, never successful revocation. **Revoke all workstations** remains available for retry. A failed revocation is incomplete; retained entries may be restored after a broker restart.
- Windows disconnection after revocation is detected through tunnel service and PBX reachability monitoring. There is no server-pushed Windows revocation channel in this version, so instantaneous client-side disconnect is not guaranteed. The PBX-side broker/firewall remains authoritative for access.
- The GUI displays the last WireGuard handshake from a fixed read-only `wg show tlp-admin latest-handshakes` query, without peer keys. Zero means no handshake; an unavailable query is explicitly unverified. A past handshake is not proof of current GUI/SSH reachability. Workstation status is a page-load snapshot, separate from remote support operation polling.

## Upgrading from 0.2.0

This also applies when upgrading from 0.2.1. Until the bootstrap installs the 0.3.0 broker, **Windows workstations** warns that the running broker does not report FreePBX Firewall integration, and FreePBX Firewall may drop workstation HTTP/HTTPS.

Install `TELIPHONES-0.3.0.tgz` through Module Admin, then rerun the documented root bootstrap with no active support session and Windows tunnels disconnected. Installation does not delete `workstations.json`, `workstation-recovery.json` or `workstation-wg.key`. Valid pairings keep their identities, addresses, permissions and original deadlines.

The bootstrap copies the current broker into its protected root-owned installation and restarts it. Protocol 3 was already used in 0.2.0: an operational socket or protocol number alone does **not** prove these security corrections are installed. Rerunning the bootstrap is mandatory even if no update warning appears.

An unmarked 0.2.0 table is treated as unfamiliar: startup disables `tlp-admin`, retains the saved pairing/key data, reports the ownership conflict and does not change or delete that table. There is deliberately no automatic adoption or marker injection. A root administrator must investigate ownership with the interface stopped and, only if positively identified as the old TELIPHONES table, explicitly remove that isolated legacy table before restarting the updated broker. Do not flush the ruleset, remove unrelated tables, clear pairing data or add a marker to an unknown table. If ownership cannot be established, leave workstation access disabled. Restoration of valid pairings requires verified new restrictions; expired temporary entries are not revived.

## Network requirements

The workstation connects directly to the configured PBX WireGuard UDP endpoint. The PBX's chosen UDP port must be reachable through the PBX host firewall, FreePBX Firewall, and any router/NAT. The module does not configure port forwarding or change unrelated network services. No relay or universal NAT traversal is provided.

The `nft` CLI is essential; enabling or running `nftables.service` is **not** required. The broker programs the kernel directly. Missing userspace tools require platform-administrator repair; the GUI has no nftables installer. Apart from the single marked INPUT jump to its own `teliphones-ws` iptables chain (see [FreePBX Firewall integration](#freepbx-firewall-integration)), TELIPHONES never changes foreign tables or chains, their default policies, or firewall services.

## Enforcement integrity and exposure limits

The only managed table is `inet teliphones_workstations`, bearing the exact table comment `TELIPHONES workstation enforcement v1`. An unfamiliar or unmarked namesake is **never** overwritten or deleted, including during uninstall. The interface is disabled and the conflict is reported. Older unmarked TELIPHONES tables require explicit operator investigation with the interface stopped; the broker does not infer ownership from a name, and adding its marker to an unknown table is not a safe migration.

Expected JSON is generated offline from the approved PBX address and SSH sources. The broker compares the actual `nft -j list table` output with the complete expected table, both base chains (type, hooks, priority and policy), ordered rules and every expression. Only kernel handles, envelope metadata and chain enumeration order are ignored. Extra rules/objects or changed destinations, interfaces, protocols, ports, verdicts or ownership fail validation. The same JSON is submitted atomically, read back and checked before peer admission. Exclusive table creation refuses a newly appearing namesake; deletion uses the inspected table handle so a replacement table is not deleted by name.

A local `nft -j monitor ruleset` stream observes external mutations, including a flush followed by restoration between periodic checks. Registration is proven by acknowledging the broker's own complete initial transaction before admission, not merely by starting a process. Expected own-event signatures are consumed without launching repair loops; unrelated-table events are ignored. External events wake the serialized enforcement worker; it disables the interface and revalidates/reapplies the policy. Approximately 15-second periodic validation is a fallback for both persistent and temporary pairings, including idle persistent peers. Stream death, malformed output or an enforcement-worker failure reports an error and attempts verified interface disablement; admission then requires broker repair/restart. Saved temporary deadlines are never extended.

**This is detection and recovery, not atomic protection against another privileged firewall manager.** External flushes/removals can expose an already-up interface until the local event is delivered and processed (or the periodic fallback runs). A transient removal can pass traffic even if rules are restored before detection. There is also a verification/admission race with concurrent external changes, and no detection-latency guarantee under load, process suspension or resource failure. Failed interface shutdown may leave access active and needs immediate operator intervention. Do not describe this as truly fail-closed or zero-exposure protection against external flushes.

## FreePBX Firewall integration

An accept verdict in TELIPHONES' nftables table is final only for that base chain. A later independent hook can still drop the packet. On a real Debian 12 / FreePBX 17 PBX with FreePBX Firewall enabled, WireGuard handshakes succeeded and TCP SYNs reached `tlp-admin`. FreePBX Firewall classified the interface as `zone-external`, and its final DROP counters increased. TELIPHONES' nft policy was not sufficient to admit traffic.

No supported mechanism for narrowly authorising traffic from an independently managed interface was available for inspection in the development workspace. FreePBX Firewall source and documentation were not present locally, and no external search was performed. Trusting `tlp-admin` as an interface zone or adding the workstation subnet to trusted networks would admit every service, so neither approach is used.

The root broker instead maintains a dedicated chain, `teliphones-ws`, in the iptables filter table selected by `/usr/sbin/iptables`. That command's backend is reported as `nf_tables` or `legacy` in the GUI. One INPUT jump is used:

```
-A INPUT -i tlp-admin -m comment --comment "TELIPHONES workstation integration v1" -j teliphones-ws
```

The jump must be the rule immediately before the first INPUT jump to `fpbxfirewall` and must follow every INPUT jump to a Fail2Ban chain. Fail2Ban hooks are recognised by the case-insensitive prefixes `fail2ban-` and `f2b-`. The FreePBX 17 test installation uses `fail2ban-sshd`, `fail2ban-SIP`, `fail2ban-BadBots`, `fail2ban-api`, `fail2ban-SSH`, `fail2ban-apache-auth`, `fail2ban-recidive` and `fail2ban-PBX-GUI`; upstream Fail2Ban uses `f2b-<jail>`. Banned addresses therefore remain banned for tunnel traffic. Each rule in the chain carries the same marker:

```
-A teliphones-ws -s <workstation>/32 -d <PBX tunnel address>/32 -i tlp-admin -p tcp -m tcp --dport 80  ... -j ACCEPT
-A teliphones-ws -s <workstation>/32 -d <PBX tunnel address>/32 -i tlp-admin -p tcp -m tcp --dport 443 ... -j ACCEPT
-A teliphones-ws -s <SSH-approved workstation>/32 ... --dport 22 ... -j ACCEPT
-A teliphones-ws ... -j RETURN
```

Only active, unexpired paired addresses are listed. TCP 22 is listed only for workstations explicitly approved for SSH. Every other packet, including SIP, AMI, database and other ports, other sources, IPv6 and ICMP, returns to normal FreePBX Firewall processing. The owned nft table still applies its own drops. IPv6 is not integrated, and `ip6tables` is not modified.

Lifecycle and safeguards:

- The complete nft policy is verified before the integration is installed. Integration is installed before `tlp-admin` is brought up.
- Updates are idempotent. The chain is rebuilt only if its parsed rules differ. The jump is moved only if it is missing, duplicated or incorrectly ordered. Every change is read back and verified. A flushed chain or missing jump is never more permissive than FreePBX's own policy.
- Revocation, expiry, disablement, broker shutdown and uninstall remove the jump and chain after the interface is disabled or removed. An iptables cleanup failure is reported and keeps recovery state, but it does not skip owned nft cleanup.
- FreePBX Firewall reloads are repaired without bringing peers down. With the `nf_tables` backend, the existing nft monitor wakes the broker on `ip filter` changes. With `legacy`, repair relies on the approximately 15-second periodic check. Until repair, tunnel traffic is dropped by FreePBX Firewall; the exposure is not widened.
- Any rule in `teliphones-ws` without the marker, an unrecognised match, or a reference from a chain other than INPUT is treated as unfamiliar. It is never modified or deleted, and workstation access is not admitted.
- No INPUT jump to `fpbxfirewall` results in status `not-detected`, and no integration rules are installed. If any Fail2Ban jump follows the FreePBX hook, no position both after Fail2Ban and before FreePBX Firewall exists. TELIPHONES then removes its integration and reports status `error`, naming the offending Fail2Ban chains. Tunnel traffic is left to FreePBX Firewall, and Fail2Ban is never bypassed. The integration is restored automatically when the ordering is corrected, for example when Fail2Ban restarts and re-inserts its hooks at INPUT position 1.
- If a reload leaves the jump anywhere other than immediately before `fpbxfirewall`, for example with a Fail2Ban hook or another rule inserted between them, the jump is moved back to that position. Every placement is read back. If a hook is inserted concurrently and the result is invalid, the integration is withdrawn and reported as an error.
- If installation or verification fails, TELIPHONES removes its rules and reports `error`. Peers stay nft-protected, but FreePBX Firewall may drop their HTTP/HTTPS. If removal cannot be verified, workstation access is disabled and recovery state is retained.

TELIPHONES never modifies FreePBX Firewall chains, zones, interface assignments, trusted networks, settings, policies or services. It never flushes, restarts, disables or reconfigures FreePBX Firewall.

Diagnostics: **Windows workstations** shows integration status as active, not installed, failed or unreported. An unreported status means the running broker predates this integration and the root bootstrap must be rerun. When a workstation has a recent handshake but integration is not active, its row warns that FreePBX Firewall may drop HTTP/HTTPS. Read-only root checks are:

```
iptables -S INPUT
iptables -S teliphones-ws
iptables -L teliphones-ws -v -n -x
```

Increasing counters on the ACCEPT rules show that integration is matching tunnel traffic.

Limitations: the hook name `fpbxfirewall` and the `fail2ban-*` chain names come from the reported FreePBX 17 installation. `f2b-*` follows the upstream Fail2Ban default. None was verified against FreePBX Firewall or Fail2Ban source. Fail2Ban hooks reached only through other chains, rather than directly from INPUT, and Fail2Ban using its own nftables tables are not inspected. A separate nftables Fail2Ban table still applies independently because an iptables accept does not override it. If an external reload places a Fail2Ban hook between the TELIPHONES jump and `fpbxfirewall`, that jail can be bypassed for authorised 80/443 (and approved 22) flows until reconciliation. Reconciliation is immediate on `nf_tables` and takes up to about 15 seconds on `legacy`. The integration's behaviour during a real FreePBX Firewall restart, its interaction with any FreePBX self-check of INPUT, and the end-to-end Windows result have not been tested on a real PBX. Simulated namespace tests do not establish that the reported connectivity failure is resolved.

## Verified uninstall and recovery

Uninstall requires root, stops the broker service and independently verifies inactive/failed state with zero main/control PIDs. It then invokes only the installed, root-owned, non-symlink broker below trusted non-writable ancestors, with isolated Python (`-I`) and a bounded timeout. Older helpers without the verified teardown entry point are refused before execution; web-owned module Python is never executed as root.

The helper shares the broker's verified teardown implementation. It removes the link before the owned rules and deletes the workstation key/state only after both absences are confirmed. A missing tool, unfamiliar table, query/disable/delete failure or helper timeout aborts uninstall and retains recovery information and the installed helper. Failed new pairing cleanup also retains its attempted public pairing metadata in root-private `workstation-recovery.json` alongside the previous saved state. Do not delete these files to hide an error; repair tools/ownership or the root broker, inspect the interface and retry. Support/gateway cleanup failures also abort artifact removal. A non-root Module Admin uninstall is refused rather than silently deleting metadata around live access.

For protocol and implementation details, see `teliphones/support_broker.py`, `teliphones/WebSupport.php`, `desktop/windows/src/core/Pairing.cpp`, and `desktop/windows/README.md`.
