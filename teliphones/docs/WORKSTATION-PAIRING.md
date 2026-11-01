# TELIPHONES 0.2.1 workstation pairing contract

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

Install `TELIPHONES-0.2.1.tgz` through Module Admin, then rerun the documented root bootstrap with no active support session and Windows tunnels disconnected. Installation does not delete `workstations.json`, `workstation-recovery.json` or `workstation-wg.key`. Valid pairings keep their identities, addresses, permissions and original deadlines.

The bootstrap copies the current broker into its protected root-owned installation and restarts it. Protocol 3 was already used in 0.2.0: an operational socket or protocol number alone does **not** prove these security corrections are installed. Rerunning the bootstrap is mandatory even if no update warning appears.

An unmarked 0.2.0 table is treated as unfamiliar: startup disables `tlp-admin`, retains the saved pairing/key data, reports the ownership conflict and does not change or delete that table. There is deliberately no automatic adoption or marker injection. A root administrator must investigate ownership with the interface stopped and, only if positively identified as the old TELIPHONES table, explicitly remove that isolated legacy table before restarting the updated broker. Do not flush the ruleset, remove unrelated tables, clear pairing data or add a marker to an unknown table. If ownership cannot be established, leave workstation access disabled. Restoration of valid pairings requires verified new restrictions; expired temporary entries are not revived.

## Network requirements

The workstation connects directly to the configured PBX WireGuard UDP endpoint. The PBX's chosen UDP port must be reachable through the PBX host firewall, FreePBX Firewall, and any router/NAT. The module does not configure port forwarding or change unrelated network services. No relay or universal NAT traversal is provided.

The `nft` CLI is essential; enabling or running `nftables.service` is **not** required. The broker programs the kernel directly. Missing userspace tools require platform-administrator repair; the GUI has no nftables installer. TELIPHONES never changes foreign tables, their default policies, or other firewall services.

## Enforcement integrity and exposure limits

The only managed table is `inet teliphones_workstations`, bearing the exact table comment `TELIPHONES workstation enforcement v1`. An unfamiliar or unmarked namesake is **never** overwritten or deleted, including during uninstall. The interface is disabled and the conflict is reported. Older unmarked TELIPHONES tables require explicit operator investigation with the interface stopped; the broker does not infer ownership from a name, and adding its marker to an unknown table is not a safe migration.

Expected JSON is generated offline from the approved PBX address and SSH sources. The broker compares the actual `nft -j list table` output with the complete expected table, both base chains (type, hooks, priority and policy), ordered rules and every expression. Only kernel handles, envelope metadata and chain enumeration order are ignored. Extra rules/objects or changed destinations, interfaces, protocols, ports, verdicts or ownership fail validation. The same JSON is submitted atomically, read back and checked before peer admission. Exclusive table creation refuses a newly appearing namesake; deletion uses the inspected table handle so a replacement table is not deleted by name.

A local `nft -j monitor ruleset` stream observes external mutations, including a flush followed by restoration between periodic checks. Registration is proven by acknowledging the broker's own complete initial transaction before admission, not merely by starting a process. Expected own-event signatures are consumed without launching repair loops; unrelated-table events are ignored. External events wake the serialized enforcement worker; it disables the interface and revalidates/reapplies the policy. Approximately 15-second periodic validation is a fallback for both persistent and temporary pairings, including idle persistent peers. Stream death, malformed output or an enforcement-worker failure reports an error and attempts verified interface disablement; admission then requires broker repair/restart. Saved temporary deadlines are never extended.

**This is detection and recovery, not atomic protection against another privileged firewall manager.** External flushes/removals can expose an already-up interface until the local event is delivered and processed (or the periodic fallback runs). A transient removal can pass traffic even if rules are restored before detection. There is also a verification/admission race with concurrent external changes, and no detection-latency guarantee under load, process suspension or resource failure. Failed interface shutdown may leave access active and needs immediate operator intervention. Do not describe this as truly fail-closed or zero-exposure protection against external flushes.

No installed FreePBX Firewall implementation or hooks were available in the development workspace. No hook integration, ordering guarantee or compatibility with its reload/flush behaviour is assumed; validate those on a disposable installed PBX. TELIPHONES does not enable/disable its services or rewrite its policies.

## Verified uninstall and recovery

Uninstall requires root, stops the broker service and independently verifies inactive/failed state with zero main/control PIDs. It then invokes only the installed, root-owned, non-symlink broker below trusted non-writable ancestors, with isolated Python (`-I`) and a bounded timeout. Older helpers without the verified teardown entry point are refused before execution; web-owned module Python is never executed as root.

The helper shares the broker's verified teardown implementation. It removes the link before the owned rules and deletes the workstation key/state only after both absences are confirmed. A missing tool, unfamiliar table, query/disable/delete failure or helper timeout aborts uninstall and retains recovery information and the installed helper. Failed new pairing cleanup also retains its attempted public pairing metadata in root-private `workstation-recovery.json` alongside the previous saved state. Do not delete these files to hide an error; repair tools/ownership or the root broker, inspect the interface and retry. Support/gateway cleanup failures also abort artifact removal. A non-root Module Admin uninstall is refused rather than silently deleting metadata around live access.

For protocol and implementation details, see `teliphones/support_broker.py`, `teliphones/WebSupport.php`, `desktop/windows/src/core/Pairing.cpp`, and `desktop/windows/README.md`.
