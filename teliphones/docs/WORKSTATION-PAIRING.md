# TELIPHONES 0.2.0 workstation pairing contract

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
- Cleanup verifies interface/table removal. Failed interface deletion attempts to take the interface down and retains its restrictive firewall. Failures are reported, not acknowledged as successful revocation; **Revoke all workstations** remains available for retry after pairing metadata is removed.
- Windows disconnection after revocation is detected through tunnel service and PBX reachability monitoring. There is no server-pushed Windows revocation channel in this version, so instantaneous client-side disconnect is not guaranteed. The PBX-side broker/firewall remains authoritative for access.
- The GUI displays the last WireGuard handshake from a fixed read-only `wg show tlp-admin latest-handshakes` query, without peer keys. Zero means no handshake; an unavailable query is explicitly unverified. A past handshake is not proof of current GUI/SSH reachability. Workstation status is a page-load snapshot, separate from remote support operation polling.

## Network requirements

The workstation connects directly to the configured PBX WireGuard UDP endpoint. The PBX's chosen UDP port must be reachable through the PBX host firewall, FreePBX Firewall, and any router/NAT. The module does not configure port forwarding or change unrelated network services. No relay or universal NAT traversal is provided.

For protocol and implementation details, see `teliphones/support_broker.py`, `teliphones/WebSupport.php`, `desktop/windows/src/core/Pairing.cpp`, and `desktop/windows/README.md`.
