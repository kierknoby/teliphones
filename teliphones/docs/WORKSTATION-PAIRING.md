# TELIPHONES workstation pairing contract

Workstation pairing is for an administrator's own Windows workstation. It is separate from the customer-authorised Remote Support session workflow. The FreePBX module and root broker remain authoritative for peer enrollment, allowed traffic, expiry and revocation.

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
- An administrator can revoke one workstation or all workstations in the FreePBX TELIPHONES page. Removing a local Windows profile only deletes the local key; it does not revoke the PBX peer.
- Windows disconnection after revocation is detected through tunnel service and PBX reachability monitoring. There is no server-pushed Windows revocation channel in this version, so instantaneous client-side disconnect is not guaranteed. The PBX-side broker/firewall remains authoritative for access.

## Network requirements

The workstation connects directly to the configured PBX WireGuard UDP endpoint. The PBX's chosen UDP port must be reachable through the PBX host firewall, FreePBX Firewall, and any router/NAT. The module does not configure port forwarding or change unrelated network services. No relay or universal NAT traversal is provided.

For protocol and implementation details, see `teliphones/support_broker.py`, `teliphones/WebSupport.php`, `desktop/windows/src/core/Pairing.cpp`, and `desktop/windows/README.md`.
