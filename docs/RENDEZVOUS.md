# TELIPHONES rendezvous and relay interface (design note)

The Windows client defines a small `IRendezvousProvider` interface in `desktop/windows/src/core/Rendezvous.h`. Its initial `DirectProvider` returns the endpoint from the approved, request-bound PBX response. The response envelope is not independently signed; provenance relies on the trusted administrator's HTTPS exchange. The interface describes a future way to resolve an identity to a reachable endpoint or optional relay without making a relay mandatory.

There is no deployed rendezvous service, relay, discovery protocol, credential, or network fallback in this repository. The current client is direct WireGuard only. If the endpoint is unreachable because of NAT or firewall policy, the client reports that limitation; it must not claim universal NAT traversal.

Any future provider must preserve these invariants:

- PBX-side pairing/session authorisation remains the sole authority for access.
- The provider never receives client or PBX private keys.
- The provider cannot broaden `AllowedIPs` or grant PBX services.
- Relay use, if added, must be explicit, observable, and separately reviewed for privacy, trust, operations and failure behaviour.
- No ordinary PBX administration or SSH port is exposed publicly by the rendezvous mechanism.

The current interface is a local design seam only; it is not a network client or service integration.
