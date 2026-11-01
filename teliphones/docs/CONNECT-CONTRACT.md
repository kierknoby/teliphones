# Connect contract: teliphones-connect/1

Connect is the integration that brings the network.

It may create infrastructure or use infrastructure the operator already controls. TELIPHONES does not prescribe a cloud provider, VPN vendor or orchestration platform.

Connect must honour the TELIPHONES session ID and absolute expiry. In On-PBX mode it may receive the PBX's ephemeral WireGuard public key and propose a peer/endpoint and collision-free session address pair. The PBX private key never leaves the PBX.

Connect has no authority to change the root grant or customer networking. If TELIPHONES rejects an allocation because it overlaps existing addressing or routes, Connect must select another allocation rather than asking TELIPHONES to alter the customer's routes.

## Reference lifecycle actions

The reference implementation retains `teliphones-connect/1` and adds lifecycle actions on the same mutually authenticated control channel:

- `provision` installs a closed customer peer and returns the gateway peer, exact engineer/Checker `/32`s, expiry, SSH public key and enrolled SSH engineer address.
- `confirm` is accepted only when the gateway observes a fresh authenticated WireGuard handshake; it enables only the restricted Checker probe.
- `activate` is accepted only from `connected` and opens the configured engineer-to-PBX service tuples after TELIPHONES accepts signed Checker evidence.
- `destroy` revokes the exact customer, session and remote identifier.

Every request includes a unique 256-bit `request_id` and `request_timestamp`. The gateway maps the verified mTLS client certificate SHA-256 fingerprint to an enrolled customer and rejects replayed or stale requests. A valid-looking session ID is not a customer identity. Returned expiry is bounded by the local absolute expiry and the gateway applies its own independent timeout. `engineer-grant` and `checker-grant` are operator-local outputs; no public unauthenticated enrollment endpoint is provided.

The repository's separate reference gateway implements this contract for disposable Linux testing. No managed gateway endpoint or external service is supplied.
