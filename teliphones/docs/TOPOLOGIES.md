# TELIPHONES topologies

TELIPHONES 0.1.3 uses three topology names. They describe where the private support network terminates; they do not prescribe who supplies that network.

## On-PBX (`on-pbx`)

The private path terminates directly on the FreePBX server. TELIPHONES can create `wg-teliphones`, generate a fresh WireGuard key locally, and accept a single session-scoped peer. The private key never leaves the PBX. The session address is a tiny allocation from the preferred `10.20.<FreePBX-major>.0/24` pool, not a route for that whole pool.

Connect may propose a different collision-free pair. TELIPHONES rejects collisions rather than changing the customer's default route, DNS, existing interfaces, forwarding or NAT.

## On-net (`on-net`)

The private path terminates elsewhere on the customer's local network. Connect owns that path. TELIPHONES does not create a PBX WireGuard interface merely because the topology is On-net. Checker must independently verify the resulting support exposure before Console can be used.

## Off-net (`off-net`)

The private path terminates outside the customer's network and may traverse the public Internet as an encrypted transport. Privileged support services must remain private to the approved path. Connect owns the path and Checker independently tests it. TELIPHONES does not alter PBX networking to manufacture an Off-net route.

The reference implementation provides an On-PBX WireGuard path. Other operators may provide an approved private path through their own Connect implementation.
