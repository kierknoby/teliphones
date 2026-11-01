# TELIPHONES integration guide

TELIPHONES defines three external integration contracts. Implementations are replaceable and may use infrastructure of the operator's choosing.

> **Connect creates. Checker observes. Console consumes. TELIPHONES decides.**

TELIPHONES does not depend on proprietary Connect, Checker or Console services. This repository includes a separate reference gateway and Checker probe for disposable Linux testing; production operators must provision their own infrastructure, identities, certificates and network.

## Authority boundary

TELIPHONES is the PBX-local authority. Only local root can create the support grant. TELIPHONES owns the session ID, absolute expiry, topology, local verification, acceptance of Checker evidence, opening of the temporary local support service and immediate local revocation.

Connect, Checker and Console cannot extend a grant, replace its identity, override a failure, resurrect an expired session or mark TELIPHONES READY themselves.

## 1. Authorise locally

Root creates a bounded session, for example:

```bash
fwconsole teliphones authorise --minutes=15 --topology=on-pbx
```

`on-pbx`, `on-net` and `off-net` are the protocol topology names. In 0.1.3 the complete executable local access path is On-PBX; the other topologies define integration contracts without pretending to provide the same local WireGuard/sshd path.

## 2. Connect creates the path

Retrieve the versioned request:

```bash
fwconsole teliphones connect-request
```

For a configured reference gateway, `fwconsole teliphones provision` sends the existing `teliphones-connect/1` request over mutual TLS. Requests carry a fresh 256-bit request ID and timestamp. The gateway maps the verified client certificate fingerprint to one enrolled customer, rejects stale/replayed requests and returns a bounded peer/session response. The PBX WireGuard private key never leaves the PBX.

TELIPHONES validates proposed local addressing and refuses collisions. Connect must propose another suitable allocation rather than alter existing customer routes, DNS or network policy.

The response contains the gateway public key/endpoint, exact gateway and engineer `/32` routes, Checker address, SSH public key and selected SSH engineer address. TELIPHONES validates these before bringing up the interface. It installs no default route and makes no customer DNS, router or forwarding changes. Connect cannot activate engineer service flows during initial provisioning.

Wait for the PBX WireGuard peer to complete a fresh handshake, then confirm transport:

```bash
fwconsole teliphones connect-confirm
fwconsole teliphones attest
```

The gateway keeps engineer flows closed at this stage. Only its session-specific Checker probe is allowed after `confirm`. The protocol remains provider-neutral; see `CONNECT-CONTRACT.md` and `../../gateway/README.md`.

## 3. TELIPHONES verifies locally

After the path exists:

```bash
fwconsole teliphones attest
```

This is deliberately local verification after `connect-confirm`. TELIPHONES verifies the current authorization, authenticated peer, local interface/address and session route. It does not perform Internet/external reachability probes and cannot certify the outside view of the path.

Failure is fail-closed. No Checker or Console stage should be used to work around failed local verification.

## 4. Checker independently observes

Obtain a fresh challenge:

```bash
fwconsole teliphones checker-request
```

Checker performs independent external observations and returns evidence bound to the session, topology, challenge nonce and validity window. TELIPHONES starts a short-lived restricted responder on the PBX WireGuard address at TCP `22221`; it runs as `asterisk`, answers only the current nonce/session, and is not privileged SSH. Evidence must carry a P-256 ECDSA/SHA-256 signature made with the Checker private key; TELIPHONES verifies it against the root-pinned public key at `/etc/teliphones/checker-ecdsa-p256.pub`.

The reference `gateway/checker_probe.py` expects separately authenticated Checker and negative-control WireGuard identities in isolated namespaces. The authorized probe must receive HTTP 204 with the exact session and nonce echo. The negative-control identity must have a test route to the PBX so the test exercises the gateway's deny rule rather than missing client routing; any successful TCP connection is exposure. The public-address check also treats any successful TCP connection as exposure. This proves the restricted Checker port only, not the GUI or SSH ports.

Submit evidence locally:

```bash
fwconsole teliphones checker-accept --evidence-file=/path/to/checker-evidence.json
```

Checker reports observations; TELIPHONES decides whether they satisfy policy. A stale, replayed, mismatched or failing result cannot authorise Console access. On acceptance, TELIPHONES stops the restricted probe and calls Connect `activate`; the gateway then opens only the customer's configured TCP profile to its mapped engineers, with nftables rules expiring no later than the original session. See `CHECKER-CONTRACT.md`.

## 5. Console consumes approved access

Only after local verification and accepted Checker evidence may root open the dedicated temporary support service using the session Console public key:

```bash
fwconsole teliphones open --ssh-key='ssh-ed25519 AAAA... session-console'
fwconsole teliphones console-handoff
```

Console consumes the returned short-lived handoff. It does not authorise, verify or extend the TELIPHONES session. No engineer portal is included; standard WireGuard, browser and SSH clients are used. See `CONSOLE-CONTRACT.md`.

The engineer config is generated on the engineer's own workstation from a gateway grant. The engineer private WireGuard key stays there. Its `AllowedIPs` contain only currently assigned PBX `/32`s. To open SSH, use the authorized engineer private key and the tunnel address, for example `ssh -p 22222 root@10.20.17.1`; this is the documented lab allocation, not a deployed endpoint.

For the GUI, use the customer's existing management hostname and authentication. If its TLS certificate name does not match the tunnel IP, arrange temporary split name resolution on the engineer workstation so the existing hostname resolves to the PBX tunnel IP; do not disable certificate validation. FreePBX Firewall policy may block the interface or service. TELIPHONES does not change or bypass that firewall. Any required rule must be separately reviewed and approved by the customer; the reference implementation does not automate that change.

## 6. Revoke locally first

Revocation, disable, expiry or quarantine closes PBX-local authority first:

```bash
fwconsole teliphones revoke
```

TELIPHONES does not wait for an external service before closing its locally owned path and credentials. Connect should independently destroy temporary remote resources, Checker challenges/evidence cease to be useful, and Console must terminate the session. External implementations should also enforce their own absolute TTL so remote resources disappear if the PBX becomes unavailable.

## Integration order

Do not introduce every integration at once. Prove the system in this order:

1. TELIPHONES alone using manual/fixture inputs.
2. Add Connect and repeatedly prove path creation and destruction.
3. Add Checker and deliberately exercise both passing and failing observations.
4. Add Console only after the authority, path and evidence gates are reliable.
5. Automate that same sequence in the operator's Connect/orchestration environment without weakening TELIPHONES' local authority.

This gives a simple fault boundary: path creation belongs to Connect; independent evidence belongs to Checker; presentation/use of an already-approved session belongs to Console; authority and state belong to TELIPHONES.

## Baseline before live testing

Capture a sanitised system snapshot before authorisation and again after revoke/expiry/uninstall:

```bash
fwconsole teliphones baseline > /root/teliphones-before.json
# perform the test
fwconsole teliphones baseline > /root/teliphones-after.json
diff -u /root/teliphones-before.json /root/teliphones-after.json
```

The capture contains interface/address, IPv4 route/rule, listening-socket and sanitised TELIPHONES metadata. It deliberately excludes private keys, credentials and configuration-file contents. Time/session fields will naturally differ; investigate unexpected system-level differences.
