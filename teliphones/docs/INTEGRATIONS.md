# TELIPHONES integration contracts

> **Connect creates. Checker observes. Console consumes. TELIPHONES decides.**

TELIPHONES is open source and provider-neutral. An operator may bring its own network and its own implementations of all three integration contracts.

## Authority boundary

TELIPHONES is the authority on the PBX. It owns enable/disable state, the root grant, session ID, absolute expiry, topology, PBX-local verification, acceptance of Checker evidence, Console handoff, revocation and the local audit trail.

No integration may create or extend a root grant, change its expiry, override quarantine, revive an expired session, or declare itself trusted.

## 1. Connect

Connect creates or supplies the temporary communications path. It may use WireGuard, an existing private network, a customer VPN, temporary infrastructure, or another mechanism appropriate to the selected topology.

TELIPHONES supports `on-pbx`, `on-net`, and `off-net`. In On-PBX, TELIPHONES can create its own ephemeral WireGuard endpoint. In On-net and Off-net, Connect terminates the private path elsewhere and TELIPHONES does not alter PBX routing to manufacture connectivity.

Generate the request with:

    fwconsole teliphones connect-request

The `teliphones-connect/1` request contains the session ID, absolute expiry, topology, FreePBX major version, preferred address pool and, for On-PBX where available, the PBX ephemeral WireGuard public key.

A Connect implementation must treat TELIPHONES network data as constraints. A proposed On-PBX address that collides with existing PBX addressing/routing is rejected; Connect must propose another pair. Connect must never require TELIPHONES to replace a default route, DNS, NAT, forwarding or customer routing.

## 2. Checker

Checker is independent of Connect. It probes the environment Connect produced and returns observations. It does not create the path, provide the console, or decide whether TELIPHONES may open access.

After PBX-local verification succeeds, obtain a fresh request:

    fwconsole teliphones checker-request

A `teliphones-checker/1` request contains a session-bound random nonce, topology, short evidence deadline and the policy to test. A conforming Checker returns the same protocol, session ID, topology and nonce plus observations.

TELIPHONES 0.2.1 requires evidence that:

* the support service is reachable from an authorised source;
* the same support service is blocked from a negative-control source;
* the support service is not exposed at the public address; and
* no unexpected service was discovered by the Checker policy.

Import evidence with:

    fwconsole teliphones checker-accept --evidence-file=/root/checker.json

Evidence with a stale challenge, wrong session, wrong topology, wrong nonce, failed negative control, public exposure, or unexpected services is rejected with a stable machine-readable reason in state/audit output.

## 3. Console

Console is the final consumer. It receives temporary connection information only after the root grant is current, PBX-local verification has passed, Checker evidence has been accepted, and TELIPHONES has opened the session-specific local adapter.

Once TELIPHONES reports READY, obtain the handoff with:

    fwconsole teliphones console-handoff

The `teliphones-console/1` envelope contains the session ID, absolute expiry, topology and temporary target. It explicitly carries no authority to authorise, verify or extend the session.

## Required interaction order

    LOCAL ROOT AUTHORISATION
             |
          CONNECT
             |
    TELIPHONES LOCAL VERIFY
             |
          CHECKER
             |
    TELIPHONES ACCEPTS EVIDENCE
             |
          CONSOLE
             |
            READY

The three integrations are intentionally asymmetric. Connect proposes/builds. Checker reports observations. Console consumes a handoff. TELIPHONES alone makes the local decision.

## Revocation and failure

TELIPHONES removes local authority immediately on revoke, disable, expiry or mandatory verification failure. It does not wait for a remote component before closing the PBX side. Connect should destroy disposable infrastructure, Checker should discard outstanding challenges, and Console should terminate the human session.

A failure must fail closed. A fresh local root authorisation is required after quarantine.
