# Checker contract: teliphones-checker/1

Checker exists because a PBX cannot independently prove how it appears from outside itself.

TELIPHONES deliberately performs no Internet/external reachability probes in 0.1.3. It verifies PBX-local invariants and asks an independent Checker for external observations.

Example request:

```json
{
  "protocol": "teliphones-checker/1",
  "session_id": "0123456789abcdef0123456789abcdef",
  "topology": "on-pbx",
  "nonce": "random-session-challenge",
  "issued_at": 1790000000,
  "expires_at": 1790000300,
  "policy": {
    "authorised_source": "required",
    "negative_control": "required",
    "public_support_access": "forbidden"
  }
}
```

Example passing evidence:

```json
{
  "protocol": "teliphones-checker/1",
  "session_id": "0123456789abcdef0123456789abcdef",
  "topology": "on-pbx",
  "nonce": "random-session-challenge",
  "observed_at": 1790000050,
  "observations": {
    "authorised_source": {"support_service": "reachable"},
    "negative_source": {"support_service": "blocked"},
    "public_address": {"support_service": "blocked"},
    "unexpected_services": []
  },
  "signature": "BASE64_ECDSA_P256_SHA256_SIGNATURE"
}
```

TELIPHONES evaluates the observations and requires a cryptographic signature. A Checker cannot substitute `safe: true` for evidence or rely on transport security alone.

## Evidence authentication

The PBX must have a trusted ECDSA P-256 public key in PEM format at `/etc/teliphones/checker-ecdsa-p256.pub`. It must be a regular file owned by root and not writable by group or other users. Install the key through a separately trusted administrative process; never accept a key supplied alongside the evidence. The corresponding private key remains with the independent Checker and must not be installed on the PBX.

The Checker signs the UTF-8 JSON representation of the evidence object with the `signature` member omitted, using ECDSA with SHA-256. Before encoding, recursively sort object keys in bytewise string order; preserve array order and JSON scalar types. Encode the resulting DER signature as base64 in `signature`. TELIPHONES rejects evidence if the key is missing, malformed, or untrusted, or if the signature does not match.

For a disposable PBX, place the independently generated PEM public key at the path above with root ownership and mode `0644` or stricter. The private key must remain exclusively on the test Checker. The checked-in fixtures are unsigned examples and are not accepted as proof.

Stable rejection reasons include `checker-required`, `checker-protocol-invalid`, `checker-session-mismatch`, `checker-nonce-mismatch`, `checker-topology-mismatch`, `checker-stale`, `checker-observation-stale`, `checker-signature-invalid`, `checker-replay`, `checker-authorised-source-failed`, `checker-negative-control-failed`, `checker-public-exposure-detected`, and `checker-unexpected-service`.

The file-import command remains root-only in 0.1.3; the administrator GUI submits evidence through the restricted root broker. Signature verification authenticates the evidence content but does not itself prove that the configured Checker performed honest or independent network observations. A future network API must preserve the same session, nonce, signature and expiry semantics.

A Checker challenge is single-use after successful acceptance. `observed_at` must fall within the challenge window; accepted evidence cannot be replayed to satisfy a later check.
