# Console contract: teliphones-console/1

Console consumes a TELIPHONES-approved temporary access path. It is not an authorisation or verification service.

TELIPHONES exposes the handoff only after the local grant is current, local verification has passed, Checker evidence has been accepted, and the temporary support adapter has opened.

The handoff includes session ID, absolute expiry, topology and temporary target. Credentials are session-specific; permanent support credentials are outside the TELIPHONES model.

Console must stop using the path when the session expires or is revoked. It cannot extend the grant.
