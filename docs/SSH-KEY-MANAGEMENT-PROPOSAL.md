# Workstation SSH keys: proposal for review

**Design only. Not implemented, not an authentication workaround.**
Windows remains **0.4.0** and the FreePBX module remains **0.3.0**.
No pairing schema, SSH server configuration or account is changed by this
document. A future implementation needs a separately approved scope and release.

## Current behaviour and reported result

The operator reports that PuTTY launched by TELIPHONES reaches the FreePBX 17
SSH server and receives:

> No supported authentication methods available (server sent: publickey)

That establishes server reachability and a public-key authentication requirement,
not a need for password fallback or proof that a particular key was offered.
An absent accepted key, unavailable agent, wrong account or rejected key/policy
can produce authentication failure; the client's session log and corresponding
sshd log distinguish them.

Current code:

- [SshReady](../desktop/windows/src/app/MainDlg.cpp) requires an active,
  monitor-verified connection and pairing SSH permission.
- [SshTargetFor](../desktop/windows/src/core/CommandLine.cpp) selects the saved
  Linux account, PBX tunnel address and TCP 22 for an administrator profile.
  The local username is not an administrator-approved account grant.
- [TerminalLaunch](../desktop/windows/src/core/Launchers.cpp) starts PuTTY with
  `-ssh`, `-P`, `-l`, `-loghost` and the tunnel address, or Windows OpenSSH via the
  selected terminal. It passes no managed identity file or key enrolment.
- PuTTY uses its own settings/Pageant where available; OpenSSH uses its own
  configuration, keys and agent. TELIPHONES does not bridge these stores.
- [Services.cpp](../desktop/windows/src/platform/Services.cpp) stores
  **WireGuard** private keys in Credential Manager. These are not SSH identity
  keys and must never be reused as them.
- [Pairing.cpp](../desktop/windows/src/core/Pairing.cpp) carries WireGuard
  identity and the `ssh` network-permission boolean, not SSH public-key authority.
- Remote Support is a different contract with a temporary service on port
  22222 and a root target. This proposal is for **My PBXs** workstation access
  only and must neither reuse nor silently alter Remote Support authority.

Thus choosing PuTTY or approving TCP 22 does not provision SSH authentication.
The Windows app observes successful process creation, not the child's completed
SSH authentication, and must not report a logged-in session from launch alone.

## Recommended workflow

### 1. Explicit local setup

Add a per-PBX **SSH access** panel, separate from global terminal preferences:
`Not configured`, `Awaiting approval`, `Approved`, `Revoked` or `Expired`.
Existing profiles start `Not configured`; do not enrol existing keys implicitly.
The selected terminal remains a global application preference.

After explicit consent, generate a fresh Ed25519 SSH key on the workstation.
Prefer a separate key per workstation **and PBX** to limit correlation and
revocation impact. Do not derive it from a WireGuard key or copy an existing
PBX/server key. Display its SHA-256 public-key fingerprint.

Require a user-controlled passphrase for an exportable private key. Store it
outside roaming profiles, under a private LocalAppData directory with an ACL
limited to the owning user and necessary system access. Prefer an agent-unlock
experience; do not persist passphrases or put them in process arguments,
environment variables, logs, pairing responses or profile JSON. Credential
Manager/DPAPI can protect local metadata but is not a substitute for an SSH
client-compatible encrypted identity and restrictive file permissions.

Use detected, verified local `ssh-keygen` / PuTTYgen tooling only after its
capability/version is checked, or a separately reviewed native implementation.
Do not introduce a bespoke key parser/converter or silently download tools.
Ed25519/server-policy incompatibility must be explicit, not trigger password
fallback or an unreviewed algorithm downgrade.

### 2. Separate public-key enrolment and account authorisation

Use a **new, explicitly versioned SSH enrolment exchange**, separate from the
existing WireGuard pairing protocol. A copy/paste public request through the
existing authenticated HTTPS FreePBX administration page avoids needing SSH
access before a key has been authorised. Never request a server private key.

Bind the request to:

- PBX identity, existing active workstation pairing ID and WireGuard public-key
  fingerprint;
- the SSH public key, its verified fingerprint and a fresh random request nonce;
- the requested non-root Linux account and requested expiry.

The full PBX administrator explicitly selects/approves the account, key and
duration with existing permission and CSRF controls. The workstation's requested
username is only a request. Validate supported key encoding/length, reject
caller-supplied authorised-key options/commands, unknown fields, replay,
cross-PBX/cross-workstation binding and expired/revoked pairings. Require proof
of possession by signing an enrolment challenge with the new private key;
review the signed message format and replay protection before implementation.

Default to **no root account** and no account creation. Offer only pre-existing
non-root accounts that the PBX owner has explicitly made eligible. Do not
silently add groups, sudo rights, passwords or shell privileges. Linux account
authorisation is distinct from FreePBX GUI administrator status.

Use an allow-listed privileged operation, not a web-selected path or shell
command, to install only the approved public key. The precise integration with
the PBX's existing `AuthorizedKeysFile` / `AuthorizedKeysCommand` policy needs
inspection and approval first. Refuse unsupported ownership, symlink,
directory-service or SSH-policy arrangements rather than rewriting sshd policy.
Manage identifiable TELIPHONES entries atomically without replacing unrelated
keys, permissions or authentication configuration.

Constrain each entry to its approved workstation tunnel `/32` and disable agent,
TCP, Unix-socket and X11 forwarding, tunnels and user startup commands. A normal
interactive shell may require PTY permission; review the exact OpenSSH options
against the installed version, rather than blindly adding `restrict` and
breaking interactive use. Preserve existing account restrictions.

An approval response binds the same request/key/account/expiry and PBX identity.
Authenticate the administrator-mediated exchange and verify nonce/key binding;
do not treat an unsigned object received from an arbitrary endpoint as authority.
The precise approval authenticity/possession format is a design-review item.

### 3. Launch with a deliberate identity

Only offer **Open SSH** once tunnel verification, current network permission and
the separately approved account/key binding are satisfied.

| Selected application | Proposed identity mechanism |
|---|---|
| Windows PowerShell / PowerShell 7 / Windows Terminal / Command Prompt | Existing Windows `ssh.exe` with an explicit identity (`-i`), `IdentitiesOnly=yes`, public-key-only authentication and password/keyboard-interactive disabled. Preserve validated address/port and per-PBX host-key alias. |
| PuTTY | An encrypted PPK of the same key, produced locally by verified PuTTYgen, passed with `-i`; or an explicitly supported Pageant workflow after agent compatibility is validated. Do not assume PuTTY reads OpenSSH private files or uses Windows' OpenSSH agent. |

Keep both private representations on the workstation if conversion is needed,
with the same restrictive storage and deletion policy. Do not export an
unencrypted intermediary to a shared/temp directory. If safe non-scripted
conversion or agent use is unavailable, explain the missing capability and
leave SSH unconfigured for that terminal. Do not silently use a different key,
terminal, account or password.

Never pass a private key or passphrase on the command line. Validate executable
paths and identity paths; pass supported arguments separately using existing
launch/quoting helpers, including paths with spaces. Preserve host-key checking:
enrol/confirm the server's **public** host-key fingerprint through the trusted
administrator path, do not disable verification or accept changed host keys
automatically. PuTTY and OpenSSH maintain separate host-key stores.

### 4. Revocation, expiry and rotation

Provide **Revoke SSH** separately from **Revoke workstation**:

- SSH revocation removes the exact managed public-key authorisation and that
  workstation's TCP 22 permission, while retaining web/WireGuard access.
- The broker holds the authoritative key/account bindings and deadlines.
  Temporary SSH authority must not outlive the pairing and must expire on the
  PBX, even if the client is offline or changes its clock.
- Pairing revocation/expiry also removes its SSH grants. Do not delete keys
  approved for a different workstation or unrelated server accounts.
- Removing an authorised key alone prevents new authentications but does not
  terminate existing shells. Specify and test how immediate revocation closes
  attributed SSH sessions/flows without killing unrelated logins; if attribution
  cannot be proved, do not claim immediate session revocation.
- Local profile/key deletion is not server-side revocation. Warn explicitly and
  retain a way for administrators to revoke lost workstations independently.
- Rotation generates a new local key and requires new administrator approval.
  Keep the old grant until the authorised transition, then revoke it explicitly;
  never widen a grant or silently fall back to a revoked key.

The current module's SSH boolean cannot express independent key/account grants
or toggle SSH without re-pairing. These are future, reviewed changes, not claims
about 0.3.0 capabilities. Restart recovery and partial-write rollback must
reconcile authoritative SSH grants without reviving expired permissions.

## Approval gates and test requirements

Review the non-root account policy, trusted approval exchange, managed
authorised-key storage, passphrase/agent UX, PuTTY conversion dependencies,
host-key enrolment and active-session revocation **before implementation**.
No public-key-only server policy should be relaxed.

Regression requirements include cross-workstation/PBX replay, nonce and
proof-of-possession failures, unknown options/paths, non-root-only selection,
web-only pairing refusal, independent SSH revocation/expiry, partial writes,
unrelated keys remaining intact, restart recovery, rotation and stolen/offline
workstation revocation. Windows tests must exercise ACLs, encrypted key formats,
agents, paths with spaces and each terminal. Real PBX tests must verify rejected
wrong keys/accounts, host-key changes, public-key-only authentication and
termination semantics without weakening Fail2Ban or FreePBX Firewall.

Related immediate investigation:
[FreePBX Firewall read-only diagnostics](FREEPBX-FIREWALL-DIAGNOSTICS.md).
