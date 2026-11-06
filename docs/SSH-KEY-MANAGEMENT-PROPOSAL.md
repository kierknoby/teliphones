# My PBXs managed SSH: implementation and validation

The current implementation targets **Windows 0.8.5**, **FreePBX 0.6.7**, **root
broker 0.6.7**, protocol **12**, independently versioned. Current source retains
the 0.6.6 nftables feedback-loop correction and adds persistent correlated
admission diagnostics and broker responsiveness corrections. The local 0.6.7
archive and checksum include current module source;
the superseded 0.6.5 archive was removed; historical archives lack those new security corrections. Historical reports and the
proposal below retain their original versions; they do not validate current source.

## Current status: native integration and initial live SSH reported successful

The **Pair -> Connect -> Open SSH -> authenticated terminal -> close ->
credentials destroyed** path is now implemented in Windows source, not replaced
by an unconditional failure gate. It uses maintained OpenSSL Ed25519 operations,
a fresh memory-backed session key, an isolated named-pipe agent, the existing
request/2 certificate endpoint, pinned host/CA identities and an owned console
helper/SSH Job. GUI-only pairing, Connection Health, appearance, WireGuard and
the independent Remote Support path are preserved.

The operator now reports successful Windows Actions builds, **all ten native
OpenSSH integration tests passing**, authenticated Windows 0.7.0 SSH into a
FreePBX 17 / Debian 12 test PBX with module 0.4.0, and owned-terminal closure
on disconnect. No run URL, commit/build hash or raw logs were supplied here;
these results are attributed reports, not locally repeated Windows tests.

**This is not a completion or production-security claim.** Real 0.4.1 firewall
stability, PBX revocation/expiry/systemd/cgroup termination, reboot, upgrade,
rollback and failure recovery remain unverified. This local environment has
Linux OpenSSH, not a Windows runtime/compiler or running systemd manager.
There is no shared-agent, plaintext-file, password or host-verification fallback.
The reported current failure where opening the embedded SSH console closes
TELIPHONES remains an unresolved release blocker; historical successful SSH
reports do not establish that the current console lifecycle is reliable.
See the [current evidence register](SECURITY.md#verification-evidence).

## Pairing identity and ephemeral certificate contract

1. Windows generates a per-PBX WireGuard key. GUI-only pairing is the default
   version-1 path and never invokes OpenSSH. Selecting **FreePBX Web + SSH Access**
   before **Generate request** generates a separately DPAPI-encrypted permanent identity,
   without requiring OpenSSH to generate either request. The version-2 contract enrols a separate,
   persistent Ed25519 workstation authentication public key; that identity must
   never be the disposable session key. Only public keys appear in
   `teliphones-pair-request/2`. Saved identities and approvals are retained.
2. A full FreePBX administrator approves the request over HTTPS with the existing
   CSRF checks and explicitly selects an existing Linux account. There is no
   default account; root requires explicitly typing `root` and must already be
   permitted by the effective system SSH policy. No account is created.
3. `teliphones-pair-response/2` binds the nonce and WireGuard key and supplies the
   account, PBX Ed25519 host public key, dedicated CA public key and managed ports.
   The trusted pairing exchange pins these keys without a fingerprint prompt.
   Windows displays the approved account read-only only after response validation;
   Copy/Save availability follows current request/response state. Changing name
   or requested access invalidates unused identities and requires regeneration.
   The response envelope is not separately signed: provenance relies on trusted
   administrator HTTPS, while SSH certificates are signature-verified separately.
4. The implemented **server** API on TCP 8765 serves a 30-second, one-use challenge
   bound to the workstation and exact WireGuard source. Windows generates a fresh
   session key locally and signs these exact bytes with the
   persistent enrolled identity, using namespace `teliphones-ssh`:
   `TELIPHONES-SSH-REQUEST-2\n<workstation_id>\n<challenge>\n<session_id>\n<ssh_public_key>\n`.
   The session ID is 32 lowercase hex characters; `ssh_public_key` is the canonical
   disposable Ed25519 public key. Neither private key belongs in the request.
5. The broker verifies the SSHSIG with the enrolled identity and issues a
   certificate for the **different session public key**, never the identity.
   Old request/1 issuance is rejected. Duplicate live session IDs/public keys
   are rejected by a bounded in-memory ledger (not a durable uniqueness ledger
   across broker restarts). The certificate includes a
   source-address critical option, PTY permission only and validity of at most
   300 seconds, capped by the pairing's original deadline. The principal is
   `tlp-eph-<workstation_id>-<identity_public_key_SHA256_first16>`; the key ID is
   `ws-<workstation_id>/<session_id>`.
6. The portable `ValidateSshCertificateBindings` parser checks the pinned CA,
   distinct session public key, principal, session ID, source and time bounds
   structurally, **not cryptographically**. It is not a digital-signature
   verifier. Separately, `VerifySshCertificateSignature` uses OpenSSL to verify
   the Ed25519 digital signature against the pinned CA before terminal launch.
   SSH itself must also authenticate against the pinned host and certificate.
   There is no reusable-key preflight: the agent permits one authentication
   signature, for the interactive client only.

### Windows provider and lifecycle

- `SshCrypto` uses static OpenSSL 3 Crypto rather than custom Ed25519 code or an
  assumed CNG signing algorithm. Session keys have no export API. Their seed is
  held in a separate locked `VirtualAlloc` page; short-lived OpenSSL key/context
  copies are freed after each operation. The seed is cleared before release.
- `SshSession` unlocks only the permanent DPAPI identity for challenge signing,
  verifies its public key against pairing, signs in memory and clears transient
  buffers. Existing unencrypted-OpenSSH-format contents inside old DPAPI blobs
  are imported in memory without changing the enrolled public identity.
- Each `SshAgent` has a random local named pipe, user/SYSTEM DACL, first-instance
  creation and remote-client rejection. It compares the connecting PID with a
  retained, live handle for exactly its SSH child. Arbitrary data, key import,
  key export and shared-agent operations are rejected.
- One signature is permitted, and only for the exact account/session certificate
  SSH userauth payload. Hostbound requests must also contain the pinned host key.
  The key is destroyed immediately after producing that signature, even before
  terminal closure. A failed authentication therefore cannot reuse its key.
- Only public identity/certificate/known_hosts/config files are staged. OpenSSH
  uses the pinned host key, isolated `-F` configuration, exact agent endpoint,
  certificate-only auth and no password, host-prompt, forwarding or mux fallback.
- Current My PBXs hosts its libvterm/ConPTY console in the application using
  `TELIPHONES-SSH.exe` as the verified companion. The companion can also serve
  external OpenSSH-backed console paths. Before creating SSH suspended,
  it must join an anonymous, non-inheritable kill-on-close Job owned by the GUI.
  The GUI verifies the child executable and Job membership, authorises the agent
  for its process handle and only then permits execution.
- SSH/helper exit, requested disconnect, profile removal and local authorisation
  expiry tear down the Job and agent. Incomplete authentication is limited to
  30 seconds. Closing/crashing/forcibly terminating the GUI closes its sole Job
  handle, killing its helper/SSH processes; no persisted session key exists to
  reload after restart. Server termination causes the client to exit independently
  of these local controls. Native crash/restart behaviour is still a validation gate.
- Process DACLs restrict new memory-reading, thread-creation and handle-duplication
  handles, including the owner's implicit WRITE_DAC permission. This is not a
  defence against privileged debuggers/administrators, malicious code already
  inside a trusted process, previously obtained privileged handles, tampered
  application binaries or a compromised Windows installation.

### Public-source checks and native evidence

With explicit research approval, Microsoft's
[Windows OpenSSH agent connection code](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/fileio.c)
was checked: `fileio_connect` connects the supplied agent path using
`CreateFileW` with overlapped pipe I/O. This is Windows implementation evidence,
not an inference from Unix sockets and not a test of any installed Windows build.
The [CNG curve list](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-named-elliptic-curves)
does not establish Ed25519 signing support; Curve25519 ECDH is not Ed25519.
OpenSSL supplies the required maintained signature implementation instead.

The existing Windows workflow now restores the declared static OpenSSL
dependency, builds both executables and native test tools, and runs real
OpenSSH/pipe/process tests. It fails explicitly if native OpenSSH Server is
missing; it does not download an unreviewed installer or silently use Unix SSH.
Runner-image documentation alone is not evidence that the required binary is
present or compatible. No new Actions run has been triggered or claimed.

## Isolation and ownership

- The API and SSH acceptor bind to the exact shared/dedicated PBX tunnel address **and**
  use `SO_BINDTODEVICE`. An alternate interface cannot reach them even if a
  firewall rule is removed. Never publish or forward these TCP ports.
- Each authorised workstation has its own port (`22000 + address last octet`)
  and root-owned, separately validated sshd configuration. An inetd-style sshd
  child receives only an accepted socket from that device-bound listener.
- Each listener runs in `teliphones-ssh-<workstation-id>.service` with
  `KillMode=control-group`, a bounded stop deadline and forced final kill.
  Temporary authorisations also set systemd `RuntimeMaxSec` to the remaining
  authorisation time. Units are bound to broker lifetime.
- Revocation stops the owned unit, verifies service state and an unpopulated
  cgroup before allowing state removal. Recovery inventories only exact owned
  unit names. Failures retain pairing/recovery state and disable the tunnel.
- A certificate expiring prevents new authentication; an established session is
  bounded by its administrator-approved pairing lifetime, not reset or extended
  by certificate renewal. Persistent pairing sessions last until revoked or
  disconnected by the server/client.
- System SSH configuration, accounts, authorized_keys and unrelated processes
  are not changed. Effective root, authentication-method, account, forced-command,
  algorithm and revoked-key policies are checked. Unsupported restricted
  configurations fail closed rather than weakening them.

### Supported system SSH policy relationship

The managed listener is a separately owned certificate-only service, not a clone
of `sshd_config`. Its sole trust path is its own CA/principal files; ordinary
`authorized_keys` do not grant access. It reuses the approved existing account
and shell, the checked host key, effective `PermitRootLogin`, `UsePAM`, accepted
public-key/CA algorithms and `RevokedKeys`. `UsePAM yes` uses the existing `sshd`
PAM service; arbitrary PAM-stack equivalence is **not** established by source
inspection. Custom PAM service names are unsupported and rejected.

The system configuration is evaluated with the approved user, exact peer source
and PBX address at **both port 22 and the actual managed port**. Any difference
in effective policy is unsupported and fails closed, even if a particular
difference looks harmless. This prevents a restrictive `Match LocalPort` from
being bypassed in either direction. Multi-factor requirements, forced commands,
chroots, external principal files/commands, custom key commands, noninteractive
accounts, UID-zero aliases and configured Allow/DenyUsers/Groups also fail closed.
DNS-dependent matching is unsupported. No automatic rewriting of administrator
policy is attempted.

Before installing generated configuration, `sshd -t` and `sshd -T -f ... -C ...`
must succeed at the **actual managed port** and client/account context. The
effective result must match owned trust files, one allowed user, certificate-only
authentication, no forwarding/user environment/RC/tunnel, expected account policy
and preserved algorithms/revocation file. Real OpenSSH tests deliberately restrict
each local-port context and alter the generated policy to prove rejection.
PAM/account effects and actual systemd behaviour still require the disposable-host
gate below; the checks do not claim preservation of every arbitrary system setting.

## Private-key material inventory and migration

| Material/location | Previous implementation | Current handling |
|---|---|---|
| Workstation SSH identity generation | `PairDlg` called `Ssh.cpp`, which ran `ssh-keygen -f ...\\identity`, creating plaintext private/public files | OpenSSL generates a permanent workstation identity in memory; DPAPI encrypts its seed before storage, with transient copies cleared |
| Windows reusable identity | `ReadSmallFile` copied the private key into `std::string`; `Services.cpp` DPAPI-encrypted it into `%LOCALAPPDATA%\\TELIPHONES\\SSH\\<profile>.dpapi` | `SshSession` decrypts only for workstation SSHSIG authentication; legacy blobs remain compatible. The identity is never the session subject |
| Per-attempt Windows private key | DPAPI decryption copied the identity into strings and a plaintext `identity` file under a random attempt directory; OpenSSH/ssh-keygen helper processes read it for public-key extraction, SSHSIG and authentication | This entire export, signing and launch path is removed, with no plaintext fallback |
| Windows runtime artefacts | Private key, public key, signature, certificate, config and known_hosts persisted until cleanup, possibly beyond a terminal/app crash | New files contain only public key/certificate, config and pinned known_hosts. Cleanup handles known legacy artefacts too; it cannot securely erase old copies or terminate old unowned terminals |
| Disposable session key | Previously the reusable identity was also the certificate subject | Generated in locked seed memory, transient OpenSSL signing contexts only, no export/persistence; one process-bound userauth signature, then explicit destruction |
| Network request | Previously public identity, challenge, signature and certificate; no private key was intentionally transmitted | Exact request/2 allows only public session key, session ID, challenge, workstation ID and identity signature; extra fields are rejected |
| PBX SSH CA | Generated by ssh-keygen into root-private `/etc/teliphones/ssh/ca` and used by signing subprocesses | Preserved across sessions and migration; private CA never sent to Windows |
| PBX trusted host key | Existing root-owned Ed25519 host key read by sshd; public key pinned during pairing | Preserved, not regenerated or modified |
| Other permanent identities | WireGuard keys in Windows Credential Manager and broker authorisation records | Unchanged; profile/session cleanup does not destroy PBX CA or other pairings |

Earlier implementations also created helper/OS and library-buffer copies.
Deletion of their files does **not** prove secure destruction or erase previously
copied credentials. Encrypted legacy identities are deleted only on explicit
profile removal/abandoned pairing, not at session closure. Removing a local
profile does not revoke the PBX record. If previous plaintext identity exposure
is suspected, explicitly revoke/re-pair; retaining a compromised identity cannot
be made safe merely by changing certificate subjects.

The managed principal changes from `tlp-...` to `tlp-eph-...`, so previously issued
identity-subject certificates cannot authenticate to the new listener.
Configuration migration recognises only the exact old owned principal, validates
the new configuration and requires verified owned-unit termination before
replacing that principal. Unknown/unsafe trust files fail closed. Migration
preserves CA, host identity and enrolled workstation identity. The real systemd
migration/termination gate below is still outstanding; updating source alone
does not stop an already running old terminal or revoke its copied key.

For this memory-backed provider, logical destruction means removing signing
capability and releasing the key object (or ending its owning app process), not proving physical
memory erasure. Sensitive copies must be minimised and cleared where practicable.
TELIPHONES cannot guarantee erasure of SSD blocks, paging files, crash dumps or
all Windows/OS memory. No such guarantee is made for Linux tmpfs test fixtures.

New root bootstrap installs both Python helpers, validates imports before
activation and attempts restoration of prior broker files/service on failure.
No SSH packages are downloaded. Managed SSH requires systemd, unified cgroup v2
and existing OpenSSH tools/host key; missing SSH prerequisites do not block
legacy/web-only PBX pairing. System SSH remains available if broker startup fails.

Legacy version-1 pairings retain network behaviour; adding managed SSH requires
an explicit SSH-capable request and administrator approval. Revocation/re-pairing changes the managed identity
and kills old owned sessions. Host/CA changes fail pinned verification and require
administrator re-pairing; there is no accept-new or password fallback. PuTTY is
unsupported for managed My PBXs certificates; Remote Support is unchanged.

## Validation and outstanding gates

- Portable C++ tests use genuine OpenSSH-generated certificates to check the
  client contract, saved-profile round trip, distinct identity/session subject,
  session-ID/CA/principal/source/expiry binding. Production OpenSSL tests verify
  SSHSIG with real ssh-keygen, import a legacy identity and reject a tampered
  certificate or wrong CA; destroyed keys cannot sign or export.
  Source assertions additionally guard against reintroducing key export,
  persistence or fallback; neither kind of test proves native Windows security.
- Linux integration runs in private mount, PID and network namespaces with
  private account databases and real sshd, certificate authentication and HTTP.
  It exercises wrong accounts/keys/host pins, replay, wrong-interface access,
  certificate expiry, revoked issuance (including pending challenges), concurrent
  distinct sessions, cross-key rejection, identity-subject/old-principal rejection
  and real managed-session process termination while an unrelated authenticated
  SSH session remains alive. Test credentials live in a private Linux tmpfs.
  Removing a test key prevents fresh login but demonstrably does not kill an
  existing authenticated session. Principal migration ordering/failure is tested
  with a mocked service stop, not genuine systemd.
- **The integration supervisor substitutes process-tree teardown for systemd.**
  The environment has no running systemd manager. Actual production unit/cgroup,
  PAM/FreePBX policy, installation rollback and upgrade/removal behaviour still
  require disposable Debian 12 / FreePBX 17 systemd validation.
- **Native Windows integration: operator-reported 10/10 passing.** The harness executes
  production crypto/agent code with actual Windows OpenSSH and a loopback sshd.
  It covers login, lack of private-key runtime files, PID/process access denial,
  simultaneous sessions, wrong certificates/host pins, tampering, expiry and
  app/SSH crashes. A separate path invokes production DPAPI identity generation,
  signed HTTP issuance/refusal, cmd-hosted console launch, local expiry, preserved
  permanent identity after session teardown and verified disconnect.
  No raw run logs or build identifier were supplied for independent review.
  These tests do not prove
  WireGuard-only admission or production systemd semantics; Linux tests and the
  disposable FreePBX gate cover those separately.

This feature must not be called production-ready or fully platform-validated
until those gates are passed.

### Required release evidence (still outstanding)

Use only a disposable Debian 12 / FreePBX 17 systemd host and a test Windows
workstation, never a production PBX. Record concrete commands, service states,
owned cgroup population, authenticated session PIDs and unchanged unrelated
administrator access for each scenario:

- Real managed interactive SSH and child/background processes: explicit revoke,
  temporary pairing expiry and broker failure must remove all owned processes
  while an unrelated authenticated system SSH session remains alive.
- Broker restart, workstation re-pair, reboot recovery, upgrade success, failed
  import/activation, successful/incomplete rollback and uninstall must preserve
  independent administrator access and never extend authorisation deadlines.
- Run the added native workflow and verify Windows agent transport, crypto,
  DPAPI/WinHTTP integration, process isolation, no private export and Job
  ownership/crash semantics. Endpoint ACLs alone are not signing-process isolation.
- Windows MSVC/MFC build; GUI-only pairing without OpenSSH; SSH opt-in and
  supported PowerShell/PowerShell 7/Command Prompt/Windows Terminal launches;
  persistent identity protection and cross-user/process isolation. Demonstrate
  normal terminal closure, app/SSH crash, forced termination, failed issuance,
  orphan recovery, simultaneous sessions, revocation, authorisation expiry,
  profile removal and Windows reboot, followed by rejected credential reuse.
  The automated subset is now operator-reported passing; the full matrix,
  especially all terminal variants and Windows reboot, still requires a test host.
- Supported Windows OpenSSH helper acceptance/rejection of valid/tampered
  certificates, and real end-to-end account/root/PAM restrictions with the PBX.
- Install the existing test prerequisites (PHP SimpleXML, WireGuard/OpenSSH tools)
  only in that authorised environment and rerun full regressions without hiding
  skips.

Temporary plaintext Windows session-key files are **not an acceptable option**.
Provider errors must remain fail-closed, and production readiness remains blocked
on the full lifecycle gates, not just the now-reported native test milestone.
Persistent-pairing sessions surviving the
five-minute certificate lifetime remain an explicit product-lifetime contract.
Certificate expiry bounds new logins, while persistent sessions intentionally
continue until revocation or connection/server termination. The local corrections
do not grant release/security sign-off or complete the requested Windows feature.

## Historical proposal (superseded)

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
