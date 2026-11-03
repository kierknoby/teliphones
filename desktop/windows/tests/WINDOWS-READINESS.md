# Windows SSH workflow readiness audit

Targets: TELIPHONES for Windows **0.7.0**, TELIPHONES for FreePBX **0.4.0**.

This audit describes executable provisioning and tests, not a successful Windows
run. The reported failure established that the selected `windows-2022` runner
lacked `System32/OpenSSH/sshd.exe`. Checking that file without provisioning it
was insufficient. The previous Unix broker import failure is separately fixed:
Windows executes portable client contracts; Linux retains full broker contracts.

## Execution order and prerequisites

| Stage | Dependency / source | Verification and failure handling |
|---|---|---|
| Checkout | Existing GitHub checkout action | No persisted Git credentials |
| Toolchain | Runner Visual Studio 2022, v143, static MFC, Windows SDK | Existing `vswhere` discovery and exact header/library/tool checks; no VS downloads |
| Project/layout checks | Runner Python and CMake | Explicit Python requirement; CMake script-mode tests check both platform registrations and provisioning order |
| OpenSSH provisioning | Elevated x64 runner, Windows DISM capability servicing, Task Scheduler | Enumerate `Get-WindowsCapability -Online` OpenSSH entries; install missing official Client/Server capabilities with `Add-WindowsCapability`; re-query Installed state and reject RestartNeeded |
| OpenSSH executable validation | Windows capability output in `%SystemRoot%\System32\OpenSSH` | Verify all three files, versions and SHA256; execute ssh version and sshd/keygen usage probes; validate exit codes AND output; export exact directory through GITHUB_PATH |
| OpenSSL restore | Runner's existing vcpkg; existing declared OpenSSL manifest | Static x64 restore, checked exit codes, versions logged; explicitly verify headers, Release/Debug crypto libraries and distributable copyright file |
| MSBuild | Verified VS tools and restored static crypto | Build GUI, console helper, native core/diagnostics and MFC window tests; existing failures remain fatal |
| Native CMake build | Runner CMake/Python/compiler, same vcpkg toolchain | Compile production core plus isolated loopback fixture core, crypto and agent/session test host |
| Win32 preflight | DPAPI, BCrypt/OpenSSL, VirtualAlloc/VirtualLock, local pipes, Jobs, process permissions | Actual native operations: locked seed/sign/destroy, user DPAPI round-trip, restrictive pipe creation, suspended child, Job assignment/process DACL/termination |
| CTest | Dependencies listed below | All six Windows tests remain enabled; any failure stops native integration |
| Native SSH integration | Windows OpenSSH, elevated task registration, current local Windows account, loopback ports | Actual SSHSIG sign/verify feature probe, generated Ed25519 host/CA, strict host key ACL, `sshd -t` and effective `sshd -T`; real authenticated login is mandatory |
| Always-run cleanup | Python and uniquely recorded fixture task/path | Stop marker, verified zero-Job-process acknowledgement, exact task deletion; recovery for interrupted harness; no service-name/process-name killing |
| Remaining native tests | Existing MFC tests, dumpbin, mt.exe, loader | Window tests, actual PE/version/manifest/import checks and helper startup tests retained |
| Distribution | Both executables plus static OpenSSL copyright and GPL licence | Existing packaging and executable hashes unchanged; upload only after successful validation |

`provision_openssh.ps1` does not start/enable the global sshd or ssh-agent service,
change public firewall rules or edit production SSH configuration. Official
capability servicing may retrieve its payload through Windows servicing; this is
the requested capability installation, not an alternate download mechanism.
No external searches/downloads were performed in the local development session.

If servicing fails, logs include the specific exception/HRESULT and available
DISM/CBS tails. A reboot requirement or an executable that cannot load is a failure,
not an assumed successful install. No unapproved ZIP/package fallback exists.
If the runner cannot install the official capability, an alternative requires
approval for an exact, version-pinned official Microsoft Win32-OpenSSH distribution
URL and an independently trusted expected SHA256. No version/hash is invented.

Capability presence does not establish feature compatibility: the installed
`ssh-keygen` must actually sign/verify SSHSIG and sign Ed25519 certificates; CTest
and native login reject unsupported behaviour. Actual versions/hashes are logged
on each runner, not assumed from the mutable runner label.

## All six Windows CTests

| Test | Runtime dependencies / provisioning | Windows behaviour and cleanup |
|---|---|---|
| `core_tests` | Compiled production portable core | No Unix imports/network; deterministic schemas/routes/commands; production loopback policy rejection explicitly retained |
| `session_diagnostics` | Win32 token/ACL/file/mutex/process APIs | Existing Windows-specific implementation; temporary stores and child handles; no POSIX execution on Windows |
| `build_layout` | Python stdlib, CMake, repository source/project files | UTF-8 for new fixtures; temporary CMake script removed; checks test registration, provisioning, isolated task XML/path quoting and all ten native methods |
| `contract_check` | Python stdlib, contract_tool, portable gateway renderer | Unix import guard; five real client schema/binding/tunnel/fingerprint/denial checks; no broker/root/network dependencies |
| `managed_ssh_check` | Official ssh-keygen, contract_tool | Generated temporary CA/keys/certs; POSIX chmod guarded; actual certificate-binding boundaries/tamper rejection; files removed by TemporaryDirectory |
| `ssh_crypto_check` | Static OpenSSL crypto tool and official ssh-keygen | Native Ed25519 lifetime/export denial, constrained userauth, SSHSIG/certificate verification and identity migration; generated fixtures removed |

The workflow provisions OpenSSH before these tests, so their existing
OpenSSH-unavailable skips cannot be used to obtain success in this workflow.
Linux additionally runs `broker_contract_check`; privileged OS/network calls in
that contract test are doubled, not represented as a native Windows result.

## Native fixture: account, configuration and lifetime

Foreground sshd running as the ordinary runner account is not an adequate
Windows logon-token environment. The harness registers a unique demand-start
SYSTEM task (`schtasks /Create /RU SYSTEM`) running the **test host**, not the
product. Its wrapper verifies the SYSTEM SID, starts sshd suspended in an
anonymous non-inheritable kill-on-close Job, then resumes it. The listener,
privilege-separated descendants and remote test commands share that Job.

The scheduled task and wrapper each have a ten-minute bound. Normal cleanup
signals a stop file, terminates the owned Job, verifies zero remaining processes,
writes an acknowledgement and removes the task. Class cleanup runs after fixture
setup failure as well as success. An always-run workflow step handles an
interrupted Python harness using a validated exact task name and temporary path.
Only fixture metadata/logs go to diagnostics, never generated CA/private keys.
The disposable runner remains the ultimate boundary for job cancellation/reboot.

The harness uses a protected temporary directory under RUNNER_TEMP (or the user
temp directory for manual runs), user/SYSTEM/Administrators ACLs, and explicitly
SYSTEM-owned host key with no broad read permissions. It never uses the global
host keys/config or `administrators_authorized_keys`. The server allows only the
current local runner account, CA/certificate authentication, no password/keyboard
interactive/agent/TCP forwarding, and binds only `127.0.0.1:22001`. The mock issuer
binds only `127.0.0.1:8765`. Both fixed contract ports are checked for collisions;
no machine firewall rules, routes or network adapters are changed.

The current provider's production route policy rejects loopback workstation
addresses. Previously the production-path fixture used `127.0.0.1/32` anyway and
would fail before requesting its certificate. The native host now links a
**separate test-only core**, compiled with `TELIPHONES_SSH_LOOPBACK_FIXTURE`, which
permits exactly that fixture source in managed-pairing validation. The application,
production core CTests and crypto tool do NOT define it. The underlying route
parser is unchanged and production rejection has an explicit regression test.
All certificate signature, subject, account, source, principal, lifetime and host
checks remain active against the exact loopback fixture values. This exception is
not shipped, is not generalised to arbitrary addresses and does not prove a real
FreePBX/WireGuard deployment. The existing test-only console executable override
also remains: real application companion packaging is validated separately.

SeDebugPrivilege is explicitly disabled in the Python probe token so tests of
ordinary process-DACL isolation do not accidentally measure an administrative
debug bypass. Privileged/debugger resistance is not a product guarantee.
Unrelated-process agent I/O is overlapped and bounded rather than an unbounded
synchronous read. Authentication/crash failures still fail the test.

## All ten native SSH tests

All rows require the common fixture above, real Windows client/server and compiled
production crypto/agent/session code. Dependencies are verified on the runner;
their presence/success has not been observed locally.

| Test | Additional dependencies / assertions | Success and failure teardown |
|---|---|---|
| `test_native_login_destroys_key_and_creates_no_private_key_files` | Actual certificate login and remote echo; one-signature key destruction; only public session artifacts | Host/agent/SSH Job closes; test files removed with fixture |
| `test_other_process_cannot_enumerate_or_use_agent` | ctypes Win32 overlapped pipe I/O, exact connecting PID enforcement | Bounded five-second probe, I/O cancellation and event/pipe close; host cleanup |
| `test_new_process_handles_cannot_read_memory_or_duplicate_credentials` | Disabled debug privilege; OpenProcess denied VM_READ/VM_WRITE/DUP_HANDLE/CREATE_THREAD | Every acquired probe handle closed; host cleanup |
| `test_concurrent_sessions_and_wrong_certificate` | Two distinct live keys/certificates and independently owned Jobs; mismatched certificate rejected | Per-host cleanup, server Job ultimately reaps remote commands |
| `test_expired_cert_and_wrong_host_fail_without_password_fallback` | Real expired certificate, wrong pinned host and cryptographically tampered certificate | Nonzero results mandatory, no fallback; each owned host stopped |
| `test_controller_crash_kills_owned_ssh_only` | Long-running remote ping, forced exact controller PID termination; unrelated login survives | Per-controller Job; unrelated host cleanup; fixture Job reaps server-side commands |
| `test_ssh_crash_ends_agent_and_prevents_reuse` | Exact owned SSH handle forcibly terminated; agent pipe disappears | Host cleanup; fixture process-tree teardown |
| `test_production_dpapi_identity_certificate_api_console_and_disconnect` | User DPAPI/LOCALAPPDATA; cmd.exe; WinHTTP; Python HTTP issuer verifies SSHSIG and correct public subject; PTY login | CloseManagedSsh, public artifacts removed, permanent identity survives session then explicit test deletion; issuer stopped |
| `test_production_certificate_refusal_cleans_identity_without_launch` | Same authenticated issuer returns 403 after verifying request | No terminal/session; test-owned DPAPI identity removed; principal restored and HTTP server stopped |
| `test_production_local_authorisation_expiry_ends_owned_session` | Real login plus fixed local authorisation deadline; bounded wait accommodates expiry | Owned SSH/helper/agent end; identity retention checked before test deletion |

The issuer's HTTP errors retain exception details in the failing test output;
sshd logs and task status make fixture startup failures actionable. Those logs
contain public fingerprints/session metadata, not private-key material.

## Remaining validation gates

- Official capability servicing, its installed version/features, PowerShell
  execution, SYSTEM task/logon privileges, MSVC test-host compilation and all
  native behaviour above require an actual new Actions run. They are NOT
  validated by Linux syntax/source tests.
- No assertion that Windows tests cover actual FreePBX/systemd revocation:
  server-enforced existing-session expiry/revocation, workstation removal, broker
  failure, cgroup cleanup and unrelated administrators still need a disposable
  real FreePBX 17/systemd target. Linux namespace OpenSSH tests substitute
  process-tree supervision, not real systemd.
- Windows reboot/hibernation, terminal matrix, real WireGuard interruptions,
  production GUI-to-PBX flow and distribution smoke tests still need target
  execution. No physical erasure guarantee for memory/pagefiles/dumps/SSDs.
- No native test was disabled or replaced with a successful stub. The audit's
  source/layout/XML tests are safeguards, not proof of Windows interoperability.
