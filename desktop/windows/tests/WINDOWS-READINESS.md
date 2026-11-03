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
| PowerShell discovery diagnostics | Exact System32 Windows PowerShell executable, separate from fixture/security tests | Record selected discovery variables and child edition/module paths; compare inherited versus PSModulePath/PSHOME-reset module loads; full exception/exit output in powershell-environment.log; not an ACL verification or success substitute |
| OpenSSH provisioning | Elevated x64 runner, Windows DISM capability servicing, Task Scheduler | Enumerate `Get-WindowsCapability -Online` OpenSSH entries; install missing official Client/Server capabilities with `Add-WindowsCapability`; re-query Installed state and reject RestartNeeded |
| OpenSSH executable validation | Windows capability output in `%SystemRoot%\System32\OpenSSH` | Verify all three files, versions and SHA256; execute ssh version and sshd/keygen usage probes; validate exit codes AND output; export exact directory through GITHUB_PATH |
| OpenSSL restore | Runner's existing vcpkg; existing declared OpenSSL manifest | Static x64 restore, checked exit codes, versions logged; explicitly verify headers, Release/Debug crypto libraries and distributable copyright file |
| MSBuild | Verified VS tools and restored static crypto | Build GUI, console helper, native core/diagnostics and MFC window tests; existing failures remain fatal |
| Native CMake build | Runner CMake/Python/compiler, same vcpkg toolchain | Compile production core plus isolated loopback fixture core, crypto and agent/session test host |
| Win32 preflight | DPAPI, BCrypt/OpenSSL, VirtualAlloc/VirtualLock, local pipes, Jobs, process permissions | Actual native operations: locked seed/sign/destroy, user DPAPI round-trip, restrictive pipe creation, suspended child, Job assignment/process DACL/termination |
| CTest | Dependencies listed below | All six Windows tests remain enabled; verbose output, JUnit and full stdout/stderr log retained; failure does not suppress independent native SSH integration |
| Real fixture preflight | Same Python/C++ fixture, ICACLS, native Win32 security APIs, Task Scheduler COM and actual OpenSSH server | Complete protected DACL replacement plus separate owner assignment; inspect exact file/task descriptors; reject and repair real deliberately invalid file ACLs; generated keys/config, SYSTEM task, live server PID/SSH banner; verified teardown; no mocked replacement |
| Native SSH integration | Windows OpenSSH, elevated task registration, current local Windows account, loopback ports | Actual SSHSIG sign/verify feature probe, generated Ed25519 host/CA, strict host key ACL, `sshd -t` and effective `sshd -T`; real authenticated login is mandatory |
| Always-run cleanup | Python and uniquely recorded fixture task/path | Stop marker, verified zero-Job-process acknowledgement, exact task deletion; recovery for interrupted harness; no service-name/process-name killing |
| Remaining native tests | Existing MFC tests, dumpbin, mt.exe, loader | Window tests, actual PE/version/manifest/import checks and helper startup tests retained |
| Distribution | Both executables plus static OpenSSL copyright and GPL licence | Existing packaging and executable hashes unchanged; upload only after successful validation |

Builds and test suites are separate Actions steps with explicit prerequisite
outcome checks and `!cancelled()`. A failed contract suite does not prevent native
SSH integration when OpenSSH provisioning, native compilation, Win32 preflight
and actual fixture preflight succeeded. Portable CTest does not depend on either preflight success, so it still
collects its own results. MFC window, PE/manifest and startup suites also run after
other test failures if the application build succeeded. Both standalone core and
diagnostics executables are attempted even if the first fails.

No step uses `continue-on-error`: failures remain job failures. Application
packaging/upload retain the default successful-job condition. Diagnostics upload
runs on success or failure, collecting `ctest-results.xml`, `ctest-output.log`,
`powershell-environment.log`, `native-fixture-preflight.log`, `native-ssh-output.log` and the existing native/startup logs in
`TELIPHONES-Windows-startup-diagnostics`. Verbose unittest names, unlimited contract
diffs and raw transport-byte errors identify exact assertions in the same run.

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

## Native fixture ACL failure and preflight

The supplied Windows traceback is an actual setup failure: ICACLS exit **87**,
`Invalid parameter "/setowner"`, before any native test ran. The host-key command
combined `/inheritance:r /grant:r ... /setowner ...`; `/setowner` is a separate
ICACLS command form, not a grant option. This is a fixture defect, not an SSH
provider defect.

The later confirmed `ca.pub` failure exposed a separate construction defect:
`icacls /grant:r` replaces grants **only for the specified SIDs**, not the whole
DACL. `/inheritance:r` removes inherited ACEs, not an existing explicit Everyone
read ACE. `/setowner` does not remove grants either. The supplied observation
establishes that Everyone survived; it does not by itself establish which
key-generation/runtime operation originally created that ACE.

The fixture now uses `SetNamedSecurityInfoW` to install a complete, protected
allowlist DACL, replacing all existing explicit and inherited entries in one
operation. The intended trusted grants are present immediately; no empty/null
DACL or permissive intermediate state is installed. Ownership remains a separate
checked `icacls /setowner` invocation, followed by independent descriptor readback.
SID-based policy is read back through native Windows APIs in
`fixture_security.cpp`, checking owner, protected DACL, exact allowed identities,
full-control masks, inheritance, propagation and unexpected flags. Unsupported
ACE forms and unexpected ACEs fail the fixture. The former PowerShell script has
been removed; the fixture does not spawn PowerShell.

- Temporary root: current user owner; current user, SYSTEM and Administrators
  have explicit inheritable full control.
- Host private key: SYSTEM owner; only SYSTEM and Administrators have explicit,
  noninherited full control; any explicit runner-user grant is removed.
- CA private/public key, host public key, principals, configuration and task XML:
  current user owner; only current user, SYSTEM and Administrators, protected
  noninherited file grants. These are disposable fixture keys, not product
  session private keys; fixture files are removed on teardown.
- Task Scheduler security: Administrators owner; protected DACL allowing only
  SYSTEM, Administrators and the runner user; actual SYSTEM SID, service-account
  logon type and highest run level verified after task registration.

`--fixture-preflight` calls the **same** `setUpClass` and class cleanups used by
the ten native tests. It checks generated Ed25519 host keys, SSHSIG support,
`sshd -t/-T`, the protected task, real SYSTEM wrapper and loopback SSH banner with
a live recorded server PID. Actual negative ACL probes separately change owner,
add an unauthorised SID, enable inheritance, reduce access rights and add a deny
ACE; every observed invalid descriptor must be rejected, then restored and
re-verified. A repair probe also seeds a real explicit Everyone read ACE, confirms
the strict checker rejects it, reapplies the complete DACL and verifies exact
SID/mask/flags/owner state. Both generated public keys are secured before first
use; generated certificate files receive the same complete replacement/readback.
Private host/CA keys, root, config, principals and task XML use the shared
constructor; host private-key access stays restricted to SYSTEM/Administrators.
Success requires acknowledged zero Job processes,
closed listener, absent scheduled task and removed temporary directory. Setup
and cleanup errors are both reported. It does not claim an authenticated login:
that remains mandatory in the unchanged ten-test integration suite.

Diagnostics include ICACLS's installed `/?` help, exact failing
argv/exit code/stdout/stderr, expected/observed ACLs and SDDL, `whoami /all`, and
OpenSSH/wrapper logs. No private-key contents or private protocol input are logged.
The C++ test host uses Unicode command-line input rather than treating Windows
ANSI argv as UTF-8. SYSTEM-wrapper failures are written to the fixture log,
because a scheduled task has no attached console. Failed shutdown does not
silently erase evidence of a still-running server/task; interrupted recovery
uses `ITaskFolder::GetTask` and accepts only `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`
as proof that a task is absent. Access-denied/RPC/service failures remain errors.

Local policy/command-construction/cleanup-error unit tests use mocks and do **not**
validate Windows ACL semantics. This Linux workspace has no PowerShell or Windows
runtime: the separate native fixture preflight, actual ICACLS commands, task
descriptors, Unicode test-host build and all ten native SSH tests remain
unexecuted locally. Runtime ICACLS help plus descriptor checks provide the
on-runner syntax and permission validation; no external searches were used.

### Latest PowerShell loader failure: evidence and correction

The supplied error, `Get-Acl: Microsoft.PowerShell.Security could not be loaded`,
establishes a module/command-loader failure **before** descriptor inspection. It
does not establish an invalid file owner or ACL. The full loader exception,
inherited module paths and exact module manifest selected on that runner are
not available locally; no remote GitHub access was performed.

The workflow's parent shell is PowerShell 7 (`pwsh`), whereas the old fixture
spawned Windows PowerShell (`powershell.exe`) without sanitising its inherited
environment. `-NoProfile` does not clear `PSModulePath` or other environment
variables. Cross-edition module/assembly discovery is therefore a concrete
fragile dependency, but **not a proven explanation for that specific run**.
Missing/damaged inbox modules or other assembly-loading errors cannot be ruled
out from the single supplied message.

The diagnostic-only probes are isolated child processes, not a workaround in
the fixture. They record only named PowerShell discovery variables, edition,
module manifest paths, exit codes and complete loader exceptions, comparing
inherited versus reset discovery variables. Even if these probes cannot load
the module, the native security checks still run independently. A later runner
cannot retroactively prove the original runner's exact condition.

Discovery tests use an explicit environment mapping, covering `PSModulePath`
present, absent and Windows-style uppercase `PSMODULEPATH`. They compare the
complete inherited/reset child environments and verify the parent is unchanged.
Reset removal is case-insensitive because Windows `os.environ.copy()` produces
uppercase keys; optional discovery variables are not assumed to exist.

The actual correction removes **all** PowerShell calls from the SSH harness:

- `GetNamedSecurityInfoW`, `GetSecurityDescriptorOwner/Control/Dacl`, `GetAce`,
  SID conversion and SDDL serialization inspect real file security; the filesystem
  must advertise persistent ACL support. No localised CLI output is parsed.
- Task Scheduler COM sets and reads back the protected task descriptor and
  resolves principal names to SIDs; its actual SYSTEM SID, service-account logon
  and highest run level are required.
- Token/account APIs return the runner SID, elevation and actual local account
  name instead of trusting `USERNAME` or a PowerShell identity query.
- Task-state/absence inspection uses COM, including interrupted cleanup; it no
  longer imports the ScheduledTasks PowerShell module.
- Errors identify the API, numeric Win32 code or HRESULT, expected result and
  actual result. Descriptor mismatch errors include expected policy and observed
  descriptor. The SYSTEM wrapper captures errors at the failing API rather than
  reporting a later, potentially stale `GetLastError`.

The audit also identified a separate **fixture-only byte transport defect**:
Python `subprocess.run(text=True, input=...)` rewrites LF to CRLF on Windows.
The production certificate-request signature covers LF-delimited bytes, so the
old mock issuer could verify different bytes from those signed by the native
provider. The fixture now sends SSHSIG input as explicit UTF-8 bytes and writes
the feature probe using exact bytes. Production cryptography is unchanged.
Local transport tests verify no text-mode stdin translation; native signature
verification/login remains a required Windows result.

### Complete fixture dependency audit

| Phase / operation | Essential dependency and handling |
|---|---|
| Before tests: tools | Official client/server/keygen provisioning and executable checks remain before dependent stages; static OpenSSL is restored and compiled; native host links SDK `taskschd`, `ole32`, `oleaut32` and `advapi32`, no added runtime package |
| Before tests: services/modules | Task Scheduler/RPC is essential and checked by provisioning plus actual native COM connection/task registration. No global sshd/ssh-agent service is started. PowerShell DISM remains only in the existing official-capability provisioning stage, not fixture verification or teardown |
| Before tests: privileges/account | Provisioning requires elevated x64; native identity query additionally verifies an elevated local-account token. SYSTEM is needed for Windows sshd logon tokens; task principal/run level/permissions are checked. Python disables debug privilege before process-isolation tests |
| Before tests: filesystem | Unique temporary path, exact SID allowlists, protected ACLs, host SYSTEM ownership, explicit CA/config/task permissions; filesystem persistent-ACL capability checked. Negative ACL probes must reject actual invalid permissions |
| Before tests: server | Generated test-only CA/host keys; public-key-only auth, pinned host, no password/interactive fallback, forwarding disabled, StrictModes enabled; `sshd -t/-T`, exclusive port availability, actual live PID/banner. No production config/firewall changes |
| During tests: API issuer | Loopback HTTP server with authenticated SSHSIG request, exact-byte verification, distinct public subject/session/principal and short-lived generated certificate; rejects invalid/denied requests; issuer thread/socket stopped in finally |
| During tests: isolation | Actual Windows named pipe and exact client PID enforcement; real process access probes, locked Ed25519 key, DPAPI, Windows SSH client/helper, anonymous kill-on-close Jobs; concurrent sessions and unexpected termination exercised, not mocked |
| During tests: paths/encoding | Native host uses `wmain`, UTF-8 protocol and UTF-16 Win32/COM APIs; Python uses argument arrays, XML task serialization and quoted OpenSSH paths. Task operations restricted to the generated fixture namespace |
| After tests: ownership/termination | Stop marker, SYSTEM wrapper kill-on-close Job, zero-active-process acknowledgement, bounded PID wait, closed loopback listener, exact task deletion and absence query; retain failure if any mandatory check fails |
| After failure/interruption | Cleanup registered immediately, recovery descriptor recorded before sensitive setup; created-but-unstarted tasks cleaned; always-run recovery ends only the recorded task and removes only its validated temporary path. No name-based process killing or production service changes |

All six Windows CTests and all ten native methods remain registered/enabled.
Unittest continues after individual test failures. Independent portable, native,
window, PE and startup results are collected using existing outcome gates;
mandatory failures remain job failures and prevent packaging/publication.
Fixture setup/preflight failure cannot be labelled an authenticated SSH test pass.

Local validation for this correction: CMake build and all seven Linux CTests
passed, including 30 project/fixture regression tests; gateway Python ran 142
tests with 141 passed and one skipped for missing WireGuard tooling. PHP,
JavaScript, documentation and module packaging regressions passed. A genuine
local OpenSSH SSHSIG probe (with Linux mode-0600 test key) accepted the exact
LF-delimited payload and rejected its CRLF-mutated equivalent. This is evidence
for byte binding, not Windows execution. The new native Win32/COM component,
real negative ACL probes, runner module probes, SYSTEM task and all ten native
SSH tests have **not** been compiled/executed in this Linux workspace. No
disposable Windows runtime, Windows SDK/compiler or authorised remote Windows
execution environment is available here; no dependencies were downloaded.

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

### Three contract assertions: locally reproduced Windows CRT behaviour

The supplied Actions summary says five tests ran with three failures; the actual
Windows assertion tracebacks were not available locally and no remote access was
performed. The following are the **local reproduction results**, not invented
values attributed to that Actions run.

Running the uncorrected five-test suite with the real local C++ contract tool and
the Windows CRT text-stdout rule (insert CR before each LF), followed by Python's
universal-newline decoding, reproduces exactly five tests / three failures:

| Test / subtest | Failing assertion | Expected | Reproduced actual |
|---|---|---|---|
| `test_response_profile_and_administrator_tunnel`, `mode='temporary'` | Rendered administrator configuration equals the expected complete configuration | `[Interface]\nPrivateKey = ...\nAddress = 100.70.1.2/32\n\n[Peer]\n...` | `[Interface]\n\nPrivateKey = ...\n\nAddress = 100.70.1.2/32\n\n\n\n[Peer]\n\n...` |
| `test_response_profile_and_administrator_tunnel`, `mode='persistent'` | Same configuration assertion, independent persistent response/profile round-trip | Same administrator configuration as temporary mode | Same doubled line breaks as temporary mode |
| `test_support_tunnel_matches_portable_gateway_renderer` | Rendered support configuration equals `engineer.render(...)` | `[Interface]\nPrivateKey = ...\nAddress = 10.99.0.2/32\n\n[Peer]\n...` | `[Interface]\n\nPrivateKey = ...\n\nAddress = 10.99.0.2/32\n\n\n\n[Peer]\n\n...` |

Keys, endpoints, routes and keepalive fields are identical in the reproduction;
only line termination differs. The administrator expected endpoint/routes are
`pbx.example.net:51821` / `100.70.1.1/32`; support uses
`gateway.example.net:51820` / `10.20.4.2/32`. All use keepalive 25. Ellipses in the
table omit unchanged synthetic fixture keys and fields, not unknown observed data.

Root cause for all three: production `RenderTunnel` intentionally returns CRLF
bytes. The test-only `contract_tool` printed those bytes through Windows CRT text
stdout, producing CRCRLF; Python `text=True` converted CRCRLF into two newlines.
The one-line request/response/fingerprint assertions strip their final newline
and were unaffected, explaining the exact failure count.

Correction: set only the Windows contract helper's stdout to `_O_BINARY`, checking
the result, before writing any output. Production tunnel rendering, files,
authentication and route validation are unchanged. The Python contract adapter
now captures bytes first, rejects CRCRLF/lone newline corruption, decodes UTF-8
explicitly and converts valid CRLF to LF for the existing Python comparison.
It does NOT collapse blank lines or strip rendered configurations to hide errors;
the complete expected output includes its final newline.

Regression coverage rejects the exact simulated CRT corruption for both
administrator and support output, accepts unchanged renderer CRLF, and rejects
LF-only transport. Actual helper bytes are checked during all three rendered
configuration assertions on both platforms. This local byte-level reproduction
does not execute MSVC or establish actual Windows/OpenSSH success; the next native
run must confirm the fix and expose any distinct assertions in its full logs.

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
