# TELIPHONES®

**Private, administrator-approved access to FreePBX from the workstation you use every day.**

TELIPHONES connects a Windows workstation to FreePBX over a narrowly routed WireGuard tunnel. Administrators can open the PBX web interface and, when separately approved, start a managed SSH session for an existing Linux account without distributing permanent administrator credentials.

There are two distinct workflows:

- **My PBXs:** a full FreePBX administrator approves a workstation pairing. Access may be temporary or persistent until revoked. Managed SSH requires explicit approval of an existing account.
- **Remote Support:** a customer-authorised support workflow uses a separately enrolled engineer identity and a time-limited grant. It is distinct from workstation pairing and requires separately operated support infrastructure.

## Current development versions

| Component | Source version | Current status |
|---|---|---|
| FreePBX module | **0.9.0.1** | Unreleased maintenance target; controlled review only, not production-approved |
| Root broker | **0.9.0.1** | Independently installed component; matching module version and protocol 12 are required |
| Pairing / workstation-management protocol | **12** | Retained; no protocol change in the current module candidate |
| Windows application | **0.10.0** (file version **0.10.0.0**) | Unreleased development target; no matching successful CI run or downloadable artifact can be verified from this checkout; native acceptance remains outstanding |

The 0.9.0.1 maintenance update fixes a PHP template parse error and retains the 0.9.0.0 pairing behavior. These independently versioned components keep protocol 12 and existing v1/v2 pairing compatibility; the optional v3 response carries an administrator-confirmed HTTPS DNS hostname. Permanent workstation authority has no expiry and remains distinct from the short renewable active-session lease. Windows 0.10.0 is unchanged. Source versions and development artifacts do not establish production approval. No release or deployment is declared here.

For automatic Windows HTTPS hostname population, a PBX administrator must explicitly configure the DNS hostname covered by the trusted certificate. A valid v3 pairing response automatically populates Windows' editable hostname field with that configured value; a blank hostname is returned as unavailable and requires manual administrator confirmation. The broker does not inspect certificate SANs or infer the TLS name from the WireGuard endpoint. Windows retains normal TLS certificate validation. Changing the PBX management service URL requires a new pairing; changing only the certificate hostname does not.

## Start here

- [FreePBX installation, upgrade and administration](teliphones/README.md)
- [Windows download/build status, pairing and operation](desktop/windows/README.md)
- [Security model and evidence boundaries](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [FreePBX firewall diagnostics](docs/FREEPBX-FIREWALL-DIAGNOSTICS.md)
- [Windows build and readiness reference](desktop/windows/tests/WINDOWS-READINESS.md)
- [Separate module and Windows changelogs](teliphones/docs/CHANGELOG.md) · [Windows history](desktop/windows/CHANGELOG.md)

## Distribution and validation

The repository retains the earlier `TELIPHONES-0.8.3.15.tgz` archive and checksum and the prior `TELIPHONES-0.9.0.0.tgz` development package. The new `TELIPHONES-0.9.0.1.tgz` and its SHA-256 sidecar are generated locally as an unreleased maintenance package for controlled validation; neither is a release or deployment. Build the module-only package deterministically and validate its exact source contents and checksum:

```bash
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
	--mode='u+rwX,go+rX,go-w' --exclude='*/.*' --exclude='*/tests' \
	--exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
	-czf TELIPHONES-0.9.0.1.tgz teliphones
sha256sum TELIPHONES-0.9.0.1.tgz > TELIPHONES-0.9.0.1.tgz.sha256
sha256sum -c TELIPHONES-0.9.0.1.tgz.sha256
PYTHONDONTWRITEBYTECODE=1 python3 teliphones/tests/package-validation.py
```

Follow the [module guide](teliphones/README.md#installing-the-module) and [upgrade procedure](teliphones/README.md#updating-teliphones) only for authorized controlled testing after reviewing the package. Module Admin does not necessarily update the separately installed root broker; repeat the documented root bootstrap and verify both component versions and protocol 12. Preserve a working root/console route and use a disposable PBX for acceptance. Do not treat local regression tests as production approval.

The Windows CI workflow defines build, test and artifact-upload steps, but the local checkout does not prove that a successful run produced a matching 0.10.0 artifact. It is not a published release or production-approved download. Native Windows recovery, service/driver, UI, and live PBX acceptance remain required. Follow the [Windows guide](desktop/windows/README.md#requirements-and-download) and its evidence-based upgrade instructions; verify the exact artifact provenance before use. No Windows feature is considered accepted solely because its source or portable tests build.

## Security and evidence boundaries

TELIPHONES complements FreePBX Firewall; it does not automatically close public management ports or replace router/host policy. Verify the private route before restricting an existing administration route. A reachable WireGuard UDP endpoint may require router port forwarding; no universal NAT traversal or relay is provided.

WireGuard authenticates the tunnel, but does not by itself prove PBX admission or application reachability. Closing a client session is not proof of server-side revocation or termination. Review the [security limitations and verification evidence](docs/SECURITY.md) before relying on the system. Do not share pairing responses, credentials, private keys, customer identities, or routable endpoints in diagnostics.

Historical test reports and investigation notes remain in versioned changelogs and development documents. They describe the evidence for their own versions and are not claims that current development has passed the same tests. The [0.8.0 development report](docs/DEVELOPMENT-0.8.0-REPORT.md) and [historical investigations](teliphones/docs/CHANGELOG.md) are retained for context.

## Development and tests

The repository contains the FreePBX module and broker in `teliphones/`, the native C++17 Win32/MFC client in `desktop/windows/`, optional gateway/lab code in `gateway/`, and project security/architecture documents in `docs/`. The module-only archive does not include the Windows application, gateway or project tests.

For local checks and disposable-system validation, see the [testing programme](teliphones/docs/TESTING.md) and [Windows readiness reference](desktop/windows/tests/WINDOWS-READINESS.md). Relevant PHP, Python, portable CTest, offline link and website tests should be run for the files changed. Passing portable tests does not establish native Windows behavior or live FreePBX compatibility.

## AI-assisted contributions

AI-assisted changes must include the repository’s required disclosure in their commit message; human contributors remain responsible for the work. See the [AI disclosure policy](teliphones/README.md#ai-assisted-contributions-and-disclosure).

## Support

Maintained by [FreePBX UK](https://github.com/freepbxUK). See [support and feedback](teliphones/README.md#support-and-feedback) for guidance on sharing sanitized evidence. Report suspected security issues privately through [FreePBX UK support](https://freepbx.uk/support/), not a public issue.

## Licence

**TELIPHONES is a UK registered trademark.** TELIPHONES is licensed under GPL version 3 or, at your option, any later version (`GPL-3.0-or-later`). The product footer uses “licensed under GPLv3” as shorthand; software licensing does not grant trademark rights. See [LICENSE](LICENSE). Windows distributions also include third-party licences.

## Author

[@kierknoby](https://github.com/kierknoby), Kieran Knowles-Byrne // [FreePBX UK](https://github.com/freepbxUK)
