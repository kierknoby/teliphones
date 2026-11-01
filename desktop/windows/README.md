# TELIPHONES for Windows (experimental)

The native Windows client is under active development. It is a compact C++17 Win32/MFC application, not a .NET application. It has two profile types:

- **My PBX** pairs a workstation with a PBX using an approval in the PBX's TELIPHONES page. Persistent pairing remains revocable from that page. Temporary pairings expire on the PBX.
- **Remote Support** keeps a locally generated engineer key and imports an operator-issued `teliphones-engineer-grant/1` JSON file. The grant must name that exact engineer public key.

Both use WireGuard for Windows and the existing TELIPHONES PBX/gateway contracts. TELIPHONES does not create SSH accounts, expose ordinary PBX ports to the Internet, bundle WireGuard, or provide a relay. Direct WireGuard requires the configured PBX/gateway UDP endpoint to be reachable; restrictive NAT/firewalls can prevent it.

## Requirements and build

- Windows 10/11 x64.
- Visual Studio 2022 with the **Desktop development with C++** workload, Windows 10/11 SDK, and the optional **C++ MFC for latest v143 build tools (x86 & x64)** component.
- WireGuard for Windows installed separately by a Windows administrator. The application checks Authenticode signatures and uses its `wireguard.exe` and `wg.exe`; it does not download or install a driver.
- Windows OpenSSH Client is needed only for the **Open SSH** button.

Open `TELIPHONES.sln` in Visual Studio, select **x64**, then build. Or run `build.ps1` in a Visual Studio 2022 Developer PowerShell:

```powershell
.\build.ps1 -Configuration Release -Platform x64
```

The application and portable core tests are written to `build\Release\`. Run `build\Release\TeliphonesCoreTests.exe` to execute the core regression tests. The portable core and broker-contract tests can also be run on Linux with CMake:

```sh
cmake -S . -B /tmp/teliphones-windows-core
cmake --build /tmp/teliphones-windows-core
ctest --test-dir /tmp/teliphones-windows-core --output-on-failure
```

### GitHub Actions build and download

The [Windows build workflow](../../.github/workflows/windows-build.yml) builds the existing Visual Studio solution in **Release x64** on a GitHub-hosted `windows-2022` runner. It runs automatically when changes under `desktop/windows/` or the workflow itself are pushed. It can also be run from **Actions > Windows build > Run workflow** once the workflow is available on the repository's default branch.

The workflow discovers Visual Studio 2022 with `vswhere`, verifies the installed x64 MSVC tools, static Unicode MFC libraries and Windows SDK, and reports the selected versions. If anything is missing, it fails with the missing component or file path; it does not install Visual Studio components, drivers or other dependencies.

The workflow runs standard-library Python project/resource layout checks before building. After a successful MSVC build, it runs `TeliphonesCoreTests.exe`, checks that `TELIPHONES.exe` is an AMD64 Windows GUI PE executable without a .NET CLR header, verifies its embedded manifest and runtime imports, and launches malformed tunnel-helper requests to verify that the real executable loads and rejects them without UAC, networking or tunnel installation. This is not an interactive GUI or WireGuard integration test. The Python broker-contract tests are Linux-only because the root broker imports `pwd`; they are not run in this Windows job.

Download **TELIPHONES-Windows-x64** from the successful run's **Artifacts** section. It contains only `TELIPHONES.exe` and this README, not source archives, test binaries, keys, profiles, caches or tunnel configurations. The workflow prints the executable's SHA-256 in its verification log; artifacts are retained for 14 days. It creates no GitHub Release and deploys nothing.

Extract the artifact and run `TELIPHONES.exe` on Windows 10/11 x64. Release builds statically link MFC and the MSVC C/C++ runtime (`/MT`), so no separate Visual C++ Redistributable or MFC DLL is expected; Windows system DLLs remain required. No .NET runtime is used. WireGuard for Windows must still be installed separately by an administrator before pairing/connecting, and **Open SSH** requires Windows OpenSSH Client. An unsigned test executable may trigger Windows SmartScreen; the workflow does not code-sign it.

## Pair an administrator workstation

1. Install the FreePBX module and complete its documented root broker bootstrap. After upgrading the module, rerun the bootstrap with no active support session so the separately installed broker is current.
2. In TELIPHONES for Windows, select **Add my PBX...**, enter a workstation name, and choose **Generate request**. Copy the request.
3. In the PBX web interface, open **Connectivity > TELIPHONES > Windows workstations**, paste the request, provide the PBX's externally reachable WireGuard hostname/IP and UDP port, select temporary or persistent access, and explicitly choose whether SSH is allowed. The pairing operation requires HTTPS.
4. Copy the response into the Windows application. The client verifies the response nonce and workstation public key before saving it.
5. Connect. Windows requests administrative approval to install/start the individual tunnel service. Open the PBX GUI through the tunnel. SSH is offered only when the PBX administrator approved it and an SSH account was supplied.
6. To revoke access, use **Revoke** in the PBX's Windows workstations table. Persistent pairings do not expire automatically. Removing the local profile deletes its local private key but does **not** revoke the PBX-side pairing.

The PBX's WireGuard UDP listener must be reachable from the workstation. The pairing firewall rules restrict the paired peer to the PBX web interface and optionally SSH; they do not enable forwarding. Review the FreePBX Firewall and router policy for the selected UDP port. The client does not alter network routes beyond the per-PBX host route.

## Remote Support profiles

1. Select **Remote Support...** and generate an engineer key. The private key is saved in Windows Credential Manager for the current Windows user; send only the displayed public key to the gateway operator.
2. The operator must enroll that public key using their trusted gateway provisioning process and issue a current grant through the reference gateway's `engineer-grant` operator command. Deliver the grant JSON over a trusted channel.
3. Select **Import grant...** to import the grant. The application rejects a grant issued for a different public key.
4. Select an unexpired authorised session and connect. The generated tunnel routes only to that session's PBX `/32`; SSH uses the existing gateway contract on TCP port `22222`.
5. The gateway remains the authority for access. A grant does not itself authorise or extend a customer session.

The reference gateway is optional infrastructure and must be separately deployed and operated. It is experimental and is not included with the Windows application.

## Local data and permissions

- Profiles contain public pairing/grant data and are stored in the user's roaming application-data directory.
- WireGuard private keys are stored separately in Windows Credential Manager and are not written into the profile file or copied into the gateway grant.
- Tunnel configuration is staged in a user-restricted local directory, revalidated by an elevated helper, then placed under `%ProgramFiles%\TELIPHONES\Tunnels` with a restrictive ACL.
- Each tunnel is demand-started. The helper grants the current Windows user only the service rights needed to query, stop and remove that TELIPHONES tunnel; it does not grant permission to start or reconfigure it.
- UAC approval is required for tunnel installation. Declining it cancels the connection.
- Only one connection is active at a time. The app probes the PBX through the tunnel, displays session expiry, and requests disconnection on expiry or detected loss of PBX reachability. Normal application exit requests disconnection.
- Revocation detection is based on reachability checks, not a server-pushed revocation channel. A revoked but otherwise reachable/established flow may not be detected instantaneously; verify teardown behavior in the supported PBX/gateway environment before relying on it.

## Test plan and limitations

The C++ core tests and contract tests check parsing, key/request binding, grant binding, narrow host routes, tunnel rendering, command construction, connection monitor behavior, and parity with the broker/gateway contracts. They do not execute Win32 APIs.

The following require real Windows and a disposable FreePBX/gateway environment:

1. Build the Visual Studio solution with the selected Visual Studio/MFC components.
2. Install and signature-check the expected WireGuard for Windows distribution; verify `wg.exe` availability and CLI behavior.
3. Approve a UAC prompt and validate tunnel service installation, ACLs, start, stop, and removal, including cancellation and an over-the-shoulder administrator account.
4. Verify Credential Manager persistence, profile file permissions, multiple profiles, and cleanup.
5. Pair with a disposable FreePBX 17 system, test HTTP/HTTPS redirection, selected UDP forwarding and FreePBX Firewall behavior, and confirm the PBX's interface and peer are removed on revocation/expiry.
6. Test Remote Support only with an explicitly enrolled test engineer key, a current grant and an authorised disposable session. Confirm gateway policy blocks access after expiry/revocation.
7. Test direct connectivity across representative NAT/firewall configurations. No universal NAT traversal or relay is implemented.

No Windows executable is included in this repository. The local development environment does not have MSVC, MFC, or a Windows SDK. A Windows build is not verified until the first GitHub Actions run successfully completes the actual MSVC/MFC solution build and validation steps. Even after that build passes, UAC, Credential Manager, WireGuard driver/service behavior, visual layout and real PBX connectivity still require interactive Windows/disposable-PBX testing.
