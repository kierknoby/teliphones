# TELIPHONES 0.2.0

TELIPHONES is an open-source FreePBX module for administrator-owned PBX connections and locally authorised, time-limited remote support. The module is located at `teliphones/` and appears under **Connectivity > TELIPHONES**, including **Windows workstations**.

The current repository development milestone is **0.2.0**. The Module Admin package is `TELIPHONES-0.2.0.tgz`. This milestone integrates Windows workstation approval, temporary or explicitly persistent pairing, direct WireGuard access to the PBX web interface and separately approved SSH, plus individual revocation and handshake status. It preserves the 0.1.3 live-status support workflow and existing FreePBX 17 authentication and security controls. The native Windows executable has compiled and launched in user-run Windows testing; end-to-end Windows/PBX connectivity remains to be tested. This is not a production release.

## ⚠️ Not Currently Suitable for Production

TELIPHONES remains experimental. Module Admin installation and the root broker bootstrap have been verified on a Debian 12 / FreePBX 17 test PBX, but it has not completed end-to-end network, interruption-recovery or adversarial security testing. Do not install it on a production PBX or gateway.

## Project Contents

- [`teliphones/README.md`](teliphones/README.md): module setup, compatibility status and security limitations.
- [`teliphones/docs/`](teliphones/docs/): provider-neutral Connect, Checker and Console contracts, integration and testing guides.
- [`gateway/README.md`](gateway/README.md): separate reference gateway, engineer/Checker tools and disposable Linux namespace laboratory.
- [`desktop/windows/README.md`](desktop/windows/README.md): experimental native Windows client, pairing workflow, build instructions and test limitations.
- [`teliphones/docs/WORKSTATION-PAIRING.md`](teliphones/docs/WORKSTATION-PAIRING.md): administrator-owned workstation pairing contract.
- [`docs/RENDEZVOUS.md`](docs/RENDEZVOUS.md): direct-first, provider-neutral future rendezvous/relay design note.
- [`gateway/config.example.json`](gateway/config.example.json): placeholder-only gateway configuration template.

After installing through Module Admin, complete the one-time root broker bootstrap described in [Complete Installation on FreePBX 17](teliphones/README.md#complete-installation-on-freepbx-17); Connectivity > TELIPHONES shows the same commands. Remote support on the FreePBX 17 / Debian 12 target is not yet validated end to end. The reference gateway is separate from the module and is not deployed or production-certified. No managed Connect, Checker, Console service or infrastructure endpoint is supplied.

For the first Windows connection, follow [Windows workstations: install, pair and connect](teliphones/README.md#windows-workstations-install-pair-and-connect). Upgrading Module Admin alone is insufficient: rerun the root bootstrap with no active support session. The old 0.1.3 package contains broker protocol 2; 0.2.0 includes protocol 3 and verifies the workstation status contract, not merely its version number. Use a WireGuard UDP endpoint actually reachable from the workstation; no automatic router configuration, NAT traversal or relay is supplied.

## Local Tests

From the module directory:

```bash
php tests/run.php
```

From the gateway directory:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The real WireGuard namespace test requires a dedicated disposable Linux VM, kernel WireGuard support, `wg`, `ip`, `nft`, OpenSSH and root network-namespace capabilities. It must not be run on a production host. See [`gateway/README.md`](gateway/README.md) for the no-network preflight and test procedure.
