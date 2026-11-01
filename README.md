# TELIPHONES 0.1.3

TELIPHONES is an open-source FreePBX module for locally authorised, time-limited remote support. The module is located at `teliphones/` and is intended to appear under **Connectivity > TELIPHONES**.

The current repository development milestone is **0.1.3**. The Module Admin package is `TELIPHONES-0.1.3.tgz`. This milestone adds live status and progress monitoring to the browser support workflow and documents the root broker bootstrap, including rerunning it after upgrades. It preserves the FreePBX 17 compatibility corrections and authentication fixes from earlier iterations; it is not a production release or proof of end-to-end connectivity.

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
