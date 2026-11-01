# TELIPHONES

TELIPHONES is an open-source FreePBX module for locally authorised, time-limited remote support. The module is located at `teliphones/` and is intended to appear under **Connectivity > TELIPHONES**.

## ⚠️ Not Currently Suitable for Production

TELIPHONES remains experimental. It has not completed live FreePBX 17 installation, end-to-end network, interruption-recovery or adversarial security testing. Do not install it on a production PBX or gateway.

## Project Contents

- [`teliphones/README.md`](teliphones/README.md): module setup, compatibility status and security limitations.
- [`teliphones/docs/`](teliphones/docs/): provider-neutral Connect, Checker and Console contracts, integration and testing guides.
- [`gateway/README.md`](gateway/README.md): separate reference gateway, engineer/Checker tools and disposable Linux namespace laboratory.
- [`gateway/config.example.json`](gateway/config.example.json): placeholder-only gateway configuration template.

The FreePBX 17 on Debian 12 target is not yet validated. The reference gateway is separate from the module and is not deployed or production-certified. No managed Connect, Checker, Console service or infrastructure endpoint is supplied.

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
