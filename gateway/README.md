# TELIPHONES Reference Gateway

This is a standalone, provider-neutral Linux reference implementation of `teliphones-connect/1`. It is intended for a dedicated disposable lab. It is not production-certified and is not installed with the FreePBX module.

The gateway keeps customer peers, engineer peers and Checker peers on one dedicated WireGuard interface, then enforces session-specific communication with nftables. Every forwarded flow is denied by default unless its exact source engineer, destination PBX and TCP service are present in an expiring firewall set. Customer-originated forwarding, engineer-to-engineer traffic, cross-customer traffic, gateway-local management access and forwarding to physical interfaces are denied by these rules.

## Requirements

- A dedicated Linux gateway host or disposable VM, not a customer's PBX.
- Python 3.11 or newer; the service uses only the Python standard library.
- Debian 12 tools/packages: `wireguard-tools` (`wg`), kernel WireGuard support, `iproute2` (`ip`, `ss`), `nftables` (`nft`), `openssh-client` (`ssh`, `ssh-keygen`), `openssh-server` (`sshd`), `openssl`, `php-cli` with the OpenSSL extension, `python3`, `procps` (`sysctl`) and `kmod` (`modprobe`). `systemd` is required for the example gateway service unit.
- Explicitly provisioned TLS server/client certificates, WireGuard public/private keys, customer mTLS fingerprints and engineer public keys.
- `net.ipv4.ip_forward=1` configured by the operator on this dedicated gateway before service start. The service refuses to enable forwarding itself.
- A routing and firewall plan for the configured control API and UDP WireGuard listener. No endpoint or firewall opening is invented by TELIPHONES.

Do not install or run this service on a production gateway as a result of these instructions. No credentials or endpoints are supplied in this repository.

## Configuration and enrolment

Start with `config.example.json`; every `REPLACE_WITH_...` field is a placeholder and makes the file invalid until replaced through a trusted, out-of-band enrollment process. Store the final configuration root-owned with mode `0600`. The daemon rejects configs writable by group/other users.

The `customers` map binds a customer identity to the SHA-256 fingerprint of its TLS client certificate and an explicit allow-list of enrolled engineers. `ssh_engineer` selects the individual engineer whose SSH public key and tunnel address are returned for that session. Each engineer and the Checker have distinct WireGuard keys and unique `/32` addresses. Never share engineer private keys. Generate keys on the identity owner's workstation and transfer only public keys to the gateway.

The gateway API requires mutual TLS and maps the verified client certificate fingerprint to one customer. Every request also includes a random 256-bit request ID and timestamp; requests outside five minutes or with a replayed ID are rejected. The SQLite database retains session tombstones and pending cleanup reservations. Protect the database, audit log and TLS files as root-only gateway state.

## Session flow

1. Local TELIPHONES authorises a fixed session and creates its PBX WireGuard key locally. The private key never leaves the PBX.
2. The PBX submits a `teliphones-connect/1` provision request over mTLS. The gateway checks customer identity, session expiry, topology, addresses, collisions, enrollment and key reuse.
3. Provisioning installs the customer WireGuard peer and an exact host route, but creates no engineer service allowance.
4. TELIPHONES configures the gateway peer and confirms a fresh WireGuard handshake. The gateway enters `connected` and allows only the dedicated Checker probe port from the separate Checker peer for at most five minutes.
5. The Checker receives a separate grant, performs the restricted nonce/session probe from its authorized namespace, and negative/public TCP controls, then signs evidence using the pinned ECDSA P-256 key.
6. TELIPHONES validates the evidence, stops the restricted probe and sends the authenticated `activate` transition. The gateway opens only the customer's configured TCP service profile for its mapped engineers, with nftables element timeouts no later than the original session expiry.
7. TELIPHONES opens the local temporary SSH daemon separately. The returned SSH key/address is for one enrolled engineer. SSH remains on the PBX's private WireGuard address and port `22222`.
8. Revoke removes local access first, then requests gateway destruction. Gateway expiry also removes firewall elements, peer state, routes and addresses. If gateway cleanup is interrupted, the allocation remains reserved and startup reconciliation retries removal.

The API paths retain the existing protocol version:

- `POST /v1/support-sessions` provisions a closed peer.
- `POST /v1/support-sessions/confirm` requires a fresh PBX handshake and grants only the restricted Checker flow.
- `POST /v1/support-sessions/activate` changes Checker-only access to the configured engineer service profile.
- `POST /v1/support-sessions/destroy` revokes the exact customer/session/remote-id combination.

All calls use a customer certificate identity, not a bearer token. A valid-looking session ID alone is insufficient. The API does not expose an unauthenticated engineer enrollment or management endpoint. `engineer-grant` and `checker-grant` are local operator CLI actions and output only the enrolled peer identity and current authorized destination `/32`s; deliver their output through a separately trusted channel.

## Engineer and Checker clients

Create an engineer's private key on that engineer's workstation, set mode `0600`, and enroll only its public key. Retrieve a current grant on the gateway with:

```bash
python3 teliphones_gateway.py --config /etc/teliphones-gateway.json checker-grant
python3 teliphones_gateway.py --config /etc/teliphones-gateway.json engineer-grant engineer-a
```

Render the client config locally. The private key is read from the workstation and is not sent to or embedded by the gateway:

```bash
python3 engineer_config.py --grant /secure/path/engineer-grant.json \
  --private-key-file /secure/path/engineer-a.key \
  --output /secure/path/engineer-a.conf
```

The generated `AllowedIPs` consists only of current authorized PBX `/32`s. A grant does not confer gateway authorization; the gateway firewall independently binds access to the enrolled engineer identity and customer session.

The independent Checker tool requires separate authorized and negative-control network namespaces, with their own authenticated WireGuard peer configuration. The negative-control namespace must have a route to the test PBX so the test exercises gateway policy rather than merely missing client routing:

```bash
python3 checker_probe.py --challenge /secure/path/challenge.json \
  --private-host 10.20.17.1 --private-port 22221 \
  --authorized-netns teliphones-checker-authorized \
  --negative-netns teliphones-checker-negative \
  --public-host REPLACE_WITH_CUSTOMER_PUBLIC_ADDRESS --public-port 22221 \
  --private-key /secure/path/checker-ecdsa-p256.key > /secure/path/evidence.json
```

The positive result must be HTTP `204` from `/teliphones-checker/1` with exact session and nonce echoes. Negative and public controls check TCP reachability; any accepted TCP connection is exposure. The Checker signing key must be owner-only ECDSA P-256. Do not copy it to the PBX. The sample invocation is not a claim that the configured ports or FreePBX Firewall permit these tests.

## Service setup

`systemd/teliphones-gateway.service` is an example unit, not installed or enabled by this repository. Adjust its code path only after preparing a dedicated disposable Linux host. The service needs network administration capabilities for WireGuard, route and nftables operations. It deliberately does not enable forwarding. The API defaults to a loopback bind in code; configure a private management bind and restrict it with host/network firewalls plus mTLS before any lab client can reach it.

The gateway refuses to use support/engineer address pools that overlap each other or the existing gateway routes and addresses. It refuses to modify a pre-existing nftables table with an unexpected structure. Review all rules on a disposable host before enabling the unit.

## Tests

Run the local state, identity, route-generation and probe-protocol tests:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

First run the no-network prerequisite check. It requires the tools above, a loaded WireGuard kernel module, effective `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, root and a disposable Debian 12 VM. The preflight does not create namespaces or change networking:

```bash
python3 tests/wireguard_namespace_lab.py --preflight
```

The actual network-namespace test creates a gateway namespace, two PBX namespaces, two engineer namespaces, an independent Checker namespace and a simulated public-side namespace. It uses `GatewayService` against real namespace WireGuard/nftables commands, real TCP listeners on 80/443, temporary OpenSSH daemons on 22222, and the module's PHP `CheckerEvidence` challenge/accept implementation. It records handshake times, observed TCP source/destination identities, signed probe outcomes and host-preservation hashes without recording private keys. Run it only on a dedicated disposable Debian 12 VM after preflight; it waits for customer B's short expiry window:

```bash
sudo env TELIPHONES_LAB_CONFIRM=disposable-host \
  PYTHONDONTWRITEBYTECODE=1 python3 tests/wireguard_namespace_lab.py \
  --evidence /root/teliphones-lab-evidence.json
```

Run this only on a disposable Linux host. The lab tests actual WireGuard handshakes, Checker positive/negative/public probes, signed PHP Checker acceptance, customer-specific TCP service responses (including source/destination addresses), SSH public-key success/failure, unauthorised cross-customer denial, persistent SSH teardown, gateway-interface outage, automatic nftables timeout, expiry/reconciliation and host state preservation. Ports 80/443 use labelled raw TCP listeners; they are not FreePBX or HTTPS servers. The harness invokes `GatewayService` methods directly with real namespace commands; it does not exercise the HTTP mTLS server or restart the systemd daemon as a separate OS process. The outage case takes the gateway WireGuard interface offline while its process remains alive. Local authorisation is represented by root-generated lab session records, not by running `fwconsole`; local SSH termination is exercised by stopping only the test sshd process tree, not by invoking the PBX's systemd unit.

## Debian 12 Disposable Runbook

Prepare a fresh, dedicated Debian 12 VM with no production credentials, routes or interfaces attached. Take a VM snapshot before testing and keep its network disconnected from production networks. Do not run this lab on a production host. The test script does not install packages, load modules, deploy a public gateway or contact external services.

If the approved image lacks packages, install them on that disposable VM from its approved Debian repositories as an administrative preparation step. This repository does not run these commands:

```bash
apt-get update
apt-get install wireguard-tools iproute2 nftables openssh-client openssh-server \
  openssl php-cli php8.2-common python3 procps kmod
```

Verify the OS, packages, executables, kernel module, PHP extension and namespace capabilities:

```bash
test "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:12
dpkg-query -W -f='${db:Status-Status} ${binary:Package}\n' \
  wireguard-tools iproute2 nftables openssh-client openssh-server openssl \
  php-cli php8.2-common python3 procps kmod
for tool in wg ip nft sysctl ssh ssh-keygen ss openssl php python3; do
  command -v "$tool" || exit 1
done
test -x /usr/sbin/sshd
test -d /sys/module/wireguard
php -r 'exit(extension_loaded("openssl") ? 0 : 1);'
python3 --version
wg --version
nft --version
ip -V
sshd -V 2>&1 || true
grep '^CapEff:' /proc/self/status
python3 - <<'PY'
line = next(line for line in open('/proc/self/status') if line.startswith('CapEff:'))
caps = int(line.split()[1], 16)
assert caps & (1 << 12), 'CAP_NET_ADMIN is missing'
assert caps & (1 << 21), 'CAP_SYS_ADMIN is missing'
print('required network namespace capabilities: present')
PY
```

If `wireguard-tools` is present but `/sys/module/wireguard` is absent, verify that the VM kernel provides WireGuard and load it with `modprobe wireguard` on the disposable VM. The test script never invokes `modprobe`.

Before confirmation, inspect the VM and ensure it contains no production resources:

```bash
ip -brief link
ip -4 route show table main
ip -4 rule show
ip netns list
```

The lab assigns these roles:

- Customer PBX A and PBX B: isolated Linux namespaces with session-scoped WireGuard peers and labelled TCP/temporary SSH services.
- Support gateway: isolated namespace running the actual `GatewayService` methods, WireGuard peers, routes and nftables policy.
- Engineer A and Engineer B: separate WireGuard keys, addresses and SSH keys; generated grants restrict each to its assigned PBX.
- Checker: a third WireGuard key/address using the module's nonce responder and PHP ECDSA Checker validation.
- Public-side probe: a directly connected test namespace that attempts the simulated PBX public-side addresses.

The lab reports `BLOCKED` with exit code 77 if a tool, kernel module, capability or explicit disposable-host confirmation is missing. To run, use the evidence command above. A successful JSON report contains actual handshake timestamps and packet responses; retain it with the test VM details. It contains no private keys.

This verifies the reference data plane, not the production mTLS HTTP API or FreePBX installation. For a genuine PBX test, separately prepare:

- Customer PBX: disposable FreePBX 17 on Debian 12, the module, WireGuard kernel/tools, `iproute2`, `systemd`, OpenSSH server/keygen, PHP cURL/OpenSSL, and a customer-enrolled mTLS certificate/CA. Permit only the required outbound gateway control API and WireGuard UDP paths; do not change the router.
- Support gateway: a dedicated disposable Linux host, unique gateway key, API TLS identity, customer certificate fingerprints, individual engineer public keys, Checker peer and ECDSA P-256 trust process, explicit forwarding and reviewed nftables/network rules.
- Engineer workstation: standard WireGuard client, individually generated private key stored locally with mode `0600`, gateway-issued grant/config, and the separately enrolled session SSH private key. Do not distribute private keys through the API or logs.
- Checker: independently operated host or namespace with its own WireGuard identity and ECDSA P-256 private key; it must perform positive, negative-route and simulated-public checks before TELIPHONES accepts evidence.

After enrollment on disposable systems, follow the staged `authorise -> provision -> connect-confirm -> attest -> Checker -> activate -> open SSH -> revoke/expire` sequence in `teliphones/docs/INTEGRATION.md`. Test the browser against the PBX's existing hostname and certificate. The reference lab's raw TCP listener is not FreePBX; FreePBX Firewall, GUI authentication/TLS, actual port bindings and alternate management ports must be checked on that PBX. TELIPHONES does not alter Firewall policy.

## Current limitations

- No real WireGuard packets have been demonstrated in the current development container; `wg` is unavailable, the user is non-root, and the host is Ubuntu 24.04 rather than the target Debian 12 VM.
- The namespace lab uses root-generated local authorization fixtures and direct `GatewayService` calls. mTLS certificate verification, Connect HTTP replay behavior and actual `fwconsole` orchestration need a separate control-plane integration test.
- The outage case takes the gateway WireGuard interface offline; it does not kill the gateway OS process or systemd service. A separate disposable-VM test must interrupt the process and validate startup recovery.
- The FreePBX host has no automatically discovered GUI, HTTPS, SSH or PJSIP ports. The reference profile defaults to TCP `80`, `443` and `22222`; the operator must configure exact ports based on the disposable PBX. No firewall policy is changed on the PBX.
- FreePBX Firewall compatibility and customer certificate deployment remain untested.
- The reference gateway is a single-host lab service, not HA, clustered or production-hardened. Its TLS and WireGuard secrets, public reachability, firewall policy, backups, audit retention and recovery need independent operational review.
- The engineering portal, customer GUI approval flow, GUI/PJSIP diagnostics and real Console distribution are outside this gateway reference.