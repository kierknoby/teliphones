# Connectivity investigation and release gate

## Confirmed history

The available repository history, including all local refs and pre-944c4b3
workstation implementations, does **not** establish a release in which
TELIPHONES itself permitted new public WireGuard UDP flows through FreePBX
Firewall. A last-known-working arbitrary-public-IP release cannot be identified
from this evidence.

- `2c8bb22` introduced workstation pairing and the UDP listener. Its nft input
  policy restricted decrypted traffic on `tlp-admin`; it did not open the public
  UDP listener in other host firewalls.
- `3a804b4` hardened nft enforcement, not public listener reachability.
- `c80619e` introduced `teliphones-ws`: per-peer TCP 80/443 and optional SSH,
  reached through an interface-scoped INPUT jump. Public UDP packets arrive on
  the WAN interface and cannot match that jump.
- `07c6e36` corrected nft ownership detection, not listener permissions.
- `e088c7f` added managed SSH/API permissions, not public UDP.
- `944c4b3` moved that same interface-scoped jump into `fpbxfirewall`, preserving
  Fail2Ban precedence and removing the intrusive INPUT rule. It did **not**
  remove an existing TELIPHONES UDP permit: none existed in the earlier code.

Thus 0.4.1 exposed an older missing listener-permission requirement; calling it
a proven removal of previously implemented UDP functionality is unsupported.
Reset windows, a trusted network, an existing custom service, or established
UDP conntrack could explain earlier successes. **None is proven for the live
PBX.** A stale peer endpoint and unanswered captured initiations cannot identify
the dropping rule, nor exclude wrong keys or another independent filter.

## Packet path and ownership

The reported INPUT order is Fail2Ban, then `fpbxfirewall`. Public UDP skips the
interface-scoped `teliphones-ws` jump. Upstream FreePBX 17 then checks RTP,
blacklist/signalling/smart hosts/registrations, networks, hosts and interfaces
(including zone service permissions), reject/responsive policy, established UDP,
and finally `fpbxlogdrop`. Installed versions and configuration must be inspected;
this is not a trace captured on the live PBX.

With iptables-nft these are nft `ip filter` rules; legacy iptables is a separate
hook traversal. TELIPHONES' `inet teliphones_workstations` input chain runs at
priority -10. It does not drop ordinary WAN packets. An nft ACCEPT is not final
across other base chains: an earlier or later independent DROP still wins.
Decrypted WireGuard packets traverse input again on `tlp-admin`, where peer
AllowedIPs, nft restrictions and per-peer TCP integration apply.

The correction uses FreePBX's persistent **Custom Service API**:
`addCustomService`, `editCustomService`, `setCustomServiceZones`,
`getAllCustomServices`, and `deleteCustomService`. The root broker requests
reconciliation through the root-only `fwconsole teliphones listener` action.
FreePBX owns generated UDP rules and restores them on its normal daemon cycle;
the broker does not add a competing raw UDP rule or restart/disable Firewall.
The one named service permits only the active listener port in external,
internal and other zones. Trusted already accepts traffic; reject/blacklist
and Fail2Ban are deliberately not bypassed. No workstation public IP is stored.
Cryptographic authentication remains WireGuard's responsibility.

The atomic root-only ownership journal identifies the service, unique creation
name and previous/requested port. Intent is persisted before FreePBX mutations,
allowing recovery after interrupted creation or editing.
Reconciliation is idempotent, updates rather than duplicates, and refuses edited
or unowned namesakes. The final unpair, shutdown and uninstall remove the owned
service. Removal is confirmed in both the API and generated IPv4 rules before
ownership is discarded. FreePBX applies database changes asynchronously: the helper
waits boundedly for the exact generated UDP service and zone jumps using read-only
iptables inspection, and reports an error if they do not converge. No kernel rules
are written by this verification. This checks generated configuration, not every
earlier blacklist, zone-selection or nft path. Pairing is not proof
of a handshake. Abrupt termination can leave a UDP service until broker recovery;
without the broker-created WireGuard interface this grants no management access.

Upstream reference inspected (not execution on FreePBX):
[Firewall.class.php](https://github.com/FreePBX/firewall/blob/release/17.0/Firewall.class.php),
[Iptables.class.php](https://github.com/FreePBX/firewall/blob/release/17.0/drivers/Iptables.class.php),
[daemon](https://github.com/FreePBX/firewall/blob/release/17.0/phar/src/firewall.php).
The branch is mutable; compare the installed module before release.

## Management ports

Previously the broker hard-coded TCP 80/443 in both policy layers and returned
`http://<tunnel-address>/admin/`. Windows independently required and reconstructed
that URL. Opening a custom TCP port alone could not fix this.

The module now offers saved `scheme:port` services (up to four), with an override.
When the current direct server port is not listed, the pairing form suggests
that service first instead of assuming 80/443. Reverse proxies require an
explicit backend-listener override; forwarded request headers are not trusted.
The first entry determines the paired URL. Both firewall layers replace their
old permissions when settings change. SSH/API reserved ports cannot be treated
as web services.

The broker reports local listening sockets covering the tunnel address.
**A socket is not proof of HTTP service, correct virtual-host routing, successful
TLS, redirects staying on the tunnel, or access from a remote peer.** Apache must
listen on the tunnel or wildcard address. TELIPHONES does not reconfigure Apache.
Use the checks below. Existing saved Windows profiles must be explicitly
re-paired after a scheme/port change; they cannot discover a new endpoint from
an unreachable old one. Updated Windows source preserves validated HTTP(S)
scheme/port through import, profile persistence and browser launch. URLs remain
bound to the allocated tunnel address and exact `/admin/` path. Connection Health
uses that URL's explicit port (or HTTP 80 / HTTPS 443), not an unrelated fallback.

## Read-only live-PBX verification (no deployment)

Use an independent existing console/root route. These commands do not change
configuration. Do not run reload, restart, flush, conntrack deletion or counter
reset commands. Do not export keys or full WireGuard configuration.

1. Establish installed provenance and service health:

   ```sh
   fwconsole ma list | grep -Ei 'teliphones|firewall'
   grep '^VERSION = ' /usr/local/lib/teliphones-broker/support_broker.py
   systemctl show teliphones-broker.service -p ActiveState -p MainPID
   iptables --version
   ip -4 address show dev tlp-admin
   wg show tlp-admin listen-port
   wg show tlp-admin endpoints
   wg show tlp-admin latest-handshakes
   ```

2. Record counters and every referenced chain, not just `teliphones-ws`:

   ```sh
   iptables-save -c
   nft -a list ruleset
   ss -lnpt
   ss -lnpu
   journalctl --since '-10 minutes' -u teliphones-broker.service --no-pager
   ```

   Inspect Firewall's Custom Services UI read-only: exactly one managed UDP
   service, correct port, external/internal/other enabled, reject not enabled.
   Follow installed `fpbxinterfaces`, network/host and zone chains to the
   generated service. Confirm INPUT retains Fail2Ban before FreePBX, one
   interface-scoped TELIPHONES jump inside FreePBX, and no new raw UDP jump.
   Independently inspect nft base-chain priorities and drops.

3. While an **already-paired** operator reconnects from an unfamiliar network,
   observe concurrently (replace WAN interface and UDP port if different):

   ```sh
   timeout 90 tcpdump -ni any 'udp port 51821'
   ```

   Compare handshake timestamps, endpoint and transfer counters before/after.
   Observe initiation and response, and the specific generated service counter
   increase. Repeat from a second unfamiliar network. Do not infer the dropping
   rule from packet arrival alone; compare relevant drop counters and existing
   logs without enabling tracing or changing rules.

4. On the PBX, inspect Apache configuration read-only:

   ```sh
   apache2ctl -S
   ss -lnpt
   ```

   Confirm the actual HTTP/HTTPS port binds wildcard or tunnel IPv4, not only
   loopback/public IPv4. From the authorised Windows peer use the exact paired
   URL, for example `curl.exe -I --max-time 10 https://100.97.10.1:8443/admin/`.
   Validate TLS normally (do not use `-k` as acceptance evidence). Inspect
   Location headers: redirects must not send administration outside the tunnel.
   Confirm GUI-only peers cannot reach SSH/API or another peer's SSH listener.

5. Observe at least five minutes of firewall logs and repeated read-only rule
   snapshots: no invading-rule reset loop, duplicates or unrelated changes.
   Broker restart, port-change, last-unpair and upgrade failure tests require
   **separately approved disposable-host testing**; they cannot honestly be
   certified by this read-only live procedure.

## Versioning and limitations

Module/broker 0.5.0 is a proposed feature target (configurable web ports), not a
released build. Windows remains the unreleased 0.7.0 development target; no
Windows binary was distributed. No archive from this working tree is a release.
No live PBX was accessed or changed. Local test results must be reported
separately from the outstanding FreePBX/watchdog, Apache and Windows-native
acceptance gates.

Local validation of the completed source:

- Module PHP/JavaScript suite: passed, including the new persistent-service API
  model (interrupted creation/edit recovery, zone failures, verified removal,
  generated-rule convergence fixtures, idempotence and ownership conflicts).
- Portable Windows CMake build with warnings as errors and all seven CTest
  entries: passed. Includes URL import/persistence/launch tests.
- The complete gateway suite passed: 156 tests, one skipped because `wg` is absent.
  Earlier interrupted-session failures are superseded by this complete run.
- Both real-packet iptables-nft/legacy labs invoke the actual PHP listener helper,
  exercising its saved ownership and read-only generated-rule verifier. The API
  and asynchronous FreePBX daemon are still models, not genuine FreePBX.
  UDP echo from two unfamiliar sources proves the modelled listener path,
  not WireGuard cryptography or real-world roaming.
- Historical archives are checked independently of current-package availability.
  The root-level 0.5.0 archive/checksum are retained for test installation;
  package validation checks extraction, metadata, source equality and integrity.
  This is not a published release or a live-PBX certification.
