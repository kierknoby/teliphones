# FreePBX 17: workstation firewall integration investigation

The 0.8.0 authority, firewall and lease implementation is documented in the
[development and acceptance report](../teliphones/docs/DEVELOPMENT-0.8.0.md).
Unknown-public-IP FreePBX 17 connectivity remains unverified. Historical evidence
below does not validate this development candidate.

This runbook records the pending listener/admission investigation, read-only
evidence collection and historical 0.4.0/0.4.1 incident. It is not installation
instructions or an archive-availability statement. Current targets
are proposed, unreleased module 0.8.0, root broker 0.8.0, protocol 12 and Windows 0.8.5. A statically validated 0.8.0 development package is available, but it is not production-ready or live-accepted; the historical 0.6.7 archive was intentionally removed from this checkout and did not contain these changes. Use the
[current upgrade guide](../teliphones/README.md#updating-teliphones) for bootstrap;
account for dedicated Locked interfaces and configured management ports when
interpreting the shared-interface/default-port examples below. The preserved
0.6.3 archive predates the subsequent module-side web-only form correction
and listener diagnostics included in 0.6.4. Proposed 0.8.0 source additionally
contains 0.6.5 durable revocation and verified removal, the 0.6.6 nftables
feedback-loop correction, and correlated admission diagnostics; the local
0.6.7 archive predates and does not contain the correction documented below.

## Current evidence and scope

### Pending listener and admission correction — 13 November 2026

**Unreleased development candidate; not production-ready or live-accepted.**
A statically validated 0.8.0 development package exists locally. The historical
0.6.7 package is not included in this checkout and is not evidence that these
0.8.0 changes are installed.
The reported failure to administer
the affected PBX from an untrusted public IP remains unresolved in live evidence.
A WireGuard handshake, TCP 8766 reachability or an iptables ACCEPT alone does
not establish management admission or web-server reachability.

#### Confirmed local defects and corrections

- `FirewallListener::verifyRules()` originally waited about 15 seconds. FreePBX
  persists Custom Service configuration before its separate rule-generation
  cycle; inspected FreePBX 17 code has 15/30/120-second scheduling modes.
  The pending reconciler submits all additions/removals before verifying them
  against one shared 150-second deadline. The broker allows 180 seconds for
  the helper. Verification still requires exact generated rules and zone jumps;
  a timeout does not count as admission. The original timeout dates to
  `8e44678` (0.5.0). The last revision confirmed working on the affected PBX
  has not been identified, and timing is not proven to explain every live symptom.
- `Broker.expire_sessions()` compared leases after `active_sessions()` had
  already filtered expired entries, so it could leave their management permits
  installed. It now compares persisted leases before filtering and reconciles
  the nft policy. The defect is present in `c8840f9` (0.6.0). A real-packet
  baseline reproduction retained GUI/SSH access after lease expiry.
- The listener/interface now closes after the last pairing authorisation expires
  or is revoked, including under Open policy. Open still permits a new explicit
  administrator-approved pairing. Losing a transport lease or disconnecting
  does not revoke an otherwise valid pairing or extend its original deadline.
- `web_listening()` now reports an IPv6 wildcard as indeterminate for IPv4,
  rather than absent: `/proc/net/tcp6` does not expose `IPV6_V6ONLY`. This avoids
  a false negative but does not prove Apache accepts the private IPv4 address.
- A provisional handover change temporarily replaced `self.reconcile_listener`
  on the shared broker and deferred verification outside `wslock`. It was
  removed. It bypassed transaction verification, failure/backoff handling and
  the background read-only fast path. Reconciliation is serialized again;
  concurrent policy changes cannot overtake an in-flight listener transaction.

**0.8.0 correction:** generation-fenced listener jobs release the authority lock
while waiting, cancel and reap superseded writers, and reject obsolete completions.
See the linked development notes for current evidence and live acceptance limits.

The convergence error identifies the owned chain, requested UDP port (or
`removal`) and final rule/zone mismatch. Broker diagnostics retain only the
sanitised structured helper output; raw rules, keys and pairing material must
not be echoed. Capture the initiating error before cleanup changes the state.

#### Historical pre-0.8.0 local evidence

An earlier 13 November 2026 working-tree run completed 269 gateway Python tests:
267 passed and two skipped; its PHP regression runner passed. This is historical
and not current verification. The 15 November 2026 gateway run executed 272
tests: 244 passed, 27 skipped, none failed, and one errored because the PHP
checker bridge could not find `php`. The PHP regression runner was unavailable
and not run. The two wake-event failures found in the earlier focused
investigation were resolved by correcting the affected test fixtures to model
stable FreePBX listener ownership and generated firewall rules. Both targets
passed with original assertions intact; 96 related broker, listener scheduling
and concurrency tests also passed. This does not establish live FreePBX
behavior. That version held `wslock` during generation; 0.8.0 replaces this with generation fencing.
See the current development notes for evidence and remaining acceptance requirements.

Real WireGuard and nft/iptables-nft packet tests ran in disposable namespaces.
They exercised untrusted-source admission, roaming, approved-IP locking,
unknown-key and pre-admission denial, GUI/SSH TCP access, lease and pairing
expiry, revocation, reconnection and modelled FreePBX rule regeneration.
The management endpoints were TCP fixtures; these are not real Apache sign-in,
managed SSH authentication, production systemd/cgroup or live FreePBX-daemon
acceptance results. No live services or firewall settings were changed.

#### Read-only collection on the affected PBX

Use the independent FreePBX UK root console; no direct SSH access is assumed.
Capture a UTC timestamp alongside the failed attempt and run:

```bash
date -u
iptables -w 5 -t filter -S
nft -a list table inet teliphones_workstations
ss -ltnp '( sport = :443 or sport = :8080 or sport = :8766 or sport = :22002 )'
journalctl -u teliphones-broker.service --since '-15 minutes' --no-pager -o short-iso
cat /var/lib/teliphones/active-sessions.json
cat /var/lib/teliphones/firewall-listener.json
```

Adjust the TCP port filter to the approved GUI/SSH ports. These two JSON files
contain lease/ownership metadata, not private keys; share outputs privately and
redact unrelated addresses/identifiers consistently. Do not collect private keys
or complete pairing/enrolment files. Retain command errors as evidence.

Correlate the requested listener ports and failed chain with the ownership
journal and generated rules at the same time. Check the admitted workstation's
lease against UTC, and follow its exact interface/source/private destination
through both firewall layers. An iptables ACCEPT cannot override a later nft
DROP. Distinguish management refusal from a web server bound only to loopback or
a different address. Check the browser's actual destination and redirects:
management should use the approved private endpoint, not depend on public GUI
access. A Trusted-zone workaround conceals the failure rather than validates it.

#### Recovery and live acceptance boundary

Preserve the independent root console and collect evidence before changing state.
Do not automatically re-pair, trust an address, flush rules, restart services,
run the bootstrap or overwrite recovery journals. A failed/unknown cleanup
outcome requires administrator investigation; a successful handshake is not a
reason to disregard it. Any installation or service/firewall change needs a
separately approved plan identifying the exact candidate and rollback files.

After the concurrency limitation is addressed and a controlled installation is
approved, verify the installed helper contents rather than relying on 0.6.7
version labels alone. With FreePBX Firewall enabled and the test source outside
Trusted, demonstrate actual private GUI login and approved managed SSH login.
Also verify pre-admission and unknown-key denial, rejection from an unapproved
IP for Locked pairings, unlocked roaming and reconnection without extending
authorisation. Test lease expiry, final-pairing expiry/revocation and listener
closure, including while generation is delayed. With separate approval, test
normal FreePBX regeneration and confirm unrelated rules, VPN traffic and SSH
sessions are preserved. Record failed steps; do not declare the incident fixed
until management access from an untrusted public IP is demonstrated.

### Operator-confirmed listener subprocess overload

The operator observed changing `fwconsole teliphones listener --listen-port=51821`
PIDs, all parented by broker 0.6.2, almost every second on a single-vCPU Debian 12
/ FreePBX 17 system. CPU returned to 96--99% idle after the broker was stopped.
This confirms the operational CPU source; keep that broker stopped.

Both installed-version 0.6.2 code and the initial pending 0.6.3 code called
the listener command unconditionally in the stable Open background branch.
Every `ip filter` nft notification wakes that worker, including changes generated
by its own integration/FreePBX operations. Periodic ticks alone caused 241
commands in the 240-tick simulated reproduction. A modelled successful helper
emitting a filter event also reproduces the feedback path. The exact live
notification stream and whether any individual command failed were not captured;
neither asynchronous rejection nor nft transaction failure is required to
produce the unnecessary subprocesses.

The 0.6.6 broker correction, retained in historical 0.6.7 and proposed 0.8.0 source, checks desired ports
against the root-owned listener journal and exact generated IPv4 service/zone
rules before background helper invocation. It does not cache success without
checking kernel state or bypass explicit pairing/cleanup verification. Failed
background transactions use monotonic 5/10/20/40/60-second backoff after
cleanup, capped at one retry transaction per minute thereafter; transactions
can include both admission and cleanup commands. Events cannot bypass cooldown.
Authoritative policy changes invalidate that cooldown, and success resets it.
Access remains disabled after failure. FreePBX rule changes still trigger
readback and repair.

The observed `51821,58490` versus `51821` is consistent with a Locked workstation
attempt followed by rollback to the then-authoritative Open/zero-peer shared policy.
A regression covers that sequence without continued port oscillation. The
historical live attempt's exact requested source-lock policy remains unproven.
This fix is included in the preserved 0.6.6 package and subsequent source;
the superseded root-level 0.6.5 archive/checksum were removed. Review before
any controlled installation. Successful local regressions are not demonstrated
end-to-end pairing or live CPU acceptance.

The operator-supplied FreePBX Firewall 17.0.1.35 snapshots contained one UDP
51821 ACCEPT and exact external/internal/other zone jumps for the owned service.
Those snapshots pass the actual admission predicate and fail the removal
predicate. They were captured after the failure, not at the failed verification.
In that earlier implementation, an Open policy with no paired workstations
could subsequently restore the shared listener through background reconciliation.
The pending correction closes listeners when no pairing authorisation remains. Neither those snapshots nor
matching installed-source hashes establish successful pairing or the initiating
transient failure. A missing dedicated Locked listener, incomplete generation,
or stale removal rules must be distinguished using the failed chain/port and
matching read-only API/kernel evidence; none is yet established as the cause.

In the investigated pre-0.8.0 implementation, pairing dispatch held `wslock` through admission, failure teardown
and restoration of the previous policy. Background `expire_workstations()`
acquires the same lock. The PHP listener helper additionally holds the ownership
journal's exclusive file lock through API changes and kernel verification.
The broker background worker therefore cannot recreate a listener during pairing
cleanup. Failure teardown verifies listener removal while interfaces are down;
only after successful cleanup does rollback restore the previous policy.
With the pending correction, restoring an empty Open policy verifies listener
removal again; it does not recreate a listener without an authorised pairing. These are separate transactions,
not contradictory simultaneous desired states. FreePBX's own asynchronous
generator is not protected by these TELIPHONES locks.

The broker now journals failed listener commands at the failure point, before
cleanup changes the progress stage. Diagnostics distinguish admission ports
from removal, include exit status and separately sanitise stdout/stderr. Only
the helper's structured convergence diagnostic is retained; unrecognised output
is explicitly withheld, not silently discarded. When admission and cleanup both
fail, the returned error retains the initiating failure as well as the cleanup
failure. Simulated concurrent-worker and PHP/socket regressions verify these
boundaries; they do not establish live FreePBX generation timing or successful
end-to-end pairing.

During module **0.4.0** / Windows **0.7.0** WireGuard and SSH testing on
FreePBX 17 / Debian 12, the operator reports intermittent PBX connectivity.
The journal identifies the exact TELIPHONES INPUT rule as an invader above
FreePBX Firewall, followed by "Resetting iptables", approximately every 41
seconds. This is separate from the earlier 0.3.1 nftables ownership correction.

The local source explains the loop: `firewall_integration()` inserted the
marked jump immediately above `fpbxfirewall` in INPUT. The broker restored that
placement after each firewall rebuild (nft monitor wakeups or the periodic
check). FreePBX's reported ordering self-check rejected it again. Successful
WireGuard handshakes or SSH between resets do not establish coexistence.
The journal establishes why this rule was rejected; without local FreePBX
source it does not establish every watchdog check or the origin of its interval.
No external search or live PBX operation was performed.

The latest operator report also confirms successful Windows builds, ten native
OpenSSH integration tests passing, initial authenticated SSH into this test PBX
and owned-terminal closure on disconnect. Those observations against 0.4.0
do not establish real 0.4.1 watchdog stability or complete PBX-side session
termination. See the [evidence register](SECURITY.md#verification-evidence).

**Source correction:** keep FreePBX's INPUT hook in place, remove only the
exact marked legacy jump, and insert that same narrow jump at position 1
**inside `fpbxfirewall`**. Only this owned jump is edited in the FreePBX chain.
Only the owned, marker-validated `teliphones-ws` chain may be rebuilt/deleted.
Unmatched packets return to the existing FreePBX rules. No trust zone/subnet,
blanket ACCEPT, Custom Rules setting, firewall service change, or policy flush
is used. Existing certificate SSH authentication, approved accounts, dedicated
listeners, WireGuard peers/AllowedIPs and nft restrictions are unchanged.
Local tests pass against a simulated layout, not the actual FreePBX watchdog.
The correction is packaged as `TELIPHONES-0.4.1.tgz`. The older
`TELIPHONES-0.4.0.tgz` remains unchanged and does not contain this correction.
Rerun the root bootstrap after upgrading and verify the installed broker is 0.4.1.

Do not disable FreePBX Firewall to reproduce this issue. If it is currently
disabled, report that first: restoring it is an operational change requiring
administrator approval and a recovery path, not part of this read-only runbook.
Do not flush rules, change zones/alternatives, unban addresses, restart services,
rerun the bootstrap, re-pair, or change permissions while collecting evidence.
No live PBX commands have been executed by the development assistant.

Run the following on the PBX from an existing root shell. Missing commands,
chains, services and files are findings: retain their errors; do not install
anything. Outputs contain network metadata and ban lists; share privately,
redacting unrelated identities consistently. Never share private keys, complete
configuration/state files, browser cookies or authentication headers.

## Implementation trace

The authoritative code is [support_broker.py](../teliphones/support_broker.py)
and [BrokerBootstrap.php](../teliphones/BrokerBootstrap.php).

| Stage | Actual implementation and boundary |
|---|---|
| Installation | Module files and the root-owned running broker are separate. Module Admin need not update `/usr/local/lib/teliphones-broker/support_broker.py` or `ssh_authority.py`. A module version or protocol 5 alone cannot prove broker revision. |
| Startup | `serve()` disables workstation access, starts the nft monitor and calls `restore_workstations()`. Persistent and unexpired entries are loaded from root-owned state. |
| Admission | `apply_workstations()` disables `tlp-admin`, installs and reads back the complete owned nft policy, configures the WireGuard interface and peers, reconciles iptables, then brings the link up. |
| Address binding | The PBX uses the first host (`.1`) of its saved `/24`; every WireGuard peer has its own saved `/32` AllowedIPs. The iptables rule requires that source, that PBX destination, `tlp-admin`, TCP and port 80/443. Legacy SSH-approved peers retain 22; managed peers instead get 8765 and their own SSH port. No LAN-IP or arbitrary-port exception is installed. |
| iptables backend | Only the first available `/usr/sbin/iptables` or `/sbin/iptables` is used. It is not automatically switched to whichever backend contains FreePBX Firewall. |
| Placement | `integration_inventory()` validates ownership and all references. `firewall_integration()` removes exact legacy INPUT jumps first, requires a **direct INPUT** jump/goto to `fpbxfirewall`, and installs one marked `tlp-admin` jump first inside that chain. All direct `fail2ban-*` / `f2b-*` INPUT targets (case-insensitive) must precede entry. FreePBX classification is skipped only for precisely matching ACCEPTs; INPUT is never reordered or given new TELIPHONES rules. |
| Fail2Ban | A recognised Fail2Ban hook after `fpbxfirewall` causes withdrawal and `error`, not bypass. Nested hooks, alternative names and independent nftables chains are not inspected by this placement algorithm. Independent drop verdicts still apply. |
| Reconciliation | `NftMonitor.event()` wakes the worker for `ip filter` events; legacy iptables relies on periodic execution. `expire_workstations()` also verifies the owned nft policy. If the interface is UP and policy valid, only integration is reconciled, without bouncing peers. Stable checks issue no writes; own iptables events may trigger an extra read-only pass, not another rewrite. |
| Updates and readback | Parsed rules are compared to `integration_rules()`. Only a differing owned chain is flushed/repopulated; only missing, duplicate or misplaced owned jumps are deleted/reinserted. Full inventory and placement are read back. `-w 5` applies per command, not across the whole transaction; races cause withdrawal/error rather than INPUT repair. |
| Removal | `teardown_workstations()` verifies interface disable/removal, closes managed SSH, removes exact old/current jumps and the owned iptables chain, then the owned nft table. An iptables error does not skip nft cleanup. `uninstall_workstations()` retains pairing/key recovery state unless cleanup succeeds. Unmarked rules or unexpected references are not touched. |
| Missing hook / recoverable error | The owned iptables integration is removed and status becomes `not-detected` / `error`. With verified nft restrictions, the link may remain UP and handshakes may succeed; FreePBX still decides web access. A later successful iteration can restore the rules. |
| Hard failure | Unverifiable integration removal, policy/monitor failures or other enforcement failures disable access. The ordinary integration-only branch does not raise an externally DOWN/absent link; monitor failure or a terminated worker requires repair, not an assurance of automatic recovery. |

The worker waits approximately 15 seconds **between** iterations unless woken.
That is not a guaranteed repair deadline: locks, subprocess timeouts, ongoing
firewall rewrites and failures can delay or prevent recovery. `-w 5` serialises
each iptables command, not the entire read/modify/verify transaction with
FreePBX. Installation is read back, but a concurrent subsequent rewrite can
invalidate it again. There is no FreePBX reload callback or ordering dependency
on its firewall service in the broker's systemd unit.

An `active` integration status is the last successful rule verification, not a
packet-path probe. An earlier INPUT drop, another iptables backend, a different
nftables base chain, output filtering or an Apache redirect can still prevent
access. Do not move the exception ahead of Fail2Ban to work around a block.

## Required real-PBX acceptance (not performed)

Use a disposable PBX or an approved maintenance window with an independent
console/recovery route. The read-only collection below is not deployment approval.

1. Verify the separately installed root-owned broker matches reviewed source
   and that its process started after installation. Keep FreePBX Firewall and
   Fail2Ban enabled, Custom Rules disabled, and capture INPUT, `fpbxfirewall`,
   all policies and unrelated rules before testing.
2. Observe for at least five minutes (multiple reported 41-second cycles).
   No TELIPHONES rule may appear in INPUT. There must be exactly one marked
   jump at the start of `fpbxfirewall`, after all INPUT Fail2Ban hooks.
   The journal must show no TELIPHONES-related invading-rule/reset loop.
3. With explicit approval, exercise actual FreePBX firewall reload/restart and
   Fail2Ban restart. After rebuild, expect temporary fallback to FreePBX policy,
   then exactly one internal jump, without peer/link churn or repeated resets.
4. Reconnect/disconnect Windows 0.7.0 repeatedly, restart the broker and PBX,
   and test persistent and unexpired/expired temporary pairings. A Windows
   disconnect alone leaves pairing authorisation intact; it must not duplicate
   or broaden rules. Deadlines must not extend across restart.
5. Test web-only and managed certificate SSH peers, pinned host keys, approved
   accounts, renewal, expiry, revocation and active-session termination. System
   SSH must not be granted to a managed peer; another peer's dedicated port,
   unknown sources, other PBX destinations, SIP/RTP/AMI/DB, IPv6 and forwarding
   over `tlp-admin` must remain denied. Preserve existing legacy SSH permission.
6. During these operations, run an ordinary SIP call with bidirectional RTP,
   unrelated authorised management sessions and representative denied probes.
   Compare unrelated rules/policies and their packet outcomes to baseline.
7. Test revoke-all, disable, shutdown and uninstall. Verify absence of both
   legacy/current marked jumps, the owned chain/table, listeners and interface;
   verify unrelated rules/policies remain unchanged and failure retains recovery
   state. Do not remove state by hand to hide a cleanup failure.

## 1. Identify installed code, running service and tools

```bash
date -Is
uname -sr
systemctl show teliphones-broker.service \
  -p ActiveState -p SubState -p MainPID -p ExecStart -p ExecMainStartTimestamp -p NRestarts
systemctl cat teliphones-broker.service --no-pager
systemctl list-units --all --type=service --no-pager |
  grep -Ei 'firewall|fail2ban|apache2|teliphones'

python3 -I - <<'PY'
from pathlib import Path
import hashlib
import xml.etree.ElementTree as ET

module = Path("/var/www/html/admin/modules/teliphones")
print("Module version:", ET.parse(module / "module.xml").findtext("version"))
for path in (module / "support_broker.py",
             Path("/usr/local/lib/teliphones-broker/support_broker.py")):
    data = path.read_bytes()
    print(path, "SHA256:", hashlib.sha256(data).hexdigest(),
          "mtime_ns:", path.stat().st_mtime_ns)
PY

readlink -f /usr/sbin/iptables
readlink -f /sbin/iptables
for tool in iptables iptables-nft iptables-legacy nft; do
  if command -v "$tool" >/dev/null 2>&1; then
    "$tool" --version
  else
    printf 'Unavailable: %s\n' "$tool"
  fi
done
journalctl -u teliphones-broker.service --since '-30 minutes' --no-pager -o short-iso
```

The module path above is the repository's documented default. If customised,
use the actual module location. Compare the two broker hashes and the source
hash from the reviewed checkout. A matching on-disk hash still does not prove
what a long-running Python process loaded: compare its start time with the
deployment history. Do not restart it just to make the hashes appear correct.

## 2. Read the broker's own status and approved addresses

Refresh **Connectivity > TELIPHONES > Windows workstations** and retain the
complete integration state, message, backend, PBX address, workstation address,
SSH flag and last handshake time. Refresh again after the packet test.

For the same read-only status directly, use the permitted `asterisk` identity;
root itself is deliberately not accepted on the control socket:

```bash
runuser -u asterisk -- /usr/bin/python3 -I - <<'PY'
import json
import socket

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(15)
    client.connect("/run/teliphones/control.sock")
    client.sendall(b'{"action":"status"}\n')
    data = bytearray()
    while b"\n" not in data:
        chunk = client.recv(4096)
        if not chunk:
            raise SystemExit("Broker closed before completing its status response")
        data.extend(chunk)
        if len(data) > 1024 * 1024:
            raise SystemExit("Broker status exceeded the diagnostic limit")
response = json.loads(data.split(b"\n", 1)[0])
if response.get("ok") is not True:
    raise SystemExit("Broker status failed: " + str(response.get("error")))
status = response["status"]
print(json.dumps({key: status.get(key) for key in
                 ("protocol", "server_time", "enabled", "workstations")}, indent=2))
PY

python3 -I - <<'PY'
from pathlib import Path
import ipaddress
import json
import time

state = json.loads(Path("/var/lib/teliphones/workstations.json").read_text())
print("Capture epoch:", int(time.time()))
print("Subnet:", state["subnet"], "UDP listener:", state["listen_port"])
print("Expected PBX address:", str(ipaddress.IPv4Network(state["subnet"])[1]))
for item in state["workstations"]:
    print({key: item.get(key) for key in
           ("id", "address", "mode", "ssh", "expires_at")})
PY

ip -details link show dev tlp-admin
ip -4 address show dev tlp-admin
ip -4 rule show
ip -4 route show table all
wg show tlp-admin listen-port
wg show tlp-admin allowed-ips
wg show tlp-admin latest-handshakes
wg show tlp-admin transfer
```

These `wg` subcommands do not print private keys. Do **not** substitute
`wg showconf` or `wg ... dump`. State output is deliberately field-limited.
The source in an observed SYN must equal the active peer's saved `/32`;
its destination must equal the `.1` PBX address, not the public/LAN address.
An expired pairing is not eligible just because its JSON entry still exists.

## 3. Capture every relevant filtering layer, with counters

```bash
iptables -w 5 -t filter -S
iptables -w 5 -t filter -L -n -v -x --line-numbers
for tool in iptables-save iptables-nft-save iptables-legacy-save; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '\n=== %s (all tables, counters retained) ===\n' "$tool"
    "$tool" -c
  else
    printf 'Unavailable: %s\n' "$tool"
  fi
done
nft -a list ruleset
fail2ban-client status
ss -ltnp '( sport = :22 or sport = :80 or sport = :443 )'
```

Keep the complete INPUT path, including any earlier jumps/drops, matching
Fail2Ban chains, `fpbxfirewall`, interface classification and final verdicts.
Inspect both backends: `nft list ruleset` does not expose legacy iptables.
Also inspect native `inet`/`ip` ingress, prerouting, input and output hooks and
any other tables that can drop packets. Do not infer the decision from the
TELIPHONES table alone. Query individual jails using only names returned by
`fail2ban-client status` (for example `fail2ban-client status sshd` **if listed**);
do not remove a ban.

To establish how this PBX generates rules without assuming FreePBX APIs:

```bash
fwconsole firewall --help
find /var/www/html/admin/modules/firewall -maxdepth 2 -type f \
  \( -name '*.php' -o -name '*.sh' \) -print
grep -RInE --include='*.php' --include='*.sh' \
  'fpbxfirewall|iptables(-restore)?|fail2ban|zone-external' \
  /var/www/html/admin/modules/firewall | head -n 160
```

This only reads locally installed code/help. No FreePBX Firewall source is
available in this repository, so the real regeneration logic cannot be
established here. Retain the matching file locations for a bounded follow-up;
do not dump unrelated configuration or run a firewall action.

## 4. Correlate one web attempt with actual packets

Keep the firewall enabled throughout. Enter the actual addresses from step 2;
do not copy an illustrative subnet from a test:

```bash
read -r -p 'PBX tunnel IPv4 address: ' PBX
read -r -p 'Paired workstation tunnel IPv4 address: ' WS
ip -4 route get "$WS" from "$PBX"
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.tlp-admin.rp_filter
iptables -w 5 -t filter -L -n -v -x --line-numbers
```

If `tcpdump` is already available, run this bounded connection-setup capture in
one PBX terminal. It selects SYN/FIN/RST packets, not normal HTTP requests.
Do not add `-A`, `-X` or write a packet capture file:

```bash
timeout 35 tcpdump -ni tlp-admin -nn -s 96 -c 60 \
  "host $WS and host $PBX and tcp and (port 80 or port 443) and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0)"
```

While it is running, try **Open FreePBX** once on the Windows workstation and
record the requested URL, error, any redirect destination and timestamp. The
application opens `http://<PBX tunnel address>/admin/`, not an arbitrary LAN URL.
An optional Windows PowerShell probe, using the same actual PBX address, is:

```powershell
$pbx = Read-Host 'PBX tunnel IPv4 address'
curl.exe --noproxy '*' --connect-timeout 5 --max-time 10 --head "http://$pbx/admin/"
curl.exe --noproxy '*' --connect-timeout 5 --max-time 10 --head "https://$pbx/admin/"
```

Use the probes only if `curl.exe` is already installed. No login, redirect
following or certificate-validation bypass is used. A certificate error is
different from a TCP timeout. A redirect to a LAN/public hostname, another port
or an untrusted HTTPS certificate needs separate investigation, not a broader
firewall exception. A proxy bypass here distinguishes direct tunnel access
from the browser's proxy configuration; it changes no permanent settings.

Immediately repeat step 3's counters and broker status. Use deltas; **never
zero counters**. An optional PBX-local HTTP HEAD with the same destination can
check Apache's response, but is not proof of tunnel ingress:

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 10 --head "http://$PBX/admin/"
journalctl -u apache2 --since '-10 minutes' --no-pager -o short-iso
```

TCP 22 reaching SSH proves neither TCP 80/443 nor Apache authentication.
Windows marks a connection verified after a TCP connection to **either** 443
or 80, not an HTTP response or successful SSH login. Subsequent probe failures
can cause automatic disconnection; correlate link/service state and timestamps.

## 5. Observe reconciliation without triggering a reload

```bash
for delay in 0 5 15 20; do
  sleep "$delay"
  date -Is
  for tool in iptables iptables-nft iptables-legacy; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '\n=== %s ===\n' "$tool"
      "$tool" -w 5 -t filter -S INPUT
      "$tool" -w 5 -t filter -S fpbxfirewall
      "$tool" -w 5 -t filter -L teliphones-ws -n -v -x --line-numbers
    fi
  done
  ip -brief link show dev tlp-admin
done
journalctl --since '-10 minutes' --no-pager -o short-iso \
  -u teliphones-broker.service -u fail2ban.service
```

Snapshots occur around 0, 5, 20 and 40 seconds. Refresh the GUI integration
message alongside them. If nft is present, `timeout 45 nft monitor ruleset`
in another terminal can observe rule regeneration without requesting changes.
It cannot observe legacy iptables changes; repeated backend snapshots still
matter. Capture the firewall service's journal using the **actual unit name**
discovered in step 1, plus the time of any already-occurring scheduled reload.

No command here restarts/reloads FreePBX Firewall. Testing an induced reload,
restart or Fail2Ban reorder requires separate approval and a maintenance plan.
Do not claim real reload recovery from a quiet 40-second observation.

## Evidence decisions and next action

| Evidence | What it establishes / next step |
|---|---|
| Module and root broker hashes differ, or running process predates deployment | Revision uncertainty. Review exact differences; updating/restarting requires approval, not automatic bootstrap. |
| `fpbxfirewall` only exists on the other backend, or is reached through a wrapper | Current hook discovery does not cover this layout. Review the real complete path, especially Fail2Ban, before designing a correction. Do not switch system alternatives. |
| Named Fail2Ban hooks follow `fpbxfirewall` | The broker deliberately withdraws integration. Preserve all bans; do not insert an exception ahead of them. A safe correction requires the actual jail/path semantics. |
| No tunnel SYN during a direct attempt | Confirm active Windows tunnel, requested destination and routes. A handshake alone does not establish a web packet path. |
| SYN appears, but TELIPHONES jump/ACCEPT counters do not increase | Check earlier verdicts/Fail2Ban, backend, source/destination/port/interface and whether integration was removed. Locate the first matching blocker with rule deltas. |
| Jump counter increases, but only RETURN increases | No exact ACCEPT matched. Compare the observed tuple against saved unexpired `/32`, `.1` destination and approved ports. |
| Exact ACCEPT counter increases but no SYN-ACK | Examine other nft/legacy hooks, OUTPUT/reply route, Apache listener and time-correlated Fail2Ban state. An ACCEPT is not proof that every independent hook accepted. |
| SYN, SYN-ACK and HTTP response succeed; browser still fails | Investigate redirects, certificate trust, proxy and Apache/application access policy. Do not widen network trust. |
| Chain repeatedly appears/disappears | Correlate timestamped rule events, broker state and firewall source/journal. Test a targeted correction only after identifying the writer and real regeneration behaviour. |
| Journal names the marked TELIPHONES INPUT rule as invading | The old broker placement conflicts with the firewall self-check. Confirm installed broker revision. The correction removes that jump and uses only the internal marked jump; do not disable FreePBX Firewall or enable Custom Rules as a workaround. |

The local packet lab uses veth interfaces and a constructed FreePBX-shaped
ruleset, not WireGuard, Apache or real FreePBX Firewall. It checks both
iptables backends independently, exact source/destination/port restrictions,
Fail2Ban precedence, chain deletion/recovery, and earlier/later independent
drops despite `active` status. It does not exercise mixed-backend deployments,
FreePBX self-checks, actual regeneration transactions or a live daemon's repair
deadline. Those remain live diagnostic requirements.

The corrected module is **0.4.1**, a patch increment from the already installed
and tested **0.4.0**. Windows remains independently versioned at **0.8.0** because
its application code is unchanged. The new review archive has a SHA-256 sidecar;
the older 0.4.0 archive is preserved. No release or deployment is performed. Supply timestamped
status, backend snapshots, relevant rule deltas and packet summaries privately
when validating this source correction.
Keep FreePBX Firewall and Fail2Ban enabled.
