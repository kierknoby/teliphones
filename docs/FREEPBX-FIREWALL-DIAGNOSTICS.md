# FreePBX 17: workstation web access investigation

## Current evidence and scope

The operator reports that Windows **0.4.0** establishes a WireGuard tunnel to the
FreePBX 17 test PBX and that PuTTY reaches its SSH server. Web access initially
required disabling FreePBX Firewall. A separate 0.3.1 nftables ownership
hotfix was successfully tested on that PBX, but the repository package and
upgrade/bootstrap path have not yet been installed and independently verified.
Do not assume the deployed root broker matches module **0.3.1** or survives the
PBX's actual firewall regeneration.

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
| Installation | Module files and the root-owned running broker are separate. Module Admin need not update `/usr/local/lib/teliphones-broker/support_broker.py`. A module version or protocol 3 alone cannot prove broker revision. |
| Startup | `serve()` disables workstation access, starts the nft monitor and calls `restore_workstations()`. Persistent and unexpired entries are loaded from root-owned state. |
| Admission | `apply_workstations()` disables `tlp-admin`, installs and reads back the complete owned nft policy, configures the WireGuard interface and peers, reconciles iptables, then brings the link up. |
| Address binding | The PBX uses the first host (`.1`) of its saved `/24`; every WireGuard peer has its own saved `/32` AllowedIPs. The iptables rule requires that source, that PBX destination, `tlp-admin`, TCP and port 80/443 (22 only with `ssh: true`). No LAN-IP or arbitrary-port exception is installed. |
| iptables backend | Only the first available `/usr/sbin/iptables` or `/sbin/iptables` is used. It is not automatically switched to whichever backend contains FreePBX Firewall. |
| Placement | The broker requires a **direct INPUT** jump/goto to the exact target `fpbxfirewall`. Its marked jump must be immediately before the first such hook and after all direct `fail2ban-*` / `f2b-*` targets (case-insensitive). FreePBX interface classification inside that hook is therefore skipped only for precisely matching ACCEPTs. |
| Fail2Ban | A recognised Fail2Ban hook after `fpbxfirewall` causes withdrawal and `error`, not bypass. Nested hooks, alternative names and independent nftables chains are not inspected by this placement algorithm. Independent drop verdicts still apply. |
| Reconciliation | `ip filter` nft events wake the worker; legacy iptables relies on periodic execution. Every iteration also verifies the owned nft policy. If the interface is UP and policy valid, only integration is reconciled, without bouncing peers. |
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

The local packet lab uses veth interfaces and a constructed FreePBX-shaped
ruleset, not WireGuard, Apache or real FreePBX Firewall. It checks both
iptables backends independently, exact source/destination/port restrictions,
Fail2Ban precedence, chain deletion/recovery, and earlier/later independent
drops despite `active` status. It does not exercise mixed-backend deployments,
FreePBX self-checks, actual regeneration transactions or a live daemon's repair
deadline. Those remain live diagnostic requirements.

The repository includes the operator-tested ownership correction as module
**0.3.1**, but its package/recovery rollout still requires validation. Windows
remains **0.4.0**. Supply the timestamped status, backend snapshots, relevant
rule deltas and packet summary privately before selecting further corrections.
Keep FreePBX Firewall and Fail2Ban enabled.
