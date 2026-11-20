# TELIPHONES 0.8.0 development implementation and acceptance

This report records the original module and root broker **0.8.0**, protocol
**12**. At the time of this historical report, the development candidate was
module/broker **0.8.1**, while Windows was independently **0.9.0**, file version
**0.9.0.0**. Current source versions are module/root broker **0.9.0.0** and
Windows **0.10.0**; consult the current component guides for status. This is an
unreleased development record, not a release. The original requirement — access from a previously unknown public IP
on FreePBX 17 / Debian 12 with Firewall enabled and no manual whitelisting —
**has not been demonstrated**. No installation, service restart, privileged
packet experiment or live acceptance was performed for this change.

## Architecture and compatibility

0.8.0 is appropriate because authority transactions, reconciliation and admission
behaviour materially change. Existing pairing identities, keys, deadlines and
protocol remain compatible. There is no identity migration. Startup discards
transport leases and requires fresh admission; it preserves valid pairings and
durable revocations. Repeat the documented root bootstrap in an authorised test
installation: Module Admin alone does not replace the installed broker helpers.

Restrictive policy, source restrictions, listener bans and SSH grant removal are
persisted before slow cleanup. Failure contains access and retains the new intent;
it does not restore the previous permission. Pairing additions may roll back.
The workstation state file and revocation journal use durable replacement.
Permission changes advance an unpredictable authority generation. Foreground
listener waits release every recursive acquisition of the authority lock, allowing
revocation to commit. A single listener job owns the writer; superseding work
cancels and reaps its process group before another writer starts. A completion
must still match its generation before it can publish or roll back state.

Shutdown latches against new mutations, cancels listener work first, clears leases
and contains interfaces. It leaves listener ownership for startup cleanup instead
of waiting for a 150-second FreePBX generation cycle inside the 90-second systemd
stop interval. Other external commands remain bounded individually; aggregate
shutdown time under many interfaces, blocked I/O or failed commands has not been
proven below 90 seconds on a real host. This is not a hard real-time guarantee.

## Firewall and lease behaviour

Public WireGuard UDP and management TCP remain separate. Public listener
verification now requires a reachable INPUT path in both IPv4 and IPv6 generated
rules. An owned ACCEPT in an unreachable chain is insufficient. Cached proofs
include both complete filter snapshots and are invalidated when either changes.
Management verification evaluates exact tunnel/source/destination/service tuples
for NEW and ESTABLISHED traffic. Earlier DROP/REJECT, conditional hooks excluding
the tunnel, earlier ACCEPT bypasses and unsupported matches prevent active status.
States distinguish active, blocked, unknown, pending and error; absent integration
also prevents admission. Failed integration clears leases and disables interfaces.

This is a conservative supported-layout interpreter, not a general firewall
interpreter or packet probe. Unconditional FreePBX/zone paths and recognised
Fail2Ban paths are modelled. Unanalysed native base hooks, a second active iptables
backend and non-filter table rules are refused. Real FreePBX interface/zone
classifiers may therefore be refused. No locally available upstream FreePBX
Firewall implementation was found to establish the CustomServicesAPI contract or
stability of the internal hook. Required evidence includes the exact installed
Firewall source/version, Custom Service API and generation lifecycle, IPv4/IPv6
ruleset snapshots, zone/interface classification, and packet traces. No external
search was performed. Unsupported layouts require implementation work backed by
that evidence, not a manual global trust workaround.

Controller TCP 8766 is available to paired tunnel peers before management admission.
GUI and approved SSH permits additionally carry absolute UTC xt_time deadlines;
terminal per-interface drops prevent falling through to unrelated trusted or
established rules when the native nftables gate disappears. The native gate remains
required and read back. Requests older than three seconds cannot renew a lease;
lease time starts from request receipt, and freshness is checked again after policy
work. Controller sockets bind to the intended interface, limit workers to 32,
limit the listen backlog to eight and bodies to 4096 bytes, and enforce a
three-second socket/request lifetime, including slow body delivery.

Both kernel deadline mechanisms use wall time. The running broker detects backward
clock drift greater than two seconds and withdraws leases. A suspended broker plus
a backward clock step is an unresolved independent-cutoff limitation. Ruleset/model
tests do not prove a 30-second kernel cutoff. Loss of both guards, privileged rule
replacement, or upstream ACCEPT bypass introduced between checks cannot have a
zero-exposure guarantee. A network lease cutoff is not termination of existing SSH
commands: managed SSH grant revocation/expiry uses separate authority and process
cleanup. Complete real cgroup/session termination still requires acceptance.
PHP listener ownership fsyncs its temporary file but does not prove directory
entry durability across power loss; interrupted ownership recovery needs testing.

## Regression evidence

The source tests exercise production functions with fake command/kernel state,
plus real unprivileged loopback HTTP. They cover durable Closed and SSH revoke
failures, pre-emption of a foreground writer, stale completion/heartbeat rejection,
recursive lock release, path refusal, native-gate loss rule construction, clock
regression, worker bounds and interface binding. Existing lifecycle, revocation,
roaming, SSH, policy and listener tests are retained. PHP tests verify generated
listener structure and topology. The upgrade failure was a disagreement between
the README paragraph and the displayed bootstrap instruction; both now contain
the same complete procedure, and the original equality assertion remains.

Exact final commands, counts, package hash and Git status are recorded in the root
`docs/DEVELOPMENT-0.8.0-REPORT.md`. Historical counts elsewhere are not evidence
for this source. Native Windows builds, privileged namespace suites and live PBX
acceptance have not been run for 0.8.0.

## Disposable PBX acceptance — not executed

Obtain explicit authorisation before this procedure. Use a disposable FreePBX 17 /
Debian 12 VM, a Windows 0.8.5 build with recorded provenance, an independent root
console, snapshots and a separate test client/network. Never use an operational
PBX. Record versions, source revisions, UTC and monotonic timestamps, ruleset and
configuration hashes; redact keys, certificates, credentials and public addresses
from any shared evidence.

1. Record both iptables backends, IPv4/IPv6 filter/non-filter rules, nft base hooks,
   FreePBX source/API version, zones and interfaces. Keep Firewall enabled throughout.
   Record existing unrelated SIP/RTP, administrator SSH, GUI and VPN connectivity.
2. Build/install the candidate using the documented Module Admin and root-bootstrap
   procedure only after authorisation. Verify both installed helper hashes, version
   0.8.0, protocol 12, socket ownership and readiness. Test upgrade from an existing
   valid pairing, repeated bootstrap and interrupted recovery without extending its
   expiry or changing its identity.
3. Prove the Windows public address is absent from trusted zones and allowlists.
   Pair GUI-only; capture UDP ingress on the public interface, the WireGuard handshake,
   tunnel controller request/response and GUI HTTP/TLS exchange. Test IPv4 and IPv6
   public endpoints separately. A handshake alone is not a pass. Refusal for an
   unsupported layout is a recorded compatibility failure, not successful acceptance.
4. Approve managed SSH separately. Verify certificate issuance, intended account and
   port, then interactive SSH. Before approval, both certificate and SSH access must
   fail. SIP/RTP/AMI/database/forwarding over the tunnel must remain denied.
5. Move to a second previously unknown public IP without whitelisting or re-pairing.
   Verify handshake, admission, GUI and approved SSH, unchanged identity/deadline,
   then repeat with a source-locked peer: an unapproved source must be refused.
6. Record the lease deadline. Probe new TCP and keep existing GUI/SSH TCP traffic
   active across it, with heartbeats stopped. With the broker deliberately paused
   in this disposable environment, verify cutoff on both iptables backends. Repeat
   after removing only the owned native gate; verify the independent deadline and
   terminal drops. Restore snapshots between cases. Do not infer packet enforcement
   from generated JSON. Measure the observed deadline/tolerance explicitly.
7. Repeat with a backwards wall-clock step while the broker runs and while paused;
   record the known limitation rather than accepting a delayed cutoff. Restore clock
   synchronisation and snapshots before subsequent cases.
8. Delay FreePBX generation; request Closed, source restriction, SSH revoke and full
   workstation revoke. Measure durable-intent latency, observe cancellation and all
   descendant processes, then release the old generation and prove no resurrection.
   Repeat with pairing expiry, process interruption, restart and cleanup failure.
9. Inject earlier DROP/REJECT, conditional INPUT hooks, early established ACCEPT,
   IPv6-only denial and competing backend rules. Status must refuse active admission;
   no unrelated rule may be removed. Reload FreePBX Firewall, restore supported
   policy and verify bounded recovery without an invading-rule/reset loop. Observe
   idle CPU, retries and watcher events for at least five minutes.
10. Send partial headers/bodies, trickled bytes, oversized bodies and more than 32
    simultaneous controller clients. Queue a heartbeat behind policy work beyond
    three seconds. Verify worker reclamation, refusal of stale admission and no
    controller exposure on public/non-tunnel interfaces.
11. Stop the broker during generation and under load. Measure against systemd's
    90-second timeout; verify interface containment, no surviving helper descendants
    and recovery from retained ownership. Verify SSH grant revocation/expiry leaves
    no owned sessions/cgroups and preserves unrelated administrator SSH. Restore the
    snapshot and repeat reboot, uninstall and failure-recovery cases.
12. Recheck unrelated calls, bidirectional RTP, management and VPNs. Retain raw logs,
    packet captures and outcomes for every case. Acceptance requires the complete
    sequence; missing evidence remains unverified.
