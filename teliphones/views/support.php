<?php
require_once dirname(__DIR__) . '/BrokerBootstrap.php';
require_once dirname(__DIR__) . '/WebSupport.php';
use FreePBX\modules\Teliphones\WebSupport;
$escape = static function ($value): string {
    return htmlspecialchars(is_scalar($value) ? (string)$value : '', ENT_QUOTES, 'UTF-8');
};
$support = isset($support) && is_array($support) ? $support : [];
$status = is_array($support['status'] ?? null) ? $support['status'] : [];
$readiness = is_array($status['readiness'] ?? null) ? $status['readiness'] : [];
$session = is_array($status['session'] ?? null) ? $status['session'] : [];
$broker = isset($broker) && is_array($broker) ? $broker : ['available' => empty($support['unavailable']), 'condition' => empty($support['unavailable']) ? 'operational' : 'unverified'];
$available = !empty($broker['available']);
$condition = $available ? 'operational' : (string)($broker['condition'] ?? 'unverified');
$conditions = [
    'not_installed' => ['Root broker not installed', 'FreePBX Module Admin installed the TELIPHONES module, but did not establish its privileged operating-system component (the root broker service). Module Admin runs as the web service account, which cannot create root-owned services; this is expected and must be completed once by root.'],
    'stopped' => ['Broker service installed but stopped', 'The teliphones-broker.service unit is installed but systemd reports it as "' . (string)($broker['service'] ?? 'inactive') . '".'],
    'socket_unavailable' => ['Broker running but control socket unavailable', 'systemd reports the broker as active, but this page cannot obtain a valid status response from /run/teliphones/control.sock' . (array_key_exists('socket_present', $broker) ? (!empty($broker['socket_present']) ? ' (the socket exists; check its ownership and the web server account)' : ' (the socket does not exist)') : '') . '.'],
    'unverified' => ['Broker state not verified', 'The control socket is unreachable and the broker service state could not be read by the web service account.'],
];
$missing = array_keys(array_filter($readiness, static function ($value) { return $value !== true; }));
$wireguardMissing = in_array('WireGuard wg', $missing, true);
$otherMissing = array_values(array_diff($missing, ['WireGuard wg']));
$phase = $available ? ($status['phase'] ?? 'Not configured') : $conditions[$condition][0] ?? 'Broker state not verified';
$unavailableReason = 'Unavailable: the privileged TELIPHONES broker is not operational (' . ($conditions[$condition][0] ?? 'not verified') . ').';
$disabled = $available ? '' : ' disabled aria-disabled="true"';
$command = static function (string $text) use ($escape): string {
    return '<pre style="user-select:all">' . $escape($text) . '</pre>';
};
$bootstrapScript = \FreePBX\modules\Teliphones\BrokerBootstrap::ROOT_BOOTSTRAP_SCRIPT;
$live = WebSupport::publicStatus($support, $broker);
$controls = WebSupport::controls($live);
$operation = $live['operation'];
$running = $operation !== null && $operation['state'] === 'running';
$wireguardInstalled = ($readiness['WireGuard wg'] ?? null) === true;
$off = static function (string $action) use ($controls): string {
    return $controls[$action]['enabled'] ? '' : ' disabled aria-disabled="true"';
};
$cell = static function (array $state) use ($escape): string {
    return '<span class="teliphones-spinner"' . ($state['kind'] === 'busy' ? '' : ' hidden') . ' aria-hidden="true"></span><span class="teliphones-cell-text teliphones-' . $escape($state['kind']) . '">' . $escape($state['text']) . '</span>';
};
$liveExtras = static function (string $action) use ($controls, $operation, $running, $escape, $cell, $available): string {
    $active = $running && $operation['action'] === $action;
    $reason = $available ? (WebSupport::CONTROL_REASONS[$controls[$action]['reason']] ?? '') : '';
    return ' <span class="teliphones-progress" data-teliphones-progress="' . $action . '"' . ($active ? '' : ' hidden') . '>'
        . $cell(['kind' => $active ? 'busy' : 'hidden', 'text' => $active ? ($operation['stage'] ?: $operation['label']) . '…' : '']) . '</span>'
        . '<p class="help-block" data-teliphones-reason="' . $action . '"' . ($reason === '' ? ' hidden' : '') . '>' . $escape($reason) . '</p>';
};
$initial = $live + ['labels' => WebSupport::ACTION_LABELS];
$outdated = $available && WebSupport::brokerOperational($support) && !$live['broker_current'];
$markdown = static function (string $text) use ($escape): string {
    return preg_replace(['/`([^`]+)`/', '/\*\*([^*]+)\*\*/'], ['<code>$1</code>', '<strong>$1</strong>'], $escape($text));
};
?>
<style>
.teliphones-spinner{display:inline-block;width:1em;height:1em;margin-right:.4em;vertical-align:-.15em;border:2px solid #ccc;border-top-color:#337ab7;border-radius:50%;animation:teliphones-spin .8s linear infinite}
.teliphones-spinner[hidden],.teliphones-progress[hidden]{display:none}
.teliphones-ok{color:#3c763d}.teliphones-fail{color:#a94442;font-weight:bold}.teliphones-busy{color:#31708f}
.teliphones-operation-failure{border:3px solid #a94442}
@keyframes teliphones-spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.teliphones-spinner{animation-duration:2.4s}}
</style>
<div class="container-fluid" id="teliphones-root" data-teliphones-ajax="ajax.php?module=teliphones">
<h2>TELIPHONES</h2>
<p>Administrator-owned PBX connections and temporary, administrator-authorised remote support. Installation and module enablement do not authorise workstation or engineer access.</p>
<?php if (!$available): ?>
<div class="alert alert-danger teliphones-system-warning">
<?php if ($condition === 'not_installed'): ?>
<h4>TELIPHONES Installation Incomplete</h4>
<p>The FreePBX module installed successfully, but its privileged operating-system component (the root broker service) requires a one-time installation step by root. Module Admin runs as the web service account and cannot create root-owned services. Follow <strong>Complete Installation</strong> below.</p>
<?php else: ?>
<strong>Privileged TELIPHONES broker unavailable: <?=$escape($conditions[$condition][0] ?? 'not verified')?>.</strong> <?=$escape($conditions[$condition][1] ?? '')?> See the recovery steps below.
<?php endif; ?>
<p>Remote support actions are disabled until the broker is operational.</p></div>
<?php elseif (!empty($support['error'])): ?>
<div class="alert alert-danger"><?=$escape($support['error'])?></div>
<?php endif; ?>
<?php if ($outdated): ?>
<div class="alert alert-warning teliphones-broker-outdated"><h4>Root broker update required</h4>
<p>The separately installed root broker is outdated or does not report compatible workstation pairing capabilities. Remote support actions still work through ordinary page submission, but automatic progress monitoring and workstation operations are unavailable. When no support session is active, rerun <strong>Complete Installation</strong> below from a root shell, then refresh this page.</p></div>
<?php endif; ?>
<?php if (isset($notice) && is_array($notice)): ?>
<?php if (!empty($notice['action_failed'])): ?>
<div class="alert alert-danger teliphones-action-failure" role="alert" style="border:3px solid #a94442;margin:20px 0;padding:15px 20px;font-size:1.1em"><strong>Operation failed: <?=$escape($notice['operation'] ?? 'TELIPHONES request')?></strong><br><?=$escape($notice['error'] ?? 'The request failed.')?></div>
<?php else: ?>
<div class="alert <?=!empty($notice['ok']) ? 'alert-info' : 'alert-danger'?>"><?=$escape($notice['error'] ?? $notice['message'] ?? 'Request submitted.')?></div>
<?php endif; ?>
<?php endif; ?>
<div id="teliphones-live" role="status" aria-live="polite">
<?php $showRunning = $running && !(isset($notice) && is_array($notice) && !empty($notice['ok'])); ?>
<div class="alert alert-info" id="teliphones-started"<?=$showRunning ? '' : ' hidden'?>><?=$showRunning ? 'TELIPHONES operation in progress: ' . $escape($operation['label']) . '. Monitoring progress automatically…' : ''?></div>
<div class="alert alert-warning" id="teliphones-slow"<?=$running && ($live['server_time'] - $operation['started_at']) > 120 ? '' : ' hidden'?>>This operation is taking longer than expected. TELIPHONES is continuing to check its status.</div>
<div class="alert alert-warning" id="teliphones-poll-warning" hidden></div>
<div class="alert alert-warning" id="teliphones-paused" hidden>Automatic monitoring paused after 15 minutes. <button type="button" class="btn btn-default btn-xs" id="teliphones-resume">Resume monitoring</button></div>
</div>
<div id="teliphones-results"></div>
<?php if (!$available || $outdated): ?>
<details class="teliphones-install"<?=$condition === 'not_installed' || $outdated ? ' open' : ''?>><summary><strong>Complete Installation</strong></summary>
<p>Run this once from an <strong>existing root shell</strong> on the PBX (Debian 12 / FreePBX 17), for example after logging in as root on the console or running <code>su -</code>. It stops without changes if not run as root. Use it only with a trusted, verified TELIPHONES installation, for example a package whose checksum you confirmed before uploading it through Module Admin.</p>
<p>It installs the root-owned broker and registers its systemd service. It does <strong>not</strong> authorise a remote support session or install packages. Broker startup revokes interrupted support sessions; existing workstation access is disabled and its owned policy revalidated before valid saved pairings are restored. Unrelated SSH, firewall and network policies are not changed. It first stages a root-owned copy of the module in <code>/root/teliphones-bootstrap</code>, so the root installer does not then execute files directly from the web-service-owned module directory.</p>
<p><strong>Do not run it during an active support session:</strong> it restarts the broker, and broker startup revokes any interrupted session and quarantines TELIPHONES. If unsure, check first as root with <code>fwconsole teliphones status</code>.</p>
<p class="teliphones-upgrade-note"><strong>After upgrading TELIPHONES:</strong> <?=$markdown(\FreePBX\modules\Teliphones\BrokerBootstrap::UPGRADE_NOTE)?></p>
<pre id="teliphones-bootstrap-script" style="user-select:all"><?=$escape($bootstrapScript)?></pre>
<button type="button" class="btn btn-default" id="teliphones-copy-bootstrap">Copy Commands</button>
<script>
(function () {
    var button = document.getElementById('teliphones-copy-bootstrap');
    var source = document.getElementById('teliphones-bootstrap-script');
    if (!button || !source) return;
    button.addEventListener('click', function () {
        var text = source.textContent;
        var copied = function () { button.textContent = 'Commands copied'; };
        var fallback = function () {
            var area = document.createElement('textarea');
            area.value = text;
            area.setAttribute('readonly', '');
            area.style.position = 'absolute';
            area.style.left = '-9999px';
            document.body.appendChild(area);
            area.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (error) { ok = false; }
            document.body.removeChild(area);
            if (ok) { copied(); return; }
            var range = document.createRange();
            range.selectNodeContents(source);
            var selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            button.textContent = 'Press Ctrl+C to copy the selected commands';
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(copied, fallback);
        } else {
            fallback();
        }
    });
})();
</script>
<p>Success ends with <code>active</code> followed by <code>TELIPHONES broker is ready.</code> If that final line is not printed, the preceding check failed; see the troubleshooting below. <strong>After successful installation, refresh this page</strong> (<a href="config.php?display=teliphones">Refresh session status</a>). The broker is shown as operational only after this page has contacted it.</p>
</details>
<?php endif; ?>
<?php if (!$available): ?>
<details class="teliphones-troubleshooting"<?=in_array($condition, ['stopped', 'socket_unavailable'], true) ? ' open' : ''?>><summary><strong>Verify the broker and troubleshoot</strong></summary>
<p>Run as root:</p>
<?=$command('systemctl status teliphones-broker.service --no-pager -l')?>
<p>Success: <code>Loaded: loaded (/etc/systemd/system/teliphones-broker.service; enabled; ...)</code> and <code>Active: active (running)</code>.</p>
<?=$command('ls -l /run/teliphones/control.sock')?>
<p>Success: a socket line beginning <code>srw-rw----</code> owned by <code>root asterisk</code>.</p>
<ul>
<li><strong>Service missing</strong> (<code>Unit teliphones-broker.service could not be found</code>): the installation step has not completed. Run <strong>Complete Installation</strong> and read its output. It requires <code>/usr/bin/python3</code>, <code>/usr/bin/systemctl</code> and the FreePBX <code>asterisk</code> account (<code>id asterisk</code>).</li>
<li><strong>Failed startup</strong> (<code>Active: failed</code> or repeated restarts): read the log with <code>journalctl -u teliphones-broker.service -n 50 --no-pager</code>. If it reports that the state directory must be root-owned and private, re-run <strong>Complete Installation</strong>, which restores root ownership of <code>/var/lib/teliphones</code>.</li>
<li><strong>Socket missing</strong> while the service is active: check the same log, then run <code>systemctl restart teliphones-broker.service</code>, which recreates the socket (not during an active support session). If the socket exists but this page still cannot reach it, confirm that the web server runs as <code>asterisk</code>: <code>ps -C apache2 -o user= | sort -u</code>.</li>
</ul>
<p>Do not change the socket's ownership or mode, or the state directory permissions, to make the page work: the broker deliberately accepts only the FreePBX <code>asterisk</code> account.</p>
</details>
<?php endif; ?>
<h3>System readiness</h3>
<p><strong data-teliphones="phase"><?=$escape($phase)?></strong>. Module status: <?=$escape($available ? (!empty($status['enabled']) ? 'Enabled' : 'Disabled') : 'Not verified (broker unavailable)')?>.</p>
<table class="table table-striped"><thead><tr><th>Required component</th><th>Status</th></tr></thead><tbody>
<tr><td>Privileged root broker</td><td><?=$available ? 'Operational (control socket verified)' : $escape($conditions[$condition][0] ?? 'Not verified')?></td></tr>
<?php if (!$available): ?>
<tr><td>Dependencies</td><td>Not verified (requires the privileged broker)</td></tr>
<?php endif; ?>
<?php foreach ($readiness as $component => $value): ?>
<tr><td><?=$escape($component)?></td><td data-teliphones-component="<?=$escape($component)?>"><?=$cell(WebSupport::readinessCell((string)$component, $value, $live))?></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php if ($available && $wireguardMissing): ?><div class="alert alert-warning" id="teliphones-wireguard-warning">WireGuard tools missing. Approve their installation below.</div><?php endif; ?>
<?php if ($available && $otherMissing): ?><div class="alert alert-warning">Other dependencies missing: <?=$escape(implode(', ', $otherMissing))?>. Missing PHP, Python, OpenSSH, systemd or FreePBX components must be repaired by the PBX platform administrator; gateway enrollment and the Checker key are configured below.</div><?php endif; ?>
<form method="post" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<button class="btn btn-default" name="action" value="dependencies" type="submit"<?=$off('dependencies')?>><?=$wireguardInstalled ? 'WireGuard tools installed' : 'Approve installation of WireGuard tools'?></button><?=$liveExtras('dependencies')?>
<?php if (!$available): ?><p class="help-block"><?=$escape($unavailableReason)?> The broker performs the package installation as root.</p><?php endif; ?>
<p>Installs only Debian's wireguard-tools using the root broker and the system's configured package repositories. No SSH service or firewall policy is changed. Missing PHP, Python, OpenSSH, systemd or root bootstrap requires the PBX platform administrator / Module Admin to repair the platform; this module cannot elevate web PHP.</p>
</form>
<h3>Remote support</h3>
<form method="post" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-minutes">Duration (minutes)</label>
<select id="teliphones-minutes" name="minutes" class="form-control"<?=$off('authorise')?>>
<?php foreach ([5, 15, 30, 60, 120, 240] as $minutes): ?><option value="<?=$minutes?>"><?=$minutes?></option><?php endforeach; ?>
</select>
<p>Authorisation permits the gateway-enrolled engineer's temporary public-key-only root SSH shell on the WireGuard address (port 22222) and the gateway's enrolled web service scope. Engineer access remains closed until local and independent Checker verification pass.</p>
<button class="btn btn-primary" name="action" value="authorise" type="submit"<?=$off('authorise')?>>Authorise Remote Support</button><?=$liveExtras('authorise')?>
<button class="btn btn-danger" name="action" value="revoke" type="submit"<?=$off('revoke')?>>Revoke Remote Support</button><?=$liveExtras('revoke')?>
<?php if (!$available): ?>
<p class="help-block"><?=$escape($unavailableReason)?> Authorisation and revocation are performed by the broker; neither can be carried out from this page now, and pressing them would not change any session.</p>
<div class="alert alert-warning teliphones-emergency"><strong>Emergency revocation.</strong> If a support session may be active, a root user on the PBX can revoke it immediately and independently of this page:<?=$command('fwconsole teliphones revoke')?>Scheduled expiry is enforced by PBX systemd timers and the temporary SSH lifetime, not by the broker or this page.</div>
<?php endif; ?>
</form>
<h3>Active session</h3>
<p>Session state: <strong data-teliphones="session-phase"><?=$cell(WebSupport::sessionPhase($live))?></strong></p>
<p id="teliphones-session-details"<?=$session ? '' : ' hidden'?>>Session: <code data-teliphones="session-id"><?=$escape($session['session_id'] ?? '')?></code><br>
Authorised engineer identity: <span data-teliphones="engineer"><?=$escape($status['engineer'] ?? 'Not yet established')?></span> (gateway-enrolled SSH key fingerprint; presence is not reported)<br>
Remaining: <span data-teliphones="remaining"><?=$escape($session ? max(0, (int)($session['expires_at'] ?? 0) - time()) : '')?></span> seconds<br>
Permitted access: <span data-teliphones="access"><?=!empty($status['access_verified']) ? 'WireGuard-scoped web access and temporary source-restricted, public-key-only root SSH.' : 'No current engineer SSH access has been confirmed.'?></span></p>
<a class="btn btn-default" href="config.php?display=teliphones">Refresh session status</a>
<?php $challenge = is_array($status['challenge'] ?? null); ?>
<div id="teliphones-evidence-section"<?=$challenge ? '' : ' hidden'?>>
<h4>Independent Checker verification</h4>
<p>The reference gateway does not provide an automatic signed Checker service. Give this session-bound challenge to your independent Checker, then submit its signed evidence here. No Linux command on the PBX is required.</p>
<pre data-teliphones="challenge"><?=$challenge ? $escape(json_encode($status['challenge'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) : ''?></pre>
<form method="post" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-evidence">Signed Checker evidence JSON</label>
<textarea id="teliphones-evidence" name="evidence" class="form-control" rows="8" maxlength="32768" required<?=$disabled?>></textarea>
<button class="btn btn-primary" type="submit" name="action" value="evidence"<?=$off('evidence')?>>Verify evidence and open approved access</button><?=$liveExtras('evidence')?>
<?php if (!$available): ?><p class="help-block"><?=$escape($unavailableReason)?></p><?php endif; ?>
</form>
</div>
<details><summary>Secure gateway enrollment</summary>
<p>Use a separately deployed gateway and a customer client certificate enrolled there. TLS verification is mandatory. Credentials are stored root-only by the broker and are never returned to the browser. Submit this form over HTTPS. Configuration changes are refused during an active session.</p>
<?php if (!$available): ?><p class="help-block"><?=$escape($unavailableReason)?> Enrollment credentials are stored by the broker; do not paste them until it is operational.</p><?php endif; ?>
<form method="post" autocomplete="off" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<fieldset<?=$off('configure')?> id="teliphones-enrollment-fields">
<?php foreach (['url' => 'Gateway HTTPS URL', 'certificate' => 'Customer client certificate PEM', 'private_key' => 'Customer client private key PEM', 'ca' => 'Gateway CA certificate PEM', 'checker_key' => 'Independent Checker ECDSA P-256 public key PEM'] as $field => $label): ?>
<label for="teliphones-<?=$field?>"><?=$escape($label)?></label>
<?php if ($field === 'url'): ?><input id="teliphones-url" class="form-control" name="url" type="url" required>
<?php else: ?><textarea id="teliphones-<?=$field?>" class="form-control" name="<?=$field?>" rows="3" maxlength="16384" required></textarea><?php endif; ?>
<?php endforeach; ?>
<button class="btn btn-default" type="submit" name="action" value="configure"<?=$off('configure')?>>Save secure enrollment</button><?=$liveExtras('configure')?>
</fieldset>
</form></details>
<p>Expiry is enforced by PBX timers and the temporary SSH systemd lifetime, independently of this page. Cleanup failures quarantine support; revocation may be retried, but quarantine is not cleared from the GUI.</p>
<?php
$workstations = WebSupport::workstations($support);
$pairingResponse = isset($notice) && is_array($notice) && !empty($notice['ok']) && WebSupport::validPairingResponse($notice['pairing_response'] ?? null) ? $notice['pairing_response'] : null;
$pairOff = $available && $workstations['ready'] ? '' : ' disabled aria-disabled="true"';
$unpairOff = $available && $workstations['supported'] ? '' : ' disabled aria-disabled="true"';
$defaultHost = preg_replace('/:[0-9]+$/', '', (string)($_SERVER['HTTP_HOST'] ?? ''));
?>
<h3 id="teliphones-workstations">Windows workstations</h3>
<p>Workstation enforcement requires the <code>nft</code> CLI (nftables userspace tools); the <code>nftables.service</code> does not need to be enabled or running. The root broker owns only the isolated <code>inet teliphones_workstations</code> table, watches local nft events and periodically verifies its complete rules. Missing tools must be repaired by the platform administrator; this page does not install nftables or change FreePBX Firewall. External firewall flushes can briefly remove protection before detection disables the interface: this is not zero-exposure or truly fail-closed protection against external changes.</p>
<p>Pair the TELIPHONES Windows application on a workstation you control, so that it can reach this PBX over WireGuard without repeating remote support authorisation. A paired workstation reaches only this PBX's administration interface (TCP 80 and 443) and, only if you allow it, SSH (TCP 22). It cannot reach other networks through the PBX. Pairing creates no accounts, passwords or SSH keys: you sign in with your existing FreePBX and SSH credentials. The PBX's WireGuard UDP port must be reachable from the workstation (for example, through a port forward on the PBX's router). Other administration and SSH ports are not exposed by pairing.</p>
<?php if ($pairingResponse !== null): ?>
<div class="alert alert-success teliphones-pairing-response" role="status"><strong>Pairing response.</strong> Copy it into the TELIPHONES Windows application to finish pairing. It contains no secret keys.
<pre id="teliphones-pairing-response" style="user-select:all;white-space:pre-wrap;word-break:break-all"><?=$escape($pairingResponse)?></pre>
<button type="button" class="btn btn-default" id="teliphones-copy-pairing">Copy pairing response</button>
<script>
(function () {
    var button = document.getElementById('teliphones-copy-pairing');
    var source = document.getElementById('teliphones-pairing-response');
    if (!button || !source) return;
    button.addEventListener('click', function () {
        var select = function () {
            var range = document.createRange();
            range.selectNodeContents(source);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            button.textContent = 'Press Ctrl+C to copy the selected response';
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(source.textContent).then(function () { button.textContent = 'Pairing response copied'; }, select);
        } else {
            select();
        }
    });
})();
</script></div>
<?php endif; ?>
<?php if (!$workstations['supported']): ?>
<p class="help-block teliphones-pairing-unavailable"><?=!$available ? $escape($unavailableReason) : ($live['broker_current'] ? 'Workstation pairing status was not reported by the root broker; pairing is unavailable.' : 'Workstation pairing requires the updated root broker; see Root broker update required above.')?></p>
<?php elseif (!$workstations['ready']): ?>
<?php if (($status['enabled'] ?? true) === false): ?>
<div class="alert alert-warning teliphones-pairing-requirements">TELIPHONES is disabled. Workstation pairing is unavailable; revocation remains available.</div>
<?php else: ?>
<div class="alert alert-warning teliphones-pairing-requirements">Workstation pairing requires WireGuard tools, iproute2 and nftables on the PBX. Missing: <?=$escape(implode(', ', array_keys(array_filter($workstations['requirements'], static function ($value) { return $value !== true; }))))?>.</div>
<?php endif; ?>
<?php endif; ?>
<?php if ($workstations['error'] !== ''): ?><div class="alert alert-danger teliphones-pairing-error"><?=$escape($workstations['error'])?></div><?php endif; ?>
<table class="table table-striped teliphones-workstations"><thead><tr><th>Workstation</th><th>Key fingerprint</th><th>Address</th><th>Access</th><th>Pairing</th><th>WireGuard status</th><th></th></tr></thead><tbody>
<?php if (!$workstations['items']): ?><tr><td colspan="7">No workstations are paired.</td></tr><?php endif; ?>
<?php foreach ($workstations['items'] as $item): ?>
<tr><td><?=$escape($item['name'])?></td><td><code><?=$escape($item['fingerprint'])?></code></td><td><?=$escape($item['address'])?></td>
<td><?=$item['ssh'] ? 'Web interface and SSH' : 'Web interface only'?></td>
<td><?=$item['mode'] === 'persistent' ? 'Persistent (until revoked)' : 'Temporary, expires ' . $escape(gmdate('Y-m-d H:i', (int)$item['expires_at'])) . ' UTC'?></td>
<td><?=$item['last_handshake'] === null ? 'Not verified (status unavailable)' : ($item['last_handshake'] === 0 ? 'Authorised; no handshake yet' : 'Last handshake ' . $escape(gmdate('Y-m-d H:i:s', $item['last_handshake'])) . ' UTC')?></td>
<td><form method="post"><input type="hidden" name="token" value="<?=$escape($token ?? '')?>"><input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-danger btn-sm" type="submit" name="action" value="unpair"<?=$unpairOff?>>Revoke</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php if (count($workstations['items']) > 1 || $workstations['error'] !== ''): ?>
<form method="post"><input type="hidden" name="token" value="<?=$escape($token ?? '')?>"><input type="hidden" name="workstation_id" value="all">
<button class="btn btn-danger" type="submit" name="action" value="unpair"<?=$unpairOff?>>Revoke all workstations</button></form>
<?php endif; ?>
<details class="teliphones-pair"><summary><strong>Pair a workstation</strong></summary>
<p>In the TELIPHONES Windows application, choose <strong>Add my PBX...</strong>, then <strong>Generate request</strong> and <strong>Copy request</strong>. Pairing explicitly authorises access to this PBX's web administration interface; SSH is a separate choice below and is not permitted by default. Check that the key fingerprint shown in the application matches the fingerprint listed above after pairing. Pairing must be performed over HTTPS.</p>
<form method="post" autocomplete="off">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<fieldset<?=$pairOff?> id="teliphones-pair-fields">
<label for="teliphones-pair-request">Pairing request from the Windows application</label>
<textarea id="teliphones-pair-request" class="form-control" name="request" rows="3" maxlength="4096" required></textarea>
<label for="teliphones-pair-host">PBX public hostname or IP address (used by the workstation to reach WireGuard)</label>
<input id="teliphones-pair-host" class="form-control" name="endpoint_host" maxlength="253" required value="<?=$escape($defaultHost)?>">
<label for="teliphones-pair-port">WireGuard UDP port on the PBX</label>
<input id="teliphones-pair-port" class="form-control" name="listen_port" inputmode="numeric" pattern="[0-9]{4,5}" required value="<?=$escape($workstations['listen_port'] ?? 51821)?>">
<label for="teliphones-pair-mode">Pairing</label>
<select id="teliphones-pair-mode" class="form-control" name="mode"><option value="temporary">Temporary</option><option value="persistent">Persistent trusted workstation (until revoked)</option></select>
<label for="teliphones-pair-minutes">Temporary pairing duration (minutes)</label>
<select id="teliphones-pair-minutes" class="form-control" name="minutes"><?php foreach ([60, 240, 480, 1440] as $minutes): ?><option value="<?=$minutes?>"><?=$minutes?></option><?php endforeach; ?></select>
<label for="teliphones-pair-ssh">SSH access through the tunnel</label>
<select id="teliphones-pair-ssh" class="form-control" name="ssh"><option value="0">Not permitted</option><option value="1">Permit SSH (TCP 22) with existing PBX credentials</option></select>
<button class="btn btn-primary" type="submit" name="action" value="pair"<?=$pairOff?>>Pair workstation</button>
</fieldset>
</form></details>
<script type="application/json" id="teliphones-initial-status"><?=json_encode($initial, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR)?></script>
<script src="modules/teliphones/assets/js/teliphones.js"></script>
</div>
