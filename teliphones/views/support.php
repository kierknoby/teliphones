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
$failedAction = isset($notice) && is_array($notice) && empty($notice['ok'])
    && is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
$expand = static function (array $actions) use ($failedAction): string {
    return in_array($failedAction, $actions, true) ? ' open' : '';
};
?>
<style>
#teliphones-root .teliphones-spinner{display:inline-block;width:1em;height:1em;margin-right:.4em;vertical-align:-.15em;border:2px solid #ccc;border-top-color:#337ab7;border-radius:50%;animation:teliphones-spin .8s linear infinite}
#teliphones-root [hidden]{display:none!important}
#teliphones-root .teliphones-ok{color:#3c763d}
#teliphones-root .teliphones-fail{color:#a94442;font-weight:bold}
#teliphones-root .teliphones-busy{color:#31708f}
#teliphones-root .teliphones-operation-failure{border:3px solid #a94442}
#teliphones-root .teliphones-panel{border:1px solid #ddd;border-radius:4px;padding:16px 20px;margin:20px 0;background:#fff}
#teliphones-root .teliphones-panel>h3{font-size:20px;margin:0 -20px 16px;padding:0 20px 12px;border-bottom:1px solid #eee}
#teliphones-root h4{font-size:16px;margin:20px 0 12px}
#teliphones-root p{line-height:1.5}
#teliphones-root label{display:block;margin:12px 0 5px}
#teliphones-root .form-control{width:100%;max-width:100%;height:auto;min-height:34px}
#teliphones-root select.form-control{max-width:30em}
#teliphones-root form{margin:12px 0}
#teliphones-root .btn{margin:6px 6px 6px 0;white-space:normal}
#teliphones-root .help-block{font-size:13px;margin:6px 0 12px}
#teliphones-root details{border-top:1px solid #eee;margin:14px 0;padding-top:12px}
#teliphones-root summary{cursor:pointer;font-weight:600;padding:4px 0}
#teliphones-root summary:focus-visible{outline:2px solid #337ab7;outline-offset:3px}
#teliphones-root details.teliphones-panel>summary{font-size:20px;padding:0}
#teliphones-root details.teliphones-panel[open]>summary{border-bottom:1px solid #eee;padding-bottom:12px;margin-bottom:16px}
#teliphones-root .teliphones-overview{display:flex;flex-wrap:wrap;gap:12px;list-style:none;padding:0}
#teliphones-root .teliphones-overview li{flex:1 1 190px;background:#f5f5f5;border:1px solid #e5e5e5;border-radius:3px;padding:10px 12px}
#teliphones-root .teliphones-overview strong{display:block;margin-bottom:5px}
#teliphones-root .teliphones-status{background:#f5f5f5;border-left:4px solid #337ab7;padding:12px 16px;margin:14px 0}
#teliphones-root .teliphones-policy-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}
#teliphones-root .teliphones-table-scroll{overflow-x:auto}
#teliphones-root .table th,#teliphones-root .table td{padding:10px 12px;vertical-align:top;overflow-wrap:anywhere}
#teliphones-root .teliphones-workstations{min-width:1050px}
#teliphones-root .teliphones-banned-list .table{min-width:560px}
#teliphones-root .teliphones-workstations td:last-child{min-width:240px}
#teliphones-root .table code{overflow-wrap:anywhere;white-space:normal}
#teliphones-root .teliphones-workstations form{margin:6px 0}
#teliphones-root .teliphones-workstations .help-block{max-width:24em}
#teliphones-root .teliphones-badge{display:inline-block;padding:3px 7px;border-radius:3px;font-size:12px;font-weight:600;line-height:1.5;background:#eee;color:#444;margin:2px 0}
#teliphones-root .teliphones-badge-success{background:#dff0d8;color:#315d32}
#teliphones-root .teliphones-badge-warning{background:#fcf8e3;color:#775c2b}
#teliphones-root .teliphones-pair-step{border-top:1px solid #eee;margin-top:18px;padding-top:4px}
#teliphones-root .teliphones-empty{padding:20px!important;color:#666;text-align:center}
#teliphones-root pre{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere}
@keyframes teliphones-spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){#teliphones-root .teliphones-spinner{animation-duration:2.4s}}
@media (max-width:767px){#teliphones-root .teliphones-policy-grid{grid-template-columns:1fr;gap:0}#teliphones-root .teliphones-panel{padding:14px}#teliphones-root .teliphones-panel>h3{margin-left:-14px;margin-right:-14px;padding-left:14px;padding-right:14px}#teliphones-root .btn{max-width:100%}}
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
<section class="teliphones-panel panel panel-default" aria-labelledby="teliphones-readiness-heading">
<h3 id="teliphones-readiness-heading">System Readiness</h3>
<p><strong data-teliphones="phase"><?=$escape($phase)?></strong>. Module status: <?=$escape($available ? (!empty($status['enabled']) ? 'Enabled' : 'Disabled') : 'Not verified (broker unavailable)')?>.</p>
<ul class="teliphones-overview">
<li><strong>Privileged root broker</strong><span class="teliphones-badge<?=$available ? ' teliphones-badge-success' : ' teliphones-badge-warning'?>"><?=$available ? 'Operational (control socket verified)' : $escape($conditions[$condition][0] ?? 'Not verified')?></span></li>
<?php foreach (array_intersect_key($readiness, array_flip(['WireGuard wg', 'Temporary SSH server', 'SSH key generation', 'Gateway enrollment', 'Checker trusted public key'])) as $component => $value): ?>
<li><strong><?=$escape($component)?></strong><span data-teliphones-component="<?=$escape($component)?>"><?=$cell(WebSupport::readinessCell((string)$component, $value, $live))?></span></li>
<?php endforeach; ?>
<?php if (!$available): ?><li><strong>Dependencies</strong>Not verified (requires the privileged broker)</li><?php endif; ?>
</ul>
<?php if ($available): ?>
<div class="alert alert-warning" id="teliphones-wireguard-warning"<?=$wireguardMissing ? '' : ' hidden'?>><?=$wireguardMissing ? 'WireGuard tools missing. Approve their installation below.' : ''?></div>
<div class="alert alert-warning" id="teliphones-other-warning"<?=$otherMissing ? '' : ' hidden'?>>
<?php if ($otherMissing): ?>Other dependencies missing: <?=$escape(implode(', ', $otherMissing))?>.<?php endif; ?>
<?php if (array_intersect($otherMissing, ['Gateway enrollment', 'Checker trusted public key'])): ?>Configure the listed items in <strong>Secure gateway enrollment</strong> below.<?php endif; ?>
<?php if (array_diff($otherMissing, ['Gateway enrollment', 'Checker trusted public key'])): ?>Ask the PBX platform administrator to repair the listed platform requirements.<?php endif; ?>
</div>
<?php endif; ?>
<details class="teliphones-dependency-help"><summary>Technical dependency details</summary>
<table class="table table-striped"><thead><tr><th>Required component</th><th>Status</th></tr></thead><tbody>
<tr><td>Privileged root broker</td><td><?=$available ? 'Operational (control socket verified)' : $escape($conditions[$condition][0] ?? 'Not verified')?></td></tr>
<?php if (!$available): ?>
<tr><td>Dependencies</td><td>Not verified (requires the privileged broker)</td></tr>
<?php endif; ?>
<?php foreach ($readiness as $component => $value): ?>
<tr><td><?=$escape($component)?></td><td data-teliphones-component="<?=$escape($component)?>"><?=$cell(WebSupport::readinessCell((string)$component, $value, $live))?></td></tr>
<?php endforeach; ?>
</tbody></table>
<p>Component detection confirms installation or configuration, not end-to-end operation. The root broker cannot repair PHP, Python, OpenSSH, systemd or FreePBX platform components or elevate web PHP.</p>
</details>
<form method="post" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<button class="btn btn-default" name="action" value="dependencies" type="submit"<?=$off('dependencies')?>><?=$wireguardInstalled ? 'WireGuard tools installed' : 'Approve installation of WireGuard tools'?></button><?=$liveExtras('dependencies')?>
<?php if (!$available): ?><p class="help-block"><?=$escape($unavailableReason)?> The broker performs the package installation as root.</p><?php endif; ?>
<p class="help-block">Installs only Debian's wireguard-tools from the system's configured repositories. No SSH service or firewall policy is changed.</p>
</form>
<details class="teliphones-enrollment"<?=$expand(['configure'])?>><summary>Secure gateway enrollment</summary>
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
</section>
<section class="teliphones-panel panel panel-default" aria-labelledby="teliphones-support-heading">
<h3 id="teliphones-support-heading">Remote Support</h3>
<div class="teliphones-status" role="status">
<strong>Session status: <span data-teliphones="session-phase"><?=$cell(WebSupport::sessionPhase($live))?></span></strong>
<p id="teliphones-session-details"<?=$session ? '' : ' hidden'?>>Session: <code data-teliphones="session-id"><?=$escape($session['session_id'] ?? '')?></code><br>
Authorised engineer identity: <span data-teliphones="engineer"><?=$escape($status['engineer'] ?? 'Not yet established')?></span> (gateway-enrolled SSH key fingerprint; presence is not reported)<br>
Remaining: <span data-teliphones="remaining"><?=$escape($session ? max(0, (int)($session['expires_at'] ?? 0) - time()) : '')?></span> seconds<br>
Permitted access: <span data-teliphones="access"><?=!empty($status['access_verified']) ? 'WireGuard-scoped web access and temporary source-restricted, public-key-only root SSH.' : 'No current engineer SSH access has been confirmed.'?></span></p>
</div>
<form method="post" data-teliphones-form>
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-minutes">Duration (minutes)</label>
<select id="teliphones-minutes" name="minutes" class="form-control"<?=$off('authorise')?>>
<?php foreach ([5, 15, 30, 60, 120, 240] as $minutes): ?><option value="<?=$minutes?>"><?=$minutes?></option><?php endforeach; ?>
</select>
<p>Authorisation permits the gateway-enrolled engineer's temporary public-key-only root SSH shell on the WireGuard address (port 22222) and the gateway's enrolled web service scope. Engineer access remains closed until local and independent Checker verification pass.</p>
<div class="teliphones-actions">
<button class="btn btn-primary" name="action" value="authorise" type="submit"<?=$off('authorise')?>>Authorise Remote Support</button>
<button class="btn btn-danger" name="action" value="revoke" type="submit"<?=$off('revoke')?>>Revoke Remote Support</button>
</div><?=$liveExtras('authorise')?><?=$liveExtras('revoke')?>
<?php if (!$available): ?>
<p class="help-block"><?=$escape($unavailableReason)?> Authorisation and revocation are performed by the broker; neither can be carried out from this page now, and pressing them would not change any session.</p>
<div class="alert alert-warning teliphones-emergency"><strong>Emergency revocation.</strong> If a support session may be active, a root user on the PBX can revoke it immediately and independently of this page:<?=$command('fwconsole teliphones revoke')?>Scheduled expiry is enforced by PBX systemd timers and the temporary SSH lifetime, not by the broker or this page.</div>
<?php endif; ?>
</form>
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
<p>Expiry is enforced by PBX timers and the temporary SSH systemd lifetime, independently of this page. Cleanup failures quarantine support; revocation may be retried, but quarantine is not cleared from the GUI.</p>
</section>
<?php
$workstations = WebSupport::workstations($support);
$pairingResponse = isset($notice) && is_array($notice) && !empty($notice['ok']) && WebSupport::validPairingResponse($notice['pairing_response'] ?? null) ? $notice['pairing_response'] : null;
$pairOff = $available && $workstations['ready'] ? '' : ' disabled aria-disabled="true"';
$sourceLockOff = WebSupport::supportsSourceLocks($support) ? '' : ' disabled aria-disabled="true"';
$unpairOff = $available && $workstations['supported'] ? '' : ' disabled aria-disabled="true"';
$policyOff = $available && $workstations['policy_supported'] ? '' : ' disabled aria-disabled="true"';
$banOff = $available && $workstations['ban_supported'] ? '' : ' disabled aria-disabled="true"';
$sessionLimitOff = $available && $workstations['session_supported'] ? '' : ' disabled aria-disabled="true"';
$manageOff = $available && $workstations['management_supported'] ? '' : ' disabled aria-disabled="true"';
$sshApprovalOff = $available && $workstations['management_supported'] && $workstations['ssh_ready'] ? '' : ' disabled aria-disabled="true"';
$defaultHost = preg_replace('/:[0-9]+$/', '', (string)($_SERVER['HTTP_HOST'] ?? ''));
$webEntries = $workstations['web'];
$webText = implode(', ', array_map(static function ($entry) { return $entry['scheme'] . ':' . $entry['port']; }, $webEntries));
// Direct server metadata, not client-controlled Host or forwarded headers.
$currentScheme = strtolower((string)($_SERVER['HTTPS'] ?? '')) === 'on' ? 'https' : 'http';
$currentPort = (int)($_SERVER['SERVER_PORT'] ?? 0) ?: ($currentScheme === 'https' ? 443 : 80);
$currentListed = in_array($currentPort, array_map(static function ($entry) { return $entry['port']; }, $webEntries), true);
$defaultWebText = $webText === '' ? 'http:80, https:443' : $webText;
if (!$currentListed && $currentPort >= 1 && $currentPort <= 65535) {
    $defaultWebText = $currentScheme . ':' . $currentPort;
}
$notListening = array_values(array_filter($webEntries, static function ($entry) { return $entry['listening'] === false; }));
$administratorSource = filter_var((string)($_SERVER['REMOTE_ADDR'] ?? ''), FILTER_VALIDATE_IP) !== false
    ? (string)$_SERVER['REMOTE_ADDR'] : '';
$workstationSources = [];
foreach ($workstations['items'] as $workstation) {
    if ($workstation['verified_endpoint'] !== null) {
        $workstationSources[] = ['name' => $workstation['name'], 'address' => $workstation['verified_endpoint']['address']];
    }
}
?>
<section class="teliphones-panel panel panel-default" aria-labelledby="teliphones-workstations">
<h3 id="teliphones-workstations">Windows Workstation Access</h3>
<div class="alert alert-warning">External firewall flushes can briefly remove restrictions: this is not zero-exposure or truly fail-closed protection. Never publish the certificate or managed SSH ports. Router/NAT forwarding of WireGuard UDP remains the administrator's responsibility.</div>
<details><summary>WireGuard, firewall and managed SSH details</summary>
<p>Workstation policy requires the <code>nft</code> CLI; <code>nftables.service</code> does not need to be enabled or running. Missing tools must be repaired by the platform administrator; this page does not install nftables.</p>
<p>Workstation enforcement requires <code>wg</code>, <code>ip</code> and <code>nft</code>. The broker owns only its isolated nft table and a marked jump inside <code>fpbxfirewall</code>, after INPUT's Fail2Ban hooks. The jump itself is not interface-filtered so dedicated Locked interfaces can use the same hook; every TELIPHONES ACCEPT rule is scoped to an exact interface, peer address, PBX address and port, and all other traffic returns to FreePBX Firewall. It never inserts a rule above FreePBX's INPUT hook. The public WireGuard UDP listeners use persistent FreePBX Custom Services: FreePBX owns its generated zone rules and applies changes asynchronously. Unlocked workstations share one listener; each Locked workstation uses a dedicated listener with an IP/CIDR/domain-derived source allowlist and is removed from the shared peer roster. WireGuard authenticates peers cryptographically. Reject zones, blacklists, Fail2Ban and unrelated services are not changed. External firewall flushes can briefly remove restrictions before detection; this is not zero-exposure protection. Managed SSH/API listeners also bind the WireGuard device independently of firewall rules.</p>
<p>Pair the TELIPHONES Windows application on a workstation you control to reach only this PBX's web interface (the configured management web services, default TCP 80/443) over WireGuard. New SSH-approved pairings use a dedicated, WireGuard-device-bound SSH listener and certificate endpoint (TCP 8765); each workstation receives only its own SSH port. Explicitly approve an existing Linux account below. Windows generates and retains its own SSH key; no accounts or passwords are created and root is never selected automatically. Existing system SSH and Remote Support are unchanged. Legacy pairings retain their original network permissions but must be re-paired for automated SSH. The broker opens the WireGuard UDP port through the PBX host firewall; any router/NAT port forwarding remains the administrator's responsibility. Never publish the certificate or managed SSH ports.</p>
</details>
<div class="teliphones-policy-grid">
<div>
<?php if ($workstations['policy_supported']): ?>
<div class="alert alert-info teliphones-connection-state" role="status">
<strong>Workstation connection state: <?=htmlspecialchars(ucfirst($workstations['connection_state']), ENT_QUOTES, 'UTF-8')?></strong>
<?php if ($workstations['connection_state'] === 'frozen'): ?><br>Existing pairings remain usable; new workstation pairings are suspended.
<?php elseif ($workstations['connection_state'] === 'closed'): ?><br>The listener is closed. Pairings are retained and can be reopened later.
<?php else: ?><br>The listener is open to authorised WireGuard peers. Pairing approval and existing service restrictions still apply.
<?php endif; ?>
</div>
<form method="post" id="teliphones-connection-state-form" data-current-state="<?=$escape($workstations['connection_state'])?>">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-connection-state">Windows workstation access</label>
<select id="teliphones-connection-state" class="form-control" name="state">
<option value="open"<?=$workstations['connection_state'] === 'open' ? ' selected' : ''?>>Open</option>
<option value="closed"<?=$workstations['connection_state'] === 'closed' ? ' selected' : ''?>>Closed</option>
<option value="frozen"<?=$workstations['connection_state'] === 'frozen' ? ' selected' : ''?>>Frozen</option>
</select>
<p class="help-block">Closed terminates workstation tunnels but retains pairings. Frozen keeps existing pairings available and prevents new pairing approvals. Open allows authorised peers to connect; WireGuard key authentication and service restrictions remain enforced.</p>
<button class="btn btn-default" type="submit" name="action" value="workstation-policy"<?=$policyOff?>>Save connection state</button>
</form>
<?php elseif ($workstations['supported']): ?>
<div class="alert alert-warning">Connection states require the updated root broker. Follow the root broker update procedure above, then refresh this page.</div>
<?php endif; ?>
</div>
<div>
<?php if ($workstations['session_supported']): ?>
<p class="teliphones-session-capacity"><strong>PBX-admitted workstation sessions:</strong> <?=$escape($workstations['connected_workstations'])?> of <?=$escape($workstations['max_sessions'])?>. Only admitted workstations can reach the configured management web services and approved SSH listener; a WireGuard handshake alone does not consume a session or prove administrative access.</p>
<form method="post" id="teliphones-session-limit-form">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-session-limit">Maximum simultaneous workstation sessions</label>
<select id="teliphones-session-limit" class="form-control" name="maximum">
<?php foreach (range(1, 128) as $maximum): ?><option value="<?=$maximum?>"<?=$workstations['max_sessions'] === $maximum ? ' selected' : ''?>><?=$maximum?></option><?php endforeach; ?>
</select>
<p class="help-block">Defaults to one. Lowering the limit below the number of currently active sessions is refused; disconnect sessions first. Existing admitted sessions expire automatically after a missed heartbeat.</p>
<button class="btn btn-default" type="submit" name="action" value="workstation-limit"<?=$sessionLimitOff?>>Save session limit</button>
</form>
<?php elseif ($workstations['supported']): ?>
<div class="alert alert-warning">Enforced workstation session capacity and status require the updated root broker (protocol 11). Update the root broker, then refresh this page.</div>
<?php endif; ?>
</div>
</div>
</section>
<section class="teliphones-panel panel panel-default" aria-labelledby="teliphones-paired-heading">
<h3 id="teliphones-paired-heading">Paired Workstations</h3>
<?php if ($pairingResponse !== null): ?>
<div class="alert alert-success teliphones-pairing-response" role="status"><strong>Pairing response.</strong> Copy it into the TELIPHONES Windows application to finish pairing. It contains no secret keys.
<pre id="teliphones-pairing-response" style="user-select:all;white-space:pre-wrap;word-break:break-all"><?=$escape($pairingResponse)?></pre>
<button type="button" class="btn btn-default" id="teliphones-copy-pairing">Copy pairing response</button>
<script>
(function () {
    var button = document.getElementById('teliphones-copy-pairing');
    var source = document.getElementById('teliphones-pairing-response');
    if (!button || !source) return;
    var originalLabel = button.textContent;
    var copiedTimer = null;
    var showLabel = function (label) {
        button.textContent = label;
        if (copiedTimer) window.clearTimeout(copiedTimer);
        copiedTimer = window.setTimeout(function () { button.textContent = originalLabel; }, 1800);
    };
    button.addEventListener('click', function () {
        var select = function () {
            var range = document.createRange();
            range.selectNodeContents(source);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            showLabel('Press Ctrl+C to copy the selected response');
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(source.textContent).then(function () {
                showLabel('Copied');
            }, select);
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
<?php $integration = $workstations['firewall_integration']; $integrationActive = $integration['state'] === 'active'; ?>
<?php if ($workstations['items'] && $integration['state'] === 'unknown'): ?>
<div class="alert alert-warning teliphones-firewall-integration">The running root broker does not report FreePBX Firewall integration. Rerun the documented root bootstrap to install the updated broker; until then FreePBX Firewall may drop workstation HTTP/HTTPS even after a successful WireGuard handshake.</div>
<?php elseif ($workstations['items'] && $integration['state'] === 'error'): ?>
<div class="alert alert-danger teliphones-firewall-integration"><strong>FreePBX Firewall integration failed.</strong> <?=$escape($integration['message'])?></div>
<?php elseif ($workstations['items'] && $integration['state'] === 'not-detected'): ?>
<div class="alert alert-info teliphones-firewall-integration"><strong>FreePBX Firewall integration not installed.</strong> <?=$escape($integration['message'])?></div>
<?php elseif ($integrationActive): ?>
<p class="help-block teliphones-firewall-integration">FreePBX Firewall integration active<?=$integration['backend'] !== null ? ' (iptables ' . $escape($integration['backend']) . ')' : ''?>. <?=$escape($integration['message'])?></p>
<?php endif; ?>
<div class="teliphones-table-scroll" role="region" aria-label="Paired workstation management" tabindex="0">
<table class="table table-striped teliphones-workstations"><thead><tr><th scope="col">Workstation</th><th scope="col">Key fingerprint</th><th scope="col">Address</th><th scope="col">Access</th><th scope="col">Pairing</th><th scope="col">WireGuard status</th><th scope="col">Administrative session</th><th scope="col">Actions</th></tr></thead><tbody>
<?php if (!$workstations['items']): ?><tr><td colspan="8" class="teliphones-empty">No workstations are paired. <a href="#teliphones-pair-panel" data-teliphones-open="teliphones-pair-panel">Pair a workstation</a> to approve access.</td></tr><?php endif; ?>
<?php foreach ($workstations['items'] as $item): ?>
<?php $currentSourceOff = $item['current_source_verified'] ? '' : ' disabled aria-disabled="true"'; ?>
<tr><td><?=$escape($item['name'])?><br><small>Diagnostic ID: <code>ws-<?=$escape($item['id'])?></code></small></td><td><code><?=$escape($item['fingerprint'])?></code></td><td><?=$escape($item['address'])?></td>
<td><?=$item['locked'] ? 'Locked to ' . $escape(implode(', ', $item['sources'])) . ' (UDP ' . $escape($item['listener_port']) . ')<br>Currently resolved: ' . $escape(implode(', ', $item['effective_sources'])) : 'Unlocked (shared listener)'?><br><?php if ($item['source_resolution_failures']): ?><span class="text-danger">Unresolved (not allowed): <?=$escape(implode(', ', $item['source_resolution_failures']))?></span><br><?php endif; ?><span class="teliphones-badge"><?=$item['ssh'] ? ($item['ssh_managed'] ? 'Web interface and managed SSH (' . $escape($item['ssh_user']) . ')' : 'Web interface and legacy SSH (existing credentials)') : 'Web interface only'?></span></td>
<td><span class="teliphones-badge"><?=$item['mode'] === 'persistent' ? 'Persistent (until revoked)' : 'Temporary, expires ' . $escape(gmdate('Y-m-d H:i', (int)$item['expires_at'])) . ' UTC'?></span></td>
<td><span class="teliphones-badge"><?=$workstations['connection_state'] === 'closed' ? 'Listener closed' : ($item['last_handshake'] === null ? 'Not verified (status unavailable)' : ($item['last_handshake'] === 0 ? 'Authorised; no handshake yet' : 'Last handshake ' . $escape(gmdate('Y-m-d H:i:s', $item['last_handshake'])) . ' UTC'))?></span><?php if ($item['verified_endpoint'] !== null): ?><br>Verified public endpoint: <code><?=$escape(strpos($item['verified_endpoint']['address'], ':') === false ? $item['verified_endpoint']['address'] : '[' . $item['verified_endpoint']['address'] . ']')?>:<?=$escape($item['verified_endpoint']['port'])?></code><?php endif; ?><?php if (is_int($item['last_handshake']) && $item['last_handshake'] > 0 && !$integrationActive && $integration['state'] !== 'not-detected'): ?><br><span class="text-danger teliphones-handshake-blocked">Handshake succeeded, but FreePBX Firewall integration is not active: HTTP/HTTPS may be dropped by FreePBX Firewall.</span><?php endif; ?></td>
<td><span class="teliphones-badge<?=$workstations['session_supported'] && $item['session_active'] && $item['session_expires_at'] > time() ? ' teliphones-badge-success' : ''?>"><?=$workstations['session_supported'] ? ($item['session_active'] && $item['session_expires_at'] > time() ? 'Admitted until ' . $escape(gmdate('Y-m-d H:i:s', $item['session_expires_at'])) . ' UTC' : 'Not admitted') : 'Unavailable'?></span></td>
<td>
<?php if ($workstations['management_supported']): ?>
<form method="post" class="teliphones-workstation-lock-form">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<input type="hidden" name="sources" value="current">
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-manage"<?=$manageOff . $currentSourceOff?> data-workstation-state="lock">Lock to Current IP</button>
<input type="hidden" name="state" value="lock">
</form>
<?php if (!$item['current_source_verified']): ?><p class="help-block">Lock to Current IP becomes available after a recent verified WireGuard handshake.</p><?php endif; ?>
<form method="post" class="teliphones-workstation-sources-form">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<input type="hidden" name="state" value="lock">
<label class="sr-only" for="teliphones-sources-<?=$escape($item['id'])?>">Allowed IP addresses, CIDR ranges and DNS names for <?=$escape($item['name'])?></label>
<input id="teliphones-sources-<?=$escape($item['id'])?>" class="form-control input-sm" name="sources" maxlength="2048" placeholder="IPv4, IPv6, CIDR or DNS names" value="<?=$escape(implode(', ', $item['sources']))?>" required<?=$manageOff?>>
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-manage"<?=$manageOff?>><?=$item['locked'] ? 'Update Allowed List' : 'Lock to Allowed List'?></button>
</form>
<?php if ($item['locked']): ?>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<input type="hidden" name="state" value="unlock">
<input type="hidden" name="sources" value="">
<button class="btn btn-warning btn-sm" type="submit" name="action" value="workstation-manage"<?=$manageOff?>>Unlock</button>
</form>
<?php endif; ?>
<?php endif; ?>
<?php if ($item['ssh_request_pending']): ?>
<p class="teliphones-badge teliphones-badge-warning"><strong>SSH elevation: Pending Approval</strong></p>
<?php if ($workstations['ssh_accounts']): ?>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<label class="sr-only" for="teliphones-ssh-user-<?=$escape($item['id'])?>">Existing Linux account for <?=$escape($item['name'])?></label>
<select id="teliphones-ssh-user-<?=$escape($item['id'])?>" class="form-control input-sm" name="ssh_user" required<?=$sshApprovalOff?>>
<option value="">Select an existing Linux account</option>
<?php foreach ($workstations['ssh_accounts'] as $account): ?><option value="<?=$escape($account)?>"><?=$escape($account)?></option><?php endforeach; ?>
</select>
<button class="btn btn-success btn-sm" type="submit" name="action" value="workstation-ssh-approve"<?=$sshApprovalOff?>>Approve SSH</button>
</form>
<?php else: ?><p class="help-block">No eligible existing Linux account is available for explicit SSH approval.</p><?php endif; ?>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-ssh-reject"<?=$sshApprovalOff?>>Reject SSH</button>
</form>
<?php endif; ?>
<?php if ($item['unlock_request_pending']): ?>
<p class="teliphones-badge teliphones-badge-warning"><strong>Workstation unlock: Pending Approval</strong></p>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-warning btn-sm" type="submit" name="action" value="workstation-unlock-approve"<?=$manageOff?>>Approve Unlock</button>
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-unlock-reject"<?=$manageOff?>>Reject Unlock</button>
</form>
<?php endif; ?>
<?php if ($item['sources_request_pending']): ?>
<p class="teliphones-badge teliphones-badge-warning"><strong>Allowed List change: Pending Approval</strong><br>Requested: <code><?=$escape(implode(', ', $item['requested_sources']))?></code></p>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-success btn-sm" type="submit" name="action" value="workstation-sources-approve"<?=$manageOff?>>Approve Allowed List</button>
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-sources-reject"<?=$manageOff?>>Reject Allowed List</button>
</form>
<?php endif; ?>
<?php if ($item['ssh_managed']): ?>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-warning btn-sm" type="submit" name="action" value="workstation-ssh-revoke"<?=$sshApprovalOff?>>Revoke SSH</button>
</form>
<?php endif; ?>
<form method="post"><input type="hidden" name="token" value="<?=$escape($token ?? '')?>"><input type="hidden" name="workstation_id" value="<?=$escape($item['id'])?>">
<button class="btn btn-danger btn-sm" type="submit" name="action" value="unpair"<?=$unpairOff?>>Revoke</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
</div>
<?php if (count($workstations['items']) > 1 || $workstations['error'] !== ''): ?>
<form method="post"><input type="hidden" name="token" value="<?=$escape($token ?? '')?>"><input type="hidden" name="workstation_id" value="all">
<button class="btn btn-danger" type="submit" name="action" value="unpair"<?=$unpairOff?>>Revoke all workstations</button></form>
<?php endif; ?>
</section>
<section class="teliphones-panel panel panel-default" aria-labelledby="teliphones-security-heading">
<h3 id="teliphones-security-heading">Security &amp; Access Restrictions</h3>
<div class="teliphones-banned-list" id="teliphones-banned-list">
<h4>Manually managed Banned list</h4>
<p>These IP/CIDR entries are dropped only on TELIPHONES WireGuard UDP listener ports. They do not change Fail2Ban, SIP/RTP or other FreePBX services. A ban can block this administrator or legitimate workstations sharing a public IP; verify the source and recovery route before applying it.</p>
<?php if (!$workstations['ban_supported']): ?><p class="help-block">Manual bans require broker protocol 10 or later; upgrade the root broker before managing this list.</p><?php endif; ?>
<?php if ($workstations['bans']): ?>
<div class="teliphones-table-scroll" role="region" aria-label="Manual listener bans" tabindex="0">
<table class="table table-striped"><thead><tr><th>Source</th><th>Reason</th><th>Expiry</th><th>Status</th><th></th></tr></thead><tbody>
<?php foreach ($workstations['bans'] as $ban): ?>
<tr><td><code><?=$escape($ban['source'])?></code></td><td><?=$escape($ban['reason'])?></td>
<td><?=$ban['expires_at'] === null ? 'No expiry' : $escape(gmdate('Y-m-d H:i:s', $ban['expires_at'])) . ' UTC'?></td>
<td><?=$ban['active'] ? 'Active' : 'Expired'?></td><td>
<form method="post"><input type="hidden" name="token" value="<?=$escape($token ?? '')?>"><input type="hidden" name="ban_id" value="<?=$escape($ban['id'])?>">
<button class="btn btn-default btn-sm" type="submit" name="action" value="workstation-unban"<?=$banOff?>>Remove ban</button></form></td></tr>
<?php endforeach; ?>
</tbody></table>
</div>
<?php else: ?><p>No manual TELIPHONES listener bans are configured.</p><?php endif; ?>
<h4>Add a manual ban</h4>
<form method="post" autocomplete="off" id="teliphones-ban-form"
 data-administrator-source="<?=$escape($administratorSource)?>"
 data-workstation-sources="<?=$escape(json_encode($workstationSources, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?: '[]')?>">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<fieldset<?=$banOff?>>
<label for="teliphones-ban-source">IP address or CIDR</label>
<input id="teliphones-ban-source" class="form-control" name="source" maxlength="64" required placeholder="198.51.100.24 or 2001:db8::/48">
<label for="teliphones-ban-reason">Reason</label>
<input id="teliphones-ban-reason" class="form-control" name="reason" maxlength="160" required>
<label for="teliphones-ban-hours">Expiry</label>
<select id="teliphones-ban-hours" class="form-control" name="hours"><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option><option value="8760">1 year</option><option value="never">No expiry</option></select>
<button class="btn btn-default" type="submit" name="action" value="workstation-ban"<?=$banOff?>>Add manual ban</button>
</fieldset></form>
<script>
(function () {
    var form = document.getElementById('teliphones-ban-form');
    var field = document.getElementById('teliphones-ban-source');
    if (!form || !field) return;
    function bits(address) {
        address = address.toLowerCase().split('%')[0];
        if (address.indexOf(':') < 0) {
            var octets = address.split('.');
            if (octets.length !== 4 || octets.some(function (part) { return !/^\d{1,3}$/.test(part) || +part > 255; })) return null;
            return octets.map(function (part) { return (+part).toString(2).padStart(8, '0'); }).join('');
        }
        var halves = address.split('::');
        if (halves.length > 2) return null;
        var left = halves[0] ? halves[0].split(':') : [];
        var right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
        var groups = left.concat(new Array(Math.max(0, 8 - left.length - right.length)).fill('0'), right);
        if (groups.length !== 8 || groups.some(function (part) { return !/^[0-9a-f]{1,4}$/.test(part); })) return null;
        return groups.map(function (part) { return parseInt(part, 16).toString(2).padStart(16, '0'); }).join('');
    }
    function contains(network, address) {
        var parts = network.trim().split('/');
        var base = bits(parts[0]), target = bits(address);
        if (base === null || target === null || base.length !== target.length) return false;
        var prefix = parts.length === 1 ? base.length : Number(parts[1]);
        return Number.isInteger(prefix) && prefix >= 0 && prefix <= base.length && base.slice(0, prefix) === target.slice(0, prefix);
    }
    form.addEventListener('submit', function (event) {
        var source = field.value.trim();
        var warnings = [];
        var admin = form.getAttribute('data-administrator-source');
        if (admin && contains(source, admin)) warnings.push('the current FreePBX administrator source (' + admin + ')');
        var workstations = [];
        try { workstations = JSON.parse(form.getAttribute('data-workstation-sources') || '[]'); } catch (ignore) { workstations = []; }
        workstations.forEach(function (item) {
            if (contains(source, item.address)) warnings.push('workstation "' + item.name + '" (' + item.address + ')');
        });
        if (warnings.length && !window.confirm('This ban overlaps ' + warnings.join(' and ') +
            '. It can interrupt this administrator or workstation, including others sharing the same public address. Continue only if you have an independent recovery route.')) {
            event.preventDefault();
        }
    });
})();
</script>
</div>
<?php if ($workstations['web_supported']): ?>
<div class="teliphones-web" id="teliphones-web">
<h4>Management web services</h4>
<p>Authorised workstations may reach exactly these PBX web services through the tunnel. The first entry is the GUI address given to newly paired Windows applications. Changing this list immediately updates the firewall permissions for every paired workstation and removes obsolete ones; already-paired workstations keep their saved GUI address until re-paired.</p>
<?php foreach ($notListening as $entry): ?>
<div class="alert alert-warning teliphones-web-listening">No service is listening for <code><?=$escape($entry['scheme'] . ':' . $entry['port'])?></code> on an address reachable through the tunnel. The firewall permits it, but workstations cannot use it until the web server listens on the wildcard or tunnel address.</div>
<?php endforeach; ?>
<?php if (!$currentListed): ?>
<div class="alert alert-info teliphones-web-current">This page is currently served over <code><?=$escape($currentScheme . ':' . $currentPort)?></code>, which is not in the configured management web services. Add it below so workstations reach the interface you actually use.</div>
<?php endif; ?>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-web-services">Management web services (comma-separated scheme:port, first entry is the workstation GUI address)</label>
<input id="teliphones-web-services" class="form-control" name="web" maxlength="120" pattern="\s*(https?:[0-9]{1,5})(\s*,\s*https?:[0-9]{1,5}){0,3}\s*" required value="<?=$escape($webText !== '' ? $webText : 'http:80, https:443')?>">
<button class="btn btn-default" type="submit" name="action" value="web"<?=$unpairOff?>>Update management web services</button>
</form>
</div>
<?php endif; ?>
</section>
<details class="teliphones-diagnostics teliphones-panel panel panel-default" id="teliphones-diagnostics"<?=!WebSupport::supportsDiagnostics($support) ? ' open' : ''?>>
<summary>Diagnostics <small>— workstation lookup and export</small></summary>
<p>Workstation diagnostics: view or export the bounded PBX-side record for one pairing-lifetime diagnostic ID. This contains server-observed broker and WireGuard events only; it does not contain Windows-local attempts. No recent handshake or traffic is not evidence that a workstation is disconnected.</p>
<?php if (!WebSupport::supportsDiagnostics($support)): ?>
<div class="alert alert-warning">Workstation diagnostics require the updated root broker. Follow the root broker update procedure above, then refresh this page.</div>
<?php else: ?>
<form id="teliphones-diagnostics-form" method="post" action="ajax.php?module=teliphones&amp;command=diagnostics">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-diagnostic-id">Diagnostic session ID (ws- followed by 16 hexadecimal characters)</label>
<input id="teliphones-diagnostic-id" class="form-control" name="diagnostic_id" maxlength="19" pattern="ws-[a-f0-9]{16}" required placeholder="ws-0123456789abcdef">
<button class="btn btn-default" type="submit">View diagnostics</button>
<a id="teliphones-diagnostics-export" hidden download>Export JSON</a>
<pre id="teliphones-diagnostics-output" aria-live="polite"></pre>
</form>
<?php endif; ?>
</details>
<?php if (!$workstations['ssh_ready']): ?><div class="alert alert-warning">Managed SSH is not ready. <?=$escape($workstations['ssh_error'] ?: 'Update the root broker and check OpenSSH/service prerequisites. Web-only pairing remains available.')?></div><?php endif; ?>
<details class="teliphones-pair teliphones-panel panel panel-default" id="teliphones-pair-panel"<?=$expand(['pair'])?>><summary>Pair a Workstation</summary>
<p>In the TELIPHONES Windows application, choose <strong>Add my PBX...</strong>, then <strong>Generate request</strong> and <strong>Copy request</strong>. Pairing explicitly authorises access to this PBX's web administration interface; SSH is a separate choice below and is not permitted by default. Check that the key fingerprint shown in the application matches the fingerprint listed above after pairing. Pairing must be performed over HTTPS.</p>
<form method="post" autocomplete="off">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<fieldset<?=$pairOff?> id="teliphones-pair-fields">
<div class="teliphones-pair-step">
<h4>1. Windows application request</h4>
<label for="teliphones-pair-request">Pairing request from the Windows application</label>
<textarea id="teliphones-pair-request" class="form-control" name="request" rows="3" maxlength="4096" required></textarea>
</div>
<div class="teliphones-pair-step">
<h4>2. PBX hostname and WireGuard</h4>
<label for="teliphones-pair-host">PBX public hostname or IP address (used by the workstation to reach WireGuard)</label>
<input id="teliphones-pair-host" class="form-control" name="endpoint_host" maxlength="253" required value="<?=$escape($defaultHost)?>">
<label for="teliphones-pair-port">WireGuard UDP port on the PBX</label>
<input id="teliphones-pair-port" class="form-control" name="listen_port" inputmode="numeric" pattern="[0-9]{4,5}" required value="<?=$escape($workstations['listen_port'] ?? 51821)?>">
</div>
<div class="teliphones-pair-step">
<h4>3. Management services and permissions</h4>
<?php if ($workstations['web_supported']): ?>
<label for="teliphones-pair-web">Management web services reachable through the tunnel (first entry becomes this workstation's GUI address)</label>
<input id="teliphones-pair-web" class="form-control" name="web" maxlength="120" pattern="\s*(https?:[0-9]{1,5})(\s*,\s*https?:[0-9]{1,5}){0,3}\s*" value="<?=$escape($defaultWebText)?>">
<p class="help-block">Defaults to the saved configuration, or this server's current scheme/port when it is not listed. Behind a reverse proxy, enter the PBX's actual listener, not the proxy port. Verify service reachability on the tunnel address; firewall permissions alone do not configure Apache. Applies to all paired workstations.</p>
<?php endif; ?>
<div id="teliphones-pair-ssh-controls" hidden>
<label for="teliphones-pair-ssh">SSH approval</label>
<select id="teliphones-pair-ssh" class="form-control" name="ssh"><option value="0">FreePBX Web Access only</option><option value="1">FreePBX Web + SSH Access</option></select>
<div id="teliphones-pair-ssh-account" hidden>
<label for="teliphones-pair-ssh-user">Authorised existing Linux account (required when SSH is approved)</label>
<input id="teliphones-pair-ssh-user" class="form-control" name="ssh_user" maxlength="32" pattern="[a-z_][a-z0-9_-]{0,31}" autocomplete="off" disabled>
<p class="help-block">Select an existing account explicitly. No account is created or selected automatically; root is never the default. Managed SSH also requires the Windows OpenSSH request capability and broker readiness.</p>
</div>
</div>
<p class="help-block" id="teliphones-pair-ssh-unavailable" aria-live="polite">SSH approval controls appear only for a valid Windows request that includes SSH capability.</p>
</div>
<div class="teliphones-pair-step">
<h4>4. Duration and optional source restrictions</h4>
<label for="teliphones-pair-mode">Pairing</label>
<select id="teliphones-pair-mode" class="form-control" name="mode"><option value="temporary">Temporary</option><option value="persistent">Persistent trusted workstation (until revoked)</option></select>
<label for="teliphones-pair-minutes">Temporary pairing duration (minutes)</label>
<select id="teliphones-pair-minutes" class="form-control" name="minutes"><?php foreach ([60, 240, 480, 1440] as $minutes): ?><option value="<?=$minutes?>"><?=$minutes?></option><?php endforeach; ?></select>
<label for="teliphones-pair-sources">Lock this workstation to approved IPs/domains (optional, comma-separated)</label>
<input id="teliphones-pair-sources" class="form-control" name="sources" maxlength="2048" placeholder="198.51.100.24, office.example.net"<?=$sourceLockOff?>>
<p class="help-block">A non-empty list uses a dedicated WireGuard listener port and tunnel interface; FreePBX Firewall service rules are managed automatically. If the PBX is behind router/NAT, forward the allocated UDP port to the PBX. DNS names are resolved and refreshed by the PBX; unresolved names do not add access. This initial lock is administrator-set during pairing.</p>
<?php if ($sourceLockOff): ?><p class="help-block">Source-lock controls require broker protocol 8; update the root broker before using this option.</p><?php endif; ?>
</div>
<div class="teliphones-pair-step">
<h4>5. Approve pairing</h4>
<button class="btn btn-primary" type="submit" name="action" value="pair"<?=$pairOff?>>Pair workstation</button>
</div>
</fieldset>
</form></details>
<script>
(function () {
    var request = document.getElementById('teliphones-pair-request');
    var controls = document.getElementById('teliphones-pair-ssh-controls');
    var unavailable = document.getElementById('teliphones-pair-ssh-unavailable');
    var approval = document.getElementById('teliphones-pair-ssh');
    var account = document.getElementById('teliphones-pair-ssh-account');
    var username = document.getElementById('teliphones-pair-ssh-user');
    var sources = document.getElementById('teliphones-pair-sources');
    if (!request || !controls || !approval || !account || !username) return;
    function updateAccount() {
        var needed = approval.value === '1' && !approval.disabled;
        account.hidden = !needed;
        username.disabled = !needed;
        username.required = needed;
    }
    function updateRequest() {
        var supported = false;
        var parts = request.value.trim().split(':');
        if (parts.length === 2 && parts[0] === 'TELIPHONES-PAIR-REQUEST-2' && /^[A-Za-z0-9_-]+$/.test(parts[1])) {
            try {
                var encoded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
                while (encoded.length % 4) encoded += '=';
                var payload = JSON.parse(window.atob(encoded));
                supported = payload.schema === 'teliphones-pair-request/2' &&
                    typeof payload.ssh_public_key === 'string' && payload.ssh_public_key.length > 0;
            } catch (ignore) {
                supported = false;
            }
        }
        controls.hidden = !supported;
        var lockedSshUnavailable = sources && sources.value.trim() !== '' &&
            !<?=$workstations['supported'] && WebSupport::supportsLockedSsh($support) ? 'true' : 'false'?>;
        approval.disabled = !supported || lockedSshUnavailable;
        if (!supported) approval.value = '0';
        if (lockedSshUnavailable) approval.value = '0';
        unavailable.hidden = supported && !lockedSshUnavailable;
        unavailable.textContent = lockedSshUnavailable
            ? 'Locked SSH approval requires the updated root broker; update it before pairing.'
            : supported
            ? 'This request includes SSH capability. SSH still requires explicit administrator approval and an existing Linux account.'
            : 'This request is web-only, invalid or not yet supplied; SSH controls are unavailable.';
        updateAccount();
    }
    request.addEventListener('input', updateRequest);
    if (sources) sources.addEventListener('input', updateRequest);
    approval.addEventListener('change', updateAccount);
    var stateForm = document.getElementById('teliphones-connection-state-form');
    if (stateForm) {
        stateForm.addEventListener('submit', function (event) {
            var selected = document.getElementById('teliphones-connection-state');
            if (selected && selected.value === 'closed' && selected.value !== stateForm.getAttribute('data-current-state') &&
                    !window.confirm('Close the TELIPHONES listener and terminate active workstation tunnels? Existing pairings will be retained. Use your independent PBX recovery route if this is your current connection.')) {
                event.preventDefault();
            }
        });
    }
    updateRequest();
})();
</script>
<script type="application/json" id="teliphones-initial-status"><?=json_encode($initial, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR)?></script>
<script src="modules/teliphones/assets/js/teliphones.js"></script>
<?php require __DIR__ . '/disclaimer.php'; ?>
</div>
