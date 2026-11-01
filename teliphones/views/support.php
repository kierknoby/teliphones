<?php
$escape = static function ($value): string {
    return htmlspecialchars(is_scalar($value) ? (string)$value : '', ENT_QUOTES, 'UTF-8');
};
$support = isset($support) && is_array($support) ? $support : [];
$status = is_array($support['status'] ?? null) ? $support['status'] : [];
$readiness = is_array($status['readiness'] ?? null) ? $status['readiness'] : [];
$session = is_array($status['session'] ?? null) ? $status['session'] : [];
$phase = $status['phase'] ?? 'Not configured';
?>
<div class="container-fluid">
<h2>TELIPHONES</h2>
<p>Temporary, administrator-authorised remote support. Installation and module enablement do not imply dependency readiness or engineer access.</p>
<?php if (isset($notice)): ?>
<div class="alert <?=$notice['ok'] ?? false ? 'alert-info' : 'alert-danger'?>"><?=$escape($notice['error'] ?? $notice['message'] ?? 'Request submitted.')?></div>
<?php endif; ?>
<?php if (!empty($support['error'])): ?><div class="alert alert-danger"><?=$escape($support['error'])?></div><?php endif; ?>
<h3>System readiness</h3>
<p><strong><?=$escape($phase)?></strong>. Module status: <?=$escape($status['enabled'] ?? false ? 'Enabled' : 'Not available or disabled')?>.</p>
<table class="table table-striped"><thead><tr><th>Required component</th><th>Status</th></tr></thead><tbody>
<?php foreach ($readiness as $component => $available): ?>
<tr><td><?=$escape($component)?></td><td><?=$available === true ? 'Installed / configured (operation not yet verified)' : 'Missing or unavailable'?></td></tr>
<?php endforeach; ?>
</tbody></table>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<button class="btn btn-default" name="action" value="dependencies" type="submit">Approve installation of WireGuard tools</button>
<p>Installs only Debian's wireguard-tools using the root broker and the system's configured package repositories. No SSH service or firewall policy is changed. Missing PHP, Python, OpenSSH, systemd or root bootstrap requires the PBX platform administrator / Module Admin to repair the platform; this module cannot elevate web PHP.</p>
</form>
<h3>Remote support</h3>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-minutes">Duration (minutes)</label>
<select id="teliphones-minutes" name="minutes" class="form-control">
<?php foreach ([5, 15, 30, 60, 120, 240] as $minutes): ?><option value="<?=$minutes?>"><?=$minutes?></option><?php endforeach; ?>
</select>
<p>Authorisation permits the gateway-enrolled engineer's temporary public-key-only root SSH shell on the WireGuard address (port 22222) and the gateway's enrolled web service scope. Engineer access remains closed until local and independent Checker verification pass.</p>
<button class="btn btn-primary" name="action" value="authorise" type="submit" <?=empty($status['can_authorise']) ? 'disabled' : ''?>>Authorise Remote Support</button>
<button class="btn btn-danger" name="action" value="revoke" type="submit">Revoke Remote Support</button>
</form>
<h3>Active session</h3>
<p>Session state: <strong><?=$escape($phase)?></strong></p>
<?php if ($session): ?>
<p>Session: <code><?=$escape($session['session_id'] ?? '')?></code><br>
Authorised engineer identity: <?=$escape($status['engineer'] ?? 'Not yet established')?> (gateway-enrolled SSH key fingerprint; presence is not reported)<br>
Remaining: <?=$escape(max(0, (int)($session['expires_at'] ?? 0) - time()))?> seconds<br>
Permitted access: <?=!empty($status['access_verified']) ? 'WireGuard-scoped web access and temporary source-restricted, public-key-only root SSH.' : 'No current engineer SSH access has been confirmed.'?></p>
<?php endif; ?>
<a class="btn btn-default" href="config.php?display=teliphones">Refresh session status</a>
<?php if (is_array($status['challenge'] ?? null)): ?>
<h4>Independent Checker verification</h4>
<p>The reference gateway does not provide an automatic signed Checker service. Give this session-bound challenge to your independent Checker, then submit its signed evidence here. No Linux command on the PBX is required.</p>
<pre><?=$escape(json_encode($status['challenge'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))?></pre>
<form method="post">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<label for="teliphones-evidence">Signed Checker evidence JSON</label>
<textarea id="teliphones-evidence" name="evidence" class="form-control" rows="8" maxlength="32768" required></textarea>
<button class="btn btn-primary" type="submit" name="action" value="evidence">Verify evidence and open approved access</button>
</form>
<?php endif; ?>
<details><summary>Secure gateway enrollment</summary>
<p>Use a separately deployed gateway and a customer client certificate enrolled there. TLS verification is mandatory. Credentials are stored root-only by the broker and are never returned to the browser. Submit this form over HTTPS. Configuration changes are refused during an active session.</p>
<form method="post" autocomplete="off">
<input type="hidden" name="token" value="<?=$escape($token ?? '')?>">
<?php foreach (['url' => 'Gateway HTTPS URL', 'certificate' => 'Customer client certificate PEM', 'private_key' => 'Customer client private key PEM', 'ca' => 'Gateway CA certificate PEM', 'checker_key' => 'Independent Checker ECDSA P-256 public key PEM'] as $field => $label): ?>
<label for="teliphones-<?=$field?>"><?=$escape($label)?></label>
<?php if ($field === 'url'): ?><input id="teliphones-url" class="form-control" name="url" type="url" required>
<?php else: ?><textarea id="teliphones-<?=$field?>" class="form-control" name="<?=$field?>" rows="3" maxlength="16384" required></textarea><?php endif; ?>
<?php endforeach; ?>
<button class="btn btn-default" type="submit" name="action" value="configure">Save secure enrollment</button>
</form></details>
<p>Expiry is enforced by PBX timers and the temporary SSH systemd lifetime, independently of this page. Cleanup failures quarantine support; revocation may be retried, but quarantine is not cleared from the GUI.</p>
</div>
