<?php
$state=$this->getState(); $enabled=!empty($state['enabled']); $hasSession=isset($state['session_id']);
$stage=(string)($state['state']??'off');
$transport=in_array($stage,['connected','verified','ready'],true)?'Connected':(in_array($stage,['peer_configured','path_provisioned'],true)?'Connecting':'Not connected');
$verification=!empty($state['checker_accepted'])?'Verified':(!empty($state['attested'])?'Local checks passed; Checker pending':'Not verified');
$engineerAccess=$stage==='ready'?'Ready for the authorised engineer':'Not available';
?>
<div class="container-fluid">
<h2>TELIPHONES</h2><p>Temporary, locally authorised support for FreePBX.</p>
<?php if(!$enabled): ?><div class="alert alert-warning"><strong>TELIPHONES is disabled.</strong> Local root must enable it before support can be authorised.</div>
<?php elseif($hasSession): ?><div class="alert alert-info"><strong>Session status: <?=htmlspecialchars(ucfirst($stage),ENT_QUOTES,'UTF-8')?></strong><br>Topology: <strong><?=htmlspecialchars($state['topology_label']??$state['topology']??'On-PBX',ENT_QUOTES,'UTF-8')?></strong><br>WireGuard transport: <?=htmlspecialchars($transport,ENT_QUOTES,'UTF-8')?><br>Verification: <?=htmlspecialchars($verification,ENT_QUOTES,'UTF-8')?><br>Engineer service access: <?=htmlspecialchars($engineerAccess,ENT_QUOTES,'UTF-8')?><br>Engineer presence: <strong>Not reliably reported</strong><br>Session: <code><?=htmlspecialchars($state['session_id']??'',ENT_QUOTES,'UTF-8')?></code><br>Expires: <?=htmlspecialchars(date(DATE_RFC3339,(int)($state['expires_at']??0)),ENT_QUOTES,'UTF-8')?><br>Remaining: <?=htmlspecialchars((string)max(0,(int)($state['expires_at']??0)-time()),ENT_QUOTES,'UTF-8')?> seconds<br><strong>Support is not implied by authorisation or transport connectivity.</strong></div>
<?php else: ?><div class="alert alert-success"><strong>TELIPHONES is enabled.</strong> Remote support is off until local root explicitly authorises a temporary window.</div><?php endif; ?>
<h4>Support topology</h4>
<p><strong>On-PBX</strong> is the reference topology. On-net and Off-net are defined integration topologies and are not currently operational.</p>
<p>FreePBX 17 prefers <code>10.20.17.0/24</code> as an allocation pool. TELIPHONES installs only the session-specific route and refuses overlapping On-PBX proposals.</p>
<h4>Root controls</h4><pre>fwconsole teliphones authorise --minutes=60 --topology=on-pbx
fwconsole teliphones authorise --minutes=60 --topology=on-net
fwconsole teliphones authorise --minutes=60 --topology=off-net
fwconsole teliphones provision
fwconsole teliphones connect-confirm
fwconsole teliphones attest
fwconsole teliphones checker-request
fwconsole teliphones checker-accept --evidence-file=/root/checker.json
fwconsole teliphones open --ssh-key='ssh-ed25519 ...'
fwconsole teliphones status
fwconsole teliphones revoke</pre>
<p>The GUI cannot create privileged support authority.</p></div>
