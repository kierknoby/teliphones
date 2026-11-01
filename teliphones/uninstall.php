<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }

require_once __DIR__ . '/BrokerBootstrap.php';
// No root execution of the web-owned module Python, and no parallel shell cleanup.
\FreePBX\modules\Teliphones\BrokerBootstrap::uninstallWorkstations();

require_once __DIR__ . '/SupportAdapter.php';
require_once __DIR__ . '/WireGuardAgent.php';
require_once __DIR__ . '/LocalAttestor.php';
require_once __DIR__ . '/CheckerEvidence.php';
require_once __DIR__ . '/ConnectClient.php';

$sessionFile = '/var/lib/teliphones/session.json';
$disabledFile = '/var/lib/teliphones/disabled';
@file_put_contents($disabledFile, "disabled\n", LOCK_EX);
@chmod($disabledFile, 0600);
$session = is_readable($sessionFile) ? json_decode((string)file_get_contents($sessionFile), true) : null;
$connect = new \FreePBX\modules\Teliphones\ConnectClient();
$remoteState = $connect->state();
$sshClean = (new \FreePBX\modules\Teliphones\SupportAdapter())->destroy();
$wireguardClean = (new \FreePBX\modules\Teliphones\WireGuardAgent())->destroy();
$attestationClean = (new \FreePBX\modules\Teliphones\LocalAttestor())->destroy();
$checkerClean = (new \FreePBX\modules\Teliphones\CheckerEvidence())->destroy();

if (!$sshClean || !$wireguardClean || !$attestationClean || !$checkerClean) {
    error_log('TELIPHONES uninstall: one or more local teardown operations failed; inspect retained state before removing it.');
}

if ($remoteState) {
    $cleanupSession = $remoteState;
    if (!$connect->destroy($cleanupSession)) {
        error_log('TELIPHONES uninstall: remote gateway cleanup failed; retained connect state for manual follow-up.');
    }
}

$remoteClean = !$remoteState || !$connect->state();
if ($sshClean && $wireguardClean && $attestationClean && $checkerClean && $remoteClean) {
    foreach ([$sessionFile, '/var/lib/teliphones/local-verification.json', $disabledFile, '/var/lib/teliphones/quarantine.json'] as $f) {
        if (is_file($f)) @unlink($f);
    }
} else {
    $quarantine = [
        'time' => date(DATE_RFC3339),
        'reason' => 'uninstall-cleanup-incomplete',
        'local_cleanup' => $sshClean && $wireguardClean && $attestationClean && $checkerClean,
        'gateway_cleanup' => $remoteClean,
    ];
    @file_put_contents('/var/lib/teliphones/quarantine.json', json_encode($quarantine, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);
    @chmod('/var/lib/teliphones/quarantine.json', 0600);
    throw new RuntimeException('TELIPHONES uninstall cleanup incomplete; broker artifacts and recovery state retained.');
}

foreach (['/etc/systemd/system/teliphones-broker.service', '/usr/local/lib/teliphones-broker/support_broker.py', '/run/teliphones/control.sock'] as $brokerFile) {
    if (file_exists($brokerFile) && !unlink($brokerFile)) throw new RuntimeException('Unable to remove TELIPHONES broker artifact.');
}

$service = '/etc/systemd/system/teliphones-reconcile.service';
if (is_executable('/usr/bin/systemctl')) {
    @exec('/usr/bin/systemctl disable teliphones-reconcile.service >/dev/null 2>&1');
}
if (is_file($service)) @unlink($service);
if (is_executable('/usr/bin/systemctl')) @exec('/usr/bin/systemctl daemon-reload >/dev/null 2>&1');
