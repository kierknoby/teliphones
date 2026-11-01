<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }
$dir = '/var/lib/teliphones';
if (!is_dir($dir)) @mkdir($dir, 0700, true);
@chmod($dir, 0700);
$config = '/etc/teliphones.conf';
if (!file_exists($config)) {
    @file_put_contents($config, "; TELIPHONES 0.0.1 development configuration\n; Support transport is temporary and session-scoped.\n; On-PBX uses local ephemeral WireGuard. On-net/Off-net require an external Connect implementation.\n");
    @chmod($config, 0600);
}


$connectConfig = '/etc/teliphones-connect.conf';
if (!file_exists($connectConfig)) {
    @file_put_contents($connectConfig, "; TELIPHONES Connect enrollment\n; Configure an implementation of the published Connect contract.\nCONNECT_URL=\nCLIENT_CERT=/etc/teliphones/connect-client.crt\nCLIENT_KEY=/etc/teliphones/connect-client.key\nCA_CERT=/etc/teliphones/connect-ca.crt\n");
    @chmod($connectConfig, 0600);
}


// TELIPHONES is enabled by default. A root-created disabled marker is preserved across upgrades.
$service = '/etc/systemd/system/teliphones-reconcile.service';
$unit = <<<'UNIT'
[Unit]
Description=TELIPHONES support authority reconciliation
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/fwconsole teliphones reconcile

[Install]
WantedBy=multi-user.target
UNIT;
if (!file_exists($service) || file_get_contents($service) !== $unit . "\n") {
    @file_put_contents($service, $unit . "\n", LOCK_EX);
    @chmod($service, 0644);
}
if (is_executable('/usr/bin/systemctl')) {
    @exec('/usr/bin/systemctl daemon-reload >/dev/null 2>&1');
    @exec('/usr/bin/systemctl enable teliphones-reconcile.service >/dev/null 2>&1');
}
