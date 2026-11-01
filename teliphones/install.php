<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }
$dir = '/var/lib/teliphones';
if (!is_dir($dir)) @mkdir($dir, 0700, true);
@chmod($dir, 0700);
$config = '/etc/teliphones.conf';
if (!file_exists($config)) {
    @file_put_contents($config, "; TELIPHONES 0.1.2 development configuration\n; Support transport is temporary and session-scoped.\n; On-PBX uses local ephemeral WireGuard. On-net/Off-net require an external Connect implementation.\n");
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

if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
    error_log('TELIPHONES: GUI root broker not installed. Module Admin installation is not running as root; no privilege escalation will be attempted.');
    return;
}
if (!is_executable('/usr/bin/python3') || !is_executable('/usr/bin/systemctl') || !function_exists('posix_getpwnam') || !posix_getpwnam('asterisk')) {
    error_log('TELIPHONES: GUI root broker requires systemd, Python 3 and the FreePBX asterisk account.');
    return;
}
if (is_link($dir) || !chown($dir, 0) || !chmod($dir, 0700)) {
    throw new RuntimeException('TELIPHONES state directory must be root-owned and private.');
}
foreach ([$config, $connectConfig] as $protectedConfig) {
    if (is_link($protectedConfig) || !chown($protectedConfig, 0) || !chmod($protectedConfig, 0600)) {
        throw new RuntimeException('TELIPHONES configuration must be root-owned and private.');
    }
}
$brokerDirectory = '/usr/local/lib/teliphones-broker';
if (is_link($brokerDirectory) || (!is_dir($brokerDirectory) && !mkdir($brokerDirectory, 0700, true))
    || fileowner($brokerDirectory) !== 0 || (fileperms($brokerDirectory) & 0022) !== 0) {
    throw new RuntimeException('TELIPHONES broker directory must be root-owned and not writable by group or other users.');
}
$brokerFile = $brokerDirectory . '/support_broker.py';
if (is_link($brokerFile) || !copy(__DIR__ . '/support_broker.py', $brokerFile) || !chown($brokerFile, 0) || !chmod($brokerFile, 0600)) {
    throw new RuntimeException('Unable to install the root-owned TELIPHONES broker.');
}
$brokerUnit = <<<'UNIT'
[Unit]
Description=TELIPHONES restricted GUI support broker
After=network.target teliphones-reconcile.service

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/teliphones-broker/support_broker.py
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
UNIT;
$brokerService = '/etc/systemd/system/teliphones-broker.service';
if (is_link($brokerService) || file_put_contents($brokerService, $brokerUnit . "\n", LOCK_EX) === false || !chown($brokerService, 0) || !chmod($brokerService, 0644)) {
    throw new RuntimeException('Unable to install the TELIPHONES broker service.');
}
exec('/usr/bin/systemctl daemon-reload 2>&1', $brokerOutput, $brokerResult);
if ($brokerResult !== 0) throw new RuntimeException('Unable to reload systemd for TELIPHONES broker.');
exec('/usr/bin/systemctl enable teliphones-broker.service 2>&1', $brokerOutput, $brokerResult);
if ($brokerResult !== 0) throw new RuntimeException('Unable to enable TELIPHONES broker.');
exec('/usr/bin/systemctl restart teliphones-broker.service 2>&1', $brokerOutput, $brokerResult);
if ($brokerResult !== 0) throw new RuntimeException('Unable to start TELIPHONES broker.');
