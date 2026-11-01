<?php
namespace FreePBX\modules\Teliphones;

// Model platform failures without running root/systemd/network commands.
$model = [];
function posix_geteuid() { global $model; return $model['uid']; }
function clearstatcache($unused = false, $path = '') {}
function is_file($path) { global $model; return !in_array($path, $model['missing'], true); }
function is_link($path) { global $model; return in_array($path, $model['links'], true); }
function fileowner($path) { global $model; return in_array($path, $model['web_owned'], true) ? 1000 : 0; }
function fileperms($path) { global $model; return in_array($path, $model['writable'], true) ? 0777 : 0700; }
function is_executable($path) { global $model; return !in_array($path, $model['missing'], true); }
function file_get_contents($path) {
    global $model;
    if ($path === BrokerBootstrap::BROKER_FILE) return $model['legacy_helper'] ? 'old broker without argument handling' : \file_get_contents(dirname(__DIR__) . '/support_broker.py');
    return \file_get_contents($path);
}
function exec($command, &$output, &$result) {
    global $model;
    $model['commands'][] = $command;
    $output = [];
    $result = 0;
    if (strpos($command, 'disable --now') !== false) $result = $model['stop_result'];
    elseif (strpos($command, 'systemctl show') !== false) {
        $output = $model['state'];
        $result = $model['show_result'];
    } else $result = $model['helper_result'];
}
require_once dirname(__DIR__) . '/BrokerBootstrap.php';
$reset = static function () use (&$model): void {
    $model = ['uid' => 0, 'missing' => [], 'links' => [], 'web_owned' => [], 'writable' => [], 'commands' => [],
        'stop_result' => 0, 'show_result' => 0, 'helper_result' => 0, 'legacy_helper' => false,
        'state' => ['ActiveState=inactive', 'MainPID=0', 'ControlPID=0', 'KillMode=control-group']];
};
$assert = static function ($value, $message): void {
    if (!$value) throw new \RuntimeException($message);
};
$fails = static function () use ($assert): void {
    try { BrokerBootstrap::uninstallWorkstations(); }
    catch (\RuntimeException $error) { return; }
    $assert(false, 'Unverified uninstall must throw.');
};
$reset();
BrokerBootstrap::uninstallWorkstations();
$assert(count($model['commands']) === 3 && strpos($model['commands'][0], 'disable --now') !== false
    && strpos($model['commands'][1], 'systemctl show') !== false
    && strpos($model['commands'][2], '/usr/bin/python3 -I \'/usr/local/lib/teliphones-broker/support_broker.py\' --uninstall-workstations') !== false,
    'Stop, independently verify stop, then execute only the trusted installed helper in isolated Python mode.');
foreach ([
    ['uid', 1000], ['missing', [BrokerBootstrap::BROKER_FILE]], ['missing', ['/usr/bin/systemctl']],
    ['missing', ['/usr/bin/timeout']], ['links', [BrokerBootstrap::BROKER_FILE]],
    ['links', [BrokerBootstrap::BROKER_DIR]], ['web_owned', [BrokerBootstrap::BROKER_FILE]],
    ['web_owned', ['/usr/local/lib']], ['writable', [BrokerBootstrap::BROKER_DIR]],
    ['writable', ['/usr/local']], ['legacy_helper', true],
] as [$key, $value]) {
    $reset(); $model[$key] = $value;
    $fails();
    $assert($model['commands'] === [], 'Untrusted/non-root uninstall must not execute a helper or stop command.');
}
foreach ([
    ['stop_result', 1], ['show_result', 1], ['state', ['ActiveState=active', 'MainPID=0', 'ControlPID=0']],
    ['state', ['ActiveState=inactive', 'MainPID=123', 'ControlPID=0']],
    ['state', ['ActiveState=inactive', 'MainPID=0', 'ControlPID=123']], ['state', []],
    ['state', ['ActiveState=inactive', 'MainPID=0', 'ControlPID=0', 'KillMode=process']],
] as [$key, $value]) {
    $reset(); $model[$key] = $value;
    $fails();
    $assert(count($model['commands']) <= 2, 'An unverified service stop must not invoke cleanup.');
}
foreach ([1, 124, 137] as $result) {
    $reset(); $model['helper_result'] = $result;
    $fails();
    $assert(count($model['commands']) === 3, 'A failed/timed-out helper must abort rather than perform fallback shell cleanup.');
}
$source = file_get_contents(dirname(__DIR__) . '/uninstall.php');
$assert(strpos($source, 'BrokerBootstrap::uninstallWorkstations();') < strpos($source, '$sessionFile'),
    'Verified workstation teardown precedes all state removal.');
$assert(!preg_match('/ip link|nft delete|unlink\(\$workstationFile/', $source),
    'No independent shell workstation cleanup or inconsistent key/state deletion is permitted.');
$assert(strpos($source, 'broker artifacts and recovery state retained') < strpos($source, 'foreach ([\'/etc/systemd/system/teliphones-broker.service\''),
    'Support cleanup failures also retain the installed recovery helper.');
echo "Broker uninstall tests: PASS (22 trust, ordering, stop verification and failure scenarios; 3 source invariants)\n";
