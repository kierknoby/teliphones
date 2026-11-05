<?php
namespace FreePBX\modules\Teliphones;

// Model file/service transactions only; no real root, SSH, account or systemd operations.
$model = [];
function posix_geteuid() { return 0; }
function posix_getpwnam($name) { return ['name' => $name]; }
function is_dir($path) { return true; }
function mkdir($path, $mode = 0700, $recursive = false) { return true; }
function chmod($path, $mode) { return true; }
function chown($path, $owner) { return true; }
function is_link($path) { return false; }
function is_executable($path) { return true; }
function fileowner($path) { return 0; }
function fileperms($path) { return 0700; }
function clearstatcache($unused = false, $path = '') {}
function file_exists($path) { global $model; return array_key_exists($path, $model['files']); }
function is_file($path) { return file_exists($path); }
function file_get_contents($path) { global $model; return $model['files'][$path] ?? false; }
function file_put_contents($path, $content, $flags = 0) {
    global $model;
    if ($model['fail_rollback'] && $content === 'previous broker') return false;
    $model['files'][$path] = $content;
    return strlen($content);
}
function copy($source, $target) {
    return file_put_contents($target, \file_get_contents(dirname(__DIR__) . '/' . basename($source))) !== false;
}
function unlink($path) { global $model; unset($model['files'][$path]); return true; }
function exec($command, &$output = null, &$result = null) {
    global $model;
    $model['commands'][] = $command;
    $output = [];
    $result = 0;
    if (strpos($command, ' -c ') !== false && $model['failure'] === 'import') $result = 1;
    if (strpos($command, ' -l ') !== false && $model['failure'] === 'php') $result = 1;
    if (strpos($command, 'systemctl restart teliphones-broker.service') !== false) {
        ++$model['restarts'];
        if ($model['failure'] === 'activation' && $model['restarts'] === 1) $result = 1;
    }
}
require_once dirname(__DIR__) . '/BrokerBootstrap.php';
$reset = static function (string $failure = '') use (&$model): void {
    $model = ['files' => [BrokerBootstrap::BROKER_FILE => 'previous broker',
        BrokerBootstrap::BROKER_DIR . '/ssh_authority.py' => 'previous authority',
        BrokerBootstrap::BROKER_DIR . '/FirewallListener.php' => 'previous listener',
        BrokerBootstrap::BROKER_UNIT => 'previous unit'], 'commands' => [], 'failure' => $failure,
        'fail_rollback' => false, 'restarts' => 0];
};
$assert = static function (bool $value, string $message): void {
    if (!$value) throw new \RuntimeException($message);
};
$reset();
$assert(BrokerBootstrap::install('/module'), 'Successful validated upgrade must start the broker.');
$assert($model['files'][BrokerBootstrap::BROKER_DIR . '/FirewallListener.php'] === \file_get_contents(dirname(__DIR__) . '/FirewallListener.php')
    && $model['files'][BrokerBootstrap::BROKER_FILE] === \file_get_contents(dirname(__DIR__) . '/support_broker.py')
    && $model['files'][BrokerBootstrap::BROKER_DIR . '/ssh_authority.py'] === \file_get_contents(dirname(__DIR__) . '/ssh_authority.py'),
    'Both current module helpers must replace the separately installed root helpers byte-for-byte.');
$assert(strpos($model['files'][BrokerBootstrap::BROKER_FILE], 'VERSION = "0.6.2"') !== false
    && strpos($model['files'][BrokerBootstrap::BROKER_FILE], 'self.ipt(iptables, "-I", FREEPBX_HOOK, "1"') !== false
    && strpos($model['files'][BrokerBootstrap::BROKER_FILE], 'def reconcile_listener(') !== false
    && strpos($model['files'][BrokerBootstrap::BROKER_FILE], 'def handle_connection(') !== false,
    'The upgraded root broker must be 0.6.2 with pairing transport, the internal FreePBX jump and persistent listener service reconciliation.');
$commands = implode("\n", $model['commands']);
$assert(strpos($commands, ' -c ') < strpos($commands, 'systemctl restart teliphones-broker.service'), 'Import validation must precede activation.');
foreach (['import', 'php', 'activation'] as $failure) {
    $reset($failure);
    try {
        BrokerBootstrap::install('/module');
        throw new \LogicException('Failed upgrade was reported as successful.');
    } catch (\RuntimeException $error) {
        $assert(strpos($error->getMessage(), 'Previous broker files restored') !== false, 'Rollback must be explicit.');
    }
    $assert($model['files'][BrokerBootstrap::BROKER_FILE] === 'previous broker'
        && $model['files'][BrokerBootstrap::BROKER_DIR . '/ssh_authority.py'] === 'previous authority'
        && $model['files'][BrokerBootstrap::BROKER_DIR . '/FirewallListener.php'] === 'previous listener'
        && $model['files'][BrokerBootstrap::BROKER_UNIT] === 'previous unit', 'Upgrade failure must restore all prior root artifacts.');
    $assert($model['restarts'] >= 1, 'Previously active broker must be restarted after rollback.');
}
$reset('activation');
$model['fail_rollback'] = true;
try {
    BrokerBootstrap::install('/module');
    throw new \LogicException('Incomplete rollback was reported as successful.');
} catch (\RuntimeException $error) {
    $assert(strpos($error->getMessage(), 'rollback is incomplete') !== false, 'Failed rollback must require explicit repair.');
}
$assert(!isset($model['files']['/etc/ssh/sshd_config']) && !isset($model['files']['/etc/passwd']),
    'Broker upgrade must never write system SSH or administrator accounts.');
echo "Broker upgrade tests: PASS (modelled validation, activation, restoration and rollback failure; real systemd still required)\n";
