<?php
require_once dirname(__DIR__) . '/WebSupport.php';
use FreePBX\modules\Teliphones\WebSupport;

$assert = static function (bool $value, string $message): void {
    if (!$value) throw new RuntimeException($message);
};
$admin = new class {
    public function checkSection($section) { return $section === '*'; }
};
$delegated = new class {
    public function checkSection($section) { return false; }
};
$unknown = new class {
    public function checkSection($section) { return 'yes'; }
};
$assert(WebSupport::authorised($admin), 'Full administrator must be accepted.');
$assert(!WebSupport::authorised(null, $admin), 'An absent session must be rejected even with a framework object.');
$assert(!WebSupport::authorised($delegated), 'Delegated page-only access must be rejected.');
$assert(!WebSupport::authorised($unknown), 'Unknown permission results must fail closed.');
$assert(!WebSupport::authorised(null), 'Missing framework user must fail closed.');
$assert(!WebSupport::authorised(new stdClass()), 'Missing framework API must fail closed.');
$integerAdmin = new class {
    public function checkSection($section) { return $section === '*' ? 1 : 0; }
};
$assert(WebSupport::authorised('admin', $integerAdmin), 'Framework user with integer permission must pass.');
$assert(WebSupport::authorised('admin', $admin), 'Scalar session username must use the framework context.');
$assert(!WebSupport::authorised($admin, $delegated), 'Restricted framework context must not fall back to a permissive session.');
foreach ([null, [], false, '', new stdClass()] as $user) {
    $assert(!WebSupport::authorised($user), 'Missing or malformed session must fail closed.');
    $assert(!WebSupport::authorised($user, $admin), 'Malformed session must fail even with framework context.');
}
foreach (['1', 'yes', 2, -1, false, null] as $result) {
    $context = new class($result) {
        private $result;
        public function __construct($result) { $this->result = $result; }
        public function checkSection($section) { return $this->result; }
    };
    $assert(!WebSupport::authorised('admin', $context), 'Arbitrary truthy permission result must be rejected.');
}
$assert(strpos(WebSupport::accessError(null, $admin), 'authentication failed') !== false, 'Authentication failure must be distinct.');
$assert(strpos(WebSupport::accessError('admin', $delegated), 'permission denied') !== false, 'Permission denial must be distinct.');
if (!class_exists('ampuser')) {
    class ampuser {
        private string $username;
        public function __construct($username) { $this->username = $username; }
        public function checkSection($section) { return $section === '*' && $this->username === 'full-admin' ? 1 : 0; }
    }
    $assert(WebSupport::authorised('full-admin'), 'Username must resolve through the available ampuser class.');
    $assert(!WebSupport::authorised('restricted-admin'), 'Username resolution must preserve restriction.');
    foreach (['true', 'yes', '1', 'forged-admin'] as $username) {
        $assert(!WebSupport::authorised($username), 'An arbitrary username string must not itself grant administrator permission.');
    }
}
$assert(WebSupport::validRequest(['action' => 'revoke', 'token' => 'token'], 'token'), 'Valid revocation request must pass.');
$assert(!WebSupport::validRequest(['action' => 'revoke', 'token' => 'wrong'], 'token'), 'Invalid CSRF token must fail.');
$assert(!WebSupport::validRequest(['action' => 'exec', 'token' => 'token'], 'token'), 'Arbitrary command must fail.');
$assert(!WebSupport::validRequest(['action' => [], 'token' => []], 'token'), 'Malformed input must fail.');

$render = static function (array $support): string {
    $token = 'test-token';
    ob_start();
    include dirname(__DIR__) . '/views/support.php';
    return (string)ob_get_clean();
};
set_error_handler(static function ($severity, $message, $file, $line): bool {
    if (!(error_reporting() & $severity)) return false;
    throw new ErrorException($message, 0, $severity, $file, $line);
});
try {
    $html = $render(['ok' => false, 'error' => '<unavailable>']);
    $assert(strpos($html, '&lt;unavailable&gt;') !== false, 'Errors must be HTML escaped.');
    $assert(strpos($html, 'value="authorise" type="submit" disabled') !== false, 'Unknown readiness must disable authorisation.');
    $assert(strpos($html, 'fwconsole teliphones') === false, 'CLI operation listing must not be shown.');
    $assert(strpos($html, 'Revoke Remote Support') !== false, 'Revocation must remain visible when status is unavailable.');
    $html = $render(['status' => ['phase' => 'Connecting', 'enabled' => true, 'readiness' => ['wg' => false], 'session' => ['state' => 'locally_verified', 'expires_at' => time() + 60], 'challenge' => ['nonce' => '<nonce>']]]);
    $assert(strpos($html, 'Missing or unavailable') !== false, 'Missing dependencies must not appear installed.');
    $assert(strpos($html, 'Signed Checker evidence JSON') !== false, 'A challenge must expose the evidence submission step.');
    $assert(strpos($html, '<nonce>') === false, 'Challenge data must be escaped.');

    $root = sys_get_temp_dir() . '/teliphones-broker-test-' . bin2hex(random_bytes(4));
    mkdir($root, 0700);
    $unit = $root . '/teliphones-broker.service';
    $socket = $root . '/control.sock';
    $client = static function ($state) use ($unit, $socket): WebSupport {
        return new WebSupport($socket, $unit, static function () use ($state) { return $state; });
    };
    $probeCalled = false;
    $notInstalled = (new WebSupport($socket, $unit, static function () use (&$probeCalled) { $probeCalled = true; return 'active'; }))->diagnoseUnavailable();
    $assert($notInstalled['condition'] === 'not_installed' && !$probeCalled, 'Missing unit must report not installed without probing systemd.');
    $unavailable = $client('active')->request(['action' => 'status']);
    $assert(!empty($unavailable['unavailable']) && $unavailable['ok'] === false, 'Unreachable socket must be flagged unavailable.');
    file_put_contents($unit, "[Unit]\n");
    $assert($client('inactive')->diagnoseUnavailable() === ['condition' => 'stopped', 'service' => 'inactive'], 'Inactive service must report stopped.');
    $assert($client('failed')->diagnoseUnavailable()['condition'] === 'stopped', 'Failed service must report stopped.');
    $assert($client('active')->diagnoseUnavailable() === ['condition' => 'socket_unavailable', 'service' => 'active', 'socket_present' => false], 'Active service without socket must report socket unavailable.');
    touch($socket);
    $assert($client('active')->diagnoseUnavailable()['socket_present'] === true, 'Present but unusable socket must be distinguished.');
    foreach ([null, '', "active\n; rm -rf /", '<b>'] as $state) {
        $assert($client($state)->diagnoseUnavailable()['condition'] === 'unverified', 'Unknown or malformed service state must be not verified.');
    }
    $assert((new WebSupport($socket, $unit . '.missing', null))->diagnoseUnavailable()['condition'] === 'not_installed', 'Default probe must not be required for a missing unit.');
    unlink($socket);
    unlink($unit);
    rmdir($root);

    $renderBroker = static function (array $broker, array $support = ['ok' => false, 'unavailable' => true, 'error' => 'x']) {
        $token = 'test-token';
        ob_start();
        include dirname(__DIR__) . '/views/support.php';
        return (string)ob_get_clean();
    };
    $script = \FreePBX\modules\Teliphones\BrokerBootstrap::ROOT_BOOTSTRAP_SCRIPT;
    $guidance = static function (string $html): string {
        $start = strpos($html, 'class="teliphones-install"');
        return $start === false ? '' : substr($html, $start, strpos($html, '<section class="teliphones-panel') - $start);
    };
    $html = $renderBroker(['available' => false, 'condition' => 'not_installed']);
    $assert(strpos($html, '<h4>TELIPHONES Installation Incomplete</h4>') !== false && strpos($html, 'The FreePBX module installed successfully') !== false,
        'Missing broker must report the installation as incomplete.');
    $assert(strpos($html, '<details class="teliphones-install" open><summary><strong>Complete Installation</strong></summary>') !== false, 'Missing broker must expand Complete Installation.');
    $assert(strpos($html, '<pre id="teliphones-bootstrap-script" style="user-select:all">' . htmlspecialchars($script, ENT_QUOTES, 'UTF-8') . '</pre>') !== false,
        'GUI must render the verified bootstrap procedure verbatim.');
    $assert(html_entity_decode(htmlspecialchars($script, ENT_QUOTES, 'UTF-8'), ENT_QUOTES, 'UTF-8') === $script, 'Copied text must equal the verified procedure.');
    $assert(strpos($html, 'id="teliphones-copy-bootstrap">Copy Commands</button>') !== false && strpos($html, "getElementById('teliphones-bootstrap-script')") !== false
        && strpos($html, 'navigator.clipboard.writeText(text)') !== false, 'Copy Commands must copy the procedure text.');
    $assert(strpos($html, 'existing root shell') !== false && strpos($html, 'refresh this page') !== false && strpos($html, 'does <strong>not</strong> authorise a remote support session') !== false
        && strpos($html, 'Do not run it during an active support session') !== false && strpos($html, 'web-service-owned module directory') !== false,
        'Installation guidance must cover root shell, scope, staging rationale, active sessions and refresh.');
    foreach (['systemctl status teliphones-broker.service --no-pager -l', 'ls -l /run/teliphones/control.sock', 'Active: active (running)', 'srw-rw----',
              'Service missing', 'Failed startup', 'Socket missing', 'journalctl -u teliphones-broker.service -n 50 --no-pager'] as $text) {
        $assert(strpos($html, $text) !== false, 'Verification/troubleshooting guidance must include: ' . $text);
    }
    $assert(strpos($html, 'fwconsole teliphones bootstrap') === false && strpos($html, '<pre style="user-select:all"># ') === false, 'Only copyable, verified commands may be shown.');
    $assert(preg_match('/\b(apt|apt-get|sudo|iptables|nft|setenforce)\b|ip route|chmod [0-7]*[2367]\b|chmod -R [ago]*\+w|PRIVATE KEY/i', strip_tags($guidance($html))) === 0,
        'Installation guidance must not touch packages, sudo, firewall, routing, permissions weakening or secrets.');
    $assert(strpos($html, 'Root broker not installed') !== false && strpos($html, 'Not configured') === false, 'Missing broker must not be reported as merely not configured.');
    $html = $renderBroker(['available' => false, 'condition' => 'stopped', 'service' => 'failed']);
    $assert(strpos($html, 'Broker service installed but stopped') !== false && strpos($html, 'Installation Incomplete') === false
        && strpos($html, '<details class="teliphones-troubleshooting" open>') !== false && strpos($html, '<details class="teliphones-install">') !== false,
        'Stopped service must expand troubleshooting, keep installation collapsed and not claim an incomplete install.');
    $html = $renderBroker(['available' => false, 'condition' => 'socket_unavailable', 'service' => 'active', 'socket_present' => true]);
    $assert(strpos($html, 'Broker running but control socket unavailable') !== false && strpos($html, 'the socket exists') !== false
        && strpos($html, '<details class="teliphones-troubleshooting" open>') !== false, 'Socket failure must show socket guidance.');
    $html = $renderBroker(['available' => false, 'condition' => 'unverified', 'service' => 'not verified']);
    $assert(strpos($html, 'Broker state not verified') !== false && strpos($html, 'Complete Installation') !== false, 'Unverified state must still offer installation guidance.');
    $html = $renderBroker(['available' => false, 'condition' => 'stopped', 'service' => '<script>']);
    $assert(strpos($html, '"<script>"') === false && strpos($html, '&lt;script&gt;') !== false, 'Service state must be escaped.');
    $html = $renderBroker(['available' => true, 'condition' => 'operational'], ['ok' => true, 'error' => null, 'status' => ['protocol' => 3, 'component_version' => '0.6.2', 'phase' => 'Ready', 'enabled' => true, 'can_authorise' => true,
        'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true], 'items' => []],
        'readiness' => ['WireGuard wg' => true, 'Gateway enrollment' => true]]]);
    $assert(strpos($html, 'Operational (control socket verified)') !== false && strpos($html, 'missing') === false
        && strpos($html, 'teliphones-install') === false && strpos($html, 'teliphones-troubleshooting') === false
        && strpos($html, 'Copy Commands') === false && strpos($html, 'teliphones-bootstrap') === false, 'Operational broker must not show installation guidance.');
    $buttonDisabled = static function (string $html, string $action): bool {
        return (bool)preg_match('/<button[^>]*value="' . $action . '"[^>]*\sdisabled/', $html);
    };
    foreach (['authorise', 'revoke', 'configure'] as $action) {
        $assert(!$buttonDisabled($html, $action), "Operational broker must enable $action.");
    }
    $assert(strpos($html, '<fieldset disabled aria-disabled="true" id="teliphones-enrollment-fields"') === false && strpos($html, 'Unavailable: the privileged') === false, 'Operational broker must not disable enrollment.');
    $assert($buttonDisabled($html, 'dependencies') && strpos($html, '>WireGuard tools installed</button>') !== false
        && strpos($html, '>Approve installation of WireGuard tools</button>') === false && strpos($html, 'WireGuard tools are installed (wg executable detected by the broker).') !== false,
        'Verified WireGuard tools must disable and relabel the installation action.');
    $assert($buttonDisabled($html, 'evidence') && preg_match('/<div id="teliphones-evidence-section" hidden>/', $html) === 1, 'Evidence submission requires a Checker challenge.');
    $html = $renderBroker(['available' => true, 'condition' => 'operational'], ['ok' => true, 'status' => ['protocol' => 3, 'phase' => 'Missing dependency', 'can_authorise' => false,
        'readiness' => ['WireGuard wg' => true, 'Required PHP functions / extensions' => false]]]);
    $assert(strpos($html, 'WireGuard tools missing') === false && strpos($html, 'Other dependencies missing: Required PHP functions / extensions') !== false
        && strpos($html, 'value="authorise" type="submit" disabled') !== false, 'Other missing dependencies must be distinguished and block authorisation.');
    $legacy = ['ok' => true, 'error' => null, 'status' => ['phase' => 'Ready', 'enabled' => true, 'can_authorise' => true, 'readiness' => ['WireGuard wg' => true, 'Gateway enrollment' => true]]];
    $html = $renderBroker(['available' => true, 'condition' => 'operational'], $legacy);
    $assert(strpos($html, '<h4>Root broker update required</h4>') !== false && strpos($html, '<details class="teliphones-install" open>') !== false
        && strpos($html, '<pre id="teliphones-bootstrap-script" style="user-select:all">' . htmlspecialchars($script, ENT_QUOTES, 'UTF-8') . '</pre>') !== false
        && strpos($html, 'Operational (control socket verified)') !== false && strpos($html, 'teliphones-system-warning') === false && strpos($html, 'teliphones-troubleshooting') === false,
        'A pre-0.1.3 broker must remain operational but require the bootstrap to be rerun.');
    $assert(preg_match('/<button[^>]*value="authorise"[^>]*\sdisabled/', $html) === 0
        && preg_match('/"broker_current":false/', $html) === 1, 'Outdated broker must keep actions available through ordinary submission and disable live monitoring.');
    $note = \FreePBX\modules\Teliphones\BrokerBootstrap::UPGRADE_NOTE;
    $plain = static function (string $text): string { return str_replace(['`', '**'], '', $text); };
    $assert(strpos(html_entity_decode(strip_tags($html), ENT_QUOTES, 'UTF-8'), $plain($note)) !== false
        && strpos($html, '<code>/usr/local/lib/teliphones-broker/support_broker.py</code>') !== false, 'GUI must render the upgrade note.');
    $html = $renderBroker(['available' => false, 'condition' => 'not_installed']);
    $assert(strpos($html, 'class="teliphones-upgrade-note"') !== false, 'Installation guidance must include the upgrade note.');
} finally {
    restore_error_handler();
}
echo "Web support tests: PASS (permission/CSRF enforcement, missing readiness, escaped state, browser workflow, broker conditions, installation guidance)\n";

require_once dirname(__DIR__) . '/BrokerBootstrap.php';
use FreePBX\modules\Teliphones\BrokerBootstrap;
$installSource = (string)file_get_contents(dirname(__DIR__) . '/install.php');
$assert(strpos($installSource, "if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }") === 6
    && substr_count($installSource, 'BrokerBootstrap::install(__DIR__);') === 1, 'Module Admin installer must delegate once to the shared bootstrap.');
$bootstrapSource = (string)file_get_contents(dirname(__DIR__) . '/BrokerBootstrap.php');
$assert(strpos($bootstrapSource, "copy(\$moduleDir . '/support_broker.py', \$brokerFile)") !== false
    && strpos($bootstrapSource, 'chmod($brokerFile, 0600)') !== false
    && strpos($bootstrapSource, 'systemctl restart teliphones-broker.service') !== false
    && strpos($bootstrapSource, "copy(\$moduleDir . '/support_broker.py', \$brokerFile)")
        < strpos($bootstrapSource, 'systemctl restart teliphones-broker.service'),
    'Root bootstrap must install the current broker as a protected root-owned file and restart it.');
$brokerSource = (string)file_get_contents(dirname(__DIR__) . '/support_broker.py');
$assert(strpos($brokerSource, 'WORKSTATION_OWNER_CHAIN = "teliphones_owner_v1"') !== false
    && strpos(BrokerBootstrap::UPGRADE_NOTE, '0.6.3 requires broker version 0.6.2, broker protocol 12') !== false
    && strpos(BrokerBootstrap::UPGRADE_NOTE, '/usr/local/lib/teliphones-broker/ssh_authority.py') !== false
    && strpos(BrokerBootstrap::UPGRADE_NOTE, 'normal system SSH service') !== false
    && strpos(BrokerBootstrap::UPGRADE_NOTE, 'incomplete rollback') !== false,
    'The upgrade note must document both protocol-6 helpers, rollback recovery and preservation of normal SSH.');
$assert(strpos($bootstrapSource, 'workstations.json') === false && strpos($bootstrapSource, 'workstation-wg.key') === false,
    'Bootstrap must not recreate or delete workstation pairing state or the PBX key.');
$assert(preg_match('/posix_geteuid\(\) !== 0\) \{\s*error_log\(\'[^\'\n]*Complete Installation on FreePBX 17[^\'\n]*\'\);\s*return false;/', $bootstrapSource) === 1,
    'Non-root installation must log the bootstrap step and return without throwing or escalating.');
$assert(preg_match('/sudo|setuid|chmod\([^)]*04[0-7]{3}|apt-get/', $bootstrapSource) === 0, 'Bootstrap must not escalate privileges or install packages.');
$assert(strpos(BrokerBootstrap::BROKER_UNIT_CONTENTS, 'ExecStart=/usr/bin/python3 ' . BrokerBootstrap::BROKER_FILE . "\n") !== false
    && strpos(BrokerBootstrap::BROKER_UNIT_CONTENTS, "User=root\n") !== false, 'Broker unit must execute the root-owned installed copy.');
$script = BrokerBootstrap::ROOT_BOOTSTRAP_SCRIPT;
$assert(strpos($script, "(\nset -eu\n") === 0 && substr($script, -1) === ')', 'Procedure must run in a fail-fast subshell.');
$assert(strpos($script, 'test "$(id -u)" -eq 0') < strpos($script, 'mkdir -p "$DEST"'), 'Procedure must verify root before changing anything.');
$assert(strpos($script, 'chown -R root:root "$DEST"') < strpos($script, 'require "/root/teliphones-bootstrap/install.php"')
    && strpos($script, 'require "/var/www') === false, 'Installer must execute only from the root-owned staging copy.');
$assert(preg_match('/\bsudo\b|\bapt|iptables|nft|ip route|chmod [0-7]*[2367]\b/', $script) === 0, 'Procedure must not escalate, install packages, weaken permissions or alter networking.');
$readme = (string)file_get_contents(dirname(__DIR__) . '/README.md');
$assert(strpos($readme, "## Complete Installation on FreePBX 17\n") !== false && strpos($readme, "```bash\n" . $script . "\n```") !== false,
    'Module README must contain the same verified procedure as the GUI.');
$assert(strpos($readme, "### After upgrading TELIPHONES\n\n" . BrokerBootstrap::UPGRADE_NOTE . "\n") !== false, 'Module README must contain the same upgrade note as the GUI.');
foreach (['does not necessarily update the separately installed, root-owned broker', 'no support session is active', 'rerun the root bootstrap'] as $text) {
    $assert(strpos(BrokerBootstrap::UPGRADE_NOTE, $text) !== false, 'Upgrade note must state: ' . $text);
}
$assert(preg_match('/\bsudo\b|chmod|setuid/', BrokerBootstrap::UPGRADE_NOTE) === 0, 'Upgrade note must not escalate privileges or weaken permissions.');
$assert(strpos($readme, 'fwconsole teliphones bootstrap') === false, 'README must not document an unverified bootstrap command.');
$consoleSource = (string)file_get_contents(dirname(__DIR__) . '/Console/Teliphones.class.php');
$assert(strpos($consoleSource, "'bootstrap'") === false, 'No unverified console bootstrap path may execute module files from the web-owned directory as root.');
echo "Broker bootstrap tests: PASS (shared installer, non-root fallback, verified root procedure, README/GUI consistency)\n";
