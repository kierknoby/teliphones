<?php
// Live status endpoint tests: authorisation, read-only status, CSRF, sanitisation and module AJAX hooks.
namespace FreePBX\modules\Teliphones {
    function stream_socket_client($address, &$errno, &$error, $timeout) {
        $response = array_shift($GLOBALS['brokerResponses']);
        if ($response !== null) {
            $pair = \stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
            fwrite($pair[1], json_encode($response) . "\n");
            $GLOBALS['brokerPeers'][] = $pair[1];
            $GLOBALS['brokerSockets'][] = $pair[1];
            return $pair[0];
        }
        $errno = 2;
        $error = 'Unavailable';
        return false;
    }
}

namespace {
    use FreePBX\modules\Teliphones\WebSupport;

    if (!interface_exists('BMO')) eval('interface BMO { public function install(); public function uninstall(); }');
    if (!class_exists('FreePBX_Helpers')) eval('class FreePBX_Helpers { public function __construct($freepbx = null) {} }');
    require_once dirname(__DIR__) . '/Teliphones.class.php';

    $assert = static function (bool $condition, string $message): void {
        if (!$condition) throw new RuntimeException($message);
    };
    $admin = new class { public function checkSection($section) { return $section === '*' ? true : false; } };
    $restricted = new class { public function checkSection($section) { return 0; } };
    $truthy = new class { public function checkSection($section) { return 'yes'; } };
    $session = ['AMP_user' => 'admin', 'teliphones_token' => 'known-token'];
    $operation = ['id' => 'abc123', 'action' => 'dependencies', 'state' => 'running', 'stage' => 'Installing WireGuard tools',
        'message' => '', 'started_at' => 1000, 'finished_at' => null];
    $ready = ['ok' => true, 'error' => null, 'status' => ['protocol' => 3, 'component_version' => '0.6.1', 'phase' => 'Missing dependency', 'enabled' => true, 'can_authorise' => false,
        'workstations' => ['ready' => false, 'requirements' => ['wg' => false, 'ip' => true, 'nft' => true], 'items' => []],
        'readiness' => ['WireGuard wg' => false, 'Gateway enrollment' => true], 'session' => null, 'server_time' => 1010, 'operation' => $operation,
        'private_key' => '-----BEGIN PRIVATE KEY-----secret', 'gateway' => ['certificate' => 'secret-cert']]];
    $client = new WebSupport('/nonexistent/control.sock', '/nonexistent/unit', static function () { return null; });
    $call = static function (string $command, string $method, array $post = [], ?array $sessionData = null, $user = null, array $responses = []) use ($client, $session, $admin): array {
        $GLOBALS['brokerResponses'] = $responses;
        $GLOBALS['brokerSockets'] = [];
        $result = WebSupport::ajax($command, $method, $post, $sessionData ?? $session, $user ?? $admin, ['HTTPS' => 'on'], $client);
        $sent = [];
        foreach ($GLOBALS['brokerSockets'] as $peer) {
            $line = fgets($peer);
            if (is_string($line)) $sent[] = json_decode($line, true)['action'] ?? null;
        }
        $result['sent'] = $sent;
        $result['json'] = json_encode($result['body']);
        return $result;
    };

    // Authorisation: every request (status and action) requires a full FreePBX administrator.
    foreach ([
        'restricted administrator' => [$session, $restricted],
        'truthy string permission' => [$session, $truthy],
        'unauthenticated session' => [[], $admin],
        'malformed session' => [['AMP_user' => ['admin']], $admin],
        'missing framework user' => [$session, new stdClass()],
    ] as $name => [$sessionData, $user]) {
        foreach ([['status', 'GET', []], ['action', 'POST', ['action' => 'dependencies', 'token' => 'known-token']]] as [$command, $method, $post]) {
            $result = $call($command, $method, $post, $sessionData, $user, [$ready, ['ok' => true]]);
            $assert($result['code'] === 403 && $result['body']['auth_error'] === true && $result['body']['teliphones_api'] === 1 && $result['sent'] === [],
                "$name must be rejected before the broker is contacted ($command).");
        }
    }

    // Status is read-only: exactly one broker "status" request, GET only, sanitised output.
    $result = $call('status', 'GET', ['action' => 'dependencies', 'token' => 'known-token'], null, null, [$ready, ['ok' => true]]);
    $status = $result['body']['status'];
    $assert($result['code'] === 200 && $result['sent'] === ['status'], 'Status polling must issue only a broker status request, even if POST data is present.');
    $assert($status['available'] === true && $status['operation']['id'] === 'abc123' && $status['operation']['state'] === 'running'
        && $status['operation']['label'] === 'Approve installation of WireGuard tools' && $status['server_time'] === 1010, 'Status must report the running operation.');
    $assert(strpos($result['json'], 'secret') === false && strpos($result['json'], 'PRIVATE KEY') === false && !isset($status['private_key']) && !isset($status['gateway']),
        'Status must not expose credentials, keys or configuration.');
    $assert($status['readiness'] === ['WireGuard wg' => false, 'Gateway enrollment' => true], 'Readiness must be a boolean map.');
    $assert($status['broker_current'] === true, 'A protocol 3 broker supports live monitoring and pairing.');
    foreach (['0.6.0', '0.6.1', '0.7.0', 'invalid', null] as $version) {
        $versioned = $ready;
        if ($version === null) unset($versioned['status']['component_version']);
        else $versioned['status']['component_version'] = $version;
        $current = WebSupport::publicStatus($versioned, ['available' => true])['broker_current'];
        $assert($current === ($version === '0.6.1' || $version === '0.7.0'),
            'Only brokers at or above the required patch version may report current.');
    }
    foreach ([null, 1, 2, '3', 3.0] as $protocol) {
        $legacy = $ready;
        $legacy['status']['protocol'] = $protocol;
        $assert(WebSupport::publicStatus($legacy, ['available' => true])['broker_current'] === false, 'Older or malformed broker protocol must not be treated as current.');
    }
    $assert(WebSupport::publicStatus($ready, ['available' => false])['broker_current'] === false, 'Unavailable broker is never current.');
    $result = $call('status', 'POST', [], null, null, [$ready]);
    $assert($result['code'] === 405 && $result['sent'] === [], 'Status must be GET only.');
    $result = $call('action', 'GET', ['action' => 'dependencies', 'token' => 'known-token'], null, null, [$ready, ['ok' => true]]);
    $assert($result['code'] === 405 && $result['sent'] === [], 'Actions must require POST.');
    foreach (['exec', '', 'status&x'] as $command) {
        $result = $call($command, 'GET', [], null, null, [$ready]);
        $assert($result['code'] === 400 && $result['sent'] === [] && $result['body']['teliphones_api'] === 1, 'Unknown AJAX commands must be rejected.');
    }

    // Untrusted operation records are dropped rather than forwarded.
    foreach ([['id' => '<script>'], ['action' => 'exec'], ['state' => 'done'], ['started_at' => 'now']] as $bad) {
        $public = WebSupport::publicStatus(['ok' => true, 'status' => ['operation' => $bad + $operation]], ['available' => true]);
        $assert($public['operation'] === null, 'Malformed operation records must be discarded.');
    }
    $public = WebSupport::publicStatus(['ok' => true, 'status' => ['operation' => ['stage' => str_repeat('x', 5000)] + $operation]], ['available' => true]);
    $assert(strlen($public['operation']['stage']) === 200, 'Operation text must be bounded.');
    $unavailable = WebSupport::publicStatus(['ok' => false, 'unavailable' => true], ['available' => false, 'condition' => 'stopped']);
    $assert($unavailable['available'] === false && $unavailable['condition'] === 'stopped' && $unavailable['operation'] === null && $unavailable['phase'] === null,
        'Unavailable broker status must not claim any operation or phase.');

    // Actions: CSRF, allowlist, server-side broker availability and started-operation reporting.
    $result = $call('action', 'POST', ['action' => 'dependencies', 'token' => 'wrong-token'], null, null, [$ready, ['ok' => true]]);
    $assert($result['code'] === 403 && $result['sent'] === ['status'] && strpos($result['body']['notice']['error'], 'security token') !== false, 'Invalid CSRF token must be rejected.');
    $result = $call('action', 'POST', ['action' => 'dependencies'], ['AMP_user' => 'admin'], null, [$ready, ['ok' => true]]);
    $assert($result['code'] === 403 && $result['sent'] === ['status'], 'Missing session token must be rejected.');
    $result = $call('action', 'POST', ['action' => 'exec', 'token' => 'known-token'], null, null, [$ready, ['ok' => true]]);
    $assert($result['code'] === 403 && $result['sent'] === ['status'], 'Non-allowlisted actions must be rejected.');
    $result = $call('action', 'POST', ['action' => 'authorise', 'token' => 'known-token'], null, null, []);
    $assert($result['code'] === 200 && $result['body']['ok'] === false && $result['sent'] === [] && $result['body']['status']['available'] === false
        && strpos($result['body']['notice']['error'], 'not attempted') !== false, 'Unavailable broker must refuse actions server-side.');
    $result = $call('action', 'POST', ['action' => 'revoke', 'token' => 'known-token'], null, null, []);
    $assert($result['body']['ok'] === false && strpos($result['body']['notice']['error'], 'Revocation was NOT performed') !== false, 'Unreachable revocation must not be reported as performed.');
    $started = ['ok' => true, 'operation_id' => 'def456', 'message' => 'TELIPHONES operation started. Monitoring progress automatically…'];
    $result = $call('action', 'POST', ['action' => 'dependencies', 'token' => 'known-token', 'minutes' => '5'], null, null, [$ready, $started, $ready]);
    $assert($result['code'] === 200 && $result['sent'] === ['status', 'dependencies', 'status'] && $result['body']['notice']['operation_id'] === 'def456'
        && $result['body']['notice']['message'] === 'TELIPHONES operation started. Monitoring progress automatically…' && strpos($result['json'], 'Refresh') === false,
        'A started operation must return its id and a fresh status for monitoring.');
    $result = $call('action', 'POST', ['action' => 'dependencies', 'token' => 'known-token'], null, null, [$ready, ['ok' => false, 'error' => 'Another TELIPHONES operation is running.'], $ready]);
    $assert($result['body']['ok'] === false && $result['body']['notice']['operation'] === 'Approve installation of WireGuard tools'
        && $result['body']['notice']['operation_id'] === null, 'Broker refusals (including duplicates) must be reported as failed actions.');
    $result = $call('action', 'POST', ['action' => 'configure', 'token' => 'known-token', 'private_key' => 'SECRET-KEY'], null, null, [$ready, ['ok' => true, 'operation_id' => 'aa', 'echo' => 'SECRET-KEY'], $ready]);
    $assert(strpos($result['json'], 'SECRET-KEY') === false, 'Action responses must not echo submitted credentials.');

    // The FreePBX module hook exposes only authenticated status, action and diagnostics commands.
    $module = (new ReflectionClass(\FreePBX\modules\Teliphones::class))->newInstanceWithoutConstructor();
    $setting = ['authenticate' => true, 'allowremote' => false];
    foreach (['status' => true, 'action' => true, 'diagnostics' => true, 'exec' => false, '' => false, 'getState' => false] as $request => $allowed) {
        $assert($module->ajaxRequest($request, $setting) === $allowed, "ajaxRequest('$request') must " . ($allowed ? 'be allowed.' : 'be refused.'));
    }
    $assert($setting === ['authenticate' => true, 'allowremote' => false], 'ajaxRequest must not disable FreePBX authentication or allow remote access.');
    $_REQUEST = ['command' => 'status'];
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SESSION = ['AMP_user' => 'admin'];
    $GLOBALS['ampuser'] = $restricted;
    $GLOBALS['brokerResponses'] = [$ready];
    $body = $module->ajaxHandler();
    $assert($body['auth_error'] === true && count($GLOBALS['brokerResponses']) === 1, 'ajaxHandler must enforce administrator access before contacting the broker.');
    $GLOBALS['ampuser'] = $admin;
    $body = $module->ajaxHandler();
    $assert($body['ok'] === true && $body['status']['operation']['id'] === 'abc123', 'ajaxHandler must return live status for administrators.');

    // Initial render of a running operation: spinner in the affected row, buttons disabled, monitoring resumes from embedded state.
    $render = static function (array $support): string {
        $broker = ['available' => true, 'condition' => 'operational'];
        $token = 't';
        ob_start();
        include dirname(__DIR__) . '/views/support.php';
        return (string)ob_get_clean();
    };
    $html = $render($ready);
    $assert(preg_match('/data-teliphones-component="WireGuard wg"><span class="teliphones-spinner" aria-hidden="true"><\/span><span class="teliphones-cell-text teliphones-busy">Installing WireGuard tools…<\/span>/u', $html) === 1,
        'A running dependency installation must show a spinner beside WireGuard wg.');
    $assert(preg_match('/data-teliphones-component="Gateway enrollment"><span class="teliphones-spinner" hidden/', $html) === 1, 'Unaffected rows must not show a spinner.');
    $assert(preg_match('/<button[^>]*value="dependencies"[^>]*\sdisabled/', $html) === 1 && strpos($html, 'Another TELIPHONES operation is in progress.') !== false,
        'The running action must be disabled with an explanation.');
    $assert(strpos($html, 'id="teliphones-live" role="status" aria-live="polite"') !== false, 'Progress must be announced to assistive technology.');
    $assert(strpos($html, 'Monitoring progress automatically…') !== false && strpos($html, 'This operation is taking longer than expected. TELIPHONES is continuing to check its status.') !== false,
        'Monitoring and slow-operation messages must be present.');
    $assert(preg_match('/<script type="application\/json" id="teliphones-initial-status">(.*?)<\/script>/s', $html, $match) === 1
        && json_decode($match[1], true)['operation']['id'] === 'abc123', 'Initial status must be embedded so monitoring resumes after navigation.');
    $assert(strpos($html, '<script src="modules/teliphones/assets/js/teliphones.js"></script>') !== false, 'The live status script must be loaded.');
    $assert(strpos($match[1], '<') === false && strpos($match[1], 'secret') === false, 'Embedded status must be script-safe and contain no secrets.');
    $failed = $ready;
    $failed['status']['operation'] = ['state' => 'failed', 'message' => 'apt failed', 'finished_at' => 1009] + $operation;
    $html = $render($failed);
    $assert(strpos($html, 'teliphones-fail">✕ Installation failed</span>') !== false && preg_match('/<button[^>]*value="dependencies"[^>]*\sdisabled/', $html) === 0,
        'A failed installation must be shown as failed and remain retryable.');
    $done = $ready;
    $done['status']['operation'] = ['state' => 'succeeded', 'finished_at' => 1009] + $operation;
    $done['status']['readiness']['WireGuard wg'] = true;
    $html = $render($done);
    $assert(strpos($html, 'data-teliphones-component="WireGuard wg"><span class="teliphones-spinner" hidden aria-hidden="true"></span><span class="teliphones-cell-text teliphones-ok">✓ Installed / configured (operation not yet verified)</span>') !== false
        && strpos($html, '>WireGuard tools installed</button>') !== false, 'Verified installation must show the success state and retire the install action.');
    $cleanup = $ready;
    $cleanup['status']['operation'] = null;
    $cleanup['status']['phase'] = 'Revoking expired session';
    $cleanup['status']['session'] = ['session_id' => 's1', 'state' => 'revoking', 'expires_at' => 900];
    $html = $render($cleanup);
    $assert(strpos($html, 'background cleanup in progress…') !== false && preg_match('/<button[^>]*value="revoke"[^>]*\sdisabled/', $html) === 0,
        'Background cleanup must show progress while revocation stays available.');
    $revoking = $ready;
    $revoking['status']['operation'] = ['action' => 'revoke', 'stage' => 'Revoking remote support'] + $operation;
    $html = $render($revoking);
    $assert(preg_match('/<button[^>]*value="revoke"[^>]*\sdisabled/', $html) === 1, 'A running revocation must not be submitted twice.');
    echo "Live status tests: PASS (administrator-only read-only status, CSRF actions, sanitisation, progress rendering, AJAX hooks)\n";
}
