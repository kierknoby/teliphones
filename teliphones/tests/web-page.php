<?php
namespace FreePBX\modules\Teliphones {
    function stream_socket_client($address, &$errno, &$error, $timeout) {
        $GLOBALS['brokerRequests']++;
        $response = array_shift($GLOBALS['brokerResponses']);
        if ($response !== null) {
            $pair = \stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
            fwrite($pair[1], json_encode($response) . "\n");
            $GLOBALS['brokerPeers'][] = $pair[1];
            return $pair[0];
        }
        $errno = 2;
        $error = 'Unavailable';
        return false;
    }
}

namespace {
    $scenario = $argv[1] ?? 'full';
    if ($scenario === 'direct') {
        register_shutdown_function(static function (): void {
            if (!empty($GLOBALS['brokerRequests'])) throw new \RuntimeException('Direct access must not contact the broker.');
        });
    } else {
        define('FREEPBX_IS_AUTH', $scenario === 'false-constant' ? false : 'framework-authenticated');
    }
    $_SERVER['REQUEST_METHOD'] = str_contains($scenario, 'post') ? 'POST' : 'GET';
    $_SESSION = ['AMP_user' => 'admin', 'teliphones_token' => 'known-token'];
    if ($scenario === 'unauthenticated') $_SESSION = [];
    if ($scenario === 'missing') unset($_SESSION['AMP_user']);
    if ($scenario === 'malformed') $_SESSION['AMP_user'] = [];
    $ampuser = new class($scenario) {
        private string $scenario;
        public function __construct($scenario) { $this->scenario = $scenario; }
        public function checkSection($section) {
            return str_contains($this->scenario, 'restricted') ? 0 : ($section === '*' ? 1 : 0);
        }
    };
    $postAction = 'revoke';
    foreach (['authorise', 'dependencies', 'configure', 'evidence'] as $candidate) {
        if (str_contains($scenario, $candidate)) $postAction = $candidate;
    }
    $_POST = ['action' => $postAction, 'token' => $scenario === 'csrf-post' ? 'wrong-token' : 'known-token', 'minutes' => '15'];
    if ($postAction === 'configure') $_SERVER['HTTPS'] = 'on';
    $GLOBALS['brokerRequests'] = 0;
    $GLOBALS['brokerPeers'] = [];
    $readyStatus = ['ok' => true, 'error' => null, 'status' => ['protocol' => 3, 'phase' => 'Missing dependency', 'enabled' => true, 'can_authorise' => true,
        'workstations' => ['ready' => false, 'requirements' => ['wg' => false, 'ip' => true, 'nft' => true], 'items' => []],
        'readiness' => ['WireGuard wg' => false, 'Temporary SSH server' => true, 'Gateway enrollment' => true, 'Checker trusted public key' => false]]];
    $GLOBALS['brokerResponses'] = [];
    if ($scenario === 'invalid-status-authorise-post') $GLOBALS['brokerResponses'] = [['ok' => false, 'error' => 'Broker internal failure.']];
    if ($scenario === 'malformed-status-authorise-post') $GLOBALS['brokerResponses'] = ['not-a-broker-object'];
    if (str_starts_with($scenario, 'recovered')) {
        $GLOBALS['brokerResponses'] = [$readyStatus];
        if ($scenario === 'recovered-authorise-post') $GLOBALS['brokerResponses'] = [$readyStatus, ['ok' => true, 'message' => 'Remote support authorisation started.'], $readyStatus];
        if ($scenario === 'recovered-failed-authorise-post') $GLOBALS['brokerResponses'] = [$readyStatus, ['ok' => false, 'error' => 'Another TELIPHONES operation is running.'], $readyStatus];
    }
    function show_view($file, $variables) {
        extract($variables);
        include $file;
    }
    ob_start();
    include dirname(__DIR__) . '/page.teliphones.php';
    $html = (string)ob_get_clean();
    $denied = in_array($scenario, ['unauthenticated', 'restricted', 'restricted-post', 'missing', 'malformed'], true);
    $recovered = str_starts_with($scenario, 'recovered');
    $actionPosts = ['invalid-status-authorise-post', 'malformed-status-authorise-post', 'full-post', 'string-constant-post', 'authorise-post', 'dependencies-post', 'configure-post', 'evidence-post'];
    $expectedRequests = $denied ? 0 : (in_array($scenario, ['recovered-authorise-post', 'recovered-failed-authorise-post'], true) ? 3 : 1);
    $fail = static function (string $message) use ($scenario): void {
        throw new RuntimeException($message . ' (' . $scenario . ')');
    };
    if ($GLOBALS['brokerRequests'] !== $expectedRequests) $fail('Incorrect broker request count: ' . $GLOBALS['brokerRequests']);
    if ($denied && (http_response_code() !== 403 || str_contains($html, 'broker unavailable'))) {
        $fail('Denied request must not reach broker readiness.');
    }
    $warnings = substr_count($html, 'teliphones-system-warning');
    $failures = substr_count($html, 'teliphones-action-failure');
    $buttonDisabled = static function (string $action) use ($html): bool {
        return (bool)preg_match('/<button[^>]*value="' . $action . '"[^>]*\sdisabled/', $html);
    };
    if (!$denied && !$recovered) {
        if ($warnings !== 1 || substr_count($html, 'TELIPHONES Installation Incomplete') !== 1) $fail('Broker-unavailable system warning must appear exactly once.');
        $expectedFailures = in_array($scenario, $actionPosts, true) ? 1 : 0;
        if ($failures !== $expectedFailures) $fail('Action-failure warning must appear only after an attempted action.');
        if ($expectedFailures && (!str_contains($html, 'border:3px solid') || !str_contains($html, 'Operation failed: ' . \FreePBX\modules\Teliphones\WebSupport::ACTION_LABELS[$postAction]))) {
            $fail('Action failure must be emphasised and name the failed operation.');
        }
        foreach (['dependencies', 'authorise', 'revoke', 'configure'] as $action) {
            if (!$buttonDisabled($action)) $fail("$action must be disabled while the broker is unavailable.");
        }
        if (!str_contains($html, '<fieldset disabled')) $fail('Enrollment fields must be disabled.');
        if (substr_count($html, 'Unavailable: the privileged TELIPHONES broker is not operational') < 3) $fail('Disabled actions must explain why.');
        if (!preg_match('/<a class="btn btn-default" href="config.php\?display=teliphones">Refresh session status<\/a>/', $html)) $fail('Refresh must remain available.');
        if (!str_contains($html, '<pre style="user-select:all">fwconsole teliphones revoke</pre>')) $fail('Emergency root revocation path must be preserved.');
        if (!is_file('/etc/systemd/system/teliphones-broker.service') && (!str_contains($html, 'TELIPHONES Installation Incomplete') || !str_contains($html, 'Copy Commands'))) {
            $fail('Missing broker must show the installation section.');
        }
        if (str_contains($html, '>Ready<') || str_contains($html, 'Operational (control socket verified)')) $fail('Unavailable broker must never be reported operational.');
    }
    if (in_array($scenario, ['full-post', 'string-constant-post'], true) && (!str_contains($html, 'Revocation was NOT performed') || str_contains($html, 'Remote support revoked'))) {
        $fail('Unreachable revocation must not be reported as successful.');
    }
    if ($recovered) {
        if ($warnings !== 0 || str_contains($html, 'Complete Installation') || str_contains($html, 'Copy Commands')) $fail('Recovered broker must clear unavailable warnings.');
        if (!str_contains($html, 'Operational (control socket verified)') || !str_contains($html, 'WireGuard tools missing') || !str_contains($html, 'Other dependencies missing: Checker trusted public key')) {
            $fail('Recovered broker must report operational state and distinguish missing dependencies.');
        }
        foreach (['dependencies', 'authorise', 'revoke', 'configure'] as $action) {
            if ($buttonDisabled($action)) $fail("$action must be enabled when the broker is available.");
        }
        if ($scenario === 'recovered-authorise-post' && ($failures !== 0 || !str_contains($html, 'Remote support authorisation started.'))) $fail('Successful action must not render a failure.');
        if ($scenario === 'recovered-failed-authorise-post' && ($failures !== 1 || !str_contains($html, 'Operation failed: Authorise Remote Support') || !str_contains($html, 'Another TELIPHONES operation is running.'))) {
            $fail('Broker-reported failure must be emphasised once.');
        }
    }
    if ($scenario === 'csrf-post' && (!str_contains($html, 'invalid action or security token') || http_response_code() !== 403 || $failures !== 0)) {
        $fail('Invalid POST CSRF must fail before a privileged request.');
    }
    echo "Web page tests: PASS ($scenario)\n";
}
