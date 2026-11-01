<?php
namespace FreePBX\modules\Teliphones {
    function stream_socket_client($address, &$errno, &$error, $timeout) {
        $GLOBALS['brokerRequests']++;
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
    $_POST = ['action' => 'revoke', 'token' => $scenario === 'csrf-post' ? 'wrong-token' : 'known-token'];
    $GLOBALS['brokerRequests'] = 0;
    function show_view($file, $variables) {
        extract($variables);
        include $file;
    }
    ob_start();
    include dirname(__DIR__) . '/page.teliphones.php';
    $html = (string)ob_get_clean();
    $denied = in_array($scenario, ['unauthenticated', 'restricted', 'restricted-post', 'missing', 'malformed'], true);
    $expectedRequests = $denied ? 0 : (in_array($scenario, ['full-post', 'string-constant-post'], true) ? 2 : 1);
    if ($GLOBALS['brokerRequests'] !== $expectedRequests) {
        throw new RuntimeException('Incorrect broker request count for ' . $scenario);
    }
    if ($denied && (http_response_code() !== 403 || str_contains($html, 'broker unavailable'))) {
        throw new RuntimeException('Denied request must not reach broker readiness.');
    }
    if (!$denied && !str_contains($html, 'Privileged TELIPHONES broker unavailable')) {
        throw new RuntimeException('Authorised user must reach distinct broker availability reporting.');
    }
    if ($scenario === 'csrf-post' && (!str_contains($html, 'invalid action or security token') || http_response_code() !== 403)) {
        throw new RuntimeException('Invalid POST CSRF must fail before a privileged request.');
    }
    echo "Web page tests: PASS ($scenario)\n";
}
