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
set_error_handler(static function ($severity, $message, $file, $line): void {
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
} finally {
    restore_error_handler();
}
echo "Web support tests: PASS (permission/CSRF enforcement, missing readiness, escaped state, browser workflow)\n";
