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
$assert(WebSupport::authorised(true, $admin), 'Full administrator must be accepted.');
$assert(!WebSupport::authorised(false, $admin), 'Unauthenticated access must be rejected.');
$assert(!WebSupport::authorised(true, $delegated), 'Delegated page-only access must be rejected.');
$assert(!WebSupport::authorised(true, $unknown), 'Unknown permission results must fail closed.');
$assert(!WebSupport::authorised(true, null), 'Missing framework user must fail closed.');
$assert(!WebSupport::authorised(true, new stdClass()), 'Missing framework API must fail closed.');
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
