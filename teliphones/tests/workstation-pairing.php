<?php
// Windows workstation pairing: server-side forwarding, HTTPS/CSRF enforcement, status sanitisation and GUI rendering.
require_once dirname(__DIR__) . '/WebSupport.php';
use FreePBX\modules\Teliphones\WebSupport;

$assert = static function (bool $value, string $message): void {
    if (!$value) throw new RuntimeException($message);
};
$recorder = new class extends WebSupport {
    public array $sent = [];
    public array $reply = ['ok' => true, 'message' => 'paired', 'pairing_response' => 'TELIPHONES-PAIR-RESPONSE-1:eyJzY2hlbWEiOiJ0ZWxpcGhvbmVzIn0'];
    public function request(array $request): array
    {
        if ($request['action'] === 'status') return ['ok' => true, 'status' => ['protocol' => 3, 'phase' => 'Ready',
            'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true], 'items' => []]]];
        $this->sent[] = $request;
        return $this->reply;
    }
};
$operational = $recorder->request(['action' => 'status']);
$https = ['HTTPS' => 'on', 'SERVER_PORT' => '443'];
$post = ['token' => 'known', 'action' => 'pair', 'request' => 'TELIPHONES-PAIR-REQUEST-1:abc', 'endpoint_host' => 'pbx.example.net',
    'listen_port' => '51821', 'mode' => 'temporary', 'minutes' => '60', 'ssh' => '1',
    'url' => 'https://evil.example', 'evidence' => '{}', 'private_key' => 'secret', 'workstation_id' => 'all'];

$result = WebSupport::handleAction($recorder, $post, 'known', $operational, $https);
$assert($result['dispatched'] && $recorder->sent === [['action' => 'pair', 'request' => 'TELIPHONES-PAIR-REQUEST-1:abc', 'endpoint_host' => 'pbx.example.net',
    'listen_port' => '51821', 'mode' => 'temporary', 'minutes' => '60', 'ssh' => '1']], 'Pairing must forward exactly its own allowlisted fields.');
$assert($result['notice']['pairing_response'] === $recorder->reply['pairing_response'], 'Pairing response must reach the page.');

$recorder->sent = [];
$result = WebSupport::handleAction($recorder, ['token' => 'known', 'action' => 'unpair', 'workstation_id' => '0123456789abcdef', 'request' => 'x'], 'known', $operational, $https);
$assert($recorder->sent === [['action' => 'unpair', 'workstation_id' => '0123456789abcdef']], 'Revocation must forward only the workstation identifier.');

$recorder->sent = [];
foreach ([['HTTPS' => 'off', 'SERVER_PORT' => '80'], []] as $server) {
    $result = WebSupport::handleAction($recorder, $post, 'known', $operational, $server);
    $assert(!$result['dispatched'] && $result['notice']['action_failed'] && strpos($result['notice']['error'], 'HTTPS') !== false, 'Pairing over HTTP must be refused server-side.');
}
$result = WebSupport::handleAction($recorder, ['action' => 'unpair', 'workstation_id' => 'all'] + ['token' => 'known'], 'known', $operational, ['HTTPS' => 'off']);
$assert($result['dispatched'], 'Revocation must remain available without HTTPS.');
$recorder->sent = [];
foreach ([['token' => 'wrong'] + $post, ['action' => 'pair'] + array_diff_key($post, ['token' => 1])] as $forged) {
    $result = WebSupport::handleAction($recorder, $forged, 'known', $operational, $https);
    $assert($result['code'] === 403 && !$result['dispatched'], 'Pairing without the CSRF token must be rejected.');
}
$result = WebSupport::handleAction($recorder, $post, 'known', ['ok' => false, 'unavailable' => true], $https);
$assert(!$result['dispatched'] && !empty($result['notice']['unavailable']), 'Pairing must be refused when the broker is unavailable.');
$assert($recorder->sent === [], 'Refused pairing requests must never reach the broker.');
foreach ([
    ['ok' => true, 'status' => ['protocol' => 2]],
    ['ok' => true, 'status' => ['protocol' => 3]],
    ['ok' => true, 'status' => ['protocol' => 3, 'workstations' => ['ready' => true, 'items' => [], 'requirements' => ['wg' => true]]]],
] as $incompatible) {
    $assert(!WebSupport::publicStatus($incompatible, ['available' => true])['broker_current'], 'A version number must not conceal missing pairing capabilities.');
    foreach (['pair', 'unpair'] as $action) {
        $result = WebSupport::handleAction($recorder, ['action' => $action, 'workstation_id' => 'all'] + $post, 'known', $incompatible, $https);
        $assert(!$result['dispatched'] && !empty($result['notice']['action_failed']), 'Incompatible workstation operations must fail before broker dispatch.');
    }
}
$assert($recorder->sent === [], 'Incompatible pairing requests must never reach the broker.');

// AJAX action route: pairing response is passed through only when well-formed.
$session = ['AMP_user' => 'admin', 'teliphones_token' => 'known'];
$admin = new class { public function checkSection($section) { return $section === '*'; } };
$restricted = new class { public function checkSection($section) { return false; } };
$ajax = WebSupport::ajax('action', 'POST', $post, $session, $admin, $https, $recorder);
$assert($ajax['body']['notice']['pairing_response'] === $recorder->reply['pairing_response'], 'AJAX must return a valid pairing response.');
$recorder->reply['pairing_response'] = '<script>alert(1)</script>';
$ajax = WebSupport::ajax('action', 'POST', $post, $session, $admin, $https, $recorder);
$assert($ajax['body']['notice']['pairing_response'] === null, 'Malformed pairing responses must be dropped.');
$recorder->sent = [];
$ajax = WebSupport::ajax('action', 'POST', $post, $session, $restricted, $https, $recorder);
$assert($ajax['code'] === 403 && $recorder->sent === [], 'Restricted administrators must not pair workstations.');

// Status sanitisation.
$item = ['id' => '0123456789abcdef', 'name' => 'ADMIN-PC', 'address' => '100.70.1.2/32', 'mode' => 'temporary', 'ssh' => true,
    'created_at' => 1, 'expires_at' => 2000000000, 'last_handshake' => 0, 'fingerprint' => 'SHA256:abcdefghijklmnop', 'public_key' => 'LEAKED-PUBLIC-KEY'];
$status = ['ok' => true, 'status' => ['protocol' => 3, 'phase' => 'Ready', 'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true],
    'error' => '', 'listen_port' => 51821, 'pbx_address' => '100.70.1.1', 'items' => [$item, ['id' => '../../x', 'name' => 'bad']]]]];
$workstations = WebSupport::workstations($status);
$assert($workstations['supported'] && $workstations['ready'] && count($workstations['items']) === 1 && !isset($workstations['items'][0]['public_key']), 'Workstation status must be allowlisted.');
$assert(!WebSupport::workstations(['ok' => true, 'status' => ['protocol' => 2, 'workstations' => $status['status']['workstations']]])['supported'], 'Older brokers do not support pairing.');
foreach (['TELIPHONES-PAIR-RESPONSE-1:abc', 'TELIPHONES-PAIR-RESPONSE-1:' . str_repeat('a', 30) . '"', 'x', null, ['a']] as $invalid) {
    $assert(!WebSupport::validPairingResponse($invalid), 'Invalid pairing responses must be rejected.');
}

$render = static function (array $support, ?array $notice = null, array $broker = ['available' => true, 'condition' => 'operational']): string {
    $token = 'test-token';
    $_SERVER['HTTP_HOST'] = 'pbx.example.net:443';
    ob_start();
    include dirname(__DIR__) . '/views/support.php';
    return (string)ob_get_clean();
};
$buttonDisabled = static function (string $html, string $action): bool {
    return (bool)preg_match('/<button[^>]*value="' . $action . '"[^>]*\sdisabled/', $html);
};
$status['status']['readiness'] = ['WireGuard wg' => true];
$html = $render($status);
$assert(strpos($html, '<code>nft</code> CLI') !== false && strpos($html, '<code>nftables.service</code> does not need to be enabled or running') !== false
    && strpos($html, 'this page does not install nftables') !== false && strpos($html, 'not zero-exposure or truly fail-closed') !== false,
    'GUI must explain essential nft userspace tools, unnecessary service activation, administrator repair and external-flush exposure limits.');
$assert(strpos($html, '<h3 id="teliphones-workstations">Windows workstations</h3>') !== false && strpos($html, '>ADMIN-PC</td>') !== false
    && strpos($html, 'Web interface and SSH') !== false && strpos($html, 'SHA256:abcdefghijklmnop') !== false
    && strpos($html, 'LEAKED-PUBLIC-KEY') === false && strpos($html, '../../x') === false, 'Paired workstations must be listed without keys.');
$assert(!$buttonDisabled($html, 'pair') && !$buttonDisabled($html, 'unpair') && strpos($html, 'value="pbx.example.net"') !== false
    && strpos($html, 'value="51821"') !== false, 'Ready broker must enable pairing and prefill the endpoint.');
$assert(strpos($html, 'Authorised; no handshake yet') !== false && strpos($html, 'Add my PBX...') !== false, 'Pairing status must not claim connectivity and must name actual Windows controls.');
$handshake = $status;
$handshake['status']['workstations']['items'][0]['last_handshake'] = 1790000000;
$assert(strpos($render($handshake), 'Last handshake ') !== false, 'Verified handshake timestamp must be rendered.');
$handshake['status']['workstations']['items'][0]['last_handshake'] = 'secret';
$assert(strpos($render($handshake), 'Not verified (status unavailable)') !== false, 'Malformed handshake must not imply connectivity.');
$assert(strpos($html, 'teliphones-pairing-response') === false, 'No pairing response is shown unless pairing just succeeded.');
$assert(preg_match('/<form method="post" autocomplete="off">\s*<input type="hidden" name="token" value="test-token">\s*<fieldset id="teliphones-pair-fields">/', $html) === 1,
    'Pairing form must carry the CSRF token and must not be intercepted by the live-status script.');

$code = 'TELIPHONES-PAIR-RESPONSE-1:' . str_repeat('A', 40);
$html = $render($status, ['ok' => true, 'action' => 'pair', 'message' => 'Workstation paired.', 'pairing_response' => $code]);
$assert(strpos($html, '<pre id="teliphones-pairing-response" style="user-select:all;white-space:pre-wrap;word-break:break-all">' . $code . '</pre>') !== false
    && strpos($html, 'Copy pairing response') !== false, 'Successful pairing must display the response with a copy button.');
$html = $render($status, ['ok' => true, 'pairing_response' => '<b>x</b>']);
$assert(strpos($html, 'teliphones-pairing-response') === false && strpos($html, '<b>x</b>') === false, 'Malformed pairing responses must not be rendered.');

$notReady = $status;
$notReady['status']['workstations']['ready'] = false;
$notReady['status']['workstations']['requirements']['nft'] = false;
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $post, 'known', $notReady, $https);
$assert(!$result['dispatched'] && $recorder->sent === [], 'Missing dependencies must block pairing server-side.');
$disabled = $status;
$disabled['status']['enabled'] = false;
$assert(!WebSupport::workstations($disabled)['ready'], 'Disabled TELIPHONES must not allow new pairings.');
$html = $render($notReady);
$assert($buttonDisabled($html, 'pair') && strpos($html, 'Missing: nft') !== false, 'Missing nftables must disable pairing with an explanation.');

$legacy = ['ok' => true, 'status' => ['protocol' => 2, 'phase' => 'Ready', 'readiness' => ['WireGuard wg' => true]]];
$html = $render($legacy);
$assert($buttonDisabled($html, 'pair') && strpos($html, 'Workstation pairing requires the updated root broker') !== false
    && strpos($html, 'Root broker update required') !== false, 'Outdated broker must disable pairing and request the update.');

$html = $render(['ok' => false, 'unavailable' => true, 'error' => 'x'], null, ['available' => false, 'condition' => 'stopped', 'service' => 'inactive']);
$assert($buttonDisabled($html, 'pair') && strpos($html, 'No workstations are paired.') !== false, 'Unavailable broker must disable pairing.');

$many = $status;
$many['status']['workstations']['items'][] = ['id' => 'fedcba9876543210', 'name' => 'LAPTOP', 'address' => '100.70.1.3/32', 'mode' => 'persistent', 'ssh' => false, 'fingerprint' => 'SHA256:x'];
$html = $render($many);
$assert(strpos($html, 'Revoke all workstations') !== false && strpos($html, 'Persistent (until revoked)') !== false && strpos($html, 'Web interface only') !== false,
    'Multiple workstations must be individually and collectively revocable.');
$cleanup = $status;
$cleanup['status']['workstations']['items'] = [];
$cleanup['status']['workstations']['error'] = 'Workstation cleanup could not be confirmed.';
$html = $render($cleanup);
$assert(strpos($html, 'Revoke all workstations') !== false && !$buttonDisabled($html, 'unpair'), 'Failed cleanup must remain retryable even when saved pairing authority is already removed.');

echo "Workstation pairing tests: PASS (field allowlist, HTTPS/CSRF, restricted admins, sanitised status, GUI states, revocation)\n";
