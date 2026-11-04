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
        if ($request['action'] === 'status') return ['ok' => true, 'status' => ['protocol' => 4, 'phase' => 'Ready',
            'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true], 'items' => []]]];
        $this->sent[] = $request;
        return $this->reply;
    }
};
$operational = $recorder->request(['action' => 'status']);
$https = ['HTTPS' => 'on', 'SERVER_PORT' => '443'];
$post = ['token' => 'known', 'action' => 'pair', 'request' => 'TELIPHONES-PAIR-REQUEST-1:abc', 'endpoint_host' => 'pbx.example.net',
    'listen_port' => '51821', 'mode' => 'temporary', 'minutes' => '60', 'ssh' => '0',
    'url' => 'https://evil.example', 'evidence' => '{}', 'private_key' => 'secret', 'workstation_id' => 'all'];

$result = WebSupport::handleAction($recorder, $post, 'known', $operational, $https);
$assert($result['dispatched'] && $recorder->sent === [['action' => 'pair', 'request' => 'TELIPHONES-PAIR-REQUEST-1:abc', 'endpoint_host' => 'pbx.example.net',
    'listen_port' => '51821', 'mode' => 'temporary', 'minutes' => '60', 'ssh' => '0']], 'Pairing must forward exactly its own allowlisted fields.');
$assert($result['notice']['pairing_response'] === $recorder->reply['pairing_response'], 'Pairing response must reach the page.');
$sourceLockedPost = ['sources' => '198.51.100.24'] + $post;
$lockedResult = WebSupport::handleAction($recorder, $sourceLockedPost, 'known', $operational, $https);
$assert(!$lockedResult['dispatched'], 'Source-lock requests must not be sent to a pre-protocol-8 broker.');
$sourceBroker = $operational;
$sourceBroker['status']['protocol'] = 8;
$recorder->sent = [];
$lockedResult = WebSupport::handleAction($recorder, $sourceLockedPost, 'known', $sourceBroker, $https);
$assert($lockedResult['dispatched'] && $recorder->sent[0]['sources'] === '198.51.100.24',
    'Source restrictions must be forwarded only to a compatible broker.');

$modern = $operational;
$modern['status']['protocol'] = 5;
$modern['status']['workstations']['ssh_ready'] = true;
$webBroker = $modern;
$webBroker['status']['protocol'] = 6;
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, ['web' => 'https:8443'] + $post, 'known', $webBroker,
    ['HTTPS' => 'on', 'SERVER_PORT' => '8443']);
$assert($result['dispatched'] && $recorder->sent[0]['web'] === 'https:8443',
    'Custom HTTPS management ports must reach a compatible broker unchanged.');
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, ['web' => 'https:8443'] + $post, 'known', $modern, $https);
$assert(!$result['dispatched'] && $recorder->sent === [], 'An old broker must not silently discard configured web permissions.');
$managedPost = ['request' => 'TELIPHONES-PAIR-REQUEST-2:abc', 'ssh_user' => 'root'] + $post;
$sshRequestPayload = json_encode(['schema' => 'teliphones-pair-request/2', 'workstation' => 'ADMIN-PC',
    'public_key' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'nonce' => 'abcdefghijklmnopqrstuv',
    'ssh_public_key' => 'ssh-ed25519 test']);
$managedPost['request'] = 'TELIPHONES-PAIR-REQUEST-2:' . rtrim(strtr(base64_encode($sshRequestPayload), '+/', '-_'), '=');
$managedPost['ssh'] = '1';
$sourceBroker['status']['workstations']['ssh_ready'] = true;
$lockedManaged = ['sources' => '198.51.100.24'] + $managedPost;
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $lockedManaged, 'known', $sourceBroker, $https);
$assert(!$result['dispatched'] && $recorder->sent === [],
    'A protocol-8 broker must not receive Locked SSH approval.');
$sourceBroker['status']['protocol'] = 9;
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $lockedManaged, 'known', $sourceBroker, $https);
$assert($result['dispatched'] && $recorder->sent[0]['ssh'] === '1' && $recorder->sent[0]['sources'] === '198.51.100.24',
    'Locked SSH approval must be sent only to a protocol-9 broker.');
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $managedPost, 'known', $modern, $https);
$assert($result['dispatched'] && count($recorder->sent) === 1 && $recorder->sent[0]['ssh_user'] === 'root'
    && !isset($recorder->sent[0]['private_key']), 'Managed SSH must forward an explicitly approved account, never secret or unrelated fields.');
foreach (['', '-root', "root\n", 'administrator;id', ['root']] as $invalidUser) {
    $recorder->sent = [];
    $result = WebSupport::handleAction($recorder, ['ssh_user' => $invalidUser] + $managedPost, 'known', $modern, $https);
    $assert(!$result['dispatched'] && $recorder->sent === [], 'Missing or invalid account approval must fail before broker dispatch.');
}
foreach ([$operational, ['status' => ['workstations' => ['ssh_ready' => false] + $modern['status']['workstations']] + $modern['status']] + $modern] as $unready) {
    $recorder->sent = [];
    $result = WebSupport::handleAction($recorder, $managedPost, 'known', $unready, $https);
    $assert(!$result['dispatched'] && $recorder->sent === [], 'An old broker or missing SSH readiness must not grant managed SSH.');
}
$noSsh = $modern;
$noSsh['status']['workstations']['ssh_ready'] = false;
$result = WebSupport::handleAction($recorder, ['ssh' => '0', 'ssh_user' => ''] + $managedPost, 'known', $noSsh, $https);
$assert($result['dispatched'], 'Missing SSH prerequisites must not disable web-only pairing.');
$result = WebSupport::handleAction($recorder, ['ssh' => '1'] + $post, 'known', $modern, $https);
$assert(!$result['dispatched'] && strpos($result['notice']['error'], 'did not include SSH capability') !== false,
    'A version-1 web-only request must never receive SSH permission.');
$policyStatus = ['ok' => true, 'status' => ['protocol' => 8, 'workstations' => [
    'ready' => true, 'items' => [], 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true],
    'connection_state' => 'closed']]];
$assert(WebSupport::supportsWorkstationPolicy($policyStatus), 'Protocol 8 must expose connection-state controls.');
$policyPost = ['token' => 'known', 'action' => 'workstation-policy', 'state' => 'frozen'];
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $policyPost, 'known', $policyStatus, $https);
$assert($result['dispatched'] && $recorder->sent[0] === ['action' => 'workstation-policy', 'state' => 'frozen'],
    'Connection-state changes must forward only the selected state.');
$sessionStatus = ['ok' => true, 'status' => ['protocol' => 11, 'workstations' => [
    'ready' => true, 'items' => [], 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true],
    'max_sessions' => 1, 'connected_workstations' => 1]]];
$assert(WebSupport::supportsWorkstationSessions($sessionStatus), 'Protocol 11 must report enforced workstation session capacity.');
$limitPost = ['token' => 'known', 'action' => 'workstation-limit', 'maximum' => '2'];
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $limitPost, 'known', $sessionStatus, $https);
$assert($result['dispatched'] && $recorder->sent[0] === ['action' => 'workstation-limit', 'maximum' => '2'],
    'Session limit updates must forward only the selected maximum.');
$manageStatus = $sessionStatus;
$manageStatus['status']['protocol'] = 12;
$managePost = ['token' => 'known', 'action' => 'workstation-manage', 'workstation_id' => '0123456789abcdef',
    'state' => 'lock', 'sources' => 'current'];
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $managePost, 'known', $manageStatus, $https);
$assert($result['dispatched'] && $recorder->sent[0] === ['action' => 'workstation-manage',
    'workstation_id' => '0123456789abcdef', 'state' => 'lock', 'sources' => 'current'],
    'Post-pair source management must forward the workstation identity and selected restrictions.');
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $managePost, 'known', $sessionStatus, $https);
$assert(!$result['dispatched'] && $recorder->sent === [],
    'A broker without post-pair policy support must not receive workstation management actions.');
$sshStatus = $manageStatus;
$sshStatus['status']['workstations']['ssh_ready'] = true;
$sshStatus['status']['workstations']['ssh_accounts'] = ['root', 'bad;account'];
$approvePost = ['token' => 'known', 'action' => 'workstation-ssh-approve',
    'workstation_id' => '0123456789abcdef', 'ssh_user' => 'root'];
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $approvePost, 'known', $sshStatus, $https);
$assert($result['dispatched'] && $recorder->sent[0] === ['action' => 'workstation-ssh-approve',
    'workstation_id' => '0123456789abcdef', 'ssh_user' => 'root'],
    'Post-pair SSH elevation must forward the explicit account selection for administrator approval.');
$oldSessionStatus = $sessionStatus;
$oldSessionStatus['status']['protocol'] = 10;
$recorder->sent = [];
$result = WebSupport::handleAction($recorder, $limitPost, 'known', $oldSessionStatus, $https);
$assert(!$result['dispatched'] && $recorder->sent === [],
    'A broker without enforced session admission must not receive session-limit settings.');
$assert(WebSupport::pairingRequestSupportsSsh($managedPost['request']), 'A version-2 request with an SSH key must expose SSH approval.');
$assert(!WebSupport::pairingRequestSupportsSsh($post['request']), 'A version-1 request must not expose SSH approval.');
$recorder->sent = [];
$assert(WebSupport::validPairingResponse('TELIPHONES-PAIR-RESPONSE-2:' . str_repeat('a', 200)), 'Version-2 pairing responses must survive the browser allowlist.');

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

$diagnosticId = 'ws-0123456789abcdef';
$diagnosticPost = ['token' => 'known', 'diagnostic_id' => $diagnosticId];
$recorder->reply = ['ok' => true, 'component_version' => '0.3.2', 'diagnostic_id' => $diagnosticId,
    'exported_at' => '2026-11-02T19:00:00Z', 'events' => [
        ['component_version' => '0.3.2', 'timestamp_utc' => '2026-11-02T18:59:00Z', 'unix_time' => 1793645940,
            'diagnostic_id' => $diagnosticId, 'source' => 'pbx', 'event' => 'peer.observation',
            'data' => ['handshake_at' => 0, 'rx_bytes' => 1, 'tx_bytes' => 2, 'private_key' => 'must-not-leak']],
        ['timestamp_utc' => '2026-11-02T18:59:00Z', 'unix_time' => 1793645940,
            'diagnostic_id' => 'ws-ffffffffffffffff', 'source' => 'pbx', 'event' => 'pairing.approved',
            'data' => ['mode' => 'persistent']],
        ['timestamp_utc' => '2026-11-02T18:59:00Z', 'unix_time' => 1793645940,
            'diagnostic_id' => $diagnosticId, 'source' => 'pbx', 'event' => 'pairing.approved',
            'data' => ['mode' => 'temporary', 'expires_at' => 1793649540, 'renewed' => false, 'token' => 'secret']],
        ['timestamp_utc' => '2026-11-02T18:59:00Z', 'unix_time' => 1793645940,
            'diagnostic_id' => $diagnosticId, 'source' => 'pbx', 'event' => 'pairing.approved',
            'data' => ['mode' => 'temporary', 'expires_at' => 1793649540, 'renewed' => false]],
    ]];
$recorder->sent = [];
$ajax = WebSupport::ajax('diagnostics', 'POST', $diagnosticPost, $session, $admin, $https, $recorder);
$assert($ajax['code'] === 200 && $ajax['body']['diagnostics']['diagnostic_id'] === $diagnosticId
    && $recorder->sent === [['action' => 'diagnostics', 'diagnostic_id' => $diagnosticId]],
    'Diagnostics request must pass only the validated session identifier to the broker.');
$events = $ajax['body']['diagnostics']['events'];
$assert(count($events) === 1 && $events[0]['event'] === 'pairing.approved'
    && $events[0]['source'] === 'pbx' && !isset($events[0]['data']['token']),
    'Diagnostics response must filter by session and drop non-whitelisted fields.');
$recorder->sent = [];
$ajax = WebSupport::ajax('diagnostics', 'POST', ['diagnostic_id' => $diagnosticId], $session, $admin, $https, $recorder);
$assert($ajax['code'] === 403 && $recorder->sent === [], 'Diagnostics must reject missing CSRF tokens.');
$ajax = WebSupport::ajax('diagnostics', 'POST', ['token' => 'wrong', 'diagnostic_id' => $diagnosticId], $session, $admin, $https, $recorder);
$assert($ajax['code'] === 403 && $recorder->sent === [], 'Diagnostics must reject invalid CSRF tokens.');
$ajax = WebSupport::ajax('diagnostics', 'POST', $diagnosticPost, $session, $restricted, $https, $recorder);
$assert($ajax['code'] === 403 && $recorder->sent === [], 'Diagnostics must remain administrator-only.');
$ajax = WebSupport::ajax('diagnostics', 'GET', $diagnosticPost, $session, $admin, $https, $recorder);
$assert($ajax['code'] === 405 && $recorder->sent === [], 'Diagnostics must require POST.');
$malformedId = WebSupport::ajax('diagnostics', 'POST', ['token' => 'known', 'diagnostic_id' => '../../secret'], $session, $admin, $https, $recorder);
$assert($malformedId['code'] === 403 && $recorder->sent === [], 'Diagnostics session filters must be strict.');
$extraDiagnostic = WebSupport::ajax('diagnostics', 'POST', $diagnosticPost + ['extra' => 'sensitive'], $session, $admin, $https, $recorder);
$assert($extraDiagnostic['code'] === 403 && $recorder->sent === [], 'Diagnostics must reject unexpected request fields.');
$legacySupport = ['ok' => true, 'status' => ['protocol' => 3]];
$ajax = WebSupport::ajax('diagnostics', 'POST', $diagnosticPost, $session, $admin, $https,
    new class($legacySupport) extends WebSupport {
        private array $status;
        public function __construct(array $status) { $this->status = $status; }
        public function request(array $request): array { return $this->status; }
    });
$assert($ajax['code'] === 409, 'Diagnostics must require the updated broker protocol.');

// Status sanitisation.
$item = ['id' => '0123456789abcdef', 'name' => 'ADMIN-PC', 'address' => '100.70.1.2/32', 'mode' => 'temporary', 'ssh' => true,
    'created_at' => 1, 'expires_at' => 2000000000, 'last_handshake' => 0,
    'verified_endpoint' => ['address' => '2001:db8::24', 'port' => 51821],
    'fingerprint' => 'SHA256:abcdefghijklmnop', 'public_key' => 'LEAKED-PUBLIC-KEY'];
$status = ['ok' => true, 'status' => ['protocol' => 4, 'phase' => 'Ready', 'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true],
    'error' => '', 'listen_port' => 51821, 'pbx_address' => '100.70.1.1', 'items' => [$item, ['id' => '../../x', 'name' => 'bad']]]]];
$workstations = WebSupport::workstations($status);
$assert($workstations['supported'] && $workstations['ready'] && count($workstations['items']) === 1 && !isset($workstations['items'][0]['public_key']), 'Workstation status must be allowlisted.');
$assert($workstations['items'][0]['verified_endpoint'] === ['address' => '2001:db8::24', 'port' => 51821],
    'Only a validated numeric, verified WireGuard endpoint may reach the administrator view.');
$sessionStatus['status']['workstations']['items'] = [$item + ['session_active' => true, 'session_expires_at' => 2000000030]];
$sessionStatus['status']['workstations']['max_sessions'] = 1;
$sessionStatus['status']['workstations']['connected_workstations'] = 1;
$sessionStatus['status']['workstations']['ssh_accounts'] = ['root', 'bad;account'];
$sessionWorkstations = WebSupport::workstations($sessionStatus);
$assert($sessionWorkstations['session_supported'] && $sessionWorkstations['max_sessions'] === 1
    && $sessionWorkstations['connected_workstations'] === 1
    && $sessionWorkstations['items'][0]['session_active']
    && $sessionWorkstations['items'][0]['session_expires_at'] === 2000000030,
    'Only validated broker lease and capacity fields must reach FreePBX session status.');
$assert($sessionWorkstations['ssh_accounts'] === ['root']
    && $sessionWorkstations['items'][0]['ssh_request_pending'] === false,
    'SSH account choices and pending-request state must be validated before rendering.');
$invalidEndpoint = $status;
$invalidEndpoint['status']['workstations']['items'][0]['verified_endpoint'] = ['address' => 'user@host', 'port' => 51821];
$assert(WebSupport::workstations($invalidEndpoint)['items'][0]['verified_endpoint'] === null,
    'Malformed or asserted endpoint text must not be presented as a verified public source.');
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
$assert(strpos($html, '<h3 id="teliphones-workstations">Windows workstations</h3>') !== false && strpos($html, '>ADMIN-PC<br><small>Diagnostic ID: <code>ws-0123456789abcdef</code></small></td>') !== false
    && strpos($html, 'Web interface and legacy SSH') !== false && strpos($html, 'SHA256:abcdefghijklmnop') !== false
    && strpos($html, 'LEAKED-PUBLIC-KEY') === false && strpos($html, '../../x') === false, 'Paired workstations must be listed without keys.');
$assert(strpos($html, 'Workstation diagnostics') !== false && strpos($html, 'does not contain Windows-local attempts') !== false,
    'Administrator page must explain and expose bounded server-side diagnostics without fabricating Windows events.');
$assert(strpos($html, 'id="teliphones-diagnostics-form" method="post"') !== false
    && strpos($html, 'name="token" value="test-token"') !== false,
    'Diagnostics form must use POST and include its session CSRF token even without JavaScript.');
$assert(!$buttonDisabled($html, 'pair') && !$buttonDisabled($html, 'unpair') && strpos($html, 'value="pbx.example.net"') !== false
    && strpos($html, 'value="51821"') !== false, 'Ready broker must enable pairing and prefill the endpoint.');
$assert(strpos($html, 'Authorised; no handshake yet') !== false && strpos($html, 'Add my PBX...') !== false, 'Pairing status must not claim connectivity and must name actual Windows controls.');
$assert(strpos($html, '[2001:db8::24]:51821') !== false, 'The authenticated public endpoint must be displayed in IPv6-safe form.');
$pendingUi = $sshStatus;
$pendingUi['status']['workstations']['items'] = [$item + ['ssh_request_pending' => true]];
$pendingHtml = $render($pendingUi);
$assert(strpos($pendingHtml, 'SSH elevation: Pending Approval') !== false
    && strpos($pendingHtml, 'Select an existing Linux account') !== false
    && strpos($pendingHtml, 'name="ssh_user"') !== false,
    'FreePBX must expose pending SSH elevation with a blank, explicit Linux-account selection.');
$pendingUi['status']['workstations']['items'][0]['unlock_request_pending'] = true;
$unlockHtml = $render($pendingUi);
$assert(strpos($unlockHtml, 'Workstation unlock: Pending Approval') !== false
    && strpos($unlockHtml, 'workstation-unlock-approve') !== false
    && strpos($unlockHtml, 'workstation-unlock-reject') !== false,
    'FreePBX must expose explicit administrator approval and rejection for Windows unlock requests.');
$pendingUi['status']['workstations']['items'][0]['sources_request_pending'] = true;
$pendingUi['status']['workstations']['items'][0]['requested_sources'] = ['198.51.100.24/32', 'example.org'];
$sourcesHtml = $render($pendingUi);
$assert(strpos($sourcesHtml, 'Allowed List change: Pending Approval') !== false
    && strpos($sourcesHtml, '198.51.100.24/32, example.org') !== false
    && strpos($sourcesHtml, 'workstation-sources-approve') !== false
    && strpos($sourcesHtml, 'workstation-sources-reject') !== false,
    'FreePBX must display the exact requested source list for explicit approval or rejection.');
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

// FreePBX Firewall integration diagnostics.
$assert(WebSupport::workstations($status)['firewall_integration'] === ['state' => 'unknown', 'message' => '', 'backend' => null],
    'A broker without integration reporting must be identified as unknown.');
$html = $render($handshake = array_replace_recursive($status, ['status' => ['workstations' => ['items' => [0 => ['last_handshake' => 1790000000]]]]]));
$assert(strpos($html, 'does not report FreePBX Firewall integration') !== false && strpos($html, 'Rerun the documented root bootstrap') !== false
    && strpos($html, 'Handshake succeeded, but FreePBX Firewall integration is not active') !== false, 'Outdated broker must explain possible FreePBX Firewall drops.');
$integration = $handshake;
$integration['status']['workstations']['firewall_integration'] = ['state' => 'active', 'message' => 'Authorised peers <b>only</b>.', 'backend' => 'nf_tables', 'hook' => 'fpbxfirewall'];
$html = $render($integration);
$assert(strpos($html, 'FreePBX Firewall integration active (iptables nf_tables). Authorised peers &lt;b&gt;only&lt;/b&gt;.') !== false
    && strpos($html, 'teliphones-handshake-blocked') === false, 'Active integration must be shown, escaped, without a blocked warning.');
$integration['status']['workstations']['firewall_integration'] = ['state' => 'error', 'message' => 'FreePBX Firewall integration failed and was removed.', 'backend' => 'evil'];
$sanitised = WebSupport::workstations($integration)['firewall_integration'];
$assert($sanitised['backend'] === null && $sanitised['state'] === 'error', 'Integration backend must be allowlisted.');
$html = $render($integration);
$assert(strpos($html, 'alert-danger teliphones-firewall-integration') !== false && strpos($html, 'teliphones-handshake-blocked') !== false,
    'Failed integration with a successful handshake must be diagnosed.');
$integration['status']['workstations']['firewall_integration'] = ['state' => 'not-detected', 'message' => 'No iptables INPUT jump to fpbxfirewall was found.'];
$html = $render($integration);
$assert(strpos($html, 'FreePBX Firewall integration not installed.') !== false && strpos($html, 'No iptables INPUT jump to fpbxfirewall') !== false,
    'Missing FreePBX hook must be reported.');
$integration['status']['workstations']['firewall_integration']['state'] = 'trusted-everything';
$assert(WebSupport::workstations($integration)['firewall_integration']['state'] === 'unknown', 'Integration state must be allowlisted.');

echo "Workstation pairing tests: PASS (field allowlist, HTTPS/CSRF, restricted admins, sanitised status, GUI states, revocation, firewall integration diagnostics)\n";
