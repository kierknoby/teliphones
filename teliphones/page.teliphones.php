<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }
require_once __DIR__ . '/WebSupport.php';
use FreePBX\modules\Teliphones\WebSupport;

$accessError = WebSupport::accessError($_SESSION['AMP_user'] ?? null, $ampuser ?? $GLOBALS['ampuser'] ?? null);
if ($accessError !== null) {
    http_response_code(403);
    echo '<div class="alert alert-danger">' . htmlspecialchars($accessError, ENT_QUOTES, 'UTF-8') . '</div>';
    return;
}
if (empty($_SESSION['teliphones_token'])) $_SESSION['teliphones_token'] = bin2hex(random_bytes(32));
$token = $_SESSION['teliphones_token'];
$client = new WebSupport();
$notice = null;
// Probe first so unavailable privileged operations are refused server-side, not only disabled in HTML.
$support = $client->request(['action' => 'status']);
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $result = WebSupport::handleAction($client, $_POST, $token, $support, $_SERVER);
    $notice = $result['notice'];
    if ($result['code'] !== 200) http_response_code($result['code']);
    if ($result['dispatched']) $support = $client->request(['action' => 'status']);
}
$broker = $client->brokerState($support);
show_view(__DIR__ . '/views/support.php', compact('support', 'notice', 'token', 'broker'));
