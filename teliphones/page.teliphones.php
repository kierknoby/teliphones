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
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!WebSupport::validRequest($_POST, $token)) {
        http_response_code(403);
        $notice = ['ok' => false, 'error' => 'TELIPHONES request rejected: invalid action or security token.'];
    } else {
        $request = ['action' => $_POST['action']];
        foreach (['minutes', 'evidence', 'url', 'certificate', 'private_key', 'ca', 'checker_key'] as $field) {
            if (isset($_POST[$field]) && is_string($_POST[$field])) $request[$field] = $_POST[$field];
        }
        if ($request['action'] === 'configure' && strtolower((string)($_SERVER['HTTPS'] ?? '')) !== 'on' && (string)($_SERVER['SERVER_PORT'] ?? '') !== '443') {
            $notice = ['ok' => false, 'error' => 'Gateway credentials may only be submitted over HTTPS. Configure FreePBX HTTPS before enrollment.'];
        } else {
            $notice = $client->request($request);
        }
    }
}
$support = $client->request(['action' => 'status']);
show_view(__DIR__ . '/views/support.php', compact('support', 'notice', 'token'));
