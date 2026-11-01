<?php
require_once dirname(__DIR__) . '/CheckerEvidence.php';

use FreePBX\modules\Teliphones\CheckerEvidence;

if (!function_exists('openssl_pkey_new')) {
    fwrite(STDERR, "Checker evidence tests require PHP OpenSSL.\n");
    exit(2);
}

$directory = sys_get_temp_dir() . '/teliphones-checker-' . bin2hex(random_bytes(8));
mkdir($directory, 0700, true);
$keyPair = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]);
if ($keyPair === false) {
    throw new RuntimeException('Unable to generate a disposable ECDSA key pair.');
}
$keyDetails = openssl_pkey_get_details($keyPair);
$publicKey = $keyDetails['key'];
$checker = new CheckerEvidence($directory, $publicKey);
$session = [
    'session_id' => bin2hex(random_bytes(16)),
    'topology' => 'on-pbx',
    'expires_at' => time() + 600,
];

$canonicalise = function (array $value) use (&$canonicalise): array {
    if (!array_is_list($value)) {
        ksort($value, SORT_STRING);
    }
    foreach ($value as &$item) {
        if (is_array($item)) {
            $item = $canonicalise($item);
        }
    }
    unset($item);
    return $value;
};
$makeEvidence = function (array $challenge, string $negativeResult = 'blocked') use ($keyPair, $canonicalise): array {
    $evidence = [
        'protocol' => 'teliphones-checker/1',
        'session_id' => $challenge['session_id'],
        'topology' => $challenge['topology'],
        'nonce' => $challenge['nonce'],
        'observed_at' => time(),
        'observations' => [
            'authorised_source' => ['support_service' => 'reachable'],
            'negative_source' => ['support_service' => $negativeResult],
            'public_address' => ['support_service' => 'blocked'],
            'unexpected_services' => [],
        ],
    ];
    $message = json_encode($canonicalise($evidence), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    if (!openssl_sign($message, $signature, $keyPair, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Unable to sign disposable Checker evidence.');
    }
    $evidence['signature'] = base64_encode($signature);
    return $evidence;
};
$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

try {
    $challenge = $checker->challenge($session);
    $accepted = $checker->accept($session, $makeEvidence($challenge));
    $assert($accepted['accepted'] === true, 'Signed evidence should be accepted.');
    $assert($checker->accepted($session), 'Accepted evidence should be bound to the current session.');

    $replay = $checker->accept($session, $makeEvidence($challenge));
    $assert(in_array('checker-replay', $replay['errors'], true), 'A consumed challenge should reject replay.');

    $challenge = $checker->challenge($session);
    $tampered = $makeEvidence($challenge);
    $tampered['observations']['authorised_source']['support_service'] = 'blocked';
    $rejected = $checker->accept($session, $tampered);
    $assert(in_array('checker-signature-invalid', $rejected['errors'], true), 'Modified evidence should fail signature validation.');

    $challenge = $checker->challenge($session);
    $negative = $checker->accept($session, $makeEvidence($challenge, 'reachable'));
    $assert(in_array('checker-negative-control-failed', $negative['errors'], true), 'A passing negative control must be blocked.');

    echo "Checker evidence tests: PASS (signature, session nonce, replay, tampering, negative control)\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $file) {
        unlink($file);
    }
    rmdir($directory);
}