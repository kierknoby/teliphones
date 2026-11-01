<?php
require_once dirname(__DIR__) . '/ConnectClient.php';

use FreePBX\modules\Teliphones\ConnectClient;

$client = (new ReflectionClass(ConnectClient::class))->newInstanceWithoutConstructor();
$validator = new ReflectionMethod(ConnectClient::class, 'validProvisionResponse');
$validator->setAccessible(true);
$session = [
    'session_id' => str_repeat('a', 32),
    'topology' => 'on-pbx',
    'expires_at' => time() + 300,
    'addresses' => ['peer' => '10.20.17.2/32'],
];
$response = [
    'protocol' => 'teliphones-connect/1',
    'session_id' => $session['session_id'],
    'remote_id' => str_repeat('b', 32),
    'expires_at' => time() + 240,
    'peer_public_key' => base64_encode(str_repeat("\x01\x02", 16)),
    'peer_endpoint' => 'gateway.example.invalid:51820',
    'gateway_address' => '10.20.17.2/32',
    'engineer_addresses' => ['10.77.0.10/32', '10.77.0.11/32'],
    'checker_addresses' => ['10.77.0.254/32'],
    'ssh_engineer_address' => '10.77.0.10/32',
    'ssh_public_key' => 'ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test',
];
$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$assert($validator->invoke($client, $response, $session), 'A correctly scoped gateway response should be accepted.');
$response['ssh_engineer_address'] = '10.77.0.12/32';
$assert(!$validator->invoke($client, $response, $session), 'An SSH identity outside the session engineer set must be rejected.');
$response['ssh_engineer_address'] = '10.77.0.10/32';
$response['checker_addresses'] = ['10.77.0.10/32'];
$assert(!$validator->invoke($client, $response, $session), 'Checker and engineer peer addresses must be distinct.');
$response['checker_addresses'] = ['0.0.0.0/0'];
$assert(!$validator->invoke($client, $response, $session), 'A default route from Connect must be rejected.');

echo "Connect response tests: PASS (session routes, SSH identity, Checker isolation, default-route rejection)\n";