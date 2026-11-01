<?php
$tests = ['module-menu.php', 'freepbx-compatibility.php', 'web-support.php', 'route-containment.php', 'address-policy.php', 'connect-response.php', 'checker-evidence.php'];
foreach ($tests as $test) {
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $test);
    passthru($command, $status);
    if ($status !== 0) {
        exit($status);
    }
}

foreach (['direct', 'full', 'false-constant', 'restricted', 'unauthenticated', 'missing', 'malformed', 'full-post', 'string-constant-post', 'restricted-post', 'csrf-post'] as $scenario) {
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/web-page.php') . ' ' . escapeshellarg($scenario);
    passthru($command, $status);
    if ($status !== 0) exit($status);
}

echo "TELIPHONES local regression suite: PASS\n";