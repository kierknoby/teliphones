<?php
$tests = ['module-menu.php', 'freepbx-compatibility.php', 'web-support.php', 'live-status.php', 'workstation-pairing.php', 'route-containment.php', 'address-policy.php', 'connect-response.php', 'checker-evidence.php'];
foreach ($tests as $test) {
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $test);
    passthru($command, $status);
    if ($status !== 0) {
        exit($status);
    }
}

foreach (['direct', 'full', 'false-constant', 'restricted', 'unauthenticated', 'missing', 'malformed', 'full-post', 'string-constant-post', 'restricted-post', 'csrf-post', 'authorise-post', 'dependencies-post', 'configure-post', 'evidence-post', 'invalid-status-authorise-post', 'malformed-status-authorise-post', 'recovered', 'recovered-authorise-post', 'recovered-failed-authorise-post'] as $scenario) {
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/web-page.php') . ' ' . escapeshellarg($scenario);
    passthru($command, $status);
    if ($status !== 0) exit($status);
}

$node = trim((string)shell_exec('command -v node 2>/dev/null'));
if ($node === '') {
    echo "Live status JavaScript tests: SKIPPED (Node.js not available)\n";
} else {
    passthru(escapeshellarg($node) . ' ' . escapeshellarg(__DIR__ . '/live-status.test.js'), $status);
    if ($status !== 0) exit($status);
}

echo "TELIPHONES local regression suite: PASS\n";