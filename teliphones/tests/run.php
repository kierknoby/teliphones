<?php
$tests = ['module-menu.php', 'freepbx-compatibility.php', 'route-containment.php', 'address-policy.php', 'connect-response.php', 'checker-evidence.php'];
foreach ($tests as $test) {
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $test);
    passthru($command, $status);
    if ($status !== 0) {
        exit($status);
    }
}

echo "TELIPHONES local regression suite: PASS\n";