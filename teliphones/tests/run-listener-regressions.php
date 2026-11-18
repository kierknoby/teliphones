<?php
// Self-contained listener-only PHP regression runner; no FreePBX installation
// or host firewall access is required by these fixtures.
foreach (['firewall-listener.php', 'firewall-listener-generation.php'] as $test) {
    passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $test), $status);
    if ($status !== 0) exit($status);
}
echo "TELIPHONES listener PHP regressions: PASS\n";
