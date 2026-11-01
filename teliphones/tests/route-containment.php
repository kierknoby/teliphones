<?php
require_once dirname(__DIR__) . '/LocalAttestor.php';

use FreePBX\modules\Teliphones\LocalAttestor;

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$assert(
    LocalAttestor::routeCoversPeer(['10.20.17.0/30 dev wg-teliphones proto kernel scope link src 10.20.17.1'], '10.20.17.2'),
    'The connected session subnet route should cover the remote peer.'
);
$assert(
    LocalAttestor::routeCoversPeer(['10.20.17.2 dev wg-teliphones scope link'], '10.20.17.2'),
    'An explicit host route on the session interface should be accepted.'
);
$assert(
    !LocalAttestor::routeCoversPeer(['10.20.18.0/30 dev wg-teliphones scope link'], '10.20.17.2'),
    'A route for a different subnet must be rejected.'
);
$assert(
    !LocalAttestor::routeCoversPeer(['10.20.17.0/24 dev wg-teliphones scope link'], '10.20.17.2'),
    'A route broader than the allocated session prefix must be rejected.'
);
$assert(
    !LocalAttestor::routeCoversPeer(['10.20.17.0/30 dev eth0 scope link'], '10.20.17.2'),
    'A matching route on another interface must be rejected.'
);

echo "Route containment tests: PASS (connected subnet, host route, wrong subnet, broad route, wrong interface)\n";