<?php
require_once dirname(__DIR__) . '/Topology.php';
require_once dirname(__DIR__) . '/WireGuardAgent.php';

use FreePBX\modules\Teliphones\Topology;
use FreePBX\modules\Teliphones\WireGuardAgent;

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$assert(Topology::validPair('10.20.17.1/30', '10.20.17.2/32'), 'The default /30 tunnel pair should be valid.');
$assert(Topology::validPair('10.20.17.0/31', '10.20.17.1/32'), 'Both endpoints of a /31 tunnel should be usable.');
$assert(!Topology::validPair('10.20.17.1/30', '10.20.18.2/32'), 'A peer outside the allocated tunnel must be rejected.');
$assert(!Topology::validPair('10.20.17.0/30', '10.20.17.2/32'), 'The /30 network address must not be assigned to the PBX.');
$assert(!Topology::validPair('10.20.17.1/30', '10.20.17.3/32'), 'The /30 broadcast address must not be assigned to the peer.');
$assert(!Topology::validPair('10.20.17.1/32', '10.20.17.2/32'), 'A /32 PBX allocation cannot contain a distinct peer.');
$assert(WireGuardAgent::subnetsOverlap('10.20.17.0/30', '10.20.0.0/16'), 'A candidate must collide with an overlapping route.');
$assert(WireGuardAgent::subnetsOverlap('10.20.17.0/30', '10.20.17.1/32'), 'A candidate must collide with an assigned interface address.');
$assert(!WireGuardAgent::subnetsOverlap('10.20.17.0/30', '10.20.18.0/30'), 'Disjoint session subnets must not collide.');

echo "Address policy tests: PASS (peer containment, /30-/31 bounds, route/address overlap)\n";