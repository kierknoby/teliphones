<?php
require_once dirname(__DIR__) . '/FirewallListener.php';
use FreePBX\modules\Teliphones\FirewallListener;

$fw = new class {
    public array $services = ['unrelated' => ['name' => 'Unrelated service']];
    public array $zones = [];
    public int $writes = 0;
    public string $fail = '';
    public function getAllCustomServices() { return $this->services; }
    public function addCustomService($name, $proto, $ports) {
        ++$this->writes;
        $id = 'service-' . substr(hash('sha256', $name), 0, 12);
        $this->services[$id] = ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => $proto, 'port' => $ports], 'custid' => $id, 'noreject' => true];
        $this->zones[$id] = ['internal'];
        if ($this->fail === 'create') throw new RuntimeException('Interrupted after creation');
    }
    public function editCustomService($id, $name, $proto, $port) {
        ++$this->writes;
        $this->services[$id]['custfw'] = ['protocol' => $proto, 'port' => $port];
        if ($this->fail === 'edit') throw new RuntimeException('Interrupted after edit');
    }
    public function deleteCustomService($id) {
        ++$this->writes;
        if ($this->fail === 'delete') return;
        unset($this->services[$id], $this->zones[$id]);
    }
    public function getCustomServiceZones($id) { return $this->zones[$id] ?? []; }
    public function setCustomServiceZones($id, $zones) {
        if ($this->fail === 'zones') throw new RuntimeException('Zone persistence failed');
        ++$this->writes; $this->zones[$id] = $zones;
    }
};
$assert = static function ($value) { if (!$value) throw new RuntimeException('Firewall service regression.'); };
$serviceForPort = static function ($fw, $port) {
    foreach ($fw->services as $id => $service) {
        if (($service['custfw']['port'] ?? null) === (string)$port) return [$id, $service];
    }
    return [null, null];
};
$state = tempnam(sys_get_temp_dir(), 'tlp-listener-');
$iptables = tempnam(sys_get_temp_dir(), 'tlp-listener-rules-');
unlink($state);
try {
    $kernelFailure = false;
    $verify = static function ($id, $port) use (&$kernelFailure) {
        if ($kernelFailure) throw new RuntimeException('Generated rules have not converged');
    };
    $reconcile = static function ($port) use ($fw, $state, $verify) {
        FirewallListener::reconcile($fw, $port, $state, $verify);
    };
    $fails = static function ($operation) use ($assert) {
        try { $operation(); } catch (RuntimeException $error) { return; }
        $assert(false);
    };
    $fw->fail = 'create';
    $fails(static function () use ($reconcile) { $reconcile(51821); });
    $assert(is_file($state) && count($fw->services) === 2);
    $fw->fail = '';
    $reconcile(51821);
    [$serviceId, $service] = $serviceForPort($fw, 51821);
    $assert($service['custfw'] === ['protocol' => 'udp', 'port' => '51821']);
    $assert($fw->zones[$serviceId] === ['external', 'internal', 'other']);
    $writes = $fw->writes;
    $reconcile(51821);
    $assert($fw->writes === $writes);
    $reconcile(51899);
    [$serviceId, $service] = $serviceForPort($fw, 51899);
    $assert(count($fw->services) === 2 && $service['custfw']['port'] === '51899');
    $fw->fail = 'create';
    $fails(static function () use ($reconcile) { $reconcile([51899, 51898]); });
    $fw->fail = '';
    $reconcile([51899, 51898]);
    $assert(count($fw->services) === 3);
    $reconcile(51899);
    [$serviceId] = $serviceForPort($fw, 51899);
    unset($fw->services[$serviceId], $fw->zones[$serviceId]);
    $fw->fail = 'create';
    $fails(static function () use ($reconcile) { $reconcile(51899); });
    $assert(is_file($state));
    $fw->fail = '';
    $reconcile(51899);
    [$serviceId, $service] = $serviceForPort($fw, 51899);
    $name = $service['name'];
    $fw->services[$serviceId]['name'] = 'Administrator changed this';
    try {
        $reconcile(0);
        throw new LogicException('Conflicting ownership was accepted.');
    } catch (RuntimeException $error) {
        $assert(isset($fw->services[$serviceId]) && is_file($state));
    }
    $fw->services[$serviceId]['name'] = $name;
    $fw->fail = 'delete';
    $fails(static function () use ($reconcile) { $reconcile([]); });
    $assert(is_file($state));
    $fw->fail = '';
    $kernelFailure = true;
    $fails(static function () use ($reconcile) { $reconcile([]); });
    $assert(is_file($state) && count($fw->services) === 1);
    $kernelFailure = false;
    $reconcile([]);
    $assert($fw->services === ['unrelated' => ['name' => 'Unrelated service']] && !is_file($state));
    $fw->fail = 'zones';
    $fails(static function () use ($reconcile) { $reconcile(51821); });
    $assert(is_file($state));
    $fw->fail = '';
    $kernelFailure = true;
    $fails(static function () use ($reconcile) { $reconcile(51821); });
    $kernelFailure = false;
    $reconcile(51821);
    $reconcile([]);
    $rules = ['-A fpbxsvc-owned -p udp -m udp --dport 51821 -j ACCEPT'];
    foreach (['external', 'internal', 'other'] as $zone) $rules[] = '-A zone-' . $zone . ' -j fpbxsvc-owned';
    $rules[] = '-A INPUT -j fpbxfirewall';
    $rules[] = '-A fpbxfirewall -j zone-external';
    $assert(FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51821));
    foreach (['-A INPUT -j DROP', '-A INPUT -j REJECT', '-A INPUT -s ::/0 -j DROP',
              '-A INPUT -s 0.0.0.0/0 -j REJECT', '-A INPUT -i eth0 -j fpbxfirewall'] as $earlier) {
        $assert(!FirewallListener::rulesConverged(array_merge([$earlier], $rules), 'fpbxsvc-owned', 51821));
    }
    // IPv4 success cannot stand in for a separate blocked IPv6 snapshot.
    $ipv6 = array_merge(['-A INPUT -j REJECT'], $rules);
    $assert(FirewallListener::rulesMismatch($ipv6, 'fpbxsvc-owned', 51821) === 'public INPUT path blocked');
    $assert(FirewallListener::publicPath([], 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (undeclared chain INPUT)');
    $assert(FirewallListener::publicPath(['-N INPUT'], 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (empty declared chain INPUT)');
    $assert(FirewallListener::publicPath(['-N arbitrary'], 'fpbxsvc-owned', 'arbitrary', [], 51821)
        === 'unknown (empty declared chain arbitrary)');
    $assert(FirewallListener::publicPath(['-A INPUT -j arbitrary'], 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (undeclared chain arbitrary)');
    $assert(FirewallListener::publicPath(['-A INPUT -j fpbxfirewall', '-A fpbxfirewall -j DROP'],
        'fpbxsvc-owned', 'INPUT', [], 51821) === 'blocked');
    $assert(FirewallListener::publicPath(['-A INPUT -m conntrack --ctstate NEW -j ACCEPT'],
        'fpbxsvc-owned', 'INPUT', [], 51821) === 'unknown (unsupported match)');

    // Captured FreePBX 17 control-flow shapes: non-unicast exclusions, DHCP
    // ranges, Fail2Ban checks for an unrelated UDP service, packet marks, zones,
    // source-specific blocks and the final listener service jump.
    $freepbx17 = [
        '-P INPUT ACCEPT',
        '-N INPUT', '-N fpbxfirewall', '-N zone-external', '-N zone-internal', '-N zone-other',
        '-N f2b-pbx-provisioning', '-N fpbxsvc-owned',
        '-A INPUT -m pkttype --pkt-type broadcast -j ACCEPT',
        '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT',
        '-A INPUT -d 255.255.255.255/32 -j ACCEPT',
        '-A INPUT -p udp -m udp --dport 67:68 -j ACCEPT',
        '-A INPUT -p udp -m multiport --dports 1194,1701 -j f2b-pbx-provisioning',
        '-A INPUT -j fpbxfirewall',
        '-A f2b-pbx-provisioning -s 198.51.100.12/32 -j REJECT',
        '-A f2b-pbx-provisioning -j RETURN',
        '-A INPUT -i eth0 -j zone-external',
        '-A fpbxfirewall -i lo -j ACCEPT',
        '-A fpbxfirewall -p udp -j MARK --set-xmark 0x2/0x2',
        '-A fpbxfirewall -m mark --mark 0x2/0x2 -j zone-external',
        '-A fpbxfirewall -s 203.0.113.0/24 -j zone-external',
        '-A fpbxfirewall -j zone-external',
        '-A zone-external -s 10.0.0.0/8 -j DROP',
        '-A zone-external -j fpbxsvc-owned',
        '-A fpbxsvc-owned -p udp -m udp --dport 51821 -j ACCEPT',
        '-A zone-internal -j fpbxsvc-owned',
        '-A zone-other -j fpbxsvc-owned',
    ];
    $assert(FirewallListener::publicPath($freepbx17, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'verified');
    $assert(FirewallListener::publicPath(['-A INPUT -d 255.255.255.255/32 -j ACCEPT',
        '-A INPUT -j fpbxsvc-owned'], 'fpbxsvc-owned', 'INPUT', [], 51821) === 'verified');
    $assert(FirewallListener::publicPath(['-A INPUT -d 224.0.0.0/4 -j ACCEPT',
        '-A INPUT -j fpbxsvc-owned'], 'fpbxsvc-owned', 'INPUT', [], 51821) === 'verified');
    $assert(FirewallListener::publicPath(['-A INPUT -d 0.0.0.0/1 -j ACCEPT',
        '-A INPUT -j fpbxsvc-owned'], 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (unsupported or ambiguous rule)');

    $dhcpOnly = ['-A INPUT -p udp -m udp --dport 67:68 -j ACCEPT', '-A INPUT -j DROP'];
    $assert(FirewallListener::publicPath($dhcpOnly, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'blocked');
    $broadAccept = ['-A INPUT -m comment --comment "known rule" -j ACCEPT'];
    $assert(FirewallListener::publicPath($broadAccept, 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (unsupported or ambiguous rule)');
    $catchAllSourceDrop = ['-A INPUT -s 0.0.0.0/0 -j DROP', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($catchAllSourceDrop, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'blocked');
    $unknownBeforeAccept = ['-A INPUT -m recent --name dynamic --rcheck -j DROP', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($unknownBeforeAccept, 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (unsupported or ambiguous rule)');
    $otherPortFail2ban = ['-A INPUT -p udp -m multiport --dports 1194,1701 -j f2b-pbx-provisioning',
        '-A f2b-pbx-provisioning -s 198.51.100.12/32 -j REJECT',
        '-A f2b-pbx-provisioning -j RETURN', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($otherPortFail2ban, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'verified');
    $sourceBlockOnly = ['-A INPUT -s 198.51.100.12/32 -j DROP', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($sourceBlockOnly, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'verified');
    $mixedBlockAndListener = ['-A INPUT -s 0.0.0.0/1 -j DROP', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($mixedBlockAndListener, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'blocked');
    $markWithoutInitialization = ['-A INPUT -m mark --mark 0x0/0x2 -j DROP', '-A INPUT -j fpbxsvc-owned'];
    $assert(FirewallListener::publicPath($markWithoutInitialization, 'fpbxsvc-owned', 'INPUT', [], 51821)
        === 'unknown (unsupported or ambiguous rule)');
    $assert(FirewallListener::publicPath(['-A INPUT -p udp -m multiport --dports 1194,1701 -j ACCEPT'],
        'fpbxsvc-owned', 'INPUT', [], 51821) === 'blocked');

    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51899));
    $assert(!FirewallListener::rulesConverged(array_slice($rules, 0, 3), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged(array_merge($rules, [$rules[0]]), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 0));
    $assert(FirewallListener::rulesConverged([], 'fpbxsvc-owned', 0));
    $blockedDuringRemoval = ['-A INPUT -j REJECT'];
    $regeneratingDuringRemoval = [];
    $assert(FirewallListener::rulesConverged($blockedDuringRemoval, 'fpbxsvc-owned', 0));
    $assert(FirewallListener::rulesConverged($regeneratingDuringRemoval, 'fpbxsvc-owned', 0));
    $blockedRemoval = tempnam(sys_get_temp_dir(), 'tlp-listener-blocked-removal-');
    file_put_contents($blockedRemoval, json_encode(['services' => [
        '51821' => ['id' => 'owned-blocked', 'name' => 'TELIPHONES WireGuard listener (managed)']
    ]]));
    $blockedFw = new class {
        public array $services = ['owned-blocked' => ['name' => 'TELIPHONES WireGuard listener (managed)',
            'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => 'udp', 'port' => '51821'], 'custid' => 'owned-blocked', 'noreject' => true]];
        public array $zones = ['owned-blocked' => ['external', 'internal', 'other']];
        public function getAllCustomServices() { return $this->services; }
        public function getCustomServiceZones($id) { return $this->zones[$id] ?? []; }
        public function deleteCustomService($id) { unset($this->services[$id], $this->zones[$id]); }
    };
    FirewallListener::reconcile($blockedFw, [], $blockedRemoval, static function ($id, $port) use ($assert) {
        $assert($port === 0, 'Removal verification must not require public INPUT reachability.');
    });
    $assert($blockedFw->services === [] && !is_file($blockedRemoval));
    unlink($blockedRemoval . '.lock');
    $chain = 'fpbxsvc-50dc73725c3e4073';
    $observed = array_map(static function ($line) use ($chain) {
        return str_replace('fpbxsvc-owned', $chain, $line);
    }, $rules);
    $assert(FirewallListener::rulesMismatch($observed, $chain, 51821) === '');
    $assert(FirewallListener::rulesMismatch($observed, $chain, 0)
        === 'service rules remain (1); zone-external jump remains; zone-internal jump remains; zone-other jump remains');
    $assert(FirewallListener::rulesMismatch($observed, 'fpbxsvc-newlistener', 52800)
        === 'UDP ACCEPT missing; zone-external jump missing; zone-internal jump missing; zone-other jump missing');
    $assert(FirewallListener::rulesMismatch($observed, $chain, 51822)
        === 'service rules differ (rules=1, exact ACCEPTs=0)');
    $assert(FirewallListener::rulesMismatch(array_merge($observed, [$observed[0]]), $chain, 51821)
        === 'service rules differ (rules=2, exact ACCEPTs=2)');
    $assert(FirewallListener::rulesMismatch(array_slice($observed, 0, 3), $chain, 51821)
        === 'zone-other jump missing');
    $assert(FirewallListener::rulesMismatch(array_merge($observed, ['-A zone-trusted -j ' . $chain]), $chain, 51821)
        === 'zone-trusted jump remains');
    file_put_contents($iptables, "#!/bin/sh\nprintf '%s\\n' "
        . implode(' ', array_map('escapeshellarg', $observed)) . "\n");
    chmod($iptables, 0700);
    FirewallListener::verifyRules('50dc7372-5c3e-4073-a477-e49ecf930b1f', 51821, $iptables);
    file_put_contents($iptables, "#!/bin/sh\nprintf '%s\\n' "
        . escapeshellarg('-A INPUT -j REJECT') . "\n");
    chmod($iptables, 0700);
    FirewallListener::verifyRules('50dc7372-5c3e-4073-a477-e49ecf930b1f', 0, $iptables);
    file_put_contents($iptables, "#!/bin/sh\nprintf '%s\\n'");
    FirewallListener::verifyRules('50dc7372-5c3e-4073-a477-e49ecf930b1f', 0, $iptables);
    file_put_contents($iptables, "#!/bin/sh\nprintf '%s\\n' "
        . escapeshellarg('-A ' . $chain . ' -m comment --comment PRIVATE-KEY-FIXTURE -j ACCEPT') . "\n");
    try {
        FirewallListener::verifyRules('50dc7372-5c3e-4073-a477-e49ecf930b1f', 51821, $iptables, hrtime(true) / 1e9);
        throw new LogicException('Unconverged listener was accepted.');
    } catch (RuntimeException $error) {
        $assert(strpos($error->getMessage(), $chain . ' UDP 51821: service rules differ (rules=1, exact ACCEPTs=0)') !== false);
        $assert(strpos($error->getMessage(), 'zone-other jump missing') !== false);
        $assert(strpos($error->getMessage(), 'PRIVATE-KEY-FIXTURE') === false);
    }
    echo "Firewall listener tests: PASS (API model, interrupted creation recovery, multi-port reconciliation, zone failure, removal verification, kernel convergence fixtures, bounded mismatch diagnostics, idempotence and unrelated preservation)\n";
} finally {
    if (is_file($iptables)) unlink($iptables);
    if (is_file($state)) unlink($state);
    if (is_file($state . '.lock')) unlink($state . '.lock');
}
