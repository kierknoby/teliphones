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
$stateDirectory = sys_get_temp_dir() . '/tlp-listener-' . bin2hex(random_bytes(8));
mkdir($stateDirectory, 0700);
$state = $stateDirectory . '/state.json';
$iptables = tempnam(sys_get_temp_dir(), 'tlp-listener-rules-');
try {
    $kernelFailure = false;
    $verify = static function ($id, $port) use (&$kernelFailure) {
        if ($kernelFailure) throw new RuntimeException('Generated rules have not converged');
    };
    $reconcile = static function ($port) use ($fw, $state, $verify) {
        FirewallListener::reconcile($fw, $port, $state, $verify);
    };
    $diagnostic = FirewallListener::recordFailure($state, [51821], new RuntimeException(
        'TLP-LISTENER-IPV6-PENDING: FreePBX generated listener rules have not converged; PRIVATE-KEY-FIXTURE'));
    $diagnosticFile = dirname($state) . '/firewall-listener-diagnostic.json';
    $assert($diagnostic === FirewallListener::lastDiagnostic($state));
    $assert($diagnostic['stage'] === 'ipv6-rule-generation'
        && $diagnostic['identifier'] === 'firewall-regeneration-in-progress');
    $assert((fileperms($diagnosticFile) & 0077) === 0);
    $assert(strpos((string)file_get_contents($diagnosticFile), 'PRIVATE-KEY-FIXTURE') === false);
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
    // Actual FreePBX 17 interface dispatch, rather than a synthetic direct
    // fpbxfirewall-to-zone shortcut.
    $rules[] = '-A INPUT -j fpbxfirewall';
    $rules[] = '-A fpbxfirewall -j fpbxinterfaces';
    $rules[] = '-A fpbxinterfaces -i eth0 -j zone-external';
    $rules[] = '-A fpbxinterfaces -i eth1 -j zone-external';
    $assert(FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51821));
    foreach (['-A INPUT -j DROP', '-A INPUT -j REJECT', '-A INPUT -s ::/0 -j DROP',
              '-A INPUT -s 0.0.0.0/0 -j REJECT'] as $earlier) {
        $assert(!FirewallListener::rulesConverged(array_merge([$earlier], $rules), 'fpbxsvc-owned', 51821));
    }
    // Security negatives: each rule precedes the managed FreePBX path and
    // blocks a new listener datagram rather than merely a synthetic chain.
    foreach ([
        '-A INPUT -p udp -m udp --dport 51821 -j DROP',
        '-A INPUT -p udp -m state --state NEW -j DROP',
        '-A INPUT -s 0.0.0.0/0 -p udp -j DROP',
    ] as $earlier) {
        $assert(!FirewallListener::rulesConverged(array_merge([$earlier], $rules), 'fpbxsvc-owned', 51821));
    }
    // The generated ACCEPT is unreachable when the external zone terminates
    // eligible packets before dispatching to the TELIPHONES service chain.
    foreach (['-A zone-external -j DROP', '-A zone-external -p udp --dport 51821 -j REJECT'] as $earlier) {
        $zoneBlocked = $rules;
        array_unshift($zoneBlocked, $earlier);
        $assert(!FirewallListener::rulesConverged($zoneBlocked, 'fpbxsvc-owned', 51821));
    }
    $assert(!FirewallListener::rulesConverged(array_merge([
        '-A INPUT -j BLOCKER', '-A BLOCKER -p udp -m udp --dport 51821 -j DROP',
    ], $rules), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged(array_merge([
        '-A INPUT -j BLOCKER', '-A BLOCKER -j DROP',
    ], $rules), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged(array_merge([
        '-A INPUT -p udp -m udp --dport 51821 -j ACCEPT',
    ], $rules), 'fpbxsvc-owned', 51821));
    // Specific source exclusions do not establish a universal listener failure.
    $assert(FirewallListener::rulesConverged(array_merge([
        '-A INPUT -s 192.0.2.1 -p udp --dport 51821 -j DROP',
    ], $rules), 'fpbxsvc-owned', 51821));
    $assert(FirewallListener::rulesMismatch($rules, 'fpbxsvc-owned', 51821, ['eth0', 'eth1']) === '');
    // Reduced dual-stack replay of the reported Debian 12 / FreePBX 17
    // nft-backed structure: Fail2Ban rejects a specific source, then returns;
    // unrelated UDP hooks and both public interfaces precede the service path.
    $actualChain = 'fpbxsvc-8f85a9fd070644d3';
    $actualSnapshot = [
        '-A INPUT -j fail2ban-SIP',
        '-A INPUT -p udp -m multiport --dports 1194 -j fail2ban-openvpn',
        '-A INPUT -j fpbxfirewall',
        '-A fail2ban-SIP -s 198.51.100.44 -p udp --dport 51821 -j REJECT --reject-with icmp-port-unreachable',
        '-A fail2ban-SIP -j RETURN',
        '-A fail2ban-openvpn -j RETURN',
        '-A fpbxfirewall -j fpbxinterfaces',
        '-A fpbxinterfaces -i eth0 -j zone-external',
        '-A fpbxinterfaces -i eth1 -j zone-external',
        '-A zone-external -j ' . $actualChain,
        '-A zone-internal -j ' . $actualChain,
        '-A zone-other -j ' . $actualChain,
        '-A ' . $actualChain . ' -p udp -m udp --dport 51821 -j ACCEPT',
    ];
    $assert(FirewallListener::rulesMismatch($actualSnapshot, $actualChain, 51821) === '');
    $ipv6Snapshot = array_map(static function ($rule) {
        return str_replace('198.51.100.44', '2001:db8::44', $rule);
    }, $actualSnapshot);
    $assert(FirewallListener::rulesMismatch($ipv6Snapshot, $actualChain, 51821) === '');
    // Lists and ranges unrelated to the listener cannot turn a harmless jail
    // hook into a listener failure.
    $unrelatedMultiport = array_merge([
        '-A INPUT -p udp -m multiport --dports 1194,1701 -j fail2ban-openvpn',
        '-A INPUT -p udp -m multiport --dports 2000:3000 -j fail2ban-openvpn',
        '-A fail2ban-openvpn -j RETURN',
    ], $rules);
    $assert(FirewallListener::rulesMismatch($unrelatedMultiport, 'fpbxsvc-owned', 51821) === '');
    $missingEth1 = array_values(array_filter($rules, static function ($rule) {
        return $rule !== '-A fpbxinterfaces -i eth1 -j zone-external';
    }));
    $assert(FirewallListener::rulesMismatch($missingEth1, 'fpbxsvc-owned', 51821, ['eth0', 'eth1'])
        === 'FreePBX listener integration unverified (public interface eth1 is not routed to zone-external)');
    $inputEth0Only = array_values(array_filter($rules, static function ($rule) {
        return $rule !== '-A INPUT -j fpbxfirewall';
    }));
    array_unshift($inputEth0Only, '-A INPUT -i eth0 -j fpbxfirewall');
    $assert(FirewallListener::rulesMismatch($inputEth0Only, 'fpbxsvc-owned', 51821, ['eth0', 'eth1'])
        === 'FreePBX listener integration unverified (public interface eth1 has no INPUT jump to fpbxfirewall)');
    $broadSources = array_merge([
        '-A INPUT -s 0.0.0.0/1 -p udp --dport 51821 -j DROP',
        '-A INPUT -s 128.0.0.0/1 -p udp --dport 51821 -j DROP',
    ], $rules);
    $assert(!FirewallListener::rulesConverged($broadSources, 'fpbxsvc-owned', 51821));
    $unrelatedInterface = array_merge([
        '-A INPUT -i eth999 -p udp --dport 51821 -j DROP',
    ], $rules);
    $assert(FirewallListener::rulesMismatch($unrelatedInterface, 'fpbxsvc-owned', 51821, ['eth0', 'eth1']) === '');
    // IPv4 success cannot stand in for a separate blocked IPv6 snapshot.
    $ipv6 = array_merge(['-A INPUT -j REJECT'], $rules);
    $assert(FirewallListener::rulesMismatch($ipv6, 'fpbxsvc-owned', 51821) === 'FreePBX listener integration blocked');

    // The admission contract is IPv4-only; IPv6 is required to be proven closed
    // when its generated Custom Service is absent. Simulate the IPv6 verifier
    // using its public rule classifier through the real reconciliation fixture.
    $ipv6ClosedButUnrecognised = [
        '-P INPUT DROP',
        '-A INPUT -p ipv6-icmp -j ACCEPT',
        '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
        '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT',
        '-A INPUT -j fail2ban-SIP',
        '-A fail2ban-SIP -m set --match-set fail2ban-v6 src -j REJECT --reject-with icmp6-port-unreachable',
        '-A fail2ban-SIP -j RETURN',
        '-A INPUT -j fpbxfirewall',
        '-A fpbxfirewall -j fpbxinterfaces',
        '-A fpbxinterfaces -i eth0 -j zone-external',
        '-A fpbxinterfaces -i eth1 -j zone-external',
        '-A zone-external -m pkttype --pkt-type multicast -j ACCEPT',
        '-A zone-external -m set --match-set local-v6 dst -j DROP',
    ];
    $assert(FirewallListener::rulesMismatch($ipv6ClosedButUnrecognised, 'fpbxsvc-owned', 51821)
        !== '', 'The .8.0 requirement for an IPv6 generated service is reproduced.');
    $ipv6Unexposed = new ReflectionMethod(FirewallListener::class, 'ipv6ListenerFailsClosed');
    $ipv6Unexposed->setAccessible(true);
    $assert($ipv6Unexposed->invoke(null, $ipv6ClosedButUnrecognised, 'fpbxsvc-owned', 51821),
        'IPv6 INPUT DROP plus unrelated/unrecognised deny rules must not block verified IPv4 pairing.');
    $unsafeIpv6Accept = $ipv6ClosedButUnrecognised;
    array_unshift($unsafeIpv6Accept, '-A INPUT -m set --match-set public-v6 src -j ACCEPT');
    $assert(!$ipv6Unexposed->invoke(null, $unsafeIpv6Accept, 'fpbxsvc-owned', 51821),
        'Unknown IPv6 ACCEPT path must remain fail-closed.');
    $broadIpv6Accept = $ipv6ClosedButUnrecognised;
    array_unshift($broadIpv6Accept, '-A INPUT -p udp -j ACCEPT');
    $assert(!$ipv6Unexposed->invoke(null, $broadIpv6Accept, 'fpbxsvc-owned', 51821),
        'A broad IPv6 UDP ACCEPT must remain fail-closed.');

    // A multicast-only ACCEPT cannot match an eligible unicast WireGuard
    // datagram, so IPv6 fallback must remain valid; broader pkttype matches
    // are still unknown and must fail closed.
    $multicastClosed = ['-P INPUT DROP', '-A INPUT -j fpbxfirewall', '-A fpbxfirewall -j zone-external',
        '-A zone-external -m pkttype --pkt-type multicast -j ACCEPT'];
    $assert(FirewallListener::publicPath($multicastClosed, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'return');
    $broadcastClosed = ['-P INPUT DROP', '-A INPUT -j fpbxfirewall', '-A fpbxfirewall -j zone-external',
        '-A zone-external -m pkttype --pkt-type broadcast -j ACCEPT'];
    $assert(FirewallListener::publicPath($broadcastClosed, 'fpbxsvc-owned', 'INPUT', [], 51821) === 'return');
    $assert(strpos(FirewallListener::publicPath(
        ['-P INPUT DROP', '-A INPUT -m pkttype --pkt-type unicast -j ACCEPT'], 'fpbxsvc-owned', 'INPUT', [], 51821), 'unknown') === 0);
    $assert(strpos(FirewallListener::publicPath(
        ['-P INPUT DROP', '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT --comment broad'], 'fpbxsvc-owned', 'INPUT', [], 51821), 'unknown') === 0);
    $assert(strpos(FirewallListener::publicPath(
        ['-P INPUT DROP', '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT'], 'fpbxsvc-owned', 'INPUT', [], 51821), 'unknown') === 0,
        'a broad INPUT multicast accept remains unsupported outside the precise FreePBX zone-chain proof');

    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51899));
    $assert(!FirewallListener::rulesConverged(array_slice($rules, 0, 3), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged(array_merge($rules, [$rules[0]]), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 0));
    $assert(FirewallListener::rulesConverged([], 'fpbxsvc-owned', 0));
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
    if (is_file(dirname($state) . '/firewall-listener-diagnostic.json')) unlink(dirname($state) . '/firewall-listener-diagnostic.json');
    if (is_dir($stateDirectory)) rmdir($stateDirectory);
}
