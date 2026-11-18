<?php
// FreePBX 17 saves Custom Services immediately; its daemon polls separately at
// 15/30/120-second intervals (phar/src/firewall.php getSettings/updateFirewallRules).
// A virtual clock exercises the real reconciler and verifier without touching a firewall.
namespace FreePBX\modules\Teliphones {
    function hrtime($number = false) { return (int) ($GLOBALS['generationClock'] * 1e9); }
    function usleep($microseconds) { $GLOBALS['generationClock'] += $microseconds / 1e6; }
    function exec($command, &$lines, &$result) {
        $fw = $GLOBALS['generationFirewall'];
        if ($GLOBALS['generationClock'] >= $fw->next && !$fw->stalled) {
            $fw->generate();
            $fw->next = $GLOBALS['generationClock'] + $fw->period;
        }
        $lines = strpos($command, 'ip6tables') !== false ? $fw->rulesV6 : $fw->rules;
        $result = 0;
    }
}
namespace {
    require_once dirname(__DIR__) . '/FirewallListener.php';
    use FreePBX\modules\Teliphones\FirewallListener;

    $fw = new class {
        public array $services = [], $zones = [], $rules = [], $rulesV6 = [];
        public float $period = 30, $next = 30;
        public bool $stalled = false;
        public function getAllCustomServices() { return $this->services; }
        public function getCustomServiceZones($id) { return $this->zones[$id] ?? []; }
        public function addCustomService($name, $protocol, $port) {
            $id = md5($name);
            $this->services[$id] = ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
                'custfw' => ['protocol' => $protocol, 'port' => $port], 'custid' => $id, 'noreject' => true];
            $this->zones[$id] = ['internal'];
        }
        public function setCustomServiceZones($id, $zones) { $this->zones[$id] = $zones; }
        public function deleteCustomService($id) { unset($this->services[$id], $this->zones[$id]); }
        public function generate() {
            // FreePBX 17 selects zones through fpbxinterfaces.
            $this->rules = [
                '-A INPUT -j fpbxfirewall',
                '-A fpbxfirewall -j fpbxinterfaces',
                '-A fpbxinterfaces -i eth0 -j zone-external',
                '-A fpbxinterfaces -i eth1 -j zone-external',
            ];
            foreach ($this->services as $id => $service) {
                $chain = 'fpbxsvc-' . substr($id, 0, 16);
                $this->rules[] = '-A ' . $chain . ' -p udp -m udp --dport ' . $service['custfw']['port'] . ' -j ACCEPT';
                foreach ($this->zones[$id] as $zone) $this->rules[] = '-A zone-' . $zone . ' -j ' . $chain;
            }
            $this->rulesV6 = $this->rules;
        }
    };
    $GLOBALS['generationFirewall'] = $fw;
    $state = tempnam(sys_get_temp_dir(), 'tlp-generation-');
    unlink($state);
    $check = static function ($ok, $message) { if (!$ok) throw new RuntimeException($message); };
    try {
        foreach ([15, 30, 120] as $period) {
            $GLOBALS['generationClock'] = 0;
            $fw->period = $fw->next = $period + 5; // daemon sleep granularity and work
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            $check(count($fw->rules) === 12, 'Admission returned before both listeners converged');
            $check($GLOBALS['generationClock'] < 150, 'Ports must share one generation cycle');
            $before = $GLOBALS['generationClock'];
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            $check($GLOBALS['generationClock'] === $before, 'An unchanged listener must not wait');
            // Normal regeneration loses the generated rules, but not the saved services.
            $fw->rules = [];
            $fw->rulesV6 = [];
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            $check(count($fw->rules) === 12, 'Regeneration did not restore both listeners');
            $before = $GLOBALS['generationClock'];
            FirewallListener::reconcile($fw, [], $state);
            $check(count($fw->rules) === 4 && !is_file($state), 'Removal returned before generated permits disappeared');
            $check($GLOBALS['generationClock'] - $before < 150, 'Removals must share one generation cycle');
        }
        $GLOBALS['generationClock'] = 0;
        $fw->stalled = true;
        try {
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            throw new LogicException('A stalled daemon admitted a listener');
        } catch (RuntimeException $error) {
            $check(strpos($error->getMessage(), 'have not converged') !== false, $error->getMessage());
            $check(is_file($state), 'Failed convergence lost recovery ownership');
            $check($GLOBALS['generationClock'] <= 150, 'Failure exceeded the transaction deadline');
        }
        // IPv4 success is not a substitute for IPv6.  This models the observed
        // nft-backed INPUT order: a Fail2Ban source-specific reject returns,
        // then FreePBX dispatches eth0 and eth1 into zone-external.
        $GLOBALS['generationClock'] = 0;
        $fw->stalled = false;
        $fw->services = $fw->zones = [];
        $fw->rules = $fw->rulesV6 = [];
        $fw->next = 0;
        FirewallListener::reconcile($fw, [51821], $state);
        $fail2ban = ['-A INPUT -j fail2ban-SIP',
                     '-A fail2ban-SIP -s 198.51.100.44 -p udp --dport 51821 -j REJECT --reject-with icmp-port-unreachable',
                     '-A fail2ban-SIP -j RETURN'];
        $fw->rules = array_merge($fail2ban, $fw->rules);
        $fw->rulesV6 = array_merge(array_map(static function ($line) {
            return str_replace('198.51.100.44', '2001:db8::44', $line);
        }, $fail2ban), $fw->rulesV6);
        FirewallListener::reconcile($fw, [51821], $state);

        // Regression boundary: 0.6.7 admitted IPv4 without inspecting IPv6;
        // the 0.8.0 implementation required this generated IPv6 service too.
        // Here IPv6 has no TELIPHONES service, but its INPUT policy is DROP and
        // normal FreePBX rules include legitimate IPv6-only classes and an
        // unrecognised Fail2Ban source-set REJECT. These cannot expose the
        // unicast WireGuard listener, so IPv4 admission must proceed.
        $fw->rulesV6 = [
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
        $saved = json_decode(file_get_contents($state), true, 16, JSON_THROW_ON_ERROR);
        $id = $saved['services']['51821']['id'];
        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
        $oldDualStackMismatch = FirewallListener::rulesMismatch($fw->rulesV6, $chain, 51821);
        $check($oldDualStackMismatch !== '', 'Fixture must reproduce 0.8.0 missing-IPv6-service failure condition.');
        $before = $GLOBALS['generationClock'];
        FirewallListener::reconcile($fw, [51821], $state);
        $check($GLOBALS['generationClock'] === $before,
            'An IPv6-closed, IPv4-admitted FreePBX listener must not wait for an ungenerated IPv6 service.');
        $check(is_file($state), 'IPv6-closed admission lost listener ownership state');

        // An unsupported classifier ending in ACCEPT could expose the
        // unbound-family WireGuard listener; never infer safety from absence
        // of the generated IPv6 Custom Service alone.
        array_unshift($fw->rulesV6, '-A INPUT -m set --match-set public-v6 src -j ACCEPT');
        try {
            FirewallListener::reconcile($fw, [51821], $state);
            throw new LogicException('An unverified, potentially exposing IPv6 ACCEPT was accepted.');
        } catch (RuntimeException $error) {
            $check(strpos($error->getMessage(), 'IPV6') !== false, $error->getMessage());
            $check(is_file($state), 'IPv6 verification failure lost listener ownership recovery state');
        }

        // A known unicast ACCEPT is equally unsafe, even with the IPv4
        // generated service fully verified.
        array_shift($fw->rulesV6);
        array_unshift($fw->rulesV6, '-A INPUT -p udp -j ACCEPT');
        try {
            FirewallListener::reconcile($fw, [51821], $state);
            throw new LogicException('A broad IPv6 UDP ACCEPT was accepted.');
        } catch (RuntimeException $error) {
            $check(strpos($error->getMessage(), 'IPV6') !== false, $error->getMessage());
        }
        echo "Firewall asynchronous generation tests: PASS (fast/normal/slow, multi-port, regeneration, removal, stalled daemon)\n";
    } finally {
        if (is_file($state)) unlink($state);
        if (is_file($state . '.lock')) unlink($state . '.lock');
    }
}
