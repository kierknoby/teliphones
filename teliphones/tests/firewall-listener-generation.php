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
        $lines = $fw->rules;
        $result = 0;
    }
}
namespace {
    require_once dirname(__DIR__) . '/FirewallListener.php';
    use FreePBX\modules\Teliphones\FirewallListener;

    $fw = new class {
        public array $services = [], $zones = [], $rules = [];
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
            $this->rules = [];
            foreach ($this->services as $id => $service) {
                $chain = 'fpbxsvc-' . substr($id, 0, 16);
                $this->rules[] = '-A ' . $chain . ' -p udp -m udp --dport ' . $service['custfw']['port'] . ' -j ACCEPT';
                foreach ($this->zones[$id] as $zone) $this->rules[] = '-A zone-' . $zone . ' -j ' . $chain;
            }
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
            $check(count($fw->rules) === 8, 'Admission returned before both listeners converged');
            $check($GLOBALS['generationClock'] < 150, 'Ports must share one generation cycle');
            $before = $GLOBALS['generationClock'];
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            $check($GLOBALS['generationClock'] === $before, 'An unchanged listener must not wait');
            // Normal regeneration loses the generated rules, but not the saved services.
            $fw->rules = [];
            FirewallListener::reconcile($fw, [51821, 52022], $state);
            $check(count($fw->rules) === 8, 'Regeneration did not restore both listeners');
            $before = $GLOBALS['generationClock'];
            FirewallListener::reconcile($fw, [], $state);
            $check(!$fw->rules && !is_file($state), 'Removal returned before generated permits disappeared');
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
        echo "Firewall asynchronous generation tests: PASS (fast/normal/slow, multi-port, regeneration, removal, stalled daemon)\n";
    } finally {
        if (is_file($state)) unlink($state);
        if (is_file($state . '.lock')) unlink($state . '.lock');
    }
}
