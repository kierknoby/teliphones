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
    $assert(FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 51899));
    $assert(!FirewallListener::rulesConverged(array_slice($rules, 0, 3), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged(array_merge($rules, [$rules[0]]), 'fpbxsvc-owned', 51821));
    $assert(!FirewallListener::rulesConverged($rules, 'fpbxsvc-owned', 0));
    $assert(FirewallListener::rulesConverged([], 'fpbxsvc-owned', 0));
    echo "Firewall listener tests: PASS (API model, interrupted creation recovery, multi-port reconciliation, zone failure, removal verification, kernel convergence fixtures, idempotence and unrelated preservation)\n";
} finally {
    if (is_file($state)) unlink($state);
    if (is_file($state . '.lock')) unlink($state . '.lock');
}
