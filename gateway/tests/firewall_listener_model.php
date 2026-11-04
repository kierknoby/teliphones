<?php
// API/daemon model only. The real helper verifies the resulting namespace kernel rules.
if ($argc !== 5 || !in_array($argv[3], ['/usr/sbin/iptables-nft', '/usr/sbin/iptables-legacy'], true)
    || !str_starts_with($argv[4], 'net:[') || readlink('/proc/self/ns/net') === $argv[4]) {
    throw new RuntimeException('Refusing to run outside the isolated packet lab.');
}
require_once dirname(__DIR__, 2) . '/teliphones/FirewallListener.php';
use FreePBX\modules\Teliphones\FirewallListener;

$fw = new class($argv[1], $argv[3]) {
    public array $services;
    public array $zones;
    private string $path;
    private string $iptables;
    public function __construct($path, $iptables) {
        $this->path = $path . '/freepbx-model.json';
        $this->iptables = $iptables;
        $data = is_file($this->path) ? json_decode(file_get_contents($this->path), true, 32, JSON_THROW_ON_ERROR) : [];
        $this->services = $data['services'] ?? [];
        $this->zones = $data['zones'] ?? [];
    }
    private function run(array $arguments): string {
        $output = [];
        exec(escapeshellarg($this->iptables) . ' -w 5 ' . implode(' ', array_map('escapeshellarg', $arguments)) . ' 2>&1', $output, $result);
        if ($result !== 0) throw new RuntimeException(implode("\n", $output));
        return implode("\n", $output);
    }
    private function save(): void {
        file_put_contents($this->path, json_encode(['services' => $this->services, 'zones' => $this->zones], JSON_THROW_ON_ERROR));
    }
    public function getAllCustomServices() { return $this->services; }
    public function getCustomServiceZones($id) { return $this->zones[$id] ?? []; }
    public function addCustomService($name, $protocol, $port): void {
        $id = '12345678-1234-1234-1234-123456789012';
        $this->services[$id] = ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => $protocol, 'port' => $port], 'custid' => $id, 'noreject' => true];
        $this->zones[$id] = ['internal'];
        $this->save();
        $this->generate($id);
    }
    public function editCustomService($id, $name, $protocol, $port): void {
        $this->services[$id]['custfw'] = ['protocol' => $protocol, 'port' => $port];
        $this->save();
        $this->generate($id);
    }
    public function setCustomServiceZones($id, $zones): void {
        $this->zones[$id] = $zones;
        $this->save();
        $this->generate($id);
    }
    public function deleteCustomService($id): void {
        unset($this->services[$id], $this->zones[$id]);
        $this->save();
        $this->generate($id);
    }
    public function generate($id): void {
        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
        $snapshot = $this->run(['-S']);
        foreach (['external', 'internal', 'other'] as $zone) {
            if (str_contains($snapshot, '-A zone-' . $zone . ' -j ' . $chain)) {
                $this->run(['-D', 'zone-' . $zone, '-j', $chain]);
            }
        }
        if (str_contains($snapshot, '-N ' . $chain)) {
            $this->run(['-F', $chain]);
            if (!isset($this->services[$id])) $this->run(['-X', $chain]);
        } elseif (isset($this->services[$id])) {
            $this->run(['-N', $chain]);
        }
        if (!isset($this->services[$id])) return;
        $this->run(['-A', $chain, '-p', 'udp', '-m', 'udp', '--dport', $this->services[$id]['custfw']['port'], '-j', 'ACCEPT']);
        foreach ($this->zones[$id] as $zone) $this->run(['-A', 'zone-' . $zone, '-j', $chain]);
    }
};
// Simulate daemon regeneration after a FreePBX rule rebuild, separately from the helper.
foreach (array_keys($fw->services) as $id) $fw->generate($id);
FirewallListener::reconcile($fw, (int)$argv[2], $argv[1] . '/listener.json',
    static function ($id, $port) use ($argv) { FirewallListener::verifyRules($id, $port, $argv[3]); });
