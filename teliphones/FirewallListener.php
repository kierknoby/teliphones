<?php
namespace FreePBX\modules\Teliphones;

/** Persistent listener permission; FreePBX, not the broker, owns the generated UDP rules. */
final class FirewallListener
{
    public const NAME = 'TELIPHONES WireGuard listener (managed)';
    private const ZONES = ['external', 'internal', 'other'];

    public static function reconcile($firewall, int $port, string $stateFile, ?callable $verify = null): void
    {
        if ($port !== 0 && ($port < 1024 || $port > 65535)) {
            throw new \RuntimeException('Invalid TELIPHONES WireGuard listener port.');
        }
        $lock = fopen($stateFile . '.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock TELIPHONES listener ownership state.');
        }
        try {
            $saved = is_file($stateFile) ? json_decode(file_get_contents($stateFile), true, 16, JSON_THROW_ON_ERROR) : null;
            if ($saved !== null && (!is_array($saved) || !is_int($saved['port'] ?? null)
                || !is_string($saved['name'] ?? self::NAME)
                || !array_key_exists('id', $saved)
                || ($saved['id'] !== null && !is_string($saved['id']))
                || (isset($saved['next_port']) && !is_int($saved['next_port'])))) {
                throw new \RuntimeException('Invalid TELIPHONES listener ownership state.');
            }
            $services = $firewall->getAllCustomServices();
            if (!is_array($services)) throw new \RuntimeException('Cannot inventory FreePBX custom services.');
            $owned = null;
            foreach ($services as $id => $service) {
                if (!is_array($service)) continue;
                $name = $saved['name'] ?? self::NAME;
                if (($service['name'] ?? '') !== $name && ($saved['id'] ?? null) !== $id) continue;
                if ($saved === null || (($saved['id'] ?? null) !== $id
                    && ($saved['id'] ?? null) !== null)
                    || ($service !== self::service($id, $saved['port'], $name)
                        && $service !== self::service($id, $saved['next_port'] ?? $saved['port'], $name))) {
                    throw new \RuntimeException('Conflicting TELIPHONES listener service; refusing to change it.');
                }
                if ($owned !== null) throw new \RuntimeException('Duplicate TELIPHONES listener services.');
                $owned = $id;
            }
            if ($port === 0) {
                if ($owned !== null) {
                    $saved['id'] = $owned;
                    self::save($stateFile, $saved);
                    $firewall->deleteCustomService($owned);
                }
                $remaining = $firewall->getAllCustomServices();
                if (!is_array($remaining) || ($owned !== null && !empty($remaining[$owned]))) {
                    throw new \RuntimeException('FreePBX listener service removal could not be verified.');
                }
                if ($owned !== null || !empty($saved['id'])) {
                    ($verify ?? [self::class, 'verifyRules'])($owned ?? $saved['id'], 0);
                }
                if (is_file($stateFile) && !unlink($stateFile)) {
                    throw new \RuntimeException('Cannot remove TELIPHONES listener ownership state.');
                }
                return;
            }
            if ($saved === null) {
                $saved = ['id' => null, 'port' => $port, 'name' => self::NAME . ' ' . bin2hex(random_bytes(8))];
                self::save($stateFile, $saved);
            }
            $name = $saved['name'] ?? self::NAME;
            if ($owned === null) {
                // Persist intent before the API call: a crash after creation is safely adoptable.
                $saved['id'] = null;
                $saved['port'] = $port;
                unset($saved['next_port']);
                self::save($stateFile, $saved);
                $firewall->addCustomService($name, 'udp', (string)$port);
                $services = $firewall->getAllCustomServices();
                foreach ($services as $id => $service) {
                    if ($service === self::service($id, $port, $name)) {
                        if ($owned !== null) throw new \RuntimeException('Duplicate TELIPHONES listener services.');
                        $owned = $id;
                    }
                }
                if ($owned === null) throw new \RuntimeException('FreePBX did not save the listener service.');
            } elseif ($services[$owned] !== self::service($owned, $port, $name)) {
                $saved['id'] = $owned;
                $saved['next_port'] = $port;
                self::save($stateFile, $saved);
                $firewall->editCustomService($owned, false, 'udp', (string)$port);
            }
            $committed = ['id' => $owned, 'port' => $port, 'name' => $name];
            if ($saved !== $committed) self::save($stateFile, $committed);
            $zones = array_values($firewall->getCustomServiceZones($owned));
            sort($zones);
            if ($zones !== self::ZONES) $firewall->setCustomServiceZones($owned, self::ZONES);
            $services = $firewall->getAllCustomServices();
            $zones = array_values($firewall->getCustomServiceZones($owned));
            sort($zones);
            if (($services[$owned] ?? null) !== self::service($owned, $port, $name) || $zones !== self::ZONES) {
                throw new \RuntimeException('FreePBX listener service configuration could not be verified.');
            }
            ($verify ?? [self::class, 'verifyRules'])($owned, $port);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function save(string $path, array $state): void
    {
        $temporary = tempnam(dirname($path), '.listener-');
        if ($temporary === false) throw new \RuntimeException('Cannot create listener ownership transaction.');
        try {
            if (!chmod($temporary, 0600)
                || file_put_contents($temporary, json_encode($state, JSON_THROW_ON_ERROR)) === false
                || !rename($temporary, $path)) {
                throw new \RuntimeException('Cannot persist TELIPHONES listener ownership state.');
            }
        } finally {
            if (is_file($temporary)) unlink($temporary);
        }
    }

    public static function verifyRules(string $id, int $port, string $iptables = '/sbin/iptables'): void
    {
        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
        for ($attempt = 0; $attempt < 30; ++$attempt) {
            $lines = [];
            exec(escapeshellarg($iptables) . ' -w 1 -t filter -S 2>&1', $lines, $result);
            if ($result !== 0) throw new \RuntimeException('Cannot inspect FreePBX generated listener rules.');
            if (self::rulesConverged($lines, $chain, $port)) return;
            usleep(500000);
        }
        throw new \RuntimeException('FreePBX generated listener rules have not converged; reconciliation will retry.');
    }

    public static function rulesConverged(array $lines, string $chain, int $port): bool
    {
        $accept = '-A ' . $chain . ' -p udp -m udp --dport ' . $port . ' -j ACCEPT';
        $rules = array_values(array_filter($lines, static function ($line) use ($chain) {
            return strpos($line, '-A ' . $chain . ' ') === 0;
        }));
        foreach (array_merge(self::ZONES, ['reject', 'trusted']) as $zone) {
            $present = in_array('-A zone-' . $zone . ' -j ' . $chain, $lines, true);
            $required = $port !== 0 && in_array($zone, self::ZONES, true);
            if ($present !== $required) return false;
        }
        return $port === 0 ? count($rules) === 0 : $rules === [$accept];
    }

    private static function service(string $id, int $port, string $name = self::NAME): array
    {
        return ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => 'udp', 'port' => (string)$port], 'custid' => $id, 'noreject' => true];
    }
}
