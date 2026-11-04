<?php
namespace FreePBX\modules\Teliphones;

/** Persistent listener permission; FreePBX, not the broker, owns the generated UDP rules. */
final class FirewallListener
{
    public const NAME = 'TELIPHONES WireGuard listener (managed)';
    private const ZONES = ['external', 'internal', 'other'];

    public static function reconcile($firewall, $ports, string $stateFile, ?callable $verify = null): void
    {
        if ($ports === 0) $ports = [];
        $ports = is_array($ports) ? $ports : [$ports];
        foreach ($ports as $port) {
            if (!is_int($port) || $port < 1024 || $port > 65535) {
                throw new \RuntimeException('Invalid TELIPHONES WireGuard listener port.');
            }
        }
        $ports = array_values(array_unique($ports));
        sort($ports, SORT_NUMERIC);
        $lock = fopen($stateFile . '.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock TELIPHONES listener ownership state.');
        }
        try {
            $saved = is_file($stateFile) ? json_decode(file_get_contents($stateFile), true, 16, JSON_THROW_ON_ERROR) : null;
            if ($saved !== null && !is_array($saved)) {
                throw new \RuntimeException('Invalid TELIPHONES listener ownership state.');
            }
            if ($saved !== null && isset($saved['port'])) {
                if (!is_int($saved['port']) || !array_key_exists('id', $saved)
                    || ($saved['id'] !== null && !is_string($saved['id']))
                    || !is_string($saved['name'] ?? self::NAME)) {
                    throw new \RuntimeException('Invalid TELIPHONES listener ownership state.');
                }
                $saved = ['services' => [(string)$saved['port'] => [
                    'id' => $saved['id'], 'name' => $saved['name'] ?? self::NAME,
                ]]];
            }
            if ($saved !== null && (!isset($saved['services']) || !is_array($saved['services']))) {
                throw new \RuntimeException('Invalid TELIPHONES listener ownership state.');
            }
            $services = $firewall->getAllCustomServices();
            if (!is_array($services)) throw new \RuntimeException('Cannot inventory FreePBX custom services.');
            $saved = $saved ?? ['services' => []];
            foreach ($saved['services'] as $port => $record) {
                if (!ctype_digit((string)$port) || !is_array($record)
                    || !array_key_exists('id', $record)
                    || ($record['id'] !== null && !is_string($record['id']))
                    || !is_string($record['name'] ?? null)) {
                    throw new \RuntimeException('Invalid TELIPHONES listener ownership record.');
                }
            }
            $ownedIds = [];
            $ownedNames = [];
            foreach ($saved['services'] as $record) {
                if (isset($record['id'])) {
                    if (isset($ownedIds[$record['id']])) {
                        throw new \RuntimeException('Duplicate TELIPHONES listener ownership identifiers.');
                    }
                    $ownedIds[$record['id']] = true;
                }
                if (isset($ownedNames[$record['name']])) {
                    throw new \RuntimeException('Duplicate TELIPHONES listener ownership names.');
                }
                $ownedNames[$record['name']] = true;
            }
            foreach ($saved['services'] as $port => $record) {
                $matches = 0;
                foreach ($services as $id => $service) {
                    if (!is_array($service)) continue;
                    if (($service['name'] ?? null) !== $record['name'] && ($record['id'] ?? null) !== $id) continue;
                    if (($record['id'] !== null && $record['id'] !== $id)
                        || $service !== self::service($id, (int)$port, $record['name'])) {
                        throw new \RuntimeException('Conflicting TELIPHONES listener service; refusing to change it.');
                    }
                    ++$matches;
                    if ($record['id'] === null) $saved['services'][$port]['id'] = $id;
                }
                if ($matches > 1) throw new \RuntimeException('Duplicate TELIPHONES listener services.');
                if ($record['id'] !== null && !isset($services[$record['id']])
                    && in_array((int)$port, $ports, true)) {
                    $saved['services'][$port]['id'] = null;
                }
            }
            self::save($stateFile, $saved);

            foreach ($ports as $port) {
                $key = (string)$port;
                if (!isset($saved['services'][$key])) {
                    $saved['services'][$key] = ['id' => null, 'name' => self::NAME . ' ' . bin2hex(random_bytes(8))];
                    self::save($stateFile, $saved);
                }
                $record = $saved['services'][$key];
                $owned = $record['id'];
                if ($owned === null) {
                    foreach ($services as $id => $service) {
                        if (!is_array($service)) continue;
                        if (($service['name'] ?? null) !== $record['name']) continue;
                        if ($service !== self::service($id, $port, $record['name'])) {
                            throw new \RuntimeException('Conflicting TELIPHONES listener service; refusing to change it.');
                        }
                        if ($owned !== null) throw new \RuntimeException('Duplicate TELIPHONES listener services.');
                        $owned = $id;
                    }
                }
                if ($owned === null) {
                    $firewall->addCustomService($record['name'], 'udp', (string)$port);
                    $services = $firewall->getAllCustomServices();
                    foreach ($services as $id => $service) {
                        if ($service === self::service($id, $port, $record['name'])) {
                            if ($owned !== null) throw new \RuntimeException('Duplicate TELIPHONES listener services.');
                            $owned = $id;
                        }
                    }
                    if ($owned === null) throw new \RuntimeException('FreePBX did not save a TELIPHONES listener service.');
                    $saved['services'][$key]['id'] = $owned;
                    self::save($stateFile, $saved);
                }
                $zones = array_values($firewall->getCustomServiceZones($owned));
                sort($zones);
                if ($zones !== self::ZONES) $firewall->setCustomServiceZones($owned, self::ZONES);
                $services = $firewall->getAllCustomServices();
                $zones = array_values($firewall->getCustomServiceZones($owned));
                sort($zones);
                if (($services[$owned] ?? null) !== self::service($owned, $port, $record['name']) || $zones !== self::ZONES) {
                    throw new \RuntimeException('FreePBX listener service configuration could not be verified.');
                }
                ($verify ?? [self::class, 'verifyRules'])($owned, $port);
            }

            foreach (array_diff(array_keys($saved['services']), array_map('strval', $ports)) as $stalePort) {
                $record = $saved['services'][$stalePort];
                $id = $record['id'];
                if ($id !== null) {
                    $services = $firewall->getAllCustomServices();
                    if (!is_array($services)) throw new \RuntimeException('Cannot inventory FreePBX custom services.');
                    if (isset($services[$id])) $firewall->deleteCustomService($id);
                    $services = $firewall->getAllCustomServices();
                    if (!is_array($services) || !empty($services[$id])) {
                        throw new \RuntimeException('FreePBX listener service removal could not be verified.');
                    }
                    ($verify ?? [self::class, 'verifyRules'])($id, 0);
                }
                unset($saved['services'][$stalePort]);
                self::save($stateFile, $saved);
            }
            if (!$saved['services'] && is_file($stateFile) && !unlink($stateFile)) {
                throw new \RuntimeException('Cannot remove TELIPHONES listener ownership state.');
            }
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
