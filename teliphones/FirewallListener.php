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

            $pending = [];
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
                $pending[$owned] = $port;
            }

            $stalePorts = array_diff(array_keys($saved['services']), array_map('strval', $ports));
            foreach ($stalePorts as $stalePort) {
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
                    $pending[$id] = 0;
                }
            }
            // FreePBX persists Custom Services immediately, but generates rules on a
            // separate 15/30/120-second cycle. Submit all changes before waiting, with
            // one deadline for the entire transaction (including removed services).
            $deadline = hrtime(true) / 1e9 + 150;
            foreach ($pending as $id => $port) {
                if ($verify !== null) $verify($id, $port);
                else {
                    self::verifyRules($id, $port, '/sbin/iptables', $deadline);
                    self::verifyRules($id, $port, '/sbin/ip6tables', $deadline);
                }
            }
            if ($verify === null) {
                // One final joint snapshot: earlier per-service success is not a
                // guarantee that the same service still exists at completion.
                $snapshots = [];
                foreach (['/sbin/iptables', '/sbin/ip6tables'] as $binary) {
                    $lines = [];
                    exec(escapeshellarg($binary) . ' -w 1 -t filter -S 2>&1', $lines, $result);
                    if ($result !== 0) throw new \RuntimeException('Cannot verify both public address families.');
                    foreach ($pending as $id => $port) {
                        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
                        $mismatch = self::rulesMismatch($lines, $chain, $port);
                        if ($mismatch !== '') throw new \RuntimeException('Final listener path verification failed: ' . $mismatch);
                    }
                    $snapshots[] = implode("\n", $lines) . "\n";
                }
                $saved['verified_rules_sha256'] = hash('sha256', implode("\0", $snapshots));
                self::save($stateFile, $saved);
            }
            foreach ($stalePorts as $stalePort) {
                unset($saved['services'][$stalePort]);
            }
            if ($stalePorts) self::save($stateFile, $saved);
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
                || file_put_contents($temporary, json_encode($state, JSON_THROW_ON_ERROR)) === false) {
                throw new \RuntimeException('Cannot persist TELIPHONES listener ownership state.');
            }
            $handle = fopen($temporary, 'r+');
            if ($handle === false || !fsync($handle)) throw new \RuntimeException('Cannot sync listener ownership.');
            fclose($handle);
            if (!rename($temporary, $path)) {
                throw new \RuntimeException('Cannot persist TELIPHONES listener ownership state.');
            }
        } finally {
            if (is_file($temporary)) unlink($temporary);
        }
    }

    public static function verifyRules(string $id, int $port, string $iptables = '/sbin/iptables', ?float $deadline = null): void
    {
        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
        $deadline = $deadline ?? hrtime(true) / 1e9 + 150;
        $lastMismatch = '';
        do {
            $lines = [];
            exec(escapeshellarg($iptables) . ' -w 1 -t filter -S 2>&1', $lines, $result);
            if ($result !== 0) throw new \RuntimeException('Cannot inspect FreePBX generated listener rules.');
            if (self::rulesConverged($lines, $chain, $port)) return;
            $lastMismatch = self::rulesMismatch($lines, $chain, $port);
            if ($port !== 0) {
                $path = self::publicPath($lines, $chain, 'INPUT', [], $port);
                // Only an absent INPUT chain or an empty, explicitly declared
                // chain is a recognised FreePBX regeneration state. Unknown
                // targets, arbitrary undeclared chains, unsupported matches,
                // and proven blocks remain immediate failures.
                $retryable = $path === 'unknown (undeclared chain INPUT)'
                    || preg_match('/^unknown \(empty declared chain (?:INPUT|fpbxfirewall|zone-(?:external|internal|other))\)$/D', $path);
                if ($path === 'blocked' || (strpos($path, 'unknown') === 0 && !$retryable)) {
                    throw new \RuntimeException('Public listener path ' . $path . '; no effective integration is claimed.');
                }
            }
            if (hrtime(true) / 1e9 >= $deadline) break;
            usleep(500000);
        } while (true);
        throw new \RuntimeException('FreePBX generated listener rules have not converged; reconciliation will retry. '
            . $chain . ' ' . ($port === 0 ? 'removal' : 'UDP ' . $port) . ': '
            . $lastMismatch);
    }

    public static function rulesConverged(array $lines, string $chain, int $port): bool
    {
        return self::rulesMismatch($lines, $chain, $port) === '';
    }

    public static function rulesMismatch(array $lines, string $chain, int $port): string
    {
        $accept = '-A ' . $chain . ' -p udp -m udp --dport ' . $port . ' -j ACCEPT';
        $rules = array_values(array_filter($lines, static function ($line) use ($chain) {
            return strpos($line, '-A ' . $chain . ' ') === 0;
        }));
        $mismatches = [];
        if ($port === 0 && count($rules) !== 0) {
            $mismatches[] = 'service rules remain (' . count($rules) . ')';
        } elseif ($port !== 0 && $rules !== [$accept]) {
            $mismatches[] = count($rules) === 0 ? 'UDP ACCEPT missing'
                : 'service rules differ (rules=' . count($rules)
                    . ', exact ACCEPTs=' . count(array_keys($rules, $accept, true)) . ')';
        }
        foreach (array_merge(self::ZONES, ['reject', 'trusted']) as $zone) {
            $present = in_array('-A zone-' . $zone . ' -j ' . $chain, $lines, true);
            $required = $port !== 0 && in_array($zone, self::ZONES, true);
            if ($present !== $required) $mismatches[] = 'zone-' . $zone . ($required ? ' jump missing' : ' jump remains');
        }
        if ($port !== 0 && !$mismatches) {
            $path = self::publicPath($lines, $chain, 'INPUT', [], $port);
            if ($path !== 'verified') $mismatches[] = 'public INPUT path ' . $path;
        }
        return implode('; ', $mismatches);
    }

    /** Conservative supported-layout proof for NEW public UDP traffic.
     * Explicit source bans remain authoritative exclusions. Unknown classifiers
     * are not interpreted as permission. This is not a live packet probe.
     */
    public static function publicPath(array $lines, string $service, string $chain = 'INPUT', array $seen = [], int $port = 0, ?array $declared = null): string
    {
        if ($chain === $service) return 'verified';
        if ($declared === null) {
            $declared = [];
            foreach ($lines as $line) {
                if (preg_match('/^-(?:N|P) ([A-Za-z0-9_-]+)(?: |$)/', $line, $match)) $declared[$match[1]] = true;
                elseif (preg_match('/^-A ([A-Za-z0-9_-]+) /', $line, $match)) $declared[$match[1]] = true;
            }
        }
        if (!isset($declared[$chain])) {
            // A missing built-in INPUT declaration can occur while FreePBX
            // rebuilds filter tables. Other missing targets are not inferred
            // safe: they may be unsupported or malformed policy.
            return $chain === 'INPUT' ? 'unknown (undeclared chain INPUT)'
                : 'unknown (undeclared chain ' . $chain . ')';
        }
        if (in_array($chain, $seen, true) || count($seen) > 32) return 'unknown (cycle)';
        $seen[] = $chain;
        $hasRules = false;
        foreach ($lines as $line) {
            $prefix = '-A ' . $chain . ' ';
            if (strpos($line, $prefix) !== 0) continue;
            $hasRules = true;
            $rule = substr($line, strlen($prefix));
            if (preg_match('/^-p udp -m udp --dport ([0-9]+) -j ACCEPT$/D', $rule, $udp) && (int)$udp[1] !== $port) continue;
            // These rules cannot admit a new public WireGuard datagram.
            if (preg_match('/^-i lo(?: |$)/', $rule)
                || preg_match('/^-p (tcp|icmp|ipv6-icmp)(?: |$)/', $rule)
                || preg_match('/^.*--(?:ctstate|state) (?:RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED) -j ACCEPT$/', $rule)) continue;
            // An administrator's explicit source rejection is an exclusion from
            // permitted sources, never something this integration overrides.
            if (preg_match('/^-s (?:0\.0\.0\.0\/0|::\/0) -j (DROP|REJECT)(?: |$)/', $rule)) return 'blocked';
            if (preg_match('/^-s [0-9a-fA-F:.\/]+ -j (DROP|REJECT)(?: |$)/', $rule)) continue;
            if (!preg_match('/^-j ([A-Za-z0-9_-]+)$/D', $rule, $match)) return 'unknown (unsupported match)';
            $target = $match[1];
            if (in_array($target, ['DROP', 'REJECT'], true)) return 'blocked';
            if ($target === 'ACCEPT') return 'unknown (bypasses owned listener)';
            if ($target === 'RETURN') return 'return';
            $result = self::publicPath($lines, $service, $target, $seen, $port, $declared);
            if ($result !== 'return') return $result;
        }
        // An empty or not-yet-declared chain is characteristic of FreePBX's
        // asynchronous regeneration window; caller retries until its deadline.
        return $hasRules ? 'return' : 'unknown (empty declared chain ' . $chain . ')';
    }

    private static function service(string $id, int $port, string $name = self::NAME): array
    {
        return ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => 'udp', 'port' => (string)$port], 'custid' => $id, 'noreject' => true];
    }
}
