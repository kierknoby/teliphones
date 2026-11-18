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
                    self::verifyIpv6Rules($id, $port, $deadline);
                }
            }
            if ($verify === null) {
                // One final joint snapshot: earlier per-service success is not a
                // guarantee that the same service still exists at completion.
                $snapshots = [];
                foreach (['/sbin/iptables', '/sbin/ip6tables'] as $binary) {
                    $lines = [];
                    exec(escapeshellarg($binary) . ' -w 1 -t filter -S 2>&1', $lines, $result);
                    $family = strpos($binary, 'ip6tables') !== false ? 'IPV6' : 'IPV4';
                    if ($result !== 0) throw new \RuntimeException('TLP-LISTENER-' . $family
                        . '-FINAL: Cannot verify both public address families.');
                    foreach ($pending as $id => $port) {
                        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
                        $mismatch = self::rulesMismatch($lines, $chain, $port);
                        if ($mismatch !== '' && !($family === 'IPV6'
                                && self::ipv6ListenerFailsClosed($lines, $chain, $port))) throw new \RuntimeException('TLP-LISTENER-' . $family
                            . '-FINAL: Final listener path verification failed: ' . $mismatch);
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

    /**
     * Store a deliberately small, root-only failure record.  This is separate
     * from ownership state: pairing rollback may remove an interface or a
     * service, but must never erase the evidence of why admission failed.
     * No command output, addresses, keys, or firewall rules are retained.
     */
    public static function recordFailure(string $stateFile, $ports, \Throwable $error): array
    {
        $message = $error->getMessage();
        $stage = 'listener-reconciliation';
        $identifier = 'listener-unexpected-failure';
        if (strpos($message, 'ROOT-HELPER-MISMATCH') !== false) {
            $stage = 'root-helper-validation'; $identifier = 'root-helper-version-mismatch';
        } elseif (strpos($message, 'Invalid TELIPHONES WireGuard listener port') !== false) {
            $stage = 'input-validation'; $identifier = 'listener-input-invalid';
        } elseif (strpos($message, 'lock TELIPHONES listener ownership') !== false
                  || strpos($message, 'ownership state') !== false
                  || strpos($message, 'ownership transaction') !== false
                  || strpos($message, 'persist TELIPHONES listener ownership') !== false) {
            $stage = 'listener-ownership-state'; $identifier = 'listener-ownership-state-failed';
        } elseif (strpos($message, 'inventory FreePBX custom services') !== false) {
            $stage = 'custom-service-inventory'; $identifier = 'firewall-inventory-failure';
        } elseif (strpos($message, 'Conflicting TELIPHONES') !== false
                  || strpos($message, 'Duplicate TELIPHONES') !== false) {
            $stage = 'custom-service-ownership'; $identifier = 'listener-service-ownership-conflict';
        } elseif (strpos($message, 'did not save a TELIPHONES') !== false) {
            $stage = 'custom-service-creation'; $identifier = 'listener-service-creation-failed';
        } elseif (strpos($message, 'service configuration could not be verified') !== false) {
            $stage = 'custom-service-zone-assignment'; $identifier = 'listener-service-configuration-failed';
        } elseif (strpos($message, 'service removal could not be verified') !== false) {
            $stage = 'custom-service-removal'; $identifier = 'listener-service-removal-failed';
        } elseif (strpos($message, 'IPV4') !== false) {
            $stage = strpos($message, 'FINAL') !== false ? 'final-ipv4-verification' : 'ipv4-rule-generation';
            $identifier = strpos($message, 'PENDING') !== false ? 'firewall-regeneration-in-progress'
                : (strpos($message, 'BLOCKED-PATH') !== false ? 'listener-firewall-path-blocked'
                : (strpos($message, 'UNSAFE-INTEGRATION') !== false ? 'listener-firewall-path-unverified' : 'listener-ipv4-verification-failed'));
        } elseif (strpos($message, 'IPV6') !== false) {
            $stage = strpos($message, 'FINAL') !== false ? 'final-ipv6-verification' : 'ipv6-rule-generation';
            $identifier = strpos($message, 'PENDING') !== false ? 'firewall-regeneration-in-progress'
                : (strpos($message, 'BLOCKED-PATH') !== false ? 'listener-firewall-path-blocked'
                : (strpos($message, 'UNSAFE-INTEGRATION') !== false ? 'listener-firewall-path-unverified' : 'listener-ipv6-verification-failed'));
        } elseif (strpos($message, 'TLP-LISTENER-BLOCKED-PATH') !== false) {
            $stage = 'firewall-path-verification'; $identifier = 'listener-firewall-path-blocked';
        } elseif (strpos($message, 'TLP-LISTENER-UNSAFE-INTEGRATION') !== false) {
            $stage = 'firewall-path-verification'; $identifier = 'listener-firewall-path-unverified';
        } elseif (strpos($message, 'both public address families') !== false) {
            $stage = 'final-family-verification'; $identifier = 'listener-family-inspection-failed';
        }
        $values = is_array($ports) ? $ports : [$ports];
        $operation = count($values) === 1 && (int)$values[0] === 0 ? 'removal' : 'admission';
        $record = ['version' => 1, 'at' => time(), 'operation' => $operation,
                   'stage' => $stage, 'identifier' => $identifier];
        self::writeDiagnostic($stateFile, $record);
        return $record;
    }

    public static function lastDiagnostic(string $stateFile): ?array
    {
        $path = dirname($stateFile) . '/firewall-listener-diagnostic.json';
        try {
            $record = json_decode((string)file_get_contents($path), true, 8, JSON_THROW_ON_ERROR);
            if (!is_array($record)
                || !preg_match('/^[a-z0-9-]{3,80}$/D', (string)($record['identifier'] ?? ''))
                || !preg_match('/^[a-z0-9-]{3,80}$/D', (string)($record['stage'] ?? ''))
                || !in_array($record['operation'] ?? null, ['admission', 'removal'], true)) return null;
            return $record;
        } catch (\Throwable $ignored) {
            return null;
        }
    }

    private static function writeDiagnostic(string $stateFile, array $record): void
    {
        $directory = dirname($stateFile);
        $path = $directory . '/firewall-listener-diagnostic.json';
        try {
            if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) return;
            $temporary = tempnam($directory, '.listener-diagnostic-');
            if ($temporary === false) return;
            try {
                if (!chmod($temporary, 0600)
                    || file_put_contents($temporary, json_encode($record, JSON_THROW_ON_ERROR)) === false) return;
                $handle = fopen($temporary, 'r+');
                if ($handle === false) return;
                try { if (!fsync($handle)) return; } finally { fclose($handle); }
                rename($temporary, $path);
            } finally {
                if (isset($temporary) && is_file($temporary)) unlink($temporary);
            }
        } catch (\Throwable $ignored) {
            // Diagnostics are evidence only; they must never weaken fail-closed admission.
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
        do {
            $lines = [];
            exec(escapeshellarg($iptables) . ' -w 1 -t filter -S 2>&1', $lines, $result);
            if ($result !== 0) throw new \RuntimeException('TLP-LISTENER-' .
                (strpos($iptables, 'ip6tables') !== false ? 'IPV6' : 'IPV4') . '-INSPECTION: Cannot inspect FreePBX generated listener rules.');
            $mismatch = self::rulesMismatch($lines, $chain, $port);
            if ($mismatch === '') return;
            // Generated service rules arrive asynchronously.  Only reject a
            // completed-looking service when the surrounding FreePBX hook is
            // demonstrably unsafe; missing generated links remain retryable.
            $integration = $port === 0 ? 'verified' : self::listenerIntegration($lines, $port, [], $chain);
            if ($integration === 'blocked' || $integration === 'unsafe') {
                throw new \RuntimeException('TLP-LISTENER-' . (strpos($iptables, 'ip6tables') !== false ? 'IPV6-' : 'IPV4-')
                    . ($integration === 'blocked' ? 'BLOCKED-PATH' : 'UNSAFE-INTEGRATION')
                    . ': FreePBX listener integration is ' . $integration . '; no effective integration is claimed.');
            }
            if (hrtime(true) / 1e9 >= $deadline) break;
            usleep(500000);
        } while (true);
        throw new \RuntimeException('TLP-LISTENER-' . (strpos($iptables, 'ip6tables') !== false ? 'IPV6' : 'IPV4') . '-PENDING: '
            . 'FreePBX generated listener rules have not converged; reconciliation will retry. '
            . $chain . ' ' . ($port === 0 ? 'removal' : 'UDP ' . $port) . ': '
            . self::rulesMismatch($lines, $chain, $port));
    }

    /**
     * FreePBX 17 can generate a Custom Service only in its IPv4 ruleset.
     * That must not make an IPv4 WireGuard pairing depend on an IPv6 ACCEPT
     * which will never arrive.  Accept the absence only when the inspected
     * IPv6 path is demonstrably closed for this UDP port; otherwise retain the
     * normal generated-rule requirement and fail closed.
     */
    private static function verifyIpv6Rules(string $id, int $port, float $deadline): void
    {
        $chain = 'fpbxsvc-' . substr(str_replace('-', '', $id), 0, 16);
        do {
            $lines = [];
            exec(escapeshellarg('/sbin/ip6tables') . ' -w 1 -t filter -S 2>&1', $lines, $result);
            if ($result !== 0) throw new \RuntimeException('TLP-LISTENER-IPV6-INSPECTION: Cannot inspect FreePBX generated listener rules.');
            $mismatch = self::rulesMismatch($lines, $chain, $port);
            if ($mismatch === '' || self::ipv6ListenerFailsClosed($lines, $chain, $port)) return;
            $integration = $port === 0 ? 'verified' : self::listenerIntegration($lines, $port, [], $chain);
            if ($integration === 'blocked' || $integration === 'unsafe') {
                throw new \RuntimeException('TLP-LISTENER-IPV6-' . ($integration === 'blocked' ? 'BLOCKED-PATH' : 'UNSAFE-INTEGRATION')
                    . ': FreePBX listener integration is ' . $integration . '; no effective integration is claimed.');
            }
            if (hrtime(true) / 1e9 >= $deadline) break;
            usleep(500000);
        } while (true);
        throw new \RuntimeException('TLP-LISTENER-IPV6-PENDING: FreePBX generated listener rules have not converged; reconciliation will retry. '
            . $chain . ' UDP ' . $port . ': ' . self::rulesMismatch($lines, $chain, $port));
    }

    /**
     * A missing IPv6 service is safe only for the narrow layout below: there
     * is no generated permit for this service, the supported INPUT traversal
     * falls through, and the INPUT policy is DROP.  Any broad ACCEPT, explicit
     * block, unsupported matcher, or non-DROP policy remains unverified.
     */
    private static function ipv6ListenerFailsClosed(array $lines, string $chain, int $port): bool
    {
        if ($port === 0) return false;
        foreach ($lines as $line) {
            if (strpos($line, '-A ' . $chain . ' ') === 0
                || preg_match('/^-A [^ ]+ (?:-i [^ ]+ )?-j ' . preg_quote($chain, '/') . '$/D', $line)) {
                return false;
            }
        }
        if (!in_array('-P INPUT DROP', $lines, true)) return false;
        return self::ipv6UnicastHasNoAccept($lines, 'INPUT', $port);
    }

    /**
     * With the IPv6 INPUT policy verified as DROP and no generated service
     * chain/jump, prove there is no earlier rule that can ACCEPT a new unicast
     * WireGuard datagram. Known non-matching IPv6 traffic (ICMPv6, loopback,
     * established-only, multicast/broadcast and other UDP ports) is ignored.
     * Interface dispatch is traversed as a possible branch. Unknown ACCEPTs
    * and unknown ACCEPT paths fail closed; a missing IPv6 service alone does
     * not make a verified IPv4 service depend on IPv6 rule generation.
     */
    private static function ipv6UnicastHasNoAccept(array $lines, string $chain, int $port, array $seen = []): bool
    {
        if (in_array($chain, $seen, true) || count($seen) > 32) return false;
        $seen[] = $chain;
        foreach ($lines as $line) {
            $prefix = '-A ' . $chain . ' ';
            if (strpos($line, $prefix) !== 0) continue;
            $rule = substr($line, strlen($prefix));
            // A terminal deny cannot expose IPv6, regardless of whether its
            // selector uses an extension we otherwise do not need to parse.
            if (preg_match('/(?:^| )-j (DROP|REJECT)(?: .*)?$/D', $rule)) continue;
            if (preg_match('/(?:^| )-i lo(?: |$)/', $rule)) continue;
            if (preg_match('/(?:^| )-p ([^ ]+)(?: |$)/', $rule, $protocol) && $protocol[1] !== 'udp') continue;
            if (preg_match('/(?:^| )--(?:dport|dports|destination-port) ([^ ]+)(?: |$)/', $rule, $destination)) {
                $matches = self::portInSpecification($destination[1], $port);
                if ($matches === false) continue;
                if ($matches === null) return false;
            }
            if (preg_match('/(?:^| )--(?:ctstate|state) ([^ ]+)(?: |$)/', $rule, $state)
                && preg_match('/^(?:RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED)$/D', $state[1])) continue;
            if (preg_match('/(?:^| )--pkt-type (multicast|broadcast)(?: |$)/', $rule)) continue;
            if (preg_match('/(?:^| )--dst-type (MULTICAST|BROADCAST)(?: |$)/i', $rule)) continue;

            // A comment match changes no packet selection and is common in
            // FreePBX-generated rules; strip only that metadata before parsing.
            $rule = preg_replace('/(?:^| )-m comment --comment (?:"[^"]*"|[^ ]+)/', '', $rule);
            if (!preg_match('/(?:^| )-j ([A-Za-z0-9_-]+)(?: |$)/', trim($rule), $targetMatch)) {
                return false;
            }
            $target = $targetMatch[1];
            if (in_array($target, ['ACCEPT'], true)) return false;
            // These targets do not terminate packet traversal. Their match
            // predicates may be opaque without creating an IPv6 admission.
            if (in_array($target, ['LOG', 'NFLOG', 'ULOG', 'TRACE', 'MARK', 'CONNMARK', 'SECMARK', 'CLASSIFY'], true)) continue;
            if ($target === 'RETURN') continue;
            if (!self::ipv6UnicastHasNoAccept($lines, $target, $port, $seen)) return false;
        }
        // Falling off a user chain returns to the caller; falling off INPUT
        // reaches the already-checked DROP policy.
        return true;
    }

    public static function rulesConverged(array $lines, string $chain, int $port, array $publicInterfaces = []): bool
    {
        return self::rulesMismatch($lines, $chain, $port, $publicInterfaces) === '';
    }

    public static function rulesMismatch(array $lines, string $chain, int $port, array $publicInterfaces = []): string
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
            $integration = self::listenerIntegration($lines, $port, $publicInterfaces, $chain);
            if ($integration !== 'verified') $mismatches[] = 'FreePBX listener integration ' . $integration;
        }
        return implode('; ', $mismatches);
    }

    /** Conservative supported-layout proof for NEW public UDP traffic.
     * Explicit source bans remain authoritative exclusions. Unknown classifiers
     * are not interpreted as permission. This is not a live packet probe.
     */
    public static function publicPath(array $lines, string $service, string $chain = 'INPUT', array $seen = [], int $port = 0): string
    {
        if ($chain === $service) return 'verified';
        if (in_array($chain, $seen, true) || count($seen) > 32) return 'unknown (cycle)';
        $seen[] = $chain;
        foreach ($lines as $line) {
            $prefix = '-A ' . $chain . ' ';
            if (strpos($line, $prefix) !== 0) continue;
            $rule = substr($line, strlen($prefix));
            if (preg_match('/^-p udp -m udp --dport ([0-9]+) -j ACCEPT$/D', $rule, $udp) && (int)$udp[1] !== $port) continue;
            // These rules cannot admit a new public WireGuard datagram.
            if (preg_match('/^-i lo(?: |$)/', $rule)
                || preg_match('/^-p (tcp|icmp|ipv6-icmp)(?: |$)/', $rule)
                || preg_match('/^.*--(?:ctstate|state) (?:RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED) -j ACCEPT$/', $rule)) continue;
            // An administrator's explicit source rejection is an exclusion from
            // permitted sources, never something this integration overrides.
            if (preg_match('/^-s (?:0\.0\.0\.0\/0|::\/0)(?: .* )?-j (DROP|REJECT)(?: |$)/', $rule)) return 'blocked';
            if (preg_match('/^-s [0-9a-fA-F:.\/]+(?: .* )?-j (DROP|REJECT)(?: |$)/', $rule)) continue;
            // FreePBX 17 dispatches the firewall zone through an interface
            // selector.  It is a supported structural route, not a permit by
            // itself; continue into its target so a missing service can fall
            // through to the INPUT DROP policy below.
            if (!preg_match('/^(?:-i [A-Za-z0-9_.:-]+ )?-j ([A-Za-z0-9_-]+)$/D', $rule, $match)) return 'unknown (unsupported match)';
            $target = $match[1];
            if (in_array($target, ['DROP', 'REJECT'], true)) return 'blocked';
            if ($target === 'ACCEPT') return 'unknown (bypasses owned listener)';
            if ($target === 'RETURN') return 'return';
            // This exception belongs only to the FreePBX zone-chain proof.
            // Exact packet-type multicast/broadcast ACCEPTs cannot match a
            // new unicast WireGuard packet; all other predicates stay unknown.
            if (in_array($target, ['zone-external', 'zone-internal', 'zone-other'], true)) {
                $result = self::freepbxZonePath($lines, $service, $target, $seen, $port);
                if ($result !== 'return') return $result;
                continue;
            }
            $result = self::publicPath($lines, $service, $target, $seen, $port);
            if ($result !== 'return') return $result;
        }
        return 'return';
    }

    private static function freepbxZonePath(array $lines, string $service, string $chain, array $seen, int $port): string
    {
        if ($chain === $service) return 'verified';
        if (in_array($chain, $seen, true) || count($seen) > 32) return 'unknown (cycle)';
        $seen[] = $chain;
        foreach ($lines as $line) {
            $prefix = '-A ' . $chain . ' ';
            if (strpos($line, $prefix) !== 0) continue;
            $rule = substr($line, strlen($prefix));
            if (preg_match('/^(?:-i [A-Za-z0-9_.:-]+ )?-m pkttype --pkt-type (?:multicast|broadcast) -j ACCEPT$/D', $rule)) continue;
            if (preg_match('/^-p udp -m udp --dport ([0-9]+) -j ACCEPT$/D', $rule, $udp) && (int)$udp[1] !== $port) continue;
            if (!preg_match('/^(?:-i [A-Za-z0-9_.:-]+ )?-j ([A-Za-z0-9_-]+)$/D', $rule, $match)) {
                return 'unknown (unsupported match)';
            }
            $target = $match[1];
            if (in_array($target, ['DROP', 'REJECT'], true)) return 'blocked';
            if ($target === 'ACCEPT') return 'unknown (bypasses owned listener)';
            if ($target === 'RETURN') return 'return';
            $result = self::freepbxZonePath($lines, $service, $target, $seen, $port);
            if ($result !== 'return') return $result;
        }
        return 'return';
    }

    /**
     * A deliberately narrow generated-service integration check.  FreePBX
     * owns packet policy: TELIPHONES verifies that its generated service is
     * reachable through INPUT and the external zone, while refusing obvious
     * broad blocks or unowned ACCEPTs.  This is not a firewall interpreter.
     */
    private static function listenerIntegration(array $lines, int $port, array $publicInterfaces = [], string $chain = ''): string
    {
        // This is intentionally a verifier for two documented FreePBX layouts,
        // not a general iptables evaluator.  It proves generated integration,
        // never arbitrary packet-path reachability.
        $inputRules = [];
        $sawInputHook = false;
        foreach ($lines as $line) {
            if (!preg_match('/^-A INPUT (.*)$/D', $line, $match)) continue;
            if (preg_match('/^(?:-i ([A-Za-z0-9_.:-]+) )?-j fpbxfirewall$/D', $match[1], $jump)) {
                $sawInputHook = true;
                $inputRules[$jump[1] ?? ''] = true;
                continue;
            }
            if ($sawInputHook) continue;
            $outcome = self::precedingRuleOutcome($lines, $match[1], $port, $publicInterfaces);
            if ($outcome !== 'irrelevant' && $outcome !== 'excluded') return $outcome;
        }
        if (!$inputRules) return 'pending';
        if ($publicInterfaces && !isset($inputRules[''])) {
            foreach ($publicInterfaces as $interface) {
                if (!isset($inputRules[$interface])) {
                    return 'unverified (public interface ' . $interface . ' has no INPUT jump to fpbxfirewall)';
                }
            }
        }

        // FreePBX 17 normally dispatches by interface.  Older supported
        // installations jump straight from fpbxfirewall to zone-external.
        $interfaces = [];
        $allInterfaces = false;
        $legacyExternal = false;
        foreach ($lines as $line) {
            if ($line === '-A fpbxfirewall -j zone-external') $legacyExternal = true;
            if ($line === '-A fpbxfirewall -j fpbxinterfaces') {
                foreach ($lines as $route) {
                    if ($route === '-A fpbxinterfaces -j zone-external') $allInterfaces = true;
                    if (preg_match('/^-A fpbxinterfaces -i ([A-Za-z0-9_.:-]+) -j zone-external$/D', $route, $match)) {
                        $interfaces[$match[1]] = true;
                    }
                }
            }
        }
        if (!$legacyExternal && !$allInterfaces && !$interfaces) return 'pending';
        foreach ($publicInterfaces as $interface) {
            if (!$allInterfaces && !$legacyExternal && !isset($interfaces[$interface])) {
                return 'unverified (public interface ' . $interface . ' is not routed to zone-external)';
            }
        }
        // A zone jump is only useful if its rules reach the owned service
        // jump. A prior terminal DROP/REJECT in zone-external makes the
        // structurally present generated ACCEPT unreachable for matching UDP.
        if ($chain !== '') {
            $zoneServiceJump = '-A zone-external -j ' . $chain;
            $reachedService = false;
            foreach ($lines as $line) {
                if (strpos($line, '-A zone-external ') !== 0) continue;
                if ($line === $zoneServiceJump) { $reachedService = true; break; }
                $outcome = self::precedingRuleOutcome($lines,
                    substr($line, strlen('-A zone-external ')), $port, $publicInterfaces);
                if (in_array($outcome, ['return', 'irrelevant', 'excluded'], true)) continue;
                return $outcome;
            }
            if (!$reachedService && in_array($zoneServiceJump, $lines, true)) return 'unverified (external zone service jump is unreachable)';
        }
        // Without caller-supplied public-interface knowledge, this establishes
        // only that FreePBX owns at least one external ingress route.
        return 'verified';
    }

    /** Classify only a preceding terminal rule relevant to a new UDP datagram. */
    private static function precedingRuleOutcome(array $lines, string $rule, int $port, array $publicInterfaces, array $seen = []): string
    {
        if (preg_match('/(?:^| )-i ([^ ]+)(?: |$)/', $rule, $interface)) {
            if ($interface[1] === 'lo') return 'irrelevant';
            if ($publicInterfaces && !in_array($interface[1], $publicInterfaces, true)) return 'irrelevant';
            if (!$publicInterfaces) return 'unverified (interface-specific preceding rule without public interface knowledge)';
        }
        if (preg_match('/(?:^| )-p ([^ ]+)(?: |$)/', $rule, $protocol)
            && $protocol[1] !== 'udp') return 'irrelevant';
        if (preg_match('/--(?:dport|dports|destination-port) ([^ ]+)(?: |$)/', $rule, $destination)) {
            $matches = self::portInSpecification($destination[1], $port);
            if ($matches === null) return 'unverified (unsupported destination-port specification)';
            if (!$matches) return 'irrelevant';
        }
        if (preg_match('/--(?:state|ctstate) ([^ ]+)(?: |$)/', $rule, $state)
            && strpos($state[1], 'NEW') === false) return 'irrelevant';
        if (preg_match('/(?:^| )-s ([^ ]+)(?: |$)/', $rule, $source)
            && !in_array($source[1], ['0.0.0.0/0', '::/0'], true)) {
            if (self::isBroadSourceRestriction($source[1])) return 'unverified (broad source restriction)';
            return 'excluded';
        }
        if (preg_match('/-j (DROP|REJECT)$/D', $rule)) return 'blocked';
        if (preg_match('/-j ACCEPT$/D', $rule)) return 'unsafe';
        if (!preg_match('/^-j ([A-Za-z0-9_-]+)$/D', $rule, $jump)) return 'unverified (unsupported preceding INPUT rule)';
        $chain = $jump[1];
        if ($chain === 'RETURN') return 'return';
        if ($chain === 'fpbxfirewall') return 'irrelevant';
        if (in_array($chain, $seen, true) || count($seen) >= 4) return 'unverified (preceding chain cycle)';
        $seen[] = $chain;
        $matched = false;
        foreach ($lines as $line) {
            $prefix = '-A ' . $chain . ' ';
            if (strpos($line, $prefix) !== 0) continue;
            $matched = true;
            $outcome = self::precedingRuleOutcome($lines, substr($line, strlen($prefix)), $port, $publicInterfaces, $seen);
            if ($outcome === 'return') return 'irrelevant';
            if ($outcome !== 'irrelevant' && $outcome !== 'excluded') return $outcome;
        }
        // Falling off a user-defined chain returns to its caller. If every
        // rule was unrelated or source-excluded, that is a verified fallthrough.
        return $matched ? 'return' : 'unverified (unknown preceding chain)';
    }

    /** @return bool|null true/false for a supported iptables single/list/range port specification. */
    private static function portInSpecification(string $specification, int $port): ?bool
    {
        foreach (explode(',', $specification) as $part) {
            if (preg_match('/^([0-9]+)$/D', $part, $match)) {
                if ((int) $match[1] === $port) return true;
                continue;
            }
            if (preg_match('/^([0-9]+):([0-9]+)$/D', $part, $match)) {
                if ((int) $match[1] > (int) $match[2]) return null;
                if ($port >= (int) $match[1] && $port <= (int) $match[2]) return true;
                continue;
            }
            return null;
        }
        return false;
    }

    private static function isBroadSourceRestriction(string $source): bool
    {
        if (preg_match('/^([0-9.]+)\/([0-9]+)$/D', $source, $match)) return (int) $match[2] < 24;
        if (preg_match('/^[0-9a-fA-F:]+\/([0-9]+)$/D', $source, $match)) return (int) $match[1] < 64;
        return false;
    }

    private static function service(string $id, int $port, string $name = self::NAME): array
    {
        return ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => 'udp', 'port' => (string)$port], 'custid' => $id, 'noreject' => true];
    }
}
