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

    /** Evaluate the filter rules for a NEW public unicast UDP listener packet.
     * Source- and interface-specific drops remain exclusions; unknown rules that
     * could permit traffic outside the owned service chain are never accepted.
     * This is a ruleset proof, not a live packet probe.
     */
    public static function publicPath(array $lines, string $service, string $chain = 'INPUT', array $seen = [], int $port = 0, ?array $declared = null): string
    {
        if ($port < 1 || $port > 65535) return 'unknown (invalid listener port)';
        if ($declared === null) {
            $declared = [];
            $policies = [];
            foreach ($lines as $line) {
                if (preg_match('/^-(?:N|P) ([A-Za-z0-9_-]+)(?: |$)/', $line, $match)) $declared[$match[1]] = true;
                elseif (preg_match('/^-A ([A-Za-z0-9_-]+) /', $line, $match)) $declared[$match[1]] = true;
                if (preg_match('/^-P ([A-Za-z0-9_-]+) (ACCEPT|DROP|REJECT)$/', $line, $match)) $policies[$match[1]] = $match[2];
            }
        } else {
            $policies = [];
            foreach ($lines as $line) {
                if (preg_match('/^-P ([A-Za-z0-9_-]+) (ACCEPT|DROP|REJECT)$/', $line, $match)) $policies[$match[1]] = $match[2];
            }
        }
        if (!isset($declared[$chain])) {
            return $chain === 'INPUT' ? 'unknown (undeclared chain INPUT)' : 'unknown (undeclared chain ' . $chain . ')';
        }
        $initialMark = ['value' => 0, 'known' => 0];
        $outcomes = self::evaluateChain($lines, $service, $chain, $port, $initialMark, [], $declared, $policies);
        foreach ($outcomes as $outcome) {
            if (str_starts_with($outcome, 'unknown-chain:')) {
                return 'unknown (undeclared chain ' . substr($outcome, strlen('unknown-chain:')) . ')';
            }
        }
        if (in_array('unknown', $outcomes, true)) return 'unknown (unsupported or ambiguous rule)';
        if (in_array('blocked', $outcomes, true)) return 'blocked';
        if (in_array('verified', $outcomes, true)) return 'verified';
        if (in_array('excluded', $outcomes, true)) return 'blocked';
        if (in_array('empty', $outcomes, true)) return 'unknown (empty declared chain ' . $chain . ')';
        return 'unknown (no verified listener path)';
    }

    /** @return string[] possible terminal outcomes for the packet classifier. */
    private static function evaluateChain(array $lines, string $service, string $chain, int $port, array $mark,
        array $stack, array $declared, array $policies): array
    {
        if ($chain === $service) return ['verified']; // The exact UDP ACCEPT is separately enforced by rulesMismatch().
        if (!isset($declared[$chain])) return ['unknown-chain:' . $chain];
        if (in_array($chain, $stack, true) || count($stack) >= 32) return ['unknown'];
        $stack[] = $chain;
        $rules = [];
        foreach ($lines as $line) {
            if (preg_match('/^-A ' . preg_quote($chain, '/') . ' (.+)$/', $line, $match)) $rules[] = $match[1];
        }
        if (!$rules) {
            if (isset($policies[$chain])) return [$policies[$chain] === 'DROP' || $policies[$chain] === 'REJECT' ? 'blocked' : 'unknown'];
            return count($stack) === 1 ? ['empty'] : ['return'];
        }
        return self::evaluateRules($lines, $service, $chain, $rules, 0, $port, $mark, $stack, $declared, $policies);
    }

    private static function evaluateRules(array $lines, string $service, string $chain, array $rules, int $index, int $port,
        array $mark, array $stack, array $declared, array $policies): array
    {
        if ($index >= count($rules)) {
            if (isset($policies[$chain])) return [$policies[$chain] === 'DROP' || $policies[$chain] === 'REJECT' ? 'blocked' : 'unknown'];
            return ['return'];
        }
        $parsed = self::parsePacketRule($rules[$index], $port, $mark);
        if ($parsed === null) return ['unknown'];
        $next = static function (array $nextMark) use ($lines, $service, $chain, $rules, $index, $port, $stack, $declared, $policies, $parsed) {
            if ($parsed['mark'] !== null) $nextMark = $parsed['mark'];
            return self::evaluateRules($lines, $service, $chain, $rules, $index + 1, $port, $nextMark, $stack, $declared, $policies);
        };
        $matched = static function (array $currentMark) use ($lines, $service, $chain, $rules, $index, $port, $stack, $declared, $policies, $parsed, $next) {
            $target = $parsed['target'];
            if ($target === 'RETURN') return ['return'];
            if ($target === 'ACCEPT') return ['unknown'];
            if ($target === 'DROP' || $target === 'REJECT') return ['blocked'];
            if ($target === 'MARK') {
                if ($parsed['mark'] === null) return ['unknown'];
                return $next($parsed['mark']);
            }
            if (!isset($declared[$target])) return ['unknown'];
            $results = self::evaluateChain($lines, $service, $target, $port, $currentMark, $stack, $declared, $policies);
            $outcomes = [];
            foreach ($results as $result) {
                if ($result === 'return' && $parsed['jump'] === '-j') {
                    $outcomes = array_merge($outcomes, $next($currentMark));
                } elseif ($result === 'return' && $parsed['jump'] === '-g') {
                    $outcomes[] = 'return';
                } else $outcomes[] = $result;
            }
            return array_values(array_unique($outcomes));
        };
        $condition = $parsed['condition'];
        if ($condition === false) return $next($mark);
        $onMatch = $matched($mark);
        if ($condition === true) return array_values(array_unique($onMatch));
        // Only known source/address/interface selectors may scope a block to a
        // subset of public packets. Unsupported predicates are never downgraded.
        if ($parsed['safeExclusion']) {
            $onMatch = array_map(static function ($outcome) {
                return $outcome === 'blocked' ? 'excluded' : $outcome;
            }, $onMatch);
        }
        return array_values(array_unique(array_merge($onMatch, $next($mark))));
    }

    /** Parse the supported iptables -S predicates for a new unicast UDP packet.
     * null means a malformed/unsupported rule; condition null means it may match.
     */
    private static function parsePacketRule(string $rule, int $port, array $mark): ?array
    {
        preg_match_all('/"(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\'|\\S+/', $rule, $matches);
        $tokens = array_map(static function ($token) {
            if (strlen($token) >= 2 && ($token[0] === '"' || $token[0] === "'")) return stripcslashes(substr($token, 1, -1));
            return $token;
        }, $matches[0]);
        $target = null;
        $jump = null;
        $conditions = [];
        $setMark = null;
        $unknown = false;
        $safeExclusion = true;
        $hasUncertainCondition = false;
        $negate = false;
        for ($i = 0; $i < count($tokens); ++$i) {
            $token = $tokens[$i];
            if ($token === '!') { $negate = true; continue; }
            if ($token === '-j' || $token === '--jump' || $token === '-g' || $token === '--goto') {
                if (!isset($tokens[$i + 1]) || $target !== null) return null;
                $jump = in_array($token, ['-g', '--goto'], true) ? '-g' : '-j';
                $target = $tokens[++$i];
                continue;
            }
            if (in_array($token, ['-m', '--match'], true)) {
                if (!isset($tokens[++$i])) return null;
                $module = $tokens[$i];
                if (!in_array($module, ['udp','tcp','icmp','icmp6','ipv6-icmp','multiport','comment','conntrack','state','pkttype','addrtype','mark','limit','hashlimit','recent','mac','physdev'], true)) $unknown = true;
                continue;
            }
            if (in_array($token, ['-p','--protocol','-s','--source','-d','--destination','-i','--in-interface','-o','--out-interface',
                '--dport','--dports','--destination-port','--sport','--sports','--source-port','--ports','--ctstate','--state',
                '--pkt-type','--mark','--dst-type','--src-type','--comment','--set-xmark','--set-mark','--and-mark','--or-mark','--xor-mark'], true)) {
                if (!isset($tokens[++$i])) return null;
                $value = $tokens[$i];
                $item = ['option' => $token, 'value' => $value, 'negate' => $negate];
                $negate = false;
                if (in_array($token, ['--set-xmark','--set-mark','--and-mark','--or-mark','--xor-mark'], true)) $setMark = $item;
                elseif ($token === '--comment') continue;
                else $conditions[] = $item;
                continue;
            }
            if (in_array($token, ['-f','--fragment'], true)) { $conditions[] = ['option' => $token, 'value' => '', 'negate' => $negate]; $negate = false; continue; }
            // Rule counters and comments do not change packet selection; unknown extensions/options do.
            if (in_array($token, ['-c','--set-counters'], true)) { $i += 2; continue; }
            if (str_starts_with($token, '--comment=')) continue;
            $unknown = true;
        }
        if ($target === null || $negate) return null;
        $result = $unknown ? null : true;
        $markBeforeRule = $mark;
        $markConditionsMatch = true;
        foreach ($conditions as $condition) {
            $value = self::packetCondition($condition['option'], $condition['value'], $port, $mark);
            if ($condition['negate']) $value = $value === null ? null : !$value;
            if ($condition['option'] === '--mark' && $value !== true) $markConditionsMatch = false;
            if ($value === false) { $result = false; break; }
            if ($value === null) {
                $result = null;
                $hasUncertainCondition = true;
                $addressSelector = !$condition['negate'] && in_array($condition['option'], ['-s','--source'], true)
                    && self::selectorNarrowsPublicRange($condition['value']);
                if (!$addressSelector) $safeExclusion = false;
            }
        }
        if ($unknown || !$hasUncertainCondition || $result === false) $safeExclusion = false;
        $newMark = null;
        if ($setMark !== null && !$unknown && $markConditionsMatch) {
            $newMark = self::applyMark($markBeforeRule, $setMark['option'], $setMark['value']);
        }
        return ['target' => $target, 'condition' => $result, 'mark' => $newMark,
            'jump' => $jump ?? '-j', 'unsupported' => $unknown, 'safeExclusion' => $safeExclusion];
    }

    private static function packetCondition(string $option, string $value, int $port, array $mark): ?bool
    {
        if ($option === '-p' || $option === '--protocol') {
            if (in_array(strtolower($value), ['udp','17'], true)) return true;
            if (strtolower($value) === 'all') return true;
            if (in_array(strtolower($value), ['tcp','6','icmp','1','icmpv6','icmp6','ipv6-icmp','58'], true)) return false;
            return null;
        }
        if (in_array($option, ['--dport','--dports','--destination-port'], true)) return self::portMatches($value, $port);
        if (in_array($option, ['--sport','--sports','--source-port'], true)) return null;
        if ($option === '--ports') return null;
        if ($option === '-i' || $option === '--in-interface') {
            if (in_array($value, ['lo','tlp-admin'], true)) return false;
            return null;
        }
        if ($option === '-o' || $option === '--out-interface') return null;
        if ($option === '-d' || $option === '--destination') return self::addressCouldBePublicUnicast($value);
        if ($option === '-s' || $option === '--source') return self::sourceCouldMatchPublic($value);
        if ($option === '--pkt-type') {
            if (in_array(strtolower($value), ['broadcast','multicast'], true)) return false;
            if (strtolower($value) === 'unicast') return true;
            return null;
        }
        if ($option === '--dst-type') {
            if (strtoupper($value) === 'BROADCAST') return null;
            if (strtoupper($value) === 'MULTICAST') return false;
            if (strtoupper($value) === 'UNICAST') return true;
            if (strtoupper($value) === 'LOCAL') return null;
            return null;
        }
        if ($option === '--src-type') {
            if (in_array(strtoupper($value), ['BROADCAST','MULTICAST'], true)) return null;
            return null;
        }
        if ($option === '--ctstate' || $option === '--state') {
            $states = array_map('strtoupper', explode(',', $value));
            if (in_array('NEW', $states, true)) return true;
            return in_array('ESTABLISHED', $states, true) || in_array('RELATED', $states, true) ? null : false;
        }
        if ($option === '--mark') {
            if (!preg_match('/^(0x[0-9a-f]+|[0-9]+)(?:\/(0x[0-9a-f]+|[0-9]+))?$/i', $value, $match)) return null;
            $wanted = intval($match[1], 0);
            $mask = isset($match[2]) ? intval($match[2], 0) : 0xffffffff;
            if (($mark['known'] & $mask) !== $mask) return null;
            return ($mark['value'] & $mask) === ($wanted & $mask);
        }
        if ($option === '-f' || $option === '--fragment') return false;
        if ($option === '--comment') return true;
        return null;
    }

    private static function portMatches(string $expression, int $port): ?bool
    {
        foreach (explode(',', $expression) as $part) {
            if (preg_match('/^(\d+)(?::(\d*))?$/', $part, $match)) {
                $low = (int)$match[1];
                $high = isset($match[2]) && $match[2] !== '' ? (int)$match[2] : $low;
                if ($port >= min($low, $high) && $port <= max($low, $high)) return true;
            } elseif (preg_match('/^:(\d+)$/', $part, $match)) {
                if ($port <= (int)$match[1]) return true;
            } else return null;
        }
        return false;
    }

    private static function addressCouldBePublicUnicast(string $expression): ?bool
    {
        return self::addressRangeCouldMatch($expression, true);
    }

    private static function sourceCouldMatchPublic(string $expression): ?bool
    {
        $parts = explode('/', $expression, 2);
        if (!isset($parts[1]) || !ctype_digit($parts[1])) return null;
        $bits = filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 32
            : (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 128 : 0);
        if ($bits === 0 || (int)$parts[1] > $bits) return null;
        return (int)$parts[1] === 0 ? true : null;
    }

    private static function addressRangeCouldMatch(string $expression, bool $destination): ?bool
    {
        $parts = explode('/', $expression, 2);
        $address = $parts[0];
        $ipv4 = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $ipv6 = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if (!$ipv4 && !$ipv6) return null;
        $bits = $ipv4 ? 32 : 128;
        if (isset($parts[1]) && (!ctype_digit($parts[1]) || (int)$parts[1] > $bits)) return null;
        $prefix = isset($parts[1]) ? (int)$parts[1] : $bits;
        if ($prefix === 0) return true;
        if ($ipv4) {
            $number = ip2long($address);
            if ($number === false) return null;
            $number = (int)sprintf('%u', $number);
            $mask = $prefix === 0 ? 0 : ((0xffffffff << (32 - $prefix)) & 0xffffffff);
            $network = $number & $mask;
            $end = $network | (~$mask & 0xffffffff);
            if ($destination) {
                // Exclude a range proven entirely multicast/broadcast; partial
                // overlap is ambiguous because the rule can match both classes.
                if ($network >= 0xe0000000 && $end <= 0xefffffff) return false;
                if ($network <= 0xefffffff && $end >= 0xe0000000) return null;
                if ($network === 0xffffffff && $end === 0xffffffff) return false;
                if ($end === 0xffffffff) return null;
                if ($network === 0) return null; // 0.0.0.0 is not a unicast host destination.
            }
            return true;
        }
        $packed = inet_pton($address);
        if ($packed === false) return null;
        if ($destination && $prefix < 8) return null;
        if ($destination && ord($packed[0]) === 0xff) return false;
        return true;
    }

    private static function selectorNarrowsPublicRange(string $expression): bool
    {
        $parts = explode('/', $expression, 2);
        if (filter_var($parts[0], FILTER_VALIDATE_IP) === false) return false;
        if (!isset($parts[1])) return true;
        if (!ctype_digit($parts[1])) return false;
        $bits = filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 32 : 128;
        $prefix = (int)$parts[1];
        return $prefix > 0 && $prefix <= $bits;
    }

    private static function applyMark(array $current, string $operation, string $expression): ?array
    {
        if (!preg_match('/^(0x[0-9a-f]+|[0-9]+)(?:\/(0x[0-9a-f]+|[0-9]+))?$/i', $expression, $match)) return null;
        $value = intval($match[1], 0);
        $mask = isset($match[2]) ? intval($match[2], 0) : 0xffffffff;
        $known = $current['known'];
        $bits = $current['value'];
        if ($operation === '--set-xmark' || $operation === '--set-mark') {
            return ['value' => ($bits & (~$mask)) | ($value & $mask), 'known' => ($known & (~$mask)) | $mask];
        }
        if ($operation === '--and-mark') {
            $knownZero = (~$value) & 0xffffffff;
            return ['value' => $bits & $value, 'known' => ($known & $value) | $knownZero];
        }
        if ($operation === '--or-mark') {
            return ['value' => $bits | $value, 'known' => $known | $value];
        }
        if ($operation === '--xor-mark') return ['value' => $bits ^ $value, 'known' => $known];
        return null;
    }

    private static function service(string $id, int $port, string $name = self::NAME): array
    {
        return ['name' => $name, 'defzones' => ['internal'], 'descr' => 'Custom Service',
            'custfw' => ['protocol' => 'udp', 'port' => (string)$port], 'custid' => $id, 'noreject' => true];
    }
}
