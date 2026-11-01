<?php
namespace FreePBX\modules\Teliphones;

class CheckerEvidence
{
    private const KEY_FILE = '/etc/teliphones/checker-ecdsa-p256.pub';
    private const FILE_NAME = 'checker.json';
    private const CHALLENGE_NAME = 'checker-challenge.json';

    private string $directory;
    private ?string $trustedPublicKey;

    public function __construct(string $directory = '/var/lib/teliphones', ?string $trustedPublicKey = null)
    {
        $this->directory = rtrim($directory, '/');
        $this->trustedPublicKey = $trustedPublicKey;
    }

    public function challenge(array $session): array
    {
        $challenge = [
            'protocol' => 'teliphones-checker/1',
            'session_id' => $session['session_id'],
            'topology' => $session['topology'],
            'nonce' => bin2hex(random_bytes(24)),
            'issued_at' => time(),
            'expires_at' => min((int)$session['expires_at'], time() + 300),
            'policy' => [
                'authorised_source' => 'required',
                'negative_control' => 'required',
                'public_support_access' => 'forbidden',
            ],
        ];

        if (!$this->write($this->evidencePath(), []) || !$this->write($this->challengePath(), $challenge)) {
            throw new \RuntimeException('Unable to persist the Checker challenge.');
        }

        return $challenge;
    }

    public function accept(array $session, array $evidence): array
    {
        $challenge = $this->read($this->challengePath());
        $errors = [];
        $now = time();

        if (!$challenge) {
            $errors[] = 'checker-required';
        }
        if ($challenge && !empty($challenge['consumed_at'])) {
            $errors[] = 'checker-replay';
        }
        if (($evidence['protocol'] ?? '') !== 'teliphones-checker/1') {
            $errors[] = 'checker-protocol-invalid';
        }
        if (!hash_equals((string)($session['session_id'] ?? ''), (string)($evidence['session_id'] ?? ''))) {
            $errors[] = 'checker-session-mismatch';
        }
        if ($challenge && !hash_equals((string)($session['session_id'] ?? ''), (string)($challenge['session_id'] ?? ''))) {
            $errors[] = 'checker-session-mismatch';
        }
        if ($challenge && !hash_equals((string)($challenge['nonce'] ?? ''), (string)($evidence['nonce'] ?? ''))) {
            $errors[] = 'checker-nonce-mismatch';
        }
        if (($evidence['topology'] ?? '') !== ($session['topology'] ?? '')) {
            $errors[] = 'checker-topology-mismatch';
        }
        if ($challenge && ($challenge['topology'] ?? null) !== ($session['topology'] ?? null)) {
            $errors[] = 'checker-topology-mismatch';
        }
        if ($challenge && $now > (int)($challenge['expires_at'] ?? 0)) {
            $errors[] = 'checker-stale';
        }

        $observed = (int)($evidence['observed_at'] ?? 0);
        if ($observed <= 0 || ($challenge && $observed < (int)($challenge['issued_at'] ?? 0)) || ($challenge && $observed > (int)($challenge['expires_at'] ?? 0)) || $observed > $now + 30) {
            $errors[] = 'checker-observation-stale';
        }
        if (!$this->verifySignature($evidence)) {
            $errors[] = 'checker-signature-invalid';
        }

        $observations = is_array($evidence['observations'] ?? null) ? $evidence['observations'] : [];
        if (($observations['authorised_source']['support_service'] ?? '') !== 'reachable') {
            $errors[] = 'checker-authorised-source-failed';
        }
        if (($observations['negative_source']['support_service'] ?? '') !== 'blocked') {
            $errors[] = 'checker-negative-control-failed';
        }
        if (($observations['public_address']['support_service'] ?? '') !== 'blocked') {
            $errors[] = 'checker-public-exposure-detected';
        }
        if (!empty($observations['unexpected_services'])) {
            $errors[] = 'checker-unexpected-service';
        }

        $accepted = count($errors) === 0;
        if ($accepted && $challenge) {
            $challenge['consumed_at'] = $now;
            if (!$this->write($this->challengePath(), $challenge)) {
                $accepted = false;
                $errors[] = 'checker-challenge-write-failed';
            }
        }
        $result = [
            'protocol' => 'teliphones-checker/1',
            'session_id' => $session['session_id'] ?? null,
            'topology' => $session['topology'] ?? null,
            'nonce' => $evidence['nonce'] ?? null,
            'accepted' => $accepted,
            'accepted_at' => $accepted ? $now : null,
            'errors' => $errors,
        ];
        if (!$this->write($this->evidencePath(), $result)) {
            $result['accepted'] = false;
            $result['accepted_at'] = null;
            $result['errors'][] = 'checker-state-write-failed';
            return $result;
        }

        return $result;
    }

    public function accepted(array $session): bool
    {
        $evidence = $this->read($this->evidencePath());
        $challenge = $this->read($this->challengePath());
        return $evidence
            && ($evidence['accepted'] ?? false) === true
            && hash_equals((string)($session['session_id'] ?? ''), (string)($evidence['session_id'] ?? ''))
            && ($session['topology'] ?? null) === ($evidence['topology'] ?? null)
            && $challenge
            && !empty($challenge['consumed_at'])
            && hash_equals((string)($challenge['nonce'] ?? ''), (string)($evidence['nonce'] ?? ''))
            && (int)($challenge['expires_at'] ?? 0) > time()
            && (int)($session['expires_at'] ?? 0) > time();
    }

    public function state(): ?array
    {
        $evidence = $this->read($this->evidencePath());
        return $evidence ?: null;
    }

    public function destroy(): bool
    {
        $ok = true;
        foreach ([$this->evidencePath(), $this->challengePath()] as $file) {
            if (is_file($file) && !@unlink($file)) {
                $ok = false;
            }
        }
        return $ok;
    }

    private function verifySignature(array $evidence): bool
    {
        if (!function_exists('openssl_verify')) {
            return false;
        }

        $signature = base64_decode((string)($evidence['signature'] ?? ''), true);
        $publicKey = $this->trustedPublicKey ?? $this->readTrustedPublicKey();
        if (!is_string($publicKey) || !is_string($signature)) {
            return false;
        }

        unset($evidence['signature']);
        $message = json_encode($this->canonicalise($evidence), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        $key = @openssl_pkey_get_public($publicKey);
        if (!is_string($message) || $key === false) {
            return false;
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($details['bits'] ?? null) !== 256
            || ($details['ec']['curve_oid'] ?? '') !== '1.2.840.10045.3.1.7') {
            return false;
        }
        return openssl_verify($message, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    private function readTrustedPublicKey(): ?string
    {
        $stat = @lstat(self::KEY_FILE);
        if (!$stat || ($stat['mode'] & 0170000) !== 0100000 || ($stat['mode'] & 0022) !== 0 || $stat['uid'] !== 0) {
            return null;
        }
        $key = @file_get_contents(self::KEY_FILE);
        return is_string($key) ? $key : null;
    }

    private function canonicalise(array $value): array
    {
        $normalise = function (array $items) use (&$normalise): array {
            if (!array_is_list($items)) {
                ksort($items, SORT_STRING);
            }
            foreach ($items as &$item) {
                if (is_array($item)) {
                    $item = $normalise($item);
                }
            }
            unset($item);
            return $items;
        };
        return $normalise($value);
    }

    private function evidencePath(): string
    {
        return $this->directory . '/' . self::FILE_NAME;
    }

    private function challengePath(): string
    {
        return $this->directory . '/' . self::CHALLENGE_NAME;
    }

    private function read(string $file): ?array
    {
        if (!is_readable($file)) {
            return null;
        }
        $value = json_decode((string)file_get_contents($file), true);
        return is_array($value) ? $value : null;
    }

    private function write(string $file, array $value): bool
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            return false;
        }
        $temporary = $file . '.tmp.' . getmypid();
        $encoded = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        if (file_put_contents($temporary, $encoded, LOCK_EX) === false) {
            return false;
        }
        @chmod($temporary, 0600);
        if (!@rename($temporary, $file)) {
            @unlink($temporary);
            return false;
        }
        return true;
    }
}