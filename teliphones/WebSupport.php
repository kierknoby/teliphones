<?php
namespace FreePBX\modules\Teliphones;

class WebSupport
{
    public static function authorised($sessionUser, $frameworkUser = null): bool
    {
        return self::accessError($sessionUser, $frameworkUser) === null;
    }

    public static function accessError($sessionUser, $frameworkUser = null): ?string
    {
        if (!(is_object($sessionUser) && is_callable([$sessionUser, 'checkSection']))
            && !(is_string($sessionUser) && trim($sessionUser) !== '') && !is_int($sessionUser)) {
            return 'TELIPHONES authentication failed: the FreePBX administrator session is missing or malformed.';
        }
        $administrator = $frameworkUser;
        if ($administrator === null) {
            if (is_object($sessionUser)) {
                $administrator = $sessionUser;
            } elseif (class_exists('ampuser')) {
                $administrator = new \ampuser((string)$sessionUser);
            }
        }
        if (!is_object($administrator) || !is_callable([$administrator, 'checkSection'])) {
            return 'TELIPHONES permission check unavailable: FreePBX administrator context could not be resolved.';
        }
        $permission = $administrator->checkSection('*');
        if ($permission !== true && $permission !== 1) {
            return 'TELIPHONES permission denied: full FreePBX administrator access is required.';
        }
        return null;
    }

    public const BROKER_ACTIONS = ['authorise', 'revoke', 'dependencies', 'evidence', 'configure', 'pair', 'unpair'];
    public const ACTION_LABELS = [
        'authorise' => 'Authorise Remote Support',
        'revoke' => 'Revoke Remote Support',
        'dependencies' => 'Approve installation of WireGuard tools',
        'evidence' => 'Submit Checker evidence',
        'configure' => 'Save secure gateway enrollment',
        'pair' => 'Pair Windows workstation',
        'unpair' => 'Revoke workstation access',
    ];
    /** Exact fields forwarded for workstation pairing actions; other actions keep their existing forwarding. */
    public const PAIRING_FIELDS = [
        'pair' => ['request', 'endpoint_host', 'listen_port', 'mode', 'minutes', 'ssh'],
        'unpair' => ['workstation_id'],
    ];

    private string $socket;
    private string $unitFile;
    /** @var callable|null */
    private $serviceState;

    public function __construct(string $socket = '/run/teliphones/control.sock', string $unitFile = '/etc/systemd/system/teliphones-broker.service', ?callable $serviceState = null)
    {
        $this->socket = $socket;
        $this->unitFile = $unitFile;
        $this->serviceState = $serviceState;
    }

    public const OPERATION_STATES = ['running', 'succeeded', 'failed'];
    /** Broker status protocol this module requires (support_broker.py PROTOCOL): 2 adds live operation records, 3 adds workstation pairing. */
    public const BROKER_PROTOCOL = 3;

    public static function brokerOperational(array $response): bool
    {
        return ($response['ok'] ?? false) === true && is_array($response['status'] ?? null);
    }

    public function brokerState(array $support): array
    {
        return self::brokerOperational($support) ? ['available' => true, 'condition' => 'operational'] : ['available' => false] + $this->diagnoseUnavailable();
    }

    /**
     * Shared by the page form POST and the AJAX action endpoint. The caller must already have
     * passed accessError(). $support is a fresh broker status probe.
     * Returns ['code' => HTTP status, 'notice' => array, 'dispatched' => bool].
     */
    public static function handleAction(WebSupport $client, array $post, string $token, array $support, array $server): array
    {
        if (!self::validRequest($post, $token)) {
            return ['code' => 403, 'dispatched' => false, 'notice' => ['ok' => false, 'error' => 'TELIPHONES request rejected: invalid action or security token.']];
        }
        $request = ['action' => $post['action']];
        $operation = self::ACTION_LABELS[$request['action']];
        foreach (self::PAIRING_FIELDS[$request['action']] ?? ['minutes', 'evidence', 'url', 'certificate', 'private_key', 'ca', 'checker_key'] as $field) {
            if (isset($post[$field]) && is_string($post[$field])) $request[$field] = $post[$field];
        }
        if (!self::brokerOperational($support)) {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'unavailable' => true, 'action' => $request['action'], 'operation' => $operation,
                'error' => $request['action'] === 'revoke'
                    ? 'Revocation was NOT performed: the privileged TELIPHONES broker is unavailable (see the system warning above). Use the emergency root revocation below if a session may be active, then follow the recovery steps above and refresh.'
                    : 'The operation was not attempted: the privileged TELIPHONES broker is unavailable (see the system warning above). Follow the installation or recovery steps above, then refresh this page and retry.']];
        }
        if ($request['action'] === 'configure' && strtolower((string)($server['HTTPS'] ?? '')) !== 'on' && (string)($server['SERVER_PORT'] ?? '') !== '443') {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => 'configure', 'operation' => $operation, 'error' => 'Gateway credentials may only be submitted over HTTPS. Configure FreePBX HTTPS before enrollment.']];
        }
        // A pairing request names the WireGuard key that will be admitted; it must not be alterable in transit.
        if ($request['action'] === 'pair' && strtolower((string)($server['HTTPS'] ?? '')) !== 'on' && (string)($server['SERVER_PORT'] ?? '') !== '443') {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => 'pair', 'operation' => $operation, 'error' => 'Workstations may only be paired over HTTPS. Open the FreePBX administration interface using https:// and try again.']];
        }
        $notice = $client->request($request);
        $notice['action'] = $request['action'];
        if (empty($notice['ok'])) {
            $notice['action_failed'] = true;
            $notice['operation'] = $operation;
        }
        return ['code' => 200, 'dispatched' => true, 'notice' => $notice];
    }

    /**
     * Browser-safe status: an allowlisted, type-checked subset of the broker status.
     * Never contains credentials, keys or configuration contents.
     */
    public static function publicStatus(array $support, array $broker): array
    {
        $status = is_array($support['status'] ?? null) ? $support['status'] : [];
        $text = static function ($value, int $max = 1000): ?string {
            return is_string($value) ? substr($value, 0, $max) : null;
        };
        $readiness = [];
        foreach (is_array($status['readiness'] ?? null) ? $status['readiness'] : [] as $name => $value) {
            if (is_string($name)) $readiness[substr($name, 0, 100)] = $value === true;
        }
        $session = [];
        if (is_array($status['session'] ?? null)) {
            foreach (['session_id', 'state'] as $field) {
                if (is_string($status['session'][$field] ?? null)) $session[$field] = substr($status['session'][$field], 0, 100);
            }
            if (is_int($status['session']['expires_at'] ?? null)) $session['expires_at'] = $status['session']['expires_at'];
        }
        $operation = null;
        $raw = $status['operation'] ?? null;
        if (is_array($raw) && is_string($raw['id'] ?? null) && preg_match('/^[a-f0-9]{1,32}$/', $raw['id'])
            && in_array($raw['action'] ?? null, self::BROKER_ACTIONS, true) && in_array($raw['state'] ?? null, self::OPERATION_STATES, true)
            && is_int($raw['started_at'] ?? null)) {
            $operation = ['id' => $raw['id'], 'action' => $raw['action'], 'label' => self::ACTION_LABELS[$raw['action']], 'state' => $raw['state'],
                'stage' => $text($raw['stage'] ?? '', 200) ?? '', 'message' => $text($raw['message'] ?? '') ?? '',
                'started_at' => $raw['started_at'], 'finished_at' => is_int($raw['finished_at'] ?? null) ? $raw['finished_at'] : null];
        }
        $available = !empty($broker['available']);
        return [
            'available' => $available,
            'broker_current' => $available && is_int($status['protocol'] ?? null) && $status['protocol'] >= self::BROKER_PROTOCOL,
            'condition' => $available ? 'operational' : (string)($broker['condition'] ?? 'unverified'),
            'phase' => $available ? ($text($status['phase'] ?? null, 200) ?? 'Not configured') : null,
            'enabled' => ($status['enabled'] ?? false) === true,
            'can_authorise' => $available && ($status['can_authorise'] ?? false) === true,
            'readiness' => $readiness,
            'session' => $session,
            'access_verified' => ($status['access_verified'] ?? false) === true,
            'engineer' => $text($status['engineer'] ?? null, 200),
            'challenge' => is_array($status['challenge'] ?? null) ? $status['challenge'] : null,
            'operation' => $available ? $operation : null,
            'server_time' => is_int($status['server_time'] ?? null) ? $status['server_time'] : time(),
            'error' => $available ? ($text($support['error'] ?? null) ?: null) : null,
        ];
    }

    /** Control availability, mirrored by assets/js/teliphones.js for live updates. */
    public static function controls(array $public, array $submitting = []): array
    {
        $available = !empty($public['available']);
        $operation = is_array($public['operation'] ?? null) ? $public['operation'] : null;
        $busy = $operation !== null && $operation['state'] === 'running';
        $installed = ($public['readiness']['WireGuard wg'] ?? null) === true;
        $session = !empty($public['session']);
        $state = static function (bool $enabled, string $reason): array {
            return ['enabled' => $enabled, 'reason' => $enabled ? '' : $reason];
        };
        return [
            'dependencies' => $state($available && !$busy && !$installed && !$session && empty($submitting['dependencies']),
                !$available ? 'broker' : ($installed ? 'installed' : (($busy || !empty($submitting['dependencies'])) ? 'running' : 'session'))),
            'authorise' => $state($available && !$busy && ($public['can_authorise'] ?? false) === true && empty($submitting['authorise']),
                !$available ? 'broker' : (($busy || !empty($submitting['authorise'])) ? 'running' : 'not-ready')),
            'revoke' => $state($available && empty($submitting['revoke']) && !($busy && $operation['action'] === 'revoke'), !$available ? 'broker' : 'running'),
            'evidence' => $state($available && !$busy && !empty($public['challenge']) && empty($submitting['evidence']),
                !$available ? 'broker' : (($busy || !empty($submitting['evidence'])) ? 'running' : 'no-challenge')),
            'configure' => $state($available && !$busy && !$session && empty($submitting['configure']),
                !$available ? 'broker' : (($busy || !empty($submitting['configure'])) ? 'running' : 'session')),
        ];
    }

    public const CONTROL_REASONS = [
        'running' => 'Another TELIPHONES operation is in progress.',
        'installed' => 'WireGuard tools are installed (wg executable detected by the broker).',
        'session' => 'Not available while a support session exists. Revoke it first.',
        'not-ready' => 'Authorisation becomes available when every required component is ready and no session is active.',
        'no-challenge' => '',
        'broker' => '',
    ];

    /** Readiness table cell: ['kind' => busy|ok|fail|plain, 'text' => string]. Mirrored in the browser monitor. */
    public static function readinessCell(string $component, $value, array $public): array
    {
        $operation = is_array($public['operation'] ?? null) ? $public['operation'] : null;
        $enrollment = in_array($component, ['Gateway enrollment', 'Checker trusted public key'], true);
        if ($operation !== null && $operation['state'] === 'running') {
            if ($operation['action'] === 'dependencies' && $component === 'WireGuard wg') return ['kind' => 'busy', 'text' => ($operation['stage'] ?: 'Installing WireGuard tools') . '…'];
            if ($operation['action'] === 'configure' && $enrollment) return ['kind' => 'busy', 'text' => ($operation['stage'] ?: 'Validating gateway enrollment') . '…'];
        }
        if ($value === true) return ['kind' => 'ok', 'text' => '✓ Installed / configured (operation not yet verified)'];
        if ($operation !== null && $operation['state'] === 'failed' && $operation['action'] === 'dependencies' && $component === 'WireGuard wg') return ['kind' => 'fail', 'text' => '✕ Installation failed'];
        if ($operation !== null && $operation['state'] === 'failed' && $operation['action'] === 'configure' && $enrollment) return ['kind' => 'fail', 'text' => '✕ Enrollment failed'];
        return ['kind' => 'plain', 'text' => 'Missing or unavailable'];
    }

    public static function sessionPhase(array $public): array
    {
        if (empty($public['available'])) return ['kind' => 'plain', 'text' => 'Not verified (broker unavailable)'];
        $operation = is_array($public['operation'] ?? null) ? $public['operation'] : null;
        $phase = (string)($public['phase'] ?? 'Not configured');
        $running = $operation !== null && $operation['state'] === 'running';
        if ($running && in_array($operation['action'], ['authorise', 'evidence', 'revoke'], true)) return ['kind' => 'busy', 'text' => $phase . ': ' . ($operation['stage'] ?: $operation['label']) . '…'];
        if (!$running && strpos($phase, 'Revoking') === 0) return ['kind' => 'busy', 'text' => $phase . ' — background cleanup in progress…'];
        if (($public['access_verified'] ?? false) === true && $phase === 'Connected') return ['kind' => 'ok', 'text' => '✓ ' . $phase];
        return ['kind' => preg_match('/failed|quarantined/i', $phase) ? 'fail' : 'plain', 'text' => $phase];
    }

    /**
     * FreePBX ajax.php handler body (module=teliphones). "status" is read-only and never
     * dispatches a privileged action; "action" requires POST, CSRF and the allowlist.
     * Returns ['code' => HTTP status, 'body' => array].
     */
    public static function ajax(string $command, string $method, array $post, array $session, $frameworkUser, array $server, WebSupport $client): array
    {
        $body = ['teliphones_api' => 1];
        if (!in_array($command, ['status', 'action'], true)) {
            return ['code' => 400, 'body' => $body + ['ok' => false, 'error' => 'Unsupported TELIPHONES request.']];
        }
        $accessError = self::accessError($session['AMP_user'] ?? null, $frameworkUser);
        if ($accessError !== null) {
            return ['code' => 403, 'body' => $body + ['ok' => false, 'auth_error' => true, 'error' => $accessError]];
        }
        if ($method !== ($command === 'status' ? 'GET' : 'POST')) {
            return ['code' => 405, 'body' => $body + ['ok' => false, 'error' => 'Method not allowed.']];
        }
        $support = $client->request(['action' => 'status']);
        if ($command === 'status') {
            return ['code' => 200, 'body' => $body + ['ok' => true, 'status' => self::publicStatus($support, $client->brokerState($support))]];
        }
        $token = is_string($session['teliphones_token'] ?? null) ? $session['teliphones_token'] : '';
        $result = self::handleAction($client, $post, $token, $support, $server);
        if ($result['dispatched']) $support = $client->request(['action' => 'status']);
        $notice = $result['notice'];
        $publicNotice = ['ok' => !empty($notice['ok']), 'action' => is_string($notice['action'] ?? null) ? $notice['action'] : null,
            'operation_id' => is_string($notice['operation_id'] ?? null) && preg_match('/^[a-f0-9]{1,32}$/', $notice['operation_id']) ? $notice['operation_id'] : null,
            'message' => is_string($notice['message'] ?? null) ? $notice['message'] : null,
            'error' => is_string($notice['error'] ?? null) ? $notice['error'] : null,
            'operation' => is_string($notice['operation'] ?? null) ? $notice['operation'] : null,
            'pairing_response' => self::validPairingResponse($notice['pairing_response'] ?? null) ? $notice['pairing_response'] : null];
        return ['code' => $result['code'], 'body' => $body + ['ok' => $publicNotice['ok'], 'notice' => $publicNotice,
            'status' => self::publicStatus($support, $client->brokerState($support))]];
    }

    public static function validRequest(array $request, string $token): bool
    {
        if (!isset($request['token'], $request['action']) || !is_string($request['token'])
            || !is_string($request['action']) || $token === '' || !hash_equals($token, $request['token'])) return false;
        return in_array($request['action'], self::BROKER_ACTIONS, true);
    }

    /** Validated workstation pairing status for server-side rendering; never contains WireGuard keys. */
    public static function workstations(array $support): array
    {
        $status = is_array($support['status'] ?? null) ? $support['status'] : [];
        $raw = is_array($status['workstations'] ?? null) ? $status['workstations'] : null;
        $supported = $raw !== null && is_int($status['protocol'] ?? null) && $status['protocol'] >= self::BROKER_PROTOCOL;
        $items = [];
        foreach ($supported && is_array($raw['items'] ?? null) ? $raw['items'] : [] as $item) {
            if (!is_array($item) || !is_string($item['id'] ?? null) || !preg_match('/^[a-f0-9]{16}$/', $item['id'])) continue;
            $items[] = ['id' => $item['id'], 'name' => substr((string)($item['name'] ?? ''), 0, 64), 'address' => substr((string)($item['address'] ?? ''), 0, 18),
                'mode' => ($item['mode'] ?? '') === 'persistent' ? 'persistent' : 'temporary', 'ssh' => ($item['ssh'] ?? false) === true,
                'expires_at' => is_int($item['expires_at'] ?? null) ? $item['expires_at'] : null,
                'fingerprint' => substr((string)($item['fingerprint'] ?? ''), 0, 40)];
        }
        $requirements = [];
        foreach ($supported && is_array($raw['requirements'] ?? null) ? $raw['requirements'] : [] as $name => $value) {
            if (is_string($name)) $requirements[substr($name, 0, 20)] = $value === true;
        }
        return ['supported' => $supported, 'ready' => $supported && ($raw['ready'] ?? false) === true, 'requirements' => $requirements,
            'error' => $supported && is_string($raw['error'] ?? null) ? substr($raw['error'], 0, 500) : '',
            'listen_port' => $supported && is_int($raw['listen_port'] ?? null) ? $raw['listen_port'] : null, 'items' => $items];
    }

    public static function validPairingResponse($value): bool
    {
        return is_string($value) && preg_match('/^TELIPHONES-PAIR-RESPONSE-1:[A-Za-z0-9_-]{20,4000}$/', $value) === 1;
    }

    /**
     * Read-only classification used only after the control socket could not be reached.
     * Returns not_installed, stopped, socket_unavailable or unverified.
     */
    public function diagnoseUnavailable(): array
    {
        if (!is_file($this->unitFile)) {
            return ['condition' => 'not_installed', 'service' => 'not installed'];
        }
        $state = $this->serviceState !== null ? ($this->serviceState)() : self::systemdActiveState();
        if (!is_string($state) || !preg_match('/^[a-z-]{1,32}$/', $state)) {
            return ['condition' => 'unverified', 'service' => 'not verified'];
        }
        if ($state !== 'active') {
            return ['condition' => 'stopped', 'service' => $state];
        }
        return ['condition' => 'socket_unavailable', 'service' => 'active', 'socket_present' => file_exists($this->socket)];
    }

    private static function systemdActiveState(): ?string
    {
        if (!is_executable('/usr/bin/systemctl') || !function_exists('proc_open')) return null;
        // Fixed argument vector; no shell and no request-derived input.
        $process = @proc_open(['/usr/bin/systemctl', 'is-active', 'teliphones-broker.service'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($process)) return null;
        stream_set_timeout($pipes[1], 3);
        $state = trim((string)fgets($pipes[1], 64));
        fclose($pipes[1]);
        proc_close($process);
        return $state === '' ? null : $state;
    }

    public function request(array $request): array
    {
        $socket = @stream_socket_client('unix://' . $this->socket, $errno, $error, 2);
        if ($socket === false) return ['ok' => false, 'unavailable' => true, 'error' => 'Privileged TELIPHONES broker unavailable. FreePBX Module Admin installed the module, but its root component is not reachable.'];
        stream_set_timeout($socket, 5);
        $payload = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
        $offset = 0;
        while ($offset < strlen($payload)) {
            $written = fwrite($socket, substr($payload, $offset));
            if ($written === false || $written === 0) {
                fclose($socket);
                return ['ok' => false, 'unavailable' => true, 'error' => 'Unable to send the TELIPHONES request.'];
            }
            $offset += $written;
        }
        $line = fgets($socket, 131073);
        fclose($socket);
        $response = is_string($line) ? json_decode($line, true) : null;
        return is_array($response) ? $response : ['ok' => false, 'unavailable' => true, 'error' => 'TELIPHONES broker did not return a valid response. Refresh status before retrying.'];
    }
}
