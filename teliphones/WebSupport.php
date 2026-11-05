<?php
namespace FreePBX\modules\Teliphones;

class WebSupport
{
    public const DIAGNOSTIC_ID_PATTERN = '/^ws-[a-f0-9]{16}$/';

    public static function moduleVersion(): string
    {
        static $version = null;
        if ($version !== null) return $version;
        $metadata = simplexml_load_file(__DIR__ . '/module.xml');
        $value = $metadata ? (string)$metadata->version : '';
        if (preg_match('/^\d+\.\d+\.\d+$/', $value) !== 1) {
            throw new \RuntimeException('TELIPHONES module version is missing or invalid.');
        }
        return $version = $value;
    }

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

    public const BROKER_ACTIONS = ['authorise', 'revoke', 'dependencies', 'evidence', 'configure', 'pair', 'unpair', 'web',
        'workstation-policy', 'workstation-manage', 'workstation-ban', 'workstation-unban', 'workstation-limit',
        'workstation-ssh-approve', 'workstation-ssh-reject', 'workstation-ssh-revoke',
        'workstation-unlock-approve', 'workstation-unlock-reject',
        'workstation-sources-approve', 'workstation-sources-reject'];
    public const ACTION_LABELS = [
        'authorise' => 'Authorise Remote Support',
        'revoke' => 'Revoke Remote Support',
        'dependencies' => 'Approve installation of WireGuard tools',
        'evidence' => 'Submit Checker evidence',
        'configure' => 'Save secure gateway enrollment',
        'pair' => 'Pair Windows workstation',
        'unpair' => 'Revoke workstation access',
        'web' => 'Update management web services',
        'workstation-policy' => 'Change workstation connection state',
        'workstation-manage' => 'Change paired workstation source restrictions',
        'workstation-ban' => 'Add TELIPHONES listener ban',
        'workstation-unban' => 'Remove TELIPHONES listener ban',
        'workstation-limit' => 'Change maximum simultaneous workstation connections',
        'workstation-ssh-approve' => 'Approve post-pair SSH elevation',
        'workstation-ssh-reject' => 'Reject post-pair SSH elevation',
        'workstation-ssh-revoke' => 'Revoke managed workstation SSH access',
        'workstation-unlock-approve' => 'Approve workstation unlock request',
        'workstation-unlock-reject' => 'Reject workstation unlock request',
        'workstation-sources-approve' => 'Approve workstation Allowed List request',
        'workstation-sources-reject' => 'Reject workstation Allowed List request',
    ];
    /** Exact fields forwarded for workstation pairing actions; other actions keep their existing forwarding. */
    public const PAIRING_FIELDS = [
        'pair' => ['request', 'endpoint_host', 'listen_port', 'mode', 'minutes', 'ssh', 'ssh_user', 'web', 'sources'],
        'unpair' => ['workstation_id'],
        'web' => ['web'],
        'workstation-policy' => ['state'],
        'workstation-manage' => ['workstation_id', 'state', 'sources'],
        'workstation-ban' => ['source', 'reason', 'hours'],
        'workstation-unban' => ['ban_id'],
        'workstation-limit' => ['maximum'],
        'workstation-ssh-approve' => ['workstation_id', 'ssh_user'],
        'workstation-ssh-reject' => ['workstation_id'],
        'workstation-ssh-revoke' => ['workstation_id'],
        'workstation-unlock-approve' => ['workstation_id'],
        'workstation-unlock-reject' => ['workstation_id'],
        'workstation-sources-approve' => ['workstation_id'],
        'workstation-sources-reject' => ['workstation_id'],
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
    public const BROKER_VERSION = '0.6.1';
    public const DIAGNOSTICS_PROTOCOL = 4;
    public const SSH_PROTOCOL = 5;
    /** Protocol 6 adds the WireGuard listener firewall permit and configurable management web services. */
    public const WEB_PROTOCOL = 6;
    public const POLICY_PROTOCOL = 8;
    public const SOURCE_LOCK_PROTOCOL = 8;
    public const LOCKED_SSH_PROTOCOL = 9;
    public const BAN_PROTOCOL = 10;
    public const SESSION_PROTOCOL = 11;
    public const WORKSTATION_MANAGEMENT_PROTOCOL = 12;

    public static function brokerOperational(array $response): bool
    {
        return ($response['ok'] ?? false) === true && is_array($response['status'] ?? null);
    }

    public static function supportsDiagnostics(array $response): bool
    {
        return self::brokerOperational($response)
            && is_int($response['status']['protocol'] ?? null)
            && $response['status']['protocol'] >= self::DIAGNOSTICS_PROTOCOL;
    }

    public static function supportsWeb(array $response): bool
    {
        return self::brokerOperational($response)
            && is_int($response['status']['protocol'] ?? null)
            && $response['status']['protocol'] >= self::WEB_PROTOCOL;
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
        if ($request['action'] === 'pair' && !empty($request['web']) && !self::supportsWeb($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Update the root broker before pairing with configured management web services.']];
        }
        if ($request['action'] === 'pair' && !empty($request['sources']) && !self::supportsSourceLocks($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Source-locked pairing requires the updated root broker. Complete the documented root broker update, then retry.']];
        }
        if ($request['action'] === 'pair' && !empty($request['sources']) && ($request['ssh'] ?? '') === '1'
            && !self::supportsLockedSsh($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Locked SSH pairing requires the updated root broker. Complete the documented root broker update, then retry.']];
        }
        // An empty value preserves the saved configuration.
        if ($request['action'] === 'pair' && isset($request['web'])
            && trim($request['web']) === '') {
            unset($request['web']);
        }
        if ($request['action'] === 'web' && !self::supportsWeb($support)) {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => 'web', 'operation' => $operation,
                'error' => 'Management web services require the updated root broker. Follow the root broker update procedure, then refresh this page.']];
        }
        if ($request['action'] === 'workstation-policy' && !self::supportsWorkstationPolicy($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Connection states require the updated root broker. Follow the root broker update procedure, then refresh this page.']];
        }
        if ($request['action'] === 'workstation-limit' && !self::supportsWorkstationSessions($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Enforced workstation session limits require the updated root broker. Complete the documented root broker update, then retry.']];
        }
        if ($request['action'] === 'workstation-manage' && !self::supportsWorkstationManagement($support)) {
            return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'error' => 'Post-pair workstation policy requires the updated root broker. Complete the documented root broker update, then retry.']];
        }
        if ($request['action'] === 'web' && strtolower((string)($server['HTTPS'] ?? '')) !== 'on'
            && (string)($server['SERVER_PORT'] ?? '') !== '443') {
            return ['code' => 403, 'dispatched' => false, 'notice' => ['ok' => false,
                'error' => 'Management web permissions may only be changed over HTTPS.']];
        }
        if (!self::brokerOperational($support)) {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'unavailable' => true, 'action' => $request['action'], 'operation' => $operation,
                'error' => $request['action'] === 'revoke'
                    ? 'Revocation was NOT performed: the privileged TELIPHONES broker is unavailable (see the system warning above). Use the emergency root revocation below if a session may be active, then follow the recovery steps above and refresh.'
                    : 'The operation was not attempted: the privileged TELIPHONES broker is unavailable (see the system warning above). Follow the installation or recovery steps above, then refresh this page and retry.']];
        }
        if (in_array($request['action'], ['pair', 'unpair', 'workstation-manage', 'workstation-ban', 'workstation-unban',
            'workstation-unlock-approve', 'workstation-unlock-reject',
            'workstation-sources-approve', 'workstation-sources-reject'], true)) {
            $workstations = self::workstations($support);
            if (!$workstations['supported'] || ($request['action'] === 'pair' && !$workstations['ready'])
                || ($request['action'] === 'workstation-manage' && !$workstations['management_supported'])
                || (in_array($request['action'], ['workstation-unlock-approve', 'workstation-unlock-reject'], true)
                    && !$workstations['management_supported'])
                || (in_array($request['action'], ['workstation-sources-approve', 'workstation-sources-reject'], true)
                    && !$workstations['management_supported'])
                || (in_array($request['action'], ['workstation-ssh-approve', 'workstation-ssh-reject', 'workstation-ssh-revoke'], true)
                    && (!$workstations['management_supported'] || !$workstations['ssh_ready']))
                || (in_array($request['action'], ['workstation-ban', 'workstation-unban'], true) && !$workstations['ban_supported'])) {
                return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => $request['action'], 'operation' => $operation,
                    'error' => !$workstations['supported']
                        ? 'Workstation operation was not attempted: the root broker does not report compatible pairing capabilities. Rerun Complete Installation from a root shell after upgrading, with no active support session.'
                        : (($request['action'] === 'pair')
                            ? self::pairingNotAttempted($workstations, ($support['status']['enabled'] ?? true) === true)
                            : (in_array($request['action'], ['workstation-ssh-approve', 'workstation-ssh-reject', 'workstation-ssh-revoke'], true)
                                ? 'Post-pair SSH elevation was not attempted: update the root broker and verify the managed SSH authority.'
                                : (in_array($request['action'], ['workstation-manage', 'workstation-unlock-approve',
                                    'workstation-unlock-reject', 'workstation-sources-approve',
                                    'workstation-sources-reject'], true)
                                ? 'Post-pair workstation policy was not attempted: update the root broker to protocol 12.'
                                : 'Manual listener bans require the updated root broker and protocol 12.')))]];
            }
        }
        if ($request['action'] === 'configure' && strtolower((string)($server['HTTPS'] ?? '')) !== 'on' && (string)($server['SERVER_PORT'] ?? '') !== '443') {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => 'configure', 'operation' => $operation, 'error' => 'Gateway credentials may only be submitted over HTTPS. Configure FreePBX HTTPS before enrollment.']];
        }
        // A pairing request names the WireGuard key that will be admitted; it must not be alterable in transit.
        if ($request['action'] === 'pair' && strtolower((string)($server['HTTPS'] ?? '')) !== 'on' && (string)($server['SERVER_PORT'] ?? '') !== '443') {
            return ['code' => 200, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true, 'action' => 'pair', 'operation' => $operation, 'error' => 'Workstations may only be paired over HTTPS. Open the FreePBX administration interface using https:// and try again.']];
        }
        if ($request['action'] === 'pair' && ($request['ssh'] ?? '') === '1'
            && !self::pairingRequestSupportsSsh($request['request'] ?? '')) {
            return ['code' => 400, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                'action' => 'pair', 'operation' => $operation,
                'error' => 'This pairing request did not include SSH capability. Request SSH in the Windows application before approving it.']];
        }
        if ($request['action'] === 'pair' && ($request['ssh'] ?? '') === '1') {
            $account = $request['ssh_user'] ?? '';
            if (preg_match('/^[a-z_][a-z0-9_-]{0,31}$/D', $account) !== 1) {
                return ['code' => 400, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                    'action' => 'pair', 'operation' => $operation,
                    'error' => 'Select the existing Linux SSH account explicitly. Root is never selected automatically.']];
            }
            if (($support['status']['protocol'] ?? 0) < self::SSH_PROTOCOL
                || ($support['status']['workstations']['ssh_ready'] ?? false) !== true) {
                return ['code' => 409, 'dispatched' => false, 'notice' => ['ok' => false, 'action_failed' => true,
                    'action' => 'pair', 'operation' => $operation,
                    'error' => 'Managed SSH is unavailable. Update the root broker and resolve its SSH readiness errors before authorising SSH. Web-only pairing remains available.']];
            }
        }
        $notice = $client->request($request);
        $notice['action'] = $request['action'];
        if (empty($notice['ok'])) {
            $notice['action_failed'] = true;
            $notice['operation'] = $operation;
        }
        return ['code' => 200, 'dispatched' => true, 'notice' => $notice];
    }

    public static function supportsWorkstationPolicy(array $support): bool
    {
        return self::brokerOperational($support)
            && is_int($support['status']['protocol'] ?? null)
            && $support['status']['protocol'] >= self::POLICY_PROTOCOL
            && is_string($support['status']['workstations']['connection_state'] ?? null)
            && in_array($support['status']['workstations']['connection_state'], ['open', 'closed', 'frozen'], true);
    }

    public static function supportsSourceLocks(array $support): bool
    {
        return self::brokerOperational($support)
            && is_int($support['status']['protocol'] ?? null)
            && $support['status']['protocol'] >= self::SOURCE_LOCK_PROTOCOL;
    }

    public static function supportsLockedSsh(array $support): bool
    {
        return self::brokerOperational($support)
            && is_int($support['status']['protocol'] ?? null)
            && $support['status']['protocol'] >= self::LOCKED_SSH_PROTOCOL;
    }

    public static function supportsWorkstationSessions(array $support): bool
    {
        return self::brokerOperational($support)
            && is_int($support['status']['protocol'] ?? null)
            && $support['status']['protocol'] >= self::SESSION_PROTOCOL
            && is_array($support['status']['workstations'] ?? null)
            && is_int($support['status']['workstations']['max_sessions'] ?? null)
            && $support['status']['workstations']['max_sessions'] >= 1
            && $support['status']['workstations']['max_sessions'] <= 128
            && is_int($support['status']['workstations']['connected_workstations'] ?? null)
            && $support['status']['workstations']['connected_workstations'] >= 0
            && $support['status']['workstations']['connected_workstations'] <= 128;
    }

    public static function supportsWorkstationManagement(array $support): bool
    {
        return self::brokerOperational($support)
            && is_int($support['status']['protocol'] ?? null)
            && $support['status']['protocol'] >= self::WORKSTATION_MANAGEMENT_PROTOCOL
            && self::supportsWorkstations($support);
    }

    public static function pairingRequestSupportsSsh($request): bool
    {
        if (!is_string($request) || strlen($request) > 4096
            || preg_match('/^TELIPHONES-PAIR-REQUEST-2:([A-Za-z0-9_-]+)$/D', trim($request), $matches) !== 1) {
            return false;
        }
        $encoded = strtr($matches[1], '-_', '+/');
        $encoded .= str_repeat('=', (4 - strlen($encoded) % 4) % 4);
        $decoded = base64_decode($encoded, true);
        if ($decoded === false) return false;
        $payload = json_decode($decoded, true);
        return is_array($payload)
            && ($payload['schema'] ?? null) === 'teliphones-pair-request/2'
            && is_string($payload['ssh_public_key'] ?? null)
            && $payload['ssh_public_key'] !== '';
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
            'broker_current' => $available && self::supportsWorkstations($support),
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
        if (!in_array($command, ['status', 'action', 'diagnostics'], true)) {
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
        if ($command === 'diagnostics') {
            $diagnosticId = $post['diagnostic_id'] ?? null;
            if (!self::validDiagnosticsRequest($post, $token) || !is_string($diagnosticId)
                || !preg_match(self::DIAGNOSTIC_ID_PATTERN, $diagnosticId)) {
                return ['code' => 403, 'body' => $body + ['ok' => false, 'error' => 'Invalid TELIPHONES diagnostic request.']];
            }
            if (!self::supportsDiagnostics($support)) {
                return ['code' => 409, 'body' => $body + ['ok' => false, 'error' => 'The root broker must be upgraded before workstation diagnostics are available.']];
            }
            $reply = $client->request(['action' => 'diagnostics', 'diagnostic_id' => $diagnosticId]);
            if (($reply['ok'] ?? false) !== true) {
                return ['code' => 503, 'body' => $body + ['ok' => false, 'error' => 'The privileged broker could not return workstation diagnostics.']];
            }
            $diagnostics = self::sanitiseDiagnostics($reply, $diagnosticId);
            return ['code' => 200, 'body' => $body + ['ok' => true, 'diagnostics' => $diagnostics]];
        }
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

    public static function validDiagnosticsRequest(array $request, string $token): bool
    {
        return array_diff(array_keys($request), ['token', 'diagnostic_id']) === []
            && isset($request['token'], $request['diagnostic_id'])
            && is_string($request['token']) && $token !== '' && hash_equals($token, $request['token'])
            && is_string($request['diagnostic_id']) && preg_match(self::DIAGNOSTIC_ID_PATTERN, $request['diagnostic_id']) === 1;
    }

    public static function sanitiseDiagnostics(array $reply, string $diagnosticId): array
    {
        $allowed = [
            'ssh.certificate' => ['expires_at' => 'int', 'serial' => 'int'],
            'ssh.terminated' => ['reason' => ['revoked', 'shutdown', 'rotation']],
            'pairing.approved' => ['mode' => ['temporary', 'persistent'], 'expires_at' => 'nullable-int', 'renewed' => 'bool'],
            'pairing.revoked' => ['reason' => ['administrator']],
            'pairing.expired' => ['reason' => ['deadline']],
            'peer.admitted' => ['access' => ['web', 'web+ssh']],
            'peer.observation' => ['handshake_at' => 'int', 'rx_bytes' => 'int', 'tx_bytes' => 'int'],
            'interface.established' => ['listen_port' => 'int'],
            'interface.removed' => [],
            'firewall.integration' => ['state' => ['inactive', 'active', 'not-detected', 'error'],
                'backend' => ['nf_tables', 'legacy', null]],
            'broker.error' => ['category' => ['workstation-enforcement', 'firewall-integration', 'telemetry-unavailable', 'cleanup-unverified']],
        ];
        $events = [];
        foreach (is_array($reply['events'] ?? null) ? array_slice($reply['events'], -200) : [] as $event) {
            if (!is_array($event) || ($event['diagnostic_id'] ?? null) !== $diagnosticId
                || ($event['source'] ?? null) !== 'pbx' || !is_string($event['event'] ?? null)
                || !array_key_exists($event['event'], $allowed) || !is_int($event['unix_time'] ?? null)
                || !is_string($event['timestamp_utc'] ?? null)
                || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $event['timestamp_utc']) !== 1) continue;
            $fields = $allowed[$event['event']];
            $data = is_array($event['data'] ?? null) ? $event['data'] : [];
            if (array_diff(array_keys($data), array_keys($fields))) continue;
            $clean = [];
            $valid = true;
            foreach ($data as $name => $value) {
                $rule = $fields[$name];
                if ($rule === 'int') $valid = is_int($value) && $value >= 0;
                elseif ($rule === 'nullable-int') $valid = $value === null || (is_int($value) && $value >= 0);
                elseif ($rule === 'bool') $valid = is_bool($value);
                else $valid = in_array($value, $rule, true);
                if (!$valid) break;
                $clean[$name] = $value;
            }
            if (!$valid) continue;
            $events[] = ['timestamp_utc' => $event['timestamp_utc'], 'unix_time' => $event['unix_time'],
                'diagnostic_id' => $diagnosticId, 'source' => 'pbx', 'event' => $event['event'], 'data' => $clean];
        }
        $exportedAt = is_string($reply['exported_at'] ?? null)
            && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $reply['exported_at']) === 1
            ? $reply['exported_at'] : gmdate('Y-m-d\TH:i:s\Z');
        return ['component_version' => self::moduleVersion(), 'diagnostic_id' => $diagnosticId,
            'exported_at' => $exportedAt, 'events' => $events];
    }

    public static function validRequest(array $request, string $token): bool
    {
        if (!isset($request['token'], $request['action']) || !is_string($request['token'])
            || !is_string($request['action']) || $token === '' || !hash_equals($token, $request['token'])) return false;
        return in_array($request['action'], self::BROKER_ACTIONS, true);
    }

    /** Protocol 3 must actually report the complete workstation capability status. */
    private static function supportsWorkstations(array $support): bool
    {
        $status = $support['status'] ?? null;
        if (!self::brokerOperational($support) || !is_int($status['protocol'] ?? null) || $status['protocol'] < self::BROKER_PROTOCOL
            || !is_string($status['component_version'] ?? null)
            || preg_match('/^\d+\.\d+\.\d+$/', $status['component_version']) !== 1
            || version_compare($status['component_version'], self::BROKER_VERSION, '<')) return false;
        $raw = $status['workstations'] ?? null;
        if (!is_array($raw) || !is_bool($raw['ready'] ?? null) || !is_array($raw['items'] ?? null) || !is_array($raw['requirements'] ?? null)) return false;
        foreach (['wg', 'ip', 'nft'] as $tool) {
            if (!is_bool($raw['requirements'][$tool] ?? null)) return false;
        }
        return true;
    }

    /** Validated workstation pairing status for server-side rendering; never contains WireGuard keys. */
    private static function pairingNotAttempted(array $workstations, bool $enabled): string
    {
        if ($enabled && !in_array(false, $workstations['requirements'], true) && $workstations['error'] !== '') {
            return 'Workstation pairing was not attempted: ' . $workstations['error'];
        }
        return 'Workstation pairing was not attempted. ' . self::pairingBlockedReason($workstations, $enabled);
    }

    /** Why pairing is not ready, distinguishing missing tools from a broker readiness error. */
    public static function pairingBlockedReason(array $workstations, bool $enabled): string
    {
        if (!$enabled) return 'TELIPHONES is disabled. Workstation pairing is unavailable; revocation remains available.';
        $missing = array_keys(array_filter($workstations['requirements'], static function ($value) { return $value !== true; }));
        if ($missing) return 'Workstation pairing requires WireGuard tools, iproute2 and nftables on the PBX. Missing: ' . implode(', ', $missing) . '.';
        if ($workstations['error'] !== '') return 'Workstation pairing is blocked by the root broker. WireGuard tools, iproute2 and nftables are installed; the failed readiness condition is reported below.';
        return 'The root broker reports that workstation pairing is not ready, although WireGuard tools, iproute2 and nftables are installed.';
    }

    public static function workstations(array $support): array
    {
        $status = is_array($support['status'] ?? null) ? $support['status'] : [];
        $raw = is_array($status['workstations'] ?? null) ? $status['workstations'] : null;
        $supported = self::supportsWorkstations($support);
        $items = [];
        $bans = [];
        foreach ($supported && is_array($raw['items'] ?? null) ? $raw['items'] : [] as $item) {
            if (!is_array($item) || !is_string($item['id'] ?? null) || !preg_match('/^[a-f0-9]{16}$/', $item['id'])) continue;
            $sources = is_array($item['sources'] ?? null) ? array_slice(array_filter($item['sources'], 'is_string'), 0, 32) : [];
            $effectiveSources = is_array($item['effective_sources'] ?? null)
                ? array_slice(array_filter($item['effective_sources'], 'is_string'), 0, 64) : [];
            $sourceFailures = is_array($item['source_resolution_failures'] ?? null)
                ? array_slice(array_filter($item['source_resolution_failures'], 'is_string'), 0, 32) : [];
            $endpoint = null;
            if (is_array($item['verified_endpoint'] ?? null) && is_string($item['verified_endpoint']['address'] ?? null)
                && filter_var($item['verified_endpoint']['address'], FILTER_VALIDATE_IP) !== false
                && is_int($item['verified_endpoint']['port'] ?? null)
                && $item['verified_endpoint']['port'] >= 1 && $item['verified_endpoint']['port'] <= 65535) {
                $endpoint = ['address' => $item['verified_endpoint']['address'], 'port' => $item['verified_endpoint']['port']];
            }
            $lastHandshake = is_int($item['last_handshake'] ?? null) && $item['last_handshake'] >= 0
                ? $item['last_handshake'] : null;
            $items[] = ['id' => $item['id'], 'name' => substr((string)($item['name'] ?? ''), 0, 64), 'address' => substr((string)($item['address'] ?? ''), 0, 18),
                'mode' => ($item['mode'] ?? '') === 'persistent' ? 'persistent' : 'temporary', 'ssh' => ($item['ssh'] ?? false) === true,
                'locked' => ($item['locked'] ?? false) === true, 'sources' => $sources,
                'effective_sources' => $effectiveSources, 'source_resolution_failures' => $sourceFailures,
                'listener_port' => is_int($item['listener_port'] ?? null) && $item['listener_port'] >= 1024 && $item['listener_port'] <= 65535
                    ? $item['listener_port'] : (is_int($raw['listen_port'] ?? null) ? $raw['listen_port'] : null),
                'ssh_managed' => ($item['ssh_managed'] ?? false) === true,
                    'ssh_request_pending' => ($item['ssh_request_pending'] ?? false) === true,
                'unlock_request_pending' => ($item['unlock_request_pending'] ?? false) === true,
                'sources_request_pending' => ($item['sources_request_pending'] ?? false) === true,
                'requested_sources' => is_array($item['requested_sources'] ?? null)
                    ? array_slice(array_filter($item['requested_sources'], 'is_string'), 0, 32) : [],
                'ssh_user' => is_string($item['ssh_user'] ?? null) && preg_match('/^[a-z_][a-z0-9_-]{0,31}$/D', $item['ssh_user']) === 1 ? $item['ssh_user'] : '',
                'ssh_port' => is_int($item['ssh_port'] ?? null) && $item['ssh_port'] >= 1 && $item['ssh_port'] <= 65535 ? $item['ssh_port'] : null,
                'expires_at' => is_int($item['expires_at'] ?? null) ? $item['expires_at'] : null,
                'last_handshake' => $lastHandshake,
                'current_source_verified' => $lastHandshake !== null && $lastHandshake > 0 && $lastHandshake >= time() - 180 && $endpoint !== null,
                'session_active' => ($item['session_active'] ?? false) === true,
                'session_expires_at' => is_int($item['session_expires_at'] ?? null) ? $item['session_expires_at'] : null,
                'verified_endpoint' => $endpoint,
                'fingerprint' => substr((string)($item['fingerprint'] ?? ''), 0, 40)];
        }
        foreach ($supported && is_array($raw['bans'] ?? null) ? $raw['bans'] : [] as $ban) {
            if (!is_array($ban) || !is_string($ban['id'] ?? null) || preg_match('/^[a-f0-9]{16}$/D', $ban['id']) !== 1
                || !is_string($ban['source'] ?? null) || !is_string($ban['reason'] ?? null)) continue;
            $parts = explode('/', $ban['source']);
            if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false
                || (isset($parts[1]) && (!ctype_digit($parts[1])
                    || (strpos($parts[0], ':') === false ? (int)$parts[1] > 32 : (int)$parts[1] > 128)))) continue;
            $bans[] = ['id' => $ban['id'], 'source' => substr($ban['source'], 0, 64),
                'reason' => substr($ban['reason'], 0, 160),
                'expires_at' => is_int($ban['expires_at'] ?? null) ? $ban['expires_at'] : null,
                'active' => ($ban['active'] ?? false) === true];
        }
        $requirements = [];
        foreach ($supported && is_array($raw['requirements'] ?? null) ? $raw['requirements'] : [] as $name => $value) {
            if (is_string($name)) $requirements[substr($name, 0, 20)] = $value === true;
        }
        $sshAccounts = [];
        foreach ($supported && is_array($raw['ssh_accounts'] ?? null) ? $raw['ssh_accounts'] : [] as $account) {
            if (is_string($account) && preg_match('/^[a-z_][a-z0-9_-]{0,31}$/D', $account) === 1) {
                $sshAccounts[] = $account;
            }
        }
        // Brokers before the FreePBX Firewall integration do not report it ("unknown"): rerun the root bootstrap.
        $integration = $supported && is_array($raw['firewall_integration'] ?? null) ? $raw['firewall_integration'] : [];
        $integrationState = in_array($integration['state'] ?? null, ['inactive', 'active', 'not-detected', 'error'], true) ? $integration['state'] : 'unknown';
        $firewallIntegration = ['state' => $integrationState,
            'message' => is_string($integration['message'] ?? null) ? substr($integration['message'], 0, 500) : '',
            'backend' => in_array($integration['backend'] ?? null, ['nf_tables', 'legacy'], true) ? $integration['backend'] : null];
        $web = [];
        foreach ($supported && is_array($raw['web'] ?? null) ? $raw['web'] : [] as $entry) {
            if (is_array($entry) && in_array($entry['scheme'] ?? null, ['http', 'https'], true)
                && is_int($entry['port'] ?? null) && $entry['port'] >= 1 && $entry['port'] <= 65535) {
                $web[] = ['scheme' => $entry['scheme'], 'port' => $entry['port'],
                    'listening' => is_bool($entry['listening'] ?? null) ? $entry['listening'] : null];
            }
        }
        return ['supported' => $supported, 'ready' => $supported && $raw['ready'] === true && !in_array(false, $requirements, true) && ($status['enabled'] ?? true) === true, 'requirements' => $requirements,
            'connection_state' => in_array($raw['connection_state'] ?? null, ['open', 'closed', 'frozen'], true) ? $raw['connection_state'] : null,
            'policy_supported' => self::supportsWorkstationPolicy($support),
            'ban_supported' => $supported && ($status['protocol'] ?? 0) >= self::BAN_PROTOCOL,
            'session_supported' => self::supportsWorkstationSessions($support),
            'management_supported' => self::supportsWorkstationManagement($support),
            'max_sessions' => self::supportsWorkstationSessions($support) ? $raw['max_sessions'] : null,
            'connected_workstations' => self::supportsWorkstationSessions($support) ? $raw['connected_workstations'] : null,
            'ssh_ready' => $supported && ($status['protocol'] ?? 0) >= self::SSH_PROTOCOL && ($raw['ssh_ready'] ?? false) === true,
            'ssh_accounts' => array_values(array_unique($sshAccounts)),
            'ssh_error' => $supported && is_string($raw['ssh_error'] ?? null) ? substr($raw['ssh_error'], 0, 500) : '',
            'error' => $supported && is_string($raw['error'] ?? null) ? substr($raw['error'], 0, 500) : '',
            'firewall_integration' => $firewallIntegration,
            'web' => $web, 'web_supported' => $supported && ($status['protocol'] ?? 0) >= self::WEB_PROTOCOL,
            'gui_url' => $supported && is_string($raw['gui_url'] ?? null)
                && preg_match('#^https?://[0-9.]{7,15}(:[0-9]{1,5})?/admin/$#D', $raw['gui_url']) === 1 ? $raw['gui_url'] : null,
            'listen_port' => $supported && is_int($raw['listen_port'] ?? null) ? $raw['listen_port'] : null,
            'bans' => $bans, 'items' => $items];
    }

    public static function validPairingResponse($value): bool
    {
        return is_string($value) && preg_match('/^TELIPHONES-PAIR-RESPONSE-[12]:[A-Za-z0-9_-]{20,16000}$/D', $value) === 1;
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
