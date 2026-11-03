<?php
namespace FreePBX\modules\Teliphones;

/**
 * Root bootstrap used by Module Admin installation and by the verified manual
 * root procedure in ROOT_BOOTSTRAP_SCRIPT.
 */
class BrokerBootstrap
{
    public const STATE_DIR = '/var/lib/teliphones';
    public const CONFIG = '/etc/teliphones.conf';
    public const CONNECT_CONFIG = '/etc/teliphones-connect.conf';
    public const RECONCILE_UNIT = '/etc/systemd/system/teliphones-reconcile.service';
    public const BROKER_DIR = '/usr/local/lib/teliphones-broker';
    public const BROKER_FILE = '/usr/local/lib/teliphones-broker/support_broker.py';
    public const BROKER_UNIT = '/etc/systemd/system/teliphones-broker.service';
    public const SERVICE = 'teliphones-broker.service';
    public const SOCKET = '/run/teliphones/control.sock';

    /**
     * For Debian 12 / FreePBX 17, from an existing root shell.
     * The 0.4.0 upgrade/rollback lifecycle still requires disposable-host validation.
     * README.md must contain this text verbatim (enforced by tests/web-support.php).
     */
    public const ROOT_BOOTSTRAP_SCRIPT = <<<'SCRIPT'
(
set -eu

SRC=/var/www/html/admin/modules/teliphones
DEST=/root/teliphones-bootstrap

test "$(id -u)" -eq 0
test -f "$SRC/install.php"
test -f "$SRC/support_broker.py"
test -f "$SRC/ssh_authority.py"

mkdir -p "$DEST"
cp -a "$SRC"/. "$DEST"/

chown -R root:root "$DEST"
chmod -R go-w "$DEST"

php -r 'define("FREEPBX_IS_AUTH", true); require "/root/teliphones-bootstrap/install.php";'

systemctl is-active teliphones-broker.service

for i in $(seq 1 30); do
    test -S /run/teliphones/control.sock && break
    sleep 1
done

test -S /run/teliphones/control.sock

echo "TELIPHONES broker is ready."
)
SCRIPT;

    /** Shared by the GUI and README; tests require both to contain this text verbatim. */
    public const UPGRADE_NOTE = 'A Module Admin upgrade updates the FreePBX module files but does not necessarily update the separately installed, root-owned broker. TELIPHONES 0.4.0 requires broker protocol 5 and both `/usr/local/lib/teliphones-broker/support_broker.py` and `/usr/local/lib/teliphones-broker/ssh_authority.py`; an older broker or a missing SSH helper cannot provide managed SSH. Confirm that no support session is active (as root: `fwconsole teliphones status`), disconnect Windows tunnels and expect existing TELIPHONES-managed SSH sessions to terminate, then rerun the root bootstrap from an existing root shell. The bootstrap retains the previous helper files and broker unit, validates the installed helpers, and enables and restarts `teliphones-broker.service`. Verify that service is active, `/run/teliphones/control.sock` exists, and the refreshed Connectivity > TELIPHONES page reports the current broker and managed SSH readiness. On failure, rollback attempts to restore prior files and the previous enabled/active state; an incomplete rollback is an error requiring recovery from the existing root shell. Do not restart, reconfigure or disable the normal system SSH service or change administrator accounts. Valid pairings retain their original deadlines; legacy SSH pairings need explicit re-pairing for managed SSH.';

    public const RECONCILE_UNIT_CONTENTS = <<<'UNIT'
[Unit]
Description=TELIPHONES support authority reconciliation
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/fwconsole teliphones reconcile

[Install]
WantedBy=multi-user.target
UNIT;

    public const BROKER_UNIT_CONTENTS = <<<'UNIT'
[Unit]
Description=TELIPHONES restricted GUI support broker
After=network.target teliphones-reconcile.service

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/teliphones-broker/support_broker.py
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
UNIT;

    /** Refuse web-owned helpers, including symlinks or writable ancestor directories. */
    public static function trustedBroker(string $path): bool
    {
        if (!is_file($path)) return false;
        do {
            clearstatcache(true, $path);
            if (is_link($path) || fileowner($path) !== 0 || (fileperms($path) & 0022) !== 0) return false;
            $parent = dirname($path);
            if ($parent === $path) break;
            $path = $parent;
        } while (true);
        return true;
    }

    public static function uninstallWorkstations(): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            throw new \RuntimeException('TELIPHONES uninstall requires root verified cleanup; no state or broker files were removed. Use an existing root shell.');
        }
        if (!self::trustedBroker(self::BROKER_FILE) || !is_executable('/usr/bin/systemctl')
            || !is_executable('/usr/bin/python3') || !is_executable('/usr/bin/timeout')) {
            throw new \RuntimeException('Trusted installed TELIPHONES broker, systemd, Python and timeout are required for uninstall. Restore the root-owned broker before retrying; recovery files retained.');
        }
        $helper = file_get_contents(self::BROKER_FILE);
        if ($helper === false || strpos($helper, 'if sys.argv[1:] == ["--uninstall-workstations"]:') === false
            || strpos($helper, 'WORKSTATION_OWNER = "TELIPHONES workstation enforcement v1"') === false) {
            throw new \RuntimeException('Installed root broker lacks verified workstation teardown. Update it using the trusted root bootstrap before uninstall; no cleanup was attempted.');
        }
        exec('/usr/bin/systemctl disable --now teliphones-broker.service 2>&1', $output, $result);
        if ($result !== 0) throw new \RuntimeException('TELIPHONES broker could not be stopped; recovery files retained.');
        $state = [];
        exec('/usr/bin/systemctl show teliphones-broker.service --property=ActiveState --property=MainPID --property=ControlPID --property=KillMode 2>&1', $state, $result);
        $values = [];
        foreach ($state as $line) {
            $pair = explode('=', $line, 2);
            if (count($pair) === 2) $values[$pair[0]] = $pair[1];
        }
        if ($result !== 0 || !in_array($values['ActiveState'] ?? '', ['inactive', 'failed'], true)
            || ($values['MainPID'] ?? '') !== '0' || ($values['ControlPID'] ?? '') !== '0'
            || ($values['KillMode'] ?? '') !== 'control-group') {
            throw new \RuntimeException('TELIPHONES broker stop could not be verified; recovery files retained.');
        }
        // -I excludes web-owned cwd/PYTHONPATH; bounded cleanup failures retain recovery artifacts.
        exec('/usr/bin/timeout 30 /usr/bin/python3 -I ' . escapeshellarg(self::BROKER_FILE) . ' --uninstall-workstations 2>&1', $cleanup, $result);
        if ($result !== 0) {
            throw new \RuntimeException('TELIPHONES workstation teardown unverified; rules, keys, state and broker retained. Repair the root broker/network tools and retry.');
        }
    }

    /**
     * Returns true when the root broker was installed and started, false when
     * root bootstrap was skipped. Throws when a root bootstrap step fails.
     */
    public static function install(string $moduleDir): bool
    {
        $dir = self::STATE_DIR;
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        @chmod($dir, 0700);
        $config = self::CONFIG;
        if (!file_exists($config)) {
            @file_put_contents($config, "; TELIPHONES 0.4.0 development configuration\n; Support transport is temporary and session-scoped.\n; On-PBX uses local ephemeral WireGuard. On-net/Off-net require an external Connect implementation.\n");
            @chmod($config, 0600);
        }

        $connectConfig = self::CONNECT_CONFIG;
        if (!file_exists($connectConfig)) {
            @file_put_contents($connectConfig, "; TELIPHONES Connect enrollment\n; Configure an implementation of the published Connect contract.\nCONNECT_URL=\nCLIENT_CERT=/etc/teliphones/connect-client.crt\nCLIENT_KEY=/etc/teliphones/connect-client.key\nCA_CERT=/etc/teliphones/connect-ca.crt\n");
            @chmod($connectConfig, 0600);
        }

        // TELIPHONES is enabled by default. A root-created disabled marker is preserved across upgrades.
        $service = self::RECONCILE_UNIT;
        $unit = self::RECONCILE_UNIT_CONTENTS;
        if (!file_exists($service) || file_get_contents($service) !== $unit . "\n") {
            @file_put_contents($service, $unit . "\n", LOCK_EX);
            @chmod($service, 0644);
        }
        if (is_executable('/usr/bin/systemctl')) {
            @exec('/usr/bin/systemctl daemon-reload >/dev/null 2>&1');
            @exec('/usr/bin/systemctl enable teliphones-reconcile.service >/dev/null 2>&1');
        }

        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            error_log('TELIPHONES: GUI root broker not installed. Module Admin installation is not running as root; no privilege escalation will be attempted. Complete the one-time root bootstrap: see Complete Installation on FreePBX 17 in the module README.');
            return false;
        }
        if (!is_executable('/usr/bin/python3') || !is_executable('/usr/bin/systemctl') || !function_exists('posix_getpwnam') || !posix_getpwnam('asterisk')) {
            error_log('TELIPHONES: GUI root broker requires systemd, Python 3 and the FreePBX asterisk account.');
            return false;
        }
        if (is_link($dir) || !chown($dir, 0) || !chmod($dir, 0700)) {
            throw new \RuntimeException('TELIPHONES state directory must be root-owned and private.');
        }
        foreach ([$config, $connectConfig] as $protectedConfig) {
            if (is_link($protectedConfig) || !chown($protectedConfig, 0) || !chmod($protectedConfig, 0600)) {
                throw new \RuntimeException('TELIPHONES configuration must be root-owned and private.');
            }
        }
        $brokerDirectory = self::BROKER_DIR;
        if (is_link($brokerDirectory) || (!is_dir($brokerDirectory) && !mkdir($brokerDirectory, 0700, true))
            || fileowner($brokerDirectory) !== 0 || (fileperms($brokerDirectory) & 0022) !== 0) {
            throw new \RuntimeException('TELIPHONES broker directory must be root-owned and not writable by group or other users.');
        }
        $brokerFile = self::BROKER_FILE;
        $sshHelper = $brokerDirectory . '/ssh_authority.py';
        $brokerService = self::BROKER_UNIT;
        $previous = [];
        foreach ([$brokerFile, $sshHelper, $brokerService] as $path) {
            if (is_link($path) || (file_exists($path) && !self::trustedBroker($path))) {
                throw new \RuntimeException('Existing TELIPHONES broker artifact is not safely root-owned.');
            }
            $previous[$path] = file_exists($path) ? file_get_contents($path) : null;
            if ($previous[$path] === false) throw new \RuntimeException('Unable to retain the previous broker for rollback.');
        }
        exec('/usr/bin/systemctl is-active --quiet teliphones-broker.service', $unused, $activeResult);
        $wasActive = $activeResult === 0;
        exec('/usr/bin/systemctl is-enabled --quiet teliphones-broker.service', $unused, $enabledResult);
        $wasEnabled = $enabledResult === 0;
        try {
            if ($wasActive) {
                exec('/usr/bin/systemctl stop teliphones-broker.service 2>&1', $unused, $stopResult);
                if ($stopResult !== 0) throw new \RuntimeException('Unable to stop the existing TELIPHONES broker safely.');
            }
            if (!copy($moduleDir . '/support_broker.py', $brokerFile) || !chown($brokerFile, 0) || !chmod($brokerFile, 0600)
                || !copy($moduleDir . '/ssh_authority.py', $sshHelper) || !chown($sshHelper, 0) || !chmod($sshHelper, 0600)) {
                throw new \RuntimeException('Unable to install the root-owned TELIPHONES broker and SSH authority.');
            }
            $check = 'import runpy,sys; runpy.run_path(sys.argv[1], run_name="teliphones_validation")';
            exec('/usr/bin/python3 -B -I -c ' . escapeshellarg($check) . ' ' . escapeshellarg($brokerFile) . ' 2>&1', $unused, $checkResult);
            if ($checkResult !== 0) throw new \RuntimeException('The installed TELIPHONES broker failed import validation.');
            if (file_put_contents($brokerService, self::BROKER_UNIT_CONTENTS . "\n", LOCK_EX) === false
                || !chown($brokerService, 0) || !chmod($brokerService, 0644)) {
                throw new \RuntimeException('Unable to install the TELIPHONES broker service.');
            }
            foreach (['daemon-reload', 'enable teliphones-broker.service', 'restart teliphones-broker.service',
                'is-active --quiet teliphones-broker.service'] as $operation) {
                exec('/usr/bin/systemctl ' . $operation . ' 2>&1', $unused, $result);
                if ($result !== 0) throw new \RuntimeException('TELIPHONES broker activation failed: ' . $operation);
            }
        } catch (\Throwable $error) {
            exec('/usr/bin/systemctl stop teliphones-broker.service 2>&1', $unused, $stopResult);
            $restored = $stopResult === 0 || !$wasActive;
            if (!$wasEnabled) {
                exec('/usr/bin/systemctl disable teliphones-broker.service 2>&1', $unused, $disableResult);
                $restored = $restored && $disableResult === 0;
            }
            foreach ($previous as $path => $content) {
                if ($content === null) {
                    if (file_exists($path) && !unlink($path)) $restored = false;
                } elseif (file_put_contents($path, $content, LOCK_EX) === false || !chown($path, 0)
                    || !chmod($path, $path === $brokerService ? 0644 : 0600)) {
                    $restored = false;
                }
            }
            exec('/usr/bin/systemctl daemon-reload 2>&1', $unused, $reloadResult);
            if ($wasActive && $restored && $reloadResult === 0) {
                exec('/usr/bin/systemctl restart teliphones-broker.service 2>&1', $unused, $restoreResult);
                $restored = $restoreResult === 0;
            }
            throw new \RuntimeException($error->getMessage() . ($restored && $reloadResult === 0
                ? ' Previous broker files restored; system SSH and administrator accounts were not changed.'
                : ' Broker rollback is incomplete: repair from an existing root shell; system SSH was not changed.'), 0, $error);
        }
        return true;
    }
}
