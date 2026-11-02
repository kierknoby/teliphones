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
     * Verified on Debian 12 / FreePBX 17. Must be run from an existing root shell.
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
    public const UPGRADE_NOTE = 'A Module Admin upgrade updates the FreePBX module files but does not necessarily update the separately installed, root-owned broker (`/usr/local/lib/teliphones-broker/support_broker.py`), because Module Admin runs as the web service account. After every TELIPHONES upgrade, confirm that no support session is active (as root: `fwconsole teliphones status`), then rerun the root bootstrap procedure from an existing root shell and refresh Connectivity > TELIPHONES. TELIPHONES 0.3.0 requires broker protocol 3 with valid workstation pairing status for Windows workstation operations and automatic monitoring; the 0.1.3 package supplied protocol 2. Until the broker is updated, the page reports **Root broker update required**, workstation operations are refused, and remote support actions fall back to ordinary page submission without automatic progress updates. Disconnect Windows tunnels before the bootstrap; valid pairings are restored when the broker restarts, without extending temporary expiry.';

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
            @file_put_contents($config, "; TELIPHONES 0.3.0 development configuration\n; Support transport is temporary and session-scoped.\n; On-PBX uses local ephemeral WireGuard. On-net/Off-net require an external Connect implementation.\n");
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
        if (is_link($brokerFile) || !copy($moduleDir . '/support_broker.py', $brokerFile) || !chown($brokerFile, 0) || !chmod($brokerFile, 0600)) {
            throw new \RuntimeException('Unable to install the root-owned TELIPHONES broker.');
        }
        $brokerService = self::BROKER_UNIT;
        if (is_link($brokerService) || file_put_contents($brokerService, self::BROKER_UNIT_CONTENTS . "\n", LOCK_EX) === false || !chown($brokerService, 0) || !chmod($brokerService, 0644)) {
            throw new \RuntimeException('Unable to install the TELIPHONES broker service.');
        }
        exec('/usr/bin/systemctl daemon-reload 2>&1', $brokerOutput, $brokerResult);
        if ($brokerResult !== 0) throw new \RuntimeException('Unable to reload systemd for TELIPHONES broker.');
        exec('/usr/bin/systemctl enable teliphones-broker.service 2>&1', $brokerOutput, $brokerResult);
        if ($brokerResult !== 0) throw new \RuntimeException('Unable to enable TELIPHONES broker.');
        exec('/usr/bin/systemctl restart teliphones-broker.service 2>&1', $brokerOutput, $brokerResult);
        if ($brokerResult !== 0) throw new \RuntimeException('Unable to start TELIPHONES broker.');
        return true;
    }
}
