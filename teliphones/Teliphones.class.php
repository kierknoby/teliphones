<?php
namespace FreePBX\modules;

use BMO;
use FreePBX_Helpers;
use FreePBX\modules\Teliphones\WebSupport;

require_once __DIR__ . '/WebSupport.php';

class Teliphones extends FreePBX_Helpers implements BMO
{
    private const STATE_FILE = '/var/lib/teliphones/session.json';
    private const DISABLED_FILE = '/var/lib/teliphones/disabled';

    public function __construct($freepbx = null) { parent::__construct($freepbx); }

    public function install()
    {
        require_once __DIR__ . '/install.php';
    }

    public function uninstall()
    {
        require_once __DIR__ . '/uninstall.php';
    }

    public function doConfigPageInit($page): void
    {
    }

    /**
     * FreePBX ajax.php allowlist. Framework authentication is left enabled (no
     * $setting changes); ajaxHandler() additionally enforces full administrator access.
     */
    public function ajaxRequest($req, &$setting)
    {
        return in_array($req, ['status', 'action', 'diagnostics'], true);
    }

    public function ajaxHandler()
    {
        $result = WebSupport::ajax((string)($_REQUEST['command'] ?? ''), (string)($_SERVER['REQUEST_METHOD'] ?? ''), $_POST,
            is_array($_SESSION ?? null) ? $_SESSION : [], $GLOBALS['ampuser'] ?? null, $_SERVER, new WebSupport());
        if ($result['code'] !== 200) http_response_code($result['code']);
        return $result['body'];
    }

    public function getState(): array
    {
        if (!is_readable(self::STATE_FILE)) return ['state' => 'off', 'enabled' => $this->isEnabled()];
        $state = json_decode((string)file_get_contents(self::STATE_FILE), true);
        if (!is_array($state)) return ['state' => 'error', 'enabled' => $this->isEnabled(), 'reason' => 'invalid-state'];
        if (!empty($state['expires_at']) && time() >= (int)$state['expires_at']) return ['state' => 'off', 'enabled' => $this->isEnabled(), 'reason' => 'expired'];
        $state['enabled'] = $this->isEnabled();
        return $state;
    }

    public function isEnabled(): bool { return !is_file(self::DISABLED_FILE); }
    public function guiCanAuthorise(): bool
    {
        return defined('FREEPBX_IS_AUTH') && WebSupport::authorised($_SESSION['AMP_user'] ?? null, $GLOBALS['ampuser'] ?? null);
    }
}
