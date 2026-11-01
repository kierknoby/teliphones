<?php
namespace FreePBX\modules;

use BMO;

class Teliphones extends BMO
{
    private const STATE_FILE = '/var/lib/teliphones/session.json';
    private const DISABLED_FILE = '/var/lib/teliphones/disabled';

    public function __construct($freepbx = null) { parent::__construct($freepbx); }

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
    public function guiCanAuthorise(): bool { return false; }
}
