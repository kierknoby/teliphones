<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }
require_once __DIR__ . '/BrokerBootstrap.php';

// Non-root Module Admin installation completes without the root broker; it is
// established once by root with BrokerBootstrap::ROOT_BOOTSTRAP_SCRIPT
// (README: Complete Installation on FreePBX 17).
\FreePBX\modules\Teliphones\BrokerBootstrap::install(__DIR__);
