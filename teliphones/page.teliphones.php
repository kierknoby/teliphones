<?php
if (!defined('FREEPBX_IS_AUTH')) { die('No direct script access allowed'); }
$state = FreePBX::Teliphones()->getState();
show_view(__DIR__ . '/views/main.php', ['state' => $state]);
