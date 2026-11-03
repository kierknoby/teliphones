<?php
$moduleFile = dirname(__DIR__) . '/module.xml';
$module = simplexml_load_file($moduleFile);
if (!$module) {
    throw new RuntimeException('module.xml is not valid XML.');
}

$menuItems = $module->menuitems->children();
$pageFile = dirname(__DIR__) . '/page.teliphones.php';
$pageSource = is_readable($pageFile) ? file_get_contents($pageFile) : '';
$assertions = [
    (string)$module->rawname === 'teliphones',
    (string)$module->name === 'TELIPHONES',
    (string)$module->version === '0.4.0',
    (string)$module->category === 'Connectivity',
    count($menuItems) === 1,
    isset($module->menuitems->teliphones),
    (string)$module->menuitems->teliphones === 'TELIPHONES',
    (string)$module->console->command->name === 'teliphones',
    (string)$module->console->command->class === 'Teliphones',
    is_string($pageSource) && strpos($pageSource, "defined('FREEPBX_IS_AUTH')") !== false,
];

if (in_array(false, $assertions, true)) {
    throw new RuntimeException('TELIPHONES module identity, Connectivity menu, unique item or page auth guard is invalid.');
}

ob_start();
require dirname(__DIR__) . '/views/disclaimer.php';
$disclaimer = ob_get_clean();
foreach ([
    'TELIPHONES is a UK registered trademark.',
    'TELIPHONES ' . (string)$module->version . ' for FreePBX is licensed under GPLv3.',
    'does not grant trademark rights',
] as $statement) {
    if (strpos($disclaimer, $statement) === false) {
        throw new RuntimeException('The FreePBX trademark/licence disclaimer is missing: ' . $statement);
    }
}
foreach (['support', 'main'] as $view) {
    $viewSource = file_get_contents(dirname(__DIR__) . '/views/' . $view . '.php');
    $footerPosition = strpos($viewSource, "require __DIR__ . '/disclaimer.php'");
    if ($footerPosition === false || $footerPosition < strrpos($viewSource, '</form>')) {
        throw new RuntimeException('The disclaimer must appear in both FreePBX GUI views.');
    }
}
if (strpos($disclaimer, '<footer ') === false) {
    throw new RuntimeException('The module disclaimer must be a footer.');
}
foreach (['text-align:center', 'font-weight:normal', 'white-space:nowrap', 'padding:16px 0'] as $style) {
    if (strpos($disclaimer, $style) === false) {
        throw new RuntimeException('The footer must be a centred, padded, regular-weight single line.');
    }
}
if (strpos($disclaimer, '<strong>') !== false || strpos($disclaimer, '<br>') !== false) {
    throw new RuntimeException('The footer must not contain bold text or explicit line breaks.');
}
if ((string)$module->license !== 'GPLv3+') {
    throw new RuntimeException('The existing GPLv3-or-later licence grant must be preserved.');
}

echo "Module metadata tests: PASS (version, CLI identity, Connectivity menu, auth-guarded page)\n";