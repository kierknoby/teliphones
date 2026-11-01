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
    (string)$module->version === '0.1.3',
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

echo "Module metadata tests: PASS (version, CLI identity, Connectivity menu, auth-guarded page)\n";