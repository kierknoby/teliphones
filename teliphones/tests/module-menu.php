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
    (string)$module->category === 'Connectivity',
    count($menuItems) === 1,
    isset($module->menuitems->teliphones),
    is_string($pageSource) && strpos($pageSource, "defined('FREEPBX_IS_AUTH')") !== false,
];

if (in_array(false, $assertions, true)) {
    throw new RuntimeException('TELIPHONES module identity, Connectivity menu, unique item or page auth guard is invalid.');
}

echo "Module menu metadata tests: PASS (Connectivity category, unique TELIPHONES item, auth-guarded page)\n";