<?php
require_once dirname(__DIR__) . '/WebSupport.php';
use FreePBX\modules\Teliphones\WebSupport;

$assert = static function (bool $value, string $message): void {
    if (!$value) throw new RuntimeException($message);
};
$now = time();
$item = ['id' => '0123456789abcdef', 'name' => '<Admin PC>', 'address' => '100.70.1.2/32',
    'fingerprint' => 'SHA256:fixture', 'mode' => 'persistent', 'ssh' => true, 'ssh_managed' => true,
    'ssh_user' => 'administrator', 'locked' => true, 'sources' => ['198.51.100.24'],
    'effective_sources' => ['198.51.100.24'], 'listener_port' => 51822,
    'last_handshake' => $now, 'verified_endpoint' => ['address' => '198.51.100.24', 'port' => 51821],
    'session_active' => true, 'session_expires_at' => $now + 60,
    'ssh_request_pending' => true, 'unlock_request_pending' => true, 'sources_request_pending' => true,
    'requested_sources' => ['2001:db8::/48']];
$fixture = ['ok' => true, 'status' => ['protocol' => 12, 'component_version' => '0.6.5', 'enabled' => true, 'phase' => 'Ready',
    'readiness' => ['WireGuard wg' => true, 'Temporary SSH server' => true,
        'Gateway enrollment' => true, 'Checker trusted public key' => true],
    'workstations' => ['ready' => true, 'requirements' => ['wg' => true, 'ip' => true, 'nft' => true],
        'ssh_ready' => true, 'ssh_accounts' => ['administrator'], 'connection_state' => 'open',
        'max_sessions' => 2, 'connected_workstations' => 1,
        'web' => [['scheme' => 'https', 'port' => 443, 'listening' => true]],
        'firewall_integration' => ['state' => 'active', 'message' => 'Scoped access only.', 'backend' => 'nf_tables'],
        'items' => [$item, array_replace($item, ['id' => 'fedcba9876543210', 'name' => 'Second PC', 'mode' => 'temporary',
            'expires_at' => $now + 3600, 'locked' => false, 'ssh' => false, 'ssh_managed' => false])],
        'bans' => [['id' => 'aaaaaaaaaaaaaaaa', 'source' => '203.0.113.24', 'reason' => '<blocked>',
            'active' => true, 'expires_at' => null]]]]];
$render = static function (array $support, ?array $notice = null, ?string $template = null): string {
    $token = 'layout-token';
    $broker = ['available' => true, 'condition' => 'operational'];
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = '443';
    $_SERVER['HTTP_HOST'] = 'pbx.example.test';
    ob_start();
    include $template ?? dirname(__DIR__) . '/views/support.php';
    return (string)ob_get_clean();
};
// Local, broker-free rendering for inspection or comparison with an extracted package.
if (($argv[1] ?? '') === '--render') {
    echo $render($fixture, null, $argv[2] ?? null);
    exit;
}
$parse = static function (string $html): DOMXPath {
    $document = new DOMDocument();
    $previous = libxml_use_internal_errors(true);
    try {
        if (!$document->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_NONET)) {
            throw new RuntimeException('Unable to parse administration HTML.');
        }
    } finally {
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
    }
    return new DOMXPath($document);
};
$html = $render($fixture);
$xpath = $parse($html);
$seen = [];
foreach ($xpath->query('//*[@id]') as $element) {
    $id = $element->getAttribute('id');
    $assert(!isset($seen[$id]), 'Duplicate element ID: ' . $id);
    $seen[$id] = true;
}
$assert($xpath->query('//form')->length === substr_count($html, '<form '), 'Forms must not be nested or lost by HTML parsing.');
foreach ($xpath->query('//label[@for]') as $label) {
    $assert(isset($seen[$label->getAttribute('for')]), 'Label must refer to an existing unique control.');
}
foreach (['System Readiness', 'Remote Support', 'Windows Workstation Access', 'Paired Workstations',
    'Security & Access Restrictions'] as $heading) {
    $assert($xpath->query('//section/h3[text()="' . $heading . '"]')->length === 1, 'Missing dedicated panel: ' . $heading);
}
$assert($xpath->query('//h2[text()="TELIPHONES 0.6.5"]')->length === 1,
    'The administration heading must use the authoritative module version.');
foreach (WebSupport::BROKER_ACTIONS as $action) {
    $buttons = $xpath->query('//button[@name="action" and @value="' . $action . '"]');
    $assert($buttons->length > 0, 'Missing existing action: ' . $action);
    foreach ($buttons as $button) {
        $form = $xpath->query('ancestor::form', $button)->item(0);
        $assert($form !== null && $form->getAttribute('method') === 'post', 'Action must remain inside a POST form.');
        $tokens = $xpath->query('.//input[@name="token"]', $form);
        $assert($tokens->length === 1 && $tokens->item(0)->getAttribute('value') === 'layout-token', 'Every action must retain its CSRF token.');
        foreach (WebSupport::PAIRING_FIELDS[$action] ?? [] as $name) {
            $assert($xpath->query('.//*[@name="' . $name . '"]', $form)->length > 0, 'Missing action field: ' . $action . '/' . $name);
        }
    }
}
$assert($xpath->query('//form[@id="teliphones-diagnostics-form"]//input[@name="token"]')->length === 1, 'Diagnostic lookup retains CSRF protection.');
$assert($xpath->query('//*[@id="teliphones-pair-panel"][@open]')->length === 0, 'Pairing is collapsed by default.');
$assert($xpath->query('//*[@id="teliphones-diagnostics"][@open]')->length === 0, 'Diagnostics are compact by default.');
$assert($xpath->query('//*[@id="teliphones-pair-fields"]//h4')->length === 5, 'Pairing retains five visible groups, not wizard steps.');
$assert(str_contains($html, '&lt;Admin PC&gt;') && str_contains($html, '&lt;blocked&gt;'), 'Workstation and ban text must remain escaped.');
$assert($xpath->query('//details//*[contains(@class,"alert-warning") and contains(.,"External firewall flushes")]')->length === 0,
    'Firewall exposure warning must not be collapsed.');
$assert($xpath->query('//*[@id="teliphones-banned-list"]/ancestor::details')->length === 0, 'Ban warnings and current bans remain visible.');

$empty = $fixture;
$empty['status']['workstations']['items'] = [];
$emptyHtml = $render($empty);
$assert(str_contains($emptyHtml, 'No workstations are paired.') && str_contains($emptyHtml, 'data-teliphones-open="teliphones-pair-panel"'),
    'Empty state must lead to the pairing action.');
foreach (['open', 'closed', 'frozen'] as $policy) {
    $policyFixture = $fixture;
    $policyFixture['status']['workstations']['connection_state'] = $policy;
    $policyXpath = $parse($render($policyFixture));
    $assert($policyXpath->query('//select[@name="state"]/option[@value="' . $policy . '" and @selected]')->length === 1,
        'The effective policy must remain selected: ' . $policy);
}
foreach (['pair' => 'teliphones-pair-panel', 'configure' => null] as $action => $id) {
    $_POST = ['action' => $action];
    $failed = $parse($render($fixture, ['ok' => false, 'error' => 'Invalid field.']));
    $selector = $id ? '//*[@id="' . $id . '"]' : '//details[@class="teliphones-enrollment"]';
    $assert($failed->query($selector . '[@open]')->length === 1, 'Failed submission must reveal its form: ' . $action);
}
$_POST = [];
$missing = $fixture;
$missing['status']['readiness']['Checker trusted public key'] = false;
$missingHtml = $render($missing);
$missingXpath = $parse($missingHtml);
$warnings = $missingXpath->query('//div[contains(@class,"alert-warning") and contains(.,"Other dependencies missing:")]');
$assert($warnings->length === 1 && str_contains($warnings->item(0)->textContent, 'Checker trusted public key')
    && !str_contains($warnings->item(0)->textContent, 'Missing PHP'), 'Configuration-only gaps must not imply unrelated dependency failures.');
$assert($missingXpath->query('//details//div[contains(.,"Other dependencies missing:")]')->length === 0, 'Missing readiness must remain visible.');
echo "Administration layout tests: PASS (all actions/fields, CSRF, unique IDs, labels, panels, escaping, policies, errors, empty state, readiness)\n";
