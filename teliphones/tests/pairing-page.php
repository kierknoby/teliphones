<?php
// Page-path fixture: status is modelled; pairing optionally uses the actual broker socket.
namespace FreePBX\modules\Teliphones {
    function stream_socket_client($address, &$errno, &$error, $timeout) {
        $GLOBALS['pageCalls']++;
        if ($GLOBALS['pageCalls'] === 2 && $GLOBALS['pageSocket'] !== '') {
            return \stream_socket_client('unix://' . $GLOBALS['pageSocket'], $errno, $error, $timeout);
        }
        $pair = \stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $response = $GLOBALS['pageCalls'] === 2
            ? ['ok' => false, 'error' => 'Modelled broker operation failure.']
            : ['ok' => true, 'status' => ['protocol' => 12, 'component_version' => WebSupport::BROKER_VERSION,
                'phase' => 'Ready', 'enabled' => true, 'readiness' => [],
                'workstations' => ['ready' => true, 'ssh_ready' => true, 'ssh_accounts' => ['administrator'],
                    'requirements' => ['wg' => true, 'ip' => true, 'nft' => true], 'items' => [],
                    'web' => [['scheme' => 'https', 'port' => 443]]]]];
        fwrite($pair[1], json_encode($response, JSON_THROW_ON_ERROR) . "\n");
        $GLOBALS['pagePeers'][] = $pair[1];
        return $pair[0];
    }
}

namespace {
    define('FREEPBX_IS_AUTH', true);
    $_POST = json_decode($argv[2] ?? '{}', true, 512, JSON_THROW_ON_ERROR);
    $_SESSION = ['AMP_user' => 'admin', 'teliphones_token' => 'pair-test-token'];
    $_SERVER = ['REQUEST_METHOD' => $_POST === [] ? 'GET' : 'POST', 'HTTPS' => 'on',
        'SERVER_PORT' => '443', 'SERVER_NAME' => 'pbx.example.net'];
    $ampuser = new class {
        public function checkSection($section) { return $section === '*' ? 1 : 0; }
    };
    $GLOBALS['pageCalls'] = 0;
    $GLOBALS['pagePeers'] = [];
    $GLOBALS['pageSocket'] = $argv[1] ?? '';
    function show_view($path, $variables) {
        $GLOBALS['pageNotice'] = $variables['notice'];
        extract($variables);
        include $path;
    }
    ob_start();
    include dirname(__DIR__) . '/page.teliphones.php';
    $html = ob_get_clean();
    $sent = [];
    foreach ($GLOBALS['pagePeers'] as $peer) {
        $sent[] = json_decode(fgets($peer), true, 512, JSON_THROW_ON_ERROR);
        fclose($peer);
    }
    $document = new \DOMDocument();
    libxml_use_internal_errors(true);
    $document->loadHTML($html);
    libxml_clear_errors();
    $xpath = new \DOMXPath($document);
    $elements = [];
    foreach ($xpath->query('//*[@id="teliphones-pair-panel"]//*[@id]') as $element) {
        $value = $element->getAttribute('value');
        if ($element->tagName === 'textarea') $value = $element->textContent;
        if ($element->tagName === 'select') {
            $options = $xpath->query('.//option[@selected]', $element);
            if ($options->length === 0) $options = $xpath->query('.//option', $element);
            $value = $options->item(0)->getAttribute('value');
        }
        $elements[] = ['id' => $element->getAttribute('id'), 'name' => $element->getAttribute('name'),
            'value' => $value, 'disabled' => $element->hasAttribute('disabled'),
            'hidden' => $element->hasAttribute('hidden'), 'required' => $element->hasAttribute('required'),
            'fieldsetDisabled' => $xpath->query('ancestor::fieldset[@disabled]', $element)->length > 0];
    }
    $script = '';
    foreach ($xpath->query('//script[not(@src)]') as $element) {
        if (str_contains($element->textContent, 'function updateRequest()')) $script = $element->textContent;
    }
    echo json_encode(['html' => $html, 'elements' => $elements, 'script' => $script,
        'notice' => $GLOBALS['pageNotice'], 'sent' => $sent, 'calls' => $GLOBALS['pageCalls']],
        JSON_THROW_ON_ERROR);
}
