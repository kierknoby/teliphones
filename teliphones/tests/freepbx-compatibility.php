<?php
namespace {
    if (!interface_exists('BMO')) {
        eval('interface BMO { public function install(); public function uninstall(); }');
    }

    if (!class_exists('FreePBX_Helpers')) {
        eval('class FreePBX_Helpers { public function __construct($freepbx = null) {} }');
    }

    require_once dirname(__DIR__) . '/Teliphones.class.php';

    $assert = static function (bool $condition, string $message): void {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    };

    $moduleClass = new \ReflectionClass(\FreePBX\modules\Teliphones::class);
    $assert($moduleClass->getParentClass()->getName() === 'FreePBX_Helpers', 'TELIPHONES must extend FreePBX_Helpers.');
    $assert($moduleClass->implementsInterface('BMO'), 'TELIPHONES must implement BMO.');

    foreach (['install', 'uninstall', 'doConfigPageInit'] as $methodName) {
        $method = $moduleClass->getMethod($methodName);
        $assert($method->isPublic(), $methodName . '() must be public.');
    }

    $assert($moduleClass->getMethod('doConfigPageInit')->hasReturnType(), 'doConfigPageInit() must declare its void return type.');
    $assert((string)$moduleClass->getMethod('doConfigPageInit')->getReturnType() === 'void', 'doConfigPageInit() must return void.');

    $moduleSource = file_get_contents(dirname(__DIR__) . '/Teliphones.class.php');
    $assert(is_string($moduleSource), 'Unable to read the module class.');
    $assert(substr_count($moduleSource, "require_once __DIR__ . '/install.php';") === 1, 'Installation must delegate exactly once to the existing installer.');
    $assert(substr_count($moduleSource, "require_once __DIR__ . '/uninstall.php';") === 1, 'Uninstallation must delegate exactly once to the existing uninstaller.');
    $assert(strpos($moduleSource, 'public function guiCanAuthorise(): bool { return false; }') !== false, 'GUI authorisation must remain disabled.');

    $view = dirname(__DIR__) . '/views/main.php';
    $render = static function ($state, bool $provideState = true) use ($view): string {
        if (!$provideState) {
            unset($state);
        }
        ob_start();
        include $view;
        return (string)ob_get_clean();
    };

    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        throw new \ErrorException($message, 0, $severity, $file, $line);
    });
    try {
        $validHtml = $render([
            'enabled' => true,
            'state' => 'ready',
            'session_id' => '0123456789abcdef',
            'expires_at' => time() + 300,
            'topology_label' => 'On-PBX',
            'checker_accepted' => true,
        ]);
        $assert(strpos($validHtml, 'Session status: Ready') !== false, 'The template must render the supplied session state.');
        $assert(strpos($validHtml, 'Session: <code>0123456789abcdef</code>') !== false, 'The template must render the supplied session identifier.');
        $assert(strpos($validHtml, 'Verification: Verified') !== false, 'The template must render verification status.');

        $missingHtml = $render(null, false);
        $assert(strpos($missingHtml, 'TELIPHONES is disabled.') !== false, 'Missing view state must safely render the disabled status.');

        $invalidHtml = $render([
            'enabled' => true,
            'state' => [],
            'session_id' => [],
            'topology_label' => [],
            'topology' => [],
            'expires_at' => [],
        ]);
        $assert(strpos($invalidHtml, 'TELIPHONES is enabled.') !== false, 'Invalid optional state fields must not prevent rendering.');
        $assert(strpos($invalidHtml, 'Session status:') === false, 'Invalid session state must safely fall back to no session.');
    } finally {
        restore_error_handler();
    }

    $pageSource = file_get_contents(dirname(__DIR__) . '/page.teliphones.php');
    $assert(is_string($pageSource) && strpos($pageSource, "show_view(__DIR__ . '/views/main.php', ['state' => \$state]);") !== false, 'The page controller must pass state into the template.');

    $GLOBALS['teliphonesCompatibilityAssertions'] = $assert;
}

namespace Symfony\Component\Console\Command {
    if (!class_exists(Command::class)) {
        class Command
        {
            public function isEnabled(): bool
            {
                return true;
            }
        }
    }
}

namespace Symfony\Component\Console\Input {
    if (!interface_exists(InputInterface::class)) {
        interface InputInterface
        {
        }
    }

    if (!class_exists(InputArgument::class)) {
        class InputArgument
        {
            public const OPTIONAL = 1;
        }
    }

    if (!class_exists(InputOption::class)) {
        class InputOption
        {
            public const VALUE_REQUIRED = 2;
        }
    }
}

namespace Symfony\Component\Console\Output {
    if (!interface_exists(OutputInterface::class)) {
        interface OutputInterface
        {
        }
    }
}

namespace {
    require_once dirname(__DIR__) . '/Console/Teliphones.class.php';

    $assert = $GLOBALS['teliphonesCompatibilityAssertions'];
    $consoleClass = new \ReflectionClass(\FreePBX\Console\Command\Teliphones::class);
    $assert($consoleClass->getName() === \FreePBX\Console\Command\Teliphones::class, 'The TELIPHONES Console command must load.');

    $inheritedMethod = $consoleClass->getMethod('isEnabled');
    $assert($inheritedMethod->isPublic(), 'Symfony Console isEnabled() must remain public.');
    $assert($inheritedMethod->getDeclaringClass()->getName() === \Symfony\Component\Console\Command\Command::class, 'TELIPHONES must not override Symfony Console isEnabled().');

    $helper = $consoleClass->getMethod('isTeliphonesEnabled');
    $assert($helper->isPrivate(), 'The module-specific enabled-state helper must remain private.');
    $assert((string)$helper->getReturnType() === 'bool', 'The module-specific enabled-state helper must return bool.');

    echo "FreePBX compatibility tests: PASS (BMO lifecycle, GUI state, Symfony Console loading)\n";
}
