<?php
namespace FreePBX\modules\Teliphones;

class WebSupport
{
    public static function authorised(bool $authenticated, $administrator): bool
    {
        return $authenticated && is_object($administrator)
            && is_callable([$administrator, 'checkSection'])
            && $administrator->checkSection('*') === true;
    }

    public static function validRequest(array $request, string $token): bool
    {
        if (!isset($request['token'], $request['action']) || !is_string($request['token'])
            || !is_string($request['action']) || $token === '' || !hash_equals($token, $request['token'])) return false;
        return in_array($request['action'], ['authorise', 'revoke', 'dependencies', 'evidence', 'configure'], true);
    }

    public function request(array $request): array
    {
        $socket = @stream_socket_client('unix:///run/teliphones/control.sock', $errno, $error, 2);
        if ($socket === false) return ['ok' => false, 'error' => 'Privileged TELIPHONES broker unavailable. Module Admin must complete the root bootstrap; installing module files alone does not grant OS privileges.'];
        stream_set_timeout($socket, 5);
        $payload = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
        $offset = 0;
        while ($offset < strlen($payload)) {
            $written = fwrite($socket, substr($payload, $offset));
            if ($written === false || $written === 0) {
                fclose($socket);
                return ['ok' => false, 'error' => 'Unable to send the TELIPHONES request.'];
            }
            $offset += $written;
        }
        $line = fgets($socket, 131073);
        fclose($socket);
        $response = is_string($line) ? json_decode($line, true) : null;
        return is_array($response) ? $response : ['ok' => false, 'error' => 'TELIPHONES broker did not return a valid response. Refresh status before retrying.'];
    }
}
