<?php
namespace FreePBX\modules\Teliphones;

/**
 * Generic HTTPS/mTLS client for an enrolled TELIPHONES Connect implementation.
 * TELIPHONES knows only the published Connect contract, not provider internals.
 */
class ConnectClient
{
    private const CONFIG='/etc/teliphones-connect.conf';
    private const STATE='/var/lib/teliphones/connect.json';

    public function ready(): bool
    {
        $c=$this->config();
        return function_exists('curl_init') && $c && !empty($c['CONNECT_URL']) && !empty($c['CLIENT_CERT']) && !empty($c['CLIENT_KEY']) && !empty($c['CA_CERT'])
            && is_readable($c['CLIENT_CERT']) && is_readable($c['CLIENT_KEY']) && is_readable($c['CA_CERT']);
    }

    public function provision(array $session,string $pbxWgPublicKey): ?array
    {
        if(!$this->ready()) return null;
        $topology=(string)($session['topology']??'on-pbx');
        if($topology==='on-pbx' && $pbxWgPublicKey==='') return null;
        $payload=['protocol'=>'teliphones-connect/1','action'=>'provision','session_id'=>$session['session_id']??'',
            'expires_at'=>$session['expires_at']??0,'topology'=>$session['topology']??'on-pbx','freepbx_major'=>$session['freepbx_major']??17,
            'preferred_pool'=>$session['preferred_pool']??'10.20.17.0/24','pbx_wg_public_key'=>$topology==='on-pbx'?$pbxWgPublicKey:null,
            'pbx_tunnel_address'=>$session['addresses']['pbx']??null,'support_tunnel_address'=>$session['addresses']['peer']??null];
        $r=$this->request('/v1/support-sessions', $payload);
        if(!$this->validProvisionResponse($r,$session)) return null;
        $safe=['session_id'=>$session['session_id'],'topology'=>$session['topology']??'on-pbx','remote_id'=>$r['remote_id'],'peer_public_key'=>$r['peer_public_key']??null,
            'peer_endpoint'=>$r['peer_endpoint']??null,'attestation_port'=>(int)($r['attestation_port']??8443),
            'ssh_public_key'=>$r['ssh_public_key']??null,'engineer_addresses'=>$r['engineer_addresses']??[],
            'checker_addresses'=>$r['checker_addresses']??[],
            'ssh_engineer_address'=>$r['ssh_engineer_address']??null,
            'gateway_address'=>$r['gateway_address']??null,'reference_only'=>(bool)($r['reference_only']??false),
            'remote_expires_at'=>(int)$r['expires_at'],'provisioned_at'=>time()];
        return $this->write($safe) ? $safe : null;
    }

    public function destroy(array $session): bool
    {
        $s=$this->state();
        if(!$s || empty($s['remote_id'])) { @unlink(self::STATE); return true; }
        if(!$this->ready()) return false;
        $r=$this->request('/v1/support-sessions/destroy',['protocol'=>'teliphones-connect/1','action'=>'destroy','session_id'=>$session['session_id']??'','remote_id'=>$s['remote_id']]);
        $ok=is_array($r) && ($r['destroyed']??false)===true;
        if($ok) @unlink(self::STATE);
        return $ok;
    }

    public function confirm(array $session): bool
    {
        return $this->sessionAction('/v1/support-sessions/confirm', $session, 'confirm');
    }

    public function activate(array $session): bool
    {
        return $this->sessionAction('/v1/support-sessions/activate', $session, 'activate');
    }

    public function forget(): void { @unlink(self::STATE); }
    public function state(): ?array { return $this->readJson(self::STATE); }

    private function request(string $path,array $payload): ?array
    {
        $c=$this->config(); if(!$c)return null;
        $payload['request_id']=bin2hex(random_bytes(32));
        $payload['request_timestamp']=time();
        $url=rtrim($c['CONNECT_URL'],'/').$path;
        $ch=curl_init($url);
        curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>30,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_SLASHES),
            CURLOPT_SSLCERT=>$c['CLIENT_CERT'],CURLOPT_SSLKEY=>$c['CLIENT_KEY'],CURLOPT_CAINFO=>$c['CA_CERT'],CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2]);
        $body=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE); curl_close($ch);
        if($body===false || $code<200 || $code>=300)return null;
        $v=json_decode((string)$body,true); return is_array($v)?$v:null;
    }

    private function validProvisionResponse(?array $r,array $session): bool
    {
        if(!$r || ($r['protocol']??'')!=='teliphones-connect/1' || !hash_equals((string)($session['session_id']??''),(string)($r['session_id']??'')))return false;
        if(!preg_match('/^[a-f0-9]{32}$/',(string)($r['remote_id']??'')))return false;
        if(($session['topology']??'on-pbx')==='on-pbx') {
            if(empty($r['peer_public_key'])||!$this->validWireGuardKey((string)$r['peer_public_key'])||empty($r['peer_endpoint'])||!$this->validEndpoint((string)$r['peer_endpoint'])||empty($r['ssh_public_key']))return false;
            if(!hash_equals((string)($session['addresses']['peer']??''),(string)($r['gateway_address']??'')))return false;
            $routes=$r['engineer_addresses']??null;
            if(!is_array($routes)||count($routes)<1||count($routes)>32)return false;
            $seen=[];
            foreach($routes as $route){
                if(!is_string($route)||!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',$route,$match)||filter_var($match[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||isset($seen[$match[1]]))return false;
                $seen[$match[1]]=true;
            }
            $checkerRoutes=$r['checker_addresses']??null;
            if(!is_array($checkerRoutes)||count($checkerRoutes)!==1||!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',(string)($checkerRoutes[0]??''),$checkerMatch)||filter_var($checkerMatch[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||isset($seen[$checkerMatch[1]]))return false;
            $sshAddress=(string)($r['ssh_engineer_address']??'');
            if(!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',$sshAddress,$sshMatch)||filter_var($sshMatch[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||!in_array($sshAddress,$routes,true))return false;
        }
        $exp=(int)($r['expires_at']??0); return $exp>time() && $exp<=(int)($session['expires_at']??0);
    }
    private function validWireGuardKey(string $key): bool { $decoded=base64_decode(trim($key),true); return $decoded!==false&&strlen($decoded)===32&&count(array_unique(str_split($decoded)))>1; }
    private function validEndpoint(string $endpoint): bool { return (bool)preg_match('/^(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$/',$endpoint,$match)&&(int)$match[1]<=65535; }
    private function sessionAction(string $path,array $session,string $action): bool
    {
        if(!$this->ready())return false;
        $state=$this->state();
        if(!$state||!hash_equals((string)($state['session_id']??''),(string)($session['session_id']??''))||empty($state['remote_id']))return false;
        $response=$this->request($path,['protocol'=>'teliphones-connect/1','action'=>$action,'session_id'=>$session['session_id'],'remote_id'=>$state['remote_id']]);
        return is_array($response)&&($response['protocol']??'')==='teliphones-connect/1'&&hash_equals((string)$session['session_id'],(string)($response['session_id']??''))&&($response['state']??'')===($action==='confirm'?'connected':'active');
    }
    private function config(): ?array
    {
        if(!is_readable(self::CONFIG))return null; $v=parse_ini_file(self::CONFIG,false,INI_SCANNER_RAW); return is_array($v)?$v:null;
    }
    private function readJson(string $f): ?array { if(!is_readable($f))return null;$v=json_decode((string)file_get_contents($f),true);return is_array($v)?$v:null; }
    private function write(array $v): bool { $tmp=self::STATE.'.tmp.'.getmypid();if(file_put_contents($tmp,json_encode($v,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false)return false;@chmod($tmp,0600);if(!@rename($tmp,self::STATE)){@unlink($tmp);return false;}return true; }
}
