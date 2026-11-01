<?php
namespace FreePBX\modules\Teliphones;

/**
 * Local verifier only. External probing belongs to the Checker integration.
 */
class LocalAttestor
{
    private const FILE='/var/lib/teliphones/local-verification.json';
    private const IFACE='wg-teliphones';

    public function placeholder(array $state): bool { return $this->write($this->base($state)); }

    public function verify(array $session,array $wgState,array $peer): array
    {
        $r=$this->base($session); $r['checked_at']=time();
        if(($session['topology']??'on-pbx')!=='on-pbx') {
            $r['mode']='external-termination';
            $r['mandatory_checks']=['pbx_network_untouched'=>'pass','session_current'=>$this->sessionCurrent($session)?'pass':'fail'];
        } else {
            $pbxCidr=(string)($wgState['addresses']['pbx']??''); $peerCidr=(string)($wgState['addresses']['peer']??'');
            $r['mode']='on-pbx';
            $r['mandatory_checks']=[
                'session_current'=>$this->sessionCurrent($session)?'pass':'fail',
                'wireguard_peer_identity'=>$this->checkPeer($peer,$peerCidr)?'pass':'fail',
                'interface_containment'=>$this->commandContains('/usr/sbin/ip -o addr show dev '.self::IFACE,$pbxCidr)?'pass':'fail',
                'route_containment'=>$this->checkRoutes((string)($wgState['addresses']['peer_ip']??''),$pbxCidr)?'pass':'fail'
            ];
        }
        $r['verified']=!in_array('fail',$r['mandatory_checks'],true);
        $r['verified_at']=$r['verified']?time():null;
        $this->write($r); return $r;
    }

    public function destroy(): bool { return !is_file(self::FILE)||@unlink(self::FILE); }
    public function state(): ?array { return $this->read(self::FILE); }

    private function base(array $s): array { return ['protocol'=>'teliphones-local/1','session_id'=>$s['session_id']??null,'topology'=>$s['topology']??null,'mode'=>'pending','verified'=>false,'checked_at'=>time(),'mandatory_checks'=>[],'note'=>'TELIPHONES verifies only PBX-local invariants. External probing belongs to Checker.']; }
    private function sessionCurrent(array $s): bool { return !empty($s['session_id']) && (int)($s['expires_at']??0)>time(); }
    private function checkPeer(array $peer,string $peerCidr): bool { $wg=$this->wg(); if($wg===''||$peerCidr==='')return false; exec($wg.' show '.self::IFACE.' allowed-ips 2>/dev/null',$rows,$rc); if($rc!==0||count($rows)!==1)return false; $p=preg_split('/\s+/',trim($rows[0]),2); if(count($p)<2||$p[0]!==trim((string)($peer['public_key']??'')))return false; $actual=array_map('trim',explode(',',$p[1])); $expected=$peer['allowed_ips']??[$peerCidr]; if(!is_array($expected))return false; sort($actual); sort($expected); return $actual===$expected&&in_array($peerCidr,$expected,true); }
    private function checkRoutes(string $peerIp,string $pbxCidr): bool
    {
        if(filter_var($peerIp,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false || !preg_match('/^\d+\.\d+\.\d+\.\d+\/(\d{1,2})$/',$pbxCidr,$match))return false;
        $prefix=(int)$match[1]; if($prefix<30||$prefix>32)return false;
        exec('/usr/sbin/ip -o -4 route show dev '.self::IFACE.' 2>/dev/null',$rows,$rc);
        return $rc===0 && self::routeCoversPeer($rows,$peerIp,$prefix,self::IFACE);
    }

    public static function routeCoversPeer(array $routes,string $peerIp,int $minimumPrefix=30,string $interface=self::IFACE): bool
    {
        $peer=ip2long($peerIp);
        if($peer===false||$minimumPrefix<0||$minimumPrefix>32)return false;
        foreach($routes as $route){
            $parts=preg_split('/\s+/',trim($route));
            $deviceIndex=array_search('dev',$parts,true);
            if($deviceIndex===false||($parts[$deviceIndex+1]??'')!==$interface)continue;
            $destination=explode('/',$parts[0],2); $network=ip2long($destination[0]);
            $prefix=isset($destination[1])?(int)$destination[1]:32;
            if($network===false||$prefix<$minimumPrefix||$prefix>32)continue;
            $mask=$prefix===0?0:(-1<<(32-$prefix));
            if(($peer&$mask)===($network&$mask))return true;
        }
        return false;
    }
    private function commandContains(string $cmd,string $needle): bool { exec($cmd.' 2>/dev/null',$o,$r); return $r===0&&$needle!==''&&strpos(implode("\n",$o),$needle)!==false; }
    private function wg(): string { foreach(['/usr/bin/wg','/usr/sbin/wg']as$p)if(is_executable($p))return$p;return''; }
    private function read(string $f): ?array { if(!is_readable($f))return null;$v=json_decode((string)file_get_contents($f),true);return is_array($v)?$v:null; }
    private function write(array $p): bool { $t=self::FILE.'.tmp.'.getmypid();if(file_put_contents($t,json_encode($p,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false)return false;@chmod($t,0600);if(!@rename($t,self::FILE)){@unlink($t);return false;}return true; }
}
