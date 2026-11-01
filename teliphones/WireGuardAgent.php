<?php
namespace FreePBX\modules\Teliphones;
require_once __DIR__.'/Topology.php';

class WireGuardAgent
{
    private const DIR='/var/lib/teliphones/wireguard';
    private const STATE=self::DIR.'/state.json';
    private const PRIVATE_KEY=self::DIR.'/private.key';
    private const PUBLIC_KEY=self::DIR.'/public.key';
    private const PEER_FILE=self::DIR.'/peer.json';
    private const IFACE='wg-teliphones';

    public function prepare(array $session): bool
    {
        if(($session['topology']??Topology::ON_PBX)!==Topology::ON_PBX) return true; // external terminator; TELIPHONES must not alter PBX networking
        if(!$this->toolingReady()||!$this->ensureDir()) return false;
        $this->destroy(); if(!$this->ensureDir()) return false;
        $private=trim((string)shell_exec($this->wg().' genkey 2>/dev/null')); if($private==='')return false;
        $public=trim((string)shell_exec('printf %s '.escapeshellarg($private).' | '.$this->wg().' pubkey 2>/dev/null')); if($public==='')return false;
        file_put_contents(self::PRIVATE_KEY,$private."\n",LOCK_EX); @chmod(self::PRIVATE_KEY,0600);
        file_put_contents(self::PUBLIC_KEY,$public."\n",LOCK_EX); @chmod(self::PUBLIC_KEY,0600);
        $addr=$session['addresses']??Topology::defaultAddresses((int)($session['freepbx_major']??17));
        return $this->writeState(['session_id'=>$session['session_id']??null,'topology'=>Topology::ON_PBX,'expires_at'=>$session['expires_at']??null,'interface'=>self::IFACE,'addresses'=>$addr,'public_key'=>$public,'peer_configured'=>false,'interface_up'=>false,'prepared_at'=>time()]);
    }

    public function configurePeer(array $session,string $publicKey,string $endpoint,array $engineerAddresses=[],array $checkerAddresses=[]): bool
    {
        if(($session['topology']??Topology::ON_PBX)!==Topology::ON_PBX) return false;
        $state=$this->state(); if(!$state||!hash_equals((string)($state['session_id']??''),(string)($session['session_id']??'')))return false;
        if(!$this->validPublicKey($publicKey)||!$this->validEndpoint($endpoint))return false;
        $addr=$state['addresses']??[]; if(!Topology::validPair((string)($addr['pbx']??''),(string)($addr['peer']??''))||$this->collides((string)$addr['subnet']))return false;
        $allowedIps=[(string)$addr['peer']];
        foreach(array_merge($engineerAddresses,$checkerAddresses) as $engineerAddress){
            if(!is_string($engineerAddress)||!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',$engineerAddress,$match)||filter_var($match[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||$this->collides($engineerAddress))return false;
            if(!in_array($engineerAddress,$allowedIps,true))$allowedIps[]=$engineerAddress;
        }
        $peer=['session_id'=>$session['session_id'],'public_key'=>trim($publicKey),'endpoint'=>trim($endpoint),'allowed_ips'=>$allowedIps,'configured_at'=>time()];
        if(!$this->writeJson(self::PEER_FILE,$peer)||!$this->bringUp($peer,$addr)){@unlink(self::PEER_FILE);return false;}
        $state['peer_configured']=true;$state['interface_up']=true;$state['peer_endpoint']=$peer['endpoint'];$state['configured_at']=time();return $this->writeState($state);
    }

    public function reconcile(array $session): bool
    {
        if(($session['topology']??Topology::ON_PBX)!==Topology::ON_PBX)return true;
        $state=$this->state(); if(!$state||!hash_equals((string)($state['session_id']??''),(string)($session['session_id']??'')))return $this->prepare($session);
        $peer=$this->peer(); if(!$peer)return true; if($this->interfaceExists())return true;
        if(!$this->bringUp($peer,$state['addresses']??[]))return false; $state['interface_up']=true;$state['reconciled_at']=time();return $this->writeState($state);
    }

    public function destroy(): bool { $ok=$this->destroyInterface(); foreach([self::PRIVATE_KEY,self::PUBLIC_KEY,self::PEER_FILE,self::STATE] as $f)if(is_file($f)&&!@unlink($f))$ok=false; return $ok; }
    public function state(): ?array{return $this->readJson(self::STATE);} public function peer(): ?array{return $this->readJson(self::PEER_FILE);} public function publicKey(): ?string{return is_readable(self::PUBLIC_KEY)?trim((string)file_get_contents(self::PUBLIC_KEY)):null;}
    public function handshakeCurrent(string $peerPublicKey,int $maxAgeSeconds=90): bool
    {
        if(!$this->validPublicKey($peerPublicKey)||$maxAgeSeconds<1)return false;
        exec($this->wg().' show '.self::IFACE.' latest-handshakes 2>/dev/null',$rows,$rc);
        if($rc!==0)return false;
        foreach($rows as $row){$parts=preg_split('/\s+/',trim($row));if(count($parts)===2&&hash_equals(trim($peerPublicKey),$parts[0])&&ctype_digit($parts[1]))return (int)$parts[1]>0&&time()-(int)$parts[1]<=$maxAgeSeconds;}
        return false;
    }
    public function toolingReady(): bool{return $this->wg()!==''&&is_executable('/usr/sbin/ip');}

    public function collides(string $subnet): bool
    {
        if(!preg_match('/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/',$subnet,$m))return true;
        $net=ip2long($m[1]);$bits=(int)$m[2]; if($net===false||$bits<1||$bits>32)return true;
        exec('/usr/sbin/ip -4 route show 2>/dev/null',$routes,$rc); if($rc!==0)return true;
        foreach($routes as $line){$first=preg_split('/\s+/',trim($line))[0]??''; if($first==='default')continue; if(strpos($first,'/')===false)$first.='/32';if(self::subnetsOverlap($subnet,$first))return true;}
        exec('/usr/sbin/ip -o -4 addr show 2>/dev/null',$addresses,$addrRc); if($addrRc!==0)return true;
        foreach($addresses as $line)if(preg_match('/\binet\s+(\d+\.\d+\.\d+\.\d+\/\d{1,2})\b/',$line,$match)&&self::subnetsOverlap($subnet,$match[1]))return true;
        return false;
    }

    public static function subnetsOverlap(string $left,string $right): bool
    {
        if(!preg_match('/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/',$left,$a)||!preg_match('/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/',$right,$b))return false;
        $leftIp=ip2long($a[1]);$rightIp=ip2long($b[1]);$leftPrefix=(int)$a[2];$rightPrefix=(int)$b[2];
        if($leftIp===false||$rightIp===false||$leftPrefix>32||$rightPrefix>32)return false;
        $leftMask=$leftPrefix===0?0:(-1<<(32-$leftPrefix));$rightMask=$rightPrefix===0?0:(-1<<(32-$rightPrefix));
        $leftNetwork=$leftIp&$leftMask;$rightNetwork=$rightIp&$rightMask;
        return (($leftNetwork&$rightMask)===$rightNetwork)||(($rightNetwork&$leftMask)===$leftNetwork);
    }

    private function bringUp(array $peer,array $addr): bool
    {
        if(!$this->toolingReady()||!is_readable(self::PRIVATE_KEY)||empty($addr['pbx'])||empty($addr['peer']))return false;
        if($this->collides((string)($addr['subnet']??'')))return false; $this->destroyInterface();
        $allowedIps=$peer['allowed_ips']??[$addr['peer']]; if(!is_array($allowedIps)||!$allowedIps)return false;
        $allowed=escapeshellarg(implode(',',$allowedIps));
        $cmds=['/usr/sbin/ip link add dev '.self::IFACE.' type wireguard',$this->wg().' set '.self::IFACE.' private-key '.escapeshellarg(self::PRIVATE_KEY).' peer '.escapeshellarg($peer['public_key']).' endpoint '.escapeshellarg($peer['endpoint']).' allowed-ips '.$allowed.' persistent-keepalive 25','/usr/sbin/ip address add '.escapeshellarg($addr['pbx']).' dev '.self::IFACE];
        foreach($allowedIps as $allowedIp)if($allowedIp!==($addr['peer']??''))$cmds[]='/usr/sbin/ip route add '.escapeshellarg($allowedIp).' dev '.self::IFACE;
        $cmds[]='/usr/sbin/ip link set up dev '.self::IFACE;
        foreach($cmds as $cmd){exec($cmd.' >/dev/null 2>&1',$o,$rc);if($rc!==0){$this->destroyInterface();return false;}} return true;
    }
    private function destroyInterface(): bool{if(!$this->interfaceExists())return true;exec('/usr/sbin/ip link del dev '.self::IFACE.' >/dev/null 2>&1',$o,$rc);return $rc===0;}
    private function interfaceExists(): bool{exec('/usr/sbin/ip link show dev '.self::IFACE.' >/dev/null 2>&1',$o,$rc);return $rc===0;}
    private function validPublicKey(string $k): bool{$d=base64_decode(trim($k),true);return $d!==false&&strlen($d)===32;}
    private function validEndpoint(string $e): bool{return(bool)preg_match('/^(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$/',trim($e),$m)&&(int)$m[1]<=65535;}
    private function wg(): string{foreach(['/usr/bin/wg','/usr/sbin/wg']as$p)if(is_executable($p))return$p;return'';}
    private function ensureDir(): bool{if(!is_dir(self::DIR)&&!@mkdir(self::DIR,0700,true)&&!is_dir(self::DIR))return false;@chmod(self::DIR,0700);return true;}
    private function readJson(string$f):?array{if(!is_readable($f))return null;$v=json_decode((string)file_get_contents($f),true);return is_array($v)?$v:null;}
    private function writeState(array$v):bool{return$this->writeJson(self::STATE,$v);} private function writeJson(string$f,array$v):bool{if(!$this->ensureDir())return false;$t=$f.'.tmp.'.getmypid();if(file_put_contents($t,json_encode($v,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false)return false;@chmod($t,0600);if(!@rename($t,$f)){@unlink($t);return false;}return true;}
}
