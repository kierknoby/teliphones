<?php
namespace FreePBX\modules\Teliphones;

class SupportAdapter
{
    private const FILE='/var/lib/teliphones/adapter.json';
    private const DIR='/var/lib/teliphones/access';
    private const AUTH_KEYS=self::DIR.'/authorized_keys';
    private const CONFIG=self::DIR.'/sshd_config';
    private const PID=self::DIR.'/sshd.pid';
    private const HOST_KEY=self::DIR.'/ssh_host_ed25519_key';
    private const PORT=22222;

    public function prepare(array $state): bool
    {
        return $this->write(['adapter'=>'temporary-console','transport'=>'wireguard','session_id'=>$state['session_id']??null,
            'expires_at'=>$state['expires_at']??null,'prepared_at'=>time(),'remote_access_opened'=>false,'attestation_required'=>true,'support_ready'=>false]);
    }

    public function open(array $state,string $publicKey,?string $authorisedSource=null,array $allowedEngineerAddresses=[]): bool
    {
        $a=$this->state(); if(!$a || !hash_equals((string)($a['session_id']??''),(string)($state['session_id']??''))) return false;
        if(!$this->validSshKey($publicKey) || !$this->sshdReady()) return false;
        $listen=(string)($state['addresses']['pbx_ip']??'');
        $sourceCidr=$authorisedSource??((string)($state['addresses']['peer_ip']??'').'/32');
        if(($state['topology']??'on-pbx')!=='on-pbx'||!filter_var($listen,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)
            ||!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',$sourceCidr,$sourceMatch)
            ||($authorisedSource!==null&&!in_array($sourceCidr,$allowedEngineerAddresses,true)))return false;
        $source=$sourceMatch[1];
        $this->stopSshd(); if(!$this->ensureDir()) return false;
        if(file_put_contents(self::AUTH_KEYS,trim($publicKey)."\n",LOCK_EX)===false)return false; @chmod(self::AUTH_KEYS,0600);
        if(!is_file(self::HOST_KEY)) { exec('/usr/bin/ssh-keygen -q -t ed25519 -N "" -f '.escapeshellarg(self::HOST_KEY).' >/dev/null 2>&1',$o,$rc); if($rc!==0)return false; @chmod(self::HOST_KEY,0600); }
        $cfg="Port ".self::PORT."\nListenAddress ".$listen."\nProtocol 2\nHostKey ".self::HOST_KEY."\nPidFile ".self::PID."\nAuthorizedKeysFile ".self::AUTH_KEYS."\nPermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nAllowUsers root@".$source."\nAllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\nGatewayPorts no\nPermitUserEnvironment no\nPermitTTY yes\nUsePAM no\nPrintMotd no\nLogLevel VERBOSE\n";
        if(file_put_contents(self::CONFIG,$cfg,LOCK_EX)===false)return false; @chmod(self::CONFIG,0600);
        exec($this->sshd().' -t -f '.escapeshellarg(self::CONFIG).' 2>/dev/null',$o,$rc); if($rc!==0)return false;
        if(!is_executable('/usr/bin/systemd-run')||!is_executable('/usr/bin/systemctl'))return false;
        $sessionId=(string)($state['session_id']??''); if(!preg_match('/^[a-f0-9]{32}$/',$sessionId))return false;
        $unit='teliphones-sshd-'.substr($sessionId,0,16);
        $lifetime=max(1,(int)($state['expires_at']??0)-time());
        $command='/usr/bin/systemd-run --quiet --collect --unit='.escapeshellarg($unit)
            .' --property=KillMode=control-group --property=TimeoutStopSec=5s --property=SendSIGKILL=yes'
            .' --property=RuntimeMaxSec='.$lifetime.' -- '.escapeshellarg($this->sshd()).' -D -e -f '.escapeshellarg(self::CONFIG);
        exec($command.' 2>/dev/null',$o,$rc); if($rc!==0)return false;
        $ready=false;
        for($attempt=0;$attempt<30;$attempt++){
            exec('/usr/bin/systemctl is-active --quiet '.escapeshellarg($unit).' 2>/dev/null',$o,$activeRc);
            if($activeRc===0&&is_readable(self::PID)){$ready=true;break;}
            usleep(100000);
        }
        if(!$ready){$this->stopUnit($unit);return false;}
        $a['remote_access_opened']=true;$a['support_ready']=true;$a['listen_address']=$listen;$a['source_address']=$source;$a['port']=self::PORT;$a['opened_at']=time();
        $a['systemd_unit']=$unit;
        if(!$this->write($a)){$this->stopUnit($unit);return false;}
        return true;
    }

    public function reconcile(array $state): bool
    {
        $a=$this->state(); if(!$a || !hash_equals((string)($a['session_id']??''),(string)($state['session_id']??''))) return $this->prepare($state);
        // Access is intentionally NOT reopened automatically after reboot. Fresh attestation + root open command required.
        if(!empty($a['remote_access_opened'])) { $this->stopSshd(); $a['remote_access_opened']=false;$a['support_ready']=false;$a['reboot_revalidation_required']=true; return $this->write($a); }
        return true;
    }

    public function destroy(): bool
    {
        $ok=$this->stopSshd(); if(!$ok)return false; foreach([self::AUTH_KEYS,self::CONFIG,self::PID,self::HOST_KEY,self::HOST_KEY.'.pub'] as $f) if(is_file($f)&&!@unlink($f))$ok=false;
        if(is_dir(self::DIR)) @rmdir(self::DIR); if(is_file(self::FILE)&&!@unlink(self::FILE))$ok=false; return $ok;
    }
    public function state(): ?array { if(!is_readable(self::FILE))return null;$d=json_decode((string)file_get_contents(self::FILE),true);return is_array($d)?$d:null; }
    private function stopSshd(): bool
    {
        $state=$this->state(); $unit=(string)($state['systemd_unit']??'');
        if($unit!=='')return(bool)preg_match('/^teliphones-sshd-[a-f0-9]{16}$/',$unit)&&$this->stopUnit($unit);
        if(!is_readable(self::PID))return true;
        $pid=(int)trim((string)file_get_contents(self::PID));
        if($pid<=1||!is_dir('/proc/'.$pid)){@unlink(self::PID);return true;}
        $command=(string)@file_get_contents('/proc/'.$pid.'/cmdline');
        if($command===''||strpos($command,self::CONFIG)===false)return false;
        if(!function_exists('posix_kill'))return false;
        $processes=$this->processTree($pid); if(!$processes)return false;
        foreach($processes as $process)@posix_kill($process,SIGTERM);
        for($attempt=0;$attempt<20;$attempt++){
            $alive=false; foreach($processes as $process)if(is_dir('/proc/'.$process)){$alive=true;break;}
            if(!$alive)break; usleep(100000);
        }
        foreach($processes as $process)if(is_dir('/proc/'.$process))@posix_kill($process,SIGKILL);
        for($attempt=0;$attempt<10;$attempt++){
            $alive=false; foreach($processes as $process)if(is_dir('/proc/'.$process)){$alive=true;break;}
            if(!$alive)break; usleep(100000);
        }
        foreach($processes as $process)if(is_dir('/proc/'.$process))return false;
        @unlink(self::PID); return true;
    }

    private function stopUnit(string $unit): bool
    {
        if(!is_executable('/usr/bin/systemctl'))return false;
        exec('/usr/bin/systemctl stop '.escapeshellarg($unit).' 2>/dev/null',$output,$stopRc);
        exec('/usr/bin/systemctl is-active --quiet '.escapeshellarg($unit).' 2>/dev/null',$output,$activeRc);
        return $activeRc!==0;
    }

    private function processTree(int $pid): array
    {
        $childrenFile='/proc/'.$pid.'/task/'.$pid.'/children';
        $children=is_readable($childrenFile)?preg_split('/\s+/',trim((string)file_get_contents($childrenFile))):[];
        $processes=[];
        foreach($children as $child){$childPid=(int)$child;if($childPid>1)$processes=array_merge($processes,$this->processTree($childPid));}
        $processes[]=$pid;
        return $processes;
    }
    private function validSshKey(string $k): bool { return (bool)preg_match('/^(ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+\/=]+(?: .*)?$/',trim($k)); }
    private function sshd(): string { foreach(['/usr/sbin/sshd','/usr/bin/sshd'] as $p)if(is_executable($p))return $p;return ''; }
    private function sshdReady(): bool { return $this->sshd()!=='' && is_executable('/usr/bin/ssh-keygen'); }
    private function ensureDir(): bool { if(!is_dir(self::DIR)&&!@mkdir(self::DIR,0700,true)&&!is_dir(self::DIR))return false;@chmod(self::DIR,0700);return true; }
    private function write(array $p): bool { $tmp=self::FILE.'.tmp.'.getmypid();if(file_put_contents($tmp,json_encode($p,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false)return false;@chmod($tmp,0600);if(!@rename($tmp,self::FILE)){@unlink($tmp);return false;}return true; }
}
