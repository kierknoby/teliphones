<?php
namespace FreePBX\modules\Teliphones;

class VerificationProbe
{
    private const STATE='/var/lib/teliphones/checker-probe.json';
    private const DIR='/run/teliphones-checker';
    private const FILE=self::DIR.'/challenge.json';
    private const PORT=22221;

    public function start(array $session,array $challenge): bool
    {
        $sessionId=(string)($session['session_id']??'');
        $bind=(string)($session['addresses']['pbx_ip']??'');
        if(($session['topology']??'on-pbx')!=='on-pbx'||!preg_match('/^[a-f0-9]{32}$/',$sessionId)
            ||!filter_var($bind,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)||!hash_equals($sessionId,(string)($challenge['session_id']??''))
            ||(int)($challenge['expires_at']??0)<=time()||!preg_match('/^[a-f0-9]{48}$/',(string)($challenge['nonce']??'')))return false;
        if(!$this->prepareDirectory()||!$this->writeChallenge($challenge))return false;
        $unit=$this->unit($sessionId);$this->stopUnit($unit);
        $python=is_executable('/usr/bin/python3')?'/usr/bin/python3':'';
        $runner=is_executable('/usr/bin/systemd-run')?'/usr/bin/systemd-run':'';
        $systemctl=is_executable('/usr/bin/systemctl')?'/usr/bin/systemctl':'';
        if($python===''||$runner===''||$systemctl===''||!posix_getpwnam('asterisk'))return false;
        $script=__DIR__.'/checker_probe_server.py';
        if(!is_file($script)||!is_readable($script))return false;
        $lifetime=max(1,(int)$challenge['expires_at']-time());
        $args=[$runner,'--quiet','--collect','--unit='.$unit,'--property=User=asterisk','--property=Group=asterisk',
            '--property=NoNewPrivileges=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes',
            '--property=PrivateTmp=yes','--property=PrivateDevices=yes','--property=CapabilityBoundingSet=',
            '--property=AmbientCapabilities=','--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
            '--property=RuntimeMaxSec='.$lifetime,'--',$python,$script,'--bind',$bind,'--port',(string)self::PORT,
            '--challenge',self::FILE,'--session',$sessionId];
        $command=implode(' ',array_map('escapeshellarg',$args));
        exec($command.' 2>/dev/null',$output,$result);
        if($result!==0)return false;
        $ready=false;
        for($attempt=0;$attempt<30;$attempt++){
            exec($systemctl.' is-active --quiet '.escapeshellarg($unit).' 2>/dev/null',$output,$active);
            if($active===0){$ready=true;break;}
            usleep(100000);
        }
        if(!$ready){$this->stopUnit($unit);return false;}
        return $this->writeState(['session_id'=>$sessionId,'unit'=>$unit,'expires_at'=>(int)$challenge['expires_at'],'bind'=>$bind,'port'=>self::PORT]);
    }

    public function destroy(): bool
    {
        $state=$this->state();
        if(!$state)return true;
        $unit=(string)($state['unit']??'');
        if(!preg_match('/^teliphones-checker-probe-[a-f0-9]{16}$/',$unit)||!$this->stopUnit($unit))return false;
        $ok=true;
        foreach([self::FILE,self::STATE]as$file)if(is_file($file)&&!@unlink($file))$ok=false;
        if(is_dir(self::DIR)&&!@rmdir(self::DIR))$ok=false;
        return $ok;
    }

    private function prepareDirectory(): bool
    {
        if(!is_dir(self::DIR)&&!@mkdir(self::DIR,0750,true)&&!is_dir(self::DIR))return false;
        $stat=@lstat(self::DIR);
        if(!$stat||($stat['mode']&0170000)!==0040000||$stat['uid']!==0||($stat['mode']&0022)!==0)return false;
        if(!@chgrp(self::DIR,'asterisk'))return false;
        @chmod(self::DIR,0750);
        return true;
    }

    private function writeChallenge(array $challenge): bool
    {
        $temporary=self::FILE.'.tmp.'.bin2hex(random_bytes(6));
        $encoded=json_encode($challenge,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        if(!is_string($encoded)||file_put_contents($temporary,$encoded."\n",LOCK_EX)===false)return false;
        @chgrp($temporary,'asterisk');@chmod($temporary,0640);
        if(!@rename($temporary,self::FILE)){@unlink($temporary);return false;}
        return true;
    }

    private function state(): ?array
    {
        if(!is_readable(self::STATE))return null;
        $state=json_decode((string)file_get_contents(self::STATE),true);
        return is_array($state)?$state:null;
    }

    private function writeState(array $state): bool
    {
        $temporary=self::STATE.'.tmp.'.getmypid();
        if(file_put_contents($temporary,json_encode($state,JSON_UNESCAPED_SLASHES)."\n",LOCK_EX)===false)return false;
        @chmod($temporary,0600);
        if(!@rename($temporary,self::STATE)){@unlink($temporary);return false;}
        return true;
    }

    private function unit(string $sessionId): string { return 'teliphones-checker-probe-'.substr($sessionId,0,16); }

    private function stopUnit(string $unit): bool
    {
        if(!preg_match('/^teliphones-checker-probe-[a-f0-9]{16}$/',$unit)||!is_executable('/usr/bin/systemctl'))return false;
        exec('/usr/bin/systemctl stop '.escapeshellarg($unit).' 2>/dev/null',$output,$stop);
        exec('/usr/bin/systemctl is-active --quiet '.escapeshellarg($unit).' 2>/dev/null',$output,$active);
        return $active!==0;
    }
}