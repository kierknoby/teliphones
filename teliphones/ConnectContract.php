<?php
namespace FreePBX\modules\Teliphones;
class ConnectContract
{
    public function request(array $s,?string $wgPublicKey=null): array { $r=['protocol'=>'teliphones-connect/1','session_id'=>$s['session_id'],'expires_at'=>$s['expires_at'],'topology'=>$s['topology'],'pbx'=>['freepbx_major'=>$s['freepbx_major']??17],'network'=>['preferred_pool'=>$s['preferred_pool']??'10.20.17.0/24']]; if($wgPublicKey)$r['pbx']['wireguard_public_key']=$wgPublicKey; return $r; }
}
