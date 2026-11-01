<?php
namespace FreePBX\modules\Teliphones;
class ConsoleContract
{
    public function handoff(array $s,array $adapter): array { return ['protocol'=>'teliphones-console/1','session_id'=>$s['session_id'],'expires_at'=>$s['expires_at'],'topology'=>$s['topology'],'target'=>['address'=>$adapter['listen_address']??null,'port'=>$adapter['port']??22222,'username'=>'root'],'restrictions'=>['session_only'=>true,'may_extend_grant'=>false,'may_authorise'=>false,'may_verify'=>false]]; }
}
