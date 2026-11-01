<?php
namespace FreePBX\modules\Teliphones;

/** TELIPHONES support topology and address policy. */
class Topology
{
    public const ON_PBX='on-pbx';
    public const ON_NET='on-net';
    public const OFF_NET='off-net';

    public static function valid(string $mode): bool { return in_array($mode,[self::ON_PBX,self::ON_NET,self::OFF_NET],true); }
    public static function label(string $mode): string { return [self::ON_PBX=>'On-PBX',self::ON_NET=>'On-net',self::OFF_NET=>'Off-net'][$mode]??'Unknown'; }
    public static function preferredPool(int $major=17): string { return '10.20.'.$major.'.0/24'; }

    /** Default first test pair. Connect may propose another collision-free /30. */
    public static function defaultAddresses(int $major=17): array
    {
        return ['subnet'=>'10.20.'.$major.'.0/30','pbx'=>'10.20.'.$major.'.1/30','pbx_ip'=>'10.20.'.$major.'.1','peer'=>'10.20.'.$major.'.2/32','peer_ip'=>'10.20.'.$major.'.2'];
    }

    public static function validPair(string $pbxCidr,string $peerCidr): bool
    {
        if(!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/(30|31)$/',$pbxCidr,$a)) return false;
        if(!preg_match('/^(10\.(?:\d{1,3}\.){2}\d{1,3})\/32$/',$peerCidr,$b)) return false;
        if(filter_var($a[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||filter_var($b[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false)return false;
        $pbx=ip2long($a[1]); $peer=ip2long($b[1]); $prefix=(int)$a[2];
        $mask=-1<<(32-$prefix); $network=$pbx&$mask;
        if(($peer&$mask)!==$network||$pbx===$peer)return false;
        if($prefix===30&&($pbx===$network||$pbx===($network|(~$mask))||$peer===$network||$peer===($network|(~$mask))))return false;
        return true;
    }
}
