<?php
$metadata = simplexml_load_file(dirname(__DIR__) . '/module.xml', 'SimpleXMLElement', LIBXML_NONET);
if ($metadata === false || trim((string)$metadata->version) === '') {
    throw new RuntimeException('TELIPHONES module version metadata is unavailable.');
}
$licenceStatement = 'TELIPHONES ' . (string)$metadata->version . ' for FreePBX is licensed under GPLv3.';
?>
<footer class="teliphones-disclaimer" style="margin-top:12px;padding:16px 0;text-align:center;font-weight:normal;white-space:nowrap;overflow-x:auto"
 title="GPLv3 licensing applies to the software and does not grant trademark rights. See LICENSE for the full licence terms.">
TELIPHONES is a UK registered trademark. <?=htmlspecialchars($licenceStatement, ENT_QUOTES, 'UTF-8')?>
</footer>
