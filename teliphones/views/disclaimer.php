<?php
$metadata = simplexml_load_file(dirname(__DIR__) . '/module.xml', 'SimpleXMLElement', LIBXML_NONET);
if ($metadata === false || trim((string)$metadata->version) === '') {
    throw new RuntimeException('TELIPHONES module version metadata is unavailable.');
}
$licenceStatement = 'TELIPHONES ' . (string)$metadata->version . ' for FreePBX is licensed under GPLv3.';
?>
<footer class="teliphones-disclaimer" style="border-top:1px solid #ccc;margin-top:20px;padding-top:12px">
<p><strong>TELIPHONES is a UK registered trademark.</strong><br>
<?=htmlspecialchars($licenceStatement, ENT_QUOTES, 'UTF-8')?></p>
<p class="help-block">GPLv3 licensing applies to the software and does not grant trademark rights. See LICENSE for the full licence terms.</p>
</footer>
