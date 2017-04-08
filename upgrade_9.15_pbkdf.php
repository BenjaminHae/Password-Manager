<?php
// this might take a long time depending on the number of users
// about 0.5s/user
// create a backup before executing!
// execute the script in an environment without a timeout for php 
// scripts
require_once("src/function/sqllink.php");
$link = sqllink();
if(!$link->beginTransaction()) {
    die('0.1');
}
$sql = "ALTER TABLE `pwdusrrecord` ADD `salt` binary(32) NOT NULL AFTER `password`";
$res = sqlexec($sql,[],$link);
if ($res == NULL) {
        $link->rollBack();
        die(2);
}

$sql = "SELECT * FROM `pwdusrrecord`";
$res = sqlexec($sql,[],$link);
while ($i = $res->fetch(PDO::FETCH_ASSOC)){
    $update = "UPDATE `pwdusrrecord` SET `password`=?, `salt`=? WHERE `id`=?";
    $salt = openssl_random_pseudo_bytes(32);
    $newpwd = hash_pbkdf2('sha256', $i['password'],$salt,$PBKDF2_ITERATIONS);
    $ures = sqlexec($update,array($newpwd,$salt,$i['id']), $link);
    if ($ures == NULL) {
        $link->rollBack();
        die(1);
    }
}
$link->commit();
die('Done');
?>
