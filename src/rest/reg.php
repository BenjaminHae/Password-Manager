<?php

require_once dirname(__FILE__).'/../function/sqllink.php';
require_once dirname(__FILE__).'/../function/ajax.php';
if (!$ALLOW_SIGN_UP) {
    http_response_code(405);
    ajaxError('signup');
}
$userdata = ["pw" => $_POST['pwd'], "usr" => $_POST['user'], "email" => $_POST['email']];

// check if a plugin wants to change some of the parameters first
$userdata = call_plugins("signupParametersReady", $userdata, true);

if (count(array_filter($userdata, function($v) {return $v == "";}))) {
    ajaxError('parameter');
}
// check length of password hash for pbkdf2
if (strlen($userdata["pw"]) > 130) {
    ajaxError('parameter');
}
if (!filter_var($userdata["email"], FILTER_VALIDATE_EMAIL)) {
    ajaxError('invalidEmail');
}
$link = sqllink();
if (!$link) {
    ajaxError('general');
}
if (!$link->beginTransaction()) {
    ajaxError('general');
}
$sql = 'SELECT COUNT(*) FROM `pwdusrrecord` WHERE `username` = ?';
$res = sqlexec($sql, [$userdata["usr"]], $link);
$num = $res->fetch(PDO::FETCH_NUM);
if ($num[0] != 0) {
    $link->commit();
    ajaxError('occupiedUser');
}
$sql = 'SELECT COUNT(*) FROM `pwdusrrecord` WHERE `email` = ?';
$res = sqlexec($sql, [$userdata["email"]], $link);
$num = $res->fetch(PDO::FETCH_NUM);
if ($num[0] != 0) {
    $link->commit();
    ajaxError('occupiedEmail');
}
// everything is ok, we could sign the user up
// check plugins first
$plugin_results = call_plugins("signupPostChecks", $userdata);
foreach ($plugin_result in $plugin_results) {
    if ($plugin_result !== Null) {
        error('plugin error', $plugin_result);
    }
}

$salt = openssl_random_pseudo_bytes(32);
$pw = hash_pbkdf2('sha256', $userdata["pw"], $salt, $PBKDF2_ITERATIONS);
$res = sqlquery('SELECT max(`id`) FROM `pwdusrrecord`', $link);
$result = $res->fetch(PDO::FETCH_NUM);
$maxnum = !$result ? 0 : (int) ($result[0]);
$sql = 'INSERT INTO `pwdusrrecord` VALUES (?,?,?,?,?,?)';
$rett = sqlexec($sql, [$maxnum + 1, $userdata["usr"], $userdata["pw"], $salt, $DEFAULT_FIELDS, $userdata["email"]], $link);
if (!$rett) {
    $link->rollBack();
    ajaxError('general');
}
$link->commit();
ajaxSuccess();
