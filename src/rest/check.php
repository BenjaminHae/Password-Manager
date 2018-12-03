<?php

require_once dirname(__FILE__).'/../function/sqllink.php';
require_once dirname(__FILE__).'/../function/user.php';
require_once dirname(__FILE__).'/../function/ajax.php';
require_once dirname(__FILE__).'/../function/plugins.php';
//todo: move all session stuff to user object
session_start();
$token = $_SESSION['session_token'];
session_regenerate_id(true);
$_SESSION['session_token'] = $token;
$sidvalue = session_id();
if (!isset($_SESSION['random_login_stamp']) || $_SESSION['random_login_stamp'] == '') {
    ajaxError('general');
}
$usr = $_POST['user'];
$pw = $_POST['pwd'];
// check length of password hash for pbkdf2
if (strlen($pw) > 130) {
    ajaxError('general');
}
if ($pw == '' || $usr == '' || $_POST['session_token'] == '') {
    ajaxError('general');
}

try {
    $db = new Db();
} 
catch {
    ajaxError('general');
}

//ToDo move to Logging module
//Clear Up.
$sql = 'DELETE FROM `blockip` WHERE UNIX_TIMESTAMP( NOW( ) ) - UNIX_TIMESTAMP(`time`) > ?';
$res = $db->sqlexec($sql, [$BLOCK_IP_TIME]);
$sql = 'DELETE FROM `history` WHERE UNIX_TIMESTAMP( NOW( ) ) - UNIX_TIMESTAMP(`time`) > ?';
$res = $db->sqlexec($sql, [$LOG_EXPIRE_TIME]);

//check if IP is blocked
$sql = 'SELECT * FROM `blockip` WHERE `ip` = ?';
$record = $db->sqlexec($sql, [getUserIP()])->fetch(PDO::FETCH_ASSOC);
if ($record) {
    ajaxError('blockIP');
}

//Todo catch around everything
try {
    $user = User::logon($db, $usr);
}
catch (Exception $e){
    ajaxError($e->message);
}

ajaxSuccess();
