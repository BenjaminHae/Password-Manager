<?php

require_once dirname(__FILE__).'/../function/sqllink.php';
require_once dirname(__FILE__).'/../function/user.php';
require_once dirname(__FILE__).'/../function/ajax.php';

$db = new Db();
try {
    $user = User::fromSession();
    $id = $_SESSION['userid'];
    $result = [];
    $result['default_timeout'] = $BROWSER_TIMEOUT;
    $result['default_letter_used'] = $DEFAULT_LETTER_USED;
    $result['default_length'] = $DEFAULT_LENGTH;
    $result['global_salt_1'] = $GLOBAL_SALT_1;
    $result['global_salt_2'] = $GLOBAL_SALT_2;
    $result['user'] = $user->id;
    $result['fields'] = $user->data()['fields'];
    $result['fields_allow_change'] = $CUSTOMIZE_FIELDS;
    $result['server_timeout'] = $SERVER_TIMEOUT;
    $result['file_enabled'] = $FILE_ENABLED ? 1 : 0;
} catch {
    ajaxError('authentication');
}

// Select Accounts
$result['accounts'] = $user->getAccounts();

// Select Files
$result['fdata'] = $user->getFiles();

// Show Login attempts
$result['loginInformation'] = $user->getLastLogins();

ajaxSuccess($result);
