<?php

function plugin_dummyMail_sendMailToAddress($options) {
    error_log($options["address"].": ".$options["content"]);
}

function plugin_dummyMail_sendMailToCurrentUser($options) {
    $options["userid"] = $_SESSION["userid"];
    return plugin_dummyMail_sendMailToUser($options);
}

function plugin_dummyMail_getMailAddress($options) {
    global $link;
    $sql = 'SELECT `email` FROM `pwdusrrecord` WHERE `id` = ?';
    $res = sqlexec($sql, [$options["userid"]], $link);
    $record = $res->fetch(PDO::FETCH_ASSOC);
    if (!$record) {
        error('dummyMail: Mail Address not found');
    }
    return $record["email"];
}

function plugin_dummyMail_sendMailToUser($options) {
    $options["address"] = plugin_dummyMail_getMailAddress($options["userid"]);
    return plugin_dummyMail_sendMailToAddress($options);
}

add_plugin_listener("sendMailToAddress", "plugin_dummyMail_sendMailToAddress");
add_plugin_listener("sendMailToCurrentUser", "plugin_dummyMail_sendMailToCurrentUser");
add_plugin_listener("sendMailToUser", "plugin_dummyMail_sendMailToUser");
