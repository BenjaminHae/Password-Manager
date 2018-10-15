<?php
include("../function/vendor/php-jwt/src/BeforeValidException.php");
include("../function/vendor/php-jwt/src/ExpiredException.php");
include("../function/vendor/php-jwt/src/JWT.php");
include("../function/vendor/php-jwt/src/SignatureInvalidException.php");

use \Firebase\JWT\JWT;

function secondFactor_createJWT($token, $expiry, $additionalSecret=""){
    global $GLOBAL_SALT_3;
    // key must be something that's never transported to the client so signatures can't be created by third parties
    $key = $GLOBAL_SALT_3.$additionalSecret;

    if (!array_key_exists("aud", $token)) {
        error("Audience key missing in jwt");
    }
    $token['iat'] = time();
    $token['exp'] = time() + $expiry;
    return JWT::encode($token, $key, 'HS256');
}
function secondFactor_verifyJWT($jwt, $key, $aud) {
    $token = (array) JWT::decode($jwt, $key, array('HS256'));
    if ($token["aud"] !== $aud) {
        error('jwt: wrong audience');
    }
    if ($token["exp"] < time()) {
        error('jwt: expired');
    }
    return $token;
}
function secondFactor_getMailAddress($userid) {
    global $link;
    $sql = 'SELECT `email` FROM `pwdusrrecord` WHERE `id` = ?';
    $res = sqlexec($sql, [$userid], $link);
    $record = $res->fetch(PDO::FETCH_ASSOC);
    if (!$record) {
        error('secondFactor: Mail Address not found');
    }
    return $record["email"];
}

function sendMail($text, $address) {
    error_log($address.": ".$text);
}

function secondFactor_UserCookieName($userid) {
    return hash_hmac("sha256", "FactorUnnecessary" + $userid, $GLOBAL_SALT_3);
}

function secondFactor_loginCredentialCheckSuccess() {
    global $_COOKIE, $GLOBAL_SALT_3, $link;
    $cookieName = secondFactor_UserCookieName($_SESSION['userid']);
    if (array_key_exists($cookieName, $_COOKIE)) {
        $key = $GLOBAL_SALT_3.$_SESSION["pwd"];
        $token = secondFactor_verifyJWT($_COOKIE[$cookieName], $key, "login");
        if ($token["sub"] === $_SESSION["user"]) {
            return Null;
        }
    }
    $_SESSION['loginok'] = "SecondFactorMissing";
    $token = ["sub" => $_SESSION["user"], "aud" => "secondFactor"];
    $jwt = secondFactor_createJWT($token, 5*60*1000, $_SESSION["pwd"]);
    $mailText = "Hi,\r\n";
    $mailText .= "click this link to login to your Password Manager:\r\n";
    $mailText .= $HOSTDOMAIN."/index.php?secondFactorToken=";
    $mailText .= $jwt;
    $address = secondFactor_getMailAddress($_SESSION["userid"]);
    sendMail($mailText, $address);
    return ["state" => "SecondFactorMissing"];
}

function secondFactor_HTTP_showFactor($jwt) {
    global $_COOKIE, $GLOBAL_SALT_3, $link;
    session_start();
    $key = $GLOBAL_SALT_3.$_SESSION["pwd"];
    $token = secondFactor_verifyJWT($jwt, $key, "secondFactor");
    if ($token["sub"] !== $_SESSION["user"]) {
        invalidateSession();
        ajaxError('loginFailed');
    }
    $_SESSION['loginok'] = "loggedIn";
    $tokenUnnecessary = [ "sub" => $_SESSION["user"], "aud" => "login" ];
    $jwt = secondFactor_createJWT($tokenUnnecessary, 6*30*24*60*60*1000, $_SESSION["pwd"]);
    $_COOKIE[secondFactor_UserCookieName($_SESSION["userid"])] = $jwt;
    ajaxSuccess(["loggedIn" => true]);
}

add_plugin_listener("loginCredentialCheckSuccess", "secondFactor_loginCredentialCheckSuccess");
add_plugin_listener("secondFactor_HTTP_showFactor", "secondFactor_HTTP_showFactor");

