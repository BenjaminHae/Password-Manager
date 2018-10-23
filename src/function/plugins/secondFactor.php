<?php

include("../function/signedTokens.php");

function secondFactor_UserCookieName($userid) {
    return hash_hmac("sha256", "FactorUnnecessary" + $userid, JWTdefaultSecret());
}

function secondFactor_loginCredentialCheckSuccess() {
    global $_COOKIE, $link, $HOSTDOMAIN;
    $cookieName = secondFactor_UserCookieName($_SESSION['userid']);
    if (array_key_exists($cookieName, $_COOKIE)) {
        $key = JWTdefaultSecret().$_SESSION["pwd"];
        $token = verifyJWT($_COOKIE[$cookieName], $key, "login");
        if ($token["sub"] === $_SESSION["user"]) {
            return Null;
        }
    }
    $_SESSION['loginok'] = "SecondFactorMissing";
    $token = ["sub" => $_SESSION["user"], "aud" => "secondFactor"];
    $jwt = createJWT($token, 5*60*1000, $_SESSION["pwd"]);
    $mailText = "Hi,\r\n";
    $mailText .= "click this link to login to your Password Manager:\r\n";
    $mailText .= $HOSTDOMAIN."/index.php?secondFactorToken=";
    $mailText .= $jwt;
    call_plugins("sendMailToCurrentUser", ["content" => $mailText]);
    return ["state" => "SecondFactorMissing"];
}

function secondFactor_HTTP_showFactor($jwt) {
    global $_COOKIE, $link;
    $FACTOR_VALIDITY = 6*30*24*60*60*1000;//half a year (in milliseconds)
    session_start();
    $key = JWTdefaultSecret().$_SESSION["pwd"];
    $token = verifyJWT($jwt, $key, "secondFactor");
    if ($token["sub"] !== $_SESSION["user"]) {
        invalidateSession();
        ajaxError('loginFailed');
    }
    $_SESSION['loginok'] = "loggedIn";
    $tokenUnnecessary = [ "sub" => $_SESSION["user"], "aud" => "login" ];
    $jwt = createJWT($tokenUnnecessary, $FACTOR_VALIDITY, $_SESSION["pwd"]);
    setcookie(secondFactor_UserCookieName($_SESSION["userid"]), $jwt, time() + $FACTOR_VALIDITY, '/', '', true, true);
    ajaxSuccess(["loggedIn" => true]);
}

add_plugin_listener("loginCredentialCheckSuccess", "secondFactor_loginCredentialCheckSuccess");
add_plugin_listener("secondFactor_HTTP_showFactor", "secondFactor_HTTP_showFactor");

