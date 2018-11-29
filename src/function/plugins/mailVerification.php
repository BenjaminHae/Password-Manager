<?php

require_once("../function/signedTokens.php");

function mailVerification_signupParametersReady($data) {
    global $_POST;
    if (array_key_exists("registrationToken", $_POST)) {
        $token = verifyJWT($_POST["registrationToken"], JWTdefaultSecret(), "signup");
        $data["email"] = $token["sub"];
        return $data;
    }
    ajaxError('email verification failed');
}

function mailVerification_HTTP_generateVerification($email) {
    global $HOSTDOMAIN;
    $token = ["sub" => $email, "aud" => "signup"];
    // valid for 12 hours
    $jwt = createJWT($token, 12*60*60*1000);
    $mailText = "Hi,\r\n";
    $mailText .= "click this link to verify your email address for signing up to the Password Manager:\r\n";
    $mailText .= $HOSTDOMAIN."/signup.php?registrationToken=";
    $mailText .= $jwt;
    call_plugins("sendMailToAddress", ["content" => $mailText, "address" => $email]);
    ajaxSuccess(["sentMail" => true]);
}

add_plugin_listener("signupParametersReady", "mailVerification_signupSuccess");
add_plugin_listener("mailVerification_HTTP_generateVerification", "mailVerification_HTTP_generateVerification");

