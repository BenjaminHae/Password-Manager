<?php

include("../function/vendor/php-jwt/src/BeforeValidException.php");
include("../function/vendor/php-jwt/src/ExpiredException.php");
include("../function/vendor/php-jwt/src/JWT.php");
include("../function/vendor/php-jwt/src/SignatureInvalidException.php");

use \Firebase\JWT\JWT;

function createJWT($token, $expiry, $additionalSecret=""){
    // key must be something that's never transported to the client so signatures can't be created by third parties
    $key = JWTdefaultSecret().$additionalSecret;

    if (!array_key_exists("aud", $token)) {
        error("Audience key missing in jwt");
    }
    $token['iat'] = time();
    $token['exp'] = time() + $expiry;
    return JWT::encode($token, $key, 'HS256');
}
function JWTdefaultSecret() {
    global $GLOBAL_SALT_3;
    return $GLOBAL_SALT_3;
}
function verifyJWT($jwt, $key, $aud) {
    $token = (array) JWT::decode($jwt, $key, array('HS256'));
    if ($token["aud"] !== $aud) {
        error('jwt: wrong audience');
    }
    if ($token["exp"] < time()) {
        error('jwt: expired');
    }
    return $token;
}
