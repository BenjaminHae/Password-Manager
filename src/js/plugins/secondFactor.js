//Plugin for handlung the second factor stuff on client side
registerPlugin("indexLayoutReady", function(data){
    if ($.urlParam("secondFactorToken")) {
        backend.doPost("pluginEndpoint", {
                "data": $.urlParam("secondFactorToken"), 
                "plugin": "secondFactor", 
                "method": "showFactor" 
            })
            .then(function(result){
                window.location.href="./password.php";
            });
    }
});
registerPlugin("loginFailed", function(data){
    if (typeof(data) == "object") {
        if ((data["message"] == "plugin error") && (data["data"]["state"] == "SecondFactorMissing")) {
            $("#loginform")[0].reset();
            throw "This is a new device. Please check your mails for verification. Do not close this window.";
        }
    }
    else {
        throw data;
    }
});
