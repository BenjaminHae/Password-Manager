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
registerPlugin("loginAuthenticationResult", function(data){

});
