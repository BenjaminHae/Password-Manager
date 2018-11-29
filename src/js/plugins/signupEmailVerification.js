//Plugin for checking mail address during registrationg on client side
registerPlugin("signupLayoutReady", function(data){
    if ($.urlParam("registrationToken")) {
        $("#signupform > div:nth-child(4)").hide();
        $("#signupform").append(
            $('<input type="hidden" name="registrationToken"/>')
                .val($.urlParam("registrationToken"))
            );
    }
    else {
        $("#signupform > div:nth-child(1)").hide();
        $("#signupform > div:nth-child(2)").hide();
        $("#signupform > div:nth-child(3)").hide();
        $("#signupform").off();
        $("#chk").off();
        $("#signupform").submit(function(e) {
            //todo:
            e.preventDefault();
            backend.doPost("pluginEndpoint", {
                    "data": $("#email").val(),
                    "plugin": "mailVerification",
                    "method": "generateVerification"
            })
                .then(function(result) {
                    showMessage('A verification email has been sent to you, please check your mails.');
                })
                .catch(function(result) {
                    showMessage('Something went wrong');
                });
        });
    }
});
