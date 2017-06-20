var JSsalt;
var PWsalt;
var session_token;
var usepin;
var randomLoginStamp;
var default_letter_used;
function defaultError(error){
    console.log("Error in "+error["routine"]+": "+error["error"]+"\r\nData:");
    console.log(error["data"]);
    alert("Error in "+error["routine"]+": "+error["error"]+"\r\nDetails in console.");
}
function isSupportFileApi() {
    if(window.File && window.FileList && window.FileReader && window.Blob) {
        return true;
    }
    return false;
}
function isAllHTML5Supports(){
    var test = 'test';
    try {
        localStorage.setItem(test, test);
        localStorage.removeItem(test);
        sessionStorage.setItem(test, test);
        sessionStorage.removeItem(test);
    } catch(e) {
        return false;
    }
    return isSupportFileApi();

}
if(!isAllHTML5Supports()) {
    window.location.href="./sorry_for_old_browser_update_hint.html";
}
$("#usepin").on("hidden.bs.modal", function () {
    $("#user").focus();
});
function dataReady(data){
    if (data["status"] != "success"){
        $("body").empty();
        $("body").text(data["message"]);
        return;
    }
    if (data["loggedIn"]){
        window.location = "./password.php";
        return;
    }
    JSsalt = data["global_salt_1"]; 
    PWsalt = data["global_salt_2"];
    session_token = data["session_token"];
    randomLoginStamp = data["random_login_stamp"];
    usepin = data["use_pin"];
    default_letter_used = data["default_letter_used"];
    if (data["allowSignup"]) {
        $("#signup").show();
    }
    $("#version").text(data["version"]);
    $("#banTime").text(data["banTime"]);
    localStorage.session_token = session_token;
    $.ajaxPrefilter(function(options, originalOptions, jqXHR){
        if (options.type.toLowerCase() === "post") {
            options.data = options.data || "";
            options.data += options.data?"&":"";
            options.data += "session_token=" + session_token;
        }
    });
    if(getcookie('device')!="") {
        if(1==usepin) {
            $("#usepin").modal("show");
            $("#pin").focus();
        }
        else{
            delpinstore();
            $("#user").focus();
        }
    } else $("#user").focus();
    $("#signup").on('click',function(e){window.location.href="signup.php";});
    $("#recover").on('click',function(e){window.location.href="recovery.php";});
    $("#delpin").on('click',function(e){delpinstore();deleteCookie('username');});
    $("#pinloginform").on('submit',function(e){
        var pin;
        e.preventDefault();
        $("#pinerrorhint").hide();
        $("#pinlogin").attr("disabled", true);
        $("#pinlogin").val("Wait");
        pin=$("#pin").val();
        $.post("rest/getpinpk.php",{user:getcookie('username'),device:getcookie('device'),sig:SHA512(SHA512(pin+localStorage.pinsalt)+randomLoginStamp)},function(msg){
            if(msg == '0') {
                $("#usepin").modal("hide");
                delpinstore();
                $("#user").focus();
                return;
            }
            else if(msg == '1') {
                $("#pin").val('');
                $("#pinerrorhint").show();
                $("#pinlogin").attr("disabled", false);
                $("#pinlogin").val("Login"); 
                return;
            }
            pwdsk=decryptchar(localStorage.en_login_sec,pin+msg);
            confkey=decryptchar(localStorage.en_login_conf,pin+msg)
            $.post("rest/check.php",{pwd:SHA512(SHA512(pbkdf2_enc(pwdsk,JSsalt,500)+getcookie('username')) + randomLoginStamp),  user: getcookie('username')},function(msg){
                if(msg!=9) {
                    $("#usepin").modal("hide");
                    delpinstore();
                    $("#user").focus();
                    return;
                }
                storeKey({"sk":pwdsk, "confusion_key":confkey,"salt":PWsalt})
                    .catch(defaultError)
                    .then(function(){
                        window.location.href="./password.php";
                    });
            });
        });
    });
    $("#loginform").on('submit',function(e){ 
        e.preventDefault();
        $("#chk").attr("disabled", true);
        $("#chk").attr("value", "Wait");
        $(".errorhint").hide();
        function process(){
            var user = $("#user").val(); 
            var pwd = $("#pwd").val();

            var secretkey='';
            //derive Secret key
            deriveKey({"password":reducedinfo(pwd,default_letter_used), "salt":JSsalt, "iterations":500})
                .catch(defaultError)
                .then(function(derivedKey){
                    secretkey = derivedKey["result"];
                    deriveKey({"password":exportKey(derivedKey["result"]), "salt":JSsalt, "iterations":500})
                        .catch(defaultError)
                        .then(function(result){
                            login_sig = result["result"];
                            $.post("rest/check.php",{pwd:SHA512(exportKey(login_sig)+user),  user: user},function(msg){
                                $(".errorhint").hide();
                                if(msg==0){
                                    $("#nouser").show();
                                    $("#chk").attr("value", "Login");
                                    $("#chk").attr("disabled", false);
                                }else if(msg==7){
                                    $("#blockip").show();
                                }else if(msg==8){
                                    $("#accountban").show();
                                    $("#chk").attr("value", "Login");
                                    $("#chk").attr("disabled", false);
                                }else if(msg==9){
                                    deriveKey({"password":SHA512(pwd+exportKey(secretkey)), "salt":JSsalt, "iterations":500})
                                        .catch(defaultError)
                                        .then(function(confkey){
                                            setCookie("username",user);
                                            storeKey({"sk":secretkey, "confusion_key":exportKey(confkey["result"]),"salt":PWsalt})
                                                .catch(defaultError)
                                                .then(function(){
                                                    window.location.href="./password.php";
                                                });
                                        });
                                }else{
                                    $("#othererror").show();
                                    $("#chk").attr("value", "Login");
                                    $("#chk").attr("disabled", false);
                                }
                            });

                        });
                });
        }
        setTimeout(process,50);
    }); 
}
$(function(){
    $.post("rest/info.php",{},function(msg){dataReady(msg);});
}); 
