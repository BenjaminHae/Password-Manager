//data contains, value, key and possibly iv or salt
//success is a function(data, result), with data being the input data and result being a string(possible of a json object containing salt/iv and the encrypted char)
function encryptChar(data, key){
    return new Promise( function(success, error) {
        if(key == ""){
            error({"data":data, "routine":"encryptChar", "error":"empty key detected"});
        }
        var p = CryptoJS.AES.encrypt(data,key).toString();
        success({"origData":data, "result":p});
    });
}
//data contains, value(possibly a json string with iv and encrypted string), key
function decryptChar(data, key){ 
    return new Promise( function(success, error) {
        if(data==""){
            success({"data":data, "result":""});
        }
        if(key == ""){
            error({"data":data, "routine":"decryptChar", "error":"empty key detected"});
            return;
        }
        var p=CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(data, key));
        success({"data":data, "result":p});
    });
} 
//data: password, salt, iterations
function deriveKey(data){
    return new Promise( function(success, error) {
        if(data["password"]==""||data["salt"]==""){
            error({"data":data, "routine":"deriveKey", "error":"empty key detected"});
            return;
        }
        var hash = CryptoJS.SHA512(data["password"]);
        var salt = CryptoJS.SHA512(data["salt"]);
        var gen_key = CryptoJS.PBKDF2(hash, salt, { keySize: 512/32, iterations: data["iterations"] });   
        success({"data":data, "result":gen_key});
    });
}
function exportKey(key){
    return String(key);
}
function importKey(key){
    return new Promise( function(success, error) {
        success(SHA512(key+salt2));
    });
}
function storeKey(data){
    return new Promise( function(success, error) {
        var storeCount = 2;
        function stored(){
            storeCount -= 1;
            if (storeCount <= 0){
                success(data);
            }
        }
        encryptChar(data["sk"], data["salt"])
            .catch(function(err) {
                error({"data":data, "routine":"storeKey-secretkey", "error":err});
            })
            .then(function(sk) {
                sessionStorage.pwdsk = sk["result"];
                stored();
            });
        encryptChar(data["confusion_key"], data["salt"])
            .catch(function(err) {
                error({"data":data, "routine":"storeKey-confkey", "error":err});
            })
            .then(function(confkey) {
                sessionStorage.confusion_key = confkey["result"];
                stored();
            });
    });
}
function retrieveKey(salt){
    return new Promise( function(success, error) {
        if(!sessionStorage.pwdsk) {
            success("");
        }
        else {
            decryptChar(sessionStorage.pwdsk, salt)
                .catch(function(err){
                    error({"data":salt, "routine":"retrieveKey", "error":err});
                })
                .then(function(key){
                    success(key["result"]);
                });
        }
    });
}
function SHA512(value){
    return String(CryptoJS.SHA512(value));
}
function decryptPassword(data, key){
    return new Promise( function(success, error) {
        var origData = data;
        var confkey;
        if ("confkey" in data)
            confkey = data["confkey"];
        else
            confkey = getconfkey(PWsalt);
        decryptChar(data["enpassword"], key)
            .catch(error)
            .then(function(result) {
                // no timeout needed as it's already async by using decryptChar
                if (result["result"]==""){
                    success({"data":result["data"], "result":""});
                    return;
                }
                success({"data":result["data"], "result":get_orig_pwd(confkey, PWsalt, String(CryptoJS.SHA512(result["data"]["name"])), ALPHABET, result["result"])});
            });
    });
}
function encryptPassword(data, key){
    return new Promise( function(success, error) {
        var confkey = getconfkey(PWsalt);
        if ("confkey" in data)
            confkey = data["confkey"];
        pass = gen_temp_pwd(confkey,PWsalt,String(CryptoJS.SHA512(data["name"])),ALPHABET,data["pass"]);
        encryptChar(pass, key)
            .catch(error)
            .then(success);
    });
}
function decryptAccount(data, key){
    return new Promise( function(success, error) {
        // no timeout needed as it's already async by using decryptChar
        var origData = data;
        var decryptedAccount = {"index": data["index"]};
        if ("kss" in data) {
            decryptedAccount["kss"] = data["kss"];
        }
        function isAccountFinished(){
            for (item in origData){
                if (!(item in decryptedAccount)) {
                    return;
                }
            }
            success({"data":origData, "result":decryptedAccount});
        }
        for (item in data){
            if (item == "index"||item=="kss"){
                continue;
            }
            (function(data, item, key, decryptedAccount){
                decryptChar(data[item], key)
                    .catch(error)
                    .then(function(result){
                        decryptedAccount[item] = result["result"];
                        isAccountFinished();
                    });
            })(data, item, key, decryptedAccount);
        }
    });
}
function encryptAccount(data, key, confkey){
    return new Promise( function(success, error) {
        var origData = data;
        var encryptedAccount = {};
        if ("index" in data) {
            encryptedAccount["index"] = data["index"];
        }
        function isAccountFinished(){
            for (item in origData){
                if (!(item in encryptedAccount)) {
                    return ;
                }
            }
            success({"data":origData, "result":encryptedAccount});
        }
        var passwordData = {"name":origData["name"], "pass":origData["newpwd"]};
        if (confkey !== undefined) {
            passwordData["confkey"] = confkey;
        }
        encryptPassword(passwordData, key)
            .catch(error)
            .then(function(result){
                encryptedAccount["newpwd"] = result["result"];
                isAccountFinished();
            });
        for (item in data){
            if (item == "index"||item == "newpwd"){
                continue;
            }
            (function(data, item, key, encryptedAccount){
                encryptChar(data[item], key)
                    .catch(error)
                    .then(function(result){
                        encryptedAccount[item] = result["result"];
                        isAccountFinished();
                    });
            })(data, item, key, encryptedAccount);
        }
    });
}
function encryptFile(data, key) {
    return new Promise( function(success, error) {
        var origData = data;
        var encryptedFile = { "id":data["id"]};
        function isFileFinished(){
            for (item in origData){
                if (!(item in encryptedFile)) {
                    return;
                }
            }
            success({"data":origData, "result":encryptedFile});
        }
        origData["fkey"] = getpwd(default_letter_used, Math.floor(Math.random() * 18) + 19);

        encryptPassword({"pass":origData["fkey"], "name":origData["fname"]}, key)
            .catch(error)
            .then(function(result){
                encryptedFile["fkey"] = result["result"];
                isFileFinished();
            });

        encryptChar(origData["data"], origData["fkey"])
            .catch(error)
            .then(function(result){
                encryptedFile["data"] = result["result"];
                isFileFinished();
            });
        encryptChar(origData["fname"], secretkey)
            .catch(error)
            .then(function(result){
                encryptedFile["fname"] = result["result"];
                isFileFinished();
            });
    });
}
function decryptArray(enc_arr, key) {
    return new Promise( function(success, error) {
        var arr_count = Object.keys(enc_arr).length;
        var dec_array = new Array();
        function arr_done(){
            arr_count -= 1;
            if (arr_count <= 0) {
                success(dec_array);
            }
        }
        for (var x in enc_arr){
            (function(item, x){
                decryptChar(item, key)
                    .catch(error)
                    .then(function(data){
                        dec_array[x] = data["result"];
                        arr_done();
                    });
            })(enc_arr[x], x);
        }
    });
}
