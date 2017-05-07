//data contains, value, key and possibly iv or salt
//success is a function(data, result), with data being the input data and result being a string(possible of a json object containing salt/iv and the encrypted char)
function encryptChar(data, key, success, error){
    if(key == ""){
        error(data, "encryptchar", "empty key detected");
        return;
    }
    var p = CryptoJS.AES.encrypt(data,key).toString();
    setTimeout(success, 1, data, p);
}
//data contains, value(possibly a json string with iv and encrypted string), key
function decryptChar(data, key, success, error){ 
    if(data==""){
        success(data, "");
        return;
    }
    if(key == ""){
        error(data, "decryptchar", "empty key detected");
        return;
    }
    var p=CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(data, key));
    setTimeout(success, 1, data, p);
} 
//data: password, salt, iterations
function deriveKey(data, success, error){
    if(data["password"]==""||data["salt"]==""){
        error(data, "deriveKey", "empty key detected");
        return;
    }
    var hash = CryptoJS.SHA512(data["password"]);
    var salt = CryptoJS.SHA512(data["salt"]);
    var gen_key = CryptoJS.PBKDF2(hash, salt, { keySize: 512/32, iterations: data["iterations"] });   
    setTimeout(success, 1, data, gen_key);
}
function decryptPassword(data, key, success, error){
    var origData = data;
    decryptChar(data["enpassword"], key, function(data, thekey){
        // no timeout needed as it's already async by using decryptChar
        if (thekey==""){
            success(data, "");
        }
        success(origData, get_orig_pwd(getconfkey(PWsalt),PWsalt,String(CryptoJS.SHA512(origData["name"])),ALPHABET,thekey));
    }, error);
}
function encryptPassword(data, key, success, error){
    var confkey = getconfkey(PWsalt);
    if ("confkey" in data)
        confkey = data["confkey"];
    pass = gen_temp_pwd(confkey,PWsalt,String(CryptoJS.SHA512(data["name"])),ALPHABET,data["pass"]);
    encryptChar(pass, key, success, error);
}
function decryptAccount(data, key, success, error){
    // no timeout needed as it's already async by using decryptChar
    var origData = data;
    var decryptedAccount = {"index": data["index"], "kss":data["kss"]};
    function isAccountFinished(){
        for (item in origData){
            if (!(item in decryptedAccount)) {
                return false;
            }
        }
        return true;
    }
    for (item in data){
        if (item == "index"||item=="kss"){
            continue;
        }
        (function(data, item, key, decryptedAccount){
            decryptChar(data[item], key, function(data, p){
                decryptedAccount[item] = p;
                if (isAccountFinished()){
                    success(origData, decryptedAccount);
                }
            }, error);
        })(data, item, key, decryptedAccount);
    }
}
function encryptAccount(data, key, success, error, confkey){
    // no timeout needed as it's already async by using decryptChar
    var origData = data;
    var encryptedAccount = {};
    if ("index" in data) {
        encryptedAccount["index"] = data["index"];
    }
    function isAccountFinished(){
        for (item in origData){
            if (!(item in encryptedAccount)) {
                return false;
            }
        }
        return true;
    }
    var passwordData = {"name":origData["name"], "pass":origData["newpwd"]};
    if (confkey !== undefined) {
        passwordData["confkey"] = confkey;
    }
    encryptPassword(passwordData, key, function(origPw, encPw){
        encryptedAccount["newpwd"] = encPw;
        if (isAccountFinished()){
            success(origData, encryptedAccount);
        }
    }, error);
    for (item in data){
        if (item == "index"||item == "newpwd"){
            continue;
        }
        (function(data, item, key, encryptedAccount){
            encryptChar(data[item], key, function(data, p){
                encryptedAccount[item] = p;
                if (isAccountFinished()){
                    success(origData, encryptedAccount);
                }
            }, error);
        })(data, item, key, encryptedAccount);
    }
}
function encryptFile(data, key, success, error) {
    var origData = data;
    var encryptedFile = { "id":data["id"]};
    function isFileFinished(){
        for (item in origData){
            if (!(item in encryptedFile)) {
                return false;
            }
        }
        return true;
    }
    origData["fkey"] = getpwd(default_letter_used, Math.floor(Math.random() * 18) + 19);

    encryptPassword({"pass":origData["fkey"], "name":origData["fname"]}, key, function(origPw, encPw){
        encryptedFile["fkey"] = encPw;
        if (isFileFinished()){
            success(origData, encryptedFile);
        }
    }, error);

    encryptChar(origData["data"], origData["fkey"], function(data, p){
        encryptedFile["data"] = p;
        if (isFileFinished()){
            success(origData, encryptedFile);
        }
    }, error);
    encryptChar(origData["fname"], secretkey, function(data, p){
        encryptedFile["fname"] = p;
        if (isFileFinished()){
            success(origData, encryptedFile);
        }

    }, error);
}
