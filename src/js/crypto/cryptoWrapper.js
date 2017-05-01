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
        decryptChar(data[item], key, function(data, p){
            decryptedAccount[item] = p;
            if (isAccountFinished()){
                success(origData, decryptedAccount);
            }
        }, error);
    }
}
function encryptAccount(data, key, success, error){
    // no timeout needed as it's already async by using decryptChar
    var origData = data;
    var encryptedAccount = {};
    if ("index" in data)
        encryptedAccount["index"] = data["index"];
    function isAccountFinished(){
        for (item in origData){
            if (!(item in encryptedAccount)) {
                return false;
            }
        }
        return true;
    }
    for (item in data){
        encryptChar(data[item], key, function(data, p){
            encryptedAccount[item] = p;
            if (isAccountFinished()){
                success(origData, decryptedAccount);
            }
        }, error);
    }
}
