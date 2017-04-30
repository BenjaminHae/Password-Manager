//data contains, value, key and possibly iv or salt
//success is a function(data, result), with data being the input data and result being a string(possible of a json object containing salt/iv and the encrypted char)
function encryptChar(data, success, error){
    if(data["key"]==""){
        error(data, "encryptchar", "empty key detected");
        return;
    }
    var p=CryptoJS.AES.encrypt(encryptch,key).toString();
    success(data, p);
}
//data contains, value(possibly a json string with iv and encrypted string), key
function decryptChar(data, success, error){ 
    if(data==""){
        success(data, "");
    }
    if(secretkey==""){
        error(data, "decryptchar", "empty key detected");
        return;
    }
    var p=CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(data, secretkey));
    success(data, p);
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
    success(data, gen_key);
}
function decryptPassword(data, success, error){
    var origData = data;
    decryptChar(data["enpassword"], function(data, thekey){
        if (thekey==""){
            success(data, "");
        }
        success(origData, get_orig_pwd(getconfkey(PWsalt),PWsalt,String(CryptoJS.SHA512(origData["name"])),ALPHABET,thekey));
    }, error);
}
function decryptAccount(data, success, error){
    var origData = data;
    var decryptedAccount = {"index": data["index"], "kss"=data["kss"]};
    function isAccountFinished(){
        for (key in data){
            if (!(key in decryptedAccount)) {
                return false;
            }
        }
        return true;
    }
    for (key in data){
        if (key == "index"||key=="kss"){
            continue;
        }
        decryptChar(data[key], function(data, p){
            decryptedAccount[key] = p;
            if (isAccountFinished()){
                success(origData, decryptedAccount);
            }
        }, error);
    }
}
