//data contains, value, key and possibly iv or salt
//success is a function(data, result), with data being the input data and result being a string(possible of a json object containing salt/iv and the encrypted char)
function encryptChar(data, key){
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    var abdata = str2ab(data);
    return window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key, //from generateKey or importKey above
        abdata //ArrayBuffer of data you want to encrypt
    )
        .then(function(encrypted){
            return { "data":data, "result":JSON.stringify({"iv":_arrayBufferToBase64(iv), "data":_arrayBufferToBase64(encrypted)})};
        })
        .catch(function(err){
            throw {"data":data, "routine":"encryptChar", "error":err};
        });
}
//data contains, value(possibly a json string with iv and encrypted string), key
function decryptChar(data, key){ 
    var crypt = JSON.parse(data);
    return window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: _base64ToArrayBuffer(crypt["iv"]), //The initialization vector you used to encrypt
        },
        key, //from generateKey or importKey above
        _base64ToArrayBuffer(crypt["data"]) //ArrayBuffer of the data
    )
        .then(function(decrypted){
            return {"data":data, "result":ab2str(decrypted)};
        })
        .catch(function(err){
            throw {"data":data, "routine":"decryptChar", "error":err};
        });
}
//data: password, salt, iterations
function deriveKey(data){
    var abdata = str2ab(data["password"]);
    var saltBuffer = str2ab(data["salt"]);
    return window.crypto.subtle.importKey(
        'raw', 
        abdata, 
        {name: 'PBKDF2'}, 
        false, 
        ['deriveBits', 'deriveKey']
    )
        .then(function(key) {
            return window.crypto.subtle.deriveKey(
                { "name": 'PBKDF2',
                    "salt": saltBuffer,
                    "iterations": 500,
                    "hash": 'SHA-512'
                },
                key,
                { "name": 'AES-CBC', "length": 256 },
                true,
                [ "encrypt", "decrypt", "wrapKey", "unwrapKey" ]
            )
        })
        .then(function(webKey) {
            return {"data":data, "result":webKey};
        });
}
function exportKey(key){
    return crypto.subtle.exportKey("jwk", key)
        .then(function (buffer) {
            return {"data":key, "result":buffer["k"]};
        })
        .catch(function(err){
            throw {"data":key, "routine":"deriveKey", "error":err};
        });
}
function importKey(key){
    return window.crypto.subtle.importKey(
        "jwk", //can be "jwk" or "raw"
        {
                kty: "oct",
                k: key,
                alg: "A256GCM",
                ext: true
        },
        {   //this is the algorithm options
            name: "AES-GCM",
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    )
        .then(function(sk){
            return sk;
        })
        .catch(function(err){
            throw {"data":key, "rountine":"importKey", "error":err};
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
        getDB(function(storage){
            storage.put({id: 1, key: data["sk"]});
            stored();
        });
        
        sessionStorage.confusion_key = data["confusion_key"];
        stored();
    });
}
function retrieveKey(salt){
    return new Promise( function(success, error) {
        getDB(function(storage){
            var getData = storage.get(1);
            getData.onsuccess = function() {
                var key = getData.result.key;
                success(key);
            };
        });
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
            .then(function(result) {
                // no timeout needed as it's already async by using decryptChar
                if (result["result"]==""){
                    success({"data":data, "result":""});
                    return;
                }
                success({"data":data, "result":get_orig_pwd(confkey, PWsalt, String(CryptoJS.SHA512(data["name"])), ALPHABET, result["result"])});
            })
            .catch(error);
    });
}
function encryptPassword(data, key){
    return new Promise( function(success, error) {
        var confkey;
        if ("confkey" in data)
            confkey = data["confkey"];
        else
            confkey = getconfkey(PWsalt);
        pass = gen_temp_pwd(confkey,PWsalt,String(CryptoJS.SHA512(data["name"])),ALPHABET,data["pass"]);
        encryptChar(pass, key)
            .then(success)
            .catch(error);
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
                    .then(function(result){
                        decryptedAccount[item] = result["result"];
                        isAccountFinished();
                    })
                    .catch(error);
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
            .then(function(result){
                encryptedAccount["newpwd"] = result["result"];
                isAccountFinished();
            })
            .catch(error);
        for (item in data){
            if (item == "index"||item == "newpwd"){
                continue;
            }
            (function(data, item, key, encryptedAccount){
                encryptChar(data[item], key)
                    .then(function(result){
                        encryptedAccount[item] = result["result"];
                        isAccountFinished();
                    })
                    .catch(error);
            })(data, item, key, encryptedAccount);
        }
    });
}
function encryptFile(data, key) {
    return new Promise( function(success, error) {
        var origData = data;
        var fkey;
        origData["fkey"] = "";
        var encryptedFile = { "id":data["id"]};
        function isFileFinished(){
            for (item in origData){
                if (!(item in encryptedFile)) {
                    return;
                }
            }
            success();
        }
        encryptedFile["id"] = origData["id"];
        return encryptChar(origData["fname"], key)
            .then(function(result){
                encryptedFile["fname"] = result["result"];
                // create key for file encryption
                return window.crypto.subtle.generateKey(
                    {
                        name: "AES-GCM",
                        length: 256, //can be  128, 192, or 256
                    },
                    true,
                    ["encrypt", "decrypt"]
                )
            })
            .then(function(newfkey){
                fkey = newfkey;
                var iv = window.crypto.getRandomValues(new Uint8Array(12));
                // Store Key
                return window.crypto.subtle.wrapKey(
                    "jwk",
                    fkey,
                    key,
                    {
                        name: "AES-GCM",
                        iv: iv,
                    }
                )})
            .then(function(wrapped){
                encryptedFile["fkey"] = JSON.stringify({"iv":_arrayBufferToBase64(iv), "data":_arrayBufferToBase64(wrapped)});
                encryptChar(origData["data"], fkey);
            })
            .then(function(result){
                encryptedFile["data"] = result["result"];
                return {"data":origData, "result":encryptedFile};
            });
    });
}
function decryptFile(data, key) {
    return new Promise( function(success, error) {
        var origData = data;
        var decryptedFile = { "id":data["id"]};
        decryptedFile["name"] = data["name"];
        delete origData["status"];
        var fkey = JSON.parse(origData["key"]);

        return window.crypto.subtle.unwrapKey(
            "jwk", //"jwk", "raw", "spki", or "pkcs8" (whatever was used in wrapping)
            _base64ToArrayBuffer(fkey["data"]),
            key, //the AES-GCM key with "unwrapKey" usage flag
            {   //these are the wrapping key's algorithm options
                name: "AES-GCM",
                    iv: _base64ToArrayBuffer(fkey["iv"]), //The initialization vector you used to encrypt
            },
            {   //this what you want the wrapped key to become (same as when wrapping)
                name: "AES-CBC",
                length: 256
            },
            false,
            ["decrypt"]
        )
            .then(function(fkey){
                //returns a key object
                delete origData["key"];
                return decryptChar(origData["data"], fkey);
            })
            .then(function(result){
                decryptedFile["data"] = result["result"];
                isFileFinished();
                return {"data":origData, "result":decryptedFile};
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
                    .then(function(data){
                        dec_array[x] = data["result"];
                        arr_done();
                    })
                    .catch(error);
            })(enc_arr[x], x);
        }
    });
}
//Get an instance of the indexedDB and do something
function getDB(callback){
    const dbName = "PasswordManagerDB";
    const storeName = "keyStore";
    const dbVersion = 1;
	var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;
    var open = indexedDB.open(dbName, dbVersion);
    open.onupgradeneeded = function() {
        var db = open.result;
	    var store = db.createObjectStore(storeName, {keyPath: "id"});
    };
    open.onsuccess = function() {
	    var db = open.result;
	    var tx = db.transaction(storeName, "readwrite");
	    var store = tx.objectStore(storeName);

	    callback(store);

	    // Close the db when the transaction is done
	    tx.oncomplete = function() {
	        db.close();
	    };
    };
}
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}
function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
function _arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}
function _base64ToArrayBuffer(base64) {
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
