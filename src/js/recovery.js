var acc_array,pass_array,other_array;
var JSsalt='';
var PWsalt='';
var ALPHABET='';
var secretkey='';
var confkey='';
var dkey='';
var has_file=0;
var fname_array;
var fkey_array;
var fdata_array;
function defaultError(error){
    alert("Error in "+error["routine"]+": "+error["error"]+"\r\nDetails in console.");
    console.log("Error in "+error["routine"]+": "+error["error"]+"\r\nData:");
    console.log(error["data"]);
}
function download(filename, text) {
    var blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    saveAs(blob, filename);
}
function export_raw(){
    if(!confirm("Confirm: This function is used ONLY to TRANSFER your password to another password manager! DON'T BACK UP this version, it's DANGEROUS!")) return;
    if(!confirm("You agree you will delete the generated content IMMEDIATELY after you finish transferring your passwords")) return;
    var result = { };

    result.status="RAW_OK";

    var x;
    result.data={ };
    for (x in acc_array)
    {
        result.data[x]={
            'account': acc_array[x],
            'password': pass_array[x],
            'other': other_array[x]
        };
        if(has_file==1 && x in fname_array){
            result.data[x].fname=fname_array[x];
            result.data[x].filedata=fdata_array[x];
        }
    }
    download("raw_pass.raw",JSON.stringify(result));
}
function export_csv(){
    if(!confirm('CSV file contains all your information in plain text format. It\'s dangerous to keep it as a backup. Only use it for transferring your data. Delete it immediately after you\'ve done. Please note the encoding for the csv file is UTF-8. You might need to specify this encoding in order to open this CSV properly in some software that uses ANSI as default encoding such as Microsoft Office.')) return;
    var obj= [];
    timeout=100000+Math.floor(Date.now() / 1000);
    var t,x,i;
    for (x in acc_array){
        tmp={};
        tmp['name']=acc_array[x];
        t=JSON.parse(other_array[x]);
        for (i in t){
            tmp[i] = t[i];
        }
        tmp['password']=pass_array[x];
        obj.push(tmp);
    }
    var csv = $.csv.fromObjects(obj);
    var blob = new Blob([csv], {type: "text/plain;charset=utf-8"});
    saveAs(blob, "export.csv");
}
function sanitize_json(s){
    var t=s;
    t=t.replace(/\n/g,'');
    return t.replace(/\r/g,'');
}
function gen_key()
{
    var i;
    var pass=$("#pwd").val();
	secretkey=String(pbkdf2_enc(reducedinfo(pass,ALPHABET),JSsalt,500));
    confkey=pbkdf2_enc(SHA512(pass+secretkey),JSsalt,500);
    secretkey=SHA512(secretkey+PWsalt);
    dkey=pbkdf2_enc(secretkey,PWsalt,500);
    for(i=0;i<=30;i++) dkey=pbkdf2_enc(dkey,PWsalt,500);
}
function gen_account_array(enc_account_array) {
    return decryptArray(enc_account_array, secretkey);
}
function gen_fname_array(enc_fname_array) {
    return decryptArray(enc_fname_array, secretkey);
}
function gen_fdata_array(fkey_array,enc_fdata_array)
{
    return new Promise( function(success, error) {
        var fdata_count = enc_fdata_array.length;
        var fdata_array = new Array();
        function fdata_done(){
            fdata_count -= 1;
            if (fdata_count <= 0) {
                success(fdata_array);
            }
        }
        for (var x in enc_fdata_array){
            (function(fdata, x){
                decryptChar(fdata, fkey_array[x])
                    .catch(error)
                    .then(function(data) {
                        var tempchar;
                        if (tempchar == "") 
                            tempchar = "Oops, there's some errors!"
                        fdata_array[x] = tempchar;
                        fdata_done();
                    });
            })(enc_fdata_array[x], x);
        }
    });
}
function gen_other_array(enc_other_array) {
    return decryptArray(enc_other_array, secretkey);
}
function gen_pass_array(account_array,enc_pass_array)
{
    return new Promise( function(success, error) {
        var pass_count = enc_pass_array.length;
        var pass_array = new Array();
        function pass_done(){
            pass_count -= 1;
            if (pass_count <= 0) {
                success(pass_array);
            }
        }
        for (var x in enc_pass_array){
            (function(pass, x) {
                decryptPassword({"enpassword": pass, "name":account_array[x]}, secretkey)
                    .catch(error)
                    .then(function(data){
                        var tempchar;
                        tempchar = data["result"];
                        if (tempchar == "") {
                            tempchar = "Oops, there's some errors!";
                        }
                        pass_array[x] = tempchar;
                    });
            })(enc_pass_array[x], x);
        }
    });
}
function gen_fkey_array(fname_array,enc_fkey_array)
{
    return new Promise( function(success, error) {
        var fkey_count = enc_fkey_array.length;
        var fkey_array = new Array();
        function fkey_done(){
            fkey_count -= 1;
            if (fkey_count <= 0) {
                success(fkey_array);
            }
        }
        for (var x in enc_fkey_array){
            (function(fkey, x) {
                decryptChar(fkey, secretkey)
                    .catch(error)
                    .then(function(data) {
                        var tempchar;
                        tempchar = data["result"];
                        if (tempchar == "") {
                            tempchar = "Oops, there's some errors!";
                        }
                        else{
                            var name;
                            name = fname_array[x];
                            tempchar = get_orig_pwd(confkey,PWsalt,SHA512(name),ALPHABET,tempchar);
                        }
                        fkey_array[x] = tempchar;
                        fkey_done();
                    });
            })(enc_fkey_array[x],x);
        }
    });
}
function readfile(){
    if (window.FileReader) {
        // FileReader are supported.
        var reader = new FileReader();
        var a=$("#backupc")[0].files;
        if (a && a[0]){
            reader.onload = function (e) {
                var txt = e.target.result;
                rec(txt);
            }
            reader.onerror = function (e) {
                alert('Error reading file!');
            }
            reader.readAsText(a[0]);          
        } else {alert('NO FILE SELECTED');}
    } else {
        alert('FileReader are not supported in this browser.');
    }
}
function downloada(x){
    function base64toBlob(base64Data, contentType) {
        contentType = contentType || '';
        var sliceSize = 1024;
        var byteCharacters = atob(base64Data);
        var bytesLength = byteCharacters.length;
        var slicesCount = Math.ceil(bytesLength / sliceSize);
        var byteArrays = new Array(slicesCount);

        for (var sliceIndex = 0; sliceIndex < slicesCount; ++sliceIndex) {
            var begin = sliceIndex * sliceSize;
            var end = Math.min(begin + sliceSize, bytesLength);

            var bytes = new Array(end - begin);
            for (var offset = begin, i = 0 ; offset < end; ++i, ++offset) {
                bytes[i] = byteCharacters[offset].charCodeAt(0);
            }
            byteArrays[sliceIndex] = new Uint8Array(bytes);
        }
        return new Blob(byteArrays, { type: contentType });
    }
    var data=fdata_array[x];
    var typedata = data.substring(5,data.search(";"));
    data = data.substring(data.search(",")+1);
    saveAs(base64toBlob(data,typedata),fname_array[x]);
}
function rec(txt){
    if($("#pwd").val()==''){
        alert("EMPTY PASSWORD IS NOT ALLOWED");
        return;
    }
    var json=JSON.parse(sanitize_json(txt));
    if(json.status!="OK") {
        alert("INVALID BACKUP FILE");
        return;
    }
    $("#recover_result").hide();
    $("#chk").attr("disabled",true);
    $("#chk").attr("value", "Processing...");
    $("#raw_button").hide();
    $("#csv_button").hide();
    JSsalt = json.JSsalt;
    PWsalt = json.PWsalt;
    ALPHABET = json.ALPHABET;
    function process(){       
        gen_key();
        var enc_pass=new Array();
        var enc_acc=new Array();
        var enc_other=new Array();
        var enc_fname=new Array();
        var enc_fkey=new Array();
        var enc_fdata=new Array();
        decryptChar(json.data, dkey)
            .catch(function(err) {
                alert("Wrong password, try again!");
                $("#chk").removeAttr("disabled");
                $("#chk").attr("value", "RECOVER IT!");
                defaultError(err);
            })
            .then(function(data) {
                json.data = JSON.parse(data["result"]);
                if(typeof json.fdata != 'undefined'){
                    return decryptChar(json.fdata, dkey)
                        .catch(defaultError)
                        .then(function(data) {
                            json.fdata = data["result"];
                            if(json.fdata.status == 'OK') {
                                json.fdata = json.fdata.data;
                                has_file = 1;
                            }
                            else {
                                has_file = 0;
                            }
                        });
                } 
                else 
                    has_file = 0;
                return;
            })
            .catch(function(err) {
                alert("Wrong password, try again!");
                $("#chk").removeAttr("disabled");
                $("#chk").attr("value", "RECOVER IT!");
                defaultError(err);
            })
            .then(function(){
                for(var x in json.data){
                    enc_acc[x]=json.data[x][0];
                    enc_pass[x]=json.data[x][1];
                    enc_other[x]=json.data[x][2];
                }
                return gen_account_array(enc_acc);
            })
            .catch(defaultError)
            .then(function(accounts){
                acc_array = accounts;
                return gen_other_array(enc_other);
            })
            .catch(defaultError)
            .then(function(other){
                other_array = other;
                return gen_pass_array(acc_array, enc_pass);
            })
            .catch(defaultError)
            .then(function(pass){
                pass_array = pass;
                if(has_file==1) {
                    for(x in json.fdata){
                        enc_fname[x]=json.fdata[x][0];
                        enc_fkey[x]=json.fdata[x][1];
                        enc_fdata[x]=json.fdata[x][2];
                    }
                    return gen_fname_array(enf_fname)
                        .catch(defaultError)
                        .then(function(fname){
                            fname_array = fname;
                            return gen_fkey_array(fname_array,enc_fkey);
                        })
                        .catch(defaultError)
                        .then(function(fkey){
                            fkey_array = fkey;
                            return gen_fdata_array(fkey_array,enc_fdata);
                        })
                        .catch(defaultError)
                        .then(function(fdata){
                            fdata_array = fdata;
                            return;
                        });
                }
                else
                    return;
            })
            .then(function(){
                var rows = [$('<tr><th>Account</th><th>Password</th><th>Other Info</th></tr>')];
                if(has_file==1) rows = [$('<tr><th>Account</th><th>Password</th><th>Other Info</th><th>Files</th></tr>')];
                for(x in acc_array){
                    var row = $('<tr></tr>')
                        .append($('<td></td>').text(acc_array[x]))
                        .append($('<td></td>').text(pass_array[x]))
                        .append($('<td></td>').text(other_array[x]));
                    if(has_file==1){
                        if (x in fname_array)
                        {
                            row.append($('<td></td>')
                                .append($('<a></a>').on('click',{x:x},function(e){downloada(e.data.x);}).text(fname_array[x])));
                        } else 
                        {
                            row.append($('<td></td>'));
                        }
                    }
                    rows.push(row);
                }
                $("#rtable").empty();
                $("#rtable").append(rows);
                $("#recover_result").show();
                $("#chk").removeAttr("disabled");
                $("#chk").attr("value", "RECOVER IT!");
                $("#raw_button").show();
                $("#csv_button").show();
            });
    }
    setTimeout(process,50);
}
$(function(){
    $("#chk").on('click',function(e){readfile();});
	$("#raw_button").on('click',function(e){export_raw();});
	$("#csv_button").on('click',function(e){export_csv();});
});
