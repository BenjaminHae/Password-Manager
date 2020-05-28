import { CryptedObject } from './cryptedObject';

export class Account {
    public index: number;
    public name: string;
    public enpassword: CryptedObject;
    public other: {[index: string]:any};
    public file: any;

    constructor(index: number, name: string, enpassword: CryptedObject) {
        this.index = index;
        this.name = name;
        this.enpassword = enpassword;
        this.other = {};
        this.file = null;
    }

    clearOther() {
        this.other = {};
    }
    clearVisibleOther() {
        for (let item in this.other) {
            if (item.substring(0,1) !== "_") {
                delete this.other[item];
            }
        }
    }
    get availableOthers(): Array<string> {
        let availableOthers = [];
        for (let otherName in this.other) {
            availableOthers.push(otherName);
        }
        return availableOthers;
    }
    setOther(name: string, value: any) {
        this.other[name] = value;
    }
    getOther(name: string) {
        return this.other[name];
    }
    getOtherJSON() {
        return JSON.stringify(this.other);
    }
    addEncryptedFile(name: string, fkey: any) {
        var self = this;
        self.file = { "name":"", "key": fkey };
        //return self.encryptionWrapper.decryptChar(name)
        //    .then(function(decryptedName) {
        //        self.file.name = decryptedName;
        //        return self.file;
        //    });
    }
    hasFile() {
        return 'file' in this;
    }
}