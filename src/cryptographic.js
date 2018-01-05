'use strict';

const crypto = require('crypto');
const {toHex} = require('buffer-io');


function hash(type, content) {
    let hash = crypto.createHash(type);
    for (let item of content) {
        hash.update(item);
    }
    return hash.digest();
}

function hmac(type, secret, content) {
    let hmac = crypto.createHmac(type, secret);
    for (let item of content) {
        hmac.update(item);
    }
    return hmac.digest();
}

function sha(...content) {return hash('sha1',content);}
function md5(...content) {return hash('md5',content);}

function hmacMD5(secret, ...content) {return hmac('md5',secret, content);};
function hmacSHA(secret, ...content) {return hmac('sha1',secret, content);};

class KeyExchange {
    constructor(name) {
        this.name = name;
    }
}

class Cipher {
    constructor(name, blockMode, keyMaterialLength, ivSize, blockSize) {
        Object.assign(this, {name, blockMode, keyMaterialLength, ivSize, blockSize});
    }
}

function pad(paddingSize, charCode) {
    return ''.padStart(paddingSize,String.fromCharCode(charCode));
}

class Hash {
    constructor(name, hashSize, paddingSize) {
        Object.assign(this, {name, hashSize, paddingSize});
        this.pad1=pad(paddingSize,0x36);
        this.pad2=pad(paddingSize,0x5c);
    }
    hash(...content) {
        return hash(this.name,content);
    }
    hmac(secret, ...content) {
        return hmac(this.name,secret,content);
    }
    computeMAC(tls, macSecret, data) {
        //console.log('MAC:',toHex(macSecret),toHex(data));
        if (tls) {
            return this.hmac(macSecret, data);
        }
        //console.log(this.name,toHex(macSecret),toHex(this.hash(macSecret, this.pad1, data)),toHex(this.hash(macSecret, this.pad2, this.hash(macSecret, this.pad1, data))));
        return this.hash(macSecret, this.pad2, this.hash(macSecret, this.pad1, data));
    }

}

const RSA = new KeyExchange("RSA");
const AES_128_CBC = new Cipher("aes-128-cbc", true, 16, 16, 16);
const DES3_EDE_CBC = new Cipher("des-ede3-cbc", true, 24, 8, 8);
const DES_CBC = new Cipher("des-cbc", true, 8, 8, 8);
const MD5 = new Hash("md5", 16, 48);
const SHA = new Hash("sha1", 20, 40);

class CipherSpec {
    constructor(certificateFormat, cipher, mac) {
        Object.assign(this, {certificateFormat, cipher, mac});
    }
    toString() {
        return this.certificateFormat.name+' '+this.cipher.name+' '+this.mac.name;
    }
}
const RSA_WITH_3DES_EDE_CBC_SHA=new CipherSpec(RSA, DES3_EDE_CBC, SHA);
const RSA_WITH_DES_CBC_SHA=new CipherSpec(RSA, DES_CBC, SHA);
const RSA_WITH_AES_128_CBC_SHA=new CipherSpec(RSA, AES_128_CBC, SHA);
const nullCipher=new CipherSpec(new KeyExchange("None"), new Cipher("None", false, 0, 0, 0), new Hash("None", 0, 0));

const cipherSuites={
    0: nullCipher,
    0x9: RSA_WITH_DES_CBC_SHA,
    0xA: RSA_WITH_3DES_EDE_CBC_SHA,
    0x2F: RSA_WITH_AES_128_CBC_SHA
};

function pHash(length, hmac, secret, seed) {
    let results=[];
    let accumulated=seed;
    while (true) {
        accumulated=hmac(secret, accumulated);
        results.push(hmac(secret, accumulated, seed));
        if (results.reduce((total,result)=>total+result.length,0)>=length) break;

    }
    return Buffer.concat(results);
}

function prf(length, secret, label, seed) {
    let pMD5=pHash(length, hmacMD5, secret.slice(0,Math.ceil(secret.length/2)), Buffer.concat([Buffer.from(label),seed]));
    let pSHA=pHash(length, hmacSHA, secret.slice(Math.floor(secret.length/2)), Buffer.concat([Buffer.from(label),seed]));
    let result=Buffer.alloc(length);
    for (let i=0;i<length;i++) {
        result[i]=pMD5[i] ^ pSHA[i];
    }
    return result;
}

module.exports={sha, md5, SHA, MD5, hmacSHA, hmacMD5, prf, cipherSuites, RSA_WITH_DES_CBC_SHA, RSA_WITH_3DES_EDE_CBC_SHA, RSA_WITH_AES_128_CBC_SHA};
