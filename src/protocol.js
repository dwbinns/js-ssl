'use strict';

// See SSLv3: https://tools.ietf.org/html/rfc6101
// See TLSv1.0: https://tools.ietf.org/html/rfc2246
// See TLSv1.1: https://tools.ietf.org/html/rfc4346
// See TLSv1.2: https://tools.ietf.org/html/rfc4346

const {cipherSuites, RSA_WITH_3DES_EDE_CBC_SHA, RSA_WITH_DES_CBC_SHA, RSA_WITH_AES_128_CBC_SHA, sha, md5, SHA, MD5, prf}=require('./cryptographic');
const {u8, u16BE, u24BE, u32BE, u64BE, read, write, type, alternative, auto, size, array, bytes, region, PacketProcessor} = require('structured-io');
const {BufferReader, toHex} = require('buffer-io');
const crypto = require('crypto');

class ProtocolVersion {
    constructor(major,minor) {
        Object.assign(this,{major,minor});
    }
    atLeast(other) {
        return this.major>other.major || (this.major==other.major && this.minor>=other.minor);
    }
    static parse(text) {
        switch(text) {
            case 'ssl3': return ProtocolVersion.SSL3;
            case 'tls1.0': return ProtocolVersion.TLS10;
            case 'tls1.1': return ProtocolVersion.TLS11;
            case 'tls1.2': return ProtocolVersion.TLS12;
        }
        throw new Error("Unknown version: "+text);
    }
    toString() {
        return major+'.'+minor;
    }
}
ProtocolVersion.encoding = [
    {major:u8},
    {minor:u8},
];

ProtocolVersion.SSL3=new ProtocolVersion(3,0);
ProtocolVersion.TLS10=new ProtocolVersion(3,1);
ProtocolVersion.TLS11=new ProtocolVersion(3,2);
ProtocolVersion.TLS12=new ProtocolVersion(3,3);

class SessionID {
}
SessionID.encoding=[
    {data:size(u8,"data")},
    {data:region("data",bytes())},
];



class ChangeCipher {
    constructor() {
        this.type=1;
    }
}
ChangeCipher.encoding=[
    {type:u8},
];


class Alert {
    constructor(level,description) {Object.assign(this,{level,description});}
}

Alert.encoding=[
    {level:alternative(u8,{
        1:"Warning",
        2:"Error",
    })},
    {description:alternative(u8,{
        0:"Close",
        10:"Unexpected message",
        20:"Bad record MAC",
        21:"Decryption failed",
        22:"Record overflow",
        30:"Decompression failure",
        40:"Handshake failure",
        41:"No certificate",
        42:"Bad certificate",
        43:"Unsuppported certificate",
        44:"Certificate revoked",
        45:"Certificate expired",
        46:"Certificate unknown",
        47:"Illegal parameter",
        48:"Unknown CA",
        49:"Access denied",
        50:"Decode error",
        51:"Decrypt error",
        60:"Export restriction",
        70:"Protocol version",
        71:"Insufficient security",
        80:"Internal error",
        90:"User cancelled",
        100:"No renegotiation",
        110:"Unsupported extension",
    })},
];

class HelloRequest {
}
HelloRequest.encoding=[];



class ClientHello {
    constructor(clientVersion,random) {
        this.clientVersion=clientVersion;
        this.random=random;
        this.sessionId=new Uint8Array();
        this.cipherSuites=[RSA_WITH_3DES_EDE_CBC_SHA, RSA_WITH_DES_CBC_SHA, RSA_WITH_AES_128_CBC_SHA];
        //this.cipherSuites=[SSL_RSA_WITH_DES_CBC_SHA];
        this.compressionMethods=[0];
    }
}
ClientHello.encoding=[
    {clientVersion:ProtocolVersion},
    {random:bytes(32)},
    {sessionId:size(u8,bytes())},
    {cipherSuites:size(u16BE,array(alternative(u16BE, cipherSuites, null)))},
    {compressionMethods:size(u8,array(u8))},
];

class ServerHello {
    constructor(serverVersion,cipherSuite,random) {
        this.serverVersion=serverVersion;
        this.cipherSuite=cipherSuite;
        this.random=random;
        this.sessionId=new Uint8Array();
        this.compressionMethods=[0];
    }
}
ServerHello.encoding=[
    {'serverVersion':ProtocolVersion},
    {'random':bytes(32)},
    {'sessionId':size(u8,bytes())},
    {'cipherSuite':alternative(u16BE,cipherSuites)},
    {'compressionMethod':u8},
];

class ServerCertificate {
    constructor(certificates) {
        this.certificates=certificates;
    }
}
ServerCertificate.encoding=[
    {certificates:size(u24BE,array(size(u24BE,bytes())))},
];


class ServerKeyExchange {
}
ServerKeyExchange.encoding=()=>{throw new Error("not supported");};

class CertificateRequest {
}
CertificateRequest.encoding=()=>{throw new Error("not supported");};

class ServerHelloDone {}
ServerHelloDone.encoding=[];

class PreMasterSecret {
    constructor(clientVersion) {
        this.clientVersion=clientVersion;
        this.random=crypto.randomBytes(46);
    }
}
PreMasterSecret.encoding=[
    {clientVersion:ProtocolVersion},
    {random:bytes(46)},
];

class ClientKeyExchange {
    constructor(preMasterSecret, publicKey) {
        if (publicKey) {
            this.exchangeKeys=crypto.publicEncrypt({key: publicKey, padding:crypto.constants.RSA_PKCS1_PADDING}, preMasterSecret);
            //console.log('PEM:',publicKey,this.exchangeKeys.length);
        }
    }
    decrypt(privateKey) {

        return crypto.privateDecrypt({key: privateKey, padding:crypto.constants.RSA_PKCS1_PADDING}, this.exchangeKeys);
    }
}
ClientKeyExchange.encoding=(clientKeyExchange, context) => context.version.atLeast(ProtocolVersion.TLS10) ? [
    {exchangeKeys:size(u16BE,bytes())},
] : [
    {exchangeKeys:bytes()},
];

class CertificateVerify {}
CertificateVerify.encoding=()=>{throw new Error("not supported");};

function md5_sha(masterSecret, allMessages, sender) {
    return Buffer.concat([
        md5(masterSecret, MD5.pad2, md5(...allMessages,sender,masterSecret,MD5.pad1)),
        sha(masterSecret, SHA.pad2, sha(...allMessages,sender,masterSecret,SHA.pad1))
    ]);
}

class Finished {
    constructor(version, masterSecret, allMessages, isClient) {

        if (version) {
            if (version.atLeast(ProtocolVersion.TLS10)) {
                this.verifyData=prf(12,masterSecret,isClient ? "client finished" : "server finished", Buffer.concat([md5(...allMessages), sha(...allMessages)]));
            } else {
                const senders=[Buffer.from('434C4E54','hex'), Buffer.from('53525652','hex')];
                this.verifyData=md5_sha(masterSecret, allMessages, senders[isClient ? 0 : 1]);

                /*console.log('messages:\n',allMessages.map(message=>toHex(message)).join('\n'));
                console.log('sender',toHex(senders[isClient ? 0 : 1]),'mastersecret',toHex(masterSecret),'pad1',MD5.pad1,'pad2',MD5.pad2);
                console.log('md5',toHex(md5(...allMessages,senders[isClient ? 0 : 1],masterSecret,MD5.pad1)));
                console.log('sha',toHex(sha(...allMessages,senders[isClient ? 0 : 1],masterSecret,SHA.pad1)));*/
            }
        }
    }

    compare(expectedFinished) {
        console.log('compare',toHex(this.verifyData),toHex(expectedFinished.verifyData));
        /*console.log('md5:',toHex(this.md5Hash),toHex(expectedFinished.md5Hash));
        console.log('sha:',toHex(this.shaHash),toHex(expectedFinished.shaHash));*/
        return Buffer.compare(this.verifyData, expectedFinished.verifyData)==0;
    }
}
Finished.encoding=(finished, context) => context.version.atLeast(ProtocolVersion.TLS10) ? [
    {verifyData:bytes(12)},
] : [
    {verifyData:bytes(36)},
    // {md5Hash:bytes(16)},
    // {shaHash:bytes(20)},
];



const HandshakeOptions={
    0:HelloRequest,
    1:ClientHello,
    2:ServerHello,
    11:ServerCertificate,
    12:ServerKeyExchange,
    13:CertificateRequest,
    14:ServerHelloDone,
    15:CertificateVerify,
    16:ClientKeyExchange,
    20:Finished,
};

class Handshake {
    constructor(body) {
        this.body=body;
    }
}

Handshake.encoding=[
    {body:type(u8,HandshakeOptions, size(u24BE,auto))},
];


class ApplicationData {
    constructor(bytes) {
        this.bytes=bytes;
    }
}
ApplicationData.encoding=[{bytes:bytes()}];

class SSLRecord {
    constructor(type,protocolVersion,data) {
        Object.assign(this,{type,protocolVersion,data});
    }
}




SSLRecord.encoding = [
    {type:alternative(u8,{
        20:ChangeCipher,
        21:Alert,
        22:Handshake,
        23:ApplicationData,
    })},
    {protocolVersion:ProtocolVersion},
    {data:size(u16BE,bytes())}
];

class SSLMACSource {
    constructor(sequenceNumber, type,version,data) {
        Object.assign(this,{sequenceNumber,type,version,data});
    }
}
SSLMACSource.encoding = [
    {sequenceNumber:u64BE},
    {type:alternative(u8,{
        20:ChangeCipher,
        21:Alert,
        22:Handshake,
        23:ApplicationData,
    })},
    (_, context) => context.version.atLeast(ProtocolVersion.TLS10) ? {version:auto} : null,
    {data:size(u16BE,bytes())}
];

module.exports={
    SSLMACSource,
    SSLRecord,
    ClientHello,
    ServerCertificate,
    ServerHelloDone,
    ServerHello,
    ClientKeyExchange,
    Finished,
    ProtocolVersion,
    ChangeCipher,
    Alert,
    Handshake,
    ApplicationData,
    PreMasterSecret
};
