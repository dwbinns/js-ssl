'use strict';

const {Duplex} = require('stream');
const {SSLProcessor} = require('./ssl');
const {asBuffer} = require('buffer-io');
const net = require('net');

function createSSLStreams(isClient, version, certificates, key) {
    let secured=false,encryptOK=false,decryptOK=false,pendingDecrypt,pendingEncrypt;
    let sslProcessor=new SSLProcessor(isClient,version,certificates,key);
    sslProcessor.sendPlainTextData=data=>{
        decryptOK=plainText.push(data);
        if (pendingDecrypt) pendingDecrypt();
    };
    sslProcessor.sendEncryptedData=data=>{
        encryptOK=encrypted.push(data);
        if (pendingEncrypt) pendingEncrypt();
    };
    sslProcessor.onSecured=()=>{
        secured=true;
        if (pendingEncrypt) pendingEncrypt();
    };

    let plainText=new Duplex({
        read:()=>{
            decryptOK=true;
            if (pendingDecrypt) pendingDecrypt();
        },
        write:(chunk,_,callback)=>{
            pendingEncrypt=()=>{
                if (secured && encryptOK) {
                    pendingEncrypt=null;
                    sslProcessor.plainTextReceived(chunk);
                    callback();
                }
            };
            pendingEncrypt();
        },
        final:(callback)=>{
            sslProcessor.close();
            callback();
        }
    });

    let encrypted=new Duplex({
        read:()=>{
            encryptOK=true;
            if (pendingEncrypt) pendingEncrypt();
        },
        write:(chunk,_,callback)=>{
            pendingDecrypt=()=>{
                if (decryptOK) {
                    pendingDecrypt=null;
                    sslProcessor.encryptedReceived(chunk);
                    callback();
                }
            };
            pendingDecrypt();
        },
        final:(callback)=>{
            sslProcessor.shutdown();
            callback();
        }
    });

    sslProcessor.start();
    return {plainText,encrypted};
}

function sslWrapSocket(socket,isClient, version,certificates, key) {
    let {plainText,encrypted}=createSSLStreams(isClient,version,certificates,key);
    encrypted.pipe(socket);
    socket.pipe(encrypted);
    return plainText;
}

function sslConnect(version, options) {
    return sslWrapSocket(net.connect(options),true,version);
}

function sslServer(version,certificates,key,onConnect) {
    return net.createServer(connection=>{
        onConnect(sslWrapSocket(connection,false,version,certificates,key));
    });
}

module.exports={sslConnect,sslServer,sslWrapSocket,createSSLStreams};
