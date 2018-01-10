'use strict';

const {
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
}=require('./protocol');
const {explainCertificate, Certificate, pemEncode, pemDecode}= require('x509-io');
const x690=require('x690-io');
const {asBuffer, BufferReader, toHex} = require('buffer-io');
const {PacketProcessor, read, write} = require('structured-io');
const crypto = require('crypto');
const {prf, sha, md5, SHA, MD5} = require('./cryptographic');

const MAX_RECORD_SIZE=2**14;

class SSLServerHandshake {
    constructor(sslProcessor, protocolVersion) {
        this.sslProcessor = sslProcessor;
        this.protocolVersion = protocolVersion;
    }

    start() {
    }

    onHandshake(handshake, priorHandshakes) {

        console.log("handshake:",handshake.body.constructor.name);
        if (handshake.body instanceof ClientHello) {
            this.clientRandom=handshake.body.random;
            let matchingCipherSuites = handshake.body.cipherSuites.filter(cipherSuite => cipherSuite);
            this.cipherSuite = matchingCipherSuites[0];
            //console.log('cipher:',''+this.cipherSuite);
            this.serverRandom=crypto.randomBytes(32);
            let negotiatedVersion=this.protocolVersion.atLeast(handshake.body.clientVersion) ? handshake.body.clientVersion : this.protocolVersion;
            this.sslProcessor.changeVersion(negotiatedVersion);
            this.sslProcessor.sendHandshake(new ServerHello(negotiatedVersion, this.cipherSuite, this.serverRandom));
            this.sslProcessor.sendHandshake(new ServerCertificate(this.sslProcessor.certificates));
            this.sslProcessor.sendHandshake(new ServerHelloDone());
        }
        if (handshake.body instanceof ClientKeyExchange) {
            this.masterSecret = this.sslProcessor.computeNextState(this.cipherSuite, this.clientRandom, this.serverRandom, handshake.body.decrypt(this.sslProcessor.key));
            //console.log("PMS",this.preMasterSecret);
        }
        if (handshake.body instanceof Finished) {
            if (!handshake.body.compare(new Finished(this.sslProcessor.version, this.masterSecret, priorHandshakes, true))) {
                this.sslProcessor.error("Handshake failure");
                console.log('Finished not compared');
            }

            this.sslProcessor.changeCipher();
            this.sslProcessor.sendHandshake(new Finished(this.sslProcessor.version, this.masterSecret, this.sslProcessor.allHandshakes, false));
            this.sslProcessor.onSecured();
        }
    }
}

class SSLClientHandshake {

    constructor(sslProcessor, clientVersion) {
        this.sslProcessor = sslProcessor;
        this.clientVersion = clientVersion;
    }

    start() {
        //this.time=(Date.now() / 1000)>>>0;
        this.clientRandom=crypto.randomBytes(32);
        this.sslProcessor.sendHandshake(new ClientHello(this.clientVersion, this.clientRandom));
    }

    onHandshake(handshake,priorHandshakes) {

        if (handshake.body instanceof ServerHello) {
            this.serverRandom=handshake.body.random;
            this.cipherSuite=handshake.body.cipherSuite;
            this.sslProcessor.changeVersion(handshake.body.serverVersion);
        }
        if (handshake.body instanceof ServerCertificate) {

            for (let certificateData of handshake.body.certificates) {
                let certificate=read(certificateData, null, Certificate);
                if (!this.serverCertificate) {
                    this.serverCertificate=certificate;
                }
            }
            if (!this.serverCertificate) {
                this.sslProcessor.error("No certificate");
            }
        }
        if (handshake.body instanceof ServerHelloDone) {
            //console.log(this.serverCertificate.tbsCertificate.subjectPublicKeyInfo.publicKey);
            let data=this.serverCertificate.tbsCertificate.subjectPublicKeyInfo.raw;
            //console.log(x690.explain(data, read(data, x690.x690auto)));

            let preMasterSecret=write(new PreMasterSecret(this.sslProcessor.version));
            this.sslProcessor.sendHandshake(new ClientKeyExchange(preMasterSecret, pemEncode('PUBLIC KEY',data)));
            this.masterSecret = this.sslProcessor.computeNextState(this.cipherSuite, this.clientRandom, this.serverRandom, preMasterSecret);
            this.sslProcessor.changeCipher();
            this.sslProcessor.sendHandshake(new Finished(this.sslProcessor.version, this.masterSecret, this.sslProcessor.allHandshakes, true));
        }
        if (handshake.body instanceof Finished) {
            if (!handshake.body.compare(new Finished(this.sslProcessor.version, this.masterSecret, priorHandshakes, false))) {
                this.sslProcessor.error("Handshake failure");
            }
            this.sslProcessor.onSecured();
        }

    }
}

class CryptoSettings {
    constructor(cipherSuite, macSecret, key, iv) {
        Object.assign(this, {cipherSuite, macSecret, key, iv});
    }
    toString() {
        return "mac="+toHex(this.macSecret)+" key="+toHex(this.key)+" iv="+toHex(this.iv);
    }
}

class Decrypt {
    constructor(sslProcessor, cryptoSettings) {
        if (cryptoSettings) {
            this.cipherDecrypt=crypto.createDecipheriv(cryptoSettings.cipherSuite.cipher.name, cryptoSettings.key, cryptoSettings.iv);
            this.cipherDecrypt.setAutoPadding(false);
        }
        this.sslProcessor=sslProcessor;
        this.sequenceNumber =0;
        this.cryptoSettings = cryptoSettings;
    }
    decrypt(type, data) {
        if (this.cryptoSettings && this.cryptoSettings.cipherSuite.cipher.blockMode) {
            let decrypted=this.cipherDecrypt.update(data);
            /*console.log('encrypted:');
            console.log(toHex(data));
            console.log('decrypted:');
            console.log(toHex(decrypted));*/
            let paddingLength=decrypted[data.length-1];
            let mac=decrypted.slice(decrypted.byteLength-paddingLength-1-this.cryptoSettings.cipherSuite.mac.hashSize,decrypted.byteLength-paddingLength-1);
            let fragment = decrypted.slice(0,decrypted.byteLength-paddingLength-1-this.cryptoSettings.cipherSuite.mac.hashSize);
            let isTLS = this.sslProcessor.version.atLeast(ProtocolVersion.TLS1_0);
            let expectedMac=this.cryptoSettings.cipherSuite.mac.computeMAC(isTLS,this.cryptoSettings.macSecret, write(new SSLMACSource(this.sequenceNumber++, type, this.sslProcessor.version, fragment), this.sslProcessor));
            /*console.log('mac found: ',toHex(mac));
            console.log('mac expect:',toHex(expectedMac));*/
            return fragment;
        }
        return data;
    }
}

class Encrypt {
    constructor(sslProcessor, cryptoSettings) {
        this.cryptoSettings = cryptoSettings;
        this.sequenceNumber = 0;
        this.sslProcessor=sslProcessor;
        if (cryptoSettings) {
            this.cipherEncrypt=crypto.createCipheriv(cryptoSettings.cipherSuite.cipher.name, cryptoSettings.key, cryptoSettings.iv);
            this.cipherEncrypt.setAutoPadding(false);
        }
    }
    encrypt(type, fragment) {
        if (this.cryptoSettings && this.cryptoSettings.cipherSuite.cipher.blockMode) {
            let isTLS = this.sslProcessor.version.atLeast(ProtocolVersion.TLS1_0);
            let mac=this.cryptoSettings.cipherSuite.mac.computeMAC(isTLS, this.cryptoSettings.macSecret, write(new SSLMACSource(this.sequenceNumber++, type, this.sslProcessor.version, fragment),this.sslProcessor));
            let blockSize=this.cryptoSettings.cipherSuite.cipher.blockSize;
            let paddingLength=blockSize-(mac.byteLength+fragment.byteLength)% blockSize-1;
            let padding=Buffer.alloc(paddingLength+1).fill(paddingLength);
            padding[paddingLength]=paddingLength;
            console.log("Writing",toHex(fragment),toHex(mac),paddingLength);
            return this.cipherEncrypt.update(Buffer.concat([fragment,mac,padding]));
        }
        return fragment;
    }
}


class SSLProcessor {
    constructor(isClient, version, certificates = [], key) {
        //this.latestVersion=ProtocolVersion.SSL3;
        //this.latestVersion=ProtocolVersion.TLS1_0;
        this.latestVersion=version;
        this.version=ProtocolVersion.SSL3;

        this.handshake=new (isClient ? SSLClientHandshake : SSLServerHandshake)(this, this.latestVersion);

        this.protocolLayers=new Map([
            [ChangeCipher, (changeChiper)=>this.onChangeCipher()],
            [Alert, (alert)=>this.onAlert(alert)],
            [Handshake, (handshake, data)=>this.onHandshake(handshake, data)],
            [ApplicationData, (applicationData)=>this.sendPlainTextData(applicationData.bytes)],
        ].map(([type,handler])=>[type,new PacketProcessor(handler,type,this)]));

        this.recordLayer=new PacketProcessor(record=>this.recordReceived(record),SSLRecord);
        this.ready=false;
        this.isClient =isClient;
        this.certificates=certificates.map(certificate=>pemDecode("CERTIFICATE", certificate));
        this.key=key;
        this.allHandshakes = [];
        this.encrypt = new Encrypt();
        this.decrypt = new Decrypt();
        this.hasShutdown=false;
        this.onShutdown=()=>0;
        this.changeVersion(this.version);

    }

    changeVersion(newVersion) {
        console.log('change version',newVersion);
        this.version=newVersion;
    }


    start() {
        this.handshake.start();
    }


    sendHandshake(body) {
        let data=new Handshake(body);
        let uint8array=write(data, this);
        this.allHandshakes.push(uint8array);
        this.encryptData(data, uint8array, Handshake);
    }

    encryptMessage(data) {
        let uint8array=write(data, this);
        this.encryptData(data, uint8array,data.constructor);
    }

    encryptData(data, uint8array, type) {
        if (this.hasShutdown) return;
        let index=0;
        while (index<uint8array.byteLength) {
            let size=Math.min(uint8array.byteLength, MAX_RECORD_SIZE);
            let unencyptedData=new Uint8Array(uint8array.buffer,index,size);
            let encryptedData=this.encrypt.encrypt(type, unencyptedData);

            let record = write(new SSLRecord(type,this.version,encryptedData));
            //console.log("writing message",size, encryptedData.byteLength,index,uint8array.buffer, record);
            index+=size;

            this.sendEncryptedData(record);
        }

    }

    plainTextReceived(uint8array) {
        try {
            this.encryptMessage(new ApplicationData(uint8array));
        } catch (e) {
            console.log(`Failed to encrypt, error: ${e}`, e.stack);
            this.close();
        }
    }

    encryptedReceived(uint8array) {
        try {
            this.recordLayer.write(uint8array);
        } catch (e) {
            console.log(`Failed to decrypt, error: ${e}`, e.stack);
            this.close();
        }
    }

    recordReceived(record) {
        if (this.hasShutdown) return;
        let protocolLayer=this.protocolLayers.get(record.type);
        let encryptedData=record.data;

        let unencyptedData=this.decrypt.decrypt(record.type, encryptedData);

        protocolLayer.write(unencyptedData);
    }

    onChangeCipher() {
        //console.log("Change cipher");
        this.decrypt=this.pendingDecrypt;
    }

    onAlert(alert) {
        console.log("Alert",alert);
        if (alert.level=="Warning") {
            if (alert.description == "Close") {
                this.encryptMessage(alert);
            }
        }
        this.shutdown();
    }

    error(message) {
        this.close(new Alert("Error",message));
    }


    close(alert=new Alert("Warning","Close")) {
        this.encryptMessage(alert);
        this.shutdown();
    }

    shutdown() {
        this.hasShutdown=true;
        this.sendEncryptedData(null);
        this.sendPlainTextData(null);
        this.onShutdown();
    }

    onHandshake(handshake, data) {
        let priorHandshakes=[...this.allHandshakes];
        this.allHandshakes.push(data);
        this.handshake.onHandshake(handshake,priorHandshakes);

    }

    computeNextState(cipherSuite, clientRandom, serverRandom, preMasterSecret) {

        /*console.log('pre master secret:',toHex(preMasterSecret));
        console.log('clientRandom:',toHex(clientRandom));
        console.log('serverRandom:',toHex(serverRandom));*/
        console.log('pms',toHex(preMasterSecret),'cr',toHex(clientRandom),'sr',toHex(serverRandom));
        //console.log('A, sha:',toHex(sha('A',preMasterSecret,clientRandom,serverRandom)),'md5:',toHex(md5(preMasterSecret,sha('A',preMasterSecret,clientRandom,serverRandom))));

        let masterSecret,keyBlockData;

        if (this.version.atLeast(ProtocolVersion.TLS1_0)) {
            masterSecret=prf(48,preMasterSecret,"master secret",Buffer.concat([clientRandom, serverRandom]));
            keyBlockData=prf(104,masterSecret,"key expansion",Buffer.concat([serverRandom, clientRandom]));
            console.log('masterSecret:',toHex(masterSecret));
            console.log('keyBlockData:',toHex(keyBlockData));
        } else {

            masterSecret=Buffer.concat([
                md5(preMasterSecret,sha('A',preMasterSecret,clientRandom,serverRandom)),
                md5(preMasterSecret,sha('BB',preMasterSecret,clientRandom,serverRandom)),
                md5(preMasterSecret,sha('CCC',preMasterSecret,clientRandom,serverRandom))
            ]);
            //console.log('master secret:',toHex(masterSecret));

            keyBlockData=Buffer.concat(
                ['A','BB','CCC','DDDD','EEEEE','FFFFFF','GGGGGGG'].map(label=>
                    md5(masterSecret, sha(label, masterSecret, serverRandom, clientRandom)))
            );
        }

        let keyBlock =new BufferReader(keyBlockData);

        let clientMACSecret=keyBlock.readBytes(cipherSuite.mac.hashSize);
        let serverMACSecret=keyBlock.readBytes(cipherSuite.mac.hashSize);
        let clientKey=keyBlock.readBytes(cipherSuite.cipher.keyMaterialLength);
        let serverKey=keyBlock.readBytes(cipherSuite.cipher.keyMaterialLength);
        let clientIV=keyBlock.readBytes(cipherSuite.cipher.ivSize);
        let serverIV=keyBlock.readBytes(cipherSuite.cipher.ivSize);
        let clientCrypto=new CryptoSettings(cipherSuite, clientMACSecret, clientKey, clientIV);
        let serverCrypto=new CryptoSettings(cipherSuite, serverMACSecret, serverKey, serverIV);
        console.log('client crypto: '+clientCrypto);
        console.log('server crypto: '+serverCrypto);
        this.pendingEncrypt=new Encrypt(this, this.isClient ? clientCrypto : serverCrypto);
        this.pendingDecrypt=new Decrypt(this, this.isClient ? serverCrypto : clientCrypto);

        return masterSecret;
    }


    changeCipher() {
        this.encryptMessage(new ChangeCipher());
        this.encrypt=this.pendingEncrypt;

    }
}

module.exports = {SSLProcessor}
