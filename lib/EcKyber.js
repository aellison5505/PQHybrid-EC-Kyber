"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcKyber = void 0;
const node_kyber_1024_1 = require("node-kyber-1024");
const crypto_1 = require("crypto");
const stream_1 = require("stream");
const node_sidh_1 = require("node-sidh");
const util_1 = require("util");
const pipeLine = util_1.promisify(stream_1.pipeline);
class EcKyber {
    /**
     * EcKyber Class creates a hybrid EC secp256k1 and PQ Kyber keys.
     * It also encrypts data with the combined keys using chacha20-poly1305.
     */
    constructor() {
        this.kyber = new node_kyber_1024_1.Kyber();
        this.ec = crypto_1.createECDH('secp256k1');
        this.sha3 = new node_sidh_1.Sha3();
    }
    /**
     * Creates the combined key pair.
     * @returns Buffer with packed private and public keys.
     */
    createKeyPair() {
        return new Promise((ret) => __awaiter(this, void 0, void 0, function* () {
            const { privateKey: KyPri, publicKey: KyPub } = yield this.kyber.createKeys();
            this.ec.generateKeys();
            const EcPri = this.ec.getPrivateKey();
            const EcPub = this.ec.getPublicKey();
            // keys length = 3168, 32, 1568, 65
            const keys = Buffer.concat([KyPri, EcPri, KyPub, EcPub]);
            ret(keys);
        }));
    }
    /**
     * Gets the PublicKey,
     * @param keys Hybrid Keys
     * @returns Buffer with the packed PublicKey
     */
    getPublicKeys(keys) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            if (keys.length !== 4833) {
                err(new Error('invalid length'));
                return;
            }
            const pubKeys = Buffer.alloc((1568 + 65), 0);
            keys.copy(pubKeys, 0, (3168 + 32));
            ret(pubKeys);
        }));
    }
    /**
     *Gets the PrivateKey,
    * @param keys Hybrid Keys
    * @returns Buffer with the packed PrivateKey
     */
    getPrivateKeys(keys) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            if (keys.length !== 4833) {
                err(new Error('invalid length'));
                return;
            }
            const privateKey = Buffer.alloc((3168 + 32), 0);
            keys.copy(privateKey, 0, 0, (3168 + 32));
            ret(privateKey);
        }));
    }
    encrypt(_arg1, _arg2, _arg3) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            let msgStream;
            let keys = Buffer.alloc(0);
            let writeStream = new _WriteStreamBuffer();
            let returnWrite;
            if (Buffer.isBuffer(_arg1)) {
                msgStream = stream_1.Readable.from(_arg1);
            }
            else if (typeof _arg1.on === 'function') {
                msgStream = _arg1;
            }
            else {
                err(new Error('invalid input'));
                return;
            }
            if (Buffer.isBuffer(_arg2)) {
                keys = _arg2;
            }
            else if (typeof _arg2.on === 'function') {
                returnWrite = _arg2;
            }
            else {
                err(new Error('invalid input'));
                return;
            }
            if (Buffer.isBuffer(_arg3)) {
                keys = _arg3;
            }
            let kyPub = Buffer.alloc(1568, 0);
            let ecPub = Buffer.alloc(65, 0);
            keys.copy(kyPub, 0, 0, 1568);
            keys.copy(ecPub, 0, 1568);
            const { cipherBytes: kyCipherBytes, secureKey: kySecureKey } = yield this.kyber.encryptKey(kyPub);
            let cryptoEc = this.ec.generateKeys();
            let ecKey = this.ec.computeSecret(ecPub);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let nonce = Buffer.alloc(12);
            crypto_1.randomFillSync(nonce);
            let cipher = crypto_1.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let writeEnc = new _EncryptStream(cipher);
            let head = Buffer.concat([nonce, cryptoEc, kyCipherBytes]);
            writeStream.write(head);
            if (returnWrite === undefined) {
                writeStream.on('finish', () => {
                    ret(writeStream.cryptoBytes);
                });
                msgStream.pipe(writeEnc).pipe(writeStream);
            }
            else {
                yield pipeLine(msgStream, writeEnc, writeStream, returnWrite);
                ret();
            }
        }));
    }
    decrypt(_cipherBytes, _keys, _writeStream) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            let kyPri = Buffer.alloc(3168, 0);
            let ecPri = Buffer.alloc(32, 0);
            _keys.copy(kyPri, 0, 0, 3168);
            _keys.copy(ecPri, 0, 3168);
            let nonce = Buffer.alloc(12);
            _cipherBytes.copy(nonce, 0, 0, (12));
            let ecPubKey = Buffer.alloc(65);
            _cipherBytes.copy(ecPubKey, 0, (12), (12 + 65));
            let kyCryptoBytes = Buffer.alloc(1568);
            _cipherBytes.copy(kyCryptoBytes, 0, (12 + 65), (12 + 65 + 1568));
            let data = Buffer.alloc(_cipherBytes.length - (12 + 65 + 1568));
            //   _cipherBytes.copy(data,0,(12+65+1568), (12+65+1568+data.length));
            let tag = Buffer.alloc(16);
            _cipherBytes.copy(tag, 0, (12 + 65 + 1568 + data.length), (12 + 65 + 1568 + data.length + 16));
            _cipherBytes.copy(data, 0, (12 + 65 + 1568), (12 + 65 + 1568 + data.length));
            let kySecureKey = yield this.kyber.decryptKey(kyPri, kyCryptoBytes);
            let cipherStream = stream_1.Readable.from(data);
            this.ec.setPrivateKey(ecPri);
            let ecKey = this.ec.computeSecret(ecPubKey);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let cipher = crypto_1.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let decData = Buffer.alloc(0);
            let writeStream = new _WriteStreamBuffer();
            let writeDec = new _DecryptStream(cipher);
            writeStream.on('finish', () => {
                ret(writeStream.cryptoBytes);
            });
            cipherStream.pipe(writeDec).pipe(writeStream);
        }));
    }
}
exports.EcKyber = EcKyber;
class _WriteStreamBuffer extends stream_1.Duplex {
    constructor(options) {
        super(options);
        this._tempBuf = [];
    }
    _read() {
        let data;
        while (data = this._tempBuf.shift()) {
            this.push(data);
        }
    }
    _write(chunk, encoding, callback) {
        if (!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);
        else
            chunk = chunk;
        this._tempBuf.push(chunk);
        callback();
    }
    _writev(chunks, callback) {
        for (let i = 0; i < chunks.length; i++) {
            const { chunk: _chunk, encoding: _encoding } = chunks[i];
            if (!Buffer.isBuffer(_chunk))
                var chunkBuf = Buffer.from(_chunk);
            else
                var chunkBuf = _chunk;
            this._tempBuf.push(chunkBuf);
            // this._tempBuf = Buffer.concat([this._tempBuf, chunkBuf]);
        }
        callback();
    }
    _final(callback) {
        this.push(null);
        callback();
    }
    get cryptoBytes() {
        return Buffer.concat(this._tempBuf);
    }
}
class _DecryptStream extends stream_1.Transform {
    constructor(decipher, options) {
        super(options);
        this.decipher = decipher;
        this.tag = Buffer.alloc(0);
        this.decipher.on('readable', () => this.decipherRead());
    }
    decipherRead() {
        let data;
        while (data = this.decipher.read()) {
            this.push(data);
        }
    }
    _transform(chunk, encoding, callback) {
        if (!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);
        if (chunk.length < 16) {
            let tempTag = Buffer.from(this.tag);
            let start = 16 - chunk.length;
            tempTag.copy(this.tag, 0, start);
            chunk.copy(this.tag, start, 0);
            callback();
            return;
        }
        else {
            this.decipher.write(Buffer.concat([Buffer.alloc(this.tag.length, this.tag), Buffer.alloc(chunk.length - 16, chunk.slice(0, chunk.length - 16))]));
            let tagStart = chunk.length - 16;
            this.tag = Buffer.alloc(16, chunk.slice(tagStart));
            callback();
        }
    }
    _flush(callback) {
        this.decipher.setAuthTag(this.tag);
        this.decipher.end(() => {
            callback();
        });
    }
}
class _EncryptStream extends stream_1.Transform {
    constructor(cipher, options) {
        super(options);
        this.cipher = cipher;
        cipher.on('readable', () => this.cipherRead());
    }
    cipherRead() {
        let data;
        while (data = this.cipher.read()) {
            this.push(data);
        }
    }
    _transform(chunk, encoding, callback) {
        if (!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);
        if (chunk)
            this.cipher.write(chunk);
        callback();
    }
    _flush(callback) {
        this.cipher.end(() => {
            let tag = this.cipher.getAuthTag();
            this.push(tag);
            callback();
        });
    }
}
//# sourceMappingURL=EcKyber.js.map