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
    encrypt(_alpha, _keys) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            let msgStream;
            if (Buffer.isBuffer(_alpha)) {
                msgStream = stream_1.Readable.from(_alpha);
            }
            else if (typeof _alpha.on === 'function') {
                msgStream = _alpha;
            }
            else {
                err(new Error('invalid input'));
                return;
            }
            let kyPub = Buffer.alloc(1568, 0);
            let ecPub = Buffer.alloc(65, 0);
            _keys.copy(kyPub, 0, 0, 1568);
            _keys.copy(ecPub, 0, 1568);
            const { cipherBytes: kyCipherBytes, secureKey: kySecureKey } = yield this.kyber.encryptKey(kyPub);
            let cryptoEc = this.ec.generateKeys();
            let ecKey = this.ec.computeSecret(ecPub);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let nonce = Buffer.alloc(12);
            crypto_1.randomFillSync(nonce);
            let cipher = crypto_1.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let writeStream = new _WriteStreamBuffer();
            let writeEnc = new _EncryptStream(cipher);
            let head = Buffer.concat([nonce, cryptoEc, kyCipherBytes]);
            writeStream.write(head);
            writeStream.on('finish', () => {
                ret(writeStream.tempBuf);
            });
            msgStream.pipe(writeEnc).pipe(writeStream);
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
            let data = Buffer.alloc(_cipherBytes.length - (12 + 65 + 1568 + 16));
            _cipherBytes.copy(data, 0, (12 + 65 + 1568), (12 + 65 + 1568 + data.length));
            let tag = Buffer.alloc(16);
            _cipherBytes.copy(tag, 0, (12 + 65 + 1568 + data.length), (12 + 65 + 1568 + data.length + 16));
            let kySecureKey = yield this.kyber.decryptKey(kyPri, kyCryptoBytes);
            this.ec.setPrivateKey(ecPri);
            let ecKey = this.ec.computeSecret(ecPubKey);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let cipher = crypto_1.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let decData = Buffer.alloc(0);
            decData = cipher.update(data);
            cipher.setAuthTag(tag);
            cipher.final();
            ret(decData);
        }));
    }
}
exports.EcKyber = EcKyber;
class _WriteStreamBuffer extends stream_1.Writable {
    constructor(options) {
        super(options);
        this._tempBuf = Buffer.alloc(0);
    }
    _writev(chunks, callback) {
        for (let i = 0; i < chunks.length; i++) {
            const { chunk: _chunk, encoding: _encoding } = chunks[i];
            if (!Buffer.isBuffer(_chunk))
                var chunkBuf = Buffer.from(_chunk);
            else
                var chunkBuf = _chunk;
            this._tempBuf = Buffer.concat([this._tempBuf, chunkBuf]);
        }
        callback();
    }
    get tempBuf() {
        return this._tempBuf;
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