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
            const pribKeys = Buffer.alloc((3168 + 32), 0);
            keys.copy(pribKeys, 0, 0, (3168 + 32));
            ret(pribKeys);
        }));
    }
    encrypt(_alpha, _keys) {
        return new Promise((ret, err) => __awaiter(this, void 0, void 0, function* () {
            let kyPub = Buffer.alloc(1568, 0);
            let ecPub = Buffer.alloc(65, 0);
            _keys.copy(kyPub, 0, 0, 1568);
            _keys.copy(ecPub, 0, 1568);
            const { cipherBytes: kyCipherBytes, secureKey: kySecureKey } = yield this.kyber.encryptKey(kyPub);
            let cryptoEc = this.ec.generateKeys();
            let ecKey = this.ec.computeSecret(ecPub);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let msg;
            let msgStream;
            if (Buffer.isBuffer(_alpha)) {
                msg = _alpha;
            }
            else if (typeof _alpha.on === 'function') {
                msgStream = _alpha;
                console.log('to do stream');
                err(new Error('invaid input'));
                return;
            }
            else {
                console.log('to do stream');
                err(new Error('invalid input'));
                return;
            }
            let nonce = Buffer.alloc(12);
            crypto_1.randomFillSync(nonce);
            let cipher = crypto_1.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let encData = Buffer.alloc(0);
            if (msg) {
                encData = cipher.update(msg);
            }
            cipher.final();
            let tag = cipher.getAuthTag();
            // pack = 12, 16, 65, 1568, variable
            let pack = Buffer.concat([nonce, tag, cryptoEc, kyCipherBytes, encData]);
            ret(pack);
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
            let tag = Buffer.alloc(16);
            _cipherBytes.copy(tag, 0, (12), (12 + 16));
            let ecPubKey = Buffer.alloc(65);
            _cipherBytes.copy(ecPubKey, 0, (12 + 16), (12 + 16 + 65));
            let kyCryptoBytes = Buffer.alloc(1568);
            _cipherBytes.copy(kyCryptoBytes, 0, (12 + 16 + 65), (12 + 16 + 65 + 1568));
            let data = Buffer.alloc(_cipherBytes.length - (12 + 16 + 65 + 1568));
            _cipherBytes.copy(data, 0, (12 + 16 + 65 + 1568), (12 + 16 + 65 + 1568 + data.length));
            let kySecureKey = yield this.kyber.decryptKey(kyPri, kyCryptoBytes);
            this.ec.setPrivateKey(ecPri);
            let ecKey = this.ec.computeSecret(ecPubKey);
            let key = yield this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let cipher = crypto_1.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let decData = Buffer.alloc(0);
            cipher.setAuthTag(tag);
            decData = cipher.update(data);
            cipher.final();
            ret(decData);
        }));
    }
}
exports.EcKyber = EcKyber;
//# sourceMappingURL=EcKyber.js.map