
import { Kyber } from 'node-kyber-1024';
import { createCipheriv, createDecipheriv, createECDH, ECDH, randomFillSync } from 'crypto';
import { ReadStream, WriteStream } from 'fs';
import { Sha3 } from 'node-sidh';


export class EcKyber {

    kyber: Kyber;
    ec: ECDH;
    sha3: Sha3;

    /**
     * EcKyber Class creates a hybrid EC secp256k1 and PQ Kyber keys.
     * It also encrypts data with the combined keys using chacha20-poly1305.
     */
    constructor() {
        this.kyber = new Kyber();
        this.ec = createECDH('secp256k1');
        this.sha3 = new Sha3();
    }

    /**
     * Creates the combined key pair.
     * @returns Buffer with packed private and public keys.
     */
    createKeyPair(): Promise<Buffer> {
        return new Promise<Buffer>(async (ret) => {
           const { privateKey: KyPri, publicKey: KyPub } =  await this.kyber.createKeys();
           this.ec.generateKeys();
           const EcPri = this.ec.getPrivateKey();
           const EcPub = this.ec.getPublicKey();
           // keys length = 3168, 32, 1568, 65
           const keys = Buffer.concat([KyPri, EcPri, KyPub, EcPub]);
           ret(keys);     
        });
    }

    /**
     * Gets the PublicKey,
     * @param keys Hybrid Keys
     * @returns Buffer with the packed PublicKey
     */
    getPublicKeys(keys: Buffer): Promise<Buffer> {
        return new Promise<Buffer>(async (ret, err) => {
            if(keys.length !== 4833) {
                err(new Error('invalid length'));
                return;
            }
            const pubKeys = Buffer.alloc((1568 + 65), 0);
            keys.copy(pubKeys,0,(3168 + 32));
            ret(pubKeys);
        });
    }

    /**
     *Gets the PrivateKey,
    * @param keys Hybrid Keys
    * @returns Buffer with the packed PrivateKey 
     */
    getPrivateKeys(keys: Buffer): Promise<Buffer> {
        return new Promise<Buffer>(async (ret, err) => {
            if(keys.length !== 4833) {
                err(new Error('invalid length'));
                return;
            }
            const pribKeys = Buffer.alloc((3168 + 32), 0);
            keys.copy(pribKeys,0,0,(3168 + 32));
            ret(pribKeys);
        });
    }
    /**
     * Takes stream and PublicKey to encrypt data with chacha20-poly1305.
     * @param stream data stream
     * @param publicKey Hybrid key
     * @returns Buffer with packed cipher data.
     */
    encrypt(stream: ReadStream, publicKey: Buffer): Promise<Buffer>;
    /**
     *  Takes a buffer and PublicKey to encrypt data with chacha20-poly1305.
     * @param message Buffer of data
     * @param publicKey Hybrid key
     * @returns Buffer with packed cipher data.
     */
    encrypt(message: Buffer, publicKey: Buffer): Promise<Buffer>;
    encrypt(_alpha: any, _keys: Buffer): Promise<Buffer> {
        return new Promise<Buffer>(async (ret, err) => {

            let kyPub = Buffer.alloc(1568, 0);
            let ecPub = Buffer.alloc(65, 0);
            _keys.copy(kyPub,0,0,1568);
            _keys.copy(ecPub,0,1568);
            const {cipherBytes: kyCipherBytes, secureKey: kySecureKey} = await this.kyber.encryptKey(kyPub);

            let cryptoEc = this.ec.generateKeys();
            let ecKey = this.ec.computeSecret(ecPub);
            let key = await this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
            let msg:Buffer;
            let msgStream: ReadStream;

           if(Buffer.isBuffer(_alpha)){
               msg = _alpha as Buffer;
           } else if(typeof _alpha.on === 'function' ) {
                msgStream = _alpha as ReadStream;
               console.log('to do stream')
               err(new Error('invaid input'));
               return
           } else {
            console.log('to do stream')
            err(new Error('invalid input'));
            return
           }

        let nonce = Buffer.alloc(12);
        randomFillSync(nonce);
      
        let cipher = createCipheriv('chacha20-poly1305' as any, key, nonce, { authTagLength: 16 });
        let encData = Buffer.alloc(0);
        if(msg) {
            encData = cipher.update(msg);
        }
        cipher.final();
        let tag = cipher.getAuthTag();
        // pack = 12, 16, 65, 1568, variable
        let pack = Buffer.concat([nonce,tag, cryptoEc,kyCipherBytes,encData]);
        ret(pack);
        });
    }

    /**
     *  Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.
     * @param cipherBytes Buffer with packed cipher data.
     * @param privateKey Hybrid Key
     * @returns Buffer with decrypted data.
     */
    decrypt(cipherBytes: Buffer, privateKey: Buffer): Promise<Buffer>;
    /**
     * Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.
     * @param cipherBytes  Buffer with packed cipher data.
     * @param privateKey Hybrid Key
     * @param writeStream stream to write data
     * @returns void
     */
    decrypt(cipherBytes: Buffer, privateKey: Buffer, writeStream: WriteStream): Promise<void>;
    decrypt(_cipherBytes: Buffer, _keys: Buffer, _writeStream?: WriteStream): Promise<any> {
        return new Promise<Buffer | void>(async (ret, err) => {
            let kyPri = Buffer.alloc(3168, 0);
            let ecPri = Buffer.alloc(32, 0);

            _keys.copy(kyPri,0,0,3168);
            _keys.copy(ecPri,0,3168);

            let nonce = Buffer.alloc(12);
            _cipherBytes.copy(nonce,0,0,(12));
            let tag = Buffer.alloc(16);
            _cipherBytes.copy(tag,0,(12),(12+16));
            let ecPubKey = Buffer.alloc(65);
            _cipherBytes.copy(ecPubKey,0,(12+16),(12+16+65));
            let kyCryptoBytes = Buffer.alloc(1568);
            _cipherBytes.copy(kyCryptoBytes,0,(12+16+65),(12+16+65+1568));
            let data = Buffer.alloc(_cipherBytes.length-(12+16+65+1568));
            _cipherBytes.copy(data,0,(12+16+65+1568), (12+16+65+1568+data.length));

            let kySecureKey = await this.kyber.decryptKey(kyPri,kyCryptoBytes);

            this.ec.setPrivateKey(ecPri);
            let ecKey = this.ec.computeSecret(ecPubKey);

            let key = await this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);

            let cipher = createDecipheriv('chacha20-poly1305' as any, key, nonce, { authTagLength: 16 });
            let decData = Buffer.alloc(0);
            cipher.setAuthTag(tag);
            decData = cipher.update(data);
            cipher.final();
            ret(decData);

        });
    }


}