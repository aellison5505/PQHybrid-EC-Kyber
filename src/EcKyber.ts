
import { Kyber } from 'node-kyber-1024';
import { Cipher, CipherCCM, CipherGCM, createCipheriv, createDecipheriv, createECDH, DecipherGCM, ECDH, randomFillSync } from 'crypto';
import { ReadStream, WriteStream } from 'fs';
import { Writable, WritableOptions, Readable, pipeline, Transform, TransformOptions, Duplex } from 'stream';
import { Sha3 } from 'node-sidh';
import { promisify } from 'util';
import { threadId } from 'worker_threads';
const pipeLine = promisify(pipeline);


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
            const privateKey = Buffer.alloc((3168 + 32), 0);
            keys.copy(privateKey,0,0,(3168 + 32));
            ret(privateKey);
        });
    }
    /**
     * Takes stream and PublicKey to encrypt data with chacha20-poly1305.
     * @param stream data stream
     * @param publicKey Hybrid key
     * @returns Buffer with packed cipher data.
     */
    encrypt(stream: ReadStream, publicKey: Buffer): Promise<Buffer>;
    encrypt(stream: ReadStream, streamWrite: WriteStream, publicKey: Buffer): Promise<void>;
    encrypt(message: Buffer, streamWrite: WriteStream, publicKey: Buffer): Promise<void>;
    /**
     *  Takes a buffer and PublicKey to encrypt data with chacha20-poly1305.
     * @param message Buffer of data
     * @param publicKey Hybrid key
     * @returns Buffer with packed cipher data.
     */
    encrypt(message: Buffer, publicKey: Buffer): Promise<Buffer>;
    encrypt(_arg1: any, _arg2: any, _arg3?: any): Promise<any> {
        return new Promise<Buffer | void>(async (ret, err) => {

            let msgStream: Readable | ReadStream;
            let keys: Buffer = Buffer.alloc(0);
            let writeStream: _WriteStreamBuffer = new _WriteStreamBuffer();
            let returnWrite;
        
            if(Buffer.isBuffer(_arg1)){
                 msgStream = Readable.from(_arg1 as Buffer);
            } else if(typeof _arg1.on === 'function' ) {
                 msgStream = _arg1 as ReadStream;
            } else {
             err(new Error('invalid input'));
             return
            }

            if(Buffer.isBuffer(_arg2)){
                keys = _arg2 as Buffer;
           } else if(typeof _arg2.on === 'function' ) {
                returnWrite = _arg2 as WriteStream;
           } else {
                err(new Error('invalid input'));
            return
           }

           if(Buffer.isBuffer(_arg3)) {
               keys = _arg3 as Buffer;
           }            

            let kyPub = Buffer.alloc(1568, 0);
            let ecPub = Buffer.alloc(65, 0);
            keys.copy(kyPub,0,0,1568);
            keys.copy(ecPub,0,1568);
            const {cipherBytes: kyCipherBytes, secureKey: kySecureKey} = await this.kyber.encryptKey(kyPub);

            let cryptoEc = this.ec.generateKeys();
            let ecKey = this.ec.computeSecret(ecPub);
            let key = await this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);
           
            let nonce = Buffer.alloc(12);
            randomFillSync(nonce);
            let cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
            let writeEnc = new _EncryptStream(cipher);
            let head = Buffer.concat([nonce, cryptoEc,kyCipherBytes]);
            writeStream.write(head);
            if(returnWrite === undefined) {
                await pipeLine(msgStream, writeEnc, writeStream);
                ret(writeStream.cryptoBytes);
            } else {
                await pipeLine(msgStream, writeEnc, returnWrite);
                ret();
            }
        });
    }

    async decipher(head: Buffer, keys: Buffer) {
        let kyPri = Buffer.alloc(3168, 0);
        let ecPri = Buffer.alloc(32, 0);
        
        keys.copy(kyPri,0,0,3168);
        keys.copy(ecPri,0,3168);
        let nonce = Buffer.alloc(12);
        head.copy(nonce,0,0,(12));
        let ecPubKey = Buffer.alloc(65);
        head.copy(ecPubKey,0,(12),(12+65));
        let kyCryptoBytes = Buffer.alloc(1568);
        head.copy(kyCryptoBytes,0,(12+65),(12+65+1568));
        //  let data = Buffer.alloc(_cipherBytes.length-(12+65+1568));
        //   _cipherBytes.copy(data,0,(12+65+1568), (12+65+1568+data.length));
        // let tag = Buffer.alloc(16);
        //_cipherBytes.copy(tag,0,(12+65+1568+data.length),(12+65+1568+data.length+16));
        // _cipherBytes.copy(data,0,(12+65+1568), (12+65+1568+data.length));
        let kySecureKey = await this.kyber.decryptKey(kyPri,kyCryptoBytes);
        // let cipherStream = Readable.from(data as Buffer);
        this.ec.setPrivateKey(ecPri);
        let ecKey = this.ec.computeSecret(ecPubKey);

        let key = await this.sha3.shake256(Buffer.concat([kySecureKey, ecKey]), 32);

        let cipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });

        return cipher;
    }

    /**
     *  Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.
     * @param cipherBytes Buffer with packed cipher data.
     * @param privateKey Hybrid Key
     * @returns Buffer with decrypted data.
     */
    decrypt(privateKey: Buffer, cipherBytes: Buffer): Promise<Buffer>;
    /**
     * Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.
     * @param cipherBytes  Buffer with packed cipher data.
     * @param privateKey Hybrid Key
     * @param writeStream stream to write data
     * @returns void
     */
    decrypt(privateKey: Buffer, cipherBytes: Buffer, writeStream: WriteStream): Promise<void>;
    decrypt(privateKey: Buffer, readStream: ReadStream, writeStream: WriteStream): Promise<void>;
    decrypt(_keys: Buffer, _arg2: any, _arg3?: WriteStream): Promise<any> {
        return new Promise<Buffer | void>(async (ret, err) => {
            let returnStream;
            let cipherStream;
            if(_arg3) {
                returnStream = _arg3 as WriteStream;
            }
            if(Buffer.isBuffer(_arg2)) {
                cipherStream = Readable.from(_arg2 as Buffer);
            } else if(typeof _arg2.on === 'function' ) {
                cipherStream = _arg2 as ReadStream;
            }
            if(!cipherStream) { 
                throw new Error('no input');
            }
            let writeStream = new _WriteStreamBuffer();
            let writeDec = new _DecryptStream(this.decipher.bind(this), _keys);
            
            if(returnStream === undefined) {
                await pipeLine(cipherStream,writeDec,writeStream);
                ret(writeStream.cryptoBytes);
            } else {
                await pipeLine(cipherStream,writeDec,returnStream);
                ret();
            }
        });
    }
}

class _WriteStreamBuffer extends Duplex {

    private _tempBuf: Array<Buffer>

    constructor(options?: WritableOptions) {
        super(options);
        this._tempBuf = [];
    }

    _read() {
        let data;
        while(data = this._tempBuf.shift()){
            this.push(data);
        }

    }

    _write(chunk: any, encoding: any, callback: Function) {
        if(!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);
        else
            chunk = chunk as Buffer;
        this._tempBuf.push(chunk);
        callback();
    }

     _writev(chunks: any[], callback: Function) {

        for(let i = 0; i < chunks.length; i++ ) {
            const {chunk: _chunk, encoding: _encoding  } = chunks[i];
            if(!Buffer.isBuffer(_chunk))
                var chunkBuf = Buffer.from(_chunk);
            else
                var chunkBuf = _chunk;
            
            this._tempBuf.push(chunkBuf);
           // this._tempBuf = Buffer.concat([this._tempBuf, chunkBuf]);
        }
            callback();
    }

    _final(callback: Function) {
        if(this.readableLength > 0) {
            this._final(callback);
            return;
        }else {
            this.push(null); 
            callback()
         
        }
    }

    get cryptoBytes() {
        return Buffer.concat(this._tempBuf);
    }
}

class _DecryptStream extends Transform {

    decipher: DecipherGCM;
    tag: Buffer;
    callDecipher: boolean;
   
    constructor(private getDecipher: Function, private keys: Buffer, options?: TransformOptions) {
        super(options);
        this.tag = Buffer.alloc(0);
        this.callDecipher = false;
        this.decipher = createDecipheriv('chacha20-poly1305', Buffer.alloc(32,0), Buffer.alloc(12,0), { authTagLength: 16 });
     //   this.decipher.on('readable', () => this.decipherRead())
    }

    private decipherRead() {
        let data;
        while (data = this.decipher.read()) {
            this.push(data);
        }
     //   this.decipher.end();
    }

    _transform(chunk: Buffer | String, encoding: any, callback: Function) {
       
        if(!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);

        if(this.callDecipher === false) {
            this.getDecipher(Buffer.alloc(1645,chunk.slice(0, 1645)), this.keys)
            .then((dec: DecipherGCM) => {
                this.decipher = dec;
                this.decipher.on('readable', () => this.decipherRead());
                chunk = Buffer.alloc(chunk.length - 1645,chunk.slice(1645));
                this.callDecipher = true;
                this._transform(chunk,encoding,callback);
            });
            return;
        }
        if(chunk.length < 16) {
            let tempTag = Buffer.from(this.tag);
            let start = 16-chunk.length;
            tempTag.copy(this.tag, 0, start);
            chunk.copy(this.tag,start,0);
            callback()
            return
        } else {
            let cBytes = Buffer.concat([Buffer.alloc(this.tag.length,this.tag),Buffer.alloc(chunk.length-16,chunk.slice(0,chunk.length-16))]);
            let data = this.decipher.write(cBytes);
            //this.push(data);
            let tagStart = chunk.length - 16;
            this.tag = Buffer.alloc(16, chunk.slice(tagStart));
            callback();
        }
    }

    _flush(callback: Function) {
    //    this.push(null);
        if(this.decipher.readableLength > 0) {
            this.decipherRead();
            this._flush(callback);
            return;
        }else {
            this.push(null)
            this.decipher.setAuthTag(this.tag);
            this.decipher.end(() => {
                
                callback()
            });
        }
    }
}

class _EncryptStream extends Transform {

    constructor(private cipher: CipherCCM, options?: TransformOptions) {
        super(options);
        cipher.on('readable', () => this.cipherRead());
    }

    private cipherRead() {
        let data;
        while (data = this.cipher.read()) {
            this.push(data);
        }
    }

    _transform(chunk: Buffer | String, encoding: any, callback: Function) {
        if(!Buffer.isBuffer(chunk))
            chunk = Buffer.from(chunk);
        if(chunk)
            this.cipher.write(chunk);
        callback();
    }

    _flush(callback: Function) {
        if(this.cipher.readableLength > 0) {
            this.cipherRead();
            this._flush(callback);
            return;
        }else {
        this.cipher.end(() => {
            let tag = this.cipher.getAuthTag();
            this.push(tag);
            this.push(null);
            callback();
            });      
        } 
    }

}