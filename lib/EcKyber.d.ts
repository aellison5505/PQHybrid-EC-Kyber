/// <reference types="node" />
import { Kyber } from 'node-kyber-1024';
import { ECDH } from 'crypto';
import { ReadStream, WriteStream } from 'fs';
import { Sha3 } from 'node-sidh';
export declare class EcKyber {
    kyber: Kyber;
    ec: ECDH;
    sha3: Sha3;
    constructor();
    createKeyPair(): Promise<Buffer>;
    getPublicKeys(keys: Buffer): Promise<Buffer>;
    getPrivateKeys(keys: Buffer): Promise<Buffer>;
    encrypt(fileStream: ReadStream, publicKeys: Buffer): Promise<Buffer>;
    encrypt(message: Buffer, publicKeys: Buffer): Promise<Buffer>;
    decrypt(cipherBytes: Buffer, privateKeys: Buffer): Promise<Buffer>;
    decrypt(cipherBytes: Buffer, privateKeys: Buffer, writeStream: WriteStream): Promise<void>;
}
//# sourceMappingURL=EcKyber.d.ts.map