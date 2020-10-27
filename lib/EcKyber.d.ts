/// <reference types="node" />
import { Kyber } from 'node-kyber-1024';
import { ECDH } from 'crypto';
import { ReadStream, WriteStream } from 'fs';
import { Sha3 } from 'node-sidh';
export declare class EcKyber {
    kyber: Kyber;
    ec: ECDH;
    sha3: Sha3;
    /**
     * EcKyber Class creates a hybrid EC secp256k1 and PQ Kyber keys.
     * It also encrypts data with the combined keys using chacha20-poly1305.
     */
    constructor();
    /**
     * Creates the combined key pair.
     * @returns Buffer with packed private and public keys.
     */
    createKeyPair(): Promise<Buffer>;
    /**
     * Gets the PublicKey,
     * @param keys Hybrid Keys
     * @returns Buffer with the packed PublicKey
     */
    getPublicKeys(keys: Buffer): Promise<Buffer>;
    /**
     *Gets the PrivateKey,
    * @param keys Hybrid Keys
    * @returns Buffer with the packed PrivateKey
     */
    getPrivateKeys(keys: Buffer): Promise<Buffer>;
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
    decipher(head: Buffer, keys: Buffer): Promise<import("crypto").DecipherCCM>;
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
}
//# sourceMappingURL=EcKyber.d.ts.map