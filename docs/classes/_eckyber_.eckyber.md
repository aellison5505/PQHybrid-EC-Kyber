**[pqhybrid-ec-kyber](../README.md)**

> [Globals](../globals.md) / ["EcKyber"](../modules/_eckyber_.md) / EcKyber

# Class: EcKyber

## Hierarchy

* **EcKyber**

## Index

### Constructors

* [constructor](_eckyber_.eckyber.md#constructor)

### Properties

* [ec](_eckyber_.eckyber.md#ec)
* [kyber](_eckyber_.eckyber.md#kyber)
* [sha3](_eckyber_.eckyber.md#sha3)

### Methods

* [createKeyPair](_eckyber_.eckyber.md#createkeypair)
* [decrypt](_eckyber_.eckyber.md#decrypt)
* [encrypt](_eckyber_.eckyber.md#encrypt)
* [getPrivateKeys](_eckyber_.eckyber.md#getprivatekeys)
* [getPublicKeys](_eckyber_.eckyber.md#getpublickeys)

## Constructors

### constructor

\+ **new EcKyber**(): [EcKyber](_eckyber_.eckyber.md)

*Defined in EcKyber.ts:12*

EcKyber Class creates a hybrid EC secp256k1 and PQ Kyber keys.
It also encrypts data with the combined keys using chacha20-poly1305.

**Returns:** [EcKyber](_eckyber_.eckyber.md)

## Properties

### ec

•  **ec**: ECDH

*Defined in EcKyber.ts:11*

___

### kyber

•  **kyber**: Kyber

*Defined in EcKyber.ts:10*

___

### sha3

•  **sha3**: Sha3

*Defined in EcKyber.ts:12*

## Methods

### createKeyPair

▸ **createKeyPair**(): Promise\<Buffer>

*Defined in EcKyber.ts:28*

Creates the combined key pair.

**Returns:** Promise\<Buffer>

Buffer with packed private and public keys.

___

### decrypt

▸ **decrypt**(`cipherBytes`: Buffer, `privateKey`: Buffer): Promise\<Buffer>

*Defined in EcKyber.ts:137*

 Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`cipherBytes` | Buffer | Buffer with packed cipher data. |
`privateKey` | Buffer | Hybrid Key |

**Returns:** Promise\<Buffer>

Buffer with decrypted data.

▸ **decrypt**(`cipherBytes`: Buffer, `privateKey`: Buffer, `writeStream`: WriteStream): Promise\<void>

*Defined in EcKyber.ts:145*

Takes packed cipher data and PublicKey to decrypt data with chacha20-poly1305.

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`cipherBytes` | Buffer | Buffer with packed cipher data. |
`privateKey` | Buffer | Hybrid Key |
`writeStream` | WriteStream | stream to write data |

**Returns:** Promise\<void>

void

___

### encrypt

▸ **encrypt**(`stream`: ReadStream, `publicKey`: Buffer): Promise\<Buffer>

*Defined in EcKyber.ts:79*

Takes stream and PublicKey to encrypt data with chacha20-poly1305.

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`stream` | ReadStream | data stream |
`publicKey` | Buffer | Hybrid key |

**Returns:** Promise\<Buffer>

Buffer with packed cipher data.

▸ **encrypt**(`message`: Buffer, `publicKey`: Buffer): Promise\<Buffer>

*Defined in EcKyber.ts:86*

 Takes a buffer and PublicKey to encrypt data with chacha20-poly1305.

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`message` | Buffer | Buffer of data |
`publicKey` | Buffer | Hybrid key |

**Returns:** Promise\<Buffer>

Buffer with packed cipher data.

___

### getPrivateKeys

▸ **getPrivateKeys**(`keys`: Buffer): Promise\<Buffer>

*Defined in EcKyber.ts:62*

Gets the PrivateKey,

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`keys` | Buffer | Hybrid Keys |

**Returns:** Promise\<Buffer>

Buffer with the packed PrivateKey

___

### getPublicKeys

▸ **getPublicKeys**(`keys`: Buffer): Promise\<Buffer>

*Defined in EcKyber.ts:45*

Gets the PublicKey,

#### Parameters:

Name | Type | Description |
------ | ------ | ------ |
`keys` | Buffer | Hybrid Keys |

**Returns:** Promise\<Buffer>

Buffer with the packed PublicKey
