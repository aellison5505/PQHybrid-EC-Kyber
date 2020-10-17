
<a name="readmemd"></a>

**[pqhybrid-ec-kyber](#readmemd)**

> [Globals](#globalsmd)

# PQHybrid-EC-Kyber

[![Build Status](https://travis-ci.com/aellison5505/PQHybrid-EC-Kyber.svg?branch=main)](https://travis-ci.com/aellison5505/PQHybrid-EC-Kyber)

### PQHybrid-EC-Kyber creates a hybrid EC secp256k1 and PQ Kyber key.
### It also encrypts data with the combined keys using chacha20-poly1305.


<a name="classes_eckyber_eckybermd"></a>

**[pqhybrid-ec-kyber](#readmemd)**

> [Globals](#globalsmd) / ["EcKyber"](#modules_eckyber_md) / EcKyber

# Class: EcKyber

## Hierarchy

* **EcKyber**

## Index

### Constructors

* [constructor](#constructor)

### Properties

* [ec](#ec)
* [kyber](#kyber)
* [sha3](#sha3)

### Methods

* [createKeyPair](#createkeypair)
* [decrypt](#decrypt)
* [encrypt](#encrypt)
* [getPrivateKeys](#getprivatekeys)
* [getPublicKeys](#getpublickeys)

## Constructors

### constructor

\+ **new EcKyber**(): [EcKyber](#classes_eckyber_eckybermd)

*Defined in EcKyber.ts:12*

EcKyber Class creates a hybrid EC secp256k1 and PQ Kyber keys.
It also encrypts data with the combined keys using chacha20-poly1305.

**Returns:** [EcKyber](#classes_eckyber_eckybermd)

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


<a name="globalsmd"></a>

**[pqhybrid-ec-kyber](#readmemd)**

> Globals

# pqhybrid-ec-kyber

## Index

### Modules

* ["EcKyber"](#modules_eckyber_md)
* ["index"](#modules_index_md)


<a name="modules_eckyber_md"></a>

**[pqhybrid-ec-kyber](#readmemd)**

> [Globals](#globalsmd) / "EcKyber"

# Module: "EcKyber"

## Index

### Classes

* [EcKyber](#classes_eckyber_eckybermd)


<a name="modules_index_md"></a>

**[pqhybrid-ec-kyber](#readmemd)**

> [Globals](#globalsmd) / "index"

# Module: "index"

## Index

### References

* [EcKyber](#eckyber)

## References

### EcKyber

Re-exports: [EcKyber](#classes_eckyber_eckybermd)
