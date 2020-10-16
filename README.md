# PQHybrid-EC-Kyber
Hybrid encryption scheme that takes an EC curve secp256k1, pq-crystals kyber 1024, and chacha20-poly1305 or aes-256-gcm to encrypt data. The returned data is a packed Buffer with the Kyber CryptoBytes, EC public key, nonce/iv, tag, and encrypted data.
