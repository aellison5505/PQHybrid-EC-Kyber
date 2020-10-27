const { EcKyber } = require('../lib/index');
const { createReadStream, createWriteStream, existsSync, statSync, unlink, unlinkSync } = require('fs');
const expect = require('chai').expect;
//const path = require('path').basename(__dirname);

describe('PQHybrid-EC-Kyber',() => {
    before(() => {
        this.ecK = new EcKyber();
    });
    describe('#createKeyPair', () => {
        before(async () => {
            this.keys = await this.ecK.createKeyPair();
        });
        it('should return all keys', () => {
            expect(this.keys.length).to.be.equal(4833);
        });
    });

    describe('#getPrivateKeys', () => {
        before(async () => {
            this.privateKey = await this.ecK.getPrivateKeys(this.keys);
        });
        it('should return privateKey key', () => {
            expect(this.privateKey.length).to.be.equal(3168 + 32);
        });
    });

    describe('#getPublicKeys', () => {
        before(async () => {
            this.publicKey = await this.ecK.getPublicKeys(this.keys);
        });
        it('should return publicKey key', () => {
            expect(this.publicKey.length).to.be.equal(1568 + 65);
        });
    });
    
    describe('#encrypt', () => {
        before(async () => {
            this.data = Buffer.from('The cat in the Hat ate the Cat!');
            this.encData = await this.ecK.encrypt(this.data,this.publicKey);
        });
        it('should return cipherData', () => {
            expect(this.encData.length).to.be.equal(1692);
        });
    });

    describe('#decrypt', () => {
        before(async () => {
            this.retData = await this.ecK.decrypt(this.privateKey, this.encData);
        });
        it('should return decrypted data equal to message data', () => {
            expect(this.retData.toString('hex')).to.be.equal(this.data.toString('hex'));
        });
    });

    describe('#encrypt - stream', () => {
        before(async () => {
            this.dStream = createReadStream(`${__dirname}/testMsg.txt`);
            this.data = Buffer.from('The cat in the Hat ate the Cat!');
            this.encDataStream = await this.ecK.encrypt(this.dStream,this.publicKey);
        });
        it('should return cipherData', () => {
            expect(this.encDataStream.length).to.be.equal(1692);
        });
    });

    describe('#decrypt - Stream', () => {
        before(async () => {
            this.rStream = createWriteStream(`${__dirname}/retMsg.txt`);
            await this.ecK.decrypt(this.privateKey,this.encDataStream, this.rStream);
        });
        it('should return decrypted data equal to message data', () => {
            let stats = statSync(`${__dirname}/retMsg.txt`);
            expect(stats.size).to.be.equal(this.data.length);
        });
    });

    describe('#encrypt - stream - stream', () => {
        before(async () => {
            this.dStream = createReadStream(`${__dirname}/testMsg.txt`);
            this.wStream = createWriteStream(`${__dirname}/testCrypto`)
            this.data = Buffer.from('The cat in the Hat ate the Cat!');
            await this.ecK.encrypt(this.dStream,this.wStream,this.publicKey);
        });
        it('should return cipherData', () => {
            let stats = statSync(`${__dirname}/testCrypto`);
            expect(stats.size).to.be.equal(1692);
        });
    });

    describe('#decrypt - Stream - Stream', () => {
        before(async () => {
            this.rStream = createWriteStream(`${__dirname}/retMsg.txt`);
            this.cStream = createReadStream(`${__dirname}/testCrypto`);
            await this.ecK.decrypt(this.privateKey, this.cStream, this.rStream);
        });
        it('should return decrypted data equal to message data', () => {
            let stats = statSync(`${__dirname}/retMsg.txt`);
            expect(stats.size).to.be.equal(this.data.length);
        });
    });


    after(() => {
        unlinkSync(`${__dirname}/testCrypto`);
        unlinkSync(`${__dirname}/retMsg.txt`);
    });
   
});
