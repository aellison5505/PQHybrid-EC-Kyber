const { EcKyber } = require('../lib/index');
const { createReadStream } = require('fs');
const expect = require('chai').expect;

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
            expect(Buffer.isBuffer(this.encData)).to.be.true;
        });
    });

    describe('#decrypt', () => {
        before(async () => {
            this.retData = await this.ecK.decrypt(this.encData,this.privateKey);
        });
        it('should return decrypted data equal to message data', () => {
            expect(this.retData.toString('hex')).to.be.equal(this.data.toString('hex'));
        });
    });

    describe('#encrypt - stream', () => {
        before(async () => {
            this.dStream = createReadStream('/mnt/d/dev/PQHybrid-EC-Kyber/test/testMsg.txt');
            this.data = Buffer.from('The cat in the Hat ate the Cat!');
            this.encDataStream = await this.ecK.encrypt(this.dStream,this.publicKey);
        });
        it('should return cipherData', () => {
            expect(Buffer.isBuffer(this.encDataStream)).to.be.true;
        });
    });

    describe('#decrypt - Stream', () => {
        before(async () => {
            this.retData = await this.ecK.decrypt(this.encDataStream,this.privateKey);
        });
        it('should return decrypted data equal to message data', () => {
            expect(this.retData.toString('hex')).to.be.equal(this.data.toString('hex'));
        });
    });
    
});
