"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const promises_1 = require("stream/promises");
const test_1 = require("./test");
const writer_1 = __importDefault(require("./writer"));
describe('JoseStreamWriter', () => {
    it('writes a JOSE stream', async () => {
        const joseStreamWriter = new writer_1.default({
            recipient: [
                {
                    key: test_1.ecdhKeyPair.publicKey,
                    alg: 'ECDH-ES+A256KW',
                    kid: test_1.ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
                }
            ],
            encryption: {
                enc: 'A256GCM'
            },
            signature: {
                publicKey: test_1.signingKeyPair.publicKey,
                privateKey: test_1.signingKeyPair.privateKey,
                alg: 'EdDSA',
                crv: 'Ed25519',
                plaintextHash: 'blake2b512',
                ciphertextHash: 'blake2b512'
            },
            chunkSize: 256
        });
        const input = (0, fs_1.createReadStream)('./test.txt');
        const output = (0, fs_1.createWriteStream)('./test.jsonl');
        await (0, promises_1.pipeline)(input, joseStreamWriter, output);
    });
});
//# sourceMappingURL=writer.test.js.map