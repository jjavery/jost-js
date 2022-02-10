"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const promises_1 = require("stream/promises");
const test_1 = require("./test");
const writer_1 = __importDefault(require("./writer"));
describe('JostWriter', () => {
    it('writes a jost stream', async () => {
        const recipient = {
            key: test_1.ecdhKeyPair.publicKey,
            alg: 'ECDH-ES+A256KW',
            kid: test_1.ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
        };
        const jostWriter = new writer_1.default({
            recipients: [recipient],
            encryption: {
                enc: 'A256GCM'
            },
            signature: {
                publicKey: test_1.signingKeyPair.publicKey,
                privateKey: test_1.signingKeyPair.privateKey,
                alg: 'EdDSA',
                crv: 'Ed25519',
                contentHash: 'blake2b512',
                tagHash: 'blake2b512'
            },
            compression: {
                type: 'deflate'
            }
            // chunkSize: 256
        });
        const input = (0, fs_1.createReadStream)('./test.txt');
        const output = (0, fs_1.createWriteStream)('./test-output.jsonl');
        await (0, promises_1.pipeline)(input, jostWriter, output);
    });
});
//# sourceMappingURL=writer.test.js.map