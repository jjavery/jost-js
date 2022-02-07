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
            signingKeyPair: test_1.signingKeyPair,
            recipients: [test_1.ecdhKeyPair.publicKey]
        });
        const input = (0, fs_1.createReadStream)('./test.txt');
        const output = (0, fs_1.createWriteStream)('./test.jsonl');
        await (0, promises_1.pipeline)(input, joseStreamWriter, output);
    });
});
//# sourceMappingURL=writer.test.js.map