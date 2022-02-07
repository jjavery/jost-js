"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const promises_1 = require("stream/promises");
const reader_1 = __importDefault(require("./reader"));
const test_1 = require("./test");
describe('JoseStreamReader', () => {
    it('reads a JOSE stream', async () => {
        const joseStreamReader = new reader_1.default({
            decryptionKeyPairs: [test_1.ecdhKeyPair]
        });
        const input = (0, fs_1.createReadStream)('./test.jsonl');
        const output = (0, fs_1.createWriteStream)('./test-output.txt');
        await (0, promises_1.pipeline)(input, joseStreamReader, output);
    });
});
//# sourceMappingURL=reader.test.js.map