"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const BufferList_1 = __importDefault(require("bl/BufferList"));
const crypto_1 = require("crypto");
const jose_1 = require("jose");
const stream_1 = require("stream");
const util_1 = require("util");
const generateKeyPromise = (0, util_1.promisify)(crypto_1.generateKey);
const defaultChunkSize = 64 * 1024;
class JoseStreamWriter extends stream_1.Transform {
    constructor(options) {
        super();
        this._ephemeralKey = null;
        this._state = 0;
        this._seq = 0;
        this._chunkSize = options.chunkSize ?? defaultChunkSize;
        this._signingKeyPair = options.signingKeyPair;
        this._recipients = options.recipients;
        this._buffer = new BufferList_1.default();
        this._hash = (0, crypto_1.createHash)('sha256');
        this._pushCallback = (0, util_1.callbackify)(this._push).bind(this);
    }
    _transform(chunk, encoding, callback) {
        this._pushCallback(chunk, callback);
    }
    _flush(callback) {
        this._pushCallback(null, callback);
    }
    async _push(chunk) {
        if (this._state === 0) {
            await this._writeHeader();
            ++this._state;
        }
        if (this._state === 1) {
            const chunkSize = this._chunkSize;
            const buffer = this._buffer;
            if (chunk != null && chunk.length > 0)
                buffer.append(chunk);
            while (buffer.length > (this.writableEnded ? 0 : chunkSize)) {
                const chunk = buffer.slice(0, chunkSize);
                buffer.consume(chunkSize);
                const end = this.writableEnded && buffer.length === 0;
                await this._writeBody(chunk, end);
                if (end)
                    ++this._state;
            }
        }
        if (this._state === 2) {
            await this._writeSignature();
            ++this._state;
        }
    }
    async _writeHeader() {
        this._ephemeralKey = await generateKeyPromise('aes', { length: 256 });
        const jwk = this._ephemeralKey.export({ format: 'jwk' });
        const plaintext = new util_1.TextEncoder().encode(JSON.stringify(jwk));
        delete jwk.k;
        let pub;
        if (this._signingKeyPair != null) {
            pub = this._signingKeyPair.publicKey.export({ format: 'jwk' });
        }
        const encrypt = new jose_1.GeneralEncrypt(plaintext).setProtectedHeader({
            enc: 'A256GCM',
            pub: pub
        });
        for (const recipient of this._recipients) {
            encrypt
                .addRecipient(recipient)
                .setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' });
        }
        const jwe = await encrypt.encrypt();
        plaintext.fill(0);
        this._updateHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeBody(chunk, end) {
        const seq = this._seq++;
        const encrypt = new jose_1.FlattenedEncrypt(chunk).setProtectedHeader({
            alg: 'dir',
            enc: 'A256GCM',
            end,
            seq,
            zip: 'DEF'
        });
        const jwe = await encrypt.encrypt(this._ephemeralKey);
        this._updateHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeSignature() {
        if (this._signingKeyPair == null)
            return;
        const hash = this._hash.digest();
        const sign = new jose_1.FlattenedSign(hash).setProtectedHeader({
            alg: 'EdDSA',
            crv: 'Ed25519'
        });
        const jws = (await sign.sign(this._signingKeyPair.privateKey));
        delete jws.payload;
        const json = JSON.stringify(jws);
        this.push(json);
        this.push('\n');
    }
    _updateHash(tag) {
        this._hash.update(Buffer.from(tag, 'base64url'));
    }
}
exports.default = JoseStreamWriter;
//# sourceMappingURL=writer.js.map