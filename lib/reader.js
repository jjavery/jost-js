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
const errors_1 = require("./errors");
const maxLineLength = 1.5 * 1024 * 1024;
class JoseStreamReader extends stream_1.Transform {
    constructor(options) {
        super();
        this.publicKey = null;
        this._ephemeralKey = null;
        this._state = 0;
        this._seq = 0;
        this._decryptionKeyPairs = options.decryptionKeyPairs;
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
        const buffer = this._buffer;
        if (chunk != null && chunk.length > 0) {
            buffer.append(chunk);
        }
        for (let i; (i = buffer.indexOf(10)), i !== -1;) {
            if (i > maxLineLength) {
                throw new errors_1.BufferOverflowError();
            }
            const line = buffer.slice(0, i + 1);
            buffer.consume(i + 1);
            const str = line.toString();
            // Eat empty lines
            if (str.length <= 2 && str.trim() === '')
                continue;
            const obj = JSON.parse(str);
            switch (this._state) {
                case 0:
                    await this._readHeader(obj);
                    ++this._state;
                    break;
                case 1:
                    const end = await this._readBody(obj);
                    if (end)
                        ++this._state;
                    break;
                case 2:
                    await this._readSignature(obj);
                    ++this._state;
                    break;
                default:
                    throw new Error('unexpected JSON block following signature');
            }
        }
    }
    async _readHeader(jwe) {
        let result = null;
        for (const keyPair of this._decryptionKeyPairs) {
            try {
                result = await (0, jose_1.generalDecrypt)(jwe, keyPair.privateKey);
                break;
            }
            catch (err) {
                if (!(err instanceof jose_1.errors.JWEDecryptionFailed))
                    throw err;
            }
        }
        if (result == null) {
            throw new errors_1.DecryptionFailedError();
        }
        let jwk;
        try {
            jwk = JSON.parse(result.plaintext.toString());
        }
        catch (err) {
            throw new errors_1.FormatError();
        }
        finally {
            result.plaintext.fill(0);
        }
        this._ephemeralKey = (0, crypto_1.createSecretKey)(jwk.k, 'base64url');
        delete jwk.k;
        this.publicKey = (0, crypto_1.createPublicKey)({
            key: result.protectedHeader.pub,
            format: 'jwk'
        });
        this._updateHash(jwe.tag);
    }
    async _readBody(jwe) {
        let end = false;
        try {
            const result = await (0, jose_1.flattenedDecrypt)(jwe, this._ephemeralKey);
            if (result.protectedHeader.end === true)
                end = true;
            if (result.protectedHeader.seq !== this._seq) {
                throw new errors_1.FormatError();
            }
            ++this._seq;
            this.push(result.plaintext);
            this._updateHash(jwe.tag);
        }
        catch (err) {
            throw new errors_1.DecryptionFailedError();
        }
        return end;
    }
    async _readSignature(jws) {
        const hash = this._hash.digest();
        jws.payload = hash.toString('base64url');
        try {
            const result = await (0, jose_1.flattenedVerify)(jws, this.publicKey);
        }
        catch (err) {
            throw new errors_1.SignatureVerificationFailedError();
        }
    }
    _updateHash(tag) {
        this._hash.update(Buffer.from(tag, 'base64url'));
    }
}
exports.default = JoseStreamReader;
//# sourceMappingURL=reader.js.map