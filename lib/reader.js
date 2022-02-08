"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const BufferList_1 = __importDefault(require("bl/BufferList"));
const crypto_1 = require("crypto");
const jose_1 = require("jose");
const stream_1 = require("stream");
const errors_1 = require("./errors");
const maxLineLength = 1.5 * 1024 * 1024;
class JoseStreamReader extends stream_1.Transform {
    constructor(options) {
        super();
        this._state = 0;
        this._seq = 0;
        this._decryptionKeyPairs = options.decryptionKeyPairs;
        this._buffer = new BufferList_1.default();
    }
    _transform(chunk, encoding, callback) {
        this._pushCallback(chunk, callback);
    }
    _flush(callback) {
        this._pushCallback(null, callback);
    }
    _pushCallback(chunk, callback) {
        this._push(chunk).then(() => {
            callback();
        }, (err) => {
            callback(err);
        });
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
                    const { end, plaintext } = await this._readBody(obj);
                    this.push(plaintext);
                    this._updatePlaintextHash(plaintext);
                    if (end)
                        ++this._state;
                    break;
                case 2:
                    if (this._plaintextHash != null) {
                        await this._readPlaintextSignature(obj);
                    }
                    else if (this._ciphertextHash != null) {
                        await this._readCiphertextSignature(obj);
                    }
                    ++this._state;
                    break;
                case 3:
                    if (this._plaintextHash != null) {
                        await this._readCiphertextSignature(obj);
                    }
                    ++this._state;
                    break;
                default:
                    throw new Error('unexpected JSON block following end');
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
        const pub = result.protectedHeader.pub;
        if (pub != null) {
            this.publicKey = (0, crypto_1.createPublicKey)({
                key: pub,
                format: 'jwk'
            });
        }
        const hashp = result.protectedHeader.hashp;
        const hashc = result.protectedHeader.hashc;
        if (hashp != null)
            this._plaintextHash = (0, crypto_1.createHash)(hashp);
        if (hashc != null)
            this._ciphertextHash = (0, crypto_1.createHash)(hashc);
        this._updateCiphertextHash(jwe.tag);
    }
    async _readBody(jwe) {
        let end = false;
        let sig = false;
        try {
            const result = await (0, jose_1.flattenedDecrypt)(jwe, this._ephemeralKey);
            if (result.protectedHeader.sig === true)
                sig = true;
            if (result.protectedHeader.end === true)
                end = true;
            if (result.protectedHeader.seq !== this._seq) {
                throw new errors_1.FormatError();
            }
            ++this._seq;
            this._updateCiphertextHash(jwe.tag);
            return { end, sig, plaintext: result.plaintext };
        }
        catch (err) {
            throw new errors_1.DecryptionFailedError();
        }
    }
    async _readPlaintextSignature(jwe) {
        if (this._plaintextHash == null)
            return;
        const { plaintext, sig } = await this._readBody(jwe);
        if (sig !== true) {
            throw new Error('expected plaintext signature');
        }
        let jws;
        try {
            jws = JSON.parse(plaintext.toString());
        }
        catch (err) {
            throw new errors_1.FormatError();
        }
        const digest = this._plaintextHash.digest();
        jws.payload = digest.toString('base64url');
        try {
            const result = await (0, jose_1.flattenedVerify)(jws, this.publicKey);
        }
        catch (err) {
            throw new errors_1.SignatureVerificationFailedError();
        }
    }
    async _readCiphertextSignature(jws) {
        if (this._ciphertextHash == null)
            return;
        const digest = this._ciphertextHash.digest();
        jws.payload = digest.toString('base64url');
        try {
            const result = await (0, jose_1.flattenedVerify)(jws, this.publicKey);
        }
        catch (err) {
            throw new errors_1.SignatureVerificationFailedError();
        }
    }
    _updateCiphertextHash(tag) {
        const hash = this._ciphertextHash;
        if (hash == null)
            return;
        hash.update(Buffer.from(tag, 'base64url'));
    }
    _updatePlaintextHash(plaintext) {
        const hash = this._plaintextHash;
        if (hash == null)
            return;
        hash.update(plaintext);
    }
}
exports.default = JoseStreamReader;
//# sourceMappingURL=reader.js.map