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
const generateKey = (0, util_1.promisify)(crypto_1.generateKey);
const defaultChunkSize = 64 * 1024;
class JoseStreamWriter extends stream_1.Transform {
    constructor(options) {
        super();
        this._ephemeralKey = null;
        this._buffer = new BufferList_1.default();
        this._state = 0;
        this._seq = 0;
        this._chunkSize = options.chunkSize ?? defaultChunkSize;
        this._recipientOptions = options.recipient;
        this._encryptionOptions = options.encryption;
        this._signatureOptions = options.signature;
        if (this._signatureOptions != null &&
            (this._signatureOptions.publicKey != null ||
                this._signatureOptions.secretKey != null)) {
            if (this._signatureOptions.ciphertextHash != null) {
                this._ciphertextHash = (0, crypto_1.createHash)(this._signatureOptions.ciphertextHash);
            }
            if (this._signatureOptions.plaintextHash != null) {
                this._plaintextHash = (0, crypto_1.createHash)(this._signatureOptions.plaintextHash);
            }
        }
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
        if (this._state === 0) {
            await this._writeHeader();
            ++this._state;
        }
        if (this._state === 1) {
            const chunkSize = this._chunkSize;
            const buffer = this._buffer;
            if (chunk != null && chunk.length > 0) {
                buffer.append(chunk);
                this._updatePlaintextHash(chunk);
            }
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
            await this._writePlaintextSignature();
            ++this._state;
        }
        if (this._state === 3) {
            await this._writeCiphertextSignature();
            ++this._state;
        }
    }
    async _writeHeader() {
        const length = parseInt(this._encryptionOptions.enc.substring(1, 4), 10);
        this._ephemeralKey = await generateKey('aes', { length });
        const jwk = this._ephemeralKey.export({ format: 'jwk' });
        const plaintext = Buffer.from(JSON.stringify(jwk), 'utf-8');
        delete jwk.k;
        let pub, hashp, hashc;
        if (this._signatureOptions != null &&
            (this._signatureOptions.publicKey != null ||
                this._signatureOptions.secretKey != null)) {
            if (this._signatureOptions.publicKey != null) {
                pub = this._signatureOptions.publicKey.export({ format: 'jwk' });
            }
            hashp = this._signatureOptions.plaintextHash;
            hashc = this._signatureOptions.ciphertextHash;
        }
        const protectedHeader = {
            enc: this._encryptionOptions.enc,
            pub,
            hashp,
            hashc
        };
        const encrypt = new jose_1.GeneralEncrypt(plaintext).setProtectedHeader(protectedHeader);
        for (const recipient of this._recipientOptions) {
            encrypt
                .addRecipient(recipient.key)
                .setUnprotectedHeader({ alg: recipient.alg, kid: recipient.kid });
        }
        const jwe = await encrypt.encrypt();
        plaintext.fill(0);
        this._updateCiphertextHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeBody(chunk, end, sig) {
        const seq = this._seq++;
        const protectedHeader = {
            alg: 'dir',
            enc: this._encryptionOptions.enc,
            end: end || undefined,
            seq,
            sig: sig || undefined
        };
        const encrypt = new jose_1.FlattenedEncrypt(chunk).setProtectedHeader(protectedHeader);
        const jwe = await encrypt.encrypt(this._ephemeralKey);
        // if (!sig) {
        this._updateCiphertextHash(jwe.tag);
        // }
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writePlaintextSignature() {
        const options = this._signatureOptions;
        if (options == null || this._plaintextHash == null)
            return;
        const digest = this._plaintextHash.digest();
        const protectedHeader = {
            alg: options.alg,
            crv: options.crv
        };
        const sign = new jose_1.FlattenedSign(digest).setProtectedHeader(protectedHeader);
        const jws = await sign.sign(options.privateKey ?? options.secretKey);
        delete jws.payload;
        const json = JSON.stringify(jws);
        await this._writeBody(Buffer.from(json, 'utf8'), false, true);
    }
    async _writeCiphertextSignature() {
        const options = this._signatureOptions;
        if (options == null || this._ciphertextHash == null)
            return;
        const digest = this._ciphertextHash.digest();
        const protectedHeader = {
            alg: options.alg,
            crv: options.crv
        };
        const sign = new jose_1.FlattenedSign(digest).setProtectedHeader(protectedHeader);
        const jws = await sign.sign(options.privateKey ?? options.secretKey);
        delete jws.payload;
        const json = JSON.stringify(jws);
        this.push(json);
        this.push('\n');
    }
    _updateCiphertextHash(tag) {
        const hash = this._ciphertextHash;
        if (hash == null)
            return;
        hash.update(Buffer.from(tag, 'base64url'));
    }
    _updatePlaintextHash(chunk) {
        const hash = this._plaintextHash;
        if (hash == null)
            return;
        hash.update(chunk);
    }
}
exports.default = JoseStreamWriter;
//# sourceMappingURL=writer.js.map