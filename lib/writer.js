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
const zlib_1 = require("zlib");
const generateKey = (0, util_1.promisify)(crypto_1.generateKey);
const defaultChunkSize = 64 * 1024;
class JoseStreamWriter extends stream_1.Transform {
    constructor(options) {
        super();
        this._ephemeralKey = null;
        this._bufferList = new BufferList_1.default();
        this._state = 0;
        this._seq = 0;
        this._chunkSize = options.chunkSize ?? defaultChunkSize;
        this._recipientOptions = options.recipients;
        this._encryptionOptions = options.encryption;
        this._signatureOptions = options.signature;
        this._compressionOptions = options.compression;
        // Initialize signatures
        if (this._signatureOptions != null &&
            (this._signatureOptions.publicKey != null ||
                this._signatureOptions.secretKey != null)) {
            if (this._signatureOptions.tagHash != null) {
                this._tagHash = (0, crypto_1.createHash)(this._signatureOptions.tagHash);
            }
            if (this._signatureOptions.contentHash != null) {
                this._contentHash = (0, crypto_1.createHash)(this._signatureOptions.contentHash);
            }
        }
        // Initialize compression
        if (this._compressionOptions != null) {
            this._compress = createCompress(this._compressionOptions.type, this._compressionOptions.options);
            this._compressOutput = new stream_1.Stream.Writable({
                write: (chunk, encoding, callback) => {
                    this._pushCallback(chunk, false, callback);
                },
                final: (callback) => {
                    this._pushCallback(null, true, callback);
                }
            });
            this._compress.pipe(this._compressOutput);
        }
    }
    _transform(chunk, encoding, callback) {
        this._updateContentHash(chunk);
        if (this._compress != null) {
            this._compress.write(chunk, callback);
        }
        else {
            this._pushCallback(chunk, false, callback);
        }
    }
    _flush(callback) {
        if (this._compress != null) {
            this._compress.end();
            this._compressOutput?.once('finish', () => {
                queueMicrotask(callback);
            });
        }
        else {
            this._pushCallback(null, true, callback);
        }
    }
    _pushCallback(chunk, end, callback) {
        this._push(chunk, end).then(() => {
            queueMicrotask(callback);
        }, (err) => {
            queueMicrotask(() => callback(err));
        });
    }
    async _push(chunk, end) {
        if (this._state === 0) {
            ++this._state;
            await this._writeHeader();
            await this._writeTagSignature();
        }
        if (this._state === 1) {
            if (end)
                ++this._state;
            await this._writeBody(chunk, end);
        }
        if (this._state === 2) {
            ++this._state;
            await this._writeContentSignature();
            await this._writeTagSignature();
        }
    }
    async _writeHeader() {
        const seq = this._seq++;
        const length = parseInt(this._encryptionOptions.enc.substring(1, 4), 10);
        this._ephemeralKey = await generateKey('aes', { length });
        const jwk = this._ephemeralKey.export({ format: 'jwk' });
        const plaintext = Buffer.from(JSON.stringify(jwk), 'utf-8');
        delete jwk.k;
        let pub, hsh, contentHash, tagHash;
        if (this._signatureOptions != null &&
            (this._signatureOptions.publicKey != null ||
                this._signatureOptions.secretKey != null)) {
            if (this._signatureOptions.publicKey != null) {
                pub = this._signatureOptions.publicKey.export({ format: 'jwk' });
            }
            contentHash = this._signatureOptions.contentHash;
            tagHash = this._signatureOptions.tagHash;
        }
        if (contentHash != null || tagHash != null) {
            hsh = {
                con: contentHash,
                tag: tagHash
            };
        }
        const protectedHeader = {
            typ: 'hdr',
            enc: this._encryptionOptions.enc,
            pub,
            hsh,
            cmp: this._compressionOptions?.type,
            seq
        };
        const encrypt = new jose_1.GeneralEncrypt(plaintext).setProtectedHeader(protectedHeader);
        for (const recipient of this._recipientOptions) {
            encrypt
                .addRecipient(recipient.key)
                .setUnprotectedHeader({ alg: recipient.alg, kid: recipient.kid });
        }
        const jwe = await encrypt.encrypt();
        plaintext.fill(0);
        this._updateTagHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeBody(chunk, end) {
        const chunkSize = this._chunkSize;
        const bl = this._bufferList;
        if (chunk != null && chunk.length > 0)
            bl.append(chunk);
        while (bl.length > (end ? 0 : chunkSize)) {
            const chunk = bl.slice(0, chunkSize);
            bl.consume(chunkSize);
            await this._writeBody2(chunk, end && bl.length === 0);
        }
    }
    async _writeBody2(chunk, end) {
        const seq = this._seq++;
        const protectedHeader = {
            typ: 'bdy',
            alg: 'dir',
            enc: this._encryptionOptions.enc,
            end: end || undefined,
            seq
        };
        const encrypt = new jose_1.FlattenedEncrypt(chunk).setProtectedHeader(protectedHeader);
        const jwe = await encrypt.encrypt(this._ephemeralKey);
        this._updateTagHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeContentSignature() {
        const options = this._signatureOptions;
        if (options == null || this._contentHash == null)
            return;
        const digest = this._contentHash.digest();
        const protectedHeader = {
            alg: options.alg,
            crv: options.crv
        };
        const sign = new jose_1.FlattenedSign(digest).setProtectedHeader(protectedHeader);
        const jws = await sign.sign(options.privateKey ?? options.secretKey);
        delete jws.payload;
        const json = JSON.stringify(jws);
        await this._writeContentSignature2(Buffer.from(json, 'utf8'));
    }
    async _writeContentSignature2(chunk) {
        const seq = this._seq++;
        const protectedHeader = {
            typ: 'con',
            alg: 'dir',
            enc: this._encryptionOptions.enc,
            seq
        };
        const encrypt = new jose_1.FlattenedEncrypt(chunk).setProtectedHeader(protectedHeader);
        const jwe = await encrypt.encrypt(this._ephemeralKey);
        this._updateTagHash(jwe.tag);
        const json = JSON.stringify(jwe);
        this.push(json);
        this.push('\n');
    }
    async _writeTagSignature() {
        const seq = this._seq++;
        const options = this._signatureOptions;
        if (options == null || this._tagHash == null)
            return;
        const digest = this._tagHash.copy().digest();
        const protectedHeader = {
            typ: 'tag',
            alg: options.alg,
            crv: options.crv,
            seq
        };
        const sign = new jose_1.FlattenedSign(digest).setProtectedHeader(protectedHeader);
        const jws = await sign.sign(options.privateKey ?? options.secretKey);
        delete jws.payload;
        const json = JSON.stringify(jws);
        this.push(json);
        this.push('\n');
    }
    _updateTagHash(tag) {
        const hash = this._tagHash;
        if (hash == null)
            return;
        hash.update(Buffer.from(tag, 'base64url'));
    }
    _updateContentHash(chunk) {
        const hash = this._contentHash;
        if (hash == null)
            return;
        hash.update(chunk);
    }
}
exports.default = JoseStreamWriter;
function createCompress(type, options) {
    switch (type) {
        case 'gzip':
            return (0, zlib_1.createGzip)(options);
        case 'deflate':
            return (0, zlib_1.createDeflate)(options);
        case 'br':
            return (0, zlib_1.createBrotliCompress)(options);
        default:
            throw new Error(`unknown compression type '${type}'`);
    }
}
//# sourceMappingURL=writer.js.map