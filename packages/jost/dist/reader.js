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
const errors_1 = require("./errors");
const machine_1 = require("./machine");
const maxLineLength = 1.5 * 1024 * 1024;
class JostReader extends stream_1.Transform {
    constructor(options) {
        super();
        this._bufferList = new BufferList_1.default();
        this._seq = 0;
        this._decryptionKeyPairs = options.decryptionKeyPairs;
        this._machine = (0, machine_1.createReaderMachine)({
            signTags: () => this._tagHash != null,
            signContent: () => this._contentHash != null
        });
        this._state = this._machine.initialState;
    }
    _stateTransition(event) {
        this._state = this._machine.transition(this._state, event);
        if (!this._state.changed) {
            // crunk
            // <sound of gears grinding>
            if (event === 'END') {
                throw new errors_1.FormatError('unexpected end of file');
            }
            throw new errors_1.FormatError(`can't transition from state '${this._state.value}' with event '${event}'`);
        }
    }
    _transform(chunk, encoding, callback) {
        this._pushCallback(chunk, false, callback);
    }
    _flush(callback) {
        this._pushCallback(null, true, callback);
    }
    _pushCallback(chunk, end, callback) {
        this._push(chunk, end).then(() => {
            queueMicrotask(callback);
        }, (err) => {
            queueMicrotask(() => callback(err));
        });
    }
    async _push(chunk, end) {
        const bl = this._bufferList;
        if (chunk != null && chunk.length > 0)
            bl.append(chunk);
        if (bl.length > 0) {
            for (let i; (i = end ? bl.length : bl.indexOf(10)), i !== -1;) {
                if (i > maxLineLength) {
                    throw new errors_1.BufferOverflowError();
                }
                const line = bl.slice(0, i + 1);
                bl.consume(i + 1);
                const str = line.toString();
                // Eat empty lines
                if (str.length <= 2 && str.trim() === '')
                    continue;
                const obj = JSON.parse(str);
                await this._push2(obj);
            }
        }
        if (end)
            this._stateTransition('END');
        if (end && this._decompress != null)
            this._decompress.end();
    }
    async _push2(obj) {
        const protectedHeader = JSON.parse(Buffer.from(obj.protected, 'base64url').toString());
        if (protectedHeader.seq !== this._seq) {
            throw new errors_1.FormatError('incorrect sequence');
        }
        ++this._seq;
        switch (protectedHeader.typ) {
            case 'hdr':
                this._stateTransition('HEADER');
                await this._readHeader(obj);
                break;
            case 'tag':
                if (this._state.value === 'header') {
                    this._stateTransition('HEADER_TAG_SIGNATURE');
                }
                else {
                    this._stateTransition('TAG_SIGNATURE');
                }
                await this._readTagSignature(obj);
                break;
            case 'bdy':
                this._stateTransition('BODY');
                const { end, plaintext } = await this._readBody(obj);
                if (this._decompress != null) {
                    await this._decompress.writePromise(plaintext);
                }
                else {
                    this._updateContentHash(plaintext);
                    this.push(plaintext);
                }
                if (end)
                    this._stateTransition('BODY_END');
                break;
            case 'con':
                this._stateTransition('CONTENT_SIGNATURE');
                await this._readContentSignature(obj);
                break;
            default:
                throw new Error(`unknown type '${protectedHeader.typ}'`);
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
        const { pub, hsh, cmp } = result.protectedHeader;
        if (pub != null) {
            this.publicKey = (0, crypto_1.createPublicKey)({
                key: pub,
                format: 'jwk'
            });
        }
        if (hsh != null) {
            const { con, tag } = hsh;
            if (con != null)
                this._contentHash = (0, crypto_1.createHash)(con);
            if (tag != null)
                this._tagHash = (0, crypto_1.createHash)(tag);
        }
        if (cmp != null) {
            const decompress = (this._decompress = createDecompress(cmp));
            decompress.writePromise = (0, util_1.promisify)(decompress.write).bind(decompress);
            decompress.on('data', (chunk) => {
                this._updateContentHash(chunk);
                this.push(chunk);
            });
        }
        this._updateTagHash(jwe.tag);
    }
    async _readBody(jwe) {
        let end = false;
        try {
            const result = await (0, jose_1.flattenedDecrypt)(jwe, this._ephemeralKey);
            if (result.protectedHeader.end === true)
                end = true;
            this._updateTagHash(jwe.tag);
            return { end, plaintext: result.plaintext };
        }
        catch (err) {
            throw new errors_1.DecryptionFailedError();
        }
    }
    async _readContentSignature(jwe) {
        if (this._contentHash == null)
            return;
        let plaintext;
        try {
            const result = await (0, jose_1.flattenedDecrypt)(jwe, this._ephemeralKey);
            this._updateTagHash(jwe.tag);
            plaintext = result.plaintext;
        }
        catch (err) {
            throw new errors_1.DecryptionFailedError();
        }
        let jws;
        try {
            jws = JSON.parse(plaintext.toString());
        }
        catch (err) {
            throw new errors_1.FormatError();
        }
        const digest = this._contentHash.digest();
        jws.payload = digest.toString('base64url');
        try {
            const result = await (0, jose_1.flattenedVerify)(jws, this.publicKey);
        }
        catch (err) {
            throw new errors_1.SignatureVerificationFailedError();
        }
    }
    async _readTagSignature(jws) {
        if (this._tagHash == null)
            return;
        const digest = this._tagHash.copy().digest();
        jws.payload = digest.toString('base64url');
        try {
            const result = await (0, jose_1.flattenedVerify)(jws, this.publicKey);
        }
        catch (err) {
            throw new errors_1.SignatureVerificationFailedError();
        }
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
exports.default = JostReader;
function createDecompress(type) {
    switch (type) {
        case 'gzip':
            return (0, zlib_1.createGunzip)();
        case 'deflate':
            return (0, zlib_1.createInflate)();
        case 'br':
            return (0, zlib_1.createBrotliDecompress)();
        default:
            throw new Error(`unknown compression type '${type}'`);
    }
}
//# sourceMappingURL=reader.js.map