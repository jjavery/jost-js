/// <reference types="node" />
import { KeyObject } from 'crypto';
import { Transform, TransformCallback } from 'stream';
import { BrotliOptions, ZlibOptions } from 'zlib';
export interface JostWriterOptions {
    chunkSize?: number;
    recipients: RecipientOptions[];
    encryption: EncryptionOptions;
    signature?: SignatureOptions;
    compression?: CompressionOptions;
}
export interface RecipientOptions {
    key: KeyObject;
    alg: 'RSA1_5' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'A128KW' | 'A192KW' | 'A256KW' | 'dir' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW' | 'PBES2-HS256+A128KW' | 'PBES2-HS384+A384KW' | 'PBES2-HS512+A256KW';
    kid?: string;
}
export interface EncryptionOptions {
    enc: 'A128CBC-HS256' | 'A192CBC-HS384' | 'A256CBC-HS512' | 'A128GCM' | 'A192GCM' | 'A256GCM';
}
export interface SignatureOptions {
    publicKey?: KeyObject;
    privateKey?: KeyObject;
    secretKey?: KeyObject;
    alg: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'EdDSA';
    crv?: 'Ed25519' | 'Ed448';
    tagHash?: 'sha256' | 'sha384' | 'sha512' | 'sha512-256' | 'blake2b512' | 'blake2s256';
    contentHash?: 'sha256' | 'sha384' | 'sha512' | 'sha512-256' | 'blake2b512' | 'blake2s256';
}
export interface CompressionOptions {
    type: 'gzip' | 'deflate' | 'br';
    options?: ZlibOptions | BrotliOptions;
}
export default class JostWriter extends Transform {
    private _chunkSize;
    private _recipientOptions;
    private _encryptionOptions;
    private _signatureOptions?;
    private _compressionOptions?;
    private _ephemeralKey;
    private _bufferList;
    private _state;
    private _seq;
    private _tagHash;
    private _contentHash;
    private _compress;
    private _compressOutput;
    constructor(options: JostWriterOptions);
    _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
    private _pushCallback;
    private _push;
    private _writeHeader;
    private _writeBody;
    private _writeBody2;
    private _writeContentSignature;
    private _writeContentSignature2;
    private _writeTagSignature;
    private _updateTagHash;
    private _updateContentHash;
}
