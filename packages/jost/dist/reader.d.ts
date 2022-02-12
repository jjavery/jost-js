/// <reference types="node" />
import { KeyObject } from 'crypto';
import { Transform, TransformCallback } from 'stream';
export interface KeyPair {
    publicKey: KeyObject;
    privateKey: KeyObject;
}
export interface JostReaderOptions {
    decryptionKeyPairs: KeyPair[];
}
export default class JostReader extends Transform {
    publicKey?: KeyObject;
    private _decryptionKeyPairs;
    private _ephemeralKey?;
    private _bufferList;
    private _machine;
    private _state;
    private _seq;
    private _tagHash?;
    private _contentHash?;
    private _decompress?;
    constructor(options: JostReaderOptions);
    private _stateTransition;
    _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
    private _pushCallback;
    private _push;
    private _push2;
    private _readHeader;
    private _readBody;
    private _readContentSignature;
    private _readTagSignature;
    private _updateTagHash;
    private _updateContentHash;
}
