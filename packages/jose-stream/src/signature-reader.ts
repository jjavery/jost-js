import BufferList from 'bl/BufferList'
import { createHash, Hash, KeyObject } from 'crypto'
import { FlattenedSign, flattenedVerify } from 'jose'
import { Stream, Transform, TransformCallback } from 'stream'
import {
  BufferOverflowError,
  DecryptionFailedError,
  FormatError,
  SignatureVerificationFailedError
} from './errors'

const maxLineLength = 1.5 * 1024 * 1024
const lfChar = '\n'.charCodeAt(0)

interface SignatureReaderOptions {
  key: KeyObject
  hash: string
}

export default class SignatureReader extends Transform {
  private _bufferList = new BufferList()
  private _key: KeyObject
  private _hashAlgorithm: string
  private _hash: Hash
  private _lastLine?: Buffer

  constructor(options: SignatureReaderOptions) {
    super()

    this._key = options.key
    this._hashAlgorithm = options.hash
    this._hash = createHash(options.hash)
  }

  _transform(
    chunk: Buffer,
    encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    this._pushCallback(chunk, false, callback)
  }

  _flush(callback: TransformCallback): void {
    this._pushCallback(null, true, callback)
  }

  private _pushCallback(
    chunk: Buffer | null,
    end: boolean,
    callback: TransformCallback
  ) {
    this._push(chunk, end).then(
      () => {
        queueMicrotask(callback)
      },
      (err) => {
        queueMicrotask(() => callback(err))
      }
    )
  }

  private async _push(chunk: Buffer | null, end: boolean) {
    const bl = this._bufferList

    if (chunk != null && chunk.length > 0) {
      bl.append(chunk)

      const lastLine = this._lastLine
      if (lastLine != null) {
        this._hash.update(lastLine)
        this.push(lastLine)
        this._lastLine = undefined
      }
    }

    if (bl.length > 0) {
      for (let i; (i = end ? bl.length : bl.indexOf(lfChar)), i !== -1; ) {
        if (i > maxLineLength) {
          throw new BufferOverflowError()
        }

        const line = bl.slice(0, i + 1)
        bl.consume(i + 1)

        if (bl.length > 0) {
          this._hash.update(line)
          this.push(line)
        } else {
          this._lastLine = line
        }
      }
    }

    if (end) {
      await this._readSignature(this._lastLine as Buffer)
    }
  }

  private async _readSignature(line: Buffer) {
    let jws

    try {
      jws = JSON.parse(line.toString())
    } catch (err) {
      throw new FormatError('unable to parse signature')
    }

    const digest = this._hash.digest('base64url')

    if (jws.payload !== digest) {
      throw new SignatureVerificationFailedError()
    }

    try {
      await flattenedVerify(jws, this._key as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }
}
