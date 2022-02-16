import BufferList from 'bl/BufferList'
import { createHash, Hash, KeyObject, sign } from 'crypto'
import {
  decodeProtectedHeader,
  FlattenedJWSInput,
  flattenedVerify,
  JWSHeaderParameters
} from 'jose'
import { Transform, TransformCallback } from 'stream'
import {
  BufferOverflowError,
  FormatError,
  KeyNotFoundError,
  SignatureVerificationFailedError
} from './errors'

const maxLineLength = 1.5 * 1024 * 1024
const lfChar = '\n'.charCodeAt(0)

/**
 * @public
 */
 export interface SignatureReaderOptions {
  detachedSignature?: string
  key?: KeyObject
  getKey?: (header: any, token: any) => Promise<KeyObject>
}

/**
 * @public
 */
 export default class SignatureReader extends Transform {
  private _bufferList = new BufferList()
  private _detachedSignature?: string
  private _key?: KeyObject
  private _getKey?: (header: any, token: any) => Promise<KeyObject>
  private _hash?: Hash
  private _firstLine: boolean = true
  private _lastLine?: Buffer

  constructor(options: SignatureReaderOptions) {
    super()

    this._detachedSignature = options.detachedSignature
    this._key = options.key
    this._getKey = options.getKey

    if (this._detachedSignature != null) {
      this._readDetachedSignature()
    }

    if (this._key == null && this._getKey == null) {
      throw new Error(
        "SignatureReaderOptions: one of 'key' or 'getKey' are required"
      )
    }
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
    if (this._detachedSignature != null) {
      if (chunk != null && chunk.length > 0) {
        this._hash?.update(chunk)
        this.push(chunk)
      }

      if (end) {
        await this._verifySignature(this._detachedSignature)
      }

      return
    }

    const bl = this._bufferList

    if (chunk != null && chunk.length > 0) {
      bl.append(chunk)

      const lastLine = this._lastLine
      if (lastLine != null) {
        this._hash?.update(lastLine)
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

        if (this._firstLine) {
          this._firstLine = false
          await this._readHeader(line.toString('utf8'))
          continue
        }

        if (bl.length > 0) {
          this._hash?.update(line)
          this.push(line)
        } else {
          this._lastLine = line
        }
      }
    }

    if (end) {
      await this._verifySignature(this._lastLine?.toString('utf8') ?? '')
    }
  }

  private async _readHeader(signature: string) {
    let jws

    try {
      jws = JSON.parse(signature)
    } catch (err) {
      throw new FormatError('unable to parse signature')
    }

    jws.payload = ''

    let protectedHeader

    try {
      const result = await flattenedVerify(jws, this._getKeyInternal.bind(this))

      protectedHeader = result.protectedHeader
    } catch (err) {
      throw new SignatureVerificationFailedError(err as Error)
    }

    const digest = (protectedHeader as any).dig

    if (digest == null) {
      throw new Error("header 'dig' digest is required")
    }

    this._hash = createHash(digest)
  }

  private _readDetachedSignature() {
    if (this._detachedSignature == null) return

    let jws

    try {
      jws = JSON.parse(this._detachedSignature)
    } catch (err) {
      throw new FormatError('unable to parse detached signature')
    }

    const protectedHeader = decodeProtectedHeader(jws)

    const digest = (protectedHeader as any).dig

    if (digest == null) {
      throw new Error("header 'dig' digest is required")
    }

    this._hash = createHash(digest)
  }

  private async _verifySignature(signature: string) {
    let jws

    try {
      jws = JSON.parse(signature)
    } catch (err) {
      throw new FormatError('unable to parse signature')
    }

    const digest = this._hash?.digest('base64url')

    if (jws.payload !== digest) {
      throw new SignatureVerificationFailedError()
    }

    try {
      await flattenedVerify(jws, this._getKeyInternal.bind(this))
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private async _getKeyInternal(
    protectedHeader?: JWSHeaderParameters,
    token?: FlattenedJWSInput
  ) {
    let key

    if (this._getKey != null) {
      key = await this._getKey(protectedHeader, token)
    } else if (this._key != null) {
      key = this._key
    }

    if (key == null) {
      throw new KeyNotFoundError()
    }

    return key
  }
}
