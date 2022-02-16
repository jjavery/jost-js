import { createHash, Hash, KeyObject } from 'crypto'
import { FlattenedSign } from 'jose'
import { Transform, TransformCallback } from 'stream'

const lfChar = '\n'.charCodeAt(0)

/**
 * @public
 */
 export interface SignatureWriterOptions {
  detached?: boolean
  keyId?: string
  publicKey?: KeyObject
  key: KeyObject
  algorithm: string
  curve?: string
  digest: string
}

/**
 * @public
 */
 export default class SignatureWriter extends Transform {
  private _detached: boolean
  private _keyId?: string
  private _publicKey?: KeyObject
  private _key: KeyObject
  private _algorithm: string
  private _curve?: string
  private _digest: string
  private _hash: Hash
  private _headerWritten = false
  private _lastChar?: number

  constructor(options: SignatureWriterOptions) {
    super()

    this._detached = options.detached ?? false
    this._keyId = options.keyId
    this._publicKey = options.publicKey
    this._key = options.key
    this._algorithm = options.algorithm
    this._curve = options.curve
    this._digest = options.digest
    this._hash = createHash(options.digest)
  }

  _transform(
    chunk: Buffer,
    encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    if (!this._detached && !this._headerWritten) {
      this._headerWritten = true

      this._writeHeader().then(
        () => {
          this._transform2(chunk, callback)
        },
        (err) => {
          queueMicrotask(() => callback(err))
        }
      )
    } else {
      this._transform2(chunk, callback)
    }
  }

  _transform2(chunk: Buffer, callback: TransformCallback) {
    this._hash.update(chunk)

    this._lastChar = chunk.at(-1)

    this.push(chunk)

    queueMicrotask(callback)
  }

  _flush(callback: TransformCallback): void {
    if (this._detached) {
      queueMicrotask(callback)
      return
    }

    if (this._lastChar !== lfChar) {
      this._hash.update('\n')
      this.push('\n', 'utf8')
    }

    this._writeSignature().then(
      () => {
        queueMicrotask(callback)
      },
      (err) => {
        queueMicrotask(() => callback(err))
      }
    )
  }

  private async _writeHeader() {
    const empty = new Uint8Array()

    const jws: any = await this._sign(empty)

    delete jws.payload

    const json = JSON.stringify(jws)

    this.push(json)
    this.push('\n')
  }

  private async _writeSignature() {
    const digest = this._hash.digest()

    const jws: any = await this._sign(digest)

    const json = JSON.stringify(jws)

    this.push(json)
    this.push('\n')
  }

  async getDetachedSignature() {
    const digest = this._hash.digest()

    const jws: any = await this._sign(digest)

    return jws
  }

  private async _sign(payload: Uint8Array) {
    const jwk = this._publicKey?.export({ format: 'jwk' })

    const protectedHeader = {
      typ: 'jose-stream-signature',
      alg: this._algorithm,
      crv: this._curve,
      dig: this._digest,
      kid: this._keyId ?? (jwk?.kid as string),
      jwk
    }

    const sign = new FlattenedSign(payload).setProtectedHeader(protectedHeader)

    const jws: any = await sign.sign(this._key)
    return jws
  }
}
