import BufferList from 'bl/BufferList'
import { createHash, createPublicKey, createSecretKey, KeyObject } from 'crypto'
import {
  errors as joseErrors,
  flattenedDecrypt,
  flattenedVerify,
  generalDecrypt,
  GeneralDecryptResult
} from 'jose'
import { Transform, TransformCallback } from 'stream'
import { callbackify } from 'util'
import {
  BufferOverflowError,
  DecryptionFailedError,
  FormatError,
  SignatureVerificationFailedError
} from './errors'

const maxLineLength = 1.5 * 1024 * 1024

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

interface JoseStreamReaderOptions {
  decryptionKeyPairs: KeyPair[]
}

export default class JoseStreamReader extends Transform {
  publicKey: KeyObject | null = null
  private _decryptionKeyPairs: KeyPair[]
  private _ephemeralKey: KeyObject | null = null
  private _buffer: BufferList
  private _state = 0
  private _seq = 0
  private _hash
  private _pushCallback

  constructor(options: JoseStreamReaderOptions) {
    super()

    this._decryptionKeyPairs = options.decryptionKeyPairs
    this._buffer = new BufferList()
    this._hash = createHash('sha256')

    this._pushCallback = callbackify(this._push).bind(this)
  }

  _transform(
    chunk: Buffer,
    encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    this._pushCallback(chunk, callback)
  }

  _flush(callback: TransformCallback): void {
    this._pushCallback(null, callback)
  }

  private async _push(chunk: Buffer | null) {
    const buffer = this._buffer

    if (chunk != null && chunk.length > 0) {
      buffer.append(chunk)
    }

    for (let i; (i = buffer.indexOf(10)), i !== -1; ) {
      if (i > maxLineLength) {
        throw new BufferOverflowError()
      }

      const line = buffer.slice(0, i + 1)
      buffer.consume(i + 1)

      const str = line.toString()

      // Eat empty lines
      if (str.length <= 2 && str.trim() === '') continue

      const obj = JSON.parse(str)

      switch (this._state) {
        case 0:
          await this._readHeader(obj)
          ++this._state
          break
        case 1:
          const end = await this._readBody(obj)
          if (end) ++this._state
          break
        case 2:
          await this._readSignature(obj)
          ++this._state
          break
        default:
          throw new Error('unexpected JSON block following signature')
      }
    }
  }

  private async _readHeader(jwe: any) {
    let result: GeneralDecryptResult | null = null

    for (const keyPair of this._decryptionKeyPairs) {
      try {
        result = await generalDecrypt(jwe, keyPair.privateKey)
        break
      } catch (err) {
        if (!(err instanceof joseErrors.JWEDecryptionFailed)) throw err
      }
    }

    if (result == null) {
      throw new DecryptionFailedError()
    }

    let jwk

    try {
      jwk = JSON.parse(result.plaintext.toString())
    } catch (err) {
      throw new FormatError()
    } finally {
      result.plaintext.fill(0)
    }

    this._ephemeralKey = createSecretKey(jwk.k, 'base64url')
    delete jwk.k

    this.publicKey = createPublicKey({
      key: (result.protectedHeader as any).pub,
      format: 'jwk'
    })
    this._updateHash(jwe.tag)
  }

  private async _readBody(jwe: any): Promise<boolean> {
    let end = false

    try {
      const result = await flattenedDecrypt(jwe, this._ephemeralKey as KeyObject)

      if ((result.protectedHeader as any).end === true) end = true
      if ((result.protectedHeader as any).seq !== this._seq) {
        throw new FormatError()
      }
      ++this._seq

      this.push(result.plaintext)

      this._updateHash(jwe.tag)
    } catch (err) {
      throw new DecryptionFailedError()
    }

    return end
  }

  private async _readSignature(jws: any) {
    const hash = this._hash.digest()

    jws.payload = hash.toString('base64url')

    try {
      const result = await flattenedVerify(jws, this.publicKey as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private _updateHash(tag: string) {
    this._hash.update(Buffer.from(tag, 'base64url'))
  }
}
