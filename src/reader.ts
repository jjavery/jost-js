import BufferList from 'bl/BufferList'
import {
  createHash,
  createPublicKey,
  createSecretKey,
  Hash,
  KeyObject
} from 'crypto'
import {
  errors as joseErrors,
  flattenedDecrypt,
  flattenedVerify,
  generalDecrypt,
  GeneralDecryptResult
} from 'jose'
import { Transform, TransformCallback } from 'stream'
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
  publicKey?: KeyObject
  private _decryptionKeyPairs: KeyPair[]
  private _ephemeralKey?: KeyObject
  private _buffer: BufferList
  private _state = 0
  private _seq = 0
  private _ciphertextHash?: Hash
  private _plaintextHash?: Hash

  constructor(options: JoseStreamReaderOptions) {
    super()

    this._decryptionKeyPairs = options.decryptionKeyPairs
    this._buffer = new BufferList()
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

  private _pushCallback(chunk: Buffer | null, callback: TransformCallback) {
    this._push(chunk).then(
      () => {
        callback()
      },
      (err) => {
        callback(err)
      }
    )
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
          const { end, plaintext } = await this._readBody(obj)
          this.push(plaintext)
          this._updatePlaintextHash(plaintext)
          if (end) ++this._state
          break
        case 2:
          if (this._plaintextHash != null) {
            await this._readPlaintextSignature(obj)
          } else if (this._ciphertextHash != null) {
            await this._readCiphertextSignature(obj)
          }
          ++this._state
          break
        case 3:
          if (this._plaintextHash != null) {
            await this._readCiphertextSignature(obj)
          }
          ++this._state
          break
        default:
          throw new Error('unexpected JSON block following end')
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

    const pub = (result.protectedHeader as any).pub

    if (pub != null) {
      this.publicKey = createPublicKey({
        key: pub,
        format: 'jwk'
      })
    }

    const hashp = (result.protectedHeader as any).hashp
    const hashc = (result.protectedHeader as any).hashc

    if (hashp != null) this._plaintextHash = createHash(hashp)
    if (hashc != null) this._ciphertextHash = createHash(hashc)

    this._updateCiphertextHash(jwe.tag)
  }

  private async _readBody(
    jwe: any
  ): Promise<{ end: boolean; sig: boolean; plaintext: Uint8Array }> {
    let end = false
    let sig = false

    try {
      const result = await flattenedDecrypt(
        jwe,
        this._ephemeralKey as KeyObject
      )

      if ((result.protectedHeader as any).sig === true) sig = true
      if ((result.protectedHeader as any).end === true) end = true
      if ((result.protectedHeader as any).seq !== this._seq) {
        throw new FormatError()
      }
      ++this._seq

      this._updateCiphertextHash(jwe.tag)

      return { end, sig, plaintext: result.plaintext }
    } catch (err) {
      throw new DecryptionFailedError()
    }
  }

  private async _readPlaintextSignature(jwe: any) {
    if (this._plaintextHash == null) return

    const { plaintext, sig } = await this._readBody(jwe)

    if (sig !== true) {
      throw new Error('expected plaintext signature')
    }

    let jws

    try {
      jws = JSON.parse(plaintext.toString())
    } catch (err) {
      throw new FormatError()
    }

    const digest = this._plaintextHash.digest()

    jws.payload = digest.toString('base64url')

    try {
      const result = await flattenedVerify(jws, this.publicKey as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private async _readCiphertextSignature(jws: any) {
    if (this._ciphertextHash == null) return

    const digest = this._ciphertextHash.digest()

    jws.payload = digest.toString('base64url')

    try {
      const result = await flattenedVerify(jws, this.publicKey as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private _updateCiphertextHash(tag: string) {
    const hash = this._ciphertextHash
    if (hash == null) return
    hash.update(Buffer.from(tag, 'base64url'))
  }

  private _updatePlaintextHash(plaintext: Uint8Array) {
    const hash = this._plaintextHash
    if (hash == null) return
    hash.update(plaintext)
  }
}
