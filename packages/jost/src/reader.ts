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
import { promisify } from 'util'
import {
  BrotliDecompress,
  createBrotliDecompress,
  createGunzip,
  createInflate,
  Gunzip,
  Inflate
} from 'zlib'
import {
  BufferOverflowError,
  DecryptionFailedError,
  FormatError,
  SignatureVerificationFailedError
} from './errors'
import { createReaderMachine } from './machine'

const maxLineLength = 1.5 * 1024 * 1024

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

interface JostReaderOptions {
  decryptionKeyPairs: KeyPair[]
}

export default class JostReader extends Transform {
  publicKey?: KeyObject
  private _decryptionKeyPairs: KeyPair[]
  private _ephemeralKey?: KeyObject
  private _bufferList = new BufferList()
  private _machine
  private _state
  private _seq = 0
  private _tagHash?: Hash
  private _contentHash?: Hash
  private _decompress?: Gunzip | Inflate | BrotliDecompress

  constructor(options: JostReaderOptions) {
    super()

    this._decryptionKeyPairs = options.decryptionKeyPairs
    this._machine = createReaderMachine({
      signTags: () => this._tagHash != null,
      signContent: () => this._contentHash != null
    })
    this._state = this._machine.initialState
  }

  private _stateTransition(event: string) {
    this._state = this._machine.transition(this._state, event)
    if (!this._state.changed) {
      // crunk
      // <sound of gears grinding>
      if (event === 'END') {
        throw new FormatError('unexpected end of file')
      }
      throw new FormatError(
        `can't transition from state '${this._state.value}' with event '${event}'`
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
    const bl = this._bufferList

    if (chunk != null && chunk.length > 0) bl.append(chunk)

    if (bl.length > 0) {
      for (let i; (i = end ? bl.length : bl.indexOf(10)), i !== -1; ) {
        if (i > maxLineLength) {
          throw new BufferOverflowError()
        }

        const line = bl.slice(0, i + 1)
        bl.consume(i + 1)

        const str = line.toString()

        // Eat empty lines
        if (str.length <= 2 && str.trim() === '') continue

        const obj = JSON.parse(str)

        await this._push2(obj)
      }
    }

    if (end) this._stateTransition('END')

    if (end && this._decompress != null) this._decompress.end()
  }

  private async _push2(obj: any) {
    const protectedHeader = JSON.parse(
      Buffer.from(obj.protected, 'base64url').toString()
    )

    if (protectedHeader.seq !== this._seq) {
      throw new FormatError('incorrect sequence')
    }
    ++this._seq

    switch (protectedHeader.typ) {
      case 'hdr':
        this._stateTransition('HEADER')

        await this._readHeader(obj)

        break

      case 'tag':
        if (this._state.value === 'header') {
          this._stateTransition('HEADER_TAG_SIGNATURE')
        } else {
          this._stateTransition('TAG_SIGNATURE')
        }

        await this._readTagSignature(obj)

        break

      case 'bdy':
        this._stateTransition('BODY')

        const { end, plaintext } = await this._readBody(obj)

        if (this._decompress != null) {
          await (this._decompress as any).writePromise(plaintext)
        } else {
          this._updateContentHash(plaintext)
          this.push(plaintext)
        }

        if (end) this._stateTransition('BODY_END')

        break

      case 'con':
        this._stateTransition('CONTENT_SIGNATURE')

        await this._readContentSignature(obj)

        break

      default:
        throw new Error(`unknown type '${protectedHeader.typ}'`)
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

    const { pub, hsh, cmp } = result.protectedHeader as any

    if (pub != null) {
      this.publicKey = createPublicKey({
        key: pub,
        format: 'jwk'
      })
    }

    if (hsh != null) {
      const { con, tag } = hsh

      if (con != null) this._contentHash = createHash(con)
      if (tag != null) this._tagHash = createHash(tag)
    }

    if (cmp != null) {
      const decompress = (this._decompress = createDecompress(cmp))

      ;(decompress as any).writePromise = promisify(decompress.write).bind(
        decompress
      )

      decompress.on('data', (chunk) => {
        this._updateContentHash(chunk)
        this.push(chunk)
      })
    }

    this._updateTagHash(jwe.tag)
  }

  private async _readBody(
    jwe: any
  ): Promise<{ end: boolean; plaintext: Uint8Array }> {
    let end = false

    try {
      const result = await flattenedDecrypt(
        jwe,
        this._ephemeralKey as KeyObject
      )

      if ((result.protectedHeader as any).end === true) end = true

      this._updateTagHash(jwe.tag)

      return { end, plaintext: result.plaintext }
    } catch (err) {
      throw new DecryptionFailedError()
    }
  }

  private async _readContentSignature(jwe: any) {
    if (this._contentHash == null) return

    let plaintext: Uint8Array

    try {
      const result = await flattenedDecrypt(
        jwe,
        this._ephemeralKey as KeyObject
      )

      this._updateTagHash(jwe.tag)

      plaintext = result.plaintext
    } catch (err) {
      throw new DecryptionFailedError()
    }

    let jws

    try {
      jws = JSON.parse(plaintext.toString())
    } catch (err) {
      throw new FormatError()
    }

    const digest = this._contentHash.digest()

    jws.payload = digest.toString('base64url')

    try {
      const result = await flattenedVerify(jws, this.publicKey as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private async _readTagSignature(jws: any) {
    if (this._tagHash == null) return

    const digest = this._tagHash.copy().digest()

    jws.payload = digest.toString('base64url')

    try {
      const result = await flattenedVerify(jws, this.publicKey as KeyObject)
    } catch (err) {
      throw new SignatureVerificationFailedError()
    }
  }

  private _updateTagHash(tag: string) {
    const hash = this._tagHash
    if (hash == null) return
    hash.update(Buffer.from(tag, 'base64url'))
  }

  private _updateContentHash(chunk: Uint8Array) {
    const hash = this._contentHash
    if (hash == null) return
    hash.update(chunk)
  }
}

function createDecompress(type: string): Gunzip | Inflate | BrotliDecompress {
  switch (type) {
    case 'gzip':
      return createGunzip()
    case 'deflate':
      return createInflate()
    case 'br':
      return createBrotliDecompress()
    default:
      throw new Error(`unknown compression type '${type}'`)
  }
}
