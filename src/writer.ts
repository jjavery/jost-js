import BufferList from 'bl/BufferList'
import {
  createHash,
  generateKey as generateKeyCallback,
  KeyObject
} from 'crypto'
import { FlattenedEncrypt, FlattenedSign, GeneralEncrypt } from 'jose'
import { Stream, Transform, TransformCallback } from 'stream'
import { promisify } from 'util'
import {
  BrotliCompress,
  BrotliOptions,
  createBrotliCompress,
  createDeflate,
  createGzip,
  Deflate,
  Gzip,
  ZlibOptions
} from 'zlib'

const generateKey = promisify(generateKeyCallback)

const defaultChunkSize = 64 * 1024

interface JoseStreamWriterOptions {
  chunkSize?: number
  recipients: RecipientOptions[]
  encryption: EncryptionOptions
  signature?: SignatureOptions
  compression?: CompressionOptions
}

export interface RecipientOptions {
  key: KeyObject
  alg:
    | 'RSA1_5'
    | 'RSA-OAEP'
    | 'RSA-OAEP-256'
    | 'A128KW'
    | 'A192KW'
    | 'A256KW'
    | 'dir'
    | 'ECDH-ES'
    | 'ECDH-ES+A128KW'
    | 'ECDH-ES+A192KW'
    | 'ECDH-ES+A256KW'
    | 'A128GCMKW'
    | 'A192GCMKW'
    | 'A256GCMKW'
    | 'PBES2-HS256+A128KW'
    | 'PBES2-HS384+A384KW'
    | 'PBES2-HS512+A256KW'
  kid?: string
}

export interface EncryptionOptions {
  enc:
    | 'A128CBC-HS256'
    | 'A192CBC-HS384'
    | 'A256CBC-HS512'
    | 'A128GCM'
    | 'A192GCM'
    | 'A256GCM'
}

export interface SignatureOptions {
  publicKey?: KeyObject
  privateKey?: KeyObject
  secretKey?: KeyObject
  alg:
    | 'HS256'
    | 'HS384'
    | 'HS512'
    | 'RS256'
    | 'RS384'
    | 'RS512'
    | 'ES256'
    | 'ES384'
    | 'ES512'
    | 'PS256'
    | 'PS384'
    | 'PS512'
    | 'EdDSA'
  crv?: 'Ed25519' | 'Ed448'
  tagHash?:
    | 'sha256'
    | 'sha384'
    | 'sha512'
    | 'sha512-256'
    | 'blake2b512'
    | 'blake2s256'
  contentHash?:
    | 'sha256'
    | 'sha384'
    | 'sha512'
    | 'sha512-256'
    | 'blake2b512'
    | 'blake2s256'
}

export interface CompressionOptions {
  type: 'gzip' | 'deflate' | 'br'
  options?: ZlibOptions | BrotliOptions
}

export default class JoseStreamWriter extends Transform {
  private _chunkSize: number
  private _recipientOptions: RecipientOptions[]
  private _encryptionOptions: EncryptionOptions
  private _signatureOptions?: SignatureOptions
  private _compressionOptions?: CompressionOptions
  private _ephemeralKey: KeyObject | null = null
  private _bufferList = new BufferList()
  private _state = 0
  private _seq = 0
  private _tagHash
  private _contentHash
  private _compress

  constructor(options: JoseStreamWriterOptions) {
    super()

    this._chunkSize = options.chunkSize ?? defaultChunkSize
    this._recipientOptions = options.recipients
    this._encryptionOptions = options.encryption
    this._signatureOptions = options.signature
    this._compressionOptions = options.compression

    // Initialize signatures
    if (
      this._signatureOptions != null &&
      (this._signatureOptions.publicKey != null ||
        this._signatureOptions.secretKey != null)
    ) {
      if (this._signatureOptions.tagHash != null) {
        this._tagHash = createHash(this._signatureOptions.tagHash)
      }
      if (this._signatureOptions.contentHash != null) {
        this._contentHash = createHash(this._signatureOptions.contentHash)
      }
    }

    // Initialize compression
    if (this._compressionOptions != null) {
      this._compress = createCompress(
        this._compressionOptions.type,
        this._compressionOptions.options
      )

      this._compress.on('data', (chunk) => {
        this._compress?.pause()
        this._pushCallback(chunk, false, () => {
          this._compress?.resume()
        })
      })

      this._compress.once('error', (err) => {
        this.emit('error', err)
      })
    }
  }

  _transform(
    chunk: Buffer,
    encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    this._updateContentHash(chunk)

    if (this._compress != null) {
      this._compress.write(chunk, callback)
    } else {
      this._pushCallback(chunk, false, callback)
    }
  }

  _flush(callback: TransformCallback): void {
    if (this._compress != null) {
      this._compress.end()
      this._compress.once('end', () => {
        this._pushCallback(null, true, callback)
      })
    } else {
      this._pushCallback(null, true, callback)
    }
  }

  private _pushCallback(
    chunk: Buffer | null,
    end: boolean,
    callback: (err?: any) => void
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
    if (this._state === 0) {
      ++this._state

      await this._writeHeader()
      await this._writeTagSignature()
    }

    if (this._state === 1) {
      if (end) ++this._state

      await this._writeBody(chunk, end)
    }

    if (this._state === 2) {
      ++this._state

      await this._writeContentSignature()
      await this._writeTagSignature()
    }
  }

  private async _writeHeader() {
    const seq = this._seq++

    const length = parseInt(this._encryptionOptions.enc.substring(1, 4), 10)
    this._ephemeralKey = await generateKey('aes', { length })
    const jwk = this._ephemeralKey.export({ format: 'jwk' })

    const plaintext = Buffer.from(JSON.stringify(jwk), 'utf-8')

    delete jwk.k

    let pub, hsh, contentHash, tagHash

    if (
      this._signatureOptions != null &&
      (this._signatureOptions.publicKey != null ||
        this._signatureOptions.secretKey != null)
    ) {
      if (this._signatureOptions.publicKey != null) {
        pub = this._signatureOptions.publicKey.export({ format: 'jwk' })
      }
      contentHash = this._signatureOptions.contentHash
      tagHash = this._signatureOptions.tagHash
    }

    if (contentHash != null || tagHash != null) {
      hsh = {
        con: contentHash,
        tag: tagHash
      }
    }

    const protectedHeader = {
      typ: 'hdr',
      enc: this._encryptionOptions.enc,
      pub,
      hsh,
      cmp: this._compressionOptions?.type,
      seq
    }

    const encrypt = new GeneralEncrypt(plaintext).setProtectedHeader(
      protectedHeader
    )

    for (const recipient of this._recipientOptions) {
      encrypt
        .addRecipient(recipient.key)
        .setUnprotectedHeader({ alg: recipient.alg, kid: recipient.kid })
    }

    const jwe = await encrypt.encrypt()

    plaintext.fill(0)

    this._updateTagHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeBody(chunk: Buffer | null, end: boolean) {
    const chunkSize = this._chunkSize
    const bl = this._bufferList

    if (chunk != null && chunk.length > 0) bl.append(chunk)

    while (bl.length > (end ? 0 : chunkSize)) {
      const chunk = bl.slice(0, chunkSize)
      bl.consume(chunkSize)

      await this._writeBody2(chunk, end && bl.length === 0)
    }
  }

  private async _writeBody2(chunk: Buffer, end: boolean) {
    const seq = this._seq++

    const protectedHeader = {
      typ: 'bdy',
      alg: 'dir',
      enc: this._encryptionOptions.enc,
      end: end || undefined,
      seq
    }

    const encrypt = new FlattenedEncrypt(chunk).setProtectedHeader(
      protectedHeader
    )

    const jwe = await encrypt.encrypt(this._ephemeralKey as KeyObject)

    this._updateTagHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeContentSignature() {
    const options = this._signatureOptions
    if (options == null || this._contentHash == null) return

    const digest = this._contentHash.digest()

    const protectedHeader = {
      alg: options.alg,
      crv: options.crv
    }

    const sign = new FlattenedSign(digest).setProtectedHeader(protectedHeader)

    const jws: any = await sign.sign(
      options.privateKey ?? (options.secretKey as KeyObject)
    )

    delete jws.payload

    const json = JSON.stringify(jws)

    await this._writeContentSignature2(Buffer.from(json, 'utf8'))
  }

  private async _writeContentSignature2(chunk: Buffer) {
    const seq = this._seq++

    const protectedHeader = {
      typ: 'con',
      alg: 'dir',
      enc: this._encryptionOptions.enc,
      seq
    }

    const encrypt = new FlattenedEncrypt(chunk).setProtectedHeader(
      protectedHeader
    )

    const jwe = await encrypt.encrypt(this._ephemeralKey as KeyObject)

    this._updateTagHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeTagSignature() {
    const seq = this._seq++

    const options = this._signatureOptions
    if (options == null || this._tagHash == null) return

    const digest = this._tagHash.copy().digest()

    const protectedHeader = {
      typ: 'tag',
      alg: options.alg,
      crv: options.crv,
      seq
    }

    const sign = new FlattenedSign(digest).setProtectedHeader(protectedHeader)

    const jws: any = await sign.sign(
      options.privateKey ?? (options.secretKey as KeyObject)
    )

    delete jws.payload

    const json = JSON.stringify(jws)

    this.push(json)
    this.push('\n')
  }

  private _updateTagHash(tag: string) {
    const hash = this._tagHash
    if (hash == null) return
    hash.update(Buffer.from(tag, 'base64url'))
  }

  private _updateContentHash(chunk: Buffer) {
    const hash = this._contentHash
    if (hash == null) return
    hash.update(chunk)
  }
}

function createCompress(
  type: string,
  options: ZlibOptions | BrotliOptions | undefined
): Gzip | Deflate | BrotliCompress {
  switch (type) {
    case 'gzip':
      return createGzip(options)
    case 'deflate':
      return createDeflate(options)
    case 'br':
      return createBrotliCompress(options)
    default:
      throw new Error(`unknown compression type '${type}'`)
  }
}
