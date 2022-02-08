import BufferList from 'bl/BufferList'
import {
  createHash,
  generateKey as generateKeyCallback,
  KeyObject
} from 'crypto'
import { FlattenedEncrypt, FlattenedSign, GeneralEncrypt } from 'jose'
import { Transform, TransformCallback } from 'stream'
import { promisify } from 'util'

const generateKey = promisify(generateKeyCallback)

const defaultChunkSize = 64 * 1024

interface JoseStreamWriterOptions {
  chunkSize?: number
  recipient: RecipientOptions[]
  encryption: EncryptionOptions
  signature?: SignatureOptions
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
  ciphertextHash?:
    | 'sha256'
    | 'sha384'
    | 'sha512'
    | 'sha512-256'
    | 'blake2b512'
    | 'blake2s256'
  plaintextHash?:
    | 'sha256'
    | 'sha384'
    | 'sha512'
    | 'sha512-256'
    | 'blake2b512'
    | 'blake2s256'
}

export default class JoseStreamWriter extends Transform {
  private _chunkSize: number
  private _recipientOptions: RecipientOptions[]
  private _encryptionOptions: EncryptionOptions
  private _signatureOptions?: SignatureOptions
  private _ephemeralKey: KeyObject | null = null
  private _buffer = new BufferList()
  private _state = 0
  private _seq = 0
  private _ciphertextHash
  private _plaintextHash

  constructor(options: JoseStreamWriterOptions) {
    super()

    this._chunkSize = options.chunkSize ?? defaultChunkSize
    this._recipientOptions = options.recipient
    this._encryptionOptions = options.encryption
    this._signatureOptions = options.signature

    if (
      this._signatureOptions != null &&
      (this._signatureOptions.publicKey != null ||
        this._signatureOptions.secretKey != null)
    ) {
      if (this._signatureOptions.ciphertextHash != null) {
        this._ciphertextHash = createHash(this._signatureOptions.ciphertextHash)
      }
      if (this._signatureOptions.plaintextHash != null) {
        this._plaintextHash = createHash(this._signatureOptions.plaintextHash)
      }
    }
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

  private _pushCallback(chunk: Buffer | null, callback: Function) {
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
    if (this._state === 0) {
      await this._writeHeader()
      ++this._state
    }

    if (this._state === 1) {
      const chunkSize = this._chunkSize
      const buffer = this._buffer

      if (chunk != null && chunk.length > 0) {
        buffer.append(chunk)
        this._updatePlaintextHash(chunk)
      }

      while (buffer.length > (this.writableEnded ? 0 : chunkSize)) {
        const chunk = buffer.slice(0, chunkSize)
        buffer.consume(chunkSize)

        const end = this.writableEnded && buffer.length === 0

        await this._writeBody(chunk, end)
        if (end) ++this._state
      }
    }

    if (this._state === 2) {
      await this._writePlaintextSignature()
      ++this._state
    }

    if (this._state === 3) {
      await this._writeCiphertextSignature()
      ++this._state
    }
  }

  private async _writeHeader() {
    const length = parseInt(this._encryptionOptions.enc.substring(1, 4), 10)
    this._ephemeralKey = await generateKey('aes', { length })
    const jwk = this._ephemeralKey.export({ format: 'jwk' })

    const plaintext = Buffer.from(JSON.stringify(jwk), 'utf-8')

    delete jwk.k

    let pub, hashp, hashc

    if (
      this._signatureOptions != null &&
      (this._signatureOptions.publicKey != null ||
        this._signatureOptions.secretKey != null)
    ) {
      if (this._signatureOptions.publicKey != null) {
        pub = this._signatureOptions.publicKey.export({ format: 'jwk' })
      }
      hashp = this._signatureOptions.plaintextHash
      hashc = this._signatureOptions.ciphertextHash
    }

    const protectedHeader = {
      enc: this._encryptionOptions.enc,
      pub,
      hashp,
      hashc
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

    this._updateCiphertextHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeBody(chunk: Buffer, end?: boolean, sig?: boolean) {
    const seq = this._seq++

    const protectedHeader = {
      alg: 'dir',
      enc: this._encryptionOptions.enc,
      end: end || undefined,
      seq,
      sig: sig || undefined
    }

    const encrypt = new FlattenedEncrypt(chunk).setProtectedHeader(
      protectedHeader
    )

    const jwe = await encrypt.encrypt(this._ephemeralKey as KeyObject)

    // if (!sig) {
      this._updateCiphertextHash(jwe.tag)
    // }

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writePlaintextSignature() {
    const options = this._signatureOptions
    if (options == null || this._plaintextHash == null) return

    const digest = this._plaintextHash.digest()

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

    await this._writeBody(Buffer.from(json, 'utf8'), false, true)
  }

  private async _writeCiphertextSignature() {
    const options = this._signatureOptions
    if (options == null || this._ciphertextHash == null) return

    const digest = this._ciphertextHash.digest()

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

    this.push(json)
    this.push('\n')
  }

  private _updateCiphertextHash(tag: string) {
    const hash = this._ciphertextHash
    if (hash == null) return
    hash.update(Buffer.from(tag, 'base64url'))
  }

  private _updatePlaintextHash(chunk: Buffer) {
    const hash = this._plaintextHash
    if (hash == null) return
    hash.update(chunk)
  }
}
