import BufferList from 'bl/BufferList'
import { createHash, generateKey, KeyObject } from 'crypto'
import { FlattenedEncrypt, FlattenedSign, GeneralEncrypt } from 'jose'
import { Transform, TransformCallback } from 'stream'
import { callbackify, promisify, TextEncoder } from 'util'

const generateKeyPromise = promisify(generateKey)

const defaultChunkSize = 64 * 1024
// const defaultChunkSize = 256

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

interface JoseStreamWriterOptions {
  chunkSize?: number
  signingKeyPair?: KeyPair
  recipients: KeyObject[]
}

export default class JoseStreamWriter extends Transform {
  private _chunkSize: number
  private _signingKeyPair?: KeyPair
  private _recipients: KeyObject[]
  private _ephemeralKey: KeyObject | null = null
  private _buffer: BufferList
  private _state = 0
  private _seq = 0
  private _hash
  private _pushCallback

  constructor(options: JoseStreamWriterOptions) {
    super()

    this._chunkSize = options.chunkSize ?? defaultChunkSize
    this._signingKeyPair = options.signingKeyPair
    this._recipients = options.recipients
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
    if (this._state === 0) {
      await this._writeHeader()
      ++this._state
    }

    if (this._state === 1) {
      const chunkSize = this._chunkSize
      const buffer = this._buffer

      if (chunk != null && chunk.length > 0) buffer.append(chunk)

      while (buffer.length > (this.writableEnded ? 0 : chunkSize)) {
        const chunk = buffer.slice(0, chunkSize)
        buffer.consume(chunkSize)

        const end = this.writableEnded && buffer.length === 0

        await this._writeBody(chunk, end)
        if (end) ++this._state
      }
    }

    if (this._state === 2) {
      await this._writeSignature()
      ++this._state
    }
  }

  private async _writeHeader() {
    this._ephemeralKey = await generateKeyPromise('aes', { length: 256 })
    const jwk = this._ephemeralKey.export({ format: 'jwk' })

    const plaintext = new TextEncoder().encode(JSON.stringify(jwk))

    delete jwk.k

    let pub;

    if (this._signingKeyPair != null) {
      pub = this._signingKeyPair.publicKey.export({ format: 'jwk' })
    }

    const encrypt = new GeneralEncrypt(plaintext).setProtectedHeader({
      enc: 'A256GCM',
      pub: pub
    })

    for (const recipient of this._recipients) {
      encrypt
        .addRecipient(recipient)
        .setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' })
    }

    const jwe = await encrypt.encrypt()

    plaintext.fill(0)

    this._updateHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeBody(chunk: Buffer, end: boolean) {
    const seq = this._seq++

    const encrypt = new FlattenedEncrypt(chunk).setProtectedHeader({
      alg: 'dir',
      enc: 'A256GCM',
      end,
      seq,
      zip: 'DEF'
    })

    const jwe = await encrypt.encrypt(this._ephemeralKey as KeyObject)

    this._updateHash(jwe.tag)

    const json = JSON.stringify(jwe)

    this.push(json)
    this.push('\n')
  }

  private async _writeSignature() {
    if (this._signingKeyPair == null) return;

    const hash = this._hash.digest()

    const sign = new FlattenedSign(hash).setProtectedHeader({
      alg: 'EdDSA',
      crv: 'Ed25519'
    })

    const jws = (await sign.sign(this._signingKeyPair.privateKey)) as any

    delete jws.payload

    const json = JSON.stringify(jws)

    this.push(json)
    this.push('\n')
  }

  private _updateHash(tag: string) {
    this._hash.update(Buffer.from(tag, 'base64url'))
  }
}
