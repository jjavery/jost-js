export class DecryptionFailedError extends Error {
  constructor() {
    super('decryption failed')
  }
}

export class BufferOverflowError extends Error {
  constructor() {
    super('buffer overflow')
  }
}

export class FormatError extends Error {}

export class SignatureVerificationFailedError extends Error {
  constructor(err?: Error) {
    super('signature verification failed: ' + err?.message)
  }
}

export class KeyNotFoundError extends Error {}
