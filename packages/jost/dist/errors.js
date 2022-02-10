"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SignatureVerificationFailedError = exports.FormatError = exports.BufferOverflowError = exports.DecryptionFailedError = void 0;
class DecryptionFailedError extends Error {
    constructor() {
        super('decryption failed');
    }
}
exports.DecryptionFailedError = DecryptionFailedError;
class BufferOverflowError extends Error {
    constructor() {
        super('buffer overflow');
    }
}
exports.BufferOverflowError = BufferOverflowError;
class FormatError extends Error {
}
exports.FormatError = FormatError;
class SignatureVerificationFailedError extends Error {
    constructor() {
        super('signature verification failed');
    }
}
exports.SignatureVerificationFailedError = SignatureVerificationFailedError;
//# sourceMappingURL=errors.js.map