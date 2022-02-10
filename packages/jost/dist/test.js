"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ecdhKeyPair = exports.signingKeyPair = void 0;
const crypto_1 = require("crypto");
const privateKey = (0, crypto_1.createPrivateKey)({
    key: {
        crv: 'Ed25519',
        d: 'IJqpZAS_S0NuuPh7Sqm9Hzs5IeafrRmsjXqaDroch6w',
        x: 'cXbDRvACe2NSsaTpOOWUZv_mH1wiPoE6Y5Jff4IyWiM',
        kty: 'OKP'
    },
    format: 'jwk'
});
const publicKey = (0, crypto_1.createPublicKey)(privateKey);
// The above key converted to X25519
const x25519PrivateKey = (0, crypto_1.createPrivateKey)({
    key: {
        crv: 'X25519',
        x: 'OhHmvNaYntMdpoH9LlPyUg9svcMzp3Jqj6zCjKK_rGs',
        d: 'GAaLBg4d_E-c1cd6hz6sBG6X7FM7xRTOMTBceCfax1A',
        kty: 'OKP'
    },
    format: 'jwk'
});
const x25519PublicKey = (0, crypto_1.createPublicKey)(x25519PrivateKey);
exports.signingKeyPair = { publicKey, privateKey };
exports.ecdhKeyPair = {
    publicKey: x25519PublicKey,
    privateKey: x25519PrivateKey
};
//# sourceMappingURL=test.js.map