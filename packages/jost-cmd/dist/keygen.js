"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const jose_stream_1 = require("jose-stream");
const jwks_1 = __importDefault(require("./jwks"));
async function default_1(options) {
    let jwks;
    let output;
    if (options.output != null) {
        try {
            try {
                jwks = jwks_1.default.fromFile(options.output);
            }
            catch (err) { }
            output = (0, fs_1.createWriteStream)(options.output);
        }
        catch (err) {
            console.error(err?.message);
            process.exit(1);
        }
    }
    else {
        output = process.stdout;
    }
    jwks ?? (jwks = new jwks_1.default());
    let alg = options.algorithm;
    let crv;
    if (alg === 'EdDSA' || alg === 'ECDH-ES') {
        crv = options.curve;
    }
    const keyPair = await (0, jose_stream_1.generateKeyPair)(alg, { crv });
    const jwk = await (0, jose_stream_1.exportJWK)(keyPair.privateKey);
    const pub = await (0, jose_stream_1.exportJWK)(keyPair.publicKey);
    jwk.kid = options.keyId;
    jwk.ts = new Date().toJSON();
    jwk.pub = pub;
    jwks.addKey(jwk);
    jwks.write(output);
    await new Promise((resolve, reject) => {
        output.end(resolve);
    });
}
exports.default = default_1;
//# sourceMappingURL=keygen.js.map