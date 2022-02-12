"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ed25519_to_x25519_1 = require("@jjavery/ed25519-to-x25519");
const commander_1 = require("commander");
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const jose_stream_1 = require("jose-stream");
const os_1 = require("os");
const promises_1 = require("stream/promises");
const jwks_1 = __importDefault(require("./jwks"));
const defaultIdentityPath = `${(0, os_1.homedir)()}/.jost/identity.jwks.json`;
async function encrypt(arg, options) {
    if ((options.recipient == null || options.recipient.length === 0) &&
        (options.recipientsFile == null || options.recipientsFile.length === 0)) {
        commander_1.program.error(`error: required options '-r, --recipient <path>' or '-R, --recipients-file <path>' not specified`);
    }
    let identities;
    const identityPath = options.identity || defaultIdentityPath;
    try {
        identities = jwks_1.default.fromFile(identityPath);
    }
    catch (err) {
        if (options.identity == null) {
            commander_1.program.error(`error: required option '-i, --identity <path>' not specified
or create a default identity file in '${defaultIdentityPath}'
example: mkdir ${(0, os_1.homedir)()}/.jost; jost keygen -o '${defaultIdentityPath}'`);
        }
        else {
            throw err;
        }
    }
    const jwk = identities?.keys[0];
    const key = (0, crypto_1.createPrivateKey)({ key: jwk, format: 'jwk' });
    const identity = {
        privateKey: key,
        publicKey: (0, crypto_1.createPublicKey)(key)
    };
    const recipients = [];
    options.recipient?.forEach((recipient) => {
        let key = (0, crypto_1.createPublicKey)({
            key: {
                crv: 'Ed25519',
                x: recipient,
                kty: 'OKP'
            },
            format: 'jwk'
        });
        key = (0, ed25519_to_x25519_1.convertEd25519PublicKeyToX25519)(key);
        recipients.push({ key, alg: 'ECDH-ES+A256KW' });
    });
    options.recipientsFile?.forEach((path) => {
        const jwks = jwks_1.default.fromFile(path);
        jwks.keys.forEach((jwk) => {
            let key = (0, crypto_1.createPublicKey)({ key: jwk, format: 'jwk' });
            key = (0, ed25519_to_x25519_1.convertEd25519PublicKeyToX25519)(key);
            recipients.push({ key, alg: 'ECDH-ES+A256KW' });
        });
    });
    shuffle(recipients);
    let input, output;
    if (arg != null) {
        input = (0, fs_1.createReadStream)(arg);
    }
    else {
        input = process.stdin;
    }
    if (options.output) {
        output = (0, fs_1.createWriteStream)(options.output);
    }
    else {
        output = process.stdout;
    }
    const jostWriter = new jose_stream_1.JostWriter({
        recipients,
        encryption: {
            enc: 'A256GCM'
        },
        signature: {
            publicKey: identity.publicKey,
            privateKey: identity.privateKey,
            alg: 'EdDSA',
            crv: 'Ed25519',
            contentHash: 'blake2b512',
            tagHash: 'blake2b512'
        },
        compression: {
            type: 'deflate'
        }
        // chunkSize: 256
    });
    await (0, promises_1.pipeline)(input, jostWriter, output);
}
exports.default = encrypt;
function shuffle(array) {
    let m = array.length, t, i;
    // While there remain elements to shuffle...
    while (m) {
        // Pick a remaining element...
        i = Math.floor(Math.random() * m--);
        // And swap it with the current element.
        t = array[m];
        array[m] = array[i];
        array[i] = t;
    }
    return array;
}
//# sourceMappingURL=encrypt.js.map