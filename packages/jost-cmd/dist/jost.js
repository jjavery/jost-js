"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const encrypt_1 = __importDefault(require("./encrypt"));
const keygen_1 = __importDefault(require("./keygen"));
const pkg = require('../package.json');
const program = new commander_1.Command();
program
    .name('jost')
    .description(`JOST version ${pkg.version}`)
    .version(pkg.version);
program
    .command('keygen')
    .allowExcessArguments(false)
    .description('Generate a key')
    .option('-o, --output <path>', 'Write the result to the file at path')
    .option('-d, --key-id <kid>', 'Assigns an id to the generated key')
    .addOption(new commander_1.Option('-a, --algorithm <alg>', 'Key algorithm')
    .choices([
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'RSA-OAEP',
    'RSA1_5',
    'ES256',
    'ES256K',
    'ES384',
    'ES512',
    'EdDSA',
    'ECDH-ES'
])
    .default('EdDSA'))
    .addOption(new commander_1.Option('-c, --curve <crv>', 'Key curve for the EdDSA and ECDH-ES algorithms')
    .choices([
    'Ed25519',
    'Ed448',
    'P-256',
    'P-384',
    'P-521',
    'X25519',
    'X448'
])
    .default('Ed25519'))
    .action(keygen_1.default);
program
    .command('encrypt')
    .argument('<input>')
    .allowExcessArguments(false)
    .description('Encrypt the input to the output')
    .option('-o, --output <path>', 'Write the result to the file at path')
    .option('-r, --recipient <recipient...>', 'Encrypt to the specified recipient')
    .option('-R, --recipients-file <path...>', 'Encrypt to the specified recipients listed at path')
    .option('-i, --identity <path>', 'Use the identity file at path')
    .action(encrypt_1.default);
program.command('decrypt').description('Decrypt the input to the output');
const argv = [...process.argv];
if ((argv[2] === 'encrypt' || argv[2] === 'decrypt') && argv.length > 4) {
    argv.splice(argv.length - 1, 0, '--');
}
;
(async () => {
    await program.parseAsync(argv);
})().then(() => { }, (err) => {
    program.error(`error: ${err?.message}`);
});
//# sourceMappingURL=jost.js.map