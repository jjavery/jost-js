import { Command, Option } from 'commander'
import decrypt from './commands/decrypt'
import encrypt from './commands/encrypt'
import export_ from './commands/export'
import keygen from './commands/keygen'
import print from './commands/print'

const pkg = require('../package.json')

const program = new Command()

program
  .name('jost')
  .description(`JOST is a tool for working with (JO)SE (ST)reams`)
  .version(pkg.version)

program
  .command('encrypt')
  .argument('<input>')
  .allowExcessArguments(false)
  .description('Encrypt the input')
  .option(
    '-r, --recipient <recipient...>',
    'Encrypt to the specified recipient'
  )
  .option(
    '-R, --recipients-file <path...>',
    'Encrypt to the specified recipients listed at path'
  )
  .option('-i, --identity <path>', 'Use the identity file at path')
  .option('-o, --output <path>', 'Write the result to the file at path')
  .option('--no-compress', "Don't compress the input prior to encryption")
  .option('--no-sign', "Don't sign the plaintext and ciphertext")
  .option('--no-self', "Don't add identity to the recipients")
  .action(async (arg, options) => {
    if (
      options.self === false &&
      (options.recipient == null || options.recipient.length === 0) &&
      (options.recipientsFile == null || options.recipientsFile.length === 0)
    ) {
      program.error(
        `error: required options '-r, --recipient <path>' or '-R, --recipients-file <path>' not specified`
      )
    }

    await encrypt(arg, options)
  })

program
  .command('decrypt')
  .argument('<input>')
  .allowExcessArguments(false)
  .description('Decrypt the input')
  .option('-i, --identity <path...>', 'Use the identity file at path')
  .option('-o, --output <path>', 'Write the result to the file at path')
  .action(decrypt)

program
  .command('keygen')
  .allowExcessArguments(false)
  .description('Generate a key')
  .option('-o, --output <path>', 'Add the generated key to the JWKS file at path')
  .option('-d, --key-id <kid>', 'Assigns an id to the generated key')
  .addOption(
    new Option('-a, --algorithm <alg>', 'Key algorithm')
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
      .default('EdDSA')
  )
  .addOption(
    new Option(
      '-c, --curve <crv>',
      'Key curve for the EdDSA and ECDH-ES algorithms'
    )
      .choices([
        'Ed25519',
        'Ed448',
        'P-256',
        'P-384',
        'P-521',
        'X25519',
        'X448'
      ])
      .default('Ed25519')
  )
  .action(keygen)

program
  .command('export')
  .allowExcessArguments(false)
  .description('Export a public key')
  .option('-i, --identity <path...>', 'Use the identity file at path')
  .option('-o, --output <path>', 'Add the exported key to the JWKS file at path')
  .option('-d, --key-id <kid>', 'Exports the key with the specified id')
  .action(export_)

program
  .command('print', { hidden: true })
  .argument('<input>')
  .allowExcessArguments(false)
  .description('Pretty-print the JOSE stream')
  .option('-o, --output <path>', 'Write the result to the file at path')
  .action(print)

const argv = [...process.argv]

// TODO: this is a hack
if ((argv[2] === 'encrypt' || argv[2] === 'decrypt') && argv.length > 4) {
  argv.splice(argv.length - 1, 0, '--')
}

;(async () => {
  await program.parseAsync(argv)
})().then(
  () => {},
  (err) => {
    program.error(`error: ${err?.message}`)
  }
)
