# JOST

JOST is a command line tool for working with (JO)SE (ST)reams. Its features enclude file encryption, decryption, signing, signature verification, and key management. See: [jose-stream](https://github.com/jjavery/jost-js/tree/main/packages/jose-stream#readme)

## Installation

```bash
npm install -g jost-cmd
```

## Usage

```bash
jost --help
```

Output:

```
Usage: jost [options] [command]

JOST version 0.1.0

Options:
  -V, --version              output the version number
  -h, --help                 display help for command

Commands:
  encrypt [options] <input>  Encrypt the input to the output
  decrypt [options] <input>  Decrypt the input to the output
  keygen [options]           Generate a key
  help [command]             display help for command
```

### Encrypt

```
Usage: jost encrypt [options] <input>

Encrypt the input to the output

Options:
  -o, --output <path>              Write the result to the file at path
  -r, --recipient <recipient...>   Encrypt to the specified recipient
  -R, --recipients-file <path...>  Encrypt to the specified recipients listed at path
  -i, --identity <path>            Use the identity file at path
  --no-compress                    Don't compress the input prior to encryption
  --no-sign                        Don't sign the plaintext and ciphertext
  --no-self                        Don't add identity to the recipients
  -h, --help                       display help for command
```

### Decrypt

```
Usage: jost decrypt [options] <input>

Decrypt the input to the output

Options:
  -o, --output <path>       Write the result to the file at path
  -i, --identity <path...>  Use the identity file at path
  -h, --help                display help for command
```

### Keygen

```
Usage: jost keygen [options]

Generate a key

Options:
  -o, --output <path>    Write the result to the file at path
  -d, --key-id <kid>     Assigns an id to the generated key
  -a, --algorithm <alg>  Key algorithm (choices: "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                         "RSA-OAEP", "RSA1_5", "ES256", "ES256K", "ES384", "ES512", "EdDSA", "ECDH-ES",
                         default: "EdDSA")
  -c, --curve <crv>      Key curve for the EdDSA and ECDH-ES algorithms (choices: "Ed25519", "Ed448", "P-256",
                         "P-384", "P-521", "X25519", "X448", default: "Ed25519")
  -h, --help             display help for command
```

## Example

```bash
jost keygen -o secret.jwks.json
jost encrypt -i secret.jwks.json -o example.jose.jsonl example.txt
jost decrypt -i secret.jwks.json -o example.txt example.jose.jsonl
```
