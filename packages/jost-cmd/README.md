# JOST

JOST is a command line tool for working with (JO)SE (ST)reams. Its features
include file encryption, decryption, signing, signature verification, and
key management.
See: [jose-stream](https://github.com/jjavery/jost-js/tree/main/packages/jose-stream#readme)

## Warning

- Beta
- Until it hits 1.0 there will be frequent changes to API and format
- Some features not functional or buggy
- Bug reports welcome
- PRs welcome but get in touch first

## Installation

```
npm install -g jost-cmd
```

## Usage

```
jost --help
```

Output:

```
Usage: jost [options] [command]

JOST is a tool for working with (JO)SE (ST)reams

Options:
  -V, --version              output the version number
  -h, --help                 display help for command

Commands:
  encrypt [options] <input>  Encrypt the input
  decrypt [options] <input>  Decrypt the input
  keygen [options]           Generate a key
  export [options]           Export a public key
  help [command]             display help for command
```

### Encrypt

```
Usage: jost encrypt [options] <input>

Encrypt the input

Options:
  -r, --recipient <recipient...>   Encrypt to the specified recipient
  -R, --recipients-file <path...>  Encrypt to the specified recipients listed at path
  -i, --identity <path>            Use the identity file at path
  -o, --output <path>              Write the result to the file at path
  --no-compress                    Don't compress the input prior to encryption
  --no-sign                        Don't sign the plaintext and ciphertext
  --no-self                        Don't add identity to the recipients
  -h, --help                       display help for command
```

### Decrypt

```
Usage: jost decrypt [options] <input>

Decrypt the input

Options:
  -i, --identity <path...>  Use the identity file at path
  -o, --output <path>       Write the result to the file at path
  -h, --help                display help for command
```

### Sign

```
Usage: jost sign [options] <input>

Sign the input

Options:
  -i, --identity <path>  Use the identity file at path
  -o, --output <path>    Write the result to the file at path
  --detached             Write a detached signature
  -h, --help             display help for command
```

### Verify

```
Usage: jost verify [options] <input>

Verify the input

Options:
  -K, --keys-file <path...>  Verify the signature using the keys listed at path
  -o, --output <path>        Write the result to the file at path
  -h, --help                 display help for command
```

### Keygen

```
Usage: jost keygen [options]

Generate a key

Options:
  -o, --output <path>    Add the generated key to the JWKS file at path
  -d, --key-id <kid>     Assigns an id to the generated key
  -a, --algorithm <alg>  Key algorithm (choices: "RS256", "RS384", "RS512",
                         "PS256", "PS384", "PS512", "RSA-OAEP", "RSA1_5",
                         "ES256", "ES256K", "ES384", "ES512", "EdDSA",
                         "ECDH-ES", default: "EdDSA")
  -c, --curve <crv>      Key curve for the EdDSA and ECDH-ES algorithms
                         (choices: "Ed25519", "Ed448", "P-256", "P-384",
                         "P-521", "X25519", "X448", default: "Ed25519")
  -h, --help             display help for command
```

### Export

```
Usage: jost export [options]

Export a public key

Options:
  -i, --identity <path...>  Use the identity file at path
  -o, --output <path>       Add the exported key to the JWKS file at path
  -d, --key-id <kid>        Exports the key with the specified id
  -h, --help                display help for command
```

## Example

### Key Management

```
jost keygen -o secret.jwks
jost export -o public.jwks
```

### Encrypt/Decrypt

```
jost encrypt -i secret.jwks -o example.jost example.txt
jost decrypt -i secret.jwks -o example.txt example.jost
```

### Encrypt to someone else's public key

```
jost encrypt -i secret.jwks -R johnsmith.jwks -o example.jost example.txt
```
