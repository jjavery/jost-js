# JOSE-Stream

Node.js encrypted streams with
[JOSE](https://datatracker.ietf.org/doc/html/rfc7165)
([JWE](https://datatracker.ietf.org/doc/html/rfc7516),
[JWS](https://datatracker.ietf.org/doc/html/rfc7515),
[JWK](https://datatracker.ietf.org/doc/html/rfc7517)) and
[JSONL](https://jsonlines.org)/[NDJSON](http://ndjson.org)

JWE and JWS have become popular formats for the exchange of encrypted and signed
data on the web. While they are well-suited for encryption and signing of short
messages, they're less suitable for long messages and large files owing to the
lack of streaming JSON or JWE parsers. Typically an entire JWE or JWS is held in
memory during encryption/decryption/signing/verification, which imposes limits
on scalability in memory-constrained and server environments. In addition,
multiple layers of Base64 encoding result in additional bandwidth and storage
overhead when utilizing sign-encrypt or sign-encrypt-sign pipelines.

JOSE-Stream proposes a streaming JWE encryption format with JWS signatures.
Plaintext is compressed and split into fixed-length chunks. Chunks are encrypted
with JWE and—along with a JWE header and JWS signatures—streamed in the JSONL
line-delimited JSON format. Compression and signatures are both optional.

For implementation examples see
[JOST](https://github.com/jjavery/jost-js/tree/main/packages/jost-cmd),
a command line tool for working with JOSE streams, which depends upon
this jose-stream package.

## Format

- Newline-delimited, one JSON per line.
- LF is preferred, but CRLF is allowed, as JSON parsers will eat the CR as
  whitespace
- Each line contains one complete JWE or JWS serialization, which itself must
  not contain any unescaped newline characters
- All JWE or JWS instances must contain a "seq" sequence property in their
  protected headers
- The value of the "seq" sequence property is an unsigned integer, starting at
  0, and incrementing by 1 with each subsequent JWE or JWS instance
- A JWE or JWS instance with a missing or out-of-order "seq" sequence value
  must invalidate the entire JSON-Stream

### Header

The header is a JWE using the
[fully general JWE JSON Serialization syntax](https://tools.ietf.org/html/rfc7516#section-7.2.1).
Its "typ" property is "jose-stream". It carries:

- The secret key used to encrypt all subsequent JWE instances
- (Optionally) the public key corresponding to the private key used to sign all
  subsequent JWS instances
- The identities of the digest, compression, and encryption algorithms used with
  subsequent JWE and JWS instances

### Header Tag Signature

The header tag signature is a JWS using the
[flattened JWS JSON Serialization syntax](https://tools.ietf.org/html/rfc7515#section-7.2.2).
Its "typ" property is "tag". It is produced by signing the base64url decoded
"tag" value of the preceding header instance using the private key corresponding
to the "pub" public-key included in the header instance. It is conditional, and
is required if the header instance includes a public key in its "pub" value.
Otherwise it must not appear in the jose-stream.

### Body

A body instance is a JWE using the
[flattened JWE JSON Serialization syntax](https://tools.ietf.org/html/rfc7516#section-7.2.2).
Its "typ" property is "bdy". It is produced by encrypting a chunk of the
(optionally compressed) plaintext using the secret key encrypted and base64url
encoded in the ciphertext property of the header instance. Multiple body
instances are allowed, one for each fixed-size chunk of the compressed
plaintext. The final body instance in the jose-stream must include the boolean
value true in its "end" property.

### Content Signature

The content signature is a JWE using the
[flattened JWE JSON Serialization syntax](https://tools.ietf.org/html/rfc7516#section-7.2.2).
Its "typ" property is "sig". It is produced by encrypting a JWS instance using
the secret key encrypted and base64url encoded in the ciphertext property of the
header instance. The JWS instance is produced by signing a digest of the
plaintext using the private key corresponding to the "pub" public-key included
in the header instance. It is conditional, and is required if the header
instance includes a public key in its "pub" value. Otherwise it must not appear
in the jose-stream.

### Final Tag Signature

The final tag signature is a JWS using the
[flattened JWS JSON Serialization syntax](https://tools.ietf.org/html/rfc7515#section-7.2.2).
Its "typ" property is "tag". It is produced by signing the base64url decoded and
concatenated "tag" values of all preceding JWE instances using the private key
corresponding to the "pub" public-key included in the header instance. It is
conditional, and is required if the header instance includes a public key in its
"pub" value. Otherwise it must not appear in the jose-stream.

### EBNF Grammar

Here's an incomplete and non-standard
[EBNF](https://en.wikipedia.org/wiki/Extended_Backus–Naur_form)-ish grammar
describing the format:

<pre>
jose-stream       = header, [ tag-signature ], { body }, body-end,
                    [ content-signature ], [tag-signature ];

header            = general-jwe( {
                      protected: {
                        typ: "jose-stream", pub: public-key,
                        dig: digest-type, cmp: compression, enc: encryption,
                        seq: 0
                      },
                      ciphertext: base64url( encrypt( body-key ) )
                    } ), newline;

tag-signature     = flattened-jws( {
                      protected: {
                        typ: "tag", seq: sequence, b64: false
                      },
                      signature: base64url( sign( digest( tag, { tag } ) ) )
                    } ), newline;

body-end          = body( {
                      protected: { end: true }
                    } );

body              = flattened-jwe( {
                      protected: {
                        typ: "bdy", seq: sequence
                      },
                      ciphertext: base64url( encrypt( chunk( compress(
                        plaintext
                      ) ) ) )
                    } ), newline;

content-signature = flattened-jwe( {
                      protected: {
                        typ: "sig", alg: "dir", enc: encryption, seq: sequence
                      },
                      ciphertext: base64url( encrypt( flattened-jws( {
                        protected: { b64: false },
                        signature: base64url( sign( digest( plaintext ) ) )
                      } ) ) )
                    } ), newline;

general-jwe       = ? <a href="https://tools.ietf.org/html/rfc7516#section-7.2.1">RFC 7516 § 7.2.1 General JWE JSON Serialization</a> ?;
flattened-jwe     = ? <a href="https://tools.ietf.org/html/rfc7516#section-7.2.2">RFC 7516 § 7.2.2 Flattened JWE JSON Serialization</a> ?;
flattened-jws     = ? <a href="https://tools.ietf.org/html/rfc7515#section-7.2.2">RFC 7515 § 7.2.2 Flattened JWS JSON Serialization</a> ?;
jwk               = ? <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 § 4 JSON Web Key (JWK) Format</a> ?;
public-key        = jwk;
body-key          = random( encryption );
tag               = ? base64urldecode(jwe.tag) of preceding JWE instance ?;
digest-type       = "sha256" | "sha384" | "sha512" | "sha512-256" |
                    "blake2b512" | "blake2s256";
compression       = "DEF" | "GZ" | "BR";
encryption        = "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" |
                    "A128GCM" | "A192GCM" | "A256GCM";
sequence          = ? Unsigned integer. Previous protected.seq + 1 ?;
base64url         = ? <a href="https://tools.ietf.org/html/rfc4648#section-5">RFC 4648 § 5 Base 64 Encoding with URL Safe Alphabet</a> ?;
base64urldecode   = ? decode of base64url to byte array ?;
encrypt           = ? JWE encryption method based on protected.enc in
                    jose-stream header ?;
sign              = ? JWS signature method based on protected.pub in jose-stream
                    header ?;
random            = ? cryptographically secure random byte array with length
                    based on requirements of ( encryption ) algorithm ?;
chunk             = ? split of input byte array into fixed-length chunks, not
                    to exceed 1.5 MiB in length ?;
digest            = ? cryptographic hash function defined by protected.dig in
                    jose-stream header ?;
compress          = ? compression function defined by protected.cmp in
                    jose-stream header ?;
newline           = "\n";
</pre>

### Example jose-stream formatted file

An example of a jose-stream formatted file with a single recipient, with
protected headers decoded from base64url to JSON, pretty-printed, and with
each newline marked explicitly:

```json
{
  "protected": {
    "typ": "jose-stream",
    "pub": {
      "crv": "Ed25519",
      "x": "cXbDRvACe2NSsaTpOOWUZv_mH1wiPoE6Y5Jff4IyWiM",
      "kty": "OKP"
    },
    "dig": "blake2b512",
    "cmp": "DEF",
    "enc": "A256GCM",
    "seq": 0,
    "epk": {
      "x": "qBBa0dpSYokFMmHt6s0KIKs1cFfqXtfJnXKV8y169T0",
      "crv": "X25519",
      "kty": "OKP"
    }
  },
  "recipients": [
    {
      "encrypted_key": "P2MEQVOueTL7GLCawJJCp0_hvDks78dYKkWQzOa6tf1AsMfHsqGEGQ",
      "header": {
        "alg": "ECDH-ES+A256KW",
        "kid": "OhHmvNaYntMdpoH9LlPyUg9svcMzp3Jqj6zCjKK_rGs"
      }
    }
  ],
  "iv": "OnFMc_YacqlaF7ON",
  "ciphertext": "b-Lr_JteXKj9yt22cMTP37n1E9yrPLhqK5l0pdfEof_lg8PHe2TqRG5hSPNpzCOhG0iOMMb-VMBV4KjBFwg9",
  "tag": "46GkceBB8ALz1kE7HwbrCQ"
}
<newline>
{
  "protected": {
    "typ": "tag",
    "alg": "EdDSA",
    "crv": "Ed25519",
    "b64": false,
    "seq": 1
  },
  "signature": "7UoTDnGuC-RYE2pI1lUgbcWSn057GY5vaugPXijKmDVR_n9iRdwa0G36KAYWx7dLNCT93yYIlslgAgFrZIh9Dw"
}
<newline>
{
  "protected": {
    "typ": "bdy",
    "alg": "dir",
    "enc": "A256GCM",
    "end": true,
    "seq": 2
  },
  "iv": "kgVytUX9Xx24SgaG",
  "ciphertext": "aWkkgmPgGUspNW_kWjW_tL3G947dD6IUA3-RTPeg2ssjqDYBbhGQzlj1SPdtZdMN0Tt2g4xAEkeqUjH2Q393h-FZ5ZUux_P8ARqba__Keqn6mJukEnMNqlVPZDaOersUSZ3lBxGMI9pUWFbl-9mYQEDxK1xt0UwUIpXwnRSdMOJynyWWhMrKzFNvUTIQ3UMwDOTB33vH8yj-8LtlTrvFwHJH_Lw6mrPTJSmd1QyTY8lvMgECMsqEGGBqsISljGRWMA4j5D-wpfLozaiHyd4G6MTjMBHZdg",
  "tag": "iV2ghlZlF3SlLEw6DDZ5xg"
}
<newline>
{
  "protected": {
    "typ": "sig",
    "alg": "dir",
    "enc": "A256GCM",
    "seq": 3
  },
  "iv": "zTXmMgqpkB-0-t2R",
  "ciphertext": "gZ3ilSyj1mWSg4kH0JiscyeP8U1V9UX1sTlijc9IaoUOYN2BaH4_In7Pzn1pHBWNCyV-zyhKBj57iayLlb2v_Ne4zAV1adt7E0soF70rNcjjlncPi67zPgXnYYLICJ_4Xg4l1UEwbaeGP2eTIQtDA8WQdAvPnfea4e6RSwy3_358y0EZBctQF-6S4LLlcyqpOMT_j8rqpzbIJTq6sSKbIbpnnF_6Ygl307WLVFLR9Q",
  "tag": "JVN9qtLtm75u9crHcB4RXg"
}
<newline>
{
  "protected": {
    "typ": "tag",
    "alg": "EdDSA",
    "crv": "Ed25519",
    "b64": false,
    "seq": 4
  },
  "signature": "swqq_9RkAsUkRjcrfs979UlqZOix35C1D-dFGzcbo7h4cTDMxq07Ee7N4x983uvG-DDgdnMoYwjBJsBgpTxMCg"
}
<newline>
```

## Goals:

- Work within the standards: Read and write JOSE-Stream encoded streams
  utilizing existing JOSE framework libraries

## Similar to JOSE-Stream:

- [libsodium secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
- [Tink Streaming AEAD](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data)
- [Miscreant STREAM](https://github.com/miscreant/meta/wiki/STREAM)
- [age STREAM](https://age-encryption.org/v1)
