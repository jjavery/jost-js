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

### Format

Here's an incomplete and non-standard
[EBNF](https://en.wikipedia.org/wiki/Extended_Backus–Naur_form)-ish grammar
describing the format:

<pre>
jose-stream       = header, [ tag-signature ], { body }, body-end,
                    [ content-signature ], [tag-signature ];

header            = general-jwe( {
                      protected: {
                        typ: "jose-stream", pub: public-key,
                        dig: digest, cmp: compression, enc: encryption,
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
digest            = "sha256" | "sha384" | "sha512" | "sha512-256" |
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

### Goals:

- Work within the standards: Read and write JOSE-Stream encoded streams
  utilizing existing JOSE framework libraries

### Similar to JOSE-Stream:

- [libsodium secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
- [Tink Streaming AEAD](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data)
- [Miscreant STREAM](https://github.com/miscreant/meta/wiki/STREAM)
- [age STREAM](https://age-encryption.org/v1)
