# JOSE-Stream

Node.js encrypted streams with [JOSE](https://datatracker.ietf.org/doc/html/rfc7165)
([JWE](https://datatracker.ietf.org/doc/html/rfc7516),
[JWS](https://datatracker.ietf.org/doc/html/rfc7515),
[JWK](https://datatracker.ietf.org/doc/html/rfc7517)) and [JSONL](https://jsonlines.org)

- JWE has become a popular format for the exchange of encrypted data on the web
- JWE is well-suited for encryption and/or signing of small JSON-formatted messages
- It's less suitable for large messages/files owing to lack of streaming JSON or
  JWE parsers
- Typically, the entire JWE held in memory during encrypt/decrypt/sign/verify
- Which may impose memory limits in constrained or server environments
- Also, multiple layers of Base64 encoding result in bandwidth/storage overhead
  when utilizing sign-encrypt or sign-encrypt-sign

JOSE-Stream proposes a streaming JWE format with optional JWS signing. Plaintext
is optionally compressed and split into fixed-size chunks. Chunks—along with a
JWE header and JWS signatures—are streamed in a JSONL line-delimited JSON format.

### Goals:

- Work within the standard: Read and write JOSE-Stream encoded streams utilizing existing JOSE framework libraries
- Optionally include signatures for plaintext and/or ciphertext
- Optional compression

### Similar to JOSE-Stream:

- [libsodium secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream)
- [Tink Streaming AEAD](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data)
- [Miscreant STREAM](https://github.com/miscreant/meta/wiki/STREAM)
- [age STREAM](https://age-encryption.org/v1)
