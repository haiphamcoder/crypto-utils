# Technical Documentation: Message Digest (MD)

## 1) Introduction

Message Digest (MD) refers to a family of one-way hash functions that map input data of arbitrary length to a fixed-size output (the digest). The primary role of a message digest is to ensure data integrity: even a single-bit change in the input should produce a substantially different digest. MD algorithms are deterministic and fast, making them suitable for integrity checks and as components within higher-level cryptographic protocols.

- **Key purpose**: Detect accidental or unauthorized modifications to data.
- **Output**: Fixed-length digest (e.g., MD5: 128 bits, SHA-256: 256 bits).
- **Usage**: File integrity verification, password storage (with salts and slow KDFs), digital signatures, MACs/HMACs.

---

## 2) Operating principle of one-way hash functions

A cryptographic hash function H maps input M to a digest D = H(M) with the following desired properties:

- **Preimage resistance**: Given D, it is computationally infeasible to find any M such that H(M) = D.
- **Second-preimage resistance**: Given M1, it is infeasible to find M2 ≠ M1 such that H(M1) = H(M2).
- **Collision resistance**: It is infeasible to find any distinct pair (M1, M2) with H(M1) = H(M2). Practical target: work factor ~ 2^(n/2) for an n-bit hash due to the birthday paradox.
- **Determinism and consistency**: The same input always yields the same digest.
- **Avalanche effect**: A small change in input leads to a large, unpredictable change in output.

Internally, many hash functions use iterative compression: the input is padded, split into fixed-size blocks, and processed by a compression function that updates an internal state. The final state becomes the digest. MD4/MD5 and SHA-1/SHA-2 families follow this Merkle–Damgård-style construction.

---

## 3) Common MD algorithms

### MD5 (128-bit)

- Designed by Ronald Rivest (1992), successor to MD4.
- Processes data in 512-bit blocks, produces a 128-bit digest.
- Historically popular for checksums and file integrity.
- **Security status**: Broken for collision resistance (practical collisions since 2005; chosen-prefix collisions demonstrated). Not recommended for security-sensitive integrity or signatures.

### SHA family (NIST)

- **SHA-1 (160-bit)**
  - Released in 1995; 512-bit block processing; 160-bit output.
  - **Security status**: Broken for collision resistance (SHAttered, 2017; chosen-prefix collisions since 2019). Not recommended.

- **SHA-2 family**
  - Includes SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
  - Uses improved compression functions and larger state sizes.
  - **Security status**: Considered secure as of today when used properly.
  - Common choices: SHA-256 and SHA-512.

- (Note) **SHA-3 (Keccak)**
  - Sponge-based construction, standardized in 2015.
  - Not part of MD line but widely used; suitable alternative when SHA-2 is not preferred.

### Why older algorithms are deprecated

- Advances in cryptanalysis have made **MD5** and **SHA-1** vulnerable to practical collision attacks, enabling malicious tampering that preserves the same digest.
- Regulatory and industry standards (e.g., NIST SP 800-131A) disallow MD5/SHA-1 for digital signatures, certificates, and new designs.

---

## 4) Practical applications

- **File integrity verification**: Compare a known-good digest with a freshly computed one to detect accidental corruption. Prefer SHA-256/SHA-512 today.
- **Password storage**: Use slow, salted password hashing/KDFs (e.g., bcrypt, scrypt, Argon2). Plain MD5/SHA-1/SHA-256 alone is not appropriate for password storage.
- **Digital signatures**: Compute a digest first (e.g., SHA-256) and sign it with a private key (RSA/ECDSA). MD5/SHA-1 are no longer acceptable for new deployments.
- **HMAC (Message Authentication Codes)**: HMAC adds secret-keyed integrity and authenticity. HMAC-MD5 still exists for legacy compatibility; prefer HMAC-SHA-256 or HMAC-SHA-512 for new systems.
- **Data deduplication and fingerprinting**: Non-cryptographic or cryptographic hashes are used as identifiers; cryptographic choices depend on threat model.

---

## 5) Limitations and security caveats

- **Collisions**: MD5 and SHA-1 are vulnerable to practical collisions; do not use them for digital signatures, TLS certificates, or tamper-evident logs.
- **Fast by design**: General-purpose digests (MD5/SHA-2) are fast and thus unsuitable alone for password hashing. Use slow, memory-hard KDFs.
- **Length extension**: Merkle–Damgård hashes are vulnerable to length-extension attacks in some constructions. HMAC is designed to mitigate this.
- **Deprecation**: Many standards deprecate MD5/SHA-1; compliance frameworks require stronger hashes.

---

## 6) Using this library (crypto-utils)

This project provides convenient utilities for MD algorithms and HMAC with flexible encodings.

- Class: `com.haiphamcoder.crypto.hash.md.MDUtil`
- Algorithms: MD2, MD4 (via BouncyCastle), MD5
- Inputs: `byte[]`, `String` (with `Charset`), `File`
- Encodings: `InputEncoding` (HEX/Base64/UTF-8/etc.), `OutputEncoding` (HEX lower/upper, Base64, Base64-URL)
- HMAC: HMAC-MD5 helpers for bytes, strings, files (formatted outputs included)

Examples:

```java
// MD5 over UTF-8 string, output Base64
String base64 = MDUtil.md5("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// MD4 over HEX input, output uppercase HEX
String md4Hex = MDUtil.md4("48656C6C6F20576F726C64", InputEncoding.HEX, OutputEncoding.HEX_UPPER);

// HMAC-MD5 with UTF-8 inputs, output HEX lower
String mac = MDUtil.hmacMd5("data", "secret", InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
```

---

## 7) References

- NIST FIPS 180-4: Secure Hash Standard (SHA-1, SHA-2)
- NIST FIPS 202: SHA-3 Standard
- NIST SP 800-131A: Transitions: Recommendation for Cryptographic Algorithms and Key Lengths
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- Wang et al. (2005) — Breaks on MD5; SHAttered (2017) — First public SHA-1 collision; CP-SHA1 (2019)
