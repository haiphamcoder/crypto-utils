# Technical Documentation: Secure Hash Algorithms (SHA) and HMAC-SHA

## 1) Introduction to SHA

Secure Hash Algorithms (SHA) are standardized cryptographic hash functions used widely across cybersecurity. They convert variable-length input into a fixed-length digest, providing a compact fingerprint of data.

- **Role in security**: Verify integrity, underpin digital signatures, certificates, and many security protocols (TLS/SSL, IPsec, SSH).
- **One-way hash properties**:
  - **Pre-image resistance**: Infeasible to recover the input from the digest.
  - **Collision resistance**: Infeasible to find two different inputs with the same digest (target work ~2^(n/2) for n-bit digest).
  - **Efficiency**: Fast to compute even for large data, suitable for streaming.
- **Evolution**:
  - **SHA-1 (160-bit)**: Released 1995; collision attacks practical since 2017 (SHAttered) and 2019 (chosen-prefix). Deprecated.
  - **SHA-2 (SHA-224/256/384/512/512-224/512-256)**: Released 2001–2008; widely deployed and considered secure today.
  - **SHA-3 (Keccak)**: Standardized 2015; sponge-based design; recommended alternative when SHA-2 is not preferred.

---

## 2) How SHA-256 works (high level)

SHA-256 processes data in 512-bit blocks and produces a 256-bit digest.

- **Padding**:
  1. Append a single 1 bit.
  2. Append k zero bits until length ≡ 448 (mod 512).
  3. Append 64-bit big-endian length of the original message.
- **Initialization**: Eight 32-bit initial hash values (H0..H7) defined by the standard.
- **Message schedule**: Expand each 512-bit block into 64 32-bit words using σ0, σ1 rotations/shifts.
- **Compression function**: Iterate 64 rounds with constants K[i], mixing working variables (a..h) using Σ0, Σ1, Ch, Maj operations.
- **Finalization**: Add working variables back into (H0..H7) and concatenate to form the 256-bit digest.

Example (conceptual): Hashing "hello" (68656c6c6f) yields a fixed 64-hex-character digest. Any one-bit change in input will drastically change the output (avalanche effect).

---

## 3) HMAC-SHA: Purpose and mechanism

HMAC (Hash-based Message Authentication Code) combines a secret key with a hash function to provide integrity and authenticity.

- **Why HMAC**: Plain hashes ensure integrity only; they don't authenticate the sender. HMAC uses a secret key so only parties with the key can produce a valid MAC.
- **SHA vs HMAC-SHA**:
  - **SHA**: Unkeyed; integrity checking and as a building block for signatures.
  - **HMAC-SHA**: Keyed; provides both integrity and authentication of messages.
- **Algorithm (for a hash with block size B)**:
  1. If key length > B, set key = Hash(key). If key length < B, right-pad with zeros to B.
  2. Compute `o_key_pad = key XOR 0x5c5c...` (B bytes), `i_key_pad = key XOR 0x363636...` (B bytes).
  3. Return `Hash(o_key_pad || Hash(i_key_pad || message))`.

HMAC is designed to be secure even if the underlying hash has certain structural weaknesses (e.g., length-extension), and is standardized in RFC 2104 and FIPS 198-1.

---

## 4) Practical applications and comparison

- **Applications**:
  - **SHA**: File checksums, digital signatures (sign the digest), certificate chains, blockchain data structures, content addressing.
  - **HMAC-SHA**: API authentication (shared secret), TLS/SSL record MAC (legacy), IPsec AH/ESP, SSH message integrity, VPN tunnels.
- **Comparison**:
  - **SHA** verifies that data hasn't changed (e.g., download integrity checks).
  - **HMAC-SHA** verifies both that data hasn't changed and that it was produced by someone holding the secret key (trust/authenticity).

---

## 5) Using this library (crypto-utils)

- Class: `com.haiphamcoder.crypto.hash.sha.SHAUtil`
- Algorithms: SHA-1, SHA-256, SHA-384, SHA-512
- Inputs: `byte[]`, `String` (with `Charset`), `File`
- Encodings: `InputEncoding` (HEX/Base64/UTF-8/etc.), `OutputEncoding` (HEX lower/upper, Base64, Base64-URL)
- HMAC: HMAC-SHA1/256/384/512 with formatted outputs

Examples:

```java
// SHA-256 over UTF-8 input, Base64 output
String b64 = SHAUtil.sha256("Hello", InputEncoding.UTF8, OutputEncoding.BASE64);

// HMAC-SHA256 with UTF-8 inputs, HEX lowercase output
String mac = SHAUtil.hmacSha256("message", "secret", InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
```

---

## 6) References

- FIPS PUB 180-4: Secure Hash Standard (SHS)
- FIPS PUB 202: SHA-3 Standard
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- NIST SP 800-107 Rev.1: Recommendation for Applications Using Approved Hash Algorithms
