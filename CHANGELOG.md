# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Short alias methods in `CRCUtil` for common presets:
  - `crc7`, `crc8`, `crc16`, `crc32`, `crc64` (with overloads and formatted variants)
- In-depth CRC technical documentation under `docs/CRC-Technical-Documentation.md`
- Unit tests covering the new short alias methods
- MD family utilities (`MDUtil`) with support for:
  - MD2, MD4 (BouncyCastle), MD5 algorithms
  - File processing variants for all algorithms
  - Custom input/output encoding support (HEX, Base64, UTF-8, etc.)
  - HMAC-MD5 with encoding flexibility
- BouncyCastle provider dependency for MD4 support
- In-depth MD technical documentation under `docs/MD-Technical-Documentation.md`
- JavaDoc comments added for `MDUtil` public APIs
- SHA family utilities (`SHAUtil`) with support for:
  - SHA-1, SHA-256, SHA-384, SHA-512 algorithms
  - File processing variants for all algorithms
  - Custom input/output encoding support (HEX, Base64, UTF-8, etc.)
  - HMAC-SHA1/256/384/512 with encoding flexibility
- In-depth SHA and HMAC technical documentation under `docs/SHA-and-HMAC-Technical-Documentation.md`
- JavaDoc comments added for `SHAUtil` public APIs
- Keccak family utilities (`KeccakUtil`) with support for:
  - Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512 algorithms
  - File processing variants for all algorithms
  - Custom input/output encoding support (HEX, Base64, UTF-8, etc.)
  - Comprehensive JavaDoc comments for all public methods
- In-depth Keccak technical documentation under `docs/Keccak-Technical-Documentation.md`
- RIPEMD family utilities (`RIPEMDUtil`) with support for:
  - RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 algorithms
  - File processing variants for all algorithms
  - Custom input/output encoding support (HEX, Base64, UTF-8, etc.)
  - HMAC-RIPEMD128/160/256/320 with encoding flexibility
  - Comprehensive JavaDoc comments for all public methods
- In-depth RIPEMD technical documentation under `docs/RIPEMD-Technical-Documentation.md`
- BLAKE family utilities (`BLAKEUtil`) with support for:
  - BLAKE2b-256, BLAKE2b-512, BLAKE2s-128, BLAKE2s-256 algorithms
  - File processing variants for all algorithms
  - Custom input/output encoding support (HEX, Base64, UTF-8, etc.)
  - Comprehensive JavaDoc comments for all public methods
  - Note: BLAKE3 and HMAC variants not available in BouncyCastle
- In-depth BLAKE technical documentation under `docs/BLAKE-Technical-Documentation.md`
- AES encryption utilities (`AESUtil`) with support for:
  - AES-128/192/256 key sizes
  - Multiple modes of operation (ECB, CBC, CFB, OFB, CTR, GCM)
  - Various padding schemes (NoPadding, PKCS5, PKCS7)
  - File encryption/decryption capabilities
  - Password-based key derivation (PBKDF2)
  - Custom input/output encoding support
  - Comprehensive JavaDoc comments for all public methods
- In-depth AES technical documentation under `docs/AES-Technical-Documentation.md`
- DES and Triple DES encryption utilities (`DESUtil`) with support for:
  - DES (56-bit key) and Triple DES (168-bit key) algorithms
  - Multiple modes of operation (ECB, CBC, CFB, OFB)
  - Various padding schemes (NoPadding, PKCS5, PKCS7)
  - File encryption/decryption capabilities
  - Password-based key derivation (PBKDF2)
  - Custom input/output encoding support
  - Comprehensive JavaDoc comments for all public methods
- RC4 stream cipher utilities (`RC4Util`) with support for:
  - Variable key sizes (40-256 bits)
  - File encryption/decryption capabilities
  - Password-based key generation (PBKDF2)
  - Custom input/output encoding support
  - Comprehensive JavaDoc comments for all public methods
- In-depth technical documentation for DES, Triple DES, and RC4 under `docs/DES-TripleDES-RC4-Technical-Documentation.md`
- Security warnings and deprecation notices for legacy algorithms
- ECDSA (Elliptic Curve Digital Signature Algorithm) utilities with support for:
  - Multiple elliptic curves (secp256r1, secp384r1, secp521r1, secp256k1)
  - Signature generation and verification for data and files
  - Custom input/output encodings (HEX, Base64, Base64-URL)
  - Multiple hash algorithms (SHA-256, SHA-384, SHA-512)
  - Comprehensive JavaDoc documentation for all public methods
- In-depth technical documentation for ECDSA under `docs/ECDSA-Technical-Documentation.md`
- RSA (Rivest-Shamir-Adleman) utilities with support for:
  - Multiple key sizes (2048, 3072, 4096 bits)
  - Encryption/decryption and digital signatures
  - Multiple padding schemes (PKCS1, OAEP-SHA1, OAEP-SHA256)
  - Multiple hash algorithms (SHA-1, SHA-256, SHA-384, SHA-512)
  - Key import/export in Base64 format
  - File operations and custom input/output encodings
  - Comprehensive JavaDoc documentation for all public methods
- In-depth technical documentation for RSA under `docs/RSA-Technical-Documentation.md`
- Initial project structure
- Maven configuration
- Comprehensive CRC (Cyclic Redundancy Check) implementation
  - Support for CRC widths 1-64 bits
  - Table-driven and bitwise computation methods
  - File streaming support with configurable buffers
  - Thread-safe static methods
- CRC algorithm presets for common standards:
  - CRC-7/MMC, CRC-8/SMBUS, CRC-10/ATM
  - CRC-11/FLEXRAY, CRC-15/CAN, CRC-16/ARC
  - CRC-24/OPENPGP, CRC-32/ISO-HDLC, CRC-64/ECMA-182
- Input/Output encoding support:
  - Input: HEX, Base64, Base64-URL, UTF-8, UTF-16LE, UTF-16BE, ISO-8859-1, Windows-1252
  - Output: HEX (lower/upper), Base64, Base64-URL
- High-level CRC utility APIs with multiple input types (byte[], String, File)
- Comprehensive JavaDoc documentation for all classes and methods
- Unit tests with standard CRC test vectors

### Changed

- Refactored CRC engine to reduce cognitive complexity
- Extracted processing methods for better maintainability

### Technical Details

- Maven dependencies: JUnit 5, Apache Commons Codec
- Java 8+ compatibility
- Optimized for large data processing
- Proper error handling with custom CryptoException
