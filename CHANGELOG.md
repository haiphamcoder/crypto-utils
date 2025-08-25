# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
