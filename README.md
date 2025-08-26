# Crypto Utils

A comprehensive Java utility library for cryptography, hashing, encoding, and data processing.

[![Java](https://img.shields.io/badge/Java-8+-blue.svg)](https://openjdk.java.net/)
[![Maven](https://img.shields.io/badge/Maven-3.6+-green.svg)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/haiphamcoder/crypto-utils)

## 🚀 Features

### **CRC (Cyclic Redundancy Check) Engine**

- **Multi-width Support**: CRC algorithms from 1 to 64 bits
- **Algorithm Presets**: 9 standard CRC implementations
- **Processing Methods**: Table-driven and bitwise computation
- **File Support**: Streaming file processing with configurable buffers
- **Thread Safety**: All methods are static and thread-safe

#### Documentation

- See in-depth CRC overview in [docs/CRC-Technical-Documentation.md](docs/CRC-Technical-Documentation.md)
- See in-depth MD overview in [docs/MD-Technical-Documentation.md](docs/MD-Technical-Documentation.md)
- See in-depth SHA and HMAC overview in [docs/SHA-and-HMAC-Technical-Documentation.md](docs/SHA-and-HMAC-Technical-Documentation.md)
- See in-depth Keccak overview in [docs/Keccak-Technical-Documentation.md](docs/Keccak-Technical-Documentation.md)
- See in-depth RIPEMD overview in [docs/RIPEMD-Technical-Documentation.md](docs/RIPEMD-Technical-Documentation.md)
- See in-depth BLAKE overview in [docs/BLAKE-Technical-Documentation.md](docs/BLAKE-Technical-Documentation.md)
- See in-depth AES overview in [docs/AES-Technical-Documentation.md](docs/AES-Technical-Documentation.md)
- See in-depth DES, Triple DES, and RC4 overview in [docs/DES-TripleDES-RC4-Technical-Documentation.md](docs/DES-TripleDES-RC4-Technical-Documentation.md)
- See in-depth ECDSA overview in [docs/ECDSA-Technical-Documentation.md](docs/ECDSA-Technical-Documentation.md)
- See in-depth RSA overview in [docs/RSA-Technical-Documentation.md](docs/RSA-Technical-Documentation.md)

### **MD Family Hash Functions**

- **MD2, MD4, MD5**: Standard message digest algorithms
- **File Processing**: Support for computing hashes of files
- **Encoding Flexibility**: Custom input/output encodings (HEX, Base64, UTF-8, etc.)
- **HMAC Support**: HMAC-MD5 for message authentication
- **BouncyCastle Integration**: MD4 support via BouncyCastle provider

### **SHA Family Hash Functions**

- **SHA-1, SHA-256, SHA-384, SHA-512**: Secure hash algorithms
- **File Processing**: Support for computing hashes of files
- **Encoding Flexibility**: Custom input/output encodings (HEX, Base64, UTF-8, etc.)
- **HMAC Support**: HMAC-SHA1/256/384/512 for message authentication
- **Industry Standard**: Widely used in TLS/SSL, digital signatures, and security protocols

### **Keccak Family Hash Functions**

- **Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512**: SHA-3 standard algorithms
- **File Processing**: Support for computing hashes of files
- **Encoding Flexibility**: Custom input/output encodings (HEX, Base64, UTF-8, etc.)
- **Sponge Construction**: Based on sponge function paradigm (different from Merkle-Damgård)
- **Cryptocurrency Support**: Used in Ethereum and other blockchain applications

### **RIPEMD Family Hash Functions**

- **RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320**: European standard hash algorithms
- **File Processing**: Support for computing hashes of files
- **Encoding Flexibility**: Custom input/output encodings (HEX, Base64, UTF-8, etc.)
- **Dual-Path Design**: Parallel processing paths for enhanced security
- **HMAC Support**: HMAC-RIPEMD128/160/256/320 for message authentication
- **Cryptocurrency Support**: Used in Bitcoin address generation

### **BLAKE Family Hash Functions**

- **BLAKE2b-256, BLAKE2b-512, BLAKE2s-128, BLAKE2s-256**: High-performance hash algorithms
- **File Processing**: Support for computing hashes of files
- **Encoding Flexibility**: Custom input/output encodings (HEX, Base64, UTF-8, etc.)
- **ChaCha-Based Design**: Based on ChaCha stream cipher for security and speed
- **Performance Optimized**: Faster than SHA-2/SHA-3 family
- **Cryptocurrency Support**: Used in Monero, Decred, and other altcoins

### **AES Encryption**

- **AES-128/192/256**: Advanced Encryption Standard with multiple key sizes
- **Multiple Modes**: ECB, CBC, CFB, OFB, CTR, GCM for different use cases
- **Padding Schemes**: NoPadding, PKCS5, PKCS7 for data formatting
- **File Encryption**: Support for encrypting/decrypting files
- **Key Derivation**: PBKDF2 password-based key generation
- **Encoding Support**: HEX, Base64, UTF-8 input/output formats

### **Input/Output Encoding**

- **Input Formats**: HEX, Base64, Base64-URL, UTF-8, UTF-16, ISO-8859-1, Windows-1252
- **Output Formats**: HEX (lowercase/uppercase), Base64, Base64-URL
- **Automatic Conversion**: Seamless encoding/decoding for CRC operations

### **CRC Algorithm Standards**

| Algorithm | Width | Use Case | Polynomial |
|-----------|-------|----------|------------|
| CRC-7/MMC | 7 | MultiMediaCard | 0x09 |
| CRC-8/SMBUS | 8 | System Management Bus | 0x07 |
| CRC-10/ATM | 10 | Asynchronous Transfer Mode | 0x233 |
| CRC-11/FLEXRAY | 11 | FlexRay Automotive | 0x385 |
| CRC-15/CAN | 15 | Controller Area Network | 0x4599 |
| CRC-16/ARC | 16 | ARCnet, Ethernet, many protocols | 0xA001 |
| CRC-24/OPENPGP | 24 | OpenPGP Message Format | 0x864CFB |
| CRC-32/ISO-HDLC | 32 | HDLC, Ethernet, ZIP, PNG | 0xEDB88320 |
| CRC-64/ECMA-182 | 64 | ECMA-182 Standard | 0x42F0E1EBA9EA3693 |

## 📖 Quick Start

### **Maven Dependency**

```xml
<dependency>
    <groupId>io.github.haiphamcoder</groupId>
    <artifactId>crypto-utils</artifactId>
    <version>0.0.4</version>
</dependency>
```

### **Basic CRC Usage**

```java
import io.github.haiphamcoder.crypto.hash.crc.CRCUtil;

// Simple CRC computation
long crc16 = CRCUtil.crc16("Hello World"); // short alias

// CRC with custom encoding (short alias)
String hexOut = CRCUtil.crc16("313233343536373839", 
    InputEncoding.HEX, OutputEncoding.HEX_LOWER);

// File CRC computation (short alias)
long fileCrc = CRCUtil.crc32(new File("data.txt"));
```

### **MD Family Usage**

```java
import io.github.haiphamcoder.crypto.hash.md.MDUtil;

// Basic MD5 computation
byte[] md5Hash = MDUtil.md5("Hello World");
String md5Hex = MDUtil.md5Hex("Hello World");

// MD5 with custom encoding
String base64Hash = MDUtil.md5("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// File MD5
String fileMd5 = MDUtil.md5Hex(new File("data.txt"));

// HMAC-MD5
byte[] hmac = MDUtil.hmacMd5("Hello World", "secret");
String hmacHex = MDUtil.hmacMd5("Hello World", "secret", 
    InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
```

### **SHA Family Usage**

```java
import io.github.haiphamcoder.crypto.hash.sha.SHAUtil;

// Basic SHA-256 computation
byte[] sha256Hash = SHAUtil.sha256("Hello World");
String sha256Hex = SHAUtil.sha256Hex("Hello World");

// SHA-256 with custom encoding
String base64Hash = SHAUtil.sha256("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// File SHA-256
String fileSha256 = SHAUtil.sha256Hex(new File("data.txt"));

// HMAC-SHA256
byte[] hmac = SHAUtil.hmacSha256("Hello World", "secret");
String hmacHex = SHAUtil.hmacSha256("Hello World", "secret", 
    InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
```

### **Keccak Family Usage**

```java
import io.github.haiphamcoder.crypto.hash.keccak.KeccakUtil;

// Basic Keccak-256 computation
byte[] keccak256Hash = KeccakUtil.keccak256("Hello World");
String keccak256Hex = KeccakUtil.keccak256Hex("Hello World");

// Keccak-256 with custom encoding
String base64Hash = KeccakUtil.keccak256("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// File Keccak-256
String fileKeccak256 = KeccakUtil.keccak256Hex(new File("data.txt"));

// Other Keccak variants
String keccak384 = KeccakUtil.keccak384Hex("Hello World");
String keccak512 = KeccakUtil.keccak512Hex("Hello World");
```

### **RIPEMD Family Usage**

```java
import io.github.haiphamcoder.crypto.hash.ripemd.RIPEMDUtil;

// Basic RIPEMD-160 computation
byte[] ripemd160Hash = RIPEMDUtil.ripemd160("Hello World");
String ripemd160Hex = RIPEMDUtil.ripemd160Hex("Hello World");

// RIPEMD-160 with custom encoding
String base64Hash = RIPEMDUtil.ripemd160("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// File RIPEMD-160
String fileRipemd160 = RIPEMDUtil.ripemd160Hex(new File("data.txt"));

// HMAC-RIPEMD160
byte[] hmac = RIPEMDUtil.hmacRipemd160("Hello World", "secret");
String hmacHex = RIPEMDUtil.hmacRipemd160("Hello World", "secret", 
    InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);

// Other RIPEMD variants
String ripemd256 = RIPEMDUtil.ripemd256Hex("Hello World");
String ripemd320 = RIPEMDUtil.ripemd320Hex("Hello World");
```

### **BLAKE Family Usage**

```java
import com.haiphamcoder.crypto.hash.blake.BLAKEUtil;

// Basic BLAKE2b-256 computation
byte[] blake2b256Hash = BLAKEUtil.blake2b256("Hello World");
String blake2b256Hex = BLAKEUtil.blake2b256Hex("Hello World");

// BLAKE2b-256 with custom encoding
String base64Hash = BLAKEUtil.blake2b256("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);

// File BLAKE2b-256
String fileBlake2b256 = BLAKEUtil.blake2b256Hex(new File("data.txt"));

// Other BLAKE variants
String blake2b512 = BLAKEUtil.blake2b512Hex("Hello World");
String blake2s128 = BLAKEUtil.blake2s128Hex("Hello World");
String blake2s256 = BLAKEUtil.blake2s256Hex("Hello World");
```

### **AES Encryption Usage**

```java
import com.haiphamcoder.crypto.encryption.AESUtil;
import javax.crypto.SecretKey;

// Generate AES keys
SecretKey key = AESUtil.generateKey(); // 256-bit by default
SecretKey key128 = AESUtil.generateKey(AESUtil.KEY_SIZE_128);

// Basic encryption/decryption
byte[] encrypted = AESUtil.encrypt("Hello World", key);
String decrypted = AESUtil.decryptString(encrypted, key);

// Custom mode and padding
byte[] encrypted = AESUtil.encrypt("Hello World", key, 
    AESUtil.MODE_GCM, AESUtil.PADDING_NONE);

// File encryption
AESUtil.encryptFile(inputFile, encryptedFile, key);
AESUtil.decryptFile(encryptedFile, decryptedFile, key);

// Password-based key generation
String password = "mySecretPassword";
byte[] salt = "randomSalt123".getBytes(StandardCharsets.UTF_8);
SecretKey keyFromPassword = AESUtil.generateKeyFromPassword(password, salt);

// Encoding support
String base64Encrypted = AESUtil.encryptToBase64("Hello World", key);
String decrypted = AESUtil.decryptFromBase64(base64Encrypted, key);
```

### **DES and Triple DES Encryption Usage**

**⚠️ Security Warning: These algorithms are deprecated and should not be used for new applications.**

```java
import com.haiphamcoder.crypto.encryption.DESUtil;
import javax.crypto.SecretKey;

// Generate keys
SecretKey desKey = DESUtil.generateDESKey();
SecretKey tripleDesKey = DESUtil.generateTripleDESKey();

// Basic encryption/decryption
byte[] encrypted = DESUtil.encryptDES("Hello World", desKey);
String decrypted = DESUtil.decryptDESString(encrypted, desKey);

// Triple DES
byte[] encrypted = DESUtil.encryptTripleDES("Hello World", tripleDesKey);
String decrypted = DESUtil.decryptTripleDESString(encrypted, tripleDesKey);

// Custom mode and padding
byte[] encrypted = DESUtil.encryptDES("Hello World", desKey,
    DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);

// File operations
DESUtil.encryptDESFile(inputFile, encryptedFile, desKey,
    DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
```

### **RC4 Stream Cipher Usage**

**⚠️ Security Warning: RC4 is deprecated due to severe vulnerabilities and should not be used for new applications.**

```java
import com.haiphamcoder.crypto.encryption.RC4Util;
import javax.crypto.SecretKey;

// Generate key
SecretKey key = RC4Util.generateKey(256);

// Basic encryption/decryption
byte[] encrypted = RC4Util.encrypt("Hello World", key);
String decrypted = RC4Util.decryptString(encrypted, key);

// File operations
RC4Util.encryptFile(inputFile, encryptedFile, key);
RC4Util.decryptFile(encryptedFile, decryptedFile, key);

// Encoding support
String base64Encrypted = RC4Util.encryptToBase64("Hello World", key);
String decrypted = RC4Util.decryptFromBase64(base64Encrypted, key);
```

### **ECDSA Digital Signatures**

**Features:**

- Support for multiple elliptic curves (secp256r1, secp384r1, secp521r1, secp256k1)
- Signature generation and verification for data and files
- Multiple hash algorithms (SHA-256, SHA-384, SHA-512)
- Custom input/output encodings (HEX, Base64, Base64-URL)

**Usage Examples:**

```java
import com.haiphamcoder.crypto.signature.ECDSAUtil;
import java.security.KeyPair;

// Generate key pair
KeyPair keyPair = ECDSAUtil.generateKeyPair(); // Default: secp256r1
KeyPair keyPair384 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP384R1);
KeyPair keyPair521 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP521R1);

// Basic signing and verification
byte[] signature = ECDSAUtil.sign("Hello World", keyPair.getPrivate());
boolean isValid = ECDSAUtil.verify("Hello World", signature, keyPair.getPublic());

// File signing and verification
byte[] fileSignature = ECDSAUtil.signFile(inputFile, keyPair.getPrivate());
boolean isValid = ECDSAUtil.verifyFile(inputFile, fileSignature, keyPair.getPublic());

// Different hash algorithms
byte[] sig256 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA256_ECDSA);
byte[] sig384 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA384_ECDSA);
byte[] sig512 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA512_ECDSA);

// Encoding support
String base64Sig = ECDSAUtil.signToBase64("Hello World", privateKey);
String hexSig = ECDSAUtil.signToHex("Hello World", privateKey);

// Verify encoded signatures
boolean isValid = ECDSAUtil.verifyFromBase64("Hello World", base64Sig, publicKey);
boolean isValid = ECDSAUtil.verifyFromHex("Hello World", hexSig, publicKey);
```

### **RSA Encryption and Digital Signatures**

**Features:**

- Support for multiple key sizes (2048, 3072, 4096 bits)
- Encryption/decryption and digital signatures
- Strongly-typed padding enum: `RSAPadding.PKCS1`, `RSAPadding.OAEP_SHA1`, `RSAPadding.OAEP_SHA256`
- Auto-chunking for large inputs built into byte[] APIs
- Key import/export in Base64 format
- File operations with enum padding

**Usage Examples:**

```java
import io.github.haiphamcoder.crypto.signature.RSAUtil;
import io.github.haiphamcoder.crypto.signature.RSAUtil.RSAPadding;
import java.security.KeyPair;

// Generate key pair
KeyPair keyPair = RSAUtil.generateKeyPair(); // Default: 2048 bits

// Encrypt/decrypt (byte[] APIs) with auto-chunking when needed (PKCS1)
byte[] plaintext = "This is a very long plaintext ...".getBytes(java.nio.charset.StandardCharsets.UTF_8);
byte[] ciphertext = RSAUtil.encrypt(plaintext, keyPair.getPublic(), RSAPadding.PKCS1);
byte[] decrypted = RSAUtil.decrypt(ciphertext, keyPair.getPrivate(), RSAPadding.PKCS1);
String recovered = new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);

// OAEP-SHA256 variant
byte[] ct2 = RSAUtil.encrypt("Hello OAEP".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                             keyPair.getPublic(), RSAPadding.OAEP_SHA256);
byte[] pt2 = RSAUtil.decrypt(ct2, keyPair.getPrivate(), RSAPadding.OAEP_SHA256);

// Default padding (PKCS1) overloads
byte[] ctDefault = RSAUtil.encrypt(plaintext, keyPair.getPublic());
byte[] ptDefault = RSAUtil.decrypt(ctDefault, keyPair.getPrivate());

// File operations (enum padding)
byte[] encFile = RSAUtil.encryptFile(inputFile, keyPair.getPublic(), RSAPadding.PKCS1);
byte[] decFile = RSAUtil.decryptFile(encFile, keyPair.getPrivate(), RSAPadding.PKCS1);

// Digital signatures
byte[] signature = RSAUtil.sign("Hello World", keyPair.getPrivate());
boolean isValid = RSAUtil.verify("Hello World", signature, keyPair.getPublic());
```

### **Text Case Conversion Utilities**

**Features:**

- Support for 12 case conversion formats
- Unicode-aware word splitting with number separation
- Case format detection and validation
- Conversion between different case formats
- Comprehensive JavaDoc documentation

**Usage Examples:**

```java
import io.github.haiphamcoder.crypto.text.TextCaseUtil;
import io.github.haiphamcoder.crypto.text.TextCaseUtil.CaseFormat;

// Basic case conversions
String snakeCase = TextCaseUtil.toSnakeCase("helloWorldExample");
String kebabCase = TextCaseUtil.toKebabCase("Hello World Example");
String camelCase = TextCaseUtil.toCamelCase("hello_world_example");
String pascalCase = TextCaseUtil.toPascalCase("hello world example");

// Advanced conversions
String constantCase = TextCaseUtil.toConstantCase("hello world example");
String dotCase = TextCaseUtil.toDotCase("HelloWorldExample");
String titleCase = TextCaseUtil.toTitleCase("hello world example");
String trainCase = TextCaseUtil.toTrainCase("hello world example");

// Case detection
CaseFormat detected = TextCaseUtil.detectCase("helloWorld");
boolean isCamelCase = TextCaseUtil.isCase("helloWorld", CaseFormat.CAMEL_CASE);

// Convert between formats
String converted = TextCaseUtil.convertCase("hello_world", 
    CaseFormat.SNAKE_CASE, CaseFormat.CAMEL_CASE);
```

### **Advanced Usage**

```java
import com.haiphamcoder.crypto.hash.crc.CRC;
import com.haiphamcoder.crypto.hash.crc.CRCParameters;

// Custom CRC parameters
CRCParameters params = new CRCParameters(
    16,           // 16-bit CRC
    0x8005L,      // polynomial
    0x0000L,      // initial value
    0x0000L,      // XOR output
    false,        // reflect input
    false         // reflect output
);

long crc = CRC.compute("Custom data".getBytes(), params);
```

## 🛠️ Installation & Build

### **Prerequisites**

- Java 8 or higher
- Maven 3.6 or higher

### **Build Commands**

```bash
# Compile and test
mvn clean test

# Build JAR
mvn clean package

# Generate Javadoc
mvn javadoc:javadoc
```

## 📚 API Documentation

### **Core Classes**

- **`CRC`**: Low-level CRC computation engine
- **`CRCParameters`**: CRC algorithm configuration
- **`CRCPresets`**: Predefined CRC standards
- **`CRCUtil`**: High-level utility methods
- **`MDUtil`**: MD family hash utilities (MD2, MD4, MD5, HMAC)
- **`SHAUtil`**: SHA family hash utilities (SHA-1, SHA-256, SHA-384, SHA-512, HMAC)
- **`EncodingUtil`**: Input/output encoding utilities
- **`KeccakUtil`**: Keccak family hash utilities (Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512)
- **`RIPEMDUtil`**: RIPEMD family hash utilities (RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320)
- **`BLAKEUtil`**: BLAKE family hash utilities (BLAKE2b-256, BLAKE2b-512, BLAKE2s-128, BLAKE2s-256)
- **`AESUtil`**: AES encryption utilities (AES-128/192/256, ECB, CBC, CFB, OFB, CTR, GCM)
- **`DESUtil`**: DES and Triple DES encryption utilities (ECB, CBC, CFB, OFB modes)
- **`RC4Util`**: RC4 stream cipher utilities (variable key sizes)
- **`ECDSAUtil`**: ECDSA digital signature utilities (multiple curves, SHA variants)
- **`RSAUtil`**: RSA encryption and digital signature utilities (multiple key sizes, padding schemes)
- **`TextCaseUtil`**: Text case conversion utilities (12 formats, unicode-aware splitting, improved word boundary detection, camelCase/PascalCase preservation)

### **Encoding Support**

- **`InputEncoding`**: Supported input formats
- **`OutputEncoding`**: Available output formats

## 🧪 Testing

The library includes comprehensive unit tests with standard CRC test vectors:

```bash
mvn test
```

All tests use the standard "123456789" test vector for validation.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`mvn test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- 📝 Create an issue on GitHub
- 📚 Check the documentation and examples
- 🧪 Review the test cases for usage patterns
- 💬 Join discussions in GitHub Issues

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes and versions.

## 🎯 Roadmap

### **Phase 1: Hash Functions** ✅

- [x] CRC algorithms (1-64 bits)
- [x] Input/Output encoding support
- [x] File processing capabilities

### **Phase 2: Cryptographic Functions** ✅

- [x] MD family (MD-2, MD-4, MD-5) with HMAC support
- [x] SHA family (SHA-1, SHA-2, SHA-3) with HMAC support
- [x] Keccak family (Keccak-224, Keccak-256, Keccak-288, Keccak-384, Keccak-512)
- [x] RIPEMD family (RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320)
- [x] BLAKE family (BLAKE2b-256, BLAKE2b-512, BLAKE2s-128, BLAKE2s-256)
- [x] AES encryption (AES-128/192/256, ECB, CBC, CFB, OFB, CTR, GCM)

### **Phase 3: Encryption & Signatures** 📋

- [x] DES, Triple DES, RC4 (Legacy algorithms with security warnings)
- [x] ECDSA (multiple curves)
- [x] RSA operations

### **Phase 4: Data Processing** 📋

- [ ] JSON/XML validation and formatting
- [x] Text case conversion utilities
- [ ] Character encoding support
- [ ] File processing utilities

## ⭐ Star History

If you find this library useful, please consider giving it a star on GitHub!

---

**Built with ❤️ by [haiphamcoder](https://github.com/haiphamcoder)**
