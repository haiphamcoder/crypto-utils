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
    <groupId>com.haiphamcoder</groupId>
    <artifactId>crypto-utils</artifactId>
    <version>1.0.0</version>
</dependency>
```

### **Basic CRC Usage**

```java
import com.haiphamcoder.crypto.hash.crc.CRCUtil;

// Simple CRC computation
long crc16 = CRCUtil.crc16("Hello World"); // short alias

// CRC with custom encoding (short alias)
String hexOut = CRCUtil.crc16("313233343536373839", 
    InputEncoding.HEX, OutputEncoding.HEX_LOWER);

// File CRC computation (short alias)
long fileCrc = CRCUtil.crc32(new File("data.txt"));
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
- **`EncodingUtil`**: Input/output encoding utilities

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

### **Phase 2: Cryptographic Functions** 🚧

- [ ] SHA family (SHA-1, SHA-2, SHA-3)
- [ ] MD family (MD-2, MD-4, MD-5)
- [ ] Keccak, SHAKE, cSHAKE, KMAC
- [ ] RIPEMD family
- [ ] BLAKE family

### **Phase 3: Encryption & Signatures** 📋

- [ ] AES (128/192/256-bit, all modes)
- [ ] DES, Triple DES, RC4
- [ ] ECDSA (multiple curves)
- [ ] RSA operations

### **Phase 4: Data Processing** 📋

- [ ] JSON/XML validation and formatting
- [ ] Text case conversion utilities
- [ ] Character encoding support
- [ ] File processing utilities

## ⭐ Star History

If you find this library useful, please consider giving it a star on GitHub!

---

**Built with ❤️ by [haiphamcoder](https://github.com/haiphamcoder)**
