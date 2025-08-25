# Technical Documentation: AES (Advanced Encryption Standard)

## 1) Introduction to AES

AES (Advanced Encryption Standard) is a symmetric block cipher that was established by the U.S. National Institute of Standards and Technology (NIST) in 2001. It is the successor to the Data Encryption Standard (DES) and has become the most widely used encryption algorithm worldwide.

- **Purpose**: Provide secure, efficient symmetric encryption for data protection
- **Development**: Selected through an open competition from 15 candidate algorithms
- **Design Philosophy**: Based on the Rijndael cipher, designed by Joan Daemen and Vincent Rijmen
- **Standards**: FIPS 197 (Federal Information Processing Standards)
- **Security Level**: Currently considered cryptographically secure

---

## 2) Algorithm Design and Structure

### **Mathematical Foundation**

AES is based on mathematical principles from finite field theory (Galois Field GF(2^8)):

- **Field Operations**: Addition and multiplication in GF(2^8)
- **Polynomial Arithmetic**: Operations on polynomials with coefficients in GF(2)
- **Linear Algebra**: Matrix operations for diffusion

### **Block Structure**

- **Block Size**: 128 bits (16 bytes) - fixed
- **Key Sizes**: 128, 192, or 256 bits (16, 24, or 32 bytes)
- **State Representation**: 4×4 matrix of bytes (for 128-bit block)
- **Round Structure**: Variable number of rounds based on key size

### **Key Schedule**

| Key Size | Rounds | Key Schedule |
|----------|--------|--------------|
| 128 bits | 10     | 11 round keys |
| 192 bits | 12     | 13 round keys |
| 256 bits | 14     | 15 round keys |

---

## 3) AES Round Function

### **Round Components**

Each AES round (except the last) consists of four transformations:

1. **SubBytes**: Non-linear substitution using S-boxes
2. **ShiftRows**: Cyclic shifting of rows
3. **MixColumns**: Linear transformation of columns
4. **AddRoundKey**: XOR with round key

### **SubBytes Transformation**

- **S-box**: 16×16 lookup table for byte substitution
- **Non-linearity**: Provides resistance to linear cryptanalysis
- **Mathematical Basis**: Multiplicative inverse in GF(2^8) followed by affine transformation

### **ShiftRows Transformation**

- **Row 0**: No shift (0 positions)
- **Row 1**: Left shift by 1 position
- **Row 2**: Left shift by 2 positions
- **Row 3**: Left shift by 3 positions

### **MixColumns Transformation**

- **Matrix Multiplication**: Each column is multiplied by a fixed polynomial
- **Diffusion**: Ensures that changes in one byte affect multiple bytes
- **Mathematical Operation**: Polynomial multiplication in GF(2^8)

### **AddRoundKey Transformation**

- **XOR Operation**: State bytes are XORed with round key bytes
- **Key Addition**: Each round uses a different key derived from the original key
- **Security**: Provides confusion and prevents pattern analysis

---

## 4) Modes of Operation

### **Electronic Codebook (ECB)**

**Characteristics:**

- **Pattern**: Same plaintext always produces same ciphertext
- **Parallelization**: Can process multiple blocks simultaneously
- **Security**: Weak - does not hide patterns in plaintext
- **Use Cases**: Not recommended for secure applications

**Security Issues:**

- **Pattern Leakage**: Plaintext patterns visible in ciphertext
- **Deterministic**: No randomness in encryption process
- **Vulnerability**: Susceptible to frequency analysis

### **Cipher Block Chaining (CBC)**

**Characteristics:**

- **Pattern**: Each ciphertext block depends on previous plaintext block
- **IV Requirement**: Requires initialization vector (IV)
- **Security**: Good - hides patterns in plaintext
- **Use Cases**: General purpose encryption, file encryption

**Operation:**

1. **First Block**: Plaintext XORed with IV, then encrypted
2. **Subsequent Blocks**: Plaintext XORed with previous ciphertext, then encrypted
3. **Decryption**: Reverse process using same IV

### **Cipher Feedback (CFB)**

**Characteristics:**

- **Pattern**: Converts block cipher to stream cipher
- **IV Requirement**: Requires initialization vector
- **Security**: Good - provides confidentiality
- **Use Cases**: Real-time encryption, streaming data

**Operation:**

1. **Encryption**: IV encrypted, result XORed with plaintext
2. **Feedback**: Ciphertext becomes input for next block
3. **Decryption**: Same process as encryption

### **Output Feedback (OFB)**

**Characteristics:**

- **Pattern**: Generates keystream independent of plaintext
- **IV Requirement**: Requires initialization vector
- **Security**: Good - provides confidentiality
- **Use Cases**: Real-time encryption, error-tolerant applications

**Operation:**

1. **Keystream Generation**: IV encrypted repeatedly to generate keystream
2. **Encryption**: Plaintext XORed with keystream
3. **Decryption**: Same process as encryption

### **Counter (CTR)**

**Characteristics:**

- **Pattern**: Generates keystream using counter values
- **IV Requirement**: Requires nonce (number used once)
- **Security**: Good - provides confidentiality and authenticity
- **Use Cases**: High-performance encryption, parallel processing

**Operation:**

1. **Counter**: Nonce + counter value encrypted
2. **Keystream**: Result used as keystream
3. **Encryption**: Plaintext XORed with keystream

### **Galois/Counter Mode (GCM)**

**Characteristics:**

- **Pattern**: Provides both confidentiality and authenticity
- **IV Requirement**: Requires 12-byte nonce
- **Security**: Excellent - authenticated encryption
- **Use Cases**: Secure communications, TLS, disk encryption

**Operation:**

1. **Encryption**: CTR mode encryption
2. **Authentication**: GHASH function for message authentication
3. **Tag**: Authentication tag appended to ciphertext

---

## 5) Padding Schemes

### **No Padding**

**Characteristics:**

- **Requirement**: Data must be multiple of block size (16 bytes)
- **Use Cases**: When data size is guaranteed to be correct
- **Security**: No additional security properties

### **PKCS#5 Padding**

**Characteristics:**

- **Format**: Adds 1-16 bytes, each byte contains padding length
- **Example**: If 3 bytes needed, adds 0x03 0x03 0x03
- **Use Cases**: General purpose encryption
- **Security**: Standard padding scheme

### **PKCS#7 Padding**

**Characteristics:**

- **Format**: Similar to PKCS#5 but works with any block size
- **Use Cases**: General purpose encryption
- **Security**: Standard padding scheme

---

## 6) Key Generation and Management

### **Random Key Generation**

**SecureRandom Usage:**

- **Source**: Cryptographically secure random number generator
- **Entropy**: High-quality entropy sources
- **Implementation**: Java's SecureRandom with proper seeding

### **Password-Based Key Derivation**

**PBKDF2 Algorithm:**

- **Purpose**: Derive cryptographic keys from passwords
- **Salt**: Random value to prevent rainbow table attacks
- **Iterations**: High iteration count to slow down attacks
- **Hash Function**: HMAC-SHA256 for key derivation

**Parameters:**

- **Salt Length**: 16-32 bytes recommended
- **Iterations**: 100,000+ recommended for security
- **Key Length**: 128, 192, or 256 bits

---

## 7) Security Analysis

### **Cryptographic Strength**

**Key Size Security:**

- **128 bits**: 2^128 operations required for brute force
- **192 bits**: 2^192 operations required for brute force
- **256 bits**: 2^256 operations required for brute force

**Current Status:**

- **128 bits**: Secure until 2030+ (NIST recommendation)
- **192 bits**: Secure until 2040+
- **256 bits**: Secure until 2050+

### **Known Attacks**

**Theoretical Attacks:**

- **Biclique Attack**: Reduces complexity slightly but not practically
- **Related-Key Attacks**: Some theoretical weaknesses in key schedule
- **Side-Channel Attacks**: Power analysis, timing attacks

**Practical Considerations:**

- **No Practical Attacks**: No successful attacks against full AES
- **Implementation Security**: Security depends on proper implementation
- **Key Management**: Weakest link is often key management

### **Security Best Practices**

**Key Management:**

- **Random Generation**: Use cryptographically secure random generators
- **Key Storage**: Secure storage of encryption keys
- **Key Rotation**: Regular key rotation for long-term security

**Mode Selection:**

- **Avoid ECB**: Never use ECB mode for secure applications
- **Use GCM**: Prefer GCM mode for authenticated encryption
- **Proper IVs**: Use random, unique IVs for each encryption

---

## 8) Performance Characteristics

### **Speed Comparison**

| Mode | Relative Speed | Security Level | Use Case |
|------|----------------|----------------|----------|
| ECB | Fastest | Low | Not recommended |
| CBC | Fast | Medium | General purpose |
| CFB | Medium | Medium | Streaming |
| OFB | Medium | Medium | Real-time |
| CTR | Fast | High | High performance |
| GCM | Medium | Highest | Secure communications |

### **Optimization Features**

**Hardware Acceleration:**

- **AES-NI**: Intel/AMD CPU instructions for AES
- **Performance**: 10-100x faster than software implementation
- **Availability**: Modern processors (2010+) support AES-NI

**Software Optimization:**

- **Lookup Tables**: Pre-computed S-box and inverse S-box
- **Bit Operations**: Efficient bit manipulation
- **Memory Access**: Optimized memory access patterns

---

## 9) Implementation Considerations

### **Java Cryptography Architecture (JCA)**

**Provider Support:**

- **Default Provider**: SunJCE provides AES implementation
- **Algorithm Names**: Standard naming conventions
- **Mode Support**: All standard modes supported
- **Padding Support**: Standard padding schemes supported

**Error Handling:**

- **Exception Types**: Specific exceptions for different error conditions
- **Input Validation**: Proper validation of input parameters
- **Resource Management**: Proper cleanup of cryptographic objects

### **Thread Safety**

**Considerations:**

- **Cipher Objects**: Not thread-safe, create new instances per thread
- **Key Objects**: Thread-safe for reading, not for modification
- **Random Generators**: Thread-safe with proper synchronization

### **Memory Management**

**Security Considerations:**

- **Key Storage**: Secure memory for sensitive key material
- **Buffer Clearing**: Clear sensitive data from memory after use
- **Garbage Collection**: Ensure sensitive objects are properly collected

---

## 10) Using this Library (crypto-utils)

### **Class: `AESUtil`**

- **Location**: `com.haiphamcoder.crypto.encryption.AESUtil`
- **Key Sizes**: 128, 192, 256 bits
- **Modes**: ECB, CBC, CFB, OFB, CTR, GCM
- **Padding**: NoPadding, PKCS5Padding, PKCS7Padding
- **Inputs**: `byte[]`, `String`, `File`
- **Encodings**: `InputEncoding` and `OutputEncoding` for flexible I/O formats

### **Basic Usage Examples**

```java
import com.haiphamcoder.crypto.encryption.AESUtil;
import javax.crypto.SecretKey;

// Generate a random AES key
SecretKey key = AESUtil.generateKey(); // 256-bit by default
SecretKey key128 = AESUtil.generateKey(AESUtil.KEY_SIZE_128);

// Basic encryption/decryption
byte[] encrypted = AESUtil.encrypt("Hello World", key);
String decrypted = AESUtil.decryptString(encrypted, key);

// Custom mode and padding
byte[] encrypted = AESUtil.encrypt("Hello World", key, 
    AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
```

### **File Encryption**

```java
// Encrypt file
AESUtil.encryptFile(inputFile, encryptedFile, key);

// Decrypt file
AESUtil.decryptFile(encryptedFile, decryptedFile, key);

// Custom mode
AESUtil.encryptFile(inputFile, encryptedFile, key, 
    AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
```

### **Encoding Support**

```java
// Encrypt to Base64
String base64Encrypted = AESUtil.encryptToBase64("Hello World", key);

// Decrypt from Base64
String decrypted = AESUtil.decryptFromBase64(base64Encrypted, key);

// Custom encoding
String hexEncrypted = AESUtil.encrypt("Hello World", key, 
    AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5,
    InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
```

### **Password-Based Key Generation**

```java
// Generate key from password
String password = "mySecretPassword";
byte[] salt = "randomSalt123".getBytes(StandardCharsets.UTF_8);
SecretKey key = AESUtil.generateKeyFromPassword(password, salt);

// Custom parameters
SecretKey key = AESUtil.generateKeyFromPassword(password, salt, 
    AESUtil.KEY_SIZE_128, 100000);
```

---

## 11) Security Recommendations

### **Mode Selection**

**For General Use:**

- **CBC Mode**: Good balance of security and performance
- **PKCS5 Padding**: Standard padding scheme
- **Random IVs**: Generate unique IV for each encryption

**For High Security:**

- **GCM Mode**: Provides both confidentiality and authenticity
- **256-bit Keys**: Maximum security level
- **Proper IV Management**: Ensure IV uniqueness

### **Key Management**

**Generation:**

- **Random Keys**: Use `generateKey()` for random keys
- **Password Keys**: Use PBKDF2 with high iteration count
- **Key Sizes**: Use 256-bit keys for maximum security

**Storage:**

- **Secure Storage**: Store keys in secure key stores
- **Access Control**: Limit access to encryption keys
- **Key Rotation**: Implement regular key rotation

### **Implementation Security**

**Best Practices:**

- **Avoid ECB**: Never use ECB mode in production
- **Unique IVs**: Ensure IV uniqueness for each encryption
- **Error Handling**: Proper exception handling without information leakage
- **Input Validation**: Validate all input parameters

---

## 12) Future Considerations

### **Cryptographic Status**

**Current Status:**

- **AES-128**: Secure until 2030+ (NIST recommendation)
- **AES-192**: Secure until 2040+
- **AES-256**: Secure until 2050+

**Long-term Considerations:**

- **Quantum Resistance**: AES may be vulnerable to quantum computers
- **Post-Quantum Cryptography**: NIST working on quantum-resistant algorithms
- **Migration Planning**: Consider long-term migration strategies

### **Performance Improvements**

**Hardware Evolution:**

- **AES-NI**: Continued improvement in hardware acceleration
- **Vector Instructions**: Advanced vector extensions for better performance
- **Specialized Hardware**: Dedicated encryption hardware

**Software Optimization:**

- **Algorithm Improvements**: Ongoing research in optimization
- **Parallel Processing**: Better parallelization techniques
- **Memory Optimization**: Improved memory access patterns

---

## 13) References

- **FIPS 197**: Advanced Encryption Standard (AES)
- **NIST Special Publication 800-38A**: Recommendation for Block Cipher Modes of Operation
- **NIST Special Publication 800-38D**: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
- **RFC 3602**: The AES-CBC Cipher Algorithm and Its Use with IPsec
- **Java Cryptography Architecture (JCA)**: Oracle documentation
- **Cryptographic Standards**: NIST cryptographic standards and guidelines
