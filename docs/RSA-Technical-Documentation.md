# RSA Technical Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [Mathematical Foundations](#mathematical-foundations)
3. [RSA Algorithm](#rsa-algorithm)
4. [Key Generation](#key-generation)
5. [Encryption and Decryption](#encryption-and-decryption)
6. [Digital Signatures](#digital-signatures)
7. [Padding Schemes](#padding-schemes)
8. [Security Analysis](#security-analysis)
9. [Performance Characteristics](#performance-characteristics)
10. [Implementation Considerations](#implementation-considerations)
11. [Usage with crypto-utils Library](#usage-with-crypto-utils-library)
12. [Best Practices and Recommendations](#best-practices-and-recommendations)
13. [References](#references)

---

## Introduction

RSA (Rivest-Shamir-Adleman) is one of the first practical public-key cryptosystems and remains one of the most widely used asymmetric cryptographic algorithms. Named after its creators Ron Rivest, Adi Shamir, and Leonard Adleman, RSA was first published in 1977 and has become a cornerstone of modern cryptography.

### Key Characteristics
- **Asymmetric Cryptography**: Uses different keys for encryption and decryption
- **Mathematical Foundation**: Based on the difficulty of factoring large composite numbers
- **Dual Functionality**: Provides both encryption/decryption and digital signatures
- **Wide Adoption**: Used in SSL/TLS, digital certificates, secure communications, and more

### Applications
- **SSL/TLS**: Secure web communications
- **Digital Signatures**: Document and software authentication
- **Key Exchange**: Secure key distribution
- **Digital Certificates**: Identity verification
- **Secure Email**: PGP and S/MIME implementations

---

## Mathematical Foundations

### Number Theory Concepts

#### Prime Numbers
A prime number is a natural number greater than 1 that has no positive divisors other than 1 and itself. RSA security relies on the difficulty of factoring the product of two large prime numbers.

#### Euler's Totient Function
For a positive integer n, φ(n) is the number of integers k in the range 1 ≤ k ≤ n for which gcd(n, k) = 1.

For RSA, where n = p × q (product of two primes):
```
φ(n) = φ(p × q) = φ(p) × φ(q) = (p-1) × (q-1)
```

#### Fermat's Little Theorem
If p is a prime number and a is any integer not divisible by p, then:
```
a^(p-1) ≡ 1 (mod p)
```

This theorem is fundamental to RSA's mathematical foundation.

### The RSA Problem

The security of RSA is based on the difficulty of the **RSA Problem**:
- **Given**: n (modulus), e (public exponent), and c = m^e mod n (ciphertext)
- **Find**: m (plaintext)

This is equivalent to computing the e-th root modulo n, which is believed to be computationally infeasible without knowing the prime factors of n.

---

## RSA Algorithm

### Key Generation

1. **Choose two distinct prime numbers**: p and q
2. **Compute modulus**: n = p × q
3. **Compute Euler's totient**: φ(n) = (p-1) × (q-1)
4. **Choose public exponent**: e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. **Compute private exponent**: d = e^(-1) mod φ(n)
6. **Public key**: (n, e)
7. **Private key**: (n, d)

### Mathematical Properties

#### Key Relationship
The public and private exponents satisfy:
```
e × d ≡ 1 (mod φ(n))
```

This means:
```
(e × d) mod φ(n) = 1
```

#### Encryption and Decryption
- **Encryption**: c = m^e mod n
- **Decryption**: m = c^d mod n

#### Mathematical Correctness
```
c^d mod n = (m^e)^d mod n = m^(e×d) mod n = m^(k×φ(n)+1) mod n = m × (m^φ(n))^k mod n = m × 1^k mod n = m
```

Where k is some integer such that e × d = k × φ(n) + 1.

---

## Key Generation

### Prime Number Selection

#### Size Requirements
- **Minimum**: 1024 bits (deprecated)
- **Recommended**: 2048 bits
- **High Security**: 3072 bits
- **Maximum Security**: 4096 bits

#### Prime Generation
1. **Random Generation**: Generate random odd numbers of appropriate size
2. **Primality Testing**: Use probabilistic tests (Miller-Rabin) to verify primality
3. **Security Considerations**: Ensure p and q are not too close together

#### Recommended Prime Sizes
| Key Size | Prime Size | Security Level |
|----------|------------|----------------|
| 2048 bits | 1024 bits each | 112 bits |
| 3072 bits | 1536 bits each | 128 bits |
| 4096 bits | 2048 bits each | 192 bits |

### Public Exponent Selection

#### Common Choices
- **e = 3**: Smallest possible, but vulnerable to certain attacks
- **e = 65537 (2^16 + 1)**: Most common choice, good balance of security and performance
- **e = 17**: Small, but more secure than e = 3

#### Requirements
- Must be coprime with φ(n)
- Should be small for efficient encryption
- Must not be too small to avoid attacks

### Private Exponent Computation

The private exponent d is computed using the Extended Euclidean Algorithm:
```
d = e^(-1) mod φ(n)
```

This is the modular multiplicative inverse of e modulo φ(n).

---

## Encryption and Decryption

### Basic Operations

#### Encryption
```
c = m^e mod n
```
Where:
- m is the plaintext message (0 ≤ m < n)
- e is the public exponent
- n is the modulus
- c is the ciphertext

#### Decryption
```
m = c^d mod n
```
Where:
- c is the ciphertext
- d is the private exponent
- n is the modulus
- m is the recovered plaintext

### Message Size Limitations

#### Maximum Message Size
The maximum size of a message that can be encrypted is:
```
max_message_size = log₂(n) bits
```

For a 2048-bit key, this is approximately 256 bytes.

#### Practical Considerations
- **Raw RSA**: Limited by key size
- **Hybrid Systems**: Use RSA for key exchange, symmetric encryption for data
- **Chunking**: Split large messages into smaller blocks

### Performance Characteristics

#### Computational Complexity
- **Encryption**: O(log e) modular exponentiations
- **Decryption**: O(log d) modular exponentiations
- **Key Generation**: O(log n) primality tests

#### Speed Comparison
| Operation | Relative Speed |
|-----------|----------------|
| RSA Encryption | 1x |
| RSA Decryption | 4-8x slower |
| Key Generation | 100-1000x slower |

---

## Digital Signatures

### Signature Generation

#### Process
1. **Hash the message**: h = Hash(m)
2. **Apply padding**: Apply appropriate padding scheme
3. **Sign**: s = (padded_hash)^d mod n
4. **Output**: Signature s

#### Mathematical Foundation
```
s = m^d mod n
```

Where m is the padded hash of the original message.

### Signature Verification

#### Process
1. **Hash the message**: h = Hash(m)
2. **Apply padding**: Apply the same padding scheme
3. **Verify**: Check if s^e mod n equals the padded hash
4. **Output**: True if verification succeeds, false otherwise

#### Mathematical Verification
```
s^e mod n = (m^d)^e mod n = m^(d×e) mod n = m mod n
```

If this equals the padded hash, the signature is valid.

### Hash Function Requirements

#### Security Requirements
- **Collision Resistance**: Hard to find two messages with same hash
- **Pre-image Resistance**: Hard to find message for given hash
- **Second Pre-image Resistance**: Hard to find second message with same hash

#### Recommended Hash Functions
- **SHA-256**: Minimum recommended
- **SHA-384**: High security applications
- **SHA-512**: Maximum security
- **SHA-1**: Deprecated, avoid use

---

## Padding Schemes

### PKCS#1 v1.5 Padding

#### Structure
```
EM = 0x00 || 0x02 || PS || 0x00 || M
```

Where:
- PS is a string of random non-zero bytes
- M is the message
- Total length equals the key size

#### Security Issues
- **Bleichenbacher Attack**: Adaptive chosen ciphertext attack
- **Timing Attacks**: Vulnerable to timing analysis
- **Padding Oracle**: Information leakage through padding validation

#### Usage
- **Encryption**: Still widely used despite known vulnerabilities
- **Signatures**: Generally secure for digital signatures

### OAEP (Optimal Asymmetric Encryption Padding)

#### Structure
```
EM = MGF1(MGF1(seed) ⊕ M) || seed ⊕ MGF1(MGF1(seed) ⊕ M)
```

Where:
- MGF1 is a mask generation function
- seed is a random value
- ⊕ is XOR operation

#### Security Properties
- **Provably Secure**: Under random oracle model
- **Chosen Ciphertext Security**: Resistant to adaptive attacks
- **Semantic Security**: No information leakage about plaintext

#### Variants
- **OAEP with SHA-1**: Widely supported
- **OAEP with SHA-256**: Recommended for new implementations

### PSS (Probabilistic Signature Scheme)

#### Structure
```
EM = maskedDB || H || 0xbc
```

Where:
- maskedDB is the masked data block
- H is the hash of the message
- 0xbc is the trailer byte

#### Security Properties
- **Provably Secure**: Under random oracle model
- **Existential Unforgeability**: Resistant to forgery attacks
- **Randomization**: Each signature is unique

---

## Security Analysis

### Known Attacks

#### Factorization Attacks

##### General Number Field Sieve (GNFS)
- **Complexity**: O(e^(1.92 × (ln n)^(1/3) × (ln ln n)^(2/3)))
- **Practical Impact**: Threatens keys smaller than 1024 bits
- **Mitigation**: Use keys ≥ 2048 bits

##### Quadratic Sieve
- **Complexity**: O(e^(√(ln n × ln ln n)))
- **Practical Impact**: Historical significance
- **Current Status**: Superseded by GNFS

#### Mathematical Attacks

##### Wiener's Attack
- **Target**: Small private exponents
- **Condition**: d < n^(1/4) / 3
- **Mitigation**: Use large private exponents

##### Boneh-Durfee Attack
- **Target**: Small private exponents
- **Condition**: d < n^(0.292)
- **Mitigation**: Use large private exponents

#### Implementation Attacks

##### Timing Attacks
- **Vulnerability**: Execution time depends on secret data
- **Mitigation**: Constant-time implementations

##### Power Analysis
- **Vulnerability**: Power consumption reveals secret data
- **Mitigation**: Power analysis resistant implementations

##### Fault Attacks
- **Vulnerability**: Hardware faults reveal secret data
- **Mitigation**: Fault detection and correction

### Security Recommendations

#### Key Sizes
- **Minimum**: 2048 bits
- **Recommended**: 3072 bits
- **High Security**: 4096 bits
- **Future Proofing**: 4096+ bits

#### Implementation Security
- **Constant-Time**: Use constant-time implementations
- **Input Validation**: Validate all inputs
- **Error Handling**: Don't leak sensitive information
- **Random Generation**: Use cryptographically secure random number generators

---

## Performance Characteristics

### Computational Complexity

#### Big-O Analysis
- **Key Generation**: O(n^3) for primality testing
- **Encryption**: O(log e × log² n)
- **Decryption**: O(log d × log² n)
- **Signature**: O(log d × log² n)
- **Verification**: O(log e × log² n)

#### Practical Performance

| Key Size | Encryption (ms) | Decryption (ms) | Key Generation (s) |
|----------|-----------------|-----------------|-------------------|
| 1024 bits | 0.1 | 0.5 | 0.1 |
| 2048 bits | 0.2 | 1.0 | 0.5 |
| 3072 bits | 0.4 | 2.0 | 2.0 |
| 4096 bits | 0.8 | 4.0 | 8.0 |

*Note: Performance varies by implementation and hardware*

### Optimization Techniques

#### Chinese Remainder Theorem (CRT)
- **Speedup**: 3-4x faster decryption
- **Implementation**: Use p and q separately
- **Security**: Requires protection against fault attacks

#### Montgomery Multiplication
- **Speedup**: 10-20% improvement
- **Implementation**: Hardware and software support
- **Compatibility**: Widely supported

#### Window Methods
- **Speedup**: 20-30% improvement
- **Memory**: Trade-off between speed and memory
- **Implementation**: Precompute common values

---

## Implementation Considerations

### Java Cryptography Architecture (JCA)

#### Key Classes
```java
// Key generation
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(keySize, new SecureRandom());

// Encryption/Decryption
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);

// Digital signatures
Signature signature = Signature.getInstance("SHA256withRSA");
signature.initSign(privateKey);
```

#### Provider Selection
- **SunRsaSign**: Default provider, good performance
- **BouncyCastle**: Additional algorithms and optimizations
- **Conscrypt**: Google's optimized implementation

### Error Handling

#### Common Exceptions
- **InvalidKeyException**: Wrong key type or corrupted key
- **IllegalBlockSizeException**: Message too large for key size
- **BadPaddingException**: Invalid padding in ciphertext
- **SignatureException**: Invalid signature format

#### Security Considerations
- **Information Leakage**: Don't reveal internal state in error messages
- **Timing Attacks**: Ensure constant-time error handling
- **Padding Oracles**: Validate padding without timing dependencies

### Thread Safety

#### Thread Safety Analysis
- **KeyPairGenerator**: Not thread-safe
- **Cipher**: Not thread-safe
- **Signature**: Not thread-safe
- **Key objects**: Immutable and thread-safe

#### Best Practices
- **Instance Per Thread**: Create separate instances for each thread
- **Synchronization**: Use synchronization when sharing instances
- **Object Pooling**: Implement object pools for high-performance applications

---

## Usage with crypto-utils Library

### Basic Operations

```java
import com.haiphamcoder.crypto.signature.RSAUtil;
import java.security.KeyPair;

// Generate key pair
KeyPair keyPair = RSAUtil.generateKeyPair();

// Encrypt data
byte[] encrypted = RSAUtil.encrypt("Hello World", keyPair.getPublic());

// Decrypt data
String decrypted = RSAUtil.decryptString(encrypted, keyPair.getPrivate());

// Sign data
byte[] signature = RSAUtil.sign("Hello World", keyPair.getPrivate());

// Verify signature
boolean isValid = RSAUtil.verify("Hello World", signature, keyPair.getPublic());
```

### Key Size Selection

```java
// Use specific key sizes
KeyPair keyPair2048 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_2048);
KeyPair keyPair3072 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_3072);
KeyPair keyPair4096 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_4096);
```

### Padding Schemes

```java
// Use different padding schemes
byte[] encryptedPKCS1 = RSAUtil.encrypt(data, publicKey, RSAUtil.PADDING_PKCS1);
byte[] encryptedOAEP1 = RSAUtil.encrypt(data, publicKey, RSAUtil.PADDING_OAEP_SHA1);
byte[] encryptedOAEP256 = RSAUtil.encrypt(data, publicKey, RSAUtil.PADDING_OAEP_SHA256);
```

### Signature Algorithms

```java
// Use different hash functions
byte[] sig256 = RSAUtil.sign(data, privateKey, RSAUtil.SIG_SHA256_RSA);
byte[] sig384 = RSAUtil.sign(data, privateKey, RSAUtil.SIG_SHA384_RSA);
byte[] sig512 = RSAUtil.sign(data, privateKey, RSAUtil.SIG_SHA512_RSA);
```

### File Operations

```java
// Encrypt files
byte[] encryptedFile = RSAUtil.encryptFile(inputFile, publicKey);

// Decrypt files
byte[] decryptedFile = RSAUtil.decryptFile(encryptedFile, privateKey);

// Sign files
byte[] fileSignature = RSAUtil.signFile(inputFile, privateKey);

// Verify file signatures
boolean isValid = RSAUtil.verifyFile(inputFile, fileSignature, publicKey);
```

### Key Import/Export

```java
// Export keys
String exportedPrivateKey = RSAUtil.exportPrivateKey(privateKey);
String exportedPublicKey = RSAUtil.exportPublicKey(publicKey);

// Import keys
PrivateKey importedPrivateKey = RSAUtil.importPrivateKey(exportedPrivateKey);
PublicKey importedPublicKey = RSAUtil.importPublicKey(exportedPublicKey);
```

### Encoding Support

```java
// Sign with custom encodings
String base64Sig = RSAUtil.sign(data, privateKey, 
    InputEncoding.UTF8, OutputEncoding.BASE64);

// Verify encoded signatures
boolean isValid = RSAUtil.verifyFromBase64(data, base64Sig, publicKey);
```

---

## Best Practices and Recommendations

### Key Management

#### Generation
- **Secure Random**: Use cryptographically secure random number generators
- **Key Size**: Use at least 2048 bits, preferably 3072 bits
- **Prime Quality**: Ensure high-quality prime numbers
- **Validation**: Validate generated keys

#### Storage
- **Private Keys**: Store in secure hardware or encrypted storage
- **Public Keys**: Can be freely distributed
- **Backup**: Implement secure backup and recovery procedures
- **Rotation**: Regularly rotate keys according to security policy

#### Distribution
- **Public Key Infrastructure**: Use PKI for key distribution
- **Certificate Validation**: Validate certificates before use
- **Key Revocation**: Implement key revocation procedures

### Implementation Security

#### Constant-Time Operations
- **Timing Attacks**: Use constant-time implementations
- **Power Analysis**: Protect against power analysis attacks
- **Fault Attacks**: Implement fault detection and correction

#### Input Validation
- **Message Size**: Validate message size limits
- **Key Validation**: Validate key parameters
- **Padding Validation**: Validate padding without timing dependencies

#### Error Handling
- **Information Leakage**: Don't leak sensitive information in error messages
- **Exception Handling**: Handle exceptions securely
- **Logging**: Avoid logging sensitive information

### Performance Optimization

#### Algorithm Selection
- **Key Size**: Choose appropriate key size for security requirements
- **Padding Scheme**: Use OAEP for encryption, PSS for signatures
- **Hash Functions**: Use SHA-256 or better for signatures

#### Implementation Techniques
- **Chinese Remainder Theorem**: Use CRT for faster decryption
- **Montgomery Multiplication**: Use optimized multiplication algorithms
- **Window Methods**: Use window methods for scalar multiplication

#### Hardware Acceleration
- **AES-NI**: Use hardware acceleration when available
- **Specialized Hardware**: Use specialized cryptographic hardware
- **Parallel Processing**: Exploit parallelism where possible

### Security Considerations

#### Threat Models
- **Classical Attacks**: Protect against mathematical attacks
- **Quantum Attacks**: Consider post-quantum alternatives
- **Side-Channel Attacks**: Protect against timing and power analysis
- **Implementation Attacks**: Protect against fault and glitch attacks

#### Risk Assessment
- **Security Level**: Assess required security level
- **Attack Vectors**: Identify potential attack vectors
- **Mitigation Strategies**: Implement appropriate mitigation strategies
- **Monitoring**: Monitor for security incidents

---

## References

### Standards and Specifications

1. **PKCS#1**: RSA Cryptography Standards
2. **RFC 8017**: PKCS #1: RSA Cryptography Specifications Version 2.2
3. **FIPS 186-4**: Digital Signature Standard (DSS)
4. **NIST SP 800-56B**: Recommendation for Pair-Wise Key Establishment Using Integer Factorization Cryptography

### Academic Papers

1. **Rivest, R. L., Shamir, A., & Adleman, L. (1978)**: A Method for Obtaining Digital Signatures and Public-Key Cryptosystems
2. **Boneh, D. (1999)**: Twenty Years of Attacks on the RSA Cryptosystem
3. **Bleichenbacher, D. (1998)**: Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1

### Implementation Guides

1. **OpenSSL Documentation**: RSA implementation guide
2. **BouncyCastle**: Java cryptography library documentation
3. **Microsoft Documentation**: .NET cryptography implementation
4. **Java Security**: JCA/JCE implementation guide

### Security Analysis

1. **NIST**: Cryptographic Standards and Guidelines
2. **ECRYPT**: European Network of Excellence in Cryptography
3. **IACR**: International Association for Cryptologic Research
4. **CRYPTREC**: Japanese Cryptographic Technology Evaluation

### Historical Context

1. **Kahn, D. (1996)**: The Codebreakers
2. **Schneier, B. (1996)**: Applied Cryptography
3. **Ferguson, N. et al. (2010)**: Cryptography Engineering

---

## Conclusion

RSA remains one of the most important and widely used cryptographic algorithms, providing both encryption and digital signature capabilities. Its mathematical foundation based on the difficulty of factoring large composite numbers has withstood decades of cryptanalysis.

### Key Strengths
- **Proven Security**: Decades of cryptanalysis and real-world use
- **Dual Functionality**: Both encryption and digital signatures
- **Wide Support**: Implemented in virtually all cryptographic libraries
- **Standards Compliance**: Well-defined standards and specifications

### Current Status
- **Security**: 2048+ bit keys provide adequate security for most applications
- **Performance**: Acceptable for key exchange and digital signatures
- **Quantum Resistance**: Vulnerable to quantum attacks (Shor's algorithm)
- **Recommendation**: Continue using for current applications, plan for post-quantum migration

### Future Considerations
- **Post-Quantum**: Research post-quantum alternatives
- **Key Sizes**: Monitor recommendations for key size increases
- **Implementation**: Continue improving implementation security
- **Standards**: Follow evolving standards and best practices

When implementing RSA, focus on:
- **Security**: Use appropriate key sizes and secure implementations
- **Performance**: Optimize for your specific use case
- **Compatibility**: Ensure interoperability with existing systems
- **Maintenance**: Keep implementations updated with security patches

RSA will continue to be a cornerstone of cryptography for the foreseeable future, even as we transition to post-quantum cryptographic algorithms.

---

*This document provides technical guidance for implementing and using RSA. Always follow current security best practices and consult with security experts for production deployments.*
