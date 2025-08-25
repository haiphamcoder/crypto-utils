# ECDSA Technical Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Mathematical Foundations](#mathematical-foundations)
3. [Elliptic Curve Cryptography](#elliptic-curve-cryptography)
4. [ECDSA Algorithm](#ecdsa-algorithm)
5. [Supported Curves](#supported-curves)
6. [Security Analysis](#security-analysis)
7. [Performance Characteristics](#performance-characteristics)
8. [Implementation Considerations](#implementation-considerations)
9. [Usage with crypto-utils Library](#usage-with-crypto-utils-library)
10. [Best Practices and Recommendations](#best-practices-and-recommendations)
11. [References](#references)

---

## Introduction

ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature algorithm that uses elliptic curve cryptography to provide strong security with smaller key sizes compared to traditional algorithms like RSA. ECDSA is widely used in modern cryptographic systems, including SSL/TLS, blockchain technologies, and digital certificates.

### Key Advantages

- **Smaller Key Sizes**: 256-bit ECDSA provides equivalent security to 3072-bit RSA
- **Efficient Operations**: Faster signature generation and verification
- **Strong Security**: Based on the discrete logarithm problem in elliptic curve groups
- **Standardized**: NIST-approved and widely adopted

### Applications

- Digital signatures for documents and software
- SSL/TLS certificate verification
- Blockchain and cryptocurrency transactions
- Secure messaging and authentication
- IoT device security

---

## Mathematical Foundations

### Elliptic Curves

An elliptic curve over a finite field Fp is defined by the equation:

```text
y² = x³ + ax + b (mod p)
```

Where:

- `p` is a prime number (the field characteristic)
- `a` and `b` are coefficients that define the curve
- `(x, y)` are coordinates on the curve
- All operations are performed modulo `p`

### Group Operations

#### Point Addition

Given two points P₁ = (x₁, y₁) and P₂ = (x₂, y₂) on the curve:

1. **If P₁ ≠ P₂**:
   - Calculate slope: λ = (y₂ - y₁) / (x₂ - x₁) (mod p)
   - x₃ = λ² - x₁ - x₂ (mod p)
   - y₃ = λ(x₁ - x₃) - y₁ (mod p)

2. **If P₁ = P₂ (Point Doubling)**:
   - Calculate slope: λ = (3x₁² + a) / (2y₁) (mod p)
   - x₃ = λ² - 2x₁ (mod p)
   - y₃ = λ(x₁ - x₃) - y₁ (mod p)

#### Scalar Multiplication

Scalar multiplication k·P is defined as:

```text
k·P = P + P + ... + P (k times)
```

This operation forms the basis of the discrete logarithm problem.

### Discrete Logarithm Problem

The security of ECDSA relies on the difficulty of solving the discrete logarithm problem:

- **Given**: Points P and Q = k·P on the curve
- **Find**: The scalar k

This problem is computationally hard for well-chosen curves and large key sizes.

---

## Elliptic Curve Cryptography

### Curve Parameters

A secure elliptic curve is defined by the sextuple (p, a, b, G, n, h):

- **p**: Prime field characteristic
- **a, b**: Curve coefficients
- **G**: Base point (generator)
- **n**: Order of the base point (prime)
- **h**: Cofactor (h = #E(Fp) / n)

### Key Generation

1. **Private Key**: Random integer d ∈ [1, n-1]
2. **Public Key**: Point Q = d·G

The private key must be kept secret, while the public key can be freely distributed.

### Security Requirements

- **Curve Order**: n should be prime and large (≥ 256 bits)
- **Field Size**: p should be large (≥ 256 bits)
- **Cofactor**: h should be small (typically 1, 2, or 4)
- **Embedding Degree**: Should be large to resist pairing attacks

---

## ECDSA Algorithm

### Signature Generation

Given a message m and private key d:

1. **Hash the message**: h = Hash(m)
2. **Generate random k**: k ∈ [1, n-1]
3. **Calculate point**: (x₁, y₁) = k·G
4. **Calculate r**: r = x₁ mod n
5. **Calculate s**: s = k⁻¹(h + r·d) mod n
6. **Output signature**: (r, s)

**Critical**: The random value k must be unique for each signature and kept secret.

### Signature Verification

Given a message m, signature (r, s), and public key Q:

1. **Hash the message**: h = Hash(m)
2. **Calculate w**: w = s⁻¹ mod n
3. **Calculate u₁**: u₁ = h·w mod n
4. **Calculate u₂**: u₂ = r·w mod n
5. **Calculate point**: (x₁, y₁) = u₁·G + u₂·Q
6. **Verify**: r ≡ x₁ mod n

If the verification passes, the signature is valid.

### Mathematical Correctness

The verification works because:

```text
u₁·G + u₂·Q = (h·w)·G + (r·w)·Q
             = w·(h·G + r·Q)
             = w·(h·G + r·d·G)
             = w·(h + r·d)·G
             = k⁻¹·(h + r·d)·G
             = k⁻¹·k·G
             = G
```

Therefore, x₁ = x-coordinate of G, and r ≡ x₁ mod n.

---

## Supported Curves

### NIST P-256 (secp256r1)

**Parameters:**

- Field size: 256 bits
- Curve: y² = x³ - 3x + b
- Base point: G = (xG, yG)
- Order: n ≈ 2²⁵⁶
- Cofactor: h = 1

**Security Level:** 128 bits
**Applications:** SSL/TLS, digital certificates, general-purpose cryptography

### NIST P-384 (secp384r1)

**Parameters:**

- Field size: 384 bits
- Curve: y² = x³ - 3x + b
- Base point: G = (xG, yG)
- Order: n ≈ 2³⁸⁴
- Cofactor: h = 1

**Security Level:** 192 bits
**Applications:** High-security applications, government systems

### NIST P-521 (secp521r1)

**Parameters:**

- Field size: 521 bits
- Curve: y² = x³ - 3x + b
- Base point: G = (xG, yG)
- Order: n ≈ 2⁵²¹
- Cofactor: h = 1

**Security Level:** 256 bits
**Applications:** Maximum security requirements, post-quantum preparation

### Bitcoin Curve (secp256k1)

**Parameters:**

- Field size: 256 bits
- Curve: y² = x³ + 7
- Base point: G = (xG, yG)
- Order: n ≈ 2²⁵⁶
- Cofactor: h = 1

**Security Level:** 128 bits
**Applications:** Bitcoin, Ethereum, cryptocurrency systems

---

## Security Analysis

### Cryptographic Strength

ECDSA security is based on the difficulty of:

1. **Discrete Logarithm Problem (DLP)**: Finding k given P and k·P
2. **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: Special case of DLP for elliptic curves

### Known Attacks

#### 1. Pollard's Rho Method

- **Complexity**: O(√n)
- **Mitigation**: Use curves with n ≥ 2²⁵⁶

#### 2. Baby-Step Giant-Step

- **Complexity**: O(√n)
- **Mitigation**: Use curves with n ≥ 2²⁵⁶

#### 3. Index Calculus

- **Complexity**: Subexponential
- **Mitigation**: Use curves with large embedding degree

#### 4. Quantum Attacks

- **Shor's Algorithm**: O((log n)³)
- **Post-Quantum**: Use post-quantum algorithms for long-term security

### Side-Channel Attacks

#### 1. Timing Attacks

- **Vulnerability**: Execution time depends on secret data
- **Mitigation**: Constant-time implementations

#### 2. Power Analysis

- **Vulnerability**: Power consumption reveals secret data
- **Mitigation**: Power analysis resistant implementations

#### 3. Fault Attacks

- **Vulnerability**: Hardware faults reveal secret data
- **Mitigation**: Fault detection and correction

### Security Recommendations

- **Key Size**: Use at least 256-bit curves (secp256r1)
- **Random Generation**: Use cryptographically secure random number generators
- **Implementation**: Use well-tested, constant-time implementations
- **Key Management**: Protect private keys with appropriate security measures

---

## Performance Characteristics

### Computational Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Key Generation | O(1) | Single scalar multiplication |
| Signing | O(1) | Single scalar multiplication |
| Verification | O(1) | Two scalar multiplications |

### Performance Comparison

| Algorithm | Key Size | Sign (ms) | Verify (ms) | Security Level |
|-----------|----------|------------|-------------|----------------|
| RSA-2048 | 2048 bits | 2.5 | 0.1 | 112 bits |
| RSA-3072 | 3072 bits | 8.5 | 0.2 | 128 bits |
| ECDSA-P256 | 256 bits | 0.8 | 1.2 | 128 bits |
| ECDSA-P384 | 384 bits | 1.5 | 2.3 | 192 bits |
| ECDSA-P521 | 521 bits | 2.8 | 4.1 | 256 bits |

***Note: Performance varies by implementation and hardware***

### Optimization Techniques

1. **Window Methods**: Precompute multiples of the base point
2. **NAF Representation**: Use non-adjacent form for scalar multiplication
3. **Parallel Processing**: Exploit parallelism in verification
4. **Hardware Acceleration**: Use dedicated cryptographic hardware

---

## Implementation Considerations

### Java Cryptography Architecture (JCA)

ECDSA is implemented through JCA's `Signature` class:

```java
// Key generation
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
keyGen.initialize(ecSpec, new SecureRandom());

// Signing
Signature signature = Signature.getInstance("SHA256withECDSA");
signature.initSign(privateKey);
signature.update(data);
byte[] sig = signature.sign();

// Verification
Signature verifier = Signature.getInstance("SHA256withECDSA");
verifier.initVerify(publicKey);
verifier.update(data);
boolean valid = verifier.verify(sig);
```

### Provider Selection

- **SunEC**: Default provider, good performance
- **BouncyCastle**: Additional curves and algorithms
- **Conscrypt**: Google's optimized implementation

### Error Handling

Common exceptions and their causes:

- `InvalidKeyException`: Wrong key type or corrupted key
- `SignatureException`: Invalid signature format or data
- `NoSuchAlgorithmException`: Unsupported algorithm or curve

### Thread Safety

- **KeyPairGenerator**: Not thread-safe
- **Signature**: Not thread-safe
- **Key objects**: Immutable and thread-safe

---

## Usage with crypto-utils Library

### Basic Operations

```java
import com.haiphamcoder.crypto.signature.ECDSAUtil;
import java.security.KeyPair;

// Generate key pair
KeyPair keyPair = ECDSAUtil.generateKeyPair();

// Sign data
byte[] signature = ECDSAUtil.sign("Hello World", keyPair.getPrivate());

// Verify signature
boolean isValid = ECDSAUtil.verify("Hello World", signature, keyPair.getPublic());
```

### Curve Selection

```java
// Use specific curves
KeyPair keyPair256 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP256R1);
KeyPair keyPair384 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP384R1);
KeyPair keyPair521 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP521R1);
KeyPair keyPairK1 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP256K1);
```

### Signature Algorithms

```java
// Use different hash functions
byte[] sig256 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA256_ECDSA);
byte[] sig384 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA384_ECDSA);
byte[] sig512 = ECDSAUtil.sign(data, privateKey, ECDSAUtil.SIG_SHA512_ECDSA);
```

### File Operations

```java
// Sign files
byte[] fileSignature = ECDSAUtil.signFile(inputFile, privateKey);

// Verify file signatures
boolean isValid = ECDSAUtil.verifyFile(inputFile, fileSignature, publicKey);
```

### Encoding Support

```java
// Sign with custom encodings
String base64Sig = ECDSAUtil.sign(data, privateKey, 
    InputEncoding.UTF8, OutputEncoding.BASE64);

// Verify encoded signatures
boolean isValid = ECDSAUtil.verifyFromBase64(data, base64Sig, publicKey);
```

### Convenience Methods

```java
// Sign to Base64
String signature = ECDSAUtil.signToBase64("Hello World", privateKey);

// Sign to hex
String hexSignature = ECDSAUtil.signToHex("Hello World", privateKey);

// Verify from Base64
boolean isValid = ECDSAUtil.verifyFromBase64("Hello World", signature, publicKey);
```

---

## Best Practices and Recommendations

### Key Management

1. **Secure Generation**: Use cryptographically secure random number generators
2. **Key Storage**: Store private keys in secure hardware or encrypted storage
3. **Key Rotation**: Regularly rotate keys according to security policy
4. **Key Backup**: Implement secure backup and recovery procedures

### Implementation Security

1. **Constant-Time**: Use constant-time implementations to prevent timing attacks
2. **Input Validation**: Validate all inputs to prevent injection attacks
3. **Error Handling**: Don't leak sensitive information in error messages
4. **Random Generation**: Ensure k values are truly random and unique

### Performance Optimization

1. **Curve Selection**: Choose appropriate curve for security requirements
2. **Hardware Acceleration**: Use hardware acceleration when available
3. **Caching**: Cache frequently used values (e.g., base point multiples)
4. **Batch Operations**: Process multiple signatures together when possible

### Security Considerations

1. **Key Size**: Use at least 256-bit curves for current security requirements
2. **Hash Functions**: Use strong hash functions (SHA-256 or better)
3. **Randomness**: Ensure high-quality randomness for k values
4. **Side Channels**: Protect against timing and power analysis attacks

---

## References

### Standards and Specifications

1. **FIPS 186-4**: Digital Signature Standard (DSS)
2. **RFC 6979**: Deterministic ECDSA
3. **NIST SP 800-186**: Recommendations for Discrete Logarithm-Based Cryptography
4. **ANSI X9.62**: Public Key Cryptography for the Financial Services Industry

### Academic Papers

1. **Johnson, D. et al. (2001)**: The Elliptic Curve Digital Signature Algorithm (ECDSA)
2. **Hankerson, D. et al. (2004)**: Guide to Elliptic Curve Cryptography
3. **Bernstein, D. J. (2006)**: Curve25519: New Diffie-Hellman Speed Records

### Implementation Guides

1. **OpenSSL Documentation**: ECDSA implementation guide
2. **BouncyCastle**: Java cryptography library documentation
3. **Microsoft Documentation**: .NET cryptography implementation

### Security Analysis

1. **NIST**: Cryptographic Standards and Guidelines
2. **ECRYPT**: European Network of Excellence in Cryptography
3. **IACR**: International Association for Cryptologic Research

---

## Conclusion

ECDSA provides a robust and efficient solution for digital signatures in modern cryptographic systems. Its combination of strong security, small key sizes, and good performance makes it an excellent choice for most applications requiring digital signatures.

Key benefits include:

- **Strong Security**: Based on well-studied mathematical problems
- **Efficiency**: Fast operations with small key sizes
- **Standardization**: Widely adopted and well-documented
- **Flexibility**: Support for various curves and hash functions

When implementing ECDSA, focus on:

- **Security**: Use appropriate key sizes and secure implementations
- **Performance**: Optimize for your specific use case
- **Compatibility**: Ensure interoperability with existing systems
- **Maintenance**: Keep implementations updated with security patches

ECDSA continues to be a cornerstone of modern cryptography and will remain relevant for the foreseeable future, even as we transition to post-quantum cryptographic algorithms.

---

*This document provides technical guidance for implementing and using ECDSA. Always follow current security best practices and consult with security experts for production deployments.*
