package io.github.haiphamcoder.crypto.signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;
import io.github.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for RSA (Rivest-Shamir-Adleman) operations including
 * key generation, encryption/decryption, and digital signatures.
 * 
 * <p>RSA is an asymmetric cryptographic algorithm that provides both
 * encryption and digital signature capabilities. It is widely used in
 * SSL/TLS, digital certificates, and secure communications.</p>
 * 
 * <p>Supported key sizes:</p>
 * <ul>
 *   <li><strong>2048 bits</strong>: Minimum recommended for current security</li>
 *   <li><strong>3072 bits</strong>: Recommended for high security applications</li>
 *   <li><strong>4096 bits</strong>: Maximum security, slower performance</li>
 * </ul>
 * 
 * <p>Note: RSA is computationally intensive and should be used primarily
 * for key exchange and digital signatures, not for bulk data encryption.</p>
 */
public final class RSAUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Standard key sizes
    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_3072 = 3072;
    public static final int KEY_SIZE_4096 = 4096;
    public static final int DEFAULT_KEY_SIZE = KEY_SIZE_2048;

    // Signature algorithms
    public static final String SIG_SHA256_RSA = "SHA256withRSA";
    public static final String SIG_SHA384_RSA = "SHA384withRSA";
    public static final String SIG_SHA512_RSA = "SHA512withRSA";
    public static final String SIG_SHA1_RSA = "SHA1withRSA";

    // Padding schemes
    public static final String PADDING_PKCS1 = "RSA/ECB/PKCS1Padding";
    public static final String PADDING_OAEP_SHA1 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String PADDING_OAEP_SHA256 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private RSAUtil() {
    }

    // ===== Key Generation =====
    /**
     * Generate an RSA key pair with default key size (2048 bits).
     * 
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }

    /**
     * Generate an RSA key pair with specified key size.
     * 
     * @param keySize key size in bits (2048, 3072, or 4096)
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair(int keySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(keySize, SECURE_RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate RSA key pair with size: " + keySize, e);
        }
    }

    /**
     * Generate an RSA key pair with custom key size and SecureRandom.
     * 
     * @param keySize key size in bits
     * @param secureRandom secure random number generator
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair(int keySize, SecureRandom secureRandom) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(keySize, secureRandom);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate RSA key pair with size: " + keySize, e);
        }
    }

    // ===== Key Import/Export =====
    /**
     * Import RSA private key from Base64 encoded PKCS8 format.
     * 
     * @param base64Key Base64 encoded private key
     * @return PrivateKey object
     */
    public static PrivateKey importPrivateKey(String base64Key) {
        try {
            byte[] keyBytes = Base64.decodeBase64(base64Key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to import RSA private key", e);
        }
    }

    /**
     * Import RSA public key from Base64 encoded X509 format.
     * 
     * @param base64Key Base64 encoded public key
     * @return PublicKey object
     */
    public static PublicKey importPublicKey(String base64Key) {
        try {
            byte[] keyBytes = Base64.decodeBase64(base64Key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to import RSA public key", e);
        }
    }

    /**
     * Export RSA private key to Base64 encoded PKCS8 format.
     * 
     * @param privateKey private key to export
     * @return Base64 encoded private key
     */
    public static String exportPrivateKey(PrivateKey privateKey) {
        return Base64.encodeBase64String(privateKey.getEncoded());
    }

    /**
     * Export RSA public key to Base64 encoded X509 format.
     * 
     * @param publicKey public key to export
     * @return Base64 encoded public key
     */
    public static String exportPublicKey(PublicKey publicKey) {
        return Base64.encodeBase64String(publicKey.getEncoded());
    }

    // ===== Encryption/Decryption =====
    /**
     * Encrypt data using RSA with default padding (PKCS1).
     * 
     * @param data data to encrypt
     * @param publicKey public key for encryption
     * @return encrypted data
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) {
        return encrypt(data, publicKey, PADDING_PKCS1);
    }

    /**
     * Encrypt data using RSA with specified padding.
     * 
     * @param data data to encrypt
     * @param publicKey public key for encryption
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey, String padding) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(padding);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("RSA encryption failed", e);
        }
    }

    /**
     * Decrypt data using RSA with default padding (PKCS1).
     * 
     * @param encryptedData encrypted data
     * @param privateKey private key for decryption
     * @return decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) {
        return decrypt(encryptedData, privateKey, PADDING_PKCS1);
    }

    /**
     * Decrypt data using RSA with specified padding.
     * 
     * @param encryptedData encrypted data
     * @param privateKey private key for decryption
     * @param padding padding scheme
     * @return decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey, String padding) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(padding);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptoException("RSA decryption failed", e);
        }
    }

    // ===== String Encryption/Decryption =====
    /**
     * Encrypt string using RSA with default padding.
     * 
     * @param data string to encrypt
     * @param publicKey public key for encryption
     * @return encrypted data
     */
    public static byte[] encrypt(String data, PublicKey publicKey) {
        return encrypt(data.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    /**
     * Encrypt string using RSA with specified padding.
     * 
     * @param data string to encrypt
     * @param publicKey public key for encryption
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encrypt(String data, PublicKey publicKey, String padding) {
        return encrypt(data.getBytes(StandardCharsets.UTF_8), publicKey, padding);
    }

    /**
     * Decrypt data to string using RSA with default padding.
     * 
     * @param encryptedData encrypted data
     * @param privateKey private key for decryption
     * @return decrypted string
     */
    public static String decryptString(byte[] encryptedData, PrivateKey privateKey) {
        byte[] decrypted = decrypt(encryptedData, privateKey);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt data to string using RSA with specified padding.
     * 
     * @param encryptedData encrypted data
     * @param privateKey private key for decryption
     * @param padding padding scheme
     * @return decrypted string
     */
    public static String decryptString(byte[] encryptedData, PrivateKey privateKey, String padding) {
        byte[] decrypted = decrypt(encryptedData, privateKey, padding);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // ===== File Encryption/Decryption =====
    /**
     * Encrypt file using RSA with default padding.
     * 
     * @param inputFile file to encrypt
     * @param publicKey public key for encryption
     * @return encrypted data
     */
    public static byte[] encryptFile(File inputFile, PublicKey publicKey) {
        return encryptFile(inputFile, publicKey, PADDING_PKCS1);
    }

    /**
     * Encrypt file using RSA with specified padding.
     * 
     * @param inputFile file to encrypt
     * @param publicKey public key for encryption
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encryptFile(File inputFile, PublicKey publicKey, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] fileData = readFileBytes(fis);
            return encrypt(fileData, publicKey, padding);
        } catch (IOException e) {
            throw new CryptoException("RSA file encryption failed", e);
        }
    }

    /**
     * Decrypt file data using RSA with default padding.
     * 
     * @param encryptedData encrypted file data
     * @param privateKey private key for decryption
     * @return decrypted file data
     */
    public static byte[] decryptFile(byte[] encryptedData, PrivateKey privateKey) {
        return decryptFile(encryptedData, privateKey, PADDING_PKCS1);
    }

    /**
     * Decrypt file data using RSA with specified padding.
     * 
     * @param encryptedData encrypted file data
     * @param privateKey private key for decryption
     * @param padding padding scheme
     * @return decrypted file data
     */
    public static byte[] decryptFile(byte[] encryptedData, PrivateKey privateKey, String padding) {
        return decrypt(encryptedData, privateKey, padding);
    }

    // ===== Digital Signatures =====
    /**
     * Sign data using RSA with default algorithm (SHA256withRSA).
     * 
     * @param data data to sign
     * @param privateKey private key for signing
     * @return signature
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        return sign(data, privateKey, SIGNATURE_ALGORITHM);
    }

    /**
     * Sign data using RSA with specified algorithm.
     * 
     * @param data data to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey, SECURE_RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("RSA signing failed", e);
        }
    }

    /**
     * Sign string using RSA with default algorithm.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @return signature
     */
    public static byte[] sign(String data, PrivateKey privateKey) {
        return sign(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Sign string using RSA with specified algorithm.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature
     */
    public static byte[] sign(String data, PrivateKey privateKey, String algorithm) {
        return sign(data.getBytes(StandardCharsets.UTF_8), privateKey, algorithm);
    }

    // ===== Signature Verification =====
    /**
     * Verify signature using RSA with default algorithm.
     * 
     * @param data original data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        return verify(data, signature, publicKey, SIGNATURE_ALGORITHM);
    }

    /**
     * Verify signature using RSA with specified algorithm.
     * 
     * @param data original data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("RSA verification failed", e);
        }
    }

    /**
     * Verify signature for string using RSA with default algorithm.
     * 
     * @param data original string
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid
     */
    public static boolean verify(String data, byte[] signature, PublicKey publicKey) {
        return verify(data.getBytes(StandardCharsets.UTF_8), signature, publicKey);
    }

    /**
     * Verify signature for string using RSA with specified algorithm.
     * 
     * @param data original string
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid
     */
    public static boolean verify(String data, byte[] signature, PublicKey publicKey, String algorithm) {
        return verify(data.getBytes(StandardCharsets.UTF_8), signature, publicKey, algorithm);
    }

    // ===== File Signing/Verification =====
    /**
     * Sign file using RSA with default algorithm.
     * 
     * @param inputFile file to sign
     * @param privateKey private key for signing
     * @return signature
     */
    public static byte[] signFile(File inputFile, PrivateKey privateKey) {
        return signFile(inputFile, privateKey, SIGNATURE_ALGORITHM);
    }

    /**
     * Sign file using RSA with specified algorithm.
     * 
     * @param inputFile file to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature
     */
    public static byte[] signFile(File inputFile, PrivateKey privateKey, String algorithm) {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] fileData = readFileBytes(fis);
            return sign(fileData, privateKey, algorithm);
        } catch (IOException e) {
            throw new CryptoException("RSA file signing failed", e);
        }
    }

    /**
     * Verify file signature using RSA with default algorithm.
     * 
     * @param inputFile file to verify
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid
     */
    public static boolean verifyFile(File inputFile, byte[] signature, PublicKey publicKey) {
        return verifyFile(inputFile, signature, publicKey, SIGNATURE_ALGORITHM);
    }

    /**
     * Verify file signature using RSA with specified algorithm.
     * 
     * @param inputFile file to verify
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid
     */
    public static boolean verifyFile(File inputFile, byte[] signature, PublicKey publicKey, String algorithm) {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] fileData = readFileBytes(fis);
            return verify(fileData, signature, publicKey, algorithm);
        } catch (IOException e) {
            throw new CryptoException("RSA file verification failed", e);
        }
    }

    // ===== Encoding Support =====
    /**
     * Sign string with custom input encoding and return signature in specified output format.
     * 
     * @param data input data
     * @param privateKey private key for signing
     * @param in input encoding
     * @param out output encoding
     * @return signature in specified output format
     */
    public static String sign(String data, PrivateKey privateKey, InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] signature = sign(inputBytes, privateKey);
        return encode(signature, out);
    }

    /**
     * Sign string with custom input encoding and return signature in specified output format.
     * 
     * @param data input data
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @param in input encoding
     * @param out output encoding
     * @return signature in specified output format
     */
    public static String sign(String data, PrivateKey privateKey, String algorithm, 
                             InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] signature = sign(inputBytes, privateKey, algorithm);
        return encode(signature, out);
    }

    /**
     * Verify signature with custom input/output encodings.
     * 
     * @param data input data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param in input encoding
     * @param out output encoding
     * @return true if signature is valid
     */
    public static boolean verify(String data, String signature, PublicKey publicKey,
                                InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] signatureBytes = decode(signature, in);
        return verify(inputBytes, signatureBytes, publicKey);
    }

    /**
     * Verify signature with custom input/output encodings and algorithm.
     * 
     * @param data input data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @param in input encoding
     * @param out output encoding
     * @return true if signature is valid
     */
    public static boolean verify(String data, String signature, PublicKey publicKey, String algorithm,
                                InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] signatureBytes = decode(signature, in);
        return verify(inputBytes, signatureBytes, publicKey, algorithm);
    }

    // ===== Convenience Methods =====
    /**
     * Sign string and return signature as Base64.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @return Base64 encoded signature
     */
    public static String signToBase64(String data, PrivateKey privateKey) {
        return sign(data, privateKey, InputEncoding.UTF8, OutputEncoding.BASE64);
    }

    /**
     * Sign string and return signature as hex.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @return hex encoded signature
     */
    public static String signToHex(String data, PrivateKey privateKey) {
        return sign(data, privateKey, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
    }

    /**
     * Verify Base64 encoded signature.
     * 
     * @param data original data
     * @param base64Signature Base64 encoded signature
     * @param publicKey public key for verification
     * @return true if signature is valid
     */
    public static boolean verifyFromBase64(String data, String base64Signature, PublicKey publicKey) {
        try {
            byte[] signatureBytes = Base64.decodeBase64(base64Signature);
            return verify(data, signatureBytes, publicKey);
        } catch (Exception e) {
            throw new CryptoException("Failed to decode Base64 signature", e);
        }
    }

    /**
     * Verify hex encoded signature.
     * 
     * @param data original data
     * @param hexSignature hex encoded signature
     * @param publicKey public key for verification
     * @return true if signature is valid
     */
    public static boolean verifyFromHex(String data, String hexSignature, PublicKey publicKey) {
        try {
            byte[] signatureBytes = Hex.decodeHex(hexSignature);
            return verify(data, signatureBytes, publicKey);
        } catch (Exception e) {
            throw new CryptoException("Failed to decode hex signature", e);
        }
    }

    // ===== Key Information =====
    /**
     * Get the key size in bits from a public key.
     * 
     * @param publicKey RSA public key
     * @return key size in bits
     */
    public static int getKeySize(PublicKey publicKey) {
        try {
            java.security.spec.RSAPublicKeySpec spec = 
                java.security.KeyFactory.getInstance(ALGORITHM)
                    .getKeySpec(publicKey, java.security.spec.RSAPublicKeySpec.class);
            return spec.getModulus().bitLength();
        } catch (Exception e) {
            throw new CryptoException("Failed to get RSA key size", e);
        }
    }

    /**
     * Get the modulus from a public key.
     * 
     * @param publicKey RSA public key
     * @return modulus as string
     */
    public static String getModulus(PublicKey publicKey) {
        try {
            java.security.spec.RSAPublicKeySpec spec = 
                java.security.KeyFactory.getInstance(ALGORITHM)
                    .getKeySpec(publicKey, java.security.spec.RSAPublicKeySpec.class);
            return spec.getModulus().toString();
        } catch (Exception e) {
            throw new CryptoException("Failed to get RSA modulus", e);
        }
    }

    /**
     * Get the public exponent from a public key.
     * 
     * @param publicKey RSA public key
     * @return public exponent as string
     */
    public static String getPublicExponent(PublicKey publicKey) {
        try {
            java.security.spec.RSAPublicKeySpec spec = 
                java.security.KeyFactory.getInstance(ALGORITHM)
                    .getKeySpec(publicKey, java.security.spec.RSAPublicKeySpec.class);
            return spec.getPublicExponent().toString();
        } catch (Exception e) {
            throw new CryptoException("Failed to get RSA public exponent", e);
        }
    }

    // ===== Helper Methods =====
    /**
     * Read file bytes using buffered reading for Java 8 compatibility.
     * 
     * @param fis FileInputStream to read from
     * @return file contents as byte array
     * @throws IOException if reading fails
     */
    private static byte[] readFileBytes(FileInputStream fis) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        return baos.toByteArray();
    }

    /**
     * Decode input string according to encoding.
     * 
     * @param input input string
     * @param encoding input encoding
     * @return decoded bytes
     */
    private static byte[] decode(String input, InputEncoding encoding) {
        try {
            switch (encoding) {
                case HEX:
                    return Hex.decodeHex(input);
                case BASE64:
                    return Base64.decodeBase64(input);
                case BASE64_URL:
                    return Base64.decodeBase64(input.replace('-', '+').replace('_', '/'));
                case UTF8:
                default:
                    return input.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new CryptoException("Failed to decode input with encoding: " + encoding, e);
        }
    }

    /**
     * Encode bytes according to output encoding.
     * 
     * @param data data bytes
     * @param encoding output encoding
     * @return encoded string
     */
    private static String encode(byte[] data, OutputEncoding encoding) {
        switch (encoding) {
            case HEX_LOWER:
                return Hex.encodeHexString(data, true);
            case HEX_UPPER:
                return Hex.encodeHexString(data, false).toUpperCase();
            case BASE64:
                return Base64.encodeBase64String(data);
            case BASE64_URL:
                return Base64.encodeBase64URLSafeString(data);
            default:
                return new String(data, StandardCharsets.UTF_8);
        }
    }
}
