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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPublicKey;
import java.security.InvalidAlgorithmParameterException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;
import io.github.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for ECDSA (Elliptic Curve Digital Signature Algorithm) operations
 * including key generation, signature creation, and verification.
 * 
 * <p>ECDSA provides digital signatures using elliptic curve cryptography, offering
 * strong security with smaller key sizes compared to RSA.</p>
 * 
 * <p>Supported curves include:</p>
 * <ul>
 *   <li><strong>secp256r1</strong> (NIST P-256): 256-bit key, widely used</li>
 *   <li><strong>secp384r1</strong> (NIST P-384): 384-bit key, high security</li>
 *   <li><strong>secp521r1</strong> (NIST P-521): 521-bit key, maximum security</li>
 *   <li><strong>secp256k1</strong> (Bitcoin curve): 256-bit key, cryptocurrency</li>
 * </ul>
 */
public final class ECDSAUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String ALGORITHM = "EC";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Standard elliptic curves
    public static final String CURVE_SECP256R1 = "secp256r1"; // NIST P-256
    public static final String CURVE_SECP384R1 = "secp384r1"; // NIST P-384
    public static final String CURVE_SECP521R1 = "secp521r1"; // NIST P-521
    public static final String CURVE_SECP256K1 = "secp256k1"; // Bitcoin curve

    // Default curve
    public static final String DEFAULT_CURVE = CURVE_SECP256R1;

    // Signature algorithms
    public static final String SIG_SHA256_ECDSA = "SHA256withECDSA";
    public static final String SIG_SHA384_ECDSA = "SHA384withECDSA";
    public static final String SIG_SHA512_ECDSA = "SHA512withECDSA";

    private ECDSAUtil() {
    }

    // ===== Key Generation =====
    /**
     * Generate an ECDSA key pair using the default curve (secp256r1).
     * 
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_CURVE);
    }

    /**
     * Generate an ECDSA key pair using the specified curve.
     * 
     * @param curveName name of the elliptic curve
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair(String curveName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyGen.initialize(ecSpec, SECURE_RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Failed to generate ECDSA key pair for curve: " + curveName, e);
        }
    }

    /**
     * Generate an ECDSA key pair with custom key size.
     * 
     * @param keySize key size in bits
     * @return generated KeyPair
     */
    public static KeyPair generateKeyPair(int keySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(keySize, SECURE_RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate ECDSA key pair with size: " + keySize, e);
        }
    }

    // ===== Signature Generation =====
    /**
     * Sign data using ECDSA with default algorithm (SHA256withECDSA).
     * 
     * @param data data to sign
     * @param privateKey private key for signing
     * @return signature bytes
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        return sign(data, privateKey, SIG_SHA256_ECDSA);
    }

    /**
     * Sign data using ECDSA with specified algorithm.
     * 
     * @param data data to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature bytes
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey, SECURE_RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("ECDSA signing failed", e);
        }
    }

    /**
     * Sign string using ECDSA with default algorithm.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @return signature bytes
     */
    public static byte[] sign(String data, PrivateKey privateKey) {
        return sign(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }

    /**
     * Sign string using ECDSA with specified algorithm.
     * 
     * @param data string to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature bytes
     */
    public static byte[] sign(String data, PrivateKey privateKey, String algorithm) {
        return sign(data.getBytes(StandardCharsets.UTF_8), privateKey, algorithm);
    }

    // ===== Signature Verification =====
    /**
     * Verify signature using ECDSA with default algorithm.
     * 
     * @param data original data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        return verify(data, signature, publicKey, SIG_SHA256_ECDSA);
    }

    /**
     * Verify signature using ECDSA with specified algorithm.
     * 
     * @param data original data
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("ECDSA verification failed", e);
        }
    }

    /**
     * Verify signature for string using ECDSA with default algorithm.
     * 
     * @param data original string
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(String data, byte[] signature, PublicKey publicKey) {
        return verify(data.getBytes(StandardCharsets.UTF_8), signature, publicKey);
    }

    /**
     * Verify signature for string using ECDSA with specified algorithm.
     * 
     * @param data original string
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(String data, byte[] signature, PublicKey publicKey, String algorithm) {
        return verify(data.getBytes(StandardCharsets.UTF_8), signature, publicKey, algorithm);
    }

    // ===== File Operations =====
    /**
     * Sign file using ECDSA with default algorithm.
     * 
     * @param inputFile file to sign
     * @param privateKey private key for signing
     * @return signature bytes
     */
    public static byte[] signFile(File inputFile, PrivateKey privateKey) {
        return signFile(inputFile, privateKey, SIG_SHA256_ECDSA);
    }

    /**
     * Sign file using ECDSA with specified algorithm.
     * 
     * @param inputFile file to sign
     * @param privateKey private key for signing
     * @param algorithm signature algorithm
     * @return signature bytes
     */
    public static byte[] signFile(File inputFile, PrivateKey privateKey, String algorithm) {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey, SECURE_RANDOM);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
            
            return signature.sign();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("ECDSA file signing failed", e);
        }
    }

    /**
     * Verify file signature using ECDSA with default algorithm.
     * 
     * @param inputFile file to verify
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifyFile(File inputFile, byte[] signature, PublicKey publicKey) {
        return verifyFile(inputFile, signature, publicKey, SIG_SHA256_ECDSA);
    }

    /**
     * Verify file signature using ECDSA with specified algorithm.
     * 
     * @param inputFile file to verify
     * @param signature signature to verify
     * @param publicKey public key for verification
     * @param algorithm signature algorithm
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifyFile(File inputFile, byte[] signature, PublicKey publicKey, String algorithm) {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                sig.update(buffer, 0, bytesRead);
            }
            
            return sig.verify(signature);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("ECDSA file verification failed", e);
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
     * @return true if signature is valid, false otherwise
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
     * @return true if signature is valid, false otherwise
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
     * @return true if signature is valid, false otherwise
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
     * @return true if signature is valid, false otherwise
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
     * Get the curve name from a public key.
     * 
     * @param publicKey ECDSA public key
     * @return curve name
     */
    public static String getCurveName(PublicKey publicKey) {
        try {
            ECPublicKey ecKey = (ECPublicKey) publicKey;
            ECParameterSpec params = ecKey.getParams();
            return params.toString();
        } catch (ClassCastException e) {
            throw new CryptoException("Key is not an ECDSA public key", e);
        }
    }

    /**
     * Get the key size in bits from a public key.
     * 
     * @param publicKey ECDSA public key
     * @return key size in bits
     */
    public static int getKeySize(PublicKey publicKey) {
        try {
            ECPublicKey ecKey = (ECPublicKey) publicKey;
            ECParameterSpec params = ecKey.getParams();
            return params.getCurve().getField().getFieldSize();
        } catch (ClassCastException e) {
            throw new CryptoException("Key is not an ECDSA public key", e);
        }
    }

    // ===== Helper Methods =====
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
