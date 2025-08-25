package com.haiphamcoder.crypto.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for RC4 stream cipher encryption and decryption.
 * 
 * <p><strong>Security Note:</strong> RC4 is considered cryptographically weak and
 * has been deprecated due to various vulnerabilities. It should not be used for
 * new applications. This implementation is provided for legacy compatibility only.</p>
 * 
 * <p>Known vulnerabilities include:</p>
 * <ul>
 *   <li>Bias in the first few bytes of output</li>
 *   <li>Weaknesses in key scheduling algorithm</li>
 *   <li>Vulnerability to various cryptanalytic attacks</li>
 * </ul>
 */
public final class RC4Util {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String ALGORITHM = "ARCFOUR";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // RC4 key sizes (typically 40-256 bits)
    public static final int MIN_KEY_SIZE = 40;
    public static final int DEFAULT_KEY_SIZE = 128;
    public static final int MAX_KEY_SIZE = 256;

    private RC4Util() {
    }

    // ===== Key Generation =====
    /**
     * Generate a random RC4 key of specified size.
     * 
     * @param keySize key size in bits
     * @return generated SecretKey
     */
    public static SecretKey generateKey(int keySize) {
        if (keySize < MIN_KEY_SIZE || keySize > MAX_KEY_SIZE) {
            throw new IllegalArgumentException("Key size must be between " + MIN_KEY_SIZE + 
                                           " and " + MAX_KEY_SIZE + " bits");
        }
        
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(keySize, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate RC4 key", e);
        }
    }

    /**
     * Generate a random RC4 key of default size (128 bits).
     * 
     * @return generated SecretKey
     */
    public static SecretKey generateKey() {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    /**
     * Generate a key from password using PBKDF2.
     * 
     * @param password password string
     * @param salt salt bytes
     * @param keySize key size in bits
     * @param iterations number of iterations
     * @return generated SecretKey
     */
    public static SecretKey generateKeyFromPassword(String password, byte[] salt, int keySize, int iterations) {
        if (keySize < MIN_KEY_SIZE || keySize > MAX_KEY_SIZE) {
            throw new IllegalArgumentException("Key size must be between " + MIN_KEY_SIZE + 
                                           " and " + MAX_KEY_SIZE + " bits");
        }
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate RC4 key from password", e);
        }
    }

    /**
     * Generate a key from password using PBKDF2 with default parameters.
     * 
     * @param password password string
     * @param salt salt bytes
     * @return generated SecretKey (128 bits)
     */
    public static SecretKey generateKeyFromPassword(String password, byte[] salt) {
        return generateKeyFromPassword(password, salt, DEFAULT_KEY_SIZE, 100000);
    }

    // ===== RC4 Encryption =====
    /**
     * Encrypt data using RC4.
     * 
     * @param data data to encrypt
     * @param key encryption key
     * @return encrypted data
     */
    public static byte[] encrypt(byte[] data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("RC4 encryption failed", e);
        }
    }

    /**
     * Encrypt string using RC4.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @return encrypted data
     */
    public static byte[] encrypt(String data, SecretKey key) {
        return encrypt(data.getBytes(StandardCharsets.UTF_8), key);
    }

    // ===== RC4 Decryption =====
    /**
     * Decrypt data using RC4.
     * 
     * @param encryptedData encrypted data
     * @param key decryption key
     * @return decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("RC4 decryption failed", e);
        }
    }

    /**
     * Decrypt string using RC4.
     * 
     * @param encryptedData encrypted data
     * @param key decryption key
     * @return decrypted string
     */
    public static String decryptString(byte[] encryptedData, SecretKey key) {
        byte[] decrypted = decrypt(encryptedData, key);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // ===== File Operations =====
    /**
     * Encrypt file using RC4.
     * 
     * @param inputFile input file
     * @param outputFile output file
     * @param key encryption key
     */
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encrypted = cipher.update(buffer, 0, bytesRead);
                if (encrypted != null) {
                    fos.write(encrypted);
                }
            }
            
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) {
                fos.write(finalBlock);
            }
            
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("RC4 file encryption failed", e);
        }
    }

    /**
     * Decrypt file using RC4.
     * 
     * @param inputFile encrypted input file
     * @param outputFile decrypted output file
     * @param key decryption key
     */
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] decrypted = cipher.update(buffer, 0, bytesRead);
                if (decrypted != null) {
                    fos.write(decrypted);
                }
            }
            
            byte[] finalBlock = cipher.doFinal();
            if (finalBlock != null) {
                fos.write(finalBlock);
            }
            
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("RC4 file decryption failed", e);
        }
    }

    // ===== Encoding Support =====
    /**
     * Encrypt string with custom input/output encodings.
     * 
     * @param data input data
     * @param key encryption key
     * @param in input encoding
     * @param out output encoding
     * @return encrypted data in specified output format
     */
    public static String encrypt(String data, SecretKey key, InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] encrypted = encrypt(inputBytes, key);
        return encode(encrypted, out);
    }

    /**
     * Decrypt string with custom input/output encodings.
     * 
     * @param encryptedData encrypted data
     * @param key decryption key
     * @param in input encoding
     * @param out output encoding
     * @return decrypted data in specified output format
     */
    public static String decrypt(String encryptedData, SecretKey key, InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(encryptedData, in);
        byte[] decrypted = decrypt(inputBytes, key);
        return encode(decrypted, out);
    }

    // ===== Convenience Methods =====
    /**
     * Encrypt string with default parameters and return as Base64.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @return Base64 encoded encrypted data
     */
    public static String encryptToBase64(String data, SecretKey key) {
        return encrypt(data, key, InputEncoding.UTF8, OutputEncoding.BASE64);
    }

    /**
     * Decrypt Base64 encoded data with default parameters.
     * 
     * @param base64Data Base64 encoded encrypted data
     * @param key decryption key
     * @return decrypted string
     */
    public static String decryptFromBase64(String base64Data, SecretKey key) {
        try {
            byte[] inputBytes = Base64.decodeBase64(base64Data);
            byte[] decrypted = decrypt(inputBytes, key);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt RC4 Base64 data", e);
        }
    }

    /**
     * Encrypt string with default parameters and return as hex.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @return hex encoded encrypted data
     */
    public static String encryptToHex(String data, SecretKey key) {
        return encrypt(data, key, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
    }

    /**
     * Decrypt hex encoded data with default parameters.
     * 
     * @param hexData hex encoded encrypted data
     * @param key decryption key
     * @return decrypted string
     */
    public static String decryptFromHex(String hexData, SecretKey key) {
        try {
            byte[] inputBytes = Hex.decodeHex(hexData);
            byte[] decrypted = decrypt(inputBytes, key);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt RC4 hex data", e);
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
