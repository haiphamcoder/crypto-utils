package com.haiphamcoder.crypto.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for AES encryption and decryption with support for multiple
 * modes, key sizes, and padding schemes.
 */
public final class AESUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String ALGORITHM = "AES";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // AES key sizes in bits
    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_192 = 192;
    public static final int KEY_SIZE_256 = 256;

    // AES modes
    public static final String MODE_ECB = "ECB";
    public static final String MODE_CBC = "CBC";
    public static final String MODE_CFB = "CFB";
    public static final String MODE_OFB = "OFB";
    public static final String MODE_CTR = "CTR";
    public static final String MODE_GCM = "GCM";

    // Padding schemes
    public static final String PADDING_NONE = "NoPadding";
    public static final String PADDING_PKCS5 = "PKCS5Padding";
    public static final String PADDING_PKCS7 = "PKCS7Padding";

    // GCM parameters
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private AESUtil() {
    }

    // ===== Key Generation =====
    /**
     * Generate a random AES key of specified size.
     * 
     * @param keySize key size in bits (128, 192, or 256)
     * @return generated SecretKey
     */
    public static SecretKey generateKey(int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(keySize, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate AES key", e);
        }
    }

    /**
     * Generate a random AES key of 256 bits.
     * 
     * @return generated SecretKey
     */
    public static SecretKey generateKey() {
        return generateKey(KEY_SIZE_256);
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
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate key from password", e);
        }
    }

    /**
     * Generate a key from password using PBKDF2 with default parameters.
     * 
     * @param password password string
     * @param salt salt bytes
     * @return generated SecretKey (256 bits)
     */
    public static SecretKey generateKeyFromPassword(String password, byte[] salt) {
        return generateKeyFromPassword(password, salt, KEY_SIZE_256, 100000);
    }

    // ===== IV Generation =====
    /**
     * Generate a random IV for the specified mode.
     * 
     * @param mode encryption mode
     * @return IV bytes
     */
    public static byte[] generateIV(String mode) {
        int ivLength = getIVLength(mode);
        byte[] iv = new byte[ivLength];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * Get IV length for the specified mode.
     * 
     * @param mode encryption mode
     * @return IV length in bytes
     */
    private static int getIVLength(String mode) {
        switch (mode) {
            case MODE_GCM:
                return GCM_IV_LENGTH;
            case MODE_CBC:
            case MODE_CFB:
            case MODE_OFB:
            case MODE_CTR:
                return 16; // AES block size
            case MODE_ECB:
            default:
                return 0; // No IV needed
        }
    }

    // ===== Encryption =====
    /**
     * Encrypt data using AES.
     * 
     * @param data data to encrypt
     * @param key encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encrypt(byte[] data, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                byte[] iv = generateIV(mode);
                if (MODE_GCM.equals(mode)) {
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
                } else {
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                }
                // Prepend IV to encrypted data
                byte[] encrypted = cipher.doFinal(data);
                byte[] result = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
                return result;
            }
            
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("AES encryption failed", e);
        }
    }

    /**
     * Encrypt data using AES with default parameters (CBC/PKCS5Padding).
     * 
     * @param data data to encrypt
     * @param key encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encrypt(byte[] data, SecretKey key) {
        return encrypt(data, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Encrypt string using AES.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encrypt(String data, SecretKey key, String mode, String padding) {
        return encrypt(data.getBytes(StandardCharsets.UTF_8), key, mode, padding);
    }

    /**
     * Encrypt string using AES with default parameters.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encrypt(String data, SecretKey key) {
        return encrypt(data, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Encrypt file using AES.
     * 
     * @param inputFile input file
     * @param outputFile output file
     * @param key encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void encryptFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                byte[] iv = generateIV(mode);
                if (MODE_GCM.equals(mode)) {
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
                } else {
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                }
                // Write IV to output file
                fos.write(iv);
            }
            
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
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("File encryption failed", e);
        }
    }

    /**
     * Encrypt file using AES with default parameters.
     * 
     * @param inputFile input file
     * @param outputFile output file
     * @param key encryption key
     */
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) {
        encryptFile(inputFile, outputFile, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== Decryption =====
    /**
     * Decrypt data using AES.
     * 
     * @param encryptedData encrypted data
     * @param key decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(encryptedData);
            } else {
                int ivLength = getIVLength(mode);
                if (encryptedData.length < ivLength) {
                    throw new CryptoException("Encrypted data too short");
                }
                
                byte[] iv = new byte[ivLength];
                byte[] data = new byte[encryptedData.length - ivLength];
                System.arraycopy(encryptedData, 0, iv, 0, ivLength);
                System.arraycopy(encryptedData, ivLength, data, 0, data.length);
                
                if (MODE_GCM.equals(mode)) {
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
                } else {
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                }
                
                return cipher.doFinal(data);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("AES decryption failed", e);
        }
    }

    /**
     * Decrypt data using AES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key decryption key
     * @return decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) {
        return decrypt(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Decrypt string using AES.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted string
     */
    public static String decryptString(byte[] encryptedData, SecretKey key, String mode, String padding) {
        byte[] decrypted = decrypt(encryptedData, key, mode, padding);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt string using AES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key decryption key
     * @return decrypted string
     */
    public static String decryptString(byte[] encryptedData, SecretKey key) {
        return decryptString(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Decrypt file using AES.
     * 
     * @param inputFile encrypted input file
     * @param outputFile decrypted output file
     * @param key decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void decryptFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                int ivLength = getIVLength(mode);
                byte[] iv = new byte[ivLength];
                int bytesRead = fis.read(iv);
                if (bytesRead != ivLength) {
                    throw new CryptoException("Failed to read IV from file");
                }
                
                if (MODE_GCM.equals(mode)) {
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
                } else {
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                }
            }
            
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
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("File decryption failed", e);
        }
    }

    /**
     * Decrypt file using AES with default parameters.
     * 
     * @param inputFile encrypted input file
     * @param outputFile decrypted output file
     * @param key decryption key
     */
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) {
        decryptFile(inputFile, outputFile, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== Encoding Support =====
    /**
     * Encrypt string with custom input/output encodings.
     * 
     * @param data input data
     * @param key encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @param in input encoding
     * @param out output encoding
     * @return encrypted data in specified output format
     */
    public static String encrypt(String data, SecretKey key, String mode, String padding, 
                                InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] encrypted = encrypt(inputBytes, key, mode, padding);
        return encode(encrypted, out);
    }

    /**
     * Decrypt string with custom input/output encodings.
     * 
     * @param encryptedData encrypted data
     * @param key decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @param in input encoding
     * @param out output encoding
     * @return decrypted data in specified output format
     */
    public static String decrypt(String encryptedData, SecretKey key, String mode, String padding,
                                InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(encryptedData, in);
        byte[] decrypted = decrypt(inputBytes, key, mode, padding);
        return encode(decrypted, out);
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

    // ===== Convenience Methods =====
    /**
     * Encrypt string with default parameters and return as Base64.
     * 
     * @param data string to encrypt
     * @param key encryption key
     * @return Base64 encoded encrypted data
     */
    public static String encryptToBase64(String data, SecretKey key) {
        return encrypt(data, key, MODE_CBC, PADDING_PKCS5, InputEncoding.UTF8, OutputEncoding.BASE64);
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
            byte[] decrypted = decrypt(inputBytes, key, MODE_CBC, PADDING_PKCS5);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt Base64 data", e);
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
        return encrypt(data, key, MODE_CBC, PADDING_PKCS5, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
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
            byte[] decrypted = decrypt(inputBytes, key, MODE_CBC, PADDING_PKCS5);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt hex data", e);
        }
    }
}
