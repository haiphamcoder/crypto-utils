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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for DES and Triple DES encryption and decryption with support for
 * multiple modes and padding schemes.
 * 
 * <p><strong>Security Note:</strong> DES is considered cryptographically weak and
 * should not be used for new applications. Triple DES is deprecated and should be
 * replaced with AES for new implementations.</p>
 */
public final class DESUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String DES_ALGORITHM = "DES";
    private static final String TRIPLE_DES_ALGORITHM = "DESede";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // DES key sizes in bits
    public static final int DES_KEY_SIZE = 56; // 64 bits with 8 parity bits
    public static final int TRIPLE_DES_KEY_SIZE = 168; // 192 bits with 24 parity bits

    // DES modes
    public static final String MODE_ECB = "ECB";
    public static final String MODE_CBC = "CBC";
    public static final String MODE_CFB = "CFB";
    public static final String MODE_OFB = "OFB";

    // Padding schemes
    public static final String PADDING_NONE = "NoPadding";
    public static final String PADDING_PKCS5 = "PKCS5Padding";
    public static final String PADDING_PKCS7 = "PKCS7Padding";

    // Block size for DES (64 bits = 8 bytes)
    private static final int DES_BLOCK_SIZE = 8;

    private DESUtil() {
    }

    // ===== Key Generation =====
    /**
     * Generate a random DES key.
     * 
     * @return generated DES SecretKey
     */
    public static SecretKey generateDESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(DES_ALGORITHM);
            keyGen.init(DES_KEY_SIZE, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate DES key", e);
        }
    }

    /**
     * Generate a random Triple DES key.
     * 
     * @return generated Triple DES SecretKey
     */
    public static SecretKey generateTripleDESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(TRIPLE_DES_ALGORITHM);
            keyGen.init(TRIPLE_DES_KEY_SIZE, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate Triple DES key", e);
        }
    }

    /**
     * Generate a key from password using PBKDF2 for DES.
     * 
     * @param password password string
     * @param salt salt bytes
     * @param iterations number of iterations
     * @return generated DES SecretKey
     */
    public static SecretKey generateDESKeyFromPassword(String password, byte[] salt, int iterations) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, DES_KEY_SIZE);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), DES_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate DES key from password", e);
        }
    }

    /**
     * Generate a key from password using PBKDF2 for Triple DES.
     * 
     * @param password password string
     * @param salt salt bytes
     * @param iterations number of iterations
     * @return generated Triple DES SecretKey
     */
    public static SecretKey generateTripleDESKeyFromPassword(String password, byte[] salt, int iterations) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, TRIPLE_DES_KEY_SIZE);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), TRIPLE_DES_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate Triple DES key from password", e);
        }
    }

    // ===== IV Generation =====
    /**
     * Generate a random IV for DES operations.
     * 
     * @param mode encryption mode
     * @return IV bytes
     */
    public static byte[] generateIV(String mode) {
        if (MODE_ECB.equals(mode)) {
            return new byte[0]; // No IV needed for ECB
        }
        byte[] iv = new byte[DES_BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    // ===== DES Encryption =====
    /**
     * Encrypt data using DES.
     * 
     * @param data data to encrypt
     * @param key DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encryptDES(byte[] data, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(data);
            } else {
                byte[] iv = generateIV(mode);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                
                byte[] encrypted = cipher.doFinal(data);
                byte[] result = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
                return result;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("DES encryption failed", e);
        }
    }

    /**
     * Encrypt data using DES with default parameters (CBC/PKCS5Padding).
     * 
     * @param data data to encrypt
     * @param key DES encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encryptDES(byte[] data, SecretKey key) {
        return encryptDES(data, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Encrypt string using DES.
     * 
     * @param data string to encrypt
     * @param key DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encryptDES(String data, SecretKey key, String mode, String padding) {
        return encryptDES(data.getBytes(StandardCharsets.UTF_8), key, mode, padding);
    }

    /**
     * Encrypt string using DES with default parameters.
     * 
     * @param data string to encrypt
     * @param key DES encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encryptDES(String data, SecretKey key) {
        return encryptDES(data, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== Triple DES Encryption =====
    /**
     * Encrypt data using Triple DES.
     * 
     * @param data data to encrypt
     * @param key Triple DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encryptTripleDES(byte[] data, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(data);
            } else {
                byte[] iv = generateIV(mode);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                
                byte[] encrypted = cipher.doFinal(data);
                byte[] result = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
                return result;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Triple DES encryption failed", e);
        }
    }

    /**
     * Encrypt data using Triple DES with default parameters.
     * 
     * @param data data to encrypt
     * @param key Triple DES encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encryptTripleDES(byte[] data, SecretKey key) {
        return encryptTripleDES(data, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Encrypt string using Triple DES.
     * 
     * @param data string to encrypt
     * @param key Triple DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return encrypted data
     */
    public static byte[] encryptTripleDES(String data, SecretKey key, String mode, String padding) {
        return encryptTripleDES(data.getBytes(StandardCharsets.UTF_8), key, mode, padding);
    }

    /**
     * Encrypt string using Triple DES with default parameters.
     * 
     * @param data string to encrypt
     * @param key Triple DES encryption key
     * @return encrypted data with IV prepended
     */
    public static byte[] encryptTripleDES(String data, SecretKey key) {
        return encryptTripleDES(data, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== DES Decryption =====
    /**
     * Decrypt data using DES.
     * 
     * @param encryptedData encrypted data
     * @param key DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted data
     */
    public static byte[] decryptDES(byte[] encryptedData, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(encryptedData);
            } else {
                if (encryptedData.length < DES_BLOCK_SIZE) {
                    throw new CryptoException("Encrypted data too short");
                }
                
                byte[] iv = new byte[DES_BLOCK_SIZE];
                byte[] data = new byte[encryptedData.length - DES_BLOCK_SIZE];
                System.arraycopy(encryptedData, 0, iv, 0, DES_BLOCK_SIZE);
                System.arraycopy(encryptedData, DES_BLOCK_SIZE, data, 0, data.length);
                
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                
                return cipher.doFinal(data);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("DES decryption failed", e);
        }
    }

    /**
     * Decrypt data using DES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key DES decryption key
     * @return decrypted data
     */
    public static byte[] decryptDES(byte[] encryptedData, SecretKey key) {
        return decryptDES(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Decrypt string using DES.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted string
     */
    public static String decryptDESString(byte[] encryptedData, SecretKey key, String mode, String padding) {
        byte[] decrypted = decryptDES(encryptedData, key, mode, padding);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt string using DES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key DES decryption key
     * @return decrypted string
     */
    public static String decryptDESString(byte[] encryptedData, SecretKey key) {
        return decryptDESString(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== Triple DES Decryption =====
    /**
     * Decrypt data using Triple DES.
     * 
     * @param encryptedData encrypted data
     * @param key Triple DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted data
     */
    public static byte[] decryptTripleDES(byte[] encryptedData, SecretKey key, String mode, String padding) {
        try {
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(encryptedData);
            } else {
                if (encryptedData.length < DES_BLOCK_SIZE) {
                    throw new CryptoException("Encrypted data too short");
                }
                
                byte[] iv = new byte[DES_BLOCK_SIZE];
                byte[] data = new byte[encryptedData.length - DES_BLOCK_SIZE];
                System.arraycopy(encryptedData, 0, iv, 0, DES_BLOCK_SIZE);
                System.arraycopy(encryptedData, DES_BLOCK_SIZE, data, 0, data.length);
                
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                
                return cipher.doFinal(data);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Triple DES decryption failed", e);
        }
    }

    /**
     * Decrypt data using Triple DES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key Triple DES decryption key
     * @return decrypted data
     */
    public static byte[] decryptTripleDES(byte[] encryptedData, SecretKey key) {
        return decryptTripleDES(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    /**
     * Decrypt string using Triple DES.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key Triple DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @return decrypted string
     */
    public static String decryptTripleDESString(byte[] encryptedData, SecretKey key, String mode, String padding) {
        byte[] decrypted = decryptTripleDES(encryptedData, key, mode, padding);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt string using Triple DES with default parameters.
     * 
     * @param encryptedData encrypted data with IV prepended
     * @param key Triple DES decryption key
     * @return decrypted string
     */
    public static String decryptTripleDESString(byte[] encryptedData, SecretKey key) {
        return decryptTripleDESString(encryptedData, key, MODE_CBC, PADDING_PKCS5);
    }

    // ===== File Operations =====
    /**
     * Encrypt file using DES.
     * 
     * @param inputFile input file
     * @param outputFile output file
     * @param key DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void encryptDESFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                byte[] iv = generateIV(mode);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
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
            throw new CryptoException("DES file encryption failed", e);
        }
    }

    /**
     * Decrypt file using DES.
     * 
     * @param inputFile encrypted input file
     * @param outputFile decrypted output file
     * @param key DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void decryptDESFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                byte[] iv = new byte[DES_BLOCK_SIZE];
                int bytesRead = fis.read(iv);
                if (bytesRead != DES_BLOCK_SIZE) {
                    throw new CryptoException("Failed to read IV from file");
                }
                
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
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
            throw new CryptoException("DES file decryption failed", e);
        }
    }

    // ===== Triple DES File Operations =====
    /**
     * Encrypt file using Triple DES.
     * 
     * @param inputFile input file
     * @param outputFile output file
     * @param key Triple DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void encryptTripleDESFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                byte[] iv = generateIV(mode);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
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
            throw new CryptoException("Triple DES file encryption failed", e);
        }
    }

    /**
     * Decrypt file using Triple DES.
     * 
     * @param inputFile encrypted input file
     * @param outputFile decrypted output file
     * @param key Triple DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     */
    public static void decryptTripleDESFile(File inputFile, File outputFile, SecretKey key, String mode, String padding) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            Cipher cipher = Cipher.getInstance(TRIPLE_DES_ALGORITHM + "/" + mode + "/" + padding);
            
            if (MODE_ECB.equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                byte[] iv = new byte[DES_BLOCK_SIZE];
                int bytesRead = fis.read(iv);
                if (bytesRead != DES_BLOCK_SIZE) {
                    throw new CryptoException("Failed to read IV from file");
                }
                
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
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
            throw new CryptoException("Triple DES file decryption failed", e);
        }
    }

    // ===== Encoding Support =====
    /**
     * Encrypt string with custom input/output encodings using DES.
     * 
     * @param data input data
     * @param key DES encryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @param in input encoding
     * @param out output encoding
     * @return encrypted data in specified output format
     */
    public static String encryptDES(String data, SecretKey key, String mode, String padding, 
                                   InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(data, in);
        byte[] encrypted = encryptDES(inputBytes, key, mode, padding);
        return encode(encrypted, out);
    }

    /**
     * Decrypt string with custom input/output encodings using DES.
     * 
     * @param encryptedData encrypted data
     * @param key DES decryption key
     * @param mode encryption mode
     * @param padding padding scheme
     * @param in input encoding
     * @param out output encoding
     * @return decrypted data in specified output format
     */
    public static String decryptDES(String encryptedData, SecretKey key, String mode, String padding,
                                   InputEncoding in, OutputEncoding out) {
        byte[] inputBytes = decode(encryptedData, in);
        byte[] decrypted = decryptDES(inputBytes, key, mode, padding);
        return encode(decrypted, out);
    }

    // ===== Convenience Methods =====
    /**
     * Encrypt string with DES using default parameters and return as Base64.
     * 
     * @param data string to encrypt
     * @param key DES encryption key
     * @return Base64 encoded encrypted data
     */
    public static String encryptDESToBase64(String data, SecretKey key) {
        return encryptDES(data, key, MODE_CBC, PADDING_PKCS5, InputEncoding.UTF8, OutputEncoding.BASE64);
    }

    /**
     * Decrypt Base64 encoded DES data with default parameters.
     * 
     * @param base64Data Base64 encoded encrypted data
     * @param key DES decryption key
     * @return decrypted string
     */
    public static String decryptDESFromBase64(String base64Data, SecretKey key) {
        try {
            byte[] inputBytes = Base64.decodeBase64(base64Data);
            byte[] decrypted = decryptDES(inputBytes, key, MODE_CBC, PADDING_PKCS5);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt DES Base64 data", e);
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
