package haiphamcoder.crypto.encryption;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.encryption.AESUtil;

class AESUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private File encryptedFile;
    private File decryptedFile;
    private static final String TEST_DATA = "Hello, World! This is a test message for AES encryption.";
    private static final String TEST_PASSWORD = "testPassword123";
    private static final byte[] TEST_SALT = "testSalt123".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() throws IOException {
        testFile = tempDir.resolve("test.txt").toFile();
        encryptedFile = tempDir.resolve("encrypted.txt").toFile();
        decryptedFile = tempDir.resolve("decrypted.txt").toFile();
        Files.write(testFile.toPath(), TEST_DATA.getBytes(StandardCharsets.UTF_8));
    }

    // ===== Key Generation Tests =====
    @Test
    void testGenerateKey128() {
        SecretKey key = AESUtil.generateKey(AESUtil.KEY_SIZE_128);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length); // 128 bits = 16 bytes
    }

    @Test
    void testGenerateKey192() {
        SecretKey key = AESUtil.generateKey(AESUtil.KEY_SIZE_192);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(24, key.getEncoded().length); // 192 bits = 24 bytes
    }

    @Test
    void testGenerateKey256() {
        SecretKey key = AESUtil.generateKey(AESUtil.KEY_SIZE_256);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    @Test
    void testGenerateKeyDefault() {
        SecretKey key = AESUtil.generateKey();
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // Default 256 bits
    }

    @Test
    void testGenerateKeyFromPassword() {
        SecretKey key = AESUtil.generateKeyFromPassword(TEST_PASSWORD, TEST_SALT);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // Default 256 bits
    }

    @Test
    void testGenerateKeyFromPasswordWithParams() {
        SecretKey key = AESUtil.generateKeyFromPassword(TEST_PASSWORD, TEST_SALT, AESUtil.KEY_SIZE_128, 50000);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length); // 128 bits
    }

    // ===== IV Generation Tests =====
    @Test
    void testGenerateIVCBC() {
        byte[] iv = AESUtil.generateIV(AESUtil.MODE_CBC);
        assertNotNull(iv);
        assertEquals(16, iv.length); // AES block size
    }

    @Test
    void testGenerateIVGCM() {
        byte[] iv = AESUtil.generateIV(AESUtil.MODE_GCM);
        assertNotNull(iv);
        assertEquals(12, iv.length); // GCM IV length
    }

    @Test
    void testGenerateIVECB() {
        byte[] iv = AESUtil.generateIV(AESUtil.MODE_ECB);
        assertNotNull(iv);
        assertEquals(0, iv.length); // No IV needed for ECB
    }

    // ===== Basic Encryption/Decryption Tests =====
    @Test
    void testEncryptDecryptBytes() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testEncryptDecryptString() {
        SecretKey key = AESUtil.generateKey();
        
        byte[] encrypted = AESUtil.encrypt(TEST_DATA, key);
        assertNotNull(encrypted);
        
        String decrypted = AESUtil.decryptString(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    // ===== Mode Tests =====
    @Test
    void testCBCMode() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testGCMMode() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testCTRMode() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_CTR, AESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CTR, AESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testECBMode() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_ECB, AESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_ECB, AESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    // ===== Padding Tests =====
    @Test
    void testPKCS5Padding() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testNoPadding() {
        SecretKey key = AESUtil.generateKey();
        // Data must be multiple of block size for NoPadding
        byte[] original = "1234567890123456".getBytes(StandardCharsets.UTF_8); // 16 bytes
        
        byte[] encrypted = AESUtil.encrypt(original, key, AESUtil.MODE_CBC, AESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CBC, AESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    // ===== File Encryption/Decryption Tests =====
    @Test
    void testFileEncryptionDecryption() {
        SecretKey key = AESUtil.generateKey();
        
        // Encrypt file
        AESUtil.encryptFile(testFile, encryptedFile, key);
        assertTrue(encryptedFile.exists());
        assertTrue(encryptedFile.length() > 0);
        
        // Decrypt file
        AESUtil.decryptFile(encryptedFile, decryptedFile, key);
        assertTrue(decryptedFile.exists());
        
        // Verify content
        try {
            String decryptedContent = new String(Files.readAllBytes(decryptedFile.toPath()), StandardCharsets.UTF_8);
            assertEquals(TEST_DATA, decryptedContent);
        } catch (IOException e) {
            fail("Failed to read decrypted file: " + e.getMessage());
        }
    }

    @Test
    void testFileEncryptionDecryptionWithMode() {
        SecretKey key = AESUtil.generateKey();
        
        // Encrypt file with GCM mode
        AESUtil.encryptFile(testFile, encryptedFile, key, AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
        assertTrue(encryptedFile.exists());
        
        // Decrypt file
        AESUtil.decryptFile(encryptedFile, decryptedFile, key, AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
        assertTrue(decryptedFile.exists());
        
        // Verify content
        try {
            String decryptedContent = new String(Files.readAllBytes(decryptedFile.toPath()), StandardCharsets.UTF_8);
            assertEquals(TEST_DATA, decryptedContent);
        } catch (IOException e) {
            fail("Failed to read decrypted file: " + e.getMessage());
        }
    }

    // ===== Encoding Tests =====
    @Test
    void testEncryptDecryptWithBase64() {
        SecretKey key = AESUtil.generateKey();
        
        String encrypted = AESUtil.encrypt(TEST_DATA, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5, 
                                         InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5,
                                         InputEncoding.BASE64, OutputEncoding.BASE64);
        // The result is Base64 encoded, so decode it to get the actual decrypted data
        String actualDecrypted = new String(Base64.decodeBase64(decrypted), StandardCharsets.UTF_8);
        assertEquals(TEST_DATA, actualDecrypted);
    }

    @Test
    void testEncryptDecryptWithHex() {
        SecretKey key = AESUtil.generateKey();
        
        String encrypted = AESUtil.encrypt(TEST_DATA, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5,
                                         InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = AESUtil.decrypt(encrypted, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5,
                                         InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        // The result is hex encoded, so decode it to get the actual decrypted data
        try {
            String actualDecrypted = new String(Hex.decodeHex(decrypted), StandardCharsets.UTF_8);
            assertEquals(TEST_DATA, actualDecrypted);
        } catch (Exception e) {
            fail("Failed to decode hex: " + e.getMessage());
        }
    }

    // ===== Convenience Method Tests =====
    @Test
    void testEncryptToBase64() {
        SecretKey key = AESUtil.generateKey();
        
        String encrypted = AESUtil.encryptToBase64(TEST_DATA, key);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = AESUtil.decryptFromBase64(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testEncryptToHex() {
        SecretKey key = AESUtil.generateKey();
        
        String encrypted = AESUtil.encryptToHex(TEST_DATA, key);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = AESUtil.decryptFromHex(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    // ===== Security Tests =====
    @Test
    void testDifferentKeysProduceDifferentCiphertexts() {
        SecretKey key1 = AESUtil.generateKey();
        SecretKey key2 = AESUtil.generateKey();
        
        byte[] encrypted1 = AESUtil.encrypt(TEST_DATA, key1);
        byte[] encrypted2 = AESUtil.encrypt(TEST_DATA, key2);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    void testSameKeyProducesDifferentCiphertexts() {
        SecretKey key = AESUtil.generateKey();
        
        byte[] encrypted1 = AESUtil.encrypt(TEST_DATA, key);
        byte[] encrypted2 = AESUtil.encrypt(TEST_DATA, key);
        
        // Should be different due to random IV
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    void testECBModeProducesSameCiphertext() {
        SecretKey key = AESUtil.generateKey();
        
        byte[] encrypted1 = AESUtil.encrypt(TEST_DATA, key, AESUtil.MODE_ECB, AESUtil.PADDING_PKCS5);
        byte[] encrypted2 = AESUtil.encrypt(TEST_DATA, key, AESUtil.MODE_ECB, AESUtil.PADDING_PKCS5);
        
        // ECB mode should produce same ciphertext for same input
        assertArrayEquals(encrypted1, encrypted2);
    }

    // ===== Error Handling Tests =====
    @Test
    void testDecryptWithWrongKey() {
        SecretKey key1 = AESUtil.generateKey();
        SecretKey key2 = AESUtil.generateKey();
        
        byte[] encrypted = AESUtil.encrypt(TEST_DATA, key1);
        
        assertThrows(Exception.class, () -> {
            AESUtil.decrypt(encrypted, key2);
        });
    }

    @Test
    void testDecryptWithWrongMode() {
        SecretKey key = AESUtil.generateKey();
        
        byte[] encrypted = AESUtil.encrypt(TEST_DATA, key, AESUtil.MODE_CBC, AESUtil.PADDING_PKCS5);
        
        assertThrows(Exception.class, () -> {
            AESUtil.decrypt(encrypted, key, AESUtil.MODE_GCM, AESUtil.PADDING_NONE);
        });
    }



    // ===== Consistency Tests =====
    @Test
    void testEncryptionConsistency() {
        SecretKey key = AESUtil.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Multiple encryptions with same key should produce different results (due to IV)
        byte[] encrypted1 = AESUtil.encrypt(original, key);
        byte[] encrypted2 = AESUtil.encrypt(original, key);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
        
        // But both should decrypt to the same result
        byte[] decrypted1 = AESUtil.decrypt(encrypted1, key);
        byte[] decrypted2 = AESUtil.decrypt(encrypted2, key);
        
        assertArrayEquals(original, decrypted1);
        assertArrayEquals(original, decrypted2);
    }

    @Test
    void testKeySizeConsistency() {
        // Test that different key sizes work correctly
        SecretKey key128 = AESUtil.generateKey(AESUtil.KEY_SIZE_128);
        SecretKey key256 = AESUtil.generateKey(AESUtil.KEY_SIZE_256);
        
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted128 = AESUtil.encrypt(original, key128);
        byte[] encrypted256 = AESUtil.encrypt(original, key256);
        
        assertNotNull(encrypted128);
        assertNotNull(encrypted256);
        
        byte[] decrypted128 = AESUtil.decrypt(encrypted128, key128);
        byte[] decrypted256 = AESUtil.decrypt(encrypted256, key256);
        
        assertArrayEquals(original, decrypted128);
        assertArrayEquals(original, decrypted256);
    }
}
