package haiphamcoder.crypto.encryption;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.encryption.DESUtil;

class DESUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private File encryptedFile;
    private File decryptedFile;
    private static final String TEST_DATA = "Hello, World! This is a test message for DES encryption.";
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
    void testGenerateDESKey() {
        SecretKey key = DESUtil.generateDESKey();
        assertNotNull(key);
        assertEquals("DES", key.getAlgorithm());
        assertEquals(8, key.getEncoded().length); // 56 bits = 7 bytes + 1 parity byte
    }

    @Test
    void testGenerateTripleDESKey() {
        SecretKey key = DESUtil.generateTripleDESKey();
        assertNotNull(key);
        assertEquals("DESede", key.getAlgorithm());
        assertEquals(24, key.getEncoded().length); // 168 bits = 21 bytes + 3 parity bytes
    }

    @Test
    void testGenerateDESKeyFromPassword() {
        SecretKey key = DESUtil.generateDESKeyFromPassword(TEST_PASSWORD, TEST_SALT, 100000);
        assertNotNull(key);
        assertEquals("DES", key.getAlgorithm());
        assertEquals(7, key.getEncoded().length); // PBKDF2 returns actual key size without parity
    }

    @Test
    void testGenerateTripleDESKeyFromPassword() {
        SecretKey key = DESUtil.generateTripleDESKeyFromPassword(TEST_PASSWORD, TEST_SALT, 100000);
        assertNotNull(key);
        assertEquals("DESede", key.getAlgorithm());
        assertEquals(21, key.getEncoded().length); // PBKDF2 returns actual key size without parity
    }

    // ===== IV Generation Tests =====
    @Test
    void testGenerateIVCBC() {
        byte[] iv = DESUtil.generateIV(DESUtil.MODE_CBC);
        assertNotNull(iv);
        assertEquals(8, iv.length); // DES block size
    }

    @Test
    void testGenerateIVECB() {
        byte[] iv = DESUtil.generateIV(DESUtil.MODE_ECB);
        assertNotNull(iv);
        assertEquals(0, iv.length); // No IV needed for ECB
    }

    // ===== DES Encryption/Decryption Tests =====
    @Test
    void testDESEncryptDecryptBytes() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testDESEncryptDecryptString() {
        SecretKey key = DESUtil.generateDESKey();
        
        byte[] encrypted = DESUtil.encryptDES(TEST_DATA, key);
        assertNotNull(encrypted);
        
        String decrypted = DESUtil.decryptDESString(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testDESModeCBC() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testDESModeECB() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testDESModeCFB() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_CFB, DESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CFB, DESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testDESModeOFB() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_OFB, DESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_OFB, DESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    // ===== Triple DES Encryption/Decryption Tests =====
    @Test
    void testTripleDESEncryptDecryptBytes() {
        SecretKey key = DESUtil.generateTripleDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptTripleDES(original, key);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);
        
        byte[] decrypted = DESUtil.decryptTripleDES(encrypted, key);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testTripleDESEncryptDecryptString() {
        SecretKey key = DESUtil.generateTripleDESKey();
        
        byte[] encrypted = DESUtil.encryptTripleDES(TEST_DATA, key);
        assertNotNull(encrypted);
        
        String decrypted = DESUtil.decryptTripleDESString(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testTripleDESModeCBC() {
        SecretKey key = DESUtil.generateTripleDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptTripleDES(original, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptTripleDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testTripleDESModeECB() {
        SecretKey key = DESUtil.generateTripleDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptTripleDES(original, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptTripleDES(encrypted, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    // ===== Padding Tests =====
    @Test
    void testDESPKCS5Padding() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testDESNoPadding() {
        SecretKey key = DESUtil.generateDESKey();
        // Data must be multiple of block size for NoPadding
        byte[] original = "12345678".getBytes(StandardCharsets.UTF_8); // 8 bytes
        
        byte[] encrypted = DESUtil.encryptDES(original, key, DESUtil.MODE_CBC, DESUtil.PADDING_NONE);
        assertNotNull(encrypted);
        
        byte[] decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_NONE);
        assertArrayEquals(original, decrypted);
    }

    // ===== File Encryption/Decryption Tests =====
    @Test
    void testDESFileEncryptionDecryption() {
        SecretKey key = DESUtil.generateDESKey();
        
        // Encrypt file
        DESUtil.encryptDESFile(testFile, encryptedFile, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertTrue(encryptedFile.exists());
        assertTrue(encryptedFile.length() > 0);
        
        // Decrypt file
        DESUtil.decryptDESFile(encryptedFile, decryptedFile, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
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
    void testTripleDESFileEncryptionDecryption() {
        SecretKey key = DESUtil.generateTripleDESKey();
        
        // Encrypt file using Triple DES
        DESUtil.encryptTripleDESFile(testFile, encryptedFile, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        assertTrue(encryptedFile.exists());
        
        // Decrypt file using Triple DES
        DESUtil.decryptTripleDESFile(encryptedFile, decryptedFile, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
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
    void testDESEncryptDecryptWithBase64() {
        SecretKey key = DESUtil.generateDESKey();
        
        String encrypted = DESUtil.encryptDES(TEST_DATA, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5, 
                                            InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5,
                                            InputEncoding.BASE64, OutputEncoding.BASE64);
        // The result is Base64 encoded, so decode it to get the actual decrypted data
        String actualDecrypted = new String(org.apache.commons.codec.binary.Base64.decodeBase64(decrypted), StandardCharsets.UTF_8);
        assertEquals(TEST_DATA, actualDecrypted);
    }

    @Test
    void testDESEncryptDecryptWithHex() {
        SecretKey key = DESUtil.generateDESKey();
        
        String encrypted = DESUtil.encryptDES(TEST_DATA, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5,
                                            InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = DESUtil.decryptDES(encrypted, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5,
                                            InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        // The result is hex encoded, so decode it to get the actual decrypted data
        try {
            String actualDecrypted = new String(org.apache.commons.codec.binary.Hex.decodeHex(decrypted), StandardCharsets.UTF_8);
            assertEquals(TEST_DATA, actualDecrypted);
        } catch (Exception e) {
            fail("Failed to decode hex: " + e.getMessage());
        }
    }

    // ===== Convenience Method Tests =====
    @Test
    void testDESEncryptToBase64() {
        SecretKey key = DESUtil.generateDESKey();
        
        String encrypted = DESUtil.encryptDESToBase64(TEST_DATA, key);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = DESUtil.decryptDESFromBase64(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    // ===== Security Tests =====
    @Test
    void testDifferentKeysProduceDifferentCiphertexts() {
        SecretKey key1 = DESUtil.generateDESKey();
        SecretKey key2 = DESUtil.generateDESKey();
        
        byte[] encrypted1 = DESUtil.encryptDES(TEST_DATA, key1);
        byte[] encrypted2 = DESUtil.encryptDES(TEST_DATA, key2);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    void testSameKeyProducesDifferentCiphertexts() {
        SecretKey key = DESUtil.generateDESKey();
        
        byte[] encrypted1 = DESUtil.encryptDES(TEST_DATA, key);
        byte[] encrypted2 = DESUtil.encryptDES(TEST_DATA, key);
        
        // Should be different due to random IV
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    void testECBModeProducesSameCiphertext() {
        SecretKey key = DESUtil.generateDESKey();
        
        byte[] encrypted1 = DESUtil.encryptDES(TEST_DATA, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        byte[] encrypted2 = DESUtil.encryptDES(TEST_DATA, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        
        // ECB mode should produce same ciphertext for same input
        assertArrayEquals(encrypted1, encrypted2);
    }

    // ===== Error Handling Tests =====
    @Test
    void testDecryptWithWrongKey() {
        SecretKey key1 = DESUtil.generateDESKey();
        SecretKey key2 = DESUtil.generateDESKey();
        
        byte[] encrypted = DESUtil.encryptDES(TEST_DATA, key1);
        
        assertThrows(Exception.class, () -> {
            DESUtil.decryptDES(encrypted, key2);
        });
    }

    @Test
    void testDecryptWithWrongMode() {
        SecretKey key = DESUtil.generateDESKey();
        
        byte[] encrypted = DESUtil.encryptDES(TEST_DATA, key, DESUtil.MODE_CBC, DESUtil.PADDING_PKCS5);
        
        assertThrows(Exception.class, () -> {
            DESUtil.decryptDES(encrypted, key, DESUtil.MODE_ECB, DESUtil.PADDING_PKCS5);
        });
    }

    // ===== Consistency Tests =====
    @Test
    void testDESEncryptionConsistency() {
        SecretKey key = DESUtil.generateDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Multiple encryptions with same key should produce different results (due to IV)
        byte[] encrypted1 = DESUtil.encryptDES(original, key);
        byte[] encrypted2 = DESUtil.encryptDES(original, key);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
        
        // But both should decrypt to the same result
        byte[] decrypted1 = DESUtil.decryptDES(encrypted1, key);
        byte[] decrypted2 = DESUtil.decryptDES(encrypted2, key);
        
        assertArrayEquals(original, decrypted1);
        assertArrayEquals(original, decrypted2);
    }

    @Test
    void testTripleDESEncryptionConsistency() {
        SecretKey key = DESUtil.generateTripleDESKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Multiple encryptions with same key should produce different results (due to IV)
        byte[] encrypted1 = DESUtil.encryptTripleDES(original, key);
        byte[] encrypted2 = DESUtil.encryptTripleDES(original, key);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
        
        // But both should decrypt to the same result
        byte[] decrypted1 = DESUtil.decryptTripleDES(encrypted1, key);
        byte[] decrypted2 = DESUtil.decryptTripleDES(encrypted2, key);
        
        assertArrayEquals(original, decrypted1);
        assertArrayEquals(original, decrypted2);
    }
}
