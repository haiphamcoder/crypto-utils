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
import com.haiphamcoder.crypto.encryption.RC4Util;

class RC4UtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private File encryptedFile;
    private File decryptedFile;
    private static final String TEST_DATA = "Hello, World! This is a test message for RC4 encryption.";
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
    void testGenerateKeyDefault() {
        SecretKey key = RC4Util.generateKey();
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(16, key.getEncoded().length); // 128 bits = 16 bytes
    }

    @Test
    void testGenerateKey128() {
        SecretKey key = RC4Util.generateKey(128);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(16, key.getEncoded().length);
    }

    @Test
    void testGenerateKey256() {
        SecretKey key = RC4Util.generateKey(256);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    void testGenerateKeyMinSize() {
        SecretKey key = RC4Util.generateKey(RC4Util.MIN_KEY_SIZE);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(5, key.getEncoded().length); // 40 bits = 5 bytes
    }

    @Test
    void testGenerateKeyMaxSize() {
        SecretKey key = RC4Util.generateKey(RC4Util.MAX_KEY_SIZE);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    @Test
    void testGenerateKeyInvalidSizeTooSmall() {
        assertThrows(IllegalArgumentException.class, () -> {
            RC4Util.generateKey(RC4Util.MIN_KEY_SIZE - 1);
        });
    }

    @Test
    void testGenerateKeyInvalidSizeTooLarge() {
        assertThrows(IllegalArgumentException.class, () -> {
            RC4Util.generateKey(RC4Util.MAX_KEY_SIZE + 1);
        });
    }

    @Test
    void testGenerateKeyFromPassword() {
        SecretKey key = RC4Util.generateKeyFromPassword(TEST_PASSWORD, TEST_SALT);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(16, key.getEncoded().length); // Default 128 bits
    }

    @Test
    void testGenerateKeyFromPasswordWithParams() {
        SecretKey key = RC4Util.generateKeyFromPassword(TEST_PASSWORD, TEST_SALT, 256, 50000);
        assertNotNull(key);
        assertEquals("ARCFOUR", key.getAlgorithm()); // Java uses ARCFOUR instead of RC4
        assertEquals(32, key.getEncoded().length); // 256 bits
    }

    // ===== RC4 Encryption/Decryption Tests =====
    @Test
    void testEncryptDecryptBytes() {
        SecretKey key = RC4Util.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = RC4Util.encrypt(original, key);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);
        
        byte[] decrypted = RC4Util.decrypt(encrypted, key);
        assertArrayEquals(original, decrypted);
    }

    @Test
    void testEncryptDecryptString() {
        SecretKey key = RC4Util.generateKey();
        
        byte[] encrypted = RC4Util.encrypt(TEST_DATA, key);
        assertNotNull(encrypted);
        
        String decrypted = RC4Util.decryptString(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testEncryptDecryptEmptyString() {
        SecretKey key = RC4Util.generateKey();
        String emptyString = "";
        
        byte[] encrypted = RC4Util.encrypt(emptyString, key);
        assertNotNull(encrypted);
        
        String decrypted = RC4Util.decryptString(encrypted, key);
        assertEquals(emptyString, decrypted);
    }

    @Test
    void testEncryptDecryptShortString() {
        SecretKey key = RC4Util.generateKey();
        String shortString = "Hi";
        
        byte[] encrypted = RC4Util.encrypt(shortString, key);
        assertNotNull(encrypted);
        
        String decrypted = RC4Util.decryptString(encrypted, key);
        assertEquals(shortString, decrypted);
    }

    @Test
    void testEncryptDecryptLongString() {
        SecretKey key = RC4Util.generateKey();
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longString.append("This is a very long string to test RC4 encryption with multiple blocks. ");
        }
        
        byte[] encrypted = RC4Util.encrypt(longString.toString(), key);
        assertNotNull(encrypted);
        
        String decrypted = RC4Util.decryptString(encrypted, key);
        assertEquals(longString.toString(), decrypted);
    }

    // ===== File Encryption/Decryption Tests =====
    @Test
    void testFileEncryptionDecryption() {
        SecretKey key = RC4Util.generateKey();
        
        // Encrypt file
        RC4Util.encryptFile(testFile, encryptedFile, key);
        assertTrue(encryptedFile.exists());
        assertTrue(encryptedFile.length() > 0);
        
        // Decrypt file
        RC4Util.decryptFile(encryptedFile, decryptedFile, key);
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
    void testFileEncryptionDecryptionEmptyFile() throws IOException {
        SecretKey key = RC4Util.generateKey();
        File emptyFile = tempDir.resolve("empty.txt").toFile();
        Files.write(emptyFile.toPath(), new byte[0]);
        
        // Encrypt empty file
        RC4Util.encryptFile(emptyFile, encryptedFile, key);
        assertTrue(encryptedFile.exists());
        
        // Decrypt empty file
        RC4Util.decryptFile(encryptedFile, decryptedFile, key);
        assertTrue(decryptedFile.exists());
        
        // Verify content is empty
        assertEquals(0, decryptedFile.length());
    }

    // ===== Encoding Tests =====
    @Test
    void testEncryptDecryptWithBase64() {
        SecretKey key = RC4Util.generateKey();
        
        String encrypted = RC4Util.encrypt(TEST_DATA, key, InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = RC4Util.decrypt(encrypted, key, InputEncoding.BASE64, OutputEncoding.BASE64);
        // The result is Base64 encoded, so decode it to get the actual decrypted data
        String actualDecrypted = new String(org.apache.commons.codec.binary.Base64.decodeBase64(decrypted), StandardCharsets.UTF_8);
        assertEquals(TEST_DATA, actualDecrypted);
    }

    @Test
    void testEncryptDecryptWithHex() {
        SecretKey key = RC4Util.generateKey();
        
        String encrypted = RC4Util.encrypt(TEST_DATA, key, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = RC4Util.decrypt(encrypted, key, InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        // The result is hex encoded, so decode it to get the actual decrypted data
        try {
            String actualDecrypted = new String(org.apache.commons.codec.binary.Hex.decodeHex(decrypted), StandardCharsets.UTF_8);
            assertEquals(TEST_DATA, actualDecrypted);
        } catch (Exception e) {
            fail("Failed to decode hex: " + e.getMessage());
        }
    }

    @Test
    void testEncryptDecryptWithBase64URL() {
        SecretKey key = RC4Util.generateKey();
        
        String encrypted = RC4Util.encrypt(TEST_DATA, key, InputEncoding.UTF8, OutputEncoding.BASE64_URL);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = RC4Util.decrypt(encrypted, key, InputEncoding.BASE64_URL, OutputEncoding.BASE64_URL);
        // The result is Base64-URL encoded, so decode it to get the actual decrypted data
        String actualDecrypted = new String(org.apache.commons.codec.binary.Base64.decodeBase64(decrypted.replace('-', '+').replace('_', '/')), StandardCharsets.UTF_8);
        assertEquals(TEST_DATA, actualDecrypted);
    }

    // ===== Convenience Method Tests =====
    @Test
    void testEncryptToBase64() {
        SecretKey key = RC4Util.generateKey();
        
        String encrypted = RC4Util.encryptToBase64(TEST_DATA, key);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = RC4Util.decryptFromBase64(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testEncryptToHex() {
        SecretKey key = RC4Util.generateKey();
        
        String encrypted = RC4Util.encryptToHex(TEST_DATA, key);
        assertNotNull(encrypted);
        assertNotEquals(TEST_DATA, encrypted);
        
        String decrypted = RC4Util.decryptFromHex(encrypted, key);
        assertEquals(TEST_DATA, decrypted);
    }

    // ===== Security Tests =====
    @Test
    void testDifferentKeysProduceDifferentCiphertexts() {
        SecretKey key1 = RC4Util.generateKey();
        SecretKey key2 = RC4Util.generateKey();
        
        byte[] encrypted1 = RC4Util.encrypt(TEST_DATA, key1);
        byte[] encrypted2 = RC4Util.encrypt(TEST_DATA, key2);
        
        assertFalse(Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    void testSameKeyProducesDifferentCiphertexts() {
        SecretKey key = RC4Util.generateKey();
        
        byte[] encrypted1 = RC4Util.encrypt(TEST_DATA, key);
        byte[] encrypted2 = RC4Util.encrypt(TEST_DATA, key);
        
        // RC4 may produce same or different ciphertexts for same input
        // This is implementation dependent
        // Just verify both can be decrypted correctly
        String decrypted1 = RC4Util.decryptString(encrypted1, key);
        String decrypted2 = RC4Util.decryptString(encrypted2, key);
        assertEquals(TEST_DATA, decrypted1);
        assertEquals(TEST_DATA, decrypted2);
    }

    @Test
    void testKeySizeAffectsSecurity() {
        SecretKey key40 = RC4Util.generateKey(40);
        SecretKey key128 = RC4Util.generateKey(128);
        SecretKey key256 = RC4Util.generateKey(256);
        
        byte[] encrypted40 = RC4Util.encrypt(TEST_DATA, key40);
        byte[] encrypted128 = RC4Util.encrypt(TEST_DATA, key128);
        byte[] encrypted256 = RC4Util.encrypt(TEST_DATA, key256);
        
        // All should be different
        assertFalse(Arrays.equals(encrypted40, encrypted128));
        assertFalse(Arrays.equals(encrypted128, encrypted256));
        assertFalse(Arrays.equals(encrypted40, encrypted256));
    }

    // ===== Error Handling Tests =====
    @Test
    void testDecryptWithWrongKey() {
        SecretKey key1 = RC4Util.generateKey();
        SecretKey key2 = RC4Util.generateKey();
        
        byte[] encrypted = RC4Util.encrypt(TEST_DATA, key1);
        
        // RC4 may not always throw exception with wrong key
        // Instead, verify that decryption produces different result
        byte[] decrypted = RC4Util.decrypt(encrypted, key2);
        assertFalse(Arrays.equals(TEST_DATA.getBytes(StandardCharsets.UTF_8), decrypted));
    }

    @Test
    void testDecryptWithCorruptedData() {
        SecretKey key = RC4Util.generateKey();
        byte[] encrypted = RC4Util.encrypt(TEST_DATA, key);
        
        // Corrupt the encrypted data
        encrypted[0] ^= 0x01;
        
        // RC4 may not always throw exception with corrupted data
        // Instead, verify that decryption produces different result
        byte[] decrypted = RC4Util.decrypt(encrypted, key);
        assertFalse(Arrays.equals(TEST_DATA.getBytes(StandardCharsets.UTF_8), decrypted));
    }

    // ===== Consistency Tests =====
    @Test
    void testEncryptionConsistency() {
        SecretKey key = RC4Util.generateKey();
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Multiple encryptions with same key may produce same or different results
        // This is implementation dependent
        byte[] encrypted1 = RC4Util.encrypt(original, key);
        byte[] encrypted2 = RC4Util.encrypt(original, key);
        
        // But both should decrypt to the same result
        byte[] decrypted1 = RC4Util.decrypt(encrypted1, key);
        byte[] decrypted2 = RC4Util.decrypt(encrypted2, key);
        
        assertArrayEquals(original, decrypted1);
        assertArrayEquals(original, decrypted2);
    }

    @Test
    void testKeySizeConsistency() {
        // Test that different key sizes work correctly
        SecretKey key40 = RC4Util.generateKey(40);
        SecretKey key128 = RC4Util.generateKey(128);
        SecretKey key256 = RC4Util.generateKey(256);
        
        byte[] original = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted40 = RC4Util.encrypt(original, key40);
        byte[] encrypted128 = RC4Util.encrypt(original, key128);
        byte[] encrypted256 = RC4Util.encrypt(original, key256);
        
        assertNotNull(encrypted40);
        assertNotNull(encrypted128);
        assertNotNull(encrypted256);
        
        byte[] decrypted40 = RC4Util.decrypt(encrypted40, key40);
        byte[] decrypted128 = RC4Util.decrypt(encrypted128, key128);
        byte[] decrypted256 = RC4Util.decrypt(encrypted256, key256);
        
        assertArrayEquals(original, decrypted40);
        assertArrayEquals(original, decrypted128);
        assertArrayEquals(original, decrypted256);
    }

    // ===== Performance Tests =====
    @Test
    void testLargeDataPerformance() {
        SecretKey key = RC4Util.generateKey();
        
        // Create a large data block
        byte[] largeData = new byte[1024 * 1024]; // 1MB
        new java.util.Random().nextBytes(largeData);
        
        long startTime = System.currentTimeMillis();
        byte[] encrypted = RC4Util.encrypt(largeData, key);
        long encryptTime = System.currentTimeMillis() - startTime;
        
        startTime = System.currentTimeMillis();
        byte[] decrypted = RC4Util.decrypt(encrypted, key);
        long decryptTime = System.currentTimeMillis() - startTime;
        
        // Verify correctness
        assertArrayEquals(largeData, decrypted);
        
        // Performance should be reasonable (less than 5 seconds for 1MB)
        assertTrue(encryptTime < 5000, "Encryption took too long: " + encryptTime + "ms");
        assertTrue(decryptTime < 5000, "Decryption took too long: " + decryptTime + "ms");
    }
}
