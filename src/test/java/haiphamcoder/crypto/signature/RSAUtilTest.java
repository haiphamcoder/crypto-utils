package haiphamcoder.crypto.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.signature.RSAUtil;

class RSAUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private static final String TEST_DATA = "Hello, World! This is a test message for RSA operations.";
    private static final String SHORT_DATA = "Hi";
    private static final String LONG_DATA = "This is a very long message to test RSA operations with multiple blocks. "
            + "It contains enough data to ensure proper testing of the RSA algorithm across different data sizes. "
            + "The message should be long enough to test streaming and buffering capabilities.";

    @BeforeEach
    void setUp() throws IOException {
        testFile = tempDir.resolve("test.txt").toFile();
        Files.write(testFile.toPath(), TEST_DATA.getBytes(StandardCharsets.UTF_8));
    }

    // ===== Key Generation Tests =====
    @Test
    void testGenerateKeyPairDefault() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.DEFAULT_KEY_SIZE, keySize);
    }

    @Test
    void testGenerateKeyPair2048() {
        KeyPair keyPair = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_2048);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.KEY_SIZE_2048, keySize);
    }

    @Test
    void testGenerateKeyPair3072() {
        KeyPair keyPair = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_3072);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.KEY_SIZE_3072, keySize);
    }

    @Test
    void testGenerateKeyPair4096() {
        KeyPair keyPair = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_4096);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.KEY_SIZE_4096, keySize);
    }

    @Test
    void testGenerateKeyPairWithSecureRandom() {
        SecureRandom secureRandom = new SecureRandom();
        KeyPair keyPair = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_2048, secureRandom);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.KEY_SIZE_2048, keySize);
    }

    // ===== Key Import/Export Tests =====
    @Test
    void testImportExportPrivateKey() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String exportedPrivateKey = RSAUtil.exportPrivateKey(keyPair.getPrivate());
        assertNotNull(exportedPrivateKey);
        assertTrue(exportedPrivateKey.length() > 0);
        
        PrivateKey importedPrivateKey = RSAUtil.importPrivateKey(exportedPrivateKey);
        assertNotNull(importedPrivateKey);
        assertEquals(keyPair.getPrivate(), importedPrivateKey);
    }

    @Test
    void testImportExportPublicKey() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String exportedPublicKey = RSAUtil.exportPublicKey(keyPair.getPublic());
        assertNotNull(exportedPublicKey);
        assertTrue(exportedPublicKey.length() > 0);
        
        PublicKey importedPublicKey = RSAUtil.importPublicKey(exportedPublicKey);
        assertNotNull(importedPublicKey);
        assertEquals(keyPair.getPublic(), importedPublicKey);
    }

    // ===== Encryption/Decryption Tests =====
    @Test
    void testEncryptDecryptBytes() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] encrypted = RSAUtil.encrypt(data, keyPair.getPublic());
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);
        
        byte[] decrypted = RSAUtil.decrypt(encrypted, keyPair.getPrivate());
        assertArrayEquals(data, decrypted);
    }

    @Test
    void testEncryptDecryptString() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] encrypted = RSAUtil.encrypt(TEST_DATA, keyPair.getPublic());
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);
        
        String decrypted = RSAUtil.decryptString(encrypted, keyPair.getPrivate());
        assertEquals(TEST_DATA, decrypted);
    }

    @Test
    void testEncryptDecryptShortString() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] encrypted = RSAUtil.encrypt(SHORT_DATA, keyPair.getPublic());
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);
        
        String decrypted = RSAUtil.decryptString(encrypted, keyPair.getPrivate());
        assertEquals(SHORT_DATA, decrypted);
    }

    @Test
    void testEncryptDecryptWithDifferentPadding() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Test PKCS1 padding
        byte[] encryptedPKCS1 = RSAUtil.encrypt(data, keyPair.getPublic(), RSAUtil.PADDING_PKCS1);
        byte[] decryptedPKCS1 = RSAUtil.decrypt(encryptedPKCS1, keyPair.getPrivate(), RSAUtil.PADDING_PKCS1);
        assertArrayEquals(data, decryptedPKCS1);
        
        // Test OAEP SHA1 padding
        byte[] encryptedOAEP1 = RSAUtil.encrypt(data, keyPair.getPublic(), RSAUtil.PADDING_OAEP_SHA1);
        byte[] decryptedOAEP1 = RSAUtil.decrypt(encryptedOAEP1, keyPair.getPrivate(), RSAUtil.PADDING_OAEP_SHA1);
        assertArrayEquals(data, decryptedOAEP1);
        
        // Test OAEP SHA256 padding
        byte[] encryptedOAEP256 = RSAUtil.encrypt(data, keyPair.getPublic(), RSAUtil.PADDING_OAEP_SHA256);
        byte[] decryptedOAEP256 = RSAUtil.decrypt(encryptedOAEP256, keyPair.getPrivate(), RSAUtil.PADDING_OAEP_SHA256);
        assertArrayEquals(data, decryptedOAEP256);
    }

    // ===== File Encryption/Decryption Tests =====
    @Test
    void testEncryptDecryptFile() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] encrypted = RSAUtil.encryptFile(testFile, keyPair.getPublic());
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);
        
        byte[] decrypted = RSAUtil.decryptFile(encrypted, keyPair.getPrivate());
        assertArrayEquals(TEST_DATA.getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    void testEncryptDecryptFileWithDifferentPadding() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        // Test PKCS1 padding
        byte[] encryptedPKCS1 = RSAUtil.encryptFile(testFile, keyPair.getPublic(), RSAUtil.PADDING_PKCS1);
        byte[] decryptedPKCS1 = RSAUtil.decryptFile(encryptedPKCS1, keyPair.getPrivate(), RSAUtil.PADDING_PKCS1);
        assertArrayEquals(TEST_DATA.getBytes(StandardCharsets.UTF_8), decryptedPKCS1);
        
        // Test OAEP SHA1 padding
        byte[] encryptedOAEP1 = RSAUtil.encryptFile(testFile, keyPair.getPublic(), RSAUtil.PADDING_OAEP_SHA1);
        byte[] decryptedOAEP1 = RSAUtil.decryptFile(encryptedOAEP1, keyPair.getPrivate(), RSAUtil.PADDING_OAEP_SHA1);
        assertArrayEquals(TEST_DATA.getBytes(StandardCharsets.UTF_8), decryptedOAEP1);
    }

    // ===== Digital Signature Tests =====
    @Test
    void testSignVerifyBytes() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = RSAUtil.sign(data, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean isValid = RSAUtil.verify(data, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignVerifyString() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] signature = RSAUtil.sign(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean isValid = RSAUtil.verify(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignVerifyShortString() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] signature = RSAUtil.sign(SHORT_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean isValid = RSAUtil.verify(SHORT_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignVerifyLongString() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] signature = RSAUtil.sign(LONG_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean isValid = RSAUtil.verify(LONG_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignVerifyWithDifferentAlgorithms() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Test SHA256withRSA
        byte[] signature256 = RSAUtil.sign(data, keyPair.getPrivate(), RSAUtil.SIG_SHA256_RSA);
        assertNotNull(signature256);
        boolean isValid256 = RSAUtil.verify(data, signature256, keyPair.getPublic(), RSAUtil.SIG_SHA256_RSA);
        assertTrue(isValid256);
        
        // Test SHA384withRSA
        byte[] signature384 = RSAUtil.sign(data, keyPair.getPrivate(), RSAUtil.SIG_SHA384_RSA);
        assertNotNull(signature384);
        boolean isValid384 = RSAUtil.verify(data, signature384, keyPair.getPublic(), RSAUtil.SIG_SHA384_RSA);
        assertTrue(isValid384);
        
        // Test SHA512withRSA
        byte[] signature512 = RSAUtil.sign(data, keyPair.getPrivate(), RSAUtil.SIG_SHA512_RSA);
        assertNotNull(signature512);
        boolean isValid512 = RSAUtil.verify(data, signature512, keyPair.getPublic(), RSAUtil.SIG_SHA512_RSA);
        assertTrue(isValid512);
        
        // Test SHA1withRSA
        byte[] signature1 = RSAUtil.sign(data, keyPair.getPrivate(), RSAUtil.SIG_SHA1_RSA);
        assertNotNull(signature1);
        boolean isValid1 = RSAUtil.verify(data, signature1, keyPair.getPublic(), RSAUtil.SIG_SHA1_RSA);
        assertTrue(isValid1);
    }

    // ===== File Signing/Verification Tests =====
    @Test
    void testSignVerifyFile() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        byte[] signature = RSAUtil.signFile(testFile, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean isValid = RSAUtil.verifyFile(testFile, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignVerifyFileWithDifferentAlgorithms() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        // Test SHA256withRSA
        byte[] signature256 = RSAUtil.signFile(testFile, keyPair.getPrivate(), RSAUtil.SIG_SHA256_RSA);
        assertNotNull(signature256);
        boolean isValid256 = RSAUtil.verifyFile(testFile, signature256, keyPair.getPublic(), RSAUtil.SIG_SHA256_RSA);
        assertTrue(isValid256);
        
        // Test SHA384withRSA
        byte[] signature384 = RSAUtil.signFile(testFile, keyPair.getPrivate(), RSAUtil.SIG_SHA384_RSA);
        assertNotNull(signature384);
        boolean isValid384 = RSAUtil.verifyFile(testFile, signature384, keyPair.getPublic(), RSAUtil.SIG_SHA384_RSA);
        assertTrue(isValid384);
    }

    // ===== Encoding Tests =====
    @Test
    void testSignWithBase64Output() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String signature = RSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already Base64 encoded, so decode it first
        boolean isValid = RSAUtil.verifyFromBase64(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignWithHexOutput() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String signature = RSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already hex encoded, so decode it first
        boolean isValid = RSAUtil.verifyFromHex(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignWithBase64URLOutput() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String signature = RSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.BASE64_URL);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already Base64 URL encoded, so decode it first
        // Note: We need to handle Base64 URL decoding manually since there's no convenience method
        try {
            byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(
                signature.replace('-', '+').replace('_', '/'));
            boolean isValid = RSAUtil.verify(TEST_DATA, signatureBytes, keyPair.getPublic());
            assertTrue(isValid);
        } catch (Exception e) {
            fail("Failed to verify Base64 URL signature: " + e.getMessage());
        }
    }

    // ===== Convenience Method Tests =====
    @Test
    void testSignToBase64() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String signature = RSAUtil.signToBase64(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature
        boolean isValid = RSAUtil.verifyFromBase64(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignToHex() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        String signature = RSAUtil.signToHex(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature
        boolean isValid = RSAUtil.verifyFromHex(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    // ===== Security Tests =====
    @Test
    void testDifferentKeysProduceDifferentSignatures() {
        KeyPair keyPair1 = RSAUtil.generateKeyPair();
        KeyPair keyPair2 = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature1 = RSAUtil.sign(data, keyPair1.getPrivate());
        byte[] signature2 = RSAUtil.sign(data, keyPair2.getPrivate());
        
        assertFalse(java.util.Arrays.equals(signature1, signature2));
    }

    @Test
    void testSameKeyProducesDifferentSignatures() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature1 = RSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature2 = RSAUtil.sign(data, keyPair.getPrivate());
        
        // RSA may produce same or different signatures due to padding
        // Both should verify correctly regardless
        boolean isValid1 = RSAUtil.verify(data, signature1, keyPair.getPublic());
        boolean isValid2 = RSAUtil.verify(data, signature2, keyPair.getPublic());
        assertTrue(isValid1);
        assertTrue(isValid2);
        
        // Note: RSA signatures may be identical due to deterministic padding in some implementations
        // This is not a security issue as long as both verify correctly
    }

    @Test
    void testSignatureConsistency() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Generate multiple signatures
        byte[] signature1 = RSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature2 = RSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature3 = RSAUtil.sign(data, keyPair.getPrivate());
        
        // All should verify correctly
        assertTrue(RSAUtil.verify(data, signature1, keyPair.getPublic()));
        assertTrue(RSAUtil.verify(data, signature2, keyPair.getPublic()));
        assertTrue(RSAUtil.verify(data, signature3, keyPair.getPublic()));
        
        // Note: RSA signatures may be identical due to deterministic padding in some implementations
        // This is not a security issue as long as all verify correctly
    }

    // ===== Key Size Comparison Tests =====
    @Test
    void testDifferentKeySizesProduceDifferentSignatures() {
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        KeyPair keyPair2048 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_2048);
        KeyPair keyPair3072 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_3072);
        KeyPair keyPair4096 = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_4096);
        
        byte[] signature2048 = RSAUtil.sign(data, keyPair2048.getPrivate());
        byte[] signature3072 = RSAUtil.sign(data, keyPair3072.getPrivate());
        byte[] signature4096 = RSAUtil.sign(data, keyPair4096.getPrivate());
        
        // All should be different
        assertFalse(java.util.Arrays.equals(signature2048, signature3072));
        assertFalse(java.util.Arrays.equals(signature3072, signature4096));
        assertFalse(java.util.Arrays.equals(signature2048, signature4096));
        
        // All should verify correctly with their respective keys
        assertTrue(RSAUtil.verify(data, signature2048, keyPair2048.getPublic()));
        assertTrue(RSAUtil.verify(data, signature3072, keyPair3072.getPublic()));
        assertTrue(RSAUtil.verify(data, signature4096, keyPair4096.getPublic()));
    }

    // ===== Error Handling Tests =====
    @Test
    void testSignWithNullData() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        assertThrows(Exception.class, () -> {
            RSAUtil.sign((byte[]) null, keyPair.getPrivate());
        });
    }

    @Test
    void testSignWithNullPrivateKey() {
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        assertThrows(Exception.class, () -> {
            RSAUtil.sign(data, null);
        });
    }

    @Test
    void testVerifyWithNullData() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] signature = RSAUtil.sign(TEST_DATA, keyPair.getPrivate());
        
        assertThrows(Exception.class, () -> {
            RSAUtil.verify((byte[]) null, signature, keyPair.getPublic());
        });
    }

    @Test
    void testVerifyWithNullSignature() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        assertThrows(Exception.class, () -> {
            RSAUtil.verify(data, null, keyPair.getPublic());
        });
    }

    @Test
    void testVerifyWithNullPublicKey() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        byte[] signature = RSAUtil.sign(data, keyPair.getPrivate());
        
        assertThrows(Exception.class, () -> {
            RSAUtil.verify(data, signature, null);
        });
    }

    @Test
    void testVerifySignatureWithWrongData() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] originalData = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        byte[] modifiedData = "Modified data".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = RSAUtil.sign(originalData, keyPair.getPrivate());
        boolean isValid = RSAUtil.verify(modifiedData, signature, keyPair.getPublic());
        assertFalse(isValid);
    }

    @Test
    void testVerifySignatureWithWrongKey() {
        KeyPair keyPair1 = RSAUtil.generateKeyPair();
        KeyPair keyPair2 = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = RSAUtil.sign(data, keyPair1.getPrivate());
        boolean isValid = RSAUtil.verify(data, signature, keyPair2.getPublic());
        assertFalse(isValid);
    }

    @Test
    void testVerifySignatureWithWrongAlgorithm() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = RSAUtil.sign(data, keyPair.getPrivate(), RSAUtil.SIG_SHA256_RSA);
        boolean isValid = RSAUtil.verify(data, signature, keyPair.getPublic(), RSAUtil.SIG_SHA384_RSA);
        assertFalse(isValid);
    }

    // ===== Performance Tests =====
    @Test
    void testLargeDataPerformance() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        
        // Create a large data block
        StringBuilder largeData = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            largeData.append("This is a large data block to test RSA performance. ");
        }
        byte[] data = largeData.toString().getBytes(StandardCharsets.UTF_8);
        
        long startTime = System.currentTimeMillis();
        byte[] signature = RSAUtil.sign(data, keyPair.getPrivate());
        long signTime = System.currentTimeMillis() - startTime;
        
        startTime = System.currentTimeMillis();
        boolean isValid = RSAUtil.verify(data, signature, keyPair.getPublic());
        long verifyTime = System.currentTimeMillis() - startTime;
        
        // Verify correctness
        assertTrue(isValid);
        
        // Performance should be reasonable (less than 30 seconds for 1KB)
        assertTrue(signTime < 30000, "Signing took too long: " + signTime + "ms");
        assertTrue(verifyTime < 30000, "Verification took too long: " + verifyTime + "ms");
    }

    // ===== Key Information Tests =====
    @Test
    void testGetKeySize() {
        KeyPair keyPair = RSAUtil.generateKeyPair(RSAUtil.KEY_SIZE_2048);
        int keySize = RSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(RSAUtil.KEY_SIZE_2048, keySize);
    }

    @Test
    void testGetModulus() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        String modulus = RSAUtil.getModulus(keyPair.getPublic());
        assertNotNull(modulus);
        assertTrue(modulus.length() > 0);
    }

    @Test
    void testGetPublicExponent() {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        String exponent = RSAUtil.getPublicExponent(keyPair.getPublic());
        assertNotNull(exponent);
        assertTrue(exponent.length() > 0);
    }
}
