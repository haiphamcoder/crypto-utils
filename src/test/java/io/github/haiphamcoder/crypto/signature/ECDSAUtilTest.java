package io.github.haiphamcoder.crypto.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;

class ECDSAUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private static final String TEST_DATA = "Hello, World! This is a test message for ECDSA signature.";
    private static final String SHORT_DATA = "Hi";
    private static final String LONG_DATA = "This is a very long message to test ECDSA signature with multiple blocks. "
            + "It contains enough data to ensure proper testing of the signature algorithm across different data sizes. "
            + "The message should be long enough to test streaming and buffering capabilities.";

    @BeforeEach
    void setUp() throws IOException {
        testFile = tempDir.resolve("test.txt").toFile();
        Files.write(testFile.toPath(), TEST_DATA.getBytes(StandardCharsets.UTF_8));
    }

    // ===== Key Generation Tests =====
    @Test
    void testGenerateKeyPairDefault() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        // Verify it's using the default curve
        String curveName = ECDSAUtil.getCurveName(keyPair.getPublic());
        assertTrue(curveName.contains("secp256r1"));
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(256, keySize);
    }

    @Test
    void testGenerateKeyPairSecp256r1() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP256R1);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        String curveName = ECDSAUtil.getCurveName(keyPair.getPublic());
        assertTrue(curveName.contains("secp256r1"));
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(256, keySize);
    }

    @Test
    void testGenerateKeyPairSecp384r1() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP384R1);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        String curveName = ECDSAUtil.getCurveName(keyPair.getPublic());
        assertTrue(curveName.contains("secp384r1"));
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(384, keySize);
    }

    @Test
    void testGenerateKeyPairSecp521r1() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP521R1);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        String curveName = ECDSAUtil.getCurveName(keyPair.getPublic());
        assertTrue(curveName.contains("secp521r1"));
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(521, keySize);
    }

    @Test
    void testGenerateKeyPairSecp256k1() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP256K1);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        String curveName = ECDSAUtil.getCurveName(keyPair.getPublic());
        assertTrue(curveName.contains("secp256k1"));
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(256, keySize);
    }

    @Test
    void testGenerateKeyPairWithSize() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair(256);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        
        int keySize = ECDSAUtil.getKeySize(keyPair.getPublic());
        assertEquals(256, keySize);
    }

    // ===== Signature Generation Tests =====
    @Test
    void testSignBytes() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = ECDSAUtil.sign(data, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verify(data, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignString() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        byte[] signature = ECDSAUtil.sign(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verify(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignShortString() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        byte[] signature = ECDSAUtil.sign(SHORT_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verify(SHORT_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignLongString() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        byte[] signature = ECDSAUtil.sign(LONG_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verify(LONG_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignWithDifferentAlgorithms() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Test SHA256withECDSA
        byte[] signature256 = ECDSAUtil.sign(data, keyPair.getPrivate(), ECDSAUtil.SIG_SHA256_ECDSA);
        assertNotNull(signature256);
        boolean isValid256 = ECDSAUtil.verify(data, signature256, keyPair.getPublic(), ECDSAUtil.SIG_SHA256_ECDSA);
        assertTrue(isValid256);
        
        // Test SHA384withECDSA
        byte[] signature384 = ECDSAUtil.sign(data, keyPair.getPrivate(), ECDSAUtil.SIG_SHA384_ECDSA);
        assertNotNull(signature384);
        boolean isValid384 = ECDSAUtil.verify(data, signature384, keyPair.getPublic(), ECDSAUtil.SIG_SHA384_ECDSA);
        assertTrue(isValid384);
        
        // Test SHA512withECDSA
        byte[] signature512 = ECDSAUtil.sign(data, keyPair.getPrivate(), ECDSAUtil.SIG_SHA512_ECDSA);
        assertNotNull(signature512);
        boolean isValid512 = ECDSAUtil.verify(data, signature512, keyPair.getPublic(), ECDSAUtil.SIG_SHA512_ECDSA);
        assertTrue(isValid512);
    }

    // ===== Signature Verification Tests =====
    @Test
    void testVerifySignature() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = ECDSAUtil.sign(data, keyPair.getPrivate());
        boolean isValid = ECDSAUtil.verify(data, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testVerifySignatureWithWrongData() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] originalData = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        byte[] modifiedData = "Modified data".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = ECDSAUtil.sign(originalData, keyPair.getPrivate());
        boolean isValid = ECDSAUtil.verify(modifiedData, signature, keyPair.getPublic());
        assertFalse(isValid);
    }

    @Test
    void testVerifySignatureWithWrongKey() {
        KeyPair keyPair1 = ECDSAUtil.generateKeyPair();
        KeyPair keyPair2 = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = ECDSAUtil.sign(data, keyPair1.getPrivate());
        boolean isValid = ECDSAUtil.verify(data, signature, keyPair2.getPublic());
        assertFalse(isValid);
    }

    @Test
    void testVerifySignatureWithWrongAlgorithm() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = ECDSAUtil.sign(data, keyPair.getPrivate(), ECDSAUtil.SIG_SHA256_ECDSA);
        boolean isValid = ECDSAUtil.verify(data, signature, keyPair.getPublic(), ECDSAUtil.SIG_SHA384_ECDSA);
        assertFalse(isValid);
    }

    // ===== File Operations Tests =====
    @Test
    void testSignFile() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        byte[] signature = ECDSAUtil.signFile(testFile, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify file signature
        boolean isValid = ECDSAUtil.verifyFile(testFile, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignFileWithDifferentAlgorithms() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        // Test SHA256withECDSA
        byte[] signature256 = ECDSAUtil.signFile(testFile, keyPair.getPrivate(), ECDSAUtil.SIG_SHA256_ECDSA);
        assertNotNull(signature256);
        boolean isValid256 = ECDSAUtil.verifyFile(testFile, signature256, keyPair.getPublic(), ECDSAUtil.SIG_SHA256_ECDSA);
        assertTrue(isValid256);
        
        // Test SHA384withECDSA
        byte[] signature384 = ECDSAUtil.signFile(testFile, keyPair.getPrivate(), ECDSAUtil.SIG_SHA384_ECDSA);
        assertNotNull(signature384);
        boolean isValid384 = ECDSAUtil.verifyFile(testFile, signature384, keyPair.getPublic(), ECDSAUtil.SIG_SHA384_ECDSA);
        assertTrue(isValid384);
    }

    @Test
    void testVerifyFileWithModifiedContent() throws IOException {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        // Sign original file
        byte[] signature = ECDSAUtil.signFile(testFile, keyPair.getPrivate());
        
        // Modify file content
        Files.write(testFile.toPath(), "Modified content".getBytes(StandardCharsets.UTF_8));
        
        // Verify should fail
        boolean isValid = ECDSAUtil.verifyFile(testFile, signature, keyPair.getPublic());
        assertFalse(isValid);
    }

    // ===== Encoding Tests =====
    @Test
    void testSignWithBase64Output() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        String signature = ECDSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already Base64 encoded, so decode it first
        boolean isValid = ECDSAUtil.verifyFromBase64(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignWithHexOutput() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        String signature = ECDSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already hex encoded, so decode it first
        boolean isValid = ECDSAUtil.verifyFromHex(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignWithBase64URLOutput() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        String signature = ECDSAUtil.sign(TEST_DATA, keyPair.getPrivate(), InputEncoding.UTF8, OutputEncoding.BASE64_URL);
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature - signature is already Base64 URL encoded, so decode it first
        // Note: We need to handle Base64 URL decoding manually since there's no convenience method
        try {
            byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(
                signature.replace('-', '+').replace('_', '/'));
            boolean isValid = ECDSAUtil.verify(TEST_DATA, signatureBytes, keyPair.getPublic());
            assertTrue(isValid);
        } catch (Exception e) {
            fail("Failed to verify Base64 URL signature: " + e.getMessage());
        }
    }

    // ===== Convenience Method Tests =====
    @Test
    void testSignToBase64() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        String signature = ECDSAUtil.signToBase64(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verifyFromBase64(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testSignToHex() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        String signature = ECDSAUtil.signToHex(TEST_DATA, keyPair.getPrivate());
        assertNotNull(signature);
        assertNotEquals(TEST_DATA, signature);
        
        // Verify signature
        boolean isValid = ECDSAUtil.verifyFromHex(TEST_DATA, signature, keyPair.getPublic());
        assertTrue(isValid);
    }

    // ===== Security Tests =====
    @Test
    void testDifferentKeysProduceDifferentSignatures() {
        KeyPair keyPair1 = ECDSAUtil.generateKeyPair();
        KeyPair keyPair2 = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature1 = ECDSAUtil.sign(data, keyPair1.getPrivate());
        byte[] signature2 = ECDSAUtil.sign(data, keyPair2.getPrivate());
        
        assertFalse(java.util.Arrays.equals(signature1, signature2));
    }

    @Test
    void testSameKeyProducesDifferentSignatures() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        byte[] signature1 = ECDSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature2 = ECDSAUtil.sign(data, keyPair.getPrivate());
        
        // ECDSA should produce different signatures due to random k value
        assertFalse(java.util.Arrays.equals(signature1, signature2));
        
        // But both should verify correctly
        boolean isValid1 = ECDSAUtil.verify(data, signature1, keyPair.getPublic());
        boolean isValid2 = ECDSAUtil.verify(data, signature2, keyPair.getPublic());
        assertTrue(isValid1);
        assertTrue(isValid2);
    }

    @Test
    void testSignatureConsistency() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        // Multiple signatures should be different but all valid
        byte[] signature1 = ECDSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature2 = ECDSAUtil.sign(data, keyPair.getPrivate());
        byte[] signature3 = ECDSAUtil.sign(data, keyPair.getPrivate());
        
        assertFalse(java.util.Arrays.equals(signature1, signature2));
        assertFalse(java.util.Arrays.equals(signature2, signature3));
        assertFalse(java.util.Arrays.equals(signature1, signature3));
        
        // All should verify correctly
        assertTrue(ECDSAUtil.verify(data, signature1, keyPair.getPublic()));
        assertTrue(ECDSAUtil.verify(data, signature2, keyPair.getPublic()));
        assertTrue(ECDSAUtil.verify(data, signature3, keyPair.getPublic()));
    }

    // ===== Curve Comparison Tests =====
    @Test
    void testDifferentCurvesProduceDifferentSignatures() {
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        KeyPair keyPair256 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP256R1);
        KeyPair keyPair384 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP384R1);
        KeyPair keyPair521 = ECDSAUtil.generateKeyPair(ECDSAUtil.CURVE_SECP521R1);
        
        byte[] signature256 = ECDSAUtil.sign(data, keyPair256.getPrivate());
        byte[] signature384 = ECDSAUtil.sign(data, keyPair384.getPrivate());
        byte[] signature521 = ECDSAUtil.sign(data, keyPair521.getPrivate());
        
        // All should be different
        assertFalse(java.util.Arrays.equals(signature256, signature384));
        assertFalse(java.util.Arrays.equals(signature384, signature521));
        assertFalse(java.util.Arrays.equals(signature256, signature521));
        
        // All should verify correctly with their respective keys
        assertTrue(ECDSAUtil.verify(data, signature256, keyPair256.getPublic()));
        assertTrue(ECDSAUtil.verify(data, signature384, keyPair384.getPublic()));
        assertTrue(ECDSAUtil.verify(data, signature521, keyPair521.getPublic()));
    }

    // ===== Error Handling Tests =====
    @Test
    void testSignWithNullData() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        assertThrows(Exception.class, () -> {
            ECDSAUtil.sign((byte[]) null, keyPair.getPrivate());
        });
    }

    @Test
    void testSignWithNullPrivateKey() {
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        assertThrows(Exception.class, () -> {
            ECDSAUtil.sign(data, null);
        });
    }

    @Test
    void testVerifyWithNullData() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] signature = ECDSAUtil.sign(TEST_DATA, keyPair.getPrivate());
        
        assertThrows(Exception.class, () -> {
            ECDSAUtil.verify((byte[]) null, signature, keyPair.getPublic());
        });
    }

    @Test
    void testVerifyWithNullSignature() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        
        assertThrows(Exception.class, () -> {
            ECDSAUtil.verify(data, null, keyPair.getPublic());
        });
    }

    @Test
    void testVerifyWithNullPublicKey() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        byte[] signature = ECDSAUtil.sign(data, keyPair.getPrivate());
        
        assertThrows(Exception.class, () -> {
            ECDSAUtil.verify(data, signature, null);
        });
    }

    // ===== Performance Tests =====
    @Test
    void testLargeDataPerformance() {
        KeyPair keyPair = ECDSAUtil.generateKeyPair();
        
        // Create a large data block
        StringBuilder largeData = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            largeData.append("This is a large data block to test ECDSA performance. ");
        }
        byte[] data = largeData.toString().getBytes(StandardCharsets.UTF_8);
        
        long startTime = System.currentTimeMillis();
        byte[] signature = ECDSAUtil.sign(data, keyPair.getPrivate());
        long signTime = System.currentTimeMillis() - startTime;
        
        startTime = System.currentTimeMillis();
        boolean isValid = ECDSAUtil.verify(data, signature, keyPair.getPublic());
        long verifyTime = System.currentTimeMillis() - startTime;
        
        // Verify correctness
        assertTrue(isValid);
        
        // Performance should be reasonable (less than 10 seconds for 10KB)
        assertTrue(signTime < 10000, "Signing took too long: " + signTime + "ms");
        assertTrue(verifyTime < 10000, "Verification took too long: " + verifyTime + "ms");
    }
}
