package haiphamcoder.crypto.hash.ripemd;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.hash.ripemd.RIPEMDUtil;

class RIPEMDUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private static final String TEST_DATA = "123456789";
    private static final String TEST_KEY = "secret";

    @BeforeEach
    void setUp() throws IOException {
        testFile = tempDir.resolve("test.txt").toFile();
        Files.write(testFile.toPath(), TEST_DATA.getBytes(StandardCharsets.UTF_8));
    }

    // ===== RIPEMD-128 Tests =====
    @Test
    void testRipemd128() {
        byte[] result = RIPEMDUtil.ripemd128(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(16, result.length); // RIPEMD-128 produces 16 bytes
    }

    @Test
    void testRipemd128String() {
        byte[] result = RIPEMDUtil.ripemd128(TEST_DATA);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testRipemd128Charset() {
        byte[] result = RIPEMDUtil.ripemd128(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testRipemd128File() {
        byte[] result = RIPEMDUtil.ripemd128(testFile);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testRipemd128Hex() {
        String result = RIPEMDUtil.ripemd128Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length()); // 16 bytes = 32 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd128HexString() {
        String result = RIPEMDUtil.ripemd128Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd128HexCharset() {
        String result = RIPEMDUtil.ripemd128Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd128HexFile() {
        String result = RIPEMDUtil.ripemd128Hex(testFile);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd128Encoding() {
        String result = RIPEMDUtil.ripemd128(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== RIPEMD-160 Tests =====
    @Test
    void testRipemd160() {
        byte[] result = RIPEMDUtil.ripemd160(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(20, result.length); // RIPEMD-160 produces 20 bytes
    }

    @Test
    void testRipemd160String() {
        byte[] result = RIPEMDUtil.ripemd160(TEST_DATA);
        assertNotNull(result);
        assertEquals(20, result.length);
    }

    @Test
    void testRipemd160Charset() {
        byte[] result = RIPEMDUtil.ripemd160(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(20, result.length);
    }

    @Test
    void testRipemd160File() {
        byte[] result = RIPEMDUtil.ripemd160(testFile);
        assertNotNull(result);
        assertEquals(20, result.length);
    }

    @Test
    void testRipemd160Hex() {
        String result = RIPEMDUtil.ripemd160Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(40, result.length()); // 20 bytes = 40 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd160HexString() {
        String result = RIPEMDUtil.ripemd160Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(40, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd160HexCharset() {
        String result = RIPEMDUtil.ripemd160Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(40, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd160HexFile() {
        String result = RIPEMDUtil.ripemd160Hex(testFile);
        assertNotNull(result);
        assertEquals(40, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd160Encoding() {
        String result = RIPEMDUtil.ripemd160(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(40, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== RIPEMD-256 Tests =====
    @Test
    void testRipemd256() {
        byte[] result = RIPEMDUtil.ripemd256(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length); // RIPEMD-256 produces 32 bytes
    }

    @Test
    void testRipemd256String() {
        byte[] result = RIPEMDUtil.ripemd256(TEST_DATA);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testRipemd256Charset() {
        byte[] result = RIPEMDUtil.ripemd256(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testRipemd256File() {
        byte[] result = RIPEMDUtil.ripemd256(testFile);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testRipemd256Hex() {
        String result = RIPEMDUtil.ripemd256Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(64, result.length()); // 32 bytes = 64 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd256HexString() {
        String result = RIPEMDUtil.ripemd256Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd256HexCharset() {
        String result = RIPEMDUtil.ripemd256Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd256HexFile() {
        String result = RIPEMDUtil.ripemd256Hex(testFile);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd256Encoding() {
        String result = RIPEMDUtil.ripemd256(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== RIPEMD-320 Tests =====
    @Test
    void testRipemd320() {
        byte[] result = RIPEMDUtil.ripemd320(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(40, result.length); // RIPEMD-320 produces 40 bytes
    }

    @Test
    void testRipemd320String() {
        byte[] result = RIPEMDUtil.ripemd320(TEST_DATA);
        assertNotNull(result);
        assertEquals(40, result.length);
    }

    @Test
    void testRipemd320Charset() {
        byte[] result = RIPEMDUtil.ripemd320(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(40, result.length);
    }

    @Test
    void testRipemd320File() {
        byte[] result = RIPEMDUtil.ripemd320(testFile);
        assertNotNull(result);
        assertEquals(40, result.length);
    }

    @Test
    void testRipemd320Hex() {
        String result = RIPEMDUtil.ripemd320Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(80, result.length()); // 40 bytes = 80 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd320HexString() {
        String result = RIPEMDUtil.ripemd320Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(80, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd320HexCharset() {
        String result = RIPEMDUtil.ripemd320Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(80, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd320HexFile() {
        String result = RIPEMDUtil.ripemd320Hex(testFile);
        assertNotNull(result);
        assertEquals(80, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testRipemd320Encoding() {
        String result = RIPEMDUtil.ripemd320(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(80, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== HMAC-RIPEMD Tests =====
    @Test
    void testHmacRipemd128() {
        byte[] result = RIPEMDUtil.hmacRipemd128(TEST_DATA.getBytes(StandardCharsets.UTF_8), TEST_KEY.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(16, result.length); // HMAC-RIPEMD128 produces 16 bytes
    }

    @Test
    void testHmacRipemd128String() {
        byte[] result = RIPEMDUtil.hmacRipemd128(TEST_DATA, TEST_KEY);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testHmacRipemd128Encoding() {
        String result = RIPEMDUtil.hmacRipemd128(TEST_DATA, TEST_KEY, InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testHmacRipemd160() {
        byte[] result = RIPEMDUtil.hmacRipemd160(TEST_DATA.getBytes(StandardCharsets.UTF_8), TEST_KEY.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(20, result.length); // HMAC-RIPEMD160 produces 20 bytes
    }

    @Test
    void testHmacRipemd160String() {
        byte[] result = RIPEMDUtil.hmacRipemd160(TEST_DATA, TEST_KEY);
        assertNotNull(result);
        assertEquals(20, result.length);
    }

    @Test
    void testHmacRipemd160Encoding() {
        String result = RIPEMDUtil.hmacRipemd160(TEST_DATA, TEST_KEY, InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(40, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testHmacRipemd256() {
        byte[] result = RIPEMDUtil.hmacRipemd256(TEST_DATA.getBytes(StandardCharsets.UTF_8), TEST_KEY.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length); // HMAC-RIPEMD256 produces 32 bytes
    }

    @Test
    void testHmacRipemd256String() {
        byte[] result = RIPEMDUtil.hmacRipemd256(TEST_DATA, TEST_KEY);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testHmacRipemd256Encoding() {
        String result = RIPEMDUtil.hmacRipemd256(TEST_DATA, TEST_KEY, InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testHmacRipemd320() {
        byte[] result = RIPEMDUtil.hmacRipemd320(TEST_DATA.getBytes(StandardCharsets.UTF_8), TEST_KEY.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(40, result.length); // HMAC-RIPEMD320 produces 40 bytes
    }

    @Test
    void testHmacRipemd320String() {
        byte[] result = RIPEMDUtil.hmacRipemd320(TEST_DATA, TEST_KEY);
        assertNotNull(result);
        assertEquals(40, result.length);
    }

    @Test
    void testHmacRipemd320Encoding() {
        String result = RIPEMDUtil.hmacRipemd320(TEST_DATA, TEST_KEY, InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(80, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== Consistency Tests =====
    @Test
    void testConsistency() {
        // Same input should produce same output
        byte[] result1 = RIPEMDUtil.ripemd160(TEST_DATA);
        byte[] result2 = RIPEMDUtil.ripemd160(TEST_DATA);
        assertArrayEquals(result1, result2);
    }

    @Test
    void testHmacConsistency() {
        // Same input and key should produce same HMAC
        byte[] result1 = RIPEMDUtil.hmacRipemd160(TEST_DATA, TEST_KEY);
        byte[] result2 = RIPEMDUtil.hmacRipemd160(TEST_DATA, TEST_KEY);
        assertArrayEquals(result1, result2);
    }

    @Test
    void testDifferentKeys() {
        // Different keys should produce different HMACs
        byte[] result1 = RIPEMDUtil.hmacRipemd160(TEST_DATA, "key1");
        byte[] result2 = RIPEMDUtil.hmacRipemd160(TEST_DATA, "key2");
        assertFalse(java.util.Arrays.equals(result1, result2));
    }
}
