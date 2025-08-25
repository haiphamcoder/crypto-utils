package haiphamcoder.crypto.hash.blake;

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
import com.haiphamcoder.crypto.hash.blake.BLAKEUtil;

class BLAKEUtilTest {

    @TempDir
    java.nio.file.Path tempDir;
    private File testFile;
    private static final String TEST_DATA = "123456789";

    @BeforeEach
    void setUp() throws IOException {
        testFile = tempDir.resolve("test.txt").toFile();
        Files.write(testFile.toPath(), TEST_DATA.getBytes(StandardCharsets.UTF_8));
    }

    // ===== BLAKE2b-256 Tests =====
    @Test
    void testBlake2b256() {
        byte[] result = BLAKEUtil.blake2b256(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length); // BLAKE2b-256 produces 32 bytes
    }

    @Test
    void testBlake2b256String() {
        byte[] result = BLAKEUtil.blake2b256(TEST_DATA);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2b256Charset() {
        byte[] result = BLAKEUtil.blake2b256(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2b256File() {
        byte[] result = BLAKEUtil.blake2b256(testFile);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2b256Hex() {
        String result = BLAKEUtil.blake2b256Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(64, result.length()); // 32 bytes = 64 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b256HexString() {
        String result = BLAKEUtil.blake2b256Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b256HexCharset() {
        String result = BLAKEUtil.blake2b256Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b256HexFile() {
        String result = BLAKEUtil.blake2b256Hex(testFile);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b256Encoding() {
        String result = BLAKEUtil.blake2b256(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== BLAKE2b-512 Tests =====
    @Test
    void testBlake2b512() {
        byte[] result = BLAKEUtil.blake2b512(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(64, result.length); // BLAKE2b-512 produces 64 bytes
    }

    @Test
    void testBlake2b512String() {
        byte[] result = BLAKEUtil.blake2b512(TEST_DATA);
        assertNotNull(result);
        assertEquals(64, result.length);
    }

    @Test
    void testBlake2b512Charset() {
        byte[] result = BLAKEUtil.blake2b512(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(64, result.length);
    }

    @Test
    void testBlake2b512File() {
        byte[] result = BLAKEUtil.blake2b512(testFile);
        assertNotNull(result);
        assertEquals(64, result.length);
    }

    @Test
    void testBlake2b512Hex() {
        String result = BLAKEUtil.blake2b512Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(128, result.length()); // 64 bytes = 128 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b512HexString() {
        String result = BLAKEUtil.blake2b512Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b512HexCharset() {
        String result = BLAKEUtil.blake2b512Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b512HexFile() {
        String result = BLAKEUtil.blake2b512Hex(testFile);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2b512Encoding() {
        String result = BLAKEUtil.blake2b512(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== BLAKE2s-128 Tests =====
    @Test
    void testBlake2s128() {
        byte[] result = BLAKEUtil.blake2s128(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(16, result.length); // BLAKE2s-128 produces 16 bytes
    }

    @Test
    void testBlake2s128String() {
        byte[] result = BLAKEUtil.blake2s128(TEST_DATA);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testBlake2s128Charset() {
        byte[] result = BLAKEUtil.blake2s128(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testBlake2s128File() {
        byte[] result = BLAKEUtil.blake2s128(testFile);
        assertNotNull(result);
        assertEquals(16, result.length);
    }

    @Test
    void testBlake2s128Hex() {
        String result = BLAKEUtil.blake2s128Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length()); // 16 bytes = 32 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s128HexString() {
        String result = BLAKEUtil.blake2s128Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s128HexCharset() {
        String result = BLAKEUtil.blake2s128Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s128HexFile() {
        String result = BLAKEUtil.blake2s128Hex(testFile);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s128Encoding() {
        String result = BLAKEUtil.blake2s128(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(32, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== BLAKE2s-256 Tests =====
    @Test
    void testBlake2s256() {
        byte[] result = BLAKEUtil.blake2s256(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(32, result.length); // BLAKE2s-256 produces 32 bytes
    }

    @Test
    void testBlake2s256String() {
        byte[] result = BLAKEUtil.blake2s256(TEST_DATA);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2s256Charset() {
        byte[] result = BLAKEUtil.blake2s256(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2s256File() {
        byte[] result = BLAKEUtil.blake2s256(testFile);
        assertNotNull(result);
        assertEquals(32, result.length);
    }

    @Test
    void testBlake2s256Hex() {
        String result = BLAKEUtil.blake2s256Hex(TEST_DATA.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result);
        assertEquals(64, result.length()); // 32 bytes = 64 hex chars
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s256HexString() {
        String result = BLAKEUtil.blake2s256Hex(TEST_DATA);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s256HexCharset() {
        String result = BLAKEUtil.blake2s256Hex(TEST_DATA, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s256HexFile() {
        String result = BLAKEUtil.blake2s256Hex(testFile);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    @Test
    void testBlake2s256Encoding() {
        String result = BLAKEUtil.blake2s256(TEST_DATA, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("[0-9a-f]+"));
    }

    // ===== Consistency Tests =====
    @Test
    void testConsistency() {
        // Same input should produce same output
        byte[] result1 = BLAKEUtil.blake2b256(TEST_DATA);
        byte[] result2 = BLAKEUtil.blake2b256(TEST_DATA);
        assertArrayEquals(result1, result2);
    }
}
