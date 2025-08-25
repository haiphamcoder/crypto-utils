package haiphamcoder.crypto.hash.md;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.hash.md.MDUtil;

/**
 * Unit tests for MD family utilities (MD2, MD4, MD5) and HMAC.
 */
class MDUtilTest {
    private static final String TEST_STRING = "Hello World";
    private static final String TEST_KEY = "secret";

    @Test
    void testMD2() {
        byte[] hash = MDUtil.md2(TEST_STRING);
        assertNotNull(hash);
        assertEquals(16, hash.length); // MD2 produces 128-bit (16-byte) hash
    }

    @Test
    void testMD2WithEncoding() {
        String hexHash = MDUtil.md2("48656C6C6F20576F726C64", InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        assertNotNull(hexHash);
        assertEquals(32, hexHash.length()); // 16 bytes = 32 hex chars
    }

    @Test
    void testMD4() {
        byte[] hash = MDUtil.md4(TEST_STRING);
        assertNotNull(hash);
        assertEquals(16, hash.length); // MD4 produces 128-bit (16-byte) hash
    }

    @Test
    void testMD4WithEncoding() {
        String base64Hash = MDUtil.md4("Hello World", InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(base64Hash);
    }

    @Test
    void testMD5() {
        byte[] hash = MDUtil.md5(TEST_STRING);
        assertNotNull(hash);
        assertEquals(16, hash.length); // MD5 produces 128-bit (16-byte) hash
    }

    @Test
    void testMD5WithEncoding() {
        String hexHash = MDUtil.md5("Hello World", InputEncoding.UTF8, OutputEncoding.HEX_UPPER);
        assertNotNull(hexHash);
        assertEquals(32, hexHash.length()); // 16 bytes = 32 hex chars
    }

    @Test
    void testHMACMD5() {
        byte[] hmac = MDUtil.hmacMd5(TEST_STRING, TEST_KEY);
        assertNotNull(hmac);
        assertEquals(16, hmac.length); // HMAC-MD5 produces 128-bit (16-byte) output
    }

    @Test
    void testHMACMD5WithEncoding() {
        String hmacHex = MDUtil.hmacMd5("Hello World", "secret", InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(hmacHex);
        assertEquals(32, hmacHex.length()); // 16 bytes = 32 hex chars
    }

    @Test
    void testMD5Hex() {
        String hexHash = MDUtil.md5Hex(TEST_STRING);
        assertNotNull(hexHash);
        assertEquals(32, hexHash.length());
    }

    @Test
    void testHMACMD5Hex() {
        String hmacHex = MDUtil.hmacMd5Hex(TEST_STRING, TEST_KEY);
        assertNotNull(hmacHex);
        assertEquals(32, hmacHex.length());
    }
}
