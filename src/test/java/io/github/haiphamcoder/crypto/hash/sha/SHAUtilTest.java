package io.github.haiphamcoder.crypto.hash.sha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;

class SHAUtilTest {
    private static final String MSG = "The quick brown fox jumps over the lazy dog";
    private static final String KEY = "secret";

    @Test
    void testSHA1_basic() {
        byte[] d = SHAUtil.sha1(MSG);
        assertNotNull(d);
        assertEquals(20, d.length); // 160-bit
    }

    @Test
    void testSHA256_basic() {
        byte[] d = SHAUtil.sha256(MSG);
        assertNotNull(d);
        assertEquals(32, d.length); // 256-bit
    }

    @Test
    void testSHA384_basic() {
        byte[] d = SHAUtil.sha384(MSG);
        assertNotNull(d);
        assertEquals(48, d.length); // 384-bit
    }

    @Test
    void testSHA512_basic() {
        byte[] d = SHAUtil.sha512(MSG);
        assertNotNull(d);
        assertEquals(64, d.length); // 512-bit
    }

    @Test
    void testSHA256_encoding() {
        String b64 = SHAUtil.sha256(MSG, InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(b64);
    }

    @Test
    void testHMAC_SHA256_encoding() {
        String hex = SHAUtil.hmacSha256(MSG, KEY, InputEncoding.UTF8, InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
        assertNotNull(hex);
        assertEquals(64, hex.length()); // 32 bytes -> 64 hex chars
    }
}
