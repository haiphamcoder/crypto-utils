package io.github.haiphamcoder.crypto.hash.keccak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;

class KeccakUtilTest {
    private static final String MSG = "Hello Keccak";

    @Test
    void testKeccak256_basic() {
        byte[] d = KeccakUtil.keccak256(MSG);
        assertNotNull(d);
        assertEquals(32, d.length);
    }

    @Test
    void testKeccak384_basic() {
        byte[] d = KeccakUtil.keccak384(MSG);
        assertNotNull(d);
        assertEquals(48, d.length);
    }

    @Test
    void testKeccak512_basic() {
        byte[] d = KeccakUtil.keccak512(MSG);
        assertNotNull(d);
        assertEquals(64, d.length);
    }

    @Test
    void testKeccak256_encoding() {
        String b64 = KeccakUtil.keccak256(MSG, InputEncoding.UTF8, OutputEncoding.BASE64);
        assertNotNull(b64);
    }
}
