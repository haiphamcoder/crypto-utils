package haiphamcoder.crypto.hash.crc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.hash.crc.CRCUtil;

/**
 * Unit tests for CRC variants using well-known test vectors.
 * 
 * <p>This test class validates the CRC implementations against standard test vectors
 * for the "123456789" input string. These test vectors are widely recognized
 * in the CRC community and are used to verify algorithm correctness.</p>
 * 
 * <p>Test vectors used:</p>
 * <ul>
 *   <li>CRC-7/MMC: 0x75</li>
 *   <li>CRC-8/SMBUS: 0xF4</li>
 *   <li>CRC-10/ATM: 0x199</li>
 *   <li>CRC-11/FLEXRAY: 0x5A3</li>
 *   <li>CRC-15/CAN: 0x059E</li>
 *   <li>CRC-16/ARC: 0xBB3D</li>
 *   <li>CRC-24/OPENPGP: 0x21CF02</li>
 *   <li>CRC-32/ISO-HDLC: 0xCBF43926</li>
 *   <li>CRC-64/ECMA-182: 0x6C40DF5F0B497347</li>
 * </ul>
 * 
 * <p>Reference: These values are computed using the standard CRC parameters
 * defined in CRCPresets and should match implementations in other CRC libraries.</p>
 * 
 * <p>The test data "123456789" is a standard test vector used across many
 * CRC implementations and specifications for validation purposes.</p>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
class CRCUtilTest {
    private static final byte[] ABC = "123456789".getBytes(StandardCharsets.US_ASCII);

    @Test
    void testCRC7_MMC() {
        long crc = CRCUtil.crc7Mmc(ABC);
        assertEquals(0x75, crc);
    }

    @Test
    void testCRC8_SMBUS() {
        long crc = CRCUtil.crc8Smbus(ABC);
        assertEquals(0xF4, crc);
    }

    @Test
    void testCRC10_ATM() {
        long crc = CRCUtil.crc10Atm(ABC);
        assertEquals(0x199, crc);
    }

    @Test
    void testCRC11_FLEXRAY() {
        long crc = CRCUtil.crc11Flexray(ABC);
        assertEquals(0x5A3, crc);
    }

    @Test
    void testCRC15_CAN() {
        long crc = CRCUtil.crc15Can(ABC);
        assertEquals(0x059E, crc);
    }

    @Test
    void testCRC16_ARC() {
        long crc = CRCUtil.crc16Arc(ABC);
        assertEquals(0xBB3D, crc);
    }

    @Test
    void testCRC24_OPENPGP() {
        long crc = CRCUtil.crc24OpenPgp(ABC);
        assertEquals(0x21CF02, crc);
    }

    @Test
    void testCrc16Arc_HexInput_HexLower() {
        String out = CRCUtil.crc16Arc("313233343536373839", InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        assertEquals("bb3d", out);
    }

    @Test
    void testCrc24OpenPgp_Utf8_Base64() {
        String out = CRCUtil.crc24OpenPgp("123456789", InputEncoding.UTF8, OutputEncoding.BASE64);
        // 0x21CF02 -> bytes [0x21,0xCF,0x02] -> Base64 "Ic8C"
        assertEquals("Ic8C", out);
    }

    @Test
    void testCRC32_ISO_HDLC() {
        long crc = CRCUtil.crc32IsoHdlc(ABC);
        assertEquals(0xCBF43926L, crc);
    }

    @Test
    void testCRC64_ECMA_182() {
        long crc = CRCUtil.crc64Ecma182(ABC);
        assertEquals(0x6C40DF5F0B497347L, crc);
    }

    // ===== Short alias method tests =====

    @Test
    void testShortAlias_crc7() {
        long crc = CRCUtil.crc7(ABC);
        assertEquals(0x75, crc);
    }

    @Test
    void testShortAlias_crc8() {
        long crc = CRCUtil.crc8(ABC);
        assertEquals(0xF4, crc);
    }

    @Test
    void testShortAlias_crc16() {
        long crc = CRCUtil.crc16(ABC);
        assertEquals(0xBB3D, crc);
    }

    @Test
    void testShortAlias_crc32() {
        long crc = CRCUtil.crc32(ABC);
        assertEquals(0xCBF43926L, crc);
    }

    @Test
    void testShortAlias_crc64() {
        long crc = CRCUtil.crc64(ABC);
        assertEquals(0x6C40DF5F0B497347L, crc);
    }

    @Test
    void testShortAliasFormatted_crc16_hex() {
        String out = CRCUtil.crc16("313233343536373839", InputEncoding.HEX, OutputEncoding.HEX_LOWER);
        assertEquals("bb3d", out);
    }
}
