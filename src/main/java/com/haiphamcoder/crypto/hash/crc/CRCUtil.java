package com.haiphamcoder.crypto.hash.crc;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import com.haiphamcoder.crypto.encoding.EncodingUtil;
import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;

/**
 * High-level static APIs for CRC computations over bytes, strings and files.
 * 
 * <p>This utility class provides convenient static methods for computing CRC values
 * using predefined presets. It supports multiple input types (byte arrays, strings,
 * files) and provides both raw long results and formatted string outputs.</p>
 * 
 * <p>Available CRC variants:</p>
 * <ul>
 *   <li><b>CRC-7/MMC</b>: 7-bit CRC used in MultiMediaCard</li>
 *   <li><b>CRC-8/SMBUS</b>: 8-bit CRC used in System Management Bus</li>
 *   <li><b>CRC-10/ATM</b>: 10-bit CRC used in ATM</li>
 *   <li><b>CRC-11/FLEXRAY</b>: 11-bit CRC used in FlexRay</li>
 *   <li><b>CRC-15/CAN</b>: 15-bit CRC used in CAN</li>
 *   <li><b>CRC-16/ARC</b>: 16-bit CRC used in ARCnet and many protocols</li>
 *   <li><b>CRC-24/OPENPGP</b>: 24-bit CRC used in OpenPGP</li>
 *   <li><b>CRC-32/ISO-HDLC</b>: 32-bit CRC used in HDLC, Ethernet</li>
 *   <li><b>CRC-64/ECMA-182</b>: 64-bit CRC used in ECMA-182</li>
 * </ul>
 * 
 * <p>Usage examples:</p>
 * <pre>{@code
 * // Basic usage
 * long crc16 = CRCUtil.crc16Arc("Hello World");
 * 
 * // With custom encoding
 * String hexOut = CRCUtil.crc16Arc("313233343536373839", InputEncoding.HEX, OutputEncoding.HEX_LOWER);
 * 
 * // File processing
 * long fileCrc = CRCUtil.crc32IsoHdlc(new File("data.txt"));
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class CRCUtil {
    private CRCUtil() {
    }

    public static long crc7Mmc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC7_MMC);
    }

    public static long crc7Mmc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC7_MMC);
    }

    public static long crc7Mmc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC7_MMC);
    }

    public static long crc7Mmc(File f) {
        return CRC.compute(f, CRCPresets.CRC7_MMC);
    }

    public static long crc8Smbus(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC8_SMBUS);
    }

    public static long crc8Smbus(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC8_SMBUS);
    }

    public static long crc8Smbus(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC8_SMBUS);
    }

    public static long crc8Smbus(File f) {
        return CRC.compute(f, CRCPresets.CRC8_SMBUS);
    }

    public static long crc10Atm(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC10_ATM);
    }

    public static long crc10Atm(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC10_ATM);
    }

    public static long crc10Atm(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC10_ATM);
    }

    public static long crc10Atm(File f) {
        return CRC.compute(f, CRCPresets.CRC10_ATM);
    }

    public static long crc11Flexray(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC11_FLEXRAY);
    }

    public static long crc11Flexray(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC11_FLEXRAY);
    }

    public static long crc11Flexray(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC11_FLEXRAY);
    }

    public static long crc11Flexray(File f) {
        return CRC.compute(f, CRCPresets.CRC11_FLEXRAY);
    }

    public static long crc15Can(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC15_CAN);
    }

    public static long crc15Can(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC15_CAN);
    }

    public static long crc15Can(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC15_CAN);
    }

    public static long crc15Can(File f) {
        return CRC.compute(f, CRCPresets.CRC15_CAN);
    }

    public static long crc16Arc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC16_ARC);
    }

    public static long crc16Arc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC16_ARC);
    }

    public static long crc16Arc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC16_ARC);
    }

    public static long crc16Arc(File f) {
        return CRC.compute(f, CRCPresets.CRC16_ARC);
    }

    public static long crc24OpenPgp(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC24_OPENPGP);
    }

    public static long crc24OpenPgp(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC24_OPENPGP);
    }

    public static long crc24OpenPgp(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC24_OPENPGP);
    }

    public static long crc24OpenPgp(File f) {
        return CRC.compute(f, CRCPresets.CRC24_OPENPGP);
    }

    public static long crc32IsoHdlc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC32_ISO_HDLC);
    }

    public static long crc32IsoHdlc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC32_ISO_HDLC);
    }

    public static long crc32IsoHdlc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC32_ISO_HDLC);
    }

    public static long crc32IsoHdlc(File f) {
        return CRC.compute(f, CRCPresets.CRC32_ISO_HDLC);
    }

    public static long crc64Ecma182(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC64_ECMA_182);
    }

    public static long crc64Ecma182(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC64_ECMA_182);
    }

    public static long crc64Ecma182(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC64_ECMA_182);
    }

    public static long crc64Ecma182(File f) {
        return CRC.compute(f, CRCPresets.CRC64_ECMA_182);
    }

    // Formatted helpers (input string with specified encoding, output string
    // encoding)
    public static String crc7Mmc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc7Mmc(decode(input, in)), 7, out);
    }

    public static String crc8Smbus(String input, InputEncoding in, OutputEncoding out) {
        return format(crc8Smbus(decode(input, in)), 8, out);
    }

    public static String crc10Atm(String input, InputEncoding in, OutputEncoding out) {
        return format(crc10Atm(decode(input, in)), 10, out);
    }

    public static String crc11Flexray(String input, InputEncoding in, OutputEncoding out) {
        return format(crc11Flexray(decode(input, in)), 11, out);
    }

    public static String crc15Can(String input, InputEncoding in, OutputEncoding out) {
        return format(crc15Can(decode(input, in)), 15, out);
    }

    public static String crc16Arc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc16Arc(decode(input, in)), 16, out);
    }

    public static String crc24OpenPgp(String input, InputEncoding in, OutputEncoding out) {
        return format(crc24OpenPgp(decode(input, in)), 24, out);
    }

    public static String crc32IsoHdlc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc32IsoHdlc(decode(input, in)), 32, out);
    }

    public static String crc64Ecma182(String input, InputEncoding in, OutputEncoding out) {
        return format(crc64Ecma182(decode(input, in)), 64, out);
    }

    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }

    private static String format(long value, int width, OutputEncoding out) {
        int numBytes = (width + 7) / 8;
        byte[] bytes = new byte[numBytes];
        long masked = (width == 64) ? value : (value & ((1L << width) - 1));
        for (int i = numBytes - 1; i >= 0; i--) {
            bytes[i] = (byte) (masked & 0xFF);
            masked >>>= 8;
        }
        return EncodingUtil.encode(bytes, out);
    }
}
