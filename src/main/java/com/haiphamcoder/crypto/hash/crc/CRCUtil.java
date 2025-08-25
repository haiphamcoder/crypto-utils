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
 * 
 * // Short alias methods
 * long crc7 = CRCUtil.crc7("Hello");
 * long crc8 = CRCUtil.crc8("Hello");
 * long crc16 = CRCUtil.crc16("Hello");
 * long crc32 = CRCUtil.crc32("Hello");
 * long crc64 = CRCUtil.crc64("Hello");
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class CRCUtil {
    private CRCUtil() {
    }

    // ===== SHORT ALIAS METHODS =====

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc7(byte[] data) {
        return crc7Mmc(data);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc7(String s) {
        return crc7Mmc(s);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc7(String s, Charset cs) {
        return crc7Mmc(s, cs);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc7(File f) {
        return crc7Mmc(f);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc8(byte[] data) {
        return crc8Smbus(data);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc8(String s) {
        return crc8Smbus(s);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc8(String s, Charset cs) {
        return crc8Smbus(s, cs);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc8(File f) {
        return crc8Smbus(f);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc16(byte[] data) {
        return crc16Arc(data);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc16(String s) {
        return crc16Arc(s);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc16(String s, Charset cs) {
        return crc16Arc(s, cs);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc16(File f) {
        return crc16Arc(f);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc32(byte[] data) {
        return crc32IsoHdlc(data);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc32(String s) {
        return crc32IsoHdlc(s);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc32(String s, Charset cs) {
        return crc32IsoHdlc(s, cs);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc32(File f) {
        return crc32IsoHdlc(f);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc64(byte[] data) {
        return crc64Ecma182(data);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc64(String s) {
        return crc64Ecma182(s);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc64(String s, Charset cs) {
        return crc64Ecma182(s, cs);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc64(File f) {
        return crc64Ecma182(f);
    }

    // Formatted alias methods
    /**
     * Compute 7-bit CRC with custom encoding using CRC-7/MMC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc7(String input, InputEncoding in, OutputEncoding out) {
        return crc7Mmc(input, in, out);
    }

    /**
     * Compute 8-bit CRC with custom encoding using CRC-8/SMBUS preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc8(String input, InputEncoding in, OutputEncoding out) {
        return crc8Smbus(input, in, out);
    }

    /**
     * Compute 16-bit CRC with custom encoding using CRC-16/ARC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc16(String input, InputEncoding in, OutputEncoding out) {
        return crc16Arc(input, in, out);
    }

    /**
     * Compute 32-bit CRC with custom encoding using CRC-32/ISO-HDLC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc32(String input, InputEncoding in, OutputEncoding out) {
        return crc32IsoHdlc(input, in, out);
    }

    /**
     * Compute 64-bit CRC with custom encoding using CRC-64/ECMA-182 preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc64(String input, InputEncoding in, OutputEncoding out) {
        return crc64Ecma182(input, in, out);
    }

    // ===== SPECIFIC CRC METHODS =====

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc7Mmc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC7_MMC);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc7Mmc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC7_MMC);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc7Mmc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC7_MMC);
    }

    /**
     * Compute 7-bit CRC using CRC-7/MMC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc7Mmc(File f) {
        return CRC.compute(f, CRCPresets.CRC7_MMC);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc8Smbus(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC8_SMBUS);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc8Smbus(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC8_SMBUS);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc8Smbus(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC8_SMBUS);
    }

    /**
     * Compute 8-bit CRC using CRC-8/SMBUS preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc8Smbus(File f) {
        return CRC.compute(f, CRCPresets.CRC8_SMBUS);
    }

    /**
     * Compute 10-bit CRC using CRC-10/ATM preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc10Atm(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC10_ATM);
    }

    /**
     * Compute 10-bit CRC using CRC-10/ATM preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc10Atm(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC10_ATM);
    }

    /**
     * Compute 10-bit CRC using CRC-10/ATM preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc10Atm(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC10_ATM);
    }

    /**
     * Compute 10-bit CRC using CRC-10/ATM preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc10Atm(File f) {
        return CRC.compute(f, CRCPresets.CRC10_ATM);
    }

    /**
     * Compute 11-bit CRC using CRC-11/FLEXRAY preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc11Flexray(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC11_FLEXRAY);
    }

    /**
     * Compute 11-bit CRC using CRC-11/FLEXRAY preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc11Flexray(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC11_FLEXRAY);
    }

    /**
     * Compute 11-bit CRC using CRC-11/FLEXRAY preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc11Flexray(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC11_FLEXRAY);
    }

    /**
     * Compute 11-bit CRC using CRC-11/FLEXRAY preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc11Flexray(File f) {
        return CRC.compute(f, CRCPresets.CRC11_FLEXRAY);
    }

    /**
     * Compute 15-bit CRC using CRC-15/CAN preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc15Can(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC15_CAN);
    }

    /**
     * Compute 15-bit CRC using CRC-15/CAN preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc15Can(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC15_CAN);
    }

    /**
     * Compute 15-bit CRC using CRC-15/CAN preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc15Can(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC15_CAN);
    }

    /**
     * Compute 15-bit CRC using CRC-15/CAN preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc15Can(File f) {
        return CRC.compute(f, CRCPresets.CRC15_CAN);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc16Arc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC16_ARC);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc16Arc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC16_ARC);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc16Arc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC16_ARC);
    }

    /**
     * Compute 16-bit CRC using CRC-16/ARC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc16Arc(File f) {
        return CRC.compute(f, CRCPresets.CRC16_ARC);
    }

    /**
     * Compute 24-bit CRC using CRC-24/OPENPGP preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc24OpenPgp(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC24_OPENPGP);
    }

    /**
     * Compute 24-bit CRC using CRC-24/OPENPGP preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc24OpenPgp(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC24_OPENPGP);
    }

    /**
     * Compute 24-bit CRC using CRC-24/OPENPGP preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc24OpenPgp(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC24_OPENPGP);
    }

    /**
     * Compute 24-bit CRC using CRC-24/OPENPGP preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc24OpenPgp(File f) {
        return CRC.compute(f, CRCPresets.CRC24_OPENPGP);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc32IsoHdlc(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC32_ISO_HDLC);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc32IsoHdlc(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC32_ISO_HDLC);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc32IsoHdlc(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC32_ISO_HDLC);
    }

    /**
     * Compute 32-bit CRC using CRC-32/ISO-HDLC preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc32IsoHdlc(File f) {
        return CRC.compute(f, CRCPresets.CRC32_ISO_HDLC);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param data input data
     * @return CRC value
     */
    public static long crc64Ecma182(byte[] data) {
        return CRC.compute(data, CRCPresets.CRC64_ECMA_182);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param s input string (UTF-8 encoded)
     * @return CRC value
     */
    public static long crc64Ecma182(String s) {
        return CRC.compute(s, StandardCharsets.UTF_8, CRCPresets.CRC64_ECMA_182);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param s  input string
     * @param cs character encoding
     * @return CRC value
     */
    public static long crc64Ecma182(String s, Charset cs) {
        return CRC.compute(s, cs, CRCPresets.CRC64_ECMA_182);
    }

    /**
     * Compute 64-bit CRC using CRC-64/ECMA-182 preset.
     * 
     * @param f input file
     * @return CRC value
     */
    public static long crc64Ecma182(File f) {
        return CRC.compute(f, CRCPresets.CRC64_ECMA_182);
    }

    // Formatted helpers (input string with specified encoding, output string
    // encoding)
    /**
     * Compute 7-bit CRC with custom encoding using CRC-7/MMC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc7Mmc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc7Mmc(decode(input, in)), 7, out);
    }

    /**
     * Compute 8-bit CRC with custom encoding using CRC-8/SMBUS preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc8Smbus(String input, InputEncoding in, OutputEncoding out) {
        return format(crc8Smbus(decode(input, in)), 8, out);
    }

    /**
     * Compute 10-bit CRC with custom encoding using CRC-10/ATM preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc10Atm(String input, InputEncoding in, OutputEncoding out) {
        return format(crc10Atm(decode(input, in)), 10, out);
    }

    /**
     * Compute 11-bit CRC with custom encoding using CRC-11/FLEXRAY preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc11Flexray(String input, InputEncoding in, OutputEncoding out) {
        return format(crc11Flexray(decode(input, in)), 11, out);
    }

    /**
     * Compute 15-bit CRC with custom encoding using CRC-15/CAN preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc15Can(String input, InputEncoding in, OutputEncoding out) {
        return format(crc15Can(decode(input, in)), 15, out);
    }

    /**
     * Compute 16-bit CRC with custom encoding using CRC-16/ARC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc16Arc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc16Arc(decode(input, in)), 16, out);
    }

    /**
     * Compute 24-bit CRC with custom encoding using CRC-24/OPENPGP preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc24OpenPgp(String input, InputEncoding in, OutputEncoding out) {
        return format(crc24OpenPgp(decode(input, in)), 24, out);
    }

    /**
     * Compute 32-bit CRC with custom encoding using CRC-32/ISO-HDLC preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc32IsoHdlc(String input, InputEncoding in, OutputEncoding out) {
        return format(crc32IsoHdlc(decode(input, in)), 32, out);
    }

    /**
     * Compute 64-bit CRC with custom encoding using CRC-64/ECMA-182 preset.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted CRC string
     */
    public static String crc64Ecma182(String input, InputEncoding in, OutputEncoding out) {
        return format(crc64Ecma182(decode(input, in)), 64, out);
    }

    // Private helper methods
    /**
     * Decode a string to a byte array using the specified encoding.
     * 
     * @param input input string
     * @param in    input encoding
     * @return decoded byte array
     */
    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }

    /**
     * Format a CRC value as a string using the specified encoding.
     * 
     * @param value CRC value
     * @param width CRC width
     * @param out   output encoding
     * @return formatted CRC string
     */
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
