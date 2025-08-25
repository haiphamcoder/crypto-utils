package com.haiphamcoder.crypto.encoding;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * Utilities for converting between encodings and bytes/strings.
 * 
 * <p>This utility class provides methods to convert data between different
 * input/output encodings and byte arrays. It supports various text encodings,
 * hexadecimal, and Base64 formats commonly used in cryptographic applications.</p>
 * 
 * <p>Key features:</p>
 * <ul>
 *   <li>Input decoding from various formats (HEX, Base64, text encodings)</li>
 *   <li>Output encoding to various formats (HEX, Base64)</li>
 *   <li>Automatic handling of whitespace in hex strings</li>
 *   <li>URL-safe Base64 support</li>
 *   <li>Comprehensive character encoding support</li>
 * </ul>
 * 
 * <p>Usage examples:</p>
 * <pre>{@code
 * // Decode hex string to bytes
 * byte[] bytes = EncodingUtil.decode("48656C6C6F", InputEncoding.HEX);
 * 
 * // Encode bytes to hex
 * String hex = EncodingUtil.encode(bytes, OutputEncoding.HEX_LOWER);
 * 
 * // Convert between Base64 variants
 * String urlSafe = EncodingUtil.encode(bytes, OutputEncoding.BASE64_URL);
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class EncodingUtil {
    private EncodingUtil() {
    }

    public static byte[] decode(String input, InputEncoding enc) {
        switch (enc) {
            case HEX:
                try {
                    return Hex.decodeHex(input.replaceAll("\\s+", "").toCharArray());
                } catch (Exception e) {
                    throw new IllegalArgumentException("Invalid hex input", e);
                }
            case BASE64:
                return Base64.decodeBase64(input);
            case BASE64_URL:
                return Base64.decodeBase64(toBase64Standard(input));
            case UTF8:
                return input.getBytes(StandardCharsets.UTF_8);
            case UTF16_LE:
                return input.getBytes(StandardCharsets.UTF_16LE);
            case UTF16_BE:
                return input.getBytes(StandardCharsets.UTF_16BE);
            case ISO_8859_1:
                return input.getBytes(StandardCharsets.ISO_8859_1);
            case US_ASCII:
                return input.getBytes(StandardCharsets.US_ASCII);
            case WINDOWS_1252:
                return input.getBytes(Charset.forName("windows-1252"));
            default:
                throw new IllegalArgumentException("Unsupported input encoding: " + enc);
        }
    }

    public static String encode(byte[] data, OutputEncoding enc) {
        switch (enc) {
            case HEX_LOWER:
                return Hex.encodeHexString(data, true);
            case HEX_UPPER:
                return new String(Hex.encodeHex(data, true));
            case BASE64:
                return Base64.encodeBase64String(data);
            case BASE64_URL:
                return toBase64Url(Base64.encodeBase64String(data));
            default:
                throw new IllegalArgumentException("Unsupported output encoding: " + enc);
        }
    }

    private static String toBase64Standard(String url) {
        return url.replace('-', '+').replace('_', '/');
    }

    private static String toBase64Url(String std) {
        return std.replace('+', '-').replace('/', '_');
    }
}
