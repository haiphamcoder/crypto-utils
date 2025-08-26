package io.github.haiphamcoder.crypto.encoding;

/**
 * Input encodings supported for converting external data into bytes.
 * 
 * <p>This enum defines the various input formats that can be automatically
 * converted to byte arrays for CRC computation and other cryptographic operations.</p>
 * 
 * <p>Supported encodings:</p>
 * <ul>
 *   <li><b>HEX</b>: Hexadecimal string (e.g., "48656C6C6F" for "Hello")</li>
 *   <li><b>BASE64</b>: Base64 encoded string (e.g., "SGVsbG8=" for "Hello")</li>
 *   <li><b>BASE64_URL</b>: URL-safe Base64 (uses - and _ instead of + and /)</li>
 *   <li><b>UTF8</b>: UTF-8 encoded text</li>
 *   <li><b>UTF16_LE</b>: UTF-16 little-endian text</li>
 *   <li><b>UTF16_BE</b>: UTF-16 big-endian text</li>
 *   <li><b>ISO_8859_1</b>: ISO-8859-1 (Latin-1) encoding</li>
 *   <li><b>WINDOWS_1252</b>: Windows-1252 (Western European) encoding</li>
 * </ul>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * // Convert hex string to bytes for CRC computation
 * String hexInput = "313233343536373839";
 * long crc = CRCUtil.crc16Arc(hexInput, InputEncoding.HEX, OutputEncoding.HEX_LOWER);
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public enum InputEncoding {
    HEX,
    BASE64,
    BASE64_URL,
    UTF8,
    UTF16_LE,
    UTF16_BE,
    ISO_8859_1,
    US_ASCII,
    WINDOWS_1252
}
