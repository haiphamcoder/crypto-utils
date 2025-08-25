package com.haiphamcoder.crypto.encoding;

/**
 * Output encodings for presenting hash/CRC results.
 * 
 * <p>This enum defines the various output formats that can be used to present
 * the results of CRC computations and other cryptographic operations.</p>
 * 
 * <p>Supported encodings:</p>
 * <ul>
 *   <li><b>HEX_LOWER</b>: Lowercase hexadecimal (e.g., "bb3d" for 0xBB3D)</li>
 *   <li><b>HEX_UPPER</b>: Uppercase hexadecimal (e.g., "BB3D" for 0xBB3D)</li>
 *   <li><b>BASE64</b>: Standard Base64 encoding (e.g., "u70=" for 0xBB3D)</li>
 *   <li><b>BASE64_URL</b>: URL-safe Base64 encoding (uses - and _ instead of + and /)</li>
 * </ul>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * // Get CRC result in different formats
 * String hexLower = CRCUtil.crc16Arc("123456789", InputEncoding.UTF8, OutputEncoding.HEX_LOWER);
 * String hexUpper = CRCUtil.crc16Arc("123456789", InputEncoding.UTF8, OutputEncoding.HEX_UPPER);
 * String base64 = CRCUtil.crc16Arc("123456789", InputEncoding.UTF8, OutputEncoding.BASE64);
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public enum OutputEncoding {
    HEX_LOWER,
    HEX_UPPER,
    BASE64,
    BASE64_URL
}
