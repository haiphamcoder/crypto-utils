package io.github.haiphamcoder.crypto.hash.md;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.haiphamcoder.crypto.encoding.EncodingUtil;
import io.github.haiphamcoder.crypto.encoding.InputEncoding;
import io.github.haiphamcoder.crypto.encoding.OutputEncoding;
import io.github.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for MD family digests (MD2, MD4, MD5) over bytes, strings, and files.
 *
 * <p>Provides both raw byte[] outputs and lowercase-hex helpers.
 * Also provides custom input/output encoding helpers and HMAC-MD5.</p>
 */
public final class MDUtil {
    private static final int BUFFER_SIZE = 64 * 1024;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private MDUtil() {
    }

    // ===== MD2 =====
    /**
     * Compute MD2 digest for the given bytes.
     *
     * @param data input data
     * @return 16-byte MD2 hash
     */
    public static byte[] md2(byte[] data) {
        return digest("MD2", null, data);
    }

    /**
     * Compute MD2 digest for a UTF-8 string.
     *
     * @param s input string (UTF-8)
     * @return 16-byte MD2 hash
     */
    public static byte[] md2(String s) {
        return md2(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute MD2 digest for a string with specified charset.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return 16-byte MD2 hash
     */
    public static byte[] md2(String s, Charset cs) {
        return md2(s.getBytes(cs));
    }

    /**
     * Compute MD2 digest for a file using streaming I/O.
     *
     * @param file input file
     * @return 16-byte MD2 hash
     * @throws CryptoException if file is missing or I/O errors occur
     */
    public static byte[] md2(File file) {
        return digestFile("MD2", null, file);
    }

    /**
     * Compute MD2 digest and return lowercase-hex string.
     *
     * @param data input data
     * @return hex string of MD2 hash
     */
    public static String md2Hex(byte[] data) {
        return Hex.encodeHexString(md2(data), true);
    }

    /**
     * Compute MD2 digest for a UTF-8 string, return lowercase-hex.
     *
     * @param s input string (UTF-8)
     * @return hex string of MD2 hash
     */
    public static String md2Hex(String s) {
        return Hex.encodeHexString(md2(s), true);
    }

    /**
     * Compute MD2 digest for a string with charset, return lowercase-hex.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return hex string of MD2 hash
     */
    public static String md2Hex(String s, Charset cs) {
        return Hex.encodeHexString(md2(s, cs), true);
    }

    /**
     * Compute MD2 digest for a file, return lowercase-hex.
     *
     * @param file input file
     * @return hex string of MD2 hash
     */
    public static String md2Hex(File file) {
        return Hex.encodeHexString(md2(file), true);
    }

    /**
     * Compute MD2 with custom input and output encodings.
     *
     * @param input input data as string
     * @param in    input encoding (how to decode the string)
     * @param out   output encoding (HEX lower/upper, Base64, Base64-URL)
     * @return formatted MD2 hash string
     */
    public static String md2(String input, InputEncoding in, OutputEncoding out) {
        return EncodingUtil.encode(md2(decode(input, in)), out);
    }

    // ===== MD4 (via BouncyCastle) =====
    /**
     * Compute MD4 digest for the given bytes.
     *
     * @param data input data
     * @return 16-byte MD4 hash
     */
    public static byte[] md4(byte[] data) {
        return digest("MD4", BouncyCastleProvider.PROVIDER_NAME, data);
    }

    /**
     * Compute MD4 digest for a UTF-8 string.
     *
     * @param s input string (UTF-8)
     * @return 16-byte MD4 hash
     */
    public static byte[] md4(String s) {
        return md4(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute MD4 digest for a string with specified charset.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return 16-byte MD4 hash
     */
    public static byte[] md4(String s, Charset cs) {
        return md4(s.getBytes(cs));
    }

    /**
     * Compute MD4 digest for a file using streaming I/O.
     *
     * @param file input file
     * @return 16-byte MD4 hash
     * @throws CryptoException if file is missing or I/O errors occur
     */
    public static byte[] md4(File file) {
        return digestFile("MD4", BouncyCastleProvider.PROVIDER_NAME, file);
    }

    /**
     * Compute MD4 digest and return lowercase-hex string.
     *
     * @param data input data
     * @return hex string of MD4 hash
     */
    public static String md4Hex(byte[] data) {
        return Hex.encodeHexString(md4(data), true);
    }

    /**
     * Compute MD4 digest for a UTF-8 string, return lowercase-hex.
     *
     * @param s input string (UTF-8)
     * @return hex string of MD4 hash
     */
    public static String md4Hex(String s) {
        return Hex.encodeHexString(md4(s), true);
    }

    /**
     * Compute MD4 digest for a string with charset, return lowercase-hex.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return hex string of MD4 hash
     */
    public static String md4Hex(String s, Charset cs) {
        return Hex.encodeHexString(md4(s, cs), true);
    }

    /**
     * Compute MD4 digest for a file, return lowercase-hex.
     *
     * @param file input file
     * @return hex string of MD4 hash
     */
    public static String md4Hex(File file) {
        return Hex.encodeHexString(md4(file), true);
    }

    /**
     * Compute MD4 with custom input and output encodings.
     *
     * @param input input data as string
     * @param in    input encoding (how to decode the string)
     * @param out   output encoding (HEX lower/upper, Base64, Base64-URL)
     * @return formatted MD4 hash string
     */
    public static String md4(String input, InputEncoding in, OutputEncoding out) {
        return EncodingUtil.encode(md4(decode(input, in)), out);
    }

    // ===== MD5 =====
    /**
     * Compute MD5 digest for the given bytes.
     *
     * @param data input data
     * @return 16-byte MD5 hash
     */
    public static byte[] md5(byte[] data) {
        return digest("MD5", null, data);
    }

    /**
     * Compute MD5 digest for a UTF-8 string.
     *
     * @param s input string (UTF-8)
     * @return 16-byte MD5 hash
     */
    public static byte[] md5(String s) {
        return md5(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute MD5 digest for a string with specified charset.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return 16-byte MD5 hash
     */
    public static byte[] md5(String s, Charset cs) {
        return md5(s.getBytes(cs));
    }

    /**
     * Compute MD5 digest for a file using streaming I/O.
     *
     * @param file input file
     * @return 16-byte MD5 hash
     * @throws CryptoException if file is missing or I/O errors occur
     */
    public static byte[] md5(File file) {
        return digestFile("MD5", null, file);
    }

    /**
     * Compute MD5 digest and return lowercase-hex string.
     *
     * @param data input data
     * @return hex string of MD5 hash
     */
    public static String md5Hex(byte[] data) {
        return Hex.encodeHexString(md5(data), true);
    }

    /**
     * Compute MD5 digest for a UTF-8 string, return lowercase-hex.
     *
     * @param s input string (UTF-8)
     * @return hex string of MD5 hash
     */
    public static String md5Hex(String s) {
        return Hex.encodeHexString(md5(s), true);
    }

    /**
     * Compute MD5 digest for a string with charset, return lowercase-hex.
     *
     * @param s  input string
     * @param cs charset to encode the string
     * @return hex string of MD5 hash
     */
    public static String md5Hex(String s, Charset cs) {
        return Hex.encodeHexString(md5(s, cs), true);
    }

    /**
     * Compute MD5 digest for a file, return lowercase-hex.
     *
     * @param file input file
     * @return hex string of MD5 hash
     */
    public static String md5Hex(File file) {
        return Hex.encodeHexString(md5(file), true);
    }

    /**
     * Compute MD5 with custom input and output encodings.
     *
     * @param input input data as string
     * @param in    input encoding (how to decode the string)
     * @param out   output encoding (HEX lower/upper, Base64, Base64-URL)
     * @return formatted MD5 hash string
     */
    public static String md5(String input, InputEncoding in, OutputEncoding out) {
        return EncodingUtil.encode(md5(decode(input, in)), out);
    }

    // ===== HMAC (MD5) =====
    /**
     * Compute HMAC-MD5 for raw bytes.
     *
     * @param data message bytes
     * @param key  secret key bytes
     * @return 16-byte HMAC output
     */
    public static byte[] hmacMd5(byte[] data, byte[] key) {
        return hmac("HmacMD5", data, key);
    }

    /**
     * Compute HMAC-MD5 for UTF-8 strings.
     *
     * @param data message string (UTF-8)
     * @param key  secret key string (UTF-8)
     * @return 16-byte HMAC output
     */
    public static byte[] hmacMd5(String data, String key) {
        return hmacMd5(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute HMAC-MD5 for strings with a shared charset.
     *
     * @param data message string
     * @param key  secret key string
     * @param cs   charset for both strings
     * @return 16-byte HMAC output
     */
    public static byte[] hmacMd5(String data, String key, Charset cs) {
        return hmacMd5(data.getBytes(cs), key.getBytes(cs));
    }

    /**
     * Compute HMAC-MD5 and return lowercase-hex.
     *
     * @param data message bytes
     * @param key  secret key bytes
     * @return hex string of HMAC-MD5
     */
    public static String hmacMd5Hex(byte[] data, byte[] key) {
        return Hex.encodeHexString(hmacMd5(data, key), true);
    }

    /**
     * Compute HMAC-MD5 for UTF-8 strings and return lowercase-hex.
     *
     * @param data message string (UTF-8)
     * @param key  secret key string (UTF-8)
     * @return hex string of HMAC-MD5
     */
    public static String hmacMd5Hex(String data, String key) {
        return Hex.encodeHexString(hmacMd5(data, key), true);
    }

    /**
     * Compute HMAC-MD5 for strings with a shared charset and return lowercase-hex.
     *
     * @param data message string
     * @param key  secret key string
     * @param cs   charset for both strings
     * @return hex string of HMAC-MD5
     */
    public static String hmacMd5Hex(String data, String key, Charset cs) {
        return Hex.encodeHexString(hmacMd5(data, key, cs), true);
    }

    /**
     * Compute HMAC-MD5 with custom encodings for message and key; format output.
     *
     * @param data    message as string
     * @param key     secret key as string
     * @param dataEnc input encoding for message
     * @param keyEnc  input encoding for key
     * @param out     output encoding (HEX lower/upper, Base64, Base64-URL)
     * @return formatted HMAC-MD5 string
     */
    public static String hmacMd5(String data, String key, InputEncoding dataEnc, InputEncoding keyEnc,
            OutputEncoding out) {
        byte[] decodedData = EncodingUtil.decode(data, dataEnc);
        byte[] decodedKey = EncodingUtil.decode(key, keyEnc);
        return EncodingUtil.encode(hmacMd5(decodedData, decodedKey), out);
    }

    // ===== Internal helpers =====
    private static byte[] digest(String algorithm, String provider, byte[] data) {
        try {
            MessageDigest md = provider == null ? MessageDigest.getInstance(algorithm)
                    : MessageDigest.getInstance(algorithm, provider);
            return md.digest(data);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException(
                    "Digest algorithm not available: " + algorithm + (provider != null ? ("/" + provider) : ""), e);
        }
    }

    private static byte[] digestFile(String algorithm, String provider, File file) {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new CryptoException("File not found: " + (file == null ? "null" : file.getAbsolutePath()));
        }
        try {
            MessageDigest md = provider == null ? MessageDigest.getInstance(algorithm)
                    : MessageDigest.getInstance(algorithm, provider);
            byte[] buffer = new byte[BUFFER_SIZE];
            try (FileInputStream fis = new FileInputStream(file)) {
                int read;
                while ((read = fis.read(buffer)) != -1) {
                    md.update(buffer, 0, read);
                }
            }
            return md.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException(
                    "Digest algorithm not available: " + algorithm + (provider != null ? ("/" + provider) : ""), e);
        } catch (IOException e) {
            throw new CryptoException("I/O error while reading file: " + file.getAbsolutePath(), e);
        }
    }

    private static byte[] hmac(String algorithm, byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
            mac.init(secretKeySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC computation failed: " + algorithm, e);
        }
    }

    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }
}
