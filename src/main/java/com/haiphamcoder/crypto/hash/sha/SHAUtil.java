package com.haiphamcoder.crypto.hash.sha;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import com.haiphamcoder.crypto.encoding.EncodingUtil;
import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for SHA family digests (SHA-1, SHA-256, SHA-384, SHA-512)
 * and HMAC variants over bytes, strings, and files.
 *
 * <p>Provides raw byte[] hashes and formatted string outputs via
 * {@link OutputEncoding}. Input strings can be decoded using
 * {@link InputEncoding}.</p>
 */
public final class SHAUtil {
    private static final int BUFFER_SIZE = 64 * 1024;

    private SHAUtil() {
    }

    // ======= Generic helpers =======
    private static byte[] digest(String algorithm, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return md.digest(data);
        } catch (Exception e) {
            throw new CryptoException("Digest algorithm not available: " + algorithm, e);
        }
    }

    private static byte[] digestFile(String algorithm, File file) {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new CryptoException("File not found: " + (file == null ? "null" : file.getAbsolutePath()));
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[BUFFER_SIZE];
            try (FileInputStream fis = new FileInputStream(file)) {
                int read;
                while ((read = fis.read(buffer)) != -1) {
                    md.update(buffer, 0, read);
                }
            }
            return md.digest();
        } catch (IOException e) {
            throw new CryptoException("I/O error while reading file: " + file.getAbsolutePath(), e);
        } catch (Exception e) {
            throw new CryptoException("Digest algorithm not available: " + algorithm, e);
        }
    }

    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }

    private static String format(byte[] data, OutputEncoding out) {
        return EncodingUtil.encode(data, out);
    }

    private static byte[] hmac(String algorithm, byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC algorithm not available: " + algorithm, e);
        }
    }

    // ======= SHA-1 =======
    /**
     * Compute SHA-1 (160-bit) hash of raw bytes.
     * 
     * @param data input data
     * @return 20-byte digest
     */
    public static byte[] sha1(byte[] data) {
        return digest("SHA-1", data);
    }

    /**
     * Compute SHA-1 of a UTF-8 string.
     * 
     * @param s input string (UTF-8)
     * @return 20-byte digest
     */
    public static byte[] sha1(String s) {
        return sha1(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute SHA-1 of a string with specified charset.
     * 
     * @param s  input string
     * @param cs charset
     * @return 20-byte digest
     */
    public static byte[] sha1(String s, Charset cs) {
        return sha1(s.getBytes(cs));
    }

    /**
     * Compute SHA-1 of a file (streaming).
     * 
     * @param f file
     * @return 20-byte digest
     */
    public static byte[] sha1(File f) {
        return digestFile("SHA-1", f);
    }

    /**
     * Compute SHA-1 and return lowercase-hex.
     * 
     * @param data input data
     * @return hex string
     */
    public static String sha1Hex(byte[] data) {
        return Hex.encodeHexString(sha1(data), true);
    }

    /**
     * Compute SHA-1 of UTF-8 string and return lowercase-hex.
     * 
     * @param s input string (UTF-8)
     * @return hex string
     */
    public static String sha1Hex(String s) {
        return Hex.encodeHexString(sha1(s), true);
    }

    /**
     * Compute SHA-1 of string with charset and return lowercase-hex.
     * 
     * @param s  input string
     * @param cs charset
     * @return hex string
     */
    public static String sha1Hex(String s, Charset cs) {
        return Hex.encodeHexString(sha1(s, cs), true);
    }

    /**
     * Compute SHA-1 of file and return lowercase-hex.
     * 
     * @param f file
     * @return hex string
     */
    public static String sha1Hex(File f) {
        return Hex.encodeHexString(sha1(f), true);
    }

    /**
     * Compute SHA-1 with custom input/output encodings.
     * 
     * @param input input string
     * @param in    input encoding
     * @param out   output encoding
     * @return formatted digest string
     */
    public static String sha1(String input, InputEncoding in, OutputEncoding out) {
        return format(sha1(decode(input, in)), out);
    }

    // ======= SHA-256 =======
    /** Compute SHA-256 (256-bit) of raw bytes. @return 32-byte digest */
    public static byte[] sha256(byte[] data) {
        return digest("SHA-256", data);
    }

    /** Compute SHA-256 of UTF-8 string. @return 32-byte digest */
    public static byte[] sha256(String s) {
        return sha256(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute SHA-256 of string with charset. @return 32-byte digest */
    public static byte[] sha256(String s, Charset cs) {
        return sha256(s.getBytes(cs));
    }

    /** Compute SHA-256 of file. @return 32-byte digest */
    public static byte[] sha256(File f) {
        return digestFile("SHA-256", f);
    }

    /** Return lowercase-hex SHA-256 of bytes. */
    public static String sha256Hex(byte[] data) {
        return Hex.encodeHexString(sha256(data), true);
    }

    /** Return lowercase-hex SHA-256 of UTF-8 string. */
    public static String sha256Hex(String s) {
        return Hex.encodeHexString(sha256(s), true);
    }

    /** Return lowercase-hex SHA-256 of string with charset. */
    public static String sha256Hex(String s, Charset cs) {
        return Hex.encodeHexString(sha256(s, cs), true);
    }

    /** Return lowercase-hex SHA-256 of file. */
    public static String sha256Hex(File f) {
        return Hex.encodeHexString(sha256(f), true);
    }

    /** Compute SHA-256 with custom input/output encodings. */
    public static String sha256(String input, InputEncoding in, OutputEncoding out) {
        return format(sha256(decode(input, in)), out);
    }

    // ======= SHA-384 =======
    /** Compute SHA-384 (384-bit) of raw bytes. @return 48-byte digest */
    public static byte[] sha384(byte[] data) {
        return digest("SHA-384", data);
    }

    /** Compute SHA-384 of UTF-8 string. @return 48-byte digest */
    public static byte[] sha384(String s) {
        return sha384(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute SHA-384 of string with charset. @return 48-byte digest */
    public static byte[] sha384(String s, Charset cs) {
        return sha384(s.getBytes(cs));
    }

    /** Compute SHA-384 of file. @return 48-byte digest */
    public static byte[] sha384(File f) {
        return digestFile("SHA-384", f);
    }

    /** Return lowercase-hex SHA-384 of bytes. */
    public static String sha384Hex(byte[] data) {
        return Hex.encodeHexString(sha384(data), true);
    }

    /** Return lowercase-hex SHA-384 of UTF-8 string. */
    public static String sha384Hex(String s) {
        return Hex.encodeHexString(sha384(s), true);
    }

    /** Return lowercase-hex SHA-384 of string with charset. */
    public static String sha384Hex(String s, Charset cs) {
        return Hex.encodeHexString(sha384(s, cs), true);
    }

    /** Return lowercase-hex SHA-384 of file. */
    public static String sha384Hex(File f) {
        return Hex.encodeHexString(sha384(f), true);
    }

    /** Compute SHA-384 with custom input/output encodings. */
    public static String sha384(String input, InputEncoding in, OutputEncoding out) {
        return format(sha384(decode(input, in)), out);
    }

    // ======= SHA-512 =======
    /** Compute SHA-512 (512-bit) of raw bytes. @return 64-byte digest */
    public static byte[] sha512(byte[] data) {
        return digest("SHA-512", data);
    }

    /** Compute SHA-512 of UTF-8 string. @return 64-byte digest */
    public static byte[] sha512(String s) {
        return sha512(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute SHA-512 of string with charset. @return 64-byte digest */
    public static byte[] sha512(String s, Charset cs) {
        return sha512(s.getBytes(cs));
    }

    /** Compute SHA-512 of file. @return 64-byte digest */
    public static byte[] sha512(File f) {
        return digestFile("SHA-512", f);
    }

    /** Return lowercase-hex SHA-512 of bytes. */
    public static String sha512Hex(byte[] data) {
        return Hex.encodeHexString(sha512(data), true);
    }

    /** Return lowercase-hex SHA-512 of UTF-8 string. */
    public static String sha512Hex(String s) {
        return Hex.encodeHexString(sha512(s), true);
    }

    /** Return lowercase-hex SHA-512 of string with charset. */
    public static String sha512Hex(String s, Charset cs) {
        return Hex.encodeHexString(sha512(s, cs), true);
    }

    /** Return lowercase-hex SHA-512 of file. */
    public static String sha512Hex(File f) {
        return Hex.encodeHexString(sha512(f), true);
    }

    /** Compute SHA-512 with custom input/output encodings. */
    public static String sha512(String input, InputEncoding in, OutputEncoding out) {
        return format(sha512(decode(input, in)), out);
    }

    // ======= HMAC (SHA-1/256/384/512) =======
    /** Compute HMAC-SHA1 of raw bytes. @return 20-byte MAC */
    public static byte[] hmacSha1(byte[] data, byte[] key) {
        return hmac("HmacSHA1", data, key);
    }

    /** Compute HMAC-SHA256 of raw bytes. @return 32-byte MAC */
    public static byte[] hmacSha256(byte[] data, byte[] key) {
        return hmac("HmacSHA256", data, key);
    }

    /** Compute HMAC-SHA384 of raw bytes. @return 48-byte MAC */
    public static byte[] hmacSha384(byte[] data, byte[] key) {
        return hmac("HmacSHA384", data, key);
    }

    /** Compute HMAC-SHA512 of raw bytes. @return 64-byte MAC */
    public static byte[] hmacSha512(byte[] data, byte[] key) {
        return hmac("HmacSHA512", data, key);
    }

    /** Compute HMAC-SHA1 with encodings. */
    public static String hmacSha1(String data, String key, InputEncoding dataIn, InputEncoding keyIn,
            OutputEncoding out) {
        return format(hmacSha1(decode(data, dataIn), decode(key, keyIn)), out);
    }

    /** Compute HMAC-SHA256 with encodings. */
    public static String hmacSha256(String data, String key, InputEncoding dataIn, InputEncoding keyIn,
            OutputEncoding out) {
        return format(hmacSha256(decode(data, dataIn), decode(key, keyIn)), out);
    }

    /** Compute HMAC-SHA384 with encodings. */
    public static String hmacSha384(String data, String key, InputEncoding dataIn, InputEncoding keyIn,
            OutputEncoding out) {
        return format(hmacSha384(decode(data, dataIn), decode(key, keyIn)), out);
    }

    /** Compute HMAC-SHA512 with encodings. */
    public static String hmacSha512(String data, String key, InputEncoding dataIn, InputEncoding keyIn,
            OutputEncoding out) {
        return format(hmacSha512(decode(data, dataIn), decode(key, keyIn)), out);
    }

    /** Return lowercase-hex HMAC-SHA1. */
    public static String hmacSha1Hex(byte[] data, byte[] key) {
        return Hex.encodeHexString(hmacSha1(data, key), true);
    }

    /** Return lowercase-hex HMAC-SHA256. */
    public static String hmacSha256Hex(byte[] data, byte[] key) {
        return Hex.encodeHexString(hmacSha256(data, key), true);
    }

    /** Return lowercase-hex HMAC-SHA384. */
    public static String hmacSha384Hex(byte[] data, byte[] key) {
        return Hex.encodeHexString(hmacSha384(data, key), true);
    }

    /** Return lowercase-hex HMAC-SHA512. */
    public static String hmacSha512Hex(byte[] data, byte[] key) {
        return Hex.encodeHexString(hmacSha512(data, key), true);
    }
}
