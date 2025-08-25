package com.haiphamcoder.crypto.hash.blake;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.haiphamcoder.crypto.encoding.EncodingUtil;
import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for BLAKE digests (BLAKE2b, BLAKE2s) over bytes,
 * strings, and files, with flexible input/output encodings.
 * Note: BLAKE3 and HMAC variants are not available in BouncyCastle.
 */
public final class BLAKEUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private BLAKEUtil() {
    }

    // ===== Generic helpers =====
    private static byte[] digest(String algorithm, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
            return md.digest(data);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException("Digest algorithm not available: " + algorithm + "/" + PROVIDER, e);
        }
    }

    private static byte[] digestFile(String algorithm, File file) {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new CryptoException("File not found: " + (file == null ? "null" : file.getAbsolutePath()));
        }
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm, PROVIDER);
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
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException("Digest algorithm not available: " + algorithm + "/" + PROVIDER, e);
        }
    }

    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }

    private static String format(byte[] data, OutputEncoding out) {
        return EncodingUtil.encode(data, out);
    }

    // ===== BLAKE2b-256 =====
    /**
     * Compute BLAKE2b-256 of raw bytes.
     * 
     * @param data input bytes
     * @return 32-byte digest
     */
    public static byte[] blake2b256(byte[] data) {
        return digest("BLAKE2B-256", data);
    }

    /**
     * Compute BLAKE2b-256 of UTF-8 string.
     * 
     * @param s input (UTF-8)
     * @return 32-byte digest
     */
    public static byte[] blake2b256(String s) {
        return blake2b256(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute BLAKE2b-256 of string with charset.
     * 
     * @param s input
     * @param cs charset
     * @return 32-byte digest
     */
    public static byte[] blake2b256(String s, Charset cs) {
        return blake2b256(s.getBytes(cs));
    }

    /**
     * Compute BLAKE2b-256 of file via streaming.
     * 
     * @param f file
     * @return 32-byte digest
     */
    public static byte[] blake2b256(File f) {
        return digestFile("BLAKE2B-256", f);
    }

    /**
     * Return lowercase-hex BLAKE2b-256 of bytes.
     */
    public static String blake2b256Hex(byte[] data) {
        return Hex.encodeHexString(blake2b256(data), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-256 of UTF-8 string.
     */
    public static String blake2b256Hex(String s) {
        return Hex.encodeHexString(blake2b256(s), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-256 of string with charset.
     */
    public static String blake2b256Hex(String s, Charset cs) {
        return Hex.encodeHexString(blake2b256(s, cs), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-256 of file.
     */
    public static String blake2b256Hex(File f) {
        return Hex.encodeHexString(blake2b256(f), true);
    }

    /**
     * Compute BLAKE2b-256 with custom encodings.
     */
    public static String blake2b256(String input, InputEncoding in, OutputEncoding out) {
        return format(blake2b256(decode(input, in)), out);
    }

    // ===== BLAKE2b-512 =====
    /**
     * Compute BLAKE2b-512 of raw bytes.
     * 
     * @return 64-byte digest
     */
    public static byte[] blake2b512(byte[] data) {
        return digest("BLAKE2B-512", data);
    }

    /**
     * Compute BLAKE2b-512 of UTF-8 string.
     * 
     * @return 64-byte digest
     */
    public static byte[] blake2b512(String s) {
        return blake2b512(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute BLAKE2b-512 of string with charset.
     * 
     * @return 64-byte digest
     */
    public static byte[] blake2b512(String s, Charset cs) {
        return blake2b512(s.getBytes(cs));
    }

    /**
     * Compute BLAKE2b-512 of file.
     * 
     * @return 64-byte digest
     */
    public static byte[] blake2b512(File f) {
        return digestFile("BLAKE2B-512", f);
    }

    /**
     * Return lowercase-hex BLAKE2b-512 of bytes.
     */
    public static String blake2b512Hex(byte[] data) {
        return Hex.encodeHexString(blake2b512(data), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-512 of UTF-8 string.
     */
    public static String blake2b512Hex(String s) {
        return Hex.encodeHexString(blake2b512(s), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-512 of string with charset.
     */
    public static String blake2b512Hex(String s, Charset cs) {
        return Hex.encodeHexString(blake2b512(s, cs), true);
    }

    /**
     * Return lowercase-hex BLAKE2b-512 of file.
     */
    public static String blake2b512Hex(File f) {
        return Hex.encodeHexString(blake2b512(f), true);
    }

    /**
     * Compute BLAKE2b-512 with custom encodings.
     */
    public static String blake2b512(String input, InputEncoding in, OutputEncoding out) {
        return format(blake2b512(decode(input, in)), out);
    }

    // ===== BLAKE2s-128 =====
    /**
     * Compute BLAKE2s-128 of raw bytes.
     * 
     * @return 16-byte digest
     */
    public static byte[] blake2s128(byte[] data) {
        return digest("BLAKE2S-128", data);
    }

    /**
     * Compute BLAKE2s-128 of UTF-8 string.
     * 
     * @return 16-byte digest
     */
    public static byte[] blake2s128(String s) {
        return blake2s128(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute BLAKE2s-128 of string with charset.
     * 
     * @return 16-byte digest
     */
    public static byte[] blake2s128(String s, Charset cs) {
        return blake2s128(s.getBytes(cs));
    }

    /**
     * Compute BLAKE2s-128 of file.
     * 
     * @return 16-byte digest
     */
    public static byte[] blake2s128(File f) {
        return digestFile("BLAKE2S-128", f);
    }

    /**
     * Return lowercase-hex BLAKE2s-128 of bytes.
     */
    public static String blake2s128Hex(byte[] data) {
        return Hex.encodeHexString(blake2s128(data), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-128 of UTF-8 string.
     */
    public static String blake2s128Hex(String s) {
        return Hex.encodeHexString(blake2s128(s), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-128 of string with charset.
     */
    public static String blake2s128Hex(String s, Charset cs) {
        return Hex.encodeHexString(blake2s128(s, cs), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-128 of file.
     */
    public static String blake2s128Hex(File f) {
        return Hex.encodeHexString(blake2s128(f), true);
    }

    /**
     * Compute BLAKE2s-128 with custom encodings.
     */
    public static String blake2s128(String input, InputEncoding in, OutputEncoding out) {
        return format(blake2s128(decode(input, in)), out);
    }

    // ===== BLAKE2s-256 =====
    /**
     * Compute BLAKE2s-256 of raw bytes.
     * 
     * @return 32-byte digest
     */
    public static byte[] blake2s256(byte[] data) {
        return digest("BLAKE2S-256", data);
    }

    /**
     * Compute BLAKE2s-256 of UTF-8 string.
     * 
     * @return 32-byte digest
     */
    public static byte[] blake2s256(String s) {
        return blake2s256(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute BLAKE2s-256 of string with charset.
     * 
     * @return 32-byte digest
     */
    public static byte[] blake2s256(String s, Charset cs) {
        return blake2s256(s.getBytes(cs));
    }

    /**
     * Compute BLAKE2s-256 of file.
     * 
     * @return 32-byte digest
     */
    public static byte[] blake2s256(File f) {
        return digestFile("BLAKE2S-256", f);
    }

    /**
     * Return lowercase-hex BLAKE2s-256 of bytes.
     */
    public static String blake2s256Hex(byte[] data) {
        return Hex.encodeHexString(blake2s256(data), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-256 of UTF-8 string.
     */
    public static String blake2s256Hex(String s) {
        return Hex.encodeHexString(blake2s256(s), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-256 of string with charset.
     */
    public static String blake2s256Hex(String s, Charset cs) {
        return Hex.encodeHexString(blake2s256(s, cs), true);
    }

    /**
     * Return lowercase-hex BLAKE2s-256 of file.
     */
    public static String blake2s256Hex(File f) {
        return Hex.encodeHexString(blake2s256(f), true);
    }

    /**
     * Compute BLAKE2s-256 with custom encodings.
     */
    public static String blake2s256(String input, InputEncoding in, OutputEncoding out) {
        return format(blake2s256(decode(input, in)), out);
    }
}
