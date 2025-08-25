package com.haiphamcoder.crypto.hash.keccak;

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
 * Utility methods for Keccak digests (Keccak-224/256/288/384/512) over bytes,
 * strings, and files, with flexible input/output encodings.
 */
public final class KeccakUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeccakUtil() {
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

    // ===== Keccak-224 =====
    /**
     * Compute Keccak-224 of raw bytes. @param data input bytes @return 28-byte
     * digest
     */
    public static byte[] keccak224(byte[] data) {
        return digest("Keccak-224", data);
    }

    /**
     * Compute Keccak-224 of UTF-8 string. @param s input (UTF-8) @return 28-byte
     * digest
     */
    public static byte[] keccak224(String s) {
        return keccak224(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute Keccak-224 of string with charset. @param s input @param cs
     * charset @return 28-byte digest
     */
    public static byte[] keccak224(String s, Charset cs) {
        return keccak224(s.getBytes(cs));
    }

    /**
     * Compute Keccak-224 of file via streaming. @param f file @return 28-byte
     * digest
     */
    public static byte[] keccak224(File f) {
        return digestFile("Keccak-224", f);
    }

    /** Return lowercase-hex Keccak-224 of bytes. */
    public static String keccak224Hex(byte[] data) {
        return Hex.encodeHexString(keccak224(data), true);
    }

    /** Return lowercase-hex Keccak-224 of UTF-8 string. */
    public static String keccak224Hex(String s) {
        return Hex.encodeHexString(keccak224(s), true);
    }

    /** Return lowercase-hex Keccak-224 of string with charset. */
    public static String keccak224Hex(String s, Charset cs) {
        return Hex.encodeHexString(keccak224(s, cs), true);
    }

    /** Return lowercase-hex Keccak-224 of file. */
    public static String keccak224Hex(File f) {
        return Hex.encodeHexString(keccak224(f), true);
    }

    /** Compute Keccak-224 with custom encodings. */
    public static String keccak224(String input, InputEncoding in, OutputEncoding out) {
        return format(keccak224(decode(input, in)), out);
    }

    // ===== Keccak-256 =====
    /** Compute Keccak-256 of raw bytes. @return 32-byte digest */
    public static byte[] keccak256(byte[] data) {
        return digest("Keccak-256", data);
    }

    /** Compute Keccak-256 of UTF-8 string. @return 32-byte digest */
    public static byte[] keccak256(String s) {
        return keccak256(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute Keccak-256 of string with charset. @return 32-byte digest */
    public static byte[] keccak256(String s, Charset cs) {
        return keccak256(s.getBytes(cs));
    }

    /** Compute Keccak-256 of file. @return 32-byte digest */
    public static byte[] keccak256(File f) {
        return digestFile("Keccak-256", f);
    }

    /** Return lowercase-hex Keccak-256 of bytes. */
    public static String keccak256Hex(byte[] data) {
        return Hex.encodeHexString(keccak256(data), true);
    }

    /** Return lowercase-hex Keccak-256 of UTF-8 string. */
    public static String keccak256Hex(String s) {
        return Hex.encodeHexString(keccak256(s), true);
    }

    /** Return lowercase-hex Keccak-256 of string with charset. */
    public static String keccak256Hex(String s, Charset cs) {
        return Hex.encodeHexString(keccak256(s, cs), true);
    }

    /** Return lowercase-hex Keccak-256 of file. */
    public static String keccak256Hex(File f) {
        return Hex.encodeHexString(keccak256(f), true);
    }

    /** Compute Keccak-256 with custom encodings. */
    public static String keccak256(String input, InputEncoding in, OutputEncoding out) {
        return format(keccak256(decode(input, in)), out);
    }

    // ===== Keccak-288 =====
    /** Compute Keccak-288 of raw bytes. @return 36-byte digest */
    public static byte[] keccak288(byte[] data) {
        return digest("Keccak-288", data);
    }

    /** Compute Keccak-288 of UTF-8 string. @return 36-byte digest */
    public static byte[] keccak288(String s) {
        return keccak288(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute Keccak-288 of string with charset. @return 36-byte digest */
    public static byte[] keccak288(String s, Charset cs) {
        return keccak288(s.getBytes(cs));
    }

    /** Compute Keccak-288 of file. @return 36-byte digest */
    public static byte[] keccak288(File f) {
        return digestFile("Keccak-288", f);
    }

    /** Return lowercase-hex Keccak-288 of bytes. */
    public static String keccak288Hex(byte[] data) {
        return Hex.encodeHexString(keccak288(data), true);
    }

    /** Return lowercase-hex Keccak-288 of UTF-8 string. */
    public static String keccak288Hex(String s) {
        return Hex.encodeHexString(keccak288(s), true);
    }

    /** Return lowercase-hex Keccak-288 of string with charset. */
    public static String keccak288Hex(String s, Charset cs) {
        return Hex.encodeHexString(keccak288(s, cs), true);
    }

    /** Return lowercase-hex Keccak-288 of file. */
    public static String keccak288Hex(File f) {
        return Hex.encodeHexString(keccak288(f), true);
    }

    /** Compute Keccak-288 with custom encodings. */
    public static String keccak288(String input, InputEncoding in, OutputEncoding out) {
        return format(keccak288(decode(input, in)), out);
    }

    // ===== Keccak-384 =====
    /** Compute Keccak-384 of raw bytes. @return 48-byte digest */
    public static byte[] keccak384(byte[] data) {
        return digest("Keccak-384", data);
    }

    /** Compute Keccak-384 of UTF-8 string. @return 48-byte digest */
    public static byte[] keccak384(String s) {
        return keccak384(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute Keccak-384 of string with charset. @return 48-byte digest */
    public static byte[] keccak384(String s, Charset cs) {
        return keccak384(s.getBytes(cs));
    }

    /** Compute Keccak-384 of file. @return 48-byte digest */
    public static byte[] keccak384(File f) {
        return digestFile("Keccak-384", f);
    }

    /** Return lowercase-hex Keccak-384 of bytes. */
    public static String keccak384Hex(byte[] data) {
        return Hex.encodeHexString(keccak384(data), true);
    }

    /** Return lowercase-hex Keccak-384 of UTF-8 string. */
    public static String keccak384Hex(String s) {
        return Hex.encodeHexString(keccak384(s), true);
    }

    /** Return lowercase-hex Keccak-384 of string with charset. */
    public static String keccak384Hex(String s, Charset cs) {
        return Hex.encodeHexString(keccak384(s, cs), true);
    }

    /** Return lowercase-hex Keccak-384 of file. */
    public static String keccak384Hex(File f) {
        return Hex.encodeHexString(keccak384(f), true);
    }

    /** Compute Keccak-384 with custom encodings. */
    public static String keccak384(String input, InputEncoding in, OutputEncoding out) {
        return format(keccak384(decode(input, in)), out);
    }

    // ===== Keccak-512 =====
    /** Compute Keccak-512 of raw bytes. @return 64-byte digest */
    public static byte[] keccak512(byte[] data) {
        return digest("Keccak-512", data);
    }

    /** Compute Keccak-512 of UTF-8 string. @return 64-byte digest */
    public static byte[] keccak512(String s) {
        return keccak512(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Compute Keccak-512 of string with charset. @return 64-byte digest */
    public static byte[] keccak512(String s, Charset cs) {
        return keccak512(s.getBytes(cs));
    }

    /** Compute Keccak-512 of file. @return 64-byte digest */
    public static byte[] keccak512(File f) {
        return digestFile("Keccak-512", f);
    }

    /** Return lowercase-hex Keccak-512 of bytes. */
    public static String keccak512Hex(byte[] data) {
        return Hex.encodeHexString(keccak512(data), true);
    }

    /** Return lowercase-hex Keccak-512 of UTF-8 string. */
    public static String keccak512Hex(String s) {
        return Hex.encodeHexString(keccak512(s), true);
    }

    /** Return lowercase-hex Keccak-512 of string with charset. */
    public static String keccak512Hex(String s, Charset cs) {
        return Hex.encodeHexString(keccak512(s, cs), true);
    }

    /** Return lowercase-hex Keccak-512 of file. */
    public static String keccak512Hex(File f) {
        return Hex.encodeHexString(keccak512(f), true);
    }

    /** Compute Keccak-512 with custom encodings. */
    public static String keccak512(String input, InputEncoding in, OutputEncoding out) {
        return format(keccak512(decode(input, in)), out);
    }
}
