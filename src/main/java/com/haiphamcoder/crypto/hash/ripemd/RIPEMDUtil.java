package com.haiphamcoder.crypto.hash.ripemd;

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

import com.haiphamcoder.crypto.encoding.EncodingUtil;
import com.haiphamcoder.crypto.encoding.InputEncoding;
import com.haiphamcoder.crypto.encoding.OutputEncoding;
import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Utility methods for RIPEMD digests (RIPEMD-128/160/256/320) over bytes,
 * strings, and files, with flexible input/output encodings and HMAC support.
 */
public final class RIPEMDUtil {
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private RIPEMDUtil() {
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

    private static byte[] hmac(String algorithm, byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm, PROVIDER);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC computation failed for " + algorithm, e);
        }
    }

    private static byte[] decode(String input, InputEncoding in) {
        return EncodingUtil.decode(input, in);
    }

    private static String format(byte[] data, OutputEncoding out) {
        return EncodingUtil.encode(data, out);
    }

    // ===== RIPEMD-128 =====
    /**
     * Compute RIPEMD-128 of raw bytes.
     * 
     * @param data input bytes
     * @return 16-byte digest
     */
    public static byte[] ripemd128(byte[] data) {
        return digest("RIPEMD128", data);
    }

    /**
     * Compute RIPEMD-128 of UTF-8 string.
     * 
     * @param s input (UTF-8)
     * @return 16-byte digest
     */
    public static byte[] ripemd128(String s) {
        return ripemd128(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute RIPEMD-128 of string with charset.
     * 
     * @param s input
     * @param cs charset
     * @return 16-byte digest
     */
    public static byte[] ripemd128(String s, Charset cs) {
        return ripemd128(s.getBytes(cs));
    }

    /**
     * Compute RIPEMD-128 of file via streaming.
     * 
     * @param f file
     * @return 16-byte digest
     */
    public static byte[] ripemd128(File f) {
        return digestFile("RIPEMD128", f);
    }

    /**
     * Return lowercase-hex RIPEMD-128 of bytes.
     */
    public static String ripemd128Hex(byte[] data) {
        return Hex.encodeHexString(ripemd128(data), true);
    }

    /**
     * Return lowercase-hex RIPEMD-128 of UTF-8 string.
     */
    public static String ripemd128Hex(String s) {
        return Hex.encodeHexString(ripemd128(s), true);
    }

    /**
     * Return lowercase-hex RIPEMD-128 of string with charset.
     */
    public static String ripemd128Hex(String s, Charset cs) {
        return Hex.encodeHexString(ripemd128(s, cs), true);
    }

    /**
     * Return lowercase-hex RIPEMD-128 of file.
     */
    public static String ripemd128Hex(File f) {
        return Hex.encodeHexString(ripemd128(f), true);
    }

    /**
     * Compute RIPEMD-128 with custom encodings.
     */
    public static String ripemd128(String input, InputEncoding in, OutputEncoding out) {
        return format(ripemd128(decode(input, in)), out);
    }

    // ===== RIPEMD-160 =====
    /**
     * Compute RIPEMD-160 of raw bytes.
     * 
     * @return 20-byte digest
     */
    public static byte[] ripemd160(byte[] data) {
        return digest("RIPEMD160", data);
    }

    /**
     * Compute RIPEMD-160 of UTF-8 string.
     * 
     * @return 20-byte digest
     */
    public static byte[] ripemd160(String s) {
        return ripemd160(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute RIPEMD-160 of string with charset.
     * 
     * @return 20-byte digest
     */
    public static byte[] ripemd160(String s, Charset cs) {
        return ripemd160(s.getBytes(cs));
    }

    /**
     * Compute RIPEMD-160 of file.
     * 
     * @return 20-byte digest
     */
    public static byte[] ripemd160(File f) {
        return digestFile("RIPEMD160", f);
    }

    /**
     * Return lowercase-hex RIPEMD-160 of bytes.
     */
    public static String ripemd160Hex(byte[] data) {
        return Hex.encodeHexString(ripemd160(data), true);
    }

    /**
     * Return lowercase-hex RIPEMD-160 of UTF-8 string.
     */
    public static String ripemd160Hex(String s) {
        return Hex.encodeHexString(ripemd160(s), true);
    }

    /**
     * Return lowercase-hex RIPEMD-160 of string with charset.
     */
    public static String ripemd160Hex(String s, Charset cs) {
        return Hex.encodeHexString(ripemd160(s, cs), true);
    }

    /**
     * Return lowercase-hex RIPEMD-160 of file.
     */
    public static String ripemd160Hex(File f) {
        return Hex.encodeHexString(ripemd160(f), true);
    }

    /**
     * Compute RIPEMD-160 with custom encodings.
     */
    public static String ripemd160(String input, InputEncoding in, OutputEncoding out) {
        return format(ripemd160(decode(input, in)), out);
    }

    // ===== RIPEMD-256 =====
    /**
     * Compute RIPEMD-256 of raw bytes.
     * 
     * @return 32-byte digest
     */
    public static byte[] ripemd256(byte[] data) {
        return digest("RIPEMD256", data);
    }

    /**
     * Compute RIPEMD-256 of UTF-8 string.
     * 
     * @return 32-byte digest
     */
    public static byte[] ripemd256(String s) {
        return ripemd256(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute RIPEMD-256 of string with charset.
     * 
     * @return 32-byte digest
     */
    public static byte[] ripemd256(String s, Charset cs) {
        return ripemd256(s.getBytes(cs));
    }

    /**
     * Compute RIPEMD-256 of file.
     * 
     * @return 32-byte digest
     */
    public static byte[] ripemd256(File f) {
        return digestFile("RIPEMD256", f);
    }

    /**
     * Return lowercase-hex RIPEMD-256 of bytes.
     */
    public static String ripemd256Hex(byte[] data) {
        return Hex.encodeHexString(ripemd256(data), true);
    }

    /**
     * Return lowercase-hex RIPEMD-256 of UTF-8 string.
     */
    public static String ripemd256Hex(String s) {
        return Hex.encodeHexString(ripemd256(s), true);
    }

    /**
     * Return lowercase-hex RIPEMD-256 of string with charset.
     */
    public static String ripemd256Hex(String s, Charset cs) {
        return Hex.encodeHexString(ripemd256(s, cs), true);
    }

    /**
     * Return lowercase-hex RIPEMD-256 of file.
     */
    public static String ripemd256Hex(File f) {
        return Hex.encodeHexString(ripemd256(f), true);
    }

    /**
     * Compute RIPEMD-256 with custom encodings.
     */
    public static String ripemd256(String input, InputEncoding in, OutputEncoding out) {
        return format(ripemd256(decode(input, in)), out);
    }

    // ===== RIPEMD-320 =====
    /**
     * Compute RIPEMD-320 of raw bytes.
     * 
     * @return 40-byte digest
     */
    public static byte[] ripemd320(byte[] data) {
        return digest("RIPEMD320", data);
    }

    /**
     * Compute RIPEMD-320 of UTF-8 string.
     * 
     * @return 40-byte digest
     */
    public static byte[] ripemd320(String s) {
        return ripemd320(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute RIPEMD-320 of string with charset.
     * 
     * @return 40-byte digest
     */
    public static byte[] ripemd320(String s, Charset cs) {
        return ripemd320(s.getBytes(cs));
    }

    /**
     * Compute RIPEMD-320 of file.
     * 
     * @return 40-byte digest
     */
    public static byte[] ripemd320(File f) {
        return digestFile("RIPEMD320", f);
    }

    /**
     * Return lowercase-hex RIPEMD-320 of bytes.
     */
    public static String ripemd320Hex(byte[] data) {
        return Hex.encodeHexString(ripemd320(data), true);
    }

    /**
     * Return lowercase-hex RIPEMD-320 of UTF-8 string.
     */
    public static String ripemd320Hex(String s) {
        return Hex.encodeHexString(ripemd320(s), true);
    }

    /**
     * Return lowercase-hex RIPEMD-320 of string with charset.
     */
    public static String ripemd320Hex(String s, Charset cs) {
        return Hex.encodeHexString(ripemd320(s, cs), true);
    }

    /**
     * Return lowercase-hex RIPEMD-320 of file.
     */
    public static String ripemd320Hex(File f) {
        return Hex.encodeHexString(ripemd320(f), true);
    }

    /**
     * Compute RIPEMD-320 with custom encodings.
     */
    public static String ripemd320(String input, InputEncoding in, OutputEncoding out) {
        return format(ripemd320(decode(input, in)), out);
    }

    // ===== HMAC-RIPEMD =====
    /**
     * Compute HMAC-RIPEMD128 of data with key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd128(byte[] data, byte[] key) {
        return hmac("HmacRIPEMD128", data, key);
    }

    /**
     * Compute HMAC-RIPEMD128 of UTF-8 string with UTF-8 key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd128(String data, String key) {
        return hmacRipemd128(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute HMAC-RIPEMD128 with custom encodings.
     * 
     * @param data input data
     * @param key secret key
     * @param dataEnc data encoding
     * @param keyEnc key encoding
     * @param out output encoding
     * @return formatted HMAC
     */
    public static String hmacRipemd128(String data, String key, InputEncoding dataEnc, InputEncoding keyEnc, OutputEncoding out) {
        byte[] decodedData = decode(data, dataEnc);
        byte[] decodedKey = decode(key, keyEnc);
        return format(hmacRipemd128(decodedData, decodedKey), out);
    }

    /**
     * Compute HMAC-RIPEMD160 of data with key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd160(byte[] data, byte[] key) {
        return hmac("HmacRIPEMD160", data, key);
    }

    /**
     * Compute HMAC-RIPEMD160 of UTF-8 string with UTF-8 key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd160(String data, String key) {
        return hmacRipemd160(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute HMAC-RIPEMD160 with custom encodings.
     * 
     * @param data input data
     * @param key secret key
     * @param dataEnc data encoding
     * @param keyEnc key encoding
     * @param out output encoding
     * @return formatted HMAC
     */
    public static String hmacRipemd160(String data, String key, InputEncoding dataEnc, InputEncoding keyEnc, OutputEncoding out) {
        byte[] decodedData = decode(data, dataEnc);
        byte[] decodedKey = decode(key, keyEnc);
        return format(hmacRipemd160(decodedData, decodedKey), out);
    }

    /**
     * Compute HMAC-RIPEMD256 of data with key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd256(byte[] data, byte[] key) {
        return hmac("HmacRIPEMD256", data, key);
    }

    /**
     * Compute HMAC-RIPEMD256 of UTF-8 string with UTF-8 key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd256(String data, String key) {
        return hmacRipemd256(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute HMAC-RIPEMD256 with custom encodings.
     * 
     * @param data input data
     * @param key secret key
     * @param dataEnc data encoding
     * @param keyEnc key encoding
     * @param out output encoding
     * @return formatted HMAC
     */
    public static String hmacRipemd256(String data, String key, InputEncoding dataEnc, InputEncoding keyEnc, OutputEncoding out) {
        byte[] decodedData = decode(data, dataEnc);
        byte[] decodedKey = decode(key, keyEnc);
        return format(hmacRipemd256(decodedData, decodedKey), out);
    }

    /**
     * Compute HMAC-RIPEMD320 of data with key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd320(byte[] data, byte[] key) {
        return hmac("HmacRIPEMD320", data, key);
    }

    /**
     * Compute HMAC-RIPEMD320 of UTF-8 string with UTF-8 key.
     * 
     * @param data input data
     * @param key secret key
     * @return HMAC digest
     */
    public static byte[] hmacRipemd320(String data, String key) {
        return hmacRipemd320(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Compute HMAC-RIPEMD320 with custom encodings.
     * 
     * @param data input data
     * @param key secret key
     * @param dataEnc data encoding
     * @param keyEnc key encoding
     * @param out output encoding
     * @return formatted HMAC
     */
    public static String hmacRipemd320(String data, String key, InputEncoding dataEnc, InputEncoding keyEnc, OutputEncoding out) {
        byte[] decodedData = decode(data, dataEnc);
        byte[] decodedKey = decode(key, keyEnc);
        return format(hmacRipemd320(decodedData, decodedKey), out);
    }
}
