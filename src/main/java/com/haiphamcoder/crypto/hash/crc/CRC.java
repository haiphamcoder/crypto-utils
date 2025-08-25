package com.haiphamcoder.crypto.hash.crc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

import com.haiphamcoder.crypto.exception.CryptoException;

/**
 * Generic table-driven CRC engine supporting widths up to 64 bits.
 * 
 * <p>This class provides a comprehensive implementation of CRC (Cyclic Redundancy Check)
 * algorithms with support for both table-driven and bitwise computation methods.
 * It handles reflected and non-reflected algorithms, custom polynomial values,
 * initial values, XOR output values, and various bit widths.</p>
 * 
 * <p>Key features:</p>
 * <ul>
 *   <li>Support for CRC widths from 1 to 64 bits</li>
 *   <li>Table-driven computation for efficient processing of 8+ bit widths</li>
 *   <li>Bitwise processing for narrow widths (< 8 bits)</li>
 *   <li>File streaming support with configurable buffer sizes</li>
 *   <li>Thread-safe static methods</li>
 * </ul>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * CRCParameters params = new CRCParameters(16, 0x8005L, 0x0000L, 0x0000L, true, true);
 * long crc = CRC.compute("Hello World".getBytes(), params);
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class CRC {
    private CRC() {
        // Utility class - prevent instantiation
    }

    /**
     * Compute CRC for input bytes with the provided parameters.
     * 
     * <p>This method automatically selects the most efficient computation strategy:</p>
     * <ul>
     *   <li>For widths < 8 and non-reflected input: uses bitwise processing</li>
     *   <li>For widths >= 8 or reflected input: uses table-driven processing</li>
     * </ul>
     * 
     * @param input the input data to compute CRC for
     * @param params the CRC algorithm parameters (width, polynomial, etc.)
     * @return the computed CRC value
     * @throws NullPointerException if input or params is null
     */
    public static long compute(byte[] input, CRCParameters params) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(params, "params");

        int width = params.width;
        long topBit = 1L << (width - 1);
        long mask = (width == 64) ? -1L : (1L << width) - 1L;
        long reg = params.initialValue & mask;

        if (!params.reflectIn && width < 8) {
            reg = processBitwise(input, params, reg, topBit, mask);
        } else {
            reg = processTableDriven(input, params, reg, topBit, mask);
        }

        if (params.reflectOut ^ params.reflectIn) {
            reg = reflect(reg, width);
        }

        reg = (reg ^ params.xorOut) & mask;
        return reg;
    }

    private static long processBitwise(byte[] input, CRCParameters params, long reg, long topBit, long mask) {
        for (byte b : input) {
            int v = b & 0xFF;
            for (int i = 0; i < 8; i++) {
                boolean bit = ((reg & topBit) != 0) ^ ((v & 0x80) != 0);
                reg = (reg << 1) & mask;
                if (bit) {
                    reg ^= params.polynomial;
                }
                v <<= 1;
            }
        }
        return reg;
    }

    private static long processTableDriven(byte[] input, CRCParameters params, long reg, long topBit, long mask) {
        long[] table = buildTable(params, topBit, mask);
        if (params.reflectIn) {
            for (byte b : input) {
                int idx = (int) ((reg ^ (b & 0xFF)) & 0xFF);
                reg = (reg >>> 8) ^ table[idx];
            }
        } else {
            for (byte b : input) {
                int idx = (params.width >= 8)
                        ? (int) (((reg >>> (params.width - 8)) ^ (b & 0xFF)) & 0xFF)
                        : (int) ((((reg << (8 - params.width)) & 0xFF) ^ (b & 0xFF)) & 0xFF);
                reg = ((reg << 8) & mask) ^ table[idx];
            }
        }
        return reg;
    }

    /**
     * Convenience method to compute CRC for a string with specified character encoding.
     * 
     * @param input the input string to compute CRC for
     * @param charset the character encoding to use for string conversion
     * @param params the CRC algorithm parameters
     * @return the computed CRC value
     * @throws NullPointerException if input, charset, or params is null
     */
    public static long compute(String input, Charset charset, CRCParameters params) {
        Objects.requireNonNull(input, "input");
        return compute(input.getBytes(charset), params);
    }

    /**
     * Compute CRC for a file using streaming buffer processing.
     * 
     * <p>This method efficiently processes large files by reading them in chunks
     * rather than loading the entire file into memory. It uses a 64KB buffer
     * for optimal performance.</p>
     * 
     * <p>The method automatically selects the appropriate processing strategy
     * based on the CRC parameters, just like the byte array version.</p>
     * 
     * @param file the file to compute CRC for
     * @param params the CRC algorithm parameters
     * @return the computed CRC value
     * @throws NullPointerException if file or params is null
     * @throws CryptoException if the file doesn't exist or I/O errors occur
     */
    public static long compute(File file, CRCParameters params) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(params, "params");
        if (!file.exists() || !file.isFile()) {
            throw new CryptoException("File not found: " + file.getAbsolutePath());
        }

        int width = params.width;
        long topBit = 1L << (width - 1);
        long mask = (width == 64) ? -1L : (1L << width) - 1L;
        long reg = params.initialValue & mask;

        reg = processFileStream(file, params, reg, topBit, mask);

        if (params.reflectOut ^ params.reflectIn) {
            reg = reflect(reg, width);
        }
        return (reg ^ params.xorOut) & mask;
    }

    /**
     * Orchestrates file processing by selecting the appropriate CRC computation method.
     * 
     * @param file the file to process
     * @param params the CRC parameters
     * @param reg the initial CRC register value
     * @param topBit the top bit mask for the CRC width
     * @param mask the bit mask for the CRC width
     * @return the computed CRC value
     */
    private static long processFileStream(File file, CRCParameters params, long reg, long topBit, long mask) {
        byte[] buffer = new byte[64 * 1024];
        try (FileInputStream fis = new FileInputStream(file)) {
            if (!params.reflectIn && params.width < 8) {
                reg = processFileBitwise(fis, buffer, params, reg, topBit, mask);
            } else if (params.reflectIn) {
                reg = processFileReflected(fis, buffer, params, reg, topBit, mask);
            } else {
                reg = processFileNonReflected(fis, buffer, params, reg, topBit, mask);
            }
        } catch (IOException e) {
            throw new CryptoException("I/O error while reading file: " + file.getAbsolutePath(), e);
        }
        return reg;
    }

    /**
     * Process file using bitwise CRC computation for narrow widths (< 8 bits).
     * 
     * <p>This method is used when the CRC width is less than 8 bits and the input
     * is not reflected. It processes each bit individually for maximum accuracy.</p>
     * 
     * @param fis the file input stream
     * @param buffer the read buffer
     * @param params the CRC parameters
     * @param reg the current CRC register value
     * @param topBit the top bit mask
     * @param mask the CRC width mask
     * @return the updated CRC register value
     * @throws IOException if I/O errors occur during file reading
     */
    private static long processFileBitwise(FileInputStream fis, byte[] buffer, CRCParameters params, long reg,
            long topBit, long mask) throws IOException {
        int read;
        while ((read = fis.read(buffer)) != -1) {
            for (int i = 0; i < read; i++) {
                int v = buffer[i] & 0xFF;
                for (int k = 0; k < 8; k++) {
                    boolean bit = ((reg & topBit) != 0) ^ ((v & 0x80) != 0);
                    reg = (reg << 1) & mask;
                    if (bit) {
                        reg ^= params.polynomial;
                    }
                    v <<= 1;
                }
            }
        }
        return reg;
    }

    /**
     * Process file using reflected table-driven CRC computation.
     * 
     * <p>This method is used when the CRC input is reflected. It uses a pre-computed
     * lookup table for efficient 8-bit processing.</p>
     * 
     * @param fis the file input stream
     * @param buffer the read buffer
     * @param params the CRC parameters
     * @param reg the current CRC register value
     * @param topBit the top bit mask
     * @param mask the CRC width mask
     * @return the updated CRC register value
     * @throws IOException if I/O errors occur during file reading
     */
    private static long processFileReflected(FileInputStream fis, byte[] buffer, CRCParameters params, long reg,
            long topBit, long mask) throws IOException {
        long[] table = buildTable(params, topBit, mask);
        int read;
        while ((read = fis.read(buffer)) != -1) {
            for (int i = 0; i < read; i++) {
                int idx = (int) ((reg ^ (buffer[i] & 0xFF)) & 0xFF);
                reg = (reg >>> 8) ^ table[idx];
            }
        }
        return reg;
    }

    /**
     * Process file using non-reflected table-driven CRC computation.
     * 
     * <p>This method is used when the CRC input is not reflected. It uses a pre-computed
     * lookup table for efficient 8-bit processing, handling both wide and narrow widths.</p>
     * 
     * @param fis the file input stream
     * @param buffer the read buffer
     * @param params the CRC parameters
     * @param reg the current CRC register value
     * @param topBit the top bit mask
     * @param mask the CRC width mask
     * @return the updated CRC register value
     * @throws IOException if I/O errors occur during file reading
     */
    private static long processFileNonReflected(FileInputStream fis, byte[] buffer, CRCParameters params, long reg,
            long topBit, long mask) throws IOException {
        long[] table = buildTable(params, topBit, mask);
        int read;
        while ((read = fis.read(buffer)) != -1) {
            for (int i = 0; i < read; i++) {
                int idx = (params.width >= 8)
                        ? (int) (((reg >>> (params.width - 8)) ^ (buffer[i] & 0xFF)) & 0xFF)
                        : (int) ((((reg << (8 - params.width)) & 0xFF) ^ (buffer[i] & 0xFF)) & 0xFF);
                reg = ((reg << 8) & mask) ^ table[idx];
            }
        }
        return reg;
    }

    /**
     * Build a lookup table for table-driven CRC computation.
     * 
     * <p>This method creates a 256-entry lookup table that can be used to compute
     * CRC values efficiently. The table building strategy depends on whether the
     * CRC algorithm uses reflected input or not.</p>
     * 
     * @param params the CRC parameters
     * @param topBit the top bit mask for the CRC width
     * @param mask the bit mask for the CRC width
     * @return a 256-element lookup table for CRC computation
     */
    private static long[] buildTable(CRCParameters params, long topBit, long mask) {
        long[] table = new long[256];
        if (params.reflectIn) {
            buildReflectedTable(table, params, mask);
        } else {
            buildNonReflectedTable(table, params, topBit, mask);
        }
        return table;
    }

    /**
     * Build a lookup table for reflected CRC algorithms.
     * 
     * <p>For reflected algorithms, the input bytes are processed from least significant
     * bit to most significant bit. This method builds a table that handles the
     * right-shift operations required for reflected processing.</p>
     * 
     * @param table the table array to populate
     * @param params the CRC parameters
     * @param mask the CRC width mask
     */
    private static void buildReflectedTable(long[] table, CRCParameters params, long mask) {
        for (int i = 0; i < 256; i++) {
            long crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 1L) != 0) {
                    crc = (crc >>> 1) ^ params.polynomial;
                } else {
                    crc = (crc >>> 1);
                }
            }
            table[i] = crc & mask;
        }
    }

    /**
     * Build a lookup table for non-reflected CRC algorithms.
     * 
     * <p>For non-reflected algorithms, the input bytes are processed from most significant
     * bit to least significant bit. This method builds a table that handles the
     * left-shift operations required for non-reflected processing.</p>
     * 
     * @param table the table array to populate
     * @param params the CRC parameters
     * @param topBit the top bit mask for the CRC width
     * @param mask the CRC width mask
     */
    private static void buildNonReflectedTable(long[] table, CRCParameters params, long topBit, long mask) {
        for (int i = 0; i < 256; i++) {
            long crc = ((long) i) << (params.width - 8);
            for (int j = 0; j < 8; j++) {
                if ((crc & topBit) != 0) {
                    crc = ((crc << 1) & mask) ^ params.polynomial;
                } else {
                    crc = (crc << 1) & mask;
                }
            }
            table[i] = crc & mask;
        }
    }

    /**
     * Reflect the bottom 'width' bits of a value.
     * 
     * <p>This method performs bit reflection, which is commonly used in CRC algorithms.
     * It reverses the order of bits within the specified width. For example, if width=8
     * and value=0x12 (00010010), the result would be 0x48 (01001000).</p>
     * 
     * @param value the value to reflect
     * @param width the number of bits to reflect
     * @return the reflected value
     */
    private static long reflect(long value, int width) {
        long res = 0L;
        for (int i = 0; i < width; i++) {
            if (((value >>> i) & 1L) != 0) {
                res |= (1L << (width - 1 - i));
            }
        }
        return res;
    }
}
