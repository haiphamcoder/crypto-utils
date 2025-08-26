package io.github.haiphamcoder.crypto.hash.crc;

/**
 * Parameters defining a CRC algorithm instance.
 * 
 * <p>This class encapsulates all the parameters needed to define a specific CRC algorithm:</p>
 * <ul>
 *   <li><b>width</b>: The number of bits in the CRC (1-64)</li>
 *   <li><b>polynomial</b>: The generator polynomial (truncated, without top bit)</li>
 *   <li><b>initialValue</b>: The initial value loaded into the CRC register</li>
 *   <li><b>xorOut</b>: The value XORed with the final CRC before output</li>
 *   <li><b>reflectIn</b>: Whether input bytes are reflected before processing</li>
 *   <li><b>reflectOut</b>: Whether the final CRC is reflected before output</li>
 * </ul>
 * 
 * <p>These parameters are used by the CRC engine to compute checksums according to
 * various CRC standards and specifications.</p>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * // CRC-16/ARC parameters
 * CRCParameters params = new CRCParameters(
 *     16,           // 16-bit CRC
 *     0xA001L,      // polynomial (reflected form)
 *     0x0000L,      // initial value
 *     0x0000L,      // XOR output
 *     true,         // reflect input
 *     true          // reflect output
 * );
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class CRCParameters {
    public final int width; // number of bits in CRC
    public final long polynomial; // truncated polynomial without the top bit
    public final long initialValue; // initial register value
    public final long xorOut; // final XOR value
    public final boolean reflectIn; // reflect input bytes
    public final boolean reflectOut; // reflect final CRC

    /**
     * Constructs a new CRCParameters instance with the specified values.
     * 
     * <p>All polynomial, initial value, and XOR output values are automatically
     * masked to fit within the specified width to ensure proper CRC computation.</p>
     * 
     * @param width the number of bits in the CRC (must be 1-64)
     * @param polynomial the generator polynomial (truncated form, without top bit)
     * @param initialValue the initial value for the CRC register
     * @param xorOut the value XORed with the final CRC before output
     * @param reflectIn whether input bytes should be reflected before processing
     * @param reflectOut whether the final CRC should be reflected before output
     * @throws IllegalArgumentException if width is not in the range 1-64
     */
    public CRCParameters(int width, long polynomial, long initialValue, long xorOut, boolean reflectIn,
            boolean reflectOut) {
        if (width <= 0 || width > 64) {
            throw new IllegalArgumentException("CRC width must be in range 1..64");
        }
        this.width = width;
        this.polynomial = mask(width, polynomial);
        this.initialValue = mask(width, initialValue);
        this.xorOut = mask(width, xorOut);
        this.reflectIn = reflectIn;
        this.reflectOut = reflectOut;
    }

    /**
     * Masks a value to fit within the specified bit width.
     * 
     * <p>This utility method ensures that polynomial, initial value, and XOR output
     * values are properly truncated to fit within the CRC width. For 64-bit CRCs,
     * no masking is applied since long values already fit within 64 bits.</p>
     * 
     * @param width the bit width to mask to
     * @param value the value to mask
     * @return the masked value (value & ((1 << width) - 1))
     */
    static long mask(int width, long value) {
        if (width == 64)
            return value;
        long mask = (1L << width) - 1L;
        return value & mask;
    }
}
