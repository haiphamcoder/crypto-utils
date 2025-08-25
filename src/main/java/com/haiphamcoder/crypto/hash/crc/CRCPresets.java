package com.haiphamcoder.crypto.hash.crc;

/**
 * Common CRC presets used in the project.
 * 
 * <p>This class provides predefined CRC parameters for commonly used CRC algorithms.
 * All polynomials are given as truncated values (without the top bit), which is
 * consistent with standard CRC definitions and the implementation in the CRC engine.</p>
 * 
 * <p>Available presets include:</p>
 * <ul>
 *   <li><b>CRC-7/MMC</b>: Used in MultiMediaCard protocol</li>
 *   <li><b>CRC-8/SMBUS</b>: Used in System Management Bus</li>
 *   <li><b>CRC-10/ATM</b>: Used in Asynchronous Transfer Mode</li>
 *   <li><b>CRC-11/FLEXRAY</b>: Used in FlexRay automotive protocol</li>
 *   <li><b>CRC-15/CAN</b>: Used in Controller Area Network</li>
 *   <li><b>CRC-16/ARC</b>: Used in ARCnet and many other protocols</li>
 *   <li><b>CRC-24/OPENPGP</b>: Used in OpenPGP message format</li>
 *   <li><b>CRC-32/ISO-HDLC</b>: Used in HDLC, Ethernet, and many other protocols</li>
 *   <li><b>CRC-64/ECMA-182</b>: Used in ECMA-182 standard</li>
 * </ul>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * // Use CRC-16/ARC preset
 * long crc = CRC.compute(data, CRCPresets.CRC16_ARC);
 * }</pre>
 * 
 * @author haiphamcoder
 * @since 1.0.0
 */
public final class CRCPresets {
        private CRCPresets() {
        }

        // CRC-7/MMC: width=7 poly=0x09 init=0x00 refin=false refout=false xorout=0x00
        public static final CRCParameters CRC7_MMC = new CRCParameters(7, 0x09L, 0x00L, 0x00L, false, false);

        // CRC-8/SMBUS: width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x00
        public static final CRCParameters CRC8_SMBUS = new CRCParameters(8, 0x07L, 0x00L, 0x00L, false, false);

        // CRC-10/ATM: width=10 poly=0x233 init=0x000 refin=false refout=false
        // xorout=0x000
        public static final CRCParameters CRC10_ATM = new CRCParameters(10, 0x233L, 0x000L, 0x000L, false, false);

        // CRC-11/FLEXRAY: width=11 poly=0x385 init=0x01A refin=false refout=false
        // xorout=0x000
        public static final CRCParameters CRC11_FLEXRAY = new CRCParameters(11, 0x385L, 0x01AL, 0x000L, false, false);

        // CRC-15/CAN: width=15 poly=0x4599 init=0x0000 refin=false refout=false
        // xorout=0x0000
        public static final CRCParameters CRC15_CAN = new CRCParameters(15, 0x4599L, 0x0000L, 0x0000L, false, false);

        // CRC-16/ARC (aka IBM): width=16 poly=0xA001 (reflected) but in normal form
        // 0x8005
        // Standard definition uses refin=true, refout=true, init=0x0000, xorout=0x0000
        public static final CRCParameters CRC16_ARC = new CRCParameters(16, 0xA001L, 0x0000L, 0x0000L, true, true);

        // CRC-24/OPENPGP: width=24 poly=0x864CFB init=0xB704CE refin=false refout=false
        // xorout=0x000000
        public static final CRCParameters CRC24_OPENPGP = new CRCParameters(24, 0x864CFBL, 0xB704CEL, 0x000000L, false,
                        false);

        // CRC-32/ISO-HDLC (aka CRC-32/ADCCP): width=32 poly=0xEDB88320 (reflected)
        // normal 0x04C11DB7, refin=true, refout=true, init=0xFFFFFFFF,
        // xorout=0xFFFFFFFF
        public static final CRCParameters CRC32_ISO_HDLC = new CRCParameters(32, 0xEDB88320L, 0xFFFFFFFFL, 0xFFFFFFFFL,
                        true, true);

        // CRC-64/ECMA-182: width=64 poly=0x42F0E1EBA9EA3693 init=0x0000000000000000
        // refin=false refout=false xorout=0x0000000000000000
        public static final CRCParameters CRC64_ECMA_182 = new CRCParameters(64, 0x42F0E1EBA9EA3693L,
                        0x0000000000000000L,
                        0x0000000000000000L, false, false);

}
