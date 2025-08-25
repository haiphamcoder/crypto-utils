# Technical Documentation: Cyclic Redundancy Check (CRC)

## 1) Introduction

Cyclic Redundancy Check (CRC) is a widely used error-detection technique for transmitted and stored data. CRC does not encrypt or compress data; instead, it computes a checksum from the original data using algebra over the binary field GF(2). Upon reception or retrieval, the system recomputes the CRC and compares it with the attached checksum. A mismatch indicates that the data was likely corrupted.

- **Primary role**: Detect random errors (bit flips, noise, attenuation, storage errors).
- **Characteristics**: Efficient, high throughput, easy to implement in both software and hardware.
- **Limitation**: CRC detects errors but does not correct them; higher-level mechanisms (retransmission, discard, error reporting) are required.

---

## 2) Operating principle (GF(2) math, polynomial division modulo 2)

CRC treats a bitstream as a polynomial over GF(2), where each bit is a coefficient (0 or 1). For example, the bit string 1101 corresponds to the polynomial \(x^3 + x^2 + 1\).

- **Generator polynomial G(x)**: A fixed, standard-specific polynomial used to compute the checksum. For instance, CRC-32 (IEEE 802.3) uses polynomial \(0x04C11DB7\) in normal (non-reflected) form.
- **Polynomial division modulo 2**: Similar to long division, but addition/subtraction are XOR (in GF(2): 1+1=0, 1-1=0, 1+0=1). There are no carries or borrows.
- **High-level process**:
  1) Take the data polynomial \(D(x)\) and multiply by \(x^n\) (n = degree of \(G(x)\)) to reserve space for the CRC.
  2) Divide \(D(x) \cdot x^n\) by \(G(x)\) modulo 2.
  3) The remainder \(R(x)\), with degree < n, is the CRC checksum.
  4) Transmit \(D(x)\) along with \(R(x)\). The receiver checks whether \([D(x) \cdot x^n + R(x)] \bmod G(x) = 0\).

Many CRC standards also define extra parameters: input reflection (refin), output reflection (refout), initial value (init), and output XOR (xorOut). These parameters characterize a standard and influence the resulting checksum.

---

## 3) CRC algorithm (step-by-step) with example

Assume a CRC variant defined by: width, polynomial, initialValue, reflectIn, reflectOut, xorOut. A generic algorithm (using a 256-entry lookup table for performance, or bit-wise for small widths):

1) Initialize the CRC register = initialValue (masked to the given width).
2) For each input byte:
   - If reflectIn = true: combine the byte in reflected form (typically XOR then shift right); otherwise combine non-reflected (shift left).
   - Update the CRC over 8 bit rounds using shifts and conditional XOR with the polynomial (reflected/non-reflected logic). With the table-driven approach, index into a precomputed table.
3) After processing all bytes:
   - If reflectOut XOR reflectIn = true, reflect the CRC value over the given width.
   - CRC = (CRC XOR xorOut), then mask to width.

Example (CRC-16/ARC, a common variant):

- width = 16, polynomial (reflected) = 0xA001, initialValue = 0x0000, refin = true, refout = true, xorOut = 0x0000.
- Data: "123456789" (canonical CRC test vector). Expected result: 0xBB3D.

You can verify with this library:

```java
long crc16 = com.haiphamcoder.crypto.hash.crc.CRCUtil.crc16("123456789"); // 0xBB3D
```

---

## 4) Common CRC standards

- **CRC-16/ARC (IBM)**
  - Width: 16
  - Polynomial (normal/reflected): 0x8005 / 0xA001
  - Init: 0x0000, refin: true, refout: true, xorOut: 0x0000
  - Test vector "123456789" -> 0xBB3D

- **CRC-32/ISO-HDLC (CRC-32 IEEE 802.3/ADCCP)**
  - Width: 32
  - Polynomial (normal/reflected): 0x04C11DB7 / 0xEDB88320
  - Init: 0xFFFFFFFF, refin: true, refout: true, xorOut: 0xFFFFFFFF
  - Test vector "123456789" -> 0xCBF43926

- **CRC-64/ECMA-182**
  - Width: 64
  - Polynomial: 0x42F0E1EBA9EA3693 (normal)
  - Init: 0x0000000000000000, refin: false, refout: false, xorOut: 0x0000000000000000
  - Test vector "123456789" -> 0x6C40DF5F0B497347

This library also includes other presets: CRC-7/MMC, CRC-8/SMBUS, CRC-10/ATM, CRC-11/FLEXRAY, CRC-15/CAN, CRC-24/OPENPGP, etc., all available via `CRCPresets`.

---

## 5) Practical applications

- **Ethernet (IEEE 802.3)**: Uses CRC-32 to detect frame errors.
- **USB**: Uses CRC-5 and CRC-16 in different protocol layers for error detection.
- **ZIP/PNG/GZIP**: Use CRC-32 to detect corruption in compressed files and images.
- **CAN, FlexRay (Automotive)**: Use CRC-15/CAN and CRC-11/FLEXRAY for frame integrity.
- **MMC/SD**: CRC-7/MMC for memory card data transfers.
- **OpenPGP**: CRC-24/OPENPGP for ASCII-armored packets.

CRC is pervasive across networking protocols, storage, archives, and embedded systems due to its low computational cost and strong detection capability for random errors.

---

### 6) Limitations

- **No error correction**: CRC only detects errors; higher-level schemes (ARQ, retransmission) must correct them.
- **Vulnerable to intentional tampering**: CRC is linear and public; an attacker can modify data and recompute a valid CRC. CRC does not provide cryptographic integrity or authentication.
- **Collision probability**: There is always a (small) chance different messages share the same CRC. Larger widths reduce this risk.

---

## 7) Using this library (`crypto-utils`)

- Core sources: `com.haiphamcoder.crypto.hash.crc.CRC`, `CRCParameters`, `CRCPresets`, `CRCUtil`.
- Supports both table-driven and bit-wise processing; supports file streaming for large data.
- Provides standard presets and short alias APIs like `crc16(...)`, `crc32(...)`, `crc64(...)` for convenience.

Examples:

```java
// CRC-32 (ISO-HDLC / IEEE 802.3) over a UTF-8 string
long c32 = com.haiphamcoder.crypto.hash.crc.CRCUtil.crc32("Hello");

// CRC-16/ARC for HEX input, output as lowercase HEX
String c16 = com.haiphamcoder.crypto.hash.crc.CRCUtil.crc16(
    "313233343536373839",
    com.haiphamcoder.crypto.encoding.InputEncoding.HEX,
    com.haiphamcoder.crypto.encoding.OutputEncoding.HEX_LOWER
);
```

---

## 8) References

- ISO/IEC 3309, ITU-T V.42, IEEE 802.3: CRC-32/ADCCP definitions.
- ECMA-182: CRC-64/ECMA-182 definition.
- Koopman, P. “32-Bit Cyclic Redundancy Codes for Internet Applications.”
- Williams, R. “A Painless Guide to CRC Error Detection Algorithms.”
