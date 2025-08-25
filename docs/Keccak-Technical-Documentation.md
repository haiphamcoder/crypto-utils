# Technical Documentation: Keccak (Predecessor of SHA-3)

## 1) Introduction to Keccak

Keccak is a family of cryptographic sponge functions that won NIST’s SHA-3 competition (2012). It became the basis for the SHA-3 standard (FIPS 202). Unlike SHA-1/SHA-2, which follow Merkle–Damgård-style constructions, Keccak uses a sponge construction, bringing different security and design properties.

- **Importance**: Selected by NIST to diversify hash designs beyond Merkle–Damgård and provide a modern, secure alternative.
- **Key characteristics**:
  - **Sponge construction**: Absorb-then-squeeze paradigm over a fixed-size internal state.
  - **Permutation-based**: Uses a fixed permutation (Keccak-p) applied iteratively to the state.
  - **Configurable**: Security level and output length are adjusted via rate (r) and capacity (c).

---

## 2) Sponge function principle

A sponge function operates on a fixed-size internal state `b = r + c` bits, where:

- **Rate (r)**: Number of bits processed (absorbed/squeezed) per permutation call. Higher r → higher throughput.
- **Capacity (c)**: Security parameter related to collision/preimage resistance (roughly, security ≈ c/2 bits). Higher c → stronger security but lower speed.

Phases:

- **Absorption**: The input is padded and split into r-bit blocks. Each block is XORed into the first r bits of the state, then the permutation is applied.
- **Squeezing**: After all input is absorbed, output bits are read from the first r bits of the state. If more output is needed, apply the permutation again and continue.

The separation between r and c allows Keccak to scale output length (XOFs) and target security levels by tuning c.

---

## 3) Keccak permutation and rounds (Keccak-p)

Keccak-p is the internal permutation applied on the state across multiple rounds. Each round consists of five steps applied to a 5×5×w state (w depends on capacity/variant):

- **θ (theta)**: Mix columns to diffuse parity across the state.
- **ρ (rho)**: Apply rotations to each lane for intra-lane diffusion.
- **π (pi)**: Permute lane positions (rearranges the 5×5 mapping).
- **χ (chi)**: Non-linear step; each bit is updated based on a non-linear Boolean function over row neighbors.
- **ι (iota)**: XOR round constants into the state to break symmetries.

By configuring the number of rounds and state size, Keccak instantiates variants used for SHA-3 output sizes.

---

## 4) From Keccak to SHA-3 (and SHAKE)

- **SHA-3 hash functions**: Defined for fixed outputs — **SHA3-224**, **SHA3-256**, **SHA3-384**, **SHA3-512**. They use specific `(r, c)` parameters to match the desired security level.
- **SHAKE (XOFs)**: SHAKE128 and SHAKE256 are extendable-output functions derived from Keccak. They produce arbitrary-length output and are used in contexts like KMAC and post-quantum schemes.
- **Keccak vs SHA-3**: Keccak is the original submission; SHA-3 standardized some padding and parameter tweaks. Many libraries still expose "Keccak-256" (original padding) alongside "SHA3-256" (FIPS 202 padding).

---

## 5) Applications

- **Cryptocurrencies**: Ethereum uses **Keccak-256** (pre-standardization padding) for addresses and transaction processing.
- **Security protocols**: SHA-3 functions serve as drop-in alternatives to SHA-2 for hashing, signatures, and integrity.
- **XOF-based constructions**: SHAKE for KMAC, cSHAKE for customization, and as building blocks in modern cryptographic designs.

---

## 6) Comparison with SHA-2

- **Design**: SHA-2 uses Merkle–Damgård with Davies–Meyer-style compression; Keccak/SHA-3 use a sponge with permutation rounds.
- **Security posture**: Both are considered secure today. SHA-3 was intended as a hedge should serious weaknesses be found in SHA-2.
- **Performance**: Depends on platform and implementation. SHA-2 is often faster on hardware with SHA extensions; Keccak/SHA-3 can be competitive and benefit from bit-slicing and vectorization.

---

## 7) Using this library (crypto-utils)

- Class: `com.haiphamcoder.crypto.hash.keccak.KeccakUtil`
- Variants: Keccak-224/256/288/384/512
- Inputs: `byte[]`, `String` (with `Charset`), `File`
- Encodings: `InputEncoding` and `OutputEncoding` for flexible I/O formats

Examples:

```java
// Keccak-256 over UTF-8 input, Base64 output
String b64 = KeccakUtil.keccak256("Hello", InputEncoding.UTF8, OutputEncoding.BASE64);

// Keccak-512 over HEX input, uppercase HEX output
String h = KeccakUtil.keccak512("48656C6C6F", InputEncoding.HEX, OutputEncoding.HEX_UPPER);
```

---

## 8) References

- FIPS 202: SHA-3 Standard (includes sponge construction details)
- Keccak team website and papers by Bertoni, Daemen, Peeters, Van Assche
- NIST SHA-3 competition reports and final selection documentation
