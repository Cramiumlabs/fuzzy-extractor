# rust-fuzzy-extractor

## Note
This project is a Proof of Concept (PoC) and is not intended yet for production use. It demonstrates the implementation of a Fuzzy Extractor for generating stable cryptographic keys from noisy data, such as biometric inputs or physical unclonable functions (PUFs).

## Fuzzy Extractor Implementation

### Overview
This implementation provides a complete Fuzzy Extractor system suitable for embedded systems. A fuzzy extractor generates stable cryptographic keys from noisy biometric or physical data (like PUF responses).

### Build Features

#### Feature Flags
- **std (default):** Standard library support with all features
- **no_std:** Embedded/bare-metal support without standard library
- **jemalloc:** Enable jemalloc allocator for benchmarking (requires std)

#### Building
```bash
# Standard build (default)
cargo build

# No-std build for embedded systems
cargo build --no-default-features --features no_std

# Build with jemalloc for benchmarking
cargo build --features jemalloc

# Using Makefile
make build-lib-std      # Build with std feature
make build-lib-nostd    # Build with no_std feature
make build-lib-all      # Build both variants
```

### Features

#### 1. Configurable Key Derivation Function (KDF) Trait
```rust
pub trait KeyDerivationFunction {
    fn derive(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str>;
}
```
The KDF trait allows you to plug in different key derivation algorithms:

- **Provided:** SimpleHashKdf - A lightweight implementation using XOR and byte rotation
- **Extendable:** Can be extended with any other KDF implementation (e.g., HKDF, PBKDF2)

#### 2. Fuzzy Extractor
```rust
pub struct FuzzyExtractor<E: ECC, K: KeyDerivationFunction>
```
The main fuzzy extractor combines:

- **SecureSketch:** For error correction (from ecc.rs)
- **KeyDerivationFunction:** For deriving cryptographic keys

##### Two-Phase Operation

###### Generate Phase
```rust
let (key, public_helper) = extractor.generate(w, seed_input)?;
```
- **Input:**
  - `w`: Noisy biometric/PUF data
  - `seed_input`: Seed material for key derivation (random or deterministic)
- **Output:**
  - `key`: Stable cryptographic key
  - `public_helper`: Public helper data (safe to store)

###### Reproduce Phase
```rust
let key = extractor.reproduce(w_prime, &public_helper)?;
```
- **Input:** Noisy data `w_prime` (close to `w`) + public helper
- **Output:** Same key as generate phase (if noise is within tolerance)

### Secure Sketch Flow

#### Sketch Phase
- **Input:** `x` (noisy data) and `m` (random secret).
- **ECC Key Generation:** Generate a codeword `c` using `m` via the ECC's `keygen` method.
- **Validation:** Ensure `x`'s length does not exceed the codeword length.
- **Extension:** Extend `x` to match the codeword length.
- **Helper Generation:** Compute helper as `c XOR x_ext`.
- **Output:** Return the helper.

#### Recover Phase
- **Input:** `helper`, `x'` (noisy version of `x`), and optional `known_erasures`.
- **Validation:** Ensure `x''`s length does not exceed the helper length.
- **Extension:** Extend `x'` to match the helper length.
- **Codeword Recovery:** Compute `c'` as `helper XOR x'_ext`.
- **ECC Reproduction:** Use the ECC's `reproduce` method to recover the original codeword `c`.
- **Output:** Return the recovered codeword.

### Security Notes
- The sketch function implements only the Secure Sketch phase (`helper = Encode(m) XOR x`).
- It does not perform entropy extraction or key derivation.
- The caller must ensure that `m` is strongly random to maintain security.

#### Recommendation
It is recommended that the size of the input `w` matches the output of the `Encode(m)` function. This ensures that runtime checks and transformations can be avoided, improving efficiency and performance.

#### Security Recommendation
For security reasons, developers should consider using the `extend_x` function to ensure that the size of `x` matches the length of the output of `Encode(m)`. This alignment helps prevent potential vulnerabilities arising from inconsistent input sizes and ensures that the system operates as intended.

### Usage Example
```rust
use rust_fuzzy_extractor::ecc::ReedSolomonECC;
use rust_fuzzy_extractor::fuzzy_extractor::{FuzzyExtractor, SimpleHashKdf};

// Configure the system
let msg_len = 16;
let err_rate = 0.2;  // Can correct up to 20% errors
let key_len = 32;    // 256-bit key

// Create components
let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
let kdf = SimpleHashKdf::new_no_salt();
let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();

// Generate phase (enrollment)
let biometric_data = b"user_fingerprint_data";
// Create seed input (could be random or derived from other source)
let seed_input = b"random_seed_or_derived_value";
let (key, helper) = extractor.generate(biometric_data, seed_input).unwrap();
// Store 'helper' publicly, use 'key' for encryption

// Reproduce phase (authentication)
let noisy_biometric = b"user_fingerprint_data"; // With noise
let recovered_key = extractor.reproduce(noisy_biometric, &helper).unwrap();
// 'recovered_key' == 'key' if noise is within tolerance
```

### Implementation Details

#### SimpleHashKdf
A lightweight KDF implementation suitable for a PoC:

- Uses simple operations: XOR, byte rotation, wrapping arithmetic
- No heavy cryptographic libraries required
- Deterministic output for same input
- Configurable with optional salt

**Note:** For production systems, consider using proper cryptographic KDFs like HKDF.

#### Error Correction
- Based on Reed-Solomon ECC
- Configurable error rate (0.0 to 0.5)
- Automatically calculates required parity bits
- Handles variable-length inputs through padding

#### No-std Compatibility
- Fully compatible with `no_std` environments
- Uses `alloc` for dynamic memory
- Suitable for embedded systems



### Running Tests
```bash
# Using Makefile
make test                 # Run all library tests (default: std feature)
make test-std             # Run tests with std feature
make test-all             # Run tests for both std and no_std

# Using cargo directly
cargo test                # Run tests with default features
cargo test --features std # Run tests with std feature
cargo test --no-default-features --features no_std  # Run no_std tests (limited)
```

### Benchmarks
The project includes comprehensive benchmarks to measure performance. Benchmarks are run with the `jemalloc` feature enabled for optimal memory allocation performance.

#### Running Benchmarks
```bash
# Using Makefile (recommended - automatically enables jemalloc)
make bench

# Using cargo directly with jemalloc feature
cargo bench --features jemalloc -- --nocapture

# Run specific benchmark
cargo bench --features jemalloc bench_fuzzy_extractor_generate -- --nocapture
```
**Note:** The `--nocapture` flag is used to display memory usage statistics printed by the memory benchmarks.

#### Benchmark Configuration
The benchmarks use:

- **Allocator:** jemalloc (enabled via jemalloc feature flag)
- **Message lengths:** 16-32 bytes
- **Error rates:** 0.1-0.2 (10-20%)
- **Key lengths:** 32-128 bytes
- **Test data:** Synthetic biometric-like inputs

### Security Considerations

#### Production Use
- Replace `SimpleHashKdf` with a proper cryptographic KDF (e.g., HKDF, PBKDF2).
- Use a true random number generator for seed generation.
- Protect the `public_helper` data from unauthorized modification, as it is critical for key reproduction.

#### Key Storage
Derived keys should be handled securely and never stored in plaintext.

#### Enhancing Security
- Ensure that the `seed_input` is derived from a high-entropy source (e.g., a cryptographic random number generator).
- Use a cryptographically secure KDF (e.g., HKDF) instead of the provided `SimpleHashKdf` for production environments.
- Regularly audit the implementation for vulnerabilities and ensure compliance with cryptographic best practices.

### Customization

#### Custom KDF Implementation
```rust
struct MyCustomKdf {
    // Your fields
}

impl KeyDerivationFunction for MyCustomKdf {
    fn derive(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str> {
        // Your implementation
    }
}

// Use it
let kdf = MyCustomKdf { /* ... */ };
let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
```

#### Adjusting Error Tolerance
```rust
// Higher error rate = more tolerance but larger helper data
let ecc_high_tolerance = ReedSolomonECC::new(16, 0.25).unwrap();

// Lower error rate = less tolerance but smaller helper data
let ecc_low_tolerance = ReedSolomonECC::new(16, 0.10).unwrap();
```

### File Structure
```
src/
├── ecc.rs              # Error correction codes & SecureSketch
├── fuzzy_extractor.rs  # Fuzzy Extractor & KDF trait (NEW)
└── lib.rs             # Module exports
```

### License & Attribution
Part of the rust-fuzzy-extractor project.

### Why Fuzzy Extractor Works

#### Key Generation
- **Encoding:** The message `m` is encoded into a codeword `c` using an Error-Correcting Code (ECC).
- **Helper Data:** The helper data `w` is computed as `c XOR x`, where `x` is the noisy input. This helper data is stored publicly.

#### Reproduction
- **Reconstructing Codeword:** During reproduction, the noisy input `x'` is used to compute `c'` as `w XOR x'`. This reconstructs a noisy version of the original codeword `c`.
- **Decoding:** The ECC's `Decode` function is applied to `c'` to recover the original message `m` if `x'` is sufficiently close to `x` (i.e., within the error-correcting capability of the ECC).

#### Why It Works
- **Error Correction:** The ECC ensures that small differences between `x` and `x'` (caused by noise) can be corrected during the decoding process. This allows the original message `m` to be recovered accurately.
- **XOR Properties:** The XOR operation ensures that the helper data `w` does not reveal `m` or `c` directly, preserving security. The reconstruction process reverses the XOR operation to retrieve the noisy codeword `c`.
- **Security:** The security of the Fuzzy Extractor relies on the randomness of `m` and the error-correcting capability of the ECC. The helper data `w` does not leak information about `m` as long as `m` is strongly random.

### Mathematical Validation of Fuzzy Extractor

#### 1. Enrollment Phase
- **Encoding:** The message `m` is encoded into a codeword `c` using an Error-Correcting Code (ECC):
  ```
  c = Encode(m)
  ```
- **Helper Data:** The helper data `w` is computed as:
  ```
  w = c ⊕ x
  ```
  where `x` is the user's input. This can be rewritten as:
  ```
  c = w ⊕ x
  ```
  This is simply a masking of the codeword `c` by the user's input `x`.

#### 2. Reconstruction Phase
- **Reconstructing Codeword:** Given a noisy input `x'` close to `x` (Hamming distance ≤ `t`), compute:
  ```
  c' = w ⊕ x' = (c ⊕ x) ⊕ x' = c ⊕ (x ⊕ x')
  ```
- **Error Pattern:** Let the error pattern `e` be:
  ```
  e = x ⊕ x'
  ```
  Then:
  ```
  c' = c ⊕ e
  ```
  This means `c'` is the true codeword `c` plus an error pattern `e`.

#### 3. Error Correction
- **Decoding:** If the ECC can correct up to `t` errors, and if `|e| ≤ t`, then:
  ```
  Decode(c') = Decode(c ⊕ e) = m
  ```
  Thus, the recovered message `m'` equals the original message `m`:
  ```
  m' = m
  ```

#### 4. Security Perspective
- **Helper Data Security:** The helper data `w = c ⊕ x` leaks only the XOR difference between two high-entropy variables. If `x` has sufficient min-entropy and the code is linear, then `w` does not reveal useful information about `m`. It acts as a one-time pad masking of the codeword.

### ✅ Conclusion
The Fuzzy Extractor construction is mathematically consistent and correct:
```math
c = Encode(m) \\ 
w = c ⊕ x \\ 
c' = w ⊕ x' = c ⊕ (x ⊕ x') \\ 
m' = Decode(c') = m \text{ if } d(x, x') ≤ t
```
This is the canonical Secure Sketch / Fuzzy Extractor formulation (Dodis et al., 2004).

### Metadata Structure for Multi-Block Helpers

The metadata structure for multi-block helpers is designed to support efficient processing of large inputs by dividing them into smaller blocks. This structure ensures that each block can be processed independently while maintaining the integrity of the overall data.

#### Metadata Fields

1. **Block Size:**
   - Specifies the size of each block in bytes.
   - Ensures consistent processing across all blocks.

2. **Number of Blocks:**
   - Indicates the total number of blocks in the input data.
   - Helps in validating the completeness of the data.

3. **Error Tolerance per Block:**
   - Defines the maximum allowable errors for each block.
   - Configurable based on the error-correcting capability of the ECC.

4. **Helper Data:**
   - Contains the public helper data for each block.
   - Stored as an array of helper data structures, one for each block.

5. **Checksum:**
   - A cryptographic checksum of the entire input data.
   - Ensures data integrity and detects tampering.

#### Example

For an input divided into 4 blocks, each of size 16 bytes, with an error tolerance of 2 errors per block, the metadata structure might look like this:

```json
{
  "block_size": 16,
  "num_blocks": 4,
  "error_tolerance": 2,
  "helpers": [
    "helper_block_1",
    "helper_block_2",
    "helper_block_3",
    "helper_block_4"
  ],
  "checksum": "a1b2c3d4e5f6g7h8"
}
```

#### Usage

The metadata structure is used during both the generate and reproduce phases:

- **Generate Phase:**
  - The input data is divided into blocks based on the specified block size.
  - Each block is processed independently to generate its helper data.
  - The metadata is constructed and stored along with the helper data.

- **Reproduce Phase:**
  - The metadata is used to validate the input data and ensure it matches the expected structure.
  - Each block is processed independently using its corresponding helper data to recover the original input.

#### Security Considerations

- **Integrity:** The checksum field ensures that the metadata and helper data have not been tampered with.
- **Error Tolerance:** Configuring the error tolerance per block allows for fine-grained control over the error-correcting capability.
- **Scalability:** The block-based structure enables efficient processing of large inputs without requiring excessive memory or computational resources.
