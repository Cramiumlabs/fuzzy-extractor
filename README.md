# README

**Note:** This project is a Proof of Concept (PoC) and is not intended yet for production use. It demonstrates the implementation of a Fuzzy Extractor for generating stable cryptographic keys from noisy data, such as biometric inputs or physical unclonable functions (PUFs).

# Fuzzy Extractor Implementation

## Overview

This implementation provides a complete Fuzzy Extractor system suitable for embedded systems. A fuzzy extractor generates stable cryptographic keys from noisy biometric or physical data (like PUF responses).

## Build Features

The project supports multiple build configurations:

### Feature Flags

- **`std`** (default): Standard library support with all features
- **`no_std`**: Embedded/bare-metal support without standard library
- **`jemalloc`**: Enable jemalloc allocator for benchmarking (requires `std`)

### Building

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

## Features

### 1. **Configurable Key Derivation Function (KDF) Trait**
```rust
pub trait KeyDerivationFunction {
    fn derive(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str>;
}
```

The KDF trait allows you to plug in different key derivation algorithms:
- Provided: `SimpleHashKdf` - A lightweight implementation using XOR and byte rotation
- Can be extended with any other KDF implementation (HKDF, PBKDF2, etc.)

### 2. **Fuzzy Extractor**
```rust
pub struct FuzzyExtractor<E: ECC, K: KeyDerivationFunction>
```

The main fuzzy extractor combines:
- **SecureSketch**: For error correction (from ecc.rs)
- **KeyDerivationFunction**: For deriving cryptographic keys

#### Two-Phase Operation:

**Generate Phase:**
```rust
let (key, public_helper) = extractor.generate(w, seed_input)?;
```
- Input: 
  - `w`: Noisy biometric/PUF data
  - `seed_input`: Seed material for key derivation (random or deterministic)
- Output: 
  - `key`: Stable cryptographic key
  - `public_helper`: Public helper data (safe to store)

**Reproduce Phase:**
```rust
let key = extractor.reproduce(w_prime, &public_helper)?;
```
- Input: Noisy data `w_prime` (close to `w`) + public helper
- Output: Same key as generate phase (if noise is within tolerance)

### Secure Sketch Flow

#### Sketch Phase
1. **Input**: `x` (noisy data) and `m` (random secret).
2. **ECC Key Generation**: Generate a codeword `c` using `m` via the ECC's `keygen` method.
3. **Validation**: Ensure `x`'s length does not exceed the codeword length.
4. **Extension**: Extend `x` to match the codeword length.
5. **Helper Generation**: Compute `helper` as `c XOR x_ext`.
6. **Output**: Return the `helper`.

#### Recover Phase
1. **Input**: `helper`, `x'` (noisy version of `x`), and optional `known_erasures`.
2. **Validation**: Ensure `x'`'s length does not exceed the helper length.
3. **Extension**: Extend `x'` to match the helper length.
4. **Codeword Recovery**: Compute `c'` as `helper XOR x'_ext`.
5. **ECC Reproduction**: Use the ECC's `reproduce` method to recover the original codeword `c`.
6. **Output**: Return the recovered codeword.

#### Security Notes
- The `sketch` function implements only the Secure Sketch phase (`helper = Encode(m) XOR x`).
- It does **not** perform entropy extraction or key derivation.
- The caller must ensure that `m` is strongly random to maintain security.

### Recommendation
It is recommended that the size of the input `w` matches the output of the `Encode(m)` function. This ensures that runtime checks and transformations can be avoided, improving efficiency and performance.

### Security Recommendation
For security reasons, developers should consider using the `extend_x` function to ensure that the size of `x` matches the length of the output of `Encode(m)`. This alignment helps prevent potential vulnerabilities arising from inconsistent input sizes and ensures that the system operates as intended.

## Usage Example

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

## Implementation Details

### SimpleHashKdf
A lightweight KDF implementation suitable for a PoC:
- Uses simple operations: XOR, byte rotation, wrapping arithmetic
- No heavy cryptographic libraries required
- Deterministic output for same input
- Configurable with optional salt
- **Note**: For production systems, consider using proper cryptographic KDFs like HKDF

### Error Correction
- Based on Reed-Solomon ECC
- Configurable error rate (0.0 to 0.5)
- Automatically calculates required parity bits
- Handles variable-length inputs through padding

### No-std Compatibility
- Fully compatible with `no_std` environments
- Uses `alloc` for dynamic memory
- Suitable for embedded systems

## Test Coverage

The implementation includes comprehensive unit tests (43 tests total):

### KDF Tests (7 tests)
- Basic functionality
- Deterministic behavior
- Different inputs produce different outputs
- Salt support
- Various output lengths
- Error cases (empty input, zero length)

### Fuzzy Extractor Tests (36 tests)

**Success Cases (14 tests):**
- Basic round-trip without noise
- Recovery with various noise levels
- Multiple key lengths
- Different error rates
- Short and long inputs
- With and without salt
- Consistency checks
- Multiple reproduce operations

**Failure Cases (5 tests):**
- Empty input
- Zero key length
- Excessive noise
- Wrong helper data
- Empty reproduce input

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

## Benchmarks

The project includes comprehensive benchmarks to measure performance. Benchmarks are run with the `jemalloc` feature enabled for optimal memory allocation performance.

### Available Benchmarks

#### Fuzzy Extractor Benchmarks
- **bench_fuzzy_extractor_generate**: Measures key generation performance (24-byte input, 15% error rate, 32-byte key)
- **bench_fuzzy_extractor_reproduce_no_noise**: Measures key recovery with perfect input match
- **bench_fuzzy_extractor_reproduce_with_noise**: Measures key recovery with intentional noise (3 errors)
- **bench_fuzzy_extractor_generate_large_key**: Tests large key generation (32-byte input, 10% error rate, 128-byte key)
- **bench_fuzzy_extractor_full_round_trip**: Measures complete generate + reproduce cycle

#### Memory Usage Benchmarks
- **bench_memory_fuzzy_extractor_generate**: Reports memory usage for key generation
- **bench_memory_fuzzy_extractor_reproduce**: Reports memory usage for key reproduction
- **bench_memory_fuzzy_extractor_large_interleaved**: Tests interleaved block processing (384-byte input with 16-byte blocks)

### Running Benchmarks

```bash
# Using Makefile (recommended - automatically enables jemalloc)
make bench

# Using cargo directly with jemalloc feature
cargo bench --features jemalloc -- --nocapture

# Run specific benchmark
cargo bench --features jemalloc bench_fuzzy_extractor_generate -- --nocapture
```

**Note**: The `--nocapture` flag is used to display memory usage statistics printed by the memory benchmarks.

### Benchmark Configuration

The benchmarks use:
- **Allocator**: jemalloc (enabled via `jemalloc` feature flag)
- **Message lengths**: 16-32 bytes
- **Error rates**: 0.1-0.2 (10-20%)
- **Key lengths**: 32-128 bytes
- **Test data**: Synthetic biometric-like inputs

## Security Considerations

1. **Production Use**: Replace `SimpleHashKdf` with a proper cryptographic KDF (HKDF, PBKDF2)
2. **Randomness**: In production, use a true random number generator for seed generation
3. **Helper Data**: The public helper data is safe to store but may leak some information about the input distribution
4. **Key Storage**: Derived keys should be handled securely and never stored in plaintext

To enhance security:
- Ensure that the `seed_input` is derived from a high-entropy source (e.g., a cryptographic random number generator).
- Use a cryptographically secure KDF (e.g., HKDF) instead of the provided `SimpleHashKdf` for production environments.
- Protect the `public_helper` data from unauthorized modification, as it is critical for key reproduction.
- Regularly audit the implementation for vulnerabilities and ensure compliance with cryptographic best practices.

## Customization

### Custom KDF Implementation

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

### Adjusting Error Tolerance

```rust
// Higher error rate = more tolerance but larger helper data
let ecc_high_tolerance = ReedSolomonECC::new(16, 0.25).unwrap();

// Lower error rate = less tolerance but smaller helper data
let ecc_low_tolerance = ReedSolomonECC::new(16, 0.10).unwrap();
```

## File Structure

```
src/
├── ecc.rs              # Error correction codes & SecureSketch
├── fuzzy_extractor.rs  # Fuzzy Extractor & KDF trait (NEW)
└── lib.rs             # Module exports
```

## License & Attribution

Part of the rust-fuzzy-extractor project.

### Why Fuzzy Extractor Works

#### Key Generation
1. **Encoding**: The message `m` is encoded into a codeword `c` using an Error-Correcting Code (ECC).
2. **Helper Data**: The helper data `w` is computed as `c XOR x`, where `x` is the noisy input. This helper data is stored publicly.

#### Reproduction
1. **Reconstructing Codeword**: During reproduction, the noisy input `x'` is used to compute `c'` as `w XOR x'`. This reconstructs a noisy version of the original codeword `c`.
2. **Decoding**: The ECC's `Decode` function is applied to `c'` to recover the original message `m` if `x'` is sufficiently close to `x` (i.e., within the error-correcting capability of the ECC).

#### Why It Works
- **Error Correction**: The ECC ensures that small differences between `x` and `x'` (caused by noise) can be corrected during the decoding process. This allows the original message `m` to be recovered accurately.
- **XOR Properties**: The XOR operation ensures that the helper data `w` does not reveal `m` or `c` directly, preserving security. The reconstruction process reverses the XOR operation to retrieve the noisy codeword `c'`.
- **Security**: The security of the Fuzzy Extractor relies on the randomness of `m` and the error-correcting capability of the ECC. The helper data `w` does not leak information about `m` as long as `m` is strongly random`.

### Mathematical Validation of Fuzzy Extractor

#### 1. Enrollment Phase
- **Encoding**: The message `m` is encoded into a codeword `c` using an Error-Correcting Code (ECC):
  ```
  c = Encode(m)
  ```
- **Helper Data**: The helper data `w` is computed as:
  ```
  w = c ⊕ x
  ```
  where `x` is the user's input. This can be rewritten as:
  ```
  c = w ⊕ x
  ```
  This is simply a masking of the codeword `c` by the user's input `x`.

#### 2. Reconstruction Phase
- **Reconstructing Codeword**: Given a noisy input `x'` close to `x` (Hamming distance ≤ t), compute:
  ```
  c' = w ⊕ x' = (c ⊕ x) ⊕ x' = c ⊕ (x ⊕ x')
  ```
- **Error Pattern**: Let the error pattern `e` be:
  ```
  e = x ⊕ x'
  ```
  Then:
  ```
  c' = c ⊕ e
  ```
  This means `c'` is the true codeword `c` plus an error pattern `e`.

#### 3. Error Correction
- **Decoding**: If the ECC can correct up to `t` errors, and if `|e| ≤ t`, then:
  ```
  Decode(c') = Decode(c ⊕ e) = m
  ```
  Thus, the recovered message `m'` equals the original message `m`:
  ```
  m' = m
  ```

#### 4. Security Perspective
- **Helper Data Security**: The helper data `w = c ⊕ x` leaks only the XOR difference between two high-entropy variables. If `x` has sufficient min-entropy and the code is linear, then `w` does not reveal useful information about `m`. It acts as a one-time pad masking of the codeword.

#### ✅ Conclusion
The Fuzzy Extractor construction is mathematically consistent and correct:
```math
\begin{aligned}
&c = \text{Encode}(m) \\
&w = c \oplus x \\
&c' = w \oplus x' = c \oplus (x \oplus x') \\
&m' = \text{Decode}(c') = m \quad \text{if } d(x, x') \leq t
\end{aligned}
```
This is the canonical Secure Sketch / Fuzzy Extractor formulation (Dodis et al., 2004).
