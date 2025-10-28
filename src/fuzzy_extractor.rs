extern crate alloc;
use alloc::vec::Vec;
use core::fmt;

use crate::ecc::{ECC, EccError, SecureSketch};

/// Error type for FuzzyExtractor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzyExtractorError {
    /// Error from ECC/SecureSketch layer
    EccError(EccError),
    /// KDF operation failed
    KdfError(&'static str),
    /// Invalid input parameters
    InvalidInput(&'static str),
}

impl fmt::Display for FuzzyExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzyExtractorError::EccError(e) => write!(f, "ECC error: {}", e),
            FuzzyExtractorError::KdfError(s) => write!(f, "KDF error: {}", s),
            FuzzyExtractorError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
        }
    }
}

impl From<EccError> for FuzzyExtractorError {
    fn from(e: EccError) -> Self {
        FuzzyExtractorError::EccError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FuzzyExtractorError {}

/// Trait for Key Derivation Functions suitable for embedded systems
///
/// This trait allows different KDF algorithms to be plugged into the FuzzyExtractor.
/// Implementations should be lightweight and suitable for resource-constrained environments.
pub trait KeyDerivationFunction {
    /// Derive a key of specified length from input material
    ///
    /// # Parameters
    /// - `input`: The input key material
    /// - `output_len`: Desired length of the derived key in bytes
    ///
    /// # Returns
    /// A vector containing the derived key, or an error string
    fn derive(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str>;
}

/// Simple hash-based KDF using XOR and byte rotation
///
/// This is a lightweight KDF suitable for embedded systems where cryptographic
/// libraries might not be available. It uses simple operations (XOR, rotation)
/// to derive keys from input material.
///
/// **Note**: This is a demonstration implementation. For production use,
/// consider using a proper cryptographic KDF like HKDF.
pub struct SimpleHashKdf {
    /// Salt for the KDF (can be empty for stateless operation)
    pub salt: Vec<u8>,
}

impl SimpleHashKdf {
    /// Create a new SimpleHashKdf with optional salt
    pub fn new(salt: Vec<u8>) -> Self {
        Self { salt }
    }

    /// Create a new SimpleHashKdf without salt
    pub fn new_no_salt() -> Self {
        Self { salt: Vec::new() }
    }

    /// Internal mixing function using byte operations
    fn mix_bytes(&self, data: &[u8], iteration: u8) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            let salt_byte = if !self.salt.is_empty() {
                self.salt[i % self.salt.len()]
            } else {
                0xA5
            };

            let mixed = byte
                .wrapping_add(iteration)
                .wrapping_mul(3)
                .rotate_left((i % 8) as u32)
                ^ salt_byte
                ^ ((i as u8).wrapping_mul(7));

            result.push(mixed);
        }
        result
    }

    /// Hash-like function using multiple mixing rounds
    fn hash_rounds(&self, input: &[u8], rounds: usize) -> Vec<u8> {
        let mut state = input.to_vec();

        for round in 0..rounds {
            state = self.mix_bytes(&state, round as u8);

            // Additional diffusion: XOR adjacent bytes
            for i in 0..state.len() {
                let next_idx = (i + 1) % state.len();
                let prev_idx = if i == 0 { state.len() - 1 } else { i - 1 };
                state[i] ^= state[next_idx].rotate_left(1) ^ state[prev_idx].rotate_right(1);
            }
        }

        state
    }
}

impl KeyDerivationFunction for SimpleHashKdf {
    fn derive(&self, input: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str> {
        if input.is_empty() {
            return Err("Input cannot be empty");
        }
        if output_len == 0 {
            return Err("Output length must be > 0");
        }

        let mut output = Vec::with_capacity(output_len);
        let mut counter: u8 = 0;

        while output.len() < output_len {
            // Prepare input with counter
            let mut block_input = input.to_vec();
            block_input.push(counter);

            // Hash the input with multiple rounds for better mixing
            let hash = self.hash_rounds(&block_input, 5);

            // Take as many bytes as needed
            let take = core::cmp::min(hash.len(), output_len - output.len());
            output.extend_from_slice(&hash[..take]);

            counter = counter.wrapping_add(1);
        }

        Ok(output)
    }
}

/// A Fuzzy Extractor that combines SecureSketch with a Key Derivation Function
///
/// The fuzzy extractor generates stable cryptographic keys from noisy biometric
/// or physical data. It consists of two phases:
///
/// 1. **Generate**: Takes noisy input `w` and produces:
///    - A stable key derived from `w`
///    - Public helper data `p` that doesn't reveal information about the key
///
/// 2. **Reproduce**: Takes noisy input `w'` (close to `w`) and helper data `p`,
///    and reproduces the same stable key
///
/// # Type Parameters
/// - `E`: The error correction code (must implement `ECC` trait)
/// - `K`: The key derivation function (must implement `KeyDerivationFunction` trait)
pub struct FuzzyExtractor<E: ECC, K: KeyDerivationFunction> {
    /// The secure sketch for error correction
    sketch: SecureSketch<E>,
    /// The key derivation function
    kdf: K,
    /// Length of the key to generate (in bytes)
    key_len: usize,
}

impl<E: ECC, K: KeyDerivationFunction> FuzzyExtractor<E, K> {
    /// Create a new FuzzyExtractor
    ///
    /// # Parameters
    /// - `ecc`: The error correction code instance
    /// - `kdf`: The key derivation function instance
    /// - `key_len`: Length of the key to generate in bytes
    pub fn new(ecc: E, kdf: K, key_len: usize) -> Result<Self, FuzzyExtractorError> {
        if key_len == 0 {
            return Err(FuzzyExtractorError::InvalidInput("key_len must be > 0"));
        }

        Ok(Self {
            sketch: SecureSketch::new(ecc),
            kdf,
            key_len,
        })
    }

    /// Generate phase: Extract a stable key from noisy input
    ///
    /// # Parameters
    /// - `w`: The noisy input (e.g., biometric data, PUF response)
    /// - `seed_input`: The seed material for key derivation (should be random or deterministic depending on use case)
    ///
    /// # Returns
    /// A tuple of `(key, public_helper_data)` where:
    /// - `key`: The derived cryptographic key
    /// - `public_helper_data`: Public data needed for reproduction (safe to store)
    pub fn generate(
        &self,
        w: &[u8],
        seed_input: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), FuzzyExtractorError> {
        if w.is_empty() {
            return Err(FuzzyExtractorError::InvalidInput("Input w cannot be empty"));
        }
        if seed_input.is_empty() {
            return Err(FuzzyExtractorError::InvalidInput(
                "seed_input cannot be empty",
            ));
        }

        let seed = self
            .kdf
            .derive(seed_input, self.sketch.ecc.message_len())
            .map_err(FuzzyExtractorError::KdfError)?;

        // Generate helper data using secure sketch
        let public_helper = self.sketch.sketch(w, &seed)?;

        // Derive the actual key from the seed
        let key = self
            .kdf
            .derive(&seed, self.key_len)
            .map_err(FuzzyExtractorError::KdfError)?;

        Ok((key, public_helper))
    }

    /// Reproduce phase: Recover the stable key from noisy input
    ///
    /// # Parameters
    /// - `w_prime`: The noisy input (should be close to original `w`)
    /// - `public_helper`: The public helper data from generate phase
    ///
    /// # Returns
    /// The same key that was generated, if `w_prime` is sufficiently close to `w`
    pub fn reproduce(
        &self,
        w_prime: &[u8],
        public_helper: &[u8],
        known_erasures: Option<&[u8]>
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        if w_prime.is_empty() {
            return Err(FuzzyExtractorError::InvalidInput(
                "Input w_prime cannot be empty",
            ));
        }
        // Recover the seed using secure sketch
        let seed = self.sketch.recover(public_helper, w_prime, known_erasures)?;

        // Derive the key from the recovered seed
        let key = self
            .kdf
            .derive(&seed, self.key_len)
            .map_err(FuzzyExtractorError::KdfError)?;

        Ok(key)
    }

    /// Get the expected length of the key produced by this extractor
    pub fn key_length(&self) -> usize {
        self.key_len
    }
}

/// Note: It is recommended that the size of `x` matches the output of `Encode(m)`.
/// This ensures that runtime checks and transformations can be avoided, improving efficiency.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::ReedSolomonECC;

    // ========================================================================
    // KDF TESTS
    // ========================================================================

    #[test]
    fn test_simple_hash_kdf_basic() {
        let kdf = SimpleHashKdf::new_no_salt();
        let input = b"test input data";

        let derived = kdf.derive(input, 32).unwrap();
        assert_eq!(derived.len(), 32);
    }

    // ========================================================================
    // FUZZY EXTRACTOR TESTS
    // ========================================================================

    #[test]
    fn test_fuzzy_extractor_basic_round_trip() {
        let msg_len = 16;
        let err_rate = 0.2;
        let key_len = 32;

        let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
        let kdf = SimpleHashKdf::new_no_salt();
        let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();

        let w = b"biometric_data_123456";
        let seed_input = vec![0xFF; w.len() + 1];

        // Generate key and helper
        let (key, helper) = extractor.generate(w, &seed_input).unwrap();
        assert_eq!(key.len(), key_len);

        // Reproduce with same input
        let w_prime = w.to_vec();
        let key_reproduced = extractor.reproduce(&w_prime, &helper, None).unwrap();

        assert_eq!(key, key_reproduced, "Keys should match with no noise");
    }

    #[test]
    fn test_fuzzy_extractor_with_various_noise_levels() {
        let msg_len = 24;
        let err_rate = 0.15;
        let key_len = 32;

        let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
        let kdf = SimpleHashKdf::new_no_salt();
        let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();

        let w = b"noisy_biometric_input_test";
        let seed_input = vec![0xFF; w.len() + 1];

        // Generate
        let (key, helper) = extractor.generate(w, &seed_input).unwrap();

        let max_errors = ReedSolomonECC::calculate_num_errors(msg_len, err_rate);

        // Test with different noise levels
        for noise_fraction in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let mut w_prime = w.to_vec();
            let noise = ((max_errors as f32) * noise_fraction).ceil() as usize;

            for i in 0..noise.min(w_prime.len()) {
                w_prime[i] ^= 0xFF;
            }

            let result = extractor.reproduce(&w_prime, &helper, None);

            if noise_fraction <= 1.0 {
                assert!(
                    result.is_ok(),
                    "Failed for noise_fraction={}",
                    noise_fraction
                );
                let key_reproduced = result.unwrap();
                assert_eq!(
                    key, key_reproduced,
                    "Keys should match for noise_fraction={}",
                    noise_fraction
                );
            } else {
                assert!(
                    result.is_err(),
                    "Excessive noise should fail for noise_fraction={}",
                    noise_fraction
                );
            }
        }
    }

    #[test]
    fn test_fuzzy_extractor_with_various_err_rate_levels() {
        let msg_len = 24;
        let key_len = 32;

        let w = b"biometric_input_test_case";
        let seed_input = vec![0xFF; w.len() + 1];

        for err_rate in [0.05, 0.1, 0.15, 0.2, 0.25] {
            // Initialize ECC and FuzzyExtractor for the current error rate
            let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
            let kdf = SimpleHashKdf::new_no_salt();
            let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();

            // Generate the key and helper data
            let (key, helper) = extractor.generate(w, &seed_input).unwrap();

            // Calculate the maximum number of correctable errors for the current error rate
            let max_errors = ReedSolomonECC::calculate_num_errors(msg_len, err_rate);

            // Inject the maximum correctable errors into the input
            let mut w_prime = w.to_vec();
            for i in 0..max_errors.min(w_prime.len()) {
                w_prime[i] ^= 0xFF; // Flip bits to simulate noise
            }

            // Attempt to reproduce the key with the noisy input
            let result = extractor.reproduce(&w_prime, &helper, None);

            // Verify that the key is successfully reproduced
            assert!(result.is_ok(), "Failed for err_rate={}", err_rate);
            let key_reproduced = result.unwrap();
            assert_eq!(
                key, key_reproduced,
                "Keys should match for err_rate={}",
                err_rate
            );
        }
    }

    #[test]
    fn stress_test_fuzzy_extractor_high_err_rate() {
        let msg_len = 24;
        let key_len = 32;
        let w = b"stress_test_biometric_input";
        let seed_input = vec![0xFF; w.len() + 1];

        // Use high error rates for stress testing
        for err_rate in [0.2, 0.25, 0.3] {
            let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
            let kdf = SimpleHashKdf::new_no_salt();
            let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();

            // Generate the key and helper data
            let (key, helper) = extractor.generate(w, &seed_input).unwrap();

            let max_errors = ReedSolomonECC::calculate_num_errors(msg_len, err_rate);

            for _ in 0..50_000 {
                // Inject the maximum correctable errors into the input
                let mut w_prime = w.to_vec();
                for i in 0..max_errors.min(w_prime.len()) {
                    w_prime[i] ^= 0xFF; // Flip bits to simulate noise
                }

                // Attempt to reproduce the key with the noisy input
                let result = extractor.reproduce(&w_prime, &helper, None);

                // Verify that the key is successfully reproduced
                assert!(
                    result.is_ok(),
                    "Failed for err_rate={} in iteration",
                    err_rate
                );
                let key_reproduced = result.unwrap();
                assert_eq!(
                    key, key_reproduced,
                    "Keys should match for err_rate={}",
                    err_rate
                );
            }
        }
    }
}
