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

/// Trait for pluggable Key Derivation Functions
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

/// A Fuzzy Extractor for generating stable keys from noisy data
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
/// # Block-Based Processing
///
/// For large inputs, the extractor can be configured to use block-based processing:
/// - The input `w` is divided into fixed-size blocks
/// - Each block is processed independently with its own secure sketch
/// - Block keys are combined into a final key using the KDF
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
    /// Optional block size for block-based processing
    /// If None, processes the entire input as a single block
    /// If Some(size), divides input into blocks of this size
    block_size: Option<usize>,
    /// Key length per block when using block-based processing
    #[allow(dead_code)]
    per_block_key_len: usize,
}

impl<E: ECC, K: KeyDerivationFunction> FuzzyExtractor<E, K> {
    /// Create a FuzzyExtractor for single-block processing
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
            block_size: None,
            per_block_key_len: key_len,
        })
    }

    /// Create a FuzzyExtractor with block-based processing
    ///
    /// # Parameters
    /// - `ecc`: The error correction code instance (will be applied to each block)
    /// - `kdf`: The key derivation function instance
    /// - `block_size`: Size of each block in bytes
    /// - `per_block_key_len`: Length of key to derive from each block
    /// - `final_key_len`: Length of the final combined key in bytes
    ///
    /// # Note
    /// The input `w` must be divisible by `block_size`, or it will be padded.
    pub fn new_with_blocks(
        ecc: E,
        kdf: K,
        block_size: usize,
        per_block_key_len: usize,
        final_key_len: usize,
    ) -> Result<Self, FuzzyExtractorError> {
        if block_size == 0 {
            return Err(FuzzyExtractorError::InvalidInput("block_size must be > 0"));
        }
        if per_block_key_len == 0 {
            return Err(FuzzyExtractorError::InvalidInput(
                "per_block_key_len must be > 0",
            ));
        }
        if final_key_len == 0 {
            return Err(FuzzyExtractorError::InvalidInput("final_key_len must be > 0"));
        }

        Ok(Self {
            sketch: SecureSketch::new(ecc),
            kdf,
            key_len: final_key_len,
            block_size: Some(block_size),
            per_block_key_len,
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
    ///
    /// # Block-Based Processing
    /// If `block_size` was configured, the input is divided into blocks and processed
    /// independently. The helper data will contain all block helpers concatenated.
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

        match self.block_size {
            None => self.generate_single_block(w, seed_input),
            Some(block_size) => self.generate_multi_block(w, seed_input, block_size),
        }
    }

    /// Helper function to derive a seed
    fn derive_seed(&self, input: &[u8], length: usize) -> Result<Vec<u8>, FuzzyExtractorError> {
        self.kdf
            .derive(input, length)
            .map_err(FuzzyExtractorError::KdfError)
    }

    /// Helper function to derive a key
    fn derive_key(&self, seed: &[u8], length: usize) -> Result<Vec<u8>, FuzzyExtractorError> {
        self.kdf
            .derive(seed, length)
            .map_err(FuzzyExtractorError::KdfError)
    }

    /// Generate for single-block (original behavior)
    fn generate_single_block(
        &self,
        w: &[u8],
        seed_input: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), FuzzyExtractorError> {
        let seed = self.derive_seed(seed_input, self.sketch.ecc.message_len())?;
        let public_helper = self.sketch.sketch(w, &seed)?;
        let key = self.derive_key(&seed, self.key_len)?;
        Ok((key, public_helper))
    }

    /// Generate for multi-block processing
    fn generate_multi_block(
        &self,
        w: &[u8],
        seed_input: &[u8],
        block_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), FuzzyExtractorError> {
        let num_blocks = (w.len() + block_size - 1) / block_size;
        let mut all_helpers = Vec::new();
        let mut all_block_keys = Vec::new();

        for i in 0..num_blocks {
            let start = i * block_size;
            let end = core::cmp::min(start + block_size, w.len());
            let w_i = &w[start..end];

            // Derive deterministic per-block seed: KDF(seed_input || block_index || w_i)
            let mut block_seed_input = Vec::with_capacity(seed_input.len() + 1 + w_i.len());
            block_seed_input.extend_from_slice(seed_input);
            block_seed_input.push(i as u8);
            block_seed_input.extend_from_slice(w_i);

            let (key_i, helper_i) = self.generate_single_block(w_i, &block_seed_input)?;

            all_helpers.push(helper_i);
            all_block_keys.extend_from_slice(&key_i);
        }

        let mut combined_helper = Vec::new();
        combined_helper.extend_from_slice(&(num_blocks as u32).to_le_bytes());
        for helper in &all_helpers {
            combined_helper.extend_from_slice(&(helper.len() as u32).to_le_bytes());
            combined_helper.extend_from_slice(helper);
        }

        let final_key = self.derive_key(&all_block_keys, self.key_len)?;
        Ok((final_key, combined_helper))
    }

    /// Reproduce phase: Recover the stable key from noisy input
    ///
    /// # Parameters
    /// - `w_prime`: The noisy input (should be close to original `w`)
    /// - `public_helper`: The public helper data from generate phase
    /// - `known_erasures`: Optional erasure information for error correction
    ///
    /// # Returns
    /// The same key that was generated, if `w_prime` is sufficiently close to `w`
    ///
    /// # Block-Based Processing
    /// If `block_size` was configured, the helper data is parsed to extract individual
    /// block helpers, and each block is processed independently.
    pub fn reproduce(
        &self,
        w_prime: &[u8],
        public_helper: &[u8],
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        if w_prime.is_empty() {
            return Err(FuzzyExtractorError::InvalidInput(
                "Input w_prime cannot be empty",
            ));
        }

        match self.block_size {
            None => self.reproduce_single_block(w_prime, public_helper, known_erasures),
            Some(block_size) => {
                self.reproduce_multi_block(w_prime, public_helper, block_size, known_erasures)
            }
        }
    }

    /// Reproduce for single-block (original behavior)
    fn reproduce_single_block(
        &self,
        w_prime: &[u8],
        public_helper: &[u8],
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        // Recover the seed using secure sketch
        let seed = self.sketch.recover(public_helper, w_prime, known_erasures)?;

        // Derive the key from the recovered seed
        let key = self
            .kdf
            .derive(&seed, self.key_len)
            .map_err(FuzzyExtractorError::KdfError)?;

        Ok(key)
    }

    /// Reproduce for multi-block processing
    fn reproduce_multi_block(
        &self,
        w_prime: &[u8],
        public_helper: &[u8],
        block_size: usize,
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        if public_helper.len() < 4 {
            return Err(FuzzyExtractorError::InvalidInput(
                "Helper data too short for block format",
            ));
        }

        let num_blocks = u32::from_le_bytes([
            public_helper[0],
            public_helper[1],
            public_helper[2],
            public_helper[3],
        ]) as usize;

        let mut offset = 4;
        let mut all_block_keys = Vec::new();

        for i in 0..num_blocks {
            if offset + 4 > public_helper.len() {
                return Err(FuzzyExtractorError::InvalidInput(
                    "Helper data corrupted: insufficient data for block length",
                ));
            }

            let helper_len = u32::from_le_bytes([
                public_helper[offset],
                public_helper[offset + 1],
                public_helper[offset + 2],
                public_helper[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + helper_len > public_helper.len() {
                return Err(FuzzyExtractorError::InvalidInput(
                    "Helper data corrupted: insufficient data for helper",
                ));
            }

            let helper_i = &public_helper[offset..offset + helper_len];
            offset += helper_len;

            let start = i * block_size;
            let end = core::cmp::min(start + block_size, w_prime.len());
            let w_i = &w_prime[start..end];

            let key_i = self.reproduce_single_block(w_i, helper_i, known_erasures)?;
            all_block_keys.extend_from_slice(&key_i);
        }

        let final_key = self
            .kdf
            .derive(&all_block_keys, self.key_len)
            .map_err(FuzzyExtractorError::KdfError)?;

        Ok(final_key)
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
    use crate::simple_hash_kdf::SimpleHashKdf;


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

    // ========================================================================
    // BLOCK-BASED FUZZY EXTRACTOR TESTS
    // ========================================================================

    #[test]
    fn test_fuzzy_extractor_block_based_basic() {
        let block_size = 16;
        let num_blocks = 384 / block_size; // 24 blocks
        let err_rate = 0.15;
        let per_block_key_len = 32;
        let final_key_len = 32;

        // Create input (384 bytes)
        let mut w = vec![0u8; 384];
        for i in 0..384 {
            w[i] = ((i * 7) % 256) as u8;
        }

        let ecc = ReedSolomonECC::new(block_size, err_rate).unwrap();
        let kdf = SimpleHashKdf::new_no_salt();
        let extractor =
            FuzzyExtractor::new_with_blocks(ecc, kdf, block_size, per_block_key_len, final_key_len)
                .unwrap();

        // Master seed
        let seed_input = vec![0xAB; block_size];

        // Generate
        let (key, helper) = extractor.generate(&w, &seed_input).unwrap();
        assert_eq!(key.len(), final_key_len);

        // Reproduce with same input
        let key_reproduced = extractor.reproduce(&w, &helper, None).unwrap();
        assert_eq!(key, key_reproduced, "Keys should match with no noise");

        println!("Block-based test passed:");
        println!("  - Blocks: {}", num_blocks);
        println!("  - Helper size: {} bytes", helper.len());
        println!("  - Final key size: {} bytes", key.len());
    }

    #[test]
    fn test_fuzzy_extractor_block_based_with_noise() {
        let block_size = 16;
        let err_rate = 0.15;
        let per_block_key_len = 32;
        let final_key_len = 32;

        // Create input (384 bytes)
        let mut w = vec![0u8; 384];
        for i in 0..384 {
            w[i] = ((i * 7) % 256) as u8;
        }

        let ecc = ReedSolomonECC::new(block_size, err_rate).unwrap();
        let kdf = SimpleHashKdf::new_no_salt();
        let extractor =
            FuzzyExtractor::new_with_blocks(ecc, kdf, block_size, per_block_key_len, final_key_len)
                .unwrap();

        let seed_input = vec![0xAB; block_size];

        // Generate
        let (key, helper) = extractor.generate(&w, &seed_input).unwrap();

        // Add noise to some blocks
        let mut w_noisy = w.clone();
        let max_errors = ReedSolomonECC::calculate_num_errors(block_size, err_rate);
        
        // Add errors to first block
        for i in 0..max_errors.min(block_size) {
            w_noisy[i] ^= 0xFF;
        }
        
        // Add errors to middle block (block 12)
        let block_offset = 12 * block_size;
        for i in 0..max_errors.min(block_size) {
            w_noisy[block_offset + i] ^= 0xFF;
        }

        // Reproduce with noisy input
        let key_reproduced = extractor.reproduce(&w_noisy, &helper, None).unwrap();
        assert_eq!(key, key_reproduced, "Keys should match with correctable noise");
    }

    #[test]
    fn test_fuzzy_extractor_block_based_different_sizes() {
        // Test with different block sizes
        for block_size in [16, 20] {
            let err_rate = 0.15;
            let per_block_key_len = 32;
            let final_key_len = 32;
            let total_size = 128;

            let w = vec![0xAA; total_size];
            let seed_input = vec![0xBB; block_size];

            let ecc = ReedSolomonECC::new(block_size, err_rate).unwrap();
            let kdf = SimpleHashKdf::new_no_salt();
            let extractor = FuzzyExtractor::new_with_blocks(
                ecc,
                kdf,
                block_size,
                per_block_key_len,
                final_key_len,
            )
            .unwrap();

            let (key, helper) = extractor.generate(&w, &seed_input).unwrap();
            let key_reproduced = extractor.reproduce(&w, &helper, None).unwrap();

            assert_eq!(
                key, key_reproduced,
                "Keys should match for block_size={}",
                block_size
            );
        }
    }
}
