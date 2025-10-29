extern crate alloc;
use crate::ecc::{ECC, SecureSketch};
use crate::errors::FuzzyExtractorError;
use alloc::vec::Vec;
use zeroize::Zeroize;


const INFO_SINGLE_BLOCK_SEED: &[u8] = b"single_block_seed";
const INFO_MULTI_BLOCK_KEY: &[u8] = b"multi_block_key";
const INFO_MULTI_BLOCK_FINAL_KEY: &[u8] = b"multi_block_final_key";

/// Trait for Key Derivation Functions
/// For product security, KDFs should be strong, resistant to length-extension attacks.
pub trait KeyDerivationFunction {
    /// Derives a key from input data with additional context information
    fn derive(&self, input: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str>;
}

/// Fuzzy Extractor for generating stable keys
pub struct FuzzyExtractor<E: ECC, K: KeyDerivationFunction> {
    sketch: SecureSketch<E>,
    kdf: K,
    key_len: usize,
    block_size: Option<usize>,
    per_block_key_len: usize,
}

impl<E: ECC, K: KeyDerivationFunction> FuzzyExtractor<E, K> {
    /// Creates a FuzzyExtractor for single-block mode
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

    /// Creates a FuzzyExtractor for multi-block mode
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
            return Err(FuzzyExtractorError::InvalidInput(
                "final_key_len must be > 0",
            ));
        }

        Ok(Self {
            sketch: SecureSketch::new(ecc),
            kdf,
            key_len: final_key_len,
            block_size: Some(block_size),
            per_block_key_len,
        })
    }

    /// Generates a key and helper data from input
    /// Note: We need a seed_input with high entropy
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

    /// Reproduces the key from noisy input and helper data
    // w and w_prime have the same length
    // If w_prime is shorter or longer, we don't know which bytes are missing/added
    // → assume same length, no padding in reproduce
    pub fn reproduce(
        &self,
        w_prime: &[u8],
        helper: &[u8],
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        if w_prime.is_empty() {
            return Err(FuzzyExtractorError::InvalidInput(
                "Input w_prime cannot be empty",
            ));
        }

        match self.block_size {
            None => self.reproduce_single_block(w_prime, helper, known_erasures),
            Some(block_size) => {
                self.reproduce_multi_block(w_prime, helper, block_size, known_erasures)
            }
        }
    }

    /// Get output key length
    pub fn key_length(&self) -> usize {
        self.key_len
    }

    fn derive_kdf(&self, input: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, FuzzyExtractorError> {
        self.kdf
            .derive(input, info, len)
            .map_err(FuzzyExtractorError::KdfError)
    }

    fn generate_single_block(
        &self,
        w: &[u8],
        seed_input: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), FuzzyExtractorError> {
        let msg_len = self.sketch.ecc.message_len();
        let mut seed = self.derive_kdf(seed_input, INFO_SINGLE_BLOCK_SEED, msg_len)?;
        let key = self.derive_kdf(&seed, INFO_SINGLE_BLOCK_SEED, self.key_len)?;
        let helper = self.sketch.sketch(w, &seed)?;
        
        // Zeroize seed after helper computed
        seed.zeroize();
        
        Ok((key, helper))
    }

    fn generate_multi_block(
        &self,
        w: &[u8],
        seed_input: &[u8],
        block_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), FuzzyExtractorError> {
        // ---- Step 1: pad input ----
        let mut w_padded = w.to_vec();
        if w.len() % block_size != 0 {
            let pad_len = block_size - (w.len() % block_size);
            w_padded.extend((0..pad_len).map(|_| 0xAA));
        }

        let num_blocks = w_padded.len() / block_size;
        let msg_len = self.sketch.ecc.message_len();

        // ---- Step 2: allocate result buffers ----
        let mut combined_helper = Vec::with_capacity(4 + num_blocks * 8);
        combined_helper.extend_from_slice(&(num_blocks as u32).to_le_bytes());

        let mut all_block_keys = Vec::with_capacity(num_blocks * self.per_block_key_len);

        // Reusable buffers (allocated once, reused per iteration)
        let mut seed_input_block = Vec::with_capacity(seed_input.len() + 1 + block_size);

        // ---- Step 3: iterate blocks ----
        for i in 0..num_blocks {
            let w_i = &w_padded[i * block_size..(i + 1) * block_size];

            // Reuse seed_input_block buffer: KDF(seed_input || block_index || w_i)
            seed_input_block.clear();
            seed_input_block.extend_from_slice(seed_input);
            seed_input_block.push(i as u8);
            seed_input_block.extend_from_slice(w_i);

            // Derive seed for this block
            let mut seed_buf = self.derive_kdf(&seed_input_block, b"generate_multi_block_seed", msg_len)?;

            // Generate helper for this block
            let helper_buf = self.sketch.sketch(w_i, &seed_buf)?;

            // Serialize helper immediately
            combined_helper.extend_from_slice(&(helper_buf.len() as u32).to_le_bytes());
            combined_helper.extend_from_slice(&helper_buf);

            // Derive and append block key directly to all_block_keys
            let mut key_i = self.derive_kdf(&seed_buf, INFO_MULTI_BLOCK_KEY, self.per_block_key_len)?;
            all_block_keys.extend_from_slice(&key_i);
            
            // Zeroize sensitive data after use
            key_i.zeroize();
            seed_buf.zeroize();
        }

        // Zeroize reusable buffer after loop completes
        seed_input_block.zeroize();
        
        // Derive final combined key
        let final_key = self.derive_kdf(&all_block_keys, INFO_MULTI_BLOCK_FINAL_KEY, self.key_len)?;
        
        // Zeroize sensitive data after final key derived
        all_block_keys.zeroize();
        w_padded.zeroize();
        
        Ok((final_key, combined_helper))
    }

    fn reproduce_single_block(
        &self,
        w_prime: &[u8],
        helper: &[u8],
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        let mut seed = self.sketch.recover(helper, w_prime, known_erasures)?;
        let key = self.derive_kdf(&seed, INFO_SINGLE_BLOCK_SEED, self.key_len)?;
        
        // Zeroize seed after key derived
        seed.zeroize();
        
        Ok(key)
    }

    // Multi-block reproduction
    // w and w_prime have the same length
    fn reproduce_multi_block(
        &self,
        w_prime: &[u8],
        helper: &[u8],
        block_size: usize,
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, FuzzyExtractorError> {
        if helper.len() < 4 {
            return Err(FuzzyExtractorError::InvalidInput("Helper too short"));
        }

        let num_blocks = u32::from_le_bytes(helper[0..4].try_into().unwrap()) as usize;
        let mut offset = 4;

        // Pad input for deterministic block size
        let mut w_padded = w_prime.to_vec();
        if w_prime.len() % block_size != 0 {
            let pad_len = block_size - (w_prime.len() % block_size);
            w_padded.extend((0..pad_len).map(|_| 0xAA));
        }

        // Preallocate result buffer
        let mut all_block_keys = Vec::with_capacity(num_blocks * self.per_block_key_len);

        for i in 0..num_blocks {
            // Parse helper_i from combined helper data
            if offset + 4 > helper.len() {
                return Err(FuzzyExtractorError::InvalidInput(
                    "Helper truncated (len prefix)",
                ));
            }
            let helper_len =
                u32::from_le_bytes(helper[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + helper_len > helper.len() {
                return Err(FuzzyExtractorError::InvalidInput(
                    "Helper truncated (block data)",
                ));
            }
            let helper_i = &helper[offset..offset + helper_len];
            offset += helper_len;

            // Extract block from w_padded
            let start = i * block_size;
            let end = core::cmp::min(start + block_size, w_padded.len());
            let w_i = &w_padded[start..end];

            // Recover seed for this block
            let mut seed_buf = self.sketch.recover(helper_i, w_i, known_erasures)?;

            // Derive and append block key directly to all_block_keys
            let mut key_i = self.derive_kdf(&seed_buf, INFO_MULTI_BLOCK_KEY, self.per_block_key_len)?;
            all_block_keys.extend_from_slice(&key_i);
            
            // Zeroize sensitive data after use
            key_i.zeroize();
            seed_buf.zeroize();
        }

        // Derive final combined key
        let final_key = self.derive_kdf(&all_block_keys, INFO_MULTI_BLOCK_FINAL_KEY, self.key_len)?;
        
        // Zeroize sensitive data after final key derived
        all_block_keys.zeroize();
        w_padded.zeroize();
        
        Ok(final_key)
    }
}


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
        assert_eq!(
            key, key_reproduced,
            "Keys should match with correctable noise"
        );
    }

    #[test]
    fn test_fuzzy_extractor_block_based_different_sizes() {
        // Test with different block sizes
        for block_size in [16, 20, 24, 28, 32] {
            let err_rate = 0.15;
            let per_block_key_len = 32;
            let final_key_len = 32;
            let total_size = 1024;

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
