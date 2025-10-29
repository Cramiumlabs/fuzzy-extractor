//! SimpleHashKdf: A lightweight key derivation function for PoC

extern crate alloc;
use crate::fuzzy_extractor::KeyDerivationFunction;
use alloc::vec::Vec;

/// Simple hash-based KDF using XOR and byte rotation
///
/// This is a lightweight KDF suitable for a PoC
///
/// **Note**: This is a demonstration implementation. For production use,
/// consider using a proper cryptographic KDF like HKDF.
#[derive(Clone)]
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
    fn hash_like(&self, input: &[u8], rounds: u8) -> Vec<u8> {
        let mut result = input.to_vec();
        for round in 0..rounds {
            result = self.mix_bytes(&result, round);
        }
        result
    }
}

impl KeyDerivationFunction for SimpleHashKdf {
    /// Derive a key of specified length from input material with additional context
    fn derive(&self, input: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, &'static str> {
        if input.is_empty() {
            return Err("Input cannot be empty");
        }
        if output_len == 0 {
            return Err("Output length must be greater than 0");
        }

        let mut derived_key = Vec::with_capacity(output_len);
        let mut counter = 0u8;

        while derived_key.len() < output_len {
            let mut block_input = input.to_vec();
            block_input.extend_from_slice(info);
            block_input.push(counter);
            let block = self.hash_like(&block_input, 3);
            derived_key.extend_from_slice(&block);
            counter = counter.wrapping_add(1);
        }

        derived_key.truncate(output_len);
        Ok(derived_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hash_kdf_basic() {
        let kdf = SimpleHashKdf::new_no_salt();
        let input = b"test input data";

        let derived = kdf.derive(input, &[], 32).unwrap();
        assert_eq!(derived.len(), 32);
    }
}
