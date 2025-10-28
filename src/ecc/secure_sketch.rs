extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::ecc::ecc_trait::{ECC, EccError};

pub struct SecureSketch<E: ECC> {
    pub ecc: E,
}

impl<E: ECC> SecureSketch<E> {
    pub fn new(ecc: E) -> Self {
        Self { ecc }
    }

    fn extend_x(&self, x: &[u8], target_len: usize) -> Vec<u8> {
        // Note: This function is designed to handle cases where the size of `x` does not match `target_len`.
        // If the developer can pre-calculate the size of `x` or transform `x` to match the required size,
        // this function can be bypassed entirely, avoiding the need for runtime checks.
        if x.is_empty() {
            vec![0xAAu8; target_len]
        } else if x.len() == target_len {
            x.to_vec()
        } else if x.len() < target_len {
            let mut extended = Vec::with_capacity(target_len);
            extended.extend_from_slice(x);
            extended.resize(target_len, 0xAAu8); // fill remaining bytes with 0xAA
            extended
        } else {
            unreachable!("extend_x should not be called when x is longer than codeword_len");
        }
    }

    /// Security note:
    /// This function implements only the Secure Sketch phase (helper = Encode(m) XOR x).
    /// It does NOT perform entropy extraction or key derivation.
    /// The caller must ensure `m` is strongly random
    pub fn sketch(&self, x: &[u8], m: &[u8]) -> Result<Vec<u8>, EccError> {
        let c = self.ecc.keygen(m)?;
        let codeword_len = c.len();
        if x.len() > codeword_len {
            return Err(EccError::InvalidLength("x", codeword_len, x.len()));
        }
        let x_ext = self.extend_x(x, codeword_len);
        let helper: Vec<u8> = c.iter().zip(x_ext.iter()).map(|(a, b)| a ^ b).collect();
        Ok(helper)
    }

    pub fn recover(
        &self,
        helper: &[u8],
        x_prime: &[u8],
        known_erasures: Option<&[u8]>,
    ) -> Result<Vec<u8>, EccError> {
        let codeword_len = helper.len();
        if x_prime.len() > codeword_len {
            return Err(EccError::InvalidLength(
                "x_prime",
                codeword_len,
                x_prime.len(),
            ));
        }
        let x_ext = self.extend_x(x_prime, codeword_len);
        let c_prime: Vec<u8> = helper
            .iter()
            .zip(x_ext.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        self.ecc.reproduce(&c_prime, known_erasures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::ecc_rs::ReedSolomonECC;

    // ========================================================================
    // CONSTRUCTOR TESTS
    // ========================================================================

    #[test]
    fn test_new() {
        let ecc = ReedSolomonECC::new(16, 0.2).unwrap();
        let sketch = SecureSketch::new(ecc);
        assert_eq!(sketch.ecc.message_len(), 16);
    }

    // ========================================================================
    // SKETCH TESTS
    // ========================================================================

    #[test]
    fn test_sketch_basic() {
        let msg_len = 16;
        let ecc = ReedSolomonECC::new(msg_len, 0.2).unwrap();
        let sketch = SecureSketch::new(ecc);

        let x = b"fingerprint";
        let m = b"secret_message!!";

        let result = sketch.sketch(x, m);
        assert!(result.is_ok());

        let helper = result.unwrap();
        assert!(!helper.is_empty());
        let (_, codeword_len, _) = ReedSolomonECC::ecc_metadata(msg_len, 0.2);
        assert_eq!(helper.len(), codeword_len);
    }

    // ========================================================================
    // RECOVER TESTS
    // ========================================================================

    #[test]
    fn test_recover_perfect_match() {
        let msg_len = 16;
        let ecc = ReedSolomonECC::new(msg_len, 0.2).unwrap();
        let sketch = SecureSketch::new(ecc);

        let x = b"perfect_match";
        let m = b"secret_message!!";

        let helper = sketch.sketch(x, m).unwrap();
        let recovered = sketch.recover(&helper, x, None).unwrap();

        assert_eq!(&recovered[..msg_len], m);
    }

    #[test]
    fn test_round_trip_no_noise() {
        let test_cases = vec![(8, 0.1), (16, 0.15), (24, 0.2)];

        for (msg_len, err_rate) in test_cases {
            let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
            let sketch = SecureSketch::new(ecc);

            let message: Vec<u8> = (0..msg_len as u8).collect();
            let x: Vec<u8> = (b'A'..=b'Z').cycle().take(msg_len / 2).collect();

            let helper = sketch.sketch(&x, &message).unwrap();
            let recovered = sketch.recover(&helper, &x, None).unwrap();

            assert_eq!(&recovered[..msg_len], &message[..]);
        }
    }
}
