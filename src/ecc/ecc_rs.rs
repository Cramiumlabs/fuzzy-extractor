extern crate alloc;
use alloc::vec::Vec;

use reed_solomon::{Decoder, Encoder};

use crate::ecc::ecc_trait::{ECC, EccError};

/// Reed–Solomon ECC implementation
pub struct ReedSolomonECC {
    pub msg_len: usize,
    pub error_rate: f32,
}

impl ReedSolomonECC {
    pub fn new(msg_len: usize, error_rate: f32) -> Result<Self, EccError> {
        if msg_len == 0 {
            return Err(EccError::InvalidParameters("msg_len must be > 0"));
        }
        if !(0.0..0.5).contains(&error_rate) {
            return Err(EccError::InvalidParameters(
                "error_rate must be in the range (0.0, 0.5)"));
        }

        let ecc_len = libm::floor((msg_len as f64 * error_rate as f64 * 2.0) as f64) as usize;
        if msg_len + ecc_len > 255 {
            return Err(EccError::InvalidParameters(
                "msg_len + ecc_len exceeds the maximum codeword size of 255 symbols"));
        }

        Ok(Self { msg_len, error_rate })
    }

    /// Compute parity + metadata
    pub fn ecc_metadata(msg_len: usize, err_rate: f32) -> (usize, usize, usize) {
        let m: f64 = msg_len as f64;
        let e = err_rate as f64;

        #[cfg(feature = "std")]
        let mut ecc_len = (m * e * 2.0).floor() as usize;
        #[cfg(not(feature = "std"))]
        let mut ecc_len = libm::floor(m * e * 2.0) as usize;

        if ecc_len % 2 != 0 {
            ecc_len += 1;
        }

        let codeword_len = msg_len + ecc_len;
        let correctable = ecc_len / 2;

        return (ecc_len, codeword_len, correctable);
    }

    fn compute_ecc_len(&self) -> usize {
        let (ecc_len, _, _) = Self::ecc_metadata(self.msg_len, self.error_rate);
        ecc_len
    }
}

impl ECC for ReedSolomonECC {
    fn message_len(&self) -> usize {
        self.msg_len
    }
    fn error_rate(&self) -> f32 {
        self.error_rate
    }
    fn parity_len(&self) -> usize {
        self.compute_ecc_len()
    }

    fn keygen(&self, message: &[u8]) -> Result<Vec<u8>, EccError> {
        if message.len() != self.msg_len {
            return Err(EccError::InvalidParameters("message length mismatch"));
        }
        let ecc_len = self.compute_ecc_len();
        let enc = Encoder::new(ecc_len);
        let encoded = enc.encode(message);
        Ok(encoded.to_vec())
    }

    fn reproduce(&self, noisy: &[u8], known_erasures: Option<&[u8]>) -> Result<Vec<u8>, EccError> {
        let ecc_len = self.compute_ecc_len();
        if noisy.is_empty() {
            return Err(EccError::InvalidParameters("noisy input empty"));
        }
        let dec = Decoder::new(ecc_len);
        let mut data = noisy.to_vec();

        match dec.correct(&mut data, known_erasures) {
            Ok(recovered) => Ok(recovered.data().to_vec()),
            Err(_) => Err(EccError::EccRecoveryFailed),
        }
    }

    fn calculate_num_errors(msg_len: usize, err_rate: f32) -> usize {
        let (_, _, correctable) = Self::ecc_metadata(msg_len, err_rate);
        correctable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inject_noise(buf: &mut [u8], num_errors: usize) {
        for i in 0..num_errors.min(buf.len()) {
            let idx = (i * 13 + 5) % buf.len();
            buf[idx] = buf[idx].wrapping_add((idx as u8).wrapping_mul(3) ^ 0xA5);
        }
    }

    // ========================================================================
    // CONSTRUCTOR TESTS
    // ========================================================================

    #[test]
    fn test_new_valid_parameters() {
        let result = ReedSolomonECC::new(16, 0.1);
        assert!(result.is_ok());
        let ecc = result.unwrap();
        assert_eq!(ecc.msg_len, 16);
        assert_eq!(ecc.error_rate, 0.1);
    }

    #[test]
    fn test_new_zero_msg_len_fails() {
        let result = ReedSolomonECC::new(0, 0.1);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_error_rate_too_high_fails() {
        let result = ReedSolomonECC::new(16, 0.5);
        assert!(result.is_err());
    }

    // ========================================================================
    // METADATA CALCULATION TESTS
    // ========================================================================

    #[test]
    fn test_ecc_metadata_various_sizes() {
        let test_cases = vec![(8, 0.1), (16, 0.15), (32, 0.2)];

        for (msg_len, err_rate) in test_cases {
            let (ecc_len, codeword_len, correctable) =
                ReedSolomonECC::ecc_metadata(msg_len, err_rate);

            assert!(ecc_len > 0);
            assert_eq!(codeword_len, msg_len + ecc_len);
            assert_eq!(correctable, ecc_len / 2);
        }
    }

    // ========================================================================
    // KEYGEN TESTS
    // ========================================================================

    #[test]
    fn test_keygen_valid_message() {
        let ecc = ReedSolomonECC::new(16, 0.2).unwrap();
        let message = b"Hello, World!123";

        let result = ecc.keygen(message);
        assert!(result.is_ok());
    }

    // ========================================================================
    // REPRODUCE TESTS
    // ========================================================================

    #[test]
    fn test_reproduce_no_errors() {
        let ecc = ReedSolomonECC::new(16, 0.2).unwrap();
        let message = b"Perfect message!";

        let encoded = ecc.keygen(message).unwrap();
        let decoded = ecc.reproduce(&encoded, None).unwrap();

        assert_eq!(&decoded[..16], message);
    }

    #[test]
    fn test_reproduce_with_correctable_errors() {
        let ecc = ReedSolomonECC::new(20, 0.2).unwrap();
        let message = b"Message with errors!";

        let mut encoded = ecc.keygen(message).unwrap();
        let correctable = ReedSolomonECC::calculate_num_errors(20, 0.2);
        inject_noise(&mut encoded, correctable / 2);

        let decoded = ecc.reproduce(&encoded, None).unwrap();
        assert_eq!(&decoded[..20], message);
    }

    // ========================================================================
    // ROUND-TRIP TESTS
    // ========================================================================

    #[test]
    fn test_round_trip_no_noise() {
        let ecc = ReedSolomonECC::new(16, 0.15).unwrap();
        let message: Vec<u8> = (0..16).collect();

        let encoded = ecc.keygen(&message).unwrap();
        let decoded = ecc.reproduce(&encoded, None).unwrap();

        assert_eq!(&decoded[..16], &message[..]);
    }
}
