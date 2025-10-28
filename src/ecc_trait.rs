extern crate alloc;
use alloc::vec::Vec;
use core::fmt;

/// Error type for ECC operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccError {
    InvalidParameters(&'static str),
    /// field name, expected (max) length, found length
    InvalidLength(&'static str, usize, usize),
    DecodingFailed,
}

impl fmt::Display for EccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EccError::InvalidParameters(s) => write!(f, "Invalid parameters: {}", s),
            EccError::InvalidLength(field, expected, found) => write!(
                f,
                "Invalid length for {}: expected <= {}, found {}",
                field,
                expected,
                found,
            ),
            EccError::DecodingFailed => write!(f, "Decoding failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EccError {}

/// ECC trait
pub trait ECC {
    fn message_len(&self) -> usize;
    fn error_rate(&self) -> f32;
    fn parity_len(&self) -> usize;

    fn keygen(&self, message: &[u8]) -> Result<Vec<u8>, EccError>;
    fn reproduce(&self, noisy: &[u8]) -> Result<Vec<u8>, EccError>;
    fn calculate_num_errors(msg_len: usize, err_rate: f32) -> usize;
}

// Re-export authoritative module under `ecc/` to avoid duplicate definitions.
pub use crate::ecc::ecc_trait::*;
