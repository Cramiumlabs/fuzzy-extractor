extern crate alloc;
use alloc::vec::Vec;
use core::fmt;

/// Error type for ECC operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccError {
    InvalidParameters(&'static str),
    /// field name, expected (max) length, found length
    InvalidLength(&'static str, usize, usize),
    EccRecoveryFailed,
}

impl fmt::Display for EccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EccError::InvalidParameters(s) => write!(f, "Invalid parameters: {}", s),
            EccError::InvalidLength(field, expected, found) => write!(
                f,
                "Invalid length for {}: expected <= {}, found {}",
                field, expected, found,
            ),
            EccError::EccRecoveryFailed => write!(f, "ECC recovery failed"),
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
    fn reproduce(&self, noisy: &[u8], known_erasures: Option<&[u8]>) -> Result<Vec<u8>, EccError>;
    fn calculate_num_errors(msg_len: usize, err_rate: f32) -> usize;
}
