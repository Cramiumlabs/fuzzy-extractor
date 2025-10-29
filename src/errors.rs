use crate::ecc::EccError;
use core::fmt;

/// Errors for FuzzyExtractor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzyExtractorError {
    EccError(EccError),
    KdfError(&'static str),
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
