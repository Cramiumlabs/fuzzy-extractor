extern crate alloc;

pub mod ecc_rs;
/// Re-export split files for backward compatibility
pub mod ecc_trait;
pub mod secure_sketch;

pub use ecc_rs::ReedSolomonECC;
pub use ecc_trait::{ECC, EccError};
pub use secure_sketch::SecureSketch;
