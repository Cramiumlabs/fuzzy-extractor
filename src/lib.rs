#![cfg_attr(not(feature = "std"), no_std)]

// Set jemallocator as the global allocator (only when jemalloc feature is enabled, e.g. for benchmarks)
#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: Jemalloc = Jemalloc;

pub mod ecc;
pub mod fuzzy_extractor;
pub mod secure_sketch;
pub mod simple_hash_kdf;
