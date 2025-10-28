#![feature(test)]

extern crate test;

use rust_fuzzy_extractor::ecc::ReedSolomonECC;
use rust_fuzzy_extractor::fuzzy_extractor::{FuzzyExtractor, SimpleHashKdf};
use test::Bencher;

// ============================================================================
// FUZZY EXTRACTOR BENCHMARKS
// ============================================================================

#[bench]
fn bench_fuzzy_extractor_generate(b: &mut Bencher) {
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];

    b.iter(|| {
        test::black_box(extractor.generate(w, &seed_input).unwrap());
    });
}

#[bench]
fn bench_fuzzy_extractor_reproduce_no_noise(b: &mut Bencher) {
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];
    let (_, helper) = extractor.generate(w, &seed_input).unwrap();

    b.iter(|| {
        test::black_box(extractor.reproduce(w, &helper, None).unwrap());
    });
}

#[bench]
fn bench_fuzzy_extractor_reproduce_with_noise(b: &mut Bencher) {
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];
    let (_, helper) = extractor.generate(w, &seed_input).unwrap();

    // Create noisy version
    let mut w_noisy = w.to_vec();
    // Inject a few errors at evenly-spaced positions
    for i in 0..3 {
        let pos = i * (w_noisy.len() / 3);
        if pos < w_noisy.len() {
            w_noisy[pos] ^= 0xFF;
        }
    }

    b.iter(|| {
        test::black_box(extractor.reproduce(&w_noisy, &helper, None).unwrap());
    });
}

#[bench]
fn bench_fuzzy_extractor_generate_large_key(b: &mut Bencher) {
    let w = b"large_biometric_input_data_sample!!";
    let msg_len = 32;
    let err_rate = 0.1;
    let key_len = 128;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];

    b.iter(|| {
        test::black_box(extractor.generate(w, &seed_input).unwrap());
    });
}

#[bench]
fn bench_fuzzy_extractor_full_round_trip(b: &mut Bencher) {
    let w = b"round_trip_test_data";
    let msg_len = 20;
    let err_rate = 0.2;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];

    b.iter(|| {
        let (_, helper) = extractor.generate(w, &seed_input).unwrap();
        test::black_box(extractor.reproduce(w, &helper, None).unwrap());
    });
}

// ============================================================================
// MEMORY USAGE BENCHMARKS
// ============================================================================

#[bench]
fn bench_memory_fuzzy_extractor_generate(b: &mut Bencher) {
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];

    // Estimate memory by calculating sizes
    let (key, helper) = extractor.generate(w, &seed_input).unwrap();
    let estimated_memory = key.len() + helper.len() + seed_input.len();

    println!("\nEstimated memory for generate:");
    println!("  - Key size: {} bytes", key.len());
    println!("  - Helper data size: {} bytes", helper.len());
    println!("  - Total output: {} bytes", estimated_memory);

    b.iter(|| {
        test::black_box(extractor.generate(w, &seed_input).unwrap());
    });
}

#[bench]
fn bench_memory_fuzzy_extractor_reproduce(b: &mut Bencher) {
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];
    let (_, helper) = extractor.generate(w, &seed_input).unwrap();

    // Estimate memory by calculating sizes
    let key = extractor.reproduce(w, &helper, None).unwrap();
    let estimated_memory = key.len() + helper.len();

    println!("\nEstimated memory for reproduce:");
    println!("  - Key size: {} bytes", key.len());
    println!("  - Helper data size: {} bytes", helper.len());
    println!("  - Total: {} bytes", estimated_memory);

    b.iter(|| {
        test::black_box(extractor.reproduce(w, &helper, None).unwrap());
    });
}

#[bench]
fn bench_memory_fuzzy_extractor_large_interleaved(b: &mut Bencher) {
    // Benchmark for 384 bytes input using 16-byte block interleaving
    let block_size = 16;
    let num_blocks = 384 / block_size; // 24 blocks
    let err_rate = 0.15;
    let per_block_key_len = 32;
    let key_len = per_block_key_len * num_blocks;

    // Create 384-byte input
    let mut w = vec![0u8; 384];
    for i in 0..384 {
        w[i] = ((i * 7) % 256) as u8;
    }

    // Pre-generate all helpers and keys
    let mut all_helpers = Vec::new();
    for block_idx in 0..num_blocks {
        let start = block_idx * block_size;
        let end = start + block_size;
        let block = &w[start..end];

        let extractor = FuzzyExtractor::new(
            ReedSolomonECC::new(block_size, err_rate).unwrap(),
            SimpleHashKdf::new_no_salt(),
            per_block_key_len,
        )
        .unwrap();

        let seed_input = vec![0xFF; block_size + 1];
        let (_, helper) = extractor.generate(block, &seed_input).unwrap();
        all_helpers.push(helper);
    }

    // Calculate memory usage
    let total_helper_size: usize = all_helpers.iter().map(|h| h.len()).sum();
    let total_memory = key_len + total_helper_size;

    println!("\nEstimated memory for interleaved (384 bytes, 16-byte blocks):");
    println!("  - Input size: {} bytes", w.len());
    println!("  - Number of blocks: {}", num_blocks);
    println!("  - Block size: {} bytes", block_size);
    println!("  - Key per block: {} bytes", per_block_key_len);
    println!("  - Total key size: {} bytes", key_len);
    println!("  - Helper per block: {} bytes", all_helpers[0].len());
    println!("  - Total helper size: {} bytes", total_helper_size);
    println!("  - Total memory: {} bytes", total_memory);

    b.iter(|| {
        let mut reproduced_keys = Vec::new();
        for block_idx in 0..num_blocks {
            let start = block_idx * block_size;
            let end = start + block_size;
            let block = &w[start..end];

            let extractor = FuzzyExtractor::new(
                ReedSolomonECC::new(block_size, err_rate).unwrap(),
                SimpleHashKdf::new_no_salt(),
                per_block_key_len,
            )
            .unwrap();

            let key = extractor.reproduce(block, &all_helpers[block_idx], None).unwrap();
            reproduced_keys.push(key);
        }

        let combined_key: Vec<u8> = reproduced_keys.into_iter().flatten().collect();
        test::black_box(combined_key);
    });
}
