#![feature(test)]

extern crate test;

use rust_fuzzy_extractor::ecc::ReedSolomonECC;
use rust_fuzzy_extractor::fuzzy_extractor::FuzzyExtractor;
use rust_fuzzy_extractor::simple_hash_kdf::SimpleHashKdf;
use test::Bencher;

// ============================================================================
// FUZZY EXTRACTOR BENCHMARKS
// ============================================================================

#[bench]
fn bench_fuzzy_extractor_generate(b: &mut Bencher) {
    // Benchmark the generate method of FuzzyExtractor
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
    // Benchmark the reproduce method without noise
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
    // Benchmark the reproduce method with noise
    let w = b"biometric_data_sample_input";
    let msg_len = 24;
    let err_rate = 0.15;
    let key_len = 32;

    let ecc = ReedSolomonECC::new(msg_len, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor = FuzzyExtractor::new(ecc, kdf, key_len).unwrap();
    let seed_input = vec![0xFF; msg_len + 1];
    let (_, helper) = extractor.generate(w, &seed_input).unwrap();

    // Create noisy version of input
    let mut w_noisy = w.to_vec();
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
fn bench_memory_fuzzy_extractor_generate(b: &mut Bencher) {
    // Benchmark memory usage for generate method
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
fn bench_memory_fuzzy_extractor_reproduce(b: &mut Bencher) {
    // Benchmark memory usage for reproduce method
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
fn bench_fuzzy_extractor_keygen(b: &mut Bencher) {
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
fn bench_fuzzy_extractor_reproduce(b: &mut Bencher) {
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
fn bench_fuzzy_extractor_keygen_with_blocks(b: &mut Bencher) {
    let block_size = 16;
    let err_rate = 0.15;
    let per_block_key_len = 32;
    let final_key_len = 32;

    let ecc = ReedSolomonECC::new(block_size, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor =
        FuzzyExtractor::new_with_blocks(ecc, kdf, block_size, per_block_key_len, final_key_len)
            .unwrap();

    let seed_input = vec![0xAB; block_size];
    let w = vec![0u8; 384];

    b.iter(|| {
        test::black_box(extractor.generate(&w, &seed_input).unwrap());
    });
}

#[bench]
fn bench_fuzzy_extractor_reproduce_with_blocks(b: &mut Bencher) {
    let block_size = 16;
    let err_rate = 0.15;
    let per_block_key_len = 32;
    let final_key_len = 32;

    let ecc = ReedSolomonECC::new(block_size, err_rate).unwrap();
    let kdf = SimpleHashKdf::new_no_salt();
    let extractor =
        FuzzyExtractor::new_with_blocks(ecc, kdf, block_size, per_block_key_len, final_key_len)
            .unwrap();

    let seed_input = vec![0xAB; block_size];
    let w = vec![0u8; 384];
    let (_, helper) = extractor.generate(&w, &seed_input).unwrap();

    b.iter(|| {
        test::black_box(extractor.reproduce(&w, &helper, None).unwrap());
    });
}
