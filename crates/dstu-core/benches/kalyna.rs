//! Absolute-throughput benchmarks for each Kalyna variant's `encrypt`/`decrypt` - not a claim of
//! meaningful cross-algorithm or cross-language comparison (those numbers are inherently rough
//! and machine-dependent), just a fixed point to catch regressions against and to have *some*
//! number on record. See `TASKS.md` "Testing & hardening" / `DECISIONS.md` D-18's note on the cost
//! of design choices.

use criterion::{criterion_group, criterion_main, Criterion};
use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_128ExpandedKey, Kalyna128_256, Kalyna128_256ExpandedKey,
    Kalyna256_256, Kalyna256_256ExpandedKey, Kalyna256_512, Kalyna256_512ExpandedKey,
    Kalyna512_512, Kalyna512_512ExpandedKey,
};
use std::hint::black_box;

macro_rules! bench_variant {
    ($c:expr, $name:literal, $variant:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {
        let key = [0x11u8; $key_len];
        let block = [0x22u8; $block_len];
        let ciphertext = <$variant>::encrypt(&key, &block);

        $c.bench_function(concat!($name, "_encrypt"), |b| {
            b.iter(|| <$variant>::encrypt(black_box(&key), black_box(&block)));
        });
        $c.bench_function(concat!($name, "_decrypt"), |b| {
            b.iter(|| <$variant>::decrypt(black_box(&key), black_box(&ciphertext)));
        });

        // Block-only timing, key schedule expanded once outside the timed loop - the honest
        // number PERFORMANCE.md's methodology text always claimed but the two benches above never
        // actually measured (D-28 stage 0/3: `key_expand` was ~60-79% of the raw functions' time).
        let expanded = <$expanded>::new(&key);
        $c.bench_function(concat!($name, "_encrypt_block_only"), |b| {
            b.iter(|| expanded.encrypt_block(black_box(&block)));
        });
        $c.bench_function(concat!($name, "_decrypt_block_only"), |b| {
            b.iter(|| expanded.decrypt_block(black_box(&ciphertext)));
        });
    };
}

fn bench_kalyna(c: &mut Criterion) {
    bench_variant!(
        c,
        "kalyna_128_128",
        Kalyna128_128,
        Kalyna128_128ExpandedKey,
        16,
        16
    );
    bench_variant!(
        c,
        "kalyna_128_256",
        Kalyna128_256,
        Kalyna128_256ExpandedKey,
        32,
        16
    );
    bench_variant!(
        c,
        "kalyna_256_256",
        Kalyna256_256,
        Kalyna256_256ExpandedKey,
        32,
        32
    );
    bench_variant!(
        c,
        "kalyna_256_512",
        Kalyna256_512,
        Kalyna256_512ExpandedKey,
        64,
        32
    );
    bench_variant!(
        c,
        "kalyna_512_512",
        Kalyna512_512,
        Kalyna512_512ExpandedKey,
        64,
        64
    );
}

criterion_group!(benches, bench_kalyna);
criterion_main!(benches);
