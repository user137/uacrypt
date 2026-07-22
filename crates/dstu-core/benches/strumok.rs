//! Absolute-throughput benchmark for `Strumok256`/`Strumok512::apply_keystream` over a few
//! buffer sizes. This measures this project's literal-16-word-shift implementation
//! (`DECISIONS.md` D-18) in isolation - it does **not** compare against the oracles' rotating
//! in-place buffer, since that would require implementing that variant here too purely to
//! benchmark it. Treat this as a regression fixed point and an absolute throughput number, not
//! confirmation either way of the shift-vs-rotate tradeoff discussed in D-18.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dstu_core::hazmat::strumok::{Strumok256, Strumok512};
use std::hint::black_box;

fn bench_strumok(c: &mut Criterion) {
    let key256 = [0x44u8; 32];
    let key512 = [0x44u8; 64];
    let iv = [0x55u8; 32];

    for &len in &[64usize, 1024, 65536] {
        c.bench_with_input(
            BenchmarkId::new("strumok_256_apply_keystream", len),
            &len,
            |b, &len| {
                let mut buf = vec![0u8; len];
                b.iter(|| {
                    Strumok256::new(black_box(&key256), black_box(&iv)).apply_keystream(&mut buf);
                });
            },
        );
        c.bench_with_input(
            BenchmarkId::new("strumok_512_apply_keystream", len),
            &len,
            |b, &len| {
                let mut buf = vec![0u8; len];
                b.iter(|| {
                    Strumok512::new(black_box(&key512), black_box(&iv)).apply_keystream(&mut buf);
                });
            },
        );
    }
}

criterion_group!(benches, bench_strumok);
criterion_main!(benches);
