//! Absolute-throughput benchmark for `Kupyna256`/`Kupyna512::digest` over a few message sizes -
//! see `crates/dstu-core/benches/kalyna.rs`'s doc comment for what this is and isn't (a
//! regression fixed point, not a cross-algorithm comparison claim).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna512};
use std::hint::black_box;

fn bench_kupyna(c: &mut Criterion) {
    for &len in &[64usize, 1024, 65536] {
        let message = vec![0x33u8; len];

        c.bench_with_input(
            BenchmarkId::new("kupyna_256_digest", len),
            &message,
            |b, m| {
                b.iter(|| Kupyna256::digest(black_box(m)));
            },
        );
        c.bench_with_input(
            BenchmarkId::new("kupyna_512_digest", len),
            &message,
            |b, m| {
                b.iter(|| Kupyna512::digest(black_box(m)));
            },
        );
    }
}

criterion_group!(benches, bench_kupyna);
criterion_main!(benches);
