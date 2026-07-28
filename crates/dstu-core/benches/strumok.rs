//! Absolute-throughput benchmark for `Strumok256`/`Strumok512::apply_keystream` over a few buffer
//! sizes. This project's original literal-16-word-shift implementation (`docs/DECISIONS.md` D-18) was
//! replaced by a ring buffer 2026-07-22 (D-26), and `apply_keystream` gained a batched, fixed-
//! index 128-byte bulk path 2026-07-27 (`docs/TASKS.md` T-135, `docs/DECISIONS.md` D-86) - this benchmark
//! measures whatever the current implementation is at any given time (an in-process regression
//! fixed point, not a snapshot of one specific historical design) and does **not** itself compare
//! against the oracles directly - see `docs/PERFORMANCE.md`'s Strumok section for the binary-level
//! comparison against outspace/UAPKI.

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
