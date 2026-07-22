//! Generates random Kalyna test cases (key/block per variant) and this project's own Rust
//! ciphertext for each, for the differential-testing harness in
//! `tests/oracle-harness/kalyna-differential/` - the Kalyna/Kupyna counterpart to the Strumok
//! harness in the sibling `strumok-differential/` directory (see `DECISIONS.md` D-22 for why that
//! one exists, and D-24 for why this one was added afterward for parity rather than leaving
//! Strumok looking like the only primitive that got this level of scrutiny).
//!
//! Deterministic (fixed PRNG seed), same reasoning as `strumok_diff_cases.rs`. Prints one line per
//! case: `<variant> <key_hex> <block_hex> <ciphertext_hex>`, `variant` being `<block_bits>-<key_bits>`
//! (e.g. `128-128`), matching `oracles/kalyna-reference/`'s own `KalynaInit(block_bits, key_bits)`.
//!
//! Usage: `cargo run --example kalyna_diff_cases -p dstu-core --release -- <case_count>` (default
//! 200 per variant), piped into the C differ - see that directory's own doc comment.

use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_256, Kalyna256_256, Kalyna256_512, Kalyna512_512,
};

/// splitmix64 - see `strumok_diff_cases.rs` for why a non-cryptographic PRNG is fine here.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

macro_rules! gen_variant {
    ($rng:expr, $count:expr, $label:literal, $variant:ty, $key_len:literal, $block_len:literal) => {
        for _ in 0..$count {
            let mut key = [0u8; $key_len];
            $rng.fill(&mut key);
            let mut block = [0u8; $block_len];
            $rng.fill(&mut block);
            let ciphertext = <$variant>::encrypt(&key, &block);
            println!(
                "{} {} {} {}",
                $label,
                to_hex(&key),
                to_hex(&block),
                to_hex(&ciphertext)
            );
        }
    };
}

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let mut rng = SplitMix64(0x4B41_4C59_4E41_3234); // fixed seed ("KALYNA24" in ASCII, arbitrary)

    gen_variant!(rng, count, "128-128", Kalyna128_128, 16, 16);
    gen_variant!(rng, count, "128-256", Kalyna128_256, 32, 16);
    gen_variant!(rng, count, "256-256", Kalyna256_256, 32, 32);
    gen_variant!(rng, count, "256-512", Kalyna256_512, 64, 32);
    gen_variant!(rng, count, "512-512", Kalyna512_512, 64, 64);
}
