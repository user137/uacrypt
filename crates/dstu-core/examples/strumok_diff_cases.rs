//! Generates random Strumok test cases (key/IV/length) and this project's own Rust keystream
//! output for each, for the differential-testing harness in
//! `tests/oracle-harness/strumok-differential/` (see that directory's README and
//! `TASKS.md`/`DECISIONS.md` for why: the 8 UAPKI-attributed fixed vectors cover a narrow slice
//! of the key/IV/length space, and Strumok has no official test vectors at all - see D-15).
//!
//! Deterministic (fixed PRNG seed) so a mismatch is reproducible without needing to save the
//! random inputs separately. Prints one line per case to stdout:
//! `<variant> <key_hex> <iv_hex> <keystream_hex>`, where `keystream_hex` is this crate's own
//! `apply_keystream` output on an all-zero buffer of the chosen length (i.e. the raw keystream).
//!
//! Usage: `cargo run --example strumok_diff_cases -p dstu-core -- <case_count>` (default 200),
//! piped into the C differ - see the sibling directory's own doc comment for the exact command.

use dstu_core::hazmat::strumok::{Strumok256, Strumok512};

/// splitmix64 - small, deterministic, not cryptographic (doesn't need to be: this only needs to
/// generate *varied* inputs, not unpredictable ones - the actual security-relevant randomness
/// requirement, `getrandom`-backed CSPRNG, is a separate concern tracked for the high-level API).
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

    fn range(&mut self, max_inclusive: usize) -> usize {
        (self.next_u64() as usize) % (max_inclusive + 1)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let mut rng = SplitMix64(0x5354_524D_4F4B_3831); // fixed seed ("STRMOK81" in ASCII, arbitrary)

    for _ in 0..count {
        let mut key256 = [0u8; 32];
        rng.fill(&mut key256);
        let mut iv = [0u8; 32];
        rng.fill(&mut iv);
        // 1..=300, not 0..=300: a zero-length case prints an empty keystream_hex field, which the
        // sibling C differ's line-based parser can't tell apart from a missing field. Zero-length
        // input is already covered by the chunk-invariance unit test in tests/strumok.rs.
        let len = 1 + rng.range(299);
        let mut buf = vec![0u8; len];
        Strumok256::new(&key256, &iv).apply_keystream(&mut buf);
        println!("256 {} {} {}", to_hex(&key256), to_hex(&iv), to_hex(&buf));

        let mut key512 = [0u8; 64];
        rng.fill(&mut key512);
        rng.fill(&mut iv);
        let len = 1 + rng.range(299);
        let mut buf = vec![0u8; len];
        Strumok512::new(&key512, &iv).apply_keystream(&mut buf);
        println!("512 {} {} {}", to_hex(&key512), to_hex(&iv), to_hex(&buf));
    }
}
