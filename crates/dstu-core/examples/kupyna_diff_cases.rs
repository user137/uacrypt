//! Generates random Kupyna test cases (messages of varying length) and this project's own Rust
//! digest for each, for the differential-testing harness in
//! `tests/oracle-harness/kupyna-differential/` - see `DECISIONS.md` D-24 for why this exists
//! (parity with the Strumok/Kalyna differential harnesses, D-22, so no primitive looks singled
//! out for extra scrutiny without reason).
//!
//! Deterministic (fixed PRNG seed), same reasoning as `strumok_diff_cases.rs`. Prints one line
//! per case: `<variant> <message_hex> <hash_hex>`, `variant` being `256` or `512`.
//!
//! Usage: `cargo run --example kupyna_diff_cases -p dstu-core -- <case_count>` (default 300 per
//! variant), piped into the C differ - see that directory's own doc comment.

use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna512};

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
        .unwrap_or(300);

    let mut rng = SplitMix64(0x4B55_5059_4E41_3234); // fixed seed ("KUPYNA24" in ASCII, arbitrary)

    for _ in 0..count {
        // Byte-aligned lengths only - matches this project's public API (see kupyna.rs's own
        // doc comment on why bit-level messages aren't supported). 1..=500, not 0..=500: a
        // zero-length message prints an empty message_hex field, which the sibling C differ's
        // line-based parser can't tell apart from a missing field - same fix as
        // strumok_diff_cases.rs. The empty-message case is already an official test vector
        // (kupyna-{256,512}.json's message_bits=0 case), so nothing is lost by excluding it here.
        let len = 1 + rng.range(499);
        let mut message = vec![0u8; len];
        rng.fill(&mut message);

        let hash256 = Kupyna256::digest(&message);
        println!("256 {} {}", to_hex(&message), to_hex(&hash256));

        let hash512 = Kupyna512::digest(&message);
        println!("512 {} {}", to_hex(&message), to_hex(&hash512));
    }
}
