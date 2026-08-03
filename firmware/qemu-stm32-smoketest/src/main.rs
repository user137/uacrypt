//! QEMU-emulated STM32 (Cortex-M4F, `netduinoplus2` machine) smoke test for `dstu-core`'s
//! `no_std`/no-`alloc` build - the "linked, running firmware" check T-116 flagged as not yet
//! built. Not a substitute for real-hardware validation (T-55/T-56, still untouched) - QEMU
//! emulates instruction semantics, not real silicon timing/side-channels.
//!
//! Runs the exact official DSTU test vectors already used by the host-side test suite (source
//! citations below match `crates/dstu-core/tests/vectors/`) and reports pass/fail via ARM
//! semihosting's `SYS_EXIT`, which becomes this process's exit code - `xtask`'s `qemu-stm32`
//! command checks it the same way `cargo run`'s own exit code already works in the embedded Rust
//! ecosystem's own QEMU-based CI examples.
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use dstu_core::hazmat::kalyna::Kalyna128_128;
use dstu_core::hazmat::kupyna::Kupyna256;
use panic_semihosting as _;

// docs/papers/Kalyna.pdf, Appendix B.2.6 - crates/dstu-core/tests/vectors/kalyna/128-128.json
const KALYNA_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
const KALYNA_PLAINTEXT: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
const KALYNA_EXPECTED_CIPHERTEXT: [u8; 16] = [
    0x81, 0xBF, 0x1C, 0x7D, 0x77, 0x9B, 0xAC, 0x20, 0xE1, 0xC9, 0xEA, 0x39, 0xB4, 0xD2, 0xAD, 0x06,
];

// docs/papers/Kupyna.pdf, Appendix B.2 (message_bits: 512) -
// crates/dstu-core/tests/vectors/kupyna/kupyna-256.json
const KUPYNA_MESSAGE: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];
const KUPYNA_EXPECTED_HASH: [u8; 32] = [
    0x08, 0xF4, 0xEE, 0x6F, 0x1B, 0xE6, 0x90, 0x3B, 0x32, 0x4C, 0x4E, 0x27, 0x99, 0x0C, 0xB2, 0x4E,
    0xF6, 0x9D, 0xD5, 0x8D, 0xBE, 0x84, 0x81, 0x3E, 0xE0, 0xA5, 0x2F, 0x66, 0x31, 0x23, 0x98, 0x75,
];

#[entry]
fn main() -> ! {
    let ciphertext = Kalyna128_128::encrypt(&KALYNA_KEY, &KALYNA_PLAINTEXT);
    if ciphertext != KALYNA_EXPECTED_CIPHERTEXT {
        hprintln!("FAIL: Kalyna-128/128 ciphertext mismatch");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("PASS: Kalyna-128/128");

    let hash = Kupyna256::digest(&KUPYNA_MESSAGE);
    if hash != KUPYNA_EXPECTED_HASH {
        hprintln!("FAIL: Kupyna-256 digest mismatch");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("PASS: Kupyna-256");

    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
