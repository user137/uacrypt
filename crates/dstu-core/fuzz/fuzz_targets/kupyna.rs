#![no_main]

use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna512};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). Kupyna::digest takes
// arbitrary-length byte input and must never panic/crash regardless of length or content -
// that's the only property this target checks (not correctness, which the vector tests cover).
fuzz_target!(|data: &[u8]| {
    let _ = Kupyna256::digest(data);
    let _ = Kupyna512::digest(data);
});
