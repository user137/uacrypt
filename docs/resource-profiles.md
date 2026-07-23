# Resource profiles: `fused` (default) vs `small-tables`

`dstu-core` builds in one of two resource profiles, chosen by a Cargo feature. Both produce
byte-identical output — same DSTU 7624/7564/8845 math, same test vectors pass either way (see
`DECISIONS.md` D-35/D-38/D-39). The only difference is a straight trade: flash/ROM footprint
against throughput.

- **`fused` (default, no feature flag needed)** — precomputed S-box+MDS lookup tables. Fast,
  costs real flash.
- **`small-tables` (`--features dstu-core/small-tables`)** — the same math computed on the fly via
  `GF(2^8)` multiplication, no big tables. Small, costs real speed.

Pick `fused` unless you have a specific, measured flash budget that doesn't fit it — see "Which one
do I need?" below.

## Memory: what each profile actually compiles in

All numbers are `const` table data linked into the binary — measured directly off
`hazmat::tables.rs`/`hazmat::strumok.rs`, not estimated.

| Table set | `fused` | `small-tables` |
|---|---:|---:|
| Kalyna/Kupyna S-boxes (`SBOXES`, `SBOXES_DEC`) | 2.0 KB | 2.0 KB |
| Kalyna/Kupyna MDS matrices (`MDS_MATRIX`, `MDS_INV_MATRIX`) | — (unused) | 0.13 KB |
| Kalyna/Kupyna precomputed MDS tables (`MDS_TABLE`, `MDS_INV_TABLE`) | 32.0 KB | not compiled |
| Kalyna/Kupyna fused S-box+MDS tables (`SBOX_MDS`, `SBOX_MDS_DEC`) | 32.0 KB | not compiled |
| **Kalyna + Kupyna subtotal** | **66.0 KB** | **~2.1 KB** |
| Strumok `T0..T7` | 16.0 KB | not compiled |
| Strumok `MUL_ALPHA`/`MUL_ALPHA_INV` (not swappable — different math, needed either way) | 4.0 KB | 4.0 KB |
| **Strumok subtotal** (reuses the Kalyna/Kupyna S-box/matrix above, adds nothing extra) | **20.0 KB** | **~4.0 KB** |
| **All three algorithms, one binary** | **~86 KB** | **~6.1 KB** |

That's a real, measured difference, not just a theoretical one: a release build of `uacrypt`
(all three algorithms linked in) is **~75 KB smaller** under `small-tables`.

**What this means depending on your target**: on a 32-bit MCU with memory-mapped flash (ARM
Cortex-M, Xtensa/RISC-V — the `fused` tables live in flash and cost *zero* RAM, only flash space).
On AVR (Harvard architecture), a `const` table copies into SRAM at startup unless placed in
`PROGMEM` with AVR-specific code — `small-tables` avoids that problem entirely by not having a
table to place.

## Speed: what that costs you

Measured with a real built binary (`uacrypt`, release build), one process per number, same
methodology as `PERFORMANCE.md`'s canonical binary-level comparison (`DECISIONS.md` D-34) — not a
theoretical estimate. Ryzen 5 PRO 4650U dev machine, Windows. One run each (not the full
multi-baseline `criterion` protocol `PERFORMANCE.md` uses for cross-implementation claims) — good
enough to size the trade-off, not a certified regression baseline.

| Algorithm | `fused` | `small-tables` | `fused` is... |
|---|---:|---:|---:|
| Kalyna-128-128 encrypt (cached schedule) | 124.0 MB/s | 5.9 MB/s | **~21x faster** |
| Kalyna-512-512 encrypt (cached schedule) | 86.4 MB/s | 3.6 MB/s | **~24x faster** |
| Kalyna-512-512 decrypt (cached schedule) | 75.6 MB/s | 3.8 MB/s | **~20x faster** |
| Kupyna-256 (64 KB message) | 92.3 MB/s | 2.4 MB/s | **~39x faster** |
| Kupyna-512 (64 KB message) | 74.4 MB/s | 1.8 MB/s | **~43x faster** |
| Strumok-256 (64 KB, cached) | 610.6 MB/s | 135.9 MB/s | **~4.5x faster** |
| Strumok-512 (64 KB, cached) | 562.4 MB/s | 139.1 MB/s | **~4.0x faster** |

**Why Strumok's gap is so much smaller than Kalyna/Kupyna's**: Kalyna and Kupyna's *entire* round
is the S-box+MDS step that the profile swaps out, so the whole cipher slows down by roughly the
same factor. Strumok's `T`-substitution is only one part of its per-word cost (LFSR feedback,
`mul_alpha`, state update all stay identical either way) — the parts that don't change dilute the
slowdown from the part that does.

**Reproducing**: `cargo build -p uacrypt --release [--features dstu-core/small-tables]`, then the
same `kalyna-block`/`kupyna-digest`/`strumok-crypt` commands `PERFORMANCE.md`'s "Reproducing" notes
document.

## Which one do I need?

A quick sizing guide by target, from `DECISIONS.md` D-35's survey of typical hardware — flash
budget is what actually decides this, not a chip-family label:

| Target | Typical flash | Fits `fused` (~86 KB tables)? | Use |
|---|---|---|---|
| Desktop / server / Raspberry Pi | MBs+ | yes, trivially | **`fused`** (default) |
| ESP32 / ESP32-S3 / ESP32-C3 | 4 MB+ | yes, trivially | **`fused`** (default) |
| STM32 F1/F3/G4/F4/F7/H7 (mid-range and up) | 64 KB – 2 MB | yes | **`fused`** (default) |
| STM32 L0/F0/G0 entry-level (e.g. L011F4, F030F4) | 16–64 KB | no | **`small-tables`** |
| Arduino Mega (ATmega2560, AVR) | 256 KB flash, 8 KB SRAM | tables fit flash, but AVR copies `const` to SRAM unless placed in `PROGMEM` — not done here yet | **`small-tables`**, and even then only once `PROGMEM` placement exists (`TASKS.md` Phase 4) |
| Arduino Uno (ATmega328P, AVR) | 32 KB flash, 2 KB SRAM | no — smaller than even `small-tables`'s footprint would need with room left for code | not viable yet either way (stretch goal, `TASKS.md` Phase 4) |

If you're not memory-constrained, don't reach for `small-tables` — you'd be trading a large,
measured speed loss for a save you don't need.

## How to build each

```sh
# fused (default) - what you get with no extra flags
cargo build -p dstu-core --release
cargo build -p uacrypt --release

# small-tables
cargo build -p dstu-core --release --no-default-features --features small-tables
cargo build -p uacrypt --release --features dstu-core/small-tables
```

Both profiles pass the exact same test suite (official DSTU vectors, `proptest` round-trips) —
`cargo test --features dstu-core/small-tables` — see `DECISIONS.md` D-39 for why one test suite
covering both is sufficient rather than needing separate verification per profile.
