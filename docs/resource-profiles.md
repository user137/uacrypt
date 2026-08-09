# Resource profiles: `fused` (default) vs `small-tables`

`dstu-core` builds in one of two resource profiles, chosen by a Cargo feature. Both produce
byte-identical output — same DSTU 7624/7564/8845 math, same test vectors pass either way (see
`docs/DECISIONS.md` D-35/D-38/D-39). The only difference is a straight trade: flash/ROM footprint
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

**A second, separate `fused`-only cost as of T-172/D-161 (`docs/DECISIONS.md`)**: Kalyna's interior
round sequence is now a genuine compile-time unroll (no loop at all, `unroll_rounds!`) under
`fused`, in exchange for a real 21-35% speed win on four of its five variants. This is *not* a
`const`-table cost like the numbers above — it's compiled code (`.text`), and it's real, measured
the same way as this doc's own linked-`uacrypt`-binary method above (not a raw rlib object-code
sum, which overestimates — an earlier pass got this wrong first, corrected same session, see
D-161): a release `uacrypt.exe` grew **+71.1 KB (+4.17%)** under `fused`. Deliberately **not**
applied to `small-tables`, which keeps Kalyna's old runtime loop specifically so this profile's
whole reason to exist (smallest possible code) isn't undercut — `small-tables`'s own binary only
grew **+9.2 KB (+0.56%)** (an unrelated, minor side effect of `NR` becoming a const generic
everywhere, kept for both profiles to avoid two parallel function signatures). Net effect: the
`fused`-vs-`small-tables` gap on a release `uacrypt.exe` widened from ~60.5 KB to ~122.4 KB. If
you're on `small-tables` for a real measured flash budget, this unroll never applies to you either
way — but note the profile split is no longer *only* about which table data links in (see D-161's
"scope of what `small-tables` now means" note): it now also picks which Kalyna round-sequence code
compiles, correctness-identical either way but a real, additive-Cargo-feature-wide performance
choice, not just a flash one.

**What this means depending on your target**: on a 32-bit MCU with memory-mapped flash (ARM
Cortex-M, Xtensa/RISC-V — the `fused` tables live in flash and cost *zero* RAM, only flash space).
On AVR (Harvard architecture), a `const` table copies into SRAM at startup unless placed in
`PROGMEM` with AVR-specific code — `small-tables` avoids that problem entirely by not having a
table to place.

## RAM/stack: what each mode costs beyond the table data above

**A different axis from the flash/const-table split above, and the same for both profiles** —
`fused`/`small-tables` only swap *which table data* is linked in; they don't change any struct
layout or working-set size. Numbers below are computed from the actual struct definitions and
array literal dimensions in the current tree (`size_of`-equivalent arithmetic, cross-checked
against the source lines cited), not measured with a memory profiler — a weaker claim than the
table above's "measured directly off `hazmat::tables.rs`", stated as such rather than inherited.

**Key-schedule storage is `MAX_NB`-sized regardless of variant** — the same oversizing pattern
`docs/TASKS.md` T-128 fixed on the *compute* side (round functions), still present on the *storage*
side: `RoundKeys` (`hazmat::kalyna.rs`) is `[[Column; MAX_NB]; ROUND_KEYS_LEN]` = `19 * 8 * 8` =
**1216 bytes**, the same for every variant — a Kalyna128_128 caller pays the identical footprint a
Kalyna512_512 caller does, even though 128-128's real round-key material is a quarter the size.
`ExpandedKey` (the cached-schedule type every `kalyna_variant!` invocation produces) holds two
(`round_keys` + `dec_keys`) = **2432 bytes** per live instance, again independent of variant. Not
flagged as a problem to fix here — just a real number the resource-constrained cases from the
sizing table below should account for.

**Same pattern on `KupynaCore` after T-134** (`docs/DECISIONS.md` D-85): T-134 made Kupyna's *compute*
path (`sub_shift_mix`/`compress` and friends) const-generic over `COLUMNS`, the direct analogue of
T-128's Kalyna fix above — but, same as T-128 for Kalyna, deliberately left `KupynaCore`'s own
*storage* untouched (`advisor()`'s explicit scope call during T-134: genericizing the struct itself
buys no throughput, since its fields are touched once per `update`, not once per round). `h`/
`buffer` are still `MAX_COLUMNS`(16)-sized regardless of variant: `[[u8; ROWS]; MAX_COLUMNS]` +
`[u8; MAX_BLOCK_BYTES]` = `128 + 128` = **256 bytes** per live `Kupyna256Hasher`/`Kupyna512Hasher`
(or `KupynaCore` inside `kupyna_kmac`/`kupyna_kdf`), even though Kupyna-256's real working state is
half that width. Const-genericizing `KupynaCore` itself would halve this to 128 bytes for
Kupyna-256 specifically - flagged in D-85 as a real memory win worth a separate follow-up task, not
pursued as part of T-134's throughput-only scope.

**GCM/GMAC's field multiply builds a transient 16-entry comb table on the stack, once per call
to `poly_mul_wide`** (`hazmat::gf2m_wide.rs`, T-125's 4-bit-window comb method, `docs/DECISIONS.md`
D-76) — new since this doc was first written, and genuinely a *stack* cost, not a *flash* one
(freed when the call returns, never linked into the binary as `const` data):

| Field width (`m`) | Used by | `t: [[u64; $limbs2]; 16]` | Total incl. `a_wide`/`acc` scratch |
|---|---|---:|---:|
| 128 (`Gf2m128`, `$limbs2=4`) | Kalyna128-\* GCM/GMAC | 16 × 4 × 8 = 512 B | ~576 B |
| 256 (`Gf2m256`, `$limbs2=8`) | Kalyna256-\* GCM/GMAC | 16 × 8 × 8 = 1024 B | ~1152 B |
| 512 (`Gf2m512`, `$limbs2=16`) | Kalyna512-512 GCM/GMAC | 16 × 16 × 8 = 2048 B | ~2304 B |

This is on the call stack of whatever calls `Gf2m*::multiply` — one block's worth of GCM's Horner
accumulation, or GMAC's equivalent — not held for the construction's lifetime, and it applies
identically to `crypto_secretbox`/`crypto_secretstream` too (both built on `Kalyna256_256Gcm`, so
they pay the `m=256`/~1152 B figure during every chunk's tag computation). **Kalyna-XTS is the
contrasting case**: T-126 replaced its once-per-block tweak-doubling with `double()` — a handful of
`u64` shift/XOR locals, no comb table at all — so XTS's own stack cost is negligible regardless of
variant, unlike GCM/GMAC's.

**`crypto_secretstream`'s `PushState`/`PullState` hold only a 32-byte subkey**, not a cached
`ExpandedKey` — the smallest persistent state of any construction in this crate, at the cost of
re-running `Kalyna256_256Gcm::new(&self.subkey)` (a full 2432-byte-schedule expansion, transient
during the call) on every `push`/`pull` chunk rather than once per stream. A deliberate space/time
trade in the current implementation, not a bug — noted here since it's directly relevant to "how
much RAM does this mode cost," not proposed as a change.

**`uacrypt`'s own I/O buffering** (CLI-layer, not `dstu-core`): `SECRETSTREAM_CHUNK_BYTES`/
`DIGEST_STREAM_CHUNK_BYTES`/`SIGN_STREAM_CHUNK_BYTES`/`STRUMOK_STREAM_CHUNK_BYTES` are all 8 KiB
(`crates/uacrypt/src/lib.rs`) — `encrypt`/`decrypt` double-buffers two chunks (`cur`+`next`) for
its rekey-lookahead logic, ~16 KiB peak; the others single-buffer, ~8 KiB peak. Separate from
these: `DIGEST_BENCH_CHUNK_BYTES` (1 MiB) is the `--iterations`-benchmark path only, sized for
throughput measurement, not real single-pass use (D-42's own "each streaming command picks a chunk
size matched to its own constraint" convention).

## Speed: what that costs you

Measured with a real built binary (`uacrypt`, release build), one process per number, same
methodology as `docs/PERFORMANCE.md`'s canonical binary-level comparison (`docs/DECISIONS.md` D-34) — not a
theoretical estimate. Ryzen 5 PRO 4650U dev machine, Windows. One run each (not the full
multi-baseline `criterion` protocol `docs/PERFORMANCE.md` uses for cross-implementation claims) — good
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

**Strumok's absolute numbers above predate 2026-07-27's batched/fixed-index `apply_keystream`
rewrite (`docs/TASKS.md` T-135, `docs/DECISIONS.md` D-86)** — both columns' real throughput is now
substantially higher (the `fused` column's own `criterion` numbers moved by roughly -53 to -65% in
time, i.e. ~2.2-2.8x higher MB/s, at message sizes at or above the new 128-byte bulk threshold;
`small-tables` gets the same batching/indexing win independently of table size, so its own absolute
number moved too, direction unmeasured here). Not re-measured in this table this pass — the
**ratio** conclusion below (Strumok's `fused`-vs-`small-tables` gap being much smaller than Kalyna/
Kupyna's, because only `T`-substitution is swapped) should still roughly hold since both columns
share the same rewrite, but treat the two absolute MB/s figures above as stale until re-measured.

**Why Strumok's gap is so much smaller than Kalyna/Kupyna's**: Kalyna and Kupyna's *entire* round
is the S-box+MDS step that the profile swaps out, so the whole cipher slows down by roughly the
same factor. Strumok's `T`-substitution is only one part of its per-word cost (LFSR feedback,
`mul_alpha`, state update all stay identical either way) — the parts that don't change dilute the
slowdown from the part that does.

**Reproducing**: `cargo build -p uacrypt --release [--features dstu-core/small-tables]`, then the
same `kalyna-block`/`kupyna-digest`/`strumok-crypt` commands `docs/PERFORMANCE.md`'s "Reproducing" notes
document.

## DSTU 4145 `verify`: the same flag, a different kind of trade (T-151/D-108)

Everything above this point is a flash/ROM-`const`-table trade. `hazmat::dstu4145::curve163`'s
`verify_combine` (the `s*G + r*Q` step DSTU 4145 signature verification needs) reuses this **same**
`small-tables` feature and the same polarity (default = faster, `small-tables` = smaller/simpler),
but for a genuinely different reason: **no new `const` table is added here at all.** The default
profile's faster path (projective/López-Dahab coordinates + Shamir's trick) computes its one small
lookup table (`{Infinity, G, Q, G+Q}`, 4 points) fresh on every `verify` call - nothing new is
linked into the binary. What `small-tables` actually buys for this one primitive is a **smaller,
already-longer-audited code path** (the classic constant-time ladder, called twice, no new
projective-coordinate arithmetic compiled in at all) rather than fewer flash bytes - a code-size/
audit-surface trade, not the memory-table trade every other row in this document describes. See
`docs/DECISIONS.md` D-108 for the full design and why.

| Profile | `verify` ops/s |
|---|---:|
| Default (fast path) | **~16,850-17,055** |
| `small-tables` (classic ladder) | ~8,850-9,040 |
| Default is... | **~1.9x faster** |

Updated 2026-08-09 (`docs/TASKS.md` T-198, `docs/DECISIONS.md` D-184) - both profiles now go
through `hazmat::gf2m163`'s hardware-`clmul` dispatch (`FieldElement::multiply()`, orthogonal to
which `verify_combine` algorithm wraps it), so both absolute numbers jumped by roughly the same
factor versus the original D-108/T-153 measurements (239.31/120.06, then 524.01/328.20) - the
**relative** gap between the two profiles stayed close to its original ~1.9-2.0x the whole time,
since the hardware path accelerates the field multiply underneath both equally. See
`docs/PERFORMANCE.md`'s own T-198 section for the full history and reproduction command.

`sign`/`verifying_key()` (which multiply by a *secret* scalar - the ephemeral nonce or private key)
are unaffected by either profile: `scalar_multiply` itself was deliberately left unchanged, in
every build configuration. (Both still benefit from the same T-198 hardware dispatch - see
`docs/PERFORMANCE.md`.)

## Which one do I need?

A quick sizing guide by target, from `docs/DECISIONS.md` D-35's survey of typical hardware — flash
budget is what actually decides this, not a chip-family label:

| Target | Typical flash | Fits `fused` (~86 KB tables)? | Use |
|---|---|---|---|
| Desktop / server / Raspberry Pi | MBs+ | yes, trivially | **`fused`** (default) |
| ESP32 / ESP32-S3 / ESP32-C3 | 4 MB+ | yes, trivially | **`fused`** (default) |
| STM32 F1/F3/G4/F4/F7/H7 (mid-range and up) | 64 KB – 2 MB | yes | **`fused`** (default) |
| STM32 L0/F0/G0 entry-level (e.g. L011F4, F030F4) | 16–64 KB | no | **`small-tables`** |
| Arduino Mega (ATmega2560, AVR) | 256 KB flash, 8 KB SRAM | tables fit flash, but AVR copies `const` to SRAM unless placed in `PROGMEM` — not done here yet | **`small-tables`**, and even then only once `PROGMEM` placement exists (`docs/TASKS.md` Phase 4) |
| Arduino Uno (ATmega328P, AVR) | 32 KB flash, 2 KB SRAM | no — smaller than even `small-tables`'s footprint would need with room left for code | not viable yet either way (stretch goal, `docs/TASKS.md` Phase 4) |

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
`cargo test --features dstu-core/small-tables` — see `docs/DECISIONS.md` D-39 for why one test suite
covering both is sufficient rather than needing separate verification per profile.
