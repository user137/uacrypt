# Performance

Canonical home for this project's benchmark numbers, methodology, and comparisons against other
implementations. `DECISIONS.md` D-23 records *why* benchmarking exists at all and links here
rather than duplicating the numbers; update this file, not D-23, when new numbers are measured.

**Fused-vs-`small-tables` numbers live separately**, in `docs/resource-profiles.md` - that's an
internal resource-profile trade-off (`DECISIONS.md` D-35/D-38/D-39), not a cross-implementation
comparison, so it doesn't belong in this file's scope.

## Why this is tracked at all

Performance is not a footnote for these algorithms. Kalyna's own design paper states high software
performance was a co-equal requirement alongside security in Ukraine's National Public
Cryptographic Competition (`docs/papers/Kalyna.pdf`), and cipher/hash design literature generally
treats throughput as a first-class, load-bearing property, not an afterthought — see e.g. the
comparative benchmarking tradition behind eSTREAM, SHA-3, and the AES competition itself, and
`docs/papers/Speed_of_modern_stream_ciphers.pdf` in this project's own paper collection. A
misuse-resistant library that's also unusably slow just pushes people back toward an unaudited,
faster alternative — so this project tracks its own numbers deliberately, not as an afterthought.

## Methodology

- **Rust**: `cargo bench -p dstu-core --bench kalyna --bench kupyna --bench strumok` (`criterion`
  0.8, `DECISIONS.md` D-23). Release-profile, `std::hint::black_box` around every benchmarked call
  so the optimizer can't elide it.
- **C comparisons**: one-off timing harnesses (not committed to this repo — see "Reproducing"
  below), built with `gcc -O2` for a fair optimization-level comparison, run on the same machine on
  the same day. Each measures many iterations of a single encrypt/hash/keystream call (key
  schedule/init done once outside the timed loop, matching how the Rust benches and each C
  implementation's own natural API boundary work) and reports mean nanoseconds per call.
- **Not a rigorous academic benchmark suite**: no CPU pinning, no isolated core, no disabled
  frequency scaling — real numbers from a real development machine, useful for relative comparison
  and regression tracking, not for citing as an authoritative cycles-per-byte figure. Ratios between
  implementations (the "Nx faster/slower" figures below) are far more robust than any single
  absolute number, since machine load affects all of them together.

**Dev machine**: AMD Ryzen 5 PRO 4650U (6 cores / 12 threads, ~2.1 GHz base), Windows 11 Pro. All
UAPKI/Oliynykov/outspace comparison numbers below are from this machine only - those oracles
aren't built on the Raspberry Pi (see below), so it contributes no comparison columns, only this
project's own numbers.

**Raspberry Pi**: Raspberry Pi 5 Model B, Broadcom BCM2712 / ARM Cortex-A76 (4 cores, 2.4 GHz),
Debian 12 (bookworm), `aarch64-unknown-linux-gnu` - the ARM/Linux hardware rig `TASKS.md` "Testing
& hardening" tracks (`.claude.local.md` has access details). Added 2026-07-22 to check this
project's own numbers across a genuinely different CPU architecture, not just a different OS.

**Recorded**: 2026-07-22 (dev machine); 2026-07-22, later the same day (Raspberry Pi, once the rig
existed).

## Implementations compared

| | What it is | Optimization posture |
|---|---|---|
| **This project** (`dstu_core`) | Rust, `hazmat` layer | Correctness-first MVP: shared S-box/MDS tables (D-13), but no combined/merged tables, no SIMD; Strumok uses a literal 16-word shift register, not a rotating buffer (D-18) |
| **Oliynykov reference C** (`oracles/kalyna-reference`, `oracles/kupyna-reference`) | The designers' own reference implementation | Optimizes for auditability/clarity, not speed — confirmed by reading the source: `MixColumns` in `kupyna-reference/kupyna.c` computes `GF(2^8)` multiplication via an 8-iteration bit-serial loop (`MultiplyGF`), no precomputed table anywhere |
| **UAPKI** (`oracles/uapki`, `library/uapkic`) | A real, state-expertise-pedigree PKI library (D-16) | Production-optimized: combined S-box+permutation tables, no correctness/speed tradeoff made in this project's favor |
| **outspace/dstu8845** | Unofficial Strumok-only implementation (D-15) | Optimized — likely a rotating buffer instead of a full state shift, the exact tradeoff D-18 chose not to make for this project's Strumok |

Kalyna/Kupyna official test vectors matched Oliynykov's reference and Bouncy Castle already
(D-13/D-10); UAPKI's own self-test data matched this project's vectors too (D-16). These are
already-trusted oracles for correctness — this is the same set of implementations, measured for
speed instead.

## Results (historical - superseded by "Binary-level comparison" below, see D-34)

**Superseded 2026-07-22, see `DECISIONS.md` D-34**: this whole section is in-process `criterion`
numbers - useful at the time for tracking each optimization's progress commit-by-commit, but no
longer this project's cross-implementation comparison method. Kept for the historical record of
what was tried and in what order (D-27 through D-30's incremental fixes), not deleted, but **"##
Binary-level (process) comparison" further below is now the single canonical comparison** - a
built CLI run as a real process, MB/s only, every implementation, every platform measured. Do not
cite the tables in this section as a current performance claim.

### Kalyna (single-block encrypt, nanoseconds — lower is better)

**Updated 2026-07-22 after D-28** (full S-box+shift+MDS fusion for encrypt, see below) — D-27
figures kept for the record. **All figures in this table: AMD Ryzen 5 PRO 4650U (dev machine) only**
— this is a historical optimization-progress snapshot predating the Raspberry Pi rig, see the
block-only table further below for the cross-CPU comparison:

| Variant | Before D-27 | After D-27 | **After D-28** | UAPKI |
|---|---|---|---|---|
| 128-128 | 4606 | 2354 | **1041** | 222 |
| 128-256 | 6284 | 2999 | **1283** | 261 |
| 256-256 | 11412 | 5443 | **1956** | 578 |
| 256-512 | 14031 | 6645 | **2296** | 663 |
| 512-512 | 27223 | 12735 | **4006** | 879 |

**After D-28: ~3.4-4.9x slower than UAPKI (was ~10.6-14.5x)** — decrypt (not fused this pass, see
below) improved too, ~36-40%, purely from the key schedule sharing the now-fused `encipher_round`.
Oliynykov's reference C is excluded from this and the other performance tables below — it's a
correctness oracle (auditability-first, not speed-optimized, see "Implementations compared" above),
not a relevant performance baseline.

**Updated again 2026-07-22 after D-29** (`ExpandedKey` — key schedule cached across calls instead
of redone every time). **All figures in this table: AMD Ryzen 5 PRO 4650U only** (also predates the
Pi rig):

| Variant, block-only (schedule cached) | This project | UAPKI |
|---|---|---|
| 128-128 encrypt | **133 ns** | 222 ns |
| 128-128 decrypt | 433 ns | 222 ns |
| 256-256 encrypt | **268 ns** | 578 ns |
| 256-256 decrypt | 1435 ns | 578 ns |
| 512-512 encrypt | **568 ns** | 879 ns |
| 512-512 decrypt | 3934 ns | 879 ns |

**Encrypt, with the schedule cached, is now *faster* than UAPKI across every variant measured** —
the raw `encrypt` function (schedule redone every call) is still the ~3.4-4.9x-slower number above;
`ExpandedKey` is the API a caller doing more than one block under the same key should use, and is
also the API any future mode of operation (D-05) will need regardless of speed, to avoid redoing
the schedule per block. Decrypt (not fused yet at this point) was 3.2-6.9x slower than
encrypt-block-only — see D-30, resolved below.

**Updated a third time 2026-07-22 after D-30** (decrypt round fused too — equivalent-inverse-cipher
restructuring, transformed interior round keys):

| Variant, block-only (schedule cached) | This project (Ryzen 5 4650U) | This project (Pi 5 / Cortex-A76) | UAPKI (Ryzen 5 4650U) | UAPKI (Pi 5 / Cortex-A76) |
|---|---|---|---|---|
| 128-128 encrypt | 132 ns | 241 ns | 222 ns | 233 ns |
| 128-128 decrypt | **144 ns** (was 433 ns) | 266 ns | 222 ns | 233 ns |
| 256-256 encrypt | 268 ns | 521 ns | 578 ns | 348 ns |
| 256-256 decrypt | **323 ns** (was 1435 ns) | 572 ns | 578 ns | 348 ns |
| 512-512 encrypt | 573 ns | 1185 ns | 879 ns | 632 ns |
| 512-512 decrypt | **691 ns** (was 3934 ns) | 1268 ns | 879 ns | 632 ns |

**Kalyna decrypt-block-only is now faster than UAPKI across every variant measured too (on the
Ryzen dev machine - see the Pi correction just below the table)** — combined
with D-29's encrypt result, this closes essentially the entire gap to UAPKI for `ExpandedKey`, the
API any real multi-block caller (or future mode of operation) would actually use. The raw one-shot
`decrypt` function (schedule *and* the new key-transform both recomputed every call) is a more
mixed picture: slightly slower for the two smallest variants (the extra `nr-1` key-transform calls
aren't offset by round fusion at low round counts) but substantially faster for the three largest —
an honest tradeoff of the one-shot convenience path, not a regression in the path that matters.
New baseline: `kalyna-decryptfusion-2026-07-22`.

**UAPKI (Pi 5) column added 2026-07-22, after building `library/uapkic` natively on the Pi**
(same pinned commit as the Ryzen build, plain `cmake`/`gcc`, no Windows-specific workaround
needed - see D-33) **specifically so the "beats UAPKI" claim above could be checked cross-
architecture, not just asserted from one machine.** It does not hold on the Pi: **UAPKI is faster
than this project's Kalyna there, by ~1.5-1.9x** (e.g. 512-512: 632 ns vs 1185 ns) - the reverse
of the Ryzen result, where this project wins by ~1.4-1.9x. Same code, same D-28 fusion, opposite
outcome depending on CPU architecture - see D-33 for the fuller writeup and the (untested)
hypotheses for why, since chasing the actual cause is future work, not done here.

### Kupyna (digest, MB/s — higher is better)

**Updated 2026-07-22 after D-28**:

| | 64 B | 1024 B | 65536 B |
|---|---|---|---|
| Before D-27 (256, Ryzen) | 2.17 | 5.26 | 5.85 |
| After D-27 (256, Ryzen) | 5.80 | 13.30 | 14.57 |
| **After D-28** (256, Ryzen) | **39.53** | **91.72** | **98.60** |
| After D-28 (256, Raspberry Pi 5) | 19.04 | 44.00 | 48.13 |
| UAPKI (256, Ryzen) | 29.93 | 88.88 | 95.48 |
| UAPKI (256, Raspberry Pi 5) | 22.94 | 63.94 | 72.61 |
| Before D-27 (512, Ryzen) | 1.26 | 3.44 | 4.10 |
| After D-27 (512, Ryzen) | 3.54 | 8.91 | 10.57 |
| **After D-28** (512, Ryzen) | **26.89** | **69.26** | **80.99** |
| After D-28 (512, Raspberry Pi 5) | 12.29 | 31.18 | 36.92 |
| UAPKI (512, Ryzen) | 18.50 | 74.46 | 85.92 |
| UAPKI (512, Raspberry Pi 5) | 16.82 | 49.53 | 60.53 |

**After D-28: Kupyna-256 is now 1.03-1.45x *faster* than UAPKI (crossed over from ~6.7x slower);
Kupyna-512 is at rough parity (0.93-1.45x, i.e. within ~7% either side)** — the full fusion plus a
correctness/performance fix (see D-28: a runtime `%` by `nb`/`columns` was replaced with a bitmask,
since both are always powers of two but not compile-time constants) closed essentially the entire
gap, far beyond this task's original "2-3x of UAPKI" expectation. **Raspberry Pi rows added
2026-07-22** — this project's own code is ~2.0-2.2x slower than the same code on the Ryzen dev
machine (consistent with Kalyna's ratio above), but **UAPKI's own Pi numbers don't slow down by
nearly as much (~1.2-1.4x vs its Ryzen numbers)** — so on the Pi, UAPKI is actually *faster* than
this project's Kupyna (~1.2-1.6x, e.g. 65536 B/256: 72.61 vs 48.13 MB/s), reversing the "we beat
UAPKI" result that holds on Ryzen. Same flip as Kalyna's, see D-33.

### Strumok (`apply_keystream`, MB/s — higher is better)

**Updated 2026-07-22 after D-26** (ring buffer + precomputed `T0..T7` tables, see below) — figures
before that change are kept for the record, not deleted, since they're the actual measurement the
optimization was checked against:

| | 64 B | 1024 B | 65536 B |
|---|---|---|---|
| This project, before D-26 (256, Ryzen) | 29.36 | 118.67 | 144.27 |
| This project, **after D-26** (256, Ryzen) | 195.86 | 553.58 | **639.47** |
| This project, after D-26 (256, Raspberry Pi 5) | 123.02 | 332.15 | 371.88 |
| outspace (256, Ryzen) | 198.89 | 1461.07 | 2055.05 |
| UAPKI (256, Ryzen) | 132.60 | 442.73 | 588.71 |
| UAPKI (256, Raspberry Pi 5) | 75.07 | 271.63 | 333.80 |
| This project, before D-26 (512, Ryzen) | 30.31 | 115.92 | 145.61 |
| This project, **after D-26** (512, Ryzen) | 198.70 | 545.19 | **639.83** |
| This project, after D-26 (512, Raspberry Pi 5) | 123.17 | 332.12 | 371.25 |
| outspace (512, Ryzen) | 230.29 | 1443.74 | 2131.68 |
| UAPKI (512, Ryzen) | 103.28 | 511.11 | 556.20 |
| UAPKI (512, Raspberry Pi 5) | 94.98 | 278.59 | 326.71 |

**After D-26: now *faster* than UAPKI's Strumok, ~3.2x slower than outspace** (was ~4-5x slower
than UAPKI, ~13-15x slower than outspace, before). No naive/reference-grade Strumok implementation
exists to compare against for the "correctness-first" side of this story — see `ORACLES.md`, no
official DSTU 8845 reference implementation is publicly known to exist. **Raspberry Pi rows added
2026-07-22** — this project's own code is ~1.6-1.7x slower than the same code on the Ryzen dev
machine (smaller gap than Kalyna/Kupyna's ~1.8-2.2x above). **Unlike Kalyna/Kupyna, this result
does *not* flip on the Pi**: this project still beats UAPKI there too, by ~1.1-1.6x (e.g. 64 B/256:
123.02 vs 75.07 MB/s) — a smaller margin than Ryzen's ~1.1-1.9x but the same direction. See D-33
for the full cross-architecture writeup, including why Strumok behaves differently from Kalyna/
Kupyna here.

## Binary-level (process) comparison — canonical, see D-34

**This is the only methodology this project uses for cross-implementation performance
comparisons, per `DECISIONS.md` D-34** (added 2026-07-22, after a same-machine discrepancy between
the in-process and binary-level Kupyna numbers surfaced exactly why mixing methods is a problem —
see D-34): a built CLI — `uacrypt` for this project (renamed 2026-07-23 from `dstutool`, D-36 —
same binary, same numbers below, name only), an equivalent thin CLI wrapper with the same
file-based interface for each oracle — run as a real external process, on each machine measured.
**One metric only: MB/s.** No `ns`/op tables, no `wall_ns` tables — process-spawn overhead was
already confirmed negligible once amortized over `N` iterations (tens of milliseconds of one-time
startup vs. the seconds-long timed loop; not re-measured every time since it doesn't change).

Each tool takes `--iterations N` and repeats the same in-memory block/digest/keystream op `N` times
in one process invocation (`--raw-schedule`, where applicable, re-expands the key every iteration;
without it, the key schedule is expanded once before the loop, matching `ExpandedKey`/each C
library's own key-setup-once convention) — this amortizes the one-time process startup over many
operations rather than spawning a process per operation, which would measure OS process creation,
not crypto.

**Machines**: both the Ryzen 5 PRO 4650U dev machine and the Raspberry Pi 5 (see "Methodology"
above) now have `uacrypt` plus a CLI wrapper for UAPKI built; outspace's Strumok wrapper is built
on both too. Oliynykov's reference C stays excluded from these tables — a deliberate, unchanged
decision (not revisited by moving to a single method): it's a correctness oracle, not a performance
baseline (see "Implementations compared" above).

### Kalyna (`kalyna-block encrypt`/`decrypt`)

MB/s = block size / per-op time (16 bytes for 128-128, 64 bytes for 512-512) — not a
message-length-dependent rate the way Kupyna/Strumok's is, but the same unit for a consistent
table shape. **N = 20000 iterations on both machines:**

| Variant | Direction | Schedule | uacrypt (Ryzen) | UAPKI (Ryzen) | uacrypt (Pi 5) | UAPKI (Pi 5) |
|---|---|---|---|---|---|---|
| 128-128 | encrypt | cached | **125.98** | 79.60 | 44.69 | **87.43** |
| 128-128 | encrypt | raw | **15.09** | 0.92 | **6.71** | 0.32 |
| 128-128 | decrypt | cached | **114.29** | 81.63 | 40.61 | **84.21** |
| 128-128 | decrypt | raw | **10.24** | 0.91 | **5.12** | 0.32 |
| 512-512 | encrypt | cached | 115.94 | **134.45** | 54.05 | **100.00** |
| 512-512 | encrypt | raw | **16.24** | 2.79 | **12.36** | 1.14 |
| 512-512 | decrypt | cached | 95.10 | **125.49** | 49.84 | **100.63** |
| 512-512 | decrypt | raw | **13.00** | 2.84 | **10.31** | 1.14 |

Confirms D-33's in-process finding via the canonical method too: **on the Pi, UAPKI wins the
cached (schedule-cached, real-usage) case** — this project trails by roughly 1.9-2.0x there
(e.g. 512-512 encrypt: 100.00 vs 54.05) — the reverse of the Ryzen result, where this project
leads by ~1.4-1.9x. The *raw* (schedule-redone-every-call) case doesn't flip on either machine:
UAPKI's raw numbers are dramatically worse everywhere (its per-call key setup is expensive), so
this project wins raw on both platforms regardless of the cached-case reversal.

**Reproducing**: `cargo build -p uacrypt --release`, then `target/release/uacrypt kalyna-block
encrypt --variant <variant> --key <path> --in <path> --out <path> --iterations <N>
[--raw-schedule]`. The UAPKI comparison CLI is a one-off C wrapper (same file interface and flags)
built the same way as this file's other C comparisons — not committed; built fresh on each machine
against `library/uapkic`'s pinned commit (`ORACLES.md`).

### Kupyna (`kupyna-digest`)

`Kupyna256`/`Kupyna512::digest` already take an arbitrary-length message, so `kupyna-digest
--variant <256|512> --in <path> --out <path> [--iterations N]` is a complete, real feature, not a
scoped-down benchmarking scaffold. No key, so no cached-vs-raw distinction. **64 KB message, N =
2000 iterations on both machines:**

| Variant | uacrypt (Ryzen) | UAPKI (Ryzen) | uacrypt (Pi 5) | UAPKI (Pi 5) |
|---|---|---|---|---|
| Kupyna-256 | 94.14 | **104.95** | 48.18 | **71.87** |
| Kupyna-512 | 75.35 | **88.48** | 36.64 | **60.56** |

**UAPKI wins on both machines here, at the binary level** — this is the discrepancy D-34
documents: the (now-superseded) in-process table above claimed this project was 1.03-1.45x
*faster* than UAPKI on Ryzen, but the binary-level numbers here (measured the same day, same
machine) put UAPKI ahead by a similar small margin instead (~10-17%). Kept as-is, not "corrected"
to agree with the in-process figure — this is exactly the kind of cross-method disagreement D-34
exists to stop producing, and the binary-level number is the one this project now treats as
authoritative. The Pi gap is larger and in the same direction (UAPKI ahead by ~1.5-1.7x there).

**Reproducing**: same pattern as Kalyna's.

### Strumok (`strumok-crypt`)

`Strumok256`/`Strumok512::apply_keystream` already XOR an arbitrary-length buffer, so
`strumok-crypt --variant <256|512> --key <path> --iv <path> --in <path> --out <path>
[--iterations N] [--raw-schedule]` is a complete feature. `--raw-schedule` re-initializes the
cipher fresh before every iteration; the default continues one cipher's state across all
`iterations` calls instead (a real continuous stream, cheaper — no repeated init). **64 KB
message, N = 2000 iterations on both machines:**

| Variant | Schedule | uacrypt (Ryzen) | outspace (Ryzen) | UAPKI (Ryzen) | uacrypt (Pi 5) | outspace (Pi 5) | UAPKI (Pi 5) |
|---|---|---|---|---|---|---|---|
| Strumok-256 | cached | 516.32 | **1957.65** | 624.44 | 372.95 | **1164.99** | 326.66 |
| Strumok-256 | raw | 545.73 | **1975.15** | 627.41 | 367.15 | **1117.29** | 321.21 |
| Strumok-512 | cached | 534.30 | **2001.26** | 584.87 | 372.11 | **1165.81** | 327.93 |
| Strumok-512 | raw | 529.50 | **1892.23** | 608.52 | 367.04 | **1117.74** | 321.15 |

Unlike Kalyna/Kupyna, this project beats UAPKI on **both** machines here (Ryzen: ~1.1-1.9x; Pi:
~1.1-1.6x, a smaller margin but the same direction) — outspace remains fastest everywhere by a
wide margin on both platforms. Consistent with D-33's in-process finding that Strumok's advantage,
unlike Kalyna/Kupyna's, doesn't depend on which CPU architecture is running it.

**Reproducing**: same pattern as Kalyna's; the outspace/UAPKI comparison CLIs are one-off C
wrappers with the same file interface, not committed — built fresh on each machine.

## What the gap is, honestly

This project's MVP deliberately chose correctness and `no_std`/embedded-portability first
(`CLAUDE.md` MVP scope) over speed. The gap to UAPKI/outspace is real and has concrete, confirmed
causes — read directly from the other implementations' source, not guessed at (`TASKS.md` has the
sketched-not-scheduled task for closing this):

- **Kalyna/Kupyna, D-27 then D-28, both 2026-07-22**: `hazmat::tables`' shared `apply_matrix` used
  to compute every `GF(2^8)` multiplication via `gf_mul` at call time (up to 64 per column) — D-27
  switched it to a precomputed `MDS_TABLE`/`MDS_INV_TABLE` (8 lookups + 7 XORs instead), roughly
  halving the gap to UAPKI. D-27 assumed the remaining gap (UAPKI's `p_boxrowcol` combining S-box
  *and* the row/column permutation into one lookup) couldn't be closed without per-`nb` tables,
  since Kalyna's row-shift offset depends on block size — **this assumption was wrong**, corrected
  in D-28: `sub_bytes` is row-indexed and `shift_rows`/Kupyna's `shift_bytes` preserve row (only
  permute columns), so they commute, and the combined `SBOX_MDS` table doesn't depend on `nb` at
  all — only the *gather index* does, which is cheap arithmetic, not a table. D-28 fused Kalyna's
  encrypt round (and Kupyna's, which shares the table) this way, closing Kupyna's gap to UAPKI
  almost entirely and Kalyna's encrypt gap substantially. D-29 then added `ExpandedKey` (schedule
  cached once, reused across calls) — with the schedule cached, Kalyna encrypt is now *faster* than
  UAPKI for every variant measured. D-30 fused the decrypt round too, via an equivalent-inverse-
  cipher restructuring (interior round keys transformed once — `DK[j] = apply_matrix(K[j],
  MDS_INV_TABLE)` — so `inv_sub_bytes` effectively moves to the front of each interior round,
  mirroring `encipher_round`'s shape). **With that, `ExpandedKey`'s encrypt *and* decrypt are both
  faster than UAPKI across every variant measured** — the gap this section used to describe is, as
  of D-30, closed for the schedule-cached API. What remains is honest, not hidden: the *raw*
  one-shot `encrypt`/`decrypt` functions (which redo the schedule, and now decrypt's key transform
  too, on every call) are still slower than UAPKI's own one-shot calls for the reasons above — that
  gap is inherent to the one-shot API shape, not something further table fusion closes, and
  `ExpandedKey` exists specifically for callers who want the schedule-cached numbers instead.
  **Scope correction, 2026-07-22, after building UAPKI on the Raspberry Pi too (D-33) and moving to
  a single binary-level testing method (D-34)**: the "faster than UAPKI" claim above was based on
  in-process `criterion` numbers on the Ryzen dev machine, and does not hold as broadly as it
  reads. On the Pi's ARM core, UAPKI is faster than this project's Kalyna and Kupyna (reversed).
  **For Kupyna specifically, it doesn't even hold at the binary level on Ryzen** - D-34 found
  UAPKI slightly ahead there too (~10-17%) once measured as a real built-binary process instead of
  an in-process function call, a discrepancy that's exactly why this project no longer treats
  in-process numbers as the comparison of record. Strumok's "faster than UAPKI" result is the one
  that holds everywhere - both platforms, both methods. See D-33/D-34 for the numbers and D-33's
  (untested) hypotheses for why Kalyna/Kupyna's ratio is architecture-sensitive but Strumok's isn't.
- **Strumok, two distinct, additive causes — both fixed 2026-07-22, see D-26**: (1)
  `oracles/strumok-dstu8845/strumok.c`'s `next_stream()` is one fully-unrolled function that
  updates each state word in place via modular indexing — it never physically moves the 16-word
  state array. This project's `next_step` used to call `s.copy_within(1..16, 0)` once per step (a
  real 120-byte move), 16 times per 16-word output block — the literal-shift-vs-ring-buffer trade
  documented in D-18 — now replaced with a `head`-indexed ring buffer, no data movement. (2)
  Separately, outspace's `T(w)` is 8 precomputed combined tables (`T0[byte0]^...^T7[byte7]`, S-box
  + MDS folded per byte position — 8 lookups total for the whole function); this project's
  `t_function` used to do 8 S-box lookups *then* a full MDS matrix-multiply via
  `apply_matrix`/`gf_mul` (up to 64 `GF(2^8)` multiplications) as a separate step — now the same 8
  precomputed tables, transcribed from outspace directly. The remaining ~3.2x gap to outspace after
  both fixes is a smaller, unchased residual (some other implementation detail, not root-caused
  further here).
- **Neither gap is a correctness or `no_std` concern** — all of it is pure throughput, addressable later
  without touching the already-verified algorithm logic (confirmed for Strumok's fix: all existing
  tests, including the 4000-case outspace differential harness, still pass unchanged).

None of this changes any implementation's standing as a correctness oracle (`ORACLES.md`) — a
reference implementation's whole reason for existing is auditable clarity, not speed, and UAPKI's
speed doesn't make it "more correct," just faster.

## Regression baseline

A named `criterion` baseline was saved the same day these numbers were recorded:

```
cargo bench -p dstu-core --bench kalyna --bench kupyna --bench strumok -- --save-baseline initial-2026-07-22
```

To check a future change against it:

```
cargo bench -p dstu-core --bench kalyna --bench kupyna --bench strumok -- --baseline initial-2026-07-22
```

**Updated 2026-07-22, same day**: once Strumok's ring-buffer/T-table change (D-26) landed, a second
baseline was saved specifically for Strumok, so future Strumok changes are checked against the
*optimized* form rather than the old, since-fixed one:

```
cargo bench -p dstu-core --bench strumok -- --save-baseline strumok-optimized-2026-07-22
cargo bench -p dstu-core --bench strumok -- --baseline strumok-optimized-2026-07-22  # to check
```

**Updated again 2026-07-22, same day**: Kalyna/Kupyna's `MDS_TABLE` change (D-27) landed too, so a
third baseline was saved for them:

```
cargo bench -p dstu-core --bench kalyna --bench kupyna -- --save-baseline kalyna-kupyna-optimized-2026-07-22
cargo bench -p dstu-core --bench kalyna --bench kupyna -- --baseline kalyna-kupyna-optimized-2026-07-22  # to check
```

**Updated again 2026-07-22, same day**: D-28's full fusion landed, so a fourth baseline was saved:

```
cargo bench -p dstu-core --bench kalyna --bench kupyna -- --save-baseline kalyna-kupyna-fused-2026-07-22
cargo bench -p dstu-core --bench kalyna --bench kupyna -- --baseline kalyna-kupyna-fused-2026-07-22  # to check
```

**Updated a third time 2026-07-22, same day**: D-29's `ExpandedKey` added new bench functions
(`*_encrypt_block_only`/`*_decrypt_block_only` in `benches/kalyna.rs`), so a fifth baseline covers
those too (Kupyna is unaffected by D-29, no new baseline needed there):

```
cargo bench -p dstu-core --bench kalyna -- --save-baseline kalyna-expandedkey-2026-07-22
cargo bench -p dstu-core --bench kalyna -- --baseline kalyna-expandedkey-2026-07-22  # to check
```

**Updated a fourth time 2026-07-22, same day**: D-30's decrypt fusion landed, so a sixth baseline
supersedes `kalyna-expandedkey-2026-07-22` for Kalyna:

```
cargo bench -p dstu-core --bench kalyna -- --save-baseline kalyna-decryptfusion-2026-07-22
cargo bench -p dstu-core --bench kalyna -- --baseline kalyna-decryptfusion-2026-07-22  # to check
```

`initial-2026-07-22`, `kalyna-kupyna-optimized-2026-07-22`, and `kalyna-expandedkey-2026-07-22` are
now all superseded for Kalyna (by `kalyna-decryptfusion-2026-07-22`, or `kalyna-kupyna-fused-2026-
07-22` for the two benches shared with Kupyna) and Strumok is still tracked against
`strumok-optimized-2026-07-22` — kept only as historical records, not what new changes should be
checked against.

`target/criterion/` is gitignored (as usual for `target/`), so this baseline lives only on whatever
machine last ran the save command above — it is **not** a portable, cross-machine regression gate
(a laptop today vs. a CI runner tomorrow will disagree on absolute numbers regardless of any code
change). Its value is catching a *relative* regression on the same machine across commits, not
establishing a portable performance contract. Re-run the save command to refresh the baseline after
an intentional performance change.

## Reproducing the C comparisons

Not committed to this repo (one-off, and pulling in a full UAPKI build is a lot of scaffolding for
something that isn't run again regularly) — but fully reproducible:

1. **Oliynykov reference C**: build `oracles/kalyna-reference`/`oracles/kupyna-reference` directly
   (`gcc -O2 -I oracles/kalyna-reference <bench.c> oracles/kalyna-reference/{kalyna,tables}.c`),
   time `KalynaEncipher`/`KupynaHash` in a loop (context/key schedule set up once, outside the
   timed loop).
2. **UAPKI**: build `oracles/uapki/library/uapkic` via its own `CMakeLists.txt`
   (`-DUAPKI_LIBS_TYPE=STATIC -DUAPKI_DISABLE_COPY=ON`; on Windows/MinGW, the vendored
   `resource.rc` is UTF-16 and `windres` chokes on it — set `RESOURCE_RC` to empty in a working
   copy of the CMakeLists, not needed for a benchmark), then time `dstu7624_encrypt` /
   `dstu7564_init`+`update`+`final` / `dstu8845_crypt` through the public `ByteArray`-based API.
3. **outspace**: build `oracles/strumok-dstu8845` the same way as the existing
   `tests/oracle-harness/strumok-differential/` harness does, time `dstu8845_crypt` in a loop.

All timing done with `clock_gettime(CLOCK_MONOTONIC, ...)`, mean over many iterations (thousands
for small buffers, hundreds for the 64 KB case) to average out timer-resolution noise.
