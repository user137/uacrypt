# Performance

Canonical home for this project's benchmark numbers, methodology, and comparisons against other
implementations. `docs/DECISIONS.md` D-23 records *why* benchmarking exists at all and links here
rather than duplicating the numbers; update this file, not D-23, when new numbers are measured.

**Fused-vs-`small-tables` numbers live separately**, in `docs/resource-profiles.md` - that's an
internal resource-profile trade-off (`docs/DECISIONS.md` D-35/D-38/D-39), not a cross-implementation
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
  0.8, `docs/DECISIONS.md` D-23). Release-profile, `std::hint::black_box` around every benchmarked call
  so the optimizer can't elide it.
- **C comparisons**: one-off timing harnesses, built with `gcc -O2` for a fair optimization-level
  comparison, run on the same machine on the same day. Each measures many iterations of a single
  encrypt/hash/keystream call (key schedule/init done once outside the timed loop, matching how the
  Rust benches and each C implementation's own natural API boundary work) and reports mean
  nanoseconds per call. **Not committed to this repo by default** (see "Reproducing" below) — the
  rationale (a lot of scaffolding for something that isn't run again regularly) held until this
  mode/oracle pairing was actually rebuilt and rerun multiple times in one week (T-131/T-133/T-138).
  **First exception, 2026-07-26 (`docs/DECISIONS.md` D-83)**: the Kalyna-CMAC vs. UAPKI wrapper is now
  committed at `tests/oracle-harness/uapki-cmac-bench/cmac_bench.c` (source only — the DLL/import
  lib it links against are downloaded/built fresh per its own doc-comment recipe, same "vendor
  nothing prebuilt" posture `oracles/` already has). The other 8 modes' UAPKI comparisons remain
  scratch-only/rebuilt-fresh for now — promote a mode to committed the same way if it starts getting
  rebuilt repeatedly, don't do it preemptively for a mode measured once.
- **Not a rigorous academic benchmark suite**: no CPU pinning, no isolated core, no disabled
  frequency scaling — real numbers from a real development machine, useful for relative comparison
  and regression tracking, not for citing as an authoritative cycles-per-byte figure. Ratios between
  implementations (the "Nx faster/slower" figures below) are far more robust than any single
  absolute number, since machine load affects all of them together.
- **10 MiB is now a mandatory message size for every binary-level (process) comparison table**,
  not an ad hoc addition (policy made explicit 2026-07-26, user-requested) — every mode that takes a
  variable-length message must include a 10 MiB row/column going forward, in addition to whatever
  smaller sizes that mode's own table already tracks. Rationale unchanged from when this was first
  added: at 10 MiB, per-call setup cost (key schedule, process spawn already amortized via
  `--iterations`) is negligible next to the actual bulk-throughput work, so it isolates steady-state
  MB/s from initialization noise better than the smaller 64 B/1 KB/64 KB points the "Results"
  section's older tables still carry. **Exempt, and why** (matching the existing "10 MiB
  re-measurement pass" section's own list, not a new carve-out): `kalyna-block` (single block only,
  no variable-length mode exists for it), `kalyna-kw` (`MAX_R = 20` blocks, `docs/DECISIONS.md` D-55 - key
  material, not a general message), `kalyna-gmac` (measured at exactly one block by design, D-57's
  UAPKI multi-block streaming-bug workaround — an oracle limitation, not an architectural one on
  this project's own side), `kalyna-ccm` (`MAX_PLAINTEXT_LEN = 255` bytes, a real cap in this
  implementation). **CMAC is not exempt** — it authenticates an arbitrary-length message the same
  way GCM/XTS do, and already has a published 10 MiB row.
- **Byte-identity-verified UAPKI comparison is now the standard for every future binary-level
  table** (policy made explicit 2026-07-26, established by T-131/D-78's CMAC/XTS wrapper rebuild —
  a "`uacrypt`-only, no UAPKI column, wrapper not rebuilt" table is a stopgap, not an acceptable
  final state, going forward). Concretely, before publishing a new or refreshed comparison table for
  any mode: (1) build or extend a small C wrapper against the pinned official prebuilt `uapkic.dll`
  (`gendef`/`dlltool` import lib, no CMake needed — D-71/D-78's method) mirroring `uacrypt`'s own
  file-based CLI shape for that mode; (2) byte-diff the wrapper's output against the real `uacrypt`
  binary for the same key/nonce-or-tweak/input, every variant, every direction, **before trusting
  any timing** — a number from an unverified wrapper is two programs possibly doing different work
  at different speeds, not a comparison (T-133's standing check, first applied this way in D-78);
  (3) time both binaries back-to-back in the same session with nothing else CPU-heavy running (a
  contemporaneous Miri run once produced a spurious +4.9% "regression" this way — discarded, not
  published, see D-77's narrative). Tables measured before this policy (block/CCM/GCM/GMAC/KW as of
  2026-07-26) are not retroactively invalidated, but their `uacrypt`-only re-runs should be paired
  with a real UAPKI column the next time that mode's table is touched, not left permanently
  `uacrypt`-only.
- **Both directions are now standard, not just the forward one** (policy made explicit 2026-07-26,
  user-requested — a one-sided table was found to be the norm up to this point and is being
  corrected going forward): every mode's binary-level table must measure `decrypt` alongside
  `encrypt` (`kalyna-block`/`kalyna-ccm`/`kalyna-gcm`/`kalyna-xts`), `verify` alongside `compute`
  (`kalyna-cmac`/`kalyna-gmac`), and `unwrap` alongside `wrap` (`kalyna-kw`) — not just whichever
  single direction happened to be measured first. **Exempt, and why**: Strumok's `apply_keystream`
  is its own inverse (XOR-based, encrypt and decrypt are the literal same operation) — measuring a
  second "direction" would just be re-measuring the same function, not new information. Kupyna has
  no inverse direction to measure (a hash has no decrypt).

**Dev machine**: AMD Ryzen 5 PRO 4650U (6 cores / 12 threads, ~2.1 GHz base), Windows 11 Pro. All
UAPKI/Oliynykov/outspace comparison numbers below are from this machine only - those oracles
aren't built on the Raspberry Pi (see below), so it contributes no comparison columns, only this
project's own numbers.

**Raspberry Pi**: Raspberry Pi 5 Model B, Broadcom BCM2712 / ARM Cortex-A76 (4 cores, 2.4 GHz),
Debian 12 (bookworm), `aarch64-unknown-linux-gnu` - the ARM/Linux hardware rig `docs/TASKS.md` "Testing
& hardening" tracks (`.claude.local.md` has access details). Added 2026-07-22 to check this
project's own numbers across a genuinely different CPU architecture, not just a different OS.

**Recorded**: 2026-07-22 (dev machine); 2026-07-22, later the same day (Raspberry Pi, once the rig
existed).

## Implementations compared

| | What it is | Optimization posture |
|---|---|---|
| **This project** (`dstu_core`) | Rust, `hazmat` layer | Correctness-first MVP: shared S-box/MDS tables (D-13), but no combined/merged tables, no SIMD; Strumok's original literal 16-word shift register (D-18) was replaced by a ring buffer 2026-07-22 (D-26), and `apply_keystream` gained a batched/fixed-index 128-byte bulk path 2026-07-27 (T-135, D-86) — this table's "Strumok uses a literal shift register" framing is stale and superseded, kept only as the historical record of D-18's original tradeoff |
| **Oliynykov reference C** (`oracles/kalyna-reference`, `oracles/kupyna-reference`) | The designers' own reference implementation | Optimizes for auditability/clarity, not speed — confirmed by reading the source: `MixColumns` in `kupyna-reference/kupyna.c` computes `GF(2^8)` multiplication via an 8-iteration bit-serial loop (`MultiplyGF`), no precomputed table anywhere |
| **UAPKI** (`oracles/uapki`, `library/uapkic`) | A real, state-expertise-pedigree PKI library (D-16) | Production-optimized: combined S-box+permutation tables, no correctness/speed tradeoff made in this project's favor |
| **outspace/dstu8845** | Unofficial Strumok-only implementation (D-15) | Optimized — a rotating buffer plus a batched, fixed-index 128-byte bulk path (`next_stream_full_crypt`); this project matched both (D-26, then T-135/D-86), closing most of the former gap |

Kalyna/Kupyna official test vectors matched Oliynykov's reference and Bouncy Castle already
(D-13/D-10); UAPKI's own self-test data matched this project's vectors too (D-16). These are
already-trusted oracles for correctness — this is the same set of implementations, measured for
speed instead.

## Results (historical - superseded by "Binary-level comparison" below, see D-34)

**Superseded 2026-07-22, see `docs/DECISIONS.md` D-34**: this whole section is in-process `criterion`
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
than UAPKI, ~13-15x slower than outspace, before). **The "~3.2x slower than outspace" figure is
superseded 2026-07-27 by T-135's batched/fixed-index rewrite (`docs/DECISIONS.md` D-86) — the binary-
level gap is now ~1.19-1.25x, see the `strumok-crypt` section's "Updated 2026-07-27" block below.
This table's own in-process 64 B/1024 B/65536 B numbers above were not re-measured this pass, kept
here as the D-26-era historical record.** No naive/reference-grade Strumok implementation
exists to compare against for the "correctness-first" side of this story — see `docs/ORACLES.md`, no
official DSTU 8845 reference implementation is publicly known to exist. **Raspberry Pi rows added
2026-07-22** — this project's own code is ~1.6-1.7x slower than the same code on the Ryzen dev
machine (smaller gap than Kalyna/Kupyna's ~1.8-2.2x above). **Unlike Kalyna/Kupyna, this result
does *not* flip on the Pi**: this project still beats UAPKI there too, by ~1.1-1.6x (e.g. 64 B/256:
123.02 vs 75.07 MB/s) — a smaller margin than Ryzen's ~1.1-1.9x but the same direction. See D-33
for the full cross-architecture writeup, including why Strumok behaves differently from Kalyna/
Kupyna here.

## Binary-level (process) comparison — canonical, see D-34

**This is the only methodology this project uses for cross-implementation performance
comparisons, per `docs/DECISIONS.md` D-34** (added 2026-07-22, after a same-machine discrepancy between
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
against `library/uapkic`'s pinned commit (`docs/ORACLES.md`).

**Updated 2026-07-26 (`docs/TASKS.md` T-121, `docs/DECISIONS.md` D-71)**: expanded to all 5 variants (was 2),
Ryzen dev machine only this pass — the Pi rig was out of scope. `N = 20000`. **UAPKI wrapper built
against the official prebuilt `uapkic-v2.0.12` Windows DLL** (`gendef`/`dlltool` import lib, no
CMake — see D-71) instead of a from-source build; cross-checked byte-identical against the real
`uacrypt` release binary before timing. UAPKI's *raw* (schedule-redone-per-call) numbers were not
re-measured for the 3 newly-added variants this pass — only cached-schedule, all 5:

| Variant | Direction | uacrypt cached (MB/s) | UAPKI cached (MB/s) | uacrypt raw (MB/s) |
|---|---|---|---|---|
| 128-128 | encrypt | **108.11** | 86.86 | 14.65 |
| 128-256 | encrypt | 78.05 | **78.20** | 12.05 |
| 256-256 | encrypt | **124.51** | 121.12 | 16.53 |
| 256-512 | encrypt | 97.26 | **107.20** | 14.05 |
| 512-512 | encrypt | 112.48 | **117.26** | 15.94 |

Roughly at parity across all 5 variants at the cached-schedule level (within ~1-10% either way,
narrower than the 2026-07-22 table's ~1.4-1.9x Kalyna lead) — a real, measured difference from the
original 2-variant table, not just more data points: 128-256/256-512/512-512 now show UAPKI
slightly ahead rather than this project leading everywhere. Not root-caused further this session.

**Updated 2026-07-26, `uacrypt`-only re-run after T-128** (const-generic round functions — no UAPKI
column, wrapper not rebuilt this session, T-131), cached schedule, both directions, N = 20000:

| Variant | uacrypt encrypt (MB/s) | uacrypt decrypt (MB/s) | vs. pre-T-128 encrypt row |
|---|---|---|---|
| 128-128 | **219.18** | 192.77 | +102.7% (was 108.11) |
| 128-256 | **160.00** | 142.86 | +105.0% (was 78.05) |
| 256-256 | **146.12** | 164.10 | +17.4% (was 124.51) |
| 256-512 | **113.88** | 125.49 | +17.1% (was 97.26) |
| 512-512 | **139.13** | 102.73 | +23.7% (was 112.48) |

Same `nb=2`-vs-`nb=4`/`nb=8` split T-128's own isolated criterion measurement predicted (~100%+
gain at `nb=2`, ~17-24% at `nb=4`/`nb=8`) — this CLI-level number (includes process/loop overhead
`criterion` doesn't) still tracks the mechanism cleanly.

**UAPKI column rebuilt same day (T-131/D-78 extension, `docs/DECISIONS.md` D-80)** — byte-for-byte
confirmed against the real `uacrypt` binary (both directions, all 5 variants) before timing;
`dstu7624_init_ecb`'s cost is excluded from the timed window here (same convention as GCM/KW/XTS
below, not the GMAC bug described above — this mode was written correctly from the start):

| Variant | uacrypt encrypt (MB/s) | UAPKI encrypt (MB/s) | uacrypt decrypt (MB/s) | UAPKI decrypt (MB/s) |
|---|---|---|---|---|
| 128-128 | **219.18** | 74.07 | **177.78** | 68.67 |
| 128-256 | **158.42** | 55.75 | **137.93** | 60.38 |
| 256-256 | **146.79** | 113.07 | **165.80** | 102.89 |
| 256-512 | **111.50** | 91.69 | **131.15** | 89.64 |
| 512-512 | **137.63** | 107.02 | 97.41 | **121.44** |

uacrypt leads on 9 of 10 cells (encrypt: every variant; decrypt: 4 of 5) — 512-512 decrypt is the
one cell where UAPKI now leads, consistent with the encrypt/decrypt asymmetry described below (this
run's own decrypt numbers differ from the encrypt-only table just above by ~5-8% run-to-run, normal
noise for this benchmark, not a regression). **Encrypt/decrypt asymmetry, same pattern
XTS shows above**: 256-256/256-512 decrypt now runs *faster* than encrypt, while 128-128/128-256/
512-512 keep encrypt ahead — `encipher_round_n`/`fused_inv_round_n` are different code paths
(T-128/D-77), so the two directions were never guaranteed to move by the same amount.

**`cppcrypto` 0.20 column added 2026-08-03** (`docs/DECISIONS.md` D-154, `docs/ORACLES.md` — an
oracle candidate, independence not established/not refuted). No CLI of its own matching this
convention (its `cryptor` tool is hardcoded to Serpent-256), so measured via a small harness calling
its library API directly, matching this table's own conventions exactly: key schedule (`init`)
excluded from the timed window, cached-schedule, N=20000. `uacrypt`'s own numbers re-measured fresh
in the same session (`cargo build -p uacrypt --release` reported no recompilation needed — already
current) rather than reused from the table above:

| Variant | uacrypt encrypt (MB/s) | cppcrypto encrypt (MB/s) | uacrypt decrypt (MB/s) | cppcrypto decrypt (MB/s) |
|---|---|---|---|---|
| 128-128 | 206.20 | **340.33** | 179.52 | **264.89** |
| 128-256 | 146.72 | **247.81** | 132.69 | **201.44** |
| 256-256 | 137.47 | **242.06** | 158.95 | **210.40** |
| 256-512 | 107.84 | **190.25** | 124.56 | **169.07** |
| 512-512 | 133.26 | **175.58** | 99.24 | **164.59** |

**cppcrypto wins all 10 cells**, by roughly 1.3-1.9x — unlike the UAPKI columns above, where the
Ryzen result usually favors `uacrypt`. Correctness confirmed first (`docs/DECISIONS.md` D-154): all
10 official `Kalyna.pdf` vectors matched byte-for-byte before any timing was trusted, per this
project's own standing practice. Not re-measured on the Raspberry Pi — `cppcrypto`'s upstream build
needs `yasm` (x86/x64-only, no ARM target) for the rest of the library even though Kalyna/Kupyna
themselves don't need it, and D-33 already shows a single-platform Kalyna number is not a general
claim, so this gap is stated rather than assumed either way.

### Kalyna-CCM (`kalyna-ccm encrypt`)

No binary-level table existed for CCM before this session — `kalyna-ccm` had no `--iterations` flag
at all until T-121 added one (D-71). **64 B message, N = 5000, all 5 variants, Ryzen only:**

| Variant | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|
| 128-128 | **29.77** | 2.48 |
| 128-256 | **21.18** | 3.27 |
| 256-256 | **27.73** | 3.16 |
| 256-512 | **19.49** | 2.39 |
| 512-512 | **15.04** | 1.94 |

**This project wins by a wide margin (~7-12x) on every variant** — the opposite pattern from
Kalyna-block/GCM above. Cause found by reading UAPKI's own source, not guessed: `hazmat::kalyna_ccm`
works entirely on fixed-size stack arrays (no heap allocation, by design — see its module doc
comment's no-alloc precedent), while UAPKI's `dstu7624_encrypt_ccm`/`ccm_padd` allocate multiple
`ByteArray`s per call (`CALLOC_CHECKED`/`ba_alloc_from_uint8` for the auth-data buffer, the
plaintext-length buffer, the CTR output, the join) — for a 64-byte message the allocation overhead
dominates the actual block-cipher work. **Not a byte-for-byte cross-tool-verified number** (D-71):
UAPKI's CCM `cipher_data` output bundles an extra CTR-encrypted tag block into the ciphertext rather
than returning tag separately (a different wire convention, not a bug), so this timing is
UAPKI-self-consistent (its own encrypt round-trips through its own decrypt) rather than compared
against our exact output shape the way the other modes below are.

**Reproducing**: `target/release/uacrypt kalyna-ccm encrypt --variant <v> --key <path> --nonce
<path> --in <path> --out <path> --tag <path> --iterations <N>`.

**Updated 2026-07-26, re-run after T-128**, 64 B, N = 5000, both directions:

| Variant | uacrypt encrypt (MB/s) | uacrypt decrypt (MB/s) | vs. pre-T-128 encrypt row |
|---|---|---|---|
| 128-128 | **50.24** | 49.57 | +68.8% (was 29.77) |
| 128-256 | **40.18** | 39.29 | +89.7% (was 21.18) |
| 256-256 | **32.87** | 32.24 | +18.6% (was 27.73) |
| 256-512 | **23.33** | 22.21 | +19.7% (was 19.49) |
| 512-512 | **18.70** | 16.98 | +24.3% (was 15.04) |

Same `nb=2`/`nb=4`/`nb=8` gain split as Kalyna-block above — CCM is a CTR-mode pass plus a CBC-MAC
over the same block cipher, so it inherits T-128's round-function speedup directly. Encrypt/decrypt
symmetric within normal noise (unlike XTS/block above), consistent with CCM's decrypt path being
essentially the same CTR+MAC work run in the same order.

**UAPKI column added same day (T-131/D-78 extension, `docs/DECISIONS.md` D-80) — still not byte-for-byte
comparable, same documented reason as before, now confirmed by reading the C source directly rather
than inferred**: `dstu7624_encrypt_ccm` (`dstu7624.c:2792`) returns `cipher_data` as
ciphertext-with-a-trailing-CTR-encrypted-checksum-suffix, but `dstu7624_decrypt_ccm` never actually
verifies against that suffix — it recomputes the checksum from the decrypted plaintext (`ccm_padd`)
and compares against a separately-supplied `h_ba` value instead, silently discarding the suffix it
just decrypted. There is no single "tag" file in UAPKI's own convention equivalent to `uacrypt`'s
separate ciphertext+tag files, so this wrapper preserves UAPKI's own two-value convention
(`--out` = full `cipher_data` blob, `--tag` = the real `h_ba` verification value) rather than forcing
a comparison that isn't meaningful. Timed self-consistently (UAPKI encrypts, UAPKI decrypts its own
output, round-trips confirmed), both directions, same 64 B scale:

| Variant | UAPKI encrypt (MB/s) | UAPKI decrypt (MB/s) |
|---|---|---|
| 128-128 | 2.71 | 3.50 |
| 128-256 | 3.28 | 3.31 |
| 256-256 | 3.17 | 2.30 |
| 256-512 | 2.48 | 2.46 |
| 512-512 | 2.24 | 2.40 |

Still the same ~7-20x uacrypt lead the earlier no-UAPKI-column table implied by comparison to the
historical pre-T-128 UAPKI row (2.48-3.27 MB/s) — this project's own per-call allocation-free design
(no heap allocation in `hazmat::kalyna_ccm`, by construction) remains the dominant reason, not
affected by the GMAC-class setup-timing bug found and fixed elsewhere this session (CCM's wrapper
was written fresh this turn with the timer already placed after `init_ccm`, matching block/GCM/KW).

### Kalyna-GCM (`kalyna-gcm encrypt`)

New command this session (T-121, D-71) — no message-length cap, unlike CCM. **All 5 variants, 64 B
and 1 MiB, Ryzen only:**

| Variant | uacrypt 64 B (MB/s) | UAPKI 64 B (MB/s) | uacrypt 1 MiB (MB/s) | UAPKI 1 MiB (MB/s) |
|---|---|---|---|---|
| 128-128 | 15.86 | **11.59**\* | 10.49 | **12.48** |
| 128-256 | 14.63 | **11.39**\* | 10.08 | **12.46** |
| 256-256 | 10.99 | **14.67** | 8.33 | **18.12** |
| 256-512 | 10.28 | **14.17** | 8.17 | **17.48** |
| 512-512 | **6.07** | 4.19 | **5.41** | 4.70 |

\* uacrypt wins the 64 B case for 128-128/128-256 specifically (15.86/14.63 vs. 11.59/11.39) despite
losing every other cell in this table — small-message overhead shape differs between the two
implementations, not investigated further. **UAPKI wins the 1 MiB case on 3 of 5 variants**,
sometimes by a wide margin (256-256: 18.12 vs. 8.33, ~2.2x) — the reverse of CCM's result above,
consistent with GCM/GHASH-style field-multiplication throughput being a different bottleneck than
CCM's per-call allocation cost. Byte-for-byte cross-checked against the real `uacrypt` binary before
timing (unlike CCM, GCM's wire format matches: same-length ciphertext, tag returned separately).

**Root-caused and fixed 2026-07-26, `docs/TASKS.md` T-125, `docs/DECISIONS.md` D-76**: an isolated timing
diagnostic (`hazmat::gf2m_wide`'s `field_axiom_tests::isolated_timing_*`, comparing
`Gf2m*::multiply` in isolation against a single `ExpandedKey::encrypt_block`) measured the field
multiply at **89.6% (m=128), 91.8% (m=256), and 94.3% (m=512) of GCM's total per-block cost** —
confirming, with a number instead of an inference, that `poly_mul_wide`'s O(m²) bit-serial multiply
was the actual bottleneck, not the block cipher (this *is* the profiling T-125 originally called
for, not a guess). Fixed by replacing `poly_mul_wide` with a 4-bit-window comb method (precompute
`T[i] = a*i` for all 16 nibble values, walk the other operand's nibbles most-significant-first) —
`m/4` accumulator iterations instead of `m`, verified against every existing GCM/GMAC/XTS official
vector and the field-axiom property tests (no new correctness test needed — a multiply
implementation swap is exactly what those already check). Measured ~1.8-2.3x faster on the multiply
itself (narrower than a pure iteration-count argument predicts; not chased further). **Re-measured,
same 64 B/1 MiB scale:**

| Variant | uacrypt 64 B (MB/s) | UAPKI 64 B (MB/s) | uacrypt 1 MiB (MB/s) | UAPKI 1 MiB (MB/s) |
|---|---|---|---|---|
| 128-128 | **18.48** | 11.60 | **18.20** | 12.67 |
| 128-256 | **15.79** | 11.39 | **16.99** | 12.63 |
| 256-256 | **16.19** | 14.61 | 16.60 | **18.10** |
| 256-512 | **14.84** | 13.53 | 15.99 | **17.71** |
| 512-512 | **10.21** | 4.27 | **12.60** | 4.75 |

**This project's own GCM throughput improved ~1.7-2.3x across every variant** (e.g. 512-512 at
1 MiB: 5.41 → 12.60 MB/s), UAPKI's numbers unchanged as expected. **T-125's original finding — the
256-256/256-512 variants losing by >2x at 1 MiB — is resolved**: the gap narrowed from ~2.14-2.18x
to **~1.09-1.11x**, safely under the 2x line that flagged it in the first place; 128-128/128-256
flip from trailing to *leading* (~1.35-1.44x), and 512-512's lead widens further (~2.65x, up from
~1.15x). Kalyna-GMAC (same field arithmetic, one multiply per block) improved by the same
mechanism — re-measured at the existing 1-block scale, this project's own throughput roughly
doubled on every variant (e.g. 512-512: 4.76 → 12.91 MB/s), widening an already-large lead further.

**Reproducing**: `target/release/uacrypt kalyna-gcm encrypt --variant <v> --key <path> --nonce
<path> --in <path> --out <path> --tag <path> --iterations <N>`.

**Updated 2026-07-26, 10 MiB, N = 50** (T-128's const-generic round-function fix,
not a new GCM-specific change — GCM's own field multiply still dominates per-block cost, so the
improvement here is smaller than T-128's own block-only numbers); do not compare these numbers
directly against the 1 MiB table above's UAPKI column (different message size).

| Variant | uacrypt encrypt (MB/s) | uacrypt decrypt (MB/s) |
|---|---|---|
| 128-128 | 19.85 | 19.85 |
| 128-256 | 19.47 | 19.45 |
| 256-256 | 17.09 | 17.09 |
| 256-512 | 16.59 | 16.60 |
| 512-512 | 12.84 | 12.84 |

**UAPKI column rebuilt same day (T-131/D-78 extension, `docs/DECISIONS.md` D-80)** — byte-for-byte
confirmed against `uacrypt` (both directions, all variants), same 10 MiB scale, before timing:

| Variant | uacrypt encrypt (MB/s) | UAPKI encrypt (MB/s) | uacrypt decrypt (MB/s) | UAPKI decrypt (MB/s) |
|---|---|---|---|---|
| 128-128 | **19.93** | 12.90 | **19.95** | 12.90 |
| 128-256 | **19.27** | 12.74 | **19.58** | 12.75 |
| 256-256 | 17.17 | **18.21** | 17.17 | **18.32** |
| 256-512 | 16.66 | **17.63** | 16.67 | 15.84 |
| 512-512 | **12.90** | 4.74 | **12.90** | 4.76 |

Mixed, same pattern the 1 MiB table already showed: uacrypt leads 128-128/128-256/512-512, UAPKI
leads 256-256/256-512 (barely, and only on encrypt for 256-512 — its own decrypt number dips below
uacrypt there, within the kind of run-to-run variance already seen elsewhere in this file). Encrypt
and decrypt are symmetric on both implementations here (unlike XTS/block/KW), consistent with GCM's
cost being field-multiply-dominated rather than round-function-direction-dependent.

Encrypt/decrypt symmetric within measurement noise (<0.1% apart on every variant), exactly as
expected — Kalyna-GCM's decrypt path is CTR-mode decryption plus the same GHASH-style tag
computation as encrypt, doing the same amount of work either direction.

Consistent with (slightly above) the post-T-125 1 MiB row above on every variant, as expected — GCM
was already steady-state at 1 MiB, and T-128 only speeds up the ~6-10% of per-block cost that isn't
the field multiply.

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

**Updated 2026-07-26 (T-121/D-71)**: added a 1 MiB data point alongside the existing 64 KB one,
Ryzen only, same `N = 2000`/`N = 100` split as the Kupyna/Strumok convention below:

| Variant | Size | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|---|
| Kupyna-256 | 1 MiB | 99.35 | **136.39** |
| Kupyna-512 | 1 MiB | 81.68 | **118.19** |

Same direction as the existing 64 B/1 KB/64 KB rows (UAPKI ahead throughout), margin widens slightly
at 1 MiB (~1.37x/1.45x vs. ~1.05-1.12x at 65536 B) rather than converging — UAPKI's lead grows
somewhat with message size here, not shrinks.

**Updated 2026-07-27 (T-134, `docs/DECISIONS.md` D-85)**: `sub_shift_mix`/`compress` became const-generic
over `COLUMNS`, so all three rows above are superseded. Fresh Ryzen-only wrapper (`kupyna_bench.c`,
scratch-only per this section's methodology, same `dstu7564_init`/`update`/`final` calls repeated
*inside* the timed loop every iteration - matching `uacrypt`'s own `bench_in_memory!` macro, which
constructs a fresh `Kupyna*Hasher` every iteration too, so there is no schedule/setup cost to
exclude here the way Kalyna's key expansion needs excluding). Byte-identity verified against
`uacrypt kupyna-digest` at `--iterations 1` before trusting any timing, both variants:

| Variant | Size | uacrypt (MB/s) | UAPKI (MB/s) | vs. this table's own pre-T-134 row |
|---|---|---|---|---|
| Kupyna-256 | 64 KB | **137.92** | 126.87 | uacrypt +46.5% (was 94.14); UAPKI ahead by 1.17x pre-T-134, uacrypt now ahead by 1.09x |
| Kupyna-512 | 64 KB | 97.18 | **116.73** | uacrypt +29.0% (was 75.35); UAPKI still ahead, margin narrows to 1.20x (was 1.17x) |
| Kupyna-256 | 1 MiB | **139.35** | 137.61 | uacrypt +40.3% (was 99.35); UAPKI's 1.37x lead is gone, roughly at parity (1.01x) |
| Kupyna-512 | 1 MiB | 98.73 | **117.39** | uacrypt +20.9% (was 81.68); UAPKI still ahead, margin narrows to 1.19x (was 1.45x) |
| Kupyna-256 | 10 MiB | 139.52 | **149.66** | uacrypt +41.7% (was 98.44); UAPKI still ahead, margin narrows to 1.07x (was ~1.45x) |
| Kupyna-512 | 10 MiB | 98.65 | **117.77** | uacrypt +21.4% (was 81.29); UAPKI still ahead, margin holds at ~1.19x (was ~1.45x) |

`uacrypt`'s own throughput gain (+41-47% for Kupyna-256, +21-29% for Kupyna-512, consistent across
all three sizes) cross-validates the `criterion` numbers in the "Regression baseline" section below
(-29 to -31% time / -17 to -19% time respectively) via an independent measurement method, per D-34's
own reasoning for keeping the two separate. **Kupyna-256 has closed essentially all of UAPKI's
former lead** (from ~1.1-1.5x down to ~1.0-1.1x, briefly ahead at 64 KB) - consistent with T-134's
own prediction that Kupyna-256 (half-width, 8 of 16 columns) had the larger fix to gain from.
**Kupyna-512's gap to UAPKI narrows but doesn't close** (still ~1.19-1.20x UAPKI-ahead at every
size) - also as predicted, since Kupyna-512 was already full-width and only gained from bounds-check
elimination/loop unrolling, not buffer-reuse. UAPKI's own absolute numbers moved somewhat between
sessions too (e.g. 88.48→116.73 MB/s for Kupyna-512/64 KB) - ordinary run-to-run machine variance,
not a UAPKI code change (UAPKI was not rebuilt or modified between measurements).

**`cppcrypto` 0.20 column added 2026-08-03** (`docs/DECISIONS.md` D-154, `docs/ORACLES.md`), same
harness/convention as its Kalyna column above — fresh `init()`/`update()`/`final()` called *inside*
the timed loop every iteration (D-80, matching `uacrypt`'s own `bench_in_memory!`), 64 KB/1 MiB/
10 MiB, `uacrypt`'s own numbers re-measured fresh the same session:

| Variant | Size | uacrypt (MB/s) | cppcrypto (MB/s) |
|---|---|---|---|
| Kupyna-256 | 64 KB | 138.94 | **147.10** |
| Kupyna-512 | 64 KB | 98.97 | **107.09** |
| Kupyna-256 | 1 MiB | 139.44 | **147.82** |
| Kupyna-512 | 1 MiB | 98.88 | **105.00** |
| Kupyna-256 | 10 MiB | 138.20 | **144.27** |
| Kupyna-512 | 10 MiB | 97.58 | **105.33** |

**cppcrypto leads at every size, but only by ~5-9%** — near parity, a much smaller gap than its
Kalyna column's ~1.3-1.9x lead above. Not root-caused further (no profiling done to isolate why
cppcrypto's Kalyna specifically pulls further ahead than its Kupyna does) - a possible future task.
Correctness confirmed first: all 10 byte-aligned official `Kupyna.pdf` vectors matched byte-for-byte
before any timing was trusted. Not re-measured on the Raspberry Pi, same `yasm`/D-33 caveat as the
Kalyna column above.

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

**Updated 2026-07-26 (T-121/D-71)**: added a 1 MiB data point, Ryzen only, uacrypt-vs-UAPKI only
(outspace not re-measured this pass):

| Variant | Size | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|---|
| Strumok-256 | 1 MiB | **656.82** | 722.66 |
| Strumok-512 | 1 MiB | **655.35** | 723.75 |

Reverses at 1 MiB specifically: UAPKI edges ahead here (~1.10x both variants), unlike every smaller
size in the existing 64 B/1 KB/64 KB table above where this project wins. A real crossover, not
noise — worth re-checking at intermediate sizes (e.g. 256 KB) in a future pass to see where exactly
it flips, not done here.

**Updated 2026-07-27 (`docs/TASKS.md` T-135, `docs/DECISIONS.md` D-86)**: `apply_keystream`'s batched/
fixed-index bulk path re-measured against outspace directly at 10 MiB, `--iterations 50` (this
project's established 10 MiB convention, matching the 10 MiB re-measurement pass below). Timer
placement mirrors `uacrypt strumok-crypt`'s own cached-schedule convention exactly (one-time
`dstu8845_init` inside the timed window, amortized over iterations), so the two numbers are
directly comparable. Two runs each, Ryzen only (outspace wrapper is scratch-only per the
"Reproducing" note above, not re-run on the Pi this pass):

| Variant | uacrypt (MB/s) | outspace (MB/s) | Gap |
|---|---|---|---|
| Strumok-256 | ~1823-1919 | ~2270-2329 | **~1.19-1.25x** (was ~3.2-3.9x pre-T-135) |
| Strumok-512 | ~1869-1877 | ~2270-2278 | **~1.21-1.22x** |

`uacrypt`'s own throughput at this message size roughly tripled (was 648.67/636.16 MB/s at the last
10 MiB measurement, T-128's pass below) — the gap to outspace closes from ~3.2-3.9x down to
roughly 1.2x, though it does not fully close (D-86 has the reasoning: the FSM's serial dependency
chain is unchanged and inherently sequential, so some scheduling-level edge for outspace's
hand-unrolled C likely remains). Correctness cross-checked independently the same session: the
existing 4000-case `tests/oracle-harness/strumok-differential/diff_against_outspace.c` harness,
re-run against the rewritten implementation, reported 0 mismatches.

**Full three-way re-measurement, 2026-07-27, same day, on request** (uacrypt/outspace/UAPKI
together, both message sizes this table already tracks — UAPKI added to the 10 MiB point for the
first time, closing the gap the earlier T-128-era pass left with only a `uacrypt`-vs-UAPKI column).
Same three binaries as above and as the original 64 B/1 KB/64 KB table at the top of this section;
`--iterations 2000` at 64 KB (this table's own established convention), `--iterations 50` at
10 MiB (the project-wide 10 MiB convention). All cached-schedule, Ryzen only:

| Variant | Size | uacrypt (MB/s) | outspace (MB/s) | UAPKI (MB/s) |
|---|---|---|---|---|
| Strumok-256 | 64 KB | **1958.35** | 2372.64 | 708.67 |
| Strumok-512 | 64 KB | **1870.64** | 2310.24 | 699.94 |
| Strumok-256 | 10 MiB | **~1870** (avg of the two runs above) | ~2300 (avg) | 628.95 |
| Strumok-512 | 10 MiB | **~1873** (avg) | ~2274 (avg) | 554.97 |

**`uacrypt` now clearly beats UAPKI at both sizes** (~2.6-2.8x at 64 KB, ~2.9-3.4x at 10 MiB) — a
reversal from every earlier UAPKI comparison in this section (64 B/1 KB/64 KB: ~1.1-1.9x; the
1 MiB point: UAPKI briefly ahead ~1.10x). The gap to outspace narrows from ~1.2-1.3x at 64 KB to
much the same at 10 MiB — consistent, not size-dependent, unlike the old byte-at-a-time
implementation's behavior. Not re-run on the Pi 5 this pass (all three wrappers here are
scratch-only, not committed, per this section's own "Reproducing" note).

New command this session (T-121, D-71) — MAC-only, no encryption, fixed 16-byte tag regardless of
variant. **All 5 variants, 64 B and 1 MiB, Ryzen only:**

| Variant | uacrypt 64 B (MB/s) | UAPKI 64 B (MB/s) | uacrypt 1 MiB (MB/s) | UAPKI 1 MiB (MB/s) |
|---|---|---|---|---|
| 128-128 | **29.92** | 3.69 | 106.85 | **235.47** |
| 128-256 | **23.65** | 3.51 | 77.19 | **182.48** |
| 256-256 | **21.66** | 3.37 | 123.36 | **265.00** |
| 256-512 | **18.14** | 3.02 | 97.26 | **215.42** |
| 512-512 | **11.84** | 2.75 | 111.03 | **156.35** |

**Sharp crossover by message size, on every variant**: this project wins small messages by a wide
margin (~6-8x at 64 B — same per-call-overhead cause as CCM above, `hazmat::kalyna_cmac` has no
allocation, UAPKI's `dstu7624_init_cmac`/`update_mac`/`final_mac` path does), but UAPKI wins large
messages by ~1.4-2.2x at 1 MiB — the inverse of the small-message picture. Consistent with a fixed
per-call setup cost dominating small inputs and raw per-byte throughput dominating large ones,
though the exact per-byte cause (table layout, compiler codegen, etc.) isn't isolated further here.

**Reproducing**: `target/release/uacrypt kalyna-cmac compute --variant <v> --key <path> --in <path>
--out <path> --iterations <N>`.

**Updated 2026-07-26, 10 MiB, N = 50** (T-128's const-generic round-function fix —
CMAC is pure block-cipher chaining with no other bottleneck diluting it, unlike GCM's field
multiply, so this is the mode where T-128's gain should show most directly).

**UAPKI column added same day (`docs/TASKS.md` T-131, `docs/DECISIONS.md` D-78)**: a small C wrapper
(scratch-only, not committed) calling UAPKI's prebuilt `uapkic.dll` v2.0.12 directly, matching this
project's own `uacrypt` file-based CLI shape. Byte-for-byte cross-checked against the real
`uacrypt` binary before trusting any timing (same key/message, all 5 variants, both compute and
verify) — every pair matched exactly, so both columns below measure the identical CMAC
construction, not two different behaviors.

| Variant | uacrypt compute (MB/s) | UAPKI compute (MB/s) | uacrypt verify (MB/s) | UAPKI verify (MB/s) |
|---|---|---|---|---|
| 128-128 | 199.82 | **235.86** | 198.86 | **236.21** |
| 128-256 | 147.41 | **182.88** | 147.51 | **182.66** |
| 256-256 | 142.44 | **263.40** | 142.30 | **265.15** |
| 256-512 | 111.54 | **214.74** | 111.66 | **214.17** |
| 512-512 | 137.14 | **150.83** | 137.12 | **151.06** |

**UAPKI still wins CMAC at this message size, by ~1.1-1.9x depending on variant** — T-128 closed
most of CMAC's gap (compare against the 1 MiB table above, where UAPKI led by ~1.4-2.2x) but not
all of it. Originally attributed to T-129's byte-wise-gather-vs-word-wide-`BT_xor*` difference as
the residual class of cost T-128 didn't touch — **T-129 was investigated 2026-07-27 and closed
without a code change** (`docs/DECISIONS.md` D-88): a measured spike showed the gather is already
near-optimal at small block sizes and a real regression to "fix" at larger ones, so this residual
gap's actual cause is still open, not a known-fixable byte-vs-word difference as originally framed.
Compute/verify symmetric within noise on both implementations, as expected.

Real, substantial improvement over the 1 MiB row above on every variant (e.g. 512-512: 111.03 →
137.16, ~+23.5%, roughly matching T-128's own `nb=8` block-only gain). **128-128's own jump (106.85
→ 199.08, ~+86%) is larger than T-128's isolated `nb=2` block-only measurement (~53-54%) predicts**
— flagged honestly, not smoothed over: some of the gap could be inter-session machine-load variance
(this table and T-128's own `criterion` numbers were measured in different sessions the same day),
some could be CMAC-specific effects T-128's isolated round-function benchmark doesn't capture (e.g.
per-block overhead outside the round function itself scaling differently at 10 MiB than at 1 MiB).
Not root-caused further here — noted for whoever next touches this table, not assumed settled.

**Re-measured 2026-07-26 at 64 B, N = 500000 (T-138, `docs/DECISIONS.md` D-82)** — a direct follow-up to
D-80's GMAC timer-placement finding: the original 64 B/1 MiB table above was measured by an earlier,
uncommitted wrapper this session never inherited, so there was no way to confirm it placed its timer
correctly. Rebuilt a fresh wrapper with the timer explicitly placed after `dstu7624_alloc`/
`dstu7624_init_cmac` (matching every other mode's convention, D-80's fix). **Byte-identity verified
first, at `--iterations 1`** (a fresh, correctly-initialized `ctx` for each of the 5 variants) — all
5 tags matched `uacrypt`'s own byte-for-byte. **A real correctness quirk found and confirmed by a
standalone probe before trusting any multi-iteration timing**: `dstu7624_final_mac` never resets
its CMAC chaining state (`ctx->state`) or buffered-tail length, so calling `update_mac`/`final_mac`
repeatedly on the same `ctx` without re-`init_cmac` produces a *different* tag on every iteration
past the first (confirmed directly: 4 repeated calls on the same message each returned a distinct
tag). **This does not invalidate the timing** — `crypt_basic_transform`'s block cipher is
constant-time/constant-work regardless of the garbage state flowing in (no secret- or
length-dependent branching), so every iteration still performs the identical amount of arithmetic;
only the *value* computed past iteration 1 is not independently meaningful, which is fine for a
pure throughput measurement (correctness is what `--iterations 1`'s byte-identity check above
already confirms). Documented in the wrapper's own source rather than assumed silently.

| Variant | uacrypt compute (MB/s) | UAPKI compute (MB/s) | uacrypt verify (MB/s) | Ratio (compute) |
|---|---|---|---|---|
| 128-128 | **161.21** | 120.98 | 131.96 | 1.33x |
| 128-256 | **119.40** | 99.53 | 101.75 | 1.20x |
| 256-256 | **95.10** | 87.19 | 83.44 | 1.09x |
| 256-512 | **74.33**\* | 72.98 | 67.16 | 1.02x |
| 512-512 | **67.80** | 46.65 | 62.02 | 1.45x |

\*Effectively tied — within normal run-to-run noise at this message size, not a decisive lead
either way.
UAPKI has no separate `verify` entry point (a MAC verify is a compute + `memcmp`, negligibly
different cost, matching the already-established "compute/verify symmetric within noise on both
implementations" finding above) — only `uacrypt`'s own verify column is shown.

**The real small-message lead is ~1.0-1.45x, not the previously-published ~6-8x.** Same corrective
shape as D-80's GMAC finding, and larger in relative terms: this project no longer has a wide
small-message advantage over UAPKI for CMAC, just a modest one, on the same T-128-improved code the
10 MiB table above already reflects. **`uacrypt`'s own 64 B number also jumped far more than T-128's
isolated round-function measurement alone would predict** (29.92 → 161.21 MB/s at 128-128, ~5.4x,
versus T-128's own `nb=2` block-only ~51-54% i.e. ~2x) — flagged, not root-caused: the original 64 B
row's exact `--iterations` count and wrapper vintage are unknown (predates this session's fixed
wrapper and this file's own "N=" annotation convention), so whether it carried a comparable
timer-placement or low-iteration-count noise issue on `uacrypt`'s own side cannot be ruled out from
here. Consistent with the already-flagged pattern two paragraphs above (128-128's 10 MiB jump also
exceeded prediction) - not an isolated one-off.

**Reproducing**: same `uacrypt` command as above at `--iterations 500000`; the UAPKI-side wrapper is
now committed at `tests/oracle-harness/uapki-cmac-bench/cmac_bench.c` (`docs/DECISIONS.md` D-83 - build
recipe in the file's own doc comment), taking `<variant> <key_path> <in_path> <out_path>
<iterations>` and printing `iterations=.. total_ns=.. per_op_ns=..` to stderr, matching `uacrypt`'s
own convention.

### Kalyna-GMAC (`kalyna-gmac compute`)

New command this session (T-121, D-71) — same shape as CMAC but no nonce, tag is the variant's full
block length. **All 5 variants, exactly one block of message (see D-71 for why: sidesteps a known
UAPKI-side multi-block streaming bug, D-57), N = 5000, Ryzen only:**

| Variant | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|
| 128-128 | **6.50** | 0.84 |
| 128-256 | **5.94** | 0.83 |
| 256-256 | **6.35** | 1.55 |
| 256-512 | **6.01** | 1.40 |
| 512-512 | **4.76** | 1.72 |

This project wins by ~4-8x on every variant, same cause as CMAC's small-message case (UAPKI's
per-call `ByteArray`/ctx setup cost, not a per-byte throughput difference — the message here is only
one block, so setup cost is nearly the whole cost).

**Re-measured 2026-07-26 after the `gf2m_wide` comb-multiply fix (see Kalyna-GCM's section above,
`docs/TASKS.md` T-125, `docs/DECISIONS.md` D-76)** — same shape (one field multiply per block), same win
mechanism as GCM, at the existing 1-block scale:

| Variant | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|
| 128-128 | **16.84** | 0.87 |
| 128-256 | **16.90** | 0.82 |
| 256-256 | **16.71** | 1.55 |
| 256-512 | **16.14** | 1.34 |
| 512-512 | **12.91** | 1.70 |

This project's own throughput roughly doubled or better on every variant (e.g. 512-512: 4.76 →
12.91 MB/s), widening an already-large lead (~10-19x now, up from ~4-8x) — UAPKI's own numbers held
steady, as expected (nothing changed on its side).

**Reproducing**: `target/release/uacrypt kalyna-gmac compute --variant <v> --key <path> --in <path>
--out <path> --iterations <N>`.

**Updated 2026-07-26, re-run after T-128**, 1 block, N = 5000, both directions:

| Variant | uacrypt compute (MB/s) | uacrypt verify (MB/s) | vs. pre-T-128 compute row |
|---|---|---|---|
| 128-128 | 21.16 | 18.87 | +25.7% (was 16.84) |
| 128-256 | 22.38 | 18.63 | +32.4% (was 16.90) |
| 256-256 | 18.51 | 16.53 | +10.8% (was 16.71) |
| 256-512 | 15.38 | 15.47 | -4.7% (was 16.14) |
| 512-512 | 12.93 | 12.37 | +0.2% (was 12.91) |

**Small and non-monotonic, unlike CMAC/CCM/block above — this tracks GCM's own modest gain, not
CMAC's large one, and that's expected**: GMAC's per-block cost is dominated by the field multiply
(same mechanism as GCM, ~90%+ per T-125/D-76's isolated timing), not the block-cipher round
function T-128 sped up, so only a small fraction of GMAC's cost is even reachable by this fix.
256-512/512-512's flat-to-slightly-down cells are within normal single-run noise for a
single-block, N=5000 operation (less averaging than CMAC/CCM's larger workloads), not a real
regression — flagged honestly rather than smoothed into a false trend.

**UAPKI column rebuilt same day (T-131/D-78 extension, `docs/DECISIONS.md` D-80) — and every UAPKI
number above this line is now understood to be an overstated gap, not a fresh finding to build on.**
Building the UAPKI-side wrapper for GMAC surfaced a real timing-methodology bug in the wrapper
itself: `dstu7624_alloc`/`dstu7624_init_gmac` were timed *inside* the same window as
`update_mac`/`final_mac`, while `uacrypt`'s own GMAC command (like every mode above) expands its
schedule once outside the timed loop. For a one-block message, `init_gmac`'s cost swamps the actual
one-block MAC computation - exactly the "setup cost is nearly the whole cost" explanation already
given above for the *old* ~4-24x numbers, except that explanation was describing an artifact of
*how the comparison was built*, not a genuine property of UAPKI's GMAC. Fixed by moving the timer
start to after `init_gmac` (matching every other mode's convention) and re-measured, same 1-block
scale, byte-identity re-confirmed unaffected by the fix (the bug was timing-only, not a correctness
bug):

| Variant | uacrypt compute (MB/s) | UAPKI compute (MB/s) | Ratio (uacrypt/UAPKI) |
|---|---|---|---|
| 128-128 | **21.30** | 11.15 | 1.91x |
| 128-256 | **22.38** | 11.17 | 2.00x |
| 256-256 | **18.65** | 16.49 | 1.13x |
| 256-512 | **17.09** | 15.86 | 1.08x |
| 512-512 | **13.22** | 4.64 | 2.85x |

**The real gap is ~1.1-2.9x, not ~4-24x** - uacrypt still leads on every variant (GMAC's field
multiply, T-125/D-76's fix, plus T-128's block-cipher gain both help it), but the margin the
project believed existed for over a year of this table's history was substantially inflated by a
benchmark bug, not by GMAC's actual design. **CMAC was checked against the same bug and is not
materially affected** - re-measuring CMAC's 10 MiB table with the identical fix produced numbers
within <1% of the already-published ones (bulk 10 MiB work dwarfs a few microseconds of per-call
setup, unlike GMAC's single block) - so CMAC's existing ~1.1-1.9x UAPKI-leads-here conclusion
stands unchanged. **Flagged, not re-measured here**: this class of bug could equally affect
historical small-message CMAC (64 B) and CCM numbers measured by an earlier, uncommitted wrapper
this session didn't inherit or inspect - those rows should be treated as unverified against this
specific failure mode until someone re-measures them with a wrapper that is confirmed to exclude
setup cost, not assumed correct by precedent.

### Kalyna-KW (`kalyna-kw wrap`)

New command this session (T-121, D-71) — wraps block-aligned key material, output is one block
longer than the input. **All 5 variants, 2 blocks of key material, N = 5000, Ryzen only:**

| Variant | uacrypt (MB/s) | UAPKI (MB/s) |
|---|---|---|
| 128-128 | 5.38 | **12.80** |
| 128-256 | 4.07 | **10.93** |
| 256-256 | 6.33 | **16.39** |
| 256-512 | 5.12 | **10.54** |
| 512-512 | 5.83 | **10.49** |

**UAPKI wins by ~1.8-2.7x on every variant** — the opposite of CMAC/GMAC/CCM's small-message
pattern above, despite KW's input here being similarly small (32-128 bytes). Not root-caused this
session; `hazmat::kalyna_kw`'s Feistel-like network runs many more block-cipher calls per byte of
key material than a CMAC/GCM pass over the same length would (proportional to `v = (n-1)*6` rounds,
`docs/DECISIONS.md` D-55), which may explain the reversal, but this wasn't confirmed by profiling.

**Root-caused and partially fixed 2026-07-26, `docs/TASKS.md` T-127, `docs/DECISIONS.md` D-76**: reading the
UAPKI benchmark harness directly (`bench.c`'s `cmd_kw`) confirmed `dstu7624_init_kw` is called once,
*outside* its `--iterations` loop - while `uacrypt`'s own `kalyna-kw wrap`/`unwrap` called
`hazmat::kalyna_kw::wrap`/`unwrap`, which re-expand the full Kalyna key schedule *every* call
(`kalyna_kw.rs`'s `wrap` used to build a fresh `ExpandedKey` internally, with no way for a caller to
avoid it). Fixed by adding `wrap_with_cipher`/`unwrap_with_cipher` (take an already-expanded cipher)
and wiring `run_kw_command`'s benchmark loop to build the schedule once, same as
`kalyna-block`/`kalyna-gcm`/`kalyna-xts` already did. **Re-measured, same 2-block-key-material
scale, N = 5000, Ryzen only:**

| Variant | uacrypt (MB/s) | UAPKI (MB/s) | uacrypt before (MB/s) | Gap before | Gap after |
|---|---|---|---|---|---|
| 128-128 | 7.06 | **12.91** | 5.38 | 2.38x | 1.83x |
| 128-256 | 4.99 | **10.50** | 4.07 | 2.69x | 2.10x |
| 256-256 | 7.23 | **16.22** | 6.33 | 2.59x | 2.24x |
| 256-512 | 6.14 | **10.85** | 5.12 | 2.06x | 1.77x |
| 512-512 | 7.34 | **10.34** | 5.83 | 1.80x | 1.41x |

UAPKI's own numbers didn't move (noise-level differences only, as expected - nothing changed on
its side). This project's own throughput improved 14-31% on every variant purely from removing the
redundant per-call schedule expansion, narrowing UAPKI's lead on every variant but not eliminating
it - confirming the schedule-redo cost was a real, measurable, partial contributor to this gap, not
the sole cause. The residual gap (~1.4-2.2x) is consistent with D-76's finding #1 (a genuine
core-round-function speed difference, ~1.3-2.7x depending on variant) - not investigated further
as a KW-specific cause beyond that.

**Reproducing**: `target/release/uacrypt kalyna-kw wrap --variant <v> --key <path> --in <path> --out
<path> --iterations <N>`.

**Updated 2026-07-26, re-run after T-128**, 2 blocks of key material, N = 5000, both directions:

| Variant | uacrypt wrap (MB/s) | uacrypt unwrap (MB/s) | vs. pre-T-128 wrap row |
|---|---|---|---|
| 128-128 | **13.84** | 11.51 | +96.0% (was 7.06) |
| 128-256 | **10.32** | 8.59 | +106.8% (was 4.99) |
| 256-256 | **9.27** | 10.34 | +28.2% (was 7.23) |
| 256-512 | 7.34 | **8.28** | +19.5% (was 6.14) |
| 512-512 | **9.02** | 6.62 | +22.9% (was 7.34) |

Same `nb=2`/`nb=4`/`nb=8` split as Kalyna-block/CCM above — KW's Feistel-like network is pure
block-cipher chaining (`v = (n-1)*6` rounds, D-55), so it inherits T-128's gain the same way.
Wrap/unwrap show the same encrypt/decrypt-direction asymmetry XTS and Kalyna-block do (256-256/
256-512 favor the reverse direction, the others favor the forward one) — consistent with
`encipher_round_n`/`fused_inv_round_n` being genuinely different code paths (T-128/D-77), not
measurement error.

**UAPKI column rebuilt same day (T-131/D-78 extension, `docs/DECISIONS.md` D-80)** — byte-for-byte
confirmed (wrap output, and unwrap round-tripping back to the original key material, both
implementations), same 2-block scale:

| Variant | uacrypt wrap (MB/s) | UAPKI wrap (MB/s) | uacrypt unwrap (MB/s) | UAPKI unwrap (MB/s) |
|---|---|---|---|---|
| 128-128 | **14.18** | 13.14 | **11.56** | 9.64 |
| 128-256 | 10.16 | **10.58** | **8.89** | 7.68 |
| 256-256 | 9.23 | **16.52** | 10.39 | **12.73** |
| 256-512 | 7.32 | **10.91** | 8.28 | **10.57** |
| 512-512 | 9.03 | **10.54** | 6.64 | **12.43** |

This resolves the "fresh UAPKI-side re-measurement needed" note this section previously carried:
KW's residual gap did **not** close as far as CMAC/XTS's did — UAPKI still leads on 8 of 10 cells
(uacrypt wins only 128-128 wrap and 128-256/256-256 unwrap), roughly the same ~1.1-1.9x range D-76's
finding #1 (a genuine round-function speed difference, separate from T-128's own gain) already
predicted as the expected residual. Consistent with T-128's own docs elsewhere in this file: KW
inherits the round-function speedup but was never expected to fully close UAPKI's remaining lead by
itself.

### Kalyna-XTS (`kalyna-xts encrypt`)

New command this session (T-121, D-71) — confidentiality-only disk-sector mode. **All 5 variants,
512 B and 4096 B sectors, Ryzen only:**

| Variant | uacrypt 512 B (MB/s) | UAPKI 512 B (MB/s) | uacrypt 4096 B (MB/s) | UAPKI 4096 B (MB/s) |
|---|---|---|---|---|
| 128-128 | **27.78** | 12.84 | **27.41** | 13.12 |
| 128-256 | **25.15** | 12.56 | **25.01** | 12.79 |
| 256-256 | 16.89 | **18.30** | 16.90 | **18.67** |
| 256-512 | 16.43 | **17.97** | 16.54 | **18.16** |
| 512-512 | **8.28** | 36.35 | **8.32** | 38.24 |

**Real finding, flagged for follow-up, not root-caused here**: the 512-512 variant is a dramatic
outlier — UAPKI runs **4.4-4.6x faster** than this project's own implementation there (36.35/38.24
vs. 8.28/8.32 MB/s), a much wider gap than any other variant/mode measured in this entire session
(every other cell in every table above is within ~2.7x, most within 2x). 128-128/128-256 show the
opposite pattern (this project ~2x ahead), and 256-256/256-512 are roughly at parity — so this isn't
a uniform "UAPKI's XTS is just faster" result, it's specific to the largest key/block variant. Not
investigated further this session (`hazmat::kalyna_xts` itself was not touched — only a new CLI
wrapper around the existing implementation was added) — see `docs/TASKS.md` T-121 for the standing note.

**Root-caused and fixed 2026-07-26, `docs/TASKS.md` T-126, `docs/DECISIONS.md` D-76**: `hazmat::gf2m_wide.rs`
had no fast path for "multiply by the fixed generator `x`" (the `two` constant XTS's tweak-doubling
uses every block) - every call paid the fully general O(m²) schoolbook `multiply` for what is
mathematically an O(m/64) shift-plus-conditional-XOR. Added `double()` (verified byte-identical to
`multiply(two)` by a property test over all three field widths before being wired in) and switched
`kalyna_xts.rs`'s tweak update to call it. **Re-measured at the exact same 512 B/4096 B scale as the
original finding above, Ryzen only:**

| Variant | uacrypt 512 B (MB/s) | UAPKI 512 B (MB/s) | uacrypt 4096 B (MB/s) | UAPKI 4096 B (MB/s) |
|---|---|---|---|---|
| 128-128 | **100.12** | 12.75 | **106.18** | 12.77 |
| 128-256 | **73.54** | 12.55 | **76.30** | 12.34 |
| 256-256 | **110.82** | 17.93 | **112.15** | 16.10 |
| 256-512 | **88.63** | 17.80 | **87.76** | 18.17 |
| 512-512 | **97.92** | 39.27 | **104.19** | 43.97 |

**Every variant improved substantially, not just 512-512** - the wasted general-multiply work exists
at every field width, just less visibly before this fix pushed it past the "dramatic outlier"
threshold at m=512 (D-76's O(m) total waste per message reasoning: `poly_mul_wide`'s cost is O(m²)
per multiply, so even at m=128 it was real, avoidable work). **The 512-512 anomaly itself is fully
reversed**: previously ~4.4-4.6x *slower* than UAPKI, now **~2.4-2.5x faster** (97.92/104.19 vs.
39.27/43.97 MB/s) - UAPKI's own numbers barely moved (39.27/43.97 vs. the original 36.35/38.24,
noise-level, as expected since nothing changed on its side). Confirmed again independently at 10 MiB
(`--iterations 50`, well past any per-call setup-cost noise): 512-512 lands at 104.60 MB/s, squarely
in the middle of the other four variants' 74-115 MB/s band, not an outlier at all anymore -
UAPKI's own 10 MiB numbers (12.70-43.11 MB/s) drop sharply with block size shrinking (128-128's
655,360 16-byte blocks vs. 512-512's 163,840 64-byte blocks for the same 10 MiB) - consistent with
the per-field-multiply heap allocation cost found in `gf2m_mul` (`dstu7624.c:2963-3001`, 3 allocations
per call) dominating UAPKI's own XTS throughput at scale, worse for smaller blocks (more of them per
message), the opposite direction from this project's now-fixed per-multiply cost (which no longer
depends on block count at all, only on `m`).

**Reproducing**: `target/release/uacrypt kalyna-xts encrypt --variant <v> --key <path> --tweak
<path> --in <path> --out <path> --iterations <N>`.

### 10 MiB re-measurement pass (T-125 follow-up, requested 2026-07-26)

Every mode whose input length isn't inherently capped was re-measured at 10 MiB (`--iterations 50`)
specifically to push past any remaining per-call setup-cost noise and confirm the numbers above are
steady-state throughput, not an artifact of the message sizes measured so far. **Modes with an
inherent length cap are excluded, and why**: `kalyna-block` (single block only, no arbitrary-length
mode exists for it), `kalyna-kw` (`MAX_R = 20` blocks, `docs/DECISIONS.md` D-55), `kalyna-gmac` (measured
at exactly one block by design, D-57's UAPKI multi-block streaming bug workaround), `kalyna-ccm`
(`MAX_PLAINTEXT_LEN = 255` bytes, a property of the DSTU CCM construction as implemented here, not a
benchmark choice).

| Mode | Variant | uacrypt (MB/s) | UAPKI (MB/s) | Matches 1 MiB number? |
|---|---|---|---|---|
| Kalyna-XTS | 128-128 | **102.59** | 12.70 | No - improved ~3.7x by T-126's fix (no prior 1 MiB point existed) |
| Kalyna-XTS | 128-256 | **74.05** | 12.50 | No - improved ~2.9x (T-126) |
| Kalyna-XTS | 256-256 | **115.16** | 18.46 | No - improved ~6.6x (T-126) |
| Kalyna-XTS | 256-512 | **90.50** | 18.01 | No - improved ~5.4x (T-126) |
| Kalyna-XTS | 512-512 | **104.60** | 43.11 | No - improved ~12.6x (T-126), no longer an outlier |
| Kalyna-CMAC | 128-128 | 102.46 | **232.46** | Yes - within 4% of the 1 MiB row above |
| Kalyna-CMAC | 128-256 | 75.23 | **178.01** | Yes - within 2% |
| Kalyna-CMAC | 256-256 | 119.26 | **254.70** | Yes - within 4% |
| Kalyna-CMAC | 256-512 | 92.84 | **205.47** | Yes - within 5% |
| Kalyna-CMAC | 512-512 | 108.68 | **152.77** | Yes - within 2% |
| Kalyna-GCM (pre-comb-multiply-fix) | 128-128 | 10.51 | **12.60** | Yes - within 1% |
| Kalyna-GCM (pre-comb-multiply-fix) | 128-256 | 10.16 | **12.25** | Yes - within 2% |
| Kalyna-GCM (pre-comb-multiply-fix) | 256-256 | 8.31 | **15.87** | Roughly - ~12% lower than the 1 MiB row's 18.12, within this methodology's noise band |
| Kalyna-GCM (pre-comb-multiply-fix) | 256-512 | 8.10 | **17.45** | Yes - within 1% |
| Kalyna-GCM (pre-comb-multiply-fix) | 512-512 | **5.50** | 4.77 | Yes - within 2%, still leads |
| Kupyna-256 | - | 95.52 | **143.03** | Roughly - UAPKI's lead widens slightly (was ~1.37x at 1 MiB, ~1.50x at 10 MiB) |
| Kupyna-512 | - | 77.94 | **114.49** | Roughly - same widening pattern (~1.45x to ~1.47x) |
| Strumok-256 | - | **648.67** | 581.13 | No - this project now leads at 10 MiB (was UAPKI ahead ~1.10x at 1 MiB) |
| Strumok-512 | - | **636.16** | 631.02 | Roughly at parity (was UAPKI ahead ~1.10x at 1 MiB) |

**CMAC confirms D-76's finding #1 directly**: its 10 MiB ratios track the already-published 1 MiB
ratios closely (within ~5%), meaning nothing about T-127's schedule-caching fix changed CMAC's
numbers at this scale (expected - the schedule cost was already amortized over tens of thousands of
block-cipher calls). Kupyna/Strumok are also within noise of their existing 1 MiB numbers, as
expected (neither fix touches either primitive). XTS is the one mode whose numbers moved at the
time this pass was run, by exactly the margin T-126's root cause predicts.

**GCM's row above is superseded, same day, by the comb-multiply fix (`docs/TASKS.md` T-125,
`docs/DECISIONS.md` D-76)** - it was measured *before* that fix landed, kept here only as the historical
"was this a message-size artifact" check it was run for (answer: no, the 1 MiB and 10 MiB numbers
agreed, so the >2x gap this pass investigated was real steady-state throughput, not overhead noise
- exactly what justified treating it as a genuine bottleneck worth root-causing rather than a
measurement quirk). The Kalyna-GCM section above has the post-fix numbers; a fresh 10 MiB GCM point
wasn't re-run this session (the 1 MiB numbers already reproduce cleanly against 64 B and against the
isolated field-multiply timing, so a third confirmation at 10 MiB wasn't judged necessary here) -
flagged for whoever next touches this table, not silently assumed unchanged.

**Reproducing**: same commands as each mode's own section above, with `--iterations 50` and a
10 MiB (`10485760`-byte) `--in` file.

**Updated 2026-07-26, same day, re-run after T-128** (const-generic Kalyna round functions):

| Mode | Variant | uacrypt 10 MiB (MB/s) | vs. this table's own pre-T-128 row |
|---|---|---|---|
| Kalyna-XTS | 128-128 | **193.73** | +88.9% (was 102.59) |
| Kalyna-XTS | 128-256 | **144.50** | +95.2% (was 74.05) |
| Kalyna-XTS | 256-256 | **135.91** | +18.0% (was 115.16) |
| Kalyna-XTS | 256-512 | **107.53** | +18.8% (was 90.50) |
| Kalyna-XTS | 512-512 | **132.41** | +26.6% (was 104.60) |
| Kupyna-256 | - | 98.44 | +3.1% (was 95.52, within noise — T-128 doesn't touch Kupyna) |
| Kupyna-512 | - | 81.29 | +4.3% (was 77.94, same reason) |
| Strumok-256 | - | 653.08 | +0.7% (was 648.67, within noise — T-128 doesn't touch Strumok) |
| Strumok-512 | - | 654.80 | +2.9% (was 636.16, same reason) |

**Updated 2026-07-27, re-run after T-134** (const-generic Kupyna round functions, `docs/DECISIONS.md`
D-85) — supersedes this table's own Kupyna rows above, with a UAPKI column added the same pass
(fresh `kupyna_bench.c` wrapper, byte-identity verified, same as the Kupyna section's own
"Updated 2026-07-27" block has the full detail):

| Mode | Variant | uacrypt 10 MiB (MB/s) | UAPKI 10 MiB (MB/s) | vs. this table's own pre-T-134 row |
|---|---|---|---|---|
| Kupyna-256 | - | **139.52** | 149.66 | +41.7% (was 98.44) |
| Kupyna-512 | - | 98.65 | **117.77** | +21.4% (was 81.29) |

**UAPKI column for Kalyna-XTS added same day (`docs/TASKS.md` T-131, `docs/DECISIONS.md` D-78)**, same
wrapper/verification as CMAC's table above (byte-for-byte identical to `uacrypt` on all 5 variants,
both directions, confirmed before timing):

| Variant | uacrypt encrypt (MB/s) | UAPKI encrypt (MB/s) | Ratio |
|---|---|---|---|
| 128-128 | **194.50** | 12.91 | 15.1x |
| 128-256 | **144.71** | 12.67 | 11.4x |
| 256-256 | **136.31** | 18.57 | 7.3x |
| 256-512 | **107.72** | 18.16 | 5.9x |
| 512-512 | **132.53** | 40.99 | 3.2x |

**This project leads UAPKI's XTS by 3.2-15.1x at 10 MiB — a far larger margin than any other mode
in this file, and root-caused, not just observed.** UAPKI's `encrypt_xts` (`dstu7624.c:3003-3067`)
calls the fully generic `gf2m_mul` (`dstu7624.c:2963-3001`) to compute the tweak's "multiply by 2"
every block — `gf2m_mul` heap-allocates three `WordArray`s (`wa_alloc_from_uint8` x2, `wa_alloc` x1)
and runs the full O(m²) modular multiply, for a step that is mathematically just a one-bit shift
plus a conditional reduction. This project's `Gf2m*::double()` (T-126/D-76) does exactly that O(m)
operation with no heap allocation at all — the same asymmetry the 1 MiB table above already flagged
for 512-512 specifically (line ~739's "3 allocations per call... dominating UAPKI's own XTS
throughput at scale") is confirmed here to hold, and to widen, across every variant now that T-128
also sped up this project's own block-cipher path. **This is not a bug on UAPKI's side** — it is
correct, just written generically (the same `gf2m_mul` is shared with GCM/GMAC's own field
multiply, where a full multiply actually is needed) rather than specialized for the one fixed
multiplicand XTS's tweak update always uses.

The wrapper re-runs `dstu7624_alloc`/`dstu7624_init_xts` every iteration but times only the
`dstu7624_encrypt`/`_decrypt` call itself, matching `uacrypt`'s own XTS benchmark path (cached
`ExpandedKey` built once outside the loop) - schedule/init cost is excluded on both sides, so the
ratio above reflects bulk per-block work, not setup. Disclosed because CMAC's table above uses the
same exclusion but shows a much smaller ratio (~1.1-1.9x) - a reader shouldn't assume the two tables
amortize setup differently just because the ratios differ that much; they don't, the difference is
the genuine per-block cost gap described above.

**XTS improves substantially on every variant, on top of T-126's already-landed fix** — XTS calls
the Kalyna block cipher directly (via `ExpandedKey::encrypt_block`) for every data unit, so it
benefits from T-128's round-function speedup the same way Kalyna-block/CMAC do, independently of
T-126's separate tweak-doubling fix; the two are additive, not overlapping causes. Kupyna/Strumok
move only within measurement noise, exactly as expected — T-128 is a `hazmat::kalyna.rs`-only
change. **T-134 (Kupyna's own analogous const-generic rewrite) and T-135 (Strumok's batched/fixed-
index rewrite) both landed 2026-07-27** - see the "Regression baseline" section below for their
measured before/after numbers. CMAC/GCM's own post-T-128 numbers are in their own sections above,
not repeated here.

**Decrypt direction added 2026-07-26, same session** (previously this table, like most of this
file, only measured the forward direction — corrected going forward, see "Methodology"):

| Variant | uacrypt XTS encrypt (MB/s) | uacrypt XTS decrypt (MB/s) |
|---|---|---|
| 128-128 | 193.73 | 173.58 |
| 128-256 | 144.50 | 131.71 |
| 256-256 | 135.91 | **153.10** |
| 256-512 | 107.53 | 122.04 |
| 512-512 | 132.41 | 98.89 |

**Not symmetric, unlike GCM/CMAC above** — encrypt and decrypt use different round-function paths
internally (`encipher_round_n` vs `fused_inv_round_n`, T-128/D-77), which already showed a real
encrypt/decrypt asymmetry in T-128's own block-only criterion numbers (e.g. `nb=8` decrypt gained
less than encrypt, ~15% vs ~22%). 256-256 decrypt actually running *faster* than its own encrypt is
a real, measured result here, not a typo — consistent direction with (though larger in magnitude
than) T-128's own block-only finding that the two directions don't scale identically across block
sizes. Not root-caused further than "the two round functions are genuinely different code paths."

**UAPKI decrypt column added same day (T-131/D-78)**, same wrapper, byte-for-byte confirmed to
round-trip back to the original 10 MiB plaintext for both implementations before timing:

| Variant | uacrypt decrypt (MB/s) | UAPKI decrypt (MB/s) | Ratio |
|---|---|---|---|
| 128-128 | **172.81** | 12.59 | 13.7x |
| 128-256 | **128.22** | 12.23 | 10.5x |
| 256-256 | **153.43** | 18.21 | 8.4x |
| 256-512 | **122.91** | 17.85 | 6.9x |
| 512-512 | **99.96** | 42.48 | 2.4x |

Same lead pattern and same root cause as the encrypt table above — `decrypt_xts` (`dstu7624.c:3069`
onward) calls the identical generic `gf2m_mul` for the same tweak-doubling step, so the per-block
allocation cost is symmetric between UAPKI's own encrypt/decrypt too (its two columns move together
within noise, same as this project's).

## What the gap is, honestly

This project's MVP deliberately chose correctness and `no_std`/embedded-portability first
(`CLAUDE.md` MVP scope) over speed. The gap to UAPKI/outspace is real and has concrete, confirmed
causes — read directly from the other implementations' source, not guessed at (`docs/TASKS.md` has the
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
  both fixes was root-caused 2026-07-26 and fixed 2026-07-27 (T-135, `docs/DECISIONS.md` D-86): batched,
  fixed-index 128-byte block generation with the input XOR fused in at `u64` granularity, matching
  `next_stream_full_crypt`'s own shape — closed the gap to ~1.19-1.25x, not further chased since
  the remainder is the LFSR/FSM's inherently serial dependency chain.
- **Kalyna-XTS, T-126, 2026-07-26**: `hazmat::gf2m_wide`'s field-element `multiply` had no fast path
  for the fixed-constant case XTS's tweak-doubling always needs (multiply by the generator `x`) -
  every tweak update paid a full general O(m²) schoolbook multiply for what is mathematically an
  O(m/64) shift-plus-conditional-XOR. Fixed by adding `double()`. Closed the 512-512 variant's
  4.4-4.6x-slower anomaly entirely (now ~2.4-2.5x *faster* than UAPKI at the same message sizes) and
  substantially improved the other four variants too (this waste existed at every field width, just
  less visibly before m=512 pushed it past "dramatic outlier"). See the Kalyna-XTS section above for
  the full before/after numbers.
- **The block-level "rough parity with UAPKI" claim (the very first table in this file, "Kalyna
  (single-block encrypt, nanoseconds")) is itself a measurement artifact, found 2026-07-26
  (`docs/DECISIONS.md` D-76)**: UAPKI's `encrypt_ecb`/`decrypt_ecb` allocate twice and free once per call
  (`dstu7624.c:2916,2922`), which dominates the timing of a single 16-64 byte block. Proven from
  numbers already in this file, no new measurement needed: UAPKI's own CMAC-at-1-MiB throughput
  (allocation-free `cmac_update`/`cmac_final`) is 1.33-2.71x *faster* than UAPKI's own block-cached
  number for the same variant - impossible unless the block number under-measures UAPKI's true
  per-block speed. This project's own CMAC-at-1-MiB tracks its own block-cached number within ~1.5%
  on every variant, confirming *this project's* block-level numbers needed no such correction. **The
  true core-round-function gap, with allocation removed from both sides, is larger than the
  block-level table implies** - UAPKI's round function is genuinely faster, ~2.7x at 128-128
  narrowing to ~1.3x at 512-512 - a core Kalyna-cipher-level gap, not specific to any mode. This is
  why Kalyna-CMAC's own gap (this file's CMAC section) needs no CMAC-specific explanation: it's
  simply exposing the real round-function gap directly, without the block-level table's allocation
  contamination.
- **Kalyna-CMAC/KW's `hazmat` API re-expanded the full key schedule on every call, T-127,
  2026-07-26**: `kalyna_cmac.rs`'s `mac`/`kalyna_kw.rs`'s `wrap`/`unwrap` took raw key bytes and
  built a fresh `ExpandedKey` internally every call, unlike `kalyna-block`/`gcm`/`xts`. Confirmed
  UAPKI's own benchmark harness (`bench.c`'s `cmd_kw`) caches its schedule once outside its own
  iteration loop - so this was a genuine asymmetry, not just an assumption. Fixed by adding
  `mac_with_cipher`/`wrap_with_cipher`/`unwrap_with_cipher` (take an already-expanded cipher) and
  wiring `uacrypt`'s benchmark loops to use them. For CMAC's own large-message benchmarks this cost
  was already amortized to nothing (confirmed unchanged after the fix); for KW's much smaller
  2-block-of-key-material benchmark it wasn't, and removing it narrowed UAPKI's lead by roughly
  14-31% across all five variants (see the Kalyna-KW section above) without eliminating it - the
  residual matches the core-round-function gap described in the point above.
- **Kalyna-GCM/GMAC, T-125, 2026-07-26**: an isolated timing diagnostic measured
  `hazmat::gf2m_wide`'s field multiply at 89.6% (m=128) to 94.3% (m=512) of GCM's per-block cost -
  the O(m²) bit-serial `poly_mul_wide`, not the block cipher, was the actual bottleneck (this is the
  profiling T-125's own text asked for, not an inference from aggregate numbers). Fixed with a
  4-bit-window comb multiply (same technique class as real-world GF(2^m) implementations, verified
  against every existing GCM/GMAC/XTS vector and property test, no new correctness test needed).
  This project's own GCM throughput improved ~1.7-2.3x across every variant; the 256-256/256-512
  cells that originally triggered T-125 (>2x slower at 1 MiB) narrowed to ~1.09-1.11x, and
  128-128/128-256/512-512 flipped from trailing or roughly-tied to clearly leading. GMAC (same field
  arithmetic) improved by the same mechanism, roughly doubling an already-large lead. **What this
  does not answer**: why UAPKI specifically wins the mid-size (256-*) variants and loses at the
  extremes (128-*/512-512) - the working hypothesis (not measured, from reading `gf2m_mul`,
  `dstu7624.c:2963-3001`) is that UAPKI's own Karatsuba multiply pays 3 heap allocations per call,
  amortized differently across the fewer-but-larger blocks a bigger `m` produces - flagged as the
  open remainder, not settled.
- **Neither gap is a correctness or `no_std` concern** — all of it is pure throughput, addressable later
  without touching the already-verified algorithm logic (confirmed for Strumok's fix: all existing
  tests, including the 4000-case outspace differential harness, still pass unchanged).

None of this changes any implementation's standing as a correctness oracle (`docs/ORACLES.md`) — a
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

**Updated 2026-07-26 (`docs/TASKS.md` T-128, `docs/DECISIONS.md` D-77)**: `encipher_round`/`fused_inv_round`
became const-generic over block size (see D-77 for the full mechanism), superseding
`kalyna-decryptfusion-2026-07-22` as the Kalyna baseline:

```
cargo bench -p dstu-core --bench kalyna -- --save-baseline pre-unroll-2026-07-26  # captured before the change
cargo bench -p dstu-core --bench kalyna -- --baseline pre-unroll-2026-07-26  # to check
```

**Before/after comparison, one clean run** (no other CPU-heavy process running concurrently — an
earlier attempt at this same comparison, taken while a background Miri run was active, produced a
spurious +4.9% "regression" reading on one cell purely from CPU contention, discarded rather than
published):

| Variant | Direction | Mode-level (Δ, key-expansion-dominated) | Block-only cached-schedule (Δ, isolates the round function) |
|---|---|---|---|
| 128-128 | encrypt | −11.8% | **−53.6%** |
| 128-128 | decrypt | −6.9% | **−51.9%** |
| 128-256 | encrypt | −12.3% | **−54.3%** |
| 128-256 | decrypt | −8.5% | **−51.3%** |
| 256-256 | encrypt | −5.7% | **−20.2%** |
| 256-256 | decrypt | −7.1% | **−40.9%** |
| 256-512 | encrypt | −5.8% | **−19.0%** |
| 256-512 | decrypt | −7.8% | **−36.5%** |
| 512-512 | encrypt | −3.2% | **−21.5%** |
| 512-512 | decrypt | −2.4% | **−15.3%** |

"Mode-level" is the full `encrypt_generic`/`decrypt_generic` call (key expansion + rounds +
zeroize) — small, sometimes noisy improvement, exactly as expected since key expansion still runs
through the unchanged runtime-`nb` round functions (the `kalyna_variant!` doc comment's own
"~60-79% of single-call time is key schedule" note). "Block-only" (`ExpandedKey::encrypt_block`/
`decrypt_block`, cached schedule) isolates the round function itself — the fair before/after metric
for this specific change — and shows the real win: largest at `nb=2` (the size that paid the worst
of the old bounds-check/oversized-buffer waste), smaller but still substantial at `nb=8` (contrary
to an initial prediction that the largest variant, already using the full buffer width, "might not
move at all" — bounds-check elimination and full loop unrolling help every size, not only the one
with wasted buffer space). Per D-34, this is criterion-based internal regression tracking only, not
a cross-implementation claim against UAPKI — the binary-level Kalyna-block table above was not
re-measured this session (see D-77/T-128).

**Updated 2026-07-27 (`docs/TASKS.md` T-134, `docs/DECISIONS.md` D-85)**: `sub_shift_mix`/`compress` became
const-generic over `COLUMNS` (Kupyna's own analogue of T-128's Kalyna rewrite), superseding
`kalyna-kupyna-fused-2026-07-22` as the Kupyna baseline:

```
cargo bench -p dstu-core --bench kupyna -- --save-baseline kupyna-pre-t134-2026-07-27  # captured before the change
cargo bench -p dstu-core --bench kupyna -- --baseline kupyna-pre-t134-2026-07-27  # to check
```

| Benchmark | Before | After | Change |
|---|---|---|---|
| Kupyna-256 / 64 B | 1.676 µs | 1.207 µs | −28.9% |
| Kupyna-512 / 64 B | 2.443 µs | 2.029 µs | −17.0% |
| Kupyna-256 / 1024 B | 11.396 µs | 8.163 µs | −30.7% |
| Kupyna-512 / 1024 B | 15.086 µs | 12.425 µs | −18.9% |
| Kupyna-256 / 65536 B | 660.20 µs | 474.13 µs | −30.4% |
| Kupyna-512 / 65536 B | 815.52 µs | 667.59 µs | −18.7% |

Per D-34, this is `criterion`-based internal regression tracking only, not a cross-implementation
claim against UAPKI — Kupyna's binary-level UAPKI comparison table (in its own section above,
"Updated 2026-07-27") has the independent binary-level re-measurement, which cross-validates these
numbers via a separate method rather than duplicating them here.

`target/criterion/` is gitignored (as usual for `target/`), so this baseline lives only on whatever
machine last ran the save command above — it is **not** a portable, cross-machine regression gate
(a laptop today vs. a CI runner tomorrow will disagree on absolute numbers regardless of any code
change). Its value is catching a *relative* regression on the same machine across commits, not
establishing a portable performance contract. Re-run the save command to refresh the baseline after
an intentional performance change.

**Updated 2026-07-27 (`docs/TASKS.md` T-135, `docs/DECISIONS.md` D-86)**: `apply_keystream` became a
batched/fixed-index bulk path over 128-byte blocks (Strumok's own analogue of T-128/T-134's
unrolling, though via a one-time array rotation rather than const-generic dispatch — see D-86 for
why), superseding `strumok-optimized-2026-07-22` as the Strumok baseline:

```
cargo bench -p dstu-core --bench strumok -- --save-baseline strumok-pre-t135-2026-07-27  # captured before the change
cargo bench -p dstu-core --bench strumok -- --baseline strumok-pre-t135-2026-07-27  # to check
```

| Benchmark | Change |
|---|---|
| Strumok-256 / 64 B | no change (−0.04%, within noise — 64 B never reaches the new 128 B bulk threshold) |
| Strumok-512 / 64 B | +2.3% (small, real — phase-boundary check overhead with no bulk path to amortize it) |
| Strumok-256 / 1024 B | **−53.5%** |
| Strumok-512 / 1024 B | **−53.7%** |
| Strumok-256 / 65536 B | **−64.7%** |
| Strumok-512 / 65536 B | **−64.7%** |

Per D-34, this is `criterion`-based internal regression tracking only — the Strumok binary-level
comparison table below has the independent, cross-implementation re-measurement.

## Reproducing the C comparisons

Not committed to this repo by default (one-off, and pulling in a full UAPKI build is a lot of
scaffolding for something that isn't run again regularly) — but fully reproducible. **Exception:
the Kalyna-CMAC vs. UAPKI wrapper is committed** (`tests/oracle-harness/uapki-cmac-bench/
cmac_bench.c`, `docs/DECISIONS.md` D-83) since it had been rebuilt from scratch repeatedly in one week
(T-131/T-133/T-138) — promote another mode's wrapper the same way if it starts recurring, rather
than committing all of them preemptively.

1. **Oliynykov reference C**: build `oracles/kalyna-reference`/`oracles/kupyna-reference` directly
   (`gcc -O2 -I oracles/kalyna-reference <bench.c> oracles/kalyna-reference/{kalyna,tables}.c`),
   time `KalynaEncipher`/`KupynaHash` in a loop (context/key schedule set up once, outside the
   timed loop).
2. **UAPKI**: build `oracles/uapki/library/uapkic` via its own `CMakeLists.txt`
   (`-DUAPKI_LIBS_TYPE=STATIC -DUAPKI_DISABLE_COPY=ON`; on Windows/MinGW, the vendored
   `resource.rc` is UTF-16 and `windres` chokes on it — set `RESOURCE_RC` to empty in a working
   copy of the CMakeLists, not needed for a benchmark), then time `dstu7624_encrypt` /
   `dstu7564_init`+`update`+`final` / `dstu8845_crypt` through the public `ByteArray`-based API.
   **Faster alternative on Windows, found 2026-07-26 (T-121/D-71)**: the official
   `specinfo-ua/UAPKI` GitHub repo publishes a signed prebuilt `uapkic.dll` as a release asset
   (confirmed via `gh api repos/specinfo-ua/UAPKI/releases`) — exports every symbol needed, no
   VC++ redistributable dependency. `gendef uapkic.dll && dlltool -d uapkic.def -l libuapkic.a -D
   uapkic.dll` (both already on this machine via the WinLibs MinGW install, `.claude.local.md`)
   produces a plain import lib, so a C wrapper links with bare `gcc -luapkic` — skips CMake and the
   `resource.rc` workaround entirely. Use the vendored headers in `oracles/uapki/library/uapkic/
   include/` for exact signatures regardless of which build path is used; if in doubt whether a
   prebuilt DLL's ABI matches the vendored headers, `dstu7624_self_test()`/`dstu7564_self_test()`/
   `dstu8845_self_test()` (all exported) are a fast sanity check before trusting any numbers from
   it.
3. **outspace**: build `oracles/strumok-dstu8845` the same way as the existing
   `tests/oracle-harness/strumok-differential/` harness does, time `dstu8845_crypt` in a loop.

All timing done with `clock_gettime(CLOCK_MONOTONIC, ...)`, mean over many iterations (thousands
for small buffers, hundreds for the 64 KB case) to average out timer-resolution noise.

## vs. international-standard analogs (OpenSSL) — T-149, D-106

Every table above compares this project against other *DSTU* implementations (UAPKI, Oliynykov's
own reference, outspace) — the right comparison for "is this a competent implementation of the
standard," but not the question most first-time visitors actually have, which is closer to "how
does this compare to the algorithm I already know." This section answers that second question,
against the same three role-analogs the GitHub Pages landing page and `docs/dstu-crypto-project.md`
already name: **AES** for Kalyna, **Whirlpool** for Kupyna, **ChaCha20** for Strumok. This is a
speed baseline against familiar names, not a correctness oracle — `docs/ORACLES.md`'s trust matrix
is unchanged, OpenSSL is not added to it.

**Methodology deviation, stated plainly**: unlike every table above (a `gcc -O2` file-in/file-out
wrapper timed the D-34 way), these OpenSSL numbers come from OpenSSL's own `openssl speed`
subcommand — a different harness, not a wrapper this project wrote. `-elapsed` makes it use
wall-clock time (matching `uacrypt`'s own timing) instead of its default CPU-user-time divisor, and
`-bytes N` fixes its buffer size to match `uacrypt`'s. Both sides report **decimal** MB/s (10⁶
bytes/s — OpenSSL's own "1000s of bytes/s" output, `uacrypt`'s `bytes / seconds / 1e6`), so the
ratios below are apples-to-apples even though the two programs' internal timing loops differ. No
byte-identity check is meaningful here (unlike the UAPKI tables) — AES, Whirlpool, and ChaCha20 are
different algorithms from Kalyna/Kupyna/Strumok by design, there is nothing to byte-diff against.

**Machine/build**: same Ryzen 5 PRO 4650U dev machine as every table above, measured 2026-07-31.
OpenSSL 3.5.5 (27 Jan 2026), MinGW64 build (`gcc -m64 -O3`), the copy already on this machine's
`PATH` — nothing downloaded for this section, since it already covers AES, Whirlpool (via
`-provider legacy -provider default`), and ChaCha20 without needing libsodium as well.

**AES-NI/AVX2 caveat — read before the tables, not after**: OpenSSL's AES and ChaCha20 use CPU
instruction-set extensions (AES-NI, AVX2) that `dstu-core` has no equivalent to by design (no SIMD,
`CLAUDE.md` MVP scope). For AES, `OPENSSL_ia32cap="~0x200000200000000"` is OpenSSL's own documented
mechanism for disabling AES-NI/PCLMULQDQ, so both an AES-NI-on *and* an AES-NI-off column are
reported below — the off column is the one that actually answers "how good is this project's
Kalyna," the on column shows what hardware acceleration this project cannot claim. No equivalently
narrow, well-documented single flag was found to disable just ChaCha20's AVX2 path without risking
disabling unrelated optimizations too (an all-capabilities-zero test dropped AES itself to *below*
its own AES-NI-off number, suggesting it disables more than one extension at a time) — so ChaCha20
below is hardware-accelerated only, flagged the same way rather than presented as if it were a
clean software-vs-software comparison. **Whirlpool has no such caveat** — OpenSSL's implementation
is plain table-driven C with no ISA-specific fast path, so it's a genuinely clean comparison to
Kupyna's own software-only design.

### Kalyna vs. AES (single block, schedule cached, MB/s — higher is better)

| Variant | uacrypt | AES (AES-NI) | AES (AES-NI off) | vs. AES-NI-off |
|---|---|---|---|---|
| 128-128 | **222.22** | 1127.55 | 380.07 | 0.58x (AES software ~1.71x faster) |
| 128-256 | **158.42** | 900.35 | 272.69 | 0.58x (AES software ~1.72x faster) |

**256-256, 256-512, 512-512 have no AES row, and won't ever** — AES has one fixed 128-bit block
size; only Kalyna's two 128-bit-block variants share anything to compare against. Against
AES-NI (hardware), the gap is ~5.1-5.7x — that number describes ISA support, not this project's
Kalyna code, per the caveat above.

### Kupyna vs. Whirlpool (digest, MB/s — higher is better)

| Variant | Size | uacrypt | Whirlpool | Ratio |
|---|---|---|---|---|
| Kupyna-256 | 16 KiB | **134.36** | 201.51 | 0.67x (Whirlpool ~1.50x faster) |
| Kupyna-256 | 10 MiB | **136.46** | 198.57 | 0.69x (Whirlpool ~1.46x faster) |
| Kupyna-512 | 16 KiB | **95.86** | 201.51 | 0.48x (Whirlpool ~2.10x faster) |
| Kupyna-512 | 10 MiB | **97.24** | 198.57 | 0.49x (Whirlpool ~2.04x faster) |

Whirlpool's output is fixed at 512 bits regardless of input size, so Kupyna-256's comparison is
throughput-only (no matching output-size counterpart) — still valid, since both are hashing the
same input bytes at the same buffer size. This is the one clean, no-asterisk table in this section:
same optimization tier (table-driven software, no ISA extensions) on both sides, so a genuine ~1.5-
2.1x gap is the actual finding, not a hardware artifact.

### Strumok vs. ChaCha20 (keystream, MB/s — higher is better)

| Variant | Size | uacrypt | ChaCha20 (AVX2) | Ratio |
|---|---|---|---|---|
| Strumok-256 | 16 KiB | **1959.92** | 3266.65 | 0.60x (ChaCha20 ~1.67x faster) |
| Strumok-256 | 10 MiB | **1891.73** | 3169.75 | 0.60x (ChaCha20 ~1.68x faster) |
| Strumok-512 | 16 KiB | **1904.58** | 3266.65 | 0.58x (ChaCha20 ~1.72x faster) |
| Strumok-512 | 10 MiB | **1879.27** | 3169.75 | 0.59x (ChaCha20 ~1.69x faster) |

ChaCha20's key is fixed at 256 bits (XChaCha20 extends the *nonce*, not the key), so Strumok-512's
row has no size-matched counterpart either — shown anyway since it's the same role comparison, just
without a key-size match. **Given ChaCha20's AVX2 acceleration and Strumok's pure-software design,
~1.6-1.7x is a genuinely competitive result**, not the ~5x-class gap AES-NI produces — closer in
spirit to the Whirlpool comparison than the AES one, even though a clean AVX2-off number wasn't
produced for it.

**Reproducing**: `openssl speed -elapsed -evp <aes-128-ecb|aes-256-ecb> -bytes 16 -seconds 3` (add
`OPENSSL_ia32cap="~0x200000200000000"` for the AES-NI-off column); `openssl speed -provider legacy
-provider default -elapsed -evp whirlpool -bytes <16384|10485760> -seconds 3`; `openssl speed
-elapsed -evp chacha20 -bytes <16384|10485760> -seconds 2`. `uacrypt` side: `kalyna-block encrypt
--variant <v> --key <16-or-32-byte key> --in <16-byte block> --out ... --iterations 3000000`,
`kupyna-digest --variant <256|512> --in <16 KiB|10 MiB file> --out ... --iterations <2000|20>`,
`strumok-crypt --variant <256|512> --key <32-or-64-byte key> --iv <32-byte IV> --in <16 KiB|10 MiB
file> --out ... --iterations <3000|30>`.

### DSTU 4145 vs. ECDSA (sign/verify, ops/s — higher is better) — T-150

`sign`/`verify` had no `--iterations` flag before this pass (unlike every other benchmarkable
command) - added for exactly this comparison (D-34's own policy: use the actual built binary, not
an internal `criterion` number, for any cross-implementation claim). The message is hashed once
before the timed loop starts (confirmed negligible: 255.98 ops/s on a 5-byte message vs. 254.51
ops/s on a 64 KiB message, within 0.6% - hashing cost genuinely doesn't move the number), and only
`sign_digest`/`verify_digest` itself is timed, key/signature parsed once outside the loop (same
D-80 discipline as every other table here). OpenSSL's own `openssl speed ecdsab163`/`ecdsap256`
already report `sign/s`/`verify/s` directly - no unit conversion needed, unlike the MB/s tables
above.

| | uacrypt (DSTU 4145) | OpenSSL nistb163 | OpenSSL nistp256 |
|---|---|---|---|
| sign/s | **255.98** | 5292.6 | 48059.1 |
| verify/s | **120.80** | 2732.6 | 16404.3 |
| vs. uacrypt | — | ~20.7x faster (sign), ~22.6x faster (verify) | ~187.7x faster (sign), ~135.8x faster (verify) |

**Two different comparisons in one table, and they answer different questions:**

- **`nistb163`** (a NIST/SECG binary curve, also over `GF(2^163)`) is the field-size-matched row -
  same underlying arithmetic cost class as this project's `gf2m163`, though **not the same curve**
  (different `b`, base point, order - this project's curve has `a = 1` per `curve163.rs`). This is
  the row that isolates "how good is this project's EC implementation," and the answer is: not very,
  by a wide margin, for a documented reason below.
- **`nistp256`** (P-256, a prime-field curve) is the "ECDSA" most readers actually mean when they
  read that name, included because the landing page's own analog table just says "ECDSA" with no
  curve specified. **Security levels are not matched between any two rows here**: a 163-bit binary
  curve is roughly an 80-bit security level (legacy/deprecated in modern practice - OpenSSL still
  ships it, NIST no longer recommends new use), while P-256 is the current ~128-bit-security
  baseline. Do not read the P-256 ratio as "DSTU 4145 is 188x worse than modern ECDSA" - part of
  that number is OpenSSL doing genuinely more expensive math for a stronger security guarantee, not
  purely an implementation-quality gap. The `nistb163` row is the fairer one, and it's still ~21-23x.

**Root cause, read from the code, not guessed**: `curve163.rs`'s own doc comment states its scalar
multiplication "always runs the full 163 iterations" - a plain constant-time double-and-add ladder,
deliberately not windowed/wNAF and with no precomputed multiples of the base point. OpenSSL's binary-
curve implementation uses windowed scalar multiplication with precomputation. **This is not the same
kind of gap as AES-NI/AVX2 above** - there's no CPU instruction-set asterisk to disclose here; it's
an algorithmic difference (iteration count and precomputation strategy), consistent with this
project's own MVP priority (`CLAUDE.md`: correctness first) and its documented constant-time
posture - a naive-but-constant-time ladder is the safe default this project chose over a
potentially-faster-but-harder-to-verify windowed implementation, not an oversight.

**Reproducing**: `openssl speed -elapsed -seconds 3 ecdsab163` / `ecdsap256` (no legacy provider or
`ia32cap` tricks needed - both curves are in the default provider on this build). `uacrypt` side:
`sign-keygen --out signing.key`, `sign-pubkey --key signing.key --out verifying.key`, a tiny
(few-byte) `--in` file, then `sign --key signing.key --in msg.bin --out msg.sig --iterations 5000`
and `verify --key verifying.key --in msg.bin --sig msg.sig --iterations 2000`.

### `verify`: classic vs. fast path (ops/s — higher is better) — T-151/D-108

Following the root cause above, `verify`'s own `s*G + r*Q` combine step (both scalars public,
unlike `sign`'s secret-nonce multiplication) got a second, faster implementation - projective
(López-Dahab) coordinates + Shamir's trick, deferring every field inversion in the computation to
one at the end, instead of the classic path's two full constant-time ladders plus their own final
inversions. Gated behind the **existing** `small-tables` Cargo feature (same one Kalyna/Kupyna/
Strumok already use for their own big-table/small-table split, same polarity: default = fast,
`small-tables` = classic, unchanged) - see `docs/DECISIONS.md` D-108 for the full design and why
this reuses that flag for a code-size/audit-surface tradeoff rather than a flash-table one.
`sign`/`verifying_key()` (secret-scalar operations) are completely unaffected - `scalar_multiply`
itself was not touched.

| Profile | verify ops/s |
|---|---|
| Default (fast path) | **239.31** |
| `small-tables` (classic, unchanged) | 120.06 |
| Speedup | **~1.99x** |

Fresh release builds this session, same key/signature/message across both binaries, both confirmed
to actually verify successfully before timing. This narrows T-150's `nistb163` gap (still ~21-23x
slower there) from the `verify` side alone by roughly half - `sign` is unaffected by this change,
so the `sign/s` numbers in the table above still reflect the classic (only) implementation.

**Reproducing**: build once with `cargo build --release -p uacrypt` (default profile) and once
with `cargo build --release -p uacrypt --features dstu-core/small-tables`, running each binary's
`verify --key ... --in ... --sig ... --iterations 5000` in turn (same `sign-keygen`/`sign-pubkey`/
`sign` setup as the table above - `sign`'s own output is unaffected by either feature, so one
signature/key pair works for both `verify` runs).

### GF(2^163) field arithmetic: bit-interleave `square` + Itoh-Tsujii `invert` — T-153/D-109

Following an owner request for a bigger win than D-108's ~1.99x (the two options originally floated
- table-based squaring and windowing `verify_combine` - were found, via an advisor-reviewed cost
analysis, to either reintroduce D-19's secret-indexing question or have a low ~1.1-1.2x ceiling; see
`docs/DECISIONS.md` D-109 for the full analysis), `gf2m163::square()` (previously
`self.multiply(self)`, zero shortcut) and `invert()` (previously a direct 162-multiply Fermat
exponentiation, despite its own doc comment naming Itoh-Tsujii as the intended approach) were
replaced with a bit-interleave squaring identity and a 9-multiply addition-chain inversion,
respectively - both **unconditional**, every build profile, including `sign`/`verifying_key()` for
the first time (D-108 explicitly left `scalar_multiply`, `sign`'s only scalar-multiplication path,
untouched).

| | `sign` ops/s | `verify` ops/s (default/fast path) | `verify` ops/s (`small-tables`/classic) |
|---|---|---|---|
| Pre-D-108 baseline (T-150) | 255.98 | 120.06 | 120.06 |
| Post-D-108 (T-151) | 255.98 (unaffected) | 239.31 | 120.06 (unaffected) |
| Post-D-109 (this entry) | **667.39** | **524.01** | **328.20** |
| Speedup vs. immediately-prior row | **~2.61x** | **~2.19x** | **~2.73x** |
| Cumulative speedup vs. pre-D-108 baseline | **~2.61x** | **~4.37x** | **~2.73x** |

Cumulatively, this narrows the `nistb163` gap from the table above to **~7.9x slower** (`sign`, was
~20.7x) and **~5.2x slower** (`verify`, was ~22.6x). The plan's own pre-committed threshold for
pursuing a further windowed `verify_combine` (Phase D) was "only if cumulative `verify` gain lands
below ~3.5x" - at ~4.37x, that threshold is already exceeded, so windowing was explicitly not
pursued this pass (see D-109's own "Phase D decision" section for the full reasoning, not repeated
here).

**Reproducing**: same binaries/setup as the table above (`cargo build --release -p uacrypt` and
`--features dstu-core/small-tables`), `sign --key signing.key --in msg.bin --out msg.sig
--iterations 5000` and `verify --key verifying.key --in msg.bin --sig msg.sig --iterations 5000` on
each binary in turn.
