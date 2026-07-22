# Performance

Canonical home for this project's benchmark numbers, methodology, and comparisons against other
implementations. `DECISIONS.md` D-23 records *why* benchmarking exists at all and links here
rather than duplicating the numbers; update this file, not D-23, when new numbers are measured.

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

**Machine**: AMD Ryzen 5 PRO 4650U (6 cores / 12 threads, ~2.1 GHz base), Windows 11 Pro.
**Recorded**: 2026-07-22.

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

## Results

### Kalyna (single-block encrypt, nanoseconds — lower is better)

**Updated 2026-07-22 after D-27** (precomputed `MDS_TABLE`, see below) — pre-D-27 figures kept for
the record:

| Variant | This project, before D-27 | This project, **after D-27** | Oliynykov C | UAPKI |
|---|---|---|---|---|
| 128-128 | 4606 | **2354** | 13019 | 222 |
| 128-256 | 6284 | **2999** | 19119 | 261 |
| 256-256 | 11412 | **5443** | 35810 | 578 |
| 256-512 | 14031 | **6645** | 45520 | 663 |
| 512-512 | 27223 | **12735** | 91406 | 879 |

**After D-27: ~7-8x faster than Oliynykov's reference C (was ~3-4x), ~10.6-14.5x slower than UAPKI
(was ~17-31x)** — roughly halves the gap to UAPKI without closing it (see "What the gap is,
honestly" for why some of it remains).

### Kupyna (digest, MB/s — higher is better)

**Updated 2026-07-22 after D-27**:

| | 64 B | 1024 B | 65536 B |
|---|---|---|---|
| This project, before D-27 (256) | 2.17 | 5.26 | 5.85 |
| This project, **after D-27** (256) | 5.80 | 13.30 | **14.57** |
| Oliynykov C (256) | 0.26 | 0.59 | 0.60 |
| UAPKI (256) | 29.93 | 88.88 | 95.48 |
| This project, before D-27 (512) | 1.26 | 3.44 | 4.10 |
| This project, **after D-27** (512) | 3.54 | 8.91 | **10.57** |
| Oliynykov C (512) | 0.14 | 0.37 | 0.43 |
| UAPKI (512) | 18.50 | 74.46 | 85.92 |

**After D-27: ~24-25x faster than Oliynykov's reference C (was ~9-12x), ~6.6-8.1x slower than
UAPKI (was ~14-21x)** — same "roughly halves the gap" story as Kalyna.

### Strumok (`apply_keystream`, MB/s — higher is better)

**Updated 2026-07-22 after D-26** (ring buffer + precomputed `T0..T7` tables, see below) — figures
before that change are kept for the record, not deleted, since they're the actual measurement the
optimization was checked against:

| | 64 B | 1024 B | 65536 B |
|---|---|---|---|
| This project, before D-26 (256) | 29.36 | 118.67 | 144.27 |
| This project, **after D-26** (256) | 195.86 | 553.58 | **639.47** |
| outspace (256) | 198.89 | 1461.07 | 2055.05 |
| UAPKI (256) | 132.60 | 442.73 | 588.71 |
| This project, before D-26 (512) | 30.31 | 115.92 | 145.61 |
| This project, **after D-26** (512) | 198.70 | 545.19 | **639.83** |
| outspace (512) | 230.29 | 1443.74 | 2131.68 |
| UAPKI (512) | 103.28 | 511.11 | 556.20 |

**After D-26: now *faster* than UAPKI's Strumok, ~3.2x slower than outspace** (was ~4-5x slower
than UAPKI, ~13-15x slower than outspace, before). No naive/reference-grade Strumok implementation
exists to compare against for the "correctness-first" side of this story — see `ORACLES.md`, no
official DSTU 8845 reference implementation is publicly known to exist.

## What the gap is, honestly

This project's MVP deliberately chose correctness and `no_std`/embedded-portability first
(`CLAUDE.md` MVP scope) over speed. The gap to UAPKI/outspace is real and has concrete, confirmed
causes — read directly from the other implementations' source, not guessed at (`TASKS.md` has the
sketched-not-scheduled task for closing this):

- **Kalyna/Kupyna, partially fixed 2026-07-22, see D-27**: `hazmat::tables`' shared `apply_matrix`
  used to compute every `GF(2^8)` multiplication via `gf_mul` at call time (up to 64 per column) —
  now a precomputed `MDS_TABLE`/`MDS_INV_TABLE` (8 lookups + 7 XORs instead), roughly halving the
  gap to UAPKI (see the tables above). The remaining gap is UAPKI's `p_boxrowcol` combining S-box
  *and* the row/column permutation into the same lookup, which this project's `sub_bytes` ->
  `shift_rows` -> `apply_matrix` still does as three separate passes — deliberately not attempted
  this pass (D-27's "narrower scope" note): Kalyna's row-shift offset depends on block size
  (`nb`), so fully fusing it would need per-variant tables, a bigger change than "one shared
  function, both algorithms benefit at once."
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

`initial-2026-07-22` is now superseded for both Kalyna/Kupyna (by `kalyna-kupyna-optimized-2026-07
-22`) and Strumok (by `strumok-optimized-2026-07-22`) — kept only as the historical "before either
optimization" record, not the one to check new changes against.

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
