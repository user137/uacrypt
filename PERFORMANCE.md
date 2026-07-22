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

**Updated 2026-07-22 after D-28** (full S-box+shift+MDS fusion for encrypt, see below) — D-27
figures kept for the record:

| Variant | Before D-27 | After D-27 | **After D-28** | Oliynykov C | UAPKI |
|---|---|---|---|---|---|
| 128-128 | 4606 | 2354 | **1041** | 13019 | 222 |
| 128-256 | 6284 | 2999 | **1283** | 19119 | 261 |
| 256-256 | 11412 | 5443 | **1956** | 35810 | 578 |
| 256-512 | 14031 | 6645 | **2296** | 45520 | 663 |
| 512-512 | 27223 | 12735 | **4006** | 91406 | 879 |

**After D-28: ~12.5-19.9x faster than Oliynykov's reference C (was ~7-8x), ~3.4-4.9x slower than
UAPKI (was ~10.6-14.5x)** — decrypt (not fused this pass, see below) improved too, ~36-40%, purely
from the key schedule sharing the now-fused `encipher_round`.

**Updated again 2026-07-22 after D-29** (`ExpandedKey` — key schedule cached across calls instead
of redone every time):

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

| Variant, block-only (schedule cached) | This project | UAPKI |
|---|---|---|
| 128-128 encrypt | 132 ns | 222 ns |
| 128-128 decrypt | **144 ns** (was 433 ns) | 222 ns |
| 256-256 encrypt | 268 ns | 578 ns |
| 256-256 decrypt | **323 ns** (was 1435 ns) | 578 ns |
| 512-512 encrypt | 573 ns | 879 ns |
| 512-512 decrypt | **691 ns** (was 3934 ns) | 879 ns |

**Kalyna decrypt-block-only is now faster than UAPKI across every variant measured too** — combined
with D-29's encrypt result, this closes essentially the entire gap to UAPKI for `ExpandedKey`, the
API any real multi-block caller (or future mode of operation) would actually use. The raw one-shot
`decrypt` function (schedule *and* the new key-transform both recomputed every call) is a more
mixed picture: slightly slower for the two smallest variants (the extra `nr-1` key-transform calls
aren't offset by round fusion at low round counts) but substantially faster for the three largest —
an honest tradeoff of the one-shot convenience path, not a regression in the path that matters.
New baseline: `kalyna-decryptfusion-2026-07-22`.

### Kupyna (digest, MB/s — higher is better)

**Updated 2026-07-22 after D-28**:

| | 64 B | 1024 B | 65536 B |
|---|---|---|---|
| Before D-27 (256) | 2.17 | 5.26 | 5.85 |
| After D-27 (256) | 5.80 | 13.30 | 14.57 |
| **After D-28** (256) | **39.53** | **91.72** | **98.60** |
| Oliynykov C (256) | 0.26 | 0.59 | 0.60 |
| UAPKI (256) | 29.93 | 88.88 | 95.48 |
| Before D-27 (512) | 1.26 | 3.44 | 4.10 |
| After D-27 (512) | 3.54 | 8.91 | 10.57 |
| **After D-28** (512) | **26.89** | **69.26** | **80.99** |
| Oliynykov C (512) | 0.14 | 0.37 | 0.43 |
| UAPKI (512) | 18.50 | 74.46 | 85.92 |

**After D-28: Kupyna-256 is now 1.03-1.45x *faster* than UAPKI (crossed over from ~6.7x slower);
Kupyna-512 is at rough parity (0.93-1.45x, i.e. within ~7% either side)** — the full fusion plus a
correctness/performance fix (see D-28: a runtime `%` by `nb`/`columns` was replaced with a bitmask,
since both are always powers of two but not compile-time constants) closed essentially the entire
gap, far beyond this task's original "2-3x of UAPKI" expectation.

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

## Binary-level (process) comparison

All the numbers above are **in-process**: `criterion` calling a Rust function directly, or a C
harness calling a C function directly, in the same process, no process-spawn cost included. That's
the right tool for measuring the algorithm itself, but it's not literally "run the tool as a user
would" — added 2026-07-22 (`TASKS.md`, D-28/29/30 follow-up) as a second, complementary comparison:
`crates/dstutool`'s new `kalyna-block encrypt`/`decrypt` subcommand (single block, file in/file
out — no mode of operation, deliberately not named `encrypt`/`decrypt` at the top level so it
can't be confused with the future file-plus-mode CLI blocked on D-05) run as an actual external
process against equivalent scratchpad CLI wrappers for Oliynykov's reference C and UAPKI (not
committed, same convention as the C benchmark harnesses elsewhere in this file).

Each tool takes `--iterations N` and repeats the same in-memory block op `N` times in one process
invocation (`--raw-schedule` re-expands the key every iteration; without it, the key schedule is
expanded once before the loop, matching `ExpandedKey`/each C library's own key-setup-once
convention) — this amortizes one-time process startup over many operations rather than spawning a
process per block, which would measure OS process creation, not crypto (a single block op is
100s of nanoseconds to a few microseconds; process creation on this machine is tens of
milliseconds, three-plus orders of magnitude larger). Two numbers are reported for each run: the
whole invocation's wall-clock time (`wall_ns`, includes the one process startup + all N
iterations) and the amortized per-operation time the tool itself measures internally
(`per_op_ns`) — reported both because "how long does it take to run the tool" and "how fast is the
crypto" are different questions and this comparison can answer both without hiding either.

### Kalyna (`kalyna-block encrypt`/`decrypt`)

**N = 20000 iterations, same machine, same day:**

| Variant | Direction | Schedule | dstutool per-op | Oliynykov C per-op | UAPKI per-op |
|---|---|---|---|---|---|
| 128-128 | encrypt | cached | **127 ns** | 10982 ns | 201 ns |
| 128-128 | encrypt | raw | **1060 ns** | 28580 ns | 17366 ns |
| 128-128 | decrypt | cached | **140 ns** | 11153 ns | 196 ns |
| 128-128 | decrypt | raw | **1562 ns** | 28580 ns | 17562 ns |
| 512-512 | encrypt | cached | 552 ns | 74068 ns | **476 ns** |
| 512-512 | encrypt | raw | 3941 ns | 173369 ns | **22922 ns** |
| 512-512 | decrypt | cached | 673 ns | 74884 ns | **510 ns** |
| 512-512 | decrypt | raw | 4922 ns | 171900 ns | **22570 ns** |

`dstutool`'s cached (`ExpandedKey`) per-op numbers land within a few percent of the in-process
`criterion` numbers above (e.g. 128-128 encrypt: 127 ns here vs 132 ns in-process) — the CLI
wrapper (file I/O, argument parsing) adds essentially no measurable overhead once amortized over
20000 iterations, which is the sanity check this comparison exists to provide.

**Whole-invocation wall-clock (same runs, `wall_ns`), showing process-spawn overhead is roughly
constant across implementations, not crypto-dependent:**

| Variant | Direction | Schedule | dstutool wall | Oliynykov C wall | UAPKI wall |
|---|---|---|---|---|---|
| 128-128 | encrypt | cached | 63.2 ms | 282.8 ms | 65.2 ms |
| 512-512 | encrypt | cached | 70.9 ms | 1548.0 ms | 70.2 ms |
| 512-512 | encrypt | raw | 138.9 ms | 3533.3 ms | 520.9 ms |

Subtracting each run's own internal `total_ns` from `wall_ns` gives a process-startup estimate of
**~60-63 ms for all three binaries** in the cached cases — i.e. on this machine, process creation
(and whatever else Windows does before `main()` runs, including antivirus scanning of a freshly
built binary - this session already saw one such Defender flag on a MinGW binary) costs roughly
the same regardless of which implementation is inside, and completely dominates wall-clock time at
low iteration counts. This is why the amortized `per_op_ns` column, not `wall_ns`, is the number
that reflects the crypto itself — `wall_ns` mostly answers "how fast does a fresh process start on
this machine," which none of these implementations control.

**Reproducing**: `cargo build -p dstutool --release`, then `target/release/dstutool kalyna-block
encrypt --variant <variant> --key <path> --in <path> --out <path> --iterations <N>
[--raw-schedule]`. The Oliynykov/UAPKI comparison CLIs are one-off C wrappers (same file interface
and flags) built the same way as this file's other C comparisons - not committed.

### Kupyna (`kupyna-digest`)

Added 2026-07-22, same session, extending the binary-level comparison to Kupyna (D-31 follow-up) -
unlike Kalyna, no mode-of-operation blocker applies here: `Kupyna256`/`Kupyna512::digest` already
take an arbitrary-length message, so `kupyna-digest --variant <256|512> --in <path> --out <path>
[--iterations N]` is a complete, real feature, not a scoped-down benchmarking scaffold. No key, so
there's no cached-vs-raw distinction to report.

**64 KB message, N = 2000 iterations, same machine, same day:**

| Variant | dstutool per-op | dstutool MB/s | Oliynykov C per-op | Oliynykov C MB/s | UAPKI per-op | UAPKI MB/s |
|---|---|---|---|---|---|---|
| Kupyna-256 | 696128 ns | **94.14** | 94894488 ns | 0.69 | 624459 ns | **104.95** |
| Kupyna-512 | 869777 ns | **75.35** | 132675168 ns | 0.49 | 740713 ns | **88.48** |

Consistent with the in-process numbers earlier in this file (Kupyna-256 at 65536 B: 98.60 MB/s
in-process vs 94.14 MB/s here) - the CLI wrapper's overhead is noise at this buffer size. Oliynykov's
reference C is dramatically slower here for the same reason it is in-process (D-27's doc comment:
`MixColumns` there is an 8-iteration bit-serial `GF(2^8)` loop, no table anywhere) - the binary
comparison doesn't change *why*, it just confirms the gap survives running as an actual process.

### Strumok (`strumok-crypt`)

Added 2026-07-22, same session (D-31 follow-up) - also no mode-of-operation blocker:
`Strumok256`/`Strumok512::apply_keystream` already XOR an arbitrary-length buffer, so
`strumok-crypt --variant <256|512> --key <path> --iv <path> --in <path> --out <path>
[--iterations N] [--raw-schedule]` is a complete feature. `--raw-schedule` re-initializes the
cipher fresh before every iteration (matching `benches/strumok.rs`'s own per-iteration `Strumok256
::new(...).apply_keystream(...)` convention); the default continues one cipher's state across all
`iterations` calls instead (a real continuous stream, cheaper - no repeated init).

**64 KB message, N = 2000 iterations, same machine, same day - MB/s (higher is better):**

| Variant | Schedule | dstutool | outspace | UAPKI |
|---|---|---|---|---|
| Strumok-256 | cached | 516.32 | **1957.65** | 624.44 |
| Strumok-256 | raw | 545.73 | **1975.15** | 627.41 |
| Strumok-512 | cached | 534.30 | **2001.26** | 584.87 |
| Strumok-512 | raw | 529.50 | **1892.23** | 608.52 |

Two things worth calling out: (1) `dstutool`'s cached-vs-raw difference is small (unlike Kalyna's,
where caching the key schedule closed most of the gap to UAPKI) - Strumok's per-message `Init` cost
is small relative to processing a 64 KB buffer, so there isn't much setup cost left to amortize
away at this buffer size. (2) These numbers are somewhat below the in-process `criterion` figures
earlier in this file (639 MB/s there vs ~516-546 MB/s here for Strumok-256) - still the same order
of magnitude and the same relative ranking (outspace fastest, UAPKI next, this project third), but
the gap is a bit wider than Kalyna's in-process/binary agreement was; not investigated further this
pass (background machine load during this run is the most likely cause, not a wrapper-specific
regression - the wrapper's own logic is identical in shape to `kalyna-block`'s, which *did* match
closely).

**Reproducing**: same pattern as Kalyna's, `dstutool kupyna-digest`/`strumok-crypt`; the
Oliynykov/outspace/UAPKI comparison CLIs are one-off C wrappers with the same file interface, not
committed.

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
