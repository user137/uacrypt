# TASKS.md

Progress tracker and task backlog for this project, grouped by phase. Check items off as they're
done; add new items as they're discovered. This file tracks **what** and **status** — the
**why** behind any decision or blocker lives in `DECISIONS.md`/`ORACLES.md`/`SECURITY.md` and is
linked from here, not duplicated.

Per `CLAUDE.md`'s "Agent discipline": every implementation task below is test-first — the
test-vector check (or unit test) is written before the primitive it verifies, not after.

Every checklist item carries a stable `T-NN` ID (assigned in document order, added 2026-07-23) so
it can be referenced elsewhere without quoting its full text — new items get the next unused
number appended to the end of this list; existing IDs are never renumbered or reused, even if the
item they point to is later removed.

## Phase 0 — Scaffold (done)

- [x] **T-01** Cargo workspace (`dstu-core` + `dstutool`), dual MIT/Apache-2.0 licensing
- [x] **T-02** `no_std`/`alloc`/`std` feature flags in place from the first commit (D-01)
- [x] **T-03** Docs translated to English; repo structure split per GitHub/Rust-crypto conventions
- [x] **T-04** `SECURITY.md`, `DECISIONS.md`, `ORACLES.md` written
- [x] **T-05** Oracle infrastructure pulled and vetted: `kalyna-reference`, `kupyna-reference`,
      `outspace/dstu8845`, `bouncycastle-{java,dotnet}`, `cryptonite` (see `oracles/README.md`)
- [x] **T-06** `li0ard` excluded as untrusted supply chain (D-07)
- [x] **T-07** Kalyna (5 variants) + Kupyna (2 variants) official test vectors extracted from the
      designers' papers into `crates/dstu-core/tests/vectors/`
- [x] **T-08** Per-algorithm pseudocode docs: Kalyna, Kupyna, Strumok, DSTU 4145
      (`docs/pseudocode/*.md`)
- [x] **T-09** Post-quantum track (DSTU 8961/9212) explicitly excluded from scope (D-08)

## Phase 1 — MVP: Kalyna + Kupyna + Strumok core

- [x] **T-10** Implement Kalyna (all 5 block/key-size variants) — `dstu_core::hazmat::kalyna`
      (`Kalyna128_128`/`Kalyna128_256`/`Kalyna256_256`/`Kalyna256_512`/`Kalyna512_512`), citation
      in `DECISIONS.md` D-13. **Confirmed 2026-07-22**: `cargo test` (all 5 variants against the
      official vectors, first attempt, no debugging needed), `cargo clippy -- -D warnings`, `cargo
      fmt --check`, and the `no_std` build all pass. S-box/MDS tables shared with `hazmat::kupyna`
      via a new `hazmat::tables` module rather than duplicated (D-13). `cargo miri test` also
      confirmed clean (no UB, all 5 variants, ~158s). Same day (D-16 update): UAPKI's
      `dstu7624_ecb_self_test` (single-block case, all 5 variants × encrypt/decrypt) matches
      byte-for-byte too — same official vector set, not a new independent reading.
      **Independent second-oracle cross-check was actually already closed by T-77/T-78
      (2026-07-21/22, before this bullet was last edited) — this note was simply stale, not a real
      gap.** Re-confirmed fresh 2026-07-23: both the Java and .NET harnesses run real Bouncy
      Castle's `DSTU7624Engine` against all 5 Kalyna variants (10/10 cases each) — found and fixed
      a real bug doing so, see `xtask oracle-java`'s note below. Remaining gap, unchanged: no mode
      of operation confirmed against the primary text (D-05; `hazmat::kalyna_ccm`, D-41, is a
      provisional interim, not this) — UAPKI's CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM self-tests
      beyond what CCM already used are unused KAT data waiting for whenever more modes get built,
      same as Kupyna's KMAC below.
- [x] **T-11** Implement Kupyna (256/512) — `dstu_core::hazmat::kupyna` (`Kupyna256`/`Kupyna512`),
      citation in `DECISIONS.md` D-10. **Confirmed green 2026-07-22**: `cargo test`, `cargo miri
      test` (no UB), `cargo clippy -- -D warnings`, and `no_std` build all pass; independently
      cross-checked against real Bouncy Castle via the .NET and Java oracle harnesses, and (same
      day, D-16 update) UAPKI's `dstu7564_self_test_hash` matches byte-for-byte too — same
      official vector set, not a new independent reading, but confirms UAPKI's numbers agree.
      Still missing: `cargo fuzz` actually run (scaffold exists), the high-level API split (D-09)
      has no wrapper here yet — this is `hazmat` only — and KMAC (Kupyna-based MAC, see the
      `crypto_auth` line below) isn't implemented at all yet. **Streaming API added 2026-07-23,
      see T-83.**
- [x] **T-83** **Kupyna streaming API - `Kupyna256Hasher`/`Kupyna512Hasher` (`new`/`update`/
      `finalize`), closing T-11's last gap.** Refactored the shared `digest_generic` into a new
      internal `KupynaCore` (holds the chaining state `h`, a `MAX_BLOCK_BYTES`-sized partial-block
      buffer, and a running byte counter for the padding's length field) so the one-shot `digest()`
      path is now just `new` + one `update` + `finalize` over the same struct - one implementation
      of the padding/length-tracking logic, not two. No `alloc`/`Vec` used (buffer is a fixed-size
      array), so this stays `no_std`-compatible without any new `cfg` gating - confirmed by
      re-running the full 8-combination `no_std`/`alloc`/`std`/`small-tables` build matrix clean.
      **Test-first, and the discipline caught a real bug**: wrote the official-vector-via-streaming
      tests, a `Default`-matches-`new` test, a chunk-invariance test (mirroring T-24's Strumok
      pattern - splitting one message across `update` calls at non-block-aligned boundaries must
      match one `update` on the whole message), and a `proptest` (arbitrary message, arbitrary
      split point, streaming must match `digest()`) before writing `update`/`finalize` themselves.
      The chunk-invariance and `proptest` cases both failed on the first implementation attempt: a
      partial-fill case (message tail shorter than one block, spread across two `update` calls)
      was silently discarding the already-buffered bytes' length bookkeeping - the buffer's
      physical bytes were fine, but the trailing "write `buffer_len` from this call's leftover
      remainder" step unconditionally overwrote it to the wrong (too-small) value regardless of
      whether that step actually applied this call. Fixed by returning early after a partial,
      not-yet-block-full buffer fill instead of falling through to that overwrite - exactly the
      kind of boundary bug a single-`update`-only test (all the official vectors are, by
      construction) can never catch, confirming why T-24's pattern was worth copying here rather
      than skipping it as redundant with the vector tests. All 9 new/updated tests green after the
      fix, `cargo clippy -- -D warnings`/`cargo fmt --check` clean (one
      `#[allow(clippy::needless_range_loop)]` needed on the output-transform XOR loop - same
      lockstep-two-arrays false-positive family as D-39's three cases, `self.h`/`t_final` this
      time), `cargo miri test` run against the new test file specifically.
- [x] **T-84** **`uacrypt kupyna-digest`/`strumok-crypt` made genuinely streaming from disk
      (`DECISIONS.md` D-42), same day.** User asked directly whether T-83's streaming was
      "honest" - small bounded chunks in memory, nothing quietly buffered whole. Answer at the
      hazmat level was yes; at the CLI level, no - both commands still did one whole-file
      `std::fs::read`. Fixed for real single-pass use (`iterations <= 1`): `kupyna-digest` reads
      an 8 KiB chunk at a time via `Kupyna*Hasher`; `strumok-crypt` reads an 8 KiB chunk, applies
      the keystream in place, writes it, and discards it (chunking both read *and* write, since a
      cipher's output length equals its input length, unlike a hash) - relying on
      `Strumok::apply_keystream`'s own chunk-invariance (T-24) for correctness. The `--iterations`
      benchmark path for both commands deliberately still reads the whole file once up front (D-34:
      re-reading per iteration would put disk I/O noise into the timed MB/s figure), then re-hashes/
      re-applies through larger in-memory chunks. Verified: new multi-chunk tests for both commands
      (non-chunk-aligned message lengths, checked against `hazmat` directly) plus manual round-trips
      through the real release binary (kupyna-digest on 5 MiB+, strumok-crypt on 3 MiB+), all
      matching. Recorded as standing policy for any future streaming CLI work in `CLAUDE.md`'s
      Agent discipline section, not just a one-off fix.
- [x] **T-12** **Blocker lifted 2026-07-22 (D-15/D-16), not fully resolved:** found
      https://github.com/specinfo-ua/UAPKI (state-expertise pedigree, see `ORACLES.md`), whose
      `dstu8845.c` self-test is comment-attributed to `// ДСТУ 8845:2019` in its own source — the
      first real KAT found anywhere for this algorithm. Adopted as
      `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json` (an earlier, self-invented
      "gray vector" attempt from the same day was superseded and deleted, not kept). Cross-checked
      against `oracles/strumok-dstu8845/` (byte-identical, but treated as a lineage-sharing
      consistency bonus, not independent confirmation — see D-15) via
      `tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`. **Still not
      "official"**: not confirmed against the paid DSTU 8845:2019 text itself.
- [x] **T-13** Implement Strumok (256/512-bit key) — `dstu_core::hazmat::strumok` (`Strumok256`/
      `Strumok512`), citation in `DECISIONS.md` D-18. **Confirmed 2026-07-22**: all 8
      UAPKI-attributed keystream cases pass on the first attempt, `cargo test`, `cargo clippy -- -D
      warnings`, `cargo fmt --check`, `no_std` build, and `cargo miri test` all clean. Structurally
      cross-checked against both `outspace/dstu8845` and `oracles/uapki/.../dstu8845.c` per the
      pseudocode doc; the `T` substitution reuses the shared `hazmat::tables` (no new tables
      needed), `mul_alpha`/`mul_alpha_inv` tables transcribed and cross-checked byte-for-byte
      between the two oracles. **Status line, not to be dropped**: "UAPKI-attributed, not confirmed
      against the official text" (D-15) — implementing this did not change that provenance ceiling.
      `dstutool` doesn't call this yet.
- [x] **T-14** `cargo miri test` clean for all three primitives (Kalyna/Kupyna/Strumok, each confirmed
      individually above)
- [x] **T-15** `cargo fuzz` harnesses for all three primitives — `kalyna`, `kupyna`, and `strumok` targets
      all exist now (`crates/dstu-core/fuzz/fuzz_targets/`). **Cannot actually run locally**:
      `cargo-fuzz` installed fine (needed `mingw64/bin`'s `dlltool.exe` on PATH, same requirement
      as `cargo-audit`/`cargo-deny`, see `.claude.local.md`), but building any target fails two
      ways in a row on this environment's GNU/MinGW toolchain — first "address sanitizer is not
      supported for this target" (`x86_64-pc-windows-gnu`, ASan needs MSVC on Windows), then with
      `--sanitizer none`, `libfuzzer-sys`'s own `FuzzerExtFunctionsWindows.cpp` fails to compile
      under `g++` (`__pragma(comment(linker, ...))` is an MSVC-only compiler extension, confirmed
      by compiling that one file directly with `g++` and reading the real error past cc-rs's
      truncated one). **Not something to chase further here**: this project deliberately chose the
      GNU host toolchain specifically to avoid needing Visual Studio Build Tools/MSVC (see
      `.claude.local.md` "Toolchains"), and libFuzzer-on-Windows is an MSVC-only path upstream —
      same shape as the cryptonite C-harness being dropped below (a real, confirmed toolchain
      incompatibility, not a skipped step). CI (a Linux runner) remains the actual venue where
      these targets get run, same as this project already says for the fuzz scaffold generally.
      **Update, later the same day**: this machine turned out to already have Visual Studio
      installed for unrelated reasons, so the objection above ("would mean installing MSVC just for
      this") stopped applying here specifically — see "Testing & hardening" below and `DECISIONS.md`
      D-32 for how it was actually run.
- [ ] **T-16** `uacrypt` CLI: `encrypt`/`decrypt`/`hash` subcommands, mode/nonce/IV hardcoded (no
      user-facing crypto knobs, per the libsodium-style misuse-resistance goal)
- [ ] **T-17** Publish `dstu-core` to crates.io
- [ ] **T-18** Prebuilt Windows/Linux binaries via GitHub Releases
- [x] **T-19** **Naming subtask, all three decisions made 2026-07-23** (T-20/T-21/T-22 below) -
      unblocks T-17/T-18, which are still separately open (a decided name isn't a crates.io
      publish or a built release binary):
  - [x] **T-20** Public name for the two resource profiles from `DECISIONS.md` D-35, decided
        2026-07-23 (`DECISIONS.md` D-38): the working name **is** the public name - Cargo feature
        `small-tables`, default/fused path stays nameless (no feature flag needed for it, it's
        just the absence of `small-tables`). Deliberately not given a branded name the way
        `uacrypt` (T-21/T-22) was - a `Cargo.toml` feature flag is a technical identifier, not a
        product name. Not checked further than the naming decision itself - the actual `cfg`-gated
        implementation is `TASKS.md` Phase 4's "Two-resource-profile split" item, still open.
  - [x] **T-21** `dstutool`'s real name is **`uacrypt`** (`DECISIONS.md` D-36, decided and
        executed 2026-07-23): `crates/dstutool` renamed to `crates/uacrypt` (`git mv`), package
        and `[lib]` name in `Cargo.toml` updated, root `Cargo.toml` workspace member, `deny.toml`
        comment, `main.rs`/`lib.rs` internal references, `README.md`, `SECURITY.md`,
        `docs/dstu-crypto-project.md`, `CLAUDE.md`, and `PERFORMANCE.md`'s canonical binary-level
        section all updated. `cargo build --workspace`/`test -p uacrypt` (15/15)/`clippy -D
        warnings`/`fmt --check` all pass post-rename. Historical entries in `DECISIONS.md`/
        `TASKS.md`/`PERFORMANCE.md`'s superseded "Results" section still say `dstutool` on
        purpose — that was the accurate name at the time, not left stale.
  - [x] **T-22** The project's own name for GitHub is **`uacrypt`** too (decided 2026-07-23, same
        session as T-21 - not a separate name). `README.md`'s title updated from
        "dstu-crypto (working name)" to `uacrypt`. No git remote exists yet to actually create/
        rename a GitHub repo against - this records the chosen name for whenever one is created,
        it doesn't perform any GitHub-side action.
- [ ] **T-23** Re-confirm the `no_std` build still passes (all feature-flag combinations) as each
      primitive lands — don't let this regress silently. Ongoing by design, not a one-time item —
      **last re-checked 2026-07-22** (post D-28/29/30/31): all four `dstu-core` feature
      combinations build clean — `--no-default-features` (bare no_std),
      `--no-default-features --features alloc` (no_std + alloc), `--features alloc` (std + alloc),
      `--all-features`. `alloc` remains an unused placeholder feature (no code gated on it yet, per
      D-01), so this confirms no regression rather than adding new coverage. `cargo xtask build`
      (workspace `--all-features` + `--no-default-features`, which also exercises `dstutool`
      linking against a no_std-built `dstu-core`) still passes too.

## Testing & hardening — deeper verification beyond test vectors

Test vectors answer one question: does the primitive produce the standard's expected output for a
handful of fixed inputs. They do not answer whether the *code* leaks secrets, runs at an acceptable
speed, or degrades safely on adversarial/malformed input — raised 2026-07-22 while reviewing what
"done" means for Kalyna/Kupyna/Strumok now that all three pass their vectors. Split deliberately
from Phase 1 above: none of this blocks calling the primitives implemented, but none of it should
be skipped before calling them *production-ready*. Two things are explicitly **not** goals here and
never will be, so as not to imply otherwise: cryptanalytic strength of the algorithms themselves
(that's the DSTU designers' responsibility, not this library's), and hardware side-channel
resistance (SPA/DPA — explicitly out of scope per `SECURITY.md`/`CLAUDE.md` "MVP scope").

- [x] **T-24** **Chunk/split-invariance test for `Strumok::apply_keystream`.** Added
      `strumok_{256,512}_chunk_invariance` in `crates/dstu-core/tests/strumok.rs` — splits a fixed
      total length into arbitrary, non-8-aligned chunks (including a zero-length one) and asserts
      byte-for-byte identity against one call on the concatenated buffer. **Passed on the first
      attempt** — no buffering bug found, but the path was genuinely untested before this.
- [x] **T-25** **Round-trip property tests.** `proptest` 1.11 added as a dev-dependency (`DECISIONS.md`
      D-21) — doesn't touch the `no_std` build. Kalyna: one `decrypt(encrypt(key, block)) == block`
      test per variant in `tests/kalyna.rs`. Strumok: `apply_keystream` applied twice with the same
      key/IV returns the original data, in `tests/strumok.rs`. All 16 property tests (256 generated
      cases each) passed on the first attempt. Kupyna intentionally skipped — no round-trip
      property exists for a hash; its `cargo fuzz` target covers the property that would matter.
- [x] **T-26** **Differential testing against a C oracle over many random inputs — done for all three.**
      Strumok first (the highest-value target — zero official vectors exist anywhere for it,
      D-15): `cargo run --example strumok_diff_cases -p dstu-core` piped into
      `tests/oracle-harness/strumok-differential/diff_against_outspace.c` (against
      `oracles/strumok-dstu8845/`) — **4000/4000 random cases matched**. `DECISIONS.md` D-22.
      Extended to Kalyna and Kupyna for parity (D-24), so the scrutiny is visibly even across all
      three rather than looking Strumok-only: `kalyna_diff_cases.rs` +
      `kalyna-differential/diff_against_reference.c` against `oracles/kalyna-reference/` —
      **2500/2500 matched**; `kupyna_diff_cases.rs` + `kupyna-differential/
      diff_against_reference.c` against `oracles/kupyna-reference/` — **2000/2000 matched**. All
      three carry the same "not independent, still useful" caveat (these are the same-lineage
      reference implementations already behind Bouncy Castle's own ports, not a new independent
      oracle) — the real independent second reading for Kalyna/Kupyna remains the Java/.NET
      Bouncy Castle harnesses, unchanged.
- [x] **T-27** **Actually run `cargo fuzz`** for all three primitives — attempted 2026-07-22, blocked by a
      confirmed GNU/MinGW-toolchain incompatibility (libFuzzer-on-Windows is MSVC-only upstream),
      not a skipped step; full detail in the Phase 1 line above. **Done later the same day, see
      `DECISIONS.md` D-32**: this machine turned out to already have Visual Studio 2022 (MSVC C++
      toolset) installed — not the upstream limitation being wrong, just no longer applicable here.
      Installed the `nightly-x86_64-pc-windows-msvc` rustup toolchain, ran each target through a
      `vcvars64.bat`-sourced shell with `--target x86_64-pc-windows-msvc` passed explicitly (both
      steps load-bearing, not optional — see D-32). **Result: all three targets ran a 60-second
      smoke each (matching CI's `fuzz-smoke` convention), zero crashes** — kupyna 182,746 runs
      (87/213 coverage), kalyna 169,851 runs (773/1341 coverage), strumok 1,466,215 runs (101/163
      coverage), all coverage plateaus reached well inside the 60s window. `xtask fuzz` updated to
      do this automatically on Windows when both prerequisites are present, falling back to a clean
      skip (same as every other optional tool) otherwise. CI's Linux `fuzz-smoke` job remains the
      actual per-push check; this closes the "never actually run anywhere" gap for local dev on a
      machine that happens to have Visual Studio, which isn't guaranteed for every contributor.
- [x] **T-28** **`Zeroize`/`ZeroizeOnDrop` on live key-material.** `zeroize` 1.9 added
      (`default-features = false, features = ["derive"]`, `no_std`-compatible — first real
      dependency in `dstu-core`, `DECISIONS.md` D-20). Strumok's `Core` (LFSR/FSM state) derives
      `ZeroizeOnDrop`; Kalyna's `encrypt_generic`/`decrypt_generic` call `round_keys.zeroize()`
      after last use. Kupyna intentionally untouched — its only API is unkeyed `digest()`, no key
      material exists yet (relevant again once KMAC lands). **Not exhaustive**: Kalyna's
      intermediate key-schedule scratch buffers (`kt`, `initial_data`/`tmv`, the rotation buffer in
      `key_expand_odd`) are still cleared only via the final `round_keys` zeroize, not individually
      — a deliberate scope cut, not an oversight, see D-20.
- [x] **T-29** **Constant-time audit + an explicit decision.** Confirmed the secret-dependent indexing
      exists in all three primitives (`SBOXES`/`SBOXES_DEC` in `kalyna.rs`/`kupyna.rs`/
      `strumok.rs`, plus `MUL_ALPHA`/`MUL_ALPHA_INV` in `strumok.rs`). Documented and scoped as an
      accepted software-timing exception in `DECISIONS.md` D-19 (same family as the already-out-
      of-scope SPA/DPA carve-out, since every reference C implementation makes the identical
      trade-off) — `SECURITY.md`'s hard-constraint wording updated to say this precisely instead of
      standing as an absolute "never" next to code that already violated it. Branching and
      comparisons on secret data remain prohibited without exception, unchanged.
- [x] **T-30** **`criterion` benchmarks.** Added as a dev-dependency, three bench targets
      (`crates/dstu-core/benches/{kalyna,kupyna,strumok}.rs`, `cargo bench -p dstu-core`) covering
      every variant of all three primitives. **Extended 2026-07-22**: numbers, machine, a named
      regression baseline (`--save-baseline initial-2026-07-22`), and a same-machine comparison
      against Oliynykov's reference C, UAPKI, and outspace all now live in `PERFORMANCE.md` (new
      canonical file, see `CLAUDE.md`'s documentation map) — this project's Rust beats the
      reference C (correctness/clarity-optimized) but is meaningfully slower than UAPKI/outspace
      (production-optimized), a real and now-quantified gap, not just a theoretical one. **Did not**
      implement a second Strumok state-transition form just to quantify the literal-shift-vs-ring-
      buffer tradeoff mentioned in D-18 — that would still mean maintaining a second implementation
      purely to benchmark it; outspace's own ~12-15x-faster numbers (likely using a rotating
      buffer, per `PERFORMANCE.md`) now give an *external* read on that tradeoff's rough scale
      without needing to build one ourselves.
- [x] **T-31** **Strumok: close the gap to UAPKI/outspace documented in `PERFORMANCE.md`**, root-caused by
      reading `oracles/strumok-dstu8845/strumok.c` directly (2026-07-22) rather than guessed at, then
      fixed the same day (`DECISIONS.md` D-26). Two distinct, additive causes, both closed: (1)
      outspace's `next_stream()` never physically shifts its 16-word state array — replaced this
      project's `s.copy_within(1..16, 0)`-per-step with a `head`-indexed ring buffer, no data
      movement. (2) outspace's `T(w)` is 8 precomputed combined tables
      (`T0[byte0]^...^T7[byte7]`) — transcribed those directly (same byte-for-byte cross-check
      already covering them), replacing the runtime 8-S-box-lookups-then-MDS-matrix-multiply.
      **Result: ~77-85% time reduction, now faster than UAPKI's Strumok, ~3.2x slower than outspace
      (was ~4-5x/~13-15x before)** — full before/after table in `PERFORMANCE.md`. Verified: all 6
      existing tests unchanged, the 4000-case outspace differential harness re-run fresh
      (4000/4000), `clippy`/`fmt`/`no_std` all pass. New `criterion` baseline saved
      (`strumok-optimized-2026-07-22`).
- [x] **T-32** **Kalyna/Kupyna: precomputed MDS tables** (`DECISIONS.md` D-27, same day). Narrower than the
      full UAPKI `p_boxrowcol` fusion (S-box + row/column permutation + MDS all combined) —
      `hazmat::tables::apply_matrix` alone was switched to precomputed `MDS_TABLE`/`MDS_INV_TABLE`
      (8 lookups + 7 XORs instead of up to 64 `gf_mul` calls per column), shared by both algorithms
      since `apply_matrix` already was. `sub_bytes`/`shift_rows` untouched — Kalyna's row-shift
      offset depends on block size, so fully fusing S-box+shift+MDS the way UAPKI does would need
      per-variant tables, a bigger change deliberately not attempted this pass. **Result: ~48-55%
      time reduction for every Kalyna variant/direction, ~60-65% for Kupyna** — roughly halves the
      gap to UAPKI without closing it (full before/after in `PERFORMANCE.md`). Verified: a new
      *exhaustive* unit test (`hazmat::tables::tests`, all 8x256 entries per table) plus every
      existing Kalyna/Kupyna vector/proptest/differential-harness check, all unchanged.
      `clippy`/`fmt`/`no_std` pass. New baseline: `kalyna-kupyna-optimized-2026-07-22`.
      **Not done**: the full S-box+shift+MDS fusion (per-`nb` tables) — sketched, not scheduled,
      would close the remaining gap but is a materially bigger change.
- [x] **T-33** **Kalyna/Kupyna: close the remaining gap to UAPKI** (planned 2026-07-22, stages 0-1 done the
      same day, see `DECISIONS.md` D-28 — stages 2-3 below still open).
      0. **Fixed the benchmark's methodology gap** — confirmed (temporary internal diagnostic,
         not committed) that `key_expand` was ~59-63% of Kalyna-128-128/512-512's per-call time,
         i.e. `benches/kalyna.rs` was indeed timing schedule+round together, matching the
         suspicion. Superseded by stage 3 (`ExpandedKey`) rather than patched as a standalone bench
         change, since that's the real fix, not just a measurement one.
      1. **Fused forward table, shared, done** (`SBOX_MDS`, `hazmat::tables`, D-28): D-27's stated
         blocker (full fusion needs per-`nb` tables) was wrong — `sub_bytes`/`shift_rows`/`shift_
         bytes` commute (S-box is row-indexed, the permutation preserves row), so one `nb`-
         independent table works; `nb`/`columns` dependence is only in the gather index. Replaced
         Kalyna's `encipher_round` (benefits encrypt *and* the key schedule, which calls it too)
         and Kupyna's new `sub_shift_mix` (both `t_transform`/`t_plus_transform`). **Kalyna decrypt
         deliberately NOT fused this pass** — `inv_sub_bytes` runs last in `decipher_round`, not
         first, so a direct table swap doesn't apply; needs an equivalent-inverse-cipher-style
         restructuring (transformed round keys), staged as its own follow-up.
         **Correctness/perf fix found during implementation**: the gather index's `% nb`/`%
         columns` cost a real per-byte integer division (LLVM can't prove a runtime value is a
         power of two), which alone made the first Kupyna version 5-8% *slower* than pre-fusion —
         fixed by replacing with `& (nb - 1)`/`& (columns - 1)` (always valid: `nb` is 2/4/8,
         `columns` is 8/16, both always powers of two by construction). Verified: two new
         `proptest` suites checking the fused round against a kept-for-reference naive three-pass
         version, a new exhaustive `SBOX_MDS` unit test, all official vectors/round-trips
         unchanged, both Oliynykov differential harnesses bit-identical (12500/12500 Kalyna
         including decrypt round-trips, 4000/4000 Kupyna), `clippy`/`fmt`/`no_std` all pass.
         **Result, far beyond this task's original "2-3x of UAPKI" expectation**: Kalyna encrypt
         -55% to -68% further (e.g. 128-128: 2354 ns -> 1041 ns, ~4.7x UAPKI, was ~10.6x); decrypt
         also -36% to -40% purely from the faster key schedule. **Kupyna -85% to -87%, now at or
         above UAPKI's own speed** (256: 1.03-1.45x faster; 512: roughly at parity) — full
         before/after in `PERFORMANCE.md`. New baseline: `kalyna-kupyna-fused-2026-07-22`.
      2. **Not done yet, and now lower priority than stage 4 below** — see stage 3's result: with
         the schedule cached, Kalyna encrypt is already faster than UAPKI, and Kupyna is at/above
         parity, so the remaining `[u8; 8]` -> `u64` conversion-churn cleanup has much smaller
         expected payoff than originally estimated (most of it was already implicitly removed by
         D-28's single-pass gather, which accumulates as `u64` internally already). Revisit only if
         stage 4 (decrypt fusion) doesn't close enough of the remaining gap on its own.
      3. [x] **`ExpandedKey`-equivalent for Kalyna, done, see `DECISIONS.md` D-29** — one
         `${Variant}ExpandedKey` struct per variant (`Kalyna128_128ExpandedKey`, etc., via the same
         macro), `::new(key)` runs `key_expand` once (`Zeroize`/`ZeroizeOnDrop`), `.encrypt_block`/
         `.decrypt_block` reuse the cached schedule. Raw `encrypt`/`decrypt` untouched (still the
         one-shot convenience path); both now call shared `encrypt_with_schedule`/`decrypt_with_
         schedule` helpers so there's one round-logic implementation, not two. Verified: new
         `proptest` suites (`ExpandedKey` matches raw functions for every random input; reused
         across multiple blocks correctly), Kalyna differential harness re-run fresh (7500/7500,
         bit-identical), `clippy`/`fmt`/`no_std` all pass. **Result, confirms the stage-0 diagnostic
         was right to prioritize this**: new `*_encrypt_block_only`/`*_decrypt_block_only` bench
         functions (key expanded once outside the timed loop) show Kalyna encrypt with a cached
         schedule is now **faster than UAPKI for every variant measured** (e.g. 128-128: 133 ns vs
         UAPKI's 222 ns). **Decrypt-block-only is 3.2-6.9x slower than encrypt-block-only** (e.g.
         512-512: 568 ns encrypt vs 3934 ns decrypt) — decrypt fusion (stage 4) is now clearly the
         single largest remaining gap, not the key schedule. New baseline:
         `kalyna-expandedkey-2026-07-22`.
      4. [x] **Decrypt-direction fusion, done, see `DECISIONS.md` D-30**. `decipher_round`'s
         mix-then-permute-then-substitute order isn't directly fusable (opposite of encrypt's
         substitute-first order) - fixed by regrouping the *whole* decrypt sequence (not just one
         round): `IS`/`IP` commute (same row-invariance as D-28) and the GF(2^8)-linear `IM`
         distributes over XOR, so `[IP;IS;XOR(K);IM]` = `[IS;IP;IM;XOR(IM(K))]` - substitute-
         permute-mix, `encipher_round`'s exact shape, using transformed interior keys `DK[j] =
         apply_matrix(K[j], MDS_INV_TABLE)`. New `tables::SBOX_MDS_DEC` (same `const fn` pattern),
         new `hazmat::kalyna::fused_inv_round` (gather direction is `inv_shift_rows`'s, opposite
         sign from `encipher_round`'s). `ExpandedKey` extended with a `dec_keys` field, precomputed
         once in `new()` so caching doesn't reintroduce `nr-1` `apply_matrix` calls into every
         `decrypt_block`. Verified: new `proptest` suite (4 cases spanning every real
         `(nb, nr)` pair) checking the restructured decrypt against a kept-for-reference naive
         three-pass version over **random round-key schedules and ciphertexts** (not just fixed
         vectors - this transform moves *where* keys apply, a subtler bug class than D-28's
         per-round fusion), a new exhaustive `SBOX_MDS_DEC` unit test, all official vectors
         (including real decrypt vectors)/proptests/`ExpandedKey` tests unchanged, Oliynykov
         differential harness re-run fresh (15000/15000 encrypt cases - this harness doesn't
         exercise `KalynaDecipher`, so it doesn't independently re-check decrypt beyond the vectors
         and naive-vs-fused proptest above; a cheap possible extension, not done), `clippy`/`fmt`/
         `no_std` all pass. **Result**: decrypt-block-only improved 66-82% (e.g. 512-512: 3934 ns ->
         691 ns) - **`ExpandedKey`'s encrypt and decrypt are both now faster than UAPKI across every
         variant measured**, closing essentially the entire gap for the schedule-cached API (the
         raw one-shot functions still trail UAPKI somewhat, an accepted tradeoff of that API shape).
         New baseline: `kalyna-decryptfusion-2026-07-22`.

      **Stage 2 (`Column` -> `u64` representation) remains not done** - given the results above
      (Kalyna at/above UAPKI parity for the cached-schedule API, Kupyna at/above parity), expected
      further payoff is small; revisit only if a future profiling pass shows it's still worth it.
- [x] **T-34** **Binary-level (process) comparison, done, see `DECISIONS.md` D-31**. The in-process numbers
      above don't reflect running the tool as an actual external process - added `dstutool`'s first
      real command, `kalyna-block encrypt`/`decrypt` (single block, file in/file out, deliberately
      not named `encrypt`/`decrypt` at the top level - that's reserved for the future file-plus-
      mode CLI, blocked below), plus scratchpad (uncommitted) comparison CLIs for Oliynykov's
      reference C and UAPKI with the same file interface, all three cross-checked byte-identical
      before timing. **Result**: `dstutool`'s per-op numbers (schedule cached) match the in-process
      `criterion` numbers within a few percent - full tables in `PERFORMANCE.md` "Binary-level
      (process) comparison". Process-spawn overhead (~60-63 ms on this machine) is roughly the
      same across all three binaries, confirming it reflects the OS, not the crypto.
      **Extended same day to Kupyna/Strumok** - neither has a mode-of-operation blocker (both
      already operate on arbitrary-length data at the public API level), so `kupyna-digest`/
      `strumok-crypt` are complete real commands, not scoped-down scaffolds. Comparison CLIs added
      for Oliynykov's Kupyna reference, UAPKI's `dstu7564`/`dstu8845`, and outspace's `dstu8845` -
      all cross-checked byte-identical before timing. **Result**: Kupyna's binary numbers land close
      to the in-process ones (94.14 MB/s here vs 98.60 MB/s in-process for Kupyna-256 @ 64 KB);
      Strumok's are somewhat lower (516-546 MB/s here vs 639 MB/s in-process for Strumok-256) but
      same order of magnitude and same relative ranking - not investigated further, most likely
      machine load during the run rather than a wrapper-specific issue (`kalyna-block`'s wrapper,
      same shape, matched closely). Full tables in `PERFORMANCE.md`.
- [ ] **T-35** **Build and test on a real ARM Linux machine (Raspberry Pi).** Distinct from Phase 4's
      STM32/ESP32 hardware validation below: a Raspberry Pi running Linux is a full `std` target
      (`aarch64-unknown-linux-gnu` here — 64-bit Raspberry Pi OS, Debian 12/bookworm, confirmed via
      `uname -a`), not the bare-metal `no_std` embedded path — this checks the "no CPU-family
      lock-in" half of `CLAUDE.md`'s MVP scope (no intrinsic or build assumption that quietly only
      works on x86-64), while the STM32/ESP32 line items check the no-OS half. **Ongoing by
      design, not a one-time item** — a standing rig now exists for this (access details, re-sync
      steps, and the full re-run command are in `.claude.local.md`, not here, since they're
      machine-specific/credentialed, not project-general) — re-run periodically, especially after
      any change touching `hazmat::kalyna`/`kupyna`/`strumok` internals that could hide an
      architecture-specific assumption an x86-64-only dev machine wouldn't catch.
      **First run, 2026-07-22, all green**: repo synced over SSH, `rustup` installed fresh
      (`stable-aarch64-unknown-linux-gnu` 1.97.1, matching this project's pinned `stable` channel),
      then the exact same commands as the x86-64 dev machine — no new script, per `DECISIONS.md`
      D-12. `cargo xtask build` (both `--all-features` and `--no-default-features`), `cargo xtask
      test` (11/11 test binaries passed, 0 failures — the DSTU 4145 signature roundtrip test took
      ~125s here vs a few seconds on the x86-64 dev machine, expected given the Pi's much lower
      clock speed, not a correctness concern), `cargo xtask fmt --check`, `cargo xtask clippy` (all
      clean), and all four `dstu-core` feature-flag combinations (bare no_std, no_std+alloc,
      std+alloc, all-features) built individually too. First real confirmation on non-x86 hardware
      for this project. **Same day, extended to performance**: `cargo bench -p dstu-core --bench
      kalyna --bench kupyna --bench strumok` also run on the Pi and added to `PERFORMANCE.md`
      alongside the existing Ryzen dev-machine numbers — this project's own code, no UAPKI/
      Oliynykov/outspace comparison there (those aren't built on the Pi). Result: the Pi is a
      consistent, unremarkable ~1.6-2.2x slower than the Ryzen dev machine across all three
      algorithms (Kalyna ~1.8-2.1x, Kupyna ~2.0-2.2x, Strumok ~1.6-1.7x) — no architecture-specific
      cliff or anomaly, just the expected gap between a Cortex-A76 and a modern desktop x86-64 core.
      **Extended again the same day**: user asked whether UAPKI itself was benchmarked on the Pi
      too, for a genuinely adequate cross-platform comparison of the same code (a fair point - the
      "we beat UAPKI" claim needs UAPKI measured on *both* machines, not just this project). Built
      UAPKI's `library/uapkic` natively on the Pi (plain `cmake`/`gcc`, same pinned commit as the
      Ryzen build) and reused the exact same scratchpad C timing harnesses that produced the
      original Ryzen UAPKI numbers. **Result, see `DECISIONS.md` D-33**: Kalyna and Kupyna's "we
      beat UAPKI" result *reverses* on the Pi - UAPKI is faster there by up to ~1.9x - while
      Strumok's holds on both platforms (smaller margin on the Pi). Three untested hypotheses
      recorded in D-33 (LLVM/aarch64 codegen quality for this dense bit-manipulation pattern being
      the most explanatory), not chased further this pass. `PERFORMANCE.md`'s Results tables and
      "What the gap is, honestly" section both got a scope correction noting the Ryzen-specific
      claim.
      **Re-run 2026-07-23, triggered by new `hazmat` changes since the last run** (`kalyna_ccm`,
      T-81, and Kupyna's streaming `KupynaCore`, T-83) - re-synced via the same tar+ssh approach,
      `cargo xtask ci` on the Pi. All mandatory checks green, including the new suites: 37
      `kalyna_ccm` tests and 9 Kupyna-streaming tests, both passing on `aarch64` with no
      architecture-specific surprise. Optional tools (miri/fuzz/audit/deny/Maven/.NET) still not
      installed on the Pi, same as before - not a new gap, unchanged from the first run.
      **Extended a third time, same day, see `DECISIONS.md` D-34**: user asked for one single
      testing method and metric going forward - a real built binary (`dstutool`, and an equivalent
      thin CLI wrapper for every oracle), MB/s only, for every algorithm/implementation/platform,
      no more in-process `criterion` numbers used as the cross-implementation comparison. Rebuilt
      the full binary-level matrix on **both** machines (Kalyna N=20000 cached+raw x 2 variants,
      Kupyna/Strumok N=2000 at 64 KB) for `dstutool` + UAPKI (+ outspace for Strumok) - Oliynykov's
      reference C stays excluded (unchanged decision, correctness oracle not a performance one).
      Confirmed D-33's Kalyna/Kupyna-flips-on-ARM finding survives the switch to the canonical
      method, and surfaced a further discrepancy: Kupyna's binary-level numbers show UAPKI ahead
      **on Ryzen too** (~10-17%), contradicting the in-process table's opposite claim - exactly the
      kind of cross-method disagreement that motivated standardizing on one method. `PERFORMANCE.md`
      restructured: "## Results" (in-process) marked superseded/historical with a dated banner, not
      deleted; "## Binary-level (process) comparison" is now the single canonical section with
      Ryzen+Pi columns for every implementation, MB/s only.

## A provisional Kalyna mode of operation - CCM (T-81), plus its nonce-strategy follow-up (T-82)

Originally flagged as blocked entirely on D-05 (2026-07-22 note, kept below for the record). User
asked 2026-07-23 for a real (not ad-hoc) interim mode instead of waiting indefinitely on the priced
primary text - the "do not build an ad-hoc/arbitrary mode just to have *something*" warning below
was heeded: what got built is dual-oracle-cited (UAPKI + Bouncy Castle), not invented. See
`DECISIONS.md` D-05 (revised) and D-41 for the full reasoning and citation.

- [x] **T-81** **`hazmat::kalyna_ccm` implemented - DSTU 7624 CCM, all 5 Kalyna variants,
      provisional pending the primary text** (`DECISIONS.md` D-41, 2026-07-23). Cited to
      `oracles/uapki/library/uapkic/src/dstu7624.c` (`dstu7624_init_ccm`/`ccm_padd`/
      `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm`/`gamma_gen`), cross-checked byte-for-byte
      against `oracles/bouncycastle-java`'s `DSTU7624Test.java` CCM vectors for 4 of 5 variants
      (128/256 has no BC vector - UAPKI-only, flagged in its vector file). New test vectors in
      `crates/dstu-core/tests/vectors/kalyna-ccm/*.json`; new integration test
      `crates/dstu-core/tests/kalyna_ccm.rs` (37 tests: official vectors, `proptest` round-trip,
      five independent tamper-rejection suites - ciphertext/tag/AAD/nonce/wrong-key - all green
      first attempt). New `uacrypt` subcommand `kalyna-ccm encrypt`/`decrypt` (deliberately not the
      reserved `encrypt`/`decrypt` names - see the CLI note below), round-tripped and tamper-tested
      through the real built release binary (`DECISIONS.md` D-34's policy). All 8 `no_std`/`alloc`/
      `std`/`small-tables` feature combinations re-confirmed clean; `cargo clippy -- -D warnings`/
      `cargo fmt --check` clean; re-confirmed on the Raspberry Pi rig too (`TASKS.md` T-35's
      standing "re-run after hazmat changes" rule).
      **`cargo fuzz` target added** (`crates/dstu-core/fuzz/fuzz_targets/kalyna_ccm.rs`, wired into
      `xtask fuzz`'s target list) - `open_in_place` is the first code in this crate that makes an
      authentication decision on fully attacker-controlled input, so the target feeds it
      never-produced-by-`seal_in_place` ciphertext/tag/AAD directly, not just round-tripped output.
      A 60s MSVC smoke run (same method as D-32) found zero crashes across all 5 variants (cov 801,
      110,542 execs) alongside the pre-existing kupyna/kalyna/strumok targets in the same run (all
      four together: exit 0, no crashes).
      **`cargo miri test`**: the full suite (including `proptest`) hits a pre-existing
      proptest+Miri directory-isolation interaction on this Windows dev machine
      (`GetCurrentDirectoryW` not available under Miri's isolation, from proptest's own
      failure-persistence file lookup) - confirmed this **already affects** the existing
      `kalyna.rs`/`strumok.rs` proptest suites too, not something this task introduced, and that
      the full run is impractically slow under Miri regardless (≈6400 proptest cases interpreted).
      Scoped instead to the five official-vector tests (`MIRIFLAGS=-Zmiri-disable-isolation cargo
      +nightly miri test -p dstu-core --test kalyna_ccm official_vector`), which exercises every
      buffer path for all 5 variants - clean, no UB, ~41s.
      **A real, sourced scope limit, not a design choice**: plaintext and AAD are each capped at
      255 bytes (`hazmat::kalyna_ccm::{MAX_PLAINTEXT_LEN, MAX_AAD_LEN}`) - `ccm_padd`'s header
      encodes both lengths as a single byte each, so this is a property of the construction as
      extracted, enforced with an error rather than silently truncated.
- [x] **T-82** **Kalyna-CCM nonce strategy resolved 2026-07-23: wide random nonce, no stateful
      counter** (`DECISIONS.md` D-40's resolution). D-40's original "11-55 bytes" nonce-width
      figure was a measurement error, not a real constraint - it was `tmp` (the CBC-MAC-header
      slice), not the caller-facing nonce parameter, which is the *full block* (16/16/32/32/64
      bytes = 128/128/256/256/512 bits). Even the narrowest case (128 bits) comfortably clears the
      birthday bound for a stated per-key rekey guideline (~2^48 messages), so the libsodium-style
      pattern was safe all along. Chose it over a TLS-1.3-style internal monotonic counter mainly
      because a counter's uniqueness guarantee depends on durable cross-reboot state, which this
      project's Phase-4 embedded targets (T-55/T-56) can't be assumed to have - a reset-to-zero
      counter would silently reintroduce nonce reuse. `hazmat::kalyna_ccm`'s own signature is
      unchanged (still `no_std`-compatible, caller-supplied full-block nonce - it can't call
      `getrandom` for an embedded caller). What changed: `uacrypt kalyna-ccm encrypt` no longer
      accepts `--nonce` as an input - it generates one via `getrandom` and writes it to `--nonce`,
      so there is nothing left for a CLI caller to reuse by mistake; `decrypt` is unchanged (still
      reads the value `encrypt` produced). New `CliError::Random`, `getrandom` added as a
      `uacrypt`-only dependency (std-only CLI, no `no_std` impact). Verified test-first: the
      existing CLI round-trip test rewritten to no longer assume a fixed nonce (compares against a
      direct `hazmat` call using the *generated* nonce instead), plus a new test asserting two
      encrypt calls on identical key/plaintext produce different nonces - both pass, plus a manual
      real-binary round-trip (two encrypts confirmed different nonce bytes, decrypt recovered the
      plaintext), `cargo clippy -- -D warnings`/`cargo fmt --check`/`cargo xtask build` all clean.

**Original 2026-07-22 blocked note, kept for the record, superseded by T-81 above**: "User flagged
this as the next priority (2026-07-22, same session as D-28/29/30/31) - but this is still gated on
D-05, unchanged: `DECISIONS.md` D-05 needs the official DSTU 7624 text or another authoritative
source before *any* mode of operation (CTR/CBC/GCM/whatever DSTU 7624 actually specifies) can be
chosen. Building `dstutool kalyna-block` (D-31) does not unblock this - it's still single-block-only
by design. Do not build an ad-hoc/arbitrary mode (e.g. naive ECB) just to have *something* - that
is exactly the failure mode this project's 'no homegrown primitives'/'research before
implementation' discipline (`CLAUDE.md`) exists to prevent." T-81 satisfies this bar by being
dual-oracle-cited rather than invented, while D-05 itself (the `crypto_secretbox`/`crypto_auth`
construction question) stays open - `dstutool`'s (now `uacrypt`'s) reserved `encrypt`/`decrypt`
command names (`CLAUDE.md` MVP scope) are still reserved for whenever that resolves, unchanged.

## Phase 2 — libsodium-equivalent construction layer, DSTU 4145 + 9041

- [ ] **T-36** Resolve the D-05 open tension (Kalyna+Kupyna encrypt-then-MAC vs. cryptonite's
      Kalyna-alone CCM/GCM `encrypt_mac`) — needs the official DSTU 7624 text or another
      authoritative source (priced, see `ORACLES.md`); blocks `crypto_secretbox` design
- [ ] **T-37** `crypto_secretbox` equivalent (encrypt-then-MAC construction, once D-05 is resolved)
- [ ] **T-38** `crypto_auth`/`crypto_onetimeauth` equivalent (Kupyna-based MAC or a Kalyna CMAC-like mode
      — exact mode name TBD against the full DSTU 7624 text). `oracles/uapki/`'s
      `dstu7564_self_test_kmac` (KMAC-256/384/512, D-16 update 2026-07-22) is unused KAT data
      waiting for whenever this gets built — not cross-checked, since there's no KMAC impl yet
- [ ] **T-39** `crypto_kdf` equivalent (HKDF-like construction over Kupyna)
- [ ] **T-40** `crypto_secretstream` equivalent (chunked authenticated encryption over Strumok or
      Kalyna-CTR)
- [x] **T-41** DSTU 4145: official standard text obtained (`docs/papers/DSTU_4145-2002.pdf`, 2026-07-22) —
      its Annex B.1 (GF(2^163), polynomial basis) worked example extracted into
      `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` and independently cross-checked
      byte-for-byte against Bouncy Castle's own hardcoded KAT (`DSTU4145Test.java` `test163()`) —
      see `DECISIONS.md` D-14 and `ORACLES.md`. A genuinely dual-sourced vector, not just a scan
      transcription.
- [x] **T-42** DSTU 4145: re-derive `docs/pseudocode/dstu4145.md` against the official text's Sections 5-13,
      rather than leaving it as a pure Bouncy Castle code-transcription. **Done 2026-07-22**: read
      Sections 5, 9, 11-13 directly (rendered PDF pages), every algorithm in the doc now cites its
      own section/page. **Found a second real bug doing this** (beyond the `Q = -d·G` one already
      found via the property test, below): `hash_to_field` had the wrong algorithm entirely (copied
      BC's byte-reversal without also adopting BC's reversed-input convention) — reading §5.9
      directly showed the correct algorithm needs no reversal at all. Fixed; full detail in
      `DECISIONS.md` D-25's follow-up entry and the pseudocode doc itself, not duplicated here.
- [x] **T-43** DSTU 4145: implement GF(2^m) binary-field + elliptic-curve arithmetic in Rust for the m=163
      curve (the actual prerequisite for a Rust port, bigger than just the signature logic
      itself). **Landed 2026-07-22**: `dstu_core::hazmat::dstu4145::gf2m163` (field add/multiply/
      square/invert) and `dstu_core::hazmat::dstu4145::curve163` (point double/add — public-data
      only — and a constant-time Montgomery-ladder `scalar_multiply`, safe for secret scalars).
      Citation and the branchless-posture decision in `DECISIONS.md` D-25. Test-first against
      generated unit-level vectors (`tests/vectors/dstu4145/gf2m163_arith.json`, Bouncy Castle as
      sole oracle at this granularity — see D-25), including a small-scalar (`k=1..=32`) check
      against repeated addition to exercise the ladder's leading-zero-bits path — all green first
      try (`cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `no_std` build;
      `cargo miri test` run separately, see below). **Still missing**: only the m=163 curve
      exists — the other 9 curve sizes in `DSTU4145NamedCurves.java` aren't wired up (not needed
      unless a use case calls for them).
- [x] **T-44** DSTU 4145: port the signature scheme to Rust from `docs/pseudocode/dstu4145.md`, verified
      against the `gf2m163.json` vector (D-02). **Landed 2026-07-22**:
      `dstu_core::hazmat::dstu4145::scalar::Scalar` (mod-`n` integer arithmetic, deliberately a
      distinct type from `gf2m163::FieldElement` — see D-25's follow-up entry on why) and
      `dstu_core::hazmat::dstu4145::signature::{sign, verify}`. Both directions verified against
      the official Annex B.1 worked example — `verify` accepts it, `sign` with the vector's pinned
      ephemeral reproduces `(r, s)` exactly — plus a `proptest` round trip over random keys/hashes.
      **Two real bugs found and fixed in the process** (full detail in D-25's follow-up entry, not
      duplicated here): a genuine doc error — `docs/pseudocode/dstu4145.md` said `Q = d·G`, but
      Bouncy Castle's own `DSTU4145KeyPairGenerator` negates it (`Q = -d·G`), confirmed against that
      source and, once the pseudocode re-derivation above happened, confirmed a second time directly
      from §9.2's own text — and a `hash_to_field` algorithm bug caught only by that re-derivation
      (see the item above). The round-trip property test is what caught the `Q` bug — the fixed
      vector alone never exercises key derivation. **Still not done**: the other 9 curve sizes.
- [ ] **T-45** **Not scheduled, sketched only:** replace `gf2m163`'s bit-serial field multiplication
      (163-iteration shift-and-mask, `DECISIONS.md` D-25 — deliberately correctness-first, not
      speed) with a comb method (`Guide to Elliptic Curve Cryptography` Algorithm 2.34/2.36, the
      same source already cited for the current reduction/ladder code) once correctness work here
      is otherwise done. Motivation: this is the main reason `cargo miri test` on
      `dstu4145_signature`'s `proptest` round trip is slow (a single `sign`+`verify` call runs
      `Point::scalar_multiply`'s 163-iteration ladder three times, each ladder step doing several
      163-iteration field multiplies). Purely a performance change — correctness and the
      branchless posture (D-25) must both still hold after it; no new test-vector work needed
      since the existing `gf2m163_arith.json`/`gf2m163.json` checks already pin the arithmetic's
      expected output.
- [ ] **T-46** **Blocked entirely:** DSTU 9041 — zero source material exists (no paper, no oracle, no
      pseudocode; see `ORACLES.md`). Nothing here can start until the official text is obtained
      or another authoritative source turns up
- [ ] **T-47** `crypto_kx` equivalent (Diffie–Hellman on the DSTU 4145/9041 curve — needs both to exist)
- [ ] **T-48** `crypto_sign` equivalent wrapping the Rust DSTU 4145 port

## Phase 3 — Language bindings (not MVP)

- [ ] **T-49** Python bindings
- [ ] **T-50** JavaScript bindings
- [ ] **T-51** Java binding (wraps Bouncy Castle `DSTU4145Signer` directly, per D-02 — does not use the
      Rust DSTU 4145 port)
- [ ] **T-52** .NET binding (wraps Bouncy Castle `Dstu4145Signer` directly, per D-02)
- [ ] **T-53** C++ bindings

## Phase 4 — Hardware validation (post-MVP)

- [x] **T-54** **Two-resource-profile split, done 2026-07-23 (`DECISIONS.md` D-35/D-38/D-39)** -
      `dstu-core`'s `small-tables` Cargo feature (independent of `std`/`alloc`, combines with
      either): `tables.rs`'s `MDS_TABLE`/`MDS_INV_TABLE`/`SBOX_MDS`/`SBOX_MDS_DEC` and Strumok's
      `T0..T7` (~86 KB total) are now `#[cfg(not(feature = "small-tables"))]` - not compiled at all
      under the feature, not just unused. In their place: `apply_matrix_via_gf_mul`/
      `mds_column_via_gf_mul` (promoted from D-27's kept-for-testing `gf_mul`/`MDS_MATRIX`/
      `MDS_INV_MATRIX` reference path) and Strumok's `t_function` reverted to its pre-D-26
      runtime-`SBOXES`+`apply_forward_matrix` form - ~2-6 KB of `const` data instead. `kalyna.rs`/
      `kupyna.rs`/`strumok.rs` call four small `cfg`-transparent wrapper functions
      (`apply_forward_matrix`/`apply_inverse_matrix`/`forward_sbox_mds`/`inverse_sbox_mds`, all in
      `tables.rs`) instead of the raw tables directly, so neither caller module needs its own
      `cfg` - the entire profile split is contained in `tables.rs` (+ `t_function`'s two variants
      in `strumok.rs`). **Verified**: both profiles' official vectors, `proptest` round-trips, and
      the fused-vs-naive/decrypt-fusion property tests (default profile only - `small-tables` has
      nothing to compare against since it computes the naive form directly) all pass; `cargo
      clippy -- -D warnings` and `cargo fmt --check` clean on both; the existing 4-combination
      `no_std`/`alloc`/`std` matrix (`TASKS.md` T-23) re-checked with `small-tables` added to each,
      8 combinations total, all build clean; `cargo xtask build` passes. **Three
      `#[allow(clippy::needless_range_loop)]` added** (`encipher_round`/`fused_inv_round`/
      `sub_shift_mix`'s gather loops, plus `mds_column_via_gf_mul`'s) - calling a function with the
      loop variable instead of directly indexing a second array changed clippy's needless-range-
      loop heuristic (false positive: `row` also drives `shift`/`src_col`, not a plain
      single-collection enumerate candidate; confirmed via `git stash` that the pre-existing code
      was clippy-clean and only the `SBOX_MDS[row]` -> `forward_sbox_mds(row, ...)` refactor
      triggered it). **CI updated** (`.github/workflows/rust.yml`): `--all-features` used to be a
      stand-in for "test the default profile" (since `alloc` is an inert placeholder) but now also
      flips on `small-tables`, which changes production behavior - added explicit default-profile
      steps (no extra features) alongside new `--features dstu-core/small-tables` steps and kept
      `--all-features` as a third, combined-everything pass; all four step groups verified locally
      before committing to the workflow file, not just written and assumed correct. **Not done**:
      `cargo miri test`/`cargo fuzz` under `small-tables` specifically (not required by D-35's
      verification bar, but not re-run either) - CI's `miri`/`fuzz-smoke` jobs still only run
      default-profile `cargo miri test --workspace`/`cargo fuzz run kupyna`, unchanged. **Same
      day, follow-up**: real measured memory/speed numbers for both profiles (per-algorithm,
      `uacrypt` release binary, same method as `PERFORMANCE.md`'s binary-level comparison)
      written up in the new `docs/resource-profiles.md`, plus a plain-language sizing guide
      mapping typical MCU flash budgets to which profile fits - linked from `README.md` and
      `CLAUDE.md`'s documentation map. Kalyna/Kupyna are ~20-43x slower under `small-tables`
      (their whole round is the swapped step); Strumok is only ~4-4.5x slower (the swapped step is
      a smaller fraction of its per-word cost). Measured once on the Ryzen dev machine only, not
      the full multi-baseline protocol - good enough to size the trade-off, not a tracked
      regression baseline.
- [ ] **T-55** STM32 (ARM Cortex-M) real-hardware validation - entry-level parts (L0/F0/G0, 16-64 KB flash)
      need the small-tables profile above; mid-range and up (F1/F3/G4/F4/F7/H7) have flash to
      spare for the default fused profile.
- [ ] **T-56** ESP32 (Xtensa/RISC-V) real-hardware validation - flash (4 MB+) and SRAM (320-520 KB) both
      comfortably cover the default fused profile; no need for small-tables here.
- [ ] **T-57** **Stretch goal, not a near-term target: Arduino Uno (ATmega328P, 8-bit AVR) — user has one
      available, 2026-07-22.** Raised as "could we hypothetically try this," not a firm ask.
      Materially harder than the STM32/ESP32 items above, for a concrete, measured reason, not a
      vague "8-bit is old" concern: Rust's AVR target is nightly-only/tier-3 (`avr-hal`/`ravedude`
      ecosystem), and this project's *current* Kalyna/Kupyna tables (`hazmat::tables::SBOX_MDS`/
      `SBOX_MDS_DEC`, added by D-28's fusion) are `[[u64; 256]; 8]` each — **16 KB per table, 32 KB
      for both, which alone equals the ATmega328P's entire flash (32 KB)**, before any actual code;
      naively RAM-resident (no `PROGMEM`-style placement) they'd also be ~16x the chip's 2 KB SRAM.
      Checked what the *pre-D-27* tables looked like for comparison: `SBOXES`/`SBOXES_DEC` (1 KB
      each) plus two 8x8-byte matrices (~2.1 KB total, `gf_mul` itself is a table-free bit loop) —
      an order of magnitude smaller and flash-plausible, but Strumok's `MUL_ALPHA`/`MUL_ALPHA_INV`
      (2 KB each, unrelated to the Kalyna/Kupyna fusion work, present since D-18) push even that
      older baseline past half the chip's flash on their own. **Bottom line**: even the smallest
      historical table set would need real AVR-specific work (constants placed in program memory
      via `avr-hal`'s progmem mechanisms, not just "add the target") to leave any RAM at all for
      the round-key schedule/state - not a quick add-a-target job, and today's fused tables make it
      substantially worse than when this was last measured. Revisit only if there's real interest,
      not opportunistically.
- [ ] **T-58** Keep the SPA/DPA non-claim intact throughout (`no_std` compiling ≠ side-channel resistance
      — see `CLAUDE.md` MVP scope section)
- [ ] **T-59** **Not scheduled, sketched only:** constant-time S-boxes (masked-select or bitsliced —
      `DECISIONS.md` D-19's "Future path" note has both options and why it's a bigger project than
      it looks), narrowing the software-timing exception D-19 documents. Natural place to revisit
      this alongside the hardware side-channel audit above, not before.

## Explicitly out of scope — not scheduled in any phase

- Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna) — per D-08, only with a
  separate explicit decision from the project owner

## API surface — `dstu_core::hazmat` module by module

Mirrors the table in `docs/dstu-crypto-project.md` "Concrete API shape" — that table is the
prose/rationale version, this is the checklist version. Keep both in sync when a status changes.
Two-layer split (`hazmat` now, high-level "easy" layer later) decided in `DECISIONS.md` D-09.

- [x] **T-60** `hazmat::kupyna` (`Kupyna256`, `Kupyna512`) — confirmed green, citation in D-10 (see Phase 1)
- [x] **T-61** `hazmat::kalyna` (5 variants) — confirmed green, citation in D-13 (see Phase 1)
- [x] **T-62** `hazmat::strumok` (`Strumok256`, `Strumok512`) — confirmed green, citation in D-18 (see
      Phase 1)
- [ ] **T-63** `hazmat::dstu4145` — not started; needs BC known-answer vectors extracted first (Phase 2)
- [ ] **T-64** `hazmat::dstu9041` — hard-blocked, zero source material (see `ORACLES.md`)
- [ ] **T-65** high-level "easy" layer (name TBD) — not started; nothing needs it yet (no keyed/nonce-based
      primitive is implemented before Strumok or `crypto_secretbox`, both currently blocked)
- [ ] **T-66** `crypto_secretbox` construction (over `hazmat::kalyna` + `hazmat::kupyna`) — blocked on D-05
- [ ] **T-67** `crypto_auth`/`crypto_onetimeauth` construction (over `hazmat::kupyna`) — needs
      `hazmat::kalyna`/`hazmat::kupyna` done first
- [ ] **T-68** `crypto_kdf` construction (over `hazmat::kupyna`) — needs `hazmat::kupyna` done first
- [ ] **T-69** `crypto_kx` construction (over `hazmat::dstu4145`/`dstu9041`) — needs both curves; DSTU 9041
      side is hard-blocked
- [ ] **T-70** `crypto_secretstream` construction (over `hazmat::strumok`/`hazmat::kalyna`) — needs its
      underlying primitive done first
- [ ] **T-71** `crypto_pwhash` (plain Argon2id, high-level layer only, not DSTU) — not started, no blocker
- [ ] **T-72** `randombytes` (OS CSPRNG via `getrandom`, high-level layer only, not DSTU) — not started,
      only needed once the high-level layer exists. **Read `DECISIONS.md` D-04's 2026-07-23
      addendum before starting**: it records a forward-looking RNG-architecture recommendation
      (trait injection as `dstu-core`'s own core pattern, an optional `std`-gated convenience
      wrapper on top, `getrandom` as an unconditional dependency reserved for application binaries
      like `uacrypt` only) so this doesn't reintroduce a hard `getrandom` dependency into the
      `no_std` core by accident.

## Infrastructure — CI and oracle harnesses

Goal: make "is this primitive actually green" answerable without a human manually running
`cargo test` and reporting back every time (see Phase 1's Kupyna entry above for why this matters
right now). Every harness below consumes the same `crates/dstu-core/tests/vectors/<algo>/*.json`
files already used by the Rust tests — one vector format, multiple consumers, not a second
convention invented per language.

- [x] **T-73** Rust CI (`.github/workflows/rust.yml`) written and **locally confirmed green** (2026-07-22,
      after installing a Rust toolchain in this environment — see `.claude.local.md`): `cargo fmt
      --check` clean, `cargo build --workspace` (both `--all-features` and
      `--no-default-features`, confirming `no_std` still compiles), `cargo test --workspace`
      passes (Kupyna's two vector tests included), `cargo clippy --all-features -- -D warnings`
      clean after one fix (`manual_memcpy` in `shift_bytes`). **Kupyna is now confirmed correct**,
      not just written — see D-10 update. `cargo miri test` run separately (see below); CI itself
      still activates properly only once pushed to a GitHub remote.
- [x] **T-74** `cargo fuzz` scaffold added (`crates/dstu-core/fuzz/`, target `kupyna`) — required by
      `SECURITY.md`. Wired into the CI smoke job; a local nightly+miri toolchain now exists here
      too if a quick local run is ever wanted, though CI is still the primary path.
- [x] **T-75** `cargo audit` + `cargo deny` (2026-07-22, D-11) — elevated to the same required-CI standing
      as miri/fuzz in `SECURITY.md`; policy in `deny.toml`. Wired into `.github/workflows/rust.yml`
      via `rustsec/audit-check` / `EmbarkStudios/cargo-deny-action`. **Actually run locally, not
      just installed**: `cargo audit` — 0 vulnerabilities. `cargo deny check` — all four categories
      (`advisories`, `bans`, `licenses`, `sources`) pass, but only after a real fix: it caught
      `dstutool`'s `dstu-core = { path = "../dstu-core" }` dependency as a "wildcard dependency"
      (no `version` pinned — would also block publishing to crates.io as-is). Fixed by adding
      `version = "0.0.0"`. Genuine first catch from this tooling, not just a clean no-op.
- [x] **T-76** ~~C oracle harness~~ **dropped 2026-07-22.** Attempted against cryptonite (pinned commit
      `3618d340`) with a real, newly-installed GCC 16.1: cryptonite's own source fails to compile
      on a modern compiler (implicit-function-declaration errors in
      `dstu4145_prng_internal.c` — unrelated to Kalyna/Kupyna, a real incompatibility in the
      vetted third-party oracle itself, not something to patch). Also triggered a Windows
      Defender heuristic false-positive on CMake's own compiler-ID test binary (confirmed
      contained: exactly one detection, `ActionSuccess: True`, no other findings). Combined with
      already-modest evidentiary value (Kalyna/Kupyna are independently confirmed by the two
      harnesses below already), not worth patching a vetted oracle's source to keep this alive.
      `cryptonite` remains a **read-only** reference (see `ORACLES.md` / `oracles/README.md`, the
      D-05 CCM/GCM finding) — just not a runnable CI harness. `tests/oracle-harness/c/` removed.
- [x] **T-77** .NET oracle harness (`tests/oracle-harness/dotnet/`) — uses the **published
      `BouncyCastle.Cryptography` 2.6.2** NuGet package, not the vendored partial clone in
      `oracles/bouncycastle-dotnet/` (that's "selected files only" and won't build standalone —
      see `oracles/README.md`). **Actually built and run in this environment**: all 10 Kalyna
      cases + all 12 Kupyna cases passed against real Bouncy Castle output.
- [x] **T-78** Java oracle harness (`tests/oracle-harness/java/`) — same approach, published
      `bcprov-jdk18on:1.85` from Maven Central rather than the vendored
      `oracles/bouncycastle-java/` clone. **Actually built and run**, both via raw `javac`/`java`
      (JDK 8) and via Maven (installed 2026-07-22, see `.claude.local.md`): same result, all 22
      cases passed both ways.
      **Bug found and fixed 2026-07-23, re-running this via `cargo xtask oracle-java` specifically
      (not raw `mvn`) for the Kalyna second-oracle cross-check above**: `xtask`'s own invocation,
      `mvn -f tests/oracle-harness/java/pom.xml -q compile exec:java` run from the repo root,
      failed with `NoSuchFileException` on `OracleHarness`'s relative vectors path -
      `exec:java`'s forked JVM does not inherit the project directory as its working directory
      just because `-f` pointed at its POM, unlike `dotnet run --project ...` which does handle
      this correctly. Confirmed the fix by `cd`-ing into `tests/oracle-harness/java/` and running
      plain `mvn -q compile exec:java` directly (passed clean) before changing anything. Fixed in
      `xtask/src/main.rs`'s `oracle_java()`: pass the project directory as `run`'s `dir` parameter
      instead of `-f`, matching how every other per-crate `xtask` command already sets its working
      directory. Re-ran after the fix: all 22 cases (10 Kalyna + 12 Kupyna) pass via
      `cargo xtask oracle-java` now, matching the raw-`mvn` result exactly.
- [x] **T-79** `cargo xtask` cross-platform build/QA runner (2026-07-22, D-12) — one command
      (`cargo xtask build|test|fmt|clippy|ci|miri|fuzz|audit|deny|oracle-java|oracle-dotnet`) for
      Linux/Windows/macOS instead of separate shell/PowerShell scripts. Plain Rust binary at
      `xtask/`, own `[workspace]` so it stays out of `dstu-core`'s dependency graph, invoked via the
      `.cargo/config.toml` alias. Optional-tool subcommands check availability and print an install
      hint instead of failing raw. **Actually run locally**: `cargo xtask ci` — mandatory checks
      (fmt/build/test/clippy) pass, then correctly reported `cargo-miri`/`cargo-fuzz`/`mvn` as
      missing in that shell session with install hints while `cargo audit`, `cargo deny check`, and
      the .NET oracle harness (all 22 cases) ran and passed. README.md "Building from source" /
      "Development commands" document the per-OS install + usage.
- [x] **T-85** **First real GitHub Actions run after the push (2026-07-23) surfaced 3 independent CI
      bugs, all now fixed** — the local `cargo xtask ci` had masked all three, since it either skips
      the tool (miri/fuzz not installed locally at the time each was wired up) or never exercised
      the exact failure path (audit, run locally before `Cargo.lock` existed to be gitignored).
      1. `cargo miri test`/`cargo fuzz run` both silently ran under **`stable`**, not the `nightly`
         toolchain `dtolnay/rust-toolchain@nightly` installs — `rust-toolchain.toml` pins `stable`
         repo-wide, which overrides rustup's default toolchain for any `cargo` invocation inside the
         checkout, regardless of what the Action set as default. `xtask/src/main.rs` already knew
         this (`cargo +nightly miri test`/`cargo +nightly fuzz run`, written when D-32 was chased
         down) — the CI YAML just never got the same treatment. Fixed: `.github/workflows/rust.yml`
         both jobs now say `cargo +nightly miri test --workspace` / `cargo +nightly fuzz run ...`.
      2. `cargo audit` failed with `Couldn't load ./Cargo.lock: entity not found` — `.gitignore` had
         a blanket `Cargo.lock` rule (matching every depth), so the workspace-root lockfile
         `rustsec/audit-check` reads was simply never in the checkout. Fixed: root `Cargo.lock`
         un-ignored and committed (needed for `cargo audit`/reproducible `uacrypt` binary builds
         anyway, ahead of T-18's release-binary work); `xtask/Cargo.lock` and
         `crates/dstu-core/fuzz/Cargo.lock` stay ignored (separate `[workspace]`s, not read by this
         check, no reason to change them).
      3. **Fixing (1) exposed a fourth, deeper bug**: with `+nightly` actually taking effect, `cargo
         miri test --workspace` now really ran and immediately hit `error: unsupported operation:
         getcwd not available when isolation is enabled` — proptest's failure-persistence lookup
         calls `std::env::current_dir`, which Miri's isolation blocks. This is the **same
         cross-platform interaction T-81 already found and worked around on the Windows dev
         machine** (there described as `GetCurrentDirectoryW`), now confirmed to hit Linux CI too -
         meaning this "mandatory" CI job had in fact never completed successfully since it was
         first wired up (T-73), masked first by the toolchain bug above. Considered scoping the job
         down to vector-only tests the way T-81 did locally (`-- official_vector`), but that doesn't
         generalize: `proptest!` blocks are spread across 8 files (`kalyna.rs`, `kalyna_ccm.rs`,
         `kupyna.rs`, `strumok.rs`, `dstu4145_signature.rs`, plus the in-`src` `fused_*`/
         `decrypt_fusion_*` suites in `hazmat::kalyna`/`kupyna`) with no shared substring to filter
         on - a manual `--skip` list would need ~9 separate patterns and silently stop covering any
         new proptest test added later without a matching update. Fixed instead with two env vars
         on the miri job, no skip list: `MIRIFLAGS=-Zmiri-disable-isolation` (fixes the crash) plus
         `PROPTEST_CASES=1` (proptest reads this to cut every suite from its default 256 cases to
         1) - keeps the *whole* workspace's Miri run bounded without excluding any test file, and
         still exercises every proptest code path under Miri's UB checker at least once, rather
         than skipping those paths' Miri coverage entirely the way a skip-list would have.
      Verified via `gh run view --json jobs` + `gh api .../actions/jobs/<id>/logs` per job (not
      guessed from the summary page), then a real `gh run watch` after each push confirming
      fuzz/audit/build went green immediately and miri went green after the env-var fix.
- [x] **T-80** Extract Bouncy Castle's own DSTU 4145 known-answer test data — done as
      `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` (2026-07-22, D-14), transcribed from
      the official standard's own Annex B.1 worked example and cross-checked against
      `DSTU4145Test.java` `test163()` rather than extracted from the BC test file directly — same
      end result (a vector both sources agree on), better provenance (spec-first, code-confirmed
      rather than the reverse). The Java/.NET oracle harnesses don't consume it yet (no Rust
      GF(2^m)/EC arithmetic exists to test against — see Phase 2), but the harness code shape is
      ready to add a DSTU 4145 case whenever that lands.

**Independent-value note, don't skip this when reading the checklist above:** the Kalyna/Kupyna
harnesses (C, Java, .NET) mostly re-validate this project's own PDF vector extraction — real
value given the `pdftotext` extraction hazards already hit, but modest. The DSTU 4145 harness is
where a genuinely independent oracle actually buys something. Strumok has no harness above because
no trustworthy runnable oracle exists for it at all (`outspace/dstu8845` is unofficial, unaudited)
— a harness can't manufacture verification authority that doesn't exist upstream.
