# TASKS.md

Progress tracker and task backlog for this project, grouped by phase. Check items off as they're
done; add new items as they're discovered. This file tracks **what** and **status** — the
**why** behind any decision or blocker lives in `DECISIONS.md`/`ORACLES.md`/`SECURITY.md` and is
linked from here, not duplicated.

Per `CLAUDE.md`'s "Agent discipline": every implementation task below is test-first — the
test-vector check (or unit test) is written before the primitive it verifies, not after.

## Phase 0 — Scaffold (done)

- [x] Cargo workspace (`dstu-core` + `dstutool`), dual MIT/Apache-2.0 licensing
- [x] `no_std`/`alloc`/`std` feature flags in place from the first commit (D-01)
- [x] Docs translated to English; repo structure split per GitHub/Rust-crypto conventions
- [x] `SECURITY.md`, `DECISIONS.md`, `ORACLES.md` written
- [x] Oracle infrastructure pulled and vetted: `kalyna-reference`, `kupyna-reference`,
      `outspace/dstu8845`, `bouncycastle-{java,dotnet}`, `cryptonite` (see `oracles/README.md`)
- [x] `li0ard` excluded as untrusted supply chain (D-07)
- [x] Kalyna (5 variants) + Kupyna (2 variants) official test vectors extracted from the
      designers' papers into `crates/dstu-core/tests/vectors/`
- [x] Per-algorithm pseudocode docs: Kalyna, Kupyna, Strumok, DSTU 4145
      (`docs/pseudocode/*.md`)
- [x] Post-quantum track (DSTU 8961/9212) explicitly excluded from scope (D-08)

## Phase 1 — MVP: Kalyna + Kupyna + Strumok core

- [x] Implement Kalyna (all 5 block/key-size variants) — `dstu_core::hazmat::kalyna`
      (`Kalyna128_128`/`Kalyna128_256`/`Kalyna256_256`/`Kalyna256_512`/`Kalyna512_512`), citation
      in `DECISIONS.md` D-13. **Confirmed 2026-07-22**: `cargo test` (all 5 variants against the
      official vectors, first attempt, no debugging needed), `cargo clippy -- -D warnings`, `cargo
      fmt --check`, and the `no_std` build all pass. S-box/MDS tables shared with `hazmat::kupyna`
      via a new `hazmat::tables` module rather than duplicated (D-13). `cargo miri test` also
      confirmed clean (no UB, all 5 variants, ~158s). Same day (D-16 update): UAPKI's
      `dstu7624_ecb_self_test` (single-block case, all 5 variants × encrypt/decrypt) matches
      byte-for-byte too — same official vector set, not a new independent reading. Still open: no
      independent second-oracle cross-check (Java/.NET harnesses don't cover Kalyna vectors yet),
      no mode of operation (D-05) — UAPKI's CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM self-tests are
      unused KAT data waiting for whenever modes get built, same as Kupyna's KMAC below —
      `dstutool` doesn't call this yet.
- [x] Implement Kupyna (256/512) — `dstu_core::hazmat::kupyna` (`Kupyna256`/`Kupyna512`),
      citation in `DECISIONS.md` D-10. **Confirmed green 2026-07-22**: `cargo test`, `cargo miri
      test` (no UB), `cargo clippy -- -D warnings`, and `no_std` build all pass; independently
      cross-checked against real Bouncy Castle via the .NET and Java oracle harnesses, and (same
      day, D-16 update) UAPKI's `dstu7564_self_test_hash` matches byte-for-byte too — same
      official vector set, not a new independent reading, but confirms UAPKI's numbers agree.
      Still missing: `cargo fuzz` actually run (scaffold exists), the streaming
      (`update`/`finalize`) API (current API is one-shot `digest()` only), the high-level API
      split (D-09) has no wrapper here yet — this is `hazmat` only — and KMAC (Kupyna-based MAC,
      see the `crypto_auth` line below) isn't implemented at all yet.
- [x] **Blocker lifted 2026-07-22 (D-15/D-16), not fully resolved:** found
      https://github.com/specinfo-ua/UAPKI (state-expertise pedigree, see `ORACLES.md`), whose
      `dstu8845.c` self-test is comment-attributed to `// ДСТУ 8845:2019` in its own source — the
      first real KAT found anywhere for this algorithm. Adopted as
      `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json` (an earlier, self-invented
      "gray vector" attempt from the same day was superseded and deleted, not kept). Cross-checked
      against `oracles/strumok-dstu8845/` (byte-identical, but treated as a lineage-sharing
      consistency bonus, not independent confirmation — see D-15) via
      `tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`. **Still not
      "official"**: not confirmed against the paid DSTU 8845:2019 text itself.
- [x] Implement Strumok (256/512-bit key) — `dstu_core::hazmat::strumok` (`Strumok256`/
      `Strumok512`), citation in `DECISIONS.md` D-18. **Confirmed 2026-07-22**: all 8
      UAPKI-attributed keystream cases pass on the first attempt, `cargo test`, `cargo clippy -- -D
      warnings`, `cargo fmt --check`, `no_std` build, and `cargo miri test` all clean. Structurally
      cross-checked against both `outspace/dstu8845` and `oracles/uapki/.../dstu8845.c` per the
      pseudocode doc; the `T` substitution reuses the shared `hazmat::tables` (no new tables
      needed), `mul_alpha`/`mul_alpha_inv` tables transcribed and cross-checked byte-for-byte
      between the two oracles. **Status line, not to be dropped**: "UAPKI-attributed, not confirmed
      against the official text" (D-15) — implementing this did not change that provenance ceiling.
      `dstutool` doesn't call this yet.
- [x] `cargo miri test` clean for all three primitives (Kalyna/Kupyna/Strumok, each confirmed
      individually above)
- [ ] `cargo fuzz` harnesses for all three primitives
- [ ] `dstutool` CLI: `encrypt`/`decrypt`/`hash` subcommands, mode/nonce/IV hardcoded (no
      user-facing crypto knobs, per the libsodium-style misuse-resistance goal)
- [ ] Publish `dstu-core` to crates.io
- [ ] Prebuilt Windows/Linux binaries via GitHub Releases
- [ ] Re-confirm the `no_std` build still passes (all feature-flag combinations) as each
      primitive lands — don't let this regress silently

## Phase 2 — libsodium-equivalent construction layer, DSTU 4145 + 9041

- [ ] Resolve the D-05 open tension (Kalyna+Kupyna encrypt-then-MAC vs. cryptonite's
      Kalyna-alone CCM/GCM `encrypt_mac`) — needs the official DSTU 7624 text or another
      authoritative source (priced, see `ORACLES.md`); blocks `crypto_secretbox` design
- [ ] `crypto_secretbox` equivalent (encrypt-then-MAC construction, once D-05 is resolved)
- [ ] `crypto_auth`/`crypto_onetimeauth` equivalent (Kupyna-based MAC or a Kalyna CMAC-like mode
      — exact mode name TBD against the full DSTU 7624 text). `oracles/uapki/`'s
      `dstu7564_self_test_kmac` (KMAC-256/384/512, D-16 update 2026-07-22) is unused KAT data
      waiting for whenever this gets built — not cross-checked, since there's no KMAC impl yet
- [ ] `crypto_kdf` equivalent (HKDF-like construction over Kupyna)
- [ ] `crypto_secretstream` equivalent (chunked authenticated encryption over Strumok or
      Kalyna-CTR)
- [x] DSTU 4145: official standard text obtained (`docs/papers/DSTU_4145-2002.pdf`, 2026-07-22) —
      its Annex B.1 (GF(2^163), polynomial basis) worked example extracted into
      `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` and independently cross-checked
      byte-for-byte against Bouncy Castle's own hardcoded KAT (`DSTU4145Test.java` `test163()`) —
      see `DECISIONS.md` D-14 and `ORACLES.md`. A genuinely dual-sourced vector, not just a scan
      transcription.
- [ ] DSTU 4145: re-derive `docs/pseudocode/dstu4145.md` against the official text's Sections 5-13
      now that they exist, rather than leaving it as a pure Bouncy Castle code-transcription (see
      the doc's 2026-07-22 update note)
- [ ] DSTU 4145: implement GF(2^m) binary-field + elliptic-curve arithmetic in Rust (does not
      exist in the tree yet — this is the actual prerequisite for a Rust port, bigger than just
      the signature logic itself)
- [ ] DSTU 4145: port the signature scheme to Rust from `docs/pseudocode/dstu4145.md` (once
      re-derived), verified against the `gf2m163.json` vector and Bouncy Castle as the oracle (D-02)
- [ ] **Blocked entirely:** DSTU 9041 — zero source material exists (no paper, no oracle, no
      pseudocode; see `ORACLES.md`). Nothing here can start until the official text is obtained
      or another authoritative source turns up
- [ ] `crypto_kx` equivalent (Diffie–Hellman on the DSTU 4145/9041 curve — needs both to exist)
- [ ] `crypto_sign` equivalent wrapping the Rust DSTU 4145 port

## Phase 3 — Language bindings (not MVP)

- [ ] Python bindings
- [ ] JavaScript bindings
- [ ] Java binding (wraps Bouncy Castle `DSTU4145Signer` directly, per D-02 — does not use the
      Rust DSTU 4145 port)
- [ ] .NET binding (wraps Bouncy Castle `Dstu4145Signer` directly, per D-02)
- [ ] C++ bindings

## Phase 4 — Hardware validation (post-MVP)

- [ ] STM32 (ARM Cortex-M) real-hardware validation
- [ ] ESP32 (Xtensa/RISC-V) real-hardware validation
- [ ] Keep the SPA/DPA non-claim intact throughout (`no_std` compiling ≠ side-channel resistance
      — see `CLAUDE.md` MVP scope section)

## Explicitly out of scope — not scheduled in any phase

- Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna) — per D-08, only with a
  separate explicit decision from the project owner

## API surface — `dstu_core::hazmat` module by module

Mirrors the table in `docs/dstu-crypto-project.md` "Concrete API shape" — that table is the
prose/rationale version, this is the checklist version. Keep both in sync when a status changes.
Two-layer split (`hazmat` now, high-level "easy" layer later) decided in `DECISIONS.md` D-09.

- [x] `hazmat::kupyna` (`Kupyna256`, `Kupyna512`) — confirmed green, citation in D-10 (see Phase 1)
- [x] `hazmat::kalyna` (5 variants) — confirmed green, citation in D-13 (see Phase 1)
- [x] `hazmat::strumok` (`Strumok256`, `Strumok512`) — confirmed green, citation in D-18 (see
      Phase 1)
- [ ] `hazmat::dstu4145` — not started; needs BC known-answer vectors extracted first (Phase 2)
- [ ] `hazmat::dstu9041` — hard-blocked, zero source material (see `ORACLES.md`)
- [ ] high-level "easy" layer (name TBD) — not started; nothing needs it yet (no keyed/nonce-based
      primitive is implemented before Strumok or `crypto_secretbox`, both currently blocked)
- [ ] `crypto_secretbox` construction (over `hazmat::kalyna` + `hazmat::kupyna`) — blocked on D-05
- [ ] `crypto_auth`/`crypto_onetimeauth` construction (over `hazmat::kupyna`) — needs
      `hazmat::kalyna`/`hazmat::kupyna` done first
- [ ] `crypto_kdf` construction (over `hazmat::kupyna`) — needs `hazmat::kupyna` done first
- [ ] `crypto_kx` construction (over `hazmat::dstu4145`/`dstu9041`) — needs both curves; DSTU 9041
      side is hard-blocked
- [ ] `crypto_secretstream` construction (over `hazmat::strumok`/`hazmat::kalyna`) — needs its
      underlying primitive done first
- [ ] `crypto_pwhash` (plain Argon2id, high-level layer only, not DSTU) — not started, no blocker
- [ ] `randombytes` (OS CSPRNG via `getrandom`, high-level layer only, not DSTU) — not started,
      only needed once the high-level layer exists

## Infrastructure — CI and oracle harnesses

Goal: make "is this primitive actually green" answerable without a human manually running
`cargo test` and reporting back every time (see Phase 1's Kupyna entry above for why this matters
right now). Every harness below consumes the same `crates/dstu-core/tests/vectors/<algo>/*.json`
files already used by the Rust tests — one vector format, multiple consumers, not a second
convention invented per language.

- [x] Rust CI (`.github/workflows/rust.yml`) written and **locally confirmed green** (2026-07-22,
      after installing a Rust toolchain in this environment — see `.claude.local.md`): `cargo fmt
      --check` clean, `cargo build --workspace` (both `--all-features` and
      `--no-default-features`, confirming `no_std` still compiles), `cargo test --workspace`
      passes (Kupyna's two vector tests included), `cargo clippy --all-features -- -D warnings`
      clean after one fix (`manual_memcpy` in `shift_bytes`). **Kupyna is now confirmed correct**,
      not just written — see D-10 update. `cargo miri test` run separately (see below); CI itself
      still activates properly only once pushed to a GitHub remote.
- [x] `cargo fuzz` scaffold added (`crates/dstu-core/fuzz/`, target `kupyna`) — required by
      `SECURITY.md`. Wired into the CI smoke job; a local nightly+miri toolchain now exists here
      too if a quick local run is ever wanted, though CI is still the primary path.
- [x] `cargo audit` + `cargo deny` (2026-07-22, D-11) — elevated to the same required-CI standing
      as miri/fuzz in `SECURITY.md`; policy in `deny.toml`. Wired into `.github/workflows/rust.yml`
      via `rustsec/audit-check` / `EmbarkStudios/cargo-deny-action`. **Actually run locally, not
      just installed**: `cargo audit` — 0 vulnerabilities. `cargo deny check` — all four categories
      (`advisories`, `bans`, `licenses`, `sources`) pass, but only after a real fix: it caught
      `dstutool`'s `dstu-core = { path = "../dstu-core" }` dependency as a "wildcard dependency"
      (no `version` pinned — would also block publishing to crates.io as-is). Fixed by adding
      `version = "0.0.0"`. Genuine first catch from this tooling, not just a clean no-op.
- [x] ~~C oracle harness~~ **dropped 2026-07-22.** Attempted against cryptonite (pinned commit
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
- [x] .NET oracle harness (`tests/oracle-harness/dotnet/`) — uses the **published
      `BouncyCastle.Cryptography` 2.6.2** NuGet package, not the vendored partial clone in
      `oracles/bouncycastle-dotnet/` (that's "selected files only" and won't build standalone —
      see `oracles/README.md`). **Actually built and run in this environment**: all 10 Kalyna
      cases + all 12 Kupyna cases passed against real Bouncy Castle output.
- [x] Java oracle harness (`tests/oracle-harness/java/`) — same approach, published
      `bcprov-jdk18on:1.85` from Maven Central rather than the vendored
      `oracles/bouncycastle-java/` clone. **Actually built and run**, both via raw `javac`/`java`
      (JDK 8) and via Maven (installed 2026-07-22, see `.claude.local.md`): same result, all 22
      cases passed both ways.
- [x] `cargo xtask` cross-platform build/QA runner (2026-07-22, D-12) — one command
      (`cargo xtask build|test|fmt|clippy|ci|miri|fuzz|audit|deny|oracle-java|oracle-dotnet`) for
      Linux/Windows/macOS instead of separate shell/PowerShell scripts. Plain Rust binary at
      `xtask/`, own `[workspace]` so it stays out of `dstu-core`'s dependency graph, invoked via the
      `.cargo/config.toml` alias. Optional-tool subcommands check availability and print an install
      hint instead of failing raw. **Actually run locally**: `cargo xtask ci` — mandatory checks
      (fmt/build/test/clippy) pass, then correctly reported `cargo-miri`/`cargo-fuzz`/`mvn` as
      missing in that shell session with install hints while `cargo audit`, `cargo deny check`, and
      the .NET oracle harness (all 22 cases) ran and passed. README.md "Building from source" /
      "Development commands" document the per-OS install + usage.
- [x] Extract Bouncy Castle's own DSTU 4145 known-answer test data — done as
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
