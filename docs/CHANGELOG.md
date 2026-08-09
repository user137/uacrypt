# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `hazmat::dstu9041`: DSTU 9041:2020 hybrid (ECIES-style) asymmetric encryption over a twisted
  Edwards curve, `l(p)=256`/E256/1 only (D-47's "ship the recommended curve first" precedent) -
  `F_p` bignum arithmetic, twisted-Edwards point arithmetic, and encrypt/decrypt composition,
  verified against the standard's own worked example (`docs/TASKS.md` T-177).
- `crypto_box`: public-key encryption over `hazmat::dstu9041`, hybrid via KDF (a random seed sealed
  asymmetrically, expanded via `hazmat::kupyna_kdf`, then `crypto_secretstream` encrypts the actual
  message) - `seal`/`open`/`SecretKey`/`PublicKey` (32-byte compressed, `x`-coordinate only,
  `docs/TASKS.md` T-178, `docs/DECISIONS.md` D-169). `uacrypt box-keygen`/`box-pubkey`/`box-seal`/
  `box-open` CLI surface.
- `hazmat::dstu4145`: a second curve, `m=257` (`gf2m257`/`curve257`/`scalar257`/`signature257`) -
  what real Diia-issued qualified signatures actually use in production (confirmed from real
  issued certificates, not just the standard's own curve table), alongside the existing `m=163`.
  `crypto_sign257` wraps it as a full sibling of `crypto_sign` (`SigningKey`/`VerifyingKey`/
  `Signature`, deterministic Kupyna-KMAC nonce). `uacrypt sign-keygen257`/`sign-pubkey257`/
  `sign257` CLI surface; `uacrypt verify` reads a curve tag byte from `--key` and handles both
  `m=163` and `m=257` signatures through the one command (`docs/TASKS.md` T-199, `docs/DECISIONS.md`
  D-185/D-186).
- `uacrypt`: real binary-level (subprocess) smoke tests, `crates/uacrypt/tests/` - 49 tests
  spawning the actual compiled `uacrypt` binary (exit codes, stdout/stderr, real files), covering
  every leaf command's golden path plus targeted attack scenarios (T-199's tagged-verifying-key
  format, `crypto_secretstream`'s wire-format tamper resistance, cross-key-type confusion between
  same-length key files). Previously the entire 140-test suite only ever called the library's
  `run()` in-process (`docs/TASKS.md` T-200).

### Changed

- `hazmat::gf2m_wide`/`hazmat::dstu4145::gf2m163`: `multiply()` now dispatches to a hardware
  carry-less-multiply implementation (`PCLMULQDQ`/`PMULL`) at runtime when the CPU supports it and
  the `std` feature is enabled, falling back to the existing portable software path otherwise -
  `no_std`/embedded builds and CPUs without the instruction are unaffected. Real measured speedups:
  Kalyna-GCM 256-256 throughput up ~2.2-4.6x on top of the already-landed word-wise `reduce` fix,
  DSTU 4145 `sign`/`verify` up ~26-32x on the dev machine (`docs/TASKS.md` T-198,
  `docs/DECISIONS.md` D-184).

## [0.2.0] - 2026-08-02

Second tagged release - GitHub Releases only, no crates.io publish (`docs/TASKS.md` T-17 stays
separately gated, same posture as v0.1.0).

### Added

- `crypto_sign`/`uacrypt`: DSTU 4145 digital-signature CLI commands - `sign-keygen`, `sign-pubkey`,
  `sign`, `verify` (`docs/TASKS.md` T-124).
- `dstu-core`: `getrandom` Cargo feature - a `no_std`-compatible RNG path via `getrandom` 0.3's
  link-time custom backend, for targets without `std` (T-123, `docs/DECISIONS.md` D-74).
- Official Strumok-256/512 supplementary test vectors from two additional state-sourced supplements
  (beyond the existing UAPKI-attributed set), D-104.
- Kani bounded-model-check proofs for `gf2m163::reduce`'s two previously hand-argued claims,
  checked exhaustively over all 2^384 possible inputs (T-145).
- CodeQL advanced-setup CI migration, explicit least-privilege CI permissions (T-143); SonarCloud
  static analysis wired into CI (T-140).

### Fixed

- DSTU 4145 `scalar_multiply` returned a wrong result for scalars at/near the curve's own group
  order - reachable in-contract at exactly one boundary value (`k == n-1`). No forgery risk
  (confirmed via an independent Bouncy Castle cross-check), but a genuine correctness bug every
  `sign`/`verify` call went through. See `docs/DECISIONS.md` D-110.

### Changed

- Performance: DSTU 4145 `sign` ~2.6x faster, `verify` ~4.4x faster (cumulative) - bit-interleave
  GF(2^163) squaring and an Itoh-Tsujii addition-chain field inversion, plus a projective/Shamir's-
  trick fast path for `verify`'s public-scalar combine step. Narrows the gap to OpenSSL's
  `nistb163` from ~21-23x to ~5-8x slower. See `docs/DECISIONS.md` D-108/D-109, `docs/PERFORMANCE.md`.
- Kalyna: const-generic round functions close most of the block-cipher gap with the UAPKI reference
  (T-128); the GCM/GMAC field-multiply bottleneck closed via a 4-bit comb multiply (T-125);
  CMAC/GMAC/KW gain a cached-schedule API surface, XTS gains a faster `GF(2^m)` doubling
  (T-126/T-127).
- Kupyna gains a const-generic compression function (T-134); Strumok's keystream generation is
  batched/fixed-index (T-135).

### Notes

- No breaking changes in the public `crypto_*`/`hazmat` API surface. `uacrypt`'s on-disk
  `encrypt`/`decrypt` wire format was already changed pre-1.0 in a prior, unreleased state (the
  chunked `crypto_secretstream` format) - not part of this release specifically.
- **Language bindings (`bindings/`) and the C ABI crate (`crates/dstu-core-capi`) are not part of
  this release** - none of the eight bindings (Python/Node/Ruby/PHP/.NET/Java/Go/C++, all done as
  of 2026-08-03, `docs/bindings-strategy.md`) or the C ABI crate itself have ever shipped in a
  tagged GitHub Release; this file only records what actually releases (crates.io/GitHub Releases),
  not every landed change - per-binding status lives in `docs/TASKS.md`/`docs/bindings-strategy.md`
  instead.
- Still pre-1.0, not audited, and **not a claim of side-channel resistance**.

## [0.1.0] - 2026-07-26

First tagged release - GitHub Releases only (`docs/TASKS.md` T-18); not published to crates.io
(`docs/TASKS.md` T-17 stays separately gated on an explicit owner request). Everything below predates
this tag; there is no reconstructed per-commit history before it.

### Added

- `dstu-core`: `hazmat` primitives for all three in-scope DSTU algorithms - Kupyna (DSTU
  7564:2014, one-shot and streaming), Kalyna (DSTU 7624:2014, single-block encrypt/decrypt across
  all five key/block-size variants), and Strumok (DSTU 8845:2019, keystream generation).
- `dstu-core`: full DSTU 7624 mode-of-operation coverage over Kalyna - ECB, CBC, CFB, OFB, CTR,
  CMAC, KW, CCM, GCM/GMAC, and XTS.
- `dstu-core`: DSTU 4145-2002 digital signatures (`hazmat::dstu4145`, deterministic nonce
  derivation).
- `dstu-core`: libsodium-shaped high-level `crypto_*` frontend over the above -
  `crypto_secretbox`, `crypto_secretstream` (chunked/streaming AEAD), `crypto_generichash`,
  `crypto_auth`, `crypto_kdf`, `crypto_stream`, `crypto_sign`, `crypto_pwhash` (Argon2id, not a
  DSTU primitive), `randombytes`.
- `dstu-core`: `no_std`/`alloc`/`std` feature gating, plus an independent `small-tables` resource
  profile for constrained targets. Cross-compilation confirmed for `thumbv7em-none-eabihf`
  (STM32 Cortex-M) and `riscv32imc-unknown-none-elf` (ESP32-C3-class RISC-V).
- `uacrypt`: CLI binary over `dstu-core` - `keygen` (fresh 32-byte key from the OS CSPRNG),
  `encrypt`/`decrypt` (over `crypto_secretstream`, genuinely chunked disk I/O), `hash`
  (Kupyna-256), plus `hazmat`-scoped multi-variant tools (`kalyna-block`, `kalyna-ccm`,
  `kupyna-digest`, `strumok-crypt`). Plain-language `--help`/`-h` for every command, `--version`/
  `-V` at the top level.
- Official DSTU test vectors for Kalyna, Kupyna, and DSTU 4145; dual-oracle verification
  (Bouncy Castle Java/.NET harnesses) for Kalyna and Kupyna.

### Changed

- `uacrypt encrypt`/`decrypt`'s on-disk wire format changed twice pre-release: originally a
  single-shot `crypto_secretbox` blob (255-byte cap), then migrated to uncapped `crypto_secretbox`
  over Kalyna-GCM, then to the current genuinely chunked `crypto_secretstream` format. Each change
  is a breaking format change from the one before it - acceptable pre-1.0 and pre-publication, not
  covered by any compatibility guarantee.

### Notes

- Kalyna-alone AEAD mode-of-operation (D-05) and the Strumok test vectors (D-15) are provisional:
  adopted on corroborating evidence, not confirmed against the primary DSTU text. See
  `docs/SECURITY.md`/`docs/DECISIONS.md` for the full provisional-status caveats.
- No independent third-party security audit has been performed. `no_std` compiling is not a
  side-channel-resistance claim.
