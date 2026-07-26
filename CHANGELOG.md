# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-07-26

First tagged release - GitHub Releases only (`TASKS.md` T-18); not published to crates.io
(`TASKS.md` T-17 stays separately gated on an explicit owner request). Everything below predates
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
  `SECURITY.md`/`DECISIONS.md` for the full provisional-status caveats.
- No independent third-party security audit has been performed. `no_std` compiling is not a
  side-channel-resistance claim.
