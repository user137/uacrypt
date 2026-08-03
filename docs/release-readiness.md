# Release readiness: what a genuine libsodium-equivalent 1.0 needs

Requested 2026-07-23 (same session as `docs/DECISIONS.md` D-43's `0.0.0` -> `0.1.0` version bump): a gap
analysis between where this project actually is and the user's stated release goal — a full
libsodium-style API with matching command surface and documentation, published to crates.io as a
complete, built-and-tested algorithm set, where **every mode of operation included is current and
safe**, not provisional. This document is that analysis. It synthesizes existing tracking
(`docs/TASKS.md`, `docs/DECISIONS.md`, `docs/dstu-crypto-project.md`'s API mapping, `docs/SECURITY.md`) rather than
duplicating it — update the source-of-truth file first when something here changes, then this
document's summary.

**See also `docs/user-journey-gaps.md` (`docs/TASKS.md` T-114)** for a persona/journey-organized
companion view — it surfaces gaps this document's construction-organized framing doesn't (e.g. no
`uacrypt keygen` command, no bare-metal cross-compile ever run) rather than duplicating this
document's findings.

## Headline finding

**Updated 2026-07-24: D-05 is no longer formally open — adopted as a working assumption, still not
primary-text-confirmed.** `docs/DECISIONS.md` D-05 — whether Kalyna alone is DSTU 7624's intended AEAD
construction, or whether confidentiality + integrity requires a separate Kalyna+Kupyna
encrypt-then-MAC design — was resolved on assumption at the project owner's explicit direction:
**Kalyna-alone** (CCM/GCM/KW), not encrypt-then-MAC. This is corroborated by two independent
non-primary sources agreeing mode-for-mode (this project's own already-vendored `oracles/uapki/`
ten-mode self-test list, and Ukrainian Wikipedia's independently-sourced ten-mode table for the
"Калина (шифр)" article — see `docs/DECISIONS.md` D-05's 2026-07-24 revision for the full table and
sourcing caveats), on top of D-41's existing UAPKI+Bouncy-Castle reference-implementation evidence.
**This is still not a reading of the priced primary DSTU 7624:2014 text** — it remains unpurchased,
and this decision is explicitly provisional, to be revised again (not silently) if that text is
ever acquired and contradicts it. The practical effect: what was a hard blocker is now a "build
against this working hypothesis" situation:

- `hazmat::kalyna_ccm` (D-41) is unchanged — still dual-oracle-verified, still not
  primary-text-confirmed, but now also matches the standard's own official mode list per both
  sources above (mode #8, "Вироблення імітовставки і гамування").
- Strumok's vector set is UAPKI-attributed, plus (D-104) independently confirmed
  against two state-sourced supplementary vectors from Держспецзв'язку/ДНДІ ТКЗІ — still not
  confirmed against the paid DSTU 8845:2019 text itself (D-15/D-16) — a separate, unrelated gap on
  a different algorithm, unaffected by D-05.
- **`crypto_secretbox` (T-37) is done, see `docs/DECISIONS.md` D-51** — a single fixed construction,
  internally-generated nonce, combined `nonce || ciphertext || tag` output, no caller-facing AAD
  parameter. **Migrated 2026-07-25 from Kalyna-CCM to Kalyna-GCM** (roadmap Step 3 item 1,
  `docs/DECISIONS.md` D-63) — `hazmat::kalyna_gcm::Kalyna256_256Gcm`, not all five variants, per D-47's
  "delete the knob" criterion. **The 255-byte cap is gone entirely, not just raised**
  (`SecretboxError::MessageTooLong` was removed, not left dormant) — GCM encodes no length into its
  construction the way CCM's header did. This does not make `uacrypt encrypt`/`decrypt` streaming:
  `--in` is still read whole into memory, so a large file now means a correspondingly large buffer
  rather than a rejection. Still provisional (inherits `hazmat::kalyna_gcm`'s D-56
  not-primary-confirmed status). One security-relevant detail the migration surfaced: unlike CCM,
  DSTU Kalyna-GCM's tag does not cover the IV/nonce at all (D-56 divergence 3) — for a
  self-contained `nonce || ciphertext || tag` blob that would have silently regressed
  tamper-evidence on the nonce prefix, so `seal`/`open` now pass the nonce itself as `kalyna_gcm`'s
  AAD internally to bind it into the tag (still no caller-facing AAD parameter). Caught by a test
  during the migration, not assumed — see D-63.
- `crypto_secretstream` (T-40/T-70) — **Done 2026-07-25, see `docs/DECISIONS.md` D-68.** The D-05-blocking
  concern (an ad hoc Strumok+KMAC EtM gap-fill would silently resolve D-05) no longer applied once
  D-05 got an adopted answer, and the construction that landed doesn't touch that question anyway —
  it's built over the already-decided `hazmat::kalyna_gcm` (D-56), a from-scratch tag-per-chunk
  framing (no DSTU streaming-AEAD standard exists, D-47's tie-breaker, libsodium's
  `crypto_secretstream_xchacha20poly1305` shape) rather than a new EtM composition. `dstu_core::
  crypto_secretstream` (`PushState`/`PullState`) is genuinely chunked - reads and writes fixed-size
  blocks rather than the whole file at once, closing the gap this bullet used to describe as open.
  `uacrypt encrypt`/`decrypt` were rewired onto it the same session (breaking wire-format change
  from the old `crypto_secretbox`-backed blob format, called out explicitly, acceptable pre-1.0).
  `crypto_secretbox` itself is unchanged and not removed - still the whole-buffer primitive for
  small/one-shot messages, still inherits `hazmat::kalyna_gcm`'s D-56 not-primary-confirmed status,
  same as `crypto_secretstream` does. `hazmat::kalyna_ccm`'s own 255-byte plaintext/AAD cap (D-41)
  remains real and unrelated - neither `crypto_secretbox` nor `crypto_secretstream` uses it.

A release billed as "current, safe modes" still cannot honestly ship on top of an
assumption-adopted, non-primary-confirmed construction without saying so exactly as loudly as
`docs/DECISIONS.md`/`docs/TASKS.md` already do internally — closing that gap fully still needs either (a)
acquiring the primary DSTU 7624:2014/8845:2019 texts and re-verifying against them, or (b) shipping
1.0 with the provisional status stated prominently in the public API/docs. (a) got meaningfully
cheaper to consider today (two new corroborating sources, no purchase) but hasn't happened; (b) is
what D-47 names as a reusable fallback rather than an ad hoc one. The choice between "keep looking
for the primary text" and "ship on the current assumption" remains the owner's to make explicitly.

## What's actually done (the solid part)

Three primitives are implemented and confirmed against official test vectors, each with an
independent second-oracle cross-check (Bouncy Castle, Java and .NET):

| Algorithm | Standard | Status |
|---|---|---|
| Kalyna | DSTU 7624:2014 | All 5 block/key-size variants, single-block encrypt/decrypt, `ExpandedKey` API. Vector-confirmed + dual-oracle. **Mode of operation: all 10/10 DSTU 7624 modes now implemented at `hazmat`**, updated 2026-07-25 (T-99) — ECB/CBC/OFB/CTR/CFB (Stage A), CMAC/KW/GCM/GMAC (Stage B-D, D-54-D-57), XTS (Stage E, T-96/D-58) all landed since this table's last real update. CCM/GCM/KW are the three combined (confidentiality+integrity) modes and the only ones eligible for a public `crypto_secretbox`-style entry point (D-47); ECB/CBC/OFB/CTR/CFB/XTS are confidentiality-only, bare CMAC/GMAC are integrity-only — none of those six may become a public `encrypt`/`decrypt` entry point on their own. All ten still share CCM's original caveat: dual-oracle-verified (UAPKI + Bouncy Castle where available), not primary-DSTU-7624:2014-text-confirmed. |
| Kupyna | DSTU 7564:2014 | Both 256/512 variants, one-shot `digest()` and streaming `Hasher`. Vector-confirmed + dual-oracle. KMAC (`crypto_auth` equivalent) now implemented too — `hazmat::kupyna_kmac`, dual-oracle with both constructions read (`docs/TASKS.md` T-38, `docs/DECISIONS.md` D-44), same provisional-pending-primary-text caveat. KDF (`crypto_kdf` equivalent) built on top of that KMAC — `hazmat::kupyna_kdf` (T-39, D-45); no DSTU standard or reference implementation exists for this construction at all, so unlike the KMAC row there is no oracle vector, ever — verified by determinism/distinctness property tests only. |
| Strumok | DSTU 8845:2019 | Both 256/512-bit key variants, keystream `apply_keystream`. UAPKI-attributed vectors, plus (D-104) two independently-sourced supplementary vectors from Держспецзв'язку/ДНДІ ТКЗІ — a real second, state-sourced oracle, though still **not** confirmed against the primary standard text itself (D-15/D-16); that specific gap remains a provenance ceiling, not a code-quality gap. |

DSTU 4145-2002 (digital signatures): the m=163 curve's `GF(2^163)` field arithmetic, point
add/double/constant-time scalar multiplication, and `sign`/`verify` are all implemented
(`hazmat::dstu4145`), verified against the official standard's own Annex B.1 worked example plus a
`proptest` round-trip, with two real bugs (a `Q = d·G` vs `Q = -d·G` sign error, a `hash_to_field`
calling-convention bug) found and fixed by re-deriving from the primary text directly rather than
trusting a single reference-implementation transcription (`docs/DECISIONS.md` D-25). **The high-level
`crypto_sign` wrapper is also done** (T-48, D-46 — a stale "no wrapper exists yet" claim
here, and a stale "table is out of date" claim about `docs/dstu-crypto-project.md`'s own mapping
table, are both corrected 2026-07-24; that table has been current on this point since T-48 landed) —
`dstu_core::crypto_sign::{SigningKey, VerifyingKey, Signature}`, deterministic (Kupyna-KMAC-derived)
nonce, no RNG dependency. Only the m=163 curve is wired up (9 other named curve sizes in Bouncy
Castle's own enumeration are not).

Engineering infrastructure that a real release needs is genuinely in place: `no_std`/`alloc`/`std`
feature-flag split confirmed across 8 build combinations including a `small-tables` constrained-MCU
resource profile (D-35/D-38/D-39); `cargo audit`/`cargo deny` in CI; a cross-platform `cargo xtask`
build/QA runner (D-12); binary-level (not just in-process) performance comparisons against
UAPKI/reference-C on both x86-64 and a real Raspberry Pi ARM64 rig (`docs/PERFORMANCE.md`, D-34);
zeroization of key material (D-20); a documented, scoped constant-time exception for
S-box/GF-multiplication table lookups, matching every reference implementation (D-19).

**Updated 2026-07-25 (T-99)**: `cargo miri test` **passed in CI for the first time in this
project's history** 2026-07-25 (37m55s, `gh run view 30157361074`) — a stale "wired into CI (with
the proptest+Miri-isolation interaction just fixed, T-85)" claim here understated the actual
history, since the job had *never* completed on any push before T-100 (D-59): it went from a
config-bug fast-fail, to a 30-minute timeout on every push for over a day, to a real pass only after
tagging every EC-ladder/field-inversion-heavy test `#[cfg_attr(miri, ignore)]` and raising
`timeout-minutes` to 150 with real measurement behind the number. `cargo fuzz`'s CI coverage was
also incomplete until this same day: `fuzz-smoke` ran only the `kupyna` target (T-98/D-61) — now a
9-target matrix covering every mode with a fuzz harness, including five (`kalyna_cmac`/`kw`/`gcm`/
`gmac`/`cfb`) that had none at all before, `kalyna_cfb` (T-91/T-101) being the sharpest of those
gaps.

## What's missing for the libsodium-equivalent surface

From `docs/dstu-crypto-project.md`'s own mapping table, the two-layer design (D-09: `hazmat::*` now,
a future high-level `crypto_*`-ergonomics layer on top) is decided; `crypto_sign` (below) is now the
first primitive with that high-level layer actually built, via `dstu_core::crypto_sign` — notably
*without* the `getrandom`-based auto-nonce shape D-09 originally anticipated (D-46's deterministic
nonce needs no RNG at all). `crypto_auth`/`crypto_kdf` are done too (T-38/T-39, D-44/D-45), now with
high-level wrappers as well (T-105, D-66, roadmap Step 3 item 2, 2026-07-25). `crypto_generichash`
also got its high-level module the same day (T-105, D-66) — a bare re-export, not a new wrapper
(see the table below for why). `crypto_stream` got its high-level wrapper too, same roadmap Step,
one day later (item 3, `docs/DECISIONS.md` D-67) — internally-generated IV, confirmed with the project
owner rather than assumed (this was the one fork the roadmap itself left open, unlike the other
three). Every high-level module in Step 3 is now done:

| libsodium equivalent | Native DSTU path | Status |
|---|---|---|
| `crypto_generichash` | Kupyna | **Done** (T-105, D-66) — `dstu_core::crypto_generichash`, a bare re-export of `hazmat::kupyna` under the top-level namespace; no new logic (no knob to hide, no DSTU keyed/variable-length-output equivalent to wrap) |
| `crypto_stream` | Strumok | **Done** (roadmap Step 3 item 3, D-67) — `dstu_core::crypto_stream`, single 256-bit variant, hidden/internally-generated IV (confirmed with the project owner), `iv \|\| ciphertext` output, **no authentication** (`decrypt` never fails on tampered input) — hazmat vectors still provisional (D-18) |
| `crypto_sign` | DSTU 4145 | **Done** (T-48, D-46) — hazmat (m=163 only) plus a high-level `dstu_core::crypto_sign` wrapper; deterministic (Kupyna-KMAC-derived, RFC-6979-style) nonce, not caller-random, eliminating nonce-reuse key recovery from the wrapper's surface. Public-key encoding is a plain uncompressed 42-byte form, explicitly not the DSTU §6.9/§6.10 compressed format |
| `crypto_box` | DSTU 9041 | **Hard-blocked** — zero source material exists for DSTU 9041 anywhere (no paper, no oracle, no pseudocode); cannot start (T-46) |
| `crypto_secretbox` | Kalyna-GCM, provisionally | **Done** (T-37, D-51), **migrated 2026-07-25 from Kalyna-CCM to Kalyna-GCM** (roadmap Step 3 item 1, D-63) — single fixed `Kalyna256_256Gcm` construction, internal nonce, combined output, no caller-facing AAD (nonce passed as AAD internally to bind it into the tag, D-63); no message-length cap, still not primary-text-confirmed |
| `crypto_auth`/`crypto_onetimeauth` | Kupyna-based KMAC | **Done** (T-38, D-44) — provisional pending the primary text, but dual-oracle with both constructions read. High-level wrapper (T-105, D-66) added 2026-07-25: `dstu_core::crypto_auth`, single 256-bit variant, opaque `Zeroize`-on-drop `Key` type |
| `crypto_kdf` | Kupyna-based KDF (libsodium `crypto_kdf`-shaped, not HKDF) | **Done** (T-39, D-45) — no DSTU standard or reference implementation exists for this at all, so unlike every other "provisional" row above, there is no oracle vector, ever; verification is determinism + distinctness property tests only. High-level wrapper (T-105, D-66) added 2026-07-25: `dstu_core::crypto_kdf`, same single-variant/opaque-key shape as `crypto_auth` |
| `crypto_kx` | DH on the DSTU 4145/9041 curve | Not started (T-47); DSTU 9041 side hard-blocked |
| `crypto_secretstream` | Chunked authenticated encryption over Kalyna-GCM | **Done** (T-40/T-70, D-68) — `dstu_core::crypto_secretstream` (`PushState`/`PullState`), a from-scratch tag-per-chunk framing (full MESSAGE/PUSH/REKEY/FINAL tag set, libsodium's shape per D-47's tie-breaker — no DSTU streaming-AEAD standard exists) over `hazmat::kalyna_gcm`/`hazmat::kupyna_kmac`, caller-buffer `no_std`-capable API; `uacrypt encrypt`/`decrypt` rewired onto it the same session (breaking wire-format change from the old `crypto_secretbox`-backed blob format) |
| `crypto_pwhash` | Not a DSTU question — plain Argon2id | **Done** (T-71, D-49/D-50) — over the `argon2` crate, dedicated `pwhash` feature (off by default, not folded into `std`); `Strength` presets mirror libsodium's own `OPSLIMIT`/`MEMLIMIT_*` constants exactly |
| `randombytes` | Not a DSTU question — OS CSPRNG via `getrandom` | **Done** (T-72, D-48) — `dstu_core::randombytes::randombytes_buf`, `std`-gated over an optional `getrandom` dependency; a plain function, deliberately not a generic `CryptoRng` trait since nothing in this crate consumes one yet |

`crypto_box`/`crypto_kx` remain empty or hard-blocked (DSTU 9041 has zero source material) —
`crypto_secretbox` (T-37, D-51/D-63) and `crypto_secretstream` (T-40/T-70, D-68) are both done, no
message-length cap and genuinely chunked I/O respectively, but still provisional. The "functional
copy of libsodium" goal has real algorithm coverage (`crypto_sign`/`crypto_auth`/`crypto_kdf`/
`crypto_secretbox`/`crypto_secretstream` done) but is not yet an API surface a libsodium user would
recognize as complete.

## Use-case coverage: is "safe modes only" enough for a real range of applications?

Requested 2026-07-24: the algorithm table above answers "which libsodium function exists," not
"can this actually build the things people build with libsodium." This section answers that,
scenario by scenario, and whether a safe (combined confidentiality+integrity) mode covers it or a
safe replacement is even possible when it doesn't (D-47's "only safe modes of operation, never an
unsafe/legacy one as a public entry point" rule applies throughout — a mode being *listed* in
DSTU 7624:2014 doesn't make it eligible for a public `encrypt`/`decrypt`-style entry point unless
it's one of the combined ones).

| Scenario | Needs | DSTU mode/primitive | Combined AEAD (safe)? | Status | Safe alternative if missing |
|---|---|---|---|---|---|
| Radio/telemetry, small packets (walkie-talkie, sensor commands) | AEAD on a short message (< 255 bytes) | Kalyna-**CCM** (mode #8) | Yes | **Done** (`hazmat::kalyna_ccm`) | not needed |
| Streaming audio, confidentiality only, no per-frame auth | Low-latency keystream | Strumok | No — confidentiality-only by itself | Done, but no integrity — `hazmat::strumok` and now `dstu_core::crypto_stream` (D-67) at the high level | Wrap each frame in Kalyna-CCM/`crypto_secretbox` instead of bare Strumok/`crypto_stream` if integrity is required |
| Encrypt one message, any size | `crypto_secretbox` equivalent | Kalyna-GCM | Yes | **Done** (`dstu_core::crypto_secretbox`, T-37, D-51, migrated to GCM 2026-07-25, D-63 — no length cap) | not needed |
| Encrypt a large file / continuous stream, without buffering it all in memory | Chunked AEAD | GCM (#7) | Yes | **Done** (`dstu_core::crypto_secretstream`, T-40/T-70, D-68) — genuinely chunked, `uacrypt encrypt`/`decrypt` rewired onto it | not needed |
| Full-disk encryption (random-access sectors) | Disk-mode cipher | XTS (#9) | No, by design — integrity is deliberately left to the filesystem layer, a recognized special case, not a gap | **Done** (`hazmat::kalyna_xts`, T-96/D-58) | None needed — this is the one standard case where a non-AEAD mode is the *correct* choice, not a compromise |
| TLS-style record layer (browser, high throughput) | Per-record chunked AEAD | Same gap as the large-file row | Yes | **Done** — `dstu_core::crypto_secretstream` (T-40/T-70, D-68) is a tag-per-chunk high-level wrapper, the same shape a record layer needs | not needed |
| Key exchange / handshake (ECDHE-equivalent) | Key agreement | DSTU 9041 (`crypto_kx`) | No mode exists at all | **Hard-blocked** — zero source material (no paper, oracle, or pseudocode, `docs/TASKS.md` T-46/T-47) | **No safe DSTU replacement exists.** The only realistic path is a non-DSTU primitive (e.g. X25519) under the same "no homegrown primitive where DSTU has a real gap" precedent as Argon2id (D-03) — an explicit scope decision for the project owner, not an engineering task |
| Digital signatures | Sign/verify | DSTU 4145 (`crypto_sign`) | Yes | **Done** | not needed |
| Message/API authentication | MAC | Kupyna-KMAC (`crypto_auth`) | Yes (integrity-only is the actual goal here) | **Done** | not needed |
| Deriving subkeys from a master key | KDF | Kupyna-KDF (`crypto_kdf`) | Yes | **Done** | not needed |
| Password storage | Password hashing | Argon2id (`crypto_pwhash`, not DSTU) | Yes | **Done** | not needed |
| Key wrapping (envelope encryption) | Key wrap | Kalyna-**KW** (mode #10) | Yes | **Done** (`hazmat::kalyna_kw`, D-55) — `hazmat`-only, libsodium has no direct equivalent to wrap at the high level (roadmap Step 3 item 4) | not needed |
| Nonces, salts, ephemeral values | CSPRNG | `randombytes` | Yes | **Done** | not needed |

**Bottom line, updated 2026-07-25 (T-40/D-68)**: for message-level and small-packet use cases
(radio, API auth, signatures, KDF, password storage, unbounded-size secretbox messages, T-37/D-51/
D-63) the safe-modes-only constraint is already fully sufficient — wrapper code exists. Bulk/
streaming use cases (large files, TLS-style record layers) are now covered too:
`dstu_core::crypto_secretstream` (T-40/T-70, D-68) is a genuinely chunked, tag-per-chunk wrapper
over `hazmat::kalyna_gcm`, and `uacrypt encrypt`/`decrypt` are rewired onto it. **The one use case
with no safe DSTU answer at all is key exchange** (`crypto_kx`/DSTU 9041) — this is a real scope
boundary, not something "safe modes only" can route around, since there is no DSTU-native mode of
any kind to choose from, safe or otherwise.

## What's missing for the CLI / release-mechanics surface

- **T-16 is done, see `docs/DECISIONS.md` D-52**: `uacrypt encrypt`/`decrypt`/`hash` are real top-level
  commands. **As of 2026-07-25 (T-40, D-68), `encrypt`/`decrypt` are rewired onto
  `dstu_core::crypto_secretstream`** (not `crypto_secretbox` anymore) — genuinely chunked, `--in`/
  `--out` streamed in fixed-size blocks rather than read whole into memory, closing the gap this
  bullet used to describe. A breaking wire-format change from the prior `crypto_secretbox`-backed
  blob format, called out explicitly, acceptable pre-1.0. `hash` has no length limit either, and
  streams from disk already, unchanged. `kalyna-block`/`kalyna-ccm`/`kupyna-digest`/`strumok-crypt`
  remain as the hazmat-scoped, multi-variant tools underneath, unchanged.
- **T-17**: `dstu-core` not published to crates.io. Now unblocked mechanically (D-43's version bump),
  but publishing a `0.1.0` that is honest about D-05 (adopted on assumption, not primary-confirmed)/
  D-15/D-41's provisional status is a judgment call for the project owner, not an engineering
  blocker.
- **T-18**: **Done 2026-07-26**, see `docs/TASKS.md` T-18/T-119. Prebuilt `uacrypt` binaries for
  Windows/Linux/macOS (Apple Silicon only), plus a `dstu-core` source distribution, are published
  as GitHub Release assets on the `v0.1.0` tag via `.github/workflows/release.yml`, verified
  against the actual downloaded assets (not just a green CI run).
- No user-facing documentation beyond this repo's own `.md` files exists yet (no rustdoc pass
  dedicated to public API ergonomics, no separate docs site/book) — a real release needs
  API-level docs a consumer reads without first reading `docs/DECISIONS.md`.
- Phase 3 (language bindings: Python/JS/Java/.NET/C++, plus PHP/Ruby/Go added 2026-08-02) — not
  required for a Rust-crate-only 1.0, but relevant if "libsodium-equivalent" is read to include
  libsodium's multi-language reach. **All nine bindings done** (T-49/T-50/T-160/T-159/T-158/T-52/
  T-51/T-163/T-53): T-49 (Python) landed 2026-08-02 -
  full `crypto_*` surface, own CI, manylinux/macOS/Windows wheels attached to GitHub Releases, not
  yet published to PyPI (separately gated, same posture as crates.io's T-17). T-50 (Node.js)
  landed the same day - full `crypto_*` surface + idiomatic `stream.Transform` secretstream
  wrapper, own CI, prebuilt artifact verified via a real fresh-install round trip, not yet
  published to npm (same gating posture). T-160 (Ruby) landed the same day too - full `crypto_*`
  surface + idiomatic `SecretStreamWriter`/`Reader` (modeled on stdlib's own `Zlib::GzipWriter`/
  `GzipReader`), own CI, a genuine packaging finding (a source gem can't install standalone at all
  - fixed via `rake native gem`'s precompiled, platform-tagged gem instead, D-136), not yet
  published to RubyGems (same gating posture). T-159 (PHP) landed the same day too - full
  `crypto_*` surface + idiomatic `DstuCoreSecretStreamWriter`/`Reader` (a native PHP stream filter
  was investigated and rejected, D-143), own CI (`shivammathur/setup-php`), a similarly honest
  packaging finding (no PECL/Composer publish path exists for a provisional binding, D-144), not
  yet published to PECL/Packagist (same gating posture). T-158 (C ABI crate,
  `crates/dstu-core-capi`) landed 2026-08-03 too - unlike the four bindings above, it IS a real
  root-workspace member (D-119/D-148, no external language runtime linked at build time); wraps
  the full `crypto_*` surface behind a `cbindgen`-generated header (`include/dstu_core.h`,
  regenerated+diffed via `cargo xtask capi`), a plain-C test harness, and per-primitive examples -
  no prebuilt binaries published anywhere yet (same gating posture as the other bindings). T-52
  (.NET, `bindings/dotnet`) landed 2026-08-03 too - the first binding with no Cargo workspace of its
  own at all, pure C# P/Invoke over T-158's C ABI, D-152. T-51 (Java, `bindings/java`) landed
  2026-08-03 too - a direct-Rust `jni`-crate binding (own Cargo workspace under `bindings/java/native`),
  full `crypto_*` surface, 56 JUnit tests including real `uacrypt` interop, D-153 - including step
  10 (Raspberry Pi re-check). T-163 (Go, `bindings/go`) landed 2026-08-03 too, all ten standard
  steps including its own Pi re-check - `cgo` over T-158's C ABI (no direct-Rust-binding toolchain
  for Go has PyO3/napi-rs/magnus's maturity), full `crypto_*` surface, `io.Writer`/`io.Reader`-shaped
  secretstream, D-155 (the Pi re-check found the Windows-only cgo `LDFLAGS` needed a per-`GOOS`
  split to link on Linux at all - a cross-OS gap, not a cross-architecture one). T-53 (C++,
  `bindings/cpp`) landed 2026-08-03 too, all ten standard steps - header-only RAII wrapper over
  T-158's C ABI (no CMake `FetchContent` for the Rust side, D-158), `std::ostream&`/
  `std::istream&`-shaped secretstream with an explicit `Finish()` (a destructor can't reliably
  distinguish exception-unwind from normal scope exit), full `crypto_*` surface, real bidirectional
  `uacrypt` interop in its test suite, its own Pi re-check (step 10) finding no bug this time. See
  `docs/bindings-strategy.md`, `docs/DECISIONS.md` D-115/D-120/D-125 through D-158, `docs/TASKS.md`
  T-49/T-50/T-51/T-52/T-53/T-158/T-159/T-160/T-163 - every planned binding has now landed.

## Libsodium API surface and crates.io publishing audit (2026-07-25)

Requested 2026-07-25: an audit of libsodium's actual official API (doc.libsodium.org) beyond the
core constructions already tracked above, plus a review of crates.io/RustCrypto-ecosystem
publishing norms, to find anything neither implemented nor tracked as a task. Findings that turned
into real actionable work are `docs/TASKS.md` T-109 through T-113 (Cargo.toml metadata, per-crate
LICENSE files, `docs.rs` metadata, `docs/CHANGELOG.md`/MSRV, crate-level provisional-status doc warning,
multi-part `crypto_sign`) - this section records the rest: corrections, and gaps deliberately **not**
scheduled, so a future session doesn't re-derive the same conclusions from scratch.

**Correction to prior assumptions**: libsodium's `crypto_kdf` is BLAKE2b-based subkey derivation
only - there is no separate `crypto_kdf_hkdf_*` family to map against. Nothing to reconcile against
`dstu_core::crypto_kdf`; the two are already the same shape.

**Confirmed an existing gap, then closed it**: libsodium's `crypto_secretstream_xchacha20poly1305`
uses four tags (MESSAGE/PUSH/REKEY/FINAL), where the absence of a FINAL tag before EOF is what
detects stream truncation - this was the actual design bar `crypto_secretstream` needed to hit, not
just per-chunk authentication. **Done 2026-07-25 (T-40/T-70, `docs/DECISIONS.md` D-68)** -
`dstu_core::crypto_secretstream` implements the full four-tag set and the truncation-via-missing-
FINAL property, hitting this bar exactly.

**Open questions for the project owner - not resolved here, not scheduled as tasks**:

- **Detached API variants** (`crypto_secretbox_detached`, `crypto_sign_detached` - tag/signature
  returned separately from ciphertext/message rather than concatenated into one blob). libsodium
  ships both combined and detached forms for these; this project's own `crypto_secretbox`/
  `crypto_sign` deliberately ship one shape only, per `docs/DECISIONS.md` D-47's "delete the knob"
  tie-breaker. Adding a detached entry point is a second knob, which is exactly what D-47 says to
  avoid absent a concrete reason - a real use case exists in the wild (storing a MAC/signature in a
  database column separate from a large blob) but none exists in this project yet. Flagged as a
  question, not resolved unilaterally the way T-105's fork was (a mistake this project already
  caught itself making once, see `docs/DECISIONS.md` D-66/D-67's process-lesson note) - needs the
  owner's call before it becomes a task.
- **`randombytes_uniform`** (unbiased bounded random integer). No consumer exists anywhere in this
  codebase today - the same "no `CryptoRng` trait, nothing consumes one yet" reasoning
  `docs/DECISIONS.md` D-48 already gave for keeping `randombytes_buf` a plain function applies here too,
  and CLAUDE.md's own "no speculative features" rule forbids adding it ahead of a real use.
  Revisit if/when a concrete caller needs a bounded random index/range without modulo bias.

**No DSTU angle - deliberately not scheduled, not an oversight**:

- `crypto_shorthash` (SipHash-2-4, explicitly non-collision-resistant, for hash-table/DoS
  resistance use) - no DSTU standard defines or implies anything like it.
- `sodium_bin2hex`/`_hex2bin`, `sodium_bin2base64`/`_base642bin`, `sodium_pad`/`_unpad` - generic
  encoding/padding utilities, not cryptographic primitives; not DSTU-scoped, and standard Rust
  crates (`hex`, `base64`) already cover this need if/when the CLI wants it.
- `sodium_increment`/`_add`/`_compare` (constant-time nonce-counter arithmetic) - this project's
  nonces are randomly generated everywhere (`crypto_secretbox`, `crypto_stream`, `kalyna_ccm`/`gcm`),
  never counter-based, so there is no counter to increment.
- Raw `crypto_scalarmult`/`_base` (bare X25519-shaped ECDH as its own public primitive, distinct
  from `crypto_kx`) - `hazmat::dstu4145` has the underlying point arithmetic internally but exposes
  no public raw scalar-multiplication entry point, and libsodium's own docs steer callers toward
  `crypto_kx` instead of this lower-level primitive anyway. `crypto_kx`'s DSTU 9041 path is already
  hard-blocked (T-46/T-47); a raw scalar-mult entry point would face the identical blocker with no
  independent use case pulling it out ahead of `crypto_kx` itself.
- `crypto_box_seal`/`_seal_open` (anonymous/sealed-box encryption) - a sub-feature of `crypto_box`,
  which is already hard-blocked on DSTU 9041 (T-46) having zero source material. Not a new blocker.
- `crypto_pwhash`'s Argon2i13/legacy scryptsalsa208sha256 variants - already deliberately narrowed
  to Argon2id only (T-71/D-49/D-50), matching libsodium's own current recommended default; the other
  variants exist in libsodium for legacy interop, not because they're preferred.

## Libsodium API surface audit, round 2 (2026-07-26)

Requested 2026-07-26 by the project owner, explicitly framed as "this keeps happening" - new
libsodium-shaped gaps (most recently: no `uacrypt` CLI for `crypto_sign`) kept surfacing one at a
time in unrelated sessions instead of being caught by a systematic pass, despite round 1 above
existing. This pass re-fetched libsodium's *current* official API table of contents directly
(`raw.githubusercontent.com/jedisct1/libsodium-doc/master/SUMMARY.md` plus the individual per-family
doc pages, not memory) rather than relying on round 1's list, specifically because libsodium's own
API surface has grown since round 1 - it now documents AEGIS-256/AEGIS-128L, AES256-GCM,
IP address encryption (`crypto_ipcrypt_*`), and post-quantum `crypto_kem`/ML-KEM768, none of which
existed in what round 1 checked against. Full section-by-section table below; the rest of this
section records what actually changed as a result (new tasks, corrections, scope notes) so this
doesn't need re-deriving from the table alone next time.

| libsodium family | Our equivalent | Status |
|---|---|---|
| `crypto_generichash` (BLAKE2b) | `crypto_generichash` (Kupyna) | Done |
| `crypto_shorthash` (SipHash) | none | No DSTU angle, no consumer - not scheduled |
| XOF (extendable-output hash) | none | Kupyna has no XOF mode, no DSTU angle |
| `crypto_secretbox` | `crypto_secretbox` (Kalyna-GCM) | Done, provisional (D-56) |
| `crypto_secretstream` | `crypto_secretstream` | Done |
| `crypto_auth`/`crypto_onetimeauth` | `crypto_auth` (Kupyna-KMAC) | Done (Poly1305-shaped one-time-key MAC specifically has no DSTU analogue) |
| AEAD family (ChaCha20-Poly1305/AEGIS-256/AEGIS-128L/AES256-GCM) | Kalyna-CCM/GCM | Not a gap - alternative cipher *choices*, already decided (D-47) |
| IP address encryption (`crypto_ipcrypt_*`) | none | No DSTU angle, no use case - not scheduled |
| `crypto_box` (+ sealed boxes) | `hazmat::dstu9041` | Hard-blocked (T-46, zero source material) |
| `crypto_sign` sign/verify | `hazmat::dstu4145` + `crypto_sign` | Done |
| `crypto_sign` keypair generation | `SigningKey::generate()` | Done (T-122, D-72) |
| `crypto_kem`/ML-KEM768 (post-quantum) | none | Explicitly out of scope, D-08's spirit - recorded so it isn't rediscovered |
| `crypto_pwhash` (+ `_str`/`_str_verify`) | `crypto_pwhash` (Argon2id) | Done - `hash_password` already returns the same opaque-string shape as `_str` |
| `crypto_kdf` | `crypto_kdf` (Kupyna-KDF) | Done |
| `crypto_kdf_hkdf_*` (RFC 5869 HKDF) | none | No DSTU angle - not scheduled (see stale-claim correction below) |
| `crypto_kx` | none | Not started (T-47), blocked on DSTU 9041 |
| `crypto_stream` | `crypto_stream` (Strumok) | Done |
| SHA-2/SHA-3/HMAC-SHA-2/Keccak-f[1600]/Poly1305/Ristretto | none | Foreign-algorithm interop exposures, not a "do we have a hash/MAC" gap - Kupyna/Kupyna-KMAC already fill that role above |
| `randombytes_buf` | `randombytes_buf` | Done |
| `randombytes_uniform` | none | No consumer - not scheduled |
| Custom RNG backend (`randombytes_set_implementation`) | new `getrandom` Cargo feature | Done (T-123, D-74) - capability parity, not mechanism parity (see the entry below) |
| `sodium_mlock`/guarded memory | none | **Open question for the owner**, not a task - see below |
| `uacrypt` CLI: `keygen`/`encrypt`/`decrypt`/`hash` | all present | Done |
| `uacrypt` CLI: `sign`/`verify` | `sign-keygen`/`sign-pubkey`/`sign`/`verify` | Done (T-124, D-73) |

**Stale claim corrected**: round 1's "Correction to prior assumptions" above (no separate
`crypto_kdf_hkdf_*` family exists) is **itself now wrong** - current libsodium documents
`crypto_kdf_hkdf_sha256_*`/`crypto_kdf_hkdf_sha512_*` (`key_derivation/hkdf.md`), a second,
distinct KDF family alongside the BLAKE2b-based `crypto_kdf` this project already maps against.
This is RFC 5869 HKDF specifically - HMAC-SHA256/512-based, not DSTU-native, offered by libsodium
as a standards-interop option alongside its own simpler `crypto_kdf`. **Still not scheduled as a
task** - same reasoning as the "No DSTU angle" list below (no DSTU standard defines an HKDF
analogue, and `dstu_core::crypto_kdf` already covers the "derive a subkey from a master key" need
this project has an actual consumer for) - but the prior claim that libsodium simply doesn't have
this family was factually wrong, not a scoping judgment, and needed fixing on its own.

**Real, previously-undocumented gaps found - added to `docs/TASKS.md`**:

- **`dstu_core::crypto_sign::SigningKey` has no keypair-generation constructor at all** - only
  `from_bytes(d: &[u8; 21])`, which requires the caller to already possess a valid private scalar
  (`1 <= d < n`, checked and rejected via `Option::None` otherwise). There is no
  `crypto_sign_keypair()`/`crypto_sign_seed_keypair()` equivalent - no way to generate a fresh
  identity through the public API without external help, and no public way for a caller to even
  perform the correct rejection-sampling-against-curve-order themselves without reaching into
  `hazmat` internals. This is the same class of journey-blocking gap T-115 closed for
  `crypto_secretstream::Key` (`uacrypt keygen`) - confirmed by reading the actual source
  (`crates/dstu-core/src/crypto_sign.rs`), not assumed from the API-mapping table, which had marked
  `crypto_sign` "Implemented" without this distinction. **Done 2026-07-26, see `docs/TASKS.md` T-122 and
  `docs/DECISIONS.md` D-72** - `SigningKey::generate()` now exists (plain OS-CSPRNG, rejection sampling
  against the curve order, not a modulo reduction).
- **No pluggable/custom RNG backend for `no_std`/embedded targets** - libsodium documents
  `randombytes_set_implementation()`/`advanced/custom_rng.md` specifically so a caller can swap in a
  hardware TRNG or other custom entropy source. `dstu_core::randombytes::randombytes_buf` was
  `std`-gated over `getrandom` with no equivalent hook - correctly absent from `no_std` builds
  (nothing promised otherwise), but there was no tracked path for a STM32/ESP32 caller to get
  `randombytes`-shaped functionality at all without a host OS's CSPRNG. **Done 2026-07-26, see
  `docs/TASKS.md` T-123 and `docs/DECISIONS.md` D-74** - a new `getrandom` Cargo feature (narrower than `std`,
  independent of it) makes `randombytes`/every `Key::generate` reachable on a bare `no_std` build,
  for a caller who has configured one of `getrandom` 0.3's own non-OS backends themselves (most
  commonly `custom`). **Capability parity with libsodium's `randombytes_set_implementation()`, not
  mechanism parity, deliberately**: `getrandom` 0.3's backend selection is a compile-time/link-time
  choice the final binary makes (an `extern "Rust"` symbol resolved at link time), not a
  runtime-swappable function pointer the way libsodium's setter is - `dstu-core` does not implement
  its own pluggable-backend registry on top, since `getrandom` already fills that role and a second
  one would duplicate an established mechanism (the same D-03/D-04 reasoning that already rejected
  a homegrown RNG). Verified end-to-end (not just "compiles"): a scratch crate defining a real
  `__getrandom_v03_custom` extern fn, built and *run*, proved the hook resolves at link time and
  actually produces the bytes `randombytes_buf`/`Key::generate` return.
- **`uacrypt` has no `sign`/`verify` CLI commands** - `dstu_core::crypto_sign` (T-48/D-46) exists
  only as a library API, confirmed via `grep` across `crates/uacrypt/src/lib.rs`'s command
  dispatch. First surfaced as a scoping note on `docs/TASKS.md` T-120 (doc-examples task, which
  documents the gap rather than closing it); this round makes it a real implementation task in its
  own right. **Done 2026-07-26, see `docs/TASKS.md` T-124 and `docs/DECISIONS.md` D-73** - `sign`/`verify`
  now exist, plus `sign-keygen`/`sign-pubkey` (a scope widening beyond the literal task text,
  needed so there's a CLI path to key material at all - the same class of gap T-115 closed for
  `encrypt`/`decrypt`).

**No DSTU/PQ angle - additions to round 1's list, deliberately not scheduled**:

- **`crypto_kem`/ML-KEM768** (post-quantum key encapsulation, new in current libsodium) - this is
  NIST's ML-KEM (Kyber), not a DSTU standard. Post-quantum primitives are explicitly out of this
  project's scope without a separate owner decision (`docs/DECISIONS.md` D-08, currently scoped to the
  *DSTU* post-quantum standards Skelya/Vershyna specifically) - the same reasoning extends to a
  non-DSTU PQ KEM a fortiori. Recorded here so it isn't independently "discovered" and proposed
  again without the context that this was already considered.
- **IP address encryption** (`crypto_ipcrypt_*`, deterministic/ND/NDX/PFX modes) - a genuinely new,
  niche libsodium feature (format-preserving encryption of IP addresses for log anonymization). No
  DSTU standard addresses this, and no evident use case in a general-purpose DSTU crypto library.
- **AEGIS-256/AEGIS-128L, AES256-GCM as `crypto_aead_*` choices** - these are alternative AEAD
  *cipher* choices libsodium offers alongside ChaCha20-Poly1305, not missing functionality - this
  project already made its combined-AEAD choice (Kalyna-CCM/GCM, `docs/DECISIONS.md` D-47's "delete the
  knob") and isn't in the business of offering a cipher menu.
- **SHA-2, SHA-3, HMAC-SHA-2, Keccak-f[1600] (raw), Poly1305 one-time auth, the
  ChaCha20/XChaCha20/Salsa20/XSalsa20 stream-cipher family** - all non-DSTU primitives libsodium
  exposes for interop with external systems/standards. This project made the "Kupyna is the hash,
  Kupyna-KMAC is the MAC, Strumok is the stream cipher" calls already (D-10/D-44/D-18); none of
  these has a consumer requiring interop with a non-DSTU external system today.
- **Ed25519↔Curve25519 conversion, Ristretto/finite-field-arithmetic helpers** - Curve25519-specific
  internals with no DSTU 4145/9041 analogue (different curve family entirely).

**Flagged as an open question for the project owner, not resolved here (security-relevant, a real
scope commitment either way)**:

- **Guarded/locked secret memory** (`sodium_mlock`/`munlock`, `sodium_malloc`/`free`,
  `sodium_mprotect_noaccess`/`readonly`/`readwrite` - `helpers/memory_management.md`). This project's
  `Zeroize`/`ZeroizeOnDrop` discipline (D-20) covers *erasing* key material after use; it does not
  cover *preventing* key material from being paged to swap/hibernation while still in use, or
  guard-page-based use-after-free/overflow detection around it - a materially different, `std`/OS-only
  guarantee (no bare-metal equivalent exists, so this could never be a `no_std`-uniform primitive the
  way `Zeroize` is). Not unilaterally scoped in either direction here, same posture as the existing
  "detached API variants" question above - needs the owner's call on whether this project's threat
  model (`docs/SECURITY.md`) wants it before it becomes a task.

`docs/dstu-crypto-project.md`'s "Concrete API shape" table (the authoritative implementation-status
table) is unaffected by this round - none of the findings above change any *existing* module's
status, they're additions (new tasks) or corrections to this file's own prior audit text.

## Concrete path to a genuinely safe, complete release

**Superseded 2026-07-25 (T-99) by `docs/TASKS.md`'s "Roadmap to a genuinely complete product"** (recorded
2026-07-24, user-approved sequencing) — that document is now the current authoritative "what's next"
plan, kept there specifically so it survives a memory clear or new session. The numbered list below
is left as a historical snapshot of this document's own earlier reasoning, corrected for factual
staleness (T-99's job) but not renumbered or resequenced to match the roadmap — read `docs/TASKS.md` for
current sequencing, this section for the reasoning behind steps 1-2 specifically (still load-bearing,
per the closing paragraph below).

In rough dependency order:

1. **D-05 resolved on assumption 2026-07-24 (T-36)** — Kalyna-alone, corroborated by two
   independent non-primary sources (this project's own vendored UAPKI ten-mode list, Ukrainian
   Wikipedia's independently-sourced ten-mode table), still not a reading of the priced primary
   DSTU 7624:2014 text. Acquiring that text (or another authoritative source) and confirming or
   revising against it remains open and would upgrade this from "assumption" to "confirmed" —
   `crypto_secretbox` (T-37, migrated to Kalyna-GCM 2026-07-25 by D-63) is built against it,
   inheriting the same provisional status, not a resolution of it.
2. **Close Strumok's provenance gap (D-15/D-16)**, if the paid DSTU 8845:2019 text becomes
   available — partially narrowed (D-104) by two independently state-sourced
   supplementary vectors (Держспецзв'язку/ДНДІ ТКЗІ), confirmed matching, but that is still not the
   primary text itself. Otherwise, the release must state "Strumok vectors are UAPKI-attributed
   plus one independent state-sourced supplementary check, not primary-text-confirmed" as
   prominently as the README banner now states the pre-release status generally.
3. **Build the missing constructions**: `crypto_auth` (T-38, D-44), `crypto_kdf` (T-39, D-45), and
   `crypto_secretbox` (T-37, D-51) all done, none blocked on external material — the Kalyna-alone
   working hypothesis (only CCM/GCM/KW eligible, per D-47, see the headline finding) is what
   `crypto_secretbox` is built against, inheriting its provisional status.
   **Updated 2026-07-25 (T-99/D-63)**: `hazmat::kalyna_gcm` (D-56) and `hazmat::kalyna_kw` (D-55) -
   the two constructions this step originally meant by "missing" for `crypto_secretstream` - are
   both built at the `hazmat` level, and `crypto_secretbox` itself has now migrated onto
   `kalyna_gcm` (roadmap Step 3 item 1, D-63), removing its 255-byte cap entirely.
   **`crypto_secretstream` (T-40/T-70) is now done too, same day, see `docs/DECISIONS.md` D-68** - the
   genuinely chunked wrapper this step was waiting on is built, `uacrypt encrypt`/`decrypt` rewired
   onto it.
4. **Build the high-level layer** (D-09's second layer) over every `hazmat` primitive that's ready —
   `crypto_sign` (step 5) is the first module built there. `crypto_auth`/`crypto_kdf` (step 3) are
   done too - a stale "don't have high-level wrappers yet either" claim here is corrected 2026-07-25
   (T-99), matching the same correction already made in the "libsodium equivalent surface" table
   above.
5. **DSTU 4145 polish**: `crypto_sign` wrapper **done** (T-48, D-46) — deterministic nonce, not
   caller-random; decide whether the other 9 curve sizes matter for 1.0 or can stay m=163-only, and
   whether the DSTU §6.9/§6.10 compressed point encoding is needed for 1.0 (the wrapper currently
   ships only an uncompressed 42-byte form).
6. **DSTU 9041 stays out of scope for 1.0** unless source material is found — don't block the rest
   of the release on a hard-blocked item with no known path forward.
7. **Mechanical release work**: `uacrypt`'s real `encrypt`/`decrypt`/`hash` commands are now done
   (T-16, D-52), and GitHub Releases binaries are too (T-18/T-119, 2026-07-26) — remaining:
   crates.io publish (T-17, still explicitly gated on an owner request) and a documentation pass
   aimed at an external consumer rather than an AI-agent-facing repo.

Steps 1-2 are the load-bearing ones: everything else can be built in parallel, but a release that
skips them is a release of provisional cryptography labeled as final, which is exactly the outcome
this document exists to flag before it happens by default.
