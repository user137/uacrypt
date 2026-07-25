# Release readiness: what a genuine libsodium-equivalent 1.0 needs

Requested 2026-07-23 (same session as `DECISIONS.md` D-43's `0.0.0` -> `0.1.0` version bump): a gap
analysis between where this project actually is and the user's stated release goal — a full
libsodium-style API with matching command surface and documentation, published to crates.io as a
complete, built-and-tested algorithm set, where **every mode of operation included is current and
safe**, not provisional. This document is that analysis. It synthesizes existing tracking
(`TASKS.md`, `DECISIONS.md`, `docs/dstu-crypto-project.md`'s API mapping, `SECURITY.md`) rather than
duplicating it — update the source-of-truth file first when something here changes, then this
document's summary.

## Headline finding

**Updated 2026-07-24: D-05 is no longer formally open — adopted as a working assumption, still not
primary-text-confirmed.** `DECISIONS.md` D-05 — whether Kalyna alone is DSTU 7624's intended AEAD
construction, or whether confidentiality + integrity requires a separate Kalyna+Kupyna
encrypt-then-MAC design — was resolved on assumption at the project owner's explicit direction:
**Kalyna-alone** (CCM/GCM/KW), not encrypt-then-MAC. This is corroborated by two independent
non-primary sources agreeing mode-for-mode (this project's own already-vendored `oracles/uapki/`
ten-mode self-test list, and Ukrainian Wikipedia's independently-sourced ten-mode table for the
"Калина (шифр)" article — see `DECISIONS.md` D-05's 2026-07-24 revision for the full table and
sourcing caveats), on top of D-41's existing UAPKI+Bouncy-Castle reference-implementation evidence.
**This is still not a reading of the priced primary DSTU 7624:2014 text** — it remains unpurchased,
and this decision is explicitly provisional, to be revised again (not silently) if that text is
ever acquired and contradicts it. The practical effect: what was a hard blocker is now a "build
against this working hypothesis" situation:

- `hazmat::kalyna_ccm` (D-41) is unchanged — still dual-oracle-verified, still not
  primary-text-confirmed, but now also matches the standard's own official mode list per both
  sources above (mode #8, "Вироблення імітовставки і гамування").
- Strumok's entire vector set is still UAPKI-attributed, not confirmed against the paid DSTU
  8845:2019 text (D-15) — a separate, unrelated gap on a different algorithm, unaffected by D-05.
- **`crypto_secretbox` (T-37) is done, see `DECISIONS.md` D-51** — a single fixed construction,
  internally-generated nonce, combined `nonce || ciphertext || tag` output, no caller-facing AAD
  parameter. **Migrated 2026-07-25 from Kalyna-CCM to Kalyna-GCM** (roadmap Step 3 item 1,
  `DECISIONS.md` D-63) — `hazmat::kalyna_gcm::Kalyna256_256Gcm`, not all five variants, per D-47's
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
- `crypto_secretstream` (T-40): the D-05-blocking concern (an ad hoc Strumok+KMAC EtM gap-fill
  would silently resolve D-05) no longer applies verbatim now that D-05 has an adopted answer.
  **Updated 2026-07-25 (T-99)**: `hazmat::kalyna_gcm` now exists (D-56) and, unlike CCM, encodes no
  length cap into its construction — and as of the same day, `crypto_secretbox` itself has been
  migrated onto it (D-63), removing the 255-byte cap at the `crypto_secretbox`/`uacrypt`
  `encrypt`/`decrypt` layer. What remains open is genuinely chunked/streaming encryption — reading
  and writing in fixed-size blocks rather than the whole file at once — since an AEAD tag still
  needs the full plaintext/ciphertext up front under the current single-shot construction.
  `hazmat::kalyna_ccm`'s own 255-byte plaintext/AAD cap (D-41) is unaffected and still real, but
  `crypto_secretbox` no longer uses that construction. `crypto_secretstream` itself — a distinct,
  genuinely chunked wrapper — is still not started.

A release billed as "current, safe modes" still cannot honestly ship on top of an
assumption-adopted, non-primary-confirmed construction without saying so exactly as loudly as
`DECISIONS.md`/`TASKS.md` already do internally — closing that gap fully still needs either (a)
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
| Kupyna | DSTU 7564:2014 | Both 256/512 variants, one-shot `digest()` and streaming `Hasher`. Vector-confirmed + dual-oracle. KMAC (`crypto_auth` equivalent) now implemented too — `hazmat::kupyna_kmac`, dual-oracle with both constructions read (`TASKS.md` T-38, `DECISIONS.md` D-44), same provisional-pending-primary-text caveat. KDF (`crypto_kdf` equivalent) built on top of that KMAC — `hazmat::kupyna_kdf` (T-39, D-45); no DSTU standard or reference implementation exists for this construction at all, so unlike the KMAC row there is no oracle vector, ever — verified by determinism/distinctness property tests only. |
| Strumok | DSTU 8845:2019 | Both 256/512-bit key variants, keystream `apply_keystream`. **UAPKI-attributed vectors only** — no independent confirmation against the primary text exists anywhere (D-15) since no such oracle has been found; this is a provenance ceiling, not a code-quality gap. |

DSTU 4145-2002 (digital signatures): the m=163 curve's `GF(2^163)` field arithmetic, point
add/double/constant-time scalar multiplication, and `sign`/`verify` are all implemented
(`hazmat::dstu4145`), verified against the official standard's own Annex B.1 worked example plus a
`proptest` round-trip, with two real bugs (a `Q = d·G` vs `Q = -d·G` sign error, a `hash_to_field`
calling-convention bug) found and fixed by re-deriving from the primary text directly rather than
trusting a single reference-implementation transcription (`DECISIONS.md` D-25). **The high-level
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
UAPKI/reference-C on both x86-64 and a real Raspberry Pi ARM64 rig (`PERFORMANCE.md`, D-34);
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
(see the table below for why). `crypto_stream` genuinely still has no high-level wrapper, only its
`hazmat` form:

| libsodium equivalent | Native DSTU path | Status |
|---|---|---|
| `crypto_generichash` | Kupyna | **Done** (T-105, D-66) — `dstu_core::crypto_generichash`, a bare re-export of `hazmat::kupyna` under the top-level namespace; no new logic (no knob to hide, no DSTU keyed/variable-length-output equivalent to wrap) |
| `crypto_stream` | Strumok | hazmat done (provisional vectors); no high-level wrapper |
| `crypto_sign` | DSTU 4145 | **Done** (T-48, D-46) — hazmat (m=163 only) plus a high-level `dstu_core::crypto_sign` wrapper; deterministic (Kupyna-KMAC-derived, RFC-6979-style) nonce, not caller-random, eliminating nonce-reuse key recovery from the wrapper's surface. Public-key encoding is a plain uncompressed 42-byte form, explicitly not the DSTU §6.9/§6.10 compressed format |
| `crypto_box` | DSTU 9041 | **Hard-blocked** — zero source material exists for DSTU 9041 anywhere (no paper, no oracle, no pseudocode); cannot start (T-46) |
| `crypto_secretbox` | Kalyna-GCM, provisionally | **Done** (T-37, D-51), **migrated 2026-07-25 from Kalyna-CCM to Kalyna-GCM** (roadmap Step 3 item 1, D-63) — single fixed `Kalyna256_256Gcm` construction, internal nonce, combined output, no caller-facing AAD (nonce passed as AAD internally to bind it into the tag, D-63); no message-length cap, still not primary-text-confirmed |
| `crypto_auth`/`crypto_onetimeauth` | Kupyna-based KMAC | **Done** (T-38, D-44) — provisional pending the primary text, but dual-oracle with both constructions read. High-level wrapper (T-105, D-66) added 2026-07-25: `dstu_core::crypto_auth`, single 256-bit variant, opaque `Zeroize`-on-drop `Key` type |
| `crypto_kdf` | Kupyna-based KDF (libsodium `crypto_kdf`-shaped, not HKDF) | **Done** (T-39, D-45) — no DSTU standard or reference implementation exists for this at all, so unlike every other "provisional" row above, there is no oracle vector, ever; verification is determinism + distinctness property tests only. High-level wrapper (T-105, D-66) added 2026-07-25: `dstu_core::crypto_kdf`, same single-variant/opaque-key shape as `crypto_auth` |
| `crypto_kx` | DH on the DSTU 4145/9041 curve | Not started (T-47); DSTU 9041 side hard-blocked |
| `crypto_secretstream` | Chunked authenticated encryption, Kalyna-alone | D-05's blocker resolved 2026-07-24 (T-40). **Updated 2026-07-25 (T-99/D-63)**: `hazmat::kalyna_gcm` now exists (D-56) and has no length cap, unlike `kalyna_ccm` (255-byte cap, D-41) — and `crypto_secretbox` itself is now built on it (D-63), removing the 255-byte cap at that layer. What remains for this row specifically is genuinely chunked/streaming encryption (fixed-size blocks rather than whole-file-in-memory), not yet built |
| `crypto_pwhash` | Not a DSTU question — plain Argon2id | **Done** (T-71, D-49/D-50) — over the `argon2` crate, dedicated `pwhash` feature (off by default, not folded into `std`); `Strength` presets mirror libsodium's own `OPSLIMIT`/`MEMLIMIT_*` constants exactly |
| `randombytes` | Not a DSTU question — OS CSPRNG via `getrandom` | **Done** (T-72, D-48) — `dstu_core::randombytes::randombytes_buf`, `std`-gated over an optional `getrandom` dependency; a plain function, deliberately not a generic `CryptoRng` trait since nothing in this crate consumes one yet |

`crypto_box`/`crypto_kx`/`crypto_secretstream` remain empty or blocked — `crypto_secretbox` is now
done too (T-37, D-51/D-63), no message-length cap since the Kalyna-GCM migration, but still
provisional. The "functional copy of libsodium"
goal has real algorithm coverage (`crypto_sign`/`crypto_auth`/`crypto_kdf`/`crypto_secretbox` done)
but is not yet an API surface a libsodium user would recognize as complete.

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
| Streaming audio, confidentiality only, no per-frame auth | Low-latency keystream | Strumok | No — confidentiality-only by itself | Done, but no integrity | Wrap each frame in Kalyna-CCM instead of bare Strumok if integrity is required |
| Encrypt one message, any size | `crypto_secretbox` equivalent | Kalyna-GCM | Yes | **Done** (`dstu_core::crypto_secretbox`, T-37, D-51, migrated to GCM 2026-07-25, D-63 — no length cap) | not needed |
| Encrypt a large file / continuous stream, without buffering it all in memory | Chunked AEAD | GCM (#7) | Yes | `hazmat::kalyna_gcm` **done** (D-56); `crypto_secretbox` now uses it (D-63) but still reads/writes the whole file at once — a genuinely chunked `crypto_secretstream` wrapper (T-40) is not built yet | not needed once wrapped |
| Full-disk encryption (random-access sectors) | Disk-mode cipher | XTS (#9) | No, by design — integrity is deliberately left to the filesystem layer, a recognized special case, not a gap | **Done** (`hazmat::kalyna_xts`, T-96/D-58) | None needed — this is the one standard case where a non-AEAD mode is the *correct* choice, not a compromise |
| TLS-style record layer (browser, high throughput) | Per-record chunked AEAD | Same gap as the large-file row | Yes | Same as the large-file row — `hazmat::kalyna_gcm` done, no high-level wrapper yet | not needed once wrapped |
| Key exchange / handshake (ECDHE-equivalent) | Key agreement | DSTU 9041 (`crypto_kx`) | No mode exists at all | **Hard-blocked** — zero source material (no paper, oracle, or pseudocode, `TASKS.md` T-46/T-47) | **No safe DSTU replacement exists.** The only realistic path is a non-DSTU primitive (e.g. X25519) under the same "no homegrown primitive where DSTU has a real gap" precedent as Argon2id (D-03) — an explicit scope decision for the project owner, not an engineering task |
| Digital signatures | Sign/verify | DSTU 4145 (`crypto_sign`) | Yes | **Done** | not needed |
| Message/API authentication | MAC | Kupyna-KMAC (`crypto_auth`) | Yes (integrity-only is the actual goal here) | **Done** | not needed |
| Deriving subkeys from a master key | KDF | Kupyna-KDF (`crypto_kdf`) | Yes | **Done** | not needed |
| Password storage | Password hashing | Argon2id (`crypto_pwhash`, not DSTU) | Yes | **Done** | not needed |
| Key wrapping (envelope encryption) | Key wrap | Kalyna-**KW** (mode #10) | Yes | **Done** (`hazmat::kalyna_kw`, D-55) — `hazmat`-only, libsodium has no direct equivalent to wrap at the high level (roadmap Step 3 item 4) | not needed |
| Nonces, salts, ephemeral values | CSPRNG | `randombytes` | Yes | **Done** | not needed |

**Bottom line, updated 2026-07-25 (T-99/D-63)**: for message-level and small-packet use cases
(radio, API auth, signatures, KDF, password storage, and now unbounded-size secretbox messages,
T-37/D-51/D-63) the safe-modes-only constraint is already fully sufficient — wrapper code exists.
For bulk/streaming use cases (large files, TLS-style record layers), the underlying gap has
narrowed further: `hazmat::kalyna_gcm` (D-56) now exists and `crypto_secretbox` itself is built on
it (D-63, roadmap Step 3 item 1, done), so there's no more length cap at that layer — what remains
is genuinely chunked/streaming I/O (fixed-size blocks rather than the whole file in memory), which
needs a distinct `crypto_secretstream` construction (T-40), not yet built. **The one use case with
no safe DSTU answer at all is key exchange** (`crypto_kx`/DSTU 9041) —
this is a real scope boundary, not something "safe modes only" can route around, since there is no
DSTU-native mode of any kind to choose from, safe or otherwise.

## What's missing for the CLI / release-mechanics surface

- **T-16 is done, see `DECISIONS.md` D-52**: `uacrypt encrypt`/`decrypt`/`hash` are real top-level
  commands now, over `dstu_core::crypto_secretbox` (`encrypt`/`decrypt`) and Kupyna-256 (`hash`).
  **`encrypt`/`decrypt` no longer have a message-length cap**, since `crypto_secretbox`'s migration
  to Kalyna-GCM (D-63) removed it — `--in` is still read whole into memory, though (unchanged code),
  so a large file means a correspondingly large in-memory buffer, not a rejection; genuinely
  chunked I/O is still `crypto_secretstream`'s (T-40) job, not built yet. `hash` has no length
  limit either, and streams from disk already. `kalyna-block`/`kalyna-ccm`/`kupyna-digest`/
  `strumok-crypt` remain as the hazmat-scoped, multi-variant tools underneath, unchanged.
- **T-17**: `dstu-core` not published to crates.io. Now unblocked mechanically (D-43's version bump),
  but publishing a `0.1.0` that is honest about D-05 (adopted on assumption, not primary-confirmed)/
  D-15/D-41's provisional status is a judgment call for the project owner, not an engineering
  blocker.
- **T-18**: no prebuilt GitHub Releases binaries for Windows/Linux/macOS.
- No user-facing documentation beyond this repo's own `.md` files exists yet (no rustdoc pass
  dedicated to public API ergonomics, no separate docs site/book) — a real release needs
  API-level docs a consumer reads without first reading `DECISIONS.md`.
- Phase 3 (language bindings: Python/JS/Java/.NET/C++) is entirely unstarted — not required for a
  Rust-crate-only 1.0, but relevant if "libsodium-equivalent" is read to include libsodium's
  multi-language reach.

## Concrete path to a genuinely safe, complete release

**Superseded 2026-07-25 (T-99) by `TASKS.md`'s "Roadmap to a genuinely complete product"** (recorded
2026-07-24, user-approved sequencing) — that document is now the current authoritative "what's next"
plan, kept there specifically so it survives a memory clear or new session. The numbered list below
is left as a historical snapshot of this document's own earlier reasoning, corrected for factual
staleness (T-99's job) but not renumbered or resequenced to match the roadmap — read `TASKS.md` for
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
2. **Close Strumok's provenance gap (D-15)**, if the paid DSTU 8845:2019 text becomes available —
   otherwise, the release must state "Strumok vectors are UAPKI-attributed, not primary-confirmed"
   as prominently as the README banner now states the pre-release status generally.
3. **Build the missing constructions**: `crypto_auth` (T-38, D-44), `crypto_kdf` (T-39, D-45), and
   `crypto_secretbox` (T-37, D-51) all done, none blocked on external material — the Kalyna-alone
   working hypothesis (only CCM/GCM/KW eligible, per D-47, see the headline finding) is what
   `crypto_secretbox` is built against, inheriting its provisional status.
   **Updated 2026-07-25 (T-99/D-63)**: `hazmat::kalyna_gcm` (D-56) and `hazmat::kalyna_kw` (D-55) -
   the two constructions this step originally meant by "missing" for `crypto_secretstream` - are
   both built at the `hazmat` level, and `crypto_secretbox` itself has now migrated onto
   `kalyna_gcm` (roadmap Step 3 item 1, D-63), removing its 255-byte cap entirely.
   `crypto_secretstream` (T-40) itself is still not started - the remaining blocker is "no
   genuinely chunked wrapper exists," not "no eligible primitive exists."
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
   (T-16, D-52) — remaining: crates.io publish (T-17), GitHub Releases binaries (T-18), and a
   documentation pass aimed at an external consumer rather than an AI-agent-facing repo.

Steps 1-2 are the load-bearing ones: everything else can be built in parallel, but a release that
skips them is a release of provisional cryptography labeled as final, which is exactly the outcome
this document exists to flag before it happens by default.
