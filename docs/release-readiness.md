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
- **`crypto_secretbox` (T-37) is unblocked to *start*, not yet built.** Per D-47 and D-05's own
  ten-mode breakdown: only CCM (done), GCM (not built — needs new GF(2^128) field arithmetic this
  crate doesn't have), and KW (not built) provide confidentiality+integrity and are eligible as its
  construction. ECB/CTR/CFB/CBC/OFB (confidentiality-only) and bare CMAC (integrity-only) — all
  real, standard-defined modes — must never become a public `crypto_secretbox`/`uacrypt
  encrypt`/`decrypt` entry point on their own.
- `crypto_secretstream` (T-40): the D-05-blocking concern (an ad hoc Strumok+KMAC EtM gap-fill
  would silently resolve D-05) no longer applies verbatim now that D-05 has an adopted answer — but
  `hazmat::kalyna_ccm`'s own 255-byte plaintext/AAD cap (D-41's sourced limit) still makes it
  unusable for a realistic streaming chunk size as-is. Not started; needs either a widened/chunked
  Kalyna-AEAD construction or GCM, neither of which exists yet.

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
| Kalyna | DSTU 7624:2014 | All 5 block/key-size variants, single-block encrypt/decrypt, `ExpandedKey` API. Vector-confirmed + dual-oracle. **Mode of operation**: only the provisional CCM above — no CBC/CFB/OFB/CTR/CMAC/XTS/GMAC from the standard's other ~10 modes are implemented (`TASKS.md` T-10's note: UAPKI's self-tests for those exist as unused KAT data). |
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
resource profile (D-35/D-38/D-39); `cargo miri test` and `cargo fuzz` wired into CI (with the
proptest+Miri-isolation interaction just fixed, T-85); `cargo audit`/`cargo deny` in CI; a
cross-platform `cargo xtask` build/QA runner (D-12); binary-level (not just in-process) performance
comparisons against UAPKI/reference-C on both x86-64 and a real Raspberry Pi ARM64 rig
(`PERFORMANCE.md`, D-34); zeroization of key material (D-20); a documented, scoped constant-time
exception for S-box/GF-multiplication table lookups, matching every reference implementation
(D-19).

## What's missing for the libsodium-equivalent surface

From `docs/dstu-crypto-project.md`'s own mapping table, the two-layer design (D-09: `hazmat::*` now,
a future high-level `crypto_*`-ergonomics layer on top) is decided; `crypto_sign` (below) is now the
first primitive with that high-level layer actually built, via `dstu_core::crypto_sign` — notably
*without* the `getrandom`-based auto-nonce shape D-09 originally anticipated (D-46's deterministic
nonce needs no RNG at all). `crypto_generichash`/`crypto_stream`/`crypto_auth`/`crypto_kdf` still
have no high-level wrapper, only their `hazmat` forms:

| libsodium equivalent | Native DSTU path | Status |
|---|---|---|
| `crypto_generichash` | Kupyna | hazmat done; no high-level wrapper |
| `crypto_stream` | Strumok | hazmat done (provisional vectors); no high-level wrapper |
| `crypto_sign` | DSTU 4145 | **Done** (T-48, D-46) — hazmat (m=163 only) plus a high-level `dstu_core::crypto_sign` wrapper; deterministic (Kupyna-KMAC-derived, RFC-6979-style) nonce, not caller-random, eliminating nonce-reuse key recovery from the wrapper's surface. Public-key encoding is a plain uncompressed 42-byte form, explicitly not the DSTU §6.9/§6.10 compressed format |
| `crypto_box` | DSTU 9041 | **Hard-blocked** — zero source material exists for DSTU 9041 anywhere (no paper, no oracle, no pseudocode); cannot start (T-46) |
| `crypto_secretbox` | Kalyna-CCM, provisionally | Unblocked to start 2026-07-24 (D-05 adopted on assumption, T-36), not yet built (T-37) |
| `crypto_auth`/`crypto_onetimeauth` | Kupyna-based KMAC | **Done** (T-38, D-44) — provisional pending the primary text, but dual-oracle with both constructions read |
| `crypto_kdf` | Kupyna-based KDF (libsodium `crypto_kdf`-shaped, not HKDF) | **Done** (T-39, D-45) — no DSTU standard or reference implementation exists for this at all, so unlike every other "provisional" row above, there is no oracle vector, ever; verification is determinism + distinctness property tests only |
| `crypto_kx` | DH on the DSTU 4145/9041 curve | Not started (T-47); DSTU 9041 side hard-blocked |
| `crypto_secretstream` | Chunked authenticated encryption, Kalyna-alone | D-05's blocker resolved 2026-07-24 (T-40), but not actually unblocked in practice — needs per-chunk AEAD over a large chunk size, and the only AEAD here (`kalyna_ccm`) caps at 255 bytes; needs a widened/chunked construction or GCM, neither built yet |
| `crypto_pwhash` | Not a DSTU question — plain Argon2id | **Done** (T-71, D-49/D-50) — over the `argon2` crate, dedicated `pwhash` feature (off by default, not folded into `std`); `Strength` presets mirror libsodium's own `OPSLIMIT`/`MEMLIMIT_*` constants exactly |
| `randombytes` | Not a DSTU question — OS CSPRNG via `getrandom` | **Done** (T-72, D-48) — `dstu_core::randombytes::randombytes_buf`, `std`-gated over an optional `getrandom` dependency; a plain function, deliberately not a generic `CryptoRng` trait since nothing in this crate consumes one yet |

`crypto_box`/`crypto_secretbox`/`crypto_kx`/`crypto_secretstream` remain empty or blocked — the
"functional copy of libsodium" goal has real algorithm coverage (`crypto_sign`/`crypto_auth`/
`crypto_kdf` done) but is not yet an API surface a libsodium user would recognize as complete.

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
| Encrypt one file/message of any size | `crypto_secretbox` equivalent | Kalyna-CCM | Yes, in principle | **Not built** (T-37) — the primitive exists, the wrapper doesn't | Build T-37 over CCM (already sufficient for the < 255-byte case) |
| Encrypt a large file / continuous stream (> 255 bytes at once) | Chunked AEAD | GCM (#7) or a widened CCM | Yes, if built | **Not built** (T-40) — `kalyna_ccm` caps at 255 bytes | Needs new GF(2^128) arithmetic for GCM, or a raised/removed CCM length limit |
| Full-disk encryption (random-access sectors) | Disk-mode cipher | XTS (#9) | No, by design — integrity is deliberately left to the filesystem layer, a recognized special case, not a gap | Not built | None needed — this is the one standard case where a non-AEAD mode is the *correct* choice, not a compromise |
| TLS-style record layer (browser, high throughput) | Per-record chunked AEAD | Same gap as the large-file row | Yes, if built | Not built | Same as above — GCM |
| Key exchange / handshake (ECDHE-equivalent) | Key agreement | DSTU 9041 (`crypto_kx`) | No mode exists at all | **Hard-blocked** — zero source material (no paper, oracle, or pseudocode, `TASKS.md` T-46/T-47) | **No safe DSTU replacement exists.** The only realistic path is a non-DSTU primitive (e.g. X25519) under the same "no homegrown primitive where DSTU has a real gap" precedent as Argon2id (D-03) — an explicit scope decision for the project owner, not an engineering task |
| Digital signatures | Sign/verify | DSTU 4145 (`crypto_sign`) | Yes | **Done** | not needed |
| Message/API authentication | MAC | Kupyna-KMAC (`crypto_auth`) | Yes (integrity-only is the actual goal here) | **Done** | not needed |
| Deriving subkeys from a master key | KDF | Kupyna-KDF (`crypto_kdf`) | Yes | **Done** | not needed |
| Password storage | Password hashing | Argon2id (`crypto_pwhash`, not DSTU) | Yes | **Done** | not needed |
| Key wrapping (envelope encryption) | Key wrap | Kalyna-**KW** (mode #10) | Yes | Not built | not needed once built |
| Nonces, salts, ephemeral values | CSPRNG | `randombytes` | Yes | **Done** | not needed |

**Bottom line**: for message-level and small-packet use cases (radio, API auth, signatures, KDF,
password storage) the safe-modes-only constraint is already fully sufficient — what's missing is
wrapper code (T-37), not a new safe primitive. For bulk/streaming use cases (large files, TLS-style
record layers) the gap is engineering, not a safety compromise — GCM or a widened CCM would close
it with an already-eligible, standard-defined combined mode. **The one use case with no safe DSTU
answer at all is key exchange** (`crypto_kx`/DSTU 9041) — this is a real scope boundary, not
something "safe modes only" can route around, since there is no DSTU-native mode of any kind to
choose from, safe or otherwise.

## What's missing for the CLI / release-mechanics surface

- **T-16**: no `uacrypt encrypt`/`decrypt`/`hash` top-level commands — those names stay reserved
  until `crypto_secretbox` (T-37) is actually built, not merely until D-05 resolves (D-05 itself
  resolved on assumption 2026-07-24, but T-37 isn't built yet). What exists (`kalyna-block`,
  `kalyna-ccm`, `kupyna-digest`, `strumok-crypt`) is hazmat-scoped and was built for binary-level
  performance comparison, not as the intended end-user surface.
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

In rough dependency order:

1. **D-05 resolved on assumption 2026-07-24 (T-36)** — Kalyna-alone, corroborated by two
   independent non-primary sources (this project's own vendored UAPKI ten-mode list, Ukrainian
   Wikipedia's independently-sourced ten-mode table), still not a reading of the priced primary
   DSTU 7624:2014 text. Acquiring that text (or another authoritative source) and confirming or
   revising against it remains open and would upgrade this from "assumption" to "confirmed," but no
   longer blocks starting `crypto_secretbox` (T-37) — only building it, still to do.
2. **Close Strumok's provenance gap (D-15)**, if the paid DSTU 8845:2019 text becomes available —
   otherwise, the release must state "Strumok vectors are UAPKI-attributed, not primary-confirmed"
   as prominently as the README banner now states the pre-release status generally.
3. **Build the missing constructions**: `crypto_auth` (T-38, D-44) and `crypto_kdf` (T-39, D-45)
   done, neither blocked on external material. `crypto_secretbox` (T-37) can now start against the
   Kalyna-CCM working hypothesis (only CCM/GCM/KW eligible, per D-47 - see the headline finding).
   `crypto_secretstream` (T-40) still needs a widened/chunked AEAD or GCM before it can start in
   practice - `kalyna_ccm`'s 255-byte cap (D-41) is the remaining blocker, not D-05 anymore.
4. **Build the high-level layer** (D-09's second layer) over every `hazmat` primitive that's ready —
   `crypto_sign` (step 5) is the first module built there; `crypto_auth`/`crypto_kdf` (step 3) don't
   have high-level wrappers yet either, only their `hazmat` forms.
5. **DSTU 4145 polish**: `crypto_sign` wrapper **done** (T-48, D-46) — deterministic nonce, not
   caller-random; decide whether the other 9 curve sizes matter for 1.0 or can stay m=163-only, and
   whether the DSTU §6.9/§6.10 compressed point encoding is needed for 1.0 (the wrapper currently
   ships only an uncompressed 42-byte form).
6. **DSTU 9041 stays out of scope for 1.0** unless source material is found — don't block the rest
   of the release on a hard-blocked item with no known path forward.
7. **Mechanical release work**: `uacrypt`'s real `encrypt`/`decrypt`/`hash` commands (T-16, gated
   on `crypto_secretbox`/T-37 actually being built, not merely on D-05 anymore), crates.io publish
   (T-17), GitHub Releases binaries (T-18), and a documentation pass aimed at an external consumer
   rather than an AI-agent-facing repo.

Steps 1-2 are the load-bearing ones: everything else can be built in parallel, but a release that
skips them is a release of provisional cryptography labeled as final, which is exactly the outcome
this document exists to flag before it happens by default.
