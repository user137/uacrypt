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

**This goal is currently blocked, not just incomplete.** The single open question that blocks it:
`DECISIONS.md` D-05 — whether Kalyna alone is DSTU 7624's intended AEAD construction, or whether
confidentiality + integrity requires a separate Kalyna+Kupyna encrypt-then-MAC design — is still
formally open, pending either the priced primary DSTU 7624:2014 text or another authoritative
source. Everything downstream of it inherits the same "provisional" status:

- `hazmat::kalyna_ccm` (the only AEAD-shaped construction that exists) is dual-oracle-verified
  (UAPKI + Bouncy Castle vectors) but explicitly **not confirmed against the primary standard text**
  (D-41).
- Strumok's entire vector set is UAPKI-attributed, not confirmed against the paid DSTU 8845:2019
  text either (D-15) — the same category of gap, on a different algorithm.
- There is no `crypto_secretbox`-equivalent construction at all yet — `hazmat::kalyna_ccm` is a
  standalone hazmat primitive, not wired up as one (`TASKS.md` T-36/T-37, both blocked on D-05).
- **Confirmed 2026-07-24, scoping T-40**: `crypto_secretstream` is not an independent gap either -
  it needs the *same* AEAD composition question D-05 asks, just chunked. Building it via a fresh
  Strumok+KMAC encrypt-then-MAC composition (the obvious-looking gap-fill, since both primitives
  already exist) would silently answer D-05 on the EtM side without the primary text - exactly the
  ad-hoc-construction failure this project's own discipline exists to prevent.

A release billed as "current, safe modes" cannot honestly ship on top of constructions the project's
own documentation already flags as unconfirmed. Closing this gap needs either (a) acquiring the
primary DSTU 7624:2014/8845:2019 texts and re-verifying the provisional constructions against them,
or (b) shipping 1.0 with the provisional status stated as loudly in the public API/docs as it
already is internally — a scope/marketing decision, not an engineering one, and one the project
owner should make explicitly rather than have it default one way silently.

## What's actually done (the solid part)

Three primitives are implemented and confirmed against official test vectors, each with an
independent second-oracle cross-check (Bouncy Castle, Java and .NET):

| Algorithm | Standard | Status |
|---|---|---|
| Kalyna | DSTU 7624:2014 | All 5 block/key-size variants, single-block encrypt/decrypt, `ExpandedKey` API. Vector-confirmed + dual-oracle. **Mode of operation**: only the provisional CCM above — no CBC/CFB/OFB/CTR/CMAC/XTS/GMAC from the standard's other ~10 modes are implemented (`TASKS.md` T-10's note: UAPKI's self-tests for those exist as unused KAT data). |
| Kupyna | DSTU 7564:2014 | Both 256/512 variants, one-shot `digest()` and streaming `Hasher`. Vector-confirmed + dual-oracle. KMAC (`crypto_auth` equivalent) now implemented too — `hazmat::kupyna_kmac`, dual-oracle with both constructions read (`TASKS.md` T-38, `DECISIONS.md` D-44), same provisional-pending-primary-text caveat. |
| Strumok | DSTU 8845:2019 | Both 256/512-bit key variants, keystream `apply_keystream`. **UAPKI-attributed vectors only** — no independent confirmation against the primary text exists anywhere (D-15) since no such oracle has been found; this is a provenance ceiling, not a code-quality gap. |

DSTU 4145-2002 (digital signatures) is further along than `docs/dstu-crypto-project.md`'s own
"Concrete API shape" table currently states (that table is stale on this point — flagged here,
should be corrected there too): the m=163 curve's `GF(2^163)` field arithmetic, point
add/double/constant-time scalar multiplication, and `sign`/`verify` are all implemented
(`hazmat::dstu4145`), verified against the official standard's own Annex B.1 worked example plus a
`proptest` round-trip, with two real bugs (a `Q = d·G` vs `Q = -d·G` sign error, a `hash_to_field`
calling-convention bug) found and fixed by re-deriving from the primary text directly rather than
trusting a single reference-implementation transcription (`DECISIONS.md` D-25). Only the m=163 curve
is wired up (9 other named curve sizes in Bouncy Castle's own enumeration are not); no `crypto_sign`
wrapper exists yet (T-48).

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
a future high-level `crypto_*`-ergonomics layer with auto-generated nonces via `getrandom`, not
built yet) is decided but the high-level layer itself doesn't exist for *any* primitive:

| libsodium equivalent | Native DSTU path | Status |
|---|---|---|
| `crypto_generichash` | Kupyna | hazmat done; no high-level wrapper |
| `crypto_stream` | Strumok | hazmat done (provisional vectors); no high-level wrapper |
| `crypto_sign` | DSTU 4145 | hazmat done (m=163 only); no high-level wrapper (T-48) |
| `crypto_box` | DSTU 9041 | **Hard-blocked** — zero source material exists for DSTU 9041 anywhere (no paper, no oracle, no pseudocode); cannot start (T-46) |
| `crypto_secretbox` | Kalyna-CCM, provisionally | Blocked on D-05 (T-36/T-37) |
| `crypto_auth`/`crypto_onetimeauth` | Kupyna-based KMAC | **Done** (T-38, D-44) — provisional pending the primary text, but dual-oracle with both constructions read |
| `crypto_kdf` | Kupyna-based KDF (libsodium `crypto_kdf`-shaped, not HKDF) | **Done** (T-39, D-45) — no DSTU standard or reference implementation exists for this at all, so unlike every other "provisional" row above, there is no oracle vector, ever; verification is determinism + distinctness property tests only |
| `crypto_kx` | DH on the DSTU 4145/9041 curve | Not started (T-47); DSTU 9041 side hard-blocked |
| `crypto_secretstream` | Chunked authenticated encryption over Strumok/Kalyna-CTR | **Blocked on D-05, not merely unscheduled** (T-40, re-scoped 2026-07-24) — needs per-chunk AEAD over a large chunk size, and the only AEAD here (`kalyna_ccm`) caps at 255 bytes; the natural gap-fill (a fresh Strumok+KMAC encrypt-then-MAC) *is* the D-05 question, so building it here would silently resolve D-05 on the EtM side without the primary text |
| `crypto_pwhash` | Not a DSTU question — plain Argon2id | Not started; no blocker, deliberately non-"Ukrainized" (documented decision) |
| `randombytes` | Not a DSTU question — OS CSPRNG via `getrandom` | Only exists inside `uacrypt` (CLI-only, D-04 addendum); no core-crate high-level wrapper yet |

Every row below `crypto_generichash`/`crypto_stream`/`crypto_sign` in this table is empty — the
"functional copy of libsodium" goal is currently three raw algorithms plus one provisional mode of
operation, not an API surface a libsodium user would recognize as equivalent yet.

## What's missing for the CLI / release-mechanics surface

- **T-16**: no `uacrypt encrypt`/`decrypt`/`hash` top-level commands — those names stay reserved
  until D-05 resolves. What exists (`kalyna-block`, `kalyna-ccm`, `kupyna-digest`, `strumok-crypt`)
  is hazmat-scoped and was built for binary-level performance comparison, not as the intended
  end-user surface.
- **T-17**: `dstu-core` not published to crates.io. Now unblocked mechanically (D-43's version bump),
  but publishing a `0.1.0` that is honest about D-05/D-15/D-41's provisional status is a judgment
  call for the project owner, not an engineering blocker.
- **T-18**: no prebuilt GitHub Releases binaries for Windows/Linux/macOS.
- No user-facing documentation beyond this repo's own `.md` files exists yet (no rustdoc pass
  dedicated to public API ergonomics, no separate docs site/book) — a real release needs
  API-level docs a consumer reads without first reading `DECISIONS.md`.
- Phase 3 (language bindings: Python/JS/Java/.NET/C++) is entirely unstarted — not required for a
  Rust-crate-only 1.0, but relevant if "libsodium-equivalent" is read to include libsodium's
  multi-language reach.

## Concrete path to a genuinely safe, complete release

In rough dependency order:

1. **Resolve D-05.** Acquire the primary DSTU 7624:2014 text (or find another authoritative source)
   and confirm or revise the Kalyna-CCM construction against it. This unblocks `crypto_secretbox`
   (T-36/T-37) and is the single highest-leverage item — nearly every other gap below assumes an
   answer here.
2. **Close Strumok's provenance gap (D-15)**, if the paid DSTU 8845:2019 text becomes available —
   otherwise, the release must state "Strumok vectors are UAPKI-attributed, not primary-confirmed"
   as prominently as the README banner now states the pre-release status generally.
3. **Build the missing constructions**: `crypto_auth` (T-38, D-44) and `crypto_kdf` (T-39, D-45)
   done, neither blocked on external material. `crypto_secretstream` (T-40) turned out to **not**
   belong in this "just engineering time" bucket on closer look (2026-07-24) - it needs per-chunk
   AEAD over a realistic chunk size, and the only AEAD here (`kalyna_ccm`) caps at 255 bytes; the
   natural gap-fill construction is the same one D-05/T-36/T-37 are blocked on, so it moves to
   step 1's dependency instead of running in parallel with it.
4. **Build the high-level layer** (D-09's second layer) over every `hazmat` primitive that's ready —
   this is what actually makes the API "libsodium-equivalent" in feel, not just in algorithm
   coverage.
5. **DSTU 4145 polish**: wrap `crypto_sign` (T-48); decide whether the other 9 curve sizes matter
   for 1.0 or can stay m=163-only.
6. **DSTU 9041 stays out of scope for 1.0** unless source material is found — don't block the rest
   of the release on a hard-blocked item with no known path forward.
7. **Mechanical release work**: `uacrypt`'s real `encrypt`/`decrypt`/`hash` commands (T-16, itself
   gated on step 1), crates.io publish (T-17), GitHub Releases binaries (T-18), and a documentation
   pass aimed at an external consumer rather than an AI-agent-facing repo.

Steps 1-2 are the load-bearing ones: everything else can be built in parallel, but a release that
skips them is a release of provisional cryptography labeled as final, which is exactly the outcome
this document exists to flag before it happens by default.
