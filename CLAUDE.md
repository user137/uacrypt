# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Communication language

Respond to the project owner in Ukrainian by default in this repository — don't wait for them to
switch language first (requested explicitly 2026-07-25; complements, doesn't replace, the global
"use Ukrainian when the user writes in Ukrainian" rule in `~/.claude/CLAUDE.md`, and mirrors the
same note already in `.claude.local.md`, recorded here too since that file isn't committed). This
governs conversational replies only — code, identifiers, commit messages, and this repo's own docs
stay in whatever language they already use.

## Project status

All three of Phase 1's MVP primitives have landed and are confirmed green. A local toolchain
(Rust, a C compiler, Maven) was installed into this environment on 2026-07-22 — see
`.claude.local.md`; `cargo`/`gcc`/`mvn` all work here now, this is no longer a "no toolchain"
environment. The workspace has two crates:

- `crates/dstu-core` — the library (`std`/`alloc` feature flags per D-01). `dstu_core::hazmat` has
  three primitives: `kupyna::{Kupyna256, Kupyna512}` (one-shot `digest()`, plus `Kupyna256Hasher`/
  `Kupyna512Hasher` for streaming `update`/`finalize` as of 2026-07-23, `docs/TASKS.md` T-83, citation
  `docs/DECISIONS.md` D-10), `kalyna::{Kalyna128_128, Kalyna128_256, Kalyna256_256,
  Kalyna256_512, Kalyna512_512}` (single-block `encrypt`/`decrypt`, citation `docs/DECISIONS.md` D-13) —
  plus, as of 2026-07-23, `kalyna_ccm` (all five variants, a provisional Kalyna-alone CCM mode of
  operation, citation `docs/DECISIONS.md` D-41, still not confirmed against the primary DSTU 7624:2014
  text — same posture as Strumok below) and `kupyna_kmac::{Kupyna256Kmac, Kupyna384Kmac,
  Kupyna512Kmac}` (the `crypto_auth` equivalent, citation `docs/DECISIONS.md` D-44 — provisional too, but
  on stronger dual-oracle evidence than `kalyna_ccm`/Strumok since both reference constructions were
  read, not just one plus the other's vectors), plus `kupyna_kdf::{Kupyna256Kdf, Kupyna384Kdf,
  Kupyna512Kdf}` (the `crypto_kdf` equivalent, `docs/DECISIONS.md` D-45, built on `kupyna_kmac` — a
  from-scratch design following libsodium's `crypto_kdf` shape, since no DSTU KDF standard or
  reference implementation exists at all; verified by property test only, no oracle vector exists
  to write) — and `strumok::{Strumok256, Strumok512}` (keystream generation via
  `apply_keystream`, citation `docs/DECISIONS.md` D-18 — vectors are UAPKI-attributed, not confirmed
  against the official DSTU 8845:2019 text itself, see D-15; as of 2026-07-31, also independently
  confirmed against two state-sourced supplementary vectors from Держспецзв'язку/ДНДІ ТКЗІ, an
  upgrade over UAPKI alone but still not equivalent to the paid standard text itself, see D-104).
  All three written test-first;
  Kalyna/Kupyna share S-box/MDS tables via the internal `hazmat::tables` module rather than
  duplicating them, and Strumok's `T` substitution reuses those same shared tables too (only its
  `mul_alpha`/`mul_alpha_inv` tables are new, since that field construction isn't shared). All
  three are **confirmed**: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, the
  `no_std` build, and `cargo miri test` all pass. Kalyna's independent second-oracle cross-check
  (Java/.NET vs. real Bouncy Castle) is done and re-confirmed 2026-07-23 - an older "still open"
  note here was simply stale (`docs/TASKS.md` T-10). As of 2026-07-24, `dstu_core::crypto_sign`
  (`SigningKey`/`VerifyingKey`/`Signature`, `docs/TASKS.md` T-48, `docs/DECISIONS.md` D-46) is the first
  high-level `crypto_*`-ergonomics module built on top of `hazmat` (D-09's second layer) — wraps
  `hazmat::dstu4145`, deterministic (Kupyna-KMAC-derived, not caller-random) nonce, no RNG
  dependency. Check `docs/TASKS.md` Phase 1 for what else is still open (`crypto_generichash`/
  `crypto_stream`/`crypto_auth`/`crypto_kdf` have no high-level wrapper yet). `kalyna_ccm`'s
  nonce strategy is resolved (`docs/DECISIONS.md` D-40, `docs/TASKS.md` T-82):
  wide random nonce generated at the CLI layer via `getrandom`, not a stateful counter — the
  hazmat-level API itself still takes a caller-supplied nonce (`no_std`-compatible). As of
  2026-07-24, `dstu_core::randombytes::randombytes_buf` (`docs/TASKS.md` T-72, `docs/DECISIONS.md` D-48) is
  the first core-crate `randombytes` wrapper — `std`-gated over an optional `getrandom`
  dependency, deliberately a plain function rather than a generic `CryptoRng` trait since nothing
  in this crate consumes one yet. `cargo
  fuzz` has now actually been run (all three
  targets, smoke runs, zero crashes) on a Windows dev machine with Visual Studio installed, via the
  MSVC toolchain/target (`docs/DECISIONS.md` D-32) — CI (Linux) remains the unconditional per-push check.
  Also as of 2026-07-24, `dstu_core::crypto_pwhash` (`hash_password`/`verify_password`/`Strength`,
  `docs/TASKS.md` T-71, `docs/DECISIONS.md` D-49/D-50) wraps the vetted `argon2` crate behind a new dedicated
  `pwhash` feature (off by default, not folded into `std`) — the deliberately non-DSTU
  `crypto_pwhash` component, with `Strength::{Interactive,Moderate,Sensitive}` citing libsodium's
  own `OPSLIMIT`/`MEMLIMIT_*` constants exactly, no raw cost-parameter knob exposed. Same day,
  `dstu_core::crypto_secretbox` (`seal`/`open`/`SecretKey`, `docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51) is
  the first `crypto_secretbox` equivalent (D-47's "delete the knob" criterion, not all five
  variants), internally-generated nonce, combined `nonce||ciphertext||tag` output, deliberately no
  AAD parameter — originally a single fixed `hazmat::kalyna_ccm::Kalyna256_256Ccm` construction,
  since migrated to Kalyna-GCM (D-63, below), which removed the original 255-byte cap. Folded into
  the existing `std` feature, not a new dedicated one, since no new dependency is introduced. Unblocked
  `docs/TASKS.md` T-16 (`uacrypt`'s reserved `encrypt`/`decrypt` commands) to start - **T-16 itself is
  now done too, same session** (`docs/DECISIONS.md` D-52): `uacrypt encrypt`/`decrypt`/`hash` are real
  commands. `encrypt`/`decrypt` are a thin CLI wrapper over `crypto_secretbox` - `--key`/`--in`/
  `--out` only, inheriting its 255-byte cap (loud error, not silent truncation - a deliberate
  product choice made with the user, not a default assumption, since a command named `encrypt`
  silently failing past 255 bytes would be a real usability trap). `hash` is fixed to Kupyna-256,
  no length cap, delegates to `kupyna-digest`'s already-streaming implementation rather than
  duplicating it. **`crypto_secretbox` migrated from Kalyna-CCM to `hazmat::kalyna_gcm::Kalyna256_256Gcm`
  (roadmap Step 3 item 1, `docs/DECISIONS.md` D-63)** — cap/caveat detail is in "MVP scope" below, not
  repeated here. The migration surfaced a real nonce-authentication gap not
  in the original plan: DSTU Kalyna-GCM's tag (unlike CCM's) never covers the IV/nonce (D-56
  divergence 3), which for `crypto_secretbox`'s self-contained `nonce||ciphertext||tag` blob would
  have let an attacker tamper the nonce prefix without failing the tag check — fixed by passing the
  nonce as `kalyna_gcm`'s internal AAD in both `seal`/`open` (still no caller-facing AAD parameter),
  caught by a test written during the migration itself, not discovered after the fact. Same day,
  roadmap Step 3 item 2 (`docs/TASKS.md` T-105, `docs/DECISIONS.md` D-66) landed too: `dstu_core::
  crypto_generichash`/`crypto_auth`/`crypto_kdf`, the high-level `crypto_*` modules for Kupyna's
  hash, KMAC, and KDF — `crypto_generichash` is a bare re-export of `hazmat::kupyna` (nothing to
  wrap), `crypto_auth`/`crypto_kdf` are thin wrappers exposing only the 256-bit
  `Kupyna256Kmac`/`Kupyna256Kdf` variant behind an opaque `Zeroize`-on-drop key type (D-47's
  "delete the knob", same as `crypto_secretbox`'s single Kalyna variant), all three unconditional
  (`no_std`-compatible) except each key type's `std`-gated `generate()`. One day later, roadmap
  Step 3 item 3 (`docs/TASKS.md` T-106, `docs/DECISIONS.md` D-67) landed too: `dstu_core::crypto_stream`
  (`encrypt`/`decrypt`/`Key`, single `Strumok256` variant only) — the one roadmap fork left
  genuinely open in `docs/TASKS.md`'s own text, put to the project owner directly before implementing
  (not decided unilaterally the way D-66's own fork was, a gap flagged after the fact): the IV is
  hidden/internally-generated, matching `crypto_secretbox`'s nonce precedent. **No authentication**
  — `hazmat::strumok` is a bare keystream generator, so `decrypt` never fails on tampered input,
  which is exactly why the functions are named `encrypt`/`decrypt` and not `seal`/`open`.
  `crypto_stream` is `std`-gated at the whole-module level (needs `Vec<u8>`), unlike the other
  three's per-item gating, since it can't avoid `alloc` the way fixed-array modules can — Step 3 is
  now fully complete (all five items done). As of 2026-07-25, roadmap Step 5 item 1 (`docs/TASKS.md`
  T-40/T-70, `docs/DECISIONS.md` D-68) landed: `dstu_core::crypto_secretstream`
  (`PushState`/`PullState`/`Key`/`Tag`) — a genuinely chunked/streaming AEAD, the one remaining
  functional gap between `crypto_secretbox`'s whole-buffer AEAD and covering large files with
  bounded memory. No DSTU standard defines a streaming AEAD mode, so (D-47's tie-breaker) this
  follows libsodium's `crypto_secretstream_xchacha20poly1305` shape — tag-per-chunk framing (full
  `Message`/`Push`/`Rekey`/`Final` tag set, the user's explicit choice over the minimal two-tag
  set) over `hazmat::kalyna_gcm` (same `Kalyna256_256Gcm` variant `crypto_secretbox` uses) with
  per-chunk subkey/counter/AAD binding built on `hazmat::kupyna_kmac` for header-derived subkeys and
  one-way `Rekey` forward secrecy — over `ChaCha20-Poly1305`. Caller-supplied `&mut [u8]` chunk
  buffers (the user's explicit choice over `Vec`-returning), per-item `std`-gated (only
  `PushState::init`'s header generation needs it) — a stricter `no_std` fit than any other
  high-level `crypto_*` module built so far. `uacrypt encrypt`/`decrypt` were rewired to it the same
  session (the user's explicit scope choice, not library-only) — a breaking wire-format change from
  the old `crypto_secretbox`-backed command (new chunked on-disk format, `--in`/`--out` genuinely
  streamed in `SECRETSTREAM_CHUNK_BYTES`-sized chunks, temp-file-then-rename atomicity so "no
  partial output on failure" still holds under real streaming I/O), called out explicitly as
  acceptable pre-1.0 rather than left implicit; `crypto_secretbox` itself is not removed, it stays a
  separate, still-tested library primitive. No oracle vector exists for this construction, ever
  (same posture as `crypto_kdf`, D-45) — verified by property test, tamper (D-64), and misuse (D-65)
  coverage instead: 22/22 library tests and 48/48 `uacrypt` tests passed on first write, full
  workspace suite/clippy/fmt/`no_std` feature matrix all clean, scoped Miri 22/22 passed with 0 UB
  in 1276.00s (~21.3 min).
- `crates/uacrypt` — the CLI binary, renamed 2026-07-23 from its `dstutool` working name
  (`docs/DECISIONS.md` D-36; older `docs/DECISIONS.md`/`docs/TASKS.md`/`docs/PERFORMANCE.md` entries predating the
  rename still say `dstutool`, left as-is since they're a historical record, not stale docs).
  No longer a placeholder: `kalyna-block encrypt/decrypt`, `kupyna-digest`, and `strumok-crypt`
  subcommands exist (`docs/DECISIONS.md` D-31), used for binary-level performance comparisons
  (`docs/PERFORMANCE.md`); as of 2026-07-23, `kalyna-ccm encrypt/decrypt` also exists (`docs/DECISIONS.md`
  D-41) — still deliberately not the reserved top-level `encrypt`/`decrypt` names: D-05 was
  resolved on assumption 2026-07-24 (Kalyna-alone, corroborated by two independent non-primary
  sources - `oracles/uapki`'s own ten-mode list and Ukrainian Wikipedia's matching mode table, see
  `docs/DECISIONS.md` D-05's latest revision), and those reserved names' other gate,
  `dstu_core::crypto_secretbox` actually being built (T-37), cleared the same day too (`docs/DECISIONS.md`
  D-51) — `uacrypt`'s own `encrypt`/`decrypt`/`hash` commands (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52)
  are now built too, same session, per the file-plus-mode-of-operation CLI the MVP scope below
  describes. `encrypt`/`decrypt`'s message-length cap was later removed (D-63) — see "MVP scope"
  below for the current-state detail; `hash` has no such limit either. **As of 2026-07-25,
  `encrypt`/`decrypt` are rewired onto `dstu_core::crypto_secretstream` instead of
  `crypto_secretbox`** (`docs/TASKS.md` T-40/T-70, `docs/DECISIONS.md` D-68) — a genuinely chunked, memory-
  bounded on-disk format, a breaking change from the prior `crypto_secretbox`-backed blob format
  (acceptable pre-1.0, called out explicitly rather than left implicit). `hash` and `kalyna-ccm`
  are unaffected.

`cargo xtask <command>` (see `xtask/`, aliased via `.cargo/config.toml`) is the one cross-platform
build/QA entry point — same command on Linux/Windows/macOS, no new install beyond `cargo` itself.
`cargo xtask ci` runs the mandatory checks then best-effort runs miri/fuzz/audit/deny/oracle
harnesses, printing an install hint for whichever optional tool isn't present rather than failing.
See `docs/DECISIONS.md` D-12 and `README.md` "Development commands". Use this instead of writing a new
one-off shell/PowerShell script for any build/QA task.

Official test vectors are extracted and verified for Kalyna and Kupyna:
`crates/dstu-core/tests/vectors/{kalyna,kupyna}/*.json` — see `docs/ORACLES.md` for provenance and
format. These vectors have additionally been run against real Bouncy Castle (Java and .NET, via
the published packages, not the vendored oracle clones) in `tests/oracle-harness/{java,dotnet}/`
and passed in full — see `docs/TASKS.md` "Infrastructure". No C/cryptonite harness — tried and
dropped, see `docs/TASKS.md` and `docs/ORACLES.md` for why.

The concrete module-by-module API surface (what's implemented, what's blocked, and why) lives in
`docs/dstu-crypto-project.md` "Concrete API shape" and is tracked as a checklist in `docs/TASKS.md`.

The full spec lives in `docs/dstu-crypto-project.md`. Read it before planning any implementation
work — it is the source of truth for scope and architecture decisions below.

## What this project is

An open-source crypto library for Ukrainian DSTU cryptographic standards, in the spirit of
**libsodium** (hard, safe defaults, misuse-resistant API) rather than OpenSSL (flexible, easy to
misconfigure).

Algorithms in scope:

| Algorithm | Standard | Type |
|---|---|---|
| Kalyna | DSTU 7624:2014 | symmetric block cipher |
| Kupyna | DSTU 7564:2014 | hash function |
| Strumok | DSTU 8845:2019 | stream cipher |
| (unnamed) | DSTU 4145-2002 | ECDSA-style digital signature |
| (unnamed) | DSTU 9041:2020 | asymmetric encryption (twisted Edwards curves) |

## MVP scope (first priority)

- Rust core implementing Kalyna + Kupyna + Strumok, verified against official DSTU test vectors.
- Single CLI binary over the core (`uacrypt`, `docs/DECISIONS.md` D-36), e.g.
  `uacrypt encrypt --key ... --in file --out file` — mode, nonce/IV etc. are hardcoded so there's
  nothing for the user to misconfigure. **Built** (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52). **As of
  2026-07-25 (`docs/DECISIONS.md` D-63), `encrypt`/`decrypt` have no message-length cap** -
  `crypto_secretbox` migrated from Kalyna-CCM to Kalyna-GCM, which encodes no length limit into
  itself. **Same day, `encrypt`/`decrypt` were rewired again onto `dstu_core::crypto_secretstream`
  (`docs/TASKS.md` T-40/T-70, `docs/DECISIONS.md` D-68)** - `--in`/`--out` are now genuinely streamed in
  fixed-size chunks (block-at-a-time disk I/O, D-42's standing policy), not read whole into memory
  - the tracked follow-up D-63 itself named is now done, not still open.
- Publish the core crate to crates.io. Not started - `docs/TASKS.md` T-17, explicitly gated on an owner
  request (re-confirmed 2026-07-26 alongside T-18 landing, below - a GitHub release and a crates.io
  publish are different platforms with different reversibility, not the same ask).
- Prebuilt binaries for Windows/Linux via GitHub Releases (not "clone and build yourself"). **Done
  2026-07-26** (`docs/TASKS.md` T-18/T-119) - also macOS (Apple Silicon), plus a `dstu-core` source
  distribution attached to the same release, wider than this bullet's original Windows/Linux-only
  wording. `.github/workflows/release.yml` builds all three platforms on a `v*` tag push.
- **No hardware or OS lock-in — platform-agnostic by construction.** This targets both ends
  genuinely, not just one with lip service to the other: full PCs/servers (Windows, Linux, macOS,
  x86-64/ARM64) *and* microcontrollers (STM32 on ARM Cortex-M, ESP32 on Xtensa/RISC-V — genuinely
  different architectures, not variations of one). Concretely:
  - **Core must be `no_std`-compatible from day one** (Cargo feature flags `std` / `alloc` /
    `no_std`) so embedded targets can be added later without a core rewrite. Real-hardware
    validation is a separate post-MVP phase. The non-embedded ARM64/Linux half of this claim now
    has a real hardware rig checking it (a Raspberry Pi, `docs/TASKS.md` "Testing & hardening" — access
    details in `.claude.local.md`, not committed); the bare-metal STM32/ESP32 half is still Phase 4.
  - No dependency, API choice, or build assumption may quietly assume a specific OS (e.g.
    Windows-only path handling, a Unix-only syscall) or a specific CPU family (e.g. an intrinsic
    with no portable fallback) unless it's isolated behind a feature flag with a working
    alternative for the platforms it excludes.
  - Important distinction: no_std/embedded compilation support ≠ resistance to hardware
    side-channel attacks (SPA/DPA). The latter needs a separate, expensive hardware audit; until
    one exists, side-channel resistance must never be claimed.

## Second priority (not MVP)

- Language bindings: Python, JavaScript, Java, .NET, C++.
- Do not reimplement DSTU 4145 signatures in the native core — for Java/.NET, wrap/integrate
  Bouncy Castle (mature existing implementation, `DSTU4145Signer`, decades in production,
  continuous external audit); for Rust, port with Bouncy Castle as a second verification oracle.

## Explicitly out of scope

- **Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna)** — do not implement, and do
  not propose implementing, without a separate explicit decision from the project owner. See D-08
  in `docs/DECISIONS.md` for the full rationale (different math class from the rest of this project,
  complexity on the order of all five in-scope algorithms combined, immature cryptanalysis, no
  vetted oracle exists). If this is ever picked up, `docs/dstu-crypto-project.md` "Post-quantum
  track" has the fuller context.

## Documentation map

| File | Read when | Update when | Canonical owner of |
|---|---|---|---|
| `docs/TASKS.md` | starting or resuming any work session | a task is started, finished, or newly discovered | phase-by-phase task backlog and progress state — status only, not rationale |
| `docs/dstu-crypto-project.md` | planning scope, API design, algorithm choices | scope or API-mapping decisions change | project scope, libsodium API mapping |
| `docs/resource-profiles.md` | choosing/explaining `fused` vs `small-tables`, sizing a target's flash budget | the profile split's memory/speed numbers change, or a new MCU tier is added to the sizing guide | `small-tables` feature memory/speed numbers (`docs/DECISIONS.md` D-35/D-38/D-39), per-target profile recommendation |
| `docs/release-readiness.md` | assessing distance to a real, complete release; deciding what to build next toward it | a blocking item resolves (esp. D-05), a new construction lands, or the gap analysis otherwise changes | gap analysis between current state and a libsodium-equivalent 1.0 (`docs/DECISIONS.md` D-43, `docs/TASKS.md` T-87) |
| `docs/user-journey-gaps.md` | assessing whether a real persona (binary user, library user, constrained-target user) can actually complete their journey end to end, not just whether a construction/API exists | a new persona-blocking gap is found or an existing one closes (e.g. T-18/`uacrypt keygen`/crates.io publication) | persona/journey-framed gap analysis (`docs/TASKS.md` T-114) — complements, doesn't replace, `docs/release-readiness.md` (construction-organized) and `docs/dstu-crypto-project.md`'s API-mapping table (libsodium-function-organized) |
| `docs/SECURITY.md` | before writing any crypto primitive or adding a dependency | threat model or hard constraints change | threat model, hard constraints, supply-chain vetting |
| `docs/DECISIONS.md` | need the reason behind an architectural choice | a new architectural decision is made | decisions + rejected alternatives, with citations |
| `docs/ORACLES.md` | before implementing or verifying any primitive | oracle trust ranking changes, or a new oracle/vector source is added | oracle trust matrix, per-algorithm oracle map, test-vector convention, list of reference implementations (`oracles/README.md` links here rather than duplicating) |
| `docs/pseudocode/*.md` | before writing a primitive's Rust implementation | the transcription changes or a new ambiguity/discrepancy is found | per-algorithm pseudocode — from-spec for Kalyna/Kupyna/Strumok, from-oracle-code for DSTU 4145 (official text now exists too — see the doc's 2026-07-22 update note — but the pseudocode itself isn't re-derived from it yet), each cross-checked and with any ambiguity flagged inline |
| `docs/rust_ai_ruleset.md` | general Rust code-style questions | never (external ruleset, treat as canonical as-is) | generic Rust engineering conventions |
| `docs/cross-language-style-guide.md` | writing or reviewing non-Rust code (oracle harnesses, future language bindings) | a new language is added, or a cross-language principle needs adjusting | cross-language naming/style principles and the per-language reference table; generalizes `docs/rust_ai_ruleset.md`, doesn't replace it |
| `README.md` | need the human-facing project overview or repo tree | repo structure changes | GitHub-facing description, top-level directory map, build/install instructions |
| `docs/PERFORMANCE.md` | need this project's benchmark numbers, or comparing against another implementation's speed | new numbers are measured, or a new comparison implementation is benchmarked | benchmark methodology (cross-implementation comparisons are binary-level/MB/s only, `docs/DECISIONS.md` D-34 — `cargo bench`/`criterion` is for internal regression tracking only, never a cross-implementation claim), recorded numbers, comparisons against reference C/UAPKI/outspace, the saved `criterion --baseline` for regression tracking |
| `xtask/src/main.rs` | adding or changing a build/QA subcommand | a new tool enters the QA stack or an existing command's invocation changes | the actual cross-platform build/QA command implementations (README.md documents usage, this owns behavior) |

`docs/rust_ai_ruleset.md` §7 (async/tokio) does not apply to the `no_std`-first core — it's only
relevant if a future CLI or binding layer adds async I/O.

## Crypto engineering hard constraints

Full detail and rationale in `docs/SECURITY.md` — this is the compressed version so it can't be missed:

- No primitive without a cited spec section (DSTU clause or reference-implementation source) —
  citation goes in `docs/DECISIONS.md`.
- **When an architectural fork has no settling DSTU citation** (spec silent/ambiguous/unavailable —
  D-05's gap is the recurring case): resolve via `docs/DECISIONS.md` D-47's ranked tie-breaker — (1) TLS
  1.3 lessons/modern AEAD consensus (combined constructions over hand-composed ones), (2)
  libsodium's API shape (hard defaults, no misconfigurable knobs), (3) expose only safe modes of
  operation, never an unsafe/legacy one as a public entry point. A real spec citation always outranks
  this rule once one exists — it's for gaps, not a license to design by analogy instead of by spec.
- No secret-dependent branching. Secret-dependent array indexing is allowed only for fixed-latency
  S-box/GF-multiplication table lookups mirroring the DSTU reference implementations — documented
  software-timing exception, see D-19 in `docs/DECISIONS.md`, not a license to add more of this
  category casually. Secret comparisons via `subtle::ConstantTimeEq`, never `==`; all key material
  is `Zeroize`/`ZeroizeOnDrop`; no secret material in logs.
- No homegrown primitives — where DSTU has a real gap (pwhash, CSPRNG), use the established
  international primitive (Argon2id, OS `getrandom`), see D-03/D-04 in `docs/DECISIONS.md`.
- **Dual-oracle verification is mandatory**: official DSTU test vectors *and* an independent
  reference implementation (Kalyna-reference, cryptonite, Bouncy Castle — see `docs/ORACLES.md` for the
  per-algorithm map). Self-consistent tests passing is not sufficient evidence.
- `cargo miri test` and `cargo fuzz` are required layers, not optional tooling.
- This is the software-side complement to the SPA/DPA note above: constant-time discipline
  reduces exposure but is never itself a side-channel-resistance claim.
- **Any wire format that bundles a nonce/IV together with ciphertext+tag into one self-contained
  blob (a `crypto_secretbox`-style construction) must verify — by reading the construction's actual
  tag computation, not assuming — that the tag covers that nonce/IV.** Not every AEAD does: DSTU
  Kalyna-GCM's tag is `E_K(acc XOR length_block)`, a function of AAD+ciphertext only (D-56
  divergence 3) — the nonce only seeds the keystream, unlike CCM (whose B0 block folds the nonce
  into the CBC-MAC) or NIST AES-GCM (`J0` is nonce-derived). If the nonce isn't covered and it
  travels in the same blob a caller trusts as one unit, an attacker can tamper the nonce prefix and
  have decryption "succeed" against wrong, unverified plaintext instead of failing closed. Fix by
  passing the nonce as the construction's own AAD parameter (binding it into the tag through the
  mechanism the construction already provides for exactly this), not by inventing a new check. See
  `docs/DECISIONS.md` D-63 for the concrete case (`crypto_secretbox`'s Kalyna-CCM→Kalyna-GCM migration)
  — check this again for every future combined-AEAD wrapper (`crypto_secretstream`/T-40 included),
  don't assume it only applied once.

## Agent discipline

- **UTF-8 everywhere, no exceptions.** Every text file in this repo — source, docs, config,
  test-vector JSON — is UTF-8, without a byte-order mark. This matters concretely here: the
  project mixes English docs with Ukrainian source material (paper titles, standard names,
  commit/PR text when the user writes Ukrainian) and extracts hex/text from PDFs via `pdftotext`
  on Windows, all of which can silently introduce UTF-16, a BOM, or a Windows codepage (e.g.
  CP1251) if a tool's default isn't checked. Verify encoding when creating or editing a file if
  there's any doubt, rather than assuming the tool defaulted correctly.
- **`WebFetch`'s summarization is unreliable on Cyrillic/font-encoding-broken PDFs and wikitext**
  (produced both a false "no relevant content" and a fabricated-sounding claim on the same D-05
  research session, 2026-07-24) — for any DSTU-related Cyrillic source, fetch raw text/wikitext
  directly (`curl`) or render pages to PNG and read them; never trust a `WebFetch` prompt's answer
  about one at face value. See `docs/DECISIONS.md` D-05's 2026-07-24 revision for the concrete case.
- **Excluding a dependency's own feature doesn't stop its transitive dependencies' *default*
  features from turning on anyway** — confirmed via `cargo tree -e normal --features <feature>`,
  not assumed, adding `argon2` (D-50): skipping `argon2`'s own `rand` feature didn't keep `rand_core`
  out, because `argon2`'s manifest enables its `password-hash` dependency without
  `default-features = false`, and `password-hash`'s own defaults include `rand_core`. Cargo feature
  unification is additive-only — nothing in *this* project's `Cargo.toml` can suppress a transitive
  default another dependency itself requested. Always verify with `cargo tree`, don't assume a
  feature flag fully scopes what it looks like it scopes.
- **Test-first, always.** Write the failing test before the implementation — a unit test, or for
  crypto code, a test-vector check (see dual-oracle verification above). Never write the
  implementation first and backfill tests afterward. This applies to every function, not just
  primitives.
  - **Every new primitive/mode/wrapper/CLI command ships three test categories, not one**:
    (1) correctness against a vector/oracle, (2) **rejection** — tampered ciphertext/tag/aad/nonce
    and wrong key, wherever a tag or checksum exists to tamper with (the "attack" pass, D-64) —
    and (3) **misuse** — invalid lengths/args/paths, a nonexistent or directory `--in`, same-path
    `--in`/`--out`, degenerate-but-legal input (empty file, all-zero key, `--iterations 0`)
    succeeding rather than erroring, and no partial output written on failure (the "fool" pass,
    D-65). Skipping either category because "it'll obviously pass" is exactly backwards — D-63's
    nonce-authentication gap and this pass's several `wrong_key_is_rejected` gaps were both found
    by noticing an *absent* test, not a code walkthrough.
  - **Where a misuse category is foreclosed by the type signature** (e.g. `SecretKey::from_bytes`
    taking `[u8; 32]` makes "wrong key length" uncompilable, not just untested), **record that in
    `docs/DECISIONS.md` as a finding, don't write a test that only proves the compiler works** — that's
    noise under this project's no-speculative-tests rule, not coverage.
  - **Rejection/misuse tests passing on first write is expected, not a test-first violation.**
    They are coverage for a code path that already exists and is already correct, not red-green
    development of new behavior — don't read "passed immediately" as a reason to doubt or skip
    them.
- **A `hazmat` streaming/incremental API existing does not make the `uacrypt` command wrapping it
  memory-bounded** (`docs/DECISIONS.md` D-42) — a CLI command has to be deliberately wired to read its
  input in fixed chunks instead of `std::fs::read`-ing the whole file, every time a new algorithm
  gains a genuine streaming API (unless its construction truly needs the whole message up front,
  e.g. a length-prefixed AEAD header — not the same thing as "the current code happens to read it
  all at once"). Both `kupyna-digest` (T-83/D-42) and `strumok-crypt` (D-42) do this now: small
  chunks for real single-pass use, larger (or unchanged in-memory) chunks for the `--iterations`
  benchmark path, sized for each path's actual constraint (memory vs. throughput) rather than
  copied from another algorithm's numbers — for a cipher this means chunking both the disk read
  *and* the disk write, since output length equals input length, unlike a hash.
- **Three-attempts rule**: if the same problem survives 3 different approaches (especially
  toolchain/build/CI issues), stop, report what was tried and what's still unknown, and wait for
  direction — don't self-authorize a 4th attempt.
- **Research before implementation**: no primitive written from memory. Verify against the
  primary source (specific DSTU clause, or real reference-implementation code) before writing it,
  and record the citation in `docs/DECISIONS.md`. **If only a reference implementation is available
  (the primary spec text doesn't exist yet or hasn't been read)**, treat that citation as
  provisional, not equivalent to a primary-source check — say so explicitly in `docs/DECISIONS.md`
  (Strumok's "UAPKI-attributed, not confirmed against the official text" framing, D-15, is the
  pattern to copy) and re-verify against the primary text as soon as it's available, rather than
  letting the provisional citation quietly age into being treated as settled. Also: **porting logic
  from a reference implementation means porting its calling convention too**, not just its
  internals — a reference implementation's function can have its own input/output convention (byte
  order, sign, units) that differs from the primary spec's, and copying the internal logic without
  also adopting (or consciously translating) that convention is a distinct failure mode from
  getting the math wrong. This is exactly how DSTU 4145's `hash_to_field` broke: transcribed from
  Bouncy Castle's `hash2FieldElement` (which expects its `hash` parameter pre-reversed relative to
  the standard's own byte convention) without adopting or flagging that requirement — see
  `docs/DECISIONS.md` D-25's follow-up entries and `docs/pseudocode/dstu4145.md`.
- **Don't trust green tests alone for security-critical code** — see dual-oracle verification
  above. Two sharper corollaries, both learned the hard way on DSTU 4145 (D-25):
  - **A test-vector fix that isn't traceable to a specific citation is suspect.** If making a test
    pass requires changing the test's own input transformation (reversing bytes, reordering
    fields, etc.), that change needs a cited reason (a spec section, or independently-confirmed
    reference-implementation behavior) before being accepted as correct — not just "now the
    numbers match." An unexplained transform that merely produces the expected output is more
    likely masking a real bug in the implementation than fixing a genuine test-setup mistake; two
    wrong steps can cancel out into a right-looking answer (exactly what happened here — a wrong
    `hash_to_field` plus a manually-added test-side reversal produced the correct number for the
    one vector on hand, for reasons that only became clear once the primary source was read).
  - **Check what a fixed vector actually exercises, not just whether it passes.** A vector that
    supplies a derived value directly (e.g. a public key `Q`) rather than deriving it from what the
    vector also gives you (e.g. a private key `d`) does not test that derivation step at all, no
    matter how many times it's run. Before calling a multi-step primitive (key generation + sign +
    verify, etc.) "vector-verified," check which steps the vector's given inputs/outputs actually
    reach — anything a fixed vector doesn't reach needs its own test (a property test over random
    inputs, per D-21/D-25, is the tool already established here for exactly this).
- **A new Cargo feature that changes production behavior (not an inert additive one like
  `alloc`) breaks `--all-features` as a stand-in for "test the default profile"** — CI needs an
  explicit default-only step (no extra features) too, or the default path silently drops out of
  coverage. Learned adding `small-tables` (D-39); `.github/workflows/rust.yml` has the pattern.
- **Swapping a direct array index (`ARRAY[loop_var]`) for a function call using the same loop
  variable (`f(loop_var, ...)`) can flip `clippy::needless_range_loop` from clean to a hard
  error**, even though the loop variable also drives other index arithmetic — a heuristic quirk,
  not a real readability problem. Resolve with a documented `#[allow]`, don't restructure the
  loop fighting it (D-39 has the pattern, three instances in `hazmat::kalyna`/`kupyna`).
- **`rust-toolchain.toml` pins `stable` repo-wide, which silently overrides a CI step's installed
  nightly toolchain** (`dtolnay/rust-toolchain@nightly`) for any bare `cargo` invocation in the
  same job — the step doesn't error on the wrong toolchain, it just runs under `stable` and fails
  confusingly later (e.g. `-Z` flags "only accepted on the nightly compiler"). Any CI step needing
  nightly (miri, fuzz) must say `cargo +nightly ...` explicitly, same as `xtask` already does
  locally — confirmed missing in `.github/workflows/rust.yml` for a full day after both jobs were
  first wired up (T-85), since `xtask`'s own local runs never hit it.
- **CI's `cargo miri test` job now genuinely passes (fixed by T-100/D-59)** — root cause was
  broader than the two proptest suites originally suspected (every DSTU 4145 EC-ladder/
  field-inversion test, not just the proptests), fixed by `#[cfg_attr(miri, ignore)]` on those
  specific tests plus raising the job's `timeout-minutes` to 150 (measured ~84 min locally for
  `dstu-core` alone). Reconfirmed on a real push (`8e5a2a8`, 2026-07-27): `success` in 2h23m.
  The lesson stands regardless: **verify a CI job's real conclusion via `gh run view`, never
  assume from a green badge or an older note like this one** — this bullet itself was stale for
  a while after the fix landed.
- **Any scoped local `cargo +nightly miri test` on a file with a `proptest!` block needs
  `PROPTEST_CASES` cut down explicitly, not just left at its default 256** — even for primitives
  with no EC-ladder cost (T-100/D-59's fix only covers scalar-multiplication-heavy tests via
  `cfg_attr(miri, ignore)`). Hit this running `crypto_secretbox`'s Miri suite (D-63): the default
  256 cases at up to 2048 bytes each ran ~40 CPU-minutes with zero output before being killed, not
  stuck — Miri's per-instruction interpretation overhead alone makes that impractical. Set
  `$env:PROPTEST_CASES = "8"` (PowerShell) before the run; that same suite then completed in
  1135.80s (~19 min), 0 UB. If a background Miri run shows a stuck-looking empty output file,
  check `Get-Process -Id <pid> | Select CPU` before assuming it's hung — real CPU time still
  accumulating means it's genuinely working, just slow under interpretation.
- **uapki's C test-vector struct literals use adjacent string-literal concatenation across
  `\`-continued lines** — a naive "grab every quoted string in file order" extractor desyncs the
  field count (bit OFB, D-53; guarded against for every mode since). Parse brace-delimited case
  blocks and concatenate adjacent string tokens per field — don't flatten the whole file's quoted
  strings into one list.
- **Bumping a workspace crate's version means updating it in (at least) two places**: the crate's
  own `[package] version`, and any other workspace crate's path-dependency `version =` field
  pointing at it (`uacrypt`'s `dstu-core = { path = ..., version = "..." }`). Missing the second
  silently reintroduces the wildcard-dependency problem `cargo deny` once caught (T-75/D-11).
  Regenerate `Cargo.lock` via a real build afterward, don't hand-edit it (D-43).
- **Porting a `crypto_secretbox`-style wrapper onto a new underlying AEAD construction (or building
  a new one) means re-deriving, not assuming, whether that construction's tag covers a
  caller-transmitted nonce/IV.** Migrating `crypto_secretbox` from Kalyna-CCM to Kalyna-GCM (D-63)
  carried over CCM's implicit assumption that the nonce is authenticated — it isn't, under GCM
  (D-56 divergence 3: tag is AAD+ciphertext only, nonce only seeds the keystream). For a
  self-contained `nonce || ciphertext || tag` blob, that would have let an attacker tamper the
  nonce prefix and get "successful" decryption of wrong plaintext instead of a tag failure — caught
  by a tamper-test written during the migration itself, not by assuming the old construction's
  properties carried forward. See the "Crypto engineering hard constraints" section above for the
  standing rule this became; re-check it for every future combined-AEAD wrapper, especially
  `crypto_secretstream` (T-40) — don't assume this was a one-off fix specific to GCM.
- **This project's doc comments are long, citation-dense prose** (by design — every claim cites a
  `docs/DECISIONS.md`/`docs/TASKS.md`/spec reference inline), which makes them prone to
  `clippy::doc_lazy_continuation` under `-D warnings`: any line starting with `**bold` or `- dash`
  (even mid-sentence, not intentionally a markdown list) gets read by clippy/rustdoc as an
  unindented list-item continuation and hard-errors. Concretely hit twice writing D-63's doc
  comments in one session. **Prevention**: don't start a doc-comment line with `**` or `- ` unless
  actually writing a markdown list; run `cargo clippy --workspace --all-features -- -D warnings`
  (and `cargo fmt --all`) right after writing or editing any doc comment, not deferred to a final
  batch check at the end of the task — catching it while the paragraph is still fresh is a
  one-line reword, catching it later means re-deriving which of several new doc sections broke.
  Same lint pass also flags `clippy::doc_markdown`: an inline all-caps or CamelCase-ish word used
  as a verb (e.g. "two messages XORed") reads as an unbackticked code identifier — wrap it in
  backticks (`` `XOR`-ed ``) rather than rewording around it. Hit writing `hazmat::strumok`'s
  key/IV-reuse warning (D-64/D-65 session) — same "run clippy right after writing the doc
  comment" prevention habit catches this too.
- **When `Edit` fails with "String to replace not found" on an anchor that `Read` shows as
  byte-identical**, don't retry the same long multi-line anchor a second time (root cause is
  usually invisible whitespace/encoding, not a typo you'll spot by re-reading) — immediately retry
  with a much shorter, single unique line from the same block instead. Worked immediately when
  this happened editing `kalyna_gcm.rs`'s doc comment (2026-07-25); don't burn the three-attempts
  budget on the same failing anchor shape.
- **Before declaring a multi-file feature/construction "done," grep its own task ID (e.g. `T-40`)
  across every file the doc map's "Update when" column implicates for that kind of change** — not
  just the one or two docs you remember touching. Landing `crypto_secretstream` (D-68) initially
  updated only `docs/TASKS.md`/`CLAUDE.md`; `docs/release-readiness.md`, `docs/dstu-crypto-project.md`,
  and `README.md` all still said "not started" in multiple places until an `advisor()` pass caught
  it by name-checking the doc map. A stale "not started" line next to your own new "Done" line is
  a worse outcome than never mentioning the doc at all.
- **Adding a new `cargo fuzz` target means syncing three places, not one**: `fuzz/Cargo.toml`'s
  `[[bin]]` entry, `.github/workflows/rust.yml`'s `fuzz-smoke` matrix, and `xtask/src/main.rs`'s
  `FUZZ_TARGETS` array (`cargo xtask fuzz`/`ci`'s own source of truth, D-12) — missing the third one
  means the project's designated single QA entry point silently skips the new target. All three
  carry an explicit "kept in sync by hand" comment; still missed one on the first pass adding
  `crypto_secretstream`'s target (D-68).
- **A `#[cfg(feature = "std")]`-gated variant on an otherwise-unconditional public error enum
  (not `#[non_exhaustive]`) changes that enum's variant count under Cargo's additive feature
  unification** — any dependency in the build graph enabling this crate's `std` feature changes the
  enum for every consumer, including ones that only asked for the `no_std` surface. First hit on
  `crypto_secretstream::SecretstreamError` (D-68, whose other high-level modules are either
  whole-module `std`-gated or have no such mixed-variant enum). Not a reason to add
  `#[non_exhaustive]` speculatively — just verify this shape is intentional and record it, don't
  discover it from a downstream break.
- **`getrandom` 0.3's custom RNG backend (relevant to any future no_std/embedded RNG work,
  `docs/TASKS.md` T-123/`docs/DECISIONS.md` D-74) is a compile-time/link-time mechanism** — a
  `--cfg getrandom_backend="custom"` flag (via `RUSTFLAGS`/`.cargo/config.toml`) plus an
  `extern "Rust" fn __getrandom_v03_custom` resolved at link time — **not** a runtime-swappable
  callback the way libsodium's `randombytes_set_implementation()` is. Don't build a home-grown
  pluggable-RNG registry to match that shape; it would duplicate a mechanism `getrandom` already
  provides (the same D-03/D-04 reasoning against homegrown RNG code). To prove a target-agnostic
  link-time hook like this actually resolves, test it on the host — it doesn't care about target
  OS, so this doesn't require standing up real bare-metal firmware infrastructure
  (entry point/panic handler/linker script) just to verify one mechanism.
- **A Cargo feature/build combination outside the usual `clippy --all-features`/default-profile
  runs can hide a real `dead_code` warning** until that exact combination is actually built (e.g.
  `--no-default-features --features <narrow-feature>`) — confirmed adding the `getrandom` feature
  (D-74): a helper function only reachable under that one narrower combination needed its own
  matching `#[cfg]`, invisible from clippy on default or `--all-features` alone. Build-check every
  entry in the feature matrix individually, not just the two usual profiles.
- **When a README example must mirror a doctest's code verbatim, diff the two programmatically**
  (extract the fenced block from each, `diff`) rather than eyeballing — caught a real silent drift
  this way while expanding `crates/dstu-core/README.md` (T-120/D-75): the README's own copy had
  quietly dropped part of an example the doctest still had.
- **When a session accumulates more than one design fork resolved by implementation rather than
  by asking first** (flagged for confirmation in `docs/DECISIONS.md`, the D-66/D-72 pattern), surface
  all of them together in one end-of-turn message before moving on to the next task — don't let
  the user discover them one at a time by reading `docs/DECISIONS.md` later (`advisor()`'s explicit
  flag, three forks in one session: T-122's `generate()` shape, T-124's `sign-keygen`/
  `sign-pubkey` widening, T-123's capability-vs-mechanism-parity call).
- **When writing a benchmark/comparison wrapper, verify the timer excludes one-time setup (ctx
  alloc + key-schedule init) — don't assume copying an existing wrapper function's structure to a
  new mode carries the same guarantee.** Confirmed the hard way extending the UAPKI comparison
  wrapper to GMAC (`docs/DECISIONS.md` D-80): `run_gmac` was copied from `run_cmac`'s original shape,
  which itself timed the whole loop (`alloc`+`init_*` included) rather than just the MAC call,
  while `uacrypt`'s own command caches its schedule outside the loop. Invisible at bulk message
  sizes (CMAC's 10 MiB was unaffected — setup cost is noise against milliseconds of real work) but
  decisive at small ones (GMAC's 1-block message made a real ~1.1-2.9x gap look like a bogus
  ~4-24x one). Any new wrapper function needs its own `t0`/`now_ns()` placed *after* the
  setup/init call, verified per-function, not inherited from a sibling's code.
- **After a const-generic rewrite (T-128/T-134 pattern) removes every production caller of an old
  runtime-parameterized function, expect a BATCH of `never used` clippy errors, not just one** -
  every function down that old call chain becomes genuinely dead at once (T-134: 7 functions -
  `sub_shift_mix`, both `add_round_constant_*`, `t_transform`/`t_plus_transform`, `compress`,
  `bytes_to_columns` - all needed `#[allow(dead_code)]` the moment `compress_block`/`finalize`
  stopped calling them). Run clippy right after rewiring the call site and add the attribute to
  the whole batch in one pass, don't fix them one at a time as clippy re-reports each.
- **A benchmark wrapper for an unkeyed/schedule-free primitive (hash digest) must call its
  init/context-setup INSIDE the timed loop, not hoist it out** - the opposite of D-80's
  cached-schedule lesson for CMAC/CCM. `uacrypt`'s own `bench_in_memory!` constructs a fresh
  `Hasher` every iteration since there's no key schedule to amortize; a fair UAPKI-side wrapper
  must re-init every iteration too - this also sidesteps D-82's CMAC-style context-reuse quirk,
  since state is never stale when re-initialized every call.
- **Before any `hazmat::{kalyna,kupyna,strumok}` perf rewrite, spike it and read the actual
  `--emit=asm` output - don't plan from source-level reasoning alone.** `RUSTFLAGS="--emit=asm -C
  debuginfo=0" cargo build --release -p dstu-core --lib` (touch the source first if cargo reports
  a cached build with no `.s` change). This reversed two planned rewrites in one session: T-139
  (Strumok double-buffering hypothesis - `next_block` was already fully inlined and SROA'd, zero
  bounds checks, the hypothesis was simply wrong) and T-129 (Kalyna word-wide gather - already
  literal-offset and bounds-check-free at `NB=8`; the "fix," once actually spiked, added real
  register spills instead of removing anything). Both closed with no code change - a complete,
  valuable outcome, not a shortfall, and not something T-134's own successful const-generic
  rewrite lets you assume will repeat next time.
- **`oracles/uapki`'s vendored clone can be stale relative to actual upstream `main`** - confirmed
  2026-07-27 forking for T-137: a raw `diff` against a fresh clone showed the *entire* file as
  different, which traced to CRLF-vs-LF line endings only (`diff --strip-trailing-cr`, or
  normalize both sides first) - the underlying code hadn't drifted at all. Before hand-copying a
  patch derived from the vendored copy into a fresh clone/fork, diff-normalize and confirm
  line-number alignment first; don't assume the vendor is current.
- **When a CI static analyzer (SonarCloud/etc.) flags a finding on your own PR, read its actual
  symbolic-execution trace, not just the one-line summary, before proposing a fix.** `curl
  https://sonarcloud.io/api/issues/search?componentKeys=<project>&pullRequest=<N>` returns each
  issue's `flows` array - the exact assumed path. Confirmed the hard way on
  `specinfo-ua/UAPKI#30` (T-137): a first fix (`==`→`>=`) addressed a plausible-looking mechanism
  but not the one the trace actually showed (the flagged path never even entered the loop body
  the fix touched) - reading the trace directly on round two pinpointed the real gap (the
  invariant needed establishing at function entry, not inside the loop).

## Reference implementations and oracles

Canonical detail — trust ranking, per-algorithm oracle map, local clones under `oracles/`, and
the `li0ard` exclusion (D-07) — lives in `docs/ORACLES.md`. Do not duplicate that list here; the full
resource survey (including non-oracle references like Ecognize/libukrypto and the crates.io niche
check) is in `docs/dstu-crypto-project.md` "Resources found".

## State certification (informational, not an MVP blocker)

- Regulator: Administration of the State Service for Special Communications
  (Держспецзв'язку). Mandatory certification only applies when the tool is used to protect state
  information resources or information whose protection is required by law. An open library on
  GitHub/GitLab by itself falls under the voluntary category.
- Certification is tied to the hash of a specific build — changing the code potentially requires
  re-certification. Not relevant to MVP development.

## Roadmap notes

- Official documentation PDFs live in `docs/papers/`, including `DSTU_4145-2002.pdf` (added
  2026-07-22 — a scan, see `.claude.local.md` for the render-then-read workflow). Test vectors are
  extracted and verified for Kalyna, Kupyna, and DSTU 4145
  (`crates/dstu-core/tests/vectors/{kalyna,kupyna,dstu4145}/`); Strumok's are UAPKI-attributed, plus
  (as of 2026-07-31) independently confirmed against two state-sourced supplementary vectors from
  Держспецзв'язку/ДНДІ ТКЗІ (`crates/dstu-core/tests/strumok.rs`'s `official_letter_vectors`), still
  not yet confirmed against the paid official text itself — see `docs/ORACLES.md`/`docs/DECISIONS.md`
  D-15/D-16/D-104.
- Verify own implementation against Kalyna-reference and the other oracles in `docs/ORACLES.md`.
- Hardware validation on STM32/ESP32 is a distinct post-MVP phase, and is not a claim of
  side-channel resistance (see MVP scope above).
