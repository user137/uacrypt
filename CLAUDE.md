# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Communication language

Respond to the project owner in Ukrainian by default in this repository — don't wait for them to
switch language first (requested explicitly 2026-07-25; complements, doesn't replace, the global
"use Ukrainian when the user writes in Ukrainian" rule in `~/.claude/CLAUDE.md`, and mirrors the
same note already in `.claude.local.md`, recorded here too since that file isn't committed). This
governs conversational replies only — code, identifiers, commit messages, and this repo's own docs
stay in whatever language they already use.

## Commands

```bash
cargo xtask ci            # mandatory checks (incl. docs-check) + best-effort miri/kani/book/fuzz/audit/deny/oracle harnesses
cargo xtask build          # both feature-set builds
cargo xtask test           # full test suite
cargo xtask clippy         # -D warnings
cargo xtask fmt --check
cargo xtask docs-check     # README/gh-pages version-marker freshness lint (T-186, mandatory)
cargo xtask book           # mdbook build - docs/ knowledge base (T-186), published to gh-pages/book/ by CI
cargo xtask bench-compare  # uacrypt vs OpenSSL, one unified table per DSTU standard (T-187, docs/PERFORMANCE.md D-106)
```

`xtask` (see `xtask/`, aliased via `.cargo/config.toml`) is the one cross-platform build/QA entry
point — same command on Linux/Windows/macOS, no new install beyond `cargo` itself. Use this instead
of writing a new one-off shell/PowerShell script for any build/QA task. Full detail: `docs/DECISIONS.md`
D-12, `README.md` "Development commands".

`bindings/python` (and every future language binding) is its own **separate** Cargo workspace
(D-119) — not reachable via the root `cargo xtask`/`cargo build --workspace`. Build/test it from
inside its own directory; see `docs/bindings-strategy.md`.

## Project status

Local toolchain (Rust, C compiler, Maven, Python) is fully installed — see `.claude.local.md` for
machine-specific paths/gotchas. This is a working dev environment, not a "no toolchain" one.

**Repo layout**: root Cargo workspace with three crates (`crates/dstu-core`, `crates/uacrypt`,
`crates/dstu-core-capi`), plus `bindings/` for language bindings — each its own separate Cargo
workspace (D-119), never a root workspace member. **All eight bindings (Python, Node.js, Ruby,
PHP, .NET, Java, Go, C++) are done** as of 2026-08-03, all ten standard steps each — see
`docs/bindings-strategy.md` for the per-binding checklist and `docs/TASKS.md` T-49/T-50/T-160/
T-159/T-158/T-52/T-51/T-163/T-53 for the full landing history. **`crypto_box` (below) was added to
all eight 2026-08-06, T-181** — every binding wraps the full `crypto_*` surface as of that date, not
just the modules that existed when each binding first landed. **`crypto_box512`/`crypto_sign257`
(below, T-193/T-199) were added to all eight bindings plus `dstu-core-capi` 2026-08-09/10, T-204**
— every binding wraps the full `crypto_*` surface again as of that date.

**`crates/dstu-core`** — the library (`std`/`alloc`/`no_std` feature flags, D-01). All primitives
below are test-first and pass `cargo test`/`clippy -D warnings`/`fmt --check`/the `no_std` build/
`cargo miri test`. For full history and rationale of any item below, its cited `T-XX`/`D-XX` is the
canonical source (`docs/TASKS.md`/`docs/DECISIONS.md`) — this section states current state only.

- `hazmat` (low-level, no defaults chosen for you — D-09's first layer):
  - `kupyna::{Kupyna256, Kupyna512}` — one-shot `digest()` + streaming `Hasher` (D-10).
  - `kalyna::{Kalyna128_128, Kalyna128_256, Kalyna256_256, Kalyna256_512, Kalyna512_512}` —
    single-block `encrypt`/`decrypt` (D-13). Independently cross-checked against real Bouncy Castle
    (Java/.NET), T-10.
  - `kalyna_ccm` — all five variants, provisional Kalyna-alone CCM, **not yet confirmed against the
    primary DSTU 7624:2014 text** (D-41). Nonce strategy: a wide random nonce generated at the CLI
    layer via `getrandom`, not a stateful counter — the `hazmat`-level API itself still takes a
    caller-supplied nonce, so it stays `no_std`-compatible (D-40/T-82).
  - `kupyna_kmac::{Kupyna256Kmac, Kupyna384Kmac, Kupyna512Kmac}` — the `crypto_auth` equivalent,
    provisional but on stronger dual-oracle evidence than `kalyna_ccm`/Strumok (D-44).
  - `kupyna_kdf::{Kupyna256Kdf, Kupyna384Kdf, Kupyna512Kdf}` — the `crypto_kdf` equivalent, built on
    `kupyna_kmac`; from-scratch design, no DSTU KDF standard or reference implementation exists at
    all, so no oracle vector is possible — verified by property test only (D-45).
  - `strumok::{Strumok256, Strumok512}` — keystream via `apply_keystream` (D-18). Vectors are
    UAPKI-attributed, **not confirmed against the primary DSTU 8845:2019 text** (D-15), but
    independently confirmed against two state-sourced supplementary vectors from
    Держспецзв'язку/ДНДІ ТКЗІ (D-104).
  - `dstu9041` (`message`/`fp256`/`curve256`/`encryption` for `l(p)=256`; `message512`/`fp512`/
    `curve512`/`encryption512` for `l(p)=512`, T-192) — hybrid (ECIES-style) asymmetric encryption
    over a twisted Edwards curve. `l(p) ∈ {256, 512}` (E256/1, E512/1) — the two curve sizes whose
    Kalyna-KW stage needs no padding variant (D-47's "ship the recommended curve first" extended to
    the second such size). Verified against the standard's own Додаток Г worked example, the sole
    oracle for this primitive (T-177, T-192).
  - Kalyna/Kupyna share S-box/MDS tables (`hazmat::tables`); Strumok's `T` substitution reuses them
    too (D-13).
  - `cargo fuzz` run on all three targets (Windows, MSVC toolchain), zero crashes (D-32); Linux CI
    remains the unconditional per-push check.
- `crypto_*` (high-level, misuse-resistant, zero-config — D-09's second layer, D-47's "delete the
  knob" applied throughout: one fixed construction/variant per module, no caller-facing nonce/IV/
  mode/AAD parameter unless noted):
  - `crypto_sign` (`SigningKey`/`VerifyingKey`/`Signature`) — wraps `hazmat::dstu4145` (`m=163`),
    deterministic Kupyna-KMAC-derived nonce, no RNG dependency for signing (T-48/D-46).
    `crypto_sign257` (T-199, D-185/D-186) is its `m=257` sibling — what real Diia-issued
    qualified signatures actually use in production, confirmed from real issued certificates —
    a separate, additively-shipped module with the same shape, not a curve flag on `crypto_sign`
    itself (that reversal, and why, is D-186's own addendum: converting `crypto_sign`'s types to
    a curve-tagged enum would have broken `dstu-core-capi`'s C ABI for no benefit). `uacrypt`'s
    `sign-keygen257`/`sign-pubkey257`/`sign257` mirror `sign-keygen`/`sign-pubkey`/`sign`; `verify`
    alone is unified and reads a curve tag byte to handle both curves' signatures. **Wired into all
    eight language bindings plus `dstu-core-capi` as of T-204 (2026-08-09/10)** - untagged
    everywhere, the curve-tag dispatch stays a `uacrypt`-layer-only concern, never duplicated into
    a binding (D-118).
  - `crypto_pwhash` (`hash_password`/`verify_password`/`Strength`) — wraps `argon2` behind a
    dedicated `pwhash` feature (off by default); `Strength::{Interactive,Moderate,Sensitive}` cites
    libsodium's own constants exactly (T-71/D-49/D-50).
  - `crypto_secretbox` (`seal`/`open`/`SecretKey`) — `Kalyna256_256Gcm`, internal nonce, combined
    `nonce||ciphertext||tag`, no AAD parameter; the nonce is passed as the construction's own
    internal AAD to keep it authenticated (closes a real gap found migrating off Kalyna-CCM, no
    message-length cap unlike the old CCM construction — T-37/D-51/D-63).
  - `crypto_generichash`/`crypto_auth`/`crypto_kdf` — Kupyna hash/KMAC/KDF wrappers, only the
    256-bit variant exposed, opaque `Zeroize`-on-drop key types (T-105/D-66).
  - `crypto_stream` (`encrypt`/`decrypt`/`Key`) — `Strumok256` only, hidden internal IV, **no
    authentication** (`decrypt` never fails on tampered input) — hence `encrypt`/`decrypt` naming,
    not `seal`/`open` (T-106/D-67).
  - `crypto_secretstream` (`PushState`/`PullState`/`Key`/`Tag`) — genuinely chunked/streaming AEAD,
    tag-per-chunk framing (`Message`/`Push`/`Rekey`/`Final`), header-derived subkeys + one-way
    `Rekey` forward secrecy; no oracle vector can ever exist for this from-scratch construction,
    verified by property/tamper/misuse tests instead (T-40/T-70/D-68).
  - `crypto_box` (`seal`/`open`/`SecretKey`/`PublicKey`) — public-key encryption over
    `hazmat::dstu9041` (`l(p)=256`), hybrid via KDF (a random seed sealed asymmetrically,
    expanded via `hazmat::kupyna_kdf`, then `crypto_secretstream` encrypts the actual message);
    `PublicKey` is 32 bytes, the curve point's `x`-coordinate only (T-178/D-169). `crypto_box512`
    is the direct `l(p)=512` (E512/1) sibling (T-193, 2026-08-08, D-182) — same shape, `PublicKey`/
    `SecretKey` at 64 bytes, seed deliberately fixed at 32 bytes/256 bits (not `l(p)=512`'s full
    424-bit KEM capacity, D-182). **Wired into all eight language bindings plus `dstu-core-capi` as
    of T-204 (2026-08-09/10)**, same shape/naming per binding as `crypto_box` itself, a distinct
    type everywhere (not interchangeable with `crypto_box`).
  - `randombytes::randombytes_buf` — `std`-gated `getrandom` wrapper (T-72/D-48).
- `selftest` — `std`-gated (`selftest` feature, off by default) runtime KAT self-check: `run()`
  re-verifies one official vector per primitive (Kalyna-128/128, Kupyna-256, Strumok-256, DSTU
  4145's Annex B.1) against the live compiled build, embedded via `include_str!`. Built so every
  language binding wraps one shared check instead of reimplementing it (T-161/D-117).

**`crates/uacrypt`** — the CLI binary (renamed from `dstutool`, D-36). `kalyna-block`,
`kupyna-digest`, `strumok-crypt`, `kalyna-ccm` subcommands exist for binary-level comparisons
(D-31/D-41, see `docs/PERFORMANCE.md`). Top-level `encrypt`/`decrypt`/`hash` are real (T-16/D-52):
`encrypt`/`decrypt` are backed by `crypto_secretstream` (migrated from `crypto_secretbox`, a
breaking pre-1.0 wire-format change — T-40/T-70/D-68), no message-length cap, `--in`/`--out`
genuinely streamed in fixed-size chunks, temp-file-then-rename atomicity; `hash` is fixed to
Kupyna-256 with no length cap, delegating to the streaming `Hasher`.

**`crates/dstu-core-capi`** — the C ABI (T-158, D-148/D-149), a real root-workspace member (unlike
the language bindings under `bindings/`, which are each their own separate Cargo workspace, D-119).
Opaque handles, explicit `DstuStatus` error codes, `catch_unwind` at every boundary call,
zeroize-on-free, `cbindgen`-generated header (`include/dstu_core.h`, regenerated+diffed via `cargo
xtask capi`). Wraps the full `crypto_*` surface, including `crypto_box512`/`crypto_sign257` as of
T-204 (2026-08-09) - see the `crypto_box`/`crypto_sign` bullets above. The foundation the
.NET/Go/C++ bindings link against directly — usable from any language with a C FFI, not just those
three. (The five direct-Rust bindings - Python/Node/Ruby/PHP/Java - link `dstu-core` itself, not
this crate, but reached the same `crypto_box512`/`crypto_sign257` coverage independently, T-204's
own Phase 3.)

Official test vectors are extracted and verified for Kalyna, Kupyna, and DSTU 4145
(`crates/dstu-core/tests/vectors/{kalyna,kupyna,dstu4145}/*.json` — see `docs/ORACLES.md` for
provenance/format) and additionally run against real Bouncy Castle (Java/.NET, published packages,
not vendored clones) in `tests/oracle-harness/{java,dotnet}/` — see `docs/TASKS.md` "Infrastructure".
Strumok's vectors are UAPKI-attributed, not yet confirmed against the paid official text — D-15/D-16/D-104.
No C/cryptonite harness — tried and dropped, see `docs/TASKS.md`/`docs/ORACLES.md` for why.

The concrete module-by-module API surface lives in `docs/dstu-crypto-project.md` "Concrete API
shape", tracked as a checklist in `docs/TASKS.md`. Read `docs/dstu-crypto-project.md` before
planning any implementation work — it is the source of truth for scope/architecture.

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
- Single CLI binary over the core (`uacrypt`, D-36) — mode, nonce/IV etc. are hardcoded so there's
  nothing for the user to misconfigure. **Built** (T-16/D-52) — see "Project status" above for the
  current `encrypt`/`decrypt`/`hash` shape.
- Publish the core crate to crates.io — not started, explicitly gated on an owner request (T-17,
  distinct from a GitHub release, different platforms/reversibility).
- Prebuilt binaries for Windows/Linux/macOS via GitHub Releases, plus a `dstu-core` source
  distribution — **done** (T-18/T-119); `.github/workflows/release.yml` builds all three on a `v*`
  tag push.
- **No hardware or OS lock-in — platform-agnostic by construction.** Targets both full PCs/servers
  (Windows, Linux, macOS, x86-64/ARM64) *and* microcontrollers (STM32/Cortex-M, ESP32/Xtensa-RISC-V)
  genuinely, not one with lip service to the other:
  - **Core must be `no_std`-compatible from day one** (`std`/`alloc`/`no_std` feature flags) so
    embedded targets can be added later without a core rewrite. Real-hardware validation is a
    separate post-MVP phase. Non-embedded ARM64/Linux is checked on a real Raspberry Pi (access in
    `.claude.local.md`); bare-metal STM32/ESP32 real silicon is still Phase 4/T-55/T-56 (not
    started). A cheaper intermediate layer exists since 2026-08-03 (D-156, T-170):
    `firmware/qemu-stm32-smoketest` runs official Kalyna/Kupyna vectors under QEMU's
    `netduinoplus2` (stock, no-fork STM32/Cortex-M4F emulation) via `cargo xtask qemu-stm32` -
    correctness-only, does not touch or claim anything about real-silicon timing/side-channels.
    ESP32 has no equivalent (no real board in mainline QEMU, would need Espressif's own fork -
    out of scope, see D-156).
  - No dependency/API/build assumption may quietly assume a specific OS or CPU family unless
    isolated behind a feature flag with a working alternative for excluded platforms.
  - `no_std`/embedded support ≠ resistance to hardware side-channel attacks (SPA/DPA) — that needs
    a separate, expensive hardware audit; until one exists, never claim side-channel resistance.

## Second priority (not MVP)

- Language bindings: Python, JavaScript (Node.js), Ruby, PHP, Java, .NET, Go, C++ — **all eight
  done as of 2026-08-03**, see `docs/bindings-strategy.md`; `crypto_box` added to all eight
  2026-08-06 (T-181). Not yet published to any package
  registry (PyPI/npm/RubyGems/Packagist/NuGet/Maven Central) — separately owner-gated, `docs/TASKS.md`
  T-164, same posture as `dstu-core` itself not being on crates.io yet.
- Do not reimplement DSTU 4145 signatures in the native core — for Java/.NET, wrap/integrate
  Bouncy Castle (mature, `DSTU4145Signer`, decades in production, continuous external audit); for
  Rust, port with Bouncy Castle as a second verification oracle.

## Explicitly out of scope

- **Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna)** — do not implement, and do
  not propose implementing, without a separate explicit decision from the project owner. See D-08
  for the full rationale (different math class, complexity on the order of all five in-scope
  algorithms combined, immature cryptanalysis, no vetted oracle). If ever picked up,
  `docs/dstu-crypto-project.md` "Post-quantum track" has the fuller context.

## Documentation map

| File | Read when | Update when | Canonical owner of |
|---|---|---|---|
| `docs/TASKS.md` | starting or resuming any work session | a task is started, finished, or newly discovered | phase-by-phase task backlog and progress state — status only, not rationale |
| `docs/dstu-crypto-project.md` | planning scope, API design, algorithm choices | scope or API-mapping decisions change | project scope, libsodium API mapping |
| `docs/resource-profiles.md` | choosing/explaining `fused` vs `small-tables`, sizing a target's flash budget | the profile split's memory/speed numbers change, or a new MCU tier is added to the sizing guide | `small-tables` feature memory/speed numbers (D-35/D-38/D-39), per-target profile recommendation |
| `docs/release-readiness.md` | assessing distance to a real, complete release; deciding what to build next toward it | a blocking item resolves (esp. D-05), a new construction lands, or the gap analysis otherwise changes | gap analysis between current state and a libsodium-equivalent 1.0 (D-43, T-87) |
| `docs/user-journey-gaps.md` | assessing whether a real persona (binary user, library user, constrained-target user) can actually complete their journey end to end, not just whether a construction/API exists | a new persona-blocking gap is found or an existing one closes | persona/journey-framed gap analysis (T-114) — complements, doesn't replace, `docs/release-readiness.md`/`docs/dstu-crypto-project.md` |
| `docs/bindings-strategy.md` | planning or building any Phase 3 language binding (Python/JS/Java/.NET/C++/PHP/Ruby) | binding scope/order changes, a new fork gets resolved, or a phase's status changes | language-binding popularity analysis, C-ABI-vs-native-FFI split, per-binding engineering checklist, phased roadmap (T-158 onward, D-115) |
| `docs/SECURITY.md` | before writing any crypto primitive or adding a dependency | threat model or hard constraints change | threat model, hard constraints, supply-chain vetting |
| `docs/DECISIONS.md` | need the reason behind an architectural choice | a new architectural decision is made | decisions + rejected alternatives, with citations |
| `docs/ORACLES.md` | before implementing or verifying any primitive | oracle trust ranking changes, or a new oracle/vector source is added | oracle trust matrix, per-algorithm oracle map, test-vector convention, list of reference implementations |
| `docs/pseudocode/*.md` | before writing a primitive's Rust implementation | the transcription changes or a new ambiguity/discrepancy is found | per-algorithm pseudocode, cross-checked, ambiguities flagged inline |
| `docs/rust_ai_ruleset.md` | general Rust code-style questions | never (external ruleset, canonical as-is) | generic Rust engineering conventions |
| `docs/cross-language-style-guide.md` | writing or reviewing non-Rust code (oracle harnesses, language bindings) | a new language is added, or a cross-language principle needs adjusting | cross-language naming/style principles and the per-language reference table; generalizes `docs/rust_ai_ruleset.md` |
| `README.md` | need the human-facing project overview or repo tree | repo structure changes | GitHub-facing description, top-level directory map, build/install instructions |
| `docs/PERFORMANCE.md` | need benchmark numbers, or comparing against another implementation's speed | new numbers are measured, or a new comparison implementation is benchmarked | benchmark methodology (cross-implementation comparisons are binary-level/MB/s only, D-34), recorded numbers, `criterion --baseline` |
| `xtask/src/main.rs` | adding or changing a build/QA subcommand | a new tool enters the QA stack or an existing command's invocation changes | the actual build/QA implementations (README documents usage, this owns behavior) |
| `docs/SUMMARY.md` / `book.toml` | adding a new doc file that should be reachable from the published knowledge base, or reordering how the book is grouped | a `docs/*.md` file is added/removed and should (or shouldn't) appear in the book | mdBook table of contents/config (T-186) — `src` points straight at `docs/`, no existing file is moved for this to work, so adding a doc file elsewhere in this table doesn't require touching this row unless it should also gain a book chapter |
| `AGENTS.md` | never by Claude Code itself (this file already auto-loads) — read by a non-Claude-Code AI agent (Cursor, Copilot, another agentic CLI) that looks for this filename by convention | this table's own row list, read-order, or any file it points to gets renamed/moved | routing a non-Claude AI agent to the right reading order; owns no content of its own — a stale pointer here is a broken link, not wrong information, but still fix it the same session it's noticed |

`docs/rust_ai_ruleset.md` §7 (async/tokio) does not apply to the `no_std`-first core — only relevant
if a future CLI or binding layer adds async I/O.

## Crypto engineering hard constraints

Full detail and rationale in `docs/SECURITY.md` — this is the compressed version so it can't be missed:

- No primitive without a cited spec section (DSTU clause or reference-implementation source) —
  citation goes in `docs/DECISIONS.md`.
- **When an architectural fork has no settling DSTU citation** (spec silent/ambiguous/unavailable):
  resolve via D-47's ranked tie-breaker — (1) TLS 1.3/modern AEAD consensus (combined constructions
  over hand-composed ones), (2) libsodium's API shape (hard defaults, no misconfigurable knobs), (3)
  expose only safe modes of operation, never unsafe/legacy as a public entry point. A real spec
  citation always outranks this rule once one exists.
- No secret-dependent branching. Secret-dependent array indexing is allowed only for fixed-latency
  S-box/GF-multiplication table lookups mirroring the DSTU reference implementations (documented
  exception, D-19 — not a license to add more casually). Secret comparisons via
  `subtle::ConstantTimeEq`, never `==`; all key material is `Zeroize`/`ZeroizeOnDrop`; no secret
  material in logs.
- No homegrown primitives — where DSTU has a real gap (pwhash, CSPRNG), use the established
  international primitive (Argon2id, OS `getrandom`), D-03/D-04.
- **Dual-oracle verification is mandatory**: official DSTU test vectors *and* an independent
  reference implementation (Kalyna-reference, cryptonite, Bouncy Castle — see `docs/ORACLES.md`).
  Self-consistent tests passing is not sufficient evidence.
- `cargo miri test` and `cargo fuzz` are required layers, not optional tooling.
- Constant-time discipline reduces side-channel exposure but is never itself a
  side-channel-resistance claim (software-side complement to the SPA/DPA note above).
- **Any wire format that bundles a nonce/IV with ciphertext+tag into one self-contained blob (a
  `crypto_secretbox`-style construction) must verify — by reading the construction's actual tag
  computation, not assuming — that the tag covers that nonce/IV.** Not every AEAD does: DSTU
  Kalyna-GCM's tag is `E_K(acc XOR length_block)`, AAD+ciphertext only (D-56 divergence 3) — the
  nonce only seeds the keystream, unlike CCM (B0 folds the nonce into the CBC-MAC) or NIST AES-GCM
  (`J0` is nonce-derived). Uncovered + travels in the same trusted blob = an attacker can tamper the
  nonce prefix and get "successful" decryption of wrong plaintext instead of failing closed. Fix:
  pass the nonce as the construction's own AAD (bind it via the mechanism already provided for
  exactly this). See D-63 for the concrete case — check this again for every future combined-AEAD
  wrapper, don't assume it only applied once.

## Agent discipline

Full incident narrative for any bulleted rule below lives under its cited `D-XX`/`T-XX` in
`docs/DECISIONS.md`/`docs/TASKS.md` — these are the operative rules only, not the postmortems.

- **UTF-8 everywhere, no exceptions** — every text file (source, docs, config, vector JSON), no BOM.
  Verify encoding whenever mixing English/Ukrainian text or extracting via `pdftotext` on Windows
  (silent UTF-16/BOM/CP1251 risk).
- **`WebFetch`'s summarization is unreliable on Cyrillic/font-encoding-broken PDFs and wikitext**
  (D-05) — fetch raw text/wikitext directly (`curl`) or render to PNG and read; never trust its
  summary at face value for these.
- **Excluding a dependency's own feature doesn't stop its transitive dependencies' *default*
  features from turning on anyway** — Cargo feature unification is additive-only (D-50). Verify with
  `cargo tree -e normal --features <feature>`.
- **Test-first, always** — a failing test (or test-vector check) before the implementation, every
  function, not just primitives.
  - **Every new primitive/mode/wrapper/CLI command ships three test categories**: (1) correctness
    against a vector/oracle, (2) **rejection** — tampered ciphertext/tag/aad/nonce, wrong key
    ("attack" pass, D-64), (3) **misuse** — invalid lengths/args/paths, degenerate-but-legal input
    succeeding rather than erroring, no partial output on failure ("fool" pass, D-65). Don't skip
    either as "obviously fine" — D-63's nonce-authentication gap was found by noticing an *absent*
    test, not a walkthrough.
  - **Where a misuse category is foreclosed by the type signature**, record that as a
    `docs/DECISIONS.md` finding instead of writing a test that only proves the compiler works.
  - **Rejection/misuse tests passing on first write is expected**, not a test-first violation.
  - **A formula-based correctness precondition (not a branch) is invisible to random sampling** —
    fixed vectors and proptest alike. Find the boundary by reading the code, test it explicitly, or
    prove exhaustively where tractable (Kani) (D-109/D-110/D-111).
- **A `hazmat` streaming API existing does not make the `uacrypt` command wrapping it
  memory-bounded** (D-42) — wire each new algorithm's CLI command to read in fixed chunks instead of
  `std::fs::read`-ing the whole file (chunk both disk read and write for a cipher), unless the
  construction genuinely needs the whole message up front.
- **Three-attempts rule**: if the same problem survives 3 different approaches (especially
  toolchain/build/CI), stop, report what was tried, wait for direction — don't self-authorize a 4th.
- **Research before implementation**: no primitive written from memory. Verify against the primary
  source (DSTU clause or real reference-implementation code) first, cite it in `docs/DECISIONS.md`.
  If only a reference implementation is available, mark the citation provisional (D-15's framing)
  and re-verify against the primary text once available. **Porting logic from a reference
  implementation means porting its calling convention too** — byte order/sign/units can differ from
  the primary spec's own convention; copying internals without flagging that convention is a
  distinct failure mode from getting the math wrong (D-25, `docs/pseudocode/dstu4145.md`).
- **Transcribing long same-character runs (repeated hex digits, etc.) from a page image is as
  failure-prone as OCR for the same pattern** — a human/AI eyeball count can silently miscount by
  dozens of digits (T-174/D-163). Stroke-count such runs programmatically instead of reading by eye,
  and verify the result against an independent property (primality, curve-membership, a known
  scalar multiple).
- **Finding a numeric convention once (e.g. hex vs. decimal) does not mean it was applied every time
  it recurs in the same source** — re-check each occurrence fresh (T-174/D-163).
- **Don't trust green tests alone for security-critical code** (D-25):
  - **A test-vector fix not traceable to a specific citation is suspect** — an unexplained input
    transformation (reversing bytes, reordering fields) that merely produces the expected output
    more likely masks a real bug than fixes a genuine test mistake.
  - **Check what a fixed vector actually exercises, not just whether it passes** — a vector supplying
    a derived value directly rather than deriving it from what it also gives doesn't test that
    derivation step at all; anything unreached needs its own property test (D-21).
- **A new Cargo feature that changes production behavior breaks `--all-features` as a stand-in for
  "test the default profile"** — CI needs an explicit default-only step too (D-39, see
  `.github/workflows/rust.yml`).
- **Swapping a direct array index for a function call using the same loop variable can flip
  `clippy::needless_range_loop` from clean to a hard error** even though the variable also drives
  other index arithmetic — a heuristic quirk. Resolve with a documented `#[allow]`, don't restructure
  fighting it (D-39).
- **`rust-toolchain.toml` pins `stable` repo-wide, silently overriding a CI step's installed nightly
  toolchain** for any bare `cargo` invocation in the same job. Any CI step needing nightly (miri,
  fuzz) must say `cargo +nightly ...` explicitly (T-85).
- **Verify a CI job's real conclusion via `gh run view`, never assume from a green badge or an older
  note** (T-100/D-59).
- **A `git stash`/`git stash pop` A/B benchmark cycle can leave `cargo bench`'s compiled binary
  stale** — Cargo's change detection does not reliably fire across a stash/pop, producing a
  reproducible-looking performance anomaly instead of an error (T-172/D-161). Before trusting a
  post-stash benchmark number, force a rebuild (`touch` the changed file) or verify the binary's own
  symbols (`objdump -d`).
- **A scoped local `cargo +nightly miri test` on a file with `proptest!` needs `PROPTEST_CASES` cut
  down explicitly** (e.g. `$env:PROPTEST_CASES = "8"`) — the default 256 cases can mean tens of
  CPU-minutes with zero output under Miri's interpretation overhead. A stuck-looking empty output
  file with real accumulating CPU time (`Get-Process -Id <pid> | Select CPU`) means it's working,
  not hung.
- **Never pipe a long-running `cargo`/`miri` command through `| tail -N` on Windows** — `tail`
  buffers until EOF, so the log stays empty for the run's entire duration (D-164). Redirecting to a
  file (`> log 2>&1`, no pipe) is not a full fix either — Windows fully-buffers non-tty stdout. Use
  `Get-Process`'s growing CPU time as the liveness signal, and add `-- --test-threads=1` so the log's
  last completed test name is the one still running when it does flush.
- **uapki's C test-vector struct literals use adjacent string-literal concatenation across
  `\`-continued lines** — a naive "grab every quoted string in file order" extractor desyncs the
  field count (D-53). Parse brace-delimited case blocks and concatenate adjacent string tokens per
  field.
- **Bumping a workspace crate's version means updating it in (at least) two places**: the crate's
  own `[package] version`, and any other workspace crate's path-dependency `version =` pointing at
  it (T-75/D-11). Regenerate `Cargo.lock` via a real build afterward, don't hand-edit it (D-43).
- **Porting a `crypto_secretbox`-style wrapper onto a new AEAD construction means re-deriving, not
  assuming, whether that construction's tag covers a caller-transmitted nonce/IV** — see "Crypto
  engineering hard constraints" above for the standing rule (D-63); re-check for every future
  combined-AEAD wrapper.
- **Every language binding's `crypto_secretstream` wrapper has two known pitfalls** (D-118, found
  building the Python one, T-49) — re-check both for every later binding: the language's own
  "always runs, even on error" cleanup hook (`__exit__`/`Dispose`/try-with-resources/RAII destructor)
  must not finalize the stream on the exception path, and the wire-format reader must itself bound
  the untrusted length-prefixed chunk field and reject trailing data after `Final`. Full detail:
  `docs/bindings-strategy.md`'s standard binding steps, step 3.
- **This project's doc comments are long, citation-dense prose**, prone to
  `clippy::doc_lazy_continuation` under `-D warnings`: a line starting with `**bold` or `- dash`
  (even mid-sentence) reads as an unindented list-item continuation and hard-errors. Don't start a
  doc-comment line with `**`/`- ` unless writing an actual markdown list; run
  `cargo clippy --workspace --all-features -- -D warnings` + `cargo fmt --all` right after writing
  any doc comment. Same lint pass flags `clippy::doc_markdown` — wrap inline all-caps/CamelCase
  words used as verbs in backticks.
- **When `Edit` fails with "String to replace not found" on an anchor `Read` shows as
  byte-identical**, don't retry the same long multi-line anchor (root cause is usually invisible
  whitespace/encoding) — retry with a much shorter, single unique line from the same block instead.
- **Before declaring a multi-file feature "done," grep its own task ID across every file the doc
  map's "Update when" column implicates** — not just the docs you remember touching.
- **A task-ID grep sweep is necessary but not sufficient — it misses free-standing state summaries
  that go stale with no task-ID string for a grep to catch** (D-159, e.g. `CLAUDE.md`'s own
  "Project status"/"Second priority" going stale through a whole binding-landing phase with no task
  ID in either sentence). Before declaring a doc-map sweep complete for a change that adds a
  workspace member or headline-scope item, separately re-read those two `CLAUDE.md` sections and
  `docs/CHANGELOG.md`'s `[Unreleased]` section. A missing `CHANGELOG.md` entry for an already-tagged
  release is the sharpest version — check `gh release list` against `docs/CHANGELOG.md`'s own
  version headers, since `CHANGELOG.md` only covers what actually ships in a tagged
  release/publish, not every landed change.
- **Adding a new `cargo fuzz` target means syncing three places**: `fuzz/Cargo.toml`'s `[[bin]]`,
  `.github/workflows/rust.yml`'s `fuzz-smoke` matrix, `xtask/src/main.rs`'s `FUZZ_TARGETS` array —
  missing the third means the QA entry point silently skips the new target.
- **`xtask/src/main.rs`'s `ci()` runs every optional layer from one `[fn() -> bool; N]` array,
  requiring every element to share that exact signature.** Giving one of those functions a
  parameter (D-164/T-175) doesn't fit directly — bind a same-shaped closure first
  (`let optional_miri: fn() -> bool = || miri(None);`) and put that in the array instead.
- **A `#[cfg(feature = "std")]`-gated variant on an otherwise-unconditional public error enum (not
  `#[non_exhaustive]`) changes that enum's variant count under Cargo's additive feature
  unification** — any dependency enabling this crate's `std` feature changes the enum for every
  consumer. Verify the shape is intentional and record it, don't discover it from a downstream break.
- **`getrandom` 0.3's custom RNG backend is a compile-time/link-time mechanism** (`--cfg
  getrandom_backend="custom"` + `extern "Rust" fn __getrandom_v03_custom`), **not** a
  runtime-swappable callback like libsodium's `randombytes_set_implementation()`. Don't build a
  home-grown pluggable-RNG registry to match that shape (D-03/D-04).
- **A Cargo feature/build combination outside the usual `--all-features`/default-profile runs can
  hide a real `dead_code` warning** until that exact combination is built — build-check every entry
  in the feature matrix individually (D-74).
- **The same "untested feature combination" pattern also hides a Miri-speed problem** —
  `dstu-core-capi` unconditionally enables `dstu-core`'s `pwhash` feature, so its FFI suite runs
  Argon2id under Miri even though `dstu-core`'s own miri run never does (`pwhash` is opt-in there).
  A downstream crate that force-enables a dependency feature needs its own feature-matrix check, not
  just the upstream crate's (D-164).
- **When a README example must mirror a doctest's code verbatim, diff the two programmatically**
  rather than eyeballing — caught real silent drift this way (T-120/D-75).
- **When a session accumulates more than one design fork resolved by implementation rather than
  asking first**, surface all of them together in one end-of-turn message — don't let the user
  discover them one at a time reading `docs/DECISIONS.md` later.
- **When writing a benchmark/comparison wrapper, verify the timer excludes one-time setup** (ctx
  alloc + key-schedule init) — copying a sibling wrapper's structure doesn't carry the same
  guarantee; invisible at bulk sizes, decisive at small ones (D-80). The opposite applies to an
  unkeyed/schedule-free primitive (hash digest) — its benchmark wrapper must call init *inside* the
  timed loop, matching `uacrypt`'s own `bench_in_memory!`.
- **After a const-generic rewrite removes every production caller of an old runtime-parameterized
  function, expect a BATCH of `never used` clippy errors, not just one** — every function down that
  call chain becomes dead at once (T-134). Run clippy right after rewiring the call site, fix the
  whole batch together.
- **Before any `hazmat::{kalyna,kupyna,strumok}` perf rewrite, spike it and read the actual
  `--emit=asm` output — don't plan from source-level reasoning alone.**
  `RUSTFLAGS="--emit=asm -C debuginfo=0" cargo build --release -p dstu-core --lib` (T-139/T-129,
  both reversed once actually spiked).
- **`oracles/uapki`'s vendored clone can be stale relative to upstream `main`** — a raw `diff`
  against a fresh clone can show the *entire* file as different from CRLF-vs-LF alone with zero real
  code drift. Diff-normalize (`diff --strip-trailing-cr`) and confirm line-number alignment before
  hand-copying a patch derived from the vendored copy.
- **When a CI static analyzer (SonarCloud/etc.) flags a finding on your own PR, read its actual
  symbolic-execution trace, not just the one-line summary, before proposing a fix.** `curl
  https://sonarcloud.io/api/issues/search?componentKeys=<project>&pullRequest=<N>` returns each
  issue's `flows` array with the exact assumed path (T-137).
- **`api/issues/search` does not surface duplication findings — that's a separate Quality Gate/
  measures endpoint.** Check `api/qualitygates/project_status?projectKey=<key>&branch=<branch>`
  (and `api/measures/component_tree`/`api/duplications/show`) whenever verifying SonarCloud is
  clean, not issues alone (T-187/T-188). `sonarcloud.yml`'s scan step passes
  `-Dsonar.qualitygate.wait=true` for the same reason — without it the job exits 0 before the gate
  is evaluated server-side.
- **A repo with no root `.gitattributes` lets `windows-latest`'s hosted runner's own system
  gitconfig silently convert every LF blob to CRLF on `actions/checkout`** — invisible unless a
  Windows-only step then diffs file content byte-for-byte (e.g. `gofmt -l`, D-155). Fix: repo-root
  `.gitattributes` with `* text=auto eol=lf` (plus binary markers for tracked binaries) — `eol=lf`
  overrides `core.autocrlf` regardless of the checkout machine's own config.
- **`openssl cms`/`smime -encrypt`/`-decrypt` silently truncate binary input at the first `0x1A`
  byte unless called with `-binary`** — the default S/MIME text-mode handling reads it as an EOF
  marker (D-170). Always pass `-binary` on both sides for non-text payloads, and verify a
  byte-for-byte round trip before trusting a timing number. Separately, Git Bash's MSYS path
  conversion rewrites a leading `/CN=...` in `-subj` into a Windows path — prefix with
  `MSYS_NO_PATHCONV=1`.
- **`openssl speed`'s own `Doing ... ops in Ts` progress line is written to stderr, not stdout** —
  only the final summary table is on stdout. Invisible in a manual `2>&1`-merged shell spike
  (T-187) — parse stderr, not stdout, when scripting this.
- **A MinGW-built `.exe` can fail or hang when launched directly from Git Bash** (bogus
  `STATUS_ENTRYPOINT_NOT_FOUND`/exit 127) **while the identical binary runs clean from PowerShell**
  (T-181). Verify exports with `objdump -p` to rule out a real build issue first, then re-run via
  the `PowerShell` tool before concluding there's a real bug — specific to process launch, not I/O.
- **mdBook's `{{#include file.md}}` resolves relative markdown links in the included content
  against the *including* file's directory, not the original file's** (T-186, `docs/introduction.md`
  transcluding root `README.md`). Use absolute `github.com/.../blob/master/...` URLs for any
  relative link in a transcluded file — re-check whenever README gains a new relative link, or
  another `{{#include}}` is added.

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

- Official documentation PDFs live in `docs/papers/`, including `DSTU_4145-2002.pdf` (a scan, see
  `.claude.local.md` for the render-then-read workflow). Test vectors are extracted and verified for
  Kalyna, Kupyna, and DSTU 4145; Strumok's are UAPKI-attributed plus independently confirmed against
  two state-sourced supplementary vectors, still not confirmed against the paid official text — see
  `docs/ORACLES.md`/`docs/DECISIONS.md` D-15/D-16/D-104.
- **`hazmat::dstu9041` (`l(p)=256`/E256/1) is implemented (T-177)** — a partial primary-text
  scan (T-173) plus a targeted supplement (T-176/D-165) gave clause citations for every algorithm
  the primitive needed (6.5–6.12); `message.rs`/`fp256.rs`/`curve256.rs`/`encryption.rs` were then
  written test-first against that source, verified end-to-end against Додаток Г's own worked
  example (the sole oracle for this primitive, `docs/ORACLES.md`). Two security findings beyond
  clause 12's literal text were caught and fixed before closure (an order-2 point via `r=p-1`, and
  a genuine order-4 subgroup from E256/1's cofactor 4) — see `docs/DECISIONS.md`'s T-177 entry.
  **`l(p)=512`/E512/1 is implemented too (T-192, 2026-08-08)** — `message512.rs`/`fp512.rs`/
  `curve512.rs`/`encryption512.rs`, same test-first/worked-example-verified pattern, both security
  findings independently re-derived (not assumed to carry over) and re-confirmed applicable.
  `l(p)=384` (needs `hazmat::kalyna_kw_p` for its non-block-aligned `M'` case, a new primitive) and
  `l(p)=768` (no worked example exists anywhere in the standard, D-168) remain unimplemented — see
  `docs/pseudocode/dstu9041.md`'s "Implementation status".
- Verify own implementation against Kalyna-reference and the other oracles in `docs/ORACLES.md`.
- Hardware validation on STM32/ESP32 is a distinct post-MVP phase, not a claim of side-channel
  resistance (see MVP scope above).
