# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

All three of Phase 1's MVP primitives have landed and are confirmed green. A local toolchain
(Rust, a C compiler, Maven) was installed into this environment on 2026-07-22 — see
`.claude.local.md`; `cargo`/`gcc`/`mvn` all work here now, this is no longer a "no toolchain"
environment. The workspace has two crates:

- `crates/dstu-core` — the library (`std`/`alloc` feature flags per D-01). `dstu_core::hazmat` has
  three primitives: `kupyna::{Kupyna256, Kupyna512}` (one-shot `digest()`, plus `Kupyna256Hasher`/
  `Kupyna512Hasher` for streaming `update`/`finalize` as of 2026-07-23, `TASKS.md` T-83, citation
  `DECISIONS.md` D-10), `kalyna::{Kalyna128_128, Kalyna128_256, Kalyna256_256,
  Kalyna256_512, Kalyna512_512}` (single-block `encrypt`/`decrypt`, citation `DECISIONS.md` D-13) —
  plus, as of 2026-07-23, `kalyna_ccm` (all five variants, a provisional Kalyna-alone CCM mode of
  operation, citation `DECISIONS.md` D-41, still not confirmed against the primary DSTU 7624:2014
  text — same posture as Strumok below) — and `strumok::{Strumok256, Strumok512}` (keystream generation via
  `apply_keystream`, citation `DECISIONS.md` D-18 — vectors are UAPKI-attributed, not confirmed
  against the official DSTU 8845:2019 text itself, see D-15). All three written test-first;
  Kalyna/Kupyna share S-box/MDS tables via the internal `hazmat::tables` module rather than
  duplicating them, and Strumok's `T` substitution reuses those same shared tables too (only its
  `mul_alpha`/`mul_alpha_inv` tables are new, since that field construction isn't shared). All
  three are **confirmed**: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, the
  `no_std` build, and `cargo miri test` all pass. Check `TASKS.md` Phase 1 for exactly what's still
  open (independent second-oracle cross-check for Kalyna, no high-level wrapper yet). `kalyna_ccm`'s
  nonce strategy is resolved (`DECISIONS.md` D-40, `TASKS.md` T-82):
  wide random nonce generated at the CLI layer via `getrandom`, not a stateful counter — the
  hazmat-level API itself still takes a caller-supplied nonce (`no_std`-compatible). `cargo
  fuzz` has now actually been run (all three
  targets, smoke runs, zero crashes) on a Windows dev machine with Visual Studio installed, via the
  MSVC toolchain/target (`DECISIONS.md` D-32) — CI (Linux) remains the unconditional per-push check.
- `crates/uacrypt` — the CLI binary, renamed 2026-07-23 from its `dstutool` working name
  (`DECISIONS.md` D-36; older `DECISIONS.md`/`TASKS.md`/`PERFORMANCE.md` entries predating the
  rename still say `dstutool`, left as-is since they're a historical record, not stale docs).
  No longer a placeholder: `kalyna-block encrypt/decrypt`, `kupyna-digest`, and `strumok-crypt`
  subcommands exist (`DECISIONS.md` D-31), used for binary-level performance comparisons
  (`PERFORMANCE.md`); as of 2026-07-23, `kalyna-ccm encrypt/decrypt` also exists (`DECISIONS.md`
  D-41) — still deliberately not the reserved top-level `encrypt`/`decrypt` names, since D-05's
  primary-text confirmation (not just a provisional mode) is what unblocks those, per the
  file-plus-mode-of-operation CLI the MVP scope below describes.

`cargo xtask <command>` (see `xtask/`, aliased via `.cargo/config.toml`) is the one cross-platform
build/QA entry point — same command on Linux/Windows/macOS, no new install beyond `cargo` itself.
`cargo xtask ci` runs the mandatory checks then best-effort runs miri/fuzz/audit/deny/oracle
harnesses, printing an install hint for whichever optional tool isn't present rather than failing.
See `DECISIONS.md` D-12 and `README.md` "Development commands". Use this instead of writing a new
one-off shell/PowerShell script for any build/QA task.

Official test vectors are extracted and verified for Kalyna and Kupyna:
`crates/dstu-core/tests/vectors/{kalyna,kupyna}/*.json` — see `ORACLES.md` for provenance and
format. These vectors have additionally been run against real Bouncy Castle (Java and .NET, via
the published packages, not the vendored oracle clones) in `tests/oracle-harness/{java,dotnet}/`
and passed in full — see `TASKS.md` "Infrastructure". No C/cryptonite harness — tried and
dropped, see `TASKS.md` and `ORACLES.md` for why.

The concrete module-by-module API surface (what's implemented, what's blocked, and why) lives in
`docs/dstu-crypto-project.md` "Concrete API shape" and is tracked as a checklist in `TASKS.md`.

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
- Single CLI binary over the core (`uacrypt`, `DECISIONS.md` D-36), e.g.
  `uacrypt encrypt --key ... --in file --out file` — mode, nonce/IV etc. are hardcoded so there's
  nothing for the user to misconfigure.
- Publish the core crate to crates.io.
- Prebuilt binaries for Windows/Linux via GitHub Releases (not "clone and build yourself").
- **No hardware or OS lock-in — platform-agnostic by construction.** This targets both ends
  genuinely, not just one with lip service to the other: full PCs/servers (Windows, Linux, macOS,
  x86-64/ARM64) *and* microcontrollers (STM32 on ARM Cortex-M, ESP32 on Xtensa/RISC-V — genuinely
  different architectures, not variations of one). Concretely:
  - **Core must be `no_std`-compatible from day one** (Cargo feature flags `std` / `alloc` /
    `no_std`) so embedded targets can be added later without a core rewrite. Real-hardware
    validation is a separate post-MVP phase. The non-embedded ARM64/Linux half of this claim now
    has a real hardware rig checking it (a Raspberry Pi, `TASKS.md` "Testing & hardening" — access
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
  in `DECISIONS.md` for the full rationale (different math class from the rest of this project,
  complexity on the order of all five in-scope algorithms combined, immature cryptanalysis, no
  vetted oracle exists). If this is ever picked up, `docs/dstu-crypto-project.md` "Post-quantum
  track" has the fuller context.

## Documentation map

| File | Read when | Update when | Canonical owner of |
|---|---|---|---|
| `TASKS.md` | starting or resuming any work session | a task is started, finished, or newly discovered | phase-by-phase task backlog and progress state — status only, not rationale |
| `docs/dstu-crypto-project.md` | planning scope, API design, algorithm choices | scope or API-mapping decisions change | project scope, libsodium API mapping |
| `docs/resource-profiles.md` | choosing/explaining `fused` vs `small-tables`, sizing a target's flash budget | the profile split's memory/speed numbers change, or a new MCU tier is added to the sizing guide | `small-tables` feature memory/speed numbers (`DECISIONS.md` D-35/D-38/D-39), per-target profile recommendation |
| `SECURITY.md` | before writing any crypto primitive or adding a dependency | threat model or hard constraints change | threat model, hard constraints, supply-chain vetting |
| `DECISIONS.md` | need the reason behind an architectural choice | a new architectural decision is made | decisions + rejected alternatives, with citations |
| `ORACLES.md` | before implementing or verifying any primitive | oracle trust ranking changes, or a new oracle/vector source is added | oracle trust matrix, per-algorithm oracle map, test-vector convention, list of reference implementations (`oracles/README.md` links here rather than duplicating) |
| `docs/pseudocode/*.md` | before writing a primitive's Rust implementation | the transcription changes or a new ambiguity/discrepancy is found | per-algorithm pseudocode — from-spec for Kalyna/Kupyna/Strumok, from-oracle-code for DSTU 4145 (official text now exists too — see the doc's 2026-07-22 update note — but the pseudocode itself isn't re-derived from it yet), each cross-checked and with any ambiguity flagged inline |
| `docs/rust_ai_ruleset.md` | general Rust code-style questions | never (external ruleset, treat as canonical as-is) | generic Rust engineering conventions |
| `docs/cross-language-style-guide.md` | writing or reviewing non-Rust code (oracle harnesses, future language bindings) | a new language is added, or a cross-language principle needs adjusting | cross-language naming/style principles and the per-language reference table; generalizes `docs/rust_ai_ruleset.md`, doesn't replace it |
| `README.md` | need the human-facing project overview or repo tree | repo structure changes | GitHub-facing description, top-level directory map, build/install instructions |
| `PERFORMANCE.md` | need this project's benchmark numbers, or comparing against another implementation's speed | new numbers are measured, or a new comparison implementation is benchmarked | benchmark methodology (cross-implementation comparisons are binary-level/MB/s only, `DECISIONS.md` D-34 — `cargo bench`/`criterion` is for internal regression tracking only, never a cross-implementation claim), recorded numbers, comparisons against reference C/UAPKI/outspace, the saved `criterion --baseline` for regression tracking |
| `xtask/src/main.rs` | adding or changing a build/QA subcommand | a new tool enters the QA stack or an existing command's invocation changes | the actual cross-platform build/QA command implementations (README.md documents usage, this owns behavior) |

`docs/rust_ai_ruleset.md` §7 (async/tokio) does not apply to the `no_std`-first core — it's only
relevant if a future CLI or binding layer adds async I/O.

## Crypto engineering hard constraints

Full detail and rationale in `SECURITY.md` — this is the compressed version so it can't be missed:

- No primitive without a cited spec section (DSTU clause or reference-implementation source) —
  citation goes in `DECISIONS.md`.
- No secret-dependent branching. Secret-dependent array indexing is allowed only for fixed-latency
  S-box/GF-multiplication table lookups mirroring the DSTU reference implementations — documented
  software-timing exception, see D-19 in `DECISIONS.md`, not a license to add more of this
  category casually. Secret comparisons via `subtle::ConstantTimeEq`, never `==`; all key material
  is `Zeroize`/`ZeroizeOnDrop`; no secret material in logs.
- No homegrown primitives — where DSTU has a real gap (pwhash, CSPRNG), use the established
  international primitive (Argon2id, OS `getrandom`), see D-03/D-04 in `DECISIONS.md`.
- **Dual-oracle verification is mandatory**: official DSTU test vectors *and* an independent
  reference implementation (Kalyna-reference, cryptonite, Bouncy Castle — see `ORACLES.md` for the
  per-algorithm map). Self-consistent tests passing is not sufficient evidence.
- `cargo miri test` and `cargo fuzz` are required layers, not optional tooling.
- This is the software-side complement to the SPA/DPA note above: constant-time discipline
  reduces exposure but is never itself a side-channel-resistance claim.

## Agent discipline

- **UTF-8 everywhere, no exceptions.** Every text file in this repo — source, docs, config,
  test-vector JSON — is UTF-8, without a byte-order mark. This matters concretely here: the
  project mixes English docs with Ukrainian source material (paper titles, standard names,
  commit/PR text when the user writes Ukrainian) and extracts hex/text from PDFs via `pdftotext`
  on Windows, all of which can silently introduce UTF-16, a BOM, or a Windows codepage (e.g.
  CP1251) if a tool's default isn't checked. Verify encoding when creating or editing a file if
  there's any doubt, rather than assuming the tool defaulted correctly.
- **Test-first, always.** Write the failing test before the implementation — a unit test, or for
  crypto code, a test-vector check (see dual-oracle verification above). Never write the
  implementation first and backfill tests afterward. This applies to every function, not just
  primitives.
- **A `hazmat` streaming/incremental API existing does not make the `uacrypt` command wrapping it
  memory-bounded** (`DECISIONS.md` D-42) — a CLI command has to be deliberately wired to read its
  input in fixed chunks instead of `std::fs::read`-ing the whole file, every time a new algorithm
  gains a genuine streaming API (unless its construction truly needs the whole message up front,
  e.g. a length-prefixed AEAD header — not the same thing as "the current code happens to read it
  all at once"). Kupyna's `kupyna-digest` does this (T-83/D-42): small chunks for real single-pass
  use, larger chunks for the `--iterations` benchmark path, sized for each path's actual
  constraint (memory vs. throughput) rather than copied from another algorithm's numbers.
  `strumok-crypt` doesn't yet — a known gap, not a silent inconsistency.
- **Three-attempts rule**: if the same problem survives 3 different approaches (especially
  toolchain/build/CI issues), stop, report what was tried and what's still unknown, and wait for
  direction — don't self-authorize a 4th attempt.
- **Research before implementation**: no primitive written from memory. Verify against the
  primary source (specific DSTU clause, or real reference-implementation code) before writing it,
  and record the citation in `DECISIONS.md`. **If only a reference implementation is available
  (the primary spec text doesn't exist yet or hasn't been read)**, treat that citation as
  provisional, not equivalent to a primary-source check — say so explicitly in `DECISIONS.md`
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
  `DECISIONS.md` D-25's follow-up entries and `docs/pseudocode/dstu4145.md`.
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

## Reference implementations and oracles

Canonical detail — trust ranking, per-algorithm oracle map, local clones under `oracles/`, and
the `li0ard` exclusion (D-07) — lives in `ORACLES.md`. Do not duplicate that list here; the full
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
  (`crates/dstu-core/tests/vectors/{kalyna,kupyna,dstu4145}/`); Strumok's are UAPKI-attributed, not
  yet confirmed against the paid official text — see `ORACLES.md`/`DECISIONS.md` D-15/D-16.
- Verify own implementation against Kalyna-reference and the other oracles in `ORACLES.md`.
- Hardware validation on STM32/ESP32 is a distinct post-MVP phase, and is not a claim of
  side-channel resistance (see MVP scope above).
