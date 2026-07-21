# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

First primitive landed and confirmed green. A local toolchain (Rust, a C compiler, Maven) was
installed into this environment on 2026-07-22 — see `.claude.local.md`; `cargo`/`gcc`/`mvn` all
work here now, this is no longer a "no toolchain" environment. The workspace has two crates:

- `crates/dstu-core` — the library (`std`/`alloc` feature flags per D-01). `dstu_core::hazmat`
  exists with one primitive: `kupyna::{Kupyna256, Kupyna512}` (one-shot `digest()` only, no
  streaming API yet). Written test-first against `crates/dstu-core/tests/kupyna.rs`, citation in
  `DECISIONS.md` D-10. **Confirmed**: `cargo test`, `cargo miri test` (no UB), `cargo clippy --
  -D warnings`, and the `no_std` build all pass. Check `TASKS.md` Phase 1 for exactly what's
  still open (streaming API, `cargo fuzz` not yet actually run, no high-level wrapper yet).
- `crates/dstutool` — the CLI binary, still a placeholder `main.rs`.

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
- Single CLI binary over the core (working name `dstutool`), e.g.
  `dstutool encrypt --key ... --in file --out file` — mode, nonce/IV etc. are hardcoded so there's
  nothing for the user to misconfigure.
- Publish the core crate to crates.io.
- Prebuilt binaries for Windows/Linux via GitHub Releases (not "clone and build yourself").
- **Core must be `no_std`-compatible from day one** (Cargo feature flags `std` / `alloc` /
  `no_std`), so embedded targets (STM32 on ARM Cortex-M, ESP32 on Xtensa/RISC-V — genuinely
  different architectures, not variations of one) can be added later without a core rewrite.
  Real-hardware validation is a separate post-MVP phase.
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
| `SECURITY.md` | before writing any crypto primitive or adding a dependency | threat model or hard constraints change | threat model, hard constraints, supply-chain vetting |
| `DECISIONS.md` | need the reason behind an architectural choice | a new architectural decision is made | decisions + rejected alternatives, with citations |
| `ORACLES.md` | before implementing or verifying any primitive | oracle trust ranking changes, or a new oracle/vector source is added | oracle trust matrix, per-algorithm oracle map, test-vector convention, list of reference implementations (`oracles/README.md` links here rather than duplicating) |
| `docs/pseudocode/*.md` | before writing a primitive's Rust implementation | the transcription changes or a new ambiguity/discrepancy is found | per-algorithm pseudocode — from-spec for Kalyna/Kupyna/Strumok, from-oracle-code for DSTU 4145 (no spec paper exists), each cross-checked and with any ambiguity flagged inline |
| `docs/rust_ai_ruleset.md` | general Rust code-style questions | never (external ruleset, treat as canonical as-is) | generic Rust engineering conventions |
| `docs/cross-language-style-guide.md` | writing or reviewing non-Rust code (oracle harnesses, future language bindings) | a new language is added, or a cross-language principle needs adjusting | cross-language naming/style principles and the per-language reference table; generalizes `docs/rust_ai_ruleset.md`, doesn't replace it |
| `README.md` | need the human-facing project overview or repo tree | repo structure changes | GitHub-facing description, top-level directory map |

`docs/rust_ai_ruleset.md` §7 (async/tokio) does not apply to the `no_std`-first core — it's only
relevant if a future CLI or binding layer adds async I/O.

## Crypto engineering hard constraints

Full detail and rationale in `SECURITY.md` — this is the compressed version so it can't be missed:

- No primitive without a cited spec section (DSTU clause or reference-implementation source) —
  citation goes in `DECISIONS.md`.
- No secret-dependent branching/indexing; secret comparisons via `subtle::ConstantTimeEq`, never
  `==`; all key material is `Zeroize`/`ZeroizeOnDrop`; no secret material in logs.
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
- **Three-attempts rule**: if the same problem survives 3 different approaches (especially
  toolchain/build/CI issues), stop, report what was tried and what's still unknown, and wait for
  direction — don't self-authorize a 4th attempt.
- **Research before implementation**: no primitive written from memory. Verify against the
  primary source (specific DSTU clause, or real reference-implementation code) before writing it,
  and record the citation in `DECISIONS.md`.
- **Don't trust green tests alone for security-critical code** — see dual-oracle verification
  above.

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

- Official documentation PDFs live in `docs/papers/`. Test vectors have already been extracted
  and verified for Kalyna and Kupyna (`crates/dstu-core/tests/vectors/`); Strumok has none in any
  source surveyed so far — confirmed gap, see `ORACLES.md`.
- Verify own implementation against Kalyna-reference and the other oracles in `ORACLES.md`.
- Hardware validation on STM32/ESP32 is a distinct post-MVP phase, and is not a claim of
  side-channel resistance (see MVP scope above).
