# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Planning stage — no source code exists yet. The repository currently contains only the project
spec (`docs/dstu-crypto-project.md`) and reference PDFs (academic papers on Kalyna, Kupyna, Strumok
cryptanalysis and hardware implementation). There is no Cargo.toml, no build, no lint, no test
commands to run. Do not invent tooling or commands that aren't there yet — check this file's
"Project status" section is still accurate before assuming otherwise.

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

## Documentation map

| File | Read when | Update when | Canonical owner of |
|---|---|---|---|
| `docs/dstu-crypto-project.md` | planning scope, API design, algorithm choices | scope or API-mapping decisions change | project scope, libsodium API mapping |
| `SECURITY.md` | before writing any crypto primitive or adding a dependency | threat model or hard constraints change | threat model, hard constraints, supply-chain vetting |
| `DECISIONS.md` | need the reason behind an architectural choice | a new architectural decision is made | decisions + rejected alternatives, with citations |
| `docs/rust_ai_ruleset.md` | general Rust code-style questions | never (external ruleset, treat as canonical as-is) | generic Rust engineering conventions |

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
  reference implementation (Kalyna-reference, cryptonite, Bouncy Castle — see "Reference
  implementations and oracles" below). Self-consistent tests passing is not sufficient evidence.
- `cargo miri test` and `cargo fuzz` are required layers, not optional tooling.
- This is the software-side complement to the SPA/DPA note above: constant-time discipline
  reduces exposure but is never itself a side-channel-resistance claim.

## Agent discipline

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

These exist for **test-vector verification only** — do not copy code directly unless a license
explicitly permits it:

- **[privat-it/cryptonite](https://github.com/privat-it/cryptonite)** — PrivatBank's library,
  BSD-2-Clause (verified license, legally clean to fork/port from). C, covers Kalyna, Kupyna,
  DSTU 4145 + legacy GOST algorithms + Western algorithms for compat. Has Java/Android JNI
  bindings. Caveat: 2016-era code; the state "expert opinion" certification lapsed 2021-11-25 and
  was not renewed publicly; no recent independent audit.
- **[Roman-Oliynykov/Kalyna-reference](https://github.com/Roman-Oliynykov/Kalyna-reference)** — C
  implementation by the actual author of the Kalyna standard. That author's GitHub
  (Roman-Oliynykov) also has a Kupyna reference implementation and some documentation. **No
  LICENSE file** — oracle for test-vector comparison only, never copy code from it.
- **[outspace/dstu8845](https://github.com/outspace/dstu8845)** — Strumok in C, unofficial.
- **[li0ard/strumok](https://github.com/li0ard/strumok)** — Strumok in TypeScript, unofficial.
- **Bouncy Castle** (Java/.NET) — mature production DSTU 4145 signature implementation
  (`DSTU4145Signer`); see "Second priority" above.
- **Ecognize/libukrypto** — WIP OpenSSL engine for DSTU, appears stalled. Useful only as a CLI
  architecture reference, not a code donor.
- **li0ard** GitHub account — fragmented single-author TypeScript/Go packages for
  Kalyna/Kupyna/Strumok/DSTU 4145. Actively updated (2025) but no independent audit and no
  consistent shared architecture across them.
- **crates.io**: the `kupyna` crate exists but is dead (single release, December 2016, no updates
  since). `kalyna`, `strumok`, `dstu4145` crates don't exist at all — a genuine open niche in the
  Rust ecosystem.

## State certification (informational, not an MVP blocker)

- Regulator: Administration of the State Service for Special Communications
  (Держспецзв'язку). Mandatory certification only applies when the tool is used to protect state
  information resources or information whose protection is required by law. An open library on
  GitHub/GitLab by itself falls under the voluntary category.
- Certification is tied to the hash of a specific build — changing the code potentially requires
  re-certification. Not relevant to MVP development.

## Roadmap notes

- Obtain official documentation PDFs with test vectors from each DSTU algorithm's authors as
  reference documentation (already collected in this repo's root as PDFs).
- Verify own implementation against Kalyna-reference and other oracles listed above.
- Hardware validation on STM32/ESP32 is a distinct post-MVP phase, and is not a claim of
  side-channel resistance (see MVP scope above).
