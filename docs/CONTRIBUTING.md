# Contributing to uacrypt

Thanks for your interest — this is an open project and pull requests are welcome. It's **pre-1.0,
not yet audited, not production-ready** (see the README's status line and `docs/release-readiness.md`
for the gap analysis), so expect some rough edges and a fair number of "why does this exist"
citations in the code — this project cites its own reasoning heavily (`docs/DECISIONS.md`) rather
than assuming it's obvious.

By participating, you're expected to follow this project's [Code of Conduct](CODE_OF_CONDUCT.md).

## Repository structure

```
.
├── CLAUDE.md              # operating guide for AI agents in this repo
├── AGENTS.md              # thin pointer to CLAUDE.md's own reading order, for non-Claude-Code AI agents
├── docs/SECURITY.md            # threat model, hard constraints, supply-chain vetting
├── docs/DECISIONS.md           # architectural decisions with rejected alternatives
├── docs/TASKS.md               # phase-by-phase task backlog and progress state
├── docs/CHANGELOG.md           # Keep a Changelog-format release history
├── docs/ORACLES.md             # oracle trust ranking, per-algorithm oracle map, test-vector provenance
├── docs/PERFORMANCE.md         # benchmark methodology and recorded numbers
├── docs/CONTRIBUTING.md        # this file
├── docs/CODE_OF_CONDUCT.md     # community standards (Contributor Covenant)
├── LICENSE-MIT
├── LICENSE-APACHE
├── .github/workflows/     # CI (rust.yml, oracle-harness.yml) and the release workflow (release.yml)
├── .github/ISSUE_TEMPLATE/, PULL_REQUEST_TEMPLATE.md  # issue/PR templates
├── .cargo/config.toml     # `cargo xtask` alias
├── xtask/                 # cross-platform build/QA runner, see "Development commands" below
├── docs/
│   ├── dstu-crypto-project.md        # main project spec (scope, API mapping)
│   ├── release-readiness.md          # gap analysis: current state vs. a libsodium-equivalent 1.0
│   ├── user-journey-gaps.md          # persona/journey-organized companion gap analysis
│   ├── resource-profiles.md          # fused vs small-tables: memory/speed numbers, which to pick
│   ├── CLI.md                        # full `uacrypt` CLI walkthrough (every subcommand)
│   ├── pseudocode/                   # per-algorithm pseudocode, cross-checked against oracles
│   ├── rust_ai_ruleset.md            # generic Rust ruleset for AI assistants
│   ├── cross-language-style-guide.md # naming/style conventions for non-Rust code
│   ├── bindings-strategy.md          # Phase 3 language-binding plan: order, C-ABI split, per-binding checklist
│   └── papers/                       # reference PDFs (specs, cryptanalysis, hardware papers)
├── crates/                # Cargo workspace
│   ├── dstu-core/          # core: Kalyna + Kupyna + Strumok
│   ├── uacrypt/            # CLI binary on top of the core
│   └── dstu-core-capi/     # C ABI - foundation for C++/.NET/Java/Go bindings (T-158)
├── bindings/               # Phase 3 language bindings, see docs/bindings-strategy.md
│   ├── python/             # PyO3, full crypto_* surface - on PyPI (T-49)
│   ├── nodejs/             # napi-rs, full crypto_* surface - on npm (T-50)
│   ├── ruby/               # magnus/rb-sys, full crypto_* surface - RubyGems in progress (T-160)
│   ├── php/                # ext-php-rs, full crypto_* surface - not on Packagist yet (T-159)
│   ├── dotnet/             # C# P/Invoke over dstu-core-capi - not on NuGet yet (T-52)
│   ├── java/               # jni crate, full crypto_* surface - not on Maven Central yet (T-51)
│   ├── go/                 # cgo over dstu-core-capi, full crypto_* surface - repo-relative only (T-163)
│   └── cpp/                # header-only RAII wrapper over dstu-core-capi, full crypto_* surface (T-53)
├── firmware/               # Phase 4 hardware/emulation checks, own Cargo workspace(s) - see docs/DECISIONS.md D-156
│   └── qemu-stm32-smoketest/  # runs official Kalyna/Kupyna vectors under QEMU's netduinoplus2 (Cortex-M4F), no real board needed (T-170)
├── tests/oracle-harness/   # Java/.NET/C harnesses that verify test vectors against real Bouncy Castle
└── oracles/                # reference implementations used as oracles - not vendored, see oracles/README.md
```

## Setting up a dev environment

Rust is the only hard requirement — everything else in this table is optional and only needed for
the specific `cargo xtask` command listed. No admin rights required on any platform for any of it.

| Tool | Needed for | Linux / macOS | Windows |
|---|---|---|---|
| Rust (stable, via `rustup`) | everything | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `winget install Rustlang.Rustup` (or `rustup-init.exe` from [rustup.rs](https://rustup.rs)) |
| C/C++ compiler | `cargo xtask fuzz` (`libfuzzer-sys` builds C++); building the manual C oracle-differential harnesses under `tests/oracle-harness/*-differential/` | usually preinstalled; else your distro's `gcc`/`build-essential` package | MinGW-w64 GCC (e.g. `winget install BrechtSanders.WinLibs.POSIX.UCRT`) builds the crate and those harnesses; **`cargo xtask fuzz` additionally needs real MSVC**, see below |
| `cargo-fuzz` | `cargo xtask fuzz` | `cargo install cargo-fuzz --locked` — runs directly against the native nightly toolchain | see "`cargo fuzz` on Windows" below |
| `miri` (nightly component) | `cargo xtask miri` | `rustup component add miri --toolchain nightly` | same |
| `kani-verifier` | `cargo xtask kani` (bounded model checking, `gf2m163::reduce` proofs) | `cargo install kani-verifier && cargo kani setup` | **not supported** — see below |
| `cargo-audit` / `cargo-deny` | `cargo xtask audit` / `cargo xtask deny` | `cargo install cargo-audit --locked` / `cargo install cargo-deny --locked` | same install commands, but each needs `dlltool.exe` on `PATH` first — comes with a MinGW-w64 install (e.g. the WinLibs package above), not with `rustup` alone |
| JDK 8+ and Maven 3.6+ | `cargo xtask oracle-java` (cross-check against real Bouncy Castle) | your distro's packages, or Maven's binary zip if unpackaged | same |
| .NET SDK 8 or 9 | `cargo xtask oracle-dotnet` (cross-check against real Bouncy Castle) | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) | same |

This project builds against the GNU host toolchain on Windows (`x86_64-pc-windows-gnu`) by default,
specifically to avoid a Visual Studio dependency for ordinary building/testing — run `rustup
default stable-x86_64-pc-windows-gnu` if `rustup-init` didn't already pick it. `rustup` reads
`rust-toolchain.toml` and installs the pinned `stable` channel plus `clippy`/`rustfmt` automatically
the first time you run any `cargo` command in this repo.

The reference implementations used as correctness oracles (`oracles/kalyna-reference`, UAPKI,
etc.) are **not** vendored in this repo — see `oracles/README.md` for what each one is and where to
get it. You only need them for the manual differential harnesses; ordinary `cargo build`/`cargo
test`/`cargo xtask ci` need none of it.

```
git clone <this repo>
cd cipher_ua
cargo build --workspace
cargo test --workspace
```

### `cargo fuzz` on Windows needs MSVC, not this project's default GNU toolchain

libFuzzer's Address Sanitizer only supports the MSVC target on Windows — the default
`x86_64-pc-windows-gnu` toolchain above cannot build or run fuzz targets at all, no matter which
flags are passed (`docs/DECISIONS.md` D-32 has the full diagnosis). To run `cargo xtask fuzz` locally on
Windows:

1. Install Visual Studio (or just the Build Tools) with the "Desktop development with C++"
   workload.
2. `rustup toolchain install nightly-x86_64-pc-windows-msvc` — an *additional* toolchain; this does
   not change the project's default GNU host toolchain used for everything else.
3. Run `cargo xtask fuzz`. It finds the Visual Studio install itself (via `vswhere.exe`'s fixed
   path) and the toolchain above, then runs each target through a `vcvars64.bat`-sourced shell with
   `--target x86_64-pc-windows-msvc` — both the environment and the explicit target flag are
   required, not just the extra toolchain (`docs/DECISIONS.md` D-32 explains why: without `vcvars64.bat`
   the ASan runtime DLL isn't found at run time, even though the build itself succeeds; without the
   explicit `--target`, `cargo-fuzz` defaults back to the GNU target regardless of which toolchain
   invoked it).

Without a Visual Studio C++ toolset installed, `cargo xtask fuzz` prints an install hint and skips
cleanly on Windows, same as any other missing optional tool — CI (Linux) remains the actual,
unconditional venue where fuzz targets run on every push.

### `cargo xtask kani` does not run on Windows at all

Unlike every other optional tool above, this isn't a missing-install-step case: `kani-verifier`'s
own source calls Unix-only std APIs (`std::os::unix::fs::symlink`, `Command::arg0`) that don't
exist on Windows, confirmed by trying `cargo install kani-verifier` directly (`docs/DECISIONS.md`
D-102). It was also tried on this project's aarch64 Raspberry Pi (Debian 12) — `cargo kani setup`
completed, but the prebuilt bundle's `cargo-kani` binary requires `GLIBC_2.39`, newer than bookworm's
`2.36`. `cargo xtask kani` prints this explanation and skips cleanly rather than a raw error — CI
(`ubuntu-latest`, D-102's `kani` job) is the actual, unconditional venue where these proofs run on
every push.

## Before you start

Read these first — they're short, and they explain *why* the code looks the way it does, not just
what it does:

- [`docs/SECURITY.md`](SECURITY.md) — threat model and **hard constraints** (no secret-dependent
  branching, `subtle::ConstantTimeEq` for secret comparisons, `Zeroize` for key material, no
  homegrown primitives where an established one exists). These aren't style preferences; a PR that
  violates one will be asked to change before anything else is reviewed.
- [`docs/DECISIONS.md`](DECISIONS.md) — architectural decisions already made, with the rejected
  alternatives and why. If you're about to propose an API shape or algorithmic choice, check here
  first — it may already have been decided (and the reasoning recorded) or explicitly rejected.
- [`docs/TASKS.md`](TASKS.md) — the phase-by-phase backlog. Good place to find something to work on,
  or to check whether what you want to add is already planned/blocked for a specific reason.
- [`docs/rust_ai_ruleset.md`](rust_ai_ruleset.md) — the generic Rust engineering conventions this
  codebase follows (applies to human contributors too, not just AI agents).

## Reporting bugs / requesting features

Use the GitHub issue templates (bug report / feature request). **Do not open a public issue for a
security vulnerability** — see `docs/SECURITY.md` "Reporting vulnerabilities" (private disclosure
via GitHub Security Advisories).

## Making a change

1. **Test-first, always.** Write the failing test before the implementation — a unit test, or for
   crypto code, a test-vector check. For a new primitive/mode/wrapper/CLI command, that means three
   categories, not one:
   - **Correctness** — against an official test vector or a cross-checked oracle
     (`docs/ORACLES.md` has the trust ranking and per-algorithm map). **Dual-oracle verification is
     mandatory** for anything touching a cryptographic primitive: official vectors *and* an
     independent reference implementation. Self-consistent tests passing is not sufficient evidence.
   - **Rejection** — tampered ciphertext/tag/AAD/nonce, wrong key, wherever there's something to
     tamper with.
   - **Misuse** — invalid lengths/args/paths, degenerate-but-legal input (empty file, all-zero key),
     no partial output written on failure.
2. **No secret-dependent branching or timing.** Secret-dependent array indexing is allowed only for
   fixed-latency table lookups mirroring the DSTU reference implementations (a documented exception
   in `docs/SECURITY.md`/`docs/DECISIONS.md` D-19) — not a license to add more of this category
   casually.
3. **No primitive written from memory.** Cite the specific DSTU clause or reference-implementation
   source in `docs/DECISIONS.md` before merging. If only a reference implementation is available
   (no primary spec text), say so explicitly and mark the citation provisional.
4. Run the checks locally before opening a PR. `cargo xtask <command>` is the one cross-platform
   entry point for build/test/QA — the same command on Linux, Windows, and macOS (`docs/DECISIONS.md`
   D-12). Run `cargo xtask help` for the full list; the essentials:

   ```
   cargo xtask build      # cargo build --workspace, both --all-features and no_std (--no-default-features)
   cargo xtask test       # cargo test --workspace --all-features
   cargo xtask fmt        # cargo fmt --all (add --check to verify without writing)
   cargo xtask clippy     # cargo clippy --workspace --all-features -- -D warnings
   cargo xtask docs-check # README/gh-pages version-marker freshness lint vs crates/dstu-core's Cargo.toml (T-186)
   ```

   `cargo xtask ci` runs the five above, then best-effort miri/kani/book/fuzz/audit/deny/oracle-harness
   layers — each checks its own tool is installed first and prints an install hint instead of a raw
   error if it's missing. `docs-check` needs no external tool, so it's mandatory rather than
   best-effort — same standing as `fmt`/`build`/`test`/`clippy`. `cargo xtask book` builds the
   mdBook knowledge base this file is part of; `cargo xtask bench-compare` runs the uacrypt-vs-OpenSSL
   benchmark table (`docs/PERFORMANCE.md`).
5. If you touched anything `no_std`-relevant (most of `dstu-core`), check the feature matrix
   individually, not just `--all-features` — a narrow combination (e.g.
   `--no-default-features --features dstu-core/small-tables`) can hide issues the broad profile
   doesn't exercise.
6. Update `docs/DECISIONS.md` (new architectural choice or citation) and `docs/TASKS.md` (task
   started/finished/newly discovered) if your change touches either — this project treats stale
   docs as a real defect, not a nice-to-have.

## Working on a language binding

The sections above are written for `dstu-core`/`uacrypt` contributors (a new primitive, mode, or
CLI command). Fixing or extending an existing binding under `bindings/` (Python, Node.js, Ruby,
PHP, .NET, Java, Go, C++), or adding a new one, follows a different, already-templated process —
see `docs/bindings-strategy.md`'s "The standard binding steps" for the authoritative ten-step list.
The parts most likely to trip up a first-time binding contributor:

- **Each binding is its own separate Cargo/language workspace** (D-119), not a member of the root
  workspace and not reachable via the root `cargo xtask`. Build and test it from inside its own
  `bindings/<lang>` directory, using that language's native tooling plus the project's own
  `cargo xtask <lang>` subcommand (e.g. `cargo xtask python`, `cargo xtask nodejs`, `cargo xtask
  ruby`, `cargo xtask php`, `cargo xtask dotnet`, `cargo xtask java`, `cargo xtask go`, `cargo
  xtask cpp`) — same cross-platform-QA-entry-point posture as the core crate (D-12), not a new
  one-off script per language.
- **The same three test categories apply, through the binding's own API surface**, not just the
  Rust core's: correctness against the shared official vectors, rejection (tampered
  ciphertext/tag/AAD/nonce, wrong key), and misuse (invalid lengths/args/paths, degenerate-but-
  legal input) — D-64/D-65.
- **If your change touches `crypto_secretstream`'s binding, re-check both known pitfalls** found
  by advisor review while building the Python wrapper (T-49), not just assume the Python fix
  generalizes: the language's own "always runs, even on error" cleanup hook (`__exit__`/
  `Dispose`/try-with-resources/RAII destructor) must not finalize the stream on the exception
  path, and the wire-format reader must itself bound the untrusted length-prefixed chunk field and
  reject trailing data after the `Final` chunk — matching the wire format on the happy path isn't
  enough, its validation has to be ported too. Full detail in `docs/bindings-strategy.md`'s
  standard binding steps, step 3.
- **Cross-arch check on real ARM64 Linux (step 10 of the standard steps, D-151)** is expected for
  any change to a binding's FFI-boundary code, not just brand-new bindings — it already found one
  real bug (a hardcoded `i8` test buffer that should have been `c_char`, silent on x86-64, broken
  on ARM Linux's unsigned-by-default `char`). If you don't have access to ARM hardware yourself,
  say so in the PR rather than skipping the step silently — a maintainer can run it.
- Doc-map sweep and `docs/TASKS.md` updates apply the same way they do for core changes (see
  "Making a change" step 6 above) — a binding change touching scope or API shape should update
  `docs/bindings-strategy.md` too, since it's the canonical owner of the per-binding checklist.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) style:
`type(scope): short description`, e.g. `feat(dstu-core): add Kalyna-XTS mode`,
`fix(uacrypt): reject empty --key file`, `docs(DECISIONS.md): record D-97`. Check `git log` for the
established scope names (crate/module names mostly).

## Opening the PR

- Keep it focused — one logical change per PR is easier to review and bisect than a bundle.
- Fill in the PR template's checklist honestly; an unchecked box with a one-line reason is more
  useful than a checked box that isn't true.
- CI (`rust.yml`, `sonarcloud.yml`, `oracle-harness.yml`) must be green. If a static-analyzer
  finding (SonarCloud) shows up on your own PR, fix it in the same PR rather than leaving it for
  later — this project treats analyzer findings as required, same as tests.

## Licensing

This project is dual-licensed under MIT / Apache-2.0. Unless you explicitly state otherwise, any
contribution you submit for inclusion will be dual-licensed as above, without any additional terms
or conditions — the standard convention for the Rust ecosystem.
