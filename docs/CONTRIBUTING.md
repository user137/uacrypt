# Contributing to uacrypt

Thanks for your interest — this is an open project and pull requests are welcome. It's a **v0.1.0
pre-release, not yet audited, not production-ready** (see the README's Status paragraph), so expect
some rough edges and a fair number of "why does this exist" citations in the code — this project
cites its own reasoning heavily (`docs/DECISIONS.md`) rather than assuming it's obvious.

By participating, you're expected to follow this project's [Code of Conduct](CODE_OF_CONDUCT.md).

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
4. Run the checks locally before opening a PR:

   ```
   cargo xtask fmt      # cargo fmt --all
   cargo xtask clippy   # cargo clippy --workspace --all-features -- -D warnings
   cargo xtask test     # cargo test --workspace --all-features
   cargo xtask build    # both --all-features and no_std (--no-default-features)
   ```

   `cargo xtask ci` runs all of the above plus best-effort miri/fuzz/audit/deny/oracle-harness
   layers (installs what it can, prints an install hint for anything missing rather than failing).
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
