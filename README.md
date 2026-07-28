# uacrypt

**v0.1.0 — pre-release / work in progress.** Not a complete library or CLI yet, not audited, not
production-ready, and **not a claim of side-channel resistance**. Core primitives (Kalyna, Kupyna)
are dual-oracle-verified against official test vectors; Strumok and the Kalyna-CCM mode are
provisional (not yet confirmed against their primary standard text — see `docs/DECISIONS.md` D-15/D-41).
**`crypto_secretstream` — the construction backing `encrypt`/`decrypt` — is provisional in a
stronger sense still**: it's a from-scratch chunked-AEAD framing with no DSTU standard defining
anything like it, so unlike Strumok/Kalyna-CCM, no primary text or oracle vector can ever exist to
confirm it against (see `docs/DECISIONS.md` D-68). See `docs/SECURITY.md` for the full threat model and hard
constraints, and the Status paragraph below for what's actually done.

An open Rust library for modern Ukrainian cryptographic standards (DSTU) — in the
spirit of **libsodium** (hard, safe defaults, hard to misuse), not OpenSSL
(flexible, easy to misuse the API).

**Status:** all three in-scope DSTU primitives are implemented at `hazmat` — Kupyna (256/512,
cross-checked against real Bouncy Castle), Kalyna (all 5 block/key-size variants, full DSTU 7624
mode-of-operation coverage: ECB/CBC/CFB/OFB/CTR/CMAC/KW/CCM/GCM/GMAC/XTS), and Strumok (keystream
generation, `docs/DECISIONS.md` D-15 — UAPKI-attributed vectors, not yet primary-text-confirmed).
`hazmat::kalyna_ccm`/`kalyna_gcm` and Strumok remain **provisional** in that same sense (dual-oracle
but not primary-DSTU-text-confirmed, `docs/DECISIONS.md` D-15/D-41/D-56). DSTU 4145 signatures
(`hazmat::dstu4145`) are also implemented and vector-confirmed. On top of `hazmat`, the
libsodium-shaped `crypto_*` layer (`crypto_secretbox`, `crypto_secretstream`, `crypto_sign`,
`crypto_auth`, `crypto_kdf`, `crypto_generichash`, `crypto_stream`, `crypto_pwhash`, `randombytes`)
and the `uacrypt` CLI (`keygen`/`encrypt`/`decrypt`/`hash`, `sign-keygen`/`sign-pubkey`/`sign`/
`verify`, plus `--help`/`--version`) are built and tested — see "Using `uacrypt`" below. DSTU 9041
is hard-blocked (no source material). See
`docs/TASKS.md` for the phase-by-phase backlog, `docs/dstu-crypto-project.md`'s "Concrete API shape" for
the authoritative module-by-module status table, and `docs/release-readiness.md` for the gap
analysis against a complete 1.0.

## Algorithms in scope

| Algorithm | Standard | Type |
|---|---|---|
| Kalyna | DSTU 7624:2014 | symmetric block cipher |
| Kupyna | DSTU 7564:2014 | hash function |
| Strumok | DSTU 8845:2019 | stream cipher |
| — | DSTU 4145-2002 | digital signature on elliptic curves |
| — | DSTU 9041:2020 | asymmetric encryption (twisted Edwards curves) |

Full MVP scope, architectural decisions, and the libsodium API mapping are in
`docs/dstu-crypto-project.md`.

`dstu-core` builds in two resource profiles - fast/table-heavy (default) or small/flash-friendly
(`--features dstu-core/small-tables`, for constrained MCUs). Same output either way, real memory
vs. speed trade-off - see `docs/resource-profiles.md` for the numbers and which one fits your
target.

## Repository structure

```
.
├── CLAUDE.md              # operating guide for AI agents in this repo
├── docs/SECURITY.md            # threat model, hard constraints, supply-chain vetting
├── docs/DECISIONS.md           # architectural decisions with rejected alternatives
├── docs/TASKS.md               # phase-by-phase task backlog and progress state
├── docs/CHANGELOG.md           # Keep a Changelog-format release history
├── docs/ORACLES.md             # oracle trust ranking, per-algorithm oracle map, test-vector provenance
├── docs/PERFORMANCE.md         # benchmark methodology and recorded numbers
├── docs/CONTRIBUTING.md        # how to propose a change, test/verification bar, commit style
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
│   ├── pseudocode/                   # per-algorithm pseudocode, cross-checked against oracles
│   ├── rust_ai_ruleset.md            # generic Rust ruleset for AI assistants
│   ├── cross-language-style-guide.md # naming/style conventions for non-Rust code
│   └── papers/                       # reference PDFs (specs, cryptanalysis, hardware papers)
├── crates/                # Cargo workspace
│   ├── dstu-core/          # core: Kalyna + Kupyna + Strumok
│   └── uacrypt/            # CLI binary on top of the core
├── tests/oracle-harness/   # Java/.NET/C harnesses that verify test vectors against real Bouncy Castle
└── oracles/                # reference implementations used as oracles - not vendored, see oracles/README.md
```

## Requirements

Rust is the only hard requirement — everything else in this table is optional and only needed for
the specific `cargo xtask` command listed. No admin rights required on any platform for any of it.

| Tool | Needed for | Linux / macOS | Windows |
|---|---|---|---|
| Rust (stable, via `rustup`) | everything | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `winget install Rustlang.Rustup` (or `rustup-init.exe` from [rustup.rs](https://rustup.rs)) |
| C/C++ compiler | `cargo xtask fuzz` (`libfuzzer-sys` builds C++); building the manual C oracle-differential harnesses under `tests/oracle-harness/*-differential/` | usually preinstalled; else your distro's `gcc`/`build-essential` package | MinGW-w64 GCC (e.g. `winget install BrechtSanders.WinLibs.POSIX.UCRT`) builds the crate and those harnesses; **`cargo xtask fuzz` additionally needs real MSVC**, see below |
| `cargo-fuzz` | `cargo xtask fuzz` | `cargo install cargo-fuzz --locked` — runs directly against the native nightly toolchain | see "`cargo fuzz` on Windows" below |
| `miri` (nightly component) | `cargo xtask miri` | `rustup component add miri --toolchain nightly` | same |
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

## Building from source

```
git clone <this repo>
cd cipher_ua
cargo build --workspace
cargo test --workspace
```

## Development commands

`cargo xtask <command>` is the one cross-platform entry point for build/test/QA — the same command
on Linux, Windows, and macOS (see `docs/DECISIONS.md` D-12 for why this exists instead of separate
shell/PowerShell scripts). Run `cargo xtask help` for the full list; the essentials:

```
cargo xtask build     # cargo build --workspace, both --all-features and no_std (--no-default-features)
cargo xtask test      # cargo test --workspace --all-features
cargo xtask fmt       # cargo fmt --all (add --check to verify without writing)
cargo xtask clippy    # cargo clippy --workspace --all-features -- -D warnings
cargo xtask ci        # the four above, then best-effort for miri/fuzz/audit/deny/oracle harnesses
```

The optional layers each check their own tool is installed first and print an install hint instead
of a raw error if it's missing (`cargo xtask miri`, `fuzz`, `audit`, `deny`, `oracle-java`,
`oracle-dotnet`) — see `docs/SECURITY.md` for why these are required in CI even though they're optional
locally.

Before implementing any primitive, read `docs/SECURITY.md` (hard constraints, mandatory
dual-oracle verification) and `docs/DECISIONS.md` (architectural decisions already made).

## Performance

`cargo bench -p dstu-core --bench kalyna --bench kupyna --bench strumok` (`criterion`). See
`docs/PERFORMANCE.md` for recorded baseline numbers, a comparison against the algorithm designers'
reference C implementation and against UAPKI (a real, production PKI library), and how to check a
change against the saved regression baseline.

## Using `uacrypt`

`uacrypt encrypt`/`decrypt`/`hash` (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52) are the real,
misuse-resistant top-level commands — mode, nonce, and algorithm are all hardcoded, nothing to
misconfigure:

```
cargo build -p uacrypt --release
uacrypt keygen --out key.bin
uacrypt encrypt --key key.bin --in message.bin --out sealed.bin
uacrypt decrypt --key key.bin --in sealed.bin --out message.bin
uacrypt hash --in file.bin --out digest.bin
```

**`encrypt`/`decrypt` have no message-length cap and stream `--in`/`--out` in fixed-size chunks** —
as of 2026-07-25 they're built over `dstu_core::crypto_secretstream` (`docs/TASKS.md` T-40/T-70,
`docs/DECISIONS.md` D-68), a genuinely chunked construction over `hazmat::kalyna_gcm`, not the earlier
whole-buffer `crypto_secretbox` (`docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51/D-63) - a large input file no
longer means a correspondingly large in-memory buffer. **Breaking wire-format change**: a file the
prior `crypto_secretbox`-backed `encrypt` produced cannot be read by this `decrypt`, and vice versa
- acceptable pre-1.0. `crypto_secretbox` itself is unchanged and still available as a library
primitive for whole-message use, just no longer what this CLI command uses. `--key` is a raw
32-byte file (`crypto_secretstream::Key`'s size) — `uacrypt keygen --out key.bin` generates one from
the OS CSPRNG (`docs/TASKS.md` T-115). `encrypt` draws a fresh random header internally on every call
and embeds it in `--out`; there is no `--nonce`/`--header` flag to supply or reuse by mistake.
**`hash` has no such limit either** — it streams `--in` from disk in fixed-size chunks regardless of
size, fixed to Kupyna-256 (32-byte digest, no `--variant` choice).

`uacrypt sign-keygen`/`sign-pubkey`/`sign`/`verify` (`docs/TASKS.md` T-124, `docs/DECISIONS.md` D-73) are the
digital-signature equivalent, built over `dstu_core::crypto_sign` (DSTU 4145): a signature proves a
file came from whoever holds the signing key and hasn't been changed since — unlike `encrypt`, it
does not hide the file's contents, only attests to who signed it and that it's unmodified. Every
command below was run for real against the release binary before being written here:

```
uacrypt sign-keygen --out signing.key
uacrypt sign-pubkey --key signing.key --out verifying.key
uacrypt sign --key signing.key --in message.bin --out message.bin.sig
uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
```

`sign-keygen`'s output (`signing.key`, 21 raw bytes) is secret — keep it like any other private key.
`sign-pubkey` derives the matching `verifying.key` (42 raw bytes) from it, safe to share or publish.
`verify` prints nothing and exits `0` on a valid signature; on a tampered file, a tampered signature,
or the wrong verifying key, it exits `1` with an error and writes nothing — it does not, and cannot,
silently accept a mismatch:

```
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
$ echo $?
0

$ echo "tampered" > message.bin
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
uacrypt: verify: signature does not verify - message, signature, or key do not match
$ echo $?
1
```

What exists below this level: `kalyna-block`, a single-block (no mode, no padding), `hazmat`-scoped
command added for a binary-level performance comparison (`docs/PERFORMANCE.md`, `docs/DECISIONS.md` D-31):

```
uacrypt kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out ct.bin
uacrypt kalyna-block decrypt --variant 128-128 --key key.bin --in ct.bin --out pt.bin
```

`--key`/`--in`/`--out` are raw binary files of the variant's exact byte length (16/32/64 bytes
depending on variant — see `--variant`'s five values).

`kalyna-ccm` (`docs/DECISIONS.md` D-41) additionally encrypts/authenticates arbitrary-length **short**
messages (plaintext and `--aad` each capped at 255 bytes — a sourced property of the construction,
not a CLI restriction, see `hazmat::kalyna_ccm`'s doc comment) using a provisional, dual-oracle-
verified Kalyna-alone CCM mode, not yet confirmed against the primary DSTU 7624:2014 text:

```
uacrypt kalyna-ccm encrypt --variant 128-128 --key key.bin --nonce nonce.bin --aad aad.bin --in msg.bin --out ct.bin --tag tag.bin
uacrypt kalyna-ccm decrypt --variant 128-128 --key key.bin --nonce nonce.bin --aad aad.bin --in ct.bin --out pt.bin --tag tag.bin
```

`--nonce` is a raw file of exactly the variant's block length (16/32/64 bytes) — but it's an
**output** on `encrypt`, not an input: `encrypt` generates a fresh random nonce itself (via the OS
CSPRNG) and writes it there, so there is nothing for you to supply or accidentally reuse. `decrypt`
reads `--nonce` back (the value `encrypt` produced) as an input, same as `--tag`. `--aad` is
optional (an empty AAD is used if omitted); `decrypt` verifies the tag before writing `--out` and
fails without writing anything on a mismatch. See `docs/DECISIONS.md` D-40 for why a random nonce is
safe here (128 bits minimum across all five variants) and its per-key message-count guideline.

Neither `kalyna-block` nor `kalyna-ccm` is the `encrypt`/`decrypt` surface above - both stay as
lower-level, hazmat-scoped tools (`kalyna-block` for exactly one block, `kalyna-ccm` for full
control over variant/nonce/AAD/tag as separate files) for anyone who explicitly wants that.
**Prebuilt binaries are available via [GitHub Releases](https://github.com/user137/uacrypt/releases)**
for Windows/Linux/macOS (Apple Silicon), plus a `dstu-core` source distribution - not published to
crates.io yet (`docs/TASKS.md` T-17).

## Embedded / `no_std` targets

`dstu-core` is `no_std`-compatible from day one (`cargo build --no-default-features`, checked by
`cargo xtask build` and in CI on every push, but only against the **host** triple). **Cross-compiling
for a real embedded target is separately confirmed** (`docs/TASKS.md` T-116, 2026-07-26): all 4
`no_std`/`alloc`/`small-tables` combinations build clean, both dev and release profiles, for
`thumbv7em-none-eabihf` (STM32 Cortex-M) and `riscv32imc-unknown-none-elf` (ESP32-C3-class
RISC-V) via plain `rustup target add` — no custom toolchain needed for either. This means it
*compiles* for real microcontroller targets — it is **not** a claim that it has been validated on
real hardware, and specifically **not** a claim of resistance to hardware side-channel attacks
(SPA/DPA), which would
need a separate, dedicated hardware audit. Real-hardware validation is a distinct post-MVP phase.

## Contributing

Pull requests are welcome. See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the test/
verification bar (dual-oracle verification, the three test categories per primitive, commit style)
and [`docs/CODE_OF_CONDUCT.md`](docs/CODE_OF_CONDUCT.md) for community standards. Security
vulnerabilities go through GitHub Security Advisories, not a public issue — see
`docs/SECURITY.md` "Reporting vulnerabilities".

## License

Dual-licensed under MIT / Apache-2.0, at the user's choice — the standard for the
Rust ecosystem. See `LICENSE-MIT` and `LICENSE-APACHE`.
