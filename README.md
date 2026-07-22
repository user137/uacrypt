# dstu-crypto (working name)

An open Rust library for modern Ukrainian cryptographic standards (DSTU) — in the
spirit of **libsodium** (hard, safe defaults, hard to misuse), not OpenSSL
(flexible, easy to misuse the API).

**Status:** two primitives landed — `dstu_core::hazmat::kupyna` (Kupyna-256/512, cross-checked
against real Bouncy Castle) and `dstu_core::hazmat::kalyna` (all 5 block/key-size variants,
single-block encrypt/decrypt, no mode of operation yet), both tested against official DSTU test
vectors. Everything else in the table below is still to come. See `TASKS.md` for the phase-by-phase
backlog and `docs/dstu-crypto-project.md` for the full scope.

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

## Repository structure

```
.
├── CLAUDE.md              # operating guide for AI agents in this repo
├── SECURITY.md            # threat model, hard constraints, supply-chain vetting
├── DECISIONS.md           # architectural decisions with rejected alternatives
├── TASKS.md               # phase-by-phase task backlog and progress state
├── LICENSE-MIT
├── LICENSE-APACHE
├── .cargo/config.toml     # `cargo xtask` alias
├── xtask/                 # cross-platform build/QA runner, see "Development commands" below
├── docs/
│   ├── dstu-crypto-project.md        # main project spec (scope, API mapping)
│   ├── pseudocode/                   # per-algorithm pseudocode, cross-checked against oracles
│   ├── rust_ai_ruleset.md            # generic Rust ruleset for AI assistants
│   ├── cross-language-style-guide.md # naming/style conventions for non-Rust code
│   └── papers/                       # reference PDFs (specs, cryptanalysis, hardware papers)
├── crates/                # Cargo workspace
│   ├── dstu-core/          # core: Kalyna + Kupyna + Strumok
│   └── dstutool/           # CLI binary on top of the core
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
flags are passed (`DECISIONS.md` D-32 has the full diagnosis). To run `cargo xtask fuzz` locally on
Windows:

1. Install Visual Studio (or just the Build Tools) with the "Desktop development with C++"
   workload.
2. `rustup toolchain install nightly-x86_64-pc-windows-msvc` — an *additional* toolchain; this does
   not change the project's default GNU host toolchain used for everything else.
3. Run `cargo xtask fuzz`. It finds the Visual Studio install itself (via `vswhere.exe`'s fixed
   path) and the toolchain above, then runs each target through a `vcvars64.bat`-sourced shell with
   `--target x86_64-pc-windows-msvc` — both the environment and the explicit target flag are
   required, not just the extra toolchain (`DECISIONS.md` D-32 explains why: without `vcvars64.bat`
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
on Linux, Windows, and macOS (see `DECISIONS.md` D-12 for why this exists instead of separate
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
`oracle-dotnet`) — see `SECURITY.md` for why these are required in CI even though they're optional
locally.

Before implementing any primitive, read `SECURITY.md` (hard constraints, mandatory
dual-oracle verification) and `DECISIONS.md` (architectural decisions already made).

## Performance

`cargo bench -p dstu-core --bench kalyna --bench kupyna --bench strumok` (`criterion`). See
`PERFORMANCE.md` for recorded baseline numbers, a comparison against the algorithm designers'
reference C implementation and against UAPKI (a real, production PKI library), and how to check a
change against the saved regression baseline.

## Using `dstutool`

The planned file-level `dstutool encrypt`/`decrypt` (mode of operation over arbitrary-length
files, see `CLAUDE.md` MVP scope) is not available yet — blocked on `DECISIONS.md` D-05 until a
mode of operation is chosen. What exists today is `kalyna-block`, a single-block (no mode, no
padding), `hazmat`-scoped command added for a binary-level performance comparison
(`PERFORMANCE.md`, `DECISIONS.md` D-31):

```
cargo build -p dstutool --release
dstutool kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out ct.bin
dstutool kalyna-block decrypt --variant 128-128 --key key.bin --in ct.bin --out pt.bin
```

`--key`/`--in`/`--out` are raw binary files of the variant's exact byte length (16/32/64 bytes
depending on variant — see `--variant`'s five values). Once the file-plus-mode CLI lands, it will
use the `encrypt`/`decrypt` command names directly; prebuilt binaries via GitHub Releases for
Windows/Linux/macOS (see `CLAUDE.md` MVP scope) are still planned for that point, not this one.

## Embedded / `no_std` targets

`dstu-core` is `no_std`-compatible from day one (`cargo build --no-default-features`, checked by
`cargo xtask build` and in CI on every push). This means it *compiles* for microcontroller targets
(e.g. `rustup target add thumbv7em-none-eabihf` for STM32 Cortex-M, or the relevant Xtensa/RISC-V
target for ESP32) — it is **not** a claim that it has been validated on real hardware, and
specifically **not** a claim of resistance to hardware side-channel attacks (SPA/DPA), which would
need a separate, dedicated hardware audit. Real-hardware validation is a distinct post-MVP phase.

## License

Dual-licensed under MIT / Apache-2.0, at the user's choice — the standard for the
Rust ecosystem. See `LICENSE-MIT` and `LICENSE-APACHE`.
