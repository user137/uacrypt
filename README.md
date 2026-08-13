# uacrypt

[![crates.io](https://img.shields.io/crates/v/dstu-core.svg)](https://crates.io/crates/dstu-core)
[![docs.rs](https://docs.rs/dstu-core/badge.svg)](https://docs.rs/dstu-core)
[![PyPI](https://img.shields.io/pypi/v/dstu-core.svg)](https://pypi.org/project/dstu-core/)
[![npm](https://img.shields.io/npm/v/dstu-core.svg)](https://www.npmjs.com/package/dstu-core)
[![CI](https://github.com/user137/uacrypt/actions/workflows/rust.yml/badge.svg)](https://github.com/user137/uacrypt/actions/workflows/rust.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

A Rust implementation of Ukrainian DSTU cryptographic standards — Kalyna (block cipher), Kupyna
(hash), Strumok (stream cipher), DSTU 4145 (digital signatures), and DSTU 9041 (asymmetric
encryption) — in the spirit of **libsodium**: hard, safe defaults, hard to misuse, rather than
OpenSSL's flexible-but-easy-to-misconfigure API. Ships as a Rust crate (`dstu-core`), a CLI
(`uacrypt`), and bindings for eight languages.

<!-- uacrypt-version: 0.3.8 -->
**Pre-1.0. Not audited. Not a claim of side-channel resistance.** `dstu-core`/`uacrypt` are on
[crates.io](https://crates.io/crates/dstu-core); the Python and Node.js bindings are on
[PyPI](https://pypi.org/project/dstu-core/)/[npm](https://www.npmjs.com/package/dstu-core) too. See
`docs/CHANGELOG.md` for what changed each release and `docs/release-readiness.md` for the gap
analysis against a complete 1.0.

## Algorithms in scope

| Algorithm | Standard | Type |
|---|---|---|
| Kalyna | DSTU 7624:2014 | symmetric block cipher |
| Kupyna | DSTU 7564:2014 | hash function |
| Strumok | DSTU 8845:2019 | stream cipher |
| — | DSTU 4145-2002 | digital signature on elliptic curves |
| — | DSTU 9041:2020 | asymmetric encryption (twisted Edwards curves) |

Full scope, architectural decisions, and the libsodium API mapping are in
`docs/dstu-crypto-project.md`. `dstu-core` also builds in a small/flash-friendly resource profile
for constrained MCUs (`--features small-tables`) — see `docs/resource-profiles.md` for the trade-off.

## Quick start

```sh
cargo add dstu-core
```

```rust
use dstu_core::crypto_secretbox::{seal, open, SecretKey};

let key = SecretKey::generate().expect("OS CSPRNG should not fail");
let sealed = seal(&key, b"message").expect("OS CSPRNG should not fail");
let opened = open(&key, &sealed).expect("authentic ciphertext");
assert_eq!(opened, b"message");
```

Or the CLI, which streams arbitrarily large files with no in-memory cap:

```sh
cargo install uacrypt   # or download a prebuilt binary from GitHub Releases
uacrypt keygen --out key.bin
uacrypt encrypt --key key.bin --in message.bin --out sealed.bin
uacrypt decrypt --key key.bin --in sealed.bin --out message.bin
```

See [`docs/CLI.md`](https://github.com/user137/uacrypt/blob/master/docs/CLI.md) for the full
command reference (`sign`/`verify`, `box-seal`/`box-open`, and the lower-level `kalyna-block`/
`kalyna-ccm` tools), and [docs.rs](https://docs.rs/dstu-core) for the full library API.

## Language bindings

The full `crypto_*` surface (`secretbox`/`secretstream`/`sign`/`auth`/`kdf`/`generichash`/`stream`/
`pwhash`, `randombytes`, `selftest`), idiomatic errors, and the same correctness/rejection/misuse
test suite, in every language below — not a thin, partial wrapper. The **README column** is the
full per-language docs; the **Package column** is where you'd actually run an install command.

| Language | Approach | README | Package |
|---|---|---|---|
| Python | PyO3, direct Rust binding | [`bindings/python`](https://github.com/user137/uacrypt/blob/master/bindings/python/README.md) | [PyPI](https://pypi.org/project/dstu-core/) |
| Node.js | napi-rs, direct Rust binding | [`bindings/nodejs`](https://github.com/user137/uacrypt/blob/master/bindings/nodejs/README.md) | [npm](https://www.npmjs.com/package/dstu-core) |
| Ruby | magnus/rb-sys, direct Rust binding | [`bindings/ruby`](https://github.com/user137/uacrypt/blob/master/bindings/ruby/README.md) | not yet published |
| PHP | ext-php-rs, direct Rust binding | [`bindings/php`](https://github.com/user137/uacrypt/blob/master/bindings/php/README.md) | not yet published |
| .NET (C#) | P/Invoke over the C ABI | [`bindings/dotnet`](https://github.com/user137/uacrypt/blob/master/bindings/dotnet/README.md) | not yet published |
| Java | `jni` crate, direct Rust binding | [`bindings/java`](https://github.com/user137/uacrypt/blob/master/bindings/java/README.md) | not yet published |
| Go | `cgo` over the C ABI | [`bindings/go`](https://github.com/user137/uacrypt/blob/master/bindings/go/README.md) | not yet published |
| C++ | header-only RAII wrapper over the C ABI | [`bindings/cpp`](https://github.com/user137/uacrypt/blob/master/bindings/cpp/README.md) | not yet published |

The C ABI itself (`crates/dstu-core-capi`, opaque handles, `cbindgen`-generated header) is what the
.NET, Go, and C++ bindings link against directly — usable from any language with a C FFI, not just
those three. See `docs/bindings-strategy.md` for the per-binding design rationale.

## Embedded / `no_std` targets

`dstu-core` is `no_std`-compatible from day one (`std`/`alloc`/`no_std` feature flags), and
cross-compiles clean for real microcontroller targets (STM32 Cortex-M, ESP32-class RISC-V) with no
custom toolchain. That's a compilation claim, not a real-hardware validation or a side-channel
resistance claim — see `docs/SECURITY.md` for the full threat model.

## Status and further reading

- [`docs/SECURITY.md`](https://github.com/user137/uacrypt/blob/master/docs/SECURITY.md) — threat model and hard constraints
- [`docs/DECISIONS.md`](https://github.com/user137/uacrypt/blob/master/docs/DECISIONS.md) — architectural decisions, with rejected alternatives
- [`docs/TASKS.md`](https://github.com/user137/uacrypt/blob/master/docs/TASKS.md) — phase-by-phase task backlog
- [`docs/release-readiness.md`](https://github.com/user137/uacrypt/blob/master/docs/release-readiness.md) — gap analysis against a libsodium-equivalent 1.0
- Full knowledge base: [user137.github.io/uacrypt](https://user137.github.io/uacrypt/)

## Contributing

Pull requests are welcome. See [`docs/CONTRIBUTING.md`](https://github.com/user137/uacrypt/blob/master/docs/CONTRIBUTING.md)
for dev environment setup, the test/verification bar (dual-oracle verification, three test
categories per primitive), and commit style, and
[`docs/CODE_OF_CONDUCT.md`](https://github.com/user137/uacrypt/blob/master/docs/CODE_OF_CONDUCT.md)
for community standards. Security vulnerabilities go through GitHub Security Advisories, not a
public issue — see `docs/SECURITY.md` "Reporting vulnerabilities".

## License

Dual-licensed under MIT / Apache-2.0, at the user's choice — the standard for the
Rust ecosystem. See `LICENSE-MIT` and `LICENSE-APACHE`.
