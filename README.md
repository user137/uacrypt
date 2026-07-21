# dstu-crypto (working name)

An open Rust library for modern Ukrainian cryptographic standards (DSTU) — in the
spirit of **libsodium** (hard, safe defaults, hard to misuse), not OpenSSL
(flexible, easy to misuse the API).

**Status: early planning stage.** The core hasn't been written yet — see `crates/`
for the current (empty) workspace skeleton and `docs/dstu-crypto-project.md` for
the full scope.

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
├── LICENSE-MIT
├── LICENSE-APACHE
├── docs/
│   ├── dstu-crypto-project.md        # main project spec (scope, API mapping)
│   ├── rust_ai_ruleset.md            # generic Rust ruleset for AI assistants
│   ├── rust-crypto-claude-advice.md  # source advice, distributed into CLAUDE/SECURITY/DECISIONS
│   └── papers/                       # reference PDFs (specs, cryptanalysis, hardware papers)
└── crates/                # Cargo workspace
    ├── dstu-core/          # core: Kalyna + Kupyna + Strumok
    └── dstutool/           # CLI binary on top of the core
```

## Development

The workspace is still empty (a build skeleton with no real primitives yet). Once
the core exists:

```
cargo build --workspace
cargo test --workspace
```

Before implementing any primitive, read `SECURITY.md` (hard constraints, mandatory
dual-oracle verification) and `DECISIONS.md` (architectural decisions already made).

## License

Dual-licensed under MIT / Apache-2.0, at the user's choice — the standard for the
Rust ecosystem. See `LICENSE-MIT` and `LICENSE-APACHE`.
