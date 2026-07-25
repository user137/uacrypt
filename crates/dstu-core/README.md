# dstu-core

Rust implementations of Ukrainian DSTU cryptographic standards — Kalyna (DSTU 7624:2014, block
cipher), Kupyna (DSTU 7564:2014, hash), and Strumok (DSTU 8845:2019, stream cipher) — in the
spirit of **libsodium** (hard, safe defaults, hard to misuse) rather than OpenSSL.

**v0.1.0 — pre-release / work in progress.** Not audited, not a claim of side-channel resistance.
Kalyna and Kupyna are dual-oracle-verified against official test vectors; Strumok and every Kalyna
mode of operation are provisional — not yet confirmed against their primary standard text (see
`DECISIONS.md`/`SECURITY.md` in the project repository, not shipped in this package, for the full
citation trail and threat model). `crypto_secretstream`/`crypto_kdf` have no oracle vector at all
and never will, since no DSTU standard defines an equivalent construction — verified by property,
tamper, and misuse tests instead.

## Two layers

- **`dstu_core::hazmat::*`** — direct algorithm implementations. No forced RNG dependency, no
  auto-generated nonces; the caller passes keys/nonces/IVs explicitly. `no_std`-compatible.
  Covers Kalyna (all 5 block/key-size variants) and its 10 DSTU 7624 modes of operation
  (ECB/CBC/OFB/CFB/CTR/CMAC/KW/GCM/GMAC/XTS), Kupyna (256/512, one-shot and streaming), Kupyna-KMAC
  and Kupyna-KDF, Strumok (256/512-bit key), and DSTU 4145 (m=163 curve only).
- **`dstu_core::crypto_*`** — libsodium-style ergonomic wrappers over `hazmat`: auto-generated
  nonces where the construction needs one, misuse-resistant defaults, a single safe variant per
  primitive instead of every knob `hazmat` exposes. Covers `crypto_secretbox`, `crypto_secretstream`,
  `crypto_sign`, `crypto_stream`, `crypto_auth`, `crypto_kdf`, `crypto_generichash`, and
  `crypto_pwhash` (Argon2id, not DSTU).

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `std` | on | Enables `getrandom`-backed key/nonce generation and any module needing `Vec`/`String` (`crypto_secretbox`, `crypto_secretstream`, `crypto_stream`). |
| `alloc` | off | Placeholder for `alloc`-only (no `std`) builds — not yet load-bearing for any code path. |
| `small-tables` | off | Swaps the fused S-box+MDS lookup tables (~86 KB) for a smaller `gf_mul`-based path (~6 KB), for flash-constrained microcontroller targets. Real memory/speed trade-off, same output. Combines with any of the above. |
| `pwhash` | off | Enables `crypto_pwhash` (Argon2id via the `argon2` crate). Off by default — most targets have no use for a password-hashing KDF and its heavier dependency surface. |

`cargo build --no-default-features` builds a bare `no_std` core with no allocator dependency at
all — this crate targets both full OSes (Windows/Linux/macOS) and bare-metal microcontrollers from
the same codebase, no CPU-family or OS lock-in by design.

## Example

```rust
use dstu_core::crypto_secretbox::{seal, open, SecretKey};

// std-gated, draws from the OS CSPRNG - both this and seal/open return Result (each can fail on
// an OS CSPRNG error; open also fails on a wrong key or tampered input).
let key = SecretKey::generate().expect("OS CSPRNG should not fail");
let sealed = seal(&key, b"message").expect("OS CSPRNG should not fail");
let opened = open(&key, &sealed).expect("authentic ciphertext");
assert_eq!(opened, b"message");
```

For streaming/large-message encryption, see `dstu_core::crypto_secretstream` instead — it processes
data in bounded chunks rather than holding the whole message in memory.

## Status and safety

This is pre-1.0, unaudited software. See the project repository's `SECURITY.md` for the full
threat model and hard constraints, `DECISIONS.md` for every architectural decision with its
citation, and `TASKS.md` for what is and isn't done yet. No claim of hardware side-channel
(SPA/DPA) resistance is made or implied anywhere in this crate.

## License

Dual-licensed under MIT / Apache-2.0, at your choice. See `LICENSE-MIT` and `LICENSE-APACHE` in
the project repository.
