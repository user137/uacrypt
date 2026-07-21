# DECISIONS.md

Architectural decisions with rejected alternatives and the reason for rejection. Add an entry at
the moment a decision is made, not retroactively.

## D-01: Core is `no_std`-compatible from day one

Feature flags `std` / `alloc` / `no_std` from the first commit.

**Rejected:** `std`-only core with embedded support bolted on later. Rejected because STM32
(Cortex-M) and ESP32 (Xtensa/RISC-V) are genuinely different architectures, not variants of one —
retrofitting `no_std` after the API has hardened would mean a core rewrite, not an addition.

## D-02: DSTU 4145 signatures — wrap, don't reimplement, for Java/.NET

Java/.NET bindings wrap Bouncy Castle's `DSTU4145Signer`. The Rust implementation, when built, uses
Bouncy Castle as a second verification oracle alongside official test vectors.

**Rejected:** reimplementing DSTU 4145 from scratch in the native core for all languages. Rejected
because Bouncy Castle's implementation has decades of production use and continuous external
audit — duplicating that from scratch buys nothing and adds unaudited surface area.

## D-03: Argon2id stays as the non-DSTU password-hashing component

`crypto_pwhash` equivalent is plain Argon2id, documented explicitly as the one deliberately
non-DSTU component.

**Rejected:** inventing a "national" password-hashing/KDF-from-password construction. Rejected
because no DSTU standard covers this, and Argon2 is the audited winner of an open international
competition (Password Hashing Competition) — there is no security rationale to displace it, only
a cosmetic one.

## D-04: CSPRNG is the OS-provided generator, not a custom design

`randombytes` equivalent uses the system CSPRNG (`getrandom` in Rust), same as libsodium itself.

**Rejected:** a custom or "national" random number generator. Rejected because RNG design is the
single highest-risk area for homegrown cryptography — no benefit justifies the risk here.

## D-05: `secretbox` equivalent is Kalyna encryption + separate Kupyna-based MAC (encrypt-then-MAC)

Symmetric AEAD is built as: Kalyna in a stream-like mode (CTR/OFB-style) for confidentiality, plus
an independent MAC keyed from Kupyna, encrypt-then-MAC, with distinct encryption and
authentication keys.

**Rejected:** treating Kalyna alone as an AEAD primitive (à la AES-GCM). Rejected because the DSTU
7624 text itself specifies that confidentiality + integrity requires combining with DSTU 7564
(Kupyna) on separate keys — there is no single-primitive AEAD in the standard to call instead. See
`docs/dstu-crypto-project.md` libsodium-mapping section.

**Not yet reconciled:** PrivatBank's cryptonite (`oracles/cryptonite/src/cryptonite/c/dstu7624.h`)
exposes `dstu7624_init_ccm` / `dstu7624_init_gcm` with a paired `dstu7624_encrypt_mac` /
`dstu7624_decrypt_mac` API — Kalyna alone, in CCM/GCM-style modes, producing authenticated
ciphertext without Kupyna. This is in tension with the rejection above and needs checking against
the actual DSTU 7624 standard text (not currently among `docs/papers/`) before this decision is
finalized either way — see `oracles/README.md` "Cryptonite" section for the full note. Do not
resolve this from cryptonite's code alone; it's a 2016 third-party implementation, not the spec.

## D-06: Reference/oracle repositories are for test-vector comparison only

Kalyna-reference, cryptonite, outspace/dstu8845 are consulted only to cross-verify test vectors,
never as a source to copy code from directly.

**Rejected:** forking/porting code directly from these repos as a shortcut. Rejected on a
per-repo basis: Kalyna-reference has no LICENSE file at all (no legal basis to copy); cryptonite is
BSD-2-Clause (legally forkable) but is 2016-era code whose state certification lapsed in 2021 and
has had no independent audit since — copying it would import unaudited, stale code under the
project's own name. See `docs/dstu-crypto-project.md` "Reference implementations and oracles".

## D-07: The `li0ard` GitHub account is excluded entirely — untrusted supply chain

`li0ard`'s TypeScript/Go packages for Kalyna/Kupyna/Strumok/DSTU 4145 are not used as a
dependency, not used as an oracle, and not linked from any project documentation. This is
stricter than D-06: other unaudited repos there are at least allowed as oracles; `li0ard` is
excluded from that category too.

**Rejected:** treating `li0ard`'s packages as one more unaudited-but-usable oracle, the same
tier as `outspace/dstu8845`. Rejected per the project owner's explicit call: unverified maintainer
identity and provenance, flagged as a potential compromise/trust risk. For a library implementing
Ukrainian national cryptographic standards, code or oracle input from a maintainer whose identity
and origin cannot be verified — and who is suspected of ties to a hostile state — is not an
acceptable risk regardless of the code's apparent quality or activity level. If this needs
revisiting later, it requires a new, independently verifiable trust basis, not just an audit of
the code itself.

## Open question: no_std vs. safe high-level API default randomness

Not yet decided. Precedent (orion): in a `no_std` build, orion's high-level "hard to misuse"
API is unavailable because it depends on `OsRng`, which doesn't exist in `no_std` — only its
low-level `hazardous` module works there. This directly tensions with D-01 (`no_std`-first) and
the project's own libsodium-style "safe defaults" goal (see `docs/dstu-crypto-project.md`): on
embedded targets, either the safe high-level API needs an injected RNG source, or it's simply
unavailable and only the low-level API ships. Resolve before the high-level API is designed.
