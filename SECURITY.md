# SECURITY.md

Threat model, hard constraints, and dependency vetting for this project. Applies from the first
line of core code — not a post-MVP addendum.

## Threat model

In scope:
- Attacker who can observe ciphertext/signatures/hashes produced by correct use of the API
  (standard cryptanalytic attacker).
- Attacker who can supply malformed/adversarial input to parsers (DER/ASN.1-like structures,
  message framing) — must not panic, must not read out of bounds.
- Attacker who can time software-level operations (timing side channels in constant-time-sensitive
  code paths: comparisons, branching/indexing on secret data).

Explicitly out of scope (until stated otherwise):
- **Hardware side-channel attacks (SPA/DPA, power/EM analysis).** Software constant-time
  discipline (see below) reduces exposure but is not equivalent to and must never be marketed as
  side-channel resistance. That requires a dedicated, separate hardware audit; see
  `docs/dstu-crypto-project.md` MVP scope. Real-hardware (STM32/ESP32) validation is a distinct
  post-MVP phase.
- Formal state certification by Держспецзв'язку — voluntary category for an open GitHub library;
  see `docs/dstu-crypto-project.md` "State certification".

## Hard constraints (non-negotiable, apply to every primitive)

- No primitive is implemented without citing the specific spec section (DSTU text, page/clause,
  or the author's reference-implementation source) it was verified against. Record the citation
  in `DECISIONS.md`.
- No secret-dependent branching or array indexing.
- All comparisons involving secret data use `subtle::ConstantTimeEq`, never `==`.
- All key-material types implement `Zeroize` / `ZeroizeOnDrop`.
- No secret material (keys, nonces derived from secrets, plaintexts) in logs, panics, or error
  messages.
- No homegrown cryptographic primitives invented from scratch. Where DSTU leaves a gap (pwhash,
  CSPRNG — see `docs/dstu-crypto-project.md` libsodium mapping section), use the established
  international primitive (Argon2id, OS CSPRNG via `getrandom`), never a "national" substitute
  invented for the sake of it.
- **Dual-oracle verification is mandatory.** Every primitive must pass both: (1) official DSTU
  test vectors, and (2) cross-check against an independent reference implementation (see
  `docs/dstu-crypto-project.md` "Reference implementations and oracles" — Kalyna-reference, cryptonite,
  Bouncy Castle for DSTU 4145). Self-consistent unit tests passing is not sufficient evidence of
  correctness for security-critical code.
- `cargo miri test` is a required CI layer (UB detection), not optional tooling.
- `cargo fuzz` is required for every parser of untrusted input bytes, not optional.
- `unsafe` code is isolated to the smallest possible module with a safe wrapper, and every
  `unsafe fn`/block carries a `// SAFETY: ...` comment stating the invariant that makes it sound.

## Supply-chain vetting (apply before adding any crypto-adjacent dependency)

| Crate | Maintainer/developer | Reproducible builds | Independent audit | CVE history |
|---|---|---|---|---|
| _(fill in per dependency before merging)_ | | | | |

## Reporting vulnerabilities

Private disclosure only — GitHub Security Advisories. Never a public issue.
