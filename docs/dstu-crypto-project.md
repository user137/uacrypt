# Open crypto library for Ukrainian DSTU standards

## Idea

An open project (library + CLI application) for modern Ukrainian cryptographic
standards. Goal: any developer or user can show up and get a reference
implementation within a minute, without hassle — in the spirit of
**libsodium** (hard, safe defaults), and **not** in the spirit of OpenSSL
(flexible, easy to misuse the API).

## Algorithms in scope

| Algorithm | Standard | Type |
|---|---|---|
| Kalyna | DSTU 7624:2014 | symmetric block cipher |
| Kupyna | DSTU 7564:2014 | hash function |
| Strumok | DSTU 8845:2019 | stream cipher |
| — | DSTU 4145-2002 | digital signature on elliptic curves |
| — | DSTU 9041:2020 | asymmetric encryption (twisted Edwards curves) |

## MVP (first priority)

- Rust core: Kalyna + Kupyna + Strumok, cross-checked against official DSTU
  test vectors.
- A single CLI binary on top of the core (working name `dstutool`), with
  subcommands like `dstutool encrypt --key ... --in file --out file` — mode,
  nonce/IV, etc. are hardcoded so there's nothing for the user to
  misconfigure.
- Publish the core to crates.io.
- Prebuilt binaries for Windows/Linux via GitHub Releases (not "clone and
  build it yourself").
- Write the core to be **`no_std`-compatible from day one** (Cargo feature
  flags `std` / `alloc` / `no_std`), so support for embedded platforms (STM32
  on ARM Cortex-M, ESP32 on Xtensa/RISC-V — these are different
  architectures, not variations of one) can be added later without rewriting
  the core. Validation on real hardware is a separate post-MVP phase.
  Important caveat: support for compiling to a microcontroller ≠ resistance
  to hardware side-channel attacks (SPA/DPA) — the latter requires a
  separate, more expensive hardware audit, and until such an audit exists,
  this is explicitly not claimed.

## Second priority (not MVP)

- Language bindings: Python, JavaScript, Java, .NET, C++.
- Do not separately reimplement DSTU 4145 in the native core — for
  Java/.NET, integrate/wrap Bouncy Castle (a mature implementation already
  exists there); for Rust, port it while relying on Bouncy Castle as a
  second verification oracle.

## Post-quantum track (explicitly out of scope)

**DSTU 8961:2019 "Skelya" and DSTU 9212:2023 "Vershyna" are deliberately not part of this
project's scope.** Do not implement either, and do not propose implementing either, without a
separate explicit decision from the project owner — see D-08 in `DECISIONS.md`.

What they are, for context if this is ever revisited:

- **DSTU 8961:2019 "Skelya"** — a post-quantum key encapsulation mechanism (KEM) and asymmetric
  encryption scheme on algebraic lattices. Same problem class as CRYSTALS-Kyber or FrodoKEM; a
  Ukrainian variant.
- **DSTU 9212:2023 "Vershyna"** — a post-quantum digital signature scheme on algebraic lattices
  with rejection sampling. The post-quantum counterpart to DSTU 4145.

Why not now:

- Qualitatively different mathematics (polynomial rings, noise sampling, CPA-to-CCA transforms)
  compared to the rest of this project (Kalyna/Kupyna/Strumok/DSTU 4145/DSTU 9041 are all
  classical cryptography).
- Implementation complexity comparable to all five other algorithms combined, with a higher risk
  of silent correctness bugs: constant-time rejection sampling, decryption failure rate,
  sensitivity to the choice of ring parameters.
- Younger and thinner cryptanalysis than internationally vetted PQ schemes — published work
  questions Skelya's "unusual field/ring choice" and probes potential attacks via sub-ring
  structure.
- No vetted Rust implementation of either algorithm exists — would have to be written from zero,
  without the dual-oracle safety net (`ORACLES.md`) the rest of this project relies on.

If this is ever taken up, treat it as a pair (Skelya + Vershyna together, mirroring the classical
4145+9041 pair) as a distinct Phase 3 / post-quantum track, with an explicit documented warning
that its cryptanalysis maturity is lower than this project's classical DSTU primitives.

## Mapping onto the libsodium API (a functional copy built on DSTU)

Goal: cover libsodium's functionality with equivalents built on Ukrainian
algorithms, with a similar API. DSTU 7624 (Kalyna) explicitly requires
combining the cipher with DSTU 7564 (Kupyna) on different keys to get
confidentiality + integrity — that is, AEAD doesn't come "out of the box"
like AES-GCM; it's a custom encrypt-then-MAC construction that has to be
designed, not a ready-made primitive from the standard.

**Direct replacement (a native DSTU counterpart exists):**

- `crypto_generichash` (BLAKE2b) → Kupyna (DSTU 7564).
- `crypto_stream` (XSalsa20) → Strumok (DSTU 8845).
- `crypto_sign` (Ed25519) → DSTU 4145.
- `crypto_box` (X25519 + AEAD) → DSTU 9041:2020 (asymmetric encryption on
  twisted Edwards curves), conceptually the same role — verify the details
  in practice during implementation.

**Needs to be constructed from existing primitives (not a missing algorithm,
a missing API wrapper):**

- `crypto_secretbox` (symmetric AEAD) → Kalyna in an encryption mode
  (CTR/OFB-like) + a separate MAC based on Kupyna, encrypt-then-MAC,
  different keys — exactly as the DSTU 7624 text itself advises. The main
  architectural point of the API: the secretbox equivalent is our own
  construction on top of two standards, not a single primitive.
- `crypto_auth` / `crypto_onetimeauth` (MAC) → HMAC based on Kupyna, or a
  CMAC-like mode of Kalyna itself (the standard has message-authentication
  modes — the exact mode name should be checked against the full DSTU text).
- `crypto_kx` (key exchange) → Diffie-Hellman on the curves from DSTU
  4145/9041. Not a separate standard, but a construction built on an
  already-existing curve.
- `crypto_kdf` (key derivation) → an HKDF-like construction based on Kupyna.
  There's no separate national KDF standard.
- `crypto_secretstream` (streaming authenticated encryption of large files in
  chunks) → a construction on top of Strumok or Kalyna-CTR + authentication
  of each chunk. A matter of API design, not algorithm search.

**Real gaps (DSTU offers nothing):**

- `crypto_pwhash` (Argon2id) — there's no Ukrainian standard for this at
  all. Argon2 is the winner of an open international competition (Password
  Hashing Competition), well audited; there's no security reason to avoid
  it. Decision: keep Argon2 as is, and honestly flag it in the documentation
  as the one non-DSTU component, and why.
- `crypto_shorthash` (SipHash) — a non-critical component, no direct DSTU
  equivalent; can be skipped in the MVP or a truncated Kupyna can be used.
- `randombytes` (CSPRNG) — not a DSTU question at all. Do not invent a
  "national" random number generator — that's the single most dangerous area
  for a homegrown design. Use the OS's system CSPRNG (`getrandom` in Rust),
  same as libsodium itself does.

**Priority summary:** Kalyna + Kupyna + Strumok + DSTU 4145 give the
foundation for secretbox/stream/generichash/sign. DSTU 9041 covers box. The
engineering work that isn't ready-made in any DSTU text — three
constructions (AEAD from Kalyna+Kupyna, KDF from Kupyna, ECDH from the
signature curve) plus the deliberate decision to leave Argon2 and the system
CSPRNG without "Ukrainization".

## Resources found

- **[privat-it/cryptonite](https://github.com/privat-it/cryptonite)** —
  PrivatBank's library. License **BSD-2-Clause** (verified) — a legally
  clean base to fork/port from. Written in C, covers Kalyna, Kupyna, DSTU
  4145 + legacy (GOST 28147, GOST 34.310/311) + Western algorithms for
  compatibility. Has Java/Android JNI bindings. Downside: 2016-era code, the
  state "expert opinion" certification was valid until 2021-11-25 and hasn't
  been publicly renewed, no recent independent audit.
- **[Roman-Oliynykov/Kalyna-reference](https://github.com/Roman-Oliynykov/Kalyna-reference)**
  — a C implementation by the author of the Kalyna standard itself. **In the
  repository — https://github.com/Roman-Oliynykov — this is the repo of the
  algorithms' author: Kalyna, Kupyna, Strumok. It also contains his Kupyna
  implementation and some documentation. There is no LICENSE file** — use
  only as an oracle for cross-checking test vectors, **do not copy the code
  directly**.
- **dstu8845 https://github.com/outspace/dstu8845** — a Strumok
  implementation in C (apparently not the official implementation).
- **Bouncy Castle** (Java and .NET) — already has a mature production
  implementation of the DSTU 4145 signature (`DSTU4145Signer`), in use for
  decades, with continuous external audit. Don't rewrite the signature for
  Java/.NET — integrate/wrap it.
- **Ecognize/libukrypto** (GitHub) — a WIP OpenSSL engine specifically for
  DSTU. Marked as WIP, appears stalled — useful as an example of CLI
  architecture, not as a code donor.
- **Excluded: the `li0ard` GitHub account** (TypeScript/Go packages for
  Kalyna/Kupyna/Strumok/DSTU 4145). Not used as a dependency, not used as an
  oracle, not linked from anywhere in this project — flagged as an untrusted
  supply-chain source with unverified maintainer provenance. See D-07 in
  `DECISIONS.md`.
- **crates.io**: the `kupyna` crate exists, but is dead — one version from
  December 2016, no updates since. The `kalyna`, `strumok`, `dstu4145`
  crates don't exist at all — a genuinely open niche in the Rust ecosystem.

## State certification (for reference, not an MVP blocker)

- Regulator: **Administration of the State Service for Special
  Communications** (Держспецзв'язку). Mandatory expert review only applies
  if the tool is used to protect state information resources or information
  whose protection is required by law. An open library on GitHub/GitLab by
  itself is a voluntary category.
- Procedure: the customer independently chooses a licensed private "expert
  organization", enters into a contract with it for the study; based on the
  results, the Administration of the State Service for Special
  Communications issues an expert opinion.
- Cost: commercial, there's no fixed state tariff — depends on the specific
  expert organization and the scope of work.
- The validity period of the opinion is individual to each case (an example,
  not a norm: the opinion on cryptonite was valid 2016→2021, ~5 years). For
  a software tool, the opinion is tied to the hash of a specific build —
  changing the code potentially requires re-certification.
- The regulation on state expert review of cryptographic information
  protection tools was last updated by order of the Administration of the
  State Service for Special Communications dated 2026-04-24 No. 302.

## On the horizon

- Obtain official documentation PDFs from the authors of each DSTU
  implementation (Kalyna, Kupyna, Strumok, DSTU 4145) with test vectors as
  reference documentation.
- Cross-check our own implementation against Kalyna-reference and other
  oracles.
- Hardware validation on STM32/ESP32 — a separate phase after the MVP.
