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
- A single CLI binary on top of the core (`uacrypt`, `DECISIONS.md` D-36), with
  subcommands like `uacrypt encrypt --key ... --in file --out file` — mode,
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
algorithms, with a similar API. **Revised 2026-07-23** (`DECISIONS.md` D-05/D-41): the paragraph
below describing Kalyna+Kupyna encrypt-then-MAC as the AEAD approach was this project's original
reading, since superseded by a provisional working hypothesis — Kalyna-alone CCM does come
"out of the box" after all, per two independent implementations (cryptonite, Bouncy Castle) and
`hazmat::kalyna_ccm`'s dual-oracle-verified construction. Both readings are unconfirmed against the
primary DSTU 7624:2014 text; kept below for the historical record, not deleted, per `CLAUDE.md`'s
"never silently deprecate" rule — see D-05 for the full reasoning.

DSTU 7624 (Kalyna) was originally read as requiring combining the cipher with DSTU 7564 (Kupyna) on
different keys to get confidentiality + integrity — that is, AEAD doesn't come "out of the box"
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

- `crypto_secretbox` (symmetric AEAD) → **provisionally** Kalyna-alone CCM
  (`hazmat::kalyna_ccm`, `DECISIONS.md` D-41), not the encrypt-then-MAC
  construction originally described here — still blocked from being wired up
  as `crypto_secretbox` itself pending D-05's primary-text confirmation. The
  original encrypt-then-MAC framing (Kalyna in an encryption mode + a
  separate Kupyna-based MAC, different keys) remains a live alternative if
  the primary text ends up requiring it; not chosen over CCM for any reason
  beyond "no primary text yet to decide between them."
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

## Concrete API shape

Turning the mapping above into an actual Rust module layout, and fixing the one structural
question that has to be settled before any code lands: whether the crate exposes one unified API
or splits into layers. **Decided (D-09 in `DECISIONS.md`): two layers**, same shape as orion:

- **`dstu_core::hazmat::*`** — direct algorithm implementations. No forced RNG dependency, no
  auto-generated nonces, caller passes keys/nonces/IVs explicitly where the algorithm needs them.
  Available in `no_std` builds (D-01) — this is the layer that can exist before any randomness
  question is settled, and the layer every primitive lands in first.
- **A future high-level "easy" layer** (name TBD, not built yet) — libsodium-style `crypto_*`
  ergonomics on top of `hazmat`: auto-generated nonces via `OsRng`/`getrandom`, misuse-resistant
  defaults, the actual point of building this library "in the spirit of libsodium" instead of
  OpenSSL. `std` (or at least `alloc` + an injected RNG) gated, since safe automatic nonce
  generation needs an RNG source `no_std` doesn't provide by itself.

Module-by-module status (libsodium name → `dstu_core` module → status):

| libsodium equivalent | `dstu_core` module | Status |
|---|---|---|
| `crypto_generichash` | `hazmat::kupyna` (`Kupyna256`, `Kupyna512`, `Kupyna256Hasher`, `Kupyna512Hasher`) | **Implemented** — one-shot `digest()` and streaming `update`/`finalize` (`TASKS.md` T-83), byte-aligned messages only. See D-10 in `DECISIONS.md`. |
| `crypto_stream` | `hazmat::strumok` (`Strumok256`, `Strumok512`) | **Implemented** — keystream generation/`apply_keystream`, both key sizes. Vectors are UAPKI-attributed, not confirmed against the *official text* yet. See D-18 in `DECISIONS.md`. |
| `hazmat::kalyna` (block primitive, not directly libsodium-mapped) | `hazmat::kalyna` (`Kalyna128_128`/`Kalyna128_256`/`Kalyna256_256`/`Kalyna256_512`/`Kalyna512_512`) | **Implemented** — single-block `encrypt`/`decrypt`, all 5 variants. See D-13 in `DECISIONS.md`. |
| `hazmat::kalyna_ccm` (mode of operation, not directly libsodium-mapped) | `hazmat::kalyna_ccm` (all 5 variants) | **Implemented, provisional** — Kalyna-alone CCM, dual-oracle-verified (UAPKI + Bouncy Castle vectors), not confirmed against the primary DSTU 7624:2014 text. See D-41 in `DECISIONS.md`. Sourced 255-byte plaintext/AAD limit; nonce-generation strategy still undecided (D-40, `TASKS.md` T-82). |
| `crypto_sign` | `hazmat::dstu4145` | **Implemented (m=163 curve only)** — `GF(2^163)` field arithmetic, point add/double, constant-time scalar multiplication, and `sign`/`verify`, all verified against the official standard's own Annex B.1 worked example plus a `proptest` round-trip (`TASKS.md` T-41/T-43/T-44, `DECISIONS.md` D-25). No high-level `crypto_sign` wrapper yet (T-48); the other 9 named curve sizes aren't wired up. This row was stale until 2026-07-23 (see `docs/release-readiness.md`) — corrected here, not just there. |
| `crypto_box` | `hazmat::dstu9041` | Hard-blocked — zero source material exists for DSTU 9041 (see `ORACLES.md`); cannot start. |
| `crypto_secretbox` | *(future construction over `hazmat::kalyna_ccm`, provisionally — see D-05/D-41)* | Blocked on D-05 (the Kalyna-alone CCM/GCM vs. Kalyna+Kupyna encrypt-then-MAC tension) — `hazmat::kalyna_ccm` exists as a standalone provisional primitive, but wiring it up as `crypto_secretbox` itself still needs the official DSTU 7624 text or another authoritative source before D-05 is non-provisionally resolved. |
| `crypto_auth`/`crypto_onetimeauth` | `hazmat::kupyna_kmac` (`Kupyna256Kmac`/`Kupyna384Kmac`/`Kupyna512Kmac`) | **Implemented, provisional** — Kupyna-based KMAC, both UAPKI's and Bouncy Castle's constructions read and cross-checked byte-for-byte on all three sizes, not confirmed against the primary DSTU 7564:2014 text. See D-44 in `DECISIONS.md`. |
| `crypto_kdf` | `hazmat::kupyna_kdf` (`Kupyna256Kdf`/`Kupyna384Kdf`/`Kupyna512Kdf`) | **Implemented** — modeled after libsodium's `crypto_kdf_derive_from_key` shape over `hazmat::kupyna_kmac`, not full RFC 5869 HKDF. No DSTU standard or reference implementation exists for this construction, so unlike the rest of this table's "provisional" rows, there is no oracle vector at all, ever — see D-45 in `DECISIONS.md`. |
| `crypto_kx` | *(future construction over `hazmat::dstu4145`/`dstu9041`)* | Needs both curve implementations to exist; DSTU 9041 side is hard-blocked. |
| `crypto_secretstream` | *(future construction over `hazmat::strumok`/`hazmat::kalyna`)* | Both underlying primitives now implemented; the construction itself not started. |
| `crypto_pwhash` | *(not DSTU — plain Argon2id, wrapped at the high-level layer only)* | Not started; low priority, no blocker. |
| `randombytes` | *(not DSTU — OS CSPRNG via `getrandom`, used only by the future high-level layer)* | Not started; no blocker, but only needed once the high-level layer exists. |

This table is the authoritative "what's actually implemented right now" for the API surface —
`TASKS.md` tracks the same work at the task-checklist level; update both when a module's status
changes.

## Resources found

- **[specinfo-ua/UAPKI](https://github.com/specinfo-ua/UAPKI)** (found 2026-07-22, user-supplied)
  — a fork of Cryptonite with a cited 2021 Ukrainian state crypto-expertise conclusion. A full
  PKI/e-signature application SDK (ASN.1, certificate/CSR handling, PKCS#11/12 key storage, a
  browser native-messaging host, Android/Java/Kotlin bindings) built on a C crypto-primitives
  library (`uapkic`) covering Kalyna, Kupyna, Strumok, and DSTU 4145 — **not DSTU 9041**, which is
  absent from its own supported-algorithms list. Used as an oracle: pruned clone at
  `oracles/uapki/`, self-test KAT data cross-referenced for DSTU 4145/Strumok (see `ORACLES.md`,
  `DECISIONS.md` D-14/D-15/D-16). **Reviewed for scope overlap with this project — none found; see
  D-17.** UAPKI operates one layer up (PKI application, not crypto primitive), in a different
  language ecosystem (C/C++ → Java/Kotlin, not Rust), and doesn't reach embedded targets at all —
  this project's niche (a safe, `no_std`-capable Rust implementation of the algorithms themselves)
  remains open and unchanged.
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
  Reinforced by the UAPKI finding (D-17): a mature C/C++ PKI stack needing these exact
  algorithms chose to hand-roll them in C rather than bind to an existing safe Rust
  implementation — circumstantial evidence the gap is real, not that the space is occupied.

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
- **Speculative, long-term, not MVP, not scheduled in any `TASKS.md` phase:** `dstu-core` could
  someday expose a C ABI (`cdylib`/`staticlib` + a plain-C header) so that C/C++ PKI stacks —
  UAPKI (see D-17) is the concrete example that prompted this — could adopt this project's
  audited Rust primitives instead of maintaining their own C implementations of the same
  algorithms. Purely a "don't forget this occurred to us" note: no design work done, no task
  created, no commitment implied. Revisit only if a concrete need or request for it shows up —
  don't let it quietly expand MVP scope in the meantime.
