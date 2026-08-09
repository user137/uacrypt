# docs/SECURITY.md

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

## CLI/binary attack surface (`uacrypt`)

The threat model above is stated at the library (`dstu-core`) level; `uacrypt` (the CLI binary,
`crates/uacrypt`) adds its own boundary - untrusted file contents, argv, and exit codes - which the
same "attacker who can supply malformed/adversarial input" scope extends to. In scope specifically:

- **On-disk wire formats as adversarial input**: a `--in` file is not guaranteed to be genuine
  output of the corresponding `encrypt`/`sign`/`box-seal`/etc. command - truncation, tampering (any
  byte, including framing/tag bytes, not just payload), and cross-format confusion (feeding one
  command's output to a different command that expects a similarly-shaped file, e.g. a `keygen` key
  where a `box-keygen` key is expected - same length, different meaning) must all fail cleanly, not
  panic or silently produce wrong output.
- **No partial output on failure**: a command that fails partway through must not leave a
  half-written `--out` behind for a later, unrelated read to pick up.
- **`--in`==`--out` (in-place usage)** must not corrupt data even when a command's own
  implementation reads and writes the same path in more than one step.

Real-subprocess coverage for this boundary lives in `crates/uacrypt/tests/` (`docs/TASKS.md`
T-200) - `std::process::Command`-spawning the actual compiled binary, not the library's `run()`
in-process, since exit codes, stdout/stderr routing, and real-filesystem behavior are only
observable at the real process boundary. Two real findings from this suite: `strumok-crypt
--in`==`--out` used to silently truncate the input to zero bytes at exit code 0 before a fix
(`docs/DECISIONS.md` D-187); and confirmation, at this same CLI/file boundary rather than only
`hazmat`'s in-process API, that both a constructed order-2 DSTU 4145 public key (`verify --key`)
and a constructed order-2 `crypto_box` ciphertext (`box-open`, the `r=p-1` case, D-167 Finding 1)
are genuinely rejected. **One gap remains, not closed and not silently dropped**: an order-4 (not
order-2) attack against `crypto_box`/`dstu9041` is still open - D-173 investigated this directly at
the `dstu-core` level, with full internal-crate access, and could not confirm either way whether a
concrete order-4 point is even reachable through the public reconstruction API (`point_from_x`) -
existence is proven, reachability isn't. This needs an analytic answer, not more test-writing;
tracked in `docs/TASKS.md` T-200/D-173.

## Known cryptanalysis (third-party literature)

Three papers sit in `docs/papers/` and were never actually surfaced anywhere in this project's
docs until this note (2026-07-31) — not a font-encoding failure like the ones corrected in
`docs/ORACLES.md` the same day, just genuinely unread. None of these change the constant-time/
dual-oracle posture above; they're recorded here because a threat model that omits published
third-party attacks on its own primitives isn't a complete one, even when none of the attacks
reach the full cipher.

- **`docs/papers/Kalyna_attacks.pdf`** (Akshima, Chang, Ghosh, Goel, Sanadhya, "Single Key Recovery
  Attacks on 9-round Kalyna-128/256 and Kalyna-256/512") — a multiset (meet-in-the-middle-variant)
  key-recovery attack reaching **9 of Kalyna-128/256's 14 rounds** (data/time/memory:
  `2^105 / 2^245.83 / 2^226.86`) and **9 of Kalyna-256/512's 18 rounds**
  (`2^217 / 2^477.83 / 2^443.45`).
- **`docs/papers/Kalyna_improved_MITM_attacks.pdf`** (Lin, Wu, "Improved Meet-in-the-Middle Attacks
  on Reduced-Round Kalyna-128/256 and Kalyna-256/512") — improves the above via a key-dependent
  sieve technique: **9 of 14 rounds on Kalyna-128/256**, and **11 of 18 rounds on Kalyna-256/512**
  (the paper's own claimed best-known results at time of writing).
- **`docs/papers/Kupyna_analysis.pdf`** (Zou, Dong, "Cryptanalysis of the Round-Reduced Kupyna Hash
  Function") — a rebound-attack collision on **5 of Kupyna-256's 10 rounds**
  (`hazmat::kupyna::Kupyna256`'s round count, confirmed against `crates/dstu-core/src/hazmat/kupyna.rs`)
  at `(2^120, 2^64)` time/memory, plus guess-and-determine meet-in-the-middle pseudo-preimage
  attacks on **6 rounds of both Kupyna-256 and Kupyna-512** (`Kupyna512` is 14 rounds) at
  `(2^250.33, 2^250.33)` and `(2^498.33, 2^498.33)` respectively.

**Reading these correctly**: every attack above is round-reduced — none reaches the full cipher
(Kalyna's full round counts are 10/14/14/18/18 across its five variants; Kupyna-256/512 are
10/14). This is not evidence of a break in `hazmat::kalyna`/`hazmat::kupyna` as shipped, and this
project makes no claim that these margins are unassailable either — it's the normal state of a
young-ish national-standard cipher accumulating third-party cryptanalysis, tracked here so a
future session doesn't have to rediscover these papers exist. Revisit this section if a future
attack closes the gap to the full round count for either cipher.

- No primitive is implemented without citing the specific spec section (DSTU text, page/clause,
  or the author's reference-implementation source) it was verified against. Record the citation
  in `docs/DECISIONS.md`.
- No secret-dependent branching. Secret-dependent array indexing is limited to fixed-latency
  table lookups mirroring the DSTU reference implementations (S-box/GF-multiplication substitution
  tables) — a documented, currently-accepted software cache-timing exposure, scoped identically to
  the hardware side-channel carve-out below (see `docs/DECISIONS.md` D-19 for the full rationale and
  exact scope). Anything beyond that — an index that depends on a *comparison outcome*, or
  variable-time table selection — is still prohibited without exception.
  - **`hazmat::gf2m_wide`/`hazmat::dstu4145::gf2m163`'s `std`-gated hardware-`clmul` dispatch**
    (`docs/TASKS.md` T-198, `docs/DECISIONS.md` D-184) is not a new carve-out and not a
    side-channel-resistance claim — the hardware path has no secret-indexed memory access at all
    (fixed loop bounds, and `PCLMULQDQ`/`PMULL`'s own documented latency is operand-value-
    independent), a strict improvement over the D-19 carve-out on the axis this bullet covers, not
    a trade against it. `no_std`/embedded builds and CPUs without the feature keep running the
    original software paths (including gf2m163's own no-array-indexing-at-all design) unchanged.
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
- `cargo kani` (bounded model checking, `docs/DECISIONS.md` D-102) is a required CI layer for
  `hazmat::dstu4145::gf2m163::reduce` — proves, for all 2^384 possible 6-limb inputs rather than
  fixed vectors or sampled proptest cases, that the closed-form reduction always produces a fully
  reduced result and matches an independent bit-at-a-time reference. Scoped to that one module for
  now (D-102 has the full rationale for why this module and not others); not a general replacement
  for miri/fuzz/proptest, which stay required everywhere they already run.
- `cargo fuzz` is required for every parser of untrusted input bytes, not optional.
- `cargo audit` (RustSec advisory database — known vulnerabilities, yanked crates) and
  `cargo deny` (license policy, duplicate/banned crates, dependency-source allowlist — policy in
  `deny.toml`) are required CI layers, same standing as `cargo miri`/`cargo fuzz` above. Currently
  check an empty dependency tree (zero external dependencies in `dstu-core`/`uacrypt` so far) —
  that's not a reason to treat them as inactive; they're the automated enforcement of the
  supply-chain table below, and must stay green as soon as any dependency is added.
- `unsafe` code is isolated to the smallest possible module with a safe wrapper, and every
  `unsafe fn`/block carries a `// SAFETY: ...` comment stating the invariant that makes it sound.
- **Any self-contained wire format that transmits a nonce/IV alongside ciphertext+tag as one blob
  a caller trusts as a unit (`crypto_secretbox`-style) must confirm the underlying construction's
  tag actually authenticates that nonce/IV — by reading the tag-computation code, never by
  assumption.** Not every AEAD construction does this: DSTU Kalyna-GCM's tag is computed purely
  from AAD and ciphertext (`E_K(accumulator XOR length_block)`) — the IV only seeds the keystream,
  it never enters the tag — unlike Kalyna-CCM (nonce folded into the first CBC-MAC block) or NIST
  AES-GCM (`J0` is nonce-derived). If the nonce is unauthenticated and ships inside a blob nobody
  separately verifies, an attacker can tamper the nonce prefix and the receiver decrypts "success"
  against different, attacker-uncontrolled-but-unverified plaintext instead of getting a tag
  failure — a real loss of tamper-evidence, not a theoretical one. The fix is to bind the nonce
  into the tag using the construction's own AAD mechanism (pass the nonce itself as `aad`), not to
  add an ad hoc secondary check. Found and fixed in `crypto_secretbox`'s Kalyna-CCM→Kalyna-GCM
  migration (`docs/DECISIONS.md` D-63) via a tamper test written during that migration, not caught by
  code review after the fact — re-verify this for every future combined-AEAD wire format
  (`crypto_secretstream`/T-40 included), it is not a one-time fix.

## Supply-chain vetting (apply before adding any crypto-adjacent dependency)

| Crate | Maintainer/developer | Reproducible builds | Independent audit | CVE history |
|---|---|---|---|---|
| `subtle` 2.6.1 | dalek-cryptography org (isis lovecruft, Henry de Valence) — the same team behind `curve25519-dalek`/`ed25519-dalek`; `subtle` is the de facto standard constant-time-comparison primitive those and many other independently audited Rust crypto crates build on | Standard `cargo`/crates.io build, no custom build script (confirmed: no `build.rs` in the published source) | Not separately audited as a standalone crate, but it underpins numerous independently audited crates in the dalek-cryptography/RustCrypto-adjacent ecosystem, same posture as the `zeroize` row below | Clean per `cargo audit` as of 2026-07-25 |
| `zeroize` 1.9 (+ `zeroize_derive`) | RustCrypto org — the de facto standard crate for this in the Rust crypto ecosystem, used by nearly every RustCrypto primitive | Standard `cargo`/crates.io build, no custom build script beyond the derive proc-macro | Not separately audited as a standalone crate, but its volatile-write approach is the same one used across audited RustCrypto crates | Clean per `cargo audit` (D-11) as of 2026-07-22, see `docs/DECISIONS.md` D-20 |
| `getrandom` 0.3.4 | rust-random org — the de facto standard OS-CSPRNG-access crate in the Rust ecosystem, dependency of `rand`/`rand_core` and thousands of downstream crates | Standard `cargo`/crates.io build; a small `build.rs` for backend target detection, no code generation | Not separately third-party-audited as a standalone crate; widely relied upon across the ecosystem (including by audited crates) as the standard OS-entropy access point | Clean per `cargo audit` as of 2026-07-24, `dstu-core`-side usage is `std`-gated/optional (`docs/DECISIONS.md` D-48) so it never enters a `no_std` build |
| `argon2` 0.5.3 (adopted, `pwhash` feature only — `docs/DECISIONS.md` D-49/D-50, T-71) | RustCrypto org (`password-hashes` monorepo) — the de facto standard Argon2 implementation in the Rust ecosystem (~40M downloads) | Standard `cargo`/crates.io build, no custom build script | Not separately third-party-audited as a standalone crate; NCC Group's and Cure53's RustCrypto-adjacent audits covered the AEAD/`xsalsa20poly1305` crates, not `password-hashes` — a real, disclosed gap | Clean per both the local `cargo audit` advisory DB and `RustSec/advisory-db` upstream, checked 2026-07-24 |
| `rand_core` 0.6.4 (transitive only, via `argon2`→`password-hash`'s own default features — `docs/DECISIONS.md` D-50) | rust-random org — the de facto standard RNG-trait crate in the Rust ecosystem | Standard `cargo`/crates.io build | Not separately third-party-audited as a standalone crate | Clean per `cargo audit` as of 2026-07-24; genuinely unused by any code in this workspace (`SaltString::generate`/`OsRng` are never called), confirmed absent from every `no_std` build since `pwhash` is never enabled there |
| _(fill in per dependency before merging)_ | | | | |

## Reporting vulnerabilities

Private disclosure only — GitHub Security Advisories. Never a public issue.
