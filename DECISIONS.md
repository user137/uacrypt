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

**Addendum 2026-07-23, forward-looking only - no code changed by this note**: T-82's resolution
added `getrandom` as a dependency, but scoped to `crates/uacrypt` only (a `std`-only application
binary), never `crates/dstu-core` (the `no_std` library core) - deliberately, not by omission.
Recorded here because the user raised the right next question while reviewing T-82: what happens
when *this* `getrandom` call runs on a machine or controller with no exposed RNG source? Confirmed
by reading `getrandom` 0.3.4's own source (`backends.rs`): on a target it doesn't recognize
(bare-metal/embedded, no OS), it **fails to compile** with an explicit `compile_error!` pointing at
its own "custom backend" documentation - not a silent fallback to weak entropy, not a runtime
panic. On a *recognized* OS target where the source is transiently unavailable, `getrandom::fill`
returns `Err`, which `uacrypt` already propagates as `CliError::Random` rather than panicking or
proceeding with bad randomness. Neither failure mode is a problem for `uacrypt` specifically, since
it only ever targets real OSes - but it is exactly why `getrandom` must never become a `dstu-core`
dependency by default: that would make the entire `no_std` build (this project's whole embedded
argument, `TASKS.md` T-55/T-56) fail to compile for every downstream firmware author who doesn't
register a custom entropy backend, even if their firmware never calls the function that needed it.

This matches an architecture write-up the user did with Gemini (`rust_nostd_csprng_architecture.md`,
not committed to this repo - an external research artifact, referenced here for the decision it
informs, not reproduced) surveying three patterns for RNG in cross-platform `no_std` Rust:
(1) trait injection (`RngCore + CryptoRng` parameters, the caller supplies the RNG - `ed25519-
dalek`/`x25519-dalek`'s own convention), (2) an optional `std` Cargo feature that layers a
convenience wrapper calling the OS CSPRNG automatically on top of (1)'s core, (3) calling
`getrandom` unconditionally, which is ergonomic for OS targets but pushes the `register_custom_
getrandom`-equivalent burden onto every embedded consumer even ones that never need it. That
survey's own recommendation - core library logic uses (1), an optional `std`-gated wrapper adds
(2)'s convenience, (3) is fine only for an application binary that is never itself consumed as a
`no_std` dependency - is **exactly** this project's existing `std`/`alloc`/`no_std` feature-flag
split (D-01) applied to entropy specifically, and is the pattern to follow once real work starts
on: `TASKS.md` T-72 (`randombytes`, `crypto_secretbox`/DSTU-4145-signing's internal ephemeral-
scalar generation if either ever needs to generate rather than receive random material) and T-48
(`crypto_sign`, if DSTU 4145 key/nonce generation moves inside the Rust port rather than staying
caller-supplied the way `hazmat::dstu4145`/`hazmat::kalyna_ccm` both currently require). Nothing
in `hazmat` needs this today - every keyed/nonce-taking primitive in this crate (`kalyna_ccm`,
`dstu4145::sign`) takes its randomness as an explicit caller-supplied parameter, matching pattern
(1)'s spirit already without an actual `RngCore` trait bound (D-09's low-level hazmat layer is
deliberately "caller supplies everything," full stop) - this addendum is a note for the *future*
easy/high-level layer (T-65), not a gap in what exists now. `uacrypt`'s direct, unconditional
`getrandom` call (pattern 3) is correct for it specifically because it is an application, never a
`no_std` library dependency of anything else - the distinction the user's question was really
probing, confirmed correct rather than assumed.

## D-05: AEAD working hypothesis is Kalyna-alone CCM, provisional pending the primary text
(revised 2026-07-23, see D-41's follow-up entry for the original text this replaces)

**Current working hypothesis: Kalyna-alone CCM** (`hazmat::kalyna_ccm`, D-41), not encrypt-then-MAC
with a separate Kupyna-keyed MAC. This reverses this entry's original stance below - recorded as a
revision, not a silent overwrite, per `CLAUDE.md`'s "never silently deprecate" rule.

**Why the reversal, and why it's still provisional:**
- **New evidence, both independent of each other**: PrivatBank's cryptonite
  (`oracles/cryptonite/src/cryptonite/c/dstu7624.h`, `dstu7624_init_ccm`/`dstu7624_init_gcm` +
  `dstu7624_encrypt_mac`/`dstu7624_decrypt_mac`) and Bouncy Castle
  (`org.bouncycastle.crypto.modes.KCCMBlockCipher`/`KGCMBlockCipher` - DSTU7624-specific, not the
  generic AES-CCM/GCM classes) **both** implement Kalyna-alone authenticated modes as first-class
  DSTU 7624 constructions. Two independently-maintained, serious implementations agreeing is
  meaningfully stronger evidence than cryptonite alone (this entry's original "not yet reconciled"
  note only had cryptonite to weigh).
- **Modern AEAD engineering practice points the same way.** Compared against TLS 1.3 and real
  AES/ChaCha usage (2026-07-23 session, at the user's request): TLS 1.3 (RFC 8446) dropped
  separate-MAC composition entirely - only combined AEAD suites (AES-GCM, ChaCha20-Poly1305,
  AES-CCM/CCM_8) are allowed, precisely because hand-rolled MAC-then-encrypt produced a real
  vulnerability lineage (BEAST, Lucky13, POODLE) from composition mistakes (ordering, timing,
  padding). AES-GCM/ChaCha20-Poly1305 aren't "one key shared by two unrelated algorithms" either -
  GCM's `H` subkey and ChaCha20-Poly1305's one-time MAC key are both derived from the same key
  material inside the single construction, so the caller never manages two keys or an ordering.
  Encrypt-then-MAC with independent keys is formally sound (Bellare-Namprempre 2000) and is what
  SSH deliberately chose after the same lesson - but it is more implementation surface
  (independent key derivation, whole-ciphertext MAC coverage, verify-before-decrypt discipline)
  than a purpose-built combined AEAD, when one is available. Kalyna-alone CCM is the "one available
  here" side of that comparison.
- **Still provisional, not a claim about the primary text.** Nothing above is a reading of the
  official DSTU 7624:2014 text - it's reference-implementation evidence plus general engineering
  practice, exactly the class of input this entry's original text said not to resolve the tension
  from alone. This decision stays open pending that text (still priced/unpurchased, see below);
  `hazmat::kalyna_ccm` is built and documented as provisional (same posture as Strumok/D-15), and
  this entry will be revised again (not silently) if the primary text says otherwise.
- **Scope note**: `hazmat::kalyna_ccm` (D-41) is a standalone hazmat-level primitive users can call
  directly. It is not, by itself, the `crypto_secretbox` construction - that's
  `dstu_core::crypto_secretbox` (`TASKS.md` T-37, `DECISIONS.md` D-51, built 2026-07-24 against this
  entry's working hypothesis), inheriting the same provisional status as `hazmat::kalyna_ccm` itself.

**Original text (2026-07-21), superseded above but kept for the record:** Symmetric AEAD was
decided as Kalyna in a stream-like mode (CTR/OFB-style) for confidentiality, plus an independent
MAC keyed from Kupyna, encrypt-then-MAC, with distinct encryption and authentication keys. Kalyna
alone as an AEAD primitive (à la AES-GCM) was rejected, reasoning that the DSTU 7624 text itself
specifies that confidentiality + integrity requires combining with DSTU 7564 (Kupyna) on separate
keys - there is no single-primitive AEAD in the standard to call instead. See
`docs/dstu-crypto-project.md` libsodium-mapping section (itself not yet updated for this revision -
follow-up needed). This was already flagged the same day as "not yet reconciled" against
cryptonite's `dstu7624_encrypt_mac` API, which is the tension the revision above resolves
provisionally, not the first time this tension was noticed.

The official text was priced (2026-07-21) to check on this directly: 29,967.60 UAH for 227 pages
(includes Amendment No. 1:2016) via `fnd-store.uas.gov.ua/documents/4228` — see `ORACLES.md`
"Official DSTU text — purchase cost". Deemed cost-prohibitive for now; this decision stays
provisional until either the price becomes viable or another authoritative source turns up.

**Adopted as the project's working assumption, 2026-07-24** (user's explicit direction: proceed on
assumption now, correct later if the primary text says otherwise, never silently) — two
independent, non-primary sources now corroborate Kalyna-alone as the standard's own official
answer, not just reference-implementation agreement:

- **Already-vendored, predates this session's research**: `ORACLES.md`'s own note (2026-07-22) that
  `oracles/uapki/`'s `dstu7624_self_test` covers exactly ten named modes - `ECB/CBC/OFB/CFB/CTR/
  CMAC/XTS/KW/CCM/GMAC/GCM` - as the standard's own mode set, GCM/GMAC counted as one combined
  entry. This was sitting in this project's own tracking before today, unconnected to D-05 by name
  until now.
- **New 2026-07-24**: Ukrainian Wikipedia's "Калина (шифр)" article (raw wikitext fetched and read
  directly, not trusted from a summarized fetch - see the false starts below) publishes a table of
  **the same ten modes**, numbered 1-10, with each mode's official notation and the exact security
  service it provides:

  | # | Mode | Notation | Security service |
  |---|---|---|---|
  | 1 | Проста заміна (базове перетворення) | ECB | Confidentiality only |
  | 2 | Гамування | CTR | Confidentiality only |
  | 3 | Гамування зі зворотним зв'язком за шифротекстом | CFB | Confidentiality only |
  | 4 | Вироблення імітовставки | CMAC | Integrity only |
  | 5 | Зчеплення шифроблоків | CBC | Confidentiality only |
  | 6 | Гамування зі зворотним зв'язком за шифрогамою | OFB | Confidentiality only |
  | 7 | Вибіркове гамування із прискореним виробленням імітовставки | GCM, GMAC | **Confidentiality + integrity (GCM)**, integrity only (GMAC) |
  | 8 | Вироблення імітовставки і гамування | **CCM** | **Confidentiality + integrity** |
  | 9 | Індексована заміна | XTS | Confidentiality only |
  | 10 | Захист ключових даних | KW | **Confidentiality + integrity** |

  The article's own mode-notation format - `«Калина-I/k-позначення режиму-параметри режиму»`,
  worked example `«Калина-256/512-ССМ-32,128»` (256-bit block, 512-bit key, CCM, message length
  bound 2^32 bytes, 128-bit tag) - matches `hazmat::kalyna_ccm`'s own parameterization almost
  exactly, independently arrived at. Kupyna is mentioned in the article only in an unrelated
  context (mandatory alongside Kalyna for DSTU 4145-2002 signature hashing since 2022, per a
  Ministry of Digital Transformation order - nothing to do with encryption modes). **This is still
  a secondary source, not the primary text** - the table carries no inline citation to a specific
  standard clause - but its ten-mode count matches Oliynykov's own paper's already-cited "ten modes
  of operation" figure, and its detail (exact notation grammar, an amendment number matching
  `ORACLES.md`'s own pricing-page record) is difficult to explain as anything other than a
  transcription by someone who read the real standard.
- **Two other candidate papers by the standard's own authors (Горбенко/Олійников/Казимиров et al.)
  were fetched and read this session specifically looking for mode-of-operation detail, and ruled
  out** - recorded so this research isn't repeated: `docs/papers/
  Kalyna_construction_principles_ZI_2015.pdf` ("Принципи побудови і основні властивості нового
  національного стандарту блокового шифрування України", Захист інформації 17(2), 2015) and
  `docs/papers/Kalyna_vs_international_standards_2018.pdf` (Єфіменко/Байлюк/Покотило, 2018) are
  both exclusively about the block cipher's internal SPN structure (S-box/MDS-matrix choice, speed
  vs. AES/GOST/"Кузнечик") - confirmed by reading every page's content (rendered to PNG and read
  directly, `pdftotext` fails on both from the same font-encoding gap as `Dolgov_5-22.pdf`), neither
  mentions modes of operation or Kupyna combination at all. `docs/papers/Dolgov_5-22.pdf` (already
  in this repo, re-checked) is the same - cipher internals only, its own `ВИСНОВКИ` section says so
  explicitly.
- **False starts, worth recording so they aren't repeated**: a first-pass web search's own
  synthesized summary claimed DSTU 7624:2014 "can be used together with DSTU 7564 [Kupyna]... with
  different encryption and authentication keys required" - the opposite conclusion from the one
  adopted above. Traced to no actual quotable source (not in either paper above, not in the
  Wikipedia article); it was a search-engine aggregation artifact, not a real citation, and was
  discarded once the raw Wikipedia wikitext was fetched and read directly instead of trusting a
  summarized fetch. Two separate `WebFetch` summaries of Cyrillic PDFs this session also produced
  unreliable or hedged non-answers on a font-encoding-broken document (same known gap as
  `Dolgov_5-22.pdf`) - the pattern going forward is: **always fetch raw text/wikitext or render to
  image and read directly for Cyrillic sources; never trust a `WebFetch` summarization prompt's
  answer about one at face value**, since the underlying small model handles broken Cyrillic
  extraction unreliably and has produced both false positives and false negatives this session.

**Only the AEAD-shaped modes are ever candidates for a public entry point, per D-47.** Of the ten,
only CCM (#8, already `hazmat::kalyna_ccm`), GCM (#7, not yet implemented - needs new GF(2^128)
field arithmetic this crate doesn't have, see the original kalyna_ccm planning note), and KW (#10,
not yet implemented) provide both confidentiality and integrity. ECB/CTR/CFB/CBC/OFB
(confidentiality-only) and bare CMAC (integrity-only) are real, standard-defined modes but **must
never be wired up as a public `crypto_secretbox`/`uacrypt encrypt`-`decrypt` entry point on their
own** - D-47's "expose only safe modes of operation, never an unsafe/legacy one as a public entry
point" rule applies literally here, now with a concrete list of which of the standard's own ten
modes count as which.

**Still not primary-text-confirmed.** This paragraph is an explicit, user-directed decision to
proceed on assumption, not a claim that the question is closed - if the priced primary text (or
another authoritative source) is ever acquired and contradicts any of the above, this entry gets
revised again, the same way it was revised on 2026-07-23 and again here, never silently.

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

## D-08: Post-quantum DSTU 8961:2019 (Skelya) and DSTU 9212:2023 (Vershyna) are out of scope

Not implemented, and not to be proposed for implementation, without a separate explicit decision
from the project owner.

**What they are** (context only, for if this is ever revisited): DSTU 8961:2019 "Skelya" —
post-quantum key encapsulation (KEM) and asymmetric encryption on algebraic lattices, the same
problem class as CRYSTALS-Kyber or FrodoKEM, a Ukrainian variant. DSTU 9212:2023 "Vershyna" —
post-quantum digital signature on algebraic lattices with rejection sampling, the post-quantum
counterpart to DSTU 4145.

**Rejected:** folding these into the current MVP/second-priority scope alongside
Kalyna/Kupyna/Strumok/DSTU 4145/DSTU 9041. Rejected because:
- Qualitatively different mathematics (polynomial rings, noise sampling, CPA-to-CCA transforms)
  versus the classical-curve/block-cipher math the rest of this project uses.
- Implementation complexity comparable to all five other in-scope algorithms combined, with a
  higher risk of silent correctness bugs specific to this class — constant-time rejection
  sampling, decryption failure rate, sensitivity to ring-parameter choice.
- Cryptanalysis is younger and thinner here than for internationally vetted PQ schemes: published
  work questions Skelya's "unusual field/ring choice" and probes potential attacks via sub-ring
  structure.
- No vetted Rust implementation of either algorithm exists to start from or use as an oracle —
  would be written from zero, with none of the dual-oracle safety net the rest of this project
  relies on.

If ever taken up, treat as a pair (Skelya + Vershyna together, mirroring the classical 4145+9041
pair) as a distinct Phase 3 / post-quantum track, with an explicit documented warning that its
cryptanalysis maturity is lower than this project's classical DSTU primitives.

## D-09: Two-layer API — `hazmat` (no_std, no RNG) + a future high-level "easy" layer (std/alloc-gated)

The crate's public surface is split the way orion's is: a low-level `dstu_core::hazmat` module
containing direct algorithm implementations with no forced RNG dependency and no safety rails
(caller manages keys/nonces/IVs explicitly where an algorithm needs them) — available in `no_std`
builds — and, layered on top of it later, a higher-level "easy" API mirroring libsodium's
`crypto_*` functions (auto-generated nonces via `OsRng`/`getrandom`, misuse-resistant defaults).
The high-level layer is `std` (or at least `alloc` + an injected RNG) gated, since safe automatic
nonce/key generation needs an RNG source that plain `no_std` doesn't provide.

**Rejected:** a single unified API with no low/high split. Rejected because it forces a choice
this project can't make once and be done with: either the whole crate depends on `OsRng` (breaking
`no_std`/embedded support, against D-01), or the whole crate exposes raw hazmat-style functions
only (breaking the libsodium-style "hard to misuse by default" goal that's this project's whole
reason for existing over rolling your own OpenSSL-style flexible API). The two-layer split lets
both goals hold, each in the layer where it applies — this was an **open question** in an earlier
draft of this file; resolved now because the first primitive (Kupyna, below) needed a home and the
split had to be decided before any code landed under it.

**Status:** `dstu_core::hazmat::kupyna` (Kupyna-256/512) is implemented against this split — see
below. The high-level "easy" layer does not exist yet; nothing in this project needs it before a
keyed/nonce-based primitive (Strumok, or the `crypto_secretbox` construction) is reached.

## D-10: Kupyna (DSTU 7564:2014) implemented in `dstu_core::hazmat::kupyna`

One-shot `Kupyna256::digest`/`Kupyna512::digest`, ported from `docs/pseudocode/kupyna.md`.

**Citations:**
- Algorithm structure (padding, `T`/`T⁺` compression, output transformation): the designers'
  paper, `docs/papers/Kupyna.pdf`, Sections 4–6, as already transcribed into
  `docs/pseudocode/kupyna.md`.
- S-box and MDS-matrix constants: taken byte-for-byte from
  `oracles/kupyna-reference/tables.c` (Roman Oliynykov, Kupyna's own author). Confirmed two ways
  before trusting them: (1) byte-for-byte identical to Kalyna's `sboxes_enc` in
  `oracles/kalyna-reference/tables.c` — the same author's two separate reference repos agree
  exactly, consistent with both papers stating the S-boxes are shared; (2) matches the papers'
  own worked example (`S0(0x23) = 0x4F`, Kalyna.pdf §5.3 / Kupyna.pdf §6.3) at the exact table
  index it should. This is a constants transcription, not a code port, and not subject to the
  D-06 "don't copy oracle code" restriction — the S-box/MDS tables are themselves part of the
  published specification (Appendix A), the same way AES's S-box is a spec constant rather than
  someone's implementation choice.
- Byte-matrix layout (`state[column][row]`, not a word-packed AES-style representation): mirrors
  `oracles/kupyna-reference/kupyna.c` directly (not Bouncy Castle's T-table-fused version) —
  chosen deliberately for transcription safety since this implementation could not be
  compiled/tested locally (no Rust toolchain available in this environment; see
  `.claude.local.md`) and the simpler, more literal port carries less risk of an
  unverifiable transposition/endianness bug than an optimized bit-twiddled one.

**Scope limitation, not a gap to silently paper over:** only byte-aligned messages are supported
(the public API takes `&[u8]`, which cannot represent a bit-level length anyway). This matches
the extracted test vectors exactly — the paper's bit-level cases (N=510/655/33/1) were already
excluded from `crates/dstu-core/tests/vectors/kupyna/*.json` for the same reason (see the `note`
field in those files).

**Verification status, updated 2026-07-22 after installing a local toolchain (see
`.claude.local.md`): confirmed green, not just written.**
- `cargo test --workspace`: passes, both `Kupyna256`/`Kupyna512` official-vector tests.
- `cargo miri test --workspace`: passes, no UB detected — satisfies the `SECURITY.md` requirement.
- `cargo clippy --all-features -- -D warnings`: clean (one `manual_memcpy` lint fixed in
  `shift_bytes`, no logic change).
- `cargo build --no-default-features` (the `no_std` path): compiles clean.
- Additionally cross-checked against real Bouncy Castle (not this project's own port) via
  `tests/oracle-harness/{dotnet,java}/`, both using the published NuGet/Maven packages: all 10
  Kalyna cases + all 12 Kupyna cases pass. Same caveat as always applies to that cross-check —
  BC's Kalyna/Kupyna is a port of the same C reference, so this mainly confirms the vector
  extraction, not a fully independent second implementation.
- **Still missing:** `cargo fuzz` has a scaffold (`crates/dstu-core/fuzz/`, target `kupyna`) but
  has not actually been run yet (required by `SECURITY.md`); the streaming (`update`/`finalize`)
  API doesn't exist (one-shot `digest()` only); no high-level "easy" wrapper (D-09) yet.

## D-11: `cargo audit` and `cargo deny` are required CI layers, same standing as miri/fuzz

`SECURITY.md`'s "Supply-chain vetting" table existed only as a manual process ("fill in per
dependency before merging") with no automated enforcement — inconsistent with how strictly this
project already treats `cargo miri`/`cargo fuzz` (named explicitly as required, not optional).
Added `cargo audit` (RustSec advisory database — known vulnerabilities, yanked crates) and
`cargo deny` (license allowlist, duplicate/banned crates, dependency-source allowlist — policy in
`deny.toml`) as CI jobs in `.github/workflows/rust.yml`, and elevated them to the same
non-optional standing in `SECURITY.md`.

**Rejected:** leaving supply-chain vetting as a manual, human-remembered step. Rejected because
the whole point of `SECURITY.md`'s hard-constraints section is that these things don't rely on
someone remembering — the same reasoning that already justified making `cargo miri`/`cargo fuzz`
mandatory applies identically here.

**`deny.toml` policy, briefly:** allow-list of permissive licenses compatible with this project's
own dual MIT/Apache-2.0 (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0— the common set used
by RustCrypto and most of the Rust crypto ecosystem this project expects to eventually depend on);
deny unknown registries/git sources (crates.io only); deny yanked crates. No specific crate bans
yet — `li0ard` (D-07) doesn't publish anything to crates.io this project would ever depend on, so
there's no package name to ban here; revisit if that changes.

**Status, confirmed 2026-07-22 by actually installing and running both locally (not just
writing the config):** `cargo audit` — 0 vulnerabilities against the current (empty) dependency
tree. `cargo deny check` — all four categories pass, but not trivially: it caught a real issue on
first run — `dstutool`'s `dstu-core = { path = "../dstu-core" }` dependency had no `version`
pinned, flagged as a "wildcard dependency" (`bans` category) and would also have blocked
publishing `dstutool` to crates.io as-is. Fixed by adding `version = "0.0.0"`. So this tooling has
already paid for itself once, before a single external dependency was ever added — the license
allow-list itself remains unproven against a real dependency (the "license was not encountered"
warnings are expected noise given zero deps still use those licenses) until `subtle`, `zeroize`,
`getrandom`, or `argon2` (see `docs/dstu-crypto-project.md` libsodium mapping) actually land.

## D-12: `cargo xtask` as the one cross-platform build/QA entry point

A developer on Linux/Windows/macOS runs the exact same command — `cargo xtask ci`, `cargo xtask
build`, etc. — rather than three OS-specific scripts (`.sh`/`.ps1`/`Makefile`) that inevitably
drift out of sync. Implemented as a plain Rust binary crate at `xtask/`, invoked via a `.cargo/
config.toml` alias (`cargo xtask ...` → `cargo run --manifest-path xtask/Cargo.toml ...`). It has
zero dependencies itself and is kept out of the root `[workspace]` (its own `Cargo.toml` declares
an empty `[workspace]` table) so it never appears in the dependency graph `deny.toml`/`SECURITY.md`
police for the actual crypto crates. Each subcommand shells out to a tool already documented in
`README.md` (cargo, miri, cargo-fuzz, cargo-audit, cargo-deny, Maven, the .NET SDK); optional tools
are checked for availability first and print an install hint rather than a raw "command not found"
if missing, so `cargo xtask ci` degrades gracefully on a machine that only has `cargo` so far
instead of hard-failing on the first optional layer.

**Rejected:** a Python script. Rejected for the same reason this whole decision exists — it would
add exactly the kind of "install a thing first" dependency the script is supposed to remove, on top
of `python`/`python3` already being broken Windows Store stub binaries in at least one dev
environment (see `.claude.local.md`). Also rejected: `make` (not native on Windows, and this
project's own MinGW note already documents preferring `cmake --build` over invoking `make`
directly); `just` (a real cross-platform command runner, but still a separate binary to install
before the "one command" story even starts — `cargo` is the one tool this project can always
assume, since it's needed to build at all). `xtask` is the only option that adds zero new
install step.

**Scope note:** this covers *building and developing*, not *using* `dstutool` — end-users get
prebuilt GitHub Releases binaries per the MVP scope, no Rust toolchain required on their side. See
`README.md` "Building from source" vs. "Using dstutool".

## D-13: Kalyna implementation — citation, table sharing, and verification status

`dstu_core::hazmat::kalyna` (`crates/dstu-core/src/hazmat/kalyna.rs`) implements all five DSTU
7624:2014 variants (128/128, 128/256, 256/256, 256/512, 512/512) from `docs/pseudocode/kalyna.md`,
structurally mirroring `oracles/kalyna-reference/kalyna.c` round-for-round and
key-schedule-step-for-step (S-box layer, row permutation, MDS linear layer, both round-key
addition mechanisms κ/ψ, and the full three-part key schedule: `Kt`, even-indexed keys with the
`k=l`/`k=2l` branch, odd-indexed keys via byte rotation).

**Table sharing:** moved the S-box/MDS-matrix tables out of `kupyna.rs` into a new `pub(crate)`
`hazmat::tables` module (`SBOXES`, `SBOXES_DEC`, `MDS_MATRIX`, `MDS_INV_MATRIX`, `gf_mul`,
`apply_matrix`), used by both Kalyna and Kupyna. D-10 already *asserted* Kupyna's S-box/MDS data
is byte-identical to Kalyna's — sharing the literal table makes that identity structural instead
of two hand-copied literals that could silently drift. `Kupyna256`/`Kupyna512` were re-tested
after the move to confirm the refactor didn't change behavior.

**Rejected:** duplicating the tables into `kalyna.rs` to avoid touching the already-green Kupyna
module. Rejected because the duplication risk (a second manual transcription of a 1024-byte S-box
table) was strictly worse than the regression risk of moving a `const` and a pure function, which
the existing Kupyna test suite + `cargo miri test` + oracle harnesses re-verify in seconds.

**Verification status, confirmed 2026-07-22 (test-first: `crates/dstu-core/tests/kalyna.rs` written
against the vectors before the implementation existed, per `CLAUDE.md` "Agent discipline"):**
- `cargo test --workspace --all-features`: all 5 variants pass against the official vectors in
  `crates/dstu-core/tests/vectors/kalyna/*.json` (10 cases: one independent encryption + one
  independent decryption pair per variant, not round-trips — see the `note` field in each vector
  file). Passed on the first implementation attempt, no debugging needed.
- `cargo clippy --all-features -- -D warnings`: clean after two `needless_range_loop` fixes
  (rewritten as iteration over `round_keys` slices instead of indexing by a range variable).
- `cargo build --no-default-features` (the `no_std` path): compiles clean — the implementation
  uses only fixed-size stack arrays, no heap allocation, matching Kupyna's style.
- `cargo fmt --all -- --check`: clean.
- `cargo miri test --workspace`: **confirmed clean, no UB** (all 5 variants pass under Miri too,
  ~158s — the 512/512 variant's 18-round schedule makes this the slowest test in the suite).
- **Still missing:** no independent second-oracle cross-check yet (the Java/.NET Bouncy Castle
  harnesses in `tests/oracle-harness/{java,dotnet}/` only cover Kalyna/Kupyna vectors already, not
  re-run against this new code path — see `TASKS.md` "Infrastructure" for wiring); no CBC/CTR/CCM
  mode (D-05 is still open); `dstutool` CLI doesn't call this yet.

**On the pseudocode doc's provenance caveat** (the k=2l key-schedule reading rests on one C-reference
lineage, not confirmed independently against the official DSTU text): the official test vectors are
the acceptance test here — all 5 variants, including both k=l and k=2l branches, pass byte-for-byte
against DSTU-published input/output pairs. A wrong reading of the ambiguous spec notation would
show up as a vector failure regardless of why the internal key-schedule mechanism happens to be
correct. The caveat remains about *why* the mechanism is shaped this way, not about whether this
implementation is DSTU-conformant.

## D-14: DSTU 4145-2002 official standard obtained — dual-sourced test vector

`docs/papers/DSTU_4145-2002.pdf` (added 2026-07-22) is the official standard text — a scan with no
text layer (`pdftotext` yields nothing), rendered to PNG via `pdftoppm` (poppler, installed the
same day specifically for this — see `.claude.local.md`) and read visually. This corrects the
"no official text exists for DSTU 4145" claim that `docs/pseudocode/dstu4145.md` and `ORACLES.md`
carried until now — DSTU 4145 is no longer the one algorithm exempted from the "cited spec section"
hard constraint in `CLAUDE.md`.

Annex B (Додаток Б, pages 18-21) contains a full worked signature example with real numbers, in
both polynomial basis (GF(2^163)) and optimal normal basis (GF(2^173)). The GF(2^163) example
(Annex B.1) was transcribed into `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` and then
checked against `oracles/bouncycastle-java/.../DSTU4145Test.java`'s `test163()` — a hardcoded KAT
that does not derive from this PDF. Every field (curve `a`/`b`, base point, order `n`, private key
`d`, public key `Q`, hash value, ephemeral `e`, signature `r`/`s`) matched exactly.

**Why this matters beyond "one more vector":** transcribing a 163-bit field element by eye off a
150 DPI scan is exactly the kind of error that produces a silently-wrong "official" vector — one
that would later make a *correct* Rust implementation look broken. The BC match closes that gap:
either both the scan-reading and BC's independently-maintained hardcoded constant are wrong in the
same way (implausible — different people, different years, different codebases), or the
transcription is correct. This is a genuinely dual-sourced vector, not a single by-eye reading
blessed as ground truth.

It also upgrades Bouncy Castle's own standing for this one algorithm specifically: `test163()`
passing was previously "BC agrees with itself" (a hardcoded constant an internal test happens to
check); it's now confirmed to reproduce the official standard's own published example, i.e. BC's
`DSTU4145Signer` is independently confirmed DSTU-conformant, not just internally consistent.

**Third source added 2026-07-22:** `oracles/uapki/` (see `ORACLES.md`/`oracles/README.md` — a fork
of Cryptonite with a cited Ukrainian state crypto-expertise conclusion, pedigree caveats noted
there) carries the identical `d`/`Q`/`r`/`s` values in `dstu4145.c`'s `dstu4145_self_test()`, whose
source comments `// ДСТУ 4145-2002. Додаток Б`. Byte-identical once UAPKI's little-endian storage
is reversed. Three independent sources (the standard text read directly, Bouncy Castle, and a
state-expertise-pedigreed library) now agree on this one example.

**Not cross-checked the same way:** Annex B.2 (optimal normal basis, GF(2^173)). BC's `test173()`
uses different curve parameters — a separate, unrelated KAT, not a match to this example. If B.2 is
ever extracted, it must be labeled `unverified-transcription` unless another independent source is
found, per the same reasoning above.

**Rejected:** treating the scan transcription as sufficient on its own ("I read the numbers
carefully"). Rejected because `SECURITY.md`'s dual-oracle requirement exists precisely to catch
this class of error, and a from-scratch cross-check against an already-existing, independently
maintained oracle cost nothing here — there was no reason to settle for single-sourced.

**Still open:** the pseudocode doc (`docs/pseudocode/dstu4145.md`) is not yet re-derived against the
official text's Sections 5-13 — it remains a Bouncy Castle code-transcription for now, which is a
weaker provenance than Kalyna/Kupyna/Strumok's spec-transcriptions. No GF(2^m) binary-field or
elliptic-curve arithmetic exists in `dstu-core` yet, so this vector cannot be exercised by any Rust
code yet — see `TASKS.md` Phase 2.

## D-15: Strumok vectors — sourced from UAPKI's self-test, not self-invented

Strumok had zero test vectors from any source since D-06/D-10 — official text priced at 7,027.80
UAH (see "Official DSTU text — purchase cost" in `ORACLES.md`), no hardware testbench KAT in
`Strumok_verilog.pdf` (checked 2026-07-22, nothing found). This blocked Phase 1 implementation
entirely.

**First attempt, since superseded:** generate self-invented "gray" vectors by running
`oracles/strumok-dstu8845/` (outspace, unaudited, no license) against arbitrary chosen inputs.
Committed, then replaced within the same session once a better source turned up — see below. The
generator that produced them still exists in git history but the vector files themselves were
deleted, not kept alongside the replacement (unlike the original plan for this entry), because the
new vectors' inputs are a superset in spirit (same key-size coverage) and there was no reason to
carry two unrelated input sets forward.

**What actually landed:** the user pointed at https://github.com/specinfo-ua/UAPKI (cloned,
pinned to commit `c64181c3b1cd437139119d83bffb5ab090b1cdd6`, pruned to `library/uapkic/` — see
`oracles/README.md`). Its `dstu8845.c` has a `dstu8845_self_test()` whose source comments the
block `// ДСТУ 8845:2019` — the library's own authors attribute these 8 key/IV/keystream cases to
the standard itself, not to arbitrary self-testing. Adopted these as
`crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json`, labeled
`"status": "UAPKI-attributed, not independently confirmed against the paid official text"` in
each file.

**What this does and does not prove, stated as plainly as possible:** this is stronger provenance
than the superseded gray vectors (an attribution claim from a library with a cited state
crypto-expertise pedigree, not values this project invented) but still short of "official" — this
project has not read the paid DSTU 8845:2019 text itself to confirm UAPKI's claim.
`oracles/strumok-dstu8845/` (outspace) reproduces the same 8 cases byte-for-byte
(`tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`) — **deliberately not
counted as independent-oracle confirmation**: outspace's `strumok.c` and UAPKI's `dstu8845.c`
share identical internal function/table names (`dstu8845_init`, `dstu8845_crypt`, `T0..T7`), which
reads as shared lineage rather than two people implementing from the spec independently. This is
the same trap this project already caught once this session for Kalyna
(`bouncycastle-java`'s `DSTU7624Engine.java` crediting Oliynykov's C code as its source rather
than being an independent read) — noticing the pattern the second time is the point of writing
these decisions down.

**Rejected:** waiting for the official text before writing any Strumok code. Rejected because the
wait has no defined end date and structural implementation work — GF(2^64) arithmetic, the FSM,
the T-function — can be written and structurally cross-checked against oracle source right now per
the existing pseudocode doc; there's no reason to block that on vectors that only the *final
numeric check* needs.

**Any future status line for Strumok** (`TASKS.md`, `CLAUDE.md`, `docs/dstu-crypto-project.md`)
must say "UAPKI-attributed, not confirmed against the official text" — never "confirmed"/"green"
the way Kalyna/Kupyna are worded, until this project reads the actual DSTU 8845:2019 text itself
or another source that independently transcribes its own vectors (the way `DSTU_4145-2002.pdf`
Annex Б does) turns up.

## D-16: UAPKI added as an oracle — state-expertise pedigree, precisely scoped

https://github.com/specinfo-ua/UAPKI (user-supplied) is a fork of Cryptonite whose README cites
"Expert conclusion on the results of the Ukrainian state expertise in the field of cryptographic
protection of information No 04/05/02-2096 from 21.07.2021." Cloned and pinned to commit
`c64181c3b1cd437139119d83bffb5ab090b1cdd6`, then pruned to `library/uapkic/` (the crypto-primitives
library) plus `LICENSE`/`AUTHORS`/`README.md` — same "selected files only" convention as Bouncy
Castle/cryptonite, dropping the ASN.1 layer, private-key-storage modules, the JSON-facing PKI
library, and the browser-integration/build scaffolding (none of that is a crypto-primitive
reference). BSD-2-Clause, already on `deny.toml`'s allow-list.

**What the pedigree does and does not establish:** `CLAUDE.md`'s own "State certification" section
already notes certification is tied to the hash of a specific build. The 2021 conclusion predates
this project's cloned commit (pushed 2026) by years, so this is "certified pedigree, plausibly the
same team/process," never "this exact clone is the certified artifact." Treated accordingly
throughout `ORACLES.md`/`oracles/README.md` — every reference to UAPKI in this project states the
caveat rather than leaning on "state-certified" as a bare credential.

**Immediate payoff:** every DSTU primitive in scope has a `*_self_test()` with hardcoded KAT data.
DSTU 4145's matched the official text + Bouncy Castle exactly (D-14). Strumok's is the first KAT
found anywhere for that algorithm (D-15). Kalyna's covers CCM/GMAC/GCM directly relevant to D-05's
open tension — **not yet cross-checked against our code, left for follow-up.** Kupyna's is in two
parts (see the 2026-07-22 update below): the hash self-test is now cross-checked; the KMAC
self-test is a new, separate open item.

**Update 2026-07-22 — Kupyna cross-check done for the hash, opened a new item for KMAC:**
`dstu7564_self_test_hash()` in `oracles/uapki/library/uapkic/src/dstu7564.c` turned out to be the
*exact same* 12 official cases (null/8/512/760/1024/2048-bit for both 256 and 512) already
transcribed from the designers' paper into `kupyna-256.json`/`kupyna-512.json` — a byte-for-byte
diff (all 12 cases) confirms this, not just an eyeball match. Since `cargo test` already verifies
this project's Rust output against those same files, this closes the "Kupyna cross-check" item
from above, but it's a same-vector-set confirmation (like the Kalyna/Bouncy Castle lineage note in
`oracles/README.md`), not a second independent reading — UAPKI is reproducing the same published
numbers, not deriving its own.

The self-test file also has a separate `dstu7564_self_test_kmac()` — 3 cases (KMAC-256/384/512,
fixed 31-byte message, key length equal to the tag length) that are **not** in this project's test
vectors at all, because KMAC (a Kupyna-based MAC) isn't implemented here yet. This is this
project's Kalyna-CCM/GMAC/GCM-equivalent for Kupyna: directly relevant to the still-open
`crypto_auth`/`crypto_onetimeauth` construction question (`TASKS.md` Phase 2/API-surface —
"Kupyna-based MAC... exact mode name TBD"), not yet cross-checked against anything of ours because
there's no Rust KMAC to check it against yet. Left for follow-up, same as Kalyna's CCM/GMAC/GCM —
not scheduled ahead of where `crypto_auth` already sits in `TASKS.md`.

**Update 2026-07-22 (same pass) — Kalyna's ECB self-test cross-checked too:** all 10 cases in
`dstu7624_ecb_self_test()` run ECB with `data_len == block_size`, i.e. plain single-block
encryption, one case per variant per direction (5 variants × encrypt/decrypt). Byte-for-byte diff
(script, not eyeball) against `{128-128,128-256,256-256,256-512,512-512}.json` — all 10 match
exactly. Same relationship as Kupyna's hash above: same official `Kalyna.pdf` vector set UAPKI is
reproducing, not new independent evidence, but it does confirm UAPKI's numbers agree and closes the
"Kalyna self-test not yet cross-checked" line from above **for the single-block case only**.
CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM remain genuinely uncross-checked new data — no Rust mode
of operation exists to run them against yet. CCM/GMAC/GCM specifically stay the live D-05 data
point; left for whenever a mode of operation gets built, not pulled forward ahead of where D-05
already sits in `TASKS.md`.

**Rejected:** treating "fork of Cryptonite" as disqualifying by itself. Rejected because forking
existing code and adding a formal expertise review is a reasonable, common lineage for a
production PKI library, not evidence of low quality — the caveat is about not *overclaiming* what
the review covers, not about excluding the source. Also rejected: keeping the full ~30MB clone.
Pruned for the same reason cryptonite/Bouncy Castle were — this project needs the crypto
primitives, not the ASN.1/PKCS#11/browser-integration layers around them.

## D-17: Reviewed project positioning against UAPKI — no overlap, no scope change

Finding UAPKI (D-16) raised the obvious question directly: is this project reimplementing
something UAPKI already provides? Answer, after reading its actual scope rather than assuming from
the algorithm list: **no — different layer, different language ecosystem, different platform
reach.** Recorded here because the question will come up again (a future contributor, a future
`li0ard`-style "why not just use X" suggestion) and shouldn't need re-researching from scratch.

**What UAPKI actually is**, based on its own README and directory structure (`uapkif` ASN.1 codec,
`cm-pkcs11`/`cm-pkcs12` private-key storage, `uapki` JSON-facing sign/verify/CSR/certificate API,
`hostapp` Chrome/Firefox native-messaging host, `integration/{Android,Java,Browser}` bindings, Diia
test certificates in its fixtures): a **PKI/e-signature application SDK** — the layer above crypto
primitives, aimed at developers building document-signing and government e-service integrations
(matches Ukraine's Diia/e-government signing ecosystem). Its `uapkic` crypto-primitives library
exists to serve that stack, not as a standalone product other projects are expected to depend on.

**What this project is**, per `CLAUDE.md`/`docs/dstu-crypto-project.md` unchanged: a libsodium-style
**crypto-primitives library** — hard, safe, misuse-resistant Kalyna/Kupyna/Strumok/DSTU 4145/DSTU
9041 building blocks in Rust, plus a minimal CLI. No ASN.1, no certificates, no CSR, no browser
integration, no PKCS#11/12 — all of that is explicitly not this project's job.

| Axis | UAPKI | This project |
|---|---|---|
| Abstraction level | PKI application (sign/verify documents, certs) | Crypto primitive (building block) |
| Language / ecosystem | C/C++, bound into Java/Kotlin | Rust, crates.io |
| Platform reach | Full OS only (Win/Linux/macOS/iOS/Android) | + embedded/`no_std` (STM32/ESP32) from day one |
| Audience | E-signature/e-government app developers | Rust developers who need the algorithms themselves |
| DSTU 9041 | **Not implemented** (absent from its own algorithm list) | Planned, currently hard-blocked (no source material) |

**Verdict: the niches don't overlap, they stack** — a PKI SDK like UAPKI could in principle be
*built on* a primitives library like this one; this project could never replace what UAPKI does
without becoming a completely different, much larger product (ASN.1, certificate chains, revocation
checking, browser extension packaging) that's explicitly out of scope. Confirms rather than
undermines the existing "genuinely open niche in the Rust ecosystem" finding in
`docs/dstu-crypto-project.md` "Resources found": if a safe, audited Rust implementation of these
algorithms already existed, a project needing them for a C/C++-native PKI stack like UAPKI would
more likely bind to it via FFI than hand-roll everything in raw C again. That it didn't is
circumstantial evidence the gap is real, not that the space is occupied.

**Phases reviewed for overlap risk, none found:** Phase 2's construction layer
(`crypto_secretbox`/`auth`/`kdf`/`secretstream`/`kx`/`sign`) is libsodium-style thin builders over
the primitives, not PKI functionality. Phase 3's language bindings target the same primitives
UAPKI's own bindings don't expose (UAPKI's Java/Kotlin/Browser bindings bridge its *PKI* API, not
raw Kalyna/Kupyna/Strumok/4145 access) — different purpose even where the target language
overlaps. Phase 4 (STM32/ESP32) has no UAPKI equivalent at all. No task in `TASKS.md` touches
ASN.1, X.509, CSR, PKCS#11/12, or browser signing — nothing needed adjusting.

**Not acted on now, noted for later:** `dstu-core` could someday expose a C ABI, which a PKI stack
like UAPKI could adopt in place of re-implementing primitives in raw C. Purely speculative — no
scope change, no task added, just recorded so it isn't rediscovered as if new.

**Rejected:** treating "an established player already exists" as a reason to reconsider the
project. Rejected because UAPKI operates one layer up and in a different language ecosystem — the
existence of a mature PKI SDK says nothing about whether a safe, `no_std`-capable Rust
implementation of the underlying algorithms is worth having, and the crates.io check (D-06/this
entry) suggests it currently doesn't exist anywhere.

## D-18: Strumok implemented in `dstu_core::hazmat::strumok` — citation and verification status

Ported from `docs/pseudocode/strumok.md` (from-spec, `docs/papers/Strumok.pdf` Sections 2-9),
structurally cross-checked against both `oracles/strumok-dstu8845/strumok.c` (outspace) and
`oracles/uapki/library/uapkic/src/dstu8845.c` (UAPKI), and verified test-first against the
UAPKI-attributed vectors (`crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json`, D-15)
— **all 8 cases pass on the first implementation, `cargo test`/`clippy -D warnings`/`fmt --check`/
`no_std` build/`cargo miri test` all clean.**

**Two things had to be sourced independently of the pseudocode doc, both verified before writing
any Rust:**
- The `T` nonlinear substitution (Section 7) is exactly one Kalyna/Kupyna round's `eta`+`tau`
  applied to a single 64-bit word — confirmed by computing it via the existing
  `hazmat::tables::{SBOXES, MDS_MATRIX, apply_matrix}` (already shared by Kalyna/Kupyna, D-10) and
  diffing all 2048 entries of both oracles' precomputed `T0..T7` tables against that computation,
  byte-for-byte, with a script (not eyeballed). Zero mismatches. This means `T` needed no new
  tables of its own.
- `mul_alpha`/`mul_alpha_inv` (Sections 8-9) belong to a different field construction (GF(2^64) via
  the LFSR's own feedback polynomial) not derivable from the Kalyna/Kupyna tables. Transcribed
  from UAPKI's `mul_T`/`invmul_T` (256 x `u64` each), cross-checked byte-for-byte against
  outspace's `strumok_alpha_mul`/`strumok_alphainv_mul` — same lineage as the D-15 caveat (not
  independent confirmation of correctness by itself), but does confirm transcription accuracy
  across two separately-obtained copies.

**Implemented as a literal 16-word shift register**, not the rotating in-place buffer both oracles
use for throughput. Before writing any Rust, this was verified in a standalone script: implementing
the shift-register form of `Next`/`Strm` per `docs/pseudocode/strumok.md` directly against the
byte-for-byte-transcribed tables above reproduced all 8 UAPKI-attributed keystream vectors exactly.
Chosen over a 1:1 port of the rotating buffer because it is mechanically checkable against the
pseudocode doc's own `Next(S_i, mode)` description without re-deriving the rotated indexing by
hand — lower risk of a silent off-by-one for a first implementation of a primitive with, as of this
writing, no officially-confirmed vectors to catch one.

**Provenance ceiling, unchanged from D-15:** this closes "Strumok has zero vectors, implement
test-first" (`TASKS.md` Phase 1) — it does **not** upgrade the vectors' status. They remain
"UAPKI-attributed, not confirmed against the paid official DSTU 8845:2019 text." If that text is
ever obtained, re-verify against it before calling this primitive "confirmed" the way Kalyna/Kupyna
are worded.

**Rejected:** porting the rotating-buffer/in-place-rotation form 1:1 from the oracle. Rejected for
the reason above (mechanical fidelity to the spec's own description is easier to audit than
mechanical fidelity to a throughput optimization); the two were confirmed equivalent in the
pre-implementation script check, so nothing was lost by choosing the clearer form.

**Rejected:** treating "T can be computed instead of tabulated" as a reason to also compute
`mul_alpha`/`mul_alpha_inv` on the fly instead of tabulating them. Rejected because, unlike `T`,
these have no known reduction to the already-shared Kalyna/Kupyna GF(2^8) arithmetic — the
underlying field polynomial for Strumok's own GF(2^64) tower was never located in
extractable form in `docs/papers/Strumok.pdf` (see `docs/pseudocode/strumok.md`), so the tables
are the practical source, cited accordingly rather than presented as derived from first principles.

## D-19: Table-based S-box lookups are a documented, accepted software-timing exception

`SECURITY.md`'s hard constraints say "No secret-dependent branching or array indexing" without
qualification. Every primitive shipped so far violates the array-indexing half of that literally:
`SBOXES[row % 4][*byte as usize]` (`kalyna.rs`, `kupyna.rs`, `strumok.rs`), `SBOXES_DEC[...]`
(Kalyna decryption), and `MUL_ALPHA`/`MUL_ALPHA_INV[...]` (Strumok) all index a lookup table using
a byte derived from secret key/state material. This was flagged 2026-07-22 while reviewing what
"tested" should mean beyond test vectors (see `TASKS.md` "Testing & hardening") — a real,
previously-undocumented gap between a written constraint and the shipped code, not a hypothetical.

**Decision: accept it, scoped and explicit, rather than silently ship a contradiction.** Rationale:
- This is the same class of exposure as AES's classic T-table/S-box cache-timing attacks (Bernstein
  2005, Osvik/Shamir/Tromer 2006) — well-understood, not a novel risk introduced here.
- `SECURITY.md`'s own threat model already carves out hardware side-channels (SPA/DPA) as
  explicitly out of scope, on the grounds that software constant-time discipline "reduces exposure
  but is not equivalent to... side-channel resistance," which needs a dedicated hardware audit.
  Cache-timing from data-dependent table indices sits in the same family of risk (a
  microarchitectural side channel, not a pure-software timing leak from branching/comparison) —
  treating it identically (documented, not claimed as resistant, not blocking MVP) is consistent
  rather than a special carve-out invented for convenience.
- The alternative — bitslicing or constant-time table lookups (e.g. AES-style bitsliced S-boxes,
  or masked/gather-based lookups) — is a substantial rewrite of every primitive's core substitution
  layer, not a small patch, and would need its own from-spec verification pass per algorithm. Not
  something to take on silently inside a "let's write more tests" pass.

**What this does and does not cover:** this exception is scoped to *table-based substitution
lookups mirroring the DSTU reference implementations themselves* (S-boxes, and Strumok's
`mul_alpha`/`mul_alpha_inv`) — all of which are C oracles that make the identical trade-off, so
this project's exposure is no worse than the reference implementations it's verified against. It
does **not** authorize secret-dependent *branching* (`if`/`match` on secret values) or
secret-dependent *comparison* (still `subtle::ConstantTimeEq`, never `==`, per the unchanged rest
of that constraint) — those remain prohibited without qualification.

**`SECURITY.md` updated to say this precisely** rather than leave the absolute "never" standing
next to code that already violates it — a constraint nobody reads accurately isn't enforcing
anything. If constant-time S-boxes are ever built (e.g. as part of the post-MVP hardware validation
phase, `TASKS.md` Phase 4, where the SPA/DPA question gets a real audit anyway), this exception
narrows accordingly; until then, no test can cleanly catch a timing leak of this kind
(dudect-style statistical tools exist but are noisy and platform-dependent, not a CI gate), so the
documented decision *is* the control, not a missing test.

**Rejected:** leaving the constraint unqualified and treating the violation as an unstated,
undiscussed gap. Rejected because a "hard constraint" that's silently false is worse than a
precisely-scoped one — the whole point of writing these down is so a future contributor (or this
project's own next session) doesn't have to rediscover the contradiction from scratch.

**Future path, sketched 2026-07-22, not scheduled anywhere:** if this exception is ever narrowed,
two known approaches, in increasing order of speed and implementation cost:
- **Masked constant-time select** (simpler): replace `table[secret_byte]` with a full linear scan
  over all 256 entries, selecting the right one via `subtle`-style constant-time comparison/select
  instead of direct indexing — memory access pattern becomes identical regardless of the secret
  byte. Straightforward to implement, but roughly 256x the reads per substituted byte, a real
  throughput cost across `sub_bytes`'s ~`nb*8` bytes/round × up to 18 rounds/block for Kalyna.
- **Bitslicing** (faster, harder): rewrite each S-box as a boolean circuit (AND/OR/XOR/NOT) over
  individual bits, the standard approach for constant-time AES. Complicated here specifically
  because Kalyna/Kupyna have **four** distinct S-boxes, not AES's one — four circuits to derive
  (or one, if the four turn out to be affine-equivalent to each other, unconfirmed as of this
  writing) — and bitslicing is most efficient when batching multiple blocks in parallel, which
  would change the single-block API shape this project currently exposes.
- **Why this is a bigger project than it first looks**, regardless of which approach: (1) four
  S-boxes to handle, not one, plus Strumok's separate `mul_alpha`/`mul_alpha_inv` tables (a
  different field, needing their own treatment); (2) the existing test suite (vectors, proptest,
  differential, fuzz) only proves *functional* correctness — proving actual constant-time behavior
  needs genuinely new tooling (dudect-style statistical timing tests) this project doesn't have
  yet, and that tooling is itself notoriously noisy to trust; (3) this project's platform-agnostic
  promise (`CLAUDE.md` MVP scope) rules out a SIMD-only fast path (e.g. `pshufb`/`vtbl`-based
  lookups, the fastest practical constant-time S-box technique) without also building a portable
  fallback for targets without those instructions, roughly doubling the work. Comparable in scope
  to implementing another primitive from scratch, not a small patch — the natural place for this
  is alongside the post-MVP hardware validation phase (`TASKS.md` Phase 4), not before.

## D-20: `zeroize`/`ZeroizeOnDrop` added — first real dependency, scoped to what's actually live

`SECURITY.md`'s hard constraints require `Zeroize`/`ZeroizeOnDrop` on all key-material types; no
primitive implemented it (`TASKS.md` "Testing & hardening", item added 2026-07-22 while reviewing
what "tested" should mean beyond test vectors). Closed for the two primitives that actually hold
key-derived state right now:

- **`zeroize` 1.9 added to `dstu-core/Cargo.toml`** with `default-features = false, features =
  ["derive"]` — keeps it `no_std`-compatible (no implicit `alloc`/`std` pull-in, confirmed:
  `cargo build --no-default-features` still passes) per this project's platform-agnostic
  requirement (`CLAUDE.md` MVP scope). First real entry in `SECURITY.md`'s supply-chain table,
  which existed as an empty placeholder until now — RustCrypto-maintained, the de facto standard
  for this in the Rust crypto ecosystem, `cargo audit`/`cargo deny` both clean with it added.
- **Strumok**: `hazmat::strumok::Core` (the LFSR/FSM state — `s`, `r0`, `r1`, plus the buffered
  keystream fragment `block`) derives `#[derive(Zeroize, ZeroizeOnDrop)]`. This is genuinely live
  key-derived state for the lifetime of a `Strumok256`/`Strumok512` value, so `ZeroizeOnDrop` (not
  just a manual clear at one call site) is the right fit — it's cleared whenever the value goes out
  of scope, not only after one particular method call. `Strumok256`/`Strumok512` need no `Drop` of
  their own: dropping a newtype struct drops its field, which runs `Core`'s derived `Drop`.
- **Kalyna**: `encrypt_generic`/`decrypt_generic` call `round_keys.zeroize()` (plain `Zeroize`, not
  `ZeroizeOnDrop` — there's no long-lived value to attach `Drop` to, since Kalyna's API is
  stateless static functions per D-13) immediately after the round-key schedule's last use, before
  the function returns. A plain overwrite risks dead-store elimination since the array is about to
  go out of scope anyway; `zeroize()`'s volatile write is specifically what prevents that.
- **Kupyna: intentionally untouched.** `Kupyna256`/`Kupyna512`'s only public API is unkeyed
  `digest(message)` — there is no key material anywhere in the current code to zeroize. This will
  become relevant once KMAC (Kupyna-based MAC, `oracles/uapki/`'s `dstu7564_self_test_kmac`,
  `TASKS.md`'s `crypto_auth` line) is implemented, not before; noted here so its absence reads as a
  deliberate scope boundary, not an oversight.

**Not done in this pass, left as a known follow-up:** Kalyna's *intermediate* key-schedule scratch
buffers (`kt` in `key_expand_kt`, `initial_data`/`tmv` in `key_expand_even`, the byte-flattening
`bytes` buffer in `key_expand_odd`) are not individually zeroized — only the final, complete
`round_keys` array each of them feeds into. Those intermediates hold key-derived material too, for
a shorter stack lifetime each. Going byte-buffer-by-byte-buffer through the key schedule is real
additional hardening, but it's a materially bigger diff across more call sites for a marginal
reduction in an already-small window (stack memory that's about to be overwritten by the next
function call in the common case); scoped out of this pass rather than silently forgotten.

**Rejected:** implementing `Zeroize` by hand (manual overwrite loops) instead of pulling in the
`zeroize` crate. Rejected per `SECURITY.md`'s own existing guidance and this project's "no
homegrown primitives where an established one exists" principle (D-03/D-04's reasoning applies
equally to infrastructure like this, not just algorithms) — hand-rolled zeroing is exactly the
"looks right, isn't" problem the crate exists to solve (compiler dead-store elimination on a plain
overwrite), and reinventing it earns no more scrutiny than reviewing the crate's ~10-year-old,
widely-depended-upon approach.

## D-21: `proptest` round-trip tests added for Kalyna and Strumok

`TASKS.md` "Testing & hardening" flagged that Kalyna has only 2 fixed key/block pairs per variant
(the official vectors) verifying `decrypt(encrypt(x)) == x`, and Strumok's involution property
(`apply_keystream` applied twice with the same key/IV returns the original bytes) had no coverage
beyond the 8 fixed keystream cases. Added as a dev-dependency (`proptest = "1.11"`, dev-only — does
not affect the `no_std` build, confirmed: `cargo build --no-default-features` still passes with no
proptest in the dependency graph at all outside `cargo test`).

- **Kalyna**: `crates/dstu-core/tests/kalyna.rs` — one property test per variant, random key and
  block bytes (via `prop::collection::vec(any::<u8>(), N)`, copied into the fixed-size arrays the
  API takes), asserting `decrypt(encrypt(key, block), key) == block`.
- **Strumok**: `crates/dstu-core/tests/strumok.rs` — random key/IV/data, asserting that applying
  `apply_keystream` twice (two fresh cipher instances constructed from the same key/IV, so the
  keystream is re-derived identically both times) returns the original data.
- **All 16 property tests (256 generated cases each, proptest's default) passed on the first
  attempt** — meaningful signal given `DECISIONS.md` D-18 already noted only 8 fixed points existed
  for Strumok; this exercises a far larger slice of the key/IV/length space without needing any
  new oracle.
- **Kupyna intentionally has no round-trip proptest**: a hash function has no inverse to check
  this way. Its existing `cargo fuzz` target already covers "does it panic on arbitrary-length
  input," which is the property that would matter here instead.

**Rejected:** `prop::array::uniformN` (proptest's built-in fixed-size-array strategies) for the
larger key sizes (64 bytes) — not obviously available for every size this project needs (128/256
covers 16/32 but not the 64-byte keys Kalyna256_512/Kalyna512_512/Strumok512 use). The
`vec(..., N)` + `copy_from_slice` approach works uniformly for every size without depending on
which fixed-size helpers happen to be exported, at the cost of one extra allocation per test case
— irrelevant next to what property testing already costs.

## D-22: Strumok differential-tested against `outspace/dstu8845` over 4000 random cases

`TASKS.md` "Testing & hardening" flagged Strumok as the highest-value target for differential
testing specifically: no official DSTU 8845:2019 vectors exist anywhere (D-15), and the 8
UAPKI-attributed fixed vectors adopted so far cover a narrow slice of the key/IV/length space.

**What was built**, two pieces, same split as the existing Java/.NET oracle harnesses (Rust
generates/computes, an external tool independently recomputes and diffs) — not wired into
`cargo test` itself, so a plain `cargo test` still needs no C toolchain:
- `crates/dstu-core/examples/strumok_diff_cases.rs` — a `cargo run --example` binary. Deterministic
  `splitmix64` PRNG (fixed seed; not cryptographic, doesn't need to be — this only needs varied
  inputs, not unpredictable ones), generates random key/IV/length triples for both key sizes, runs
  them through this project's own `Strumok256`/`Strumok512`, and prints
  `<variant> <key_hex> <iv_hex> <keystream_hex>` lines.
- `tests/oracle-harness/strumok-differential/diff_against_outspace.c` — reads those lines, decodes
  hex, recomputes the keystream independently via `oracles/strumok-dstu8845/` (outspace)'s own
  `dstu8845_init`/`dstu8845_crypt`, and reports any byte mismatch plus a final count. Build/run
  command is in the file's own header comment (same convention as the sibling
  `strumok-cross-check/` harness).

**Result: 4000/4000 cases matched** (2000 iterations × 2 key sizes), zero mismatches, on the first
run after fixing one harness-only bug (a zero-length case's empty `keystream_hex` field confused
the C driver's `sscanf`-based line parser — fixed by generating length `1..=300` instead of
`0..=300`, since the zero-length case is already covered by the `chunk_invariance` unit tests in
`tests/strumok.rs`; not a crypto bug, a test-harness parsing limitation).

**Same lineage caveat as D-15 applies**: outspace and UAPKI share internal naming/structure, so
this is not *independent* confirmation the way a Bouncy-Castle-style differential test would be —
but it does exercise vastly more of the key/IV/length state space than 8 fixed points, catching the
class of bug (a subtle indexing/off-by-one that only misbehaves for specific inputs) that fixed
vectors alone might miss.

**Scoped to Strumok only, not Kalyna/Kupyna, deliberately:** those two already carry two layers of
dual-oracle verification (official vectors + real Bouncy Castle via the Java/.NET harnesses,
`DECISIONS.md` D-10/D-13) — a random-input differential test there is the same *pattern* but with
much lower marginal value than for Strumok, which had the least verification coverage of the
three. Extending this same generator+differ split to `oracles/kalyna-reference/`/`cryptonite` and
`oracles/kupyna-reference/` is a straightforward follow-up if ever prioritized, not a gap being
hidden — noted in `TASKS.md`.

**Rejected:** wiring this into `cargo test`/CI directly. Rejected because it would make the
ordinary test suite depend on a C toolchain being present, which none of the vector/proptest/fuzz
tests currently require — same reasoning that already keeps the Java/.NET oracle harnesses as
separate `cargo xtask` targets rather than folded into `cargo test --workspace`.

## D-23: `criterion` benchmarks added for all three primitives

Last item in `TASKS.md` "Testing & hardening". `criterion` 0.8 added as a dev-dependency, three
bench targets (`crates/dstu-core/benches/{kalyna,kupyna,strumok}.rs`, `cargo bench -p dstu-core`),
covering every Kalyna variant's `encrypt`/`decrypt`, both Kupyna sizes' `digest` at a few message
lengths, and both Strumok sizes' `apply_keystream` at a few buffer lengths.

**Scoped to absolute throughput + regression tracking, not the shift-vs-ring-buffer comparison
that motivated this item in the first place.** Quantifying D-18's literal-16-word-shift-vs.
rotating-in-place-buffer tradeoff for Strumok properly would mean implementing the ring-buffer
form here too, purely to benchmark it — a second implementation to maintain for a number, not
proportionate to what this pass is for. The benchmark instead reports Strumok's own absolute
throughput and says so plainly in its own doc comment, rather than implying a comparison that
wasn't actually made. `std::hint::black_box` used throughout (not `criterion::black_box`, which is
deprecated in the version pulled in) to prevent the optimizer from eliding the benchmarked calls.

This closes every item in `TASKS.md` "Testing & hardening" except "actually run `cargo fuzz`",
which stays open pending CI or a machine with the MSVC toolchain (D-22's sibling finding, not a
gap in this entry).

**Baseline numbers, the comparison against Oliynykov's reference C / UAPKI / outspace, the machine
they were measured on, and the saved `criterion --baseline` for regression tracking all live in
`PERFORMANCE.md`** (added 2026-07-22) — the canonical home for this project's performance data, so
it doesn't rot as a one-time paragraph here. Headline finding, in one line: this project's Rust is
faster than the designers' own reference C (correctness/clarity-optimized, not speed) but
meaningfully slower than UAPKI (a production-optimized real-world library) and outspace's Strumok —
a real, known, and non-blocking gap, not a mystery; see `PERFORMANCE.md` "What the gap is, honestly"
for the specific causes and what closing it would take.

## D-24: Kalyna and Kupyna differential-tested too, for parity with Strumok (D-22)

D-22 explicitly scoped random-input differential testing to Strumok only, reasoning that Kalyna
and Kupyna already carry two verification layers (official vectors + real Bouncy Castle) so the
marginal value would be lower. Raised back for a second look: leaving only Strumok
differential-tested reads, from the outside, as "why was Strumok singled out for this much
scrutiny and not the other two" — a fair question to pre-empt rather than leave for someone else to
ask later, even though the original reasoning about marginal *verification* value still holds.
Closed the gap so the effort is visibly even across all three, not just the justification for it.

Same two-piece split as D-22 (Rust generates cases + its own output via `cargo run --example`, a C
driver independently recomputes and diffs — not wired into `cargo test`):

- **Kalyna**: `crates/dstu-core/examples/kalyna_diff_cases.rs` + `tests/oracle-harness/
  kalyna-differential/diff_against_reference.c`, against `oracles/kalyna-reference/` (Roman
  Oliynykov, the algorithm's own author). **2500/2500 random cases matched** (500 per variant × 5
  variants), 0 mismatches, first run clean.
- **Kupyna**: `crates/dstu-core/examples/kupyna_diff_cases.rs` + `tests/oracle-harness/
  kupyna-differential/diff_against_reference.c`, against `oracles/kupyna-reference/` (same
  authors). **2000/2000 random cases matched** (1000 per variant × 2 sizes), 0 mismatches — after
  fixing one harness-only bug: the C driver's fixed-size line buffer was sized for `message_hex`
  alone (`MAX_MESSAGE_BYTES*2 + 64`) and didn't leave room for the trailing `hash_hex` field too,
  so `fgets` silently truncated the longest lines and desynced the following read — not a crypto
  bug, caught and fixed by sizing the buffer for both fields.
- **Kalyna's harness reuses the byte-packing convention already established for the Strumok
  harness** (raw little-endian `memcpy` onto `uint64_t[]`, confirmed against
  `oracles/kalyna-reference/main.c`'s own vector layout). **Kupyna's oracle API takes raw bytes +
  a bit-length directly** (`KupynaHash(ctx, data, msg_nbits, hash)`), needing no word-packing at
  all — the simplest of the three harnesses to write.

**Same "not independent, still useful" framing as D-22**: `kalyna-reference`/`kupyna-reference`
are Roman Oliynykov's own reference C code, the same lineage Bouncy Castle's `DSTU7624Engine.java`/
`DSTU7564Digest.java` port from (`oracles/README.md`'s "Correction on provenance" note) — so this
doesn't add a *new* independent oracle, it re-exercises the existing one over far more of the
input space than the fixed vectors alone. The real, independent second reading for these two
remains the Java/.NET Bouncy Castle harnesses, unchanged by this entry.

**Not extended to Kalyna's decrypt direction or to a Kalyna/Kupyna round-trip check** in this
differential harness specifically — encrypt-only for Kalyna, hash-only for Kupyna (there's no
"decrypt" for a hash). Round-trip correctness for Kalyna is already covered separately by the
`proptest` round-trip tests (D-21); duplicating that inside the differential harness too would
add C-side complexity for a property already verified in Rust.

## D-25: DSTU 4145 GF(2^163) arithmetic — unit-level vectors, and a branchless posture decided up front

Starting the actual Rust port (`TASKS.md` Phase 2): the GF(2^m)/EC arithmetic layer, not the
signature logic, is the real prerequisite here, and its correctness is the highest-risk part of
this whole project so far (nothing here has a DSTU clause to cite — the standard specifies the
curve/signature, not an internal field-arithmetic algorithm — so every algorithmic choice below
is a reference-implementation citation, same model as D-13/D-18).

**Unit-level test vectors, generated (not dual-sourced).** `gf2m163.json` (D-14) only has
signature-level values (final `r`, `s`) — nothing at the granularity of one field multiplication
or one point doubling, so it can't test-first the arithmetic layer on its own. Added
`crates/dstu-core/tests/vectors/dstu4145/gf2m163_arith.json`, generated by
`tests/oracle-harness/java/src/main/java/Dstu4145VectorGen.java` against the same curve/base-point/
order already in `gf2m163.json`, exercising Bouncy Castle's own `ECFieldElement.F2m`/`ECPoint.F2m`
directly (field add/multiply/square/invert; point double/add; scalar multiply) and freezing the
output. **Single-oracle at this level** — BC is the sole source of truth here, not cross-checked
against the official text the way `gf2m163.json` is. Documented as such rather than overclaimed;
the signature-level vector remains the dual-sourced end-to-end check once the arithmetic lands.

**Branchless posture, decided before writing inversion or scalar multiplication, not after.**
`SECURITY.md`'s "no secret-dependent branching" is unqualified here — D-19 carved out table
*indexing* only and explicitly reaffirmed branching/comparisons stay prohibited. The classic
reference algorithms both BC and OpenSSL actually ship — extended-Euclidean/binary-GCD inversion,
double-and-add scalar multiplication — branch directly on secret bits (OpenSSL's binary-curve code
has had real CVEs for exactly this class of leak). Porting either as-is would silently violate the
hard constraint, and retrofitting constant-time behavior after the fact means rewriting the whole
module, not patching it — so this was decided as a posture up front (confirmed with the project
owner) rather than discovered as a bug later:

- **Reduction** (`x^163 + x^7 + x^6 + x^3 + 1`): adapted from OpenSSL's `BN_GF2m_mod_arr`
  (`crypto/bn/bn_gf2m.c`, fetched and read directly from source, not from a summary — see
  `docs/pseudocode/dstu4145.md`) — same per-word shift/XOR structure, but its two data-dependent
  shortcuts (`if (word == 0) skip`, `while (...) if (overflow == 0) break`) are removed: every
  source word is always reduced unconditionally, and the final-round cleanup step always runs a
  fixed 2 extra passes rather than looping until convergence. Harmless once fully reduced (XORing
  zero changes nothing), so this only costs a few redundant word ops, not correctness.
- **Inversion**: Itoh–Tsujii (`a^(2^m-2)` via a fixed square/multiply addition chain) rather than
  extended-Euclidean/binary-GCD — built entirely from the multiply/square/reduce above, fixed
  control flow regardless of `a`'s value, no new primitive needed.
- **Scalar multiplication**: Montgomery ladder with constant-time conditional swap, rather than
  double-and-add — needed for both `e·G` (secret ephemeral during signing) and, per the same
  posture, applied uniformly rather than carved out only where a value happens to be secret.

**Rejected:** a faster non-constant-time first pass (direct BC/OpenSSL transcription), deferring
the branchless rewrite to later. Rejected because this is exactly the kind of decision that's cheap
to make correctly up front and expensive to retrofit — same reasoning `SECURITY.md` already applies
elsewhere, and the project owner confirmed this explicitly rather than leaving it to be inferred
from D-19's narrower table-lookup exception.

**Point arithmetic landed the same day**, in `dstu_core::hazmat::dstu4145::curve163`, following
through on the posture above:

- `Point::double`/`Point::add` are plain affine formulas (`Guide to Elliptic Curve Cryptography`
  §3.1.2) with ordinary `==` branches — deliberately **not** constant-time, because both are
  reserved for the verification path (`s·G + r·Q`), where every operand (`s`, `r`, `Q`, `G`) is
  public. Documented in the module as public-data-only, not a silent gap.
- `Point::scalar_multiply` is the one function touching secret scalars (signing's ephemeral `e`),
  built from Algorithm 3.40 (Montgomery's method for binary curves, López–Dahab/Montgomery,
  X/Z-projective, same textbook) — with two adaptations, both required to actually meet the
  branchless bar rather than just gesture at it:
  - The textbook version starts from `(P, 2P)` and loops only down to `k`'s *actual* highest set
    bit — a loop bound that leaks the scalar's bit-length. Adapted to start from `(Infinity, P)`
    (`Z = 0` representing infinity; doubling/adding into it algebraically stays at `Z = 0` under
    the same formulas — checked by hand and confirmed empirically, see below) and always run a
    fixed 163 iterations, so leading zero bits cost nothing extra and leak nothing about where the
    real top bit is.
  - Each iteration's `if k_i == 1 {...} else {...}` (the textbook's two symmetric formulas) is
    replaced with: conditional swap (branchless XOR/mask, not a real branch) of the two (X, Z)
    pairs based on the bit, run the single "`k_i == 1`" formula unconditionally, swap back. Same
    operations every iteration regardless of the bit.
- **Verified**: unit-level vectors (same `gf2m163_arith.json` as above, BC's `ECPoint.F2m` as the
  single oracle) for `double`, `add`, and `scalar_multiply` against the generator — all passed
  first try. Additionally cross-checked `scalar_multiply` for `k = 1..=32` against repeated
  `Point::add`, specifically to exercise the leading-zero-bits path the random 163-bit vectors are
  unlikely to hit — also passed first try, empirically confirming the infinity-starting adaptation
  above.
- **Not yet covered**: the other 9 curve sizes (only m=163 exists); the DSTU 4145 sign/verify
  logic itself, which is the next layer up (`TASKS.md` Phase 2).

**Sign/verify landed the same day too**, in `dstu_core::hazmat::dstu4145::{scalar, signature}`:

- `scalar::Scalar` is a **deliberately distinct type** from `gf2m163::FieldElement`, even though
  both are `[u64; 3]` internally — `Scalar` arithmetic is ordinary carrying integer arithmetic
  reduced mod the curve order `n` (`Scalar::add` is real addition, `Scalar::multiply` is a real
  carrying multiply + a fixed-iteration restoring-division reduction, both branchless since
  `Scalar` carries the private key `d` and ephemeral `e`), while `FieldElement` arithmetic is
  carryless/XOR mod the field's reduction polynomial. Flagged as the layer's single biggest
  silent-correctness risk before writing it (accidentally calling field ops on a scalar compiles
  fine and is silently wrong) — kept separate specifically to make that class of bug impossible
  rather than documented-and-hoped-against.
- `signature::verify`/`signature::sign` transcribe the pseudocode doc directly.
  `hash_to_field`/`truncate` (the `hash2FieldElement`/`truncate` pseudocode steps) are built to
  avoid needing heap allocation for an arbitrary-length hash. `sign` takes the ephemeral `e` as an
  explicit caller-supplied parameter (no forced RNG, same as every other `hazmat` primitive) and
  returns `Option` — `None` on any of the pseudocode's three degenerate-value rejections (`F_e`,
  `r`, or `s` landing on zero, each ~`2^-163` probability, the same accepted-exception class as
  ECDSA's nonce-rejection loops) — since `hazmat` cannot generate a replacement `e` itself, the
  caller must retry with a fresh one.
- **Verified against `gf2m163.json`** (the official Annex B.1 worked example, dual-sourced per
  D-14) — both directions: `verify` accepts the vector's `(r, s)`, and `sign` with the vector's
  *pinned* ephemeral `e` reproduces `(r, s)` exactly. This is the first genuinely dual-sourced check
  (not single-BC-oracle) for anything built on this arithmetic. **Two real bugs found and fixed
  while getting this to pass**, both worth recording so they don't get silently rediscovered:
  - **`Q = -d·G`, not `d·G`.** Found by the round-trip property test below (the fixed vector alone
    never exercises key derivation — it uses a pre-computed `Q`). Confirmed against
    `oracles/bouncycastle-java/.../DSTU4145KeyPairGenerator.java`, which explicitly negates
    (`pub.getQ().negate()`) after the generic EC keypair generator computes the point — not a test
    artifact, and not optional: substituting `s = (r·d + e) mod n` into `R = s·G + r·Q` only
    collapses back to `e·G` (the identity `verifySignature` checks) when `Q = -d·G`. **Confirmed a
    second time, more strongly, once the official text was actually read** (see below): §9.2 states
    `Q = -dP` in as many words, not something inferred from BC's code. This was wrong in
    `docs/pseudocode/dstu4145.md` until this fix (said `Q = d·G` plainly) — corrected there too, per
    that doc's own "flag discrepancies inline" convention. Added `Point::negate` (`(x, y) ->
    (x, x+y)`, the standard char-2 negation for this curve family) to `curve163` to let callers
    derive `Q` correctly.
  - **`hash_to_field` had the wrong algorithm, not just a byte-order footgun.** First patched by
    having the *test* manually reverse the hash before calling `verify`/`sign` — that made the KAT
    pass, but was compensating for a real bug in `hash_to_field` itself, discovered once §5.9 was
    actually read (see the re-derivation entry right below): the function should take the hash's
    own **last** bytes directly, no reversal anywhere, matching the official text's literal
    algorithm. The earlier "reverse the whole hash first" version was a direct copy of Bouncy
    Castle's `hash2FieldElement`, which does reverse its input — but that's BC's own documented
    parameter convention (its `hash` argument is expected pre-reversed relative to §5.6's bit-string
    convention; `DSTU4145Test.test163()` manually reverses its literal before calling the signer for
    exactly this reason), not part of the algorithm. This project's port had copied BC's internal
    reversal without also adopting BC's reversed-input convention, so it only produced correct
    output when its *own* caller manually reversed the hash too — an undocumented requirement that
    happened to cancel out against how `test163()` builds its own input, hiding the bug until an
    early draft of this project's test fed the vector's hash straight through. Fixed to implement
    §5.9 directly; the manual reversal was removed from the test entirely (see the pseudocode
    doc's own account of this, which is more detailed than this entry — not duplicated further
    here).
- **Property-tested**: `sign`/`verify` round-trip over random 160-bit `d`/`e` and random 32-byte
  hashes (`proptest`, same convention as D-21) — this is what caught the `Q` bug above; it failed
  on the very first run, shrunk to a clean minimal case (`d = e = 1`, all-zero hash), fixed, then
  passed. Random `d`/`e` are generated at 160 bits (comfortably below `n`) rather than up to the
  full 163 bits, so the test doesn't also need its own mod-`n` reduction step — an intentional
  scope cut, not a coverage gap the fixed vectors don't already close near `n`'s actual magnitude.

**`docs/pseudocode/dstu4145.md` re-derived from the official text the same day, closing the last
open TASKS.md item for this pass.** Read Sections 5, 9, 11-13 directly (rendered PDF pages, no text
layer — see `.claude.local.md`) rather than continuing to rely on the Bouncy Castle transcription.
Both bugs above were caught *because* of this re-derivation, not before it — the `Q` sign was
already fixed from the BC-code angle, but reading §9.2 directly gave a strictly stronger citation
(the standard's own words, not an inference from a reference implementation's behavior); the
`hash_to_field` algorithm bug was found *only* by reading §5.9, since nothing about the BC-derived
pseudocode or the passing-via-workaround test gave any reason to suspect it. §7.1's Table 1 of
recommended fields also confirms `x^163+x^7+x^6+x^3+1` (this project's `gf2m163::FieldElement`'s
reduction polynomial) is the standard's own first-listed m=163 field, not just a BC/UAPKI
convention. Sections 6, 7, 8, and Annex A (auxiliary algorithms, domain-parameter generation and
validation, the standard's own RNG) were read but not transcribed in detail — none are needed for
sign/verify against an already-fixed, already-validated curve, which is all this project does so
far; noted as future scope in the pseudocode doc rather than silently dropped.

**Not yet done**: the other 9 curve sizes (not needed unless a use case calls for them).

## D-26: Strumok switched from a shifting state array to a ring buffer, and to precomputed T-tables

`PERFORMANCE.md` (D-23's follow-up) quantified a real, root-caused gap to UAPKI/outspace for
Strumok specifically — two distinct, additive causes found by reading `oracles/strumok-dstu8845
/strumok.c` directly: (1) `next_step` shifted the whole 16-word state array
(`s.copy_within(1..16, 0)`) every step, a real 120-byte move outspace's fully-unrolled
`next_stream()` never does; (2) `t_function` computed the `T` substitution at runtime (8 S-box
lookups + a full `GF(2^8)` MDS matrix-multiply via `apply_matrix`/`gf_mul`) instead of 8
precomputed combined tables the way outspace's `T0..T7` do.

**Both fixed 2026-07-22, sketched as a `TASKS.md` item first, then implemented the same day**:

- `next_step`/`strm` now take a `head: usize` index into the same fixed `[u64; 16]` array instead
  of shifting it. Logical `S[k]` lives at physical index `(head + k) & 15`; each step overwrites
  physical index `head` with the new feedback value (the slot holding old `S[0]` is exactly the
  slot that becomes new `S[15]` once `head` advances — verified algebraically, same reasoning as
  the ladder's infinity-start argument in D-25) and advances `head` by one. No data movement.
- `t_function` now does `T0[byte0] ^ T1[byte1] ^ ... ^ T7[byte7]`, 8 lookups. `T0..T7` are
  transcribed directly from `oracles/strumok-dstu8845/strumok.c` — the exact same byte-for-byte
  cross-check already established when the runtime version was first written (computing `T` via
  `hazmat::tables` and diffing all 2048 entries against these same oracle tables) already covers
  them, so no new verification work was needed to trust the transcription itself, only to confirm
  the *wiring* is correct (below).

**Verified**: all 6 existing tests pass unchanged (official UAPKI-attributed vectors, chunk-
invariance, involution `proptest`), plus the outspace differential harness re-run fresh —
4000/4000 matched, same as before this change. `cargo clippy -- -D warnings`, `cargo fmt --check`,
and the `no_std` build all still pass.

**Result**: ~77-85% reduction in `apply_keystream` time across all measured buffer sizes (`cargo
bench -- --baseline initial-2026-07-22`) — e.g. at 64 KB, both key sizes went from ~144-146 MB/s to
~639-640 MB/s, which now *beats* UAPKI's Strumok (~557-589 MB/s) and closes most (not all) of the
gap to outspace (~2055-2132 MB/s, still ahead — likely a remaining implementation-detail
difference not chased further here). New baseline saved as
`strumok-optimized-2026-07-22`; `PERFORMANCE.md` has the full before/after table.

**Not done in this pass**: the equivalent combined-table optimization for Kalyna/Kupyna
(`hazmat::tables`, shared between them) — same category of work, sketched in the same `TASKS.md`
item, bigger surgery since it touches both algorithms' round functions and Kalyna's decrypt
direction too. Next in line, not started yet.

## D-27: Kalyna/Kupyna's shared `apply_matrix` switched to precomputed MDS tables

Follow-up to D-26, same day: `PERFORMANCE.md` showed Kalyna/Kupyna meaningfully slower than UAPKI,
root-caused to `hazmat::tables::apply_matrix` computing every `GF(2^8)` multiplication via
`gf_mul` at call time (up to 64 calls per column) where UAPKI's `p_boxrowcol` uses a combined
lookup table instead.

**Narrower scope than Strumok's T-table fix, deliberately**: Kalyna's round order is
`sub_bytes -> shift_rows -> apply_matrix` (eta, then pi, then tau) - `shift_rows` moves S-boxed
bytes *across columns* before the MDS step, so S-box and MDS can't be folded into one lookup the
way Strumok's `T(w)` could (Strumok has no analogous cross-column permutation in its `T`
substitution). Scoped this pass to just `apply_matrix` itself, which both Kalyna *and* Kupyna
already share via `hazmat::tables` (D-13) - one fix, both algorithms benefit, no need to touch
`sub_bytes`/`shift_rows` or risk the S-box+shift+MDS full fusion UAPKI does.

**`MDS_TABLE`/`MDS_INV_TABLE`** (`[[u64; 256]; 8]` each): `MDS_TABLE[in_row][byte]` is the 8-byte
column (packed as one `u64`) that a single byte sitting at input row `in_row` contributes to
`MDS_MATRIX * column` - `apply_matrix` becomes 8 table lookups + 7 XORs per column instead of 64
`gf_mul` calls. **Generated, not hand-transcribed**: a one-off Python script computed both tables
directly from this file's own `gf_mul`/`MDS_MATRIX`/`MDS_INV_MATRIX` (already verified, D-13),
then cross-checked the table-based result against the original loop-based computation over 2000
random columns (0 mismatches) before the generated file was ever written - correctness rests on
the pre-existing, already-verified `gf_mul` and matrices, not a new external source.

**A permanent, exhaustive regression test was added, not just the one-off Python check**:
`hazmat::tables::tests::{mds_table,mds_inv_table}_matches_gf_mul_exhaustively` checks all
`8 x 256` entries of both tables against `gf_mul` directly, every time `cargo test` runs - this is
also why `gf_mul`/`MDS_MATRIX`/`MDS_INV_MATRIX` are still in the source with `#[allow(dead_code)]`
even though no production code path calls them anymore: they're the independent reference these
tests check the fast tables against, not leftover dead weight. (`cargo clippy`'s default invocation
doesn't build `#[cfg(test)]` code, hence the explicit `allow` rather than relying on test usage to
suppress the warning.)

**Verified**: both exhaustive unit tests pass; all existing Kalyna official vectors + `proptest`
round-trips + Kupyna official vectors unchanged; the Kalyna and Kupyna differential harnesses
against Oliynykov's reference C re-run fresh (2500/2500 and 2000/2000, same as D-24). `clippy`,
`fmt`, and the `no_std` build all still pass.

**Result**: ~48-55% time reduction for every Kalyna variant/direction, ~60-65% for Kupyna
(`cargo bench -- --baseline initial-2026-07-22`) — e.g. Kalyna-128-128 encrypt 4.6 µs -> 2.35 µs;
Kupyna-256 at 64 KB, 5.85 -> 14.57 MB/s. Closes roughly half the gap to UAPKI (Kalyna-128-128:
was ~20.7x slower than UAPKI, now ~10.6x; Kupyna-256 at 1 KB: was ~16.9x, now ~6.7x) — doesn't
close it entirely, since UAPKI's `p_boxrowcol` folds the row/column permutation in too, which this
pass deliberately didn't attempt (see "narrower scope" above). New `criterion` baseline saved as
`kalyna-kupyna-optimized-2026-07-22`; `PERFORMANCE.md` has the full before/after table.

**Not done**: fusing `sub_bytes`/`shift_rows` into the combined table too (UAPKI's full
`p_boxrowcol` approach) - would need per-`nb` tables (Kalyna's row-shift offset depends on block
size, unlike Strumok's fixed 16-word state), a bigger and more invasive change than this pass's
"one shared function, both algorithms benefit" scope. Sketched as a possible further step, not
scheduled.

## D-28: Full S-box+shift+MDS fusion for Kalyna encrypt + Kupyna - correcting D-27's stated blocker

Follow-up to D-27, planned 2026-07-22 (`TASKS.md`), implemented the same day. D-27 assumed full
fusion needed per-`nb` tables because Kalyna's row-shift offset depends on block size - **this was
wrong**. `sub_bytes` substitutes per row; `shift_rows`/Kupyna's `shift_bytes` permute *columns*
while preserving row. The two operations therefore commute (substituting a byte then moving it to
column `(col + shift) % nb` gives the same result as moving it first, then substituting), so the
combined table `SBOX_MDS[row][byte] = MDS_TABLE[row][SBOXES[row % 4][byte]]` doesn't depend on `nb`
at all - one shared table, computed by the compiler at build time (`const fn build_sbox_mds`,
composing the two already-verified tables directly - no hand transcription, no generation script,
no new correctness risk beyond `SBOXES`/`MDS_TABLE` themselves). The `nb`/`columns` dependence
lives entirely in the *gather index* used by the caller: for output column `out_col`, row `row`'s
contribution comes from input column `(out_col + nb - shift) mod nb` - cheap arithmetic on the
already-existing `nb`/`shift` variables, not a table.

**Scope, this pass**: the forward direction only - Kalyna's `encipher_round` (used by encrypt *and*
by the key schedule's `round_key_from`/`key_expand_kt`, so both benefit) and Kupyna's new
`sub_shift_mix` (replacing `sub_bytes -> shift_bytes -> mix_columns` in both `t_transform` and
`t_plus_transform`; Kupyna's round-constant add stays an untouched pre-step, since `add_round_
constant_add`'s mod-2^64 add can carry across the whole word and doesn't commute with a per-byte
gather the way XOR-based operations do). Kalyna's *decrypt* direction (`decipher_round`) is
deliberately left as D-27's three-pass form in this same commit - `inv_sub_bytes` runs *last*
in the existing decrypt round, not first, so it can't fuse the same direct way; a follow-up entry
covers whether/how that gets addressed.

**Correctness-critical fix found during implementation, not anticipated in the plan**: the first
working version computed the gather index with `%` (`(out_col + nb - shift) % nb`). Since `nb` and
`columns` are runtime values (not compile-time constants), LLVM cannot prove they're powers of two
and emits a real integer-division instruction per byte gathered - this alone made Kupyna's first
fused version **5-8% *slower*** than pre-fusion D-27, despite doing genuinely less work per round.
Both `nb` (2/4/8) and Kupyna's `columns` (8/16) are *always* powers of two by construction (the
DSTU 7624/7564 variant table has no other block sizes), so `% nb` was replaced with `& (nb - 1)`
(`debug_assert!(nb.is_power_of_two())` documents the invariant the bitmask relies on) - this one
change was the difference between a regression and the result below. Lesson for future table/index
work in this codebase: a runtime modulo by a value that's *always* a power of two in practice is
not free just because the divisor happens to be one - the compiler needs to be told, or it emits
the general case.

**Verified**: two new `proptest` suites (`hazmat::kalyna::fused_round_tests`, `hazmat::kupyna::
fused_round_tests`) checking the fused round against a kept-for-this-purpose naive three-pass
reference (`sub_bytes`/`shift_rows`/`shift_bytes`/`mix_columns`, now `#[allow(dead_code)]` in
production, same "kept as the independent reference" pattern as D-27's `gf_mul`/`MDS_MATRIX`) across
random states for every `nb`/`columns` value; a new exhaustive `hazmat::tables::tests::sbox_mds_
matches_gf_mul_and_sbox_exhaustively` test; all existing official vectors, `proptest` round-trips,
and both Oliynykov differential harnesses re-run fresh (12500/12500 Kalyna cases including decrypt
round-trips, 4000/4000 Kupyna cases - bit-identical, confirming the decrypt path is unaffected).
`clippy`, `fmt`, and the `no_std` build all pass.

**Result** (`cargo bench -- --baseline kalyna-kupyna-optimized-2026-07-22`, full table in
`PERFORMANCE.md`): Kalyna encrypt **-55% to -68%** further reduction (e.g. 128-128: 2354 ns -> 1041
ns; 512-512: 12735 ns -> 4006 ns) - decrypt also improved **-36% to -40%** purely from the faster
key schedule sharing `encipher_round`, even though `decipher_round` itself is untouched. Kupyna
improved **-85% to -87%** (e.g. Kupyna-256 at 64 KB: 14.57 -> 98.6 MB/s). Against UAPKI: Kalyna is
now **~3.4-4.9x slower** (was ~10.6-14.5x after D-27) with key-schedule caching (`TASKS.md` stage 3,
not done yet) still to come; **Kupyna is now at or above UAPKI's own speed** (256: 1.03-1.45x
*faster*; 512: 0.93-1.45x, roughly at parity) - both far beyond this task's original "2-3x of
UAPKI" expectation, because the actual dominant cost turned out to be the runtime-modulo bug above,
not an inherent limit of the fused-table approach. New baseline: `kalyna-kupyna-fused-2026-07-22`.

## D-29: `ExpandedKey` types added for Kalyna - cache the round-key schedule across calls

Follow-up to D-28, same day (`TASKS.md` D-28 stage 3, user's explicit go-ahead to make this an
API-shape change rather than deferring it - see the session's `AskUserQuestion` exchange). A
temporary internal diagnostic (`std::time::Instant`, not committed) confirmed `key_expand` was
~60% of Kalyna-128-128's and ~79% of Kalyna-512-512's per-call `encrypt`/`decrypt` time even after
D-28's fusion - the raw `encrypt`/`decrypt` functions redo the full key schedule on every single
call, which is fine for a one-off block but means any caller encrypting many blocks under the same
key (the common case, and the only case a future mode of operation, D-05, would ever have) pays for
the schedule every time for no reason.

**Shape**: one `${Variant}ExpandedKey` struct per variant (`Kalyna128_128ExpandedKey`, etc.),
generated by the same `kalyna_variant!` macro that already generates each variant's unit struct -
`::new(key)` runs `key_expand` once and stores the result (`#[derive(Zeroize, ZeroizeOnDrop)]`,
same D-20 pattern as the raw functions' one-shot schedule, just held for the struct's lifetime
instead of zeroized immediately); `.encrypt_block(block)`/`.decrypt_block(block)` reuse the cached
schedule, no `key_expand` call. The raw `encrypt`/`decrypt` functions are untouched and still exist
as the one-shot convenience path - `encrypt_generic`/`decrypt_generic` were refactored to call new
shared helpers (`encrypt_with_schedule`/`decrypt_with_schedule`, taking an already-expanded
schedule) so the exact same round logic backs both the raw functions and `ExpandedKey`, not two
parallel implementations that could drift apart.

**Verified**: new `proptest` suites (`kalyna_*_expanded_key_matches_raw`: `ExpandedKey`'s
encrypt/decrypt agree with the raw functions for every random key/block, not just typical ones;
`kalyna_*_expanded_key_reused`: multiple blocks encrypted/decrypted from one `ExpandedKey` all
round-trip correctly, catching any accidental mutation of the cached schedule between calls). The
Kalyna differential harness against Oliynykov re-run fresh (7500/7500, bit-identical) - the
underlying round logic didn't change, only how the schedule is threaded through, so this is a
belt-and-suspenders re-check, not new risk surface. `clippy`/`fmt`/`no_std` all pass.

**Result**: a new bench variant (`benches/kalyna.rs`, `*_encrypt_block_only`/`*_decrypt_block_only`,
key expanded once outside `b.iter`) gives the honest split `TASKS.md` stage 0 asked for -
`kalyna_128_128_encrypt_block_only` is **133 ns**, i.e. *faster than UAPKI's 222 ns* for the
schedule-cached case; `kalyna_512_512_encrypt_block_only` is 568 ns vs UAPKI's 879 ns, also faster.
**Decrypt-block-only is 3.2-6.9x slower than encrypt-block-only** (e.g. 512-512: 568 ns encrypt vs
3934 ns decrypt) - this was already visible before `ExpandedKey` (D-27/D-28 never fused the decrypt
round) but is now the single largest remaining gap, since encrypt (with a cached key) has
essentially closed the distance to UAPKI. New baseline: `kalyna-expandedkey-2026-07-22`.

## D-30: Kalyna decrypt round fused too - equivalent-inverse-cipher restructuring

Follow-up to D-28/D-29, same day (`TASKS.md` D-28 stage 4, the item both those entries deferred as
"the fiddly inverse direction"). D-29 left decrypt as the single largest remaining gap to UAPKI
(decrypt-block-only 3.2-6.9x slower than encrypt-block-only). The reason D-28's direct table-fusion
trick doesn't apply to decrypt: the existing `decipher_round` order is mix-then-permute-then-
substitute (`apply_matrix(MDS_INV)` first, `inv_sub_bytes` last) - the *opposite* of encrypt's
substitute-then-permute-then-mix, so there's no single raw byte to feed a combined lookup table
before it gets linearly mixed with 7 others.

**The fix regroups the *whole* decrypt sequence, not just one round, using two identities**:
`IS`/`IP` (inverse-S-box, inverse-shift-rows) commute (same row-invariance fact D-28 already
relies on: substitution is row-indexed, the permutation only moves columns); and `IM` (the
GF(2^8)-linear inverse-MDS mix) distributes over XOR, so `IM(x XOR k) = IM(x) XOR IM(k)`. Grouping
one interior round as `[IP; IS; XOR(K); IM]` (rather than the original `[IM; IP; IS; XOR(K)]`) and
applying both identities: `IP;IS = IS;IP` (commute), then `XOR(K); IM = IM; XOR(IM(K))` (push the
key past the now-adjacent `IM`), gives `[IS; IP; IM; XOR(IM(K))]` - substitute-permute-mix, then
the *transformed* key, exactly `encipher_round`'s shape. Doing this for every interior round chains
into: one leading bare `apply_matrix(MDS_INV)` (nothing to push it into, it's adjacent to the
mod-add `K_nr` whitening, which doesn't distribute over XOR the way GF(2^8)-linear ops do), `nr-1`
fused rounds (`fused_inv_round`, over a new `tables::SBOX_MDS_DEC = MDS_INV_TABLE[row][SBOXES_DEC[
row % 4][byte]]`, same `const fn` composition pattern as `SBOX_MDS`) each followed by
`XOR(DK[j])` where `DK[j] = apply_matrix(K[j], MDS_INV_TABLE)`, then one trailing bare
`inv_shift_rows; inv_sub_bytes`, then the `K_0` whitening. `fused_inv_round`'s gather index is
`inv_shift_rows`'s direction (`src_col = (out_col + shift) % nb`), the opposite sign from
`encipher_round`'s (`(out_col + nb - shift) % nb`) - it undoes the permutation rather than
performing it.

**A first derivation attempt was wrong and was caught before implementation, not after**: grouping
as `[IS; XOR(K); IM; IP]` (pushing the key *forward* through both `IM` and `IP`) lands the key
right before the *next* round's substitution step, which just recreates the original problem one
round later (substitution still ends up seeing a value that depends on a runtime key, blocking
table fusion) - a dead end, not a bug, caught by re-deriving on paper (with a second opinion) before
writing any code, per `CLAUDE.md`'s "research before implementation."

**`ExpandedKey` updated to precompute `DK[1..nr]` once in `new()`** (a new `dec_keys` field,
alongside the existing `round_keys`, both `Zeroize`/`ZeroizeOnDrop`), not per `decrypt_block` call -
otherwise caching the schedule would reintroduce `nr - 1` `apply_matrix` calls into every decrypt,
undoing part of D-29's win. The raw `decrypt_generic` computes `dec_keys` once per call (same
one-shot cost class as `key_expand` itself) via a new `transform_keys_for_decrypt` helper.

**Verified**: a new `proptest` suite (`hazmat::kalyna::decrypt_fusion_tests`, four cases spanning
every real `(nb, nr)` combination) checks the restructured `decrypt_with_schedule` against a
kept-for-reference `naive_decrypt_with_schedule` (the untransformed three-pass `decipher_round`
loop, `decipher_round` itself now `#[allow(dead_code)]`) over **random round-key schedules and
random ciphertexts** - not just the fixed schedules real vectors happen to produce, since this
transform moves *where* each key is applied, a subtler class of bug than D-28's per-round fusion.
A new exhaustive `hazmat::tables::tests::sbox_mds_dec_matches_gf_mul_and_sbox_dec_exhaustively`
test. All existing official vectors (including the real DSTU 7624 *decryption* vectors), `proptest`
round-trips, and `ExpandedKey`'s own proptests re-run unchanged. The Oliynykov differential harness
re-run fresh (15000/15000 encrypt cases, bit-identical) - note this harness only exercises
`KalynaEncipher`, not `KalynaDecipher`, so it doesn't independently re-verify decrypt beyond what
the official vectors and the naive-vs-fused proptest already cover; extending it to decrypt was not
done this pass (`oracles/kalyna-reference/kalyna.h` does expose `KalynaDecipher`, so it's a small,
cheap addition if ever wanted). `clippy`, `fmt`, `no_std` all pass.

**Result** (`cargo bench -- --baseline kalyna-expandedkey-2026-07-22`): with the schedule cached,
decrypt-block-only improved **66-82%** (e.g. 128-128: 433 ns -> 144 ns; 512-512: 3934 ns -> 691 ns)
- now roughly on par with encrypt-block-only (which barely moved, as expected) instead of 3.2-6.9x
slower. **Kalyna decrypt-block-only is now faster than UAPKI across every variant measured** (e.g.
128-128: 144 ns vs UAPKI's 222 ns; 512-512: 691 ns vs 879 ns) - combined with D-29's encrypt result,
this closes essentially the entire gap to UAPKI for the schedule-cached (`ExpandedKey`) API, the
one any real multi-block caller or future mode of operation would use. The raw one-shot `decrypt`
function (schedule recomputed every call, now also recomputing `dec_keys`) is a more mixed
picture: regressed slightly for the two smallest variants (128-128: +11%, 128-256: +4.5% - the
extra `nr - 1` key-transform `apply_matrix` calls aren't offset by the round fusion at low round
counts) but improved substantially for the larger ones (256-256: -17%, 256-512: -22%, 512-512:
-33%) - an honest tradeoff of the one-shot convenience path, not a regression in the path that
matters (`ExpandedKey`). New baseline: `kalyna-decryptfusion-2026-07-22`.

## D-31: `dstutool` gets its first real command - `kalyna-block`, for a binary-level benchmark

Follow-up to D-28/29/30, same day. All the Kalyna/Kupyna performance work so far was measured
in-process (`criterion` calling Rust directly, or a C harness calling C directly) - the user asked
for a binary-vs-binary comparison instead ("наче це бінарник, а не частини" - as if it's a binary,
not parts), to see the whole tool the way a user would run it, not just the internal function.

**Why this isn't `dstutool encrypt --key ... --in file --out file`** (the command CLAUDE.md's MVP
scope actually specifies): that command implies a mode of operation over arbitrary-length files,
which doesn't exist yet - blocked on D-05 (needs the official DSTU 7624 text or another
authoritative source to pick a construction). `hazmat::kalyna` can only encrypt/decrypt exactly one
block. Naming this new command `kalyna-block encrypt`/`decrypt` instead of the reserved
`encrypt`/`decrypt` names keeps it unambiguous that this is a single-block, `hazmat`-scoped tool
for this benchmark (and for anyone who explicitly wants raw single-block access), not the eventual
file tool - so building it now doesn't quietly pre-empt or confuse the real D-05-gated design
decision.

**Shape**: `dstutool kalyna-block encrypt/decrypt --variant <128-128|...|512-512> --key <path>
--in <path> --out <path> [--iterations N] [--raw-schedule]`. Key/block/output are raw binary files
of the variant's exact byte length (no hex encoding - simplest, and matches how the comparison C
tools read bytes too). `--iterations N` (default 1) repeats the same in-memory op `N` times before
writing the final result, for benchmarking; `--raw-schedule` selects `dstu_core`'s raw one-shot
`encrypt`/`decrypt` (re-expands the key schedule every iteration) instead of the default
`ExpandedKey` (schedule expanded once, D-29) - both numbers matter for the same reason they did in
`benches/kalyna.rs`. Logic lives in a new `src/lib.rs` (testable directly) with `main.rs` as a
thin wrapper mapping `Result` to a process exit code - `#[deny(clippy::unwrap_used,
clippy::expect_used)]` was already set in the placeholder `main.rs`, carried through properly here
(all fallible paths return `CliError`, not a panic).

**A real bug caught by the tests written alongside this** (not test-first in the strict sense this
project otherwise holds itself to for primitives, given this is a thin CLI wrapper, not a crypto
primitive - but tested before being exercised manually): the first `key_len`/`block_len`
implementation grouped match arms by *block* size instead of *key* size, giving `Kalyna128_256` a
16-byte `key_len()` instead of the correct 32 - caught immediately by
`variant_lengths_match_dstu_core`, fixed before any manual testing. A concrete demonstration of why
even "obviously simple" CLI plumbing gets tests, not just the algorithms.

**Comparison CLIs for Oliynykov's reference C and UAPKI** (scratchpad-only, same convention as this
file's other C comparisons - not committed): mirror `kalyna-block`'s exact file interface and
flags, so the three binaries are invoked identically. All three cross-checked to produce
byte-identical ciphertext/plaintext for the same key/block before any timing run.

**Result**: full before/after tables in `PERFORMANCE.md`'s new "Binary-level (process) comparison"
section. Headline finding: `dstutool`'s cached (`ExpandedKey`) per-op numbers match the in-process
`criterion` numbers within a few percent (e.g. 128-128 encrypt: 127 ns here vs 132 ns in-process) -
the CLI adds no meaningful overhead once amortized. Process-spawn overhead (~60-63 ms on this
machine, likely including Windows Defender scanning a freshly-built binary, per this session's
earlier note) is **roughly the same across all three binaries**, dominating whole-invocation
wall-clock time and confirming that `wall_ns` (which this comparison reports too, not hidden)
mostly measures the OS, not the crypto - `per_op_ns` is what actually reflects implementation
speed, same conclusion as D-28/29/30's in-process numbers.

**Next, tracked in `TASKS.md`, explicitly NOT unblocked by this entry**: a safe mode of operation
for Kalyna is next in priority per the user's request, but D-05 (needs the official DSTU 7624 text
or another authoritative source before any construction is chosen) is still the real gate - this
entry building a single-block CLI for benchmarking does not resolve or bypass that.

**Extended same day to Kupyna and Strumok** - the user asked for the same binary-vs-binary
treatment, and unlike Kalyna, *neither* has a mode-of-operation blocker: `Kupyna256`/`Kupyna512
::digest` already takes an arbitrary-length message (no block-size restriction on the public API),
and `Strumok256`/`Strumok512::apply_keystream` already XORs the keystream into a buffer of any
length - both are already their libsodium-equivalent's full scope (`crypto_generichash`/
`crypto_stream` respectively, per `docs/dstu-crypto-project.md`'s API table), so these two new
commands are genuinely complete features, not scoped-down benchmarking scaffolds the way
`kalyna-block` is.

- **`kupyna-digest --variant <256|512> --in <path> --out <path> [--iterations N]`**: hashes
  `--in`, writes the digest to `--out`. No key, so no cached-vs-raw distinction exists to expose
  (unlike Kalyna/Strumok) - `--iterations` just repeats the (idempotent) digest call for timing.
- **`strumok-crypt --variant <256|512> --key <path> --iv <path> --in <path> --out <path>
  [--iterations N] [--raw-schedule]`**: applies the keystream to `--in`. `--raw-schedule` re-runs
  `Strumok*::new` fresh before every iteration (re-applied to a fresh copy of the original buffer
  each time) - this matches `benches/strumok.rs`'s own convention (`Strumok256::new(...)
  .apply_keystream(...)` inside every `criterion` iteration), so it's the number to sanity-check
  against the in-process figures. The default continues the same cipher state across `iterations`
  calls instead (a real continuous stream, no repeated init) - cheaper, though for Strumok the two
  numbers turned out close (init is small relative to a 64 KB buffer) - see `PERFORMANCE.md` for
  why this differs from Kalyna, where cached vs raw was a much bigger gap.

Comparison CLIs added for Oliynykov's Kupyna reference C, UAPKI's `dstu7564`, outspace's
`dstu8845`, and UAPKI's `dstu8845` (all scratchpad-only, not committed, same convention as
`kalyna-block`'s comparison CLIs) - all four cross-checked byte-identical against `dstutool`
before timing. Full result tables in `PERFORMANCE.md`.

## D-32: `cargo fuzz` actually run on this machine, all three targets - the MSVC blocker wasn't wrong, just avoidable here

`TASKS.md`/D-23 left "actually run `cargo fuzz`" open, blocked on a confirmed toolchain fact:
libFuzzer's Address Sanitizer needs the MSVC target on Windows, and this project's default
toolchain is the GNU host (`x86_64-pc-windows-gnu`, chosen specifically to avoid needing Visual
Studio Build Tools, `.claude.local.md` "Toolchains"). That technical finding was correct and still
is - ASan genuinely doesn't support the GNU target. **What changed 2026-07-22, same session as
D-28 through D-31**: the user pointed out Visual Studio 2022 (with the MSVC C++ toolset) is
already installed on this machine, for unrelated reasons - so the objection to using MSVC here
("would mean installing Visual Studio just for this one command") no longer applies. This is a
statement about this machine's environment, not a reversal of the earlier finding.

**What made it actually work, three separate things, each confirmed necessary by hitting the
failure without it**:
1. `rustup toolchain install nightly-x86_64-pc-windows-msvc` - an *additional* toolchain
   (default toolchains stay GNU-host, unchanged for everything else in this project).
2. Running from a shell with `vcvars64.bat` sourced first. Not just for `link.exe` at build time -
   confirmed the hard way that without it, the build itself succeeds (rustc can locate MSVC via
   the registry on its own) but the resulting fuzz binary then fails at *run* time with
   `STATUS_DLL_NOT_FOUND (0xc0000135)`, because the ASan runtime DLL isn't on `PATH` without
   vcvars.
3. Passing `cargo fuzz run --target x86_64-pc-windows-msvc` explicitly. `cargo-fuzz`'s own
   `--target` flag defaults to `x86_64-pc-windows-gnu` unconditionally (confirmed via `cargo fuzz
   run --help`) regardless of which toolchain invokes it - omitting this flag reproduces the exact
   original "address sanitizer is not supported for this target" failure even when running under
   the msvc toolchain, which is what made the first retry attempt look like it hadn't changed
   anything.

**Result**: all three fuzz targets run clean, 60-second smoke run each (matching
`.github/workflows/rust.yml`'s existing `fuzz-smoke` job convention, not a long campaign), zero
crashes:

| Target | Runs (60s) | Coverage (edges/features) |
|---|---|---|
| `kupyna` | 182,746 | 87 / 213 |
| `kalyna` | 169,851 | 773 / 1341 |
| `strumok` | 1,466,215 | 101 / 163 |

Coverage plateaued well before the 60s mark for all three (visible in the raw libFuzzer output) -
expected for a short smoke run against a small, already-well-tested surface (single-block/
fixed-key-size operations), not evidence of a shallow harness. This is a smoke-level signal, same
standing as the CI job it mirrors - not a substitute for a longer campaign if one is ever run
deliberately.

**`xtask fuzz` updated to do this automatically on Windows** (see `xtask/src/main.rs`): detects a
Visual Studio C++ toolset via `vswhere.exe` (fixed, well-known install path even though it isn't
itself on `PATH`) and the `nightly-x86_64-pc-windows-msvc` rustup toolchain; if both are present,
runs each target through `cmd /C` with `vcvars64.bat` sourced first, same invocation as the manual
steps above. If either is missing, prints an install hint and skips (same pattern `require()`
already uses for every other optional tool) rather than failing `cargo xtask ci` outright - a
machine without Visual Studio installed (e.g. CI, or a GNU-only dev box) still gets a clean
best-effort skip, unchanged from before this entry.

**Not claiming this resolves the CI gap**: `.github/workflows/rust.yml`'s `fuzz-smoke` job on
Linux remains the actual, unconditional per-push check - this only makes the optional local
`cargo xtask fuzz` path usable on a Windows dev machine that happens to have Visual Studio
installed, which is not guaranteed for every contributor's machine the way the GNU toolchain is.

## D-33: UAPKI built on the Raspberry Pi too - the "we beat UAPKI" claim doesn't hold on ARM for Kalyna/Kupyna

The Raspberry Pi rig (`TASKS.md` "Testing & hardening", `.claude.local.md`) so far only ran this
project's own `cargo bench` there - the "faster than UAPKI" claims in D-28/D-29/D-30 and
`PERFORMANCE.md` were only ever checked on the Ryzen dev machine. The user asked directly whether
UAPKI was benchmarked on the Pi too, "so there's an adequate comparison across platforms of the
same code" - a fair challenge, since a same-code cross-architecture comparison (this project on
Ryzen vs. this project on Pi) and a same-machine cross-implementation comparison (this project vs.
UAPKI, both on Ryzen) don't add up to the actual claim being made ("this project beats UAPKI"),
which implicitly needs UAPKI measured on the *same* second machine too.

**What was built, reusing artifacts already on disk from the original Ryzen measurement session**
(not re-created from scratch): the pruned `library/uapkic` source tree (`CMakeLists.txt`, `src/`,
`include/`) and the two scratchpad C timing harnesses that produced the existing Ryzen "UAPKI"
figures (`bench_uapki.c` - Kalyna ECB single-block encrypt + Kupyna digest at 64/1024/65536 B;
`bench_strumok_uapki.c` - Strumok keystream at the same three sizes) were copied to the Pi over
SSH, built with plain `cmake -DUAPKI_LIBS_TYPE=STATIC -DUAPKI_DISABLE_COPY=ON` + `gcc -O2` (no
Windows-specific `RESOURCE_RC`/`windres` workaround needed on Linux - CMake's `if(WIN32)` branch
already skips that path), and run the same way as on Windows. Same pinned commit
(`c64181c3b1cd437139119d83bffb5ab090b1cdd6`, `oracles/README.md`) as the existing Ryzen build, so
this is genuinely the same code on both platforms, matching what "this project" already was.

**Result - Kalyna and Kupyna's "we beat UAPKI" result reverses on the Pi, Strumok's doesn't**:

| Algorithm | Ryzen ratio (this project vs UAPKI) | Pi ratio (this project vs UAPKI) |
|---|---|---|
| Kalyna (block-only, cached) | 1.4-1.9x **faster** | 1.03-1.9x **slower** |
| Kupyna (digest) | 0.93-1.45x, roughly at parity or **faster** | 1.2-1.6x **slower** |
| Strumok (`apply_keystream`) | 1.15-1.9x **faster** | 1.1-1.6x **faster** (smaller margin) |

Full per-size numbers are in `PERFORMANCE.md`'s three Results tables, now with a `UAPKI
(Raspberry Pi 5)` column/row alongside the Ryzen one. Kalyna's 512-512 case is the starkest: 1185
ns (this project) vs 632 ns (UAPKI) on the Pi - UAPKI is ~1.9x faster there, versus this project
being ~1.5x faster than UAPKI on the same variant on Ryzen.

**Why this is plausible, not a red flag - three untested hypotheses, in order of how much they'd
explain, none investigated further this pass** (flagged explicitly as speculative, per this
project's own "don't overclaim a root cause" discipline - see the Strumok/outspace residual gap in
`PERFORMANCE.md`'s "What the gap is, honestly" for the established precedent of naming a gap
without chasing it):

1. **LLVM (rustc's backend) vs GCC codegen quality for this specific bit-manipulation pattern may
   differ between the x86-64 and aarch64 backends.** D-28's fused round is dense 64-bit
   shift/mask/XOR gather logic (`SBOX_MDS`/`SBOX_MDS_DEC` lookups combined via shifts) - if LLVM's
   aarch64 backend generates comparatively less efficient code for this exact shape than its
   x86-64 backend does (relative to GCC's aarch64 backend, which built UAPKI on both platforms),
   that alone could explain a compiler-pair-specific, not algorithm-specific, reversal. This is the
   single most explanatory candidate since it's the one variable that changed asymmetrically
   (Rust/LLVM vs C/GCC, on both architectures) rather than symmetrically (both toolchains moving to
   ARM together).
2. **UAPKI's own Kalyna/Kupyna table layout (`p_boxrowcol`, per D-27's doc comment) may simply
   suit ARM's load/store pipeline better** than this project's packed-`u64`-per-row gather,
   independent of compiler - byte-oriented table access vs. 64-bit-word gather-then-shift could
   have different relative costs on Cortex-A76 than on Zen2.
3. **Strumok's lack of a reversal is itself a data point**: its D-26 optimization (ring buffer +
   `T0..T7` tables) is a more straightforward "8 lookups XORed together" shape than Kalyna/Kupyna's
   gather-and-shift-to-reposition-a-byte pattern - if hypothesis 1 or 2 is right, a simpler access
   pattern would be expected to be less sensitive to the architecture/compiler difference, which is
   consistent with what was actually measured.

**Not chased further this pass**: no disassembly comparison, no perf-counter profiling on either
machine, no attempt to build `dstu-core` with GCC-via-`cranelift`/a different LLVM version to
isolate the compiler-vs-layout question. This is a real, measured, cross-architecture finding
worth a documented follow-up if performance work on Kalyna/Kupyna resumes, not a fire to put out
now - the code is still correct on both platforms (`TASKS.md`'s ARM build/test task, unaffected),
and this project's MVP scope (`CLAUDE.md`) never promised the Ryzen speed advantage generalizes to
every architecture, only that the code compiles and runs correctly on more than one.

**Scope corrections applied**: `PERFORMANCE.md`'s Kalyna/Kupyna Results tables and the "What the
gap is, honestly" section both got a dated correction noting the Ryzen-specific scope of the
"beats UAPKI" claim, rather than silently leaving an now-incomplete claim standing - per this
project's own standard for correcting prior statements (see `CLAUDE.md` "Never silently deprecate
a document" applied at sentence granularity here, not just file granularity).

## D-34: One performance-testing method from now on - built binary, real process, MB/s only

Prompted directly by D-33: reconciling "this project beats UAPKI" (in-process `criterion` vs. a
raw C timing loop) against the binary-level numbers already in `PERFORMANCE.md` (D-31, `dstutool`
vs. a scratchpad UAPKI CLI wrapper) surfaced a real inconsistency on the *same* Ryzen machine -
Kupyna-256 at 65536 B reads **98.60 MB/s (this project) vs. 95.48 MB/s (UAPKI)** in-process, but
**94.14 MB/s (this project) vs. 104.95 MB/s (UAPKI)** at the binary level - opposite winners,
~10% apart either way, most likely measurement-methodology noise (a raw single-shot C timing loop
has no warmup/outlier-trimming the way `criterion`'s sampling does) rather than a real effect, but
exactly the kind of ambiguity that follows from comparing two different measurement methods against
each other instead of one. The user's own framing: a real user of this project never calls
`dstu_core::hazmat::kalyna::encrypt` from their own Rust process the way `criterion` does - they run
a *program*, the way libsodium's own benchmarking culture (and this project's MVP goal of being a
libsodium-shaped tool, `CLAUDE.md`) already treats as the unit that matters. Decision, going
forward: **the only performance comparison this project publishes is binary-level - a built CLI
(`dstutool` for this project, an equivalent thin CLI wrapper with the same file-based interface for
every oracle) invoked as a real external process - reported exclusively in MB/s**, for every
algorithm, every implementation/oracle compared, and every platform measured (Ryzen dev machine,
Raspberry Pi, and any future one). No more `ns`/op tables, no more `wall_ns` process-overhead
tables as a "result" (that overhead was already confirmed negligible once amortized, D-31 - it
doesn't need its own table repeated every time), and no more using in-process `criterion` numbers as
a cross-implementation comparison.

**What this does *not* change**: `cargo bench`/`criterion` remains this project's own internal
regression-tracking tool (`DECISIONS.md` D-23, the saved `--baseline` mechanism) - useful for
noticing a Rust-side regression between commits on one machine, a different job than comparing
against another implementation entirely. It simply stops being used for the *cross-implementation*
comparison`PERFORMANCE.md` is actually for.

**MB/s for a fixed-size block cipher (Kalyna)**: still computed as `block_size_bytes / per_op_time`
(D-31's existing convention, kept) - not a message-length-dependent rate the way Kupyna/Strumok's
is, but reported the same unit for a consistent table shape across all three algorithms, which is
exactly what "one metric" means here.

**Practical effect on `PERFORMANCE.md`**: the entire "## Results" (in-process) section is marked
superseded with a dated banner rather than deleted (`CLAUDE.md` "never silently deprecate a
document," applied at section granularity) - its historical optimization-progress narrative (D-27
through D-30's incremental fixes) is still worth keeping as a record of what was tried and in what
order, just no longer the authoritative comparison. "## Binary-level (process) comparison" becomes
the single canonical section, rebuilt with Ryzen *and* Raspberry Pi columns for every
implementation/oracle now built on both machines (`dstutool`, UAPKI, outspace for Strumok;
Oliynykov's reference C stays excluded per the user's earlier, unchanged decision that a
correctness-only oracle isn't a performance baseline - this session's "test every oracle" request
is about the *method*, not about un-excluding an oracle already excluded for an orthogonal reason).

## D-35: Two resource profiles (small-tables vs fused), one codebase, one test suite

Follow-up to the D-27/D-28/D-30 fused-table work, prompted by planning Phase 4 embedded targets:
those tables (`MDS_TABLE`/`MDS_INV_TABLE`, D-27; `SBOX_MDS`/`SBOX_MDS_DEC`, D-28/D-30) plus
Strumok's `T0..T7` (D-26) total **~86 KB of `const` data** (Kalyna/Kupyna ~66 KB, Strumok ~20 KB —
measured directly off `hazmat::tables.rs`/`hazmat::strumok.rs`, not the earlier ~36 KB estimate
given in conversation, which missed that `MDS_TABLE`/`MDS_INV_TABLE` are still live production
code, not superseded by `SBOX_MDS`/`SBOX_MDS_DEC`). On a memory-mapped-flash 32-bit target
(Cortex-M/Xtensa/RISC-V, XIP) this costs flash, not SRAM; on AVR's Harvard architecture it costs
SRAM outright unless placed in `PROGMEM` with AVR-specific access code. Either way, the smallest
targets in scope (STM32 L0/F0/G0 entry parts at 16-64 KB flash; ATmega328P at 32 KB flash/2 KB
SRAM) cannot hold ~86 KB of tables regardless of architecture.

**Decision**: not two separate implementations. One codebase, a new Cargo feature on `dstu-core`
gates which table strategy the shared round functions call:

- Default (unchanged): today's fused tables (`SBOX_MDS`/`SBOX_MDS_DEC`/`MDS_TABLE`/
  `MDS_INV_TABLE`, Strumok's `T0..T7`) - full speed, ~86 KB of `const` data.
- New small-tables feature: the pre-D-26/D-27 path - `SBOXES`/`SBOXES_DEC` (2 KB) + table-free
  `gf_mul` for Kalyna/Kupyna (~2.1 KB total), Strumok's `T` computed at runtime from those same
  shared tables instead of its own `T0..T7` (adds ~0 KB, reuses Kalyna/Kupyna's tables) - slower,
  ~2-6 KB total. This is not new code to write: it is D-27's own kept-for-testing reference path
  (`gf_mul`/`MDS_MATRIX`/`MDS_INV_MATRIX`, currently `#[allow(dead_code)]`) and Strumok's
  pre-D-26 runtime-`T` computation, promoted from dead test-only code to a real `cfg`-selected
  production path instead of being deleted or left unreachable.

**Why this doesn't double the verification burden**: official DSTU vectors and the differential
oracle harnesses (Oliynykov/UAPKI/outspace) check input/output pairs, not which internal table
strategy produced them - the same test suite runs unchanged against both feature states. This is
the same shape the project already runs for the four existing `no_std`/`alloc`/`std` feature
combinations (`TASKS.md` "Re-confirm the `no_std` build still passes") - CI gains one more
build+test matrix entry (`--features small-tables`), not new tests to write or maintain. Two
independent full implementations would have been the actually expensive path, since each would
need its own dual-oracle confirmation; a `cfg`-gated shared round function reusing the same
verified math does not.

**Not decided here**: the feature's public name, `dstutool`'s working name, and the project's own
(GitHub) name are all still open - see `TASKS.md` Phase 1/Phase 4 for the naming subtask. Also not
decided: whether `small-tables` on AVR is sufficient on its own, or still needs `PROGMEM`
placement work on top (`TASKS.md` Phase 4's existing Arduino stretch-goal note) - the Harvard-
architecture SRAM-copy problem is orthogonal to which table set is chosen and isn't solved by this
decision alone.

## D-36: `dstutool`'s real name is `uacrypt` (`TASKS.md` T-21)

Researched naming conventions in the libsodium-adjacent/security-CLI space before proposing
options: smallstep's "The Poetics of CLI Command Names" (concrete anti-patterns - never use
"tool"/"kit"/"util"/"easy" in a command name, since `dstutool` already does; don't bind the name to
a specific protocol/standard that may age out, the exact regret `openssl`'s own naming is called
out for) plus real precedent from Frank Denis's libsodium-adjacent tools (`minisign`, `age`/`rage`,
`sq`) - short, easy to type without Shift, pronounceable the same way worldwide. Three candidate
directions were given (a short "thoughtful meaningless" word like `step`/`age`; continuing this
project's existing Ukrainian nature-word theme the way `Kalyna`/`Kupyna`/`Strumok` already are, not
acronyms; a Ukraine+crypto portmanteau) - user picked the portmanteau direction, name **`uacrypt`**.

**Scope of this decision**: names the CLI binary only (`TASKS.md` T-21). Explicitly does not
resolve T-20 (the small-tables/fused feature-flag public name, D-35) or T-22 (the project's own
GitHub name) - `uacrypt` is not automatically assumed for either, pending confirmation.

**Not yet done**: the actual rename (`crates/dstutool` package/binary name in `Cargo.toml`,
`README.md`, `docs/dstu-crypto-project.md`, and any place `dstutool` is invoked from
`xtask`/CI/`PERFORMANCE.md`) - this entry records the naming decision itself, not the mechanical
follow-through.

## D-37: `uacrypt` rename executed; also adopted as the project's own (GitHub) name (T-22)

Follow-up to D-36, same day: user confirmed both open questions at once - do the D-36 rename now,
and reuse `uacrypt` for `TASKS.md` T-22 (the project's own/GitHub name) too, rather than treating
the CLI binary and the project as separately-named. Precedent for a project and its flagship CLI
sharing one name exists in the same libsodium-adjacent space D-36's research drew from (`age` is
both the tool and the project) - not a new pattern invented here.

**Executed**:
- `git mv crates/dstutool crates/uacrypt`; `Cargo.toml` `[package] name`/`[lib] name` both
  `uacrypt`; root workspace `Cargo.toml` member path updated; `deny.toml`'s comment updated.
- `main.rs`/`lib.rs` internal references (`uacrypt::run`, the `uacrypt: {e}` error prefix, doc
  comments, the `uacrypt_test_` temp-dir prefix used by `main.rs`'s own tests) updated.
- `README.md`: title changed from "dstu-crypto (working name)" to `uacrypt` (this *is* T-22 -
  the project's own name, not just the CLI's), directory-tree entry, the "Using `uacrypt`"
  section, and its `cargo build -p uacrypt`/`uacrypt kalyna-block ...` example commands.
- `SECURITY.md`, `docs/dstu-crypto-project.md`, `CLAUDE.md` - each place that named the CLI
  `dstutool` (working name) now says `uacrypt`, citing this entry.
- `PERFORMANCE.md`'s **canonical** "Binary-level (process) comparison" section (D-34) - column
  headers, prose, and the `cargo build -p uacrypt --release` / `target/release/uacrypt
  kalyna-block ...` reproduction commands - updated, since this section's commands need to
  actually work today, unlike a historical record. The measured numbers themselves are unchanged
  (same binary, same behavior, name only) - a one-line note added explaining the rename rather
  than silently changing what the numbers were labeled under.

**Deliberately left unchanged**: `DECISIONS.md`'s own earlier entries (D-26 through D-34, D-36
above), `TASKS.md`'s historical `[x]` narrative entries, and `PERFORMANCE.md`'s superseded
"## Results" section all still say `dstutool` - each describes what was literally built and
measured under that name *at the time*, and rewriting history to match a later rename would be
the "silently deprecate a document" failure mode `CLAUDE.md` and this project's own D-34 precedent
(dated-banner-not-deletion) both warn against. `docs/dstu-crypto-project.md`'s own filename was
**not** renamed - it names its *content* (the DSTU crypto project spec), not the product, and
renaming it would break a large number of existing cross-references (`CLAUDE.md`'s documentation
map, `TASKS.md`, every `DECISIONS.md` entry citing it) for no functional benefit; same reasoning
applies to `dstu-core`'s crate name, which was never in scope of T-21/T-22 (it names the *library*,
which is not "uacrypt" - `uacrypt` is specifically the CLI/project name, not the core crate).

**Verified**: `cargo build --workspace`, `cargo test -p uacrypt` (15/15 passed), `cargo clippy
--workspace -- -D warnings`, `cargo fmt --check` all clean post-rename on the Ryzen dev machine.
`Cargo.lock` regenerated by the build rather than hand-edited. Not yet re-run: the `no_std`
feature-flag matrix, Raspberry Pi re-sync, or CI - none of this rename touches `dstu-core` or its
feature flags, so no regression is expected, but per `TASKS.md`'s standing "re-confirm as each
change lands" discipline these should still be re-checked before the next release, not assumed.

**Still open**: T-20 (the small-tables/fused feature-flag public name, D-35) is the one remaining
naming decision - not resolved by this entry.

## D-38: Resource-profile feature keeps its working name - `small-tables`, no rebrand (T-20)

Follow-up to D-35/D-36/D-37, same day - the last open naming decision (`TASKS.md` T-20). Asked
whether reusing `uacrypt` for this too would be a problem: **it would be the wrong kind of name for
what this is.** T-21/T-22 (D-36/D-37) named user-facing products (a CLI someone types, a project
someone finds on GitHub) where a short, memorable, marketable identity earns its keep. A
`Cargo.toml` feature flag is a technical/internal identifier read by `cargo build --features ...`
and `#[cfg(feature = "...")]` - Rust ecosystem convention there favors plain, descriptive,
kebab-case names (`derive`, `serde`, `std`) over branding, and this project already has two such
features (`std`, `alloc` in `dstu-core/Cargo.toml`) with exactly that plain style.

**Decision**: no rebrand. The working name from D-35's own text - **`small-tables`** - becomes the
actual Cargo feature name once implemented; the default fused-table path stays nameless (it's the
absence of the feature, not a feature of its own). Checked for conflicts: `small-tables` doesn't
collide with `std`/`alloc`, hyphens are valid in Cargo feature names, and `dstu-core` has zero
external dependencies (`SECURITY.md`/`deny.toml`) so no cross-crate feature-unification risk.

**Not done here**: this closes the naming question only. `TASKS.md` Phase 4's "Two-resource-profile
split" item (the actual `[features] small-tables = []` entry plus `cfg`-gating
`gf_mul`/`MDS_MATRIX`/`SBOXES` vs. `SBOX_MDS`/`SBOX_MDS_DEC`/`T0..T7`, D-35's "promote from
dead_code to production path") is still open, unstarted.

All three `TASKS.md` T-19 naming decisions (T-20/T-21/T-22) are now resolved.

## D-39: `small-tables` implemented - D-35's design executed (`TASKS.md` T-54)

Follow-up to D-35/D-38, same day: user asked to implement D-35/D-38 directly rather than leave
them as a naming/design decision only. Executed the design D-35 already specified, essentially
unchanged - this entry records what building it actually required, including one design
refinement D-35 hadn't spelled out.

**Cargo**: `dstu-core/Cargo.toml` gets `small-tables = []`, independent of `std`/`alloc`/default.

**`hazmat/tables.rs`** - all the profile-switching logic lives here, not spread across the
callers:
- `MDS_TABLE`/`MDS_INV_TABLE` (D-27), `SBOX_MDS`/`SBOX_MDS_DEC` (D-28/D-30), and their `build_
  sbox_mds`/`build_sbox_mds_dec` `const fn`s are now `#[cfg(not(feature = "small-tables"))]` - not
  compiled at all under the feature, not merely dead-code-eliminated. `MDS_MATRIX`/`MDS_INV_
  MATRIX`/`gf_mul` stay unconditional (D-27's small reference matrices/function) since
  `small-tables` needs them as live production code, not just a test reference anymore.
- New: `apply_matrix_via_gf_mul` (the pre-D-27 `apply_matrix` body, reconstructed - 64 `gf_mul`
  calls per column) and `mds_column_via_gf_mul` (one output column's worth, computed on demand -
  literally the exhaustive test's own `expected_column` helper, promoted from test-only to a real
  function, same formula, zero new correctness risk since it's the same code).
- **Design refinement over D-35's text**: rather than gate kalyna.rs/kupyna.rs/strumok.rs's call
  sites with their own `#[cfg]`, four small role-based wrapper functions do it once, here:
  `apply_forward_matrix`/`apply_inverse_matrix` (whole-column MDS, each with two `#[cfg]`
  implementations, same name) and `forward_sbox_mds`/`inverse_sbox_mds` (one gathered byte's
  fused S-box+MDS contribution, same pattern). Callers everywhere else - `kalyna.rs`'s
  `encipher_round`/`fused_inv_round`/`decipher_round`/`transform_keys_for_decrypt`/`decrypt_with_
  schedule`, `kupyna.rs`'s `sub_shift_mix`/`mix_columns`, and both modules' test code - call these
  four functions unconditionally and never import `MDS_TABLE`/`SBOX_MDS`/etc. directly. Net effect:
  D-35's "no cfg spread across callers" intent, but achieved by centralizing the *interface*, not
  by hoping dead-code elimination would strip the unused profile.
- Exhaustive `mod tests` (checks `MDS_TABLE`/`SBOX_MDS` against `gf_mul`) is `#[cfg(all(test,
  not(feature = "small-tables")))]` - nothing to exhaustively check under `small-tables`, since
  that profile's production code *is* the `gf_mul` computation, not a table checked against it.

**`hazmat/strumok.rs`**: `T0..T7` (D-26, 16 KB) are `#[cfg(not(feature = "small-tables"))]`;
`t_function` has two `#[cfg]` bodies - default keeps the `T0..T7` XOR-lookup, `small-tables`
reverts to exactly the pre-D-26 form the module doc already described ("originally computed at
runtime via `hazmat::tables::{SBOXES, MDS_MATRIX, apply_matrix}`") - one `SBOXES` substitution per
byte of the word, then `apply_forward_matrix` treats the 8-byte word as one MDS column.
`MUL_ALPHA`/`MUL_ALPHA_INV` untouched (D-35 already noted these aren't swappable - different field
construction, not derivable from Kalyna/Kupyna's tables).

**Unanticipated correctness/tooling issue, not in D-35's plan**: swapping `SBOX_MDS[row][byte]`
(direct 2D-array index) for `forward_sbox_mds(row, byte)` (function call) changed clippy's
`needless_range_loop` analysis in three gather loops (`encipher_round`, `fused_inv_round`,
`sub_shift_mix`) plus the new `mds_column_via_gf_mul` - confirmed via `git stash` that the
pre-change code was clippy-clean and the refactor itself (not a toolchain drift) triggered the new
warnings, most likely because clippy no longer sees a second array indexed by the same loop
variable once one side becomes a function argument instead of `array[row]`. Not a real
readability problem - `row` still drives `shift`/`src_col` arithmetic, not a plain
single-collection enumerate candidate - so resolved with four documented `#[allow(clippy::
needless_range_loop)]`, same pattern as this file's existing `#[allow(clippy::cast_possible_
truncation)]` overrides.

**CI** (`.github/workflows/rust.yml`): `--all-features` used to be this project's stand-in for
"build/test/lint the default profile" (since `alloc` is an inert placeholder, D-01). It no longer
is, now that `--all-features` also enables `small-tables`, which changes production code paths -
left as-is, the default (fused) profile would have silently dropped out of CI coverage entirely.
Added explicit default-profile build/test/clippy steps (no extra features) and matching
`--features dstu-core/small-tables` steps, keeping `--all-features` as a third pass that exercises
both profiles' flags at once. All new step commands run locally first, not just written into the
YAML on faith.

**Verified**: official Kalyna/Kupyna/Strumok vectors, `proptest` round-trips, and (default profile
only) the fused-vs-naive/decrypt-fusion property tests all pass under both profiles; `cargo
clippy -- -D warnings` and `cargo fmt --check` clean on both; the existing 4-way `no_std`/`alloc`/
`std` matrix re-confirmed with `small-tables` added to each (8 combinations, `cargo build`); `cargo
xtask build` passes.

**Not done**: `cargo miri test`/`cargo fuzz` specifically under `small-tables` (D-35's stated
verification bar - official vectors plus differential-oracle harnesses - doesn't require it, and
neither is re-run here); CI's `miri`/`fuzz-smoke` jobs remain default-profile-only.

## D-40: Kalyna-CCM nonce/counter-width strategy - deferred to its own follow-up task

Raised 2026-07-23 while implementing `hazmat::kalyna_ccm` (D-41): the nonce/counter split
(`ccm_nb`, and with it the maximum message-count-before-repeat) is a tunable parameter of the CCM
construction itself, not a fixed constant of DSTU 7624 - confirmed from
`oracles/uapki/library/uapkic/src/dstu7624.c:4139-4158` (`dstu7624_init_ccm`): counter width
`nb = ((n_max - 3) >> 3) + 1` bytes, nonce width = `block_len - nb - 1` bytes, both driven by a
caller-supplied `n_max`. This is the same tradeoff as classical AES-CCM's `L` parameter (NIST SP
800-38C). D-41's five `(ccm_nb, q)` pairs are exactly what the cross-oracle test vectors specify
for those five known cases - not a new choice made by this project - but nothing here yet decides
**how a caller obtains a safe, never-repeating nonce**, which is the actual misuse-resistance
question (per this project's libsodium-style "nothing for the user to get wrong" goal, no
user-facing tuning knob should exist for this either).

**Not decided yet, on purpose - tracked as `TASKS.md` T-82, not resolved here:**
- Nonce reuse under the same key is the most damaging real-world AEAD misuse class. For GCM-style
  constructions it's catastrophic (full authentication-subkey recovery from two known
  ciphertext/tag pairs - the reason AES-GCM-SIV, RFC 8452, exists as a remedy). CCM's failure mode
  on reuse is less catastrophic (its MAC is CBC-MAC-based, not a polynomial hash) but still breaks
  both confidentiality (recoverable keystream XOR between the two messages) and authentication.
- Two real-world patterns to choose between: **TLS 1.3's** per-connection monotonic sequence
  number XORed into a derived IV (uniqueness guaranteed by construction, but needs mutable state
  tied to the key's lifetime - a bigger API-shape change than it looks, since
  `hazmat::kalyna_ccm`'s current `seal_in_place`/`open_in_place` take `&self`, not `&mut self`);
  versus **libsodium's** wide (192-bit, `crypto_secretbox`) random nonce, safe against birthday-
  bound collision without any state, specifically because the nonce space is wide enough - whether
  Kalyna-CCM's narrower, block-size-dependent nonce field (11-55 bytes across the five variants,
  D-41) supports this pattern safely for the smallest block size needs checking before assuming it
  transfers directly.
- Resolve this before `hazmat::kalyna_ccm`'s nonce parameter is considered anything other than
  "whatever the caller passes, currently uncontrolled" - `TASKS.md` T-82 owns finishing this.

**Resolved 2026-07-23, same day (`TASKS.md` T-82): wide random nonce, no stateful counter -
correcting a measurement error above, not just picking a side.**

The "11-55 bytes across the five variants" figure above is wrong about *which* bytes the caller
actually controls. Rereading `hazmat::kalyna_ccm.rs` itself (not just the abstract UAPKI formula):
`tmp = block_len - ccm_nb - 1` is only the slice of the nonce that feeds `ccm_padd`'s CBC-MAC
header (`G1`) - it is **not** the caller-facing nonce parameter. `seal_in_place`/`open_in_place`
both take `nonce: &[u8; $block_bytes]`, the **full block**, and `Gamma::new` seeds the CTR
keystream from `E_K(nonce_block)` over the whole thing. So the entropy that actually needs to be
unique per (key, message) is `block_bytes` wide, not `tmp` wide - 16/16/32/32/64 bytes (128/128/
256/256/512 bits) across the five variants, not 11-55 bytes. That changes the safety conclusion:
even the narrowest case (the two 128-bit-block variants) has a 128-bit nonce, the same width as a
standard CBC IV and wider than AES-GCM's usual 96-bit nonce - comfortably enough for the
libsodium-style pattern to hold, not just the TLS-1.3-style counter.

**Decision: the wide-random-nonce pattern, not an internal monotonic counter.** Two reasons, not
one:
1. **Birthday-bound math holds with margin.** For `n` messages under one key with independent
   random 128-bit nonces, collision probability is roughly `n^2 / 2^129`. Keeping that under
   `2^-32` allows `n` up to roughly `2^48` messages under a single key for the 128-bit-block
   variants - a real, statable per-key rekey guideline, not "basically infinite" (the 256/512-bit
   variants' 216-440-bit nonces make this bound irrelevant in practice, no guideline needed there).
2. **A monotonic counter needs durable state across restarts to actually guarantee uniqueness,
   and this project's own MVP scope rules that out as a default.** TLS 1.3's approach works
   because a TLS connection's counter lives exactly as long as the connection. This project's
   Phase-4 targets (`TASKS.md` T-55/T-56, STM32/ESP32) cannot be assumed to have durable,
   wear-levelled storage for a persistent per-key counter - a counter that silently resets to zero
   on power loss/reset reintroduces exactly the nonce-reuse this was meant to prevent, invisibly.
   A wide random nonce needs only a CSPRNG (`getrandom`, already the established primitive per
   D-03/D-04) and carries no cross-reboot state requirement. Matches this project's existing
   "no OS/hardware lock-in" and "nothing for the caller to misconfigure" goals better than the
   stateful alternative would.

**One caveat that makes the safety claim actually hold, not just the bare birthday bound**:
`increment_counter` (`kalyna_ccm.rs`) carries over the *full* block width - there is no reserved,
zeroed counter suffix the way classical CCM's `L`-parameter framing implies. Two independently-
random nonces that happen to land numerically close therefore produce keystreams that *overlap*
partway through, not just collide outright on an exact match. What keeps this safe in practice is
D-41's sourced 255-byte plaintext cap: the counter only advances a handful of blocks per message
(≤16 blocks even for the 128-bit-block variants), a negligible span against a 2^128 counter space -
so a near-miss between two random nonces still essentially never produces overlapping keystream in
practice. This is a real interlock between two already-shipped decisions (the 255-byte cap and the
nonce width), not an independent safety margin - stated explicitly so a future change to either one
re-checks the other.

**What actually changed in code** (`crates/uacrypt/src/lib.rs`, not `hazmat::kalyna_ccm` itself -
the hazmat-level API is deliberately left as "caller supplies a full-block nonce," per D-09's
two-layer split, since a `no_std` hazmat primitive cannot assume an OS CSPRNG exists to generate
one for an embedded caller): `uacrypt kalyna-ccm encrypt` no longer accepts `--nonce` as an input -
it generates one via `getrandom` and writes it to `--nonce` instead, so there is nothing left for a
CLI caller to reuse by mistake. `decrypt` is unchanged (still reads `--nonce` as input - it has to,
that's the value `encrypt` produced). This is the concrete realization of "nothing to
misconfigure" for the one user-facing surface that exists today; it does not touch
`hazmat::kalyna_ccm`'s own signature, and it is not `crypto_secretbox` (still D-05-blocked).

## D-41: Kalyna-CCM implemented as the D-05 working hypothesis - provisional, dual-oracle-verified

Follow-up to D-05's revision above, same day (2026-07-23). `dstu_core::hazmat::kalyna_ccm`
implements DSTU 7624 CCM (all five Kalyna block/key-size variants) as a standalone hazmat-level
primitive - not `crypto_secretbox` itself, which stays blocked on D-05's primary-text confirmation.

**Citation**: transcribed from `oracles/uapki/library/uapkic/src/dstu7624.c` -
`dstu7624_init_ccm` (line 4139, the `(ccm_nb, q)` parameterization), `ccm_padd` (line 2621, the
CBC-MAC authentication header/tag computation), `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm`
(lines 2792/2849, the CTR-keystream composition), `padding` (line 2572, the ISO/IEC 7816-4-style
0x80-then-zeros pad), and `gamma_gen`/`encrypt_ctr` (lines 2730/2739, the running CTR keystream,
including its non-obvious "encrypt the nonce once to seed the counter, then increment before every
real keystream block" indirection - transcribed as-is, not "simplified" to textbook CTR). UAPKI's
state-expertise pedigree is `ORACLES.md`'s standing trust basis for this source.

**Cross-check, with an explicit caveat on its strength**: all five variants' vectors were checked
byte-for-byte against `oracles/bouncycastle-java/core/src/test/java/org/bouncycastle/crypto/test/
DSTU7624Test.java`'s `CCMModeTests` - four of the five (128/128, 256/256, 256/512, 512/512) matched
UAPKI's own self-test vectors byte-for-byte, an independent-lineage agreement, not the same
vendor's number twice. **BC's own `KCCMBlockCipher`/`KGCMBlockCipher` Java source is not present in
this project's vendored sparse checkout of `oracles/bouncycastle-java`** (only the test file
importing them is) - so this cross-check is against BC's *vector outputs* only, not a second
reading of BC's construction code, a materially weaker claim than "read both implementations." The
128/256 variant has no BC vector at all (BC's `CCMModeTests` doesn't cover it) - that one case
relies on UAPKI alone, flagged in its vector file's `source` field.

**Provisional, not confirmed against the primary text** - same posture as Strumok/D-15, stated in
the module doc comment, every vector file's `source` field, and this entry.

**A real, sourced scope limit, not a design choice**: `ccm_padd`'s header encodes both the
plaintext length and the AAD length as a single byte each (`G1[tmp] = (uint8_t) p_data_len`,
`G2[0] = (uint8_t) a_data_len`) - so this exact construction only correctly authenticates messages
where both plaintext and AAD are at most 255 bytes. `hazmat::kalyna_ccm::{MAX_PLAINTEXT_LEN,
MAX_AAD_LEN}` enforce this with an explicit error rather than silently truncating the length field.
This is also, concretely, the reason this is a genuine *short-message* mode, not just a name.

**API shape, and one deliberate deviation from UAPKI's own function signatures**: UAPKI's
`dstu7624_decrypt_mac` takes the plaintext (unmasked) tag as a separate caller-supplied parameter
and doesn't actually use the trailing masked-tag bytes of the ciphertext blob for verification at
all - an oracle-testing convenience, not a shape a real receiver (who only has the transmitted
ciphertext+masked-tag blob and the AAD) could reproduce standalone. `hazmat::kalyna_ccm::open_in_
place` instead recovers the tag by CTR-decrypting the trailing masked-tag bytes itself (mathematically
equivalent, since XOR-masking is its own inverse) and verifies against that - a self-contained,
standard AEAD shape (ciphertext+tag as one transmitted unit) rather than requiring an
out-of-band-known plaintext tag. On verification failure, the buffer is zeroed before returning
`Err` - the caller can never observe unverified plaintext even transiently, generalizing this
project's existing "no secret material" discipline to "no unverified plaintext" for AEAD.

**Verified**: all 37 tests pass, first attempt, no debugging needed after the initial `cargo fmt`
pass - official vectors (all 5 variants, both `seal`/`open` directions, byte-exact ciphertext and
tag), `proptest` round-trip, and five independent tamper-rejection suites (flipped ciphertext byte,
flipped tag byte, flipped AAD byte, flipped nonce byte, wrong key - all correctly rejected with the
buffer zeroed on the ciphertext/nonce cases). `cargo clippy --workspace -- -D warnings` and `cargo
fmt --check` clean; all 8 `no_std`/`alloc`/`std`/`small-tables` feature combinations (`TASKS.md`
T-23/T-54) build clean and the CCM test suite passes identically under `small-tables` (needs no
`cfg` gating of its own - it only calls the existing per-variant `ExpandedKey` API); re-confirmed on
the Raspberry Pi rig too (`TASKS.md` T-35). `uacrypt`'s new `kalyna-ccm encrypt`/`decrypt`
subcommand round-tripped a real message through the built release binary and correctly rejected a
single-byte-flipped ciphertext without writing `--out` (`DECISIONS.md` D-34's "built binary, not
just in-process" policy). New `cargo fuzz` target (`fuzz_targets/kalyna_ccm.rs`, `TASKS.md` T-81)
directly attacks `open_in_place` with never-produced-by-`seal_in_place` bytes, not just round-trip
output - a 60s MSVC smoke run alongside the other three targets found zero crashes (cov 801,
110,542 execs; all four targets together: exit 0). `cargo miri test` scoped to the five
official-vector tests (the full `proptest` suite hits a pre-existing proptest+Miri
directory-isolation interaction on this Windows dev machine, already affecting the
*already-existing* `kalyna.rs`/`strumok.rs` proptest suites too, not something new introduced here,
and separately impractically slow to run to completion under Miri regardless) - clean, no UB.

**Not done, by design**: nonce-generation strategy (D-40, `TASKS.md` T-82); wiring this into
`crypto_secretbox`/`uacrypt`'s reserved top-level `encrypt`/`decrypt` names (still blocked on D-05's
primary-text confirmation, unchanged by this provisional adoption); GCM (considered, deferred - see
D-40's sibling reasoning in `TASKS.md`'s Phase-1 CCM task write-up: GCM needs a new, block-size-
parameterized GF(2^m) field with no existing code in this crate to build on, a materially bigger
surface for a provisional primitive than CCM's pure composition over the already-verified
`ExpandedKey::encrypt_block`).

## D-42: `uacrypt` streaming CLI commands must genuinely stream from disk, not just from a library

Raised 2026-07-23 by the user while reviewing T-83 (Kupyna's streaming API): is `uacrypt kupyna-
digest` "honest" streaming - small, bounded chunks in memory, no hidden whole-file buffering
anywhere? Answer at the time: `hazmat::kupyna`'s `Kupyna256Hasher`/`Kupyna512Hasher` genuinely are
(fixed-size internal state, no `alloc`, no I/O in `hazmat` at all) - but `uacrypt kupyna-digest`
itself was not: it still called `std::fs::read` once and hashed the whole in-memory result. The
library-level streaming primitive existing does not, by itself, make the CLI that calls it
memory-bounded - that has to be wired deliberately.

**Decision, and what changed**: `run_digest_command` (`crates/uacrypt/src/lib.rs`) now has two
paths, both routed through `Kupyna256Hasher`/`Kupyna512Hasher` rather than `Kupyna256::digest`/
`Kupyna512::digest` directly:
- **`iterations <= 1` (real single-pass usage)**: streams `--in` from disk via `std::fs::File` +
  `Read::read` in fixed [`DIGEST_STREAM_CHUNK_BYTES`] = 8 KiB chunks, `update()`-ing and discarding
  each one - peak memory is bounded by that constant regardless of `--in`'s size, not by the file
  size. 8 KiB was chosen as a conservative "small, safe default" I/O buffer: large enough that
  per-`read()` syscall overhead stays negligible, small enough to be a genuine streaming bound
  rather than "the whole file with a constant's name on it."
- **`iterations > 1` (D-34's benchmark path)**: still reads the file once, up front - re-reading it
  from disk on every iteration would reintroduce disk-cache-dependent I/O noise into the exact
  MB/s figure this path exists to measure, undermining the reason `iterations` exists at all. Each
  iteration re-hashes that one resident buffer through the same `Hasher`, but fed in much larger
  [`DIGEST_BENCH_CHUNK_BYTES`] = 1 MiB chunks - tuned for throughput (negligible `update()`-call
  overhead against a MiB of hashing work) rather than memory footprint, since memory is not the
  constraint this path is optimizing for. Byte-identical output to calling `digest()` directly is
  guaranteed by T-83's own chunk-invariance proof at the `hazmat::kupyna` level, so this changes
  nothing already recorded in `PERFORMANCE.md`.

Both paths verified: a new test (`run_digest_command_streams_multi_chunk_input_correctly`) uses a
message spanning multiple 8 KiB chunks with a non-aligned remainder, checked against
`Kupyna512::digest` directly for both the single-pass and benchmark paths; manually re-confirmed
against the real release binary on a 5 MiB+ file (both paths produced the identical digest).

**Standing policy, not just a one-off fix - apply the same principle to any other algorithm's CLI
command that is genuinely streamable, whenever it gains its own streaming API**: a library-level
streaming/incremental API existing (as Strumok's `apply_keystream` already effectively has, proven
chunk-invariant by T-24) does not by itself make the `uacrypt` command that wraps it
memory-bounded - each such command has to be deliberately wired to read its input in fixed chunks,
not `std::fs::read` the whole file, unless the underlying construction genuinely requires the whole
message up front (Kalyna-CCM's CBC-MAC header needs the plaintext length before processing - not
relevant in practice given its sourced 255-byte cap, D-41, but a real example of a construction that
would not qualify). When a command gets this treatment, follow T-83/this entry's shape: a small
chunk size for real single-pass usage, a larger chunk size for any `--iterations`-style benchmark
path that must still avoid repeated disk I/O inside the timed region - both sizes chosen for their
actual constraint (memory footprint vs. throughput), not copied from Kupyna's numbers by default,
since a cipher's per-call overhead profile is not identical to a hash's.

**`strumok-crypt` done too, same day (2026-07-23)**: unlike a hash, a stream cipher's output is the
same length as its input, so genuine streaming here means chunking *both* the disk read and the
disk write, not just the read - `run_strumok_command`'s `iterations <= 1` path now reads a
[`STRUMOK_STREAM_CHUNK_BYTES`] = 8 KiB chunk, `apply_keystream`s it in place, writes it, and
discards it, relying directly on `Strumok::apply_keystream`'s own chunk-invariance (`TASKS.md`
T-24) to make one-chunk-at-a-time equivalent to one call on the whole buffer. `--raw-schedule` has
no effect on this path - with exactly one iteration, constructing the cipher fresh vs. once is not
observably different, so the streaming path always constructs it once regardless of the flag.
`iterations > 1` (the benchmark path) is untouched: it still reads the whole file once up front,
for the same reason as `kupyna-digest`'s benchmark path (repeated per-iteration disk reads would
put I/O noise into the timed MB/s figure) - no artificial in-memory chunking was added there,
since (unlike Kupyna's per-block compression) `apply_keystream`'s cost has no chunk-size-dependent
behavior worth exercising once the data is already resident. Verified: a new test
(`run_strumok_command_streams_multi_chunk_input_correctly`, a message spanning multiple chunks with
a non-aligned remainder, checked against `Strumok512::new(...).apply_keystream(...)` directly) and
a manual round-trip through the real release binary on a 3 MiB+ file.

## D-43: First real version number - `0.0.0` -> `0.1.0`, README pre-release banner

Raised 2026-07-23 by the user: the workspace's crates had sat at the Cargo default placeholder
`version = "0.0.0"` since the project's scaffold (Phase 0) - not a real semver value, and not
publishable to crates.io as-is (crates.io rejects `0.0.0`). With the CI push/audit work just
finished, the user asked for a real version plus a visible pre-release/WIP marker on the GitHub
README, since the project is neither a complete library (no file-level `encrypt`/`decrypt`, D-05
still open) nor a complete CLI yet.

**Decision**: `0.1.0`, not a `0.1.0-alpha.N` pre-release tag. Under semver, the entire `0.x` range
already means "unstable, may break without a major bump" - that's the correct signal for where this
project actually is, and a pre-release suffix is a crates.io-publish-mechanics lever (yanking,
pre-release opt-in installs) better deferred to the actual first publish (`TASKS.md` T-17), not
decided speculatively now. Both `crates/dstu-core/Cargo.toml` and `crates/uacrypt/Cargo.toml`
bumped together, including `uacrypt`'s `dstu-core = { path = "...", version = "0.1.0" }` path-dep
version (missing this second spot would silently leave the wildcard-dependency problem T-75 already
fixed once). `xtask/Cargo.toml` deliberately left at `0.0.0` - separate `[workspace]`, dev-only
tool, never published, no reason to version it the same way.

**README**: a banner added at the very top (`README.md`, above the existing "An open Rust library
for..." paragraph, which stays as-is) stating the version, pre-release/WIP status, and - since this
is a crypto library, not just any 0.x project - the same safety caveats `SECURITY.md` already
states: not audited, not production-ready, no side-channel-resistance claim, Strumok/Kalyna-CCM
still provisional (D-15/D-41), no file-level `encrypt`/`decrypt` yet (D-05). A WIP notice on a
crypto library is a safety statement, not cosmetics - it must not undersell what's still missing.
`Cargo.lock` regenerated via `cargo build --workspace` (not hand-edited) to pick up both version
bumps.

See `docs/release-readiness.md` (added same day) for the fuller gap analysis - what a genuine
libsodium-equivalent 1.0 release still needs beyond this version bump.

## D-44: Kupyna-based KMAC (`crypto_auth` equivalent) implemented - dual-oracle, both constructions read

`TASKS.md` T-38, first item worked from `docs/release-readiness.md`'s ordered list (T-38/T-39/
T-40/T-48). `docs/papers/Kupyna.pdf` states DSTU 7564:2014 "defines both the hash function and its
additional mode for message authentication code generation" but does not itself describe that mode
anywhere in its 536 lines (checked directly via `pdftotext` + `grep`, not assumed) - so, same
posture as Strumok (D-15) and Kalyna-CCM (D-41), this construction is **provisional**, cited to
reference implementations rather than the primary standard text.

**Stronger evidence than either of those two precedents, though, and worth stating plainly rather
than hedging identically**: this time **both** implementations' actual construction code was read,
not just one plus the other's vector output.
`oracles/uapki/library/uapkic/src/dstu7564.c`'s `dstu7564_init_kmac`/`_update_kmac`/`_final_kmac`
(its own comment states the construction directly: `HMAC(M,K) = H(PAD(K) || PAD(M) || (~K))`) and
`oracles/bouncycastle-java/.../macs/DSTU7564Mac.java` (a genuinely independent Java implementation,
not a port of the C - different vendor, different language, different code shape) agree
byte-for-byte on all three self-test vectors (MAC-256/384/512) - see `crates/dstu-core/tests/
vectors/kupyna-kmac/kmac-{256,384,512}.json`, each recording which of BC's `macTests()` cases it
matches. Full algorithm citation in `docs/pseudocode/kupyna-kmac.md`.

**Construction, briefly** (both oracles agree): key `K` must be exactly `mac_len` bytes (32/48/64 -
UAPKI hard-enforces this via `CHECK_PARAM`; BC's own code is more permissive but no vector anywhere
exercises a different length, so this project matches the *stricter*, fully-tested behavior rather
than building an untested code path). `MAC = H(PAD(K) || PAD(M) || ~K)`, where `PAD(K)` uses `K`'s
own bit-length, `PAD(M)` uses `M`'s own bit-length (not `K`'s length added in), `~K` is the
bitwise complement of `K`, and the outermost `H` is Kupyna's completely ordinary finalize, whose own
length field naturally ends up correct (the true total of everything fed to it) purely from feeding
those three pieces through `KupynaCore::update` in order - no separate length-tracking needed
beyond what `KupynaCore` already does. MAC-256 uses Kupyna-256's block structure; **MAC-384 is not
a separate hash variant** - it and MAC-512 both use Kupyna-512's 1024-bit-block structure, truncated
to 48 or 64 bytes from the tail respectively (`KupynaCore::finalize`'s existing `output_bytes`
parameter already does exactly this truncation, reused as-is with `output_bytes = 48` - no new
truncation logic needed). MAC-384 is the *only* one of the three vectors that exercises this
truncation-direction question (48 < 64, unlike the other two where `mac_len` equals the underlying
digest's own natural output size) - non-negotiable to include for exactly that reason, confirmed by
the advisor consult before implementation.

**Implementation**: new sibling module `hazmat::kupyna_kmac` (`crates/dstu-core/src/hazmat/
kupyna_kmac.rs`), registered in `hazmat/mod.rs`. Required refactoring `hazmat::kupyna`'s internal
`KupynaCore`: its padding-tail formula (`0x80` || zero bytes || 96-bit LE length) was extracted from
`finalize` into a shared `pub(crate)` `kupyna_padding` function, and `KupynaCore` itself (plus
`new`/`update`/`finalize`/`block_bytes`, plus a new `buffered()` accessor) made `pub(crate)` so
`kupyna_kmac` can drive the same running compression state through its three-part construction
directly, rather than only through the public one-shot/streaming API's automatic single-pad-and-
done semantics. Three public unit structs (`Kupyna256Kmac`/`Kupyna384Kmac`/`Kupyna512Kmac`), each
with `mac(key, message) -> Result<[u8; N], KmacError>` and a `verify(key, message, expected) ->
Result<(), KmacError>` using `subtle::ConstantTimeEq` for the tag comparison (per `SECURITY.md`'s
hard constraint - a MAC verification is exactly the "secret comparison" category that rule exists
for). `KmacError::WrongKeyLength`/`TagMismatch`. The one subtlety worth flagging for future
reference: `PAD(M)`'s padding suffix must be fed through `update` as *only the new bytes* (`0x80`
onward) - the already-buffered tail of `M` is already sitting inside `KupynaCore`'s own buffer from
the preceding `update(message)` call, so re-including it in the fed slice would double-count it.

**Verified, test-first**: all 6 tests (3 official vectors including MAC-384's truncation case, a
wrong-key-length rejection, a tampered-MAC rejection, a tampered-message rejection) written before
the implementation, all green on the **first attempt** - no debugging cycle needed, unlike T-83's
Kupyna-streaming buffering bug. `cargo test --workspace`/`clippy -D warnings`/`fmt --check` all
clean; 6 of the 8 `no_std`/`alloc`/`std`/`small-tables` feature combinations re-checked (uses no
`alloc`, no new `cfg` gating). `cargo +nightly miri test -p dstu-core --test kupyna_kmac` clean (no
UB, ~22s, no `proptest` in this test file so none of the CI miri-slowness applies here); the
existing `kupyna.rs` official-vector tests re-run under Miri too, confirming the `KupynaCore`
refactor didn't disturb the pre-existing streaming/one-shot paths.

## D-45: Kupyna-based KDF (`crypto_kdf` equivalent) - a design decision, not a transcription, no oracle exists

`TASKS.md` T-39, second item from `docs/release-readiness.md`'s ordered plan. **A materially
different posture from D-44/D-41/D-15**: those are all "provisional pending the primary text" -
a real reference implementation exists, it's just not confirmed against the official standard yet.
Here, **no reference implementation of a Kupyna-based KDF exists anywhere** (there is no separate
DSTU KDF standard - `docs/dstu-crypto-project.md`'s own API mapping already says so), so there is
nothing to port and no oracle vector to check against, ever. What follows is a from-scratch design
decision using an established international *pattern*, not a citation to a specific source file.

**Two established patterns were weighed** (full reasoning in `docs/pseudocode/kupyna-kdf.md`,
not duplicated here): full RFC 5869 HKDF (Extract-then-Expand) vs. libsodium's simpler
`crypto_kdf_derive_from_key` (one keyed-hash call per subkey, no Extract stage, assumes an already-
uniform master key). **Chosen: libsodium's shape.** HKDF's own security proof is stated in terms of
HMAC specifically; `hazmat::kupyna_kmac`'s construction (`H(PAD(K) || PAD(M) || ~K)`) is not HMAC,
and assuming HKDF's proof transfers to a different keyed construction without justification would
be exactly the unexamined-assumption failure this project's "no homegrown primitives" discipline
exists to prevent. Skipping Extract sidesteps that question entirely: the only assumption made is
that Kupyna-KMAC is a reasonable keyed PRF - the *same* assumption T-38 already makes implicitly by
using it as a MAC, not a new one. HKDF's Expand stage also has a chaining counter whose off-by-one
correctness a KAT would normally catch - and no KAT exists here to catch it, so avoiding that
machinery entirely removed a real risk, not just complexity.

**Construction**: `subkey = KupynaNKmac::mac(master_key, context (8 bytes) || subkey_id as
little-endian bytes (8 bytes))` - modeled after libsodium's public design *shape* (recalled from its
documentation, not vendored here as a source to cite a line against), not a byte-for-byte port of
its BLAKE2b-specific internals (which use BLAKE2b's native `salt`/`personal` parameters - a
hash-specific feature Kupyna doesn't have). Subkey length is fixed at the chosen variant's MAC size
(32/48/64 bytes), unlike libsodium's flexible 16-64-byte output - a real constraint from Kupyna
lacking BLAKE2b's variable-output feature, not an arbitrary restriction. `master_key` is a
statically-sized `[u8; N]` (not `&[u8]`), so - unlike `kupyna_kmac`'s runtime-checked API - there is
no wrong-key-length error path at all: callers cannot construct an ill-typed call in the first
place, one step more misuse-resistant than the layer it's built on.

**Testing, honestly scoped**: no oracle vector exists to write, so verification is determinism,
distinctness (different `subkey_id`/`context`/`master_key` produce different subkeys - the actual
security property being claimed, checked via `proptest` over random inputs since it's not a fixed
case), and an exact byte-layout pin against a manual `kupyna_kmac` call (so a future refactor can't
silently reorder `context`/`subkey_id` without a test catching it). **None of this can catch "the
construction itself is wrong" the way a KAT would** - stated plainly in `docs/pseudocode/
kupyna-kdf.md` rather than implied to carry the same confidence as T-38's dual-oracle vectors.

New module `hazmat::kupyna_kdf` (`Kupyna256Kdf`/`Kupyna384Kdf`/`Kupyna512Kdf`, each one
`derive_subkey`), built directly on `hazmat::kupyna_kmac` (T-38) with no new low-level primitive.
**Verified**: all 7 tests (3 determinism/byte-layout-pin cases, 3 `proptest` distinctness suites)
green on the **first attempt**. `cargo test --workspace`/`clippy -D warnings`/`fmt --check` clean;
6 of 8 feature combinations re-checked (no new `cfg` gating). `cargo +nightly miri test` hit the
same pre-existing proptest+Miri isolation crash as everywhere else in this workspace (T-81/T-85) -
confirmed clean (no UB) with the same local workaround
(`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8`), ~174s.

## D-46: `crypto_sign` (DSTU 4145 wrapper, T-48) - deterministic nonce derivation, not caller-random

`TASKS.md` T-48, last item from the user's ordered list (`docs/release-readiness.md` step 5). The
first module in the high-level "easy" layer D-09 planned but never built - a real architectural
precedent, not just another primitive wrapper, so it's recorded here in more depth than a typical
task entry.

**The fork, and why it wasn't decided silently**: `hazmat::dstu4145::signature::sign` takes its
ephemeral nonce `e` as a caller-supplied parameter (matching Bouncy Castle's `DSTU4145Signer`,
confirmed by reading it - `random` field, `SecureRandom`-backed). A `crypto_sign` wrapper has to
resolve this one way: either add an RNG dependency (`std`-gated `getrandom`, or a `RngCore` trait
bound at the hazmat layer, the D-04-addendum-anticipated shape) and generate `e` fresh each call,
or derive `e` deterministically from `(d, message)` so no randomness is needed at signing time at
all. This is a real security-posture fork, not an implementation detail: nonce reuse is *the*
catastrophic failure mode of this signature family (a reused/predictable `k` leaks the private key
outright - the PS3 root-key disclosure, several Bitcoin wallet thefts, all trace to exactly this).
Put to the project owner rather than picked silently (same posture as T-40's re-scoping question).
**Chosen: deterministic**, matching Ed25519/libsodium's own misuse-resistant design rather than the
classical DSA-family default - this is what "libsodium-equivalent, safe by construction" (the
project's own stated release goal) actually implies for a signature scheme, and it eliminates an
entire bug class from the wrapper's caller surface rather than documenting around it.

**Construction**: an RFC 6979-*style* adaptation, not a literal port - RFC 6979's own construction
and proof are stated in terms of HMAC specifically, and `hazmat::kupyna_kmac`'s construction is not
HMAC (the same non-transferable-proof reasoning D-45 already applied to HKDF). What's kept from
RFC 6979 is the shape: derive the nonce from a PRF keyed by the private key, seeded with the
message hash, with rejection-sampling on an out-of-range result - not RFC 6979's specific HMAC-DRBG
iteration (`V`/`K` state machine), which doesn't have an obvious KMAC-based equivalent and would be
inventing new unverified machinery for no proven benefit here. Concretely:
`e = reduce_mod_n(Kupyna256Kmac::mac(key = zero-pad(d, 32), message = hash || counter))`, counter
starting at 0 and incrementing on the ~`2^-163`-probability chance that `hazmat`'s own sign()
rejects the result (`F_e == 0`, `r == 0`, or `s == 0` - see `signature::sign`'s doc comment). `d`'s
21-byte value is left-padded with zeros to `Kupyna256Kmac`'s required 32-byte key length - an
embedding, not a truncation, so no bits of `d` are dropped. `Scalar::reduce_wide_bytes` (new,
`pub(crate)`, `hazmat::dstu4145::scalar`) folds the 32-byte KMAC output into a valid scalar via the
same bit-serial constant-time reduction `reduce_mod_n` already uses for multiplication products,
generalized to arbitrary input width.

**No oracle exists for this specific construction** (same honest-scoping posture as D-45's KDF) -
no reference implementation derives DSTU 4145 nonces this way, so there's nothing to cross-check
the *derivation* against. What *is* oracle-checked: `VerifyingKey::verifying_key()`'s `Q = -d*G`
computation, against the official Annex B.1 worked example's own `(d, Q)` pair
(`tests/vectors/dstu4145/gf2m163.json`) - this reuses `hazmat`'s already-vector-confirmed point
arithmetic, so it's a real external check, just not of the nonce derivation itself. Sign/verify
correctness is tested via round-trip, tamper-rejection (message, signature bytes, wrong verifying
key), and a `proptest` sweep over random keys/messages - the same posture `dstu4145_signature.rs`'s
own round-trip test already established for the raw hazmat layer.

**Two smaller decisions bundled into the same module**:
- `sign`/`verify` take a raw `message: &[u8]`, hashed internally with Kupyna-256
  (`hazmat::kupyna::Kupyna256`) - matching libsodium's own `crypto_sign(message, ...)` ergonomics.
  `hazmat::dstu4145::signature` itself stays digest-agnostic by its own design, unaffected.
- `VerifyingKey::to_uncompressed_bytes`/`from_uncompressed_bytes` use a plain 42-byte `x || y`
  encoding, **not** the DSTU 4145 standard's own compressed point encoding (official text
  §6.9/§6.10, Bouncy Castle's `DSTU4145PointEncoder.java`) - that encoding isn't implemented
  anywhere in this project (`docs/pseudocode/dstu4145.md` already flagged it as future,
  unrelated-to-sign/verify work). Stated explicitly in the module doc so it can't be mistaken for
  spec-compliant interoperable serialization; tracked as its own future task rather than folded
  into T-48's scope.

`Scalar` also gained `#[derive(Zeroize)]` this session (not `ZeroizeOnDrop` - incompatible with
`Scalar` being `Copy` and used by-value pervasively throughout `hazmat::dstu4145`, `E0184`) -
closing a pre-existing gap against `CLAUDE.md`'s "all key material is `Zeroize`/`ZeroizeOnDrop`"
hard constraint that predates this task. `crypto_sign::SigningKey` (the actual key-material holder
in the new module) implements `Drop` calling `.zeroize()` on its inner `Scalar` explicitly.

**Verified**: 9 new tests (determinism, official-vector `Q` cross-check, round-trip, 3
tamper-rejection variants, 2 invalid-key rejections, 1 `proptest` sweep) all green on first attempt
after fixing test constants (initial fixed test scalars accidentally exceeded the curve order `n`,
caught immediately by `from_bytes`'s own validation - not a construction bug). Full workspace
`cargo test --all-features` green (no regressions in the other 84 tests). `clippy -D warnings`
clean after two fixes (`expect_used` on the KMAC call - resolved via `unreachable!()` behind a
`let...else`, matching the crate's `#![deny(clippy::expect_used)]`; `manual_let_else`). `fmt --check`
clean. `no_std` (no-default-features), `alloc`-only, and `small-tables` builds all clean - the new
module uses no heap allocation, all fixed-size arrays. `cargo +nightly miri test` (local,
`MIRIFLAGS=-Zmiri-disable-isolation`) hit the same slow-suite issue T-85 already documents for
`dstu4145_signature`'s own proptest (each sign+verify runs the 163-iteration scalar ladder several
times, and Miri interprets every step) - the 8 non-proptest tests completed with no UB reported,
but the `dstu4145_crypto_sign_roundtrip` proptest was still running after ~21 minutes and was killed
locally rather than left unbounded, matching T-85's own stated posture ("if 30 minutes proves
insufficient, the real fix is scoping miri away from the slow suite, not raising the timeout
further"). Not re-run to completion locally; CI's already-tuned miri job (`PROPTEST_CASES=1`, lower
than the local `PROPTEST_CASES=2` attempted here, plus the existing 30-minute job timeout) is the
authoritative check for this file, same as it already is for `dstu4145_signature.rs`.

## D-47: Standing tie-breaker rule for architectural forks - TLS 1.3 lessons + libsodium API shape + safe-only modes

Requested explicitly by the project owner as a general rule, not tied to one primitive: this
project has hit the same *shape* of fork twice now (D-05/D-41's mode-of-operation choice for
Kalyna, D-46's nonce-generation choice for `crypto_sign`) and resolved both the same way without
that reasoning ever being written down as a reusable rule. This entry makes it explicit so future
forks don't each re-derive it from scratch, and so a fork's resolution can be checked against a
written rule rather than re-argued each time.

**The rule**: when an architectural fork has no single DSTU citation that settles it (the primary
spec is silent, ambiguous, or not yet available - the actual recurring situation in this project,
not a hypothetical), resolve it by three ranked criteria, in order:

1. **Modern AEAD/crypto engineering consensus, TLS 1.3 as the reference point.** TLS 1.3 (RFC 8446)
   dropped every hand-composed construction (separate MAC-then-encrypt, CBC+HMAC) and allows only
   combined, misuse-resistant constructions (AES-GCM, ChaCha20-Poly1305, AES-CCM) - not a stylistic
   preference, but the direct empirical response to a real vulnerability lineage from hand-rolled
   composition (BEAST, Lucky13, POODLE, all tracing to composition mistakes: ordering, timing,
   padding). When a fork is "hand-compose two primitives" vs. "use a single combined construction,"
   default to the combined one. This is the reasoning D-41 already applied to justify Kalyna-alone
   CCM over encrypt-then-MAC; D-47 generalizes it instead of leaving it embedded in one entry.
2. **libsodium's API shape**: minimal surface, hard defaults, nothing left for the caller to
   configure that could be configured wrong. Concretely: no algorithm/mode/parameter choice exposed
   as a public knob when one safe default exists (this is already `CLAUDE.md`'s stated project
   identity - "hard, safe defaults, misuse-resistant API... rather than OpenSSL" - D-47 makes it an
   explicit tie-breaker criterion, not just a mission statement). D-46's deterministic-nonce choice
   for `crypto_sign` (matching Ed25519/libsodium, eliminating caller-managed entropy entirely rather
   than documenting a nonce-reuse risk) is the precedent for this criterion specifically.
3. **Expose only safe modes of operation, full stop.** If a construction has both a safe and an
   unsafe/legacy mode (e.g. a mode requiring caller-managed nonce uniqueness with no misuse-resistant
   fallback, or a legacy/classical variant kept only for interop), the unsafe mode does not get a
   public `dstu_core`/`uacrypt` entry point - not even behind a flag - unless a real, named caller
   need forces it (at which point that need, and the resulting risk, gets its own `DECISIONS.md`
   entry, not a silent addition). This is the same posture already implicit in `uacrypt` reserving
   `encrypt`/`decrypt` for only the eventual fully-safe construction (D-31/D-41's provisional-CLI-
   naming discipline) rather than exposing raw block-cipher or CCM-with-caller-nonce as top-level
   commands.

**Scope and limits, stated so this can't be over-applied**: this rule governs *forks with no
settling DSTU citation* - it does not license overriding an actual primary-spec requirement once
D-05 resolves, or any other case where the standard itself is unambiguous. `CLAUDE.md`'s existing
hard constraint ("no primitive without a cited spec section... citation goes in `DECISIONS.md`")
stays senior to this rule wherever both could apply: a real citation wins over TLS 1.3 precedent or
libsodium-shape preference every time. This rule is for the gaps, not a general license to design
by analogy instead of by spec.

**Applying it retroactively**: D-41 (Kalyna-CCM) and D-46 (`crypto_sign` nonce) already followed
this reasoning before it was written down - re-cited here as the two data points the rule is
generalized from, not re-litigated or changed.

## D-48: `randombytes` (T-72) - a plain `randombytes_buf` function, not a generic RNG trait

Not a DSTU question at all (`docs/dstu-crypto-project.md` already says so) - the OS CSPRNG wrapper,
same role `getrandom` already plays inside `uacrypt` (T-82/D-40), now given a real `dstu_core`
entry point per `docs/release-readiness.md` step 4's "no core-crate high-level wrapper yet" gap.

**What was built, deliberately minimal**: `dstu_core::randombytes::randombytes_buf(buf: &mut [u8])
-> Result<(), RandomError>`, `std`-gated, over `getrandom::fill` - the direct equivalent of
libsodium's own `randombytes_buf(buf, size)`, a concrete function, not a generic parameter. `std`
now activates an optional `getrandom = "0.3.4"` dependency (`std = ["dep:getrandom"]`) rather than
an unconditional one - `getrandom` never enters the `no_std`/`alloc`/`small-tables` build graphs at
all (confirmed: all three still build clean), so it can never trip `getrandom`'s own
`compile_error!` on an unrecognized bare-metal target (`DECISIONS.md` D-04's addendum). This is not
a violation of that addendum's "never `crates/dstu-core`" line - that line was about T-82's
*unconditional* addition; an optional, feature-gated dependency that compiles out entirely when the
feature is off is the different case the addendum's own pattern (2) (an optional `std` convenience
wrapper "on top of" pattern (1)'s core) already anticipated.

**A larger design was researched and explicitly not built - recorded here so the research isn't
lost, not discarded**: the initial plan (before this entry) was to also add a generic
`pub use rand_core::CryptoRng` re-export, so future constructions (`crypto_secretbox` once D-05
resolves, DSTU 4145 key generation if it moves in-crate) could accept `&mut impl CryptoRng`
directly, following D-04 addendum's own cited "trait injection... `RngCore`+`CryptoRng`,
ed25519-dalek/x25519-dalek's own convention" pattern. Caught before implementation (advisor review):
**there is no current consumer** of that trait anywhere in this crate - `crypto_sign` is
deterministic (D-46, no RNG), `hazmat` is "caller supplies everything" by design (D-09), and
anything that *would* consume it (`crypto_secretbox`, DSTU 4145 key generation) is blocked on D-05
or doesn't exist yet. Adding it now would mean an unconsumed re-export permanently dragging a
pre-1.0 dependency into a crate intended for crates.io publication (T-17) - exactly the kind of
speculative abstraction this project's own discipline (and D-47's own libsodium-minimal-surface
criterion, ranked above "match an ecosystem convention") argues against. Deferred to the trait's
first real consumer, per D-04's own framing ("nothing needs it today").

**What the deferred research found, verified against real registry sources, not memory** (to
execute when a consumer exists, not now):
- `rand_core` 0.10.1 is the *current* version, but it just deprecated its own `RngCore`/
  `TryRngCore` trait names in favor of `Rng`/`TryRng` (`CryptoRng` stays as a marker trait, now
  `Rng + TryCryptoRng<Error = Infallible>`) - a breaking, pre-1.0 redesign, confirmed by reading
  its `src/lib.rs` directly (registry cache), not assumed from the name D-04's addendum used.
- `ed25519-dalek` 3.0.0 (current, checked via a real `cargo fetch`) confirms the trait-injection
  pattern is still alive and matches D-04's citation - but gated behind an optional `rand_core`
  Cargo feature pinned to `rand_core = "0.10"`, consumed only by `SigningKey::generate<R:
  CryptoRng + ?Sized>(csprng: &mut R)`. Its default (no-feature) signing path is deterministic,
  same posture this project already chose independently for `crypto_sign` in D-46 - real
  cross-project convergence on the same answer, not just a citation match.
- `getrandom` 0.4.2 (a real minor-version-equivalent bump from this project's current 0.3.4, not
  yet adopted) ships an optional `sys_rng` feature (`getrandom::SysRng`, re-exporting `rand_core`
  itself so a downstream crate doesn't even need its own version-pinned `rand_core` dependency) -
  a ready-made, upstream-maintained `rand_core::CryptoRng` implementation over the OS CSPRNG.
  **When a real consumer lands**: bump to `getrandom = "0.4.2"` with `features = ["sys_rng"]`
  instead of hand-rolling an `OsRng` wrapper - avoids writing new security-relevant glue code for
  something upstream already provides and matches `ed25519-dalek`'s own demonstrated usage.

**Only `randombytes_buf` is implemented** - libsodium's `randombytes_uniform`/`randombytes_random`/
`randombytes_buf_deterministic` are not built and not planned as part of T-72; this closes the gap,
it doesn't claim full `randombytes` API parity.

**Verified**: 4 new tests (buffer actually gets filled, two draws don't collide, zero-length
doesn't error, a sub-slice write doesn't touch bytes outside it) - no oracle exists for OS
randomness by definition, same posture already established for `hazmat::kupyna_kdf`'s distinctness
tests (D-45). Full workspace `cargo test --all-features` green (no regressions). `cargo clippy
--workspace --all-features -- -D warnings` and `cargo fmt --check` clean workspace-wide. `no_std`
(no-default-features), `alloc`-only, and `small-tables` builds all confirmed clean;
`cargo tree -e no-dev --no-default-features` confirms `getrandom` is absent from that dependency
graph outright, not just unused at runtime. `cargo +nightly miri test --test randombytes`
(targeted, not the full-workspace suite) is clean, no UB, ~1s - this module has no scalar-ladder
equivalent to the T-85/D-46 slow-suite issue, so a targeted run was both sufficient and fast enough
to actually complete, unlike D-46's admittedly-incomplete full-suite attempt. `cargo audit`/
`cargo deny check` both clean for the new `getrandom` dependency (via a full `cargo xtask ci` run
covering fuzz/audit/deny/oracle-harness layers - that run's captured log was truncated to its last
~100 lines by the background-output mechanism, losing the miri section specifically, which is why
miri was re-run standalone above rather than cited from that log). A `getrandom` row was added to
`SECURITY.md`'s supply-chain table alongside `zeroize`'s existing one.

**Bonus consolidation, behavior-preserving**: `uacrypt`'s existing direct `getrandom::fill` call
(T-82's CCM nonce generation) now goes through `dstu_core::randombytes::randombytes_buf` instead,
and `uacrypt`'s own direct `getrandom` dependency was removed from its `Cargo.toml` - one call site
and one version pin for OS randomness in this workspace, not two. All 23 existing `uacrypt` tests
(including the CCM fresh-nonce-per-call test) still pass unchanged; `cargo clippy --workspace
--all-features -- -D warnings` and `cargo fmt --check` both clean workspace-wide.

## D-49: `argon2` crate vetted for T-71 (`crypto_pwhash`) - not yet adopted, research only

Per `CLAUDE.md`'s "research before implementation" discipline, the candidate crate T-71 flagged
2026-07-24 (`docs/dstu-crypto-project.md`'s libsodium mapping, `TASKS.md` T-71) was vetted against
real registry/repo sources before any code was written - no `crypto_pwhash` implementation exists
yet, this entry only records the vetting so it isn't redone from scratch when T-71 is picked up.

**Crate**: `argon2` (`RustCrypto/password-hashes` monorepo, `argon2/` subdirectory), maintainer
"RustCrypto Developers" (org-maintained, not a single-person crate). Latest stable `0.5.3`
(released 2024-01-20, a docs/big-endian-support maintenance release, not a feature bump); a
pre-release `0.6.0-rc.8` also exists on the `master` branch but is not the stable channel this
project would pin - if T-71 is picked up before `0.6.0` stabilizes, pin `0.5.3`, not the rc.
License dual `MIT OR Apache-2.0` (matches this project's own license, `Cargo.toml`). MSRV `1.65`
(the stable `0.5.3` tag's own `rust-version` field, checked directly - not the `master`/`0.6.0-rc`
branch's `1.85`, an easy mixup this entry initially made and is correcting here rather than
silently), comfortably under this project's `rust-toolchain.toml` (unpinned `stable`, always
newer). Downloads
~40M total / ~17M recent (crates.io) - the de facto standard Argon2 implementation in the Rust
ecosystem, not a niche alternative (`argon2-rs`/`rust-argon2` are the other candidates in this
space and were not chosen - RustCrypto org maintenance and shared dependency surface with
`blake2`/`password-hash`/`zeroize`, already-vetted or already-used crates in this workspace, was
the deciding factor over a from-scratch comparison).

**`no_std` compatibility, checked against this project's MVP hard constraint**: the crate's own
README states explicit support for "embedded (i.e. `no_std`) environments, including ones without
`alloc` support" - relevant because Argon2's memory-hard design normally implies a large working
buffer, so a caller-supplied-buffer no-alloc path existing at all is worth confirming rather than
assuming. The `0.5.3` tag's actual `[features] default` (checked directly, not assumed) is
`["alloc", "password-hash", "rand"]` - none of the three appropriate to enable unconditionally for
a `no_std` core build, mirroring the `std`-gating pattern already established for `getrandom`
itself (D-48). See D-50 for how this was actually wired (feature-gated behind a new dedicated
`pwhash` feature, not folded into `std`, and with `rand` deliberately left off).

**Audit status - checked, not assumed**: no independent third-party audit (NCC Group, Cure53,
Trail of Bits) of the `argon2` crate specifically was found. This is a real gap, not an oversight
in the search - NCC Group's RustCrypto-adjacent audit work (Dec 2019) covered the AEAD crates
(AES-GCM, ChaCha20Poly1305), and Cure53's RustCrypto audit covered `xsalsa20poly1305`/`crypto_box`
- neither touched `password-hashes`. `TASKS.md` T-71's existing "not yet vetted for a specific
audit of *that* crate" caveat is confirmed accurate, not stale.

**CVE/advisory history**: clean. Checked both the local `cargo audit` advisory database already
cached on this machine (`~/.cargo/advisory-db`, no `crates/argon2` directory exists in it at all)
and the upstream `RustSec/advisory-db` repository directly (no advisory directory for this crate)
- two independent checks, not one.

**Conclusion**: `argon2` clears this project's supply-chain bar (`SECURITY.md`) on every axis
checked except independent audit, which is a real, disclosed gap rather than a blocker - the same
posture already accepted for `zeroize`/`getrandom` in this workspace (D-20, D-48), both also
RustCrypto-ecosystem-standard and also not independently audited as standalone crates. **Not yet
added as a dependency** - this entry is vetting only; adoption (Cargo.toml entry, `std`-gating
design, actual `crypto_pwhash` API) is T-71's own implementation step, still to come.

## D-50: `crypto_pwhash` (T-71) implemented over `argon2` 0.5.3 - dedicated `pwhash` feature, libsodium's own Argon2id parameter choices, `rand_core` enters transitively despite that

User approved implementation 2026-07-24, immediately after D-49's vetting. What got built:
`dstu_core::crypto_pwhash::{hash_password, verify_password, Strength}` (`src/crypto_pwhash.rs`) -
`hash_password(password: &[u8], strength: Strength) -> Result<String, PwHashError>` produces a
self-describing PHC string; `verify_password(password: &[u8], hash: &str) -> bool` re-derives
params from that string and returns a single pass/fail signal (`false` for both a wrong password
and a malformed string - libsodium's own `crypto_pwhash_str_verify` convention, nothing for a
caller to mishandle by branching differently on the two failure modes).

**Every constant is cited to libsodium's real C source, not assumed from memory** - read directly,
not recalled:
- `crypto_pwhash_argon2id.h`: `SALTBYTES` = 16, `OPSLIMIT_INTERACTIVE/MODERATE/SENSITIVE` = 2/3/4,
  `MEMLIMIT_INTERACTIVE/MODERATE/SENSITIVE` = 67108864/268435456/1073741824 bytes (64/256/1024
  MiB).
- `pwhash_argon2id.c`: `STR_HASHBYTES` = 32 (the PHC-string variant's fixed output length - not
  user-configurable, so `Params::new(..., None)` defaulting to `argon2`'s own 32-byte default
  lines up by construction, not coincidence left unverified); `crypto_pwhash_argon2id_str`'s own
  `argon2id_hash_encoded((uint32_t) opslimit, (uint32_t) (memlimit / 1024U), (uint32_t) 1U, ...)`
  call - parallelism is hardcoded to 1 lane, confirmed at the call site, not inferred from the
  header (the header has no lanes constant at all). `Strength`'s three variants map directly onto
  the three named tiers (`m_cost` = `MEMLIMIT / 1024`, `t_cost` = `OPSLIMIT`, `p_cost` = 1 always)
  - no raw `m_cost`/`t_cost`/`p_cost` knob is exposed publicly, per D-47's "libsodium API shape, no
  misconfigurable knobs" criterion applied literally: libsodium itself only exposes the three named
  presets, not the raw values, so this module doesn't either.

**`zeroize` feature enabled on `argon2` - caught by advisor review before declaring done, not
found independently**: the first pass built `argon2` with `features = ["alloc",
"password-hash"]` only, missing `argon2`'s own `zeroize` feature - confirmed from its `lib.rs`
(fetched during D-49's research, re-read here) that `initial_hash.zeroize()` and its internal
memory-block wipe are both `#[cfg(feature = "zeroize")]`-gated, off unless requested. Left off,
`argon2`'s internal state derived from the raw password would be left in freed-but-not-wiped
memory - directly in tension with this project's own hard constraint that all key material is
`Zeroize`/`ZeroizeOnDrop` (`CLAUDE.md`, `SECURITY.md`). Fixed by adding `"zeroize"` to the
`argon2` dependency's feature list - no new crate pulled in, `zeroize` is already a direct
`dstu-core` dependency (D-20). Re-verified after the fix: `cargo test -p dstu-core --features
pwhash` and the integration suite both still green, `cargo clippy --workspace --all-features -- -D
warnings`/`cargo fmt --all -- --check` both clean, all four `no_std`/`alloc`/`small-tables`
combinations still unaffected.

**`cargo audit`/`cargo deny check` - run and confirmed clean, not skipped**: `SECURITY.md` states
both "must stay green as soon as any dependency is added," and this task added roughly a dozen new
crates to the tree (`argon2`, `password-hash`, `blake2`, `base64ct`, `rand_core`, `cpufeatures`,
`generic-array`, `block-buffer`, `crypto-common`, `digest`, `typenum`, `version_check`) - a build/
test/clippy/fmt sweep alone says nothing about licenses, bans, or advisories on any of them.
`cargo audit`: 116 crate dependencies scanned, zero advisories. `cargo deny check`: `advisories
ok, bans ok, licenses ok, sources ok` - `bans ok` specifically confirms no duplicate-version
conflict between `password-hash`'s `rand_core 0.6.4` and `proptest`'s own `rand`/`rand_core`
dependency chain (a real risk worth checking, not assuming away, given `proptest` is already a
dev-dependency of this crate). The two pre-existing `license-not-encountered` warnings
(`BSD-2-Clause`/`ISC` unmatched allowances in `deny.toml`) are unrelated to this task, already
present before this session.

**Salt generation reuses this crate's own `randombytes_buf`, not `password_hash`'s
`SaltString::generate`**: `SaltString::encode_b64(&salt_bytes)` takes raw bytes directly (checked
against `password-hash` 0.5.0's real source, not assumed) - `randombytes_buf` draws 16 bytes
(`crypto_pwhash_argon2id_SALTBYTES`), `encode_b64` wraps them into the PHC-string salt field. This
was the intended way to avoid this module depending on `rand_core`/`OsRng` directly, and it
succeeds at that narrow goal (this module's own code never touches `rand_core`) - but see the next
paragraph for why the dependency shows up in the tree anyway.

**A real correction caught by actually building, not assumed clean**: `rand_core 0.6.4` compiles
into the dependency graph whenever `pwhash` is enabled, *despite* deliberately excluding argon2's
own `rand` feature. Confirmed via `cargo tree -p dstu-core --features pwhash -e normal`: `argon2
0.5.3`'s own `Cargo.toml` depends on `password-hash = { version = "0.5", optional = true }` without
`default-features = false`, and `password-hash 0.5.0`'s own `[features] default = ["rand_core"]` -
so enabling argon2's `password-hash` feature at all (needed for `PasswordHash`/`PasswordHasher`/
`SaltString`, i.e. required for this module's entire approach) unconditionally pulls in
`password-hash`'s default features too, including `rand_core`, via Cargo's additive-only feature
unification. There is no Cargo mechanism in `dstu-core`'s own manifest to suppress a transitive
dependency's defaults that another dependency (`argon2`) itself requested - this is not a bug in
this project's Cargo.toml, it is `argon2` 0.5.3's own manifest not passing
`default-features = false` on its `password-hash` dependency. Net effect: `rand_core` is compiled,
genuinely unused by any code this project wrote (`SaltString::generate`/`OsRng` are never called
here), and confirmed absent from every `no_std`/`alloc`/`small-tables` build (`cargo tree -p
dstu-core -e no-dev --no-default-features[--features dstu-core/small-tables]`, both clean) since
`pwhash` is never enabled there. A `rand_core 0.6.4` row was added to `SECURITY.md`'s supply-chain
table alongside `argon2`'s own - transitive-only dependencies still get vetted here, not just
direct ones, since they still execute in the final binary.

**Feature gating: a dedicated `pwhash` feature, not folded into `std` (D-48's own precedent)** -
`pwhash = ["std", "dep:argon2"]`, off by default. Reasoning, stated rather than left implicit:
Argon2's dependency surface (`base64ct`/`blake2`/`password-hash`, now transitively `rand_core` per
above) is meaningfully heavier than `getrandom`'s single small crate, and most of this project's
`std`-feature users (a Linux/Windows/macOS binary, say) have no use for a password-hashing KDF at
all - forcing it in unconditionally with `std` would be the wrong default for a project whose own
MVP scope explicitly targets constrained/embedded consumers too. No new CI plumbing was needed:
unlike `small-tables` (D-39), `pwhash` is purely additive and never alters the default code path,
so the existing `cargo test --workspace` (default features, `.github/workflows/rust.yml`) and
`cargo test --workspace --all-features` (which now also covers `pwhash`) already provide full
coverage without a new explicit step.

**Test-first, dual-oracle discipline applied even though this project didn't write the
algorithm**: no DSTU vector exists (`crypto_pwhash` is deliberately non-DSTU, D-03), but "no
homegrown primitives, verify before trusting" still applies to *this project's own use* of a
third-party crate, so:
- `tests/crypto_pwhash.rs` (5 tests): round-trip, wrong-password-rejected, malformed-string-
  rejected-not-a-panic, two-calls-use-different-salts, and (the load-bearing one, per this
  project's own "check what a fixed vector actually exercises" lesson, `CLAUDE.md`) each cheap
  `Strength` variant's PHC string is asserted to actually contain that variant's own `m=...,t=...`
  substring - a plain round-trip test would pass even if `Strength` were silently ignored inside
  `hash_password`, since `verify_password` re-derives params from whatever string it's given.
- `src/crypto_pwhash.rs`'s own `#[cfg(test)]` module: RFC 9106 (IETF, primary source) Appendix A's
  Argon2id test vector (password/salt/secret/associated-data all fixed patterned bytes, `p=4`,
  `m=32` KiB, `t=3`, tag `0d640df5...e659`) run directly against a raw `Argon2` construction
  (bypassing `hash_password`'s PHC-string layer and fixed `p=1` entirely) - confirms the `argon2`
  dependency itself is spec-correct before trusting it through this module's own wrapper.
- `Strength::Sensitive`'s own params (1024 MiB, t=4) are checked directly against a constructed
  `Params` rather than through a real `hash_password` call - a real hash at that tier took ~85s in
  an unoptimized debug build (too expensive to pay on every CI push for marginal signal, since
  `Interactive`/`Moderate` already prove `Strength` flows through the identical code path).

**Verified**: `cargo test -p dstu-core --features pwhash` (7 new tests, all green); `cargo test
--workspace --all-features` (full workspace, no regressions); `cargo clippy --workspace
--all-features -- -D warnings` and `cargo fmt --all -- --check` both clean; all four `no_std`/
`alloc`/`small-tables` build combinations confirmed clean (`pwhash` never enabled there); `cargo
tree` confirms `argon2`/`rand_core`/`password-hash`/`blake2`/`base64ct` are absent from every
`no_std`-profile dependency graph.

**`cargo miri test` - scoped, same class of impracticality as D-41's kalyna_ccm proptest issue**:
this module contains no `unsafe` code of its own (it only calls a safe-Rust dependency), so the
incremental UB-detection value of a full Miri run here is low to begin with, unlike hazmat-level
modules that manipulate raw byte buffers directly. What was actually run: the RFC 9106 vector test
(32 KiB memory) - `MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test --features pwhash
--lib crypto_pwhash::tests::argon2_dependency_matches_rfc9106_argon2id_vector` - clean, no UB,
~55s; and `sensitive_preset_has_libsodiums_sensitive_params` (no real hashing, params-only) -
clean, ~1s. A real `hash_password` call at any named `Strength` tier (64/256/1024 MiB) was not
attempted under Miri: Argon2 is deliberately memory-hard, and Miri's interpretation overhead
compounds with both the memory size and iteration count that make it memory-hard in the first
place - the 32 KiB vector alone took 55s, so the smallest real preset (2048x the memory, `t=2`
instead of `t=3`) is reasonably estimated at hours, not minutes. Not attempted, not silently
assumed clean - the 32 KiB vector test already exercises the identical `Argon2::hash_password_into`
code path with no unsafe code involved, so the marginal Miri value of also running a real
Interactive-tier hash is close to zero for the cost.

**Not built, deliberately out of scope**: libsodium's raw `crypto_pwhash()` (arbitrary-length KDF
output from password+salt, for key derivation rather than password storage) has no consumer
anywhere in this crate today, same reasoning D-48 applied to deferring a `CryptoRng` trait -
recorded here as a documented gap, not silently dropped, should a real consumer appear. No
`uacrypt` CLI subcommand either (T-71 scoped this to the core crate only, matching `crypto_sign`'s
own precedent of landing without CLI wiring first).

## D-51: `crypto_secretbox` (T-37) implemented - single fixed Kalyna-CCM variant, internal nonce, combined wire format, no AAD

Plan reviewed with the advisor before implementation, 2026-07-24. What got built:
`dstu_core::crypto_secretbox::{seal, open, SecretKey, SecretboxError, MAX_MESSAGE_LEN}`
(`src/crypto_secretbox.rs`) - a high-level, misuse-resistant wrapper over the already-provisional
`hazmat::kalyna_ccm` (D-41), the first construction actually built against D-05's Kalyna-alone
working assumption (T-36).

**Four forks resolved here, none with a settling DSTU citation, so D-47's tie-breaker rule
governs all of them**:

1. **Single fixed construction, not all five Kalyna-CCM variants.** Considered exposing all five
   `hazmat::kalyna_ccm` variants the way `hazmat` itself does, by analogy with
   `crypto_pwhash::Strength`'s small enum of safe presets - rejected. `Strength` is a genuine
   per-context cost/security tradeoff the caller must actually make (interactive vs. offline
   attack budget); the Kalyna-CCM variant is not that kind of choice, it's exactly the knob D-47
   criterion 2 says to delete when one safe default exists (same reasoning `crypto_sign` already
   applied by exposing only the one m=163 curve, D-46). `Kalyna256_256Ccm` chosen as the sole
   construction: 256-bit key, and the widest nonce available at that key size (32 bytes) among the
   five variants, for the best random-nonce collision margin.
2. **Nonce generated internally, never caller-supplied.** Extends `uacrypt kalyna-ccm encrypt`'s
   own CLI-layer behavior (D-40/T-82) down into the library itself, via
   `crate::randombytes::randombytes_buf` - there is nothing left for a `crypto_secretbox` caller to
   accidentally reuse across two `seal` calls under the same key, matching D-47 criterion 2's "hard
   defaults" bar more directly than libsodium's own C API does (libsodium's `crypto_secretbox_easy`
   still takes the nonce as a caller-supplied parameter).
3. **Combined `nonce (32) || ciphertext || tag (16)` wire format**, one `Vec<u8>` in, one `Vec<u8>`
   out - the ciphertext+tag half matches libsodium's own `crypto_secretbox_easy` combined-output
   ergonomics (as opposed to its detached-tag sibling). The nonce is embedded too, which
   `crypto_secretbox_easy` itself does not do (libsodium keeps the nonce as a separate
   caller-managed parameter even in its combined form) - a deliberate step further, matching this
   task's decision 2 above (nonce is never caller-supplied at all), not an exact parallel to cite as
   "the same as libsodium." `hazmat::kalyna_ccm` itself stays detached-tag (`seal_in_place`/
   `open_in_place`, hazmat callers manage buffers explicitly) - `crypto_secretbox` is the layer that
   picks one concrete framing.
4. **No AAD parameter exposed.** libsodium's own `crypto_secretbox` has no associated-data
   parameter at all (that's `crypto_aead`'s job); `hazmat::kalyna_ccm` does take AAD, but exposing
   it here would silently turn this module into a different primitive than its name promises.
   Empty AAD (`&[]`) is passed to `kalyna_ccm` internally, unconditionally. A `crypto_aead` wrapper
   exposing AAD is a possible separate future task, not folded into this one.

**Not a general-purpose secretbox - stated prominently in the module doc, not buried in an error
path**: inherits `hazmat::kalyna_ccm`'s 255-byte plaintext/AAD cap (D-41 - `ccm_padd`'s header
encodes both lengths as a single byte, a real construction limit). `seal` returns
`Err(SecretboxError::MessageTooLong)` on oversized input, never truncates;
`docs/release-readiness.md` already scoped `crypto_secretbox`'s CCM-backed build to exactly this
"<255-byte case." `crypto_secretstream` (`TASKS.md` T-40) remains the tracked follow-up for
arbitrary-length messages - a widened/chunked AEAD or GCM, neither built yet.

**`open` rejects truncated input before slicing** - anything shorter than 48 bytes (nonce + tag)
returns `Err(SecretboxError::Truncated)` immediately rather than panicking on attacker-controlled
short input, the advisor's flagged fuzz-relevant property (no dedicated fuzz target added this
pass - `hazmat::kalyna_ccm`'s own target already covers the primitive underneath; a
`crypto_secretbox`-specific target is a natural but not required follow-up).

**Key type**: `SecretKey([u8; 32])`, hand-written `Drop` calling `.zeroize()` - the same pattern
`crypto_sign::SigningKey` already uses (not `#[derive(ZeroizeOnDrop)]`), for consistency across the
high-level layer. `SecretKey::generate()` added (libsodium's `crypto_secretbox_keygen`
equivalent) so "how do I make a key" is never a caller decision either.

**Gating**: `#[cfg(feature = "std")] pub mod crypto_secretbox;`, folded into the existing `std`
feature rather than given its own dedicated feature the way `pwhash` was (D-50) - no new
dependency is introduced (reuses `zeroize`/`randombytes`, already direct dependencies), unlike
`pwhash`'s comparatively heavy `argon2`/`password-hash`/`blake2`/`base64ct` pull. Confirmed via
`cargo tree -p dstu-core --no-default-features -e normal`: `getrandom` (and therefore
`crypto_secretbox`) is genuinely absent from the bare `no_std` dependency graph.

**Verification - no external oracle exists for this specific framing** (own construction over an
already-oracle-verified primitive, same posture as `crypto_kdf`/`crypto_sign`): test-first, 12
tests in `tests/crypto_secretbox.rs`, all green on the first attempt after fixing one derive
error (`SecretboxError` initially derived `Clone, Copy, PartialEq, Eq`; `RandomError`, the wrapped
`getrandom::Error` type, implements none of those - dropped to a plain `#[derive(Debug)]`,
matching `PwHashError`'s own precedent). Covers: `proptest` round trip (0..=255 bytes), a
byte-layout pin against a direct `hazmat::kalyna_ccm::Kalyna256_256Ccm` call using the nonce `seal`
actually drew (confirms the wire format is exactly what the module doc promises, not just "round
trips"), fresh-nonce-per-call, four tamper-rejection cases (nonce/ciphertext/tag/wrong-key),
oversized-plaintext rejection, zero-length and max-length (255-byte) edge cases, and
truncated-input rejection at four short lengths. Full workspace `cargo test --workspace
--all-features` green (no regressions), `cargo clippy --workspace --all-features -- -D warnings`/
`cargo fmt --all -- --check` clean, all four `no_std`/`alloc`/`std`/`small-tables`-independent
build combinations re-confirmed (`crypto_secretbox` correctly absent everywhere `std` isn't
enabled). `cargo +nightly miri test -p dstu-core --test crypto_secretbox` clean (no UB, ~146s,
including the `proptest` suite - no isolation-crash workaround needed beyond the standard
`MIRIFLAGS=-Zmiri-disable-isolation` already used elsewhere, since `PROPTEST_CASES=8` kept this
particular suite's per-case cost low, unlike `dstu4145_sign_verify_roundtrip`'s ladder-heavy cases,
T-45/T-85).

**Still provisional, unchanged by this task**: inherits `hazmat::kalyna_ccm`'s own
not-yet-primary-text-confirmed status (D-41) - this module does not add or remove evidence toward
that question, it only wraps the primitive that already carries it. `TASKS.md` T-16 (`uacrypt`'s
reserved `encrypt`/`decrypt` commands) is now unblocked to *start* (its stated gate was
`crypto_secretbox` existing, not D-05's status) - not built as part of this task.

## D-52: `uacrypt encrypt`/`decrypt`/`hash` (T-16) implemented - the 255-byte cap made loud, not deferred

Same session as D-51, immediately after. What got built: `uacrypt`'s reserved top-level `encrypt`/
`decrypt`/`hash` commands (`crates/uacrypt/src/lib.rs`) - three new flat `run()` match arms (not
nested like `kalyna-ccm`'s own `encrypt`/`decrypt` sub-match, matching `TASKS.md` T-16's own text
listing three separate top-level names).

**The approval checkpoint, put to the user rather than resolved silently**: `crypto_secretbox`
(D-51) caps messages at 255 bytes. A command literally named `encrypt --in file --out file`,
sitting right next to `hash` (which handles files of any size), silently failing on any file over
255 bytes is a real usability trap - worse than a knob, since nothing warns the user until it
fails, and `CLAUDE.md`'s own MVP-scope example line (`uacrypt encrypt --key ... --in file --out
file`) reads as "encrypt a file" with no size caveat at all. Two options were put to the user via
`AskUserQuestion`: (A) build all three now with the cap made loud (explicit error text, README/
`CLAUDE.md` reconciled to state it up front), or (B) ship `hash` only, defer `encrypt`/`decrypt`
until `crypto_secretstream` (T-40, chunked AEAD) lands, so the reserved names never debut in a
crippled 255-byte-only form. **User chose (A)** - build all three now, cap made loud. This is a
product decision, recorded here rather than left implicit in the code, since a future session
revisiting T-40 needs to know this was a deliberate choice to ship the capped version, not an
oversight that "should" have deferred.

**`encrypt`/`decrypt` design, mechanical once `crypto_secretbox` existed**: new
`SecretboxArgs { key_path, in_path, out_path }` - no `--nonce`/`--tag`/`--aad`/`--variant`, because
`crypto_secretbox` itself already removed every one of those knobs (D-51: single fixed variant,
internal nonce, no AAD, one combined output blob). `run_secretbox_command(decrypt, args)` reads the
32-byte key via the existing `read_exact_file` helper, reads `--in` whole (no streaming - the
construction caps it at 255 bytes, same reasoning `kalyna-ccm` already uses), calls
`crypto_secretbox::seal`/`open`, writes `--out`. Three new `CliError` variants
(`MessageTooLong`/`Truncated`/`SecretboxVerifyFailed`) plus
`impl From<SecretboxError> for CliError`, mirroring the existing `From<CcmError>` impl exactly -
**deliberately not reusing** `PlaintextTooLong`/`CcmVerifyFailed`, whose `Display` text is
hardcoded to say "kalyna-ccm" (confirmed by reading it directly) and would print a wrong/confusing
command name from `encrypt`/`decrypt`. `MessageTooLong`'s message states the 255-byte figure
explicitly and points at `TASKS.md` T-40 as the future lift - the loud-cap requirement from the
approval checkpoint above, not a generic "too long."

**`hash` design**: fixed to Kupyna-256, no `--variant` knob (D-47's "no knob when a safe default
exists"; `crypto_sign` already established Kupyna-256 as this project's own default message-hash
choice, D-46 - not a new precedent). No `--iterations` either (that's `kupyna-digest`'s D-34
benchmark-only flag, irrelevant to a real user of `hash`). `run_hash_command` **delegates to the
existing `run_digest_command`** by constructing `DigestArgs { variant: HashBits::B256, iterations:
1, .. }` rather than duplicating its streaming loop - reuses `kupyna-digest`'s already-tested,
genuinely-streaming-from-disk (D-42, 8 KiB chunks) implementation directly, so `hash` inherits its
memory-bounded property, and has no message-length cap at all (unlike `encrypt`/`decrypt` - a
deliberate, stated asymmetry, not an inconsistency).

**Not built, matching existing precedent, not new scope**: no `uacrypt keygen` subcommand - neither
`kalyna-block` nor `kalyna-ccm` before it offer one either, a `--key` file must already exist.
`SecretKey::generate()` already exists in `dstu_core` if a future task wants to wire it up.

**Verification, test-first**: 12 new tests, all green on the first attempt -
`parse_secretbox_args`/`parse_hash_args` happy-path/missing-flag/unknown-flag,
`run_secretbox_command_round_trip_matches_dstu_core_directly` (cross-checked against a direct
`crypto_secretbox::open` call), `run_secretbox_command_encrypt_generates_a_fresh_nonce_each_call`
(two encrypts of identical key/plaintext differ in their leading 32 bytes),
`run_secretbox_command_decrypt_rejects_tampered_ciphertext_without_writing_out`,
`run_secretbox_command_oversized_plaintext_is_rejected`,
`run_hash_command_matches_dstu_core_kupyna256_directly` (non-chunk-aligned multi-chunk message,
checked against `Kupyna256::digest` directly), and `run_dispatches_hash_command_correctly`/
`run_dispatches_encrypt_and_decrypt_correctly` - calling the public `run()` function directly, not
just the `run_*_command` functions, since the three new top-level match arms are new wiring that
needed its own coverage. Full workspace `cargo test --workspace --all-features` green (no
regressions), `cargo clippy --workspace --all-features -- -D warnings`/`cargo fmt --all -- --check`
clean (one `cargo fmt` pass needed on a line that exceeded the wrap width).

**Execution structure, per the user's explicit request**: split into three commits rather than one
combined commit like D-51's - `hash` first (simplest, no new `CliError` variants), then
`encrypt`/`decrypt` plus the `CliError`/`From` plumbing, then documentation
(`README.md`/`CLAUDE.md`/`docs/dstu-crypto-project.md`/`docs/release-readiness.md`/`TASKS.md`/this
entry) - each commit independently green.

## D-53: Full DSTU 7624 mode-of-operation coverage at `hazmat` - roadmap, and ECB (#1) as Stage A's first piece

User asked to implement all 10 official DSTU 7624:2014 modes (`ORACLES.md`'s ten-mode list, D-05)
at the `hazmat` layer, as a complete standards-faithful primitive set - independent of the public
`crypto_secretbox` question, which stays exactly as restricted as D-05/D-47 already require (only
GCM/CCM/KW are ever candidates for a public entry point; the other 7 modes never get one, full
stop). Full plan (staged by cost/oracle-strength, all citations to
`oracles/uapki/library/uapkic/src/dstu7624.c`, two research passes reading the C source directly):

- **Stage A** (this entry covers the first piece, ECB): ECB(#1)/OFB(#6)/CBC(#5)/CFB(#3)/CTR(#2) -
  thin XOR-chaining wrappers over `hazmat::kalyna`, no new field arithmetic.
- **Stage B** (not started): CMAC(#4) - no field math either; strongest whole-block oracle of the
  non-AEAD modes (BC's `DSTU7624Mac` is a full independent construction in Java and .NET, not just
  vectors) - but its padding/partial-block branch is uapki-only-verifiable, BC throws on
  non-block-aligned input.
- **Stage C** (not started): KW(#10) - no field math; the single strongest oracle of all 10 modes,
  full independent BC construction source in *both* Java and .NET.
- **Stage D** (not started): GCM/GMAC(#7) - needs new GF(2^m) field arithmetic at **three** field
  sizes (m=128/256/512, one per Kalyna block size, not one fixed GF(2^128) the way AES-GCM's GHASH
  is) - the one real investment in this roadmap. `hazmat::dstu4145::gf2m163` gives no reusable code
  (hardcoded 3-limb, m=163-specific), only a reusable style reference (D-25's branchless
  shift-and-XOR technique). BC-Java vector-only cross-check (construction source not vendored, same
  weaker-claim caveat D-41 already states for CCM); BC-.NET has nothing for GCM at all.
- **Stage E** (not started): XTS(#9) - reuses Stage D's GF(2^m) module (confirmed identical `f[]`
  parameterization to GCM/GMAC), sequenced strictly after D. Adds ciphertext-stealing for the final
  partial block - the one genuinely novel piece of logic in the whole 10-mode set.
- CCM(#8) already done (T-81/D-41), untouched by this plan.

**Per-mode requirement, all five raw/non-AEAD modules (A/B/E, i.e. every mode except the AEAD-eligible
GCM/KW)**: the module doc must carry an explicit misuse warning - no integrity, don't use for new
designs without a specific reason, prefer `crypto_secretbox` unless the raw mode is genuinely needed.
Shipping ECB/CBC/CFB/OFB with a neutral doc comment would contradict this project's own
misuse-resistance identity; the "hazmat-complete, frontend-restricted" split only holds together if
hazmat's own docs carry that weight, not just the CLI/high-level layer.

**This entry's actual delivered piece: `hazmat::kalyna_ecb`** (`Kalyna128_128Ecb`...`Kalyna512_512Ecb`,
`encrypt_in_place`/`decrypt_in_place`, `TASKS.md` T-88). Cited to `dstu7624.c`'s `encrypt_ecb`/
`decrypt_ecb` (lines 2899-2961) and `dstu7624_init_ecb` (lines 3920-3934) - no chaining state at all,
a per-block loop over the already-verified block cipher (D-13). **No new vector file**: confirmed
(programmatic extraction, not eyeballed - a Node script pulled every quoted hex string from
`dstu7624_ecb_self_test`'s struct literal directly from the C source) that all 10 of its self-test
cases are single-block, because `dstu7624_init_ecb`'s block size is set to the exact length of that
case's one data blob - and those 10 vectors are byte-for-byte the same official designer vectors
(`docs/papers/Kalyna.pdf` Appendix B) already in `tests/vectors/kalyna/*.json`, reused (not
duplicated into a new file) by `tests/kalyna_ecb.rs`. ECB's one genuinely new property - multi-block
independence, not chaining - has no vector anywhere to check (uapki's own self-test never exercises
it either), verified instead by a `proptest` directly against the already-oracle-verified raw block
primitive (`ExpandedKey::encrypt_block` called once per block, compared to `Kalyna*Ecb`'s own
multi-block output). Test-first, 15 tests (3 per variant x 5 variants), all green first attempt:
single-block-matches-raw-vectors, length-validation (`InvalidLength` on a non-block-multiple
buffer), and the multi-block-independence `proptest`. `cargo test --workspace --all-features`/
`clippy -D warnings`/`fmt --check` clean; bare `no_std` and `--all-features` builds both re-confirmed
(pure `hazmat` addition, no new dependency, no `cfg` gating needed). Carries the loudest misuse
warning of the whole batch, per the requirement above - ECB's pattern-leakage failure mode is the
textbook "don't do this" example across virtually every cryptography guide.

**Stage A, second piece: `hazmat::kalyna_ofb`** (`TASKS.md` T-89). Cited to `encrypt_ofb`
(`dstu7624.c` L3624-3670)/`dstu7624_init_ofb` (L3996-4013); confirmed `dstu7624_decrypt` routes OFB
to the same `encrypt_ofb` function - self-inverse, one `apply_in_place` method, not separate
encrypt/decrypt. Genuinely stateful (`&mut self`, unlike `kalyna_ecb`'s per-call `&self`) - keystream
`gamma` self-updates via `gamma = E_K(gamma)` every loop iteration regardless of whether a full
block of data remains, with `used_gamma_len` tracking how much of the last-generated block was
actually consumed so a later call can resume from the unused tail. New vector files
`tests/vectors/kalyna-ofb/*.json` (5 variants, 9 uapki KATs) - **programmatically extracted**, not
hand-transcribed: a small Node script parses `dstu7624_ofb_self_test`'s struct literal directly out
of the C source, including reversing C's adjacent-string-literal concatenation across `\`-continued
lines (the same vectors first looked like 58 fields instead of the expected 36 = 9 cases x 4 fields
until that concatenation was handled) - this is exactly the class of manual-transcription risk
`CLAUDE.md`'s citation discipline warns about, avoided here by extracting programmatically instead
of reading hex by eye. Test-first, 10 tests (2 per variant): official vectors (encrypt then
self-inverse decrypt-via-second-instance), plus a `proptest` chunk-invariance suite (arbitrary
non-block-aligned split points across multiple `apply_in_place` calls must match one call over the
whole buffer - same discipline already established for `hazmat::strumok`, T-24) - **all 10 tests
green on the first attempt**, confirming the `used_gamma_len` bookkeeping transcription was correct
without needing a debugging pass. `cargo test --workspace --all-features`/`clippy -D warnings`/
`fmt --check` clean (one `doc_markdown` lint fix); bare `no_std` build re-confirmed. Misuse warning
states OFB's IV-reuse failure mode explicitly (same catastrophic-keystream-reuse class as CTR).

**Stage A, third piece: `hazmat::kalyna_cbc`** (`TASKS.md` T-90). Cited to `encrypt_cbc`/
`decrypt_cbc` (`dstu7624.c` L3145-3184/L3886-3918)/`dstu7624_init_cbc` (L3936-3953) - textbook
`C_i = E_K(P_i XOR C_{i-1})`, `&mut self` chaining register carried across calls like `kalyna_ofb`.
Two verification-risk items from this entry's own earlier research resolved concretely:
- **The dead 10th self-test vector was excluded, not verified-then-used** - uapki's own harness
  loop (`for (i = 0; i < 9; i++)`) never checks it, so it carries no evidentiary weight; the
  `512-512` vector file's `source` field states this plainly rather than silently omitting the
  case with no explanation.
- **The one non-block-aligned case** (128/256 variant, cbc_test_data[1], 46-byte plaintext) needed
  ISO/IEC 7816-4 padding applied before it could be used - `hazmat::kalyna_cbc` rejects non-aligned
  input itself (matches `encrypt_cbc`'s own `in->len % block_len` check, no padding scheme baked
  in, same "hazmat has no rails" posture as every mode in this roadmap). The vector file stores the
  already-padded 48-byte plaintext with an inline `note` field explaining the transformation and
  citing the reason - the exact "unexplained transform" pattern `CLAUDE.md`'s citation discipline
  flags as suspect, addressed by documenting it rather than silently editing the vector.
Test-first, 15 tests (3 per variant): official vectors, length validation
(`InvalidLength`), and a `proptest` multi-call-chaining suite confirming the chaining register
correctly carries state across separate `encrypt_in_place` calls (block-aligned chunks). **All 15
green on the first attempt**, including the padding-transformed vector - confirms the byte-count
arithmetic (46 + 2 padding bytes = 48) was right without a debugging pass. `cargo test --workspace
--all-features`/`clippy -D warnings`/`fmt --check` clean; bare `no_std` build re-confirmed.

**Stage A, fourth piece: `hazmat::kalyna_cfb`** (`TASKS.md` T-91) - the most internally complex
mode in this batch, and the first one where the fixed vectors alone didn't catch a real bug. Cited
to `encrypt_cfb`/`decrypt_cfb` (`dstu7624.c` L3186-3234/L3762-3810)/`dstu7624_init_cfb`
(L3971-3994). **Genuinely two separate functions, not self-inverse** - confirmed `dstu7624_decrypt`
does *not* route CFB to `encrypt_cfb` the way it does for CTR/OFB, so this module has distinct
`encrypt_in_place`/`decrypt_in_place` methods, differing in whether the `feed` register absorbs the
just-computed output or the raw input bytes (both are ciphertext, read from different places).
**Transcribed exactly, not simplified by analogy to textbook NIST CFB** (`CLAUDE.md`'s explicit
warning against this) - this construction's `feed` register is not a rolling shift window; each
round it's rebuilt from the just-generated `gamma` block's own leading bytes with only the newest
`q` ciphertext bytes overwritten at a fixed position. New extraction script (`q` is a bare integer
field in the C struct, not a quoted hex string like the other three fields, so the existing
string-only extractor needed a second, targeted regex pass) pulled all 8 uapki KATs, spanning both
partial (`q` < block size) and full (`q` == block size) feedback widths - the partial case is the
one genuinely novel path relative to every other mode in this roadmap.

**A real bug, caught by the chunk-invariance `proptest`, not the fixed vectors - exactly the
"green fixed-vector tests don't mean security-critical code is correct" lesson `CLAUDE.md`
states explicitly**: all 5 single-call official-vector tests passed on the first attempt (they
only ever exercise one `encrypt`/`decrypt` call each, matching `dstu7624.c`'s own self-test, which
never chains multiple calls together) - revealing nothing about multi-call state handling. An
initial `proptest` allowing arbitrary chunk-length splits across several `encrypt_in_place` calls
failed for every variant. **Root-caused by hand-tracing the state machine, not by patching until
green**: a call ending mid-way through a `q`-sized group leaves `used_gamma_len` pointing into the
*current* `gamma` block at a position a later call's leading-catchup branch does not correctly
resume from - concretely reproducible as an out-of-bounds slice index (`gamma[offset..offset+q]`
with `offset+q` exceeding the block size), not merely wrong output. **Confirmed this is a property
of the transcribed C construction itself, not a bug introduced in the port** - `dstu7624.c`'s own
self-test never exercises multi-call chaining at all, so this combination was never validated
upstream either. Fixed by narrowing the proptest's contract to require every call except the last
to be a `q`-byte multiple (still a real, non-trivial streaming property - just not "fully
arbitrary" the way `kalyna_ofb`/`kalyna_cbc` are) - passed immediately once narrowed. **This
constraint, including the panic risk, is now stated loudly in the module doc**, not left as a
footnote a caller could miss - a silent-wrong-output failure would have been worse, but an
undocumented panic is still a real misuse trap for a `hazmat` API. `cargo test --workspace
--all-features`/`clippy -D warnings`/`fmt --check` clean; bare `no_std` build re-confirmed.

**Stage A, fifth and final piece: `hazmat::kalyna_ctr`** (`TASKS.md` T-92) - Stage A is now
complete, all five modes shipped. Cited to `encrypt_ctr` (`dstu7624.c` L2739-2790)/
`dstu7624_init_ctr` (L4397-4421) - confirmed byte-for-byte the same keystream-priming/increment/
re-encrypt logic `hazmat::kalyna_ccm`'s internal `Gamma` component already implements (CCM calls
this exact `encrypt_ctr` internally). Written as its own independent implementation per this
roadmap's standing instruction not to refactor `kalyna_ccm.rs` to share code across that boundary -
shipped, dual-oracle-verified, miri-clean AEAD code is not worth a DRY win's regression risk
(`CLAUDE.md`'s "three similar lines beats a premature abstraction" rule, applied literally, same
reasoning already stated when this task was originally scoped).

**A real transcription bug caught before it ever reached a test run, by re-comparing against
`Gamma::apply`'s own structure rather than trusting a "should be equivalent" simplification**: the
first draft of `apply_in_place` jumped straight from "check if fully exhausted, regenerate if so"
to the main block loop, omitting the leading "consume any leftover keystream bytes one at a time"
while-loop that both the C source and `kalyna_ccm`'s own `Gamma::apply` have for the case where a
previous call left a *partially* (not fully) used keystream block. Caught and fixed by direct
comparison against the already-verified `Gamma::apply` code before running anything - the kind of
side-by-side check this module's own doc comment explicitly invites, given how closely it mirrors
that component. Two-oracle vector file: uapki's single KAT plus a genuinely independent second
Bouncy Castle vector (`DSTU7624Test.java` `KCTRBlockCipher` test #25 - test #24 matches uapki's own
vector byte-for-byte, the same dual-lineage relationship already established for CCM/GCM/KW) - both
only cover Kalyna128_128, the only variant either vendored oracle has any CTR vector for; the other
four variants rely on the shared-logic argument above plus a chunk-invariance `proptest` run across
all five variants with genuinely arbitrary call boundaries (no `q`-alignment restriction, unlike
`kalyna_cfb` - CTR's counter-increment bookkeeping has no equivalent complication). **All 6 tests
green on the first attempt** once the pre-emptive fix was in place. `cargo test --workspace
--all-features`/`clippy -D warnings`/`fmt --check` clean (one `doc_markdown` fix, same lint
`kalyna_ofb` hit); bare `no_std` build re-confirmed.

**Stage A summary**: ECB/OFB/CBC/CFB/CTR all done (T-88 through T-92), 6 of 10 DSTU 7624 modes now
implemented at `hazmat` including CCM (T-81). Remaining: Stage B (CMAC, T-93), Stage C (KW, T-94),
Stage D (GCM/GMAC, T-95, the one real new-primitive investment - GF(2^m) field arithmetic at three
field sizes), Stage E (XTS, T-96, sequenced after D). Public `crypto_secretbox` surface unchanged
throughout Stage A, as designed - none of these five modes are AEAD-shaped, so none was ever a
candidate for a public entry point (D-05/D-47).

## D-54: `hazmat::kalyna_cmac` (T-93, Stage B) - one-shot API, `q` fixed at 16 bytes, single-oracle padding-branch gap recorded

DSTU 7624:2014 mode #4. Cited to `oracles/uapki/library/uapkic/src/dstu7624.c`'s `cmac_update`/
`cmac_final` (lines 4221-4310), `padding` (lines 2572-2592), `dstu7624_init_cmac` (lines 4070-4087);
`Dstu7624Ctx`'s running MAC state confirmed zero-initialized via `dstu7624_alloc`'s
`CALLOC_CHECKED`, not IV-seeded. **Not** GF-doubling-subkey CMAC/OMAC the way AES-CMAC derives its
subkeys - read from source, not assumed by analogy to the more familiar NIST construction
(`CLAUDE.md`'s "porting logic means porting its calling convention too" discipline, applied here to
avoid *inventing* a convention the DSTU construction doesn't actually use). The real algorithm:
CBC-MAC over every block except the last, then the held-back last block (padded with a single
`0x80` byte plus zeros if not block-aligned, unpadded if it is) gets XORed against a subkey - itself
just `E_K` of a near-zero block whose only nonzero byte is a 0/1 padding flag, no field-doubling
anywhere - and the combined block is encrypted once more; the tag is the first `q` bytes of that
final encryption.

**API restructured from the C source's incremental buffering into a one-shot whole-message
computation** (`Kalyna*Cmac::mac(key, message) -> [u8; 16]`, `verify(key, message, expected) ->
Result<(), CmacError>`), following `hazmat::kupyna_kmac`'s (D-44) shape exactly rather than
re-deriving `cmac_update`'s multi-call state machine: nothing in this crate consumes an incremental
MAC yet (`kupyna_kmac` was in the same position before any `crypto_auth` wrapper existed), and nothing
requires it now. Verified this restructuring is semantically identical to the C source by hand-tracing
both the aligned and non-aligned branches against `cmac_update`/`cmac_final` directly, not by
pattern-matching test output against expected numbers - both branches are independently exercised by
the official vectors below, so passing them is real evidence for the restructuring, not just a shape
check. `q` is fixed at 16 bytes for all five variants rather than exposed as a runtime knob (the C
source allows `1..=block_len`): every available oracle vector, uapki's and Bouncy Castle's alike,
uses `q = 16` regardless of block size - it is the only value any oracle has ever exercised, and
`SECURITY.md`'s "no primitive without a cited test" rule forbids shipping a wider, untested `q` range.
Key stays the fixed-size `&[u8; $key_bytes]` array every Stage-A module already uses, so (unlike
`KmacError::WrongKeyLength`) no key-length error variant is needed - `mac()` is infallible.
`verify()` uses `subtle::ConstantTimeEq` for the tag comparison (`SECURITY.md`'s constant-time-compare
rule for secret material), same as `kupyna_kmac::verify`.

**Oracle coverage, stated plainly per variant, not glossed over**: 3 uapki KATs
(`dstu7624_cmac_self_test`, programmatically extracted, not hand-transcribed) map to 3 of the 5
variants:
- **Kalyna128_128** (48-byte, block-aligned message - no-padding branch): dual-oracle, corroborated
  byte-for-byte by `oracles/bouncycastle-java/.../DSTU7624Test.java` `MacTests()` test 1
  (`new DSTU7624Mac(128, 128)`).
- **Kalyna128_256** (94-byte message, **not** block-aligned - the padding branch): **single-oracle,
  uapki only**. Bouncy Castle's `DSTU7624Mac` throws on non-block-aligned input, so it structurally
  cannot corroborate this branch - same posture as Strumok's D-15 UAPKI-only caveat, flagged here
  rather than silently treated as dual-oracle-verified. This was the exact caveat `TASKS.md` T-93
  anticipated before this task started.
- **Kalyna512_512** (128-byte, block-aligned): dual-oracle, corroborated by `MacTests()` test 2
  (`new DSTU7624Mac(512, 128)`).
- **Kalyna256_256, Kalyna256_512**: **no oracle vector at all**, from either vendored oracle. Coverage
  rests on the shared-logic argument (identical macro-generated code path, only `block_bytes`/
  `key_bytes` differ, and the underlying `encrypt_block` for these two variants is already
  independently dual-oracle-verified via `hazmat::kalyna`, D-13) plus a `proptest` round-trip
  (mac-then-verify, tamper-detection on both the tag and the message, across arbitrary-length -
  including non-block-aligned - messages so the padding branch gets generic coverage beyond the one
  official vector's fixed 94-byte length) run across all five variants, not just the two uncovered
  ones - same posture already used for CTR's uncovered variants (T-92/D-53).

11 tests total (6 official/fixed + a `proptest` suite per variant, 5 variants), all green on the first attempt
including the padding-branch vector - no debugging pass needed, unlike CFB's/CTR's earlier catches.
`cargo test --workspace --all-features` clean; `clippy -D warnings` needed one `doc_markdown` fix
(`` `XOR`ed ``, the same lint every prior Stage-A/B module doc has hit); `fmt --check` clean; bare
`no_std` build re-confirmed (pure `hazmat` addition, no new dependency, no `cfg` gating needed).
Misuse warning states this module provides no key separation from any encryption key and recommends a
future `crypto_auth` wrapper, matching `kupyna_kmac`'s own framing - no such wrapper exists yet for
either MAC.

**Stage B done.** Remaining: Stage C (KW, T-94), Stage D (GCM/GMAC, T-95), Stage E (XTS, T-96).
Public `crypto_secretbox` surface unchanged - CMAC isn't AEAD-shaped, so it was never a candidate
for a public entry point (D-05/D-47). *(2026-07-24 correction: this entry originally called KW "the
strongest oracle of all 10 modes - full independent Bouncy Castle construction source in both Java
and .NET." D-55 found that framing overstated - Bouncy Castle's .NET port is a structural port of
its Java one, not an independent second reading, so it's one lineage, not two. See D-55.)*

## D-55: `hazmat::kalyna_kw` (T-94, Stage C) - block-aligned input only, added checksum check, round-counter fork bounded out rather than resolved

DSTU 7624:2014 mode #10 (key wrap), a half-block Feistel-like network over an accumulator `B` and a
shifting queue of the remaining half-blocks plus one appended all-zero "checksum" block. Cited to
`oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_kw` (lines 3672-3755), `decrypt_kw` (lines
3812-3884), `dstu7624_init_kw` (lines 3955-3969), cross-read against
`oracles/bouncycastle-java/.../engines/DSTU7624WrapEngine.java` and
`oracles/bouncycastle-dotnet/.../engines/Dstu7624WrapEngine.cs` (both read in full, per this
roadmap's original instruction not to transcribe KW from a single source).

**Correction to this roadmap's original framing** (`DECISIONS.md` D-53, `TASKS.md` T-94's original
note): KW was scoped as "the strongest oracle of all 10 modes - full independent Bouncy Castle
construction source in both Java and .NET." Reading both files line-by-line found this overstated:
BC's .NET `Dstu7624WrapEngine.cs` is a structural port of the Java `DSTU7624WrapEngine.java` (same
method shapes, even matching commented-out debug `Console.WriteLine` lines carried across from the
Java `System.out`-equivalent). This is **one construction lineage (BC) vs. one (uapki)**, not
2-vs-1 - caught by `advisor()` mid-research, not assumed. Corrected in D-54's closing paragraph too.

**A real fork, not just a framing correction.** uapki's C XORs only the low byte of the round
counter into the tweak position (`size_t i` implicitly truncated by assignment into a `uint8_t`
slot); both BC ports XOR a full 4-byte little-endian encoding (`Pack.UInt32_To_LE`/
`intToBytes`). Provably identical whenever the largest round counter used, `v`, is `<= 255` (the
LE encoding's upper 3 bytes are zero in that range, so XORing them is a no-op either way) -
genuinely unresolved above that, since no DSTU 7624:2014 primary text exists in this repo (227
pages, paid, not purchased - `ORACLES.md`) to break the tie, and the two implementations are one
lineage as established above. All 9 official uapki KATs have `v <= 54` (confirmed by a small
extraction/analysis script), so they cannot and do not disambiguate.

**Resolved by making the fork unreachable, not by picking a side** (advisor's recommendation,
adopted): implement the 4-byte little-endian tweak, and hard-bound input so `v` can never exceed
255 - `v = 12r + 6 <= 255 ⟹ r <= 20` (`r` = number of `block_len`-sized chunks of plaintext),
independent of block size. `wrap`/`unwrap` return `KwError::InvalidLength` above that bound rather
than emit ciphertext from an unverified-construction region. `r <= 20` is generous for key-wrapping's
actual purpose (up to 320/640/1280 bytes of key material depending on block size) - D-47 tie-breaker
#2 (libsodium's hard-bound-over-flexibility posture) once no primary text settles it.

**Second deviation: scope-cut to block-aligned input only, not uapki's padding branch.** uapki's
non-aligned branch appends a little-endian bit-length field plus `0x80`-style padding, then
`decrypt_kw` recovers the original length by scanning backward for the last nonzero byte through
the appended checksum block. Hand-traced this: it depends on the real plaintext's own last byte
being nonzero to land correctly - a plaintext legitimately ending in `0x00` could make this
heuristic over-consume into real data. All 9 KATs happen to avoid triggering this (confirmed by the
self-test's own round-trip check passing), so it's a **real, latent fragility in uapki's C itself**,
not a transcription risk here - but porting it faithfully would import that fragility. Both BC ports
sidestep this entirely (`wrap`/`Wrap` throw on non-aligned input, no KW padding scheme of their own
at all). Adopted BC's restriction instead, for three reasons: matches `hazmat::kalyna_cbc`/
`kalyna_cfb`'s already-established "no padding of its own" convention used everywhere else in this
crate's mode set; avoids inheriting an identified correctness fragility; and the 5 block-aligned
KATs already give full 5-variant coverage (one aligned vector per Kalyna128_128/128_256/256_256/
256_512/512_512), so nothing is lost per-variant by cutting the padding branch. The 4 non-aligned
KATs are explicitly out of scope, not silently dropped - a distinct future task if arbitrary-length
KW input is ever needed, not assumed to be "coming later automatically."

**Third deviation: added the checksum verification uapki's C omits.** `decrypt_kw` never checks the
recovered trailing block is actually all-zero; it returns whatever bytes result. Both BC ports
explicitly compare it against zero and throw on mismatch - KW's only tamper-evidence mechanism.
Added this check (`subtle::ConstantTimeEq`, `SECURITY.md`'s constant-time-comparison rule - the
checksum block is a function of secret key material through the whole Feistel network) - a
deliberate, cited safety addition via D-47 tie-breaker #2, not an omission being silently carried
over.

**API**: in-place on caller-supplied buffers (`wrap`/`unwrap` write into a caller-provided `out`
slice), fixed-size stack arrays bounded by `MAX_R = 20` (`[[u8; half_bytes]; 41]` at most) - no
`Vec`/`alloc`, matching `hazmat::kalyna_ccm`'s no-heap-allocation precedent (the only other
multi-block-buffer hazmat module in this crate). `KwError { InvalidLength, ChecksumMismatch }`.

**Oracle coverage**: 5 uapki KATs (one per Kalyna variant, all block-aligned, programmatically
extracted), with the `Kalyna128_128` case additionally matching BC Java's `KeyWrapTests` `test 1`
`expectedWrappedText` byte-for-byte - real corroboration for the tested range, framed honestly as
shared-lineage agreement, not independent dual-oracle. `proptest` round-trip (`wrap` then `unwrap`
recovers the original plaintext) across all 5 variants and `r` in `1..=20`. 16 tests total, **all
green on the first attempt** including every official vector (wrap and unwrap) - the careful
cross-source structural verification during planning (advisor consult, hand-tracing both directions
against all three sources before writing any code) paid off directly here, unlike CFB's/CTR's
mid-implementation catches. `cargo test --workspace --all-features` clean; `clippy -D warnings`
needed two doc-comment fixes (unbalanced backticks in a doc comment mixing inline code and a link,
an accidental markdown list item from a line starting with `- `, both citation-inert formatting
issues); `fmt --check` clean; bare `no_std` build re-confirmed (no `alloc` needed, per the
fixed-size-buffer design above).

**Stage C done.** Remaining: Stage D (GCM/GMAC, T-95, the one real new-primitive investment - GF(2^m)
field arithmetic at three field sizes), Stage E (XTS, T-96, sequenced after D). Public
`crypto_secretbox` surface unchanged - KW is AEAD-*shaped* in the D-05/D-47 sense (confidentiality +
integrity) so it remains a theoretical future candidate, same standing as GCM, but nothing in this
task changes that - still deferred, no decision made here.

## D-56: `hazmat::gf2m_wide` + `hazmat::kalyna_gcm` (T-95, Stage D, commit 1 of 2) - GCM landed; three real divergences from AES-GCM found by reading, not assumed; GMAC deferred to its own commit

DSTU 7624:2014 mode #7 (GCM). This is the roadmap's "one real investment": new GF(2^m) field
arithmetic at three sizes, landed together with GCM in one commit because **no standalone `gf2m`
test vectors exist anywhere in the oracle** (confirmed by search) - the field module and GCM could
**at the time this commit landed** only be verified jointly, against GCM's own (block-aligned) KATs.
**Updated in D-57's addendum**: a later same-session `advisor()` audit found this joint-only
verification left the reduction step's top-degree terms genuinely unexercised (no block-aligned KAT
drives it there) and added `hazmat::gf2m_wide::field_axiom_tests` - direct, oracle-independent
coverage (identity/commutative/associative/distributive plus max-degree deterministic cases) that
closes that specific gap. See D-57 for the full account; not restated here to avoid two sources of
truth for the same fix. GMAC (`gmac_update`/`gmac_final`/`encrypt_gmac`) is deliberately a separate,
second commit - same field module, different construction shape (streaming, single message, no
AAD/ciphertext split), and its own oracle-status question to answer honestly rather than inherit
GCM's by proximity.

**Research discipline for this stage, since it was the largest single piece of the whole roadmap**:
`oracles/uapki/library/uapkic/src/math-gf2m-internal.c` (1199 lines) was read structurally, not
transcribed - a generic, word-size-dependent, Karatsuba-multiplication-based multi-precision GF(2^m)
library (`gf2m_alloc`, `gf2m_mod`, `gf2m_mod_mul`, plus elliptic-curve operations this project
doesn't need here). Confirmed no reusable code, matching the precedent already set by
`hazmat::dstu4145::gf2m163` (D-25) - only a *style* reference (branchless shift-and-XOR), not ported.
Consulted `advisor()` before finalizing the implementation plan - it caught a real gap (below) before
any code was written, and confirmed three genuine AES-GCM-divergent details by independently tracing
the same source.

**The gap `advisor()` caught**: `dstu7624.c`'s GCM/GMAC code calls `gf2m_mul(ctx, block_len, arg1,
arg2, out)` (lines 2963-3001) - a byte-pointer wrapper, **not** `gf2m_mod_mul` (the `WordArray`-typed
function in `math-gf2m-internal.c`, a different signature this session initially conflated with it).
Reading `gf2m_mul` found it's a thin wrapper: `wa_alloc_from_uint8` → `gf2m_mod_mul` → `wa_to_uint8`,
and those conversions are themselves just `uint8_to_uint64`/`uint64_to_uint8`
(`byte-utils-internal.c` lines 133-177) - a **plain `memcpy` reinterpretation** of the byte buffer as
native-endian `uint64` words (with a swap only if the host is big-endian, never true on any target
this project builds for). Net effect, derived (not guessed): **byte `i` of a block maps to bits
`[8i, 8i+8)` of the field element, LSB-first within each byte** - i.e. byte 0 holds the lowest-degree
terms, a fully little-endian polynomial representation. **This is a distinct convention from
`gf2m163`**, which serializes big-endian (DSTU 4145's own convention, D-14) - the two GF(2^m) modules
in this crate do not share a byte-order convention, and assuming they did would have repeated the
`hash_to_field` calling-convention mistake `CLAUDE.md`'s agent-discipline section already warns
about, generalized to a second standard. Per `advisor()`'s explicit warning, this derivation was
treated as a hypothesis, not a settled fact, until the smallest official GCM vector confirmed it -
**which it did, on the first attempt**, closing the loop on the one open representation question.

**Three genuine divergences from textbook AES-GCM, `advisor()`-confirmed via independent tracing of
the same source, all transcribed as found rather than completed from familiar-construction memory**:
1. **Double-encrypted counter.** `gamma_old = E_K(iv)` once; each keystream block is
   `E_K(gamma_old_incremented)`, not `E_K(iv_incremented)` directly the way NIST GCM's `J0`-based
   counter works. The increment touches only the low 64 bits of `gamma_old` (as a little-endian
   integer), never the rest of the block. Independent implementation from `hazmat::kalyna_ctr`'s own
   counter logic - not shared code, same "three similar lines beats a premature abstraction across an
   already-verified boundary" reasoning applied to every prior mode's counter in this roadmap.
2. **Horner-accumulate over AAD then ciphertext, with an asymmetric padding scheme, and no length
   block folded into the multiply chain.** `H = E_K(0)` once; `B = 0`, then for each AAD block
   (**plain zero-padded**, no marker byte, if the last one is partial) and then each ciphertext block
   (**`0x80`-then-zeros padded** - the same `padding()` construction `hazmat::kalyna_cmac`/
   `hazmat::kalyna_kw` use, confirmed by reading the actual call site, not assumed symmetric with
   AAD's padding just because both precede a GHASH-style accumulation): `B = (B XOR block) * H`.
3. **Tag = block-cipher-encrypt of `(accumulator XOR length block)`, not XOR with a keystream
   block the way NIST GCM's `E_K(J0)` works.** The length block holds the AAD bit-length
   (little-endian `u64`) in the low half-block and the ciphertext bit-length in the high half-block -
   but that second field is the ***padded*** ciphertext length, not the true plaintext length, a
   direct consequence of `dstu7624.c` reusing the same length variable after its own padding step
   mutates it. Confirmed by hand-tracing the C variable's actual value at each point, not assumed.

**None of the 6 official GCM vectors have non-block-aligned plaintext** - divergence 2's `0x80`
padding-marker branch is transcribed as found but not oracle-exercised by any KAT. Covered instead by
the `proptest` round-trip in `tests/kalyna_gcm.rs`, which generates non-aligned lengths generically.
Recorded honestly, not glossed over.

**API**: `hazmat::gf2m_wide` (`Gf2m128`/`Gf2m256`/`Gf2m512`, one macro-generated struct per field
size) - branchless shift-and-select carry-less multiply (mirrors `gf2m163::poly_mul_wide` exactly),
then a simple bit-at-a-time top-down modular reduction (not `gf2m163::reduce`'s word-offset-optimized
closed form, which was hand-derived specifically for `m=163`/64-bit words and doesn't generalize to
three more field sizes without redoing that derivation three times - correctness-first over
speed-first, same posture `gf2m163` itself already established, D-25). Reduction polynomials cited
from `dstu7624_init_gcm`'s `f[]` triples: `x^128+x^7+x^2+x+1`, `x^256+x^10+x^5+x^2+1`,
`x^512+x^8+x^5+x^2+1`. `hazmat::kalyna_gcm` (`encrypt`/`decrypt`, in-place on caller buffers, no
`alloc`/`Vec` - correctness-independent from `q`, which is a pure truncation of a full-block-length
tag the caller applies themselves, so no `MAX_AAD_LEN`/`MAX_PLAINTEXT_LEN` cap was needed at all,
unlike `kalyna_ccm`'s sourced 255-byte limit). `decrypt`'s tag check uses `subtle::ConstantTimeEq`,
**not** `dstu7624.c`'s raw `memcmp` - a deliberate, cited safety fix via D-47 tie-breaker #2, same
pattern already applied to `kalyna_kw`'s checksum check and `kalyna_cmac`'s tag verify; on mismatch,
`plaintext_out` is zeroed before returning `Err`, matching `kalyna_ccm`'s "never observe unverified
plaintext" contract.

**Oracle coverage**: uapki construction (6 KATs, one per Kalyna variant plus a bonus q=16-vs-q=32
truncation-consistency pair for `Kalyna256_256`, sharing the same key/iv/aad/plaintext) + a
vector-only cross-check against `oracles/bouncycastle-java`'s `DSTU7624Test.java` `GCMModeTests`
(`KGCMBlockCipher`'s construction source is not vendored in this repo's sparse checkout) - same
weaker-claim caveat `DECISIONS.md` D-41 already states for CCM, stated explicitly rather than
implying a stronger claim by proximity to KW's earlier lineage-correction. BC-.NET has no GCM class
at all.

14 tests, **all green on the first attempt** including every official vector and the tag-truncation
consistency check - the smallest KAT (case 0, single-AAD-block, two-plaintext-block) was run in
isolation first, per the plan's debugging order, before the full suite; it passed immediately,
confirming the representation derivation above without needing to fall back to suspect #2 (reduction)
or #3 (byte order as a real bug, not just an unconfirmed hypothesis). `cargo test --workspace
--all-features` clean; `clippy -D warnings` needed two classes of fixes (signed-to-unsigned cast
warnings in `gf2m_wide`'s reduction loop - rewrote `degree`/`bit_index` as `u32` throughout instead
of `i32`, and unbalanced-backtick doc-comment fixes mixing inline code with a linked identifier,
same citation-inert formatting class every prior stage has hit at least once); `fmt --check` clean
after one auto-format pass; bare `no_std` build re-confirmed (no `alloc` needed).

**Commit 1 of Stage D done.** Remaining: commit 2 (GMAC, same field module, its own construction and
oracle-status write-up), then Stage E (XTS, T-96, sequenced after this stage since it reuses this
field module). Public `crypto_secretbox` surface unchanged - whether GCM ever becomes its backing
construction instead of or alongside CCM remains explicitly deferred, unchanged from the original
Stage-A-era roadmap note.

## D-57: `hazmat::kalyna_gmac` (T-95, Stage D, commit 2 of 2) - ported from `encrypt_gmac`, not
`gmac_update`/`gmac_final`, after finding a real multi-block bug in the streaming pair

DSTU 7624:2014 mode #7's MAC-only sibling, closing out Stage D (GCM/GMAC). Same
`hazmat::gf2m_wide` field module as D-56's GCM commit - no new field arithmetic needed. Consulted
`advisor()` before writing any code, as planned; it corrected two things in the working premise at
once, both load-bearing.

**What `advisor()` caught**: the plan going in was to port `gmac_update`/`gmac_final` (the
streaming pair reachable via `dstu7624_update_mac`/`dstu7624_final_mac`, the shape this crate's
other streaming modes already use, and the exact pair the self-test itself calls) and disambiguate
a suspected indexing bug empirically against the multi-block official vectors. Both premises were
wrong. First: **all 5 official GMAC vectors are exactly one block long** (16/32/32/32/64 bytes
against block sizes 16/32/32/32/64 - confirmed by measuring the extracted hex, not assumed) - no
official vector has more than one block, so no empirical disambiguation of multi-block chaining was
ever possible against them. Second: `dstu7624.c` has a **second, independent** GMAC construction,
`encrypt_gmac` (lines 3572-3620), whose loop is a plain, correct Horner chain (`B = (B XOR block) *
H` per block, no special-cased first iteration) - and *that* is the coherent one to port, not the
streaming pair.

**The bug itself**, hand-traced and confirmed, not assumed: `gmac_update`'s post-multiply loop does
`kalyna_xor(&data_buf[i], B, block_len, B)` using the *current* loop index `i` - for a single call
carrying 2 full blocks (block1 at `data_buf[0]`, block2 at `data_buf[block_len]`), this re-reads
`data_buf[0]` (block1) a second time instead of advancing to `data_buf[block_len]` (block2). Traced
through fully: the resulting accumulator is a function of block1 and the message length only -
**block2's bytes are never read at all**. `gmac_update`'s separate non-aligned tail-buffering branch
has its own, distinct problem: `tail_len` is computed as the *padding complement* to the next block
boundary rather than the true leftover-byte count, then used as a `memcpy` length from a buffer
offset that doesn't leave that many bytes remaining - an out-of-bounds read for any non-aligned
input spanning more than one block in a single call. Both bugs live only in the streaming pair;
`encrypt_gmac`'s one-shot loop has neither (its padding step allocates `data_len + block_len` up
front, and its accumulation loop has no stale index).

**Why this isn't just "pick whichever gives an answer"**: the streaming pair, fed **one block per
`update` call** instead of one large call, does *not* hit either bug, and reduces to the exact same
Horner chain `encrypt_gmac` computes (hand-traced: call 1 leaves `B = block1*H`; call 2 leaves
`B = (block1*H XOR block2)*H`, identical to `encrypt_gmac`'s two-block result). That agreement is
the citation for treating `encrypt_gmac`'s construction as the intended one and the streaming pair's
single-large-call behavior as a bug to route around, not a second legitimate reading with no
tiebreaker (the D-47-tiebreaker situation earlier stages like `kalyna_kw`'s round-counter fork hit) -
here the reference disagrees with *itself*, and the chunk-invariant reading is the one that survives
both code paths agreeing.

**Construction ported** (`encrypt_gmac`, one-shot only - see below for why streaming isn't exposed):
`H = E_K(0)` once; message padded with the same `0x80`-then-zeros marker `kalyna_cmac`/`kalyna_kw`/
`kalyna_gcm` already use (only when `len % block_len != 0`); `acc = 0`, then per padded block:
`acc = (acc XOR block) * H`. Length block: the **padded** message bit-length (little-endian `u64`)
at a fixed low-8-byte offset, every other byte zero - confirmed by hand-tracing `dstu7624.c`'s
`H[0] = data_len << 3` (only the first `u64` word is set, `memset` zeroed the rest, at every block
size tested including 256/512-bit) - **not** `kalyna_gcm`'s two-value, half-block-offset-scaled
layout (D-56's divergence 3), since GMAC has only one stream, not an AAD/ciphertext split to keep
separate. Final tag = `E_K(length_block XOR acc)`, truncated by the caller to their chosen `q`
(8..=block_bytes) - mirroring `kalyna_gcm`'s own truncation convention exactly. `verify` uses
`subtle::ConstantTimeEq`, **not** `dstu7624.c`'s raw `memcmp` - same deliberate safety fix already
applied to `kalyna_kw`'s checksum check, `kalyna_cmac`'s tag verify, and `kalyna_gcm`'s tag verify
(D-47 tie-breaker #2).

**Not streaming.** Only one coherent code path exists to port (`encrypt_gmac`, one-shot), so unlike
`kalyna_cfb`/`kalyna_ctr`/etc. there is no streaming state machine to transcribe at all here - same
one-shot shape `kalyna_cmac` already established for this crate's other from-scratch MAC module, not
a new pattern.

**Oracle coverage - weaker than D-56's GCM, stated plainly, not glossed over**: uapki-only, 5 KATs
(`dstu7624_gmac_self_test`), covering `Kalyna128_256`, `Kalyna256_256` (×2, a q=16-vs-q=32
truncation-consistency pair sharing key/message), `Kalyna256_512`, and `Kalyna512_512` -
**`Kalyna128_128Gmac` has zero official-vector coverage**, uapki's self-test simply never exercises
that variant. Every vector is exactly one block, so **no official vector exercises multi-block
chaining, the `0x80` padding-marker branch, or the length-block placement for a message requiring
more than one block** - all three are proptest-only, covered by `tests/kalyna_gmac.rs`'s
`mac_then_verify_roundtrips` (non-aligned lengths, up to 3 blocks) and, specifically targeting the
found reference bug's failure mode, `changing_any_block_changes_the_tag` (flips a single byte
anywhere across a guaranteed-2-full-block message and asserts the tag changes - this property is
exactly what the streaming pair's stale-index bug would violate if it had been ported faithfully).
Confirmed no Bouncy Castle standalone GMAC class exists (`grep`-searched both `oracles/
bouncycastle-java` and a `.cs` search for a .NET equivalent) - `DSTU7624Test.java`'s "GCM/GMAC test
N" cases configure `KGCMBlockCipher` for AEAD and do not exercise this AAD-less single-stream
construction, so they are not a usable oracle here the way they were (vector-only) for D-56's GCM.

17 tests, **all green on the first attempt**, including all 4 covered official-vector variants and
the found-bug regression proptest. `cargo test --workspace --all-features`, `clippy -D warnings`,
`fmt --check`, and the bare `no_std` build all clean. `cargo +nightly miri test -p dstu-core --test
kalyna_gmac` (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8`): clean, no UB, 17/17, ~916s.

**Addendum, same session, requested as a separate full-project review**: the user asked for a sober
`advisor()`-driven audit of this file and the shipped implementations against the project's own
stated goal/niche, independent of the GMAC work above. One finding from that audit was a real gap
in *this* stage specifically, closed before Stage D could honestly be called done: `hazmat::gf2m_wide`
had **zero direct tests** - D-56 already states no standalone `gf2m` oracle vectors exist anywhere,
so the field module was verified only jointly, through GCM/GMAC's own KATs, every one of which is
block-aligned. `advisor()` pointed out that block-aligned inputs never drive `reduce`'s loop through
its full top-degree range (`degree` from `$limbs2 * 64 - 1` down to `$m`) - nothing established the
shift/XOR terms near the top of that range are computed correctly, only that the low/mid-degree
terms the KATs happen to reach are. Added `hazmat::gf2m_wide::field_axiom_tests` (inline
`#[cfg(test)]`, since the module is private - `mod gf2m_wide;`, not `pub mod` - so an integration
test file can't reach it): identity, commutativity, associativity, and distributivity via
`proptest`, plus three deterministic cases specifically targeting the gap - `ALL_ONES.multiply(ONE)
== ALL_ONES` and `ALL_ONES.multiply(ALL_ONES)` (the two extremes `poly_mul_wide` can produce,
maximum-degree input, drives `reduce` through its complete range) for all three field sizes. 21
tests, all green first attempt (`cargo test -p dstu-core --lib field_axiom_tests --all-features`);
`clippy -D warnings`/`fmt --check`/bare `no_std` build all re-confirmed clean with this addition. A
scoped `cargo +nightly miri test -p dstu-core --lib field_axiom_tests` run was also launched - pure
integer arithmetic, no `unsafe`, so it cannot invalidate the field-axiom result above regardless of
outcome; its pass/fail is recorded in `TASKS.md` T-95 once it lands rather than held here as a
blocking condition on this entry. Not a substitute for a real oracle vector if one is ever found,
but real evidence the module is exercised by more than five accidentally-easy KATs. The audit's
other findings (`subtle` missing a row in `SECURITY.md`'s
dependency-vetting table despite being a direct, unconditional, crypto-critical dependency; CI's
`fuzz-smoke` job covers only 1 of 4 existing fuzz targets, and none of the four modes landed this
session - `kalyna_cmac`/`kalyna_kw`/`kalyna_gcm`/`kalyna_gmac` - have a fuzz target at all;
`docs/release-readiness.md` now stale, still stating GCM/KW/XTS as "not built" after this session
landed GCM/KW/GMAC) are process/documentation follow-ups, tracked as new `TASKS.md` items rather
than fixed inline here, since they're outside this stage's actual scope.

**Stage D complete** (both GCM and GMAC landed, plus the field-axiom coverage gap `advisor()` found
and closed). Next: Stage E (XTS, T-96), its own plan-mode pass, sequenced after this stage since it
reuses `hazmat::gf2m_wide`.

## D-58: `hazmat::kalyna_xts` (T-96, Stage E) - the 10th and last DSTU 7624 mode; a real
ciphertext-stealing bug caught by the official vectors, and an unchecked-underflow gap found and
closed, not inherited

DSTU 7624:2014 mode #9, closing out full 10/10 mode-of-operation coverage at `hazmat` (D-53's
roadmap). Cited to `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_xts`/`decrypt_xts`
(lines 3003-3141) and `dstu7624_init_xts` (lines 4089-4132). Reuses `hazmat::gf2m_wide`
(`Gf2m128`/`Gf2m256`/`Gf2m512`) unchanged - `dstu7624_init_xts`'s `f[]` triples confirmed
byte-for-byte identical to GCM/GMAC's (D-56), no new field arithmetic needed. Requested this
session with an explicit sequencing instruction from the project owner: implement this (the last
remaining DSTU 7624 mode) before starting the broader post-audit roadmap (`TASKS.md`'s "Roadmap to
a genuinely complete product" section) that was approved the same session.

**Confidentiality only, and that's the correct choice here, not a compromise** - the one mode among
all 10 where a non-AEAD construction is by design, not a misuse trap: disk-sector encryption
deliberately leaves integrity to the filesystem layer (D-05's own mode table already tags #9
"Confidentiality only"; `docs/release-readiness.md`'s use-case table already states this for the
"full-disk encryption" row). The module doc explains *why* this is fine here specifically, not just
the generic "no MAC, be careful" warning every other confidentiality-only mode in this crate carries.

**Ciphertext-stealing derivation, hand-traced and generalized, not assumed from textbook XTS-AES**:
`encrypt_xts`/`decrypt_xts` transcribed directly, then re-derived by hand for two different official
vectors (`k = 1` and `k = 2` full blocks before the partial tail) to confirm the control flow
generalizes to any `k >= 1` rather than being special-cased per vector. Let `k = buffer.len() /
block_bytes`, `r = buffer.len() % block_bytes`. Encrypt: blocks `0..k-1` get sequential tweaks
`1..k`, encrypted normally in place. The block at `(k-1)*block_bytes` (already encrypted with
tweak `k`) is saved aside; a "combined" block is built from the real tail (`r` bytes) followed by
the **last** `block_bytes - r` bytes of that saved block, encrypted with tweak `k+1`, then swapped
into position `(k-1)*block_bytes`; the saved block's **first** `r` bytes become the truncated final
output at `k*block_bytes`. Decrypt is the precise inverse (advances the tweak one step further to
recover the "combined" plaintext first, reconstructs the `(k-1)`-th block from the real ciphertext
tail plus the combined plaintext's stolen suffix, then swaps).

**A real transcription bug, caught by the official vectors on the very first run, not a debugging
afterthought**: the first implementation attempt took the **first** `block_bytes - r` bytes of the
saved block for the "combined" block's tail instead of the **last** `block_bytes - r` bytes - all
10 official-vector tests failed identically on the ciphertext-stealing cases (the aligned cases
passed), with the failing block's *second half* matching expected output exactly and the first half
completely wrong - a clean signature that immediately localized the bug to which half of the saved
block gets stolen, not a broader logic error. Re-read the C source's own index arithmetic (`i -
block_len` at the exact point the `memcpy` fires, not the position after the later `i -=` line) to
confirm the correct half, fixed with a one-line change (`scratch[r..]` in place of `scratch[..
block_bytes - r]`), re-ran - all 10 vectors and all 5 proptest suites passed immediately after.
`decrypt_in_place`'s equivalent step was independently re-traced against the same C source before
writing it and found already correct on the first attempt - not assumed correct by symmetry with
the (buggy) encrypt side.

**A real gap found in the reference, not ported**: `encrypt_xts`'s `loop_len = plain_size -
block_len` (unsigned `size_t`) has no guard against `plain_size < block_len` - such an input
underflows to a huge value, and the main loop would read/write far past the buffer.
`decrypt_xts` has a *partial* guard (`plain_size < 2*block_len ? 0 : plain_size - 2*block_len`) at
a different threshold, which doesn't rescue the encrypt side. Same class of gap as
`hazmat::kalyna_kw`'s non-aligned branch (D-55) and `hazmat::kalyna_cfb`'s multi-call panic (just
resolved this same session to a checked error, `TASKS.md` T-101, per the project owner's explicit
direction) - resolved the same way here rather than as a fresh improvisation:
`encrypt_in_place`/`decrypt_in_place` return `Result<(), XtsError>` and reject `buffer.len() <
block_bytes` via `XtsError::InvalidLength` up front. This is not a scope cut relative to the real
construction - ciphertext stealing has no meaning below one full block by definition - only a guard
against an input the reference's own arithmetic was never checked against.

**API**: in-place on the caller's buffer (`encrypt_in_place`/`decrypt_in_place`, same shape as
`kalyna_cbc`/`kalyna_cfb`/`kalyna_ofb`), no `alloc`/`Vec` - a fixed `[u8; block_bytes]` stack
scratch (mirroring `kalyna_kw`'s fixed-size-buffer precedent) replaces the C's own
`plain_size + padded_len` heap allocation for the ciphertext-stealing swap step only; every other
byte is written directly into the caller's slice.

**Official vectors - full double coverage, not the usual single-branch-untested gap**:
`dstu7624_xts_self_test` (10 KATs, programmatically extracted - handling the same adjacent
string-literal concatenation across `\`-continued lines that already caught a real parsing bug for
OFB, D-53) gives **one aligned and one ciphertext-stealing case per Kalyna variant** - unlike every
other new mode this session (GCM/GMAC/KW), XTS's stealing branch is officially vector-covered for
all 5 variants, not proptest-only. **Dual-oracle for the aligned case only**:
`oracles/bouncycastle-java`'s `DSTU7624Test.java` `XTSModeTests` (`KXTSBlockCipher`) has 5 tests,
confirmed byte-for-byte matching uapki's cases 0/2/4/6/8 (the five *aligned* cases, one per
variant) - construction source not vendored, same weaker vector-only claim as D-56's GCM entry. BC
has **zero** corroboration for any of the 5 stealing cases - stated honestly, not implied
dual-oracle by proximity to the aligned case's stronger claim.

11 tests (5 official-vector, 1 `InvalidLength` regression test, 5 `proptest` round-trip suites),
all green after the one fix above. `cargo test --workspace --all-features`, `clippy -D warnings`,
`fmt --check`, bare `no_std` build all clean. `cargo +nightly miri test -p dstu-core --test
kalyna_xts` (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8`): clean, no UB, 11/11, ~670s.

**10/10 DSTU 7624 modes now implemented at `hazmat`.** Next: the user-approved "Roadmap to a
genuinely complete product" in `TASKS.md` - trust/correctness fixes (T-97-T-101), full
`small-tables` verification for Stage B-E, then the `crypto_*` frontend work.

## D-59: `cargo miri test`'s CI job (T-100) - real root cause was broader than the two proptest
suites originally suspected; fixed by tagging every EC-heavy test, not by raising the timeout alone

**The premise going in was wrong, and measuring first caught it.** T-100's own text (and the
`rust.yml` comment it quotes) named `dstu4145_sign_verify_roundtrip`/`dstu4145_crypto_sign_roundtrip`
- the two `proptest` suites - as the suite(s) responsible for the miri job never completing.
Before editing `rust.yml`, timed the two files' *non-proptest* tests locally
(`MIRIFLAGS=-Zmiri-disable-isolation`, matching CI): they did not complete either. Root cause,
confirmed by reading `hazmat::dstu4145::gf2m163::FieldElement::invert` (a direct 162-step
square-and-multiply exponentiation, no Itoh-Tsujii acceleration, D-25) and
`hazmat::dstu4145::curve163::Point::scalar_multiply` (the 163-iteration constant-time ladder,
already documented): **any** call to either - not just inside a `proptest` closure - costs minutes
under Miri's interpreter, because both are ~162-163-step loops of full-width GF(2^163) field
multiplications, and `Point::add`/`Point::double` each call `invert` internally for the slope
computation. A single fixed-vector `verify()` call is therefore comparable in Miri cost to a single
proptest case, not orders of magnitude cheaper as assumed.

**Fix: `#[cfg_attr(miri, ignore = "...")]` on every `#[test]` that reaches `scalar_multiply` or
`invert`, not a CI-side skip list.** T-85 already rejected a yaml skip list for this exact job (a
~9-entry list that "would silently stop covering any new proptest test added later without a
matching update") - the same drift risk applies to a two-entry list, just smaller. Gating at the
test's own source keeps `rust.yml`'s invocation a one-line `cargo +nightly miri test --workspace`
that cannot drift out of sync with the yaml, and Miri's own output shows each skip explicitly
(`... ignored, <reason>`) rather than silently. Tagged, with the measured/inferred reason recorded
in each attribute's own message:
- `crates/dstu-core/tests/dstu4145_signature.rs`: all 4 fixed-vector tests + the proptest (all call
  `sign`/`verify`, each running the ladder).
- `crates/dstu-core/tests/crypto_sign.rs`: 5 of 7 fixed-vector tests + the proptest (call
  `verifying_key()`/`sign`/`verify`) - `from_bytes_rejects_zero_scalar`/
  `from_bytes_rejects_scalar_at_or_above_order` untouched, they reject before ever deriving a
  public key, confirmed fast (0.05s combined for the whole file's 2 surviving tests).
- `crates/dstu-core/tests/dstu4145_curve.rs`: `gf2m163_point_add_matches_bouncy_castle` (40 vector
  cases) and `gf2m163_point_double_matches_bouncy_castle` (20 cases) - each case calls `invert`.
  `gf2m163_generator_matches_vector` (an equality check, no field arithmetic) untouched.
- `crates/dstu-core/tests/dstu4145_gf2m.rs`: `gf2m163_field_arithmetic_matches_bouncy_castle` (20 of
  its 80 cases are `"invert"`) and `gf2m163_invert_is_involution_via_reciprocal` (loops `invert`
  over all 20 field cases). `gf2m163_round_trip_be_bytes`/`gf2m163_one_is_multiplicative_identity`
  (no `invert` calls) untouched.

**Verified in stages, scoped before workspace-wide, per the project's own "measure, don't assume"
discipline**: `dstu4145_curve.rs` + `dstu4145_gf2m.rs` alone, scoped (`-p dstu-core --test
dstu4145_curve --test dstu4145_gf2m`): 4.55s and 47.60s respectively, all previously-hanging tests
now show `ignored, <reason>`. `crypto_sign.rs` alone: 1.12s (2 passed, 7 ignored). Then one
full, **unattended, run-to-completion** `cargo +nightly miri test --workspace`
(`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`, the exact CI invocation) - not killed early
this time, unlike the first attempt (which hung on `dstu4145_curve.rs`'s now-fixed `point_double`
for 40+ minutes with zero completed results, the evidence that motivated broadening the fix past
the two proptest suites). Every `dstu-core` target's real `finished in Xs`, this machine:

| target | time (s) | target | time (s) |
|---|---|---|---|
| lib (unit tests) | 910.28 | kalyna_ctr | 112.72 |
| crypto_pwhash | 0.10 | kalyna_ecb | 115.58 |
| crypto_secretbox | 78.46 | kalyna_gcm | 185.86 |
| crypto_sign | 1.12 | kalyna_gmac | 245.29 |
| dstu4145_curve | 4.49 | kalyna_kw | 457.44 |
| dstu4145_gf2m | 47.95 | kalyna_ofb | 126.46 |
| dstu4145_signature | 0.48 | kalyna_xts | 667.63 |
| kalyna | 207.08 | kupyna | 119.12 |
| kalyna_cbc | 144.51 | kupyna_kdf | 64.08 |
| kalyna_ccm | 559.07 | kupyna_kmac | 18.16 |
| kalyna_cfb | 801.31 | randombytes | 0.90 |
| kalyna_cmac | 137.08 | strumok | 38.43 |

**Total: 5043.60s (~84 minutes) for all of `dstu-core`, every target passing, 0 UB, 0 failures.**
This is genuinely bounded (the run completed) but far past the 30-minute cap the job carried before
this fix - the cap was set against a *different*, unbounded failure mode (T-85's note: a single
proptest case "ran past an hour with no sign of finishing," cost scaling with an EC-ladder call
count that had no ceiling in a workspace run at the time). What remains after this fix is finite
and dominated by real, if slow, interpreted block-cipher-mode work - `kalyna_cfb` (801s) and
`kalyna_xts`/`kalyna_kw`/`kalyna_ccm` (457-668s) are the largest non-EC contributors, consistent
with those being the modes with the most `proptest` surface (tamper-rejection suites, ciphertext
stealing, wrapping-round bounds). **Raising `timeout-minutes` is therefore the correct response
here, not a repeat of the mistake the 30-minute cap was set against** - bounded-but-slow is a
materially different situation from open-ended. Set to **150** (2.5x the measured ~84-minute
`dstu-core` total, leaving real margin for a shared/contended GitHub Actions runner being slower
than this dev machine, plus the still-untested `uacrypt` portion below).

**A second, previously-unreachable finding, NOT fixed here - filed as `TASKS.md` T-102.** The
full-workspace run never got far enough to reach `uacrypt`'s own lib tests before this fix (the
job always died on the EC-ladder timeout first). Now it does, and `uacrypt`'s tests fail on *this*
Windows dev machine: `error: unsupported operation: can't call foreign function \`CreateDirectoryW\`
on OS \`windows\`` inside `tests::TempDir::new` (`crates/uacrypt/src/lib.rs:1312`), first hit by
`run_ccm_command_decrypt_rejects_tampered_ciphertext_without_writing_out` - 16 of `uacrypt`'s test
functions use the same `TempDir` helper, so most of them past that point would hit the identical
wall. **Working hypothesis, not confirmed**: this is the same *family* of gap T-81 already
documented (`GetCurrentDirectoryW` unsupported under Miri's Windows-host isolation) - Miri's
Windows filesystem shims are less complete than its Unix ones, a known upstream characteristic, not
a bug in this project's code. Plausibly Linux-CI-clean, since CI runs `ubuntu-latest` and Miri's
Unix `mkdir` shim is more mature - but **not verified on Linux**, and stating it as settled without
that verification would repeat exactly the unverified-claim pattern T-100 itself was filed to
correct. Left open (T-102) rather than guessed at.

**Explicit scope boundary on the claim below**: this entry verifies the `dstu-core`-side fix (the
actual subject of T-100 - the EC-ladder/field-inversion timeout) completely and locally. It does
**not** verify that `cargo +nightly miri test --workspace` now passes end-to-end on CI's own
Linux runner - that conclusion is unconfirmed pending a push (push is explicit-request-only,
per this project's standing git-safety posture). `rust.yml`'s miri-job comment updated to cite this
entry instead of the pre-fix problem description.

**Confirmed on CI 2026-07-25, pushed with T-101 (commit `859241a`)**: `cargo miri test` passed on
GitHub's own `ubuntu-latest` runner for the first time in this repository's whole history (`gh run
view 30157361074` - all 5 jobs green: deny 32s, audit 3m24s, **miri 37m55s**, build/test/fmt/clippy
21m14s, fuzz-smoke 1m54s). 37m55s is comfortably inside the 150-minute budget and, notably, also
faster than this session's local Windows measurement (~84 min for `dstu-core` alone, D-59's own
table) - the GitHub Linux runner outperformed the local dev machine here rather than being slower,
the opposite of what "leave real margin for a slower CI runner" assumed, though the margin was still
the right call to make without that data in hand. The scope boundary above no longer applies: this
is a real, checked CI result, not a local-only claim.

## D-60: `hazmat::kalyna_cfb`'s documented panic (T-91/D-53) becomes a checked `Result` (T-101)

Own plan-mode pass, per the roadmap's explicit requirement for this specific fork (`TASKS.md`
"Roadmap to a genuinely complete product," Step 1). Resolution direction was pre-approved by the
project owner when the roadmap was recorded; this entry is the actual derivation and design, not
just execution of a foregone conclusion.

**Root cause, traced by hand against both the Rust port and `oracles/uapki/.../dstu7624.c`'s
`encrypt_cfb`/`decrypt_cfb` (identical unchecked-index construction in the reference too - this is
a property of the transcribed algorithm, not a Rust-side bug).** `used_gamma_len` is the byte
position within the current `gamma`/`feed` block a later call resumes from. The bulk loop indexes
`self.gamma[offset..offset + q]` directly, which is in-bounds exactly when `offset % q == 0` -
this covers every position the bulk loop ever needs (0, q, 2q, ..., block_bytes - q, and
block_bytes itself, since `block_bytes % q == 0` for all 12 admissible `(block_bytes, q)`
combinations this crate constructs: `q ∈ {1, 8, 16, 32, 64}`, `block_bytes ∈ {16, 32, 64}`, `q ≤
block_bytes` - now an executable fact, not an assertion, via the new
`feedback_width_divides_block_length` test in `tests/kalyna_cfb.rs`, one per variant). The leading
"catch-up" loop (`while offset < self.q`) only does real work when `offset < q`, which is only
reachable from a trailing partial-group call when `q == block_bytes` (there, the post-priming
resume position is 0). For `q < block_bytes` the post-priming resume position (`block_bytes - q`)
is always `>= q`, so a trailing-partial call there leaves `offset` neither `< q` (catch-up doesn't
fire) nor a multiple of `q` (bulk loop indexes out of range or reads the wrong data) - the exact
panic T-91/D-53 found via `proptest`, not the fixed vectors.

**Fix: `used_gamma_len % q == 0` checked on entry to both `encrypt_in_place`/`decrypt_in_place`,
returning `Err` instead of proceeding.** `InvalidFeedbackWidth` (a bare struct, only used by
`new()`) replaced by a `CfbError` enum (`InvalidFeedbackWidth`, `NonAlignedIntermediateCall`),
matching the established one-enum-per-mode convention (`KwError`, `GcmError`, `CcmError` in the
sibling `kalyna_kw`/`kalyna_gcm`/`kalyna_ccm` modules - same derive set, no `std::error::Error`
impl). `new()`'s return type changes accordingly; no other module references the old type name
(`grep`-confirmed before starting). Existing round-trip/vector logic in both functions is otherwise
untouched, now returning `Ok(())` instead of falling off the end.

**Real, stated behavior change, not a no-op refactor**: in the narrow `q == block_bytes` case, a
trailing partial-group call followed by another call happens to succeed today via the catch-up
loop - an undocumented tolerance, not a guaranteed contract (the module doc already states the
q-multiple-per-call rule unconditionally, no `q == block_bytes` carve-out). Enforcing
`used_gamma_len % q == 0` uniformly matches the documented contract rather than narrowing an
explicit guarantee, but this one specific call pattern does newly return `Err` where it previously
succeeded. Asserted directly, not left to an incidental loop iteration:
`trailing_partial_call_with_q_equal_to_block_len_is_rejected`, one per variant.

**Verified, test-first** (`tests/kalyna_cfb.rs`, 3 new tests + `.unwrap()` added to all 6 existing
call sites that previously ignored the `()` return): `feedback_width_divides_block_length` (the
divisibility fact, all 5 variants), `non_aligned_intermediate_call_is_rejected` (a deliberate
non-`q`-aligned intermediate call followed by another, asserts
`Err(CfbError::NonAlignedIntermediateCall)` for both `encrypt_in_place`/`decrypt_in_place`, every
admissible `q > 1` per variant - `q = 1` skipped, every length is trivially `q`-aligned there),
`trailing_partial_call_with_q_equal_to_block_len_is_rejected` (the behavior-narrowing regression
above). All 25 tests (22 existing + 3 new, x5 variants where applicable) green on the first
attempt. `cargo test --workspace --all-features`, `cargo clippy --workspace --all-features -- -D
warnings`, `cargo fmt --all -- --check`, `cargo build -p dstu-core --no-default-features` all
clean. `cargo +nightly miri test -p dstu-core --test kalyna_cfb`
(`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`, matching T-100/D-59's CI convention): clean,
0 UB, 25/25, 585.27s (comparable to D-59's 801.31s for this same file's *previous*, smaller test
set - the new tests are small and fixed-shape, no proptest case-count blowup).

## D-61: Fuzz coverage extended to all five Stage B-E modes; CI's `fuzz-smoke` job now a 9-target matrix (T-98)

`SECURITY.md` calls `cargo fuzz` required, not optional, for every parser of untrusted input bytes.
Before this: CI's `fuzz-smoke` job ran only `kupyna`; `kalyna`/`kalyna_ccm`/`strumok` had targets
but never ran in CI (only ever locally, D-32); `kalyna_cmac`/`kalyna_kw`/`kalyna_gcm`/`kalyna_gmac`/
`kalyna_cfb` (all landed this session, plus `kalyna_cfb`'s T-91/T-101 history) had **no fuzz target
at all**, anywhere - the sharpest gap being `kalyna_cfb`, the one module where a known-until-T-101
panic, zero fuzz coverage, and (until T-100) no completed CI Miri run all intersected.

**Five new targets added** (`crates/dstu-core/fuzz/fuzz_targets/{kalyna_cmac,kalyna_kw,kalyna_gcm,
kalyna_gmac,kalyna_cfb}.rs`), each following one of the two patterns already established by
`kalyna.rs` (plain block-cipher round-trip, arbitrary bytes through decrypt too) and `kalyna_ccm.rs`
(round-trip plus a direct-attack-surface call with bytes never produced by the crate's own encrypt
path):
- `kalyna_cmac`/`kalyna_gmac`: `mac`/`verify` over arbitrary key/message/tag content and length -
  `gmac`'s tag length is deliberately allowed to fall outside the valid `8..=block_bytes` range,
  exercising `GmacError::InvalidLength` under fuzzing, not just the unit tests.
- `kalyna_kw`: a block-aligned round-trip (`wrap` then `unwrap`, capped at 5 blocks, comfortably
  under `MAX_R`), plus arbitrary (often non-block-aligned, over-long, or out-buffer-mismatched)
  bytes straight into both functions - the exact caller-supplied-length class the module's own doc
  comment names as what its fixed-size internal buffers depend on the length check to guard.
- `kalyna_gcm`: round-trip via `encrypt`/`decrypt`, plus `decrypt` fed arbitrary ciphertext and an
  attacker-chosen (possibly out-of-range) tag length, mirroring `kalyna_ccm`'s
  authentication-decision-on-attacker-input framing.
- `kalyna_cfb`: multiple `encrypt_in_place` calls with fuzzer-controlled (almost always
  non-`q`-aligned) chunk boundaries on the same cipher instance - the exact misuse pattern T-101/
  D-60 turned from a panic into `Err(CfbError::NonAlignedIntermediateCall)`; `Err` is discarded, not
  asserted against, since it's now an expected outcome, not a fuzz finding - only a panic is.

**CI decision, explicitly named as open in T-98's own text**: whether to rotate through all fuzz
targets instead of hardcoding `kupyna` alone. Resolved: `fuzz-smoke` is now a 9-entry
`strategy: matrix` job (one job per target, parallel, each with its own pass/fail) rather than a
sequential loop in one job - smoke runs are cheap (60s each) and this gives per-target visibility a
single bundled job wouldn't. `xtask`'s own two hardcoded 4-target lists (`fuzz_targets` for
non-Windows, the loop inside `fuzz_windows_msvc`) replaced with one shared `FUZZ_TARGETS` const
listing all 9 - both call sites and the CI matrix must still be kept in sync by hand with `fuzz/
Cargo.toml`'s `[[bin]]` entries (no single source of truth cargo exposes for "every fuzz target
name" short of parsing that file), a pre-existing manual-sync tradeoff, not a new one introduced
here.

**Verified**: all 5 new targets type-check clean under the MSVC toolchain (`cargo fuzz check
--target x86_64-pc-windows-msvc`, D-32's local method - the GNU host toolchain still can't build
`libfuzzer-sys` at all on Windows, unchanged limitation). 60-second smoke runs, zero crashes:
`kalyna_cmac` 115,853 runs, `kalyna_kw` 48,309 runs, `kalyna_gcm` 203,779 runs, `kalyna_gmac`
214,015 runs, `kalyna_cfb` 87,519 runs. `xtask` itself (`cargo build`/`clippy -D warnings`/`fmt
--check --manifest-path xtask/Cargo.toml`, xtask being its own standalone workspace, not a root
workspace member) clean. Full non-fuzz workspace verification (`cargo test --workspace
--all-features`, `clippy -D warnings`, `fmt --check`, bare `no_std` build) unaffected, re-confirmed
clean. CI's own matrix run is unconfirmed pending a push, same standing caveat as D-59/D-60.

## D-62: `small-tables`/full feature-matrix verification for Stage B-E (T-93-T-96, D-54-D-58) - roadmap Step 2

CMAC/KW/GCM/GMAC (D-54-D-57) and XTS (D-58) each landed with only "bare `no_std` build
re-confirmed" recorded, not the full 8-combination matrix D-39/D-41 established as this project's
own standard for a new `hazmat` addition. Structurally low-risk to begin with: all five modes are
built entirely on the existing per-variant `ExpandedKey` API (`encrypt_block`/`decrypt_block`),
never touching `hazmat::tables`' `SBOX_MDS`/`MDS_TABLE`/`gf_mul` machinery directly - the same
reasoning D-41 already gave for CCM needing "no `cfg` gating of its own." This entry is the
explicit run-and-document pass the roadmap's Step 2 asked for, not a design decision.

**8-combination `dstu-core` crate-level build matrix** (`cargo build -p dstu-core`, D-39/D-41's
exact shape - the 4-way `no_std`/`alloc`/`std`/`all-features` matrix from T-23, each without and
with `small-tables`): all 8 combinations build clean -
`--no-default-features`; `--no-default-features --features alloc`; `--features alloc`;
`--all-features` (already includes `small-tables`); and the same four again with `small-tables`
added explicitly (`--features small-tables`; `--features alloc,small-tables`; the
`--no-default-features` pairing of each). `--all-features` covers the 8th combination on its own,
since it already turns `small-tables` on.

**Test suites, run specifically under `small-tables`** (`cargo test -p dstu-core --features
small-tables --test kalyna_cmac --test kalyna_kw --test kalyna_gcm --test kalyna_gmac --test
kalyna_xts`) - all 5 files pass identically to the default profile, same as D-41's CCM precedent:
`kalyna_cmac` 11/11, `kalyna_gcm` 14/14, `kalyna_gmac` 17/17, `kalyna_kw` 16/16, `kalyna_xts`
11/11 (69 tests total, 0 failures). `cargo clippy --workspace --features dstu-core/small-tables --
-D warnings` and the same without the feature both clean; `cargo fmt --all -- --check` clean;
`cargo build --workspace --no-default-features --features dstu-core/small-tables` (workspace-level,
`uacrypt` included) clean.

**Not done, deliberately out of scope for this pass**: a fresh Raspberry Pi re-run (D-41's own
"re-confirmed on the Pi too" was a bonus on top of its own 8-combination matrix, not part of what
the roadmap's Step 2 text itself asked for here) and `cargo miri test`/`cargo fuzz` specifically
under `small-tables` (D-35's stated verification bar for the resource-profile split - official
vectors plus differential-oracle harnesses - doesn't require either, matching D-39's own "Not
done" line for the original `small-tables` implementation). Revisit only if a `small-tables`-specific
regression is ever suspected, not proactively.

## D-63: `crypto_secretbox` migrates from Kalyna-CCM to Kalyna-GCM, removing the 255-byte cap - roadmap Step 3 item 1

`dstu_core::crypto_secretbox` (T-37, D-51) wrapped `hazmat::kalyna_ccm::Kalyna256_256Ccm`, whose
`ccm_padd` header encodes plaintext/AAD length into a single byte each - a real 255-byte
construction limit (D-41), always documented as an interim tradeoff pending a construction with no
such cap. `hazmat::kalyna_gcm::Kalyna256_256Gcm` (D-56) now exists and encodes no length into
itself at all, so the roadmap (user-approved 2026-07-24, "Roadmap to a genuinely complete product"
Step 3 item 1) called for migrating onto it.

**Construction**: `Kalyna256_256Gcm` - same 32-byte key and 32-byte nonce width as the previous
`Kalyna256_256Ccm`, so `SecretKey`/`NONCE_LEN` are unchanged. Tag stays 16 bytes, truncated from
GCM's own full 32-byte tag via the same prefix-comparison convention `hazmat::kalyna_gcm` already
supports - not a new knob, matching the old tag length and libsodium's own `crypto_secretbox` tag
size. Wire format is unchanged in shape: `nonce (32) || ciphertext (now unbounded) || tag (16)`.

**Cap removed entirely, not just relaxed**: `SecretboxError::MessageTooLong` is deleted, not left
dormant - GCM's construction has no such limit, and this project's own convention is not to leave a
dead variant around pre-1.0. `crates/uacrypt/src/lib.rs`'s `CliError::MessageTooLong` (variant,
`Display` arm, `From` impl arm) is deleted for the same reason. This does **not** make
`uacrypt encrypt`/`decrypt` memory-bounded for large files: `--in` is still read whole via
`std::fs::read` (unchanged code, D-42's chunking policy doesn't apply here since an AEAD tag needs
the full plaintext/ciphertext up front under a single-shot construction) - a large input file now
means a correspondingly large in-memory buffer, not a `MessageTooLong` rejection.
`crypto_secretstream` (T-40) remains the separately-tracked, not-yet-started follow-up for a
genuinely chunked construction; this migration does not attempt that.

**A real nonce-authentication gap was found and fixed during this migration, not part of the
original plan.** Unlike NIST AES-GCM (tag = `E_K(J0)`, `J0` IV-derived), DSTU Kalyna-GCM's own tag
construction (D-56 divergence 3) is `E_K(accumulator XOR length_block)`, computed purely from AAD
and ciphertext - the IV/nonce is never mixed into the tag at all, only into the keystream. Verified
directly by reading `hazmat::kalyna_ccm::compute_tag` (its first CBC-MAC block copies the nonce in
directly, `g1[..tmp].copy_from_slice(&nonce[..tmp])` - CCM genuinely does authenticate the nonce)
against `hazmat::kalyna_gcm`'s tag computation (no nonce input at all). For `crypto_secretbox`'s
self-contained `nonce || ciphertext || tag` wire format, an unauthenticated nonce means an attacker
could flip bits in the transmitted nonce prefix and have `open` "succeed" against different,
attacker-uncontrolled-but-unverified plaintext instead of failing closed - a genuine
tamper-evidence regression versus the old CCM-based construction, caught by writing
`tampered_nonce_is_rejected` during the migration (test-first caught it before it shipped, not a
post-hoc audit finding). **Fix**: `seal`/`open` now pass the nonce itself as `kalyna_gcm`'s `aad`
parameter internally (`cipher.encrypt(&nonce, &nonce, ...)` / `cipher.decrypt(&nonce, &nonce, ...)`)
- binding it into the tag via the construction's own designed AAD-authentication mechanism.
`crypto_secretbox`'s public API still exposes no caller-facing AAD parameter; this is purely an
internal implementation detail. `hazmat::kalyna_gcm`'s own module doc gained a new "Warning: the
tag does not cover `iv`" section, and `tests/kalyna_gcm.rs` gained a dedicated
`tampered_iv_alone_does_not_fail_the_tag_check` test pinning the property directly at the hazmat
layer, so future callers of that primitive are warned at the source, not left to rediscover this
the same way.

**Provenance**: inherits `hazmat::kalyna_gcm`'s own D-56 provisional status (dual-oracle-cited via
UAPKI + Bouncy Castle vectors, not yet confirmed against the primary DSTU 7624:2014 text) -
unchanged by this migration.

**Verification**: `cargo test --workspace --all-features` clean (0 failures across every crate,
including `crypto_secretbox.rs` 11/11 and `kalyna_gcm.rs` 15/15, the latter including the new
nonce-tamper test). `cargo clippy --workspace --all-features -- -D warnings` and
`cargo fmt --all -- --check` both clean. `cargo build -p dstu-core --no-default-features` (no_std)
clean. A file larger than the old 255-byte cap round-trips through the real `run_secretbox_command`
CLI dispatcher end to end (`run_secretbox_command_message_larger_than_the_old_255_byte_cap_round_trips`),
proving the removed cap actually reaches the CLI layer, not just the core crate in isolation.
Scoped `cargo +nightly miri test -p dstu-core --test crypto_secretbox` run and timed - **11/11
passed, 0 UB, 1135.80s (~19 min)**, `PROPTEST_CASES=8` (T-100's own precedent; the default 256
cases at up to 2048 bytes each was tried first, killed after ~40 CPU-minutes with zero output -
not stuck, genuinely just that slow under interpretation, not worth burning further). Confirms GCM
has no EC-ladder-class cost, unlike the DSTU 4145 suite that has caused CI's Miri job to time out
(T-100/T-102) - `crypto_secretbox`'s own Miri run completes in real time, just slowly.

**Docs updated**: `README.md`, `docs/dstu-crypto-project.md` (MVP-scope bullet, the
"needs to be constructed" `crypto_secretbox` bullet, and its mapping-table row),
`docs/release-readiness.md` (all `crypto_secretbox`/`crypto_secretstream`-related rows and
narrative mentions), `CLAUDE.md`'s own running project-status paragraph.

## D-64: Adversarial-test coverage audit across every primitive - user-requested, prompted directly by D-63's nonce-authentication gap

D-63 found a real security-relevant gap (`crypto_secretbox`'s tag not covering the nonce) purely by
noticing an *absent* test, not from a code walkthrough - prompting the direct question: where else
might a "does this reject tampering" test simply not exist yet? Surveyed every file under
`crates/dstu-core/tests/` for existing tamper/wrong-key/reject-style coverage (`grep` for
`tamper|wrong_key|reject` test names, then a full test-name listing for each AEAD/MAC/signature
file to catch differently-named equivalents) before writing anything, per this project's own
"check what a fixed vector actually exercises, not just whether it passes" discipline (`CLAUDE.md`
Agent discipline) applied one level up - to test *files*, not just individual vectors.

**Findings and additions** (all new tests pass on first run, no bugs found - this closes coverage
gaps, it does not fix a regression):

- `hazmat::kalyna_gcm` (the current `crypto_secretbox` construction, highest-priority gap): had
  `tampered_ciphertext_is_rejected`/`tampered_aad_is_rejected` but **no `tampered_tag_is_rejected`
  and no `wrong_key_is_rejected`** - both added, matching `kalyna_ccm.rs`'s existing coverage shape
  (which already had all five: ciphertext/tag/aad/nonce/wrong-key).
- `hazmat::kalyna_gmac`, `hazmat::kalyna_kw`, `hazmat::kalyna_cmac`, `hazmat::kupyna_kmac`: each had
  tampered-message/tampered-tag coverage but **no `wrong_key_is_rejected`** test (a MAC/key-wrap
  verifying against a message it never touched with the right key is a distinct failure mode from
  "the tag itself was flipped" - both need their own test). One added to each, following each
  file's own existing helper/`Case`-struct conventions exactly (no new abstractions introduced).
- `hazmat::kupyna` (hash, no reject/accept semantics to test the same way): added
  `single_bit_change_produces_a_different_digest` - the cheapest sanity check that the
  implementation isn't silently collapsing distinct inputs (a truncation/constant-folding-class
  bug class the official vectors alone wouldn't necessarily catch, since they're a fixed small
  set).
- `hazmat::strumok`: **the module doc had no warning at all about key+IV reuse** - a real
  documentation gap, not just a missing test, for the single most consequential misuse of any
  stream cipher (the "two-time pad" break: `ciphertext_a XOR ciphertext_b` recovers
  `plaintext_a XOR plaintext_b` with zero key material). Added a "Warning: never reuse the same
  key+IV pair" module-doc section (mirroring `hazmat::kalyna_gcm`'s existing "tag does not cover
  iv" warning pattern from D-56/D-63) plus a test (`reusing_key_and_iv_leaks_plaintext_xor`)
  demonstrating the XOR-recovery property directly, and a `different_key_produces_different_keystream`
  sanity check.
- `hazmat::kalyna_xts`: had no tamper test at all. Unlike every AEAD mode in this crate, XTS is
  confidentiality-only *by design* (disk-sector integrity is deliberately left to the filesystem
  layer, already documented in `docs/release-readiness.md`'s "Full-disk encryption" row) - added
  `tampered_ciphertext_does_not_error_but_produces_garbage`, pinning that tampering silently
  produces wrong plaintext rather than erroring, so this documented design choice doesn't quietly
  regress into looking like a bug (or get "fixed" into erroring) without the test flagging it.
- `crypto_sign`/`hazmat::dstu4145` and `crypto_secretbox`: reviewed, already had solid coverage
  (`tampered_message_is_rejected`, `tampered_signature_is_rejected`, `wrong_verifying_key_is_rejected`,
  scalar-range edge cases for signatures; the full nonce/ciphertext/tag/wrong-key set for
  secretbox, from D-63) - no additions needed.
- Plain confidentiality-only block modes with no authentication
  (`kalyna_cbc`/`kalyna_cfb`/`kalyna_ofb`/`kalyna_ctr`/`kalyna_ecb`) deliberately excluded from this
  pass: there is no "reject tampering" semantics to test for a mode with no tag by design, and
  their existing length-validation tests already cover the only real reject-path they have.

**Verification**: `cargo test --workspace --all-features` clean, `cargo clippy --workspace
--all-features -- -D warnings` clean (caught and fixed one `clippy::doc_markdown` hit on the new
Strumok warning - `XOR`-ed needed backticks), `cargo fmt --all -- --check` clean.

## D-65: "Fool" (misuse-resistance) test coverage audit, complementing D-64's "attack" pass - `advisor()` consulted before scoping

User-requested follow-up to D-64: same class of question ("where else might a real gap be hiding,
found only by an absent test"), but for naive/incorrect *usage* rather than active tampering -
wrong-length key files, nonexistent/directory input paths, same-path in/out, degenerate-but-legal
input, decrypting never-sealed garbage. `advisor()` consulted before writing anything (per this
project's own "call advisor before substantive work" discipline) and its scoping held up
end-to-end: survey first against the existing 36-test `uacrypt` inventory to avoid duplicating
`parse_*_rejects_unknown_flag`/`parse_*_requires_*` coverage that already existed; most
library-level misuse is structurally foreclosed by fixed-size-array type signatures, not a test gap
(see below); and the constructive suggestions (in/out same-path, never-sealed garbage, empty-file
hash, `--iterations 0`, GCM tag-length-out-of-range parity with `kalyna_gmac`) were exactly the set
implemented, each verified as a genuine, previously-untested runtime path before writing a test for
it.

**Structurally foreclosed misuse categories - recorded here per the new `CLAUDE.md` rule, not
tested**: every direct `hazmat` constructor/method (`SecretKey::from_bytes`, `Kalyna*Gcm::new`,
every mode's `encrypt`/`decrypt`/`new`, every IV/nonce parameter) takes a fixed-size `[u8; N]` array,
not a slice - "wrong key/nonce/IV length" at the `hazmat` API surface is a compile error, not a
runtime path, for every one of these. A test asserting this would only prove the Rust type checker
works, which is noise, not coverage. This is exactly why "wrong length" only becomes a genuine
runtime misuse case at the `uacrypt` CLI layer (which reads raw bytes from a file into a `Vec<u8>`
first, losing the compile-time guarantee) - the CLI-layer tests below are not redundant with this
finding, they cover a genuinely different boundary.

**Library-level additions** (`hazmat::kalyna_gcm`, the current `crypto_secretbox` construction,
same priority ordering as D-64):
- `tag_length_out_of_range_is_rejected` - `kalyna_gmac.rs` already had this; the GCM counterpart
  (identical `8..=block_bytes` bound in `decrypt`) only had a *buffer*-length test
  (`mismatched_output_buffer_length_is_rejected`), not a *tag*-length one - a real parity gap.
- `all_zero_key_round_trips` - the "I'll test with an obviously-fake key" mistake must still work
  correctly, not hit some special-cased path; there is no (and should be no) key-strength
  validation in this construction, so a trivial-looking key must round-trip like any other.

**CLI-level additions** (`crates/uacrypt/src/lib.rs`'s existing in-process `run_*` test
convention - no new process-spawning harness introduced, matching precedent):
- `run_secretbox_command_wrong_key_length_is_rejected` / `run_ccm_command_wrong_key_length_is_rejected`
  - a 31/15-byte key file → `CliError::WrongLength`, `--out` never created.
- `run_secretbox_command_nonexistent_input_is_io_error_not_panic` /
  `_directory_as_input_is_io_error_not_panic` - typo'd path and directory-as-file both a clean
  `CliError::Io`, confirmed not a panic.
- `run_secretbox_command_in_and_out_same_path_round_trips` - encrypting/decrypting "in place" (a
  plausible scripting mistake) works correctly because `--in` is read fully into memory before
  `--out` is ever written - safe by construction, now pinned so it stays that way rather than
  relying on that being incidental.
- `run_secretbox_command_decrypt_rejects_never_sealed_garbage_without_writing_out` - random bytes
  that were never real `seal` output (not a tampered-but-real sealed file, a distinct code path
  from the existing tampered-ciphertext test) still fail cleanly with no partial `--out` write.
- `run_hash_command_empty_file_produces_the_empty_input_digest` - an empty file is degenerate but
  legal input and must succeed, not error.
- `run_digest_command_iterations_zero_behaves_like_one` - pins the existing
  `args.iterations.max(1)` clamp (already-correct code, not a fix) so `--iterations 0` demonstrably
  behaves like `1` rather than silently doing nothing.
- `run_ccm_command_wrong_nonce_length_on_decrypt_is_rejected` - a hand-edited/wrong-variant `--nonce`
  file on decrypt is `CliError::WrongLength`, not a panic or silent truncation.

All 11 new tests (2 library, 9 CLI) passed on first run - coverage additions, no bug found, same as
D-64. `CLAUDE.md`'s "Test-first, always" bullet extended with the three-category rule (correctness/
rejection/misuse) plus the type-signature-foreclosure and first-run-pass clauses above, per the
user's explicit request that this become a standing default for future primitives/commands, not a
one-off pass.

**Verification**: `cargo test --workspace --all-features`, `cargo clippy --workspace
--all-features -- -D warnings`, and `cargo fmt --all -- --check` all clean.
