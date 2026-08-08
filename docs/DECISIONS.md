# docs/DECISIONS.md

Architectural decisions with rejected alternatives and the reason for rejection. Add an entry at
the moment a decision is made, not retroactively.

## D-01: Core is `no_std`-compatible from day one

Feature flags `std` / `alloc` / `no_std` from the first commit.

**Rejected:** `std`-only core with embedded support bolted on later. Rejected because STM32
(Cortex-M) and ESP32 (Xtensa/RISC-V) are genuinely different architectures, not variants of one —
retrofitting `no_std` after the API has hardened would mean a core rewrite, not an addition.

## D-02: DSTU 4145 signatures — wrap, don't reimplement, for Java/.NET

**Superseded 2026-08-02 by D-115 — kept for the historical record, not deleted.** This entry
predates `hazmat::dstu4145`/`dstu_core::crypto_sign` actually existing; once they did (verified
against the standard's own Annex B.1 worked example, dual-oracle-cross-checked against real Bouncy
Castle, D-25/D-46), the premise below no longer holds — see D-115 for the current decision (every
binding, Java/.NET included, exposes this project's own `crypto_sign`; Bouncy Castle stays the
verification oracle only).

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
argument, `docs/TASKS.md` T-55/T-56) fail to compile for every downstream firmware author who doesn't
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
on: `docs/TASKS.md` T-72 (`randombytes`, `crypto_secretbox`/DSTU-4145-signing's internal ephemeral-
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
  `dstu_core::crypto_secretbox` (`docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51, built 2026-07-24 against this
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
(includes Amendment No. 1:2016) via `fnd-store.uas.gov.ua/documents/4228` — see `docs/ORACLES.md`
"Official DSTU text — purchase cost". Deemed cost-prohibitive for now; this decision stays
provisional until either the price becomes viable or another authoritative source turns up.

**Adopted as the project's working assumption, 2026-07-24** (user's explicit direction: proceed on
assumption now, correct later if the primary text says otherwise, never silently) — two
independent, non-primary sources now corroborate Kalyna-alone as the standard's own official
answer, not just reference-implementation agreement:

- **Already-vendored, predates this session's research**: `docs/ORACLES.md`'s own note (2026-07-22) that
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
  `docs/ORACLES.md`'s own pricing-page record) is difficult to explain as anything other than a
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
- `cargo miri test --workspace`: passes, no UB detected — satisfies the `docs/SECURITY.md` requirement.
- `cargo clippy --all-features -- -D warnings`: clean (one `manual_memcpy` lint fixed in
  `shift_bytes`, no logic change).
- `cargo build --no-default-features` (the `no_std` path): compiles clean.
- Additionally cross-checked against real Bouncy Castle (not this project's own port) via
  `tests/oracle-harness/{dotnet,java}/`, both using the published NuGet/Maven packages: all 10
  Kalyna cases + all 12 Kupyna cases pass. Same caveat as always applies to that cross-check —
  BC's Kalyna/Kupyna is a port of the same C reference, so this mainly confirms the vector
  extraction, not a fully independent second implementation.
- **Still missing:** `cargo fuzz` has a scaffold (`crates/dstu-core/fuzz/`, target `kupyna`) but
  has not actually been run yet (required by `docs/SECURITY.md`); the streaming (`update`/`finalize`)
  API doesn't exist (one-shot `digest()` only); no high-level "easy" wrapper (D-09) yet.

## D-11: `cargo audit` and `cargo deny` are required CI layers, same standing as miri/fuzz

`docs/SECURITY.md`'s "Supply-chain vetting" table existed only as a manual process ("fill in per
dependency before merging") with no automated enforcement — inconsistent with how strictly this
project already treats `cargo miri`/`cargo fuzz` (named explicitly as required, not optional).
Added `cargo audit` (RustSec advisory database — known vulnerabilities, yanked crates) and
`cargo deny` (license allowlist, duplicate/banned crates, dependency-source allowlist — policy in
`deny.toml`) as CI jobs in `.github/workflows/rust.yml`, and elevated them to the same
non-optional standing in `docs/SECURITY.md`.

**Rejected:** leaving supply-chain vetting as a manual, human-remembered step. Rejected because
the whole point of `docs/SECURITY.md`'s hard-constraints section is that these things don't rely on
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
an empty `[workspace]` table) so it never appears in the dependency graph `deny.toml`/`docs/SECURITY.md`
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
  re-run against this new code path — see `docs/TASKS.md` "Infrastructure" for wiring); no CBC/CTR/CCM
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
"no official text exists for DSTU 4145" claim that `docs/pseudocode/dstu4145.md` and `docs/ORACLES.md`
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

**Third source added 2026-07-22:** `oracles/uapki/` (see `docs/ORACLES.md`/`oracles/README.md` — a fork
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
carefully"). Rejected because `docs/SECURITY.md`'s dual-oracle requirement exists precisely to catch
this class of error, and a from-scratch cross-check against an already-existing, independently
maintained oracle cost nothing here — there was no reason to settle for single-sourced.

**Still open:** the pseudocode doc (`docs/pseudocode/dstu4145.md`) is not yet re-derived against the
official text's Sections 5-13 — it remains a Bouncy Castle code-transcription for now, which is a
weaker provenance than Kalyna/Kupyna/Strumok's spec-transcriptions. No GF(2^m) binary-field or
elliptic-curve arithmetic exists in `dstu-core` yet, so this vector cannot be exercised by any Rust
code yet — see `docs/TASKS.md` Phase 2.

## D-15: Strumok vectors — sourced from UAPKI's self-test, not self-invented

Strumok had zero test vectors from any source since D-06/D-10 — official text priced at 7,027.80
UAH (see "Official DSTU text — purchase cost" in `docs/ORACLES.md`), no hardware testbench KAT in
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

**Any future status line for Strumok** (`docs/TASKS.md`, `CLAUDE.md`, `docs/dstu-crypto-project.md`)
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
throughout `docs/ORACLES.md`/`oracles/README.md` — every reference to UAPKI in this project states the
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
`crypto_auth`/`crypto_onetimeauth` construction question (`docs/TASKS.md` Phase 2/API-surface —
"Kupyna-based MAC... exact mode name TBD"), not yet cross-checked against anything of ours because
there's no Rust KMAC to check it against yet. Left for follow-up, same as Kalyna's CCM/GMAC/GCM —
not scheduled ahead of where `crypto_auth` already sits in `docs/TASKS.md`.

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
already sits in `docs/TASKS.md`.

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
overlaps. Phase 4 (STM32/ESP32) has no UAPKI equivalent at all. No task in `docs/TASKS.md` touches
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
test-first" (`docs/TASKS.md` Phase 1) — it does **not** upgrade the vectors' status. They remain
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

`docs/SECURITY.md`'s hard constraints say "No secret-dependent branching or array indexing" without
qualification. Every primitive shipped so far violates the array-indexing half of that literally:
`SBOXES[row % 4][*byte as usize]` (`kalyna.rs`, `kupyna.rs`, `strumok.rs`), `SBOXES_DEC[...]`
(Kalyna decryption), and `MUL_ALPHA`/`MUL_ALPHA_INV[...]` (Strumok) all index a lookup table using
a byte derived from secret key/state material. This was flagged 2026-07-22 while reviewing what
"tested" should mean beyond test vectors (see `docs/TASKS.md` "Testing & hardening") — a real,
previously-undocumented gap between a written constraint and the shipped code, not a hypothetical.

**Decision: accept it, scoped and explicit, rather than silently ship a contradiction.** Rationale:
- This is the same class of exposure as AES's classic T-table/S-box cache-timing attacks (Bernstein
  2005, Osvik/Shamir/Tromer 2006) — well-understood, not a novel risk introduced here.
- `docs/SECURITY.md`'s own threat model already carves out hardware side-channels (SPA/DPA) as
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

**`docs/SECURITY.md` updated to say this precisely** rather than leave the absolute "never" standing
next to code that already violates it — a constraint nobody reads accurately isn't enforcing
anything. If constant-time S-boxes are ever built (e.g. as part of the post-MVP hardware validation
phase, `docs/TASKS.md` Phase 4, where the SPA/DPA question gets a real audit anyway), this exception
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
  is alongside the post-MVP hardware validation phase (`docs/TASKS.md` Phase 4), not before.

## D-20: `zeroize`/`ZeroizeOnDrop` added — first real dependency, scoped to what's actually live

`docs/SECURITY.md`'s hard constraints require `Zeroize`/`ZeroizeOnDrop` on all key-material types; no
primitive implemented it (`docs/TASKS.md` "Testing & hardening", item added 2026-07-22 while reviewing
what "tested" should mean beyond test vectors). Closed for the two primitives that actually hold
key-derived state right now:

- **`zeroize` 1.9 added to `dstu-core/Cargo.toml`** with `default-features = false, features =
  ["derive"]` — keeps it `no_std`-compatible (no implicit `alloc`/`std` pull-in, confirmed:
  `cargo build --no-default-features` still passes) per this project's platform-agnostic
  requirement (`CLAUDE.md` MVP scope). First real entry in `docs/SECURITY.md`'s supply-chain table,
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
  `docs/TASKS.md`'s `crypto_auth` line) is implemented, not before; noted here so its absence reads as a
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
`zeroize` crate. Rejected per `docs/SECURITY.md`'s own existing guidance and this project's "no
homegrown primitives where an established one exists" principle (D-03/D-04's reasoning applies
equally to infrastructure like this, not just algorithms) — hand-rolled zeroing is exactly the
"looks right, isn't" problem the crate exists to solve (compiler dead-store elimination on a plain
overwrite), and reinventing it earns no more scrutiny than reviewing the crate's ~10-year-old,
widely-depended-upon approach.

## D-21: `proptest` round-trip tests added for Kalyna and Strumok

`docs/TASKS.md` "Testing & hardening" flagged that Kalyna has only 2 fixed key/block pairs per variant
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
  attempt** — meaningful signal given `docs/DECISIONS.md` D-18 already noted only 8 fixed points existed
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

`docs/TASKS.md` "Testing & hardening" flagged Strumok as the highest-value target for differential
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
`docs/DECISIONS.md` D-10/D-13) — a random-input differential test there is the same *pattern* but with
much lower marginal value than for Strumok, which had the least verification coverage of the
three. Extending this same generator+differ split to `oracles/kalyna-reference/`/`cryptonite` and
`oracles/kupyna-reference/` is a straightforward follow-up if ever prioritized, not a gap being
hidden — noted in `docs/TASKS.md`.

**Rejected:** wiring this into `cargo test`/CI directly. Rejected because it would make the
ordinary test suite depend on a C toolchain being present, which none of the vector/proptest/fuzz
tests currently require — same reasoning that already keeps the Java/.NET oracle harnesses as
separate `cargo xtask` targets rather than folded into `cargo test --workspace`.

## D-23: `criterion` benchmarks added for all three primitives

Last item in `docs/TASKS.md` "Testing & hardening". `criterion` 0.8 added as a dev-dependency, three
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

This closes every item in `docs/TASKS.md` "Testing & hardening" except "actually run `cargo fuzz`",
which stays open pending CI or a machine with the MSVC toolchain (D-22's sibling finding, not a
gap in this entry).

**Baseline numbers, the comparison against Oliynykov's reference C / UAPKI / outspace, the machine
they were measured on, and the saved `criterion --baseline` for regression tracking all live in
`docs/PERFORMANCE.md`** (added 2026-07-22) — the canonical home for this project's performance data, so
it doesn't rot as a one-time paragraph here. Headline finding, in one line: this project's Rust is
faster than the designers' own reference C (correctness/clarity-optimized, not speed) but
meaningfully slower than UAPKI (a production-optimized real-world library) and outspace's Strumok —
a real, known, and non-blocking gap, not a mystery; see `docs/PERFORMANCE.md` "What the gap is, honestly"
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

Starting the actual Rust port (`docs/TASKS.md` Phase 2): the GF(2^m)/EC arithmetic layer, not the
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
`docs/SECURITY.md`'s "no secret-dependent branching" is unqualified here — D-19 carved out table
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
  control flow regardless of `a`'s value, no new primitive needed. **This was the intended design
  from this entry onward, but the code that actually shipped for a long stretch was a simpler direct
  162-round Fermat exponentiation instead** (a self-acknowledged gap, noted only in `invert()`'s own
  doc comment, never recorded here) — closed by `docs/DECISIONS.md` D-109/`docs/TASKS.md` T-153, which
  replaced it with the addition-chain form this bullet always described.
- **Scalar multiplication**: Montgomery ladder with constant-time conditional swap, rather than
  double-and-add — needed for both `e·G` (secret ephemeral during signing) and, per the same
  posture, applied uniformly rather than carved out only where a value happens to be secret.

**Rejected:** a faster non-constant-time first pass (direct BC/OpenSSL transcription), deferring
the branchless rewrite to later. Rejected because this is exactly the kind of decision that's cheap
to make correctly up front and expensive to retrofit — same reasoning `docs/SECURITY.md` already applies
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
  logic itself, which is the next layer up (`docs/TASKS.md` Phase 2).

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
open docs/TASKS.md item for this pass.** Read Sections 5, 9, 11-13 directly (rendered PDF pages, no text
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

`docs/PERFORMANCE.md` (D-23's follow-up) quantified a real, root-caused gap to UAPKI/outspace for
Strumok specifically — two distinct, additive causes found by reading `oracles/strumok-dstu8845
/strumok.c` directly: (1) `next_step` shifted the whole 16-word state array
(`s.copy_within(1..16, 0)`) every step, a real 120-byte move outspace's fully-unrolled
`next_stream()` never does; (2) `t_function` computed the `T` substitution at runtime (8 S-box
lookups + a full `GF(2^8)` MDS matrix-multiply via `apply_matrix`/`gf_mul`) instead of 8
precomputed combined tables the way outspace's `T0..T7` do.

**Both fixed 2026-07-22, sketched as a `docs/TASKS.md` item first, then implemented the same day**:

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
`strumok-optimized-2026-07-22`; `docs/PERFORMANCE.md` has the full before/after table.

**Not done in this pass**: the equivalent combined-table optimization for Kalyna/Kupyna
(`hazmat::tables`, shared between them) — same category of work, sketched in the same `docs/TASKS.md`
item, bigger surgery since it touches both algorithms' round functions and Kalyna's decrypt
direction too. Next in line, not started yet.

## D-27: Kalyna/Kupyna's shared `apply_matrix` switched to precomputed MDS tables

Follow-up to D-26, same day: `docs/PERFORMANCE.md` showed Kalyna/Kupyna meaningfully slower than UAPKI,
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
`kalyna-kupyna-optimized-2026-07-22`; `docs/PERFORMANCE.md` has the full before/after table.

**Not done**: fusing `sub_bytes`/`shift_rows` into the combined table too (UAPKI's full
`p_boxrowcol` approach) - would need per-`nb` tables (Kalyna's row-shift offset depends on block
size, unlike Strumok's fixed 16-word state), a bigger and more invasive change than this pass's
"one shared function, both algorithms benefit" scope. Sketched as a possible further step, not
scheduled.

## D-28: Full S-box+shift+MDS fusion for Kalyna encrypt + Kupyna - correcting D-27's stated blocker

Follow-up to D-27, planned 2026-07-22 (`docs/TASKS.md`), implemented the same day. D-27 assumed full
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
`docs/PERFORMANCE.md`): Kalyna encrypt **-55% to -68%** further reduction (e.g. 128-128: 2354 ns -> 1041
ns; 512-512: 12735 ns -> 4006 ns) - decrypt also improved **-36% to -40%** purely from the faster
key schedule sharing `encipher_round`, even though `decipher_round` itself is untouched. Kupyna
improved **-85% to -87%** (e.g. Kupyna-256 at 64 KB: 14.57 -> 98.6 MB/s). Against UAPKI: Kalyna is
now **~3.4-4.9x slower** (was ~10.6-14.5x after D-27) with key-schedule caching (`docs/TASKS.md` stage 3,
not done yet) still to come; **Kupyna is now at or above UAPKI's own speed** (256: 1.03-1.45x
*faster*; 512: 0.93-1.45x, roughly at parity) - both far beyond this task's original "2-3x of
UAPKI" expectation, because the actual dominant cost turned out to be the runtime-modulo bug above,
not an inherent limit of the fused-table approach. New baseline: `kalyna-kupyna-fused-2026-07-22`.

## D-29: `ExpandedKey` types added for Kalyna - cache the round-key schedule across calls

Follow-up to D-28, same day (`docs/TASKS.md` D-28 stage 3, user's explicit go-ahead to make this an
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
key expanded once outside `b.iter`) gives the honest split `docs/TASKS.md` stage 0 asked for -
`kalyna_128_128_encrypt_block_only` is **133 ns**, i.e. *faster than UAPKI's 222 ns* for the
schedule-cached case; `kalyna_512_512_encrypt_block_only` is 568 ns vs UAPKI's 879 ns, also faster.
**Decrypt-block-only is 3.2-6.9x slower than encrypt-block-only** (e.g. 512-512: 568 ns encrypt vs
3934 ns decrypt) - this was already visible before `ExpandedKey` (D-27/D-28 never fused the decrypt
round) but is now the single largest remaining gap, since encrypt (with a cached key) has
essentially closed the distance to UAPKI. New baseline: `kalyna-expandedkey-2026-07-22`.

## D-30: Kalyna decrypt round fused too - equivalent-inverse-cipher restructuring

Follow-up to D-28/D-29, same day (`docs/TASKS.md` D-28 stage 4, the item both those entries deferred as
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

**Result**: full before/after tables in `docs/PERFORMANCE.md`'s new "Binary-level (process) comparison"
section. Headline finding: `dstutool`'s cached (`ExpandedKey`) per-op numbers match the in-process
`criterion` numbers within a few percent (e.g. 128-128 encrypt: 127 ns here vs 132 ns in-process) -
the CLI adds no meaningful overhead once amortized. Process-spawn overhead (~60-63 ms on this
machine, likely including Windows Defender scanning a freshly-built binary, per this session's
earlier note) is **roughly the same across all three binaries**, dominating whole-invocation
wall-clock time and confirming that `wall_ns` (which this comparison reports too, not hidden)
mostly measures the OS, not the crypto - `per_op_ns` is what actually reflects implementation
speed, same conclusion as D-28/29/30's in-process numbers.

**Next, tracked in `docs/TASKS.md`, explicitly NOT unblocked by this entry**: a safe mode of operation
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
  numbers turned out close (init is small relative to a 64 KB buffer) - see `docs/PERFORMANCE.md` for
  why this differs from Kalyna, where cached vs raw was a much bigger gap.

Comparison CLIs added for Oliynykov's Kupyna reference C, UAPKI's `dstu7564`, outspace's
`dstu8845`, and UAPKI's `dstu8845` (all scratchpad-only, not committed, same convention as
`kalyna-block`'s comparison CLIs) - all four cross-checked byte-identical against `dstutool`
before timing. Full result tables in `docs/PERFORMANCE.md`.

## D-32: `cargo fuzz` actually run on this machine, all three targets - the MSVC blocker wasn't wrong, just avoidable here

`docs/TASKS.md`/D-23 left "actually run `cargo fuzz`" open, blocked on a confirmed toolchain fact:
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

The Raspberry Pi rig (`docs/TASKS.md` "Testing & hardening", `.claude.local.md`) so far only ran this
project's own `cargo bench` there - the "faster than UAPKI" claims in D-28/D-29/D-30 and
`docs/PERFORMANCE.md` were only ever checked on the Ryzen dev machine. The user asked directly whether
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

Full per-size numbers are in `docs/PERFORMANCE.md`'s three Results tables, now with a `UAPKI
(Raspberry Pi 5)` column/row alongside the Ryzen one. Kalyna's 512-512 case is the starkest: 1185
ns (this project) vs 632 ns (UAPKI) on the Pi - UAPKI is ~1.9x faster there, versus this project
being ~1.5x faster than UAPKI on the same variant on Ryzen.

**Why this is plausible, not a red flag - three untested hypotheses, in order of how much they'd
explain, none investigated further this pass** (flagged explicitly as speculative, per this
project's own "don't overclaim a root cause" discipline - see the Strumok/outspace residual gap in
`docs/PERFORMANCE.md`'s "What the gap is, honestly" for the established precedent of naming a gap
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
now - the code is still correct on both platforms (`docs/TASKS.md`'s ARM build/test task, unaffected),
and this project's MVP scope (`CLAUDE.md`) never promised the Ryzen speed advantage generalizes to
every architecture, only that the code compiles and runs correctly on more than one.

**Scope corrections applied**: `docs/PERFORMANCE.md`'s Kalyna/Kupyna Results tables and the "What the
gap is, honestly" section both got a dated correction noting the Ryzen-specific scope of the
"beats UAPKI" claim, rather than silently leaving an now-incomplete claim standing - per this
project's own standard for correcting prior statements (see `CLAUDE.md` "Never silently deprecate
a document" applied at sentence granularity here, not just file granularity).

## D-34: One performance-testing method from now on - built binary, real process, MB/s only

Prompted directly by D-33: reconciling "this project beats UAPKI" (in-process `criterion` vs. a
raw C timing loop) against the binary-level numbers already in `docs/PERFORMANCE.md` (D-31, `dstutool`
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
regression-tracking tool (`docs/DECISIONS.md` D-23, the saved `--baseline` mechanism) - useful for
noticing a Rust-side regression between commits on one machine, a different job than comparing
against another implementation entirely. It simply stops being used for the *cross-implementation*
comparison`docs/PERFORMANCE.md` is actually for.

**MB/s for a fixed-size block cipher (Kalyna)**: still computed as `block_size_bytes / per_op_time`
(D-31's existing convention, kept) - not a message-length-dependent rate the way Kupyna/Strumok's
is, but reported the same unit for a consistent table shape across all three algorithms, which is
exactly what "one metric" means here.

**Practical effect on `docs/PERFORMANCE.md`**: the entire "## Results" (in-process) section is marked
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
combinations (`docs/TASKS.md` "Re-confirm the `no_std` build still passes") - CI gains one more
build+test matrix entry (`--features small-tables`), not new tests to write or maintain. Two
independent full implementations would have been the actually expensive path, since each would
need its own dual-oracle confirmation; a `cfg`-gated shared round function reusing the same
verified math does not.

**Not decided here**: the feature's public name, `dstutool`'s working name, and the project's own
(GitHub) name are all still open - see `docs/TASKS.md` Phase 1/Phase 4 for the naming subtask. Also not
decided: whether `small-tables` on AVR is sufficient on its own, or still needs `PROGMEM`
placement work on top (`docs/TASKS.md` Phase 4's existing Arduino stretch-goal note) - the Harvard-
architecture SRAM-copy problem is orthogonal to which table set is chosen and isn't solved by this
decision alone.

## D-36: `dstutool`'s real name is `uacrypt` (`docs/TASKS.md` T-21)

Researched naming conventions in the libsodium-adjacent/security-CLI space before proposing
options: smallstep's "The Poetics of CLI Command Names" (concrete anti-patterns - never use
"tool"/"kit"/"util"/"easy" in a command name, since `dstutool` already does; don't bind the name to
a specific protocol/standard that may age out, the exact regret `openssl`'s own naming is called
out for) plus real precedent from Frank Denis's libsodium-adjacent tools (`minisign`, `age`/`rage`,
`sq`) - short, easy to type without Shift, pronounceable the same way worldwide. Three candidate
directions were given (a short "thoughtful meaningless" word like `step`/`age`; continuing this
project's existing Ukrainian nature-word theme the way `Kalyna`/`Kupyna`/`Strumok` already are, not
acronyms; a Ukraine+crypto portmanteau) - user picked the portmanteau direction, name **`uacrypt`**.

**Scope of this decision**: names the CLI binary only (`docs/TASKS.md` T-21). Explicitly does not
resolve T-20 (the small-tables/fused feature-flag public name, D-35) or T-22 (the project's own
GitHub name) - `uacrypt` is not automatically assumed for either, pending confirmation.

**Not yet done**: the actual rename (`crates/dstutool` package/binary name in `Cargo.toml`,
`README.md`, `docs/dstu-crypto-project.md`, and any place `dstutool` is invoked from
`xtask`/CI/`docs/PERFORMANCE.md`) - this entry records the naming decision itself, not the mechanical
follow-through.

## D-37: `uacrypt` rename executed; also adopted as the project's own (GitHub) name (T-22)

Follow-up to D-36, same day: user confirmed both open questions at once - do the D-36 rename now,
and reuse `uacrypt` for `docs/TASKS.md` T-22 (the project's own/GitHub name) too, rather than treating
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
- `docs/SECURITY.md`, `docs/dstu-crypto-project.md`, `CLAUDE.md` - each place that named the CLI
  `dstutool` (working name) now says `uacrypt`, citing this entry.
- `docs/PERFORMANCE.md`'s **canonical** "Binary-level (process) comparison" section (D-34) - column
  headers, prose, and the `cargo build -p uacrypt --release` / `target/release/uacrypt
  kalyna-block ...` reproduction commands - updated, since this section's commands need to
  actually work today, unlike a historical record. The measured numbers themselves are unchanged
  (same binary, same behavior, name only) - a one-line note added explaining the rename rather
  than silently changing what the numbers were labeled under.

**Deliberately left unchanged**: `docs/DECISIONS.md`'s own earlier entries (D-26 through D-34, D-36
above), `docs/TASKS.md`'s historical `[x]` narrative entries, and `docs/PERFORMANCE.md`'s superseded
"## Results" section all still say `dstutool` - each describes what was literally built and
measured under that name *at the time*, and rewriting history to match a later rename would be
the "silently deprecate a document" failure mode `CLAUDE.md` and this project's own D-34 precedent
(dated-banner-not-deletion) both warn against. `docs/dstu-crypto-project.md`'s own filename was
**not** renamed - it names its *content* (the DSTU crypto project spec), not the product, and
renaming it would break a large number of existing cross-references (`CLAUDE.md`'s documentation
map, `docs/TASKS.md`, every `docs/DECISIONS.md` entry citing it) for no functional benefit; same reasoning
applies to `dstu-core`'s crate name, which was never in scope of T-21/T-22 (it names the *library*,
which is not "uacrypt" - `uacrypt` is specifically the CLI/project name, not the core crate).

**Verified**: `cargo build --workspace`, `cargo test -p uacrypt` (15/15 passed), `cargo clippy
--workspace -- -D warnings`, `cargo fmt --check` all clean post-rename on the Ryzen dev machine.
`Cargo.lock` regenerated by the build rather than hand-edited. Not yet re-run: the `no_std`
feature-flag matrix, Raspberry Pi re-sync, or CI - none of this rename touches `dstu-core` or its
feature flags, so no regression is expected, but per `docs/TASKS.md`'s standing "re-confirm as each
change lands" discipline these should still be re-checked before the next release, not assumed.

**Still open**: T-20 (the small-tables/fused feature-flag public name, D-35) is the one remaining
naming decision - not resolved by this entry.

## D-38: Resource-profile feature keeps its working name - `small-tables`, no rebrand (T-20)

Follow-up to D-35/D-36/D-37, same day - the last open naming decision (`docs/TASKS.md` T-20). Asked
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
external dependencies (`docs/SECURITY.md`/`deny.toml`) so no cross-crate feature-unification risk.

**Not done here**: this closes the naming question only. `docs/TASKS.md` Phase 4's "Two-resource-profile
split" item (the actual `[features] small-tables = []` entry plus `cfg`-gating
`gf_mul`/`MDS_MATRIX`/`SBOXES` vs. `SBOX_MDS`/`SBOX_MDS_DEC`/`T0..T7`, D-35's "promote from
dead_code to production path") is still open, unstarted.

All three `docs/TASKS.md` T-19 naming decisions (T-20/T-21/T-22) are now resolved.

## D-39: `small-tables` implemented - D-35's design executed (`docs/TASKS.md` T-54)

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

**Not decided yet, on purpose - tracked as `docs/TASKS.md` T-82, not resolved here:**
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
  "whatever the caller passes, currently uncontrolled" - `docs/TASKS.md` T-82 owns finishing this.

**Resolved 2026-07-23, same day (`docs/TASKS.md` T-82): wide random nonce, no stateful counter -
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
   Phase-4 targets (`docs/TASKS.md` T-55/T-56, STM32/ESP32) cannot be assumed to have durable,
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
state-expertise pedigree is `docs/ORACLES.md`'s standing trust basis for this source.

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
fmt --check` clean; all 8 `no_std`/`alloc`/`std`/`small-tables` feature combinations (`docs/TASKS.md`
T-23/T-54) build clean and the CCM test suite passes identically under `small-tables` (needs no
`cfg` gating of its own - it only calls the existing per-variant `ExpandedKey` API); re-confirmed on
the Raspberry Pi rig too (`docs/TASKS.md` T-35). `uacrypt`'s new `kalyna-ccm encrypt`/`decrypt`
subcommand round-tripped a real message through the built release binary and correctly rejected a
single-byte-flipped ciphertext without writing `--out` (`docs/DECISIONS.md` D-34's "built binary, not
just in-process" policy). New `cargo fuzz` target (`fuzz_targets/kalyna_ccm.rs`, `docs/TASKS.md` T-81)
directly attacks `open_in_place` with never-produced-by-`seal_in_place` bytes, not just round-trip
output - a 60s MSVC smoke run alongside the other three targets found zero crashes (cov 801,
110,542 execs; all four targets together: exit 0). `cargo miri test` scoped to the five
official-vector tests (the full `proptest` suite hits a pre-existing proptest+Miri
directory-isolation interaction on this Windows dev machine, already affecting the
*already-existing* `kalyna.rs`/`strumok.rs` proptest suites too, not something new introduced here,
and separately impractically slow to run to completion under Miri regardless) - clean, no UB.

**Not done, by design**: nonce-generation strategy (D-40, `docs/TASKS.md` T-82); wiring this into
`crypto_secretbox`/`uacrypt`'s reserved top-level `encrypt`/`decrypt` names (still blocked on D-05's
primary-text confirmation, unchanged by this provisional adoption); GCM (considered, deferred - see
D-40's sibling reasoning in `docs/TASKS.md`'s Phase-1 CCM task write-up: GCM needs a new, block-size-
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
  nothing already recorded in `docs/PERFORMANCE.md`.

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
discards it, relying directly on `Strumok::apply_keystream`'s own chunk-invariance (`docs/TASKS.md`
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
pre-release opt-in installs) better deferred to the actual first publish (`docs/TASKS.md` T-17), not
decided speculatively now. Both `crates/dstu-core/Cargo.toml` and `crates/uacrypt/Cargo.toml`
bumped together, including `uacrypt`'s `dstu-core = { path = "...", version = "0.1.0" }` path-dep
version (missing this second spot would silently leave the wildcard-dependency problem T-75 already
fixed once). `xtask/Cargo.toml` deliberately left at `0.0.0` - separate `[workspace]`, dev-only
tool, never published, no reason to version it the same way.

**README**: a banner added at the very top (`README.md`, above the existing "An open Rust library
for..." paragraph, which stays as-is) stating the version, pre-release/WIP status, and - since this
is a crypto library, not just any 0.x project - the same safety caveats `docs/SECURITY.md` already
states: not audited, not production-ready, no side-channel-resistance claim, Strumok/Kalyna-CCM
still provisional (D-15/D-41), no file-level `encrypt`/`decrypt` yet (D-05). A WIP notice on a
crypto library is a safety statement, not cosmetics - it must not undersell what's still missing.
`Cargo.lock` regenerated via `cargo build --workspace` (not hand-edited) to pick up both version
bumps.

See `docs/release-readiness.md` (added same day) for the fuller gap analysis - what a genuine
libsodium-equivalent 1.0 release still needs beyond this version bump.

## D-44: Kupyna-based KMAC (`crypto_auth` equivalent) implemented - dual-oracle, both constructions read

`docs/TASKS.md` T-38, first item worked from `docs/release-readiness.md`'s ordered list (T-38/T-39/
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
Result<(), KmacError>` using `subtle::ConstantTimeEq` for the tag comparison (per `docs/SECURITY.md`'s
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

`docs/TASKS.md` T-39, second item from `docs/release-readiness.md`'s ordered plan. **A materially
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

`docs/TASKS.md` T-48, last item from the user's ordered list (`docs/release-readiness.md` step 5). The
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
   need forces it (at which point that need, and the resulting risk, gets its own `docs/DECISIONS.md`
   entry, not a silent addition). This is the same posture already implicit in `uacrypt` reserving
   `encrypt`/`decrypt` for only the eventual fully-safe construction (D-31/D-41's provisional-CLI-
   naming discipline) rather than exposing raw block-cipher or CCM-with-caller-nonce as top-level
   commands.

**Scope and limits, stated so this can't be over-applied**: this rule governs *forks with no
settling DSTU citation* - it does not license overriding an actual primary-spec requirement once
D-05 resolves, or any other case where the standard itself is unambiguous. `CLAUDE.md`'s existing
hard constraint ("no primitive without a cited spec section... citation goes in `docs/DECISIONS.md`")
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
`compile_error!` on an unrecognized bare-metal target (`docs/DECISIONS.md` D-04's addendum). This is not
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
`docs/SECURITY.md`'s supply-chain table alongside `zeroize`'s existing one.

**Bonus consolidation, behavior-preserving**: `uacrypt`'s existing direct `getrandom::fill` call
(T-82's CCM nonce generation) now goes through `dstu_core::randombytes::randombytes_buf` instead,
and `uacrypt`'s own direct `getrandom` dependency was removed from its `Cargo.toml` - one call site
and one version pin for OS randomness in this workspace, not two. All 23 existing `uacrypt` tests
(including the CCM fresh-nonce-per-call test) still pass unchanged; `cargo clippy --workspace
--all-features -- -D warnings` and `cargo fmt --check` both clean workspace-wide.

## D-49: `argon2` crate vetted for T-71 (`crypto_pwhash`) - not yet adopted, research only

Per `CLAUDE.md`'s "research before implementation" discipline, the candidate crate T-71 flagged
2026-07-24 (`docs/dstu-crypto-project.md`'s libsodium mapping, `docs/TASKS.md` T-71) was vetted against
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
- neither touched `password-hashes`. `docs/TASKS.md` T-71's existing "not yet vetted for a specific
audit of *that* crate" caveat is confirmed accurate, not stale.

**CVE/advisory history**: clean. Checked both the local `cargo audit` advisory database already
cached on this machine (`~/.cargo/advisory-db`, no `crates/argon2` directory exists in it at all)
and the upstream `RustSec/advisory-db` repository directly (no advisory directory for this crate)
- two independent checks, not one.

**Conclusion**: `argon2` clears this project's supply-chain bar (`docs/SECURITY.md`) on every axis
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
`Zeroize`/`ZeroizeOnDrop` (`CLAUDE.md`, `docs/SECURITY.md`). Fixed by adding `"zeroize"` to the
`argon2` dependency's feature list - no new crate pulled in, `zeroize` is already a direct
`dstu-core` dependency (D-20). Re-verified after the fix: `cargo test -p dstu-core --features
pwhash` and the integration suite both still green, `cargo clippy --workspace --all-features -- -D
warnings`/`cargo fmt --all -- --check` both clean, all four `no_std`/`alloc`/`small-tables`
combinations still unaffected.

**`cargo audit`/`cargo deny check` - run and confirmed clean, not skipped**: `docs/SECURITY.md` states
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
`pwhash` is never enabled there. A `rand_core 0.6.4` row was added to `docs/SECURITY.md`'s supply-chain
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
"<255-byte case." `crypto_secretstream` (`docs/TASKS.md` T-40) remains the tracked follow-up for
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
that question, it only wraps the primitive that already carries it. `docs/TASKS.md` T-16 (`uacrypt`'s
reserved `encrypt`/`decrypt` commands) is now unblocked to *start* (its stated gate was
`crypto_secretbox` existing, not D-05's status) - not built as part of this task.

## D-52: `uacrypt encrypt`/`decrypt`/`hash` (T-16) implemented - the 255-byte cap made loud, not deferred

Same session as D-51, immediately after. What got built: `uacrypt`'s reserved top-level `encrypt`/
`decrypt`/`hash` commands (`crates/uacrypt/src/lib.rs`) - three new flat `run()` match arms (not
nested like `kalyna-ccm`'s own `encrypt`/`decrypt` sub-match, matching `docs/TASKS.md` T-16's own text
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
explicitly and points at `docs/TASKS.md` T-40 as the future lift - the loud-cap requirement from the
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
(`README.md`/`CLAUDE.md`/`docs/dstu-crypto-project.md`/`docs/release-readiness.md`/`docs/TASKS.md`/this
entry) - each commit independently green.

## D-53: Full DSTU 7624 mode-of-operation coverage at `hazmat` - roadmap, and ECB (#1) as Stage A's first piece

User asked to implement all 10 official DSTU 7624:2014 modes (`docs/ORACLES.md`'s ten-mode list, D-05)
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
`encrypt_in_place`/`decrypt_in_place`, `docs/TASKS.md` T-88). Cited to `dstu7624.c`'s `encrypt_ecb`/
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

**Stage A, second piece: `hazmat::kalyna_ofb`** (`docs/TASKS.md` T-89). Cited to `encrypt_ofb`
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

**Stage A, third piece: `hazmat::kalyna_cbc`** (`docs/TASKS.md` T-90). Cited to `encrypt_cbc`/
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

**Stage A, fourth piece: `hazmat::kalyna_cfb`** (`docs/TASKS.md` T-91) - the most internally complex
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

**Stage A, fifth and final piece: `hazmat::kalyna_ctr`** (`docs/TASKS.md` T-92) - Stage A is now
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
`docs/SECURITY.md`'s "no primitive without a cited test" rule forbids shipping a wider, untested `q` range.
Key stays the fixed-size `&[u8; $key_bytes]` array every Stage-A module already uses, so (unlike
`KmacError::WrongKeyLength`) no key-length error variant is needed - `mac()` is infallible.
`verify()` uses `subtle::ConstantTimeEq` for the tag comparison (`docs/SECURITY.md`'s constant-time-compare
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
  rather than silently treated as dual-oracle-verified. This was the exact caveat `docs/TASKS.md` T-93
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

**Correction to this roadmap's original framing** (`docs/DECISIONS.md` D-53, `docs/TASKS.md` T-94's original
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
pages, paid, not purchased - `docs/ORACLES.md`) to break the tie, and the two implementations are one
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
Added this check (`subtle::ConstantTimeEq`, `docs/SECURITY.md`'s constant-time-comparison rule - the
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
weaker-claim caveat `docs/DECISIONS.md` D-41 already states for CCM, stated explicitly rather than
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
outcome; its pass/fail is recorded in `docs/TASKS.md` T-95 once it lands rather than held here as a
blocking condition on this entry. Not a substitute for a real oracle vector if one is ever found,
but real evidence the module is exercised by more than five accidentally-easy KATs. The audit's
other findings (`subtle` missing a row in `docs/SECURITY.md`'s
dependency-vetting table despite being a direct, unconditional, crypto-critical dependency; CI's
`fuzz-smoke` job covers only 1 of 4 existing fuzz targets, and none of the four modes landed this
session - `kalyna_cmac`/`kalyna_kw`/`kalyna_gcm`/`kalyna_gmac` - have a fuzz target at all;
`docs/release-readiness.md` now stale, still stating GCM/KW/XTS as "not built" after this session
landed GCM/KW/GMAC) are process/documentation follow-ups, tracked as new `docs/TASKS.md` items rather
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
remaining DSTU 7624 mode) before starting the broader post-audit roadmap (`docs/TASKS.md`'s "Roadmap to
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
resolved this same session to a checked error, `docs/TASKS.md` T-101, per the project owner's explicit
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
genuinely complete product" in `docs/TASKS.md` - trust/correctness fixes (T-97-T-101), full
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

**A second, previously-unreachable finding, NOT fixed here - filed as `docs/TASKS.md` T-102.** The
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

Own plan-mode pass, per the roadmap's explicit requirement for this specific fork (`docs/TASKS.md`
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

`docs/SECURITY.md` calls `cargo fuzz` required, not optional, for every parser of untrusted input bytes.
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

## D-66: `crypto_generichash`/`crypto_auth`/`crypto_kdf` high-level modules (T-105) - roadmap Step 3 item 2

`docs/TASKS.md`'s roadmap left this step's shape as an explicit fork: "decide whether a dedicated
re-export module is needed for naming parity with `crypto_sign`/`crypto_secretbox`/`crypto_pwhash`,
or a table entry suffices." Resolved by building the modules, not settling for documentation alone
- Step 3's own stated goal is "the libsodium-shaped `crypto_* `frontend over everything in
`hazmat`," and a caller browsing `dstu_core`'s top-level modules for `crypto_auth` and finding
nothing there (having to already know to look under `hazmat::kupyna_kmac` instead) is exactly the
discoverability gap that goal exists to close, independent of whether new logic is warranted.

**The three modules are not one shape, though** - inspecting each `hazmat` primitive's actual API
before wrapping it (per this project's "research before implementation" discipline) showed real
differences:

- **`crypto_generichash`** (`dstu_core::crypto_generichash`) is a bare `pub use` of
  `hazmat::kupyna::{Kupyna256, Kupyna512, Kupyna256Hasher, Kupyna512Hasher}` - no new type, no new
  logic. `hazmat::kupyna`'s `digest()`/`Hasher` API already has nothing left to hide (no algorithm
  knob beyond output size, no nonce, no length cap), and libsodium's own `crypto_generichash`
  value-adds over a bare hash function - a caller-chosen variable output length, and an optional
  key for keyed hashing - have no DSTU equivalent to re-derive: Kupyna has no variable-output mode,
  and DSTU 7564:2014's own keyed construction is a distinct primitive (`hazmat::kupyna_kmac`),
  already surfaced separately as `crypto_auth` below, not a parameter of this one. Writing a
  wrapper type here would only be indirection with no behavior behind it. **Both `Kupyna256` and
  `Kupyna512` are re-exported here, unlike `crypto_auth`/`crypto_kdf`'s single-variant choice
  below** - not an inconsistency: libsodium's own `crypto_generichash` is itself variable-output
  (the caller picks the digest length), so exposing both Kupyna sizes is the direct DSTU analogue
  of that choice, whereas libsodium's `crypto_auth`/`crypto_kdf` are fixed-output by design, which
  is what D-47's "delete the knob" is matching for those two.
- **`crypto_auth`** (`dstu_core::crypto_auth::{auth, verify, Key}`) and **`crypto_kdf`**
  (`dstu_core::crypto_kdf::MasterKey::derive_subkey`) are thin wrappers, matching each other's
  shape exactly. Two departures from their respective `hazmat` APIs, both D-47's "delete the knob"
  criterion (the same rule `crypto_secretbox` applied to Kalyna's five variants, D-51):
  - **Only the 256-bit size is exposed** - `hazmat::kupyna_kmac`/`hazmat::kupyna_kdf` each also
    have 384/512-bit variants (`Kupyna384Kmac`/`Kupyna512Kmac`, `Kupyna384Kdf`/`Kupyna512Kdf`),
    left `hazmat`-only, matching this crate's existing default-to-256-bit convention
    (`crypto_secretbox`'s `Kalyna256_256Gcm`, `crypto_sign`'s internal `Kupyna256` message hash).
  - **The key is an opaque, `Zeroize`-on-drop type** (`Key` for `crypto_auth`, `MasterKey` for
    `crypto_kdf`) constructed only via `from_bytes([u8; 32])` or a `generate()` convenience
    constructor - not a raw `&[u8]`/`[u8; 32]` the caller manages themselves. For `crypto_auth`
    this also **forecloses `hazmat::kupyna_kmac::KmacError::WrongKeyLength` at this layer
    entirely**: `Key` can only ever be exactly 32 bytes, so `auth()` is infallible and `verify()`'s
    error type ([`TagMismatch`]) has exactly one variant. Per `CLAUDE.md`'s own documented
    convention for this exact situation, this is recorded here as a type-signature foreclosure,
    not something requiring a test that would only prove the compiler works. `crypto_kdf` has no
    equivalent error to foreclose - `hazmat::kupyna_kdf::Kupyna256Kdf::derive_subkey` was already
    infallible before this wrapper.

**`std` gating is per-item, not per-module** - a deliberate departure from `crypto_secretbox`'s
whole-module `#[cfg(feature = "std")]` gate. All three new modules are declared unconditionally in
`lib.rs` (no `#[cfg]`), unlike `crypto_secretbox` (which needs `Vec<u8>` for its output) - none of
`crypto_generichash`/`crypto_auth`/`crypto_kdf` needs `alloc` at all, every input/output is a
fixed-size array, so gating the whole module the same way would have been a needless `no_std`
regression: this crate's stated MVP priority is `no_std`-from-day-one (`CLAUDE.md`), and
`hazmat::kupyna_kmac`/`hazmat::kupyna_kdf` are themselves already used unconditionally inside
`crypto_sign` without a `std` gate. Only `Key::generate()`/`MasterKey::generate()` - the
convenience constructors that draw fresh key material from the OS CSPRNG via
`crate::randombytes::randombytes_buf` - are individually `#[cfg(feature = "std")]`-gated, mirroring
`crypto_secretbox::SecretKey::generate()`'s own reason for existing (D-51) without forcing the rest
of the module through the same gate. Confirmed, not assumed: `cargo build -p dstu-core
--no-default-features` (bare `no_std`), `--features alloc`, and `--features small-tables` all build
clean with these three modules present.

**Tests** (`tests/crypto_auth.rs`, `tests/crypto_kdf.rs`, `tests/crypto_generichash.rs`) follow the
D-64/D-65 three-category convention where it actually applies, not by rote: correctness
(delegation - each wrapper's output is asserted equal to a direct call into the already
official-vector-tested `hazmat` layer, since the underlying construction itself is not
re-verified here), rejection (`crypto_auth` only - tampered tag, tampered message, wrong key, all
`Err(TagMismatch)`; `crypto_kdf` has no tag or checksum to tamper with, so this category is
genuinely absent, not skipped by oversight), and misuse (empty message / all-zero key for
`crypto_auth`, all-zero master key for `crypto_kdf` - both degenerate-but-legal, both must succeed).
`crypto_generichash`'s own test file has no rejection/misuse category at all: it is a bare
re-export with zero new logic, so its only new, independently-testable fact is that the re-export
path itself resolves to the same `hazmat` behavior - a smoke test, not a gap.

**Provenance**: unchanged from each wrapped `hazmat` primitive - `crypto_generichash` inherits
`hazmat::kupyna`'s D-10 status, `crypto_auth` inherits `hazmat::kupyna_kmac`'s D-44 (dual-oracle,
not yet primary-text-confirmed), `crypto_kdf` inherits `hazmat::kupyna_kdf`'s D-45 (no oracle
vector exists for this construction at all, ever).

**Verification**: `cargo test --workspace --all-features` clean (new test files: 8/8 `crypto_auth`,
5/5 `crypto_kdf`, 2/2 `crypto_generichash`, all passed on first run - coverage additions, no bug
found, consistent with D-64/D-65's own observation that this is expected for new coverage over
already-correct code, not a red flag). `cargo clippy --workspace --all-features -- -D warnings` and
`cargo fmt --all -- --check` both clean (one fix needed along the way: `crypto_auth::auth()`
initially used `.expect(...)` on the `Kupyna256Kmac::mac` call to discharge the
type-signature-foreclosed `WrongKeyLength` case - `CLAUDE.md`'s `#![deny(clippy::expect_used)]`
rejects that crate-wide, same as `crypto_secretbox::seal` already had to route around via a
`let Ok(...) else { unreachable!(...) }` pattern instead; fixed the same way here). `cargo build -p
dstu-core --no-default-features`/`--features alloc`/`--features small-tables` all clean (see the
per-item `std`-gating section above for why this matters here specifically).

**Docs updated**: `docs/dstu-crypto-project.md` (mapping table rows for all three, plus the
"high-level easy layer" prose paragraph, which was stale - it still said "not built yet" despite
`crypto_sign`/`crypto_secretbox`/`crypto_pwhash` already existing), `docs/release-readiness.md`
(mapping table rows and the "no high-level wrapper" prose), `docs/TASKS.md` (roadmap Step 3 item 2
marked done, RESUME HERE section updated - including correcting its own stale "no commit has been
made yet" claim from before D-63/D-64/D-65/T-103/T-104 were actually committed).

**Addendum 2026-07-25 - roadmap Step 3 items 4 and 5 (no code change, documentation/confirmation
only)**:
- **Item 4 (KW stays `hazmat`-only)**: `docs/release-readiness.md`'s use-case table already stated
  this ("hazmat-only, libsodium has no direct equivalent to wrap at the high level"); the gap was
  that `docs/dstu-crypto-project.md`'s own canonical libsodium-mapping table (the one this
  documentation map names the actual owner of that mapping) had no `hazmat::kalyna_kw` row at all.
  Added one, explicit about *why* there's no wrapper: libsodium itself has no key-wrap primitive to
  map onto, so this is a documented gap in libsodium parity, not an oversight or a future
  `crypto_kw` waiting to be built.
- **Item 5 (`crypto_kx`/`crypto_box` stay hard-blocked)**: re-checked against `docs/ORACLES.md` and
  `docs/TASKS.md` T-46/T-47 rather than assumed unchanged - still zero DSTU 9041 source material
  (no paper, oracle, or pseudocode) anywhere this project has looked. Both
  `docs/dstu-crypto-project.md`'s and `docs/release-readiness.md`'s existing rows for these two
  already say so accurately; no doc changes needed, confirmation recorded here per this project's
  "confirmed, not assumed" convention rather than left as a silent no-op.

## D-67: `crypto_stream` high-level module (T-106) - roadmap Step 3 item 3

Unlike D-66's fork (Step 3 item 2), this roadmap step named its own open question explicitly in
`docs/TASKS.md`'s own text: "whether the IV is auto-generated (hidden from the caller, like
`crypto_secretbox`'s nonce) or stays explicit is its own fork, decided when this is actually picked
up." Put to the project owner directly via `AskUserQuestion` before writing any code, not decided
unilaterally the way D-66's fork was (a framing gap D-66 itself was called out for after the fact -
see this project's advisor-review discipline). **Chosen: hidden/internally-generated IV**, matching
`crypto_secretbox`'s own nonce precedent (D-51) - `hazmat::strumok`'s own module doc carries a
"never reuse the same key+IV pair" warning backed by a dedicated catastrophic-two-time-pad test
(`reusing_key_and_iv_leaks_plaintext_xor`, T-103), which weighed toward removing that footgun from
the caller's surface entirely, the same reasoning D-51 gave for secretbox's nonce.

**Shape**: `dstu_core::crypto_stream::{encrypt, decrypt, Key, StreamError}`, wrapping
`hazmat::strumok::Strumok256` only - the other variant (`Strumok512`) stays `hazmat`-only, matching
D-66's "delete the knob" precedent for `crypto_auth`/`crypto_kdf` (single 256-bit variant, not all
available sizes). `Key` is an opaque, `Zeroize`-on-drop 32-byte type (`generate()`/`from_bytes()`/
`as_bytes()`), same shape as D-66's `Key`/`MasterKey`. Wire format: `iv (32 bytes) || ciphertext
(plaintext.len() bytes)` - no tag, since Strumok is a bare keystream generator with nothing to
authenticate with.

**No authentication - and the naming says so on purpose.** `decrypt` never fails on tampered input:
there is no tag, so a modified `sealed` value produces different, silently-wrong plaintext instead
of an error - the same documented no-integrity-by-design property `hazmat::kalyna_xts` already has
(`tampered_ciphertext_does_not_error_but_produces_garbage`, T-93/D-58). This module's functions are
named `encrypt`/`decrypt`, **not** `seal`/`open` - `crypto_secretbox` reserves `seal`/`open`
specifically to signal "this authenticates" (an intentional naming distinction, not an
afterthought), and using the same verbs here for a primitive with zero tamper-evidence would blur
that signal for anyone skimming function names alone. The module doc's "No authentication" section
states this loudly and points callers needing integrity at `crypto_secretbox` (or a future
`crypto_secretstream`, T-40) instead.

**`std`-gating differs from D-66's three modules.** `encrypt`/`decrypt` return `Vec<u8>` (arbitrary
message length, same reason `crypto_secretbox` needs it) - unlike D-66's `crypto_generichash`/
`crypto_auth`/`crypto_kdf`, which only ever move fixed-size arrays and so could stay unconditional
with just `generate()` gated per-item, `crypto_stream` genuinely cannot avoid `Vec` at all, so the
*whole module* is `#[cfg(feature = "std")]`-gated in `lib.rs`, exactly matching `crypto_secretbox`'s
own precedent rather than D-66's per-item pattern. Confirmed, not assumed: `cargo build -p
dstu-core --no-default-features`/`--features alloc`/`--features small-tables` all build clean with
`crypto_stream` correctly absent from all three (it only appears in the `--all-features` /
default-`std` build).

**Tests** (`tests/crypto_stream.rs`) adapt `tests/crypto_secretbox.rs`'s own test shape for zero
authentication rather than reusing it verbatim: `round_trip`, `zero_length_plaintext_round_trips`,
`large_message_round_trips`, `two_calls_use_different_ivs`,
`truncated_input_is_rejected_not_a_panic`, `wire_format_is_iv_then_ciphertext`, and a
`round_trip_property` proptest all carry over directly. The tamper-*rejection* tests
(`crypto_secretbox`'s `wrong_key_is_rejected`/`tampered_*_is_rejected`) have no equivalent here -
there is no tag to make them meaningful - replaced with two tests pinning the *absence* of
rejection instead: `wrong_key_produces_different_plaintext_not_an_error` and
`tampered_ciphertext_does_not_error_but_produces_garbage`, matching `tests/kalyna_xts.rs`'s already-
established convention for the same documented property on a different primitive.

**Provenance**: unchanged from `hazmat::strumok`'s own D-18 status - UAPKI-attributed vectors, not
yet confirmed against the primary DSTU 8845:2019 text.

**Verification**: `cargo test -p dstu-core --all-features --test crypto_stream` - 9/9 passed on
first run (coverage over already-correct code, consistent with D-64/D-65/D-66's own observation
that this is expected, not a red flag). `cargo clippy --workspace --all-features -- -D warnings`
and `cargo fmt --all -- --check` both clean. `cargo doc -p dstu-core --no-deps --all-features` with
`RUSTDOCFLAGS="-D warnings"` - zero errors originating from `crypto_stream.rs` itself (several
pre-existing errors in unrelated `hazmat::kalyna_*` files exist independently of this change, out
of scope here - `rustdoc -D warnings` isn't yet part of this project's standing verification set).
`cargo build -p dstu-core --no-default-features`/`--features alloc`/`--features small-tables` all
clean. **Scoped Miri run - DONE, matching D-63's roadmap-mandated bar**: `MIRIFLAGS=
-Zmiri-disable-isolation PROPTEST_CASES=8 cargo +nightly miri test -p dstu-core --test
crypto_stream` - **9/9 passed, 0 UB, 119.85s**. First attempt omitted `MIRIFLAGS` and failed on
`round_trip_property` with `GetCurrentDirectoryW not available when isolation is enabled`
(proptest's failure-persistence `getcwd` call, the same class of Windows-Miri-isolation gap this
project has hit and documented repeatedly, e.g. T-102) - not a bug in this module, fixed by setting
the flag this project already uses everywhere else for exactly this reason. Full workspace `cargo
test --workspace --all-features` re-confirmed clean after `crypto_stream` landed (exit code 0,
every crate's suite passing, including the new `tests/crypto_stream.rs`).

**Docs updated**: `docs/dstu-crypto-project.md` (mapping table row, "high-level easy layer" prose),
`docs/release-readiness.md` (mapping table row, the "no high-level wrapper" prose, and the
"Streaming audio" use-case scenario row), `docs/TASKS.md` (roadmap Step 3 item 3 marked done, backlog
entry T-106 added, RESUME HERE section updated to record Step 3 as fully complete),
`CLAUDE.md`'s own running project-status paragraph.

## D-68: `crypto_secretstream` (T-40/T-70) - roadmap Step 5 item 1, a from-scratch chunked AEAD, and `uacrypt encrypt`/`decrypt` migrate to it

`crypto_secretbox`/`uacrypt encrypt`/`decrypt` (D-51, migrated to Kalyna-GCM by D-63) still read
`--in` whole into memory - an AEAD tag needs the full plaintext/ciphertext up front. T-40 (roadmap
Step 5's own explicit "T-40 first" ordering, user-approved 2026-07-25, advisor-reviewed) closes that
gap with a genuinely chunked construction. Own plan-mode pass taken first, per this roadmap's
standing convention for real feature work (unlike the packaging items in the same step).

**No DSTU citation - from scratch, D-47's tie-breaker rule applied.** No DSTU standard defines a
streaming/chunked AEAD mode. Followed libsodium's `crypto_secretstream_xchacha20poly1305` shape
(tag-per-chunk framing, `FINAL` tag whose absence signals truncation) over this crate's own
primitives instead of ChaCha20-Poly1305 - same posture `kupyna_kdf` (D-45) already established:
**no oracle vector exists for this construction, ever**, verification is property-test-only.

**Three forks put to the project owner directly** (D-66/D-67 precedent - decide explicitly, don't
pick silently), all resolved 2026-07-25 before writing any code:
- **Tag set**: chose the **full libsodium set** (`MESSAGE`/`PUSH`/`REKEY`/`FINAL`), not the
  minimal two-tag set recommended as the D-47-consistent default. `uacrypt encrypt`/`decrypt` itself
  only ever emits `MESSAGE`/`FINAL` (no sub-message boundaries or key-rotation need for one file),
  but the library implements and tests all four, since a future caller may need `PUSH`/`REKEY`.
- **API shape**: chose **caller-supplied `&mut [u8]` chunk buffers**, not `Vec`-returning - the
  `push`/`pull` step machinery is a stricter `no_std` fit than any other high-level `crypto_*`
  module's equivalent step (per-item `std` gating, only `PushState::init`'s header generation needs
  it, matching `crypto_auth`/`crypto_kdf`'s pattern rather than `crypto_stream`'s whole-module
  gate). **Correction, caught in review before this entry was finalized**: `PushState::init` is
  `PushState`'s *only* constructor, so under `no_std` a caller can build a `PullState` but has no
  way to start a new stream at all - the module is decrypt-only without `std` (D-09's "`hazmat`
  never generates its own randomness" reasoning, unchanged, but the module doc originally implied a
  more symmetric `no_std` story than the code actually has). An unconditional
  `PushState::from_header(key, header)` (caller supplies the header instead of it being drawn
  internally) would close this gap, but that's a scope question for the project owner, not
  something to build unilaterally under CLAUDE.md's "no speculative features" rule - flagged here,
  not shipped.
- **Scope**: chose **library and `uacrypt encrypt`/`decrypt` rewiring together**, not library-only -
  reasoning given: if a session ends partway through this step, the substantive item should already
  be fully landed end to end, not left as an unused library with the CLI still on the old primitive.

**Construction.** `PushState::init` draws a random 32-byte header and derives the stream's initial
subkey as `Kupyna256Kmac::mac(key = master_key, message = header)` - `hazmat::kupyna_kmac`'s `mac()`
takes an arbitrary-length message under a fixed 32-byte key, unlike `crypto_kdf`'s
`derive_subkey(subkey_id: u64, context: &[u8; 8])`, which can't absorb an arbitrary-length header
(confirmed by reading both signatures before designing, not assumed). This is the standing
nonce/IV-coverage rule (see D-63, and CLAUDE.md's "Crypto engineering hard constraints" section,
which names this construction by name as a case to re-check) applied at stream-setup time instead
of per-chunk AAD: since the subkey itself is a function of the header, a tampered header derives
the wrong subkey and the very first chunk's tag fails closed - confirmed by
`tampered_header_is_rejected` in `tests/crypto_secretstream.rs`, not just asserted in a doc comment.

Each chunk is encrypted with `hazmat::kalyna_gcm::Kalyna256_256Gcm` (same variant `crypto_secretbox`
already uses) under a 32-byte IV that is all-zero except its low 8 bytes, which hold a `u64` chunk
counter - monotonically increasing, tracked identically on both sides, **never transmitted, never
reset (including across a `Rekey`)**. The counter and the chunk's tag byte are passed together as
`kalyna_gcm`'s `aad` (`counter.to_le_bytes() || [tag_byte]`) - the same "bind out-of-band data into
the tag via AEAD's own AAD mechanism" pattern D-63 established for `crypto_secretbox`'s nonce.
Binding the counter into AAD, rather than trusting a transmitted position, is what defeats
reordering, interior chunk drops, and splicing a chunk from a different stream: a receiver always
verifies against *its own* expected counter, so anything not exactly next-in-sequence fails its tag
check; splicing from a different stream fails for a second, independent reason too (a different
random header derives a different subkey). Flipping the transmitted tag byte itself (e.g.
`Final`→`Message`, to hide truncation from a caller) is caught the same way - `pull()` uses the
wire-read `tag_byte` directly as part of the AAD it verifies, so a flipped byte changes the AAD and
fails the tag check before the wrong `Tag` is ever trusted or returned.

**`Rekey`**: `new_subkey = Kupyna256Kmac::mac(key = current_subkey, message = b"DSTU-secretstream-rekey")`
- one-way (KMAC), so a compromised later subkey doesn't recover earlier chunks' key (the
forward-secrecy property libsodium's own rekey exists for). Pinned by
`rekey_changes_the_subkey_and_old_subkey_no_longer_decrypts`, which checks both directions: a
correctly-tracking `PullState` decrypts chunks on both sides of the rekey, and a `PullState` that
never processed the `Rekey` chunk (still on the initial subkey/counter) fails to decrypt the
post-rekey chunk.

**`Final`**: marks the state finalized (`is_finalized()`); any further `push`/`pull` call on that
state errors. This is what makes truncation detectable - a caller reaching end-of-input without
ever having seen `Final` knows the stream was cut short. The check itself lives in the caller's I/O
loop (`is_finalized()` is the primitive this module provides for it), since only the caller knows
when its input is exhausted - `uacrypt decrypt` is the concrete example (see below).

**Placement**: `dstu_core::crypto_secretstream`, not a new `hazmat` module - a single fixed
composition (D-47 "delete the knob"), not a family of variants, matching `crypto_secretbox`'s
precedent (no separate `hazmat` layer) rather than `kupyna_kdf`'s (whose multi-variant family
needed one).

**Tests** (`tests/crypto_secretstream.rs`, 22 tests, all passed on first write - coverage over
already-correct code, consistent with D-64/D-65/D-66's own observation that this is expected, not a
red flag): round-trip (single chunk, zero-length final chunk, multi-chunk, `Push` boundary
reported back correctly), the rekey forward-secrecy pair above, and the full D-64/D-65 pass -
wrong key, tampered header/ciphertext/tag, flipped tag byte, dropped interior chunk, swapped
chunks, spliced chunk from a different stream, push/pull-after-`Final` rejected, all-zero key
round-trips (degenerate-but-legal), mismatched buffer lengths rejected, unknown tag byte rejected,
plus a `round_trip_property` proptest over random chunk counts/sizes/tag sequences.

**`uacrypt encrypt`/`decrypt` rewired** (`crates/uacrypt/src/lib.rs`) - `crypto_secretbox` itself is
**not removed or deprecated**, it stays a separate, still-tested library primitive (libsodium itself
keeps both APIs published side by side); only the CLI's `encrypt`/`decrypt` subcommands switch their
backing construction. New on-disk format: `header (32 bytes)` then repeated
`tag_byte (1) || chunk_len (4, LE u32) || ciphertext (chunk_len) || auth_tag (16)` records until a
`Final`-tagged record. `SECRETSTREAM_CHUNK_BYTES = 8 * 1024` matches `DIGEST_STREAM_CHUNK_BYTES`/
`STRUMOK_STREAM_CHUNK_BYTES` (D-42) - both `--in` reads and `--out` writes are now genuinely
chunked, on both `encrypt` and `decrypt`, unlike the old whole-buffer command.

**Breaking wire-format change, called out explicitly**: a file the old `crypto_secretbox`-backed
`encrypt` produced cannot be read by the new `decrypt`, and vice versa. Acceptable pre-1.0
(`README.md`'s pre-release banner) - a deliberate, recorded trade, not an oversight.

**Atomicity preserved under genuine streaming I/O**: the old command computed the whole output in
memory before one `std::fs::write`, so a failure never touched `--out` for free. Streaming write
can't get that for free - `run_secretstream_command` writes to `<out_path>.secretstream-tmp`
(`OsString` append, not `Path::with_extension`/`format!("{}", path.display())`, so it's correct
for both an already-extensioned `--out` and a non-UTF-8 path) and only `std::fs::rename`s it onto
the real `--out` after the whole stream verifies, deleting the temp file on every error path
instead - preserves D-65's "no partial output on failure" guarantee, now doing real work instead of
getting it for free from whole-buffer I/O. `--in`/`--out` same-path still round-trips
(`run_secretstream_command_in_and_out_same_path_round_trips`) because the input `File` handle is
fully read and out of scope before the rename runs.

**One CLI-layer hardening addition beyond the plan**: `decrypt`'s chunk-record parser rejects any
`chunk_len` field greater than `SECRETSTREAM_CHUNK_BYTES` before ever allocating a buffer for it
(`CliError::SecretstreamChunkTooLarge`) - a real `encrypt`-produced file never has a chunk longer
than that constant, so a larger value in untrusted `--in` is definitionally corrupted or hostile,
and allocating an attacker-controlled `Vec` sized directly off an unvalidated `u32` length field
would otherwise be a memory-exhaustion footgun parsing untrusted input. Exercised by
`run_secretstream_command_decrypt_rejects_never_sealed_garbage_without_writing_out`.

**New `CliError` variants** (`SecretstreamTruncated`/`SecretstreamVerifyFailed`/
`SecretstreamUnknownTag`/`SecretstreamTrailingData`/`SecretstreamChunkTooLarge`), each with distinct
`Display` text, matching this project's own precedent of not reusing another command's hardcoded
message (`PlaintextTooLong`/`CcmVerifyFailed` vs. `Truncated`/`SecretboxVerifyFailed`, before this
change). The old `CliError::Truncated`/`SecretboxVerifyFailed` variants and the
`From<SecretboxError>` impl backing them are removed outright, not left dormant - nothing produces
them once `encrypt`/`decrypt` no longer call `crypto_secretbox`, and this project's standing rule is
to delete unused code rather than leave backwards-compatibility scaffolding behind.

**CLI tests** (`crates/uacrypt/src/lib.rs`'s `tests` module) mirror the library's three categories at
the file-I/O level: round trip (single-chunk, multi-chunk spanning `SECRETSTREAM_CHUNK_BYTES * 3 +
777` bytes, and an empty file), tampered ciphertext / truncated stream / trailing-data-after-`Final`
all rejected with no `--out` written, wrong key length, nonexistent/directory `--in`, `--in`/`--out`
same-path, and never-`encrypt`-produced garbage input.

**Verification**: `cargo test -p dstu-core --all-features --test crypto_secretstream` - 22/22
passed. `cargo test -p uacrypt --all-features` - 48/48 passed (including the 16 rewritten/new
`secretstream`-named tests). `cargo test --workspace --all-features` - full suite green. `cargo
clippy --workspace --all-features -- -D warnings` and the `small-tables` variant both clean (one
real finding along the way: `clippy::doc_markdown` on an unbacktick'd "ChaCha20-Poly1305" in the
module doc, fixed inline - the exact trap CLAUDE.md's "Agent discipline" section already names).
`cargo fmt --all --check` clean. `cargo build -p dstu-core --no-default-features`/`--features
alloc`/`--features small-tables`/`--all-features` all build clean, confirming `crypto_secretstream`
compiles correctly across the feature matrix (per-item `std` gating, not a whole-module gate).
Scoped Miri (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8 cargo +nightly miri test -p
dstu-core --test crypto_secretstream`) - **22/22 passed, 0 UB, 1276.00s (~21.3 min)** - noticeably
slower than `crypto_secretbox`'s ~19 min (D-63), as expected for a multi-chunk construction with
more state per test (advisor flagged this ahead of time, `PROPTEST_CASES=8` was set from the
start rather than discovered the hard way). Full workspace `cargo test --workspace --all-features`
re-run after the `uacrypt` rewire landed - clean, every crate's suite passing. `round_trip_property`
widened, same review pass, to actually cover random tag sequences (`Push`/`Rekey` on non-final
chunks via a `non_final_tag` helper, not just `Message`), matching this entry's own "verified by
property test" claim precisely rather than leaving `Push`/`Rekey` covered only by their dedicated
unit tests. **The recorded Miri run above predates this widening** - it covers the file as it stood
before `round_trip_property` was broadened, not the broadened version; re-running Miri specifically
for that widening wasn't judged necessary, since `Push`/`Rekey`'s code paths were already exercised
under Miri via the dedicated `rekey_changes_the_subkey_and_old_subkey_no_longer_decrypts` unit test
in the same 22/22 run - the widening adds property-test *coverage breadth*, not a previously-
Miri-unchecked code path. Stated explicitly per this project's own D-25 lesson ("check what a test
actually exercised, not just whether it passes") rather than leaving a reader to assume the 1276.00s
figure reflects the post-widening test file.

**Fuzz coverage** (CLAUDE.md: "`cargo fuzz` ... a required layer, not optional tooling"; D-61's
precedent of extending coverage whenever a new attacker-input-parsing surface lands) - added
`fuzz_targets/crypto_secretstream.rs` (10th target, `fuzz/Cargo.toml` `[[bin]]` entry,
`.github/workflows/rust.yml`'s `fuzz-smoke` matrix). Exercises `PullState::pull` on fully
attacker-controlled `tag_byte`/ciphertext/tag/length combinations never produced by a real `push`
(the same "direct attack surface" pattern `kalyna_gcm`'s/`kalyna_kw`'s fuzz targets already use) as
well as a push/pull round trip with attacker-influenced tag sequences. Local smoke run (D-32's
documented MSVC-toolchain/`vcvars64` workflow, `x86_64-pc-windows-msvc` target) - **71,780 runs in
60s, zero crashes**. `uacrypt decrypt`'s CLI-layer `chunk_len`-vs-`SECRETSTREAM_CHUNK_BYTES` bound
(`CliError::SecretstreamChunkTooLarge`) is a sanity check the fuzzer's coverage complements, not
duplicates - the fuzz target exercises the library's own `pull()` directly, not the CLI's on-disk
framing parser.

**Two accuracy corrections made during review, before this entry was first committed** (not found
after the fact): the `no_std` claim above is now correctly scoped to the `push`/`pull` step
machinery, not the whole module (see the API-shape fork's correction note); and
`SecretstreamError::Random` is `#[cfg(feature = "std")]` on an otherwise-unconditional, non-
`#[non_exhaustive]` public enum - this crate's first module with that shape (`crypto_secretbox`/
`crypto_stream` are whole-module `std`-gated, so their error types never hit it). Cargo feature
unification is additive, so any dependency in a build graph enabling this crate's `std` feature
changes `SecretstreamError`'s variant count for every consumer of it, including ones that only
asked for the `no_std` surface. Not a problem pre-1.0, and not a reason to add `#[non_exhaustive]`
speculatively (CLAUDE.md's "no speculative features" rule) - recorded so a future consumer-facing
break doesn't get diagnosed from scratch.

**Docs updated**: `docs/TASKS.md` (T-40/T-70 marked done, Step 5 next-steps list updated), `CLAUDE.md`'s
own running project-status paragraph (both the `dstu-core` module list and the `uacrypt` bullet),
`docs/release-readiness.md` (every stale "not started"/"still open" T-40 mention across the
headline finding, the libsodium-mapping table, the use-case table, the bottom-line paragraph, the
CLI section, and the libsodium-audit section - all corrected to Done, not just the newest one
added), `docs/dstu-crypto-project.md` (the MVP-scope bullet, the original Strumok/Kalyna-CTR
planning sketch corrected in place with a note rather than silently rewritten, and the "Concrete API
shape" mapping table row), and `README.md` (the stale "no file-level encrypt/decrypt command exists
yet" opening note, and the `encrypt`/`decrypt` usage section's construction/wire-format description).
Missing this pass entirely on the first write of this entry - caught by `advisor()` review citing
CLAUDE.md's own doc map (`docs/release-readiness.md` owns "a new construction lands",
`docs/dstu-crypto-project.md` owns "scope or API-mapping decisions change") - is recorded here as a
process note: D-67 (the closest prior analogue, one item earlier in this same roadmap) listed both
files in its own "Docs updated" line and this entry originally didn't; don't repeat the omission.

## D-69: MSRV set to 1.87.0 (T-111) - the binding floor is this crate's own code, not a dependency

**Measured, not guessed** (`cargo metadata --format-version 1 --all-features --filter-platform
<target>`, both `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-gnu`, then real `cargo
+<toolchain> build` runs, per this file's standing "no primitive/claim from memory" discipline
applied to tooling claims too): the dependency graph's own declared floors top out at `1.85` (`zeroize` 1.9.0, `base64ct` 1.8.3 via
`argon2`'s `pwhash` feature, `getrandom` 0.4.3 pulled in transitively by `proptest`/`rand`) and
`1.86` (`criterion` 0.8.2 itself, plus `clap` 4.6.4 - not `uacrypt`'s CLI, which is hand-parsed;
`clap` is `criterion`'s own bench-harness dependency, confirmed via `Cargo.lock`'s `[[package]]`
entry for `criterion`, not assumed from the name alone). Both are dev-dependency-only, not reached
by a bare `cargo build --workspace`. None of those are the real constraint.

**The actual floor is `dstu_core`'s own use of `u64::is_multiple_of`/`usize::is_multiple_of`**
(`unsigned_is_multiple_of`, rust-lang/rust#128101), used unconditionally (not behind any feature
gate) in `hazmat::kalyna_kw`, `hazmat::kalyna_cbc`, `hazmat::kalyna_ecb`, `hazmat::kalyna_ccm`, and
across most of the `tests/` suite. Confirmed by bisection with real toolchains, not inferred from
the tracking issue number alone: `cargo +1.86.0-x86_64-pc-windows-msvc build --workspace --target
x86_64-pc-windows-msvc` fails with `E0658: use of unstable library feature
'unsigned_is_multiple_of'` (31 errors, all at `is_multiple_of` call sites); `cargo
+1.87.0-x86_64-pc-windows-msvc build --workspace --all-features` and `cargo
+1.87.0-x86_64-pc-windows-msvc test --workspace --all-features --no-run` (compiles every test
binary, including `--all-features`) both succeed. `--no-default-features` and
`--no-default-features --features small-tables` also confirmed clean at 1.87 - moot for this
specific floor since the triggering calls aren't feature-gated, but checked anyway rather than
assumed, matching D-39/D-41/D-62's own precedent for a new build-matrix claim.

**Toolchain note, specific to this dev machine, not a project-wide finding**: `1.85.0`/`1.86.0`
under the `-x86_64-pc-windows-gnu` host triple failed at the link step (`dlltool.exe` not found)
even with the `rust-mingw` component installed - a self-contained-linker default that changed
between this machine's `stable` (1.97.1) and these older releases, unrelated to this crate's own
code. Worked around by installing the `-x86_64-pc-windows-msvc` variant of each candidate instead
(this machine already has Visual Studio/`link.exe, per D-32's Miri/fuzz precedent) and building
with `--target x86_64-pc-windows-msvc` explicitly. Not a `no_std`/portability regression - CI
verifies the real MSRV floor on `ubuntu-latest`, where this quirk doesn't apply.

**Declared**: `rust-version = "1.87.0"` added to both `crates/dstu-core/Cargo.toml` and
`crates/uacrypt/Cargo.toml`. Scope is build + `cargo test` (confirmed both) + `cargo bench`
(`criterion` 0.8.2's own floor is `1.86`, already below `1.87`, so it's covered without being the
binding case). New CI
job (`.github/workflows/rust.yml`) pins `dtolnay/rust-toolchain@1.87.0` and runs `cargo +1.87.0
build --workspace --all-features` plus the `--no-default-features` counterpart, on
`ubuntu-latest`, separate from the main `test` job - build-only, deliberately not running `clippy`
at MSRV (an older `clippy` fires lints the pinned-`stable` job's newer `clippy` doesn't, and this
project has no intention of satisfying two `clippy` versions in perpetuity) and not running the
full test suite at MSRV in CI (already confirmed locally that it compiles; re-running it on every
push doubles CI time for a floor that `rust-toolchain.toml`'s `stable` pin already exercises at a
newer version every push anyway).

**Why this is a `docs/DECISIONS.md` entry and not packaging hygiene like T-107/T-109/T-110/T-112**: the
measurement was genuinely surprising - a naive "check `cargo metadata` for the highest declared
`rust_version`" pass would have landed on `1.85` or `1.86` and silently shipped an MSRV that broke
on this crate's own code, not a dependency's. `is_multiple_of` was not chosen deliberately for its
stabilization version; it was written as ordinary idiomatic Rust without checking against an MSRV
target, since no MSRV had been declared yet at the time. Left as-is rather than rewritten to
`% ... == 0` to artificially lower the number to `1.85` - T-111's stated scope is "pick and record
an actual MSRV," not "minimize it," and a two-version gap from the dependency floor doesn't justify
churning five call sites for a crate that isn't published yet.

**`docs/CHANGELOG.md` (Keep a Changelog format) added** - first version of the file, `0.1.0` is
unreleased so there is one `## [Unreleased]` section (Added/Changed), not a reconstructed
per-commit history.

## D-70: `crypto_sign::sign_digest`/`verify_digest` (T-113) - the advisor's flag confirmed, collapsed to a small addition

**Checked the primary text first, per this file's own standing "no primitive/estimate from memory"
rule, before scheduling T-113 as real feature work.** `docs/pseudocode/dstu4145.md` §5.9/§9/§10 is
unambiguous: DSTU 4145 signs `h ← hash_to_field(H(T))` - a hash of the message, computed once and
consumed as a single field element - not a domain-separated multi-part construction the way
Ed25519ph is. The advisor's hypothesis (raised when this roadmap item was scoped) held: there is no
"streaming signer" to design, only a need to let the hash itself be computed incrementally instead
of requiring the whole message in memory for one `Kupyna256::digest` call.

**Shape**: `SigningKey::sign_digest(&self, digest: &[u8; 32]) -> Signature` and
`VerifyingKey::verify_digest(&self, digest: &[u8; 32], sig: &Signature) -> bool` added to
`dstu_core::crypto_sign`, taking an already-computed Kupyna-256 digest directly. `sign`/`verify` are
now thin wrappers (`self.sign_digest(&Kupyna256::digest(message))` /
`self.verify_digest(&Kupyna256::digest(message), sig)`) - no behavior change for existing callers,
confirmed by a same-message equivalence test (`sign_digest_matches_sign_on_the_same_message`). A
caller with a large or streamed message now hashes it themselves via the already-existing
`hazmat::kupyna::Kupyna256Hasher::{new, update, finalize}` (already `no_std`-compatible, bounded
memory regardless of message size, T-83) and passes the resulting digest straight in - nothing new
needed at the hashing layer, only at this wrapper's entry points.

**Tests added** (`tests/crypto_sign.rs`): correctness (`sign_digest` matches `sign` on the same
message; a digest produced by streaming `Kupyna256Hasher` in two chunks matches the one-shot
`Kupyna256::digest` and round-trips through `sign_digest`/`verify_digest`) and rejection
(`verify_digest_rejects_tampered_digest`). One real gotcha hit writing the rejection test: the first
attempt flipped `digest[0]`, which passed verification unchanged - not a bug, but `hash_to_field`
(§5.9, see the docstring in `docs/pseudocode/dstu4145.md`) only consumes the digest's own **last**
21 bytes, so a byte outside that window is provably inert. Fixed by flipping `digest[31]` instead,
with a comment explaining why the byte position matters here (a case this project's own "check what
a fixed vector actually exercises" discipline generalizes to: check what a *tamper* actually
exercises, not just whether the assertion is phrased correctly).

**No new Miri run** - `sign_digest`/`verify_digest` reuse the exact same `signature::sign`/`verify`
and `Point::scalar_multiply` calls the original `sign`/`verify` already made; the new tests are
`#[cfg_attr(miri, ignore)]` for the same reason every other `crypto_sign` test already is (the
163-iteration EC ladder, T-100), so a Miri run would exercise zero new code paths, not skipped
verification.

**Verified**: `cargo test --workspace --all-features` (dstu-core's `crypto_sign.rs`: 12/12,
including the 3 new tests; full workspace: all green), `cargo clippy --workspace --all-features -- -D
warnings` clean, `cargo fmt --all -- --check` clean, `cargo build -p dstu-core --no-default-features`
clean (`crypto_sign` is an unconditional module, confirming this addition didn't accidentally
introduce a `std`/`alloc` requirement).

## D-71: Five new `uacrypt` benchmark CLI commands (GCM/CMAC/GMAC/KW/XTS) for an expanded UAPKI comparison - T-121

User requested an updated, expanded binary-level performance comparison against UAPKI
(`docs/PERFORMANCE.md`, canonical since D-34), with the explicit choice (via `AskUserQuestion`) to add
real CLI exposure for the five DSTU 7624 modes that had none at all - GCM, CMAC, KW, GMAC, XTS -
over the narrower option of just re-measuring the existing four commands' coverage.

**Same precedent as D-31 exactly**: these are `hazmat`-scoped benchmarking/interop tools, not the
safe, misuse-resistant top-level `encrypt`/`decrypt`/`hash` surface (T-16, D-52) - explicit
variant/key/nonce/tag as separate files, no hidden defaults, named `kalyna-gcm`/`kalyna-cmac`/
`kalyna-gmac`/`kalyna-kw`/`kalyna-xts` rather than anything that could be mistaken for the reserved
top-level names. `kalyna-ccm` (pre-existing, D-41) also gained `--iterations` in this same session -
it had none before, so its own per-op cost was previously unmeasurable through the binary at all,
an oversight this task closed as a byproduct of needing it for GCM's own comparable benchmark.

**Shapes, one per mode, matching each `hazmat` module's real API** (checked by reading each module
directly, not assumed from `kalyna-ccm`'s shape):

- `kalyna-gcm encrypt/decrypt` - same file interface as `kalyna-ccm` (`--variant --key --nonce --aad
  --in --out --tag --iterations`), tag always the variant's full block length (no `--tag-len` knob -
  D-47's "delete the knob", same call `crypto_secretbox` made for its own fixed-length tag).
- `kalyna-cmac compute/verify` - MAC-only, no encryption: `compute --out <tag>` /
  `verify --tag <path>`. Tag is always 16 bytes (`hazmat::kalyna_cmac`'s own fixed `q`, D-54).
- `kalyna-gmac compute/verify` - same shape as `kalyna-cmac`, but **no `--nonce` flag** - checked by
  reading `hazmat::kalyna_gmac` directly rather than assumed from GCM's shape (a wrong assumption
  caught before writing any code): `mac`/`verify` take no IV at all, unlike GCM. Tag is the
  variant's full block length, same as GCM's.
- `kalyna-kw wrap/unwrap` - `--variant --key --in --out`, no `--iterations`-adjacent flags beyond
  that. `--in` must be block-aligned (1..=20 blocks for `wrap`, `hazmat::kalyna_kw`'s own `MAX_R`
  bound).
- `kalyna-xts encrypt/decrypt` - `--variant --key --tweak --in --out`. `--tweak` is one block's
  worth of bytes (the "data unit" tweak seed `hazmat::kalyna_xts::encrypt_in_place`'s `iv` parameter
  actually takes) - **not** a sector index this CLI derives on the caller's behalf; the help text
  says so explicitly so a caller encodes their own sector index into a block-length buffer
  themselves if that's their use case.

**`run()`'s dispatch match arm was split into a new `dispatch_kalyna_mode` helper** purely to stay
under `clippy::pedantic`'s `too_many_lines` lint (100-line default) once five more command arms were
added - `cmd`/`rest` passed through unchanged, no behavior change, just a mechanical extraction
(caught immediately by `cargo clippy --workspace --all-features -- -D warnings`, fixed before
writing any tests).

**Test coverage, proportionate per `CLAUDE.md`'s three-category rule**: these are thin CLI wrappers
over already-vector-verified `hazmat` primitives (Kalyna itself is the primitive under test; GCM/
CMAC/GMAC/KW/XTS are already dual-oracle-verified modes of operation, D-56/D-54/D-57/D-55), so
correctness here means a round-trip through the CLI matches a direct `hazmat` call, not a fresh
vector derivation. Rejection (D-64) wherever a tag/checksum exists to tamper (GCM tag, CMAC/GMAC
tag, KW's checksum block). **XTS has no rejection category by design** - confidentiality-only mode,
no tag at all (`hazmat::kalyna_xts`'s own module doc comment: this is the correct, standard design
for disk-sector encryption, not a gap) - recorded as a finding via the one misuse test that *is*
reachable (input shorter than one block), not padded out with a vacuous test. Misuse (D-65):
wrong-length key, missing `--tag`/`--out` depending on subcommand, non-block-aligned KW input. 17
new tests total (64 -> 81), all green on first write - expected for coverage of already-correct code
paths, not a test-first violation (same framing D-64/D-65's own original session used).

**UAPKI comparison - faster path found than `docs/PERFORMANCE.md`'s documented CMake build**: the
official `specinfo-ua/UAPKI` GitHub repo publishes a signed prebuilt Windows `uapkic.dll`
(`v2.0.12`), confirmed via `gh api repos/specinfo-ua/UAPKI/releases` and `objdump -p` (exports every
symbol needed, only depends on `KERNEL32`/`ADVAPI32` - no VC++ redistributable). `gendef`+`dlltool`
(already on this machine, part of the WinLibs MinGW install, `.claude.local.md`) generates a plain
import lib, so a one-off C wrapper links against it with bare `gcc` - no CMake, no `resource.rc`
UTF-16/`windres` workaround needed at all. This supersedes `docs/PERFORMANCE.md`'s CMake recipe as the
faster local path on this machine; the CMake path remains documented there for anyone without a
prebuilt-binary option (e.g. CI, a different OS/arch).

**Two real UAPKI-side findings from cross-checking the wrapper byte-for-byte against the real
`uacrypt` release binary before any timing run** (same discipline D-31 established - "all three
cross-checked to produce byte-identical ciphertext/plaintext... before any timing run"), both found
by reading `oracles/uapki/library/uapkic/src/dstu7624.c` directly, not assumed:

1. **GMAC**: UAPKI's own generic `dstu7624_update_mac`/`dstu7624_final_mac` streaming path
   disagrees with itself on multi-block input given in one call - this is **not a new bug**, it's
   `docs/DECISIONS.md` D-57's already-documented finding (the same stale-index bug in `gmac_update` that
   `hazmat::kalyna_gmac` was deliberately ported from `encrypt_gmac` to avoid), re-confirmed
   empirically here for the first time against a real byte-for-byte comparison rather than only
   hand-traced. Worked around for the benchmark by using exactly one block of input, which the
   buggy path handles correctly (the bug only manifests across a block boundary within one call) -
   a clean timing number, not a correctness claim about UAPKI's multi-block GMAC.
2. **CCM wire format differs from ours**: `dstu7624_encrypt_ccm`'s `cipher_data` output is
   `ciphertext || CTR-encrypted(tag)` concatenated into one buffer (`ba_join(pdata_buf_part,
   h_part)` in the source) - not a same-length ciphertext with the tag returned separately, the
   convention `hazmat::kalyna_ccm::seal_in_place`/this project's own `kalyna-ccm` CLI both use. Not
   a bug on either side, just a different framing choice neither `docs/DECISIONS.md` D-41 nor D-55's
   citation work had previously had reason to compare at this level of detail. Consequence for this
   session: CCM's timing number is UAPKI-self-consistent (its own encrypt round-trips through its
   own decrypt) rather than cross-tool byte-verified the way the other eight compared modes are -
   correctness of *our* CCM implementation is unaffected (already dual-oracle-verified, D-41), this
   only affects what this particular ad hoc benchmark wrapper could verify about UAPKI's side.
   Also found in the same reading pass: `dstu7624_init_ccm`'s `n_max` parameter is not literally
   "the message's bit length" despite the header doc's phrasing - it's a small, mostly
   message-length-independent protocol constant (confirmed against UAPKI's own
   `dstu7624_ccm_self_test` vectors: `n_max=32` for every `q=16` case regardless of whether the
   plaintext was 15 or 133 bytes) - the wrapper hardcodes `n_max` from `q` alone (32/48/64 for
   `q=16/32/64`) rather than deriving it from the actual message length, matching those vectors'
   own pattern.

Separately, `key_wrap_dstu7624`/`key_unwrap_dstu7624` (exported by the DLL, initially assumed to be
the UAPKI equivalent of `hazmat::kalyna_kw`) turned out to be a **different construction entirely**
on inspection of `keywrap.c`: a CMS-style key-wrap per a separate technical specification
(RFC 5652-adjacent, per its own doc comment), with a hardcoded 32-byte block size and its own
internal CMAC+CFB framing plus a fixed IV - not the raw DSTU 7624 mode-of-operation #10 this
project's `hazmat::kalyna_kw` implements. The correct comparison point is `dstu7624_init_kw` +
`dstu7624_encrypt`/`decrypt` (the same `encrypt_kw`/`decrypt_kw` functions D-55 already cites) -
used instead, and cross-checked byte-identical against `uacrypt kalyna-kw wrap`.

**Results**: full new tables in `docs/PERFORMANCE.md`'s "Binary-level (process) comparison" section,
dated 2026-07-26. All 5 Kalyna variants now covered for block/CCM/GCM (previously only 2); new GCM/
CMAC/GMAC/KW/XTS subsections; larger message sizes (1 MiB) added alongside the existing 64 B/1 KB/
64 KB points for Kupyna/Strumok/CMAC/GCM. This dev machine only (Ryzen 5 PRO 4650U) - the Raspberry
Pi rig was out of scope for this pass.

**Real finding, not assumed**: Kalyna-XTS on the 512-512 variant specifically runs 4-4.6x *slower*
in this project's own implementation than in UAPKI's (e.g. 4096 B sector: 492481 ns vs. 107118 ns) -
a much wider gap than any other variant or mode measured in this session (most are within 2x either
direction, and several beat UAPKI outright). Not root-caused here - flagged for a follow-up
investigation, not a regression introduced by this session's own changes (XTS itself, `hazmat::
kalyna_xts`, was not touched - only a new CLI wrapper was added around the existing, already-tested
implementation).

**Verified**: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-features -- -D
warnings`, `cargo test --workspace --all-features` (81/81 `uacrypt` tests, full `dstu-core` suite
unaffected since no `hazmat` code changed), `cargo build -p dstu-core --no-default-features` all
clean. Manually smoke-tested every new command against the real release binary before writing
formal tests (GCM/CMAC/GMAC/KW/XTS round-trips, all correct).

## D-72: `crypto_sign::SigningKey::generate()` - keypair generation via rejection sampling, not modulo reduction - T-122

`docs/release-readiness.md`'s 2026-07-26 libsodium-API-surface re-audit found `crypto_sign` had no
`crypto_sign_keypair()` equivalent at all: `SigningKey::from_bytes` only *validates* a caller-supplied
`d`, so nothing could obtain a working signing key through the public API cold (same class of gap
T-115 closed for `crypto_secretstream::Key`, `uacrypt keygen`). `docs/TASKS.md` T-122's own scope text
left the shape as an explicit fork ("`generate()` or a `from_seed`-style deterministic variant,
project owner's call") - resolved here by implementation, not a prior user decision (same posture
D-66 flagged for its own fork, D-67's addendum): plain OS-CSPRNG `generate()`, matching every other
`crypto_*` module's own convention with no exception so far (`crypto_secretbox`/`crypto_auth`/
`crypto_kdf`/`crypto_stream`/`crypto_secretstream` all draw fresh key material from
`crate::randombytes` rather than a caller-supplied seed) - flag for confirmation if that reasoning
doesn't hold.

**Rejection sampling, not `reduce_wide_bytes`-style modulo reduction**: `hazmat::dstu4145::scalar::
Scalar::reduce_wide_bytes` already exists and would have been the one-line-shorter way to fold random
bytes into a valid scalar, but T-122's own scope text called that out by name as the wrong tool here -
folding a wide, uniformly-random value mod `n` biases small residues whenever `n` isn't a power of two
(it isn't: `curve163::order()`'s top byte is `0x04`). `reduce_wide_bytes`'s existing callers
(`crypto_sign`'s own nonce derivation) fold a 256-bit KMAC output mod a ~163-bit `n` - a ratio so wide
the bias is cryptographically negligible there, but keypair generation is exactly the case a citable
reference (FIPS 186-4's own extra-bits-then-reduce guidance is for *that* wide-ratio case, not a
same-order-of-magnitude candidate) would flag as the wrong shape for a bare 21-byte candidate. Real
rejection sampling instead: draw 21 fresh bytes, mask the top byte to its low 3 bits (`0x07`) since
`n` occupies 163 of the top byte's 168 available bits (21 bytes = 168 bits; top byte `0x04` = binary
`00000100`, highest set bit at position 2, so the value occupies bits 0..=162 - 163 bits total,
matching the curve's own `m=163` name) - keeps the average rejection rate near 50% instead of over
90% for an unmasked 168-bit draw, then retry on a masked candidate that's still `>= n` or `== 0`.

**The comparison itself goes through a new constant-time primitive, not a branching `>=`** - the new
`pub(crate) Scalar::from_candidate_bytes` (`hazmat/dstu4145/scalar.rs`), which reuses the module's
own `sub3` subtract-with-borrow primitive (already used throughout for secret scalar arithmetic) to
test `candidate < n` via the borrow flag, rather than a lexicographic byte-array `>=` the way the
*pre-existing* `SigningKey::from_bytes` does it (left unchanged - out of this task's scope, and a
much smaller information leak there since it validates a caller-supplied `d` against a public
constant, not a rejection-sampling loop iterating over many candidates). `T-122`'s own text asked
for exactly this: "the `subtle`/constant-time discipline `docs/SECURITY.md` already requires elsewhere
should apply to the rejection loop too, not just the final scalar use." The loop's *iteration count*
still varies with the candidate (unavoidable in any rejection-sampling scheme, standard practice
across EC libraries doing the same thing for non-power-of-two group orders), but evaluating any one
candidate does not branch on its value beyond that.

**`#[cfg(feature = "std")]`-gated**, same per-item convention as `crypto_auth`/`crypto_kdf`/
`crypto_stream`/`crypto_secretstream`'s own `Key::generate` (D-66/D-67/D-68) - needs
`crate::randombytes`, which needs `getrandom`. `Scalar::from_candidate_bytes` itself is also
`#[cfg(feature = "std")]`-gated (its only caller needs `std`) rather than left unconditional and
unused under a bare `no_std` build - caught by the `--no-default-features` build itself producing a
`dead_code` warning on the first pass, fixed before this was called done, not left as a known
warning.

**Test coverage**: correctness - `generate_produces_a_key_that_signs_and_verifies` runs 20 fresh
generations (a single success can't distinguish "always works" from "got lucky this run" the way a
fixed vector would, since `generate` has no oracle vector - same posture as `crypto_kdf`, D-45).
Distinctness - `two_calls_to_generate_produce_different_keys`, compared via the public `Q = -d*G`
(`SigningKey` exposes no byte accessor for `d` itself, by design - `Drop` zeroizes it), same
convention as `crypto_secretbox`/`crypto_stream`'s own `two_calls_use_different_nonces`/
`two_calls_use_different_ivs`. Five new unit tests for `Scalar::from_candidate_bytes` directly
(`scalar.rs`'s own `#[cfg(test)]` module, following `hazmat::kalyna`/`kupyna`'s existing in-file-test
precedent rather than `tests/`, since the function is `pub(crate)` and unreachable from an
integration test): rejects zero, rejects `n` itself, rejects a value one above `n`, accepts `n - 1`,
accepts `1` - the boundary cases a rejection-sampling comparison actually needs to get right.
**Misuse coverage foreclosed by the type signature**: `generate()` takes no arguments, so there is no
reachable misuse surface beyond what its signature already forecloses - recorded here rather than
padded out with a vacuous test, per `CLAUDE.md`'s own documented convention for this exact case.

**Verified**: `cargo test -p dstu-core --lib` (39/39, includes the 5 new `Scalar` unit tests),
`cargo test -p dstu-core --all-features --test crypto_sign` (14/14), full `cargo test --workspace`,
`cargo clippy --workspace -- -D warnings` / `--features dstu-core/small-tables` / `--all-features`
(all three clean), `cargo fmt --all -- --check`, and the four-combination `dstu-core` build matrix
(`--no-default-features`, `+alloc`, `+small-tables`, `--all-features`) all clean with zero warnings.

## D-73: `uacrypt sign-keygen`/`sign-pubkey`/`sign`/`verify` - a libsodium-shaped CLI over `crypto_sign` - T-124

`docs/release-readiness.md`'s 2026-07-26 re-audit found `uacrypt` had `crypto_sign` (T-48/D-46)
built as a library API but no CLI surface for it at all - confirmed by `grep` across the command
dispatch, no `sign`/`verify` arm anywhere. `docs/TASKS.md` T-124's own scope text named only `sign`/
`verify` (plus flagged the signing-key file format as an explicit open fork: "raw 21-byte scalar
vs. something else... project owner's call").

**Scope widened beyond the literal task text - resolved by implementation, flagged for
confirmation, not a prior user decision** (same posture D-72/D-66's own forks took for their own
session): `sign`/`verify` alone would have had no CLI path to obtain key material at all - a
signing key can't reuse `keygen`'s 32-byte symmetric-key format (a 21-byte scalar has a real
validity constraint, `1 <= d < n`, that 32 arbitrary CSPRNG bytes don't satisfy). This is exactly
the class of gap T-115 already closed once for `encrypt`/`decrypt` (`uacrypt keygen`) - shipping
`sign`/`verify` without an equivalent would recreate that same journey-blocking gap for the new
feature on day one. Two new commands added: `sign-keygen` (fresh signing key via
`SigningKey::generate`, T-122/D-72) and `sign-pubkey` (derives the matching verifying key via
`verifying_key()`). **Not a `--type` flag on the existing `keygen` command** - a flag choosing
between two incompatible key shapes (32-byte symmetric vs. 21-byte signing scalar) is exactly the
kind of knob D-47's "delete the knob" criterion exists to avoid; a typo'd flag value pointing
`keygen` at the wrong algorithm is a real misuse class a separate command can't have.

**Key/signature file formats - the fork T-124 named explicitly**: raw fixed-length bytes
throughout, no envelope/PEM/DER - matching every other key or signature file already in this
project (32-byte `crypto_secretstream`/`crypto_stream` keys, 42-byte `VerifyingKey` encoding that
already existed). `sign-keygen`/`sign --key` is the raw 21-byte big-endian private scalar;
`sign-pubkey --out`/`verify --key` is the raw 42-byte uncompressed `x || y` encoding
(`VerifyingKey::to_uncompressed_bytes`, pre-existing); `sign --out`/`verify --sig` is the raw
42-byte `r || s` signature (`Signature::to_bytes`, pre-existing). `SigningKey` had no byte
accessor at all before this - `SigningKey::to_bytes()` added to `dstu-core`'s `crypto_sign.rs`
(returns `self.0.to_be_bytes()`, the caller becomes responsible for zeroizing the returned array,
same convention `Scalar::to_be_bytes`/`VerifyingKey::to_uncompressed_bytes` already have) purely so
`sign-keygen` has something to write to disk.

**`sign`/`verify` stream `--in`, they don't load it whole**: both call the new `hash_file_streamed`
helper (8 KiB chunks through `Kupyna256Hasher`, exactly `kupyna-digest`/`hash`'s own D-42
convention) and then `SigningKey::sign_digest`/`VerifyingKey::verify_digest` (T-113) - not
`SigningKey::sign`/`VerifyingKey::verify`'s whole-message convenience wrappers, which would defeat
the point of T-113 existing. Peak memory for `sign`/`verify` stays bounded regardless of `--in`'s
size, matching `encrypt`/`decrypt`/`hash`'s own existing memory-boundedness claim.

**`verify` succeeds silently** (`Ok(())`, exit 0, nothing printed or written) on a valid signature
- matching `kalyna-cmac verify`/`kalyna-gmac verify`'s own convention, not `decrypt`'s (which writes
plaintext on success): there is nothing for `verify` to produce beyond a yes/no answer, and a
Unix-style silent-success/loud-failure convention is more predictable for scripting than inventing
new stdout output.

**`run()`'s four new match arms split into `dispatch_sign_command`** - the exact same
`clippy::pedantic` `too_many_lines` lint D-71 already hit for `dispatch_kalyna_mode`, caught
immediately by `cargo clippy` before writing any tests.

**Test coverage, `CLAUDE.md`'s three-category rule**: correctness - a full CLI-level golden path
(`sign-keygen` → `sign-pubkey` → `sign` → `verify`, all through the real command functions) plus a
cross-check against calling `dstu_core::crypto_sign::SigningKey::sign` directly. Rejection (D-64) -
tampered message, tampered signature (flipped low bit of `s`), and a signature verified against the
wrong verifying key, all three must fail `verify` (matching T-120's own explicit "show the failure
path too" requirement for sign/verify examples). Misuse (D-65) - wrong-length signing/verifying
key/signature files, a zero-scalar key that's the *right length but not a valid private key* (a
distinct case `SignKeyInvalid` reports, separate from `WrongLength`), a nonexistent `--in`, and
`--out` naming a directory for both new keygen-family commands.

**Two test-setup bugs found and fixed while running the new tests, not real code bugs**: two
misuse tests used `[0x11u8; 21]` as a "some valid signing key, don't care which" fixture - but that
isn't actually a valid scalar (`d >= n`, since `n`'s top byte is `0x04` and `0x11 > 0x04`), so
`SigningKey::from_bytes` correctly rejected it with `SignKeyInvalid` instead of the test's expected
`Io`/directory error. Caught immediately by running the tests (both failed on first write) rather
than assumed passing - fixed with a `small_signing_key(low_byte)` test helper (mirrors
`dstu-core`'s own `tests/crypto_sign.rs::small_scalar`), not by loosening the assertion.

**Verified**: full `cargo test --workspace` (110/110 `uacrypt` tests, up from 81; full `dstu-core`
suite unaffected - no `hazmat` code changed beyond `crypto_sign::SigningKey::to_bytes`), `cargo
clippy --workspace -- -D warnings` / `--features dstu-core/small-tables` / `--all-features` (all
three clean), `cargo fmt --all -- --check`, and the `dstu-core` build matrix
(`--no-default-features`/`+alloc`/`--all-features`) all clean.

## D-74: A new `getrandom` Cargo feature makes `randombytes` reachable on `no_std` - capability parity with `randombytes_set_implementation()`, not mechanism parity - T-123

`docs/release-readiness.md`'s 2026-07-26 re-audit found `dstu_core::randombytes::randombytes_buf`
(and every `Key::generate`/`SigningKey::generate` built on it) unconditionally `std`-gated - correct
per D-04's addendum (unconditionally pulling `getrandom` into a bare `no_std` build would break
compilation for every embedded consumer who never calls the function that needed it), but it also
meant there was no tracked path *at all* for a real embedded caller (STM32/ESP32, Phase 4) to get
fresh key/nonce material through this crate, once one actually needs to - libsodium's own
`randombytes_set_implementation()`/`advanced/custom_rng.md` exists specifically for this case.

**Researched before designing anything** (`CLAUDE.md`'s "no primitive/infra decision from memory"
rule applies here too, not just cryptographic primitives) - `advisor()` consulted before touching
`Cargo.toml`, per this project's standing "own plan-mode pass before an architectural fork" practice
(D-67/D-68's precedent). Read `getrandom 0.3.4`'s actual vendored source
(`~/.cargo/registry/.../getrandom-0.3.4/src/backends/custom.rs`, `Cargo.toml`) rather than recalling
its API from memory: backend selection is controlled by a `getrandom_backend` `--cfg` flag (set via
`RUSTFLAGS` or `.cargo/config.toml`'s `rustflags`, by the **final binary crate**, never by a library
dependency), not a Cargo feature `getrandom` itself exposes. The `custom` backend specifically
requires the final binary to define `extern "Rust" fn __getrandom_v03_custom(dest, len) -> Result<(),
Error>`, resolved at **link time**, not registered at runtime.

**Decision: capability parity with libsodium's `randombytes_set_implementation()`, not mechanism
parity.** `getrandom` 0.3's backend system already *is* the pluggable-RNG mechanism libsodium's
setter plays the same role for - building a second, `dstu-core`-owned runtime-pluggable
registry (a `static`/`AtomicPtr` function-pointer slot) on top would duplicate an already-established
upstream primitive, the exact class of homegrown-RNG-adjacent risk D-03/D-04 already rejected once
for the RNG itself, and would add global mutable state plus an init-order footgun ("what does
`randombytes_buf` do if nothing was registered yet?") - a misuse surface D-47's "delete the knob"
criterion says to remove, not add. `advisor()`'s explicit recommendation, taken as-is rather than
independently re-litigated: don't build the registry, don't spend an `AskUserQuestion` on it.

**Mechanism**: a new Cargo feature `getrandom = ["dep:getrandom"]`, and `std = ["getrandom"]` (was
`std = ["dep:getrandom"]`) - `getrandom` is the narrower half of what `std` already enabled,
independent of it, so a `no_std` build can opt into RNG capability without opting into `std`/`alloc`
at all. `#![cfg_attr(not(feature = "std"), no_std)]` in `lib.rs` is unaffected - the crate stays
`#![no_std]` under `getrandom` alone, exactly the shape an embedded consumer needs. Every site whose
only reason for being `#[cfg(feature = "std")]`-gated was "needs `crate::randombytes`" widened to
`#[cfg(any(feature = "std", feature = "getrandom"))]`, enumerated deliberately (per `advisor()`'s
explicit list) rather than trusting a global find-replace: `lib.rs`'s `pub mod randombytes`;
`crypto_sign::SigningKey::generate` (T-122) and its `hazmat::dstu4145::scalar::Scalar::
from_candidate_bytes` helper; `crypto_auth::Key::generate`; `crypto_kdf::Key::generate`;
`crypto_secretstream::Key::generate` **and** `PushState::init` (two items, not one - caught by
`advisor()` before it became a compile error the way D-68's own `SecretstreamError::Random` mixed-
variant-enum finding was discovered *after* the fact); and `SecretstreamError::Random`'s variant,
`Display` arm, and `From<RandomError>` impl (the exact "cfg-gated variant on an otherwise-
unconditional public enum" shape `CLAUDE.md`'s own agent-discipline section flags by name from that
D-68 finding). `crypto_secretbox`/`crypto_stream` deliberately untouched - their whole-module gate is
`Vec`/`alloc`, not RNG, out of this task's scope.

**Verified empirically, both directions, before writing any code beyond the `Cargo.toml` change**
(per `advisor()`'s explicit instruction to run the spike before touching anything else): using the
`thumbv7em-none-eabihf` target already installed for T-116,
`cargo build -p dstu-core --no-default-features --features getrandom --target thumbv7em-none-eabihf`
**fails** with `getrandom`'s own `compile_error!` ("target is not supported... define a custom
backend") when no backend `--cfg` is set - re-confirming D-04's addendum's claim still holds, not
assumed unchanged - and **succeeds** once `RUSTFLAGS='--cfg getrandom_backend="custom"'` is set,
with `randombytes_buf` itself now compiled in (not just `getrandom` the dependency). The *host*
build (`--no-default-features`, no `getrandom` feature at all) is unaffected either way - confirming
this feature is additive/opt-in, not a change to the existing bare-`no_std` default D-04 protects.

**End-to-end link-time+runtime proof, the T-117 standard ("ran," not "should work")**: an `.rlib`
cross-build proves compilation, not that the `extern "Rust"` hook actually resolves and executes at
link time - that distinction is T-116's own recorded caveat about `.rlib` cross-builds, and building
a real linked bare-metal firmware binary just to prove this one mechanism would need an entry point/
panic handler/`memory.x` this repo doesn't have (the same gap T-116 already flagged as a separate,
un-self-assigned candidate). Since `getrandom`'s custom-backend mechanism is target-agnostic - it
works identically on the host, since it's a Rust-level `extern` symbol, not an OS syscall - the
link-time+runtime proof was done on the host instead: a scratch crate (path-dependency on
`dstu-core` with `default-features = false, features = ["getrandom"]`, `.cargo/config.toml` setting
the same `getrandom_backend = "custom"` rustflag) defines a real `__getrandom_v03_custom` that fills
with an obviously-non-OS deterministic pattern (`0xAB + i`, not a real CSPRNG - the point is proving
*this* function ran, not producing real entropy) and calls both `randombytes_buf` directly and
`crypto_auth::Key::generate()` through it. Built and run for real: output byte-for-byte matched the
fake pattern through both call paths, proving the extern symbol resolved at link time, actually
executed, and every widened `generate()` genuinely reaches through to it - not merely that the crate
compiles for an embedded target in isolation.

**Doc/CI updates**: `randombytes.rs`'s own module doc rewritten (was: "must never become a `no_std`
core dependency" - now stale, since it explicitly can via `getrandom`; explains the two opt-in paths
and the capability/mechanism-parity distinction), `crypto_sign.rs`/`scalar.rs`'s stale
"`#[cfg(feature = "std")]`-gated" doc-comment prose fixed in the same pass (not left as the exact
"stale line next to your new line" failure `CLAUDE.md`'s agent-discipline section already names
from D-68), `crates/dstu-core/README.md`'s feature-flag table gained a `getrandom` row,
`docs/release-readiness.md`'s "Custom RNG backend" row and its "no tracked path" bullet both updated
to Done rather than left contradicting this entry.

**Verified**: full `cargo test --workspace` unaffected (all suites still green on default features -
this feature is inert-additive on the host, `getrandom` picks its OS backend automatically with no
cfg set, so unlike `small-tables` this does **not** need its own `--all-features`-bypasses-default
CI concern), `cargo clippy --workspace -- -D warnings` / `--features dstu-core/small-tables` /
`--all-features` / `-p dstu-core --no-default-features --features getrandom` (all four clean),
`cargo fmt --all -- --check`, `cargo build -p dstu-core --no-default-features --features getrandom`
on both the host and `thumbv7em-none-eabihf` (with and without the backend cfg, as above). Deliberately
not added as a `cargo test --no-default-features --features getrandom` CI step - unrelated
pre-existing `proptest`/`Vec`-based strategies elsewhere in `hazmat::kupyna`'s test suite need
`alloc` regardless of this feature, so a `no_std` *test* run was never a supported combination
(CI's own convention is `cargo build --no-default-features`, build-only, for exactly this reason) -
confirmed by trying it and reading the actual error, not assumed.

## D-75: Locally-verified usage examples across every `crypto_*` module and `uacrypt` command - T-120

Requested 2026-07-26: beginner-friendly, actually-run examples for both audiences (`uacrypt` binary
users, `dstu-core` library users), across every safe construction, in both resource profiles. The
task's own scope note about a missing `sign`/`verify` CLI was already stale by the time this task
was picked up - T-124 closed that gap earlier the same session - so this task documents a CLI
surface that now fully exists, not a partial one.

**Wired in as real doctests (`cargo test -p dstu-core --doc`), not README-only prose** - the task's
own stated preference ("prefer wiring examples in as real doctests... wherever the surface allows
it, so this class of bug gets ongoing regression coverage instead of a one-time manual check"), and
directly responsive to T-117's own lesson: the pre-existing `crypto_secretbox` README example
silently didn't compile for months because nothing ever actually ran it. Zero doctests existed
anywhere in this crate before this task (`cargo test -p dstu-core --doc` returned "0 tests" going
in) - a green field, not an extension of existing coverage.

**One doctest added per `crypto_*` module** (`# Example` section in each module's own top-level doc
comment), each explaining in plain language what the construction protects against - and, critically,
what it does *not* protect against, since that's the more common misuse:
- `crypto_secretbox` - encrypt a whole in-memory message; success path plus a tampered-ciphertext
  rejection (the module already had a README example, T-117 - converted into a real doctest here,
  not left as the one construction without ongoing regression coverage).
- `crypto_secretstream` - a single-chunk round trip (real multi-chunk streaming is `uacrypt
  encrypt`/`decrypt`'s own job, already covered by its own test suite) plus a tampered-chunk
  rejection.
- `crypto_sign` - **both the success path and a rejected forgery**, per this task's own explicit
  requirement ("a signature example that only shows the happy path doesn't demonstrate the
  primitive actually does what it claims", D-64's reasoning extended to documentation) - a
  different message and a different signing key both correctly fail to verify.
- `crypto_auth` - MAC compute/verify plus a tampered-message rejection, framed against `crypto_sign`
  explicitly ("proves someone who has the key, not specifically you").
- `crypto_kdf` - derive two subkeys from one master key, framed as the alternative to managing two
  unrelated secrets; distinctness (different `subkey_id`) and determinism (same inputs, same
  output) both shown.
- `crypto_generichash` - one-shot vs. incremental hashing of the same message produce the same
  digest, framed against `crypto_auth` explicitly (no secret key, so no proof of origin).
- `crypto_stream` - encrypt/decrypt round-trip, **plus the contrasting failure mode**: a tampered
  ciphertext byte does *not* error, it silently decrypts to different garbage - the opposite of
  every other example's rejection behavior, called out explicitly so a reader doesn't assume all
  `crypto_*` modules authenticate.
- `crypto_pwhash` - `hash_password`/`verify_password` round trip, `Strength::Interactive` used
  deliberately (fastest of the three presets) so the doctest itself doesn't take real seconds and
  hundreds of MiB per test run the way `Moderate`/`Sensitive` would.

**Real bug found and fixed while writing these, not just executing a checklist**: the very first
attempt at the `crypto_auth` example tripped `clippy::doc_lazy_continuation` (`CLAUDE.md`'s own
named gotcha) - a sentence read as an unindented markdown list continuation because it started a
line with `- unlike a signature...`. Fixed by rewording rather than indenting (the sentence wasn't
actually a list item), caught by running `cargo clippy --workspace -- -D warnings` immediately after
writing the doc comment, exactly the prevention habit `CLAUDE.md` already prescribes for this class
of lint.

**Verified across every combination that matters, not just the default**: `cargo test -p dstu-core
--doc` (7/7, `pwhash` correctly absent - it's feature-gated), `--all-features` (8/8, `pwhash`
included), and `--features small-tables` (7/7) - confirming the task's own explicit requirement
that a library user picking `small-tables` sees the identical API, not a guess. `cargo build -p
dstu-core` under the full `no_std`/`alloc`/`small-tables`/`getrandom`/`--all-features` combination
matrix all clean (doc comments alone cannot break a non-doctest build, but confirmed anyway since
`#[cfg]`-gated code was touched nowhere in this task - only doc comments).

**`crates/dstu-core/README.md`'s single `crypto_secretbox`-only `## Example` section expanded to
`## Examples`, one subsection per module** - code blocks copy-pasted verbatim from the doctests
(diffed programmatically against each module's actual doc-comment source, not eyeballed) so the two
copies cannot silently drift apart while both describe the same behavior; a byte-identical copy
found and fixed one real divergence during that diff (the README's `crypto_secretstream` example
had been trimmed to omit the tamper-rejection tail the doctest kept - restored to match rather than
left as an intentional-looking omission).

**CLI side (`uacrypt` binary users)**: every command in `README.md`'s "Using `uacrypt`" section and
`crates/uacrypt/README.md`'s command list was re-run against the real release binary
(`cargo build -p uacrypt --release`) before being confirmed accurate, not assumed unchanged since
T-107/T-115/T-124 last touched them - `keygen`/`encrypt`/`decrypt`/`hash` round-trip correctly;
`sign-keygen`/`sign-pubkey`/`sign`/`verify` (T-124, new since T-120 was originally scoped) added to
`README.md`'s CLI section with a real, run-for-real transcript showing both `verify`'s exit-`0`
silent success and its exit-`1` loud failure on a tampered file - the transcript's exact stdout/
stderr text and exit codes were captured from an actual run, not composed from reading the source.

**Verified**: `cargo test --workspace --all-features` (all suites, including the new doctests),
`cargo clippy --workspace -- -D warnings` / `--features dstu-core/small-tables` / `--all-features`
(all three clean, after the `doc_lazy_continuation` fix above), `cargo fmt --all -- --check`, and
the `dstu-core` `no_std` build matrix, all clean.

## D-76: T-125 follow-up - block-level benchmark contamination found, XTS/CMAC-GMAC-KW root causes split into T-126/T-127

Requested 2026-07-26, same day as T-121/T-125: rather than profiling T-125's open GCM/CMAC
non-monotonic pattern directly, the request was to reason from Kalyna's actual algorithmic
complexity (round count, block-cipher-call count per mode) against `docs/PERFORMANCE.md`'s already-
published numbers, with `advisor()` consulted at each step before committing to a mechanism -
`CLAUDE.md`'s "read directly from the other implementation's source, not guessed at" rule extended
to performance claims, not just correctness ones.

**First pass, rejected.** A research subagent proposed a `[ZERO_COLUMN; MAX_NB]` fixed-size scratch
buffer in `hazmat::kalyna.rs`'s round functions as the mechanism explaining why 512-512 (`nb=8`)
outperforms 128-*/256-* relatively in both CMAC and GCM. `advisor()` falsified this on the first
call: the theory predicts *worst* relative performance at `nb=2` (most wasted, zeroed buffer space)
and *best* at `nb=8` (buffer fully used) - but `docs/PERFORMANCE.md`'s own block-level table (the one
measurement that isolates the round function from any mode-of-operation cost) shows the *opposite*
ordering (128-128 leads UAPKI by 24%, 512-512 trails by 4%). A mechanism that predicts the wrong
sign on data already in hand is not evidence, however plausible it reads - discarded without
further investigation.

**Second pass, three findings confirmed by direct source reading, not narrative:**

1. **The block-level "rough parity with UAPKI" claim is a measurement artifact.** UAPKI's
   `encrypt_ecb`/`decrypt_ecb` (`dstu7624.c:2899-2961`) call `ba_to_uint64_with_alloc` then
   `ba_alloc_from_uint64` - two heap allocations plus a `free`, every call - to convert to/from its
   public `ByteArray` type. For a single 16-64 byte block this allocation is a large fraction of the
   measured time. This needed no new benchmark to prove: UAPKI's *own* CMAC-at-1-MiB throughput
   (`cmac_update`/`cmac_final`, confirmed heap-allocation-free by reading the source) is 1.33-2.71x
   **faster** than UAPKI's *own* block-cached number for the same variant - which is impossible for
   a construction built from chained calls to that same block cipher unless the block number
   under-measures UAPKI's true per-block speed. Our own CMAC-at-1-MiB tracks our own block-cached
   number within ~1.5% on every variant, exactly what an allocation-free chain predicts, confirming
   *our* block-level number needed no such correction. **Net effect: the true core-round-function
   gap (allocation removed from both sides) is larger than the block-level table showed - UAPKI's
   round function is genuinely faster than ours, ~2.7x at 128-128 narrowing to ~1.3x at 512-512.**
   This is a core-cipher-level finding, not specific to any mode, and explains why T-125's CMAC
   cells look the way they do without needing a CMAC-specific cause at all.
2. **Kalyna-XTS's separate 512-512 anomaly (T-121/D-71) is root-caused** - split out to **T-126**.
   `hazmat::gf2m_wide.rs` has no fast path for "multiply by the fixed generator `x`"; XTS's
   once-per-block tweak-doubling (`kalyna_xts.rs`'s `gamma.multiply(two)`) pays the full general
   O(m²) schoolbook multiply for what is mathematically an O(m/64) shift-plus-conditional-XOR
   operation. Cost scales as roughly O(m) total waste per message (O(m²) per multiply × O(1/m)
   multiplies), worst exactly at m=512 - matching the one variant that blows up. Confirmed *not* to
   generalize to GCM's own field multiply: GCM's Horner accumulation multiplies by `H`, a dense
   key-derived operand, which is a genuinely general multiply in any implementation, nothing to
   specialize away - this is why XTS is containable and GCM (still open, see below) isn't.
3. **`hazmat::kalyna_cmac`/`kalyna_gmac`/`kalyna_kw`'s one-shot API re-expands the full key schedule
   on every call** - split out to **T-127**. `kalyna_cmac.rs:52`/`kalyna_kw.rs:95` both construct a
   fresh `ExpandedKey` from raw key bytes inside `mac`/`wrap`, unlike `kalyna-block`/`gcm`/`xts`,
   which take an already-expanded cipher object. Confirmed on our side by reading the source; the
   corresponding claim about UAPKI's own (uncommitted) benchmark wrapper is *inferred* from
   `docs/PERFORMANCE.md`'s documented convention, not independently verified - stated as such, not
   overclaimed. This is a real API gap affecting production callers too, not just a benchmark
   artifact: any caller MACing/wrapping more than one message under one key pays a full schedule
   expansion every call today, with no way to avoid it.

**Left open, deliberately**: GCM's non-monotonic 256-*/nb-dependent pattern. `advisor()` explicitly
directed cutting the subagent's composite "two opposite trends compound at nb=4" explanation from
scope - neither implementation uses a precomputed GHASH-style table, so this doesn't reduce to
finding 3's "specialize the fixed-constant case" fix, and no mechanism found by source reading
alone predicted the right shape without also being unfalsifiable. Needs `perf`/instrumented
profiling, per T-125's own original framing - not resolved here, and not guessed at just to close
the task.

Both T-126 and T-127's fixes are speed-only: T-126 must produce byte-identical output to the
existing general `multiply`, verified against it directly rather than a new derivation; T-127 adds
an additional entry point that reuses the exact same `ExpandedKey`/schedule logic already used
elsewhere, with the existing raw-key functions kept as thin wrappers - neither changes any
construction's cryptographic logic, so existing tests (vectors, tamper/misuse coverage, property
tests) remain the correctness gate, no new oracle needed.

**Both implemented and re-measured the same day**, per the project owner's explicit condition that
a fix only proceeds if it's safe and doesn't touch cryptographic strength or the algorithm itself -
both qualified (pure speed specializations/API additions, not construction changes) and were built
test-first as usual:

- **T-126**: `double()` added to `gf2m_wide.rs`'s `gf2m_field!` macro (shift-plus-conditional-XOR,
  O(m/64)), with a property test (`double_matches_general_multiply_by_two`, all three field widths,
  plus an `ALL_ONES`-specific carry-out case) written *before* wiring it into `kalyna_xts.rs`'s
  tweak update, per this project's test-first standing rule. Re-measured at the exact 512 B/4096 B
  scale the original T-121 finding used: the 512-512 anomaly (previously ~4.4-4.6x slower than
  UAPKI) is now **~2.4-2.5x faster**, and all four other variants improved substantially too -
  confirming the mechanism applied to every field width, not just the one that had crossed into
  "dramatic outlier" territory. Independently re-confirmed at 10 MiB (`--iterations 50`): 512-512
  lands in the middle of the other variants' throughput band, not an outlier at all.
- **T-127**: `mac_with_cipher`/`verify_with_cipher` added to `kalyna_cmac.rs`/`kalyna_gmac.rs`,
  `wrap_with_cipher`/`unwrap_with_cipher` added to `kalyna_kw.rs`; `uacrypt`'s three corresponding
  benchmark loops rewired to build the `ExpandedKey` once outside `--iterations`, closing the
  finding's own stated caveat along the way - `bench.c`'s `cmd_kw` was read directly and confirmed
  to already cache its own schedule outside its loop, so the asymmetry this task fixed was real,
  not merely inferred from convention. Re-measured at KW's existing 2-block-of-key-material scale:
  this project's own throughput improved 14-31% across all five variants (UAPKI's own numbers held
  steady, as expected), narrowing its lead from ~1.8-2.7x to ~1.4-2.2x without eliminating it - the
  residual is consistent with, and not distinguished further from, the core-round-function gap
  found in this decision's first half. CMAC's own already-published 1-MiB numbers were confirmed
  unchanged after the fix, exactly as predicted (the schedule cost was already amortized to nothing
  at that scale).

Full verification for both: `cargo test --workspace --all-features` (every test binary, 0
failures - including all 12 `kalyna_xts` tests, 12 `kalyna_cmac`, 18 `kalyna_gmac`, 17 `kalyna_kw`,
and 43 `dstu-core` lib tests covering the new `gf2m_wide` property tests), `cargo clippy
--workspace --all-features -- -D warnings` and `cargo fmt --all -- --check` clean (two
`clippy::doc_markdown` "MACing" hits and one `clippy::cast_sign_loss` hit fixed along the way, both
previously-documented lint shapes in `CLAUDE.md`), and `--no-default-features`/`--features
alloc`/`--features small-tables` builds all clean. Full numbers for both fixes, plus the new 10 MiB
re-measurement pass across every mode without an inherent length cap (requested the same session,
to rule out any remaining per-call setup-cost noise), are in `docs/PERFORMANCE.md`'s Kalyna-XTS/Kalyna-KW
sections and its new "10 MiB re-measurement pass" subsection.

## D-76 continued: T-125's own GCM/GMAC finding, root-caused and fixed the same day

Requested as a direct follow-up ("continue the investigation where we still lag by a multiple") -
of the gaps left in this file's first half, T-125's own Kalyna-GCM 256-256/256-512 anomaly (~2.1-2.2x
at 1 MiB) was the only one still genuinely multiple-fold and unexplained; the core-round-function gap
(finding #1 above, ~1.3-2.7x) was flagged by `advisor()` as *not* the next target - `hazmat::kalyna.rs`
is the crate's most load-bearing, most-fused file (D-28/D-29/D-30), and the user's own condition
("only if safe and doesn't affect cryptographic strength") argued for the more contained target
first.

**`advisor()`'s specific direction, followed exactly**: GCM's per-block cost is one block-cipher
call plus one general `Gf2m*::multiply` against the dense, key-derived `H` - with this project's own
already-published numbers (Kalyna-block cached: 124.51 MB/s at 256-256; Kalyna-GCM: 8.31 MB/s), ~93%
of GCM's time already had to be the field multiply, arithmetically, with no profiler needed. The
open question was never "where does the time go" but "why does UAPKI's Karatsuba+malloc multiply
win at m=256 and lose at m=512" - answerable by isolating the multiply's own cost, not by profiling
GCM as a whole.

**Isolated timing, three field widths** (`hazmat::gf2m_wide::field_axiom_tests::isolated_timing_*`,
`#[ignore]`d manual-`Instant` diagnostics, `cargo test --release -- --ignored --nocapture`): a single
`Gf2m128::multiply` costs 8.58x a `Kalyna128_128ExpandedKey::encrypt_block` (1525.5 ns vs. 177.8 ns);
`Gf2m256` costs 11.22x (3837.5 vs. 341.9 ns); `Gf2m512` costs 16.51x (11407.5 vs. 691.0 ns) - i.e.
the field multiply is 89.6%/91.8%/94.3% of GCM's total per-block cost, rising with `m` exactly as
`poly_mul_wide`'s O(m²) schoolbook cost predicts. This *is* T-125's own requested profiling step,
done with a scratch timing harness rather than an external profiler (`perf` isn't readily available
on this Windows dev machine) - the isolation (multiply alone vs. block-cipher alone) gives the same
answer a call-graph profiler would, for this specific question.

**Fix, `advisor()`-specified**: a 4-bit-window comb multiply, chosen over an 8-bit window because
`a` (the operand the table is keyed on) changes every block in GCM's Horner accumulation - a
256-entry table (8-bit window) would be rebuilt from scratch every single multiply, strictly worse
than the 16-entry table a 4-bit window needs. Construction: `T[0] = 0`, `T[1] = a`, then for
`i in 1..8`: `T[2i] = T[i] << 1`, `T[2i+1] = T[2i] XOR a` (the standard doubling recursion, 7
shift+XOR pairs, all at the double-width `$limbs2` size since even `T[15]` already exceeds `$limbs`
width). The other operand is then walked nibble-by-nibble, most-significant-first: shift the
accumulator left by 4 bits, `XOR` in `T[nibble]`, repeat for `m/4` nibbles - `m/4` accumulator
iterations instead of the previous bit-serial method's `m`. `reduce` (the O(m) bit-at-a-time
modular-reduction step) was left untouched, per `advisor()`'s explicit note that it's a much smaller
fraction of the total (~512 iterations at m=512 vs. `poly_mul_wide`'s pre-fix ~16,384 word-ops) -
revisit only if a future measurement shows otherwise, not assumed now.

**Correctness gate**: no new test written for the multiply-implementation swap itself, per
`advisor()`'s explicit direction - the four existing field-axiom property tests
(`multiply_is_commutative`/`_associative`/`_distributes_over_add`/`multiply_by_one_is_identity`)
already check exactly the property a broken comb implementation would violate, and all five official
GCM vectors, five GMAC vectors, and five XTS vectors (XTS doesn't call `poly_mul_wide` at all since
T-126's `double()`, but exercises `reduce`/`Self` the same way) are an unchanged, independent,
byte-exact gate. All passed on first run. Full workspace `cargo test --workspace --all-features`
(every test binary, 0 failures), `clippy --workspace --all-features -- -D warnings`/`fmt --all --
--check` clean (one more `clippy::doc_markdown` "XORing" hit, same previously-documented lint shape),
and the `--no-default-features`/`--features alloc`/`--features small-tables` build matrix all clean.

**Measured speedup**: ~1.8-2.3x faster on the multiply alone (narrower than the ~4-6x a pure
iteration-count argument predicts - `advisor()` flagged this as worth investigating if pursued
further, not chased here; likely candidates are the table-build overhead and the indexed `T[nibble]`
lookup costing more than the old branchless masked-`XOR` per bit did, but this is inferred from the
mechanism, not measured). Re-measuring the isolated ratio after the fix: `Gf2m128` drops to 4.28x
the block cipher (was 8.58x), `Gf2m256` to 5.80x (was 11.22x), `Gf2m512` to 7.03x (was 16.51x) -
consistent with the ~1.8-2.3x multiply speedup at each width. Binary-level GCM throughput improved
~1.7-2.3x across every variant (`docs/PERFORMANCE.md` has the full table); T-125's own trigger - the
256-256/256-512 cells losing by >2x at 1 MiB - narrowed from ~2.14-2.18x to **~1.09-1.11x**, closing
the task. GMAC (identical field-arithmetic shape) improved by the same mechanism, roughly doubling
an already-large lead.

**What this does not resolve, stated plainly rather than left implicit**: why UAPKI specifically
wins the mid-size (256-*) variants and loses at both extremes (128-*/512-512) even after this fix -
a candidate mechanism exists (UAPKI's own `gf2m_mul`, `dstu7624.c:2963-3001`, pays 3 heap allocations
per call via its Karatsuba path, `math-gf2m-internal.c:840-1002`, amortized differently across the
fewer-but-larger blocks a bigger `m` produces per message), read from source but never measured in
isolation the way this decision's own multiply-vs-block-cipher numbers were. Do not present it as
settled in a future pass without first doing the equivalent isolation on UAPKI's own side.

**The `#[ignore]`d isolated-timing tests are a deliberate, retained diagnostic, not leftover
scaffolding** - `advisor()`'s explicit call: they are this fix's own before/after instrument (already
re-run once, above), kept for the same purpose on any future `gf2m_wide` change, not a correctness
assertion (hence `#[ignore]`, not part of the normal `cargo test` run).

## D-77: `encipher_round`/`fused_inv_round` made const-generic over block size - T-128

Requested 2026-07-26 as a direct follow-up to comparing `hazmat::kalyna.rs`'s fused round functions
against UAPKI's `p_boxrowcol`/`BT_xor128`/`BT_xor256`/`BT_xor512` macros: "unroll the loop into 5
variant-specific implementations," explicitly conditioned on doing so "with the advisor and maximally
safely, with tests and everything necessary."

**`advisor()`'s first call reframed the request before any code was written.** The five
`kalyna_variant!` invocations collapse to **three** distinct block sizes - `encipher_round`/
`fused_inv_round` depend only on `nb` (`state.len()`), never on `nk`/`nr`: `nb=2`
(Kalyna128_128/Kalyna128_256), `nb=4` (Kalyna256_256/Kalyna256_512), `nb=8` (Kalyna512_512). UAPKI's
own three macros (not five) confirm this is the real fork. Writing "5 hand-unrolled
implementations" would have produced two verbatim duplicate pairs - no extra speed, and two more
places for the encrypt and decrypt directions to silently diverge from each other over time.

**The actual overhead, per `advisor()`'s diagnosis**: `nb` is a runtime `usize` at a call site where
every real caller (`kalyna_variant!`) supplies a compile-time-known literal. That single fact causes
three compounding costs simultaneously: (1) the interior loop over `ROWS`/`nb` can't be unrolled by
the compiler without a known trip count, (2) every `state[..]` access is bounds-checked because
`state: &mut [Column]` is a runtime-length slice, not a fixed-size array, and (3) the intermediate
`result: [ZERO_COLUMN; MAX_NB]` buffer is always allocated and zero-initialized at the full 8-column
width, 4x more than `nb=2` (the most common variant, 128-bit block) actually needs.

**`advisor()`'s directed fix: thread a `const NB: usize` through the round functions first, measure
before considering hand-written per-size bodies** - this gives the compiler the same fixed trip count
and fixed-size buffer hand-unrolling would provide, without duplicating the algorithm five (or even
three) times. Implemented as new `encipher_round_n<const NB: usize>`/`fused_inv_round_n<const NB:
usize>` functions, with `encrypt_with_schedule`/`decrypt_with_schedule`/`encrypt_generic`/
`decrypt_generic` becoming `<const NB: usize>` generic (`kalyna_variant!`'s call sites pass `$nb` via
turbofish - one monomorphized instantiation per block size, structurally matching UAPKI's per-size
macro approach). The original runtime-`nb` `encipher_round`/`fused_inv_round` are kept, not deleted -
`round_key_from`/`key_expand_kt` (key-schedule computation, run once per `ExpandedKey`/
`encrypt_generic` call rather than once per round) still call them directly, since there's no
per-block-throughput benefit to specializing a call site that only ever executes 2-3 times per key
expansion. `fused_inv_round` picked up `#[allow(dead_code)]` (same D-27/D-28 "kept for the
differential-test reference" pattern already established for `sub_bytes`/`shift_rows`/
`decipher_round`) since `decrypt_with_schedule` no longer calls it directly.

A new `state_array_mut<const NB: usize>(full: &mut [Column; MAX_NB]) -> &mut [Column; NB]` helper
narrows the always-`MAX_NB`-sized scratch array's live `NB`-column prefix into the fixed-size
reference the const-generic round functions need, via `TryFrom`. The conversion can never actually
fail (`NB <= MAX_NB` holds by construction at every call site), but `lib.rs` denies
`clippy::unwrap_used`/`clippy::expect_used` crate-wide, so the `Err` arm uses `unreachable!` instead
of `.unwrap()`/`.expect()` - a lint-compliance detail, not a new fallibility the caller needs to
handle.

**Safety net, `advisor()`-specified before implementation, all satisfied before committing**:
- A new differential-test module, `const_round_tests`, checks the retained runtime-`nb`
  `encipher_round`/`fused_inv_round` against the new `encipher_round_n`/`fused_inv_round_n` over
  random state, for all three `NB` values and both directions (6 proptest functions) - this is the
  test that would actually catch a transposed gather index or off-by-one in the rewrite, distinct
  from the pre-existing `fused_round_tests`/`decrypt_fusion_tests` (which check the *algorithm*
  against a from-scratch naive reference, not this refactor against the pre-refactor code).
- Full workspace `cargo test --workspace --all-features` green (every test binary, including all 5
  Kalyna variants' official vectors and every mode built on top: ECB/CTR/CBC/CFB/OFB/CMAC/KW/GCM/
  GMAC/XTS/CCM, `crypto_secretbox`/`crypto_secretstream`, `uacrypt`) - this round function is under
  every one of those, so a wrong output here would be silent wrong ciphertext crate-wide, not a
  localized bug.
- `cargo clippy --workspace --all-features -- -D warnings` and `cargo fmt --all -- --check` clean.
- `--no-default-features`, `--features alloc`, `--features small-tables`, and `--features pwhash`
  all build individually clean (not just the default profile + `--all-features`, per this project's
  own standing feature-matrix lesson).
- Scoped Miri (`crates/dstu-core`, `PROPTEST_CASES=8 cargo +nightly miri test --all-features
  hazmat::kalyna`) **did not complete this session** - three attempts, all blocked by the same
  Miri+proptest+Windows tooling interaction rather than anything in this change, split out to
  **T-130** instead of blocking this commit on it (user's explicit direction, given every other
  layer below passed clean and CI's own Miri job has never once passed either, T-100): (1) default
  isolation aborts on `GetCurrentDirectoryW not available when isolation is enabled` - proptest's
  failure-persistence file logic calls `std::env::current_dir()`; (2)
  `MIRIFLAGS=-Zmiri-disable-isolation` (the error's own suggested fix) appeared to hang - ~35
  minutes wall time against ~0.8s of actual CPU time on the `miri.exe` process (checked via
  `Get-Process -Id <pid> | Select CPU`, this file's own documented diagnostic for telling "slow
  interpretation" from "genuinely stuck" - this was the latter), killed rather than waited out
  further; (3) `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` under default isolation hit the identical
  `current_dir()` error, implying Miri's default isolation blocks the interpreted program's view of
  its own environment variables too, so proptest's env-var opt-out never took effect. Does not
  weaken this change's own correctness verification - the 6 new `const_round_tests` proptest
  functions ran and passed under the normal (non-Miri) `cargo test --workspace --all-features`
  along with everything else; only Miri's specific UB-detection layer is missing, not correctness
  confirmation.
- The full 10-target `cargo xtask fuzz` smoke suite (Windows MSVC toolchain path,
  `fuzz_windows_msvc` - `cargo fuzz` alone fails on this machine's default `windows-gnu` target,
  "address sanitizer is not supported for this target") ran clean, 0 crashes.
- Constant-time discipline unaffected: same `forward_sbox_mds`/`inverse_sbox_mds` table lookups,
  same D-19 documented exception, no new secret-dependent branch - const-generic specialization
  changes only what the compiler knows about loop trip counts and buffer sizes at compile time, not
  what data drives any branch or array index.

**Measured** (`cargo bench -p dstu-core --bench kalyna -- --baseline pre-unroll-2026-07-26`;
D-34's "criterion is for internal regression tracking only, never a cross-implementation claim"
caveat applies - this is a same-machine, before/after comparison, not a new claim against UAPKI):
block-only (cached-schedule) time - which isolates the round function from key-expansion cost, the
fair before/after metric for this specific change - dropped substantially at every block size, most
at the smallest (`nb=2`, the size that pays the worst of the old buffer/bounds-check waste) and
least but still real at the largest (`nb=8`, contrary to one initial prediction that it "might not
move at all" since its buffer usage was already full-width - bounds-check elimination and full loop
unrolling help every size, not only the one with wasted buffer space). Full-call
(`encrypt_generic`/`decrypt_generic`) improved by a much smaller and sometimes noisy amount, exactly
as expected: those calls are key-expansion-dominated (the `kalyna_variant!` doc comment's own
"~60-79% of single-call time is key schedule" note), and key expansion still runs through the
unchanged runtime-`nb` round functions. Full per-variant numbers are in `docs/PERFORMANCE.md`'s
"Regression baseline" section, not repeated here. Binary-level (`uacrypt` vs UAPKI process
comparison, D-34's canonical cross-implementation method) was not re-measured this session - the
UAPKI comparison wrapper isn't committed to the repo and wasn't rebuilt here.

**What this does not fix, split out to T-129** (a separate, more invasive change, not attempted
here): the round functions still gather state one byte at a time (`state[src_col][row]`,
recomputing `src_col`/`shift` fresh on every one of the `ROWS * NB` iterations) where UAPKI's
`p_boxrowcol` table plus `BT_xor*` macros operate on whole 64-bit words - fewer, wider operations
than a byte-wise gather. This was the fifth structural difference identified when comparing
`encipher_round` against `p_boxrowcol` directly; the other four (runtime `nb`, bounds-checked slice
indexing, the oversized always-zeroed scratch buffer, and a separate copy-back pass building into
`result` then `copy_from_slice`-ing into `state`) are exactly what this decision's fix closes.
User's explicit instruction: do not build an equivalent for the `small-tables` feature - that
profile deliberately trades throughput for a smaller table footprint (D-35/D-38/D-39), and a
word-wide gather is a throughput-only change with no meaning under that tradeoff.

## D-78: UAPKI comparison-CLI wrapper rebuilt for CMAC/XTS - T-131/T-133

Requested 2026-07-26: "Чому в таблиці не має uapki? Треба ж з чимось порівнювати" - the user
noticed `docs/PERFORMANCE.md`'s freshly re-measured 10 MiB tables (post-T-128) had no UAPKI column and
asked why, making clear the `uacrypt`-only half of T-131 wasn't the actual ask.

**`advisor()`'s direction**: don't write seven wrappers - check first whether `oracles/uapki` has a
committed `bench.c` harness to reuse; if not, write one wrapper binary covering CMAC and XTS first
(largest T-128 gains, per `docs/PERFORMANCE.md`'s +86%/+95% cells), verify byte-identical before
trusting any timing, and don't touch `hazmat` code - nothing about this task needs a source change.
**No `bench.c` exists in the vendored `oracles/uapki` tree** (verified: `find` for the filename
returned nothing, and `grep` for `cmd_kw` across the whole tree matches only `dstu7624.c`) - so the
harness `docs/PERFORMANCE.md`'s T-127/D-76 entry cites ("reading the UAPKI benchmark harness directly -
`bench.c`'s `cmd_kw`") came from somewhere outside this committed clone (the release zip, an
uncommitted download, or the citation itself needs re-checking). Not chased further here - flagged
so that T-127 citation isn't silently assumed re-derivable from what's actually in the repo.

**Mechanics, matching D-71's already-documented method**: downloaded
`uapki-v2.0.12-win-amd64-signed.zip` (`gh release download v2.0.12 --repo specinfo-ua/UAPKI`,
confirmed via `gh api .../releases` this asset exists for the exact version this project already
cites), extracted `uapkic.dll`, `gendef uapkic.dll` then
`dlltool -d uapkic.def -l libuapkic.a -D uapkic.dll` to build an import lib, confirmed every needed
symbol (`dstu7624_alloc`/`_init_cmac`/`_init_xts`/`_encrypt`/`_decrypt`/`_update_mac`/`_final_mac`/
`_free`, `ba_alloc_from_uint8`/`_get_buf_const`/`_get_len`/`_free`) is actually exported in the
generated `.def` before writing any C. Wrote `uapki_bench.c` (scratch-only, not committed) against
the vendored `oracles/uapki/library/uapkic/include/*.h` headers (source-available locally, calling
into the prebuilt DLL - the header/DLL version pairing was not independently re-verified beyond
both being v2.0.12-labeled, consistent with this project's existing `oracles/uapki` pin), mirroring
`uacrypt`'s own `kalyna-cmac compute|verify`/`kalyna-xts encrypt|decrypt` file-based CLI shape
exactly (`--variant`/`--key`/`--in`/`--out`/`--tag`/`--tweak`/`--iterations`), timed with
`QueryPerformanceCounter` around only the `dstu7624_encrypt`/`_decrypt`/`_update_mac`+`_final_mac`
call itself, not surrounding setup. Compiled clean on the first attempt (`gcc -O2 ... -luapkic`).

**Verification gate, run before any timing was trusted (this is also T-133's first concrete
instance, not a separate effort)**: byte-diffed `uacrypt`'s and the wrapper's output for all 5
variants - CMAC compute (tag), CMAC verify (cross-checked each implementation's tag against the
other's), XTS encrypt (ciphertext), XTS decrypt (round-tripped back to the original plaintext,
checked against both implementations' own ciphertext). All 15 identity checks matched exactly. No
adjustment was made to force a match anywhere - matching D-25's standing warning against
unexplained transforms that merely produce the expected output.

**Timing taken same session, nothing else CPU-heavy running** (learned from an earlier discarded
+4.9% spurious "regression" this session caused by contemporaneous Miri background load, D-77's own
narrative) - both binaries run back-to-back at 10 MiB, N=50, both directions:

- **CMAC**: UAPKI still wins, ~1.1-1.9x depending on variant (128-128: 235.86 vs 199.82 MB/s;
  256-256: 263.40 vs 142.44 MB/s) - narrower than the pre-T-128 1 MiB table's ~1.4-2.2x gap, and
  exactly the residual T-129 (byte-wise gather vs UAPKI's word-wide `BT_xor*`) predicts is still
  open. Not a new finding - confirms T-128 closed part of CMAC's gap, not all of it, with a number
  instead of an inference.
- **XTS**: this project leads by 3.2-15.1x, the widest margin of any mode measured in this entire
  file. Root-caused by reading `dstu7624.c` directly, not guessed: `encrypt_xts`/`decrypt_xts`
  (lines 3003/3069) call the fully generic `gf2m_mul` (lines 2963-3001) to compute the tweak's
  "multiply by 2" every block - `gf2m_mul` heap-allocates three `WordArray`s
  (`wa_alloc_from_uint8` x2, `wa_alloc` x1) and runs a full O(m²) modular multiply for a step that
  is mathematically just a one-bit shift plus a fixed conditional reduction. This project's
  `Gf2m*::double()` (T-126/D-76) is exactly that O(m), allocation-free operation. **Confirms and
  extends what the 1 MiB table already flagged for 512-512 specifically** ("3 allocations per
  call... dominating UAPKI's own XTS throughput at scale") - now shown to hold across every
  variant, and to widen further once T-128 also sped up this project's own block-cipher path.
  **Not a bug on UAPKI's side** - `gf2m_mul` is correct, and is shared with GCM/GMAC's own field
  multiply, where a full multiply genuinely is needed; it is simply not specialized for XTS's one
  fixed multiplicand the way this project's `double()` is.

**Scope left open**: block/CCM/GCM/GMAC/KW have no rebuilt UAPKI wrapper yet - `uapki_bench.exe`
can be extended with the remaining `dstu7624_init_*` calls rather than rebuilt from scratch, tracked
under T-131's remaining scope, not a new task.

## D-79: Byte-identity-verified UAPKI comparison made the standing methodology - policy, not just this session's practice

Decided 2026-07-26, prompted directly by the user after seeing D-78's CMAC/XTS results: a
`uacrypt`-only table with UAPKI's column simply absent ("wrapper not rebuilt this session, see
T-131" - the pattern every mode's table used right after T-128) is a stopgap, not an acceptable
resting state for this project's canonical comparison method (D-34). Going forward, per
`docs/PERFORMANCE.md`'s "Methodology" section (new bullet, same entry point as the 10 MiB and
both-directions policies): any new or refreshed binary-level table must (1) build or extend a C
wrapper against the pinned prebuilt `uapkic.dll` for that mode, (2) byte-diff its output against
the real `uacrypt` binary for every variant/direction *before* trusting any timing - this is T-133's
standing check, not a one-off - and (3) time both binaries back-to-back in the same session with
nothing else CPU-heavy running.

Not retroactive - block/CCM/GCM/GMAC/KW's existing `uacrypt`-only 2026-07-26 tables stay published
as-is, flagged for a real UAPKI column the next time each is touched, not backfilled here just to
satisfy the new policy immediately.

## D-80: UAPKI wrapper extended to block/GCM/GMAC/KW/CCM - and a real GMAC timing bug found in the process

Requested 2026-07-26, directly off the user noticing the previous overview table collapsed each
mode to one number and asked why decrypt/verify/unwrap comparisons against UAPKI were missing -
D-79's new policy said every future table needs both directions *and* a real UAPKI column, so this
extends `uapki_bench.exe` (T-131/D-78) to the five modes D-79 flagged as not-yet-rebuilt: block
(ECB), GCM, GMAC, KW, CCM.

**Mechanics**: read `dstu7624.h`/`dstu7624.c` directly for each mode's API shape rather than
assuming symmetry with CMAC/XTS - `dstu7624_encrypt`/`_decrypt` already dispatch ECB and KW (same
functions XTS already used), GCM/CCM go through `dstu7624_encrypt_mac`/`_decrypt_mac`, GMAC through
`update_mac`/`final_mac` (same shape as CMAC). CCM's tag/nonce-length/`n_max` parameters were
derived from `hazmat::kalyna_ccm.rs`'s own `kalyna_ccm_variant!` macro invocations (`ccm_nb` values
{4,4,4,6,8}, `q` values {16,16,16,32,64}) and matched to UAPKI's `nb=((n_max-3)>>3)+1` formula
(`dstu7624_init_ccm`, `dstu7624.c:4139`) by picking `n_max` in the valid range for each target `nb`.

**Verification gate, same standard as D-78**: byte-diffed every mode/direction/variant before
trusting any timing. Block (ECB encrypt+decrypt), GCM (encrypt+decrypt, cross-verified each
implementation decrypting the other's ciphertext), GMAC (compute+verify, cross-verified each
implementation verifying the other's tag), KW (wrap+unwrap, round-tripped back to original key
material) - 40 checks, all matched. CCM confirmed **not** byte-comparable, exactly as D-71 already
documented, now root-caused by reading `dstu7624_encrypt_ccm`/`_decrypt_ccm` directly
(`dstu7624.c:2792`/`2849`) rather than citing the earlier finding secondhand: `cipher_data` bundles
a trailing CTR-encrypted checksum suffix that `decrypt_ccm` computes via one CTR pass but never
actually checks - verification instead recomputes the checksum from decrypted plaintext (`ccm_padd`)
against a separately-supplied `h_ba` value. There is no single wire-format "tag" on UAPKI's side
equivalent to `uacrypt`'s separate ciphertext+tag files; CCM stays self-consistent-only (5 UAPKI
own-round-trip checks, all passed), same posture as before, not forced into a comparison that
doesn't hold.

**A real bug found while writing this, not by inspection but by the numbers looking wrong**: GMAC's
freshly-measured 1-block UAPKI numbers came out close to the *old*, already-published ~0.8-1.7 MB/s
figures - suspicious, since T-125/D-76's comb-multiply fix and T-128's round-function fix should
both have moved UAPKI's *comparison baseline* not at all (nothing changed on UAPKI's side) but were
expected to widen this project's own lead, not reproduce the old absolute numbers almost exactly.
Checking `run_gmac`'s code (copied from `run_cmac`'s original structure) found the actual cause:
`dstu7624_alloc`/`dstu7624_init_gmac` were timed *inside* the same window as
`update_mac`/`final_mac`, not excluded the way block/GCM/KW/CCM/XTS (written correctly from D-78's
XTS pattern onward) all do - `uacrypt`'s own GMAC command expands its schedule once outside the
loop (matching every other mode), so this was comparing "UAPKI cold-starts every call" against
"uacrypt reuses a cached schedule," not a fair per-op comparison. For a one-block message, the
cold-start cost dominates enough to make the whole historical "~4-24x uacrypt lead" conclusion
mostly an artifact of this asymmetry, not a property of GMAC's design. Fixed (moved the timer start
to after `init_gmac`, matching every other mode), byte-identity re-confirmed unaffected (timing-only
bug, not a correctness one), re-measured:

**The real gap is ~1.1-2.9x, not ~4-24x.** uacrypt still leads every variant, but the margin this
project believed existed for the entirety of this table's prior history was substantially inflated
by the benchmark, not by GMAC. **CMAC was checked against the identical bug and is not materially
affected** - re-running CMAC's 10 MiB table with the same fix produced numbers within <1% of
already-published ones, because bulk 10 MiB work dwarfs microseconds of per-call setup the way a
single block cannot. Both tables are in `docs/PERFORMANCE.md`'s GMAC section with the full before/after
comparison; not repeated here.

**Flagged, not chased further**: this exact failure mode (timing a cold-start cost inside a loop
that the counterpart binary excludes) could equally have affected historical small-message CMAC
(64 B) and CCM numbers measured by an earlier, uncommitted wrapper this session never inherited or
inspected - those older rows should be treated as unverified against this specific bug, not assumed
correct by precedent, until someone re-measures them with a wrapper confirmed to exclude setup cost.
Lesson for future wrapper code, any mode: **the timer must start after every one-time setup call
(`alloc`/`init_*`) and stop before any teardown (`free`), matching whichever side of the comparison
already does this - copying an existing wrapper function's *shape* without checking where it places
`now_ns()` relative to setup carries this bug forward silently**, exactly what happened copying
`run_cmac`'s structure into `run_gmac` without re-deriving the timer placement from first principles.

## D-81: T-130 resolved - Windows Miri/proptest hang is mechanism-wide, not Kalyna-specific, and attempt four's untried flag combination actually works

Requested 2026-07-26 by the perf/hygiene roadmap's own Tier B: before trusting the tier ordering
(T-130 gates Tier C's Miri done-bar), resolve the roadmap's explicit open question - does T-130's
Windows Miri hang reproduce on `hazmat::kupyna`/Strumok's proptest suites too, or is it specific to
`hazmat::kalyna`? Not assumed either way, per the roadmap's own instruction, even though the
mechanism (proptest's failure-persistence code calling `std::env::current_dir()`, which Miri's
default isolation blocks) plainly has nothing to do with Kalyna's code specifically.

**Step 1 - routing question, cheapest discriminator first (`advisor()`'s explicit suggestion)**:
ran `cargo +nightly miri test -p dstu-core --lib
hazmat::kupyna::fused_round_tests::fused_sub_shift_mix_matches_naive_256` with **no flags at all** -
a single fast, no-key-schedule Kupyna proptest function. It aborted with the identical
`GetCurrentDirectoryW not available when isolation is enabled` panic, the identical stack trace
through `proptest::test_runner::failure_persistence::file::absolutize_source_file` ->
`std::env::current_dir`, as T-130's original `hazmat::kalyna` finding. **Confirmed: this is a
proptest-mechanism-wide Windows/Miri interaction, not anything about Kalyna's code** - answers the
open question without touching Kalyna at all, and without risking another multi-minute wait on an
ambiguous flag combination.

**Step 2 - attempt four, the combination T-130's own text named as untried**:
`MIRIFLAGS=-Zmiri-disable-isolation` *and* `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` together (not
either alone - attempt 2 tried disable-isolation alone, attempt 3 tried the persistence env var
alone under default isolation and hit the same `current_dir()` error, since isolation was hiding
the env var from the interpreted program), plus `PROPTEST_CASES=8` (D-63's already-established
scoped-Miri lesson: leaving `PROPTEST_CASES` at its default 256 is impractical under Miri's
interpretation overhead, unrelated to whether the run is actually stuck). Run against the same
Kupyna function: **completed cleanly in 28.01s, 1 passed.** Immediately re-ran the identical
combination against `hazmat::kalyna::fused_round_tests::fused_encipher_round_matches_naive_nb2`
(the same module T-130 was originally diagnosed against) to confirm the fix isn't Kupyna-specific
either: **completed cleanly in 28.87s, 1 passed.** Toolchain: `miri 0.1.0 (87e5904f5e 2026-07-20)`,
`nightly-x86_64-pc-windows-gnu` - the same toolchain T-130's three prior attempts used, so this is
a flag-combination fix, not a toolchain-version fix.

**Attempt 2's original "hung" read is corrected, not just superseded**: T-130 recorded ~35 minutes
wall time against ~0.8s of CPU on the `miri.exe` PID as "genuinely stuck." Re-checking the same
diagnostic on a fresh disable-isolation run this session (`Get-Process | Select Id, ProcessName,
CPU`) showed the `miri.exe` process had already accumulated **22.70s of CPU within about the first
30 seconds of wall time** - real, active computation, not stalled. Attempt 2 was very likely
progressing the entire 35 minutes (interpretation of a 256-case proptest run under Miri is simply
that slow) rather than deadlocked; it was never given the reduced `PROPTEST_CASES` or the
persistence-env-var fix that made attempt 4 tractable, so "stuck" and "slow" were never actually
distinguished at the time. Filed here as a general lesson for reading Miri CPU tea-leaves: with
`cargo miri test`'s parent/child process structure, check CPU across the whole `cargo`/`cargo-miri`/
`miri` process tree, not one PID in isolation, before concluding a run is deadlocked rather than
merely slow.

**Practical fix for any future `hazmat::kalyna`/`kupyna` Miri run on this Windows host**: set both
`MIRIFLAGS=-Zmiri-disable-isolation` and `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1`, and keep
`PROPTEST_CASES` low (8, matching D-63's precedent) for anything beyond a single quick function -
this is now a routine invocation pattern for this project on this host, not a one-off workaround.

**Follow-up, same session: full-module confirmation, not just the single-function proof.** Ran
`cargo +nightly miri test -p dstu-core --lib hazmat::kalyna::` (all three existing proptest modules
- `fused_round_tests`, `const_round_tests` (T-128's own new differential suite), and
`decrypt_fusion_tests` - 13 functions total) under the same fixed combination. **13/13 passed, 0
UB, finished in 511.16s (~8.5 min).** This is the Miri layer T-129/T-134/T-135's own done-bar
requires and that CI has never once produced (T-100) - now available locally on this host for the
module it matters most for. T-129 in particular (Tier C's most invasive Kalyna change) can now get
a real local Miri pass as part of its own safety net, not just the workspace test/clippy/fmt/
feature-matrix/fuzz layers T-128 shipped with.

## D-82: CMAC re-measured at 64 B with a timer-placement-fixed wrapper - T-138, and a real UAPKI CMAC-reuse quirk found in the process

Direct follow-up to D-80's GMAC timer-placement finding, requested by the perf/hygiene roadmap's
Tier A item 2: the currently-published 64 B/1 MiB CMAC table (`docs/PERFORMANCE.md`, "New command this
session, T-121") was measured by an earlier, uncommitted UAPKI wrapper this session never
inherited or inspected - no way to confirm from here whether it placed its timer correctly (before
or after `dstu7624_alloc`/`dstu7624_init_cmac`), the same ambiguity D-80 resolved for GMAC.

**Recipe** (scratch-only, not committed, per this project's standing "C comparisons aren't
committed" policy, `docs/PERFORMANCE.md`'s own "Reproducing the C comparisons" section): downloaded the
signed `uapki-v2.0.12-win-amd64-signed.zip` release asset (same as D-71/D-78), `gendef`/`dlltool`
to build an import lib, wrote a fresh `cmac_bench.c` against the vendored
`oracles/uapki/library/uapkic/include/dstu7624.h`/`byte-array.h` headers - `<variant> <key_path>
<in_path> <out_path> <iterations>`, printing `iterations=.. total_ns=.. per_op_ns=..` to stderr,
matching `uacrypt`'s own convention exactly. Timer placed explicitly after `dstu7624_alloc` +
`dstu7624_init_cmac` (the one-time Kalyna key-schedule expansion, analogous to `uacrypt`'s cached
`ExpandedKey`), matching D-80's fix and every other mode's wrapper convention.

**Byte-identity verified first, at `--iterations 1`** (fresh `ctx` per run): all 5 variants' tags
matched `uacrypt`'s own `kalyna-cmac compute` output exactly.

**A real correctness quirk found and confirmed before trusting multi-iteration timing, not
assumed**: wrote a standalone probe (`probe.c`) that calls `dstu7624_init_cmac` once, then
`dstu7624_update_mac`/`dstu7624_final_mac` four times in a row on the *same* message without
re-initializing - each of the 4 calls returned a **different** tag. Root cause, confirmed by
reading `dstu7624.c` directly: `cmac_final` computes the tag by reading `ctx->state` (the running
CBC-MAC chaining value) and `ctx->mode.cmac.last_block`/`lblock_len`, but never resets either
afterward - `dstu7624_init_cmac`'s call to `dstu7624_init` is the only code path that zeroes
`ctx->state`. Reusing a `ctx` across independent messages via `update_mac`/`final_mac` alone (no
reinit) silently accumulates stale chaining state from the previous message into the next
computation - a real API footgun in UAPKI's own C interface, not something to route around
silently: DSTU 7624's CMAC construction itself is correct, this is purely about how a *caller*
must sequence UAPKI's stateful update/final split for a fresh message (call `init_cmac` again, not
just `update_mac`/`final_mac`).

**This does not invalidate a multi-iteration throughput measurement, verified by reasoning about
the actual code path, not assumed**: `crypt_basic_transform` (Kalyna's block cipher, invoked by
both `cmac_update`'s chaining loop and `cmac_final`'s last-block encryption) has no secret- or
data-length-dependent branching (this project's own D-19 constant-time-table-lookup discipline,
and UAPKI's own implementation matches that shape) - so every iteration of the timed loop performs
the identical number of block-cipher invocations and memory operations regardless of what garbage
is in `ctx->state`. Only the *value* produced past iteration 1 is not independently meaningful;
correctness is established once, at `--iterations 1` with a fresh `ctx`, which is exactly what the
byte-identity check above already does. This is why the wrapper only writes out iteration 0's tag,
documented inline in `cmac_bench.c` itself rather than left implicit.

**Re-measured, N = 500000, 64 B, both directions**:

| Variant | uacrypt compute (MB/s) | UAPKI compute (MB/s) | uacrypt verify (MB/s) | Ratio |
|---|---|---|---|---|
| 128-128 | 161.21 | 120.98 | 131.96 | 1.33x |
| 128-256 | 119.40 | 99.53 | 101.75 | 1.20x |
| 256-256 | 95.10 | 87.19 | 83.44 | 1.09x |
| 256-512 | 74.33 | 72.98 | 67.16 | 1.02x |
| 512-512 | 67.80 | 46.65 | 62.02 | 1.45x |

**The real small-message lead is ~1.0-1.45x, not the previously-published ~6-8x** - the same
corrective shape D-80 found for GMAC (there ~4-24x claimed vs ~1.1-2.9x real), here even more
pronounced. `docs/PERFORMANCE.md`'s CMAC section updated with the corrected table and commentary, old
table left in place (not deleted) with the correction appended after it, matching this project's
own "don't silently overwrite, append the correction" convention already used for GMAC.

**Flagged, not chased further**: `uacrypt`'s own 64 B number jumped far more (29.92 → 161.21 MB/s
at 128-128, ~5.4x) than T-128's isolated round-function benchmark predicts (~51-54% i.e. ~2x at
`nb=2`) - the original 64 B row's exact `--iterations` count and wrapper vintage are unknown
(predates this session's numbering convention), so whether it shares some of GMAC's original bug
shape on `uacrypt`'s own side cannot be ruled out from here. Consistent with an already-flagged
pattern in this same file (the 10 MiB CMAC table's 128-128 jump also exceeded T-128's prediction) -
not treated as newly alarming, but not silently smoothed over either.

## D-83: The Kalyna-CMAC vs. UAPKI comparison wrapper is now committed - T-133, a deliberate exception to the "C comparisons aren't committed" policy

T-133 (formalize the byte-for-byte UAPKI comparison into a "committed, reusable script" rather
than an ad hoc habit) directly conflicts with `docs/PERFORMANCE.md`'s own "Reproducing the C
comparisons" text, which states these harnesses are deliberately *not* committed ("one-off, and
pulling in a full UAPKI build is a lot of scaffolding for something that isn't run again
regularly"). `CLAUDE.md`'s documentation map names `docs/PERFORMANCE.md` the canonical owner of
benchmark methodology - reversing that policy is not a sequencing detail the perf/hygiene
roadmap's own approval covers, so this was put to the project owner directly (`AskUserQuestion`,
2026-07-26) rather than decided unilaterally, even though the "isn't run again regularly"
rationale looked plainly outdated (this exact wrapper was rebuilt from scratch three times in one
week for T-131/T-133/T-138). **Answer: commit it.**

**What's committed**: `tests/oracle-harness/uapki-cmac-bench/cmac_bench.c` - the CMAC-only wrapper
built for T-138's 64 B re-measurement (see D-82), cleaned up with a full doc-comment header
(purpose, build recipe, usage, and the CMAC-context-reuse quirk D-82 found, so a future session
doesn't have to rediscover any of it). Matches this repo's existing `tests/oracle-harness/*`
convention (`kalyna-differential/`, `strumok-cross-check/`, etc. - source only, built fresh
on-demand) with one difference worth flagging: those siblings link against vendored oracle
*source* (`oracles/*`, itself gitignored per D-02/D-06 but present locally once fetched); this one
links against UAPKI's official prebuilt Windows DLL, which isn't vendored source at all - the
DLL/import-lib build step (`gh release download` + `gendef`/`dlltool`) is documented in the file's
own header, and the resulting `.dll`/`.def`/`.a` artifacts are gitignored
(`.gitignore` additions, same rationale as the pre-existing `*.exe`/`*.o` rules for this
directory). Rebuilt from the committed source and re-verified byte-identical against `uacrypt`
(128-128, `--iterations 1000`) before considering this done - the committed copy is not just
assumed to match the scratch version it was cleaned up from.

**Scope, deliberately narrow**: only CMAC is committed. The other 8 modes this project publishes
UAPKI comparisons for (block/GCM/GMAC/KW/XTS/CCM, plus Kupyna/Strumok) stay scratch-only/rebuilt-
fresh, per `docs/PERFORMANCE.md`'s now-updated methodology text - promote another mode's wrapper to
committed the same way if it starts recurring the way CMAC's did, rather than committing all nine
preemptively on the strength of one mode's pattern. `docs/PERFORMANCE.md`'s "Methodology" and
"Reproducing the C comparisons" sections, and the CMAC section's own "Reproducing" line, all
updated to reflect this specific exception rather than reading as a blanket policy reversal.

## D-84: T-136's encrypt/decrypt asymmetry confirmed to already show up at the isolated round-function level, at exactly the nb=4 boundary - cause still open

T-136 asked for "a `criterion` differential benchmark isolating `encipher_round_n::<4>` against
`fused_inv_round_n::<4>` alone (no surrounding mode-of-operation overhead)" as the first concrete
step toward explaining why Kalyna-block/XTS/KW's decrypt (or unwrap) direction runs *faster* than
encrypt specifically on the 256-256/256-512 variants (`nb=4`), and not on the 128-bit/512-bit
variants. **No new code was needed**: `benches/kalyna.rs`'s existing `_encrypt_block_only`/
`_decrypt_block_only` pairs (added for T-128, cached `ExpandedKey`, no key-expansion overhead) are
already exactly this isolated measurement - single block, schedule cached outside the timed loop,
nothing else in the call path. Ran `cargo bench -p dstu-core --bench kalyna -- block_only` and
read the existing numbers rather than duplicating them with new code.

**Result** (median of each 3-point CI):

| Variant (nb) | encrypt_block_only | decrypt_block_only | Faster direction |
|---|---|---|---|
| 128-128 (nb=2) | 73.04 ns | 83.84 ns | encrypt (~13% faster) |
| 128-256 (nb=2) | 102.34 ns | 114.39 ns | encrypt (~11% faster) |
| 256-256 (nb=4) | 225.35 ns | 197.39 ns | **decrypt** (~14% faster) |
| 256-512 (nb=4) | 287.11 ns | 248.49 ns | **decrypt** (~15% faster) |
| 512-512 (nb=8) | 463.49 ns | 631.19 ns | encrypt (~36% faster) |

**This answers T-136's own diagnostic question**: the asymmetry already shows up at the isolated
round-function level (no mode-of-operation bookkeeping, no I/O, no key-schedule cost) - so the
cause is confirmed to be in `encipher_round_n`/`fused_inv_round_n` themselves (or how they compile
at `nb=4` specifically), not in Kalyna-XTS/KW's surrounding mode-of-operation code, ruling out one
of T-136's two branches (mode-of-operation-level cause) directly rather than by inference. The
flip is sharp and specific to `nb=4` - `nb=2` and `nb=8` both favor encrypt, only `nb=4` favors
decrypt, on both variants that share it.

**Not resolved by this measurement, deliberately left open per T-136's own remaining candidates**:
*why* the round functions themselves are asymmetric at exactly `nb=4` - the inverse table
(`SBOX_MDS_DEC`) cache-line behavior, compiler codegen/register-allocation differences between the
two functions' `nb=4` monomorphization, or a branch-predictor/instruction-cache effect are all
still untested hypotheses from T-136's own text. This session's contribution is narrowing the
search space (confirmed round-function-level, not elsewhere) and providing an already-real
`criterion` baseline for whoever investigates further - not a root cause.

## D-85: T-134 - Kupyna `sub_shift_mix` const-generic-over-`COLUMNS`, direct T-128 analogue, done

Tier C's first item of the 2026-07-26 perf/hygiene roadmap (`docs/TASKS.md`), gated on its own
`advisor()` consultation and plan-mode pass, both done before any code was written. Same shape as
T-128/D-77 (`hazmat::kalyna`'s `encipher_round` -> `encipher_round_n<const NB>`): `sub_shift_mix`
and its per-round neighbors took a runtime `columns: usize` and an oversized `MAX_COLUMNS`(16)-wide
scratch buffer even though only two values are ever real - verified, not assumed, by grepping every
`KupynaCore::new`/`digest_generic`/`kmac_generic` call site (`kupyna.rs:337,351,362,394`,
`kupyna_kmac.rs:123-125` via `kmac_variant!`, `kupyna_kdf.rs:42-44`): the `(columns, rounds,
last_row_shift)` triple is exactly `(8,10,7)` or `(16,14,11)`, never a third combination
(Kupyna384Kmac reuses Kupyna-512's `(16,14,11)` state with a truncated 48-byte output, not a
distinct round shape).

**Design decision, from `advisor()`**: did not make `KupynaCore` itself const-generic. It's shared
by `kupyna.rs`, `kupyna_kmac.rs`, and (transitively) `kupyna_kdf.rs`; its `buffer`/`buffer_len`/
`total_len` fields are touched once per `update` call, not once per round, so genericizing the
whole struct buys no throughput while rippling a breaking signature change into every caller.
Instead: `KupynaCore` stays runtime-parameterized, and its two hot call sites
(`compress_block`, and `finalize`'s own direct `t_transform` call for the output transformation -
a second hot call site the original task note didn't separately name, added here since it's a
comparable share of total work to one `compress_block` call for single-block messages) each got a
2-arm `match self.columns { 8 => ..., 16 => ..., _ => unreachable!() }` dispatching into the
const-generic path - the match costs nothing (same arm every call for a given hasher, sits at the
per-block/per-finalize boundary, not inside the per-round loop).

**Implementation** (`crates/dstu-core/src/hazmat/kupyna.rs`): `sub_shift_mix_n`,
`add_round_constant_xor_n`/`add_round_constant_add_n`, `t_transform_n`/`t_plus_transform_n`
(`COLUMNS` and `ROUNDS` both const generics, paired one-to-one), `compress_n`, `bytes_to_columns_n`,
plus `state_array_mut_kupyna`/`h_to_array` (slice/copy-to-array coercions, copying
`hazmat::kalyna`'s `state_array_mut::<NB>` shape verbatim - `unreachable!` instead of
`.unwrap()`/`.expect()` only because `lib.rs` denies both crate-wide, D-19/SECURITY.md, not because
the conversion can fail). `compress_n`'s `t_input`/`q_input` are exactly `COLUMNS` wide, not
`MAX_COLUMNS` - the actual "2x wasted zeroing" fix for Kupyna-256, not just the round-loop trip
count. The runtime `sub_shift_mix`/`add_round_constant_xor`/`add_round_constant_add`/
`t_transform`/`t_plus_transform`/`compress`/`bytes_to_columns` are retained with `#[allow(dead_code)]`
as the differential-test reference (same treatment as `sub_bytes`/`shift_bytes`/`mix_columns`,
D-28) - all seven became genuinely unreachable from production code once `compress_block`/
`finalize` were rewired, which is why each now carries the attribute (missing on the first clippy
pass, caught immediately by `-D warnings`). `KupynaCore::rounds` is now unread (the match arms hard-
code `ROUNDS`) but kept as a stored field with a documented `#[allow(dead_code)]` rather than
removed, to avoid rippling a signature change into `kupyna_kmac.rs`'s call sites - out of this
task's scope per its own plan.

**Tests, written before the implementation** (test-first, `#[cfg(test)] mod const_shift_mix_tests`,
mirroring `hazmat::kalyna`'s `const_round_tests`, `kalyna.rs:681-729`): property tests over random
state proving `sub_shift_mix`/`compress`/`bytes_to_columns` match their `_n` twins exactly, for both
`COLUMNS ∈ {8, 16}` - 6 new tests, all passing on first write against the already-correct dynamic
reference (per `CLAUDE.md`'s standing note, this is expected, not a test-first violation). Full
workspace suite (`cargo test --workspace --all-features`, 300+ tests across both crates, including
the official `kupyna/*.json` and `kupyna-kmac/*.json` vectors) passed with no regressions.
`cargo clippy --workspace --all-features -- -D warnings` and `cargo fmt --all -- --check` both
clean. Full feature matrix built and clippy-checked individually (`--no-default-features`,
`--no-default-features --features alloc`, `--no-default-features --features small-tables`,
`--features small-tables`) - the `small-tables` combination matters here specifically since it
changes `forward_sbox_mds`'s table indirection, per `CLAUDE.md`'s standing caution about narrow
feature combinations hiding real warnings. Scoped `cargo +nightly miri test --lib hazmat::kupyna`
under T-130's confirmed-working flags (`MIRIFLAGS=-Zmiri-disable-isolation
PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 PROPTEST_CASES=8`): 8/8 passed, 0 UB, 180.64s.

**Measured before/after** (`cargo bench --bench kupyna`, fresh `kupyna-pre-t134-2026-07-27`
baseline saved before the first edit - the existing `kalyna-kupyna-fused-2026-07-22` baseline
predates T-128 and isn't a valid reference point on its own):

| Benchmark | Before | After | Change |
|---|---|---|---|
| Kupyna-256 / 64 B | 1.676 µs | 1.207 µs | **-28.9%** |
| Kupyna-512 / 64 B | 2.443 µs | 2.029 µs | **-17.0%** |
| Kupyna-256 / 1024 B | 11.396 µs | 8.163 µs | **-30.7%** |
| Kupyna-512 / 1024 B | 15.086 µs | 12.425 µs | **-18.9%** |
| Kupyna-256 / 65536 B | 660.20 µs | 474.13 µs | **-30.4%** |
| Kupyna-512 / 65536 B | 815.52 µs | 667.59 µs | **-18.7%** |

Matches T-134's own predicted-not-measured direction: Kupyna-256 (half-width, 8 of 16 columns) in
T-128's `nb=2`/`nb=4` range (~20-55%, measured ~29-31%); Kupyna-512 (already full-width) in T-128's
`nb=8` range (~15-22%, measured ~17-19%).

**Out of scope, flagged as a follow-up, not folded in here**: const-genericizing `KupynaCore`
itself would also halve its `h`+`buffer` footprint (256→128 bytes for Kupyna-256), a real memory
win for `docs/resource-profiles.md`'s MCU tiers - a distinct finding from this task's throughput
goal, not pursued in this diff per the same "deliberately narrow" discipline T-133 used (D-83).

**Binary-level UAPKI re-measurement, same day, on request**: the numbers above are `criterion`
(in-process); per D-34 that's internal regression tracking only, never a cross-implementation
claim. A fresh `kupyna_bench.c` wrapper (scratch-only, same UAPKI-prebuilt-DLL recipe as
`uapki-cmac-bench`, D-83) was built against `dstu7564_init`/`update`/`final`, called fresh *inside*
the timed loop every iteration to match `uacrypt`'s own `bench_in_memory!` (no schedule to exclude
here, unlike Kalyna's key expansion). Byte-identity verified before timing. Real, binary-level
before/after (64 KB/1 MiB/10 MiB, Ryzen, `docs/PERFORMANCE.md`'s Kupyna section has the full table):
`uacrypt`'s own throughput rose +41-47% (Kupyna-256) and +21-29% (Kupyna-512) across all three
sizes - consistent with (cross-validates, via an independent method) the `criterion` deltas above.
Against UAPKI specifically: Kupyna-256's former ~1.1-1.5x UAPKI lead is now closed to ~1.0-1.1x
(briefly ahead at 64 KB); Kupyna-512's gap narrows from ~1.45x to ~1.19-1.20x but doesn't close,
consistent with T-134's own prediction that Kupyna-512 (already full-width) had the smaller fix to
gain from.

## D-86: T-135 - Strumok `apply_keystream` batched/fixed-index rewrite, done

**Problem**: `hazmat::strumok.rs`'s `apply_keystream` XORed the keystream byte-at-a-time, with
`next_step`'s ring-buffer indices (`(head + k) & 15`) recomputed from a runtime `head` on every
single step - a real, avoidable overhead not present in `oracles/strumok-dstu8845/strumok.c`'s
`next_stream_full_crypt`, which batch-generates a full 128-byte (16-word) block per call using
literal state-slot indices and fuses the input XOR into the same pass at `u64` granularity. T-135's
own `docs/TASKS.md` entry (2026-07-26) identified this as the leading candidate for D-26's still-open
"remaining ~3.2x gap... a smaller, unchased residual" note.

**`advisor()` consulted before any code was written** (per the roadmap's own repeated instruction),
followed by a plan-mode pass - both this task's own process requirement, not assumed satisfied by
an earlier session's general roadmap sequencing call.

**Design chosen, and what was rejected**:
1. **One-time array rotation (`[u64; 16]::rotate_left`) to normalize `head` to `0`, not a 16-way
   const-generic dispatch on `head`** (the `hazmat::kalyna`/`kupyna` T-128/T-134 pattern, which
   would otherwise be the obvious "follow the established pattern" choice). Rejected specifically
   for code size: 16 fully-unrolled monomorphizations of a 16-step function is a different order of
   magnitude than T-134's 2 `COLUMNS` instantiations, and this project budgets flash down to 16-64
   KB STM32 parts (`docs/resource-profiles.md`) and ships a whole `small-tables` feature purely to
   save 16 KB - code-size discipline outranked pattern-resemblance here. The rotation is cheap in
   practice: a full 16-step batch is always a net-zero rotation (16 mod 16 == 0), so `head` stays
   `0` across every subsequent batch within a call and across calls in steady-state streaming use -
   the rotate fires at most once per `apply_keystream` call, usually never after the first. Note
   `rotate_left` does make a transient stack copy of secret LFSR state for that one call, the same
   category as the pre-D-26 `copy_within` this project moved away from - accepted deliberately here
   (bounded to at most once per call, not once per step, unlike the pre-D-26 cost) rather than
   treated as free.
2. **Three-phase `apply_keystream` (drain/bulk/remainder), `block: [u8; 8]` left unwidened.** The
   bulk path only runs once the existing 8-byte block buffer is empty/aligned; arbitrary chunk
   sizes and cross-call alignment (the `crypto_stream`/`uacrypt strumok-crypt` streaming use case)
   still work exactly as before, with no new secret buffer requiring `Zeroize`. Mirrors
   `dstu8845_crypt`'s own `>=128`-bytes/remainder split.
3. **The new `next_block` function is derived from *this project's* `strm`+`next_step` call order,
   not transcribed from the oracle's.** `next_stream_full_crypt` computes its output *after*
   updating `S[i]`, using the already-advanced `r0`/`r1`; this project's `apply_keystream` always
   called `strm` (pre-step state) *before* `next_step`. Each of the 16 unrolled steps was derived
   symbolically from that pair at `head = k` for `k = 0..16`, not adapted from the C by eye - the
   per-`k` index triples (`prev`/`p11`/`p13`) are spelled out explicitly in `next_block`'s doc
   table for auditability. Correctness is established by the new differential test (below), not by
   resemblance to the oracle.
4. **`chunks_exact(8)`/`from_le_bytes`/`to_le_bytes`, not a pointer cast**, for the 16 input/output
   words - `&mut [u8]` carries no alignment guarantee in Rust (unlike the oracle's
   `(uint64_t *)in` cast), so the cast pattern would be UB and a Miri finding. Same "port the
   calling convention, not just the internals" trap `CLAUDE.md` already records for DSTU 4145's
   `hash_to_field` (D-25), in a new guise.
5. No `#[cfg(feature = "small-tables")]` needed on `next_block` itself - it calls whichever
   `t_function` is already in scope, same as `next_step` does.

**Tests, written before the implementation was trusted** (`hazmat::strumok::tests`, a **unit test
module inside `strumok.rs` itself**, not `tests/strumok.rs` - an integration test only sees the
public `Strumok256`/`Strumok512` API, which no longer has the pre-T-135 code path to compare
against, so private access to `Core`/`strm`/`next_step` was required): a frozen
`scalar_reference_apply_keystream` (an exact, never-updated copy of the pre-rewrite byte-at-a-time
algorithm) as the oracle for two proptests (`strumok_256_batched_matches_scalar_reference`,
`strumok_512_batched_matches_scalar_reference` - random key/IV/data up to 600 bytes, fed both as
one whole-buffer call and via a randomly cycling sequence of chunk sizes up to 300 bytes, comparing
against the scalar reference's own whole-buffer output), plus two fixed, deliberately-constructed
tests: `boundary_lengths_match_scalar_reference` (lengths 127/128/129/135/256/263, straddling the
new 128-byte threshold) and `mid_word_carry_crosses_bulk_boundary_within_one_call` (a hand-picked
3-then-258-byte call split so the drain phase's leftover carry lands exactly at the point where the
*same* second call must enter the bulk path and then fall back to the scalar remainder - the one
handoff shape a single-shot or call-aligned test can't reach). All four passed on first write
(expected - coverage for already-written code, not red-green development, per `CLAUDE.md`'s
"rejection/misuse tests passing immediately" note applied here to a perf-motivated boundary rather
than a security one). The pre-existing official vectors, `apply_keystream_is_involution` proptest,
and `chunk_invariance_test!` in `tests/strumok.rs` all still passed unmodified. Full workspace
suite (`cargo test --workspace --all-features`), default-only and `--features small-tables`
individually (not just `--all-features`, per D-39's standing lesson), `cargo clippy --workspace
--all-features -- -D warnings` and `cargo fmt --all -- --check` (both clean after one
`clippy::unwrap_used` fix - `chunks_exact(8)`'s `try_into().unwrap()` was replaced with an explicit
`copy_from_slice` into a `[u8; 8]`, since this crate denies `unwrap_used`/`expect_used` crate-wide),
and the full `no_std`/`getrandom` build matrix (`cargo xtask build`) all passed. Scoped
`cargo +nightly miri test -p dstu-core --lib strumok` (`MIRIFLAGS=-Zmiri-disable-isolation
PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 PROPTEST_CASES=8`, T-130/D-81's confirmed-working
combination): 4/4 passed, 0 UB, 109.98s.

**Independent extra correctness signal, beyond this task's own plan**: re-ran the existing 4000-case
`tests/oracle-harness/strumok-differential/diff_against_outspace.c` harness (`cargo run --example
strumok_diff_cases -p dstu-core --release -- 2000 | diff_against_outspace.exe`) against the
rewritten implementation - **4000 cases checked, 0 mismatches**. This exercises the batched path
against outspace's own keystream computation directly, not just against this project's own frozen
scalar reference.

**Measured before/after, `criterion`** (`cargo bench --bench strumok`, fresh
`strumok-pre-t135-2026-07-27` baseline saved before the first edit - the existing
`strumok-optimized-2026-07-22` baseline predates this task):

| Benchmark | Change |
|---|---|
| Strumok-256 / 64 B | no change (−0.04%, within noise - 64 B never reaches the 128 B bulk threshold) |
| Strumok-512 / 64 B | +2.3% (small, real regression - the phase-check branches add a little overhead when the bulk path never fires) |
| Strumok-256 / 1024 B | **−53.5%** |
| Strumok-512 / 1024 B | **−53.7%** |
| Strumok-256 / 65536 B | **−64.7%** |
| Strumok-512 / 65536 B | **−64.7%** |

Per D-34, this is internal regression tracking only. The small 64 B regression is an accepted,
explicit tradeoff (three phase-boundary checks added to a path that used to be a single loop) for a
~2.2-2.8x speedup on any message actually large enough to hit the bulk path - not chased further,
since T-135 exists specifically for the large-message gap to outspace, not the 64 B case.

**Binary-level re-measurement, on this task's own plan (not optional)**: a scratch-only
`strumok_bench.c` wrapper (not committed, same "one-off C wrapper... not committed" convention
already documented for Strumok's binary comparisons) was built linking directly against
`oracles/strumok-dstu8845/strumok.c` (source, not a DLL - unlike the UAPKI comparisons, matching
`strumok-differential`/`strumok-cross-check`'s existing linkage convention). Its timer placement
mirrors `uacrypt strumok-crypt`'s own cached-schedule convention exactly (`dstu8845_init` happens
*after* `t0`, inside the timed window, amortized over `iterations` - matching
`run_strumok_command`'s `Core::new` placement in `crates/uacrypt/src/lib.rs`, not the stricter
"exclude all one-time setup" convention `uapki-cmac-bench` uses for a different comparison target)
so the two numbers are directly comparable. 10 MiB input, `--iterations 50` (this project's
established 10 MiB re-measurement convention), Ryzen, two runs each to check for noise:

| Variant | uacrypt (MB/s) | outspace (MB/s) | Gap |
|---|---|---|---|
| Strumok-256 | ~1823-1919 | ~2270-2329 | **~1.19-1.25x** (was ~3.2-3.9x pre-T-135, ~648.67 MB/s at the last 10 MiB measurement, T-128's pass) |
| Strumok-512 | ~1869-1877 | ~2270-2278 | **~1.21-1.22x** (was ~636.16 MB/s) |

The gap to outspace closes from ~3.2-3.9x down to roughly 1.2x - most of the T-135 target is
closed, not fully eliminated. Consistent with the expectation set before implementation: the FSM's
serial dependency chain (`r1_k = t_function(r0_{k-1})`) is unchanged and inherently sequential, so
this fix removes indexing/branching/byte-store-reload overhead (confirmed the dominant cost, given
the ~2.2-2.8x in-process speedup) but does not and cannot address the one structurally serial part
outspace's own fully-unrolled, compiler-scheduled code likely still has some remaining edge on
(e.g. instruction-level parallelism the Rust compiler schedules less aggressively across the
`next_block` macro-expanded steps than a hand-unrolled, hand-scheduled C function might). Not
investigated further here - T-135's own scope was the batching/indexing overhead specifically, not
closing the entire residual gap; a future task could dig into the remaining ~1.2x if it's ever
judged worth chasing.

**Confirmed the win reaches real callers, not just the `--iterations` benchmark path**: the
`--iterations 50` re-measurement above feeds the whole 10 MiB buffer to `apply_keystream` in one
call, so it's worth checking the actual single-pass paths chunk large enough to reach the new
128-byte bulk threshold at all. `uacrypt strumok-crypt`'s real (`iterations <= 1`) path streams
`--in` to `--out` in `STRUMOK_STREAM_CHUNK_BYTES`-sized pieces (`crates/uacrypt/src/lib.rs:2519`) -
8 KiB, i.e. 64 full 128-byte blocks per chunk, so the bulk path dominates real CLI usage well
before the tail. `dstu_core::crypto_stream::encrypt`/`decrypt` (`crypto_stream.rs`) call
`apply_keystream` once over the entire `Vec<u8>` message, so any message `>= 128` bytes reaches the
bulk path directly. Neither call site needed changes for this - both already fed `apply_keystream`
buffers wide enough to benefit.

## D-87: T-139 - investigated why outspace is still ~1.2x ahead post-T-135; hypothesis refuted by reading the actual asm, no code change

**Question, from the user, 2026-07-27**: after T-135/D-86 closed most of the gap to outspace
(~3.2-3.9x down to ~1.19-1.25x), why is outspace still a bit ahead?

**Initial hypothesis** (source-reading only, not yet verified): `Core::apply_keystream`'s bulk
loop (`strumok.rs:1024-1036`) round-trips every 128-byte block through memory twice - a pre-loop
copies `data` into a local `input: [u64; 16]` stack array, `next_block` reads `input[k]`/writes a
local `out: [u64; 16]`, then a post-loop copies `out` back into `data`. `oracles/strumok-
dstu8845/strumok.c`'s `next_stream_full_crypt(ctx, in, out)` does one fused unaligned load from
`in[i]`, XOR, one store to `out[i]`, directly against the caller's buffers - no staging array.
`next_block` also carried no `#[inline]` hint, unlike the oracle's `static inline`.

**`advisor()` redirected before any plan-mode/rewrite work**: don't plan a rewrite for an untested
hypothesis - the cheap, decisive experiment is a 2x2 (`#[inline(never)]` vs `#[inline(always)]` on
`next_block`, `criterion` at 65536 B, the size with the most bulk iterations and least setup
noise), and if that's ambiguous, read the actual `--emit=asm` output rather than guess further.

**The 2x2 was inconclusive** - not because the experiment was flawed, but because this machine's
measurement noise floor at the time was far wider than expected. A same-code rerun (no attribute
change at all, twice in a row) showed ~5-9% swings between separate `cargo bench` invocations -
wider than `advisor()`'s assumed ±3% band - so `#[inline(never)]`, `#[inline(always)]`, and the
unannotated default all landed within a few percent of each other, no clear winner or loser
distinguishable from noise.

**Fell back to reading the generated assembly** (`RUSTFLAGS="--emit=asm" cargo build --release -p
dstu-core --lib`, then `target/release/deps/dstu_core-<hash>.s`), which settled it decisively:
- **`next_block` has no separate symbol in the emitted `.s` at all** - grepping for it found only
  the calling `Core::apply_keystream` symbol (and the `Strumok256`/`Strumok512` thin `jmp` wrappers
  to it). LLVM inlined it, confirmed by absence, not inferred from behavior.
- **The `input`/`out` local arrays do not appear as a literal write-then-read-back memory
  round-trip.** The bulk-loop label's body (`.LBB32_19` in this build) is one long, deeply
  interleaved sequence of shifts/table-XORs operating on general-purpose registers, with `movq
  ..., NNN(%rsp)` spills scattered throughout - but those are the register allocator's own spill
  code for the ~18+ simultaneously-live values (16 state words + `r0`/`r1` + in-flight input/output
  words), not a semantically distinct "stage to `input`, compute, stage to `out`" sequence. SROA
  already fused it into the same computation graph the fusion rewrite would have hand-written.
- **The 128 `T0..T7`/`MUL_ALPHA`/`MUL_ALPHA_INV` table lookups per 128-byte block (8 lookups x 16
  steps) carry zero bounds-check branches** - each index is derived from a `u8` byte (`(w & 0xff)`,
  `(w >> 8) & 0xff`, etc.), providing the same array length as the table (`[u64; 256]`), so
  rustc/LLVM proves the access in-bounds statically and elides the check. The only `cmp`/`jae`
  found inside the bulk-loop label's own body is the outer `len - pos >= 128` loop-continuation
  test itself, executed once per 128 bytes, not per lookup. (`panic_bounds_check`/
  `slice_index_fail` calls do exist elsewhere in the function, but confirmed - by checking their
  line ranges - to live in the drain/remainder scalar per-byte sections, not the bulk-loop body.)

**Conclusion: the hypothesis was wrong. No fusion rewrite was written.** Both suspected sources of
overhead (double staging traffic, missed inlining) are already eliminated by LLVM at `-O2`/release
- writing the fusion by hand would at best reproduce what the compiler already generates, and at
worst measures as pure noise while being reported as a win, exactly the failure mode `advisor()`
warned against. Per `advisor()`'s own framing, this is a complete and valuable outcome for T-139,
not a failed task - the user's question is answered ("it's not the thing I suspected"), and the
repo doesn't gain unnecessary code churn on already-optimal output.

**What remains unexplained**: the actual ~1.2x residual gap's root cause is still open. The likely
remaining candidates - GCC vs. rustc/LLVM instruction scheduling/register-allocation differences on
this specific interleaved-dependency-chain shape, or something in how many registers are actually
live at once forcing different spill patterns between the two toolchains - would need side-by-side
GCC-emitted assembly for `next_stream_full_crypt` compared against the `.s` output analyzed here,
not another source-level Rust hypothesis. Not pursued further this session; flagged as the honest
open end if this residual is ever judged worth chasing (same posture T-136 already established for
its own still-open root cause).

**Verification**: no production code changed (the `#[inline(never)]`/`#[inline(always)]`
attributes used for the 2x2 experiment were both reverted; `next_block`'s signature and body are
byte-for-byte the same as T-135 left them, confirmed via `grep inline` returning nothing and the
existing test suite (`cargo test -p dstu-core --lib strumok --test strumok --all-features`, 10/10)
plus `cargo fmt --all -- --check` passing clean). Scratch `.s` dumps deleted after inspection, not
committed.

## D-88: T-129 - Kalyna word-wide gather investigated via a measured spike, not shipped; closes the Tier C perf roadmap

**Premise, from `docs/TASKS.md`'s own T-129 entry**: `encipher_round_n`/`fused_inv_round_n` gather state
one byte at a time via `state[src_col][row]`, recomputing `src_col` on every one of the `ROWS * NB`
iterations, versus UAPKI's `p_boxrowcol` table plus `BT_xor128`/`BT_xor256`/`BT_xor512` macros,
which load/XOR whole 64-bit words. This was the fifth structural difference named comparing
`encipher_round` against UAPKI's C directly (2026-07-26), left open by T-128's const-generic
refactor as a "genuinely different, more invasive restructuring" not attempted there.

**`advisor()` consulted before any plan-mode pass, per this project's standing practice for
`hazmat::kalyna.rs` changes.** Its first and most consequential finding: the premise was already
partly checked by reading `encipher_round_n::<8>`'s actual `--emit=asm` output before the consult
(the same discipline established for T-139/D-87 an hour earlier in the same session) - and found
partly false, mirroring D-87 exactly. The compiled function is 64 single-byte loads at **literal,
compile-time-folded offsets** (e.g. `movzbl 57(%rcx), %edx`) - `NB` being const already eliminated
the "`src_col` recomputed every iteration" cost entirely, the same way T-128's own const-generic fix
did for the runtime-`nb` version. **Zero bounds-check branches** survive (each index is `u8`-
derived, statically provable within `0..256`). One shared table-base register with fixed `+0/2048/
…/14336` offsets (`SBOX_MDS`'s 8 row-tables are laid out contiguously, so no per-row address
recomputation is needed). 8 interleaved XOR-accumulator register chains give the scheduler
instruction-level parallelism across output columns. This is not a naive byte-wise gather - it is
already close to what a hand-optimized version would produce.

**`advisor()`'s redirect, mirroring T-139's own lesson explicitly**: don't plan the rewrite, spike
it - and predicted, before any measurement, that hoisting whole-column-word loads could plausibly
*regress* `NB=8` specifically (8 live input words + 8 accumulators + temporaries against ~14-16
GPRs) even if it helped smaller `NB`, and that `NB=2`/`NB=4` (not yet examined, since only the
`NB=8` monomorphization survives as a standalone symbol) needed checking separately since T-128's
own per-`nb` deltas were largest at `nb=2` and smallest at `nb=8`.

**The spike, applied and measured, not just reasoned about**: `encipher_round_n` was temporarily
changed to `let words: [u64; NB] = core::array::from_fn(|c| u64::from_le_bytes(state[c]));` once
per round, replacing `state[src_col][row]` with `((words[src_col] >> (row * 8)) & 0xff) as u8`.
Same-source, before/after `--emit=asm` comparison for all three monomorphizations:

- **`NB=2`**: **zero measurable difference.** `encrypt_with_schedule::<2>`'s inlined body (which
  contains `encipher_round_n::<2>` inline, confirmed no separate symbol exists at this size either
  before or after) is byte-for-byte identical in instruction count (207 lines, 7 spills, 19 stack
  references, both before and after). Reading the *baseline* body directly showed why: byte
  extraction already happens via register-to-register `movzbl %r11b, %r11d`-style moves from an
  already-loaded 64-bit value, not fresh memory reloads - LLVM's own SROA/mem2reg had already
  performed the equivalent transformation the spike tried to force by hand.
- **`NB=8`**: **a measurable regression.** The clean baseline (64 direct single-byte loads, 0 spill
  stores) became 0 direct-memory byte loads but **34 new spill stores and 71 total stack
  references** (vs. 0 and 34 respectively in the baseline - roughly double the total memory
  traffic). Holding 8 live 64-bit column words simultaneously, on top of 8 output accumulators and
  round-key temporaries, exceeds the available general-purpose register file - exactly the failure
  mode `advisor()` predicted before the spike was run, not discovered after the fact and
  rationalized.
- **`NB=4`**: **a regression in kind.** The spike changed LLVM's own inlining decision:
  `encipher_round_n::<4>` stopped being inlined into `encrypt_with_schedule::<4>`'s round loop
  (416 lines, no separate symbol, in the baseline) and became a real, separately-defined function
  reached via `callq` (76-line caller plus an out-of-line callee, in the spiked build) - introducing
  real call/return overhead into what is currently a fully-inlined hot loop. Exact magnitude not
  separately quantified (would need the callee's own body measured on its own), but the direction
  is unambiguous and consistent with the `NB=8` finding: the extra `[u64; NB]` array construction
  makes the function look larger/costlier to LLVM's inliner, at exactly the size where the decision
  was already marginal.

**No code change shipped.** Three monomorphizations, three no-help-or-regression outcomes is a
decisive result, not an inconclusive one - per the same framing `advisor()` gave for T-139/D-87,
"the hypothesis was wrong" is the complete and valuable outcome for T-129 too, not a reason to force
a change that measurably makes the hot path worse at the two block sizes where it does anything at
all. `hazmat::kalyna.rs` is unchanged from before this investigation - confirmed via `git diff`
showing no delta (not merely "should be," verified directly), plus `cargo test -p dstu-core --lib
kalyna --all-features` (13/13, including `const_round_tests`/`fused_round_tests`/
`decrypt_fusion_tests` for all three block sizes) and `cargo fmt --all -- --check` both passing
clean after reverting.

**Why `criterion` wasn't used to validate this**: the same session's T-139/D-87 investigation had
already established this machine's noise floor at ±5-9% between back-to-back runs of *identical*
code - wider than the 5-15% range a real effect at this level would plausibly move things by. Using
asm/spill-count evidence instead of a noisy benchmark number, and saying so explicitly, follows
`advisor()`'s own explicit instruction from that same consult rather than dressing up an
unreliable delta as a result.

**This closes the entire Tier C perf/hygiene roadmap** (`docs/TASKS.md`'s "RESUME HERE" section,
2026-07-27): T-128/T-134/T-135 shipped real, measured wins; T-136's asymmetry (first measurement
done, deeper root cause still open as its own standalone task) and T-129's gather (investigated,
explained, not rewritten) both ended without further code changes. A perf-investigation roadmap
ending with two "measured, hypothesis didn't hold" outcomes alongside three real wins is a
legitimate, complete way for it to close - not a shortfall against what the roadmap set out to
check.

## D-89: T-136 deeper pass - Kalyna's `nb=4` encrypt/decrypt asymmetry narrowed to register-allocation pressure, not table/branch-predictor effects; root cause still not fully mechanistic

**Background**: `docs/DECISIONS.md` D-84 (2026-07-26) confirmed T-136's asymmetry - decrypt beats
encrypt by ~14-15% at `nb=4` specifically (256-256/256-512), the opposite direction from `nb=2`
(~11-13% encrypt-favors) and `nb=8` (~36% encrypt-favors) - already shows up at the isolated
round-function level (`ExpandedKey::encrypt_block`/`decrypt_block`, cached schedule), ruling out a
mode-of-operation-level cause. The remaining candidates the task itself named: `SBOX_MDS`/
`SBOX_MDS_DEC` cache-line behavior, compiler codegen/register-allocation differences, or branch-
predictor/instruction-cache effects.

**This pass, same session as T-129/D-88, same method**: read `--emit=asm` output for
`encrypt_with_schedule::<4>` and `decrypt_with_schedule::<4>` directly (both fully inline their
respective round function at `NB=4` - no standalone `encipher_round_n`/`fused_inv_round_n` symbol
exists at this size, confirmed by grep). Isolated each function's repeated round-loop body (the
code between the loop label and its own back-edge `jne`), excluding `decrypt_with_schedule`'s extra
one-time boundary passes (`apply_inverse_matrix`/`inv_shift_rows`/`inv_sub_bytes` - real, structural
extra work decrypt does that encrypt's simpler whitening doesn't need, D-30's own equivalent-
inverse-cipher restructuring, not a mystery) so the comparison is round-loop-to-round-loop, not
whole-function-to-whole-function.

**Two of the three candidates are directly ruled out, not just deprioritized**:
- **Branch predictor**: neither loop body contains a single conditional branch - both are
  straight-line code between the loop's own back-edge jump (same shape T-129/D-88 already found
  for `encipher_round_n::<8>` in isolation - `NB` being const-generic eliminates all the index
  arithmetic that would otherwise need branches).
- **Table/cache-line behavior**: both loops index the same shape of table (`SBOX_MDS`/
  `SBOX_MDS_DEC`, 8 contiguous 256-entry `[u64; 256]` rows, one shared `leaq`-loaded base register
  reused via fixed `+0/2048/…/14336`-style offsets) - no structural difference in how either table
  is accessed.

**Points at register-allocation pressure specifically, measured, not inferred**: isolating just the
round-loop body at `NB=4`, encrypt's loop has **20 spill stores and 77 total stack references**;
decrypt's has **14 spill stores and 48 total stack references** - roughly 40% more spill traffic
for encrypt despite both loops doing the same count of gather-XOR operations per round (28 XOR/pack
instructions each, confirmed matching). This correlates with, and is a plausible cause of, the
measured ~14-15% timing gap - more spill/reload traffic per round directly costs cycles.

**Not fully mechanistically explained.** *Why* LLVM's register allocator produces more spill-
forcing live ranges for the forward round's `(out_col + NB - shift) & nb_mask` index arithmetic
than the inverse round's `(out_col + shift) & nb_mask` - despite both being equally simple modular
arithmetic over the same constant `NB=4` - isn't derived here. Pinning that down would need an
instruction-by-instruction diff of the two loop bodies (which register holds which partial sum
across which range of instructions), not attempted this pass. Also not run: the task's own
predicted cross-check (whether the effect moves or disappears on the Raspberry Pi's different
microarchitecture - a register-allocation-driven cost is intuitively less portable across
architectures than a genuinely algorithmic one, making this a real, checkable discriminator not yet
exercised).

**Process note**: `advisor()` returned "temporarily overloaded" when consulted for this pass, so
this stayed pure investigation (no plan-mode gate needed, since no code was written or considered -
the same posture T-136's own task text already sets, "performance-curiosity, not gating any
release-readiness item"). A future session picking this up further should still get an `advisor()`
opinion before treating "diff the two loop bodies instruction-by-instruction" as an actionable next
step, rather than extrapolating a fix from this asm reading alone - this pass narrows the
*category* of cause (compiler codegen/register allocation, not algorithm or hardware-branch-
prediction), it does not yet identify a *specific, actionable* fix, and per D-87/D-88's own lesson
this session, an unmeasured intuition about what would help register allocation is exactly the kind
of thing that needs a spike-and-measure check, not assumption, before any code is written.

**No code changed.** `hazmat::kalyna.rs` untouched (confirmed via `git diff`, no delta).

## D-90: T-137 - two UAPKI local fixes drafted (Kalyna XTS tweak-doubling, Strumok byte-at-a-time consumption), both verified against UAPKI's own self-tests plus a Strumok differential against outspace - not opened upstream

**Scope**: T-137 is explicitly framed as "work out whether the fix is real, draft it, verify it
locally, then check back with the user before opening anything on `specinfo-ua/UAPKI`" - this
entry records that verification work, not a decision to publish anything. Both `oracles/uapki/`
source files touched are entirely gitignored in this project (confirmed via `git status --ignored`)
- the patches exist only in this local working directory.

**Fix 1 - Kalyna XTS tweak-doubling** (the task's original finding, T-131/D-78). `encrypt_xts`/
`decrypt_xts` in `oracles/uapki/library/uapkic/src/dstu7624.c` call the fully generic `gf2m_mul`
(3 heap-allocated `WordArray`s, full O(m²) `gf2m_mod_mul`) every block, always to multiply the
tweak `gamma` by the fixed generator `two` (`two[0]=2`, the field element `x`). Read `gf2m_mul`,
`gf2m_mod_mul`, and `Gf2mCtx`'s `f`/`f_ext` fields directly (not assumed) to confirm: multiplying a
polynomial-basis GF(2^m) element by `x` is a single left-shift of the whole bit-vector, with one
conditional XOR of the reduction polynomial's low-degree terms substituted for the `x^m` term that
shifted out of range, only when the pre-shift top bit was set - O(m/64) word ops, not O(m²).
Confirmed this is the **exact same field and reduction polynomial** `dstu-core`'s own
`hazmat::gf2m_wide.rs` `Gf2m128/256/512::double()` already implements for GCM/GMAC (T-126/D-76):
`dstu7624_init_xts`'s `f[]` triples (`{7,2,1}`/`{10,5,2}`/`{8,5,2}` for block_len 16/32/64) are
byte-identical to `dstu7624_init_gmac`'s - confirmed by reading both initializers side by side, not
assumed from the shared field size alone. Also confirmed the byte/word convention matches
(`gf2m_wide.rs`'s own module doc already derived this from `uint8_to_uint64`'s plain little-endian
`memcpy`, the same conversion `gf2m_mul`'s wrapper uses) - reused that citation rather than
re-deriving it, per `CLAUDE.md`'s calling-convention-matters lesson.

Added `gf2m_double(Gf2mCtx *ctx, size_t block_len, uint8_t *arg, uint8_t *out)` as a new sibling
function directly after `gf2m_mul` - no WordArray/heap allocation at all, a local `uint64_t
words[8]` stack buffer, `uint8_to_uint64`/`uint64_to_uint8` for the byte conversion (reusing UAPKI's
own existing endian-safe helpers rather than a raw pointer cast), the identical shift-carry-reduce
loop `Gf2m*::double()` uses, reduction terms read from `ctx->f[1..3]` at runtime (not hardcoded per
block size, so it's correct for whichever `Gf2mCtx` it's called against). Repointed all 5 XTS call
sites that multiplied by `two` (`encrypt_xts` x2, `decrypt_xts` x3, one of which chains a second
doubling into a scratch buffer) to `gf2m_double` instead - `gf2m_mul` itself and all GCM/GMAC call
sites (which multiply by a genuinely variable secret value, not a fixed constant) are untouched,
confirmed by grep showing every remaining `gf2m_mul(` call site is GCM/GMAC's.

**Fix 2 - Strumok's byte-at-a-time consumption** (user-requested 2026-07-27, same session,
extending T-137's scope directly off T-135's own just-shipped fix). Read `oracles/uapki/library/
uapkic/src/dstu8845.c`'s `dstu8845_crypt` directly: `next_gamma()` already batch-generates a full
128-byte (16-word) `ctx->gamma[16]` block, but the consuming loop was `while (in_len--) { *in++ ^=
gamma[ctx->gamma_cntr++]; if (ctx->gamma_cntr == 128) next_gamma(ctx); }` - one byte, one bounds
check, at a time. This is the identical gap `dstu-core`'s own `hazmat::strumok.rs` `apply_keystream`
had before T-135 (D-86) - UAPKI already does the "batch-generate a full block" half of the fix but
not the "consume it word-at-a-time" half. Restructured into the same three-phase shape T-135
established: drain to an 8-byte `gamma_cntr` boundary byte-at-a-time (whatever partial word is
left), then `memcpy` 8 bytes into a `uint64_t`, XOR against `ctx->gamma[gamma_cntr/8]` (a real
`uint64_t[16]` struct field - no alignment concern, unlike a raw `uint8_t*` reinterpretation would
have), `memcpy` back, advancing 8 bytes at a time while a full word remains before the next
128-byte regeneration, remainder byte-at-a-time. Loops correctly across multiple regenerations
within one call (traced by hand for a 250-byte tail crossing two `next_gamma()` calls, then
confirmed empirically, see below) - `next_gamma()` resets `gamma_cntr = 0` internally, so the bulk
loop's own `ctx->gamma_cntr < 128` condition re-admits the freshly generated buffer without any
extra bookkeeping. `next_gamma`, key schedule, and IV setup are untouched.

**Verification, both fixes together, compiled directly with gcc/MinGW** (the vendored `oracles/
uapki/` clone is missing `rc-version.h.in`, blocking the CMake path - `cmake -G "MinGW Makefiles"`
failed on `configure_file` for that reason; compiling `uapkic/src/*.c` directly, the same approach
already used for `uapki-cmac-bench`'s DLL-free siblings, avoided the issue entirely):

- `dstu7624_self_test()` (covers all of ECB/CBC/CFB/OFB/CTR/CMAC/KW/CCM/GCM/GMAC/XTS, including
  `dstu7624_xts_self_test`'s 10 official fixed vectors) and `dstu8845_self_test()` (8 fixed Strumok
  vectors) both return `RET_OK` with both fixes applied simultaneously.
- **Each fix's self-test was confirmed capable of catching a real bug, not just passing vacuously**
  (the same discipline this session's D-88/D-89 asm-reading work already established for measured
  claims): a deliberately wrong reduction constant in `gf2m_double` (`words[0] ^= 3` instead of
  `^= 1`) made `dstu7624_self_test()` return 33, not 0; a deliberately wrong word index in the
  Strumok bulk loop (`gamma[(gamma_cntr/8) ^ 1]` instead of `gamma[gamma_cntr/8]`) made
  `dstu8845_self_test()` fail the same way. Both reverted immediately after confirming, correct
  code re-verified passing before moving on.
- **Strumok fix additionally cross-checked against outspace directly**, not just UAPKI's own 8
  fixed vectors: outspace's `strumok.c` compiled to a separate object file with `-D` renames
  (`dstu8845_alloc` -> `outspace_dstu8845_alloc`, etc.) to avoid a symbol clash when linked into the
  same test binary as UAPKI's own same-named functions. 16 one-shot lengths straddling the 128-byte
  threshold (1/7/8/9/63/64/65/127/128/129/135/200/256/260/384/500) x both key sizes, plus 2
  multi-call chunk-split cases deliberately crossing the 128-byte gamma-regeneration boundary
  mid-call and mid-drain - all matched byte-for-byte. **One initial "mismatch" traced to a hand-
  typed arithmetic error in the test harness itself** (`130 + 9 + 250` instead of `130 + 8 + 250`
  for a 10-chunk split with eight 1-byte chunks in the middle - undercounting the declared total by
  one byte left the buffer's last byte never processed on the UAPKI side while outspace's one-shot
  call processed the full declared length) - isolated by comparing the patched function against a
  frozen copy of the original byte-at-a-time algorithm directly (not the outspace comparison, to
  rule out which side had the bug), confirmed the patch itself was correct and the harness had the
  off-by-one, fixed the harness, re-ran clean. Consistent with this project's own standing note
  (`CLAUDE.md`) that an unexplained transform needed to make a test pass is suspect until the actual
  cause is found, not just patched over.
- `dstu7624_xts_self_test`'s pass is itself the confirmation that GCM/GMAC's `gf2m_mul` call sites
  are unaffected, since `dstu7624_self_test()` runs GCM/GMAC's own self-tests in the same call.

**Not done, deliberately**: no criterion/binary-level timing re-measurement of either fix against
UAPKI (that's a separate re-confirmation step, not needed to establish correctness, and this task's
own gate is about correctness/safety before any upstream step, not a fresh performance claim).
Reading UAPKI's `CONTRIBUTING`/license/PR conventions - the stated prerequisite for actually
drafting a PR - was not done this pass either. **Nothing opened upstream** - both fixes stay local
drafts pending the user's own next decision, per this task's standing, unchanged gate.

## D-91: T-137 - PR opened on specinfo-ua/UAPKI (explicit user request), gate cleared

**Explicit go-ahead**: the user asked directly to check UAPKI's PR rules and open a pull request
with our changes plus tests, following their project's own structure/files - this is the "check
back with the user before opening anything" step D-90 held open, now satisfied. This entry records
the mechanics of actually doing it, not a new correctness finding (D-90 already has that).

**Checked UAPKI's contribution conventions before doing anything else, not assumed**: `gh api
repos/specinfo-ua/UAPKI` and its `.github`/root/`library` contents - no `CONTRIBUTING.md`, no PR
template, only a CI workflow under `.github/workflows`. License is BSD-2-Clause (permissive,
confirmed from `LICENSE`). Recent merged PR titles (`gh pr list`) follow a loose `MODULE: short
description` convention, mixing Ukrainian and English - matched that shape for this PR's title.

**Found the local vendored `oracles/uapki/` clone is stale relative to current upstream** -
important enough to flag on its own. A line-by-line `diff` between the vendored copy and a fresh
`main` clone initially showed the *entire* file as different; tracing it down (via `file` and
`diff --strip-trailing-cr`) showed the real cause was CRLF-vs-LF line endings, not content drift -
after normalizing line endings, the only real differences were exactly the two patches D-90 already
made. Confirmed by exact line-number match (`gf2m_mul`/`encrypt_xts`/`decrypt_xts` at the identical
line numbers in both). This means the underlying algorithm/structure hadn't changed upstream since
the vendor was fetched, but the encoding/formatting had - re-applying the patch by hand-copying from
the stale vendor without checking this first could have silently introduced a CRLF/LF mismatch or
missed a real upstream change. Re-derived and re-applied both patches fresh against the actual
current `main`, not copy-pasted from the stale vendor.

**Mechanics**: `gh repo fork specinfo-ua/UAPKI --clone=false` (fork to `user137/UAPKI`, none
existed before), shallow-cloned it into a scratch directory (kept fully separate from this
project's own `oracles/uapki/`, which stays untouched and gitignored), created branch
`fix/xts-strumok-fast-path`. Re-applied via PowerShell (not the Edit tool, which doesn't preserve
CRLF/BOM byte-for-byte the way this repo's files need) both D-90 patches plus a new addition
requested for this pass: a 200-byte `dstu8845_self_test` case (Strumok-256, `key256_1`/`iv_1`,
crossing the 128-byte gamma-regeneration boundary once) - the existing 8 fixed vectors are all
exactly 64 bytes and never exercise more than one `next_gamma()` call per `dstu8845_crypt`
invocation, so none of them would have caught a boundary-crossing bug in the bulk-XOR restructuring.
Generated the expected 25-word output using the already-validated patched implementation itself
(trusted per D-90's extensive differential testing against outspace) - its first 8 words matched
the existing `k256_1_iv_1` vector byte-for-byte, an unplanned but welcome internal cross-check that
the 200-byte extension is consistent with the already-trusted 64-byte value, not just internally
self-consistent.

**Caught and fixed two accidental side effects from the PowerShell-based patching, before
committing, not after**: (1) writing the file back re-encoded it, which silently dropped
`dstu8845.c`'s original UTF-8 BOM (`EF BB BF`) - confirmed by comparing first bytes against `git
show HEAD:...` rather than assuming encoding round-tripped cleanly, then rewrote with the BOM
explicitly restored so the diff wouldn't carry an unrelated whole-file encoding change. (2) the new
`gf2m_double` function was missing the blank line separating it from the following `encrypt_xts` -
cosmetic, but fixed before commit rather than left as PR noise. Re-verified both self-tests
(`dstu7624_self_test`/`dstu8845_self_test`, including the new 200-byte case) and the outspace
differential all still pass after both fixes, compiled directly from the fork clone (not the stale
vendor) - not assuming the copy-over preserved correctness, checking it directly.

**Also re-ran the same negative check D-90 already established, against the fork's own copy**:
deliberately corrupted the new 200-byte vector's last word, confirmed `dstu8845_self_test` fails
(not vacuous), reverted, re-confirmed clean.

**Result**: PR opened - **https://github.com/specinfo-ua/UAPKI/pull/30**, title "UAPKIC: fast paths
for Kalyna-XTS tweak doubling and Strumok gamma consumption", body explains both findings and both
patches in the structure the user asked for (what was found, what was changed, how it was
verified), written in English to match this project's own mixed-language PR precedent on the
upstream repo. `git diff --stat` on the fork branch: 2 files changed (`dstu7624.c`, `dstu8845.c`),
121 insertions / 6 deletions - no other files touched. This project's own `oracles/uapki/` (the
stale vendor) was never modified as part of opening the PR - it remains exactly as D-90 left it,
gitignored, a separate concern from the fork.

## D-92: T-137 - SonarCloud CI on the UAPKI PR, two follow-up rounds to green; T-140 opened for this project's own Rust equivalent

**CI ran automatically on PR #30** (specinfo-ua/UAPKI has SonarCloud wired into `.github/workflows`
already) and failed the Quality Gate on first push: one BLOCKER (`c:S3519`, "memory access should
be explicitly bounded to prevent buffer overflows") plus 3 MINOR code-smell findings, all in the
new code this PR added.

**Round 1 fix - addressed the MINOR findings directly, attempted the BLOCKER by pattern-matching
the obvious fix**: made `gf2m_double`'s `ctx`/`arg` parameters `const` (both read-only, matching
`gf2m_mod_mul`'s own existing const-correctness elsewhere in the same file), split a combined
`uint64_t carry, next_carry, top_bit;` declaration into one identifier per statement. For the
BLOCKER, changed `if (ctx->gamma_cntr == 128)` to `>= 128` in all three loops - reasoned (and
confirmed via `assert()` across the existing 32+-case differential/self-test suite) that the
equality check was safe given the invariant, but SonarCloud's symbolic execution couldn't prove it
across the new bulk loop's compound condition, and an equality check gives no safety margin if
that invariant is ever violated by a future change - `>=` is behaviorally identical, strictly more
robust. Discovered incidentally that this fix made `two[0] = 2` (and the whole `two` buffer in
`encrypt_xts`) dead code, since `gf2m_double` never takes the multiplier as an input - removed
both. Pushed, re-ran locally (`-Wall -Wextra` clean, both self-tests, outspace differential all
still green) before pushing.

**Round 1 result: still failed, same BLOCKER, same line.** Read the actual symbolic-execution
trace via SonarCloud's public issues API (`api/issues/search`), not just the summary comment - it
showed the analyzer exploring a path where the bulk loop's *own* condition (`ctx->gamma_cntr <
128`) is assumed false specifically because `gamma_cntr` is already `>= 128`, **before the loop
body ever executes even once**, then falling through to the remainder loop with that assumption
intact. The `==`-to-`>=` change inside each loop body was irrelevant to this specific path, since
no loop body runs on it at all - the real question the analyzer is asking is "what does this
function know about `ctx->gamma_cntr`'s value on entry," and the answer, from a purely
intraprocedural view, is nothing: the invariant that `gamma_cntr` stays in `0..127` is maintained
across `next_gamma()`/`dstu8845_crypt` call history, not established anywhere within this one
function. This almost certainly also explains why the *original*, byte-identical remainder loop
was never flagged before this PR - as unchanged code with no local diff, it wasn't scored against
the "New Code" Quality Gate, even though the same absence-of-local-proof already existed there.

**Round 2 fix - established the invariant locally, at the point of entry**: added `if
(ctx->gamma_cntr >= 128) { ctx->gamma_cntr = 0; }` as the first statement after `gamma`/`in`/
`in_len` are read, before any of the three loops. Purely defensive (the value this "corrects" can
only be exactly 128, never observed given the actual invariant) but gives the analyzer (and any
future reader) a fact it can verify by reading four lines, not by trusting call history across two
functions. Re-verified locally (self-tests + outspace differential, `cppcheck --enable=warning,
style` also clean, though weaker than SonarCloud's own engine and not treated as equivalent
confirmation) before pushing.

**Round 2 result: `SonarCloud Code Analysis` and `SonarCloud` both `pass`** (`gh pr checks 30`) -
PR fully green, no further findings.

**Process note, why this took two rounds instead of one**: the first fix addressed a plausible-
looking but not the actual mechanism SonarCloud's checker uses - confirmed only by reading the
tool's own symbolic-execution trace (`flows` array in the issues API response) rather than
guessing from the one-line message a second time. The same "read the actual trace/output, don't
pattern-match a fix from the summary" discipline this session already used for `--emit=asm`
investigations (D-87/D-88) applies just as much to a third-party static analyzer's findings.

**Follow-up recorded as its own task, not folded into this one**: `docs/TASKS.md` T-140 - the user
asked, mid-session, whether SonarCloud could be added to this project's own GitHub CI for Rust
specifically, prompted directly by watching it catch something neither `clippy` nor manual review
had for the UAPKI C code. Confirmed via web search (not recalled): free for public repos, Rust
support since April 2025 via wrapping ~85 `clippy` lints (not an independent analyzer), "Automatic
Analysis" doesn't support Rust so it needs an explicit `sonar-scanner` CI step, and the account/
org-creation step is a hard blocker on the user's own GitHub OAuth action - not something this
agent can perform. `cppcheck` (2.21.0) confirmed already installed locally as a lighter-weight,
offline pre-check option in the meantime, alongside the `cargo clippy` this project's CI already
requires.

## D-93: T-140 - SonarCloud account/token wired up same day, project key/org confirmed via API rather than guessed

**Sequence, same session as D-92's scaffold**: the user created the SonarCloud org/project via
GitHub OAuth (the step D-92 flagged as a hard blocker on the user, unchanged) and pasted the
generated token directly in chat, rather than setting it themselves via `gh secret set` or the
GitHub web UI - the path this task's own text had explicitly recommended to avoid exactly this.
Since it had already happened by the time it was seen, the response was to handle it as carefully
as possible from that point forward, not to re-litigate the ask: the token was never echoed back
or printed in any tool output or file, and was set via
`printf '%s' "$TOKEN" | gh secret set SONAR_TOKEN --repo user137/uacrypt` (reading from stdin) not
`gh secret set SONAR_TOKEN --body "$TOKEN"` (a literal CLI argument, more likely to surface in a
process listing or shell history than data piped to a command's stdin). Confirmed set via
`gh secret list --repo user137/uacrypt` (name and update timestamp only - GitHub's own API design
never re-displays a secret's value once set, by design, not something this session's own care
achieved).

**`sonar.projectKey`/`sonar.organization` resolved via SonarCloud's own API, not the GitHub-
username convention assumed and left as a placeholder in D-92**: `GET
api/organizations/search?member=true` (using the now-configured token) returned org key `user137`;
`GET api/projects/search?organization=user137` returned project key `user137_uacrypt`. Both happen
to match the guessable `<github-username>`/`<username>_<repo>` pattern the SonarCloud OAuth flow
typically produces, but this was confirmed from the account's own actual state, not assumed from
that pattern holding - the same "verify, don't guess project-specific properties" standard D-92
itself already called for.

**Still open, honestly**: the workflow has not been observed running successfully - that requires
an actual push/PR to trigger `.github/workflows/sonarcloud.yml` for real, which didn't happen
within this session. First real trigger (next push to `master`, or the next PR) is the actual
end-to-end confirmation, not yet claimed here.

**A worth-repeating note for future sessions, not just this one**: a secret handed directly in
chat should be treated as needing rotation regardless of how carefully it's then handled on this
end - the token traveled through a chat transcript before reaching any tool, which this session's
own handling can't retroactively undo. Not a code/process finding to fix here, just worth surfacing
to the user directly rather than silently proceeding as if nothing unusual happened.

## D-94: T-140's first two SonarCloud findings fixed - Cognitive Complexity in `Core::apply_keystream` and `run`

**First real analysis run (D-93) found exactly 2 open issues, both `rust:S3776` (Cognitive
Complexity), both CRITICAL/CODE_SMELL, no bugs or vulnerabilities**: `hazmat::strumok.rs`'s
`Core::apply_keystream` (17 vs. 15 allowed) and `uacrypt::run` (the top-level CLI dispatcher,
same threshold). User confirmed via chat to fix both, citing existing test coverage as the reason
this is safe - verification below re-confirms that, not just assumes it from the request.

**`apply_keystream` split into `drain`/`bulk`/`remainder`, one private method per phase** (the
same three phases T-135/D-86 already named and documented) - `apply_keystream` itself is now three
sequential calls, each helper taking over exactly the loop it used to contain. Pure code
organization, no math/behavior change. **Verified not just correct but not a performance
regression either**, given T-135's whole point was eliminating overhead in this exact function:
- `cargo test -p dstu-core --lib strumok --test strumok --all-features`: all 10 tests pass
  (T-135's differential/boundary/chunk-invariance/involution/vector suite, unchanged).
- `RUSTFLAGS="--emit=asm" cargo build --release -p dstu-core --lib`: no separate `drain`/`bulk`/
  `remainder` symbols exist in the output - all three fully inlined into `apply_keystream`, the
  same single-caller inlining `next_block` already got (D-87). Confirmed by absence, not assumed.
- `cargo bench --bench strumok -- --baseline strumok-pre-t135-2026-07-27`: -63.3% at 65536 B,
  matching T-135's own recorded -64.7% (small variance is ordinary run-to-run noise, not a
  regression from the split) - the win is fully retained.

**`run` split via a new `dispatch_simple` helper**, applied to the 6 arms
(`kupyna-digest`/`strumok-crypt`/`hash`/`keygen`/`encrypt`/`decrypt`) that all repeated the
identical "check `--help` once, then parse-and-run" shape inline. This is the same "extract a
dispatch helper purely to bring `run`'s own Cognitive/line-count complexity down" precedent
`dispatch_kalyna_mode`/`dispatch_sign_command` already established for D-71 - not a new pattern,
extending an existing one to the arms it hadn't reached yet. `kalyna-block`/`kalyna-ccm` (which
each have their own nested `encrypt|decrypt` sub-match, a genuinely different shape) were left
inline rather than forced into the same helper. Verified: `cargo test -p uacrypt` - 110/110 passed
unchanged (the existing CLI test suite already exercises every command's help-flag and dispatch
path, so this was real coverage, not asserted from the user's own confidence alone).

**Process note**: both fixes hit the identical `clippy::doc_markdown` false-positive on the
capitalized word `SonarCloud` inside a doc comment (`CLAUDE.md`'s own recorded lesson from the
`crypto_secretstream`/`hazmat::strumok` session) - caught and fixed immediately by running clippy
right after writing each doc comment, not deferred to a batch check at the end, per that same
standing note.

**Full workspace verification after both fixes**: `cargo test --workspace --all-features`,
`cargo clippy --workspace --all-features -- -D warnings`, `cargo fmt --all -- --check` all clean.

## D-95: T-136 closed - Kalyna's `nb=4` encrypt/decrypt asymmetry confirmed as an x86-64-specific compiler-codegen artifact via a real aarch64 cross-check, not a portable algorithmic property

**Background**: D-89 narrowed `nb=4`'s asymmetry (decrypt beats encrypt by ~14-15%, opposite `nb=2`/
`nb=8`) to register-allocation pressure (20 vs 14 spill stores, 77 vs 48 total stack references in
the isolated round-loop body), but from a single data point, with two of its own named follow-ups
left unattempted: extending the spill count to `nb=2`/`nb=8`, and the cross-architecture check on
the Raspberry Pi rig (a register-allocation-driven cost should behave differently on aarch64's
larger register file than a genuinely algorithmic one would). `advisor()` was consulted before this
pass per D-89's own explicit recommendation, and both follow-ups below are its proposed order, not
a design decided here.

**Step 1 - spill count extended to `nb=2`/`nb=8`, same isolated-round-loop method as D-89 (validated
by exact match on the `nb=4` "total stack refs" metric: 77/48, reproduced bit-for-bit before trusting
the extension)**:

| `NB` | Winner (D-84) | Winner's stack refs | Loser's stack refs |
|---|---|---|---|
| 2 | encrypt | 11 | 17 |
| 4 | decrypt | 48 | 77 |
| 8 | encrypt | 8 (+0 in the called function) | 151 |

Sign tracks at all three points now, not one: the faster direction always has fewer stack
references. This is real support for D-89's register-pressure attribution, not just a
single-point correlation anymore.

**New structural finding at `nb=8`, distinct from D-89's `nb=4` index-arithmetic hypothesis**: LLVM
does **not** inline `encipher_round_n::<8>` into `encrypt_with_schedule::<8>` - it compiles as a
standalone function (`callq` from the round loop, confirmed via a real symbol in the `.s` output),
with **zero** stack spills inside its own body (pure-GPR gather-XOR, ~150 instructions). Meanwhile
`fused_inv_round_n::<8>` **is** fully inlined into `decrypt_with_schedule::<8>` (no standalone
symbol), producing a single ~450-instruction loop body with 151 stack references. A non-inlined
function gets its own independently-scoped register allocation problem, bounded to just that
function's own live ranges - structurally a very different allocation problem than a monolithic
inlined loop that must share the allocator's view with the whole calling function. This inlining
*decision* itself, not just index arithmetic, is a plausible mechanism at this specific size.

**Step 2 - Raspberry Pi "uacipher" cross-check (aarch64, confirmed reachable via `ssh`, repo synced
per `.claude.local.md`'s documented tar+ssh recipe)**. Confirmed the three confounders advisor
flagged before trusting the comparison: (1) same `--emit=asm` symbol check on aarch64 shows the
*identical* inlining pattern - `encipher_round_n::<8>` compiles standalone, `fused_inv_round_n::<8>`
and both `NB=2`/`NB=4` round functions are fully inlined on both platforms, so the code *shape*
being compared is the same, not an apples-to-oranges artifact of a different backend's inlining
heuristic; (2) default feature profile only (`std`, no `small-tables`) on both runs; (3) every ratio
below is computed **within** its own machine - raw ns are never compared cross-machine (different
clock, different microarchitecture - that comparison would be meaningless, not a `docs/DECISIONS.md`
D-34 cross-implementation-claim violation since it's the same code, just stated explicitly so a
future reader doesn't misread it that way).

`cargo bench -p dstu-core --bench kalyna -- block_only`, same command both machines:

| variant (`NB`) | x86-64 winner / gap | aarch64 (Pi) winner / gap |
|---|---|---|
| kalyna_128_128 (2) | encrypt, ~13.1% | encrypt, ~38.2% |
| kalyna_128_256 (2) | encrypt, ~10.3% | encrypt, ~31.7% |
| kalyna_256_256 (4) | **decrypt**, ~12.3% | **encrypt**, ~17.4% |
| kalyna_256_512 (4) | **decrypt**, ~5.1% | **encrypt**, ~13.4% |
| kalyna_512_512 (8) | encrypt, ~26.6% | encrypt, ~20.3% |

**The `nb=4` result is the decisive one.** Both variants **flip winner** between x86-64 and aarch64,
on code that is confirmed fully inlined and structurally identical in shape on both platforms. That
rules out an algorithmic/portable explanation outright - if the cipher's own structure favored one
direction at this block size, the winner would not flip just from changing the register file/ISA
backend. This is exactly the "gap disappears or flips -> x86 codegen artifact" outcome advisor named
as the discriminating result. `nb=2`/`nb=8` keep the *same* winner on both platforms but at
substantially different magnitudes (13.1%->38.2%, 26.6%->20.3%) - consistent with a
register-pressure-flavored effect that exists on both ISAs but is scaled differently by each
platform's register file size (x86-64's 16 GPRs vs aarch64's larger file), though the exact scaling
mechanism is not derived here.

**Disposition: T-136 closed.** The category of cause is now established with real cross-architecture
evidence, not just x86-side inference: **x86-64-specific LLVM register-allocation/codegen behavior,
not a property of the Kalyna algorithm itself.** Per T-136's own text ("performance-curiosity, not
gating any release-readiness item") and the D-87/D-88 precedent this session already set twice, a
complete, correctly-scoped investigation that ends in "here is the established cause, no code
change is warranted" is a full close, not a deferral. What remains genuinely open, and is *not*
worth reopening this task for, is the finer mechanistic question D-89 already flagged as
out-of-scope for a curiosity task: the exact instruction-by-instruction reason LLVM's allocator
treats the forward and inverse round's index arithmetic differently on x86-64 specifically. **No
code changed** (`git diff` confirms `hazmat::kalyna.rs` untouched) - correct/round-trip behavior on
every variant and block size was never in question, only which direction happens to run faster.

**Bonus, not scope-creep**: this session's Pi run (fresh sync, build, and a real `cargo bench`
execution on the rig) partially exercises T-35 (real ARM Linux build/test validation, still open in
`docs/TASKS.md` under its own separate scope) - noted here for the record, not expanded into.

## D-96: Root markdown declutter - six docs moved to `docs/`, all repo-wide citations rewritten with a `docs/` prefix (T-141, owner-requested)

Owner request 2026-07-28: the repo root had 8 `.md` files (`CHANGELOG.md`, `CLAUDE.md`,
`DECISIONS.md`, `ORACLES.md`, `PERFORMANCE.md`, `README.md`, `SECURITY.md`, `TASKS.md`) cluttering
the GitHub landing page. Only `README.md` (GitHub's own landing-page file) and `CLAUDE.md` (Claude
Code's project-instructions file) needed to stay at root; the other six moved into the existing
`docs/` directory.

**GitHub Community Standards concern checked, not assumed:** the owner's own screenshot of the
repo's "Community Standards" page showed `SECURITY.md` recognized as "Security policy" (green
check) while it still lived at root. GitHub recognizes several community-health files (README,
SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT) in the repository root, the `.github/` folder, or
a `docs/` folder - moving `SECURITY.md` into `docs/` does not drop it from that checklist.

**Citation survey before writing any script:** grepped every tracked file (`git ls-files`, 213
files, `oracles/` and `target/` excluded as untracked/ignored) for all six filenames. Found **zero**
actual markdown-link-syntax (`](...)`) references anywhere in the repo to any of the six - every
citation is prose/backtick, e.g. `` `TASKS.md` T-135 `` or "see SECURITY.md". Exactly one file,
`oracles/README.md`, uses a real relative path (`../DECISIONS.md` etc., one level up from
`oracles/`) - every other citation across all 213 tracked files (132 for `DECISIONS.md` alone) is a
bare filename with no path component at all, because until now these six files were siblings of
everything citing them from root, and files elsewhere in the tree simply write the bare filename as
a citation convention, not a resolvable relative link.

**Convention chosen: uniform repo-root-relative `docs/NAME.md` everywhere, no same-directory
exception.** Confirmed this already-established repo convention before assuming a same-directory
citation should stay bare: `docs/release-readiness.md` already cites its own sibling
`docs/dstu-crypto-project.md` with the full `docs/` prefix, not a bare filename, despite being in
the same directory - and `CLAUDE.md`'s own "Documentation map" table does the same for every
existing `docs/*.md` entry. Matching that convention means every citation of the six moved files,
including the six citing each other from within `docs/` itself after the move, gets the `docs/`
prefix - simpler to apply uniformly by script than special-casing "same directory," and consistent
with what a reader already sees for every other file in `docs/`.

**Executed via a one-off Python script** (`migrate_docs.py`, not committed - scratchpad-only,
per-task tool), not by hand, given the reference count. Logic: `git mv` the six files into `docs/`;
then for each of the six names, across every tracked file, (a) `((?:\.\./)+)NAME\.md` -> insert
`docs/` right before the name, keeping the captured `../` prefix (handles `oracles/README.md`'s one
real relative link), and (b) a bare-name pattern with a negative lookbehind excluding word
characters, `/`, `.`, `-` before the match (so already-prefixed `docs/NAME.md` and the `../`-style
matches from (a) are never double-prefixed) -> `docs/NAME.md`. Result: 149 files touched, 1317
substitutions, zero leftover bare or double-prefixed references (verified by re-grepping the whole
tree afterward for both failure shapes).

**Bug found and fixed in the same pass, not shipped**: the script's first run used `pathlib.Path.
read_text`/`write_text` with Python's default `newline=None` universal-newline translation, which
silently rewrote every touched file's line endings from this repo's LF-only convention to CRLF on
this Windows dev machine (`os.linesep`) - not just the touched lines, the *entire* file, confirmed
by comparing raw bytes (`git show HEAD:<file> | xxd` vs. the working-tree copy) on an untouched
first line. Caught by `cargo fmt --all -- --check` flagging exactly the 69 touched `.rs` files as
"Incorrect newline style" - not a pre-existing condition, confirmed by finding an untouched `.rs`
file (`benches/kupyna.rs`) that stayed pure LF throughout. Fixed with a second pass reading/writing
raw bytes (`Path.read_bytes`/`write_bytes`, `b'\r\n'` -> `b'\n'`, no text-mode translation) across
all 149 touched files; `cargo fmt --all -- --check` and `git diff --stat` (149 files,
1154(+)/1138(-), matching the pre-CRLF-bug numbers) confirmed clean afterward. Lesson for any future
repo-wide find-and-replace script on this Windows dev machine: never use `pathlib`/`open()` text
mode for bulk rewrites of a checked-in-LF repo - use binary mode, or explicit `newline=''`,
regardless of how small the substitution looks.

**Verification**: `cargo build --workspace`, `cargo clippy --workspace --all-features -- -D
warnings`, and `cargo fmt --all -- --check` all clean after the CRLF fix; `cargo test --workspace`
run to confirm no functional regression (this was a citation-text/file-location change only, no
source logic touched). `readme = "README.md"` fields in both crates' `Cargo.toml` were confirmed
untouched (they point at each crate's own `crates/*/README.md`, unrelated to the root `README.md`
this change is about). No code changed - only file locations and citation text.

## D-97: GitHub Community Standards gaps closed - Code of Conduct, Contributing guide, issue/PR templates (T-142)

Owner request 2026-07-28, immediately after T-141/D-96: a GitHub "Community Standards" screenshot
showed Description/README/License/Security policy already green, with Code of conduct,
Contributing, Issue templates, and Pull request template still missing. Two explicit choices were
asked of the owner rather than assumed, since both are public-facing and hard to walk back quietly:

1. **Code of Conduct enforcement contact: GitHub Issues, not a private email.** The owner chose
   this over publishing a personal email address in a public file. Documented explicitly in
   `docs/CODE_OF_CONDUCT.md`'s "Enforcement" section as non-confidential (visible to other
   repository watchers), with a clear pointer that **security vulnerabilities are a separate
   process** (GitHub Security Advisories, `docs/SECURITY.md`) - conflating the two would have been
   a real mistake, since CoC violations and security reports have very different confidentiality
   needs.
2. **Contribution stance: open project, PRs welcome** - the owner chose this over a "solo project,
   contributions limited" framing. This shaped `docs/CONTRIBUTING.md`'s tone throughout (welcoming,
   not gatekeeping) while still stating the real bar plainly: dual-oracle verification, the
   three-test-category rule (correctness/rejection/misuse), no secret-dependent branching, and
   citing `docs/SECURITY.md`/`docs/DECISIONS.md` before proposing an API shape - the same
   substantive requirements this project already holds itself to, not watered down for external
   contributors.

**Placement: `docs/`, not root**, for `CODE_OF_CONDUCT.md`/`CONTRIBUTING.md` - consistent with
D-96's just-established convention (only `README.md`/`CLAUDE.md` stay at root) and with GitHub's
own documented recognition of community-health files in the repository root, `.github/`, *or*
`docs/` (already confirmed empirically for `SECURITY.md` in D-96 - the Community Standards
checklist still showed it green after that move). Issue templates and the PR template **must** live
in `.github/` - that is not optional/stylistic, GitHub only discovers
`.github/ISSUE_TEMPLATE/*.md` and `.github/PULL_REQUEST_TEMPLATE.md` from that exact location.

**Content is project-specific, not generic boilerplate copy-pasted in:**
- `docs/CODE_OF_CONDUCT.md` - Contributor Covenant v2.1 (the de facto standard text), enforcement
  section rewritten for the GitHub-Issues choice above and cross-linked to `docs/SECURITY.md` for
  the actually-separate vulnerability-disclosure process.
- `docs/CONTRIBUTING.md` - written from this project's real practices already documented in
  `CLAUDE.md`/`docs/SECURITY.md`/`docs/TASKS.md` (test-first, dual-oracle verification, the
  three-test-category rule, `cargo xtask` as the single build/QA entry point, the Conventional
  Commits style already visible in `git log`), not a generic Rust-project template - a contributor
  who only reads this file gets the same substantive bar an AI agent following `CLAUDE.md` does.
- `.github/ISSUE_TEMPLATE/bug_report.md`/`feature_request.md` - both point away from filing a
  security report as a public issue; `feature_request.md`'s checklist asks the reporter to check
  `docs/TASKS.md`/`docs/DECISIONS.md` first (a new-feature request that's already planned or
  already explicitly rejected is common noise this heads off cheaply). `config.yml` adds a direct
  "Security vulnerability" contact link to `.../security/advisories/new` rather than relying on
  the templates' own in-body text alone.
- `.github/PULL_REQUEST_TEMPLATE.md` - checklist mirrors `docs/CONTRIBUTING.md`'s verification bar
  item-for-item (three test categories, dual-oracle, constant-time discipline, `docs/DECISIONS.md`/
  `docs/TASKS.md` doc-sync) rather than a generic "tests pass? docs updated?" checklist.

`README.md` updated: repository-structure tree gained the four new paths, and a new short
"Contributing" section (before "License") links all of `docs/CONTRIBUTING.md`,
`docs/CODE_OF_CONDUCT.md`, and `docs/SECURITY.md`'s vulnerability-reporting process. No source code
touched - documentation/governance files only.

## D-98: CodeQL default-setup findings triaged - 69 `hard-coded-cryptographic-value` false positives, 11 real `missing-workflow-permissions` fixed (T-143)

Owner surfaced a GitHub "Security and quality" > Code scanning screenshot showing 80 open alerts,
all newly opened (~20 min old at the time), across two rules: `rust/hard-coded-cryptographic-value`
(69, severity "critical") and `actions/missing-workflow-permissions` (11, severity "medium").
Confirmed via `gh api repos/.../code-scanning/default-setup`: `state: configured`,
`languages: [actions, c-cpp, csharp, java-kotlin, rust]`, `updated_at` the same day - this is
GitHub's **CodeQL default setup**, enabled outside this session (no workflow file added it, unlike
`sonarcloud.yml`/T-140 which is a separate, explicit scanner), running on its own weekly schedule.
Distinct from SonarCloud: two different tools, two different alert surfaces, not to be conflated in
a future session.

**The 69 `hard-coded-cryptographic-value` alerts are false positives, but for three genuinely
different reasons - not one blanket excuse.** Sampled representative alerts from every implicated
file via the Code Scanning API (`gh api repos/.../code-scanning/alerts`), not just the highest-line
ones, specifically to falsify the "100% false positive" claim rather than assume it:

1. **Test-vector files** (`crates/dstu-core/tests/{kalyna_ccm,kalyna_gcm,kalyna_xts,kalyna_ofb,
   kalyna_cfb,kalyna_cbc,kalyna_ctr,strumok}.rs`, and `#[cfg(test)]` modules in
   `hazmat::strumok`/`uacrypt::lib` above line 3267 where its `mod tests` starts) - literal
   known-answer keys/IVs are *required* for a reproducible crypto test, not a secret exposure. Spot
   checked `uacrypt/src/lib.rs:5012` (`let key = [0xCCu8; 16];` inside
   `run_xts_command_round_trip_matches_dstu_core_directly`, an obviously-synthetic pattern-fill
   value in a named `#[test]` fn) specifically to rule out a real committed key hiding among the
   higher line numbers - confirmed clean.
2. **Byte-length literals misread as key material** - `crates/uacrypt/src/lib.rs`'s variant-dispatch
   macros (`run_ccm_variant!(Kalyna128_128Ccm, 16, 16, 16)`,
   `run_gcm_variant!(Kalyna256_512Gcm, 64, 32)`, `run_xts_variant!`, `run_strumok_variant!` etc.,
   lines 641-2630, all *above* the test module) pass `16`/`32`/`64` as key/nonce/tag **byte-length**
   arguments selecting which Kalyna/Strumok variant to instantiate - not literal key/IV bytes. The
   query's heuristic flags any numeric literal near a crypto-typed call site regardless of what the
   literal actually represents.
3. **Zero-init buffer immediately overwritten with real (non-hardcoded) data** -
   `crates/dstu-core/examples/strumok_diff_cases.rs:58` (`let mut iv = [0u8; 32]; rng.fill(&mut
   iv);`, a seeded-PRNG-generated differential-test IV, not a secret) and `uacrypt`'s
   `run_strumok_variant!`/`run_stream_variant!` macros (`let mut iv_arr = [0u8; 32];
   iv_arr.copy_from_slice(&iv);`, filled from the CLI's actual `--key`/runtime-provided IV before
   any use). Both are scratch buffers the analyzer flags before tracking the overwrite.

**`crypto_secretstream.rs:244`'s `chunk_iv` needed a fourth, more careful pass** - the buffer isn't
fully overwritten (`fn chunk_iv(counter: u64) -> [u8; 32] { let mut iv = [0u8; 32]; iv[..8]
.copy_from_slice(&counter.to_le_bytes()); iv }` leaves bytes 8..32 permanently zero), so bucket 3's
framing doesn't apply as-is. Traced the actual safety argument instead of assuming: this module's
own doc comment (`crypto_secretstream.rs:27-29`) already states the design explicitly - the IV's
low 8 bytes are a `u64` counter that is "monotonically increasing per chunk... never transmitted
and **never reset** (including across a `Tag::Rekey`)". Confirmed by grepping every `counter`/
`rekey` site: `counter` starts at 0 once per `PushState`/`PullState` and only ever increments
(`self.counter += 1`), including across `Tag::Rekey => rekey(&mut self.subkey)` - the subkey
changes on rekey, the counter does not reset. So GCM's actual requirement (nonce **uniqueness**
under a given key, not unpredictability) holds two ways: the counter alone never repeats within one
state's lifetime, and the subkey is independently unique per stream (random per-header key via
`docs/DECISIONS.md`'s established pattern). The constant-zero high bytes are provably harmless, not
merely "immediately overwritten" - a materially different, and more defensible, dismissal rationale
than bucket 3's.

**Disposition, split in two:**
- **The 11 `actions/missing-workflow-permissions` alerts are real and fixed in this pass** (not
  false positives - CLAUDE.md's "fix a CI-run static analyzer's findings in the same pass" applies
  here by the same logic as the SonarCloud rule, D-93/D-94, even though this scan isn't PR-attached).
  Added an explicit workflow-level `permissions: contents: read` default to all four workflow files
  (`rust.yml`, `release.yml`, `oracle-harness.yml`, `sonarcloud.yml`) rather than blanket-copying one
  block everywhere without checking each job's actual need first:
  - `release.yml`'s `publish-release` job already had its own `contents: write` override (it creates
    the GitHub Release) - left untouched, confirmed still correct, not widened.
  - `rust.yml`'s `audit` job (`rustsec/audit-check@v2`) gets its own override,
    `contents: read` + `checks: write` - confirmed via the action's own README
    (`gh api repos/rustsec/audit-check/contents/README.md`) that `checks: write` is what it needs
    to publish its check-run annotation; deliberately did **not** add the README's other suggested
    `issues: write`, since this project doesn't currently rely on it auto-opening issues for
    RustSec advisories and adding it unprompted would be scope creep on a permissions-hardening pass.
  - Every other job (`test`, `miri`, `fuzz-smoke`, `deny`, `msrv` in `rust.yml`; `build-binary`/
    `package-library` in `release.yml`; `dotnet`/`java` in `oracle-harness.yml`; `sonarcloud` in
    `sonarcloud.yml`) only checks out and builds/tests/lints/scans - confirmed by reading each job's
    actual steps, not assumed - so the workflow-level `contents: read` default is sufficient and
    correct for all of them.
- **The 69 `hard-coded-cryptographic-value` alerts are not fixed by a code change** - there is no
  real secret to remove, and "fixing" a false positive by obscuring a legitimate test vector or a
  correct-by-design constant would make the code worse, not better. Two mechanisms exist to close
  them out on GitHub's side: (a) dismiss each alert via `PATCH
  /repos/{owner}/{repo}/code-scanning/alerts/{n}` with `dismissed_reason` - GitHub's API accepts
  `"used in tests"` as a distinct reason from `"false positive"`, which is the more accurate label
  for the ~50-60 test-vector-file alerts (bucket 1) vs. the general `"false positive"` label for
  buckets 2/3 and the corrected `crypto_secretstream.rs` rationale; or (b) migrate the repo from
  CodeQL **default setup** to **advanced setup** (a checked-in workflow file), which is required to
  use a `codeql-config.yml` path/query filter - GitHub does not honor a custom config file under
  default setup, only under advanced setup. Left as an explicit choice for the project owner (a
  bulk dismissal of 69 alerts on a public repo's Security tab is a visible-to-others action, not
  something to take unilaterally) rather than resolved unilaterally in this pass.

## D-99: Migrated CodeQL from default setup to advanced setup, query-filtering the false-positive rule instead of dismissing 69 alerts (T-143 follow-up)

Owner chose migration over bulk-dismissal (D-98's open question) specifically because dismissal
doesn't scale: bucket 1 of D-98's false-positive taxonomy (crypto test-vector fixtures) is the
largest share and this project keeps adding DSTU modes/vectors, so every new test file with a fixed
key would keep re-triggering the same rule, requiring dismissal again indefinitely. A config-level
exclusion closes the whole class once.

**Verified before touching anything irreversible, in the order advisor set out - each step gated
on the previous one's real evidence, not assumption:**

1. **Did default setup actually analyze `c-cpp`/`csharp`/`java-kotlin`, or fail silently?** This
   mattered because `tests/oracle-harness/*-differential/*.c` has no Makefile/CMake (per
   `docs/ORACLES.md`, built ad hoc per-file), so a naive "autobuild" would plausibly fail quietly
   and produce a false "0 results = clean" signal. Checked
   `gh api repos/.../code-scanning/analyses`: every language's analysis `environment` showed
   `"build-mode":"none"` - source-only extraction, no compilation attempted at all - with a real
   `rules_count` (52-76 per language, not zero). This resolved the uncertainty: all three genuinely
   ran their full query sets and found nothing, not a silent build failure. Consequence: dropping
   these languages from the advanced-setup migration would have been a real (if currently
   zero-finding) coverage loss, so all five languages (`actions`, `c-cpp`, `csharp`, `java-kotlin`,
   `rust`) were kept, and since none of them need an actual build (`build-mode: none` throughout),
   the advanced-setup workflow needed no Maven/dotnet/gcc/cargo build steps at all - checkout +
   `init` + `analyze`, same shape for every language.
2. **`.github/workflows/codeql.yml` written from GitHub's own auto-generated advanced-setup
   template** (the owner pasted it directly from the Security tab's "Set up advanced" flow) rather
   than from memory - kept its detected language/build-mode matrix and `github/codeql-action/
   {init,analyze}@v4` versions verbatim, trimmed the generic boilerplate comments, added this
   project's own citation-style comments, and added `config-file:
   ./.github/codeql/codeql-config.yml` to the `init` step (absent from the generic template, since
   it doesn't know about our query exclusion).
3. **`.github/codeql/codeql-config.yml`**: one `query-filters: - exclude: { id:
   rust/hard-coded-cryptographic-value }` entry - nothing else changed, default query suite
   otherwise untouched. Named trade-off, recorded in the file itself: a genuinely committed secret
   would no longer be caught by *this specific rule*; the compensating control is code review plus
   `docs/SECURITY.md`'s existing hard constraints and mandatory dual-oracle test-vector process,
   not another scanner - stated explicitly so a future session doesn't assume static analysis alone
   still covers this class of mistake.
4. **Pushed the workflow with default setup still enabled** (deliberately did not disable it first -
   advisor's explicit ordering: prove the replacement works before removing the original safety
   net). Watched the run to completion (`gh run view`, all 5 `Analyze (<language>)` jobs
   `success`), then verified via `gh api .../code-scanning/analyses` for the exact commit SHA that
   the config was *actually honored*, not silently ignored by a path typo: Rust's `rules_count`
   dropped from 25 to 24 (exactly the one excluded query) and its `results_count` dropped from 69
   to 0 in the same analysis - two independent numbers moving together is what confirms the filter
   applied, not just "the run was green." Every other language's `rules_count` matched its
   pre-migration default-setup number exactly (csharp 52, java-kotlin 76, c-cpp 58, actions 17) -
   confirming no coverage was accidentally lost elsewhere.
5. **Only then** - `gh api --method PATCH repos/.../code-scanning/default-setup -f
   state=not-configured`, confirmed via a follow-up `GET` returning `"state":"not-configured"`.
   The 69 previously-open `hard-coded-cryptographic-value` alerts transitioned to `fixed`
   automatically once the rule stopped running (GitHub's own behavior for a query removed from the
   active analysis, not a manual dismissal) - confirmed via
   `gh api .../code-scanning/alerts?state=open` returning zero open alerts, rather than assumed.
   No `dismissed_reason` API calls were made - D-98's "used in tests"/"false positive" dismissal
   path was superseded by this migration, exactly as planned (not run in parallel, which
   would have made it impossible to tell which mechanism actually closed each alert).

**Net result**: 0 open code-scanning alerts, full 5-language coverage preserved, the one
confirmed-false-positive rule structurally silenced going forward (not just for today's 69
instances), and the workflow file itself is now this project's own to maintain (version-pin
`codeql-action`, same maintenance shape as its other four hand-tuned workflows) rather than
GitHub's auto-managed default.

## D-100: Dependabot version updates enabled via a checked-in config, not the bare "Enable" toggle (T-144)

Owner request 2026-07-29, prompted directly by D-99: migrating CodeQL to advanced setup made this
project responsible for its own pinned action versions (`github/codeql-action@v4` etc.) for the
first time, rather than GitHub silently keeping default setup current - Dependabot version updates
is the automated way to keep that (and the small `cargo` dependency set) current without relying on
someone remembering to check manually. Owner explicitly chose a real `.github/dependabot.yml` with
"careful" settings over the bare Security-tab "Enable" button (which uses undocumented, unreviewable
defaults).

**Four `updates:` entries, not one** - three separate `cargo` directories plus one
`github-actions` entry:
- `/` - the main workspace (`dstu-core` + `uacrypt`), the actual shipped product.
- `/xtask` - deliberately excluded from the main `[workspace]` table (own doc comment,
  `xtask/src/main.rs`) specifically so a QA-tool dependency bump can never touch the product's own
  dependency graph; has its own `Cargo.lock` (`.gitignore`'s `/xtask/Cargo.lock` entry), so
  Dependabot needs its own directory entry too - it does not walk nested lockfiles from one root
  config block.
- `/crates/dstu-core/fuzz` - `cargo-fuzz`'s own crate, same reasoning (own `Cargo.lock`,
  `docs/SECURITY.md`'s "fuzzing is required, not optional" makes keeping its own toolchain current
  worth tracking too).
- `/` (`github-actions`) - one entry covers every `.github/workflows/*.yml` file's pinned action
  versions; Dependabot discovers all of them from a single directory, no per-workflow entry needed.

**"Careful" specifics, each a deliberate choice, not a copied default:**
- `schedule: weekly` (Monday), not daily - matches this project's existing CI cadence
  (`rust.yml`'s own comment about avoiding pile-ups) and avoids a PR every day for a dependency set
  this small.
- `open-pull-requests-limit`: 5 for the two "/" entries, 3 for `xtask`/`fuzz` - caps how many open
  PRs can accumulate if updates go unreviewed for a while; low because the dependency count itself
  is already small (`deny.toml`'s own comment: "dstu-core/uacrypt have zero external dependencies"
  beyond the few explicitly vetted ones in `docs/SECURITY.md`'s supply-chain table).
- `versioning-strategy: auto` on the main workspace, added deliberately even though it's
  Dependabot's own default (self-documenting intent, not a no-op). **First attempt used
  `increase-if-necessary` and GitHub's schema rejected it outright** - Cargo's `versioning-strategy`
  only accepts `auto`/`lockfile-only`, not npm's wider `increase`/`widen`/`increase-if-necessary`
  set; caught by GitHub's own config validation on push, not discovered by reading docs first.
  `lockfile-only` was considered next and rejected too: it never edits `Cargo.toml` at all, so a
  new version outside the current caret range could never surface as a PR - defeats tracking a
  library crate meant for downstream consumption (`docs/TASKS.md` T-17, not yet published) for
  exactly the major/minor bumps that matter most. `auto` is the closest available match to the
  original intent. Not applied to `xtask`/`fuzz` (binaries/dev-tools, not published, no downstream
  range to protect) - left at Dependabot's ecosystem default there too, no override needed.
- `groups: minor-and-patch` (by `update-types`) on every entry, **major versions deliberately left
  ungrouped** - routine patch/minor bumps across a small dependency set can safely land as one PR,
  but a breaking major bump to a vetted crypto-adjacent dependency (`zeroize`, `subtle`, `argon2`,
  `getrandom`) should get its own individual PR and its own explicit look, not be bundled in with
  routine noise.
- `commit-message.prefix` matches this project's already-established Conventional-Commits scope
  convention (`docs/CONTRIBUTING.md`): `deps` / `deps(xtask)` / `deps(fuzz)` for the three `cargo`
  entries, `ci` for `github-actions` (matching the scope already used for workflow-file changes,
  e.g. this session's own `ci(workflows): ...`/`ci(codeql): ...` commits).
- No auto-merge configured anywhere, deliberately - every Dependabot PR still needs a manual review
  and green CI before merging, same bar as any other PR (`docs/CONTRIBUTING.md`); Dependabot only
  *opens* PRs here, nothing merges itself.

**Amendment, first real run (2026-07-29):** the config validated and opened 7 PRs on the first
pass (#1-#7 across all four `updates:` entries) - three findings from watching that actual run,
none requiring the schema-error class of fix D-100's `versioning-strategy` correction needed, but
worth recording so a future session doesn't re-diagnose them from scratch:
1. **`commit-message.include: "scope"` was redundant, not broken** - Dependabot's scope value for
   this repo is always the literal word `deps` regardless of ecosystem/directory, so combining it
   with prefixes that already spell out the scope (`deps`, `deps(xtask)`, `deps(fuzz)`) produced
   ugly, redundant titles like "deps(deps): bump getrandom..." and "deps(fuzz)(deps): update
   getrandom requirement...". Removed `include: "scope"` from all four entries; the `github-actions`
   entry's bare `ci` prefix became `ci(deps)` directly so it doesn't lose the "these are dependency
   bumps" signal that `include: "scope"` used to add. Already-open PRs keep their old titles until
   Dependabot next touches them - not worth manually renaming.
2. **The `github-actions` entry's job "errored" after opening exactly 5 PRs, with the message
   "Dependabot cannot open any more pull requests"** - this is `open-pull-requests-limit: 5`
   working exactly as configured, not a bug: more than 5 action-version updates were available,
   Dependabot opened the first 5 and correctly stopped rather than exceeding the cap. Surfaces as a
   red "Errored" status in the Dependency graph > Dependabot tab, which reads alarming but isn't -
   worth remembering the next time this tab shows red, before assuming the config itself is broken.
3. **PR #1's `SonarQube Cloud (Rust)` check failed with "Not authorized... check the SONAR_TOKEN
   environment variable"** - traced via `gh run view --log-failed` to confirm before assuming it
   was a real break from the `getrandom` 0.3->0.4 bump. It wasn't: GitHub does not pass repository
   secrets to workflows triggered by a Dependabot-authored PR by default (a security boundary, not
   a misconfiguration here) - `sonarcloud.yml`'s own existing comment already anticipated this
   general shape ("it's safe to merge in that state" for the secret-missing case). This will recur
   on **every** Dependabot PR going forward for this one specific check, unrelated to whatever
   dependency is being bumped - expected, known noise, not a per-PR problem to chase. Everything
   else on PR #1 was still `pending`/passing when checked.
4. **PR #3 (`dtolnay/rust-toolchain` 1.87.0 -> 1.100.0) was a real problem, not noise - closed, and
   the underlying dependency ignored.** `rust.yml`'s `msrv` job pins `dtolnay/rust-toolchain@1.87.0`
   deliberately as this project's MSRV floor (see the job's own doc comment), not as "whatever's
   current" - Dependabot has no way to distinguish that from an ordinary version to bump, and
   proposed 1.100.0 on the very first run. Confirmed via `gh pr diff` that merging it would have
   silently defeated the job's entire purpose *and* broken it outright at the same time: the job's
   own `cargo +1.87.0` invocations further down (`rust.yml:169-170`, required by the
   `rust-toolchain.toml`-overrides-bare-`cargo` gotcha already documented in `CLAUDE.md`) are
   hardcoded and don't move with the action ref, so the PR's own MSRV build check failed -
   confirmed the failure, not just predicted it. Closed the PR with an explanatory comment and
   added `ignore: - dependency-name: "dtolnay/rust-toolchain"` to the `github-actions` entry, since
   this would otherwise recur roughly every six weeks (Rust's release cadence) forever - bumping
   the MSRV floor itself is a deliberate, by-hand project decision (see `docs/DECISIONS.md`'s
   pattern for other MSRV-floor changes), not something to accept via an automated PR.

**Second amendment, same day: all 6 remaining first-run PRs closed, major cargo bumps blocked
automatically.** After #3, the two `getrandom` 0.3->0.4 PRs (#1 fuzz, #2 main workspace) were the
next-most-concerning: a major-version bump to a dependency this project's own docs (D-74) already
flag as needing careful version-specific attention (the `getrandom` 0.3 custom no_std backend hook
mechanism), opened automatically with no gate beyond "CI will catch it eventually." Rather than
leave majors ungrouped-but-still-automatic (the original D-100 design) and rely on catching each
one manually as it lands, tightened further: **`ignore: - dependency-name: "*", update-types:
["version-update:semver-major"]` added to all three `cargo` entries** (main, `xtask`, `fuzz`) -
major-version bumps no longer open a PR at all for any Cargo dependency, only minor/patch do.
`cargo audit` (`rust.yml`'s own job, runs on every push regardless of Dependabot) still
independently catches known vulnerabilities in whatever version is currently pinned, so this
doesn't reduce vulnerability-detection coverage - it only removes the *proactive* "here's a newer
major version" nudge, which for a 4-5-dependency, individually-vetted crypto-adjacent project is a
reasonable trade: a major bump to `zeroize`/`subtle`/`getrandom`/`argon2` should be a deliberate,
by-hand decision (checked against changelogs, re-verified against `docs/SECURITY.md`'s supply-chain
table) the same way an MSRV-floor bump already is, not something that arrives as an unprompted PR.
Not applied to the `github-actions` entry - official Action major bumps are lower-risk (clear
compatibility notes, breakage caught immediately by this project's own required CI checks) and
this project has no equivalent documented sensitivity to any specific Action version the way it
does to `getrandom`, so those still get individual (not blocked) major-bump PRs.

All 6 remaining first-run PRs (#1, #2, #4-#7) were closed with an explanatory comment rather than
merged or left open - #1/#2 for the reason above, #4-#7 (routine GitHub Action minor/patch bumps)
simply to let Dependabot recreate them cleanly under the now-fixed `commit-message` config (the
"deps(deps):"-style redundant titles from the first amendment) rather than leave stale-titled PRs
open. None of this discards real work - every closed PR is Dependabot-authored and will reopen
with a corrected title on the next scheduled check if the update is still current.

## D-101: Removed `.github/dependabot.yml` entirely - Dependabot Security Updates already covers "vulnerability only" with zero config (T-144 reversal)

Owner's question after D-100's two rounds of friction (`versioning-strategy` schema rejection, the
MSRV-pin false-positive on PR #3, the `getrandom` major-bump risk): "configure Dependabot to only
act on an explicit vulnerability, ignore the rest?" Checked before building anything, rather than
hand-rolling that behavior on top of the existing `updates:` config - and it turned out to already
exist, on, and unrelated to the file this project had been fighting with:

- `gh api repos/.../automated-security-fixes` -> `{"enabled": true, "paused": false}` - **Dependabot
  Security Updates** (a distinct GitHub feature from "Version Updates", enabled/managed via repo
  Settings > Security, not `dependabot.yml`) opens a PR **only** when a dependency has a known
  vulnerability in GitHub's Advisory Database, bumping to the minimum version that fixes it -
  exactly "explicit vulnerability, auto-PR, ignore everything else."
- `gh api repos/.../vulnerability-alerts` -> `204 No Content` (GitHub's convention for "enabled") -
  **Dependabot Alerts** (surfaces known vulnerabilities in the Security tab, no PR) was also
  already on.

Both work with **no config file at all** - sensible built-in defaults, zero maintenance surface.
Everything D-100 built (`versioning-strategy`, per-directory `groups`, `commit-message` prefixes,
the `dtolnay/rust-toolchain`/major-version `ignore` rules) was solving a *different* problem -
**Version Updates**, GitHub's "a newer release exists, security-relevant or not" feature - which is
opinionated, has a much larger configuration surface, and is what generated every round of friction
this session (D-100's two amendments, three separate PR-closing passes). For a small, individually-
vetted dependency set (`docs/SECURITY.md`'s supply-chain table) where `cargo audit` already runs on
every push as an independent vulnerability check, the "stay current on non-security releases"
feature was solving a problem this project doesn't strongly need automated, at a cost (config
complexity, PR volume, the getrandom-major/MSRV-pin false-positive risk) that outweighed the
benefit.

**Disposition: `.github/dependabot.yml` deleted entirely.** Dependabot Security Updates + Alerts
(both already enabled, confirmed via API rather than assumed) are now the sole automated dependency
mechanism, unchanged and requiring no maintenance. `docs/TASKS.md` T-144 is revised in place to
record the reversal rather than left pointing at a file that no longer exists.

## D-102: Kani (bounded model checking) adopted, scoped to `gf2m163::reduce` only (T-145)

Owner asked where Kani specifically (not "more tools generically") would add real value on top of
the existing miri/fuzz/proptest stack, and to pilot it before deciding whether to keep it. miri
catches UB on the runs it happens to make; fuzz/proptest sample random inputs; Kani instead proves
a property for *every* input in a bounded space via CBMC. That's only worth the added CI surface
where a function has (a) compile-time-fixed loop bounds (no unwinding over caller-controlled
length) and (b) a property currently trusted by hand-argument rather than machine-checked.

**Survey of `hazmat` against those two criteria** (see the pilot session's analysis in full):
- `dstu4145::gf2m163::reduce` (`crates/dstu-core/src/hazmat/dstu4145/gf2m163.rs`) is the strongest
  fit found: fixed 3+2-iteration loops (word count is a compile-time constant for `m=163`), a
  closed-form word-shift reduction whose own doc comment says "one pass is provably enough" and
  "provably sufficient" — hand-derived claims, never previously checked by anything wider than the
  small hand-picked property tests in `dstu4145_gf2m.rs` (no proptest exists for this module at
  all). Used in every DSTU 4145 sign/verify call.
- `gf2m_wide.rs` (the `m`=128/256/512 GCM/GMAC field, same closed-form-reduction shape) is the same
  category, one tier down: it already has proptest coverage, and is GCM/GMAC-only rather than
  signature-critical. Not picked up in this pass — a natural next candidate if this proves out
  further.
- Kalyna/Kupyna S-box/MDS table indexing: **not a fit** — indices are already `u8 as usize` or
  `% nb`, which Rust's own type system proves in-bounds; Kani would add nothing over what the
  compiler already guarantees.
- DSTU 4145's EC scalar-multiplication ladder (`scalar.rs`): **not a fit** — the same 163+
  iteration cost that already forced `#[cfg_attr(miri, ignore)]` (T-100/D-59) would equally blow up
  CBMC's unwinding; only a single ladder step, not the full loop, could ever be a Kani target.
- `crypto_secretstream`/AEAD/`kalyna_gcm`: **not a fit** — loops over caller-controlled message
  length are unbounded from Kani's perspective; the nonce-authentication class of bug this project
  already hit once (D-63) is a design-level invariant, better caught by the tamper tests already
  required (D-64), not a numeric proof.
- `argon2`/`getrandom`: **not a fit** — external crates, nothing of this project's own to verify.
- Kani proves **no side-channel/constant-time property** — not to be confused with, or used to
  relax, the separate SPA/DPA disclaimer already in `CLAUDE.md`/`docs/SECURITY.md`.

**Platform reality, confirmed by trying, not assumed:**
- Windows (this project's own dev machine): `cargo install kani-verifier` fails to compile.
  `kani-verifier 0.67.0`'s own source calls `std::os::unix::fs::symlink` and
  `Command::arg0` — genuinely absent on this platform, not a missing-dependency case.
- This project's aarch64 Raspberry Pi (Debian 12 bookworm, `docs/TASKS.md`'s ARM hardware rig):
  `cargo install kani-verifier` and `cargo kani setup` both succeeded (an aarch64-linux prebuilt
  bundle does exist, wider platform support than expected going in) — but the resulting
  `cargo-kani` binary requires `GLIBC_2.39`; bookworm ships `2.36`. Upgrading the Pi's system glibc
  to chase this was judged not worth the risk to a live machine for a pilot.
- `x86_64-unknown-linux-gnu` (GitHub Actions `ubuntu-latest`) is Kani's actual officially-supported
  target and where it was proven out: pushed a throwaway `workflow_dispatch`/branch-scoped-`push`
  pilot workflow (never merged to `master`), two `#[kani::proof]` harnesses in a `#[cfg(kani)] mod
  kani_proofs` block in `gf2m163.rs` — one checking `reduce`'s output is always `< 2^163` (top 29
  bits of word 2 clear), one checking `reduce` matches an independent bit-at-a-time reference
  written straight from the polynomial identity `x^163 = x^7+x^6+x^3+1`, with no word-level
  shortcuts. Both came back `VERIFICATION:- SUCCESSFUL` (0.22s and 45.37s respectively), ~1m22s
  total job time including the one-time `cargo install kani-verifier`/`cargo kani setup` cost.

**Disposition: adopted, scoped to `gf2m163::reduce` only.**
- `#[cfg(kani)] mod kani_proofs` block stays in `gf2m163.rs` (the pilot code, unchanged).
- `crates/dstu-core/Cargo.toml` registers `[lints.rust] unexpected_cfgs = { check-cfg =
  ["cfg(kani)"] }` — `kani` is a cfg set by `cargo kani`'s own compiler shim, not a Cargo feature,
  and without this registration `clippy -D warnings` (every other CI job) would hard-error on the
  `#[cfg(kani)]` attribute itself.
- `.github/workflows/rust.yml` gets a new mandatory `kani` job (`ubuntu-latest`, mirroring the
  `miri`/`fuzz-smoke` jobs' standing: required on every push, not best-effort) - no `--harness`
  filter, since `#[kani::proof]` fns are auto-discovered (unlike `cargo-fuzz`'s targets, which need
  the separate `FUZZ_TARGETS` list).
- `xtask` gets a `kani` subcommand, best-effort locally like `miri`/`fuzz`/`audit`/`deny` - except
  on Windows, where it prints the specific unix-API-only reason above (not `require`'s generic
  "not found on PATH" message, since installing it here would never work regardless of PATH).
- The temporary pilot branch/workflow (`pilot/kani-gf2m163`, `.github/workflows/kani-pilot.yml`)
  is deleted now that the real integration lands in `rust.yml`/`xtask` directly - it was scaffolding
  to answer "does this work," not itself part of the permanent setup.
- Not extended to `gf2m_wide.rs` or anything else in this pass - `docs/TASKS.md` T-145 tracks that
  as a possible future follow-up, not a commitment made here.

## D-103: `cargo miri test`'s CI job exceeded its 150-min cap - CI runner variance on an
already-thin margin, not a code regression (T-146)

Owner noticed `rust` was showing `cancelled` on `master`'s current HEAD and asked why. **Checked
before guessing**, per this project's own standing discipline (D-59's "measure, don't assume"):
`gh run view` on that run (`30401713356`, commit `5a89efa`) showed every job green except `cargo
miri test`, which the annotations state explicitly exceeded its own `timeout-minutes: 150` cap -
a real timeout, not a concurrency-group cancellation (no later push on `master` could have
preempted it; it's the current HEAD).

**Root-caused as margin erosion, not a regression, by checking history rather than the diff
alone:**
- The last run that actually completed (not cancelled) was commit `8e5a2a8` (2026-07-27, `gh run
  view 30286706271`) - `cargo miri test` passed, but at **2h23m0s of the 2h30m0s (150-min) cap** -
  already ~95% utilized, ~7 minutes of real margin.
- `git log 8e5a2a8..5a89efa -- crates/` shows exactly **one** commit touching anything under
  `crates/` in between: `ebbb11b` (T-141), a pure documentation-citation-path rewrite (`DECISIONS.md`
  → `docs/DECISIONS.md` etc. in doc comments) - no source, test, or dependency change of any kind.
- Every `rust` run on `master` between those two (the T-140-T-144 commit burst, pushed minutes
  apart) shows `cancelled` too, but that's this workflow's own `concurrency: cancel-in-progress`
  policy preempting each run as the next commit landed before miri could finish - not evidence of
  a timeout in each case, just noise from a rapid commit burst.

**Conclusion: the 150-min budget (set in D-59, 2.5x a `dstu-core`-only local measurement, before
`uacrypt`'s own tests were confirmed to run under CI's Miri too, T-102) had already eroded to a
razor-thin margin purely from organic growth across everything landed since D-59** (`crypto_secretbox`/
`crypto_secretstream`/`crypto_auth`/`crypto_kdf`/`crypto_stream`/`crypto_pwhash`/`crypto_sign` and
their own `proptest` suites, plus `uacrypt`'s CLI test suite now actually reached). `ebbb11b`'s
doc-only diff simply happened to be the commit sitting at HEAD when ordinary shared-runner
variance (a few minutes slower than 2026-07-27's run) tipped an already-thin margin over the edge -
it did not cause the overrun.

**Disposition: `timeout-minutes` raised from 150 to 240** (`.github/workflows/rust.yml`) - real
headroom over the last confirmed real duration (143 min) rather than the smallest bump that would
have covered just this one overrun, and still well under GitHub-hosted runners' 360-min hard cap.
Verify the next real `master` push lands `cargo miri test` green via `gh run view`, not just an
assumption that a bigger number alone fixes it (same verification discipline D-59 and the
Node-20-deprecation-era reconfirm already established) - see `docs/TASKS.md` T-146 for that
follow-up check.

## D-104: Official supplementary Strumok-256/512 test vectors received from Держспецзв'язку -
upgrades but does not close D-15/D-16 (T-147)

The owner filed a public-information request asking Держспецзв'язку (State Service for Special
Communications) whether recommended parameters/worked examples for DSTU 8845:2019 (Strumok) and
DSTU 9041:2020 exist outside the paid standard texts. The response (Адміністрація Держспецзв'язку)
states plainly - the request/response's own reference number, filing date, and signatory are
deliberately not recorded here or anywhere else in this repository: this project is public, and
those specifics would be enough to cross-reference a public request log and identify the owner,
which is a real de-anonymization risk the technical content below doesn't need to carry:
- Recommended parameters/worked examples for both standards are in the standard texts themselves,
  as their own annexes - not purchased here (D-15/D-16, D-08's post-quantum-adjacent cost note).
- **ДНДІ ТКЗІ (the State Research Institute of Cybersecurity Technologies and Information
  Protection) uses, in addition to Annex Д (Annex D)'s own known-answer tests, two supplementary
  test examples for Strumok-256/512** during real conformance expert examinations of concrete
  crypto-protection tools - attached to the letter.
- No other test-value sets, reference implementations, methodological guidance, or technical
  reports exist at Держспецзв'язку for either standard, beyond the standard texts themselves.

**This is a genuinely independent oracle** - sourced directly from the state institution that
performs conformance expertise for implementations of this standard, not from a third-party
library's own self-test (UAPKI/outspace, D-15's existing "shared lineage, not independent
authorship" caveat). It does not, by itself, confirm this project's implementation against Annex Д
of the standard text (still unpurchased) - D-15/D-16 stay open on that specific, narrower claim.
Worded as an **upgrade, not a closure**, per this project's own standing rule against letting a
provisional citation quietly age into a settled one.

**Two distinct byte-order conventions had to be derived from the letter's own notation, not
assumed** - the same D-25 `hash_to_field` failure mode (a source's own calling/labeling convention
differing from this crate's array convention, requiring a citation-backed transform rather than a
silent flip-until-green):
- **Key/IV:** the appendix labels bytes `Key31, Key30, ..., Key0` / `IV31, ..., IV0`, printed in
  that descending-index order left-to-right. `hazmat::strumok::init_state`'s `kw`/`ivw` helpers
  read array index 0 first (ascending) - the reverse of the letter's printed order. Reversing the
  transcribed byte sequence was the first thing tried (predicted from the labeling before running
  anything, not discovered by trial), and it was confirmed correct empirically: encrypting with the
  reversed key/IV against the still-untransformed `RandBlock` produced output that was an exact
  per-8-byte-word permutation of the expected value, not unrelated bytes - proof the key/IV
  orientation was right, since a wrong key/IV would have produced a keystream bearing no
  relationship to the expected one at all.
- **`RandBlock`** (the raw keystream over an all-zero input; carries no index annotation, unlike
  Key/IV): matches this crate's output only after each 8-byte word is *also* independently
  byte-reversed - a distinct convention from Key/IV's own, derived from the word-permutation
  pattern actually observed above (not assumed to be the same transform as Key/IV, and not derived
  by guessing further reversals). Confirmed for every one of the 32 words across both the
  Strumok-256 and Strumok-512 cases.
- Both variants share the identical printed IV value in the letter - a free cross-check that the
  transcription is faithful, since a transcription slip in one variant's copy would have broken
  that equality independently of the cipher logic.

**Disposition:** `crates/dstu-core/tests/strumok.rs` gained a new `official_letter_vectors` module
with `strumok_256`/`strumok_512` tests, transcribing the hex **exactly as printed** in the letter
(byte-for-byte eyeball-diffable against it) and applying the two derived transforms explicitly
in-code with the derivation cited in the module doc comment, rather than pre-reordering the
literals silently. Both tests pass. `docs/ORACLES.md`'s Strumok section updated to record the new
source and the upgraded (not closed) status. Of the two source PDFs, only the appendix
(`docs/papers/Strumok_official_test_vectors_2026-07-31.pdf` - Key/IV/RandBlock only, no personal
data) is committed, per the owner's explicit choice; the cover letter itself carries the owner's
own name and email in its addressee block and this repository is public, so it stays local, not
committed, and not cited here by its own reference number or exact date either - see this entry's
opening paragraph for why.

DSTU 9041:2020 remains untouched by this pass - the letter confirms no oracle exists for it beyond
the (unpurchased) standard text, consistent with `docs/ORACLES.md`'s existing "no oracle exists
anywhere" entry for that algorithm. Not started, not planned by this decision.

## D-105: A previously-recorded "font-encoding failure" was false for five PDFs; re-examination
found a usable DSTU 9041:2020 pseudocode source plus three unread cryptanalysis papers (T-148)

While investigating the Skorobahatko DSTU 9041 thesis (D-104's follow-up, prompted by the owner
directly asking why it "wasn't readable"), the standing claim in `docs/ORACLES.md` - that
Cyrillic-heavy PDFs in this project lose their prose to a missing `ToUnicode` CMap - was checked
directly with `pdftotext -layout` rather than trusted from the existing note. **The claim was
false for every file it had been applied to**: `Dolgov_5-22.pdf`, `Strumok_verilog.pdf`,
`Kalyna_construction_principles_ZI_2015.pdf`, `Kalyna_vs_international_standards_2018.pdf`, and
the Skorobahatko thesis itself all extract clean, complete Ukrainian prose via plain
`pdftotext -layout` - no rendering-to-PNG needed. The only real defect is cosmetic (Cyrillic `і`
sometimes extracts as Latin `i`, a LaTeX/T2A glyph-sharing quirk, not a missing-CMap failure).
`docs/ORACLES.md` corrected in five places (the general PDF-extraction note, the Dolgov/Kalyna
bullets, and the DSTU 9041 bullet) rather than left to quietly keep misleading a future session -
`docs/DECISIONS.md`'s own standing rule against provisional claims aging into settled ones applies
to false-negative claims exactly as much as to unverified-positive ones.

**Consequence for DSTU 9041:2020**: the Skorobahatko thesis (KPI, 2023) turned out to contain a
complete, numbered encryption algorithm (15 steps) and decryption algorithm (19 steps) in its
§1.2, plus a second, independently-phrased restatement in §2.1.1 - real, previously-missed source
material for an algorithm this project had marked hard-blocked with zero sources of any kind.
**`docs/pseudocode/dstu9041.md` written from it**, both forms transcribed, with every internal
inconsistency flagged inline rather than silently resolved (this project's own D-15/D-25
discipline for exactly this situation): most notably, both algorithm forms independently make the
same "scalar times the wrong operand" slip in their decryption step (`T' = e*r`/`T = hP` where the
point `R`/`εP` reconstructed from the ciphertext must be meant instead) - two separately-worded
sections making the identical mistake reads as a genuine authorial error rather than a
transcription artifact of this project's own extraction, though that inference is not itself a
citable confirmation and is recorded as such, not asserted as fact. Four further gaps (no
`l_max(p)` formula, no concrete curve parameters, no KIVREP definition beyond its acronym
expansion, no hash-identifier/user-group registry) are recorded in the pseudocode doc's own "Open
gaps" section.

**This does not unblock `hazmat::dstu9041`.** The thesis is a single secondary source citing the
standard as its own `[15]`, with no oracle or reference implementation anywhere to cross-check
against - the thinnest evidentiary position any algorithm in this project has had. It clears the
bar for a `docs/pseudocode/*.md` draft (that doc's entire charter is to state what a source says,
ambiguities included) but not the dual-oracle bar this project's hard constraints require before
writing a primitive. `docs/dstu-crypto-project.md`'s "hard-blocked, zero source material" framing
for DSTU 9041 is deliberately left as-is, not reworded to "unblocked" - doing so would be exactly
the provisional-citation-aging-into-settled failure this project's own conventions warn against.

**Separately, three cryptanalysis papers already sitting in `docs/papers/` had never been
referenced anywhere in this project's docs** (`Kalyna_attacks.pdf`, `Kalyna_improved_MITM_attacks.pdf`,
`Kupyna_analysis.pdf`) - not a font-encoding casualty, just genuinely unread until this pass.
Surfaced in a new `docs/SECURITY.md` "Known cryptanalysis" section: best-known round-reduced
attacks reach 9-11 of Kalyna's 14-18 rounds (depending on variant) and 5-6 of Kupyna's 10-14
rounds - none reach the full cipher, so this changes no code or claim, but a threat model that
omits known third-party attacks on its own primitives is incomplete, and these papers existing
unread in the repo for this long was itself worth correcting.

## D-106: Benchmarked Kalyna/Kupyna/Strumok against their international role-analogs
(AES/Whirlpool/ChaCha20 via OpenSSL) — a new comparison axis, not a replacement for the
UAPKI/Oliynykov/outspace tables (T-149)

The owner asked for a performance comparison against the specific analogs the GitHub Pages landing
page's orientation table (added the same session) already names for each DSTU primitive: AES for
Kalyna, Whirlpool for Kupyna, ChaCha20 for Strumok, and left the choice of reference binary
(libsodium or OpenSSL) to the assistant.

**OpenSSL only, no libsodium.** The dev machine already has OpenSSL 3.5.5 (MinGW64 build) on
`PATH`, and its `openssl speed` subcommand covers all three needed primitives — AES, Whirlpool (via
`-provider legacy -provider default`), and ChaCha20 — in one binary. No dev headers/import library
for either OpenSSL or libsodium are installed on this machine (`pacman` itself isn't present in this
Git-Bash environment, so the project's usual "vendor nothing, download prebuilt" pattern for a new
oracle DLL would need a fresh package-manager or manual-download step); since OpenSSL's own CLI
already answers every measurement needed without that step, adding libsodium as a second dependency
would have been unjustified scope, not a genuine gap.

**`openssl speed`, not a `docs/PERFORMANCE.md`-style D-34 file wrapper.** Every existing
cross-implementation table in this project is produced by a small `gcc -O2` C harness with the same
file-in/file-out shape as `uacrypt`'s own CLI, timed the same way (D-34). Writing an equivalent
wrapper against OpenSSL's `libcrypto` would need its dev headers/import lib, which (per above)
aren't installed here. `openssl speed -elapsed -bytes N` is a different, but not less legitimate,
harness — it's the actual OpenSSL project's own benchmark tool, in wide use for exactly this kind of
comparison. `-elapsed` switches its default CPU-user-time divisor to wall-clock (matching
`uacrypt`'s own timing), and `-bytes N` pins its buffer size to match what's fed to `uacrypt`. Both
sides report decimal (10⁶-byte) MB/s, so the ratios are valid even though the two timing loops
differ — this deviation is stated plainly in `docs/PERFORMANCE.md`'s new section rather than left
implicit, since blending two silently-different timing philosophies in one table is exactly the
failure the file's existing byte-identity-verification policy (for the UAPKI tables) exists to
prevent, and there's no byte-identity check available here to substitute (different algorithms by
design — AES/Whirlpool/ChaCha20 aren't supposed to produce the same bytes as Kalyna/Kupyna/Strumok).

**AES-NI is a real confound, so both an on and an off column are reported for AES.**
`OPENSSL_ia32cap="~0x200000200000000"` is OpenSSL's own documented mechanism for disabling
AES-NI/PCLMULQDQ; confirmed empirically to actually change the number on this build (AES-128-ECB:
1127.55 → 380.07 MB/s at a 16-byte buffer) before trusting it for the table. `dstu-core` has no SIMD
by design (`CLAUDE.md` MVP scope: correctness/portability first), so the AES-NI-off column is the
one that actually answers "how good is this project's Kalyna" — the on column is disclosed too, but
explicitly framed as measuring ISA support, not this project's code.

**ChaCha20 has the same AVX2 confound, with no equally clean toggle found.** Tried
`OPENSSL_ia32cap="0:0:0:0:0"` (all capability words zeroed) as a blunter version of the same idea;
it also dropped AES-128-ECB further, to *below* its own AES-NI-specific-mask number (169.0 vs 380.1
MB/s) — evidence it disables more than just AES-NI/AVX2 (likely basic 64-bit-optimized code paths
too), which would make a ChaCha20 number produced this way an apples-to-oranges "how slow is naive C
chacha" figure, not "how fast is chacha without AVX2." Rather than publish a number produced by an
unverified, possibly-overbroad mask, ChaCha20 is reported hardware-accelerated only, with the same
"this measures ISA support, not just the algorithm" caveat AES-NI-on carries — not a claim that
Strumok and ChaCha20 are on equal optimization footing.

**Whirlpool needed the legacy provider loaded** (`-provider legacy -provider default`) — without it,
`openssl speed -evp whirlpool` silently reports all-zero throughput rather than erroring, since
OpenSSL 3.x moved Whirlpool out of the default provider. Confirmed once with the flag before
trusting any number from it. No ISA-specific fast path exists for it in this OpenSSL build (plain
table-driven C, same optimization tier as Kupyna's own design) — the one comparison in this pass
with no hardware-acceleration caveat attached.

**Where a variant has no size-matched counterpart, the table says so explicitly rather than forcing
a row or silently omitting the algorithm.** AES has one fixed 128-bit block, so Kalyna-256-256/
256-512/512-512 get no AES row at all (there's no AES variant to put in it). ChaCha20's key is fixed
at 256 bits (XChaCha20 extends the nonce, not the key), so Strumok-512 is compared for role/
throughput only, flagged as such, not presented as a key-size match. Whirlpool's output is fixed at
512 bits regardless of input length, so Kupyna-256's row is a throughput-only comparison too — still
valid, since both are hashing the same input bytes.

**Not added to `docs/ORACLES.md`.** OpenSSL is a speed baseline against a recognizable name, not a
correctness reference for any DSTU standard — adding it to the oracle trust matrix would misstate
what it's being used for here.

Numbers, reproduction commands, and the full caveat text live in `docs/PERFORMANCE.md`'s new "vs.
international-standard analogs (OpenSSL)" section — not duplicated here.

**Extension, T-150: DSTU 4145 vs. ECDSA added to this same comparison axis.** The owner asked
whether the signature primitive could be benchmarked the same way and compared against ECDSA - the
one algorithm this decision's original table left as "not yet benchmarked." Same OpenSSL-only
approach as the rest of D-106, but two new mechanics this pass surfaced:

1. **`sign`/`verify` had no `--iterations` flag** - unlike every other benchmarkable command in this
   CLI. Added, following the exact existing precedent (same flag name/shape as `kupyna-digest`, no
   `--raw-schedule` since signing has no key-schedule step to cache/redo, same reasoning `kalyna-kw`
   already documents for the same omission). Test-first: parse happy-path/rejection tests mirroring
   `parse_digest_args`'s own, plus a behavioral test (`sign_verify_with_iterations_still_round_trips`)
   confirming the signature `--iterations > 1` actually writes is still the real, `verify`-accepted
   one, not a benchmark-only placeholder.
2. **The hash step had to be excluded from the timed loop, and this needed checking, not assuming.**
   `sign`/`verify` hash the input with Kupyna-256 before signing/verifying the digest;
   `openssl speed ecdsab163`/`ecdsap256` never touch a file at all, signing a fixed digest
   repeatedly. Confirmed the hash is genuinely negligible by comparing a 5-byte and a 64 KiB
   message (255.98 vs. 254.51 ops/s, within 0.6%) rather than assuming "small file, must be fine."

**Field size matched (`GF(2^163)`), curve not matched, security level not matched — three separate
facts, each stated once, not conflated.** OpenSSL's `nistb163` shares this project's field size
(163-bit binary), so it's the fairer comparison for "how good is this implementation" - but it is a
different curve (different `b`/base point/order) and, more importantly, a similar-but-not-identical
legacy security tier. `nistp256` is also reported (it's what "ECDSA" means to most readers, matching
the landing page's own unqualified analog label) but explicitly flagged as **not** a same-security-
level comparison - P-256 is a ~128-bit-security curve doing more expensive math for a stronger
guarantee, so its ~136-188x gap must not be read as a pure implementation-quality verdict the way
`nistb163`'s ~21-23x gap can be.

**Root-caused, not left as a bare ratio.** `curve163.rs`'s own doc comment already states its scalar
multiplication always runs the full 163-iteration ladder - a constant-time double-and-add with no
windowing/precomputation, unlike OpenSSL's binary-curve path. This is a different category of gap
from D-106's AES-NI/AVX2 findings above: not a CPU instruction-set asterisk, an algorithmic one -
consistent with `CLAUDE.md`'s MVP priority (correctness/auditability first) and this project's
constant-time discipline (D-19). Not a bug, and not fixed as part of this pass - recorded as the
honest reason for the gap, the same posture D-106's AES-NI disclosure already established.

Numbers and reproduction commands are in `docs/PERFORMANCE.md`'s new "DSTU 4145 vs. ECDSA" subsection
(same file, same top-level OpenSSL section as the rest of D-106) - not duplicated here.

## D-107: Spiked `-C target-feature=+avx2` on `uacrypt` release builds — no measurable gain, and a
real SIMD implementation (not just the compiler flag) is deliberately not being pursued for now

Following D-106's OpenSSL comparison (whose AES-NI/AVX2 numbers prompted the question), the owner
asked whether this project could reuse AVX for its own algorithms in a performance build, similar in
spirit to the existing `fused`/`small-tables` split (D-35/D-38/D-39). Spiked directly rather than
reasoned about in the abstract, per this project's own T-129/T-139 precedent (spike and read the
actual result before planning a rewrite).

**What was tried**: two separate release builds of `uacrypt` from the same source (`cargo build
--release -p uacrypt` into distinct `--target-dir`s), one plain, one with
`RUSTFLAGS="-C target-feature=+avx2"` — no source changes, since the question was whether the
existing scalar code already has anything in it for LLVM's auto-vectorizer to widen. Byte-identity
confirmed first (Kalyna encrypt/decrypt round-trip, Kupyna digest, Strumok keystream all produced
identical output between the two builds) before trusting any timing, same discipline as every other
table in `docs/PERFORMANCE.md`.

**Result, same Ryzen 5 PRO 4650U dev machine, repeated to rule out noise**:

| Primitive | Baseline | `+avx2` | Verdict |
|---|---|---|---|
| Kalyna-128/128 (block, cached) | 75 ns/op | 76 ns/op | flat |
| Kalyna-128/256 (block, cached) | 100 ns/op | 102 ns/op | flat |
| Kupyna-256, 10 MiB | ~137 MB/s | ~131-133 MB/s | **~3-4% slower, reproduced twice** |
| Kupyna-512, 10 MiB | 90.58 MB/s | 90.55 MB/s | flat |
| Strumok-256, 10 MiB | ~1876-1893 MB/s | ~1841-1861 MB/s | noise-level, no consistent direction |
| Strumok-512, 10 MiB | 1886.47 MB/s | 1858.99 MB/s | noise-level |

**No gain anywhere; Kupyna measurably regresses.** Consistent with T-129/T-139's own `--emit=asm`
finding that this codebase's hot loops are already bounds-check-free scalar code with no independent
parallel work across loop iterations for an auto-vectorizer to exploit — enabling a wider ISA target
without restructuring the algorithm to actually process multiple blocks/words per call just adds
register-allocation pressure, which is the likely cause of Kupyna's small regression. **No code
change made** — same "complete, valuable outcome, not a shortfall" framing T-129/T-139 already
established for a spike that closes with nothing to land.

**Separately, the owner asked about a genuine hand-written SIMD implementation** (a real third
build profile alongside `fused`/`small-tables`, not just a compiler flag on the existing code) — that
is a materially different, larger proposal than the flag spike above, and carries risks distinct
from `small-tables`' own (D-38/D-39 was cheap precisely because it's the *same* code, same timing
profile, just smaller tables):

1. **Timing side-channel risk** — this project's only accepted secret-dependent-array-indexing
   exception (D-19) holds specifically because the current S-box/MDS lookups are fixed-latency
   scalar reads mirroring the DSTU reference implementations. Hand-written SIMD gather instructions
   (`vpgatherdd` etc.) have data-dependent latency on several microarchitectures (cache-line-conflict
   sensitive) — a naive vectorized table lookup could reintroduce exactly the timing channel D-19's
   scalar approach avoids. A genuinely constant-time SIMD path (bitslicing) is not "vectorize the
   existing loop" — it's a from-scratch alternative implementation of the primitive, need its own
   full research-before-implementation and dual-oracle pass, same bar as any new primitive.
2. **Contradicts D-01's portability pillar unless carefully scoped** — AVX2/AVX-512 are x86-64-only;
   ARM64 would need a separate NEON implementation, and no SIMD path exists at all for the embedded
   Cortex-M/RISC-V targets D-01 also commits to. A real SIMD variant needs per-ISA code plus runtime
   feature detection (`is_x86_feature_detected!` + scalar fallback) so a binary built for one CPU
   doesn't `SIGILL` on an older one — a kind of runtime branching this project has never needed
   before (`fused`/`small-tables` are both compile-time-only, byte-identical, no dispatch).
3. **Multiplies the verification matrix** — a SIMD code path is a distinct implementation, not an
   optimization of the existing one, so it needs its own dual-oracle vector pass, tamper/misuse
   tests, and its own CI matrix row (`small-tables`' own D-39 lesson: a new production-behavior
   feature not covered by `--all-features` alone silently drops out of coverage). Miri's SIMD-
   intrinsic support is also inconsistent enough that "cargo miri test as a required layer" may not
   cleanly cover the new code at all.
4. **No measured payoff to justify the above yet** — the flag-only spike above shows the current
   scalar code has nothing for a vectorizer to widen; a real gain would require changing the
   primitive's own call boundary (processing multiple blocks per call, the same idea AES-NI's
   multi-block pipelining uses), which is an API change, not a build-profile addition.

**Decision: not pursued for now.** Recorded as a deliberate non-implementation, the same posture
D-08 uses for post-quantum algorithms — revisit only if a concrete, measured use case justifies
carrying points 1-3's cost, not preemptively.

## D-108: `verify_combine` — a faster, default-profile-only `s*G + r*Q` for DSTU 4145 `verify`,
via López-Dahab projective coordinates and Shamir's trick; `scalar_multiply` itself untouched
(`docs/TASKS.md` T-151)

Following T-150's DSTU-4145-vs-ECDSA benchmark (`sign`/`verify` 20-190x slower than OpenSSL,
root-caused to `curve163::scalar_multiply`'s constant-time ladder having no windowing/
precomputation), the owner asked what could be optimized and whether it would be safe. Two
operations were distinguished: `sign`/`verifying_key()` multiply by a **secret** scalar (the
ephemeral nonce `e`, the private key `d`) and must stay constant-time; `verify`'s `s*G + r*Q`
multiplies only by **public** data (`r`, `s`, `Q`, `G` — `signature.rs`'s own module doc already
says so). The owner's explicit decision: **leave `scalar_multiply` completely unchanged** (used
identically for `sign`/`verifying_key()` in every build), and add a faster implementation **only**
for `verify`'s combine step, with an advisor-reviewed plan first.

**A naive approach was spiked and rejected before this one.** Composing a windowed multiply from
the file's existing affine `double`/`add` was measured (not assumed) to be a ~20x *regression*:
each `double`/`add` call carries its own field inversion, and `FieldElement::invert()` — measured
this session — costs **338.7x** a single `multiply()`/`square()` (1263ns vs 427781ns, release
build; direct Fermat exponentiation, not Itoh-Tsujii-accelerated). The only way to win is to defer
every inversion in a multi-step computation to a single one at the very end — projective
coordinates.

### Approach

**López-Dahab (X:Y:Z) projective coordinates, representing affine `(x,y) = (X/Z, Y/Z²)`**, combined
with **Shamir's trick** (simultaneous double-and-add over both scalars, one shared doubling per bit
position, using a 4-entry runtime table `{Infinity, G, Q, G+Q}` — `G+Q` computed once per `verify`
call via the existing trusted affine `Point::add`). Implemented in
`hazmat::dstu4145::curve163.rs`:

- `ProjectivePoint { x, y, z }`, `Z == ZERO` representing infinity.
- `double()`: the "dbl-2005-dl" formula (Bernstein/Lange Explicit-Formulas Database,
  `hyperelliptic.org/EFD/g12o/auto-shortw-lopezdahab.html`), specialized to this curve's `a2 = 1`.
  **Citation status**: no copy of Hankerson/Menezes/Vanstone "Guide to Elliptic Curve Cryptography"
  exists in `docs/papers/` (unlike `scalar_multiply`'s cited Algorithm 3.40), so the EFD page —
  fetched via raw `curl` and cross-checked character-for-character against the raw HTML, not
  trusted from `WebFetch`'s AI-summarized read alone, per this project's own standing distrust of
  `WebFetch` summarization on load-bearing content — is the citation of record. Its own stated cost
  (4M+5S) was independently re-derived by counting every `multiply`/`square` call in the
  transcribed Rust and matched exactly.
- `mixed_add()`: the "madd-2005-dl" formula (same source, 8M+5S), guarded ahead of the formula
  itself for **totality** (not attack resistance — see below) in this order: accumulator infinity →
  return the table point converted to projective form directly; table point infinity → return the
  accumulator unchanged; matching affine x (`B == 0` in the formula's own intermediate, reused
  rather than a separate comparison) → dispatch to `double()` if y also matches, else return
  infinity (char-2 negation is `(x, x+y)`, so matching-x-differing-y must be the negative).
- `to_affine()`: the single deferred inversion for the whole computation.
- `shamir_double_scalar_multiply(g, s, q, r)`: builds the table, finds the highest bit where `s` or
  `r` is set (safe to skip leading zeros — this is a public, variable-time path, unlike the
  ladder's fixed 163 iterations), then double-and-adds down to bit 0.

**On the infinity/x-coincidence guards**: an early draft of this entry described them as closing an
attacker-exploitable gap. That framing doesn't survive a read of `verify` itself
(`signature.rs:81`): the recomputed `r' = truncate_162(h·rx)` is checked against the caller-supplied
`r` regardless of what `verify_combine` does internally, so steering the accumulator to infinity
mid-computation gains an attacker nothing they couldn't get by guessing `r`/`s` outright. The real
reason the guards exist is that the López-Dahab formulas above are only defined for the generic
case (neither operand infinity, x-coordinates differ) — without them, a genuine signature whose
partial sum happens to coincide with the table point (structurally possible for any `Q`/`r`/`s`,
not just a ~2⁻¹⁶³ curiosity) would hit undefined formula behavior and could wrongly reject a valid
signature — a build-profile correctness divergence from `small-tables`, not a forgery vector. The
guards make the fast path total, which is required regardless of exploitability.

### Feature gating

Reuses the **existing** `small-tables` Cargo feature (`Cargo.toml` line ~35) that Kalyna/Kupyna/
Strumok already use for their fused-table/small-table split, same polarity: default (feature off)
= `verify_combine`'s new fast path; `small-tables` = today's unchanged
`g.scalar_multiply(s) + q.scalar_multiply(r)`. One function, two `#[cfg]`-gated bodies, matching
`hazmat::tables::apply_forward_matrix`'s exact idiom — no `#[cfg]` in `signature.rs`, which calls
`curve163::verify_combine(g, s, q, r)` unconditionally.

**Important disanalogy, stated explicitly rather than left implicit**: Kalyna/Kupyna/Strumok's use
of `small-tables` is a flash/ROM-vs-throughput trade (swap ~86 KB of `const` lookup tables for a
~6 KB `gf_mul`-based path). This is different: `verify_combine`'s fast path adds **no new `const`
table** — `{Infinity, G, Q, G+Q}` is computed fresh every `verify` call, not baked into the binary.
Reusing `small-tables` here is a **code-size/audit-surface** trade (one simpler, already-audited
code path for constrained/high-assurance targets vs. a second, newer implementation of the same
math for everyone else), not a flash-table trade. `docs/resource-profiles.md` is updated to say so.

### Engaging D-107's declined-SIMD reasoning point by point

D-107 declined a "third build profile" for hand-written SIMD, citing (a) D-19's narrow exception
scope, (b) portability, (c) verification cost, (d) no measured payoff. This work differs:

- **(a) sidestepped cleanly** — `verify_combine`'s fast path never touches secret-scalar code;
  `scalar_multiply` is untouched and remains the only function ever called with `e`/`d`.
- **(b) sidestepped cleanly** — pure portable Rust field arithmetic, no intrinsics, no per-ISA code,
  no runtime feature detection.
- **(c) only partially sidestepped, not eliminated** — this genuinely is a second implementation of
  `s*G + r*Q`. A bug in it produces a *behavioral divergence between build profiles* (default
  wrongly rejects/accepts relative to `small-tables`), the same class of risk D-39 already flagged
  for `small-tables` itself. The differential proptest below narrows this risk; it doesn't remove
  it the way (a)/(b) are removed outright.
- **(d) answered with a measured number, not the earlier session's arithmetic estimate** — see
  Results below.

### Tests

`crates/dstu-core/tests/dstu4145_curve.rs`, all calling the public `curve163::verify_combine`
wrapper (never the fast path's internals directly), each compared against
`g.scalar_multiply(s) + q.scalar_multiply(r)` computed inline from the existing trusted primitives
— trivially true under `small-tables` (literally the same code on both sides), genuinely
discriminating by default:

- `verify_combine_matches_classic_for_small_scalars` (1..=8 × 1..=8)
- `verify_combine_matches_classic_for_asymmetric_magnitudes` (one tiny scalar, one ~160-bit large
  scalar — deliberately **not** `order()-1`; see the T-152 note below for why that specific value
  is excluded here)
- `verify_combine_matches_classic_when_r_eq_s_eq_one` (loop body never executes)
- `verify_combine_handles_mid_loop_infinity` — hand-constructed: with `Q = -2G`, `s = 8` (`0b1000`),
  `r = 7` (`0b0111`), the Shamir accumulator hits exactly `Point::Infinity` after 2 bits
  (`(2 - 2·1)·G`) while the final result is nonzero (`(8 - 2·7)·G`) — exercises the totality guards
  directly rather than hoping a proptest stumbles onto a ~2⁻¹⁶³ event.
- `verify_combine_matches_classic_for_random_scalars` (proptest, random nonzero `s`/`r < n` via the
  160-bit pattern `dstu4145_signature.rs`'s existing round-trip proptest already uses, `q` derived
  from a random `d` the same way).

Every existing `verify`/`verify_digest` call in `dstu4145_signature.rs`/`crypto_sign.rs` (KAT,
tamper, misuse, round-trip) transitively re-verifies the new path with zero changes to those files,
since `verify` calls the wrapper unconditionally.

### Results

Fresh release builds, same dev machine, same methodology as T-150 (`uacrypt verify --iterations`,
same signature/key/message across both binaries, both confirmed to actually verify first):

| Profile | ops/s |
|---|---|
| Default (new fast path) | **239.31** |
| `small-tables` (classic, unchanged) | 120.06 |

**~1.99x measured speedup** — close to the ~1.9x arithmetic estimate worked out beforehand
(163 shared doublings + ~122 mixed-adds + 1 final inversion + the `G+Q` precompute, vs. the
classic path's 2 full ladders + 7 total inversions), which is itself a useful cross-check that
nothing unaccounted-for is happening.

**Miri**: measured, not assumed — even under the default profile's faster path,
`gf2m163_tampered_signature_is_rejected` (a `verify`-only test, no `sign` call) did not finish
within a 180-second `cargo +nightly-x86_64-pc-windows-msvc miri test --include-ignored` run.
~2x faster than "minutes" (T-100) is still minutes. All three `verify`-only tests in
`dstu4145_signature.rs` keep their `#[cfg_attr(miri, ignore)]` unconditionally, unchanged.

**CI, stated precisely**: `.github/workflows/rust.yml` already runs `cargo test --workspace`
(default) and `cargo test --workspace --features dstu-core/small-tables` as separate steps — no new
feature, no new CI matrix row needed. But `--all-features` turns `small-tables` **on**, so that
job's final "all features" pass exercises the *slow/classic* path, not the new one — only the bare
`cargo test --workspace` step exercises `verify_combine`'s fast path. Both passes run the
differential tests above; only one of them is actually discriminating.

### A separate finding, filed but not chased here

Building the differential proptest surfaced a `scalar_multiply` question unrelated to this work:
for `q = G.double()`, `q.scalar_multiply(&curve163::order())` is not `Point::Infinity`, and
`q.scalar_multiply(&(order()-1))` equals `q` rather than `q.negate()` — both surprising given `q`
has order exactly `n` (`n` is odd, so `gcd(2,n)=1`). 200 random ~163-bit scalars unrelated to
`order()`'s specific value all showed the doubling homomorphism holding correctly, so this isn't a
general "large scalar" issue — it's specific to values at/adjacent to `n` itself, and `order()`
itself is arguably outside `scalar_multiply`'s own documented `k < n` contract regardless. Filed as
`docs/TASKS.md` T-152 (not fixed here, needs its own dual-oracle cross-check) — this is why
`verify_combine_matches_classic_for_asymmetric_magnitudes` above uses a large-but-not-`order()-1`
scalar instead of the boundary value. **Update, later session: root-caused, oracle-confirmed, and
fixed — see D-110 below.**

`cargo test --workspace` / `--features dstu-core/small-tables` / `--all-features`,
`cargo clippy --workspace --all-features -- -D warnings`, and `cargo fmt --all --check` all pass.

## D-109: bit-interleave `square` + Itoh-Tsujii-style addition-chain `invert` for GF(2^163) -
unconditional, no feature gate, benefits `sign` for the first time (`docs/TASKS.md` T-153)

D-108's ~1.99x `verify` speedup felt too small to the owner ("Щось приріст надто малий, ми
відстаємо на порядок... повинно бути щось суттєвіше") given `verify` is still ~21-23x slower than
OpenSSL's `nistb163` and `sign` (untouched by D-108) is ~20.7x slower. The owner asked whether
caching/tables could do better, in the order windowing-then-squaring; an advisor-reviewed
cost-analysis agent was asked to check that ordering rather than assume it, with instructions to
report honestly if the suspicion (windowing has a low ceiling) held up.

### The analysis, and why the order got reversed

- **Table-based squaring** (literally what the owner asked about) reintroduces the exact
  secret-indexing question D-19/D-25 carefully scoped: a plain array lookup keyed on a byte of a
  **secret** field element, inside `scalar_multiply`'s ladder, is a fresh case D-19's exception
  doesn't cover (that exception is scoped specifically to S-box/MDS lookups mirroring the DSTU
  reference implementations). A masked/branchless version (reading the whole table every time,
  `cswap`-style) would likely cost *more* than today's `multiply(self,self)`-based `square()`,
  making `sign`'s constant-time path slower, not faster - the one thing this option was supposed to
  help.
- **Windowing `verify_combine` alone has a low ceiling**, confirmed rather than assumed: it only
  reduces point-*additions*, not the ~163 point-*doublings* needed to shift the Shamir accumulator
  across the full bit-length, and doublings already dominate cost. A joint `(a,b)`-table blows up
  combinatorially past window-width 2; a decoupled "comb-for-`G` + separate-ladder-for-`Q`" design
  loses Shamir's shared-doubling benefit entirely (163 shared doublings -> 184 total: 163 for `Q`'s
  own chain + 21 for `G`'s comb). A first draft of this analysis also missed that converting a
  runtime-built table of `Q`'s projective multiples back to affine form (needed for `mixed_add`'s
  affine-only second argument) would cost one inversion *per table entry* unless a new Montgomery
  batch-inversion primitive is built - advisor review caught this gap, which raises windowing's real
  cost above the first estimate. Net ceiling: **~1.1-1.2x** beyond D-108's already-shipped 1.99x -
  not the order-of-magnitude the owner was looking for, and it only helps `verify` - `sign` stays
  untouched either way.
- **The actual lever, found during review, not in the owner's original two-item list**:
  `gf2m163::square()` was just `self.multiply(self)` (zero shortcut), and `FieldElement::invert()`
  (measured this session at **338.7x** a single `multiply()`/`square()` call, 1263ns vs 427781ns
  release build) was a direct 162-round Fermat exponentiation - despite its own doc comment already
  naming Itoh-Tsujii as the intended, asymptotically-faster approach, a documented-vs-shipped gap
  nobody had gone back to close. Both fixes are **unconditional** (every caller, every build
  profile, including `sign`/`verifying_key()` for the first time) and need **no new constant-time
  exception**, unlike table-squaring.

Owner approved the corrected order: squaring + Itoh-Tsujii first, re-measure, then only pursue
windowing if the numbers still justify it.

### Approach

**Bit-interleave squaring** (`gf2m163.rs`): GF(2) squaring satisfies `a(x)^2 = a(x^2)` (char-2
cross terms vanish: `(a_i*x^i)^2 = a_i*x^(2i)` since each coefficient is 0 or 1) - a pure bit-spread,
not a multiplication. `spread32to64(x: u32) -> u64` places bit `i` of `x` at bit `2*i` of the
result (zero inserted between every pair), via the "interleave bits by binary magic numbers"
technique (Sean Eron Anderson's Bit Twiddling Hacks,
`graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN`), widened from its usual
16-to-32-bit form to 32-to-64-bit by doubling every mask/shift constant. `square_wide(a: &[u64;3])
-> [u64;6]` applies this to each limb's low/high 32-bit halves independently - limb `i`'s low 32
bits (global bits `[64i, 64i+31]`) spread to output limb `2i`, its high 32 bits (`[64i+32,
64i+63]`) to output limb `2i+1`, both landing exactly on a limb boundary with no shift needed at
placement time. `FieldElement::square()`'s body changes from `self.multiply(self)` to
`reduce(square_wide(&self.0))` - the existing, unchanged `reduce()` consumes the wide result
exactly as it already does for `multiply()`'s `poly_mul_wide` output. No array indexing anywhere in
either new function, so no D-19-adjacent question exists at all - fits directly inside D-25's
"branchless by construction" posture, extended to a fresh operation.

**Itoh-Tsujii-style addition-chain inversion** (`gf2m163.rs`): `2^163 - 2 = 2*(2^162 - 1)`, so
`invert()` computes `(self^(2^162-1))^2`. `self^(2^162-1)` is built via repeated application of
`T_(i+j) = T_i^(2^j) * T_j` (`T_k` denoting `self^(2^k-1)`) over the chain derived directly from
`162 = 2*81 = 2*(80+1)`: `1 -> 2 -> 3 -> 6 -> 12 -> 24 -> 27 -> 54 -> 81 -> 162` - **9** combine
steps (9 multiplies total), each preceded by the fixed number of squarings its `2^j` factor costs
(squaring does **not** become free in this polynomial-basis representation - the ~162 total
squarings are unchanged from the direct form; only the multiply count drops, from 162 to 9). The
chain was derived and verified by test, not transcribed from a citation hunt (a deliberate choice,
given this same session's earlier `verify_combine`/`order()` debugging cost real time chasing a
paper trail instead of the test) - the differential test against `invert_direct` (the prior direct
form, kept as a test-only oracle, not a second production path) is the actual proof of correctness.
The chain is a fixed, public sequence over a fixed, public exponent, identical for every call
regardless of `self`'s value - the same constant-time argument that already justified the prior
fixed-iteration direct form.

### Tests

- `square_wide_matches_multiply_wide_at_limb_boundaries`/`_for_all_bits_set` (`gf2m163.rs` internal
  `#[cfg(test)]`, since `square_wide` is private): differential against the already-trusted
  `poly_mul_wide(a, a)` oracle at the **wide** (pre-`reduce`) level specifically, not just the final
  reduced result - catches a placement bug `reduce()`'s own normalization could otherwise silently
  absorb. Covers bit 0/1, bits 63/64/65 (limb-0/limb-1 boundary), bits 127/128/129 (limb-1/limb-2
  boundary), bit 162 (top meaningful bit, limb 2 is only 35/64 full), and every meaningful bit set
  at once.
- `gf2m163_square_matches_multiply_at_byte_boundaries` + a proptest
  (`gf2m163_square_matches_multiply_for_random_elements`) in the external `dstu4145_gf2m.rs`,
  against the public API (`a.square()` vs. `a.multiply(a)`).
- `invert_matches_invert_direct` (proptest) + `invert_matches_invert_direct_at_edge_values`
  (`ONE`, and a value with only the top meaningful bit set) in `gf2m163.rs` internal tests, against
  `invert_direct` (the preserved prior direct-loop form).
- **Zero changes needed** to any existing vector/KAT test (`gf2m163_arith.json`'s `"square"`/
  `"invert"` cases, `gf2m163_invert_is_involution_via_reciprocal`, every `dstu4145_signature.rs`/
  `dstu4145_curve.rs`/`crypto_sign.rs` sign/verify test) - all transitively re-verify both new
  implementations with no test edits, since every one of them calls through the public
  `square()`/`invert()` API this change replaces underneath.
- **One Kani proof written**, `square_wide_matches_poly_mul_wide_self` - same structural shape as
  `reduce`'s two existing proofs (fixed shift/AND/OR/XOR over a symbolic input, no data-dependent
  bounds), constrained via `kani::assume(a[2] >> 35 == 0)` to the actual `FieldElement` invariant
  (top 29 bits of limb 2 clear) rather than the full unconstrained `[u64;3]` space, since that's the
  real precondition every caller upholds. **Not compiled or run locally**: `#[cfg(kani)]` is gated
  out of every build/test/clippy/fmt command this session ran, and `kani` isn't a dev-dependency
  here for `--cfg kani` to resolve outside the real tool anyway. `cargo kani` is Linux/macOS-only
  (`xtask::kani`, D-102), so CI is this proof's first actual execution, not a second confirmation of
  one already run - read its real pass/fail from the CI run itself, don't assume from a clean local
  build the way this project's own standing rule already warns against for CI badges in general.
  **`invert()`'s own addition-chain proof was deliberately not attempted** - unlike `square_wide`, it
  would need to symbolically execute the full ~162-squaring, 9-multiply chain end to end (an
  unrolled field-arithmetic computation, not a fixed bit-shuffle), an enormous SAT instance by
  comparison. Recorded as "not attempted, expected intractable," the same T-100 precedent already
  established for Miri applied here to Kani, rather than left as an open best-effort item.

### A pre-existing clippy finding fixed in passing

`cargo clippy --workspace -- -D warnings` (the **default**, no-features profile - a real, separate
required CI step, distinct from `--all-features`) failed on `curve163.rs`'s
`shamir_double_scalar_multiply` (D-108's own code, confirmed via `git stash` to already fail at
`ef2eb49` before this session's changes): `clippy::cast_possible_truncation` on
`((bit_at(s, i) << 1) | bit_at(r, i)) as usize`. `bit_at` only ever returns 0 or 1, so the index is
provably `0..=3` - fixed with a scoped `#[allow(clippy::cast_possible_truncation)]` and a one-line
comment stating why, per this project's own rule that a CI-static-analyzer finding on your own
branch's history gets fixed in the same pass, not left open because tests already passed.
Unrelated to this task's own scope, fixed because it was discovered while verifying clippy across
all four feature combinations for the square/invert change.

### Results

Fresh release builds, same dev machine, same methodology as T-150/T-151 (`uacrypt sign`/
`verify --iterations 5000`, same key/signature/message across all binaries, each confirmed to
actually sign/verify successfully first):

| | `sign` ops/s | `verify` ops/s (default/fast path) | `verify` ops/s (`small-tables`/classic) |
|---|---|---|---|
| Pre-D-108 baseline (T-150) | 255.98 | 120.06 | 120.06 |
| Post-D-108 (T-151) | 255.98 (unaffected) | 239.31 | 120.06 (unaffected) |
| Post-D-109 (this entry) | **667.39** | **524.01** | **328.20** |
| Speedup vs. immediately-prior row | **~2.61x** | **~2.19x** | **~2.73x** |
| Cumulative speedup vs. pre-D-108 baseline | **~2.61x** | **~4.37x** | **~2.73x** |

`sign`'s ~2.61x is close to the ~2.3x estimate worked out beforehand, and is `sign`/
`verifying_key()`'s first-ever speedup, since D-108 explicitly left `scalar_multiply` untouched.
`verify`'s default-path number cumulatively beats OpenSSL's `nistb163` gap down to **~5.2x slower**
(was ~22.6x pre-D-108); `sign` similarly improves to **~7.9x slower** (was ~20.7x). Note
`small-tables`'s own internal speedup (~2.73x) isolates Phase A+B's pure field-arithmetic
contribution in isolation, holding the combine algorithm fixed (classic, unchanged) - useful as a
cross-check that the field-arithmetic work alone, independent of D-108's projective-coordinates
work, is responsible for a large, genuine share of the gain, not just the two effects being
conflated.

**`sign`'s own profile split isn't a code-path difference, and the ~5% gap between them isn't
noise**: `sign` measured 667.39 ops/s under default, 633.93 ops/s under `small-tables` (table above
reports the default number only, as the table is organized by `verify`'s profile split, which is
the actual code-path fork - `sign`'s own path never branches on this feature). `sign_digest`
derives its deterministic nonce via Kupyna-KMAC (D-46), and `small-tables` swaps Kupyna's own
internal table-vs-computed path - a real, separate effect from this entry's `square`/`invert` work,
not measurement jitter and not something either D-108 or this entry claims to control for.

### The Phase D (windowed `verify_combine`) decision

The plan set this threshold **before** the numbers existed (same discipline as D-108's own upfront
estimate check): pursue a windowed Shamir table for `verify_combine` only if **total default-path
`verify` throughput landed below ~3.5x of the original pre-D-108 classic baseline (120.06 ops/s)** -
the gate is read against that cumulative total, **not** against this entry's own isolated increment
over D-108 (~2.19x, which alone would misleadingly look like it satisfies "below 3.5x") - **and** a
quick spike showed Montgomery batch inversion (needed for the windowing table) would cost under
~10% of the combine step. **The measured cumulative total is ~4.37x (524.01 ops/s vs. 120.06),
already past the 3.5x threshold** - Phase D is explicitly not pursued. This is a deliberate stop
decided against a pre-committed number, not an oversight or a task left incomplete; windowing's own
ceiling (~1.1-1.2x more, per the cost analysis above) would not have justified the new `G_TABLE`
const data, a new Montgomery batch-inversion primitive, and their audit/test surface even if the
threshold hadn't
already been crossed.

`cargo test --workspace` / `--features dstu-core/small-tables` / `--all-features`, `cargo clippy`
on all four of `.github/workflows/rust.yml`'s feature combinations (default, `small-tables`,
`--no-default-features --features getrandom`, `--all-features`) with `-D warnings`, and
`cargo fmt --all --check` all pass (the pre-existing CRLF/newline-style warning on Windows checkouts
under `autocrlf=true` is a known, already-diagnosed local artifact, reproduced even at a clean `git
stash` of this session's changes - not a real content difference, see D-108's own prior session
notes). `cargo build --workspace --no-default-features` (`no_std` check) passes. Miri (via
`cargo +nightly-x86_64-pc-windows-msvc miri test`, `MIRIFLAGS=-Zmiri-disable-isolation
PROPTEST_CASES=1` matching CI's actual invocation, not the crate's proptest default of 256 cases):
`square_wide`'s tests pass in ~4.6s; the new external `square` tests (proptest + edge cases) pass in
~25s; `invert_matches_invert_direct` (proptest, 1 case under CI's real `PROPTEST_CASES=1`) and
`invert_matches_invert_direct_at_edge_values` (2 fixed cases) both independently confirmed to
complete (respectively within a shared budget, and in ~106s standalone) - all tractable, none
needed a new `#[cfg_attr(miri, ignore)]`.

**A real Miri coverage gain, not just "no regression"**: this entry's 9-multiply `invert()`
invalidated the stated rationale behind several *pre-existing* `#[cfg_attr(miri, ignore)]`
exclusions from T-100 - each one said `invert`'s old 162-multiply direct form was "as expensive per
call as `scalar_multiply`'s ladder," which is no longer true. Re-measured (not left as a stale
comment next to now-faster code) at `MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`:
`gf2m163_field_arithmetic_matches_bouncy_castle` (20 invert vector cases of 80 total) now completes
in **~76s** (was unbounded/excluded); `gf2m163_invert_is_involution_via_reciprocal` in **~230s**;
`gf2m163_point_double_matches_bouncy_castle`/`gf2m163_point_add_matches_bouncy_castle` (each one
`invert` call per vector case, via `Point::double`/`add`) in **~91s**/**~95s**. All four exclusions
removed - `dstu4145_gf2m.rs`/`dstu4145_curve.rs` comments updated to explain why. **Left
unconditionally excluded**: `scalar_multiply`-based tests (`gf2m163_scalar_multiply_matches_
bouncy_castle` re-confirmed still not finishing within 300s) and every `sign`/`verify`/`crypto_sign`
round-trip test - their exclusion rests on `scalar_multiply`'s own 163-iteration ladder cost, which
this entry doesn't touch (only `invert()`'s multiply count and `square()`'s cost within each
iteration changed, not the iteration count itself).

## D-110: `scalar_multiply` correctness bug at the curve-order boundary, root-caused and fixed
(`docs/TASKS.md` T-152)

T-151/D-108's own differential tests surfaced a finding filed as T-152 rather than chased in that
session: for `q = G.double()` (order exactly `n`, `n` odd so `gcd(2, n) = 1`),
`q.scalar_multiply(&curve163::order())` was not `Point::Infinity` (Lagrange's theorem), and
`q.scalar_multiply(&(order()-1))` equaled `q` itself instead of `q.negate()`. The owner asked for a
deep investigation this session, with oracle confirmation and an advisor consult, not just internal
reasoning - this entry is that investigation, plus the fix.

### Root cause

`scalar_multiply`'s final projective-to-affine step (`curve163.rs`) recovers `kP`'s affine
coordinates from the ladder's `(X1:Z1)`/`(X2:Z2)` pairs, which respectively hold `kP`/`(k+1)P`.
That recovery formula is only valid when **both** `kP` and `(k+1)P` are finite points - it needs
each one's affine x-coordinate, and infinity has none. The code never checked this: it called
`z1.invert()`/`z2.invert()` unconditionally, and `FieldElement::invert(ZERO)` returns `ZERO` (a
deliberate "undefined but zero by Fermat's formula" convention, not a panic - see `gf2m163.rs`'s
own doc comment) rather than signaling infinity. Two distinct corruptions follow, confirmed by a
scratch probe (`q.scalar_multiply` at `k = 0, n-1, n, n+1`, deleted before commit - not part of the
permanent test suite) before any fix was written:

- **`z1 == ZERO`** (`kP == O`, i.e. `k == 0` or `k == ord(self)`): `x1_affine` comes out `0`
  (garbage, not "no valid x"), and - worked out algebraically and confirmed by the probe - the
  y-recovery formula reduces to `y1 = x^2` in this case (not a random value, a specific wrong one).
  Reproduced at both `k = 0` and `k = n` (probe output identical for both: `(0, x^2)`).
- **`z2 == ZERO`** (`(k+1)P == O`, i.e. `k == ord(self) - 1`): `x1_affine` is actually correct here
  (this curve family's negation is `(x,y) -> (x, x+y)` - `P`/`-P` share an x-coordinate, so a
  correct x can't distinguish them), but the y-formula's dependence on `x2_affine` (silently `0`
  instead of undefined) reduces algebraically to `y1 = y` - i.e. the function returns `q` verbatim
  instead of `q.negate()`, exactly matching T-152's original report.

### Oracle confirmation (not just self-consistency)

A new one-off Java program (`tests/oracle-harness/java/src/main/java/Dstu4145T152Oracle.java`,
same "one-off debug tool" precedent as `Dstu4145Debug.java`, D-25) computed `Q.multiply(n)`,
`Q.multiply(n-1)`, `Q.multiply(n+1)` via Bouncy Castle's own `ECPoint` arithmetic, independent of
anything in this codebase: confirmed `Q.multiply(n)` is `INFINITY` and `Q.multiply(n-1)` equals
`Q.negate()` exactly (both `true` per the program's own boolean checks) - i.e. the *expected*
correct values, not just a re-derivation of what "should" happen. This is the dual-oracle
confirmation T-152 asked for before concluding anything further.

### Severity

Reachable in the documented `k < n` contract only at the single point `k == n - 1` (probability
`~2^-163` for a uniformly random secret scalar - `sign`/`verifying_key()`'s own scalars are never
realistically going to land there). An advisor review initially raised whether this was
attacker-reachable via `small-tables`' `verify_combine(g, s, q, r) = g.scalar_multiply(s) +
q.scalar_multiply(r)`, since `r`/`s` are parsed from the signature - checked `signature.rs::verify`
and confirmed `r`/`s` are only bounded to `(0, n)`, so `s == n - 1` (or `r == n - 1`) does reach the
buggy path there. On reflection this is not a live concern either direction: reaching it requires
*constructing* a signature whose own `s` (or `r`) equals `n - 1`, which no honest signer ever
produces (same `~2^-163` improbability as the scalar itself) and which only affects whether that
one self-selected signature verifies - there's no attacker action that turns this into rejecting
*someone else's* valid signature, and the final `r' == r` check means it was never a forgery vector
either. **Net**: an in-contract correctness bug at one specific boundary scalar, no realistic
security consequence in either direction. The default profile's projective/Shamir path (D-108) was
never affected - `ProjectivePoint::to_affine`/`mixed_add` already guard `Z == ZERO` throughout.

One further boundary noted but not chased: `z2 == 0` also arises for every odd `k` when `self` has
order 2 (`x == 0`), a case this fix doesn't special-case - but that input is already broken upstream
of this fix (`x.invert()` on `ZERO` in the same recovery step), and DSTU 4145 only ever calls
`scalar_multiply` on `G` or an already-validated `Q`, neither of which is an order-2 point. The fix
assumes a full-order input point; recorded here, not worth a dedicated check.

### The fix - two different cases, two different shapes, per advisor review

The two corruptions are not the same bug and don't take the same fix:

- **`z1 == ZERO`** (`k == 0`/`k == ord(self)`): `Point::Infinity` is a different **enum variant**
  from `Point::Affine` - not a same-shape value a branchless mask can select between, unlike the
  other case. Fixed with an explicit early-return branch right after the ladder loop: `if
  is_zero_mask(z1) != 0 { return Point::Infinity; }`. This only fires for `k == 0` or `k >=
  ord(self)`, both outside (or at the exact edge of) `k < n`'s documented contract for a full-order
  point - a deliberate, named exception to this function's branchless posture, not a fresh timing
  side channel for any in-range secret scalar DSTU 4145 actually constructs. **The zero *test*
  itself still uses `is_zero_mask`, not `z1 == FieldElement::ZERO`** - a first draft used the
  derived `PartialEq`, which an advisor review caught as a `==` on secret-derived data, exactly what
  `docs/SECURITY.md`'s hard constraint forbids (the branch on the resulting mask is the only
  data-dependent step left, which is unavoidable given the enum-variant mismatch).
- **`z2 == ZERO`** (`k == ord(self) - 1`): genuinely inside the documented contract, and `z2` is
  secret-scalar-derived, so this needed to stay branchless. The correct answer is exactly
  `-self = (x, x + y)` (`Point::negate`) - `x1_affine` is already right either way, so only `y`
  needs correcting. Two new private helpers in `curve163.rs`, matching the file's existing
  `cswap`-style manual-mask idiom rather than pulling in `subtle` (this file's own established
  branchless-mask convention, not a project-wide rule against `subtle` - `subtle::ConstantTimeEq`
  remains the right tool for byte-slice/tag comparisons elsewhere in this codebase):
  - `is_zero_mask(a: FieldElement) -> u64`: the standard `x | wrapping_neg(x)` top-bit branchless
    zero test (for nonzero `x`, either `x` or `-x` has its sign bit set in two's complement; for
    `x == 0` neither does), applied to the OR of all 3 limbs.
  - `select(mask, if_mask, otherwise) -> FieldElement`: one-sided branchless select, same
    XOR-and-mask shape as `cswap`'s swap.

  `y1_affine = select(is_zero_mask(z2), x + y, y1_affine_formula)` - the formula still computes
  (and `z2.invert()` is still called on a possibly-zero value, staying branchless), but the
  corrupted result is masked out afterward rather than trusted. `gf2m163.rs`'s `invert()` doc
  comment updated to name this as the one documented exception to "callers must never invert
  zero," rather than leaving that claim silently false.

### Tests

`crates/dstu-core/tests/dstu4145_curve.rs`: `scalar_multiply_at_order_boundary_matches_bouncy_castle`
(direct boundary check at `k = 0, n-1, n, n+1` against `Point::Infinity`/`q.negate()`/`q`/`q`) and
`verify_combine_matches_classic_at_order_boundary` (the same boundary through both `verify_combine`
build-profile bodies). Both carry the same `#[cfg_attr(miri, ignore = ...)]` as the file's existing
`scalar_multiply`-based tests (T-100) - each calls `scalar_multiply` several times, and that
ladder's per-call cost, not this fix, is what's too slow to interpret under Miri.

**Confirmed both tests actually catch the bug, not just pass vacuously**: `git stash`ed the two
`src/` fixes and re-ran both tests pre-fix. `scalar_multiply_at_order_boundary_matches_bouncy_castle`
fails in both build profiles (a direct correctness check, not a differential one). Verifying
`verify_combine_matches_classic_at_order_boundary` this way is what caught a wrong first-draft
claim: it only discriminates under the **default** profile (fails pre-fix there, as expected, since
default's already-infinity-safe Shamir path disagreed with `classic_combine`'s then-buggy
`scalar_multiply` calls); under `small-tables` it passes **even pre-fix**, because
`verify_combine`'s own `small-tables` body *is* `classic_combine`'s definition (same "trivially true
under `small-tables`" caveat the file's other tests already carry) - both sides call the same
(then-equally-buggy) `scalar_multiply`, so they agree regardless of whether it's correct. The test's
doc comment states this explicitly rather than the stronger (and, before this check, wrong)
"both profiles now agree" claim. The pre-existing
`verify_combine_matches_classic_for_asymmetric_magnitudes` test's comment (which had explicitly
steered its large-scalar case away from `order()`/`order()-1` because of this exact finding) is
updated to point at the new dedicated boundary test rather than continuing to avoid it. Zero changes
needed to any other existing test - all transitively re-verify through the public API.

### Verification

Full workspace `cargo test` (all passing, no failures), `cargo test --features small-tables` for
`dstu4145_curve`/`dstu4145_gf2m`, `cargo clippy --workspace --all-features -- -D warnings` and both
the default and `small-tables`-only profiles individually, `cargo fmt --all --check`, `cargo build
--no-default-features` (`no_std` check) - all clean. The scratch probe used to confirm the root
cause and the fix (`crates/dstu-core/examples/t152_probe.rs`) was deleted before committing, per
this project's convention that a one-off investigation aid doesn't become a shipped artifact (it
would otherwise sit in the crate's real `examples/` directory alongside the permanent
`*_diff_cases.rs` examples) - the permanent regression coverage is the two tests above, not the
probe.

## D-111: survey for T-152-shaped bugs across the other DSTU primitives (`docs/TASKS.md` T-154)

After D-110 shipped, the owner asked directly: do the other DSTU standards in this codebase
(Kalyna, Kupyna, Strumok) need the same kind of boundary-value tests? Rather than guess, surveyed
the codebase for the specific bug *shape* T-152 was, consulted advisor before concluding, and
closed the one genuine analogue found (in DSTU 4145 itself, not the other three algorithms).

### The bug shape, precisely, so the survey has a real filter

T-152 wasn't "an edge case was untested" in general - it was specifically: **a routine's
correctness rests on an algebraic precondition expressed as a formula, not a branch** (the
projective-to-affine recovery silently assumed `kP`/`(k+1)P` are finite, with no check), **and the
precondition fails only on a vanishingly small set of inputs** (`~2^-163` of the space) that no
amount of random sampling - fixed KAT vectors *or* proptest - will ever land on by chance. That
combination is the actual filter: a formula (not a branch) whose validity silently depends on
avoiding a low-probability set. A branch that already handles a degenerate case explicitly, or a
degenerate case with probability high enough that testing would organically hit it, is a different
and lesser concern.

### Where it does not exist

- **Kalyna, Kupyna, Strumok**: no field inversion and no "point at infinity"/degenerate-element
  concept anywhere in these three algorithms' code (`grep -rln "invert" crates/dstu-core/src/
  hazmat/` returns only `curve163.rs`/`gf2m163.rs` plus one false positive - `kupyna_kmac.rs`'s
  `inverted_key` local variable, an unrelated XOR-padding name, not a field inversion). These are
  SPNs/an LFSR+FSM stream cipher, not curve/field arithmetic with a "formula assumes non-degenerate
  input" structure - the bug class genuinely does not exist outside DSTU 4145.
- **Kalyna-GCM/CCM/CTR counter increment**: `wrapping_add`-based, full block width (not a
  NIST-style truncated 32-bit counter), wraps only after `2^128` blocks. Not a T-152-shaped
  boundary at all - it's unreachable *by construction* (no realistic message size gets remotely
  close), not unreachable *by improbability* the way `k = n-1` was reachable-in-principle. Different
  category, correctly not pursued.
- **`curve163::ProjectivePoint`'s own infinity guards** (`mixed_add`/`to_affine`, `verify_combine`'s
  fast path, D-108): already has a **deliberately hand-constructed** test for exactly this shape -
  `verify_combine_handles_mid_loop_infinity`, which builds a specific `s`/`r` pair so the Shamir
  accumulator hits `Point::Infinity` mid-loop, not just checks it never does. This is the pattern
  working as intended, cited here as the precedent D-110's own new boundary tests followed - not
  itself a gap.

### Where a real (though much smaller) analogue existed: `signature::sign`'s three `None` branches

`sign` returns `None` on three conditions (its own doc comment already calls these out as
`~2^-163`-probability "degenerate-value rejections": `Point::Infinity` from `g.scalar_multiply(e)`,
`fe_x == ZERO`, `is_zero(r)`/`s.is_zero()`). All three are explicit `if`-then-`return None`
branches - visibly correct on inspection, unlike T-152's silently-wrong formula - so an advisor
review was explicit that this is **not** the T-152 shape; the only real open question was narrower:
does each branch actually fire cleanly, or does something upstream break first, and (per the
`Scalar`-foreclosure precedent this project already uses, `CLAUDE.md`'s "misuse category foreclosed
by the type signature" rule) is it even reachable at all. Splits three ways once actually checked:

1. **`Point::Infinity` (`g.scalar_multiply(e) == O`)**: provably unreachable for `g = generator()`
   and any `Scalar` `e` - `Scalar::from_be_bytes`'s own callers already reject `e == 0`
   (`from_bytes_rejects_zero_scalar`, `crypto_sign.rs`), and `G` has prime order `n`, so `e*G == O`
   only when `e ≡ 0 mod n`, impossible for `e ∈ [1, n)`. Foreclosed by the type/contract, per
   `CLAUDE.md`'s existing rule - documented here, no test written that would only prove the
   compiler (or `Scalar`'s own already-tested rejection) works.
2. **`fe_x == ZERO`**: *also* provably unreachable for `g = generator()`, for a different,
   curve-theoretic reason worth stating explicitly since it's non-obvious: the curve's unique point
   with `x = 0` is `(0, sqrt(b))` (every `GF(2^163)` element has exactly one square root - the
   Frobenius map `x -> x^2` is a field automorphism in char 2, so it always exists), and that point
   has order exactly 2 (`Point::double`'s own `x1 == ZERO -> Infinity` branch confirms this
   algebraically and in code). Since `n` (the order of `G`) is odd, `gcd(2, n) = 1`, so a point of
   order 2 cannot lie in the cyclic subgroup `<G>` (Lagrange's theorem: every element's order in
   `<G>` divides `n`, which has no factor of 2). Therefore no integer `e` ever makes `e*G`'s x-
   coordinate zero. Confirmed computationally, not just algebraically, via a scratch probe (deleted
   after use): built `(0, sqrt(b))` directly from `b`'s square root (`y = b^(2^162)`, the Frobenius
   inverse) and confirmed `y^2 == b` and `Point::double` sends it to `Infinity`. Foreclosed given
   honest `g = generator()` (the only way `sign`/`crypto_sign` ever call this in practice) -
   documented, not tested for reachability that doesn't exist.
3. **`is_zero(r)` / `s.is_zero()`**: genuinely reachable at `~2^-163` for honest inputs, **not**
   foreclosed by any type - `hash`/`e` are freely caller-chosen at the `hazmat` layer (any byte
   string decodes to *some* `FieldElement` via `hash_to_field`), and unlike the two branches above,
   this makes them **deliberately constructible by solving backward**, not brute force: a scratch
   probe (`crates/dstu-core/examples/sign_degenerate_probe.rs`, deleted after use) computed
   `h = (2^162) * fe_x^{-1}` for `e = 1` (forcing `r`'s low-162-bit truncation to zero, since
   `fe_x^{-1}` is directly computable via the already-public `FieldElement::invert`), and
   `d = -e * r^{-1} \bmod n` for a second `e`/`hash` pair (forcing `s = r*d + e \equiv 0`, via a
   scratch extended-binary-GCD written only for this probe - `Scalar` itself has no `invert()`,
   deliberately not added just for this). Both confirmed to make `sign` return `None` exactly as
   predicted - now permanent tests, `sign_rejects_when_r_would_be_zero`/
   `sign_rejects_when_s_would_be_zero` in `dstu4145_signature.rs`, hardcoding the computed `h`/`d`
   values (no Miri exclusion needed - each is a single `sign` call, same cost class as the file's
   existing single-call worked-example tests, not the many-iteration proptest that does carry one).

### The generalizable rule (the durable output of this survey)

Not "add boundary tests everywhere" - narrower: **where a routine's correctness rests on an
algebraic precondition expressed as a formula rather than a branch, random sampling (fixed vectors
or proptest) is structurally blind to it; the boundary must be enumerated by reading the code**
(what makes a denominator zero, an inverse undefined, a projective coordinate vanish) **and tested
explicitly, or proven exhaustively where that's tractable.** The corollary this project already has
evidence for: `gf2m163::reduce`/`square_wide` are immune to this specific failure mode because Kani
proves them over *every* possible input (not a sample) - `scalar_multiply` was exposed precisely
because it's the one function in this family exhaustive verification can't reach (D-109's own
"not attempted, expected intractable" call). That intractability is the actual signal for where
this class of bug can hide, not a rule to sprinkle boundary tests on every function generically.
Added as a new bullet in this project's `CLAUDE.md` "Agent discipline" list, cross-referencing
rather than duplicating the existing D-64/D-65 three-test-category rule - that rule is about a new
primitive's initial coverage checklist (correctness/rejection/misuse), this one is a narrower
methodology note about what a "correctness against a vector/oracle" test can and cannot see.

### Verification

`cargo test -p dstu-core --test dstu4145_signature` (7 tests, including the two new ones) and the
full workspace suite all pass; `cargo clippy --workspace --all-features -- -D warnings` and
`cargo fmt --all --check` clean. Both scratch probes used for this survey (the `sqrt(b)`/order-2
check and the `sign_degenerate_probe.rs` backward-solve) were deleted before committing, same
convention as D-110's own probe.

## D-112: D-109's `square_wide` Kani proof was overstated as "expected tractable" - CI proved
otherwise, replaced with a proof of the actual novel arithmetic instead

Discovered running the release checklist before tagging v0.2.0: `cargo kani` on `master` had been
**red** since T-153/D-109's own commit (`b3fec3e`), not caught earlier because a prior CI check in
this same session happened to run before that job finished, and nobody re-checked its final
conclusion before moving on to T-152/T-154's own commits (both of which inherited the same failure,
unnoticed, since their own CI runs were also not fully re-checked at completion). This is exactly
the "verify a CI job's real conclusion via `gh run view`, never assume from a green badge" lesson
this project's own `CLAUDE.md` already states for the Miri job (T-100/D-59) - it applied here too,
missed once, caught now before a release shipped on top of it.

### What was actually wrong

D-109's doc comment claimed `square_wide_matches_poly_mul_wide_self` was "same structural shape as
`reduce`'s two existing proofs... so expected tractable" and asked CI to confirm rather than assert
it locally (Kani being Linux/macOS-only, `xtask::kani`, D-102). CI's answer, read from the job log
rather than assumed from the 20-minute timeout alone: `Checking harness ...
square_wide_matches_poly_mul_wide_self...` was the last line before the runner killed the job -
CBMC was still working, not stuck in a loop or crashed. The "same shape as `reduce`" claim doesn't
hold up: `reduce`'s two proofs are pure fixed shift/AND/OR/XOR over one symbolic input, with no
multiplication of two symbolic operands anywhere. `square_wide_matches_poly_mul_wide_self` instead
asked CBMC to prove that `poly_mul_wide(a, a)` - a real carry-less multiplication of the *same*
symbolic 163-bit value against itself - equals `square_wide(a)`'s independent bit-spread
construction. Proving two different multiplier constructions agree over the same symbolic operand
is a well-known hard class for SAT/CBMC (multiplier equivalence checking) - a fundamentally
different cost profile from a fixed bit-shuffle, regardless of how similar the *code* looks.

### The fix - a different proof, not a longer timeout

Raising the job's 20-minute budget was rejected as the fix: the underlying SAT instance is the
expensive kind (product-of-symbolic-operands), not merely a large-but-linear one like `reduce`'s -
there's no principled bound to raise it *to* with any confidence, unlike T-146/D-103's `cargo miri
test` timeout raise (150m -> 240m), which was against a job already known to complete, just with an
eroding margin. Instead, replaced the proof with `spread32to64_is_exact_bit_doubling`: proves
`spread32to64`'s own bit-doubling specification directly (bit `i` of a symbolic `u32` lands at bit
`2*i` of the output, every other output bit zero) - the one genuinely novel piece of arithmetic in
D-109's squaring work, and provable with no multiplication of symbolic operands at all (just fixed
shift/AND/OR/XOR over one symbolic `u32`, the same tractable shape as `reduce`'s own two proofs).
`square_wide`'s limb-placement composition (which half of which input limb lands at which output
limb) is *not* re-proven exhaustively - it's a simple, inspectable placement of three
`spread32to64` calls (already explained in `square_wide`'s own doc comment), covered instead by the
existing limb-boundary unit tests and the random-element proptest in `dstu4145_gf2m.rs`. This
mirrors the split this project already applies to `invert()`'s own addition chain (never
Kani-attempted for the analogous reason, D-109's own "not attempted, expected intractable" call) -
Kani for the tractable fixed-shuffle subset, differential testing for the parts that chain multiple
symbolic-operand operations together.

### Verification - actually run on real Kani, not left to CI to discover a second time

The dev machine is Windows (Kani is Linux/macOS-only, D-102), but the project's Raspberry Pi
(`raspberrypi`/"uacipher", the existing ARM-hardware verification target, `docs/TASKS.md` "Testing &
hardening") is real Linux and was already reachable - used it to actually run Kani rather than
trust CI blind a second time in the same session. `kani-verifier` there was pinned at 0.67.0
(`cargo install --list`), whose bundled toolchain needs a newer glibc than this Pi's Debian 12
(bookworm) ships (`GLIBC_2.39` required, `2.36` present, confirmed via `ldd --version` and the
`cargo-kani` binary's own dynamic-link error) - **not fixed by upgrading the Pi's OS** (rejected:
this is a real device the owner uses, and stepping a stable Debian release for one verification
run is a disproportionately risky trade). Fixed instead by pinning an **older** `kani-verifier`
release whose own bundled toolchain matches this glibc: `cargo install kani-verifier --version
0.55.0 --locked` installed fine but its bundled nightly (~Aug 2024) predates the `edition2024`
feature this workspace's `Cargo.lock` now needs (`zeroize 1.9.0` requires it) - one version too
old. `cargo install kani-verifier --version 0.62.0 --locked` (bundled toolchain
`nightly-2025-04-24`) was the version that actually worked: new enough for `edition2024`, and its
own prebuilt CBMC/kani binaries still link against this Pi's glibc 2.36 without issue. **Recorded
as a new fact worth keeping**, not just a one-off unblock: the working range for this specific
Debian-12-aarch64 Pi is `kani-verifier` **0.56.0-0.6x** roughly (untested precisely where the upper
edge is) - neither the newest release CI now uses (0.67.0, needs glibc 2.39) nor overly old ones
(0.55.0, edition2024 gap) work unmodified; a future re-check should start from 0.62.0 and adjust
from there rather than re-discovering this range from scratch.

**Real result, all three `#[kani::proof]` harnesses in `gf2m163.rs`, one `cargo kani -p dstu-core`
run**: `reduce_output_is_fully_reduced`, `reduce_matches_naive_bit_loop` (both pre-existing, D-102),
and the new `spread32to64_is_exact_bit_doubling` - **3 of 3 successfully verified, 0 failures,
total verification time under 1 second** (a run in isolation of just the new harness alone measured
`0.42s`). This is the actual, machine-confirmed proof this entry's fix was aiming for, not an
assumption deferred to the next CI run - the CI run remains the second, continuous confirmation
(same "trust but verify a CI job's real conclusion" posture, applied this time before merging
rather than after). `cargo test -p dstu-core --lib` (stable toolchain, same Pi) also reconfirmed
green, unaffected by any of the Kani-toolchain juggling above (Kani's own nightly is a separate,
`rustup`-managed toolchain, never the crate's own build toolchain).

## D-113: `cargo miri test` hung twice in a row preparing v0.2.0 - two `verify_combine_*` tests
missing the Miri-exclusion attribute their own sibling tests already carry

Same release checklist as D-112, one commit later (`42ef197`): `cargo miri test` (240min timeout,
T-146/D-103) was cancelled twice in a row, ~171min then ~188min of total silence each time before
the runner killed it, instead of the ~2h23m the last known-good run (`8e5a2a8`) took. A re-run of
the exact same job was tried first (in case of ordinary CI-runner variance, the T-146 precedent) -
identical outcome both times, ruling out flakiness.

### Wrong initial read, corrected before acting on it

Both hangs stopped printing test results at the same point: the last visible line was
`dstu4145_curve.rs`'s `verify_combine_matches_classic_for_random_scalars ... ok` (a `proptest!`
block, the last test declared in the file), followed by total silence until the timeout. First
hypothesis was a harness-transition deadlock - something in proptest's post-success cleanup (its
failure-persistence file handling, already known to need `-Zmiri-disable-isolation` for `getcwd`,
per `rust.yml`'s own comment) hanging under Miri's interpreted filesystem I/O. This was wrong, and
would have sent investigation toward `gf2m163.rs`'s D-109 arithmetic or proptest internals for no
reason. The actual tell: `dstu4145_curve.rs` declares **12** `#[test]` fns; the log shows only
**10** results (6 `ok`, 4 already-`#[cfg_attr(miri, ignore)]`-marked). Rust's test harness prints a
result line when a test *finishes*, not when it starts, and runs tests in parallel threads - "last
line printed" is not "where execution stopped." Two tests never finished at all in either run:
`verify_combine_matches_classic_for_small_scalars` and `verify_combine_matches_classic_when_r_eq_
s_eq_one`. `..._for_random_scalars` merely happened to be the last one that *did* finish before the
other two's threads ran out the clock.

### Root cause: compute, not deadlock - the exact drift `rust.yml`'s own comment predicted

Neither missing test carries the `#[cfg_attr(miri, ignore = "...")]` attribute every sibling
`scalar_multiply`-calling test in the same file already has (T-100's original exclusion,
citing `Point::scalar_multiply`'s 163-iteration constant-time ladder as too slow to interpret
under Miri - each call already costs minutes per the file's other exclusions and D-109/T-153's
own measured `invert()` timings). `verify_combine_matches_classic_for_small_scalars` loops an 8x8
grid of scalar pairs, calling `classic_combine` (two `scalar_multiply` calls each) every
iteration - 128 ladder invocations in one test. `verify_combine_matches_classic_when_r_eq_
s_eq_one` calls it once - only 2 ladder invocations, but that alone already matches the cost of
every other single-call test in the file that already needs the exclusion. Both tests were added
by T-150/T-151 (D-108) without the attribute. `.github/workflows/rust.yml`'s own comment on the
`miri` job states this exact risk verbatim: *"a new EC-heavy test added later without the
attribute silently reintroduces the timeout."* It did, for two full releases' worth of commits
(T-150/151, T-152, T-153, T-154, T-155), never caught because the job's real conclusion wasn't
re-checked via `gh run view` until this release's own checklist forced it - the same lesson
D-112 records for the `kani` job, independently true here for `miri` too. The last known-good
Miri run (`8e5a2a8`) never executed either test, since D-108 hadn't landed yet.

### Fix

Added the same `#[cfg_attr(miri, ignore = "...")]` attribute to both tests, citing T-100 like
their neighbors (`docs/TASKS.md` T-156). Confirmed locally that this doesn't affect normal test
runs: `cargo test -p dstu-core --test dstu4145_curve` - all 12 tests still pass outside Miri,
where the attribute is inert. The actual Miri pass/fail must still be confirmed on the next CI
run via `gh run view`, not assumed - the same "verify, don't assume" posture applied throughout
this release's checklist.

**Confirmed 2026-08-02**: CI run `30720207523` (commit `a5b602e`)'s `cargo miri test` job
completed in 2h44m18s, `conclusion: success` - back in the normal range, fix held on real CI.

## D-114: v0.2.0 released; `publish-crates` CI job added for future tags, v0.2.0 itself excluded

With D-113's fix confirmed on CI, the full `rust.yml` run (`30720207523`) went green across all 16
jobs. Tagged and pushed `v0.2.0` (pointing at `a5b602e`); `.github/workflows/release.yml` built
`uacrypt` for Linux/macOS/Windows plus the `dstu-core` source distribution and published the
GitHub Release (`create GitHub release` job, 14s) with all four assets attached. Added the
previously-prepared release notes via `gh release edit v0.2.0 --notes-file ...`.

Same session, wired crates.io publication into CI for future releases (`docs/TASKS.md` T-157,
T-17's automation half): a new `publish-crates` job in `release.yml`, `needs: publish-release` so
it only runs once the GitHub Release itself has actually succeeded, running `cargo publish -p
dstu-core` then (after a 30s sleep) `cargo publish -p uacrypt`, both against
`secrets.CARGO_REGISTRY_TOKEN` (added by the project owner this session). The sleep and ordering
aren't arbitrary: `uacrypt`'s packaged `Cargo.toml` has its `dstu-core` path dependency stripped
down to `version = "0.2.0"` (a plain path dependency doesn't survive `cargo package`), so its own
publish-time verification build resolves `dstu-core` against the crates.io registry, not the local
workspace - it has to actually be there first.

**Deliberately not on the v0.2.0 tag itself.** The owner made this scope call twice, explicitly,
after I flagged a real conflict (choosing "auto-publish on every `v*` tag" would have silently
pulled v0.2.0 into crates.io too, contradicting an earlier session's explicit "v0.2.0 stays
GitHub-only" decision): v0.2.0 ships GitHub-only, matching v0.1.0; automatic crates.io publication
starts with the tag after it. No version-check conditional was needed to enforce this - the
`publish-crates` job was added in a commit made *after* the `v0.2.0` tag already existed, so the
existing tag's own workflow run (already completed) can never see it; only a future `v*` tag,
cut from a commit that includes this change, will trigger it.

`docs/TASKS.md` T-17 (the actual first crates.io publish) stays open - this decision is the CI
plumbing, not the publish event itself.

## D-115: Language-bindings strategy — C-ABI split, uniform `crypto_sign`, naming

Full analysis in `docs/bindings-strategy.md` (2026-08-02, `docs/TASKS.md` T-158 onward) — this entry
is the citation trail for its three resolved forks, not a duplicate of the reasoning.

1. **C ABI vs. native FFI, split by tooling maturity.** Python (PyO3) and Node (napi-rs) bind the
   `dstu-core` Rust crate directly. C++ and .NET consume a new `bindings/capi` C ABI crate instead
   (C++: header + link, .NET: P/Invoke). Java is deliberately left open pending a spike (`jni` crate
   vs. JNI-over-`capi`) before committing. Ruby follows Python/Node's direct-binding shape; PHP
   follows C++/.NET's C-ABI-consuming shape.

   **Rejected:** routing every binding through one C ABI uniformly. Rejected because Python/Node
   already have mature, idiomatic direct-Rust-binding toolchains (PyO3+maturin, napi-rs) — forcing
   them through a C ABI would double-marshal data and lose native types (`bytes`/`Uint8Array`) for
   no benefit.

2. **`crypto_sign` (DSTU 4145) exposure is uniform across every binding, including Java/.NET.**
   Supersedes D-02's Java/.NET-wraps-Bouncy-Castle instruction, which predates
   `hazmat::dstu4145`/`dstu_core::crypto_sign` actually existing and being dual-oracle-verified
   (D-25/D-46). Every binding now calls this project's own Rust `crypto_sign`; Bouncy Castle remains
   the verification oracle only, the same role it already has in `tests/oracle-harness/`.

   **Rejected:** keeping D-02's original split (Java/.NET wrap Bouncy Castle, other bindings call
   Rust). Rejected because a Java binding that silently omits `crypto_sign`, or answers it from a
   different library than every other binding uses, is a worse, less consistent API surface than
   one that calls the same audited implementation everywhere — and the original reason for the
   split (no trustworthy Rust implementation existed yet) no longer applies.

3. **Package naming: `uacrypt`/`dstu-core` (registry-idiomatic spelling) on every registry.**
   Confirmed with the project owner 2026-08-02, matching the existing CLI binary (D-36) and crate
   names rather than inventing a new brand or a `dstu-ua-` prefix. Verified free on PyPI, npm,
   NuGet, and Maven Central (direct registry API/search checks, not a search engine — see
   `docs/bindings-strategy.md`'s table for the exact results) — no collision with `li0ard` (D-07),
   whose npm packages live under the separate `@li0ard/*` scope.

   **Rejected:** a `dstu-ua-` prefix for defensive disambiguation from `li0ard`. Rejected as
   unnecessary once the actual namespaces were checked directly — `@li0ard/kalyna` and an unscoped
   `dstu-core` cannot collide, so the extra prefix would only add friction with no real safety
   benefit.

Scope note, not a fourth fork: PHP and Ruby bindings (`docs/TASKS.md` T-159/T-160) were added to
Phase 3's scope this same session at the project owner's explicit request, positioned after the
original five languages, not interleaved with them — `docs/bindings-strategy.md`'s popularity
analysis section has the ordering rationale.

## D-116: Every binding is "install and forget" — zero-config API, prebuilt binaries

Requested 2026-08-02 by the project owner, as an explicit addition to `docs/bindings-strategy.md`'s
per-binding checklist (not covered by D-115's three forks): a binding must be trivial to adopt, not
just correct. Two concrete, checkable requirements, not aspirational language:

1. **Zero-config API** — a binding's public surface takes a key and a message and returns a result,
   with no mode/nonce/IV/padding parameter exposed to the consumer and no setup step beyond
   constructing a key. This is the same "delete the knob" philosophy D-47 already established for
   the Rust core itself (`crypto_secretbox`/`crypto_secretstream`'s internally-generated nonce) —
   applying it to bindings is a direct extension, not a new principle.
2. **Prebuilt binaries per platform, for every binding** — the same bar already set for `uacrypt`
   itself (T-18/T-119, GitHub Release binaries for Windows/Linux/macOS; D-12's own scope note: "end-
   users get prebuilt GitHub Releases binaries... no Rust toolchain required on their side"). A
   binding's consumer installs a package (wheel, npm tarball, JAR, NuGet package, prebuilt extension)
   and never runs `cargo build` themselves. This is a packaging-mechanism requirement, checked at
   local/CI-artifact build time — it does not wait on or depend on the separate, still-owner-gated
   registry-publish decision (T-17's crates.io precedent, extended to PyPI/npm/Maven Central/NuGet/
   RubyGems/Packagist by `docs/bindings-strategy.md`).

**Rejected:** treating ergonomics as a documentation/README concern to polish after a binding
otherwise works. Rejected because a binding that compiles and passes tests but requires the
consumer to run a local Rust toolchain, or to pass a nonce/mode parameter it shouldn't expose, fails
this project's own stated goal for language bindings — "hassle-free... install and forget" — even
though nothing about it would show up as a failing test. Recorded as a functional requirement on
each binding phase (`docs/TASKS.md` T-49/T-50/T-51/T-52/T-53/T-158/T-159/T-160), not left as an
unwritten expectation.

## D-117: Shared `dstu_core::selftest` module — one runtime KAT self-check, every binding wraps it

Requested 2026-08-02 by the project owner, alongside D-116: every binding needs (1) its local test
suite to run the actual official test vectors through the binding's own API, not just round-trip
against itself, and (2) a runtime self-test function the binding's *consumer* can call — proof the
exact installed binary produces correct outputs on their exact platform, callable from their own
code, not just from this project's CI.

**Decision: build the self-test once, at the `dstu_core` level, not once per binding.** A new
`dstu_core::selftest` module re-runs the official KAT vectors (Kalyna/Kupyna/Strumok/DSTU 4145 —
the same `crates/dstu-core/tests/vectors/*.json` data, embedded via a build step rather than
hand-copied, so there is exactly one source of truth) against the live compiled implementation and
returns a pass/fail report naming which primitive failed, if any. Gated behind a new Cargo feature
(embedding vector data costs binary size, real weight for `no_std`/`small-tables` embedded targets,
irrelevant weight for any binding's build) — off by default in the bare `dstu-core` crate, on by
default in every binding's own `Cargo.toml`. Every binding (Python/Node/Java/.NET/C++/PHP/Ruby)
exposes a thin, idiomatically-named wrapper around this one implementation — same "don't duplicate
shared logic per language" precedent as Kalyna/Kupyna's shared S-box/MDS tables (D-13) — plus,
incidentally, gives `uacrypt` itself a natural future `selftest` CLI command and gives Phase 4
hardware validation (STM32/ESP32) a way to confirm a cross-compiled build works on real silicon,
neither of which is scoped as a task here, both noted so they aren't "discovered" as a surprise
later.

**Rejected:** reimplementing the self-test independently in each binding language (e.g. a Python
function that separately loads the JSON vectors and calls the Python binding's own API). Rejected
because it multiplies the maintenance surface by the number of bindings for logic that has nothing
language-specific about it, and risks exactly the kind of silent drift between per-language copies
this project's "one source of truth" discipline exists to prevent elsewhere (test vectors,
architectural decisions, doc-map cross-references).

**Sequencing note:** scheduled as `docs/TASKS.md` T-161, a prerequisite for every binding phase —
it should land as one of Phase 3's first concrete implementation steps, before or alongside T-49's
scaffold, not bolted on after bindings already exist.

**Confirmed as a genuine gap 2026-08-02, not assumed from this entry's own text.** The project
owner asked directly whether everything the bindings plan leans on already exists in stock Rust, or
whether features had been invented for the bindings layer without the underlying Rust support.
Checked by reading the actual source, not by re-reading this document: `find
crates/dstu-core/src/hazmat -maxdepth 1 -name "*.rs"` and a `grep -i selftest` across
`crates/dstu-core/src`. Result — every `crypto_*` module the bindings checklist references is real
(`crypto_auth`/`crypto_generichash`/`crypto_kdf`/`crypto_pwhash`/`crypto_secretbox`/
`crypto_secretstream`/`crypto_sign`/`crypto_stream`/`randombytes`, all present as files), and
`crypto_secretstream`'s chunked `PushState`/`PullState` construction plus all 10 `hazmat` Kalyna
modes are real and documented — but `selftest`/`self_test` genuinely does not exist anywhere in
`dstu-core` yet. This module is the one piece of Phase 3 that is real new Rust-core work, not a
binding-layer wrapper around something already built — which is exactly why T-161 is sequenced
first rather than assumed available when a later binding phase reaches for it.

**Landed 2026-08-02, see `docs/TASKS.md` T-161.** `dstu_core::selftest::run()` re-checks one
official vector per primitive (Kalyna-128/128, Kupyna-256, Strumok-256, DSTU 4145's Annex B.1
worked example) against the live compiled build, embedded from the same
`crates/dstu-core/tests/vectors/*.json` files via `include_str!` and a small hand-rolled
string/hex scanner (no `serde` dependency - matches this crate's existing convention rather than
adding one). New `selftest` Cargo feature, requires `std`, off by default. Caught one real parsing
bug during implementation, not by inspection: DSTU 4145's `qy`/`r`/`s` hex values are sometimes one
nibble short of a full byte, which a first strict-even-length hex decoder rejected outright - fixed
by adopting the same leading-zero-pad convention `tests/dstu4145_signature.rs`'s own `decode_hex`
helper already uses, once the mismatch was traced rather than assumed. See T-161 for the full
verification record (clippy/fmt/`no_std` matrix, the two documented `#[allow]`s).

## D-118: Idiomatic streaming wrapper over `crypto_secretstream`; browser/WASM explicitly deferred

Raised 2026-08-02 by the project owner as an open question, not a directive: should bindings ship a
".NET `System.IO.Compression`-style ready pipeline" — a stream-in, stream-out API that handles
chunking internally — the way .NET's archiving APIs or a browser's Web Crypto API do, so a
programmer never assembles the loop themselves? Answered after discussion, two parts:

1. **Yes, but as an extension of D-116, not a new concept.** `crypto_secretstream` (`PushState`/
   `PullState`, D-68) already *is* the chunked pipeline — what was missing from the per-binding
   checklist was the requirement that every binding wrap it in that language's own native
   stream/pipe idiom (.NET `Stream`/`CryptoStream`-shaped, Node `stream.Transform`, Python
   file-like object, Java `InputStream`/`OutputStream`, C++ `istream`/`ostream`), not a raw
   push/pull loop the consumer manages by hand. Added to `docs/bindings-strategy.md`'s checklist.
   **Building T-49's own wrapper (2026-08-02) surfaced two pitfalls generalizable to every later
   language's wrapper, not Python-specific** — see `docs/bindings-strategy.md`'s "standard binding
   steps" step 3 for the full detail, re-check both there before writing Node/.NET/Java/C++'s own:
   (1) the language's "always runs, even on error" cleanup hook (`__exit__`/`Dispose`/
   try-with-resources/RAII destructor) must not finalize the stream on the error path, or a
   partial write silently produces a stream that reads back as complete; (2) the wire-format
   reader must itself bound an untrusted length-prefixed field and reject trailing bytes after
   `Final`, mirroring `uacrypt decrypt`'s own checks — matching the wire format is not enough,
   its validation has to be ported too.

   **Rejected: adding new configuration surface** ("a bit wider" was the project owner's own
   phrasing, floated then set aside in the same discussion). D-47's "delete the knob" still holds —
   the "wider" need is already met by *which* `crypto_*` primitive a caller reaches for
   (`secretbox`/`secretstream`/`sign`/etc.), not by new tunables inside any single one of them.
   Widening any individual primitive's parameters would re-open exactly the misuse surface D-47 was
   written to close.

2. **Browser/WASM target: explicitly out of scope for now, not silently assumed either way.** The
   project owner's own comparison (browsers shipping ready TLS/signing via the Web Crypto API) is a
   genuinely different target from what `docs/bindings-strategy.md`'s "JavaScript" phase (T-50)
   already scopes — Node.js via `napi-rs`, a real native binary that cannot run in a browser at all.
   A browser-usable build would need `wasm-bindgen`/a WASM target, a distinct toolchain and its own
   binding-shape decisions (no filesystem, no native threads the same way, a different prebuilt-
   artifact story than D-116 describes for every other binding). Confirmed with the project owner:
   **not scheduled now** — T-50 stays Node-only. If browser usage becomes a real need later, it's a
   new scoping decision, not an assumed extension of T-50.

## D-119: Bindings that link an external language runtime get their own Cargo workspace, not root membership

Discovered 2026-08-02 starting T-49 (Python binding) implementation, via `advisor()` review before
scaffolding: both `docs/bindings-strategy.md`'s T-49 step 1 and the original approved plan file say
"scaffold `bindings/python/` as a new Cargo workspace member." Checking that literally against
`.github/workflows/rust.yml` before writing any code surfaced a real conflict, not a style
preference.

**The conflict:** two existing CI jobs use `--workspace` explicitly and would silently start
covering the new crate the moment it's added to the root `[workspace] members` list:
`cargo +nightly miri test --workspace` (line 105) and `cargo +1.87.0 build --workspace
--all-features` / `--no-default-features` (the MSRV-pinned job, lines 190-191). A PyO3 `cdylib`
extension module is not something Miri can meaningfully interpret (it isn't a `#[test]`-driven
crate in the sense Miri assumes, and it needs an actual Python interpreter to even link on
Windows), and the MSRV job would newly depend on `pyo3` supporting Rust 1.87 - neither dependency
this project's core crates carry today. `default-members` does not help here: every job above
passes `--workspace` explicitly, which overrides `default-members` by design.

**Decision: `bindings/python/Cargo.toml` (and every other binding that itself compiles as a Rust
crate linking an external language runtime at build time - Node via `napi-rs`, Ruby via `magnus`)
gets its own `[workspace]` table, declaring itself a standalone Cargo project, not a member of the
repo-root workspace.** A path dependency on `dstu-core` (`{ path = "../../crates/dstu-core" }`)
still works across separate workspaces - Cargo doesn't require a shared workspace for a path
dependency to resolve, only that the referenced `Cargo.toml` exists at that path. Each such
binding therefore carries its own `Cargo.lock`, is built/tested with its own `cargo build`/`test`
invocation (`--manifest-path bindings/python/Cargo.toml`, or `cd`'d into that directory), and gets
its own CI job rather than a step folded into the existing Rust matrix - keeping the separation the
whole point of this decision, not re-entangling it one workflow file later.

**T-158 (the C ABI crate) is unaffected and stays a real root-workspace member** - confirmed
distinct from Python/Node/Ruby: it is plain Rust with `cbindgen` as its only extra tool, no
external interpreter/runtime linked at build time, so it carries none of the Miri/MSRV risk above.
`docs/bindings-strategy.md`'s T-158 entry already says "verify the existing 8-combination feature
matrix still passes with this new workspace member present" - that check only makes sense, and
stays correct, because T-158 *is* a member. C++/.NET/Java(-via-JNI-over-capi)/PHP consume T-158's
header rather than compiling their own Rust workspace member at all, so this decision doesn't reach
them either.

**Consequences tracked, not deferred to be rediscovered:**
- `cargo xtask deny`/`cargo xtask audit`'s dependency-vetting coverage does not see a
  separate-workspace binding's own `Cargo.lock` unless a future `xtask` change explicitly points at
  it with `--manifest-path` - a real coverage gap, not a decision to leave it unvetted forever.
- Each such binding's `xtask` subcommand (T-49/T-50/T-160's own step 5) must be **best-effort with
  an install-hint fallback**, matching `cargo xtask ci`'s existing posture for miri/fuzz/audit
  (D-12) - requiring every contributor to have a Python/Node/Ruby toolchain just to run `cargo
  xtask ci` would be a regression from today's "one Rust toolchain, everything else optional" bar.
- `docs/bindings-strategy.md` T-49's step 1 text and the original plan file's Phase 1 step 1
  ("Scaffold `bindings/python/` as a new Cargo workspace member") are corrected in the same commit
  as the T-49 scaffold itself, not left contradicting this entry.

**Rejected: adding it to root `members` and accepting the Miri/MSRV job scope creep.** Rejected
because both of those jobs exist for reasons unrelated to any binding (verifying `dstu-core`/
`uacrypt`'s own UB-freedom and minimum-supported-Rust-version), and silently widening what they
cover the moment a binding crate is scaffolded is exactly the kind of "discovered as a surprise
later" outcome this project's own agent-discipline notes already warn against for other doc-map
gaps.

**Verification before this entry was written, not assumed:** re-ran the *exact* CI commands
locally against T-161's `selftest` feature landing in the same session -
`cargo build --workspace --all-features`, `cargo test --workspace --all-features`, `cargo clippy
--workspace --all-features -- -D warnings` - all clean (the `--all-features` combination, which
turns on `selftest` together with `small-tables`/`pwhash`/`getrandom` at once, had not been
explicitly built before landing T-161; confirmed no interaction bug between `selftest`'s Kalyna/
Kupyna checks and the `small-tables` alternate code path). Also confirmed `cargo package --list -p
dstu-core` includes `tests/vectors/*.json` in the packaged crate by Cargo's own default inclusion
rules, so `selftest`'s `include_str!` paths resolve correctly even from a future crates.io-
published `dstu-core` (T-17, still gated) - not a gap, verified rather than assumed.

## D-120: T-49 (Python binding) done in full - CI, wheels, examples, doc-map sweep

Completed 2026-08-02, steps 5 and 7-9 of `docs/bindings-strategy.md`'s standard binding template
(steps 1-4 and 6 already landed earlier the same day, D-119/D-117 cover those).

**Step 5 (CI wiring), two distinct pieces per advisor review** - `release.yml` only fires on `v*`
tags, so reusing only it would leave this binding with zero regression coverage between releases:

1. `.github/workflows/bindings-python.yml`, its own job, not folded into `rust.yml`'s matrix
   (D-119's separate-workspace reasoning applies here too). `test` (matrix ubuntu/macos/windows):
   `cargo fmt --check` runs ubuntu-only - the other two legs hit the same autocrlf false positive
   `rust.yml`'s own fmt job already avoids by never running there (confirmed empirically: the
   first push failed on `windows-latest` flagging *every* checked-in file, not just new ones, as
   "Incorrect newline style" - the pre-existing, already-diagnosed artifact `docs/DECISIONS.md`'s
   own D-108 notes elsewhere, now confirmed to also reproduce on a real GitHub-hosted Windows
   runner, not just this local dev machine). `cargo build -p uacrypt --release` runs first, from
   the repo root - `tests/test_secretstream.py`'s interop test silently *skips* rather than fails
   without the binary, which would make the job pass green while not exercising the wire-format
   check that justifies the binding existing; the pytest step greps for `SKIPPED` and fails the job
   if found, confirmed on real CI to actually run (not skip) on all three platforms, 57/57 passing
   everywhere. `maturin build --release --out dist` + `pip install --no-index --find-links dist
   dstu-core` is used instead of `maturin develop`, since `develop` requires a virtualenv a bare
   `actions/setup-python` interpreter on a fresh runner isn't. A `wheel-preview` job runs the real
   `PyO3/maturin-action@v1`/`manylinux: auto` recipe on every push specifically so a broken recipe
   is caught immediately rather than discovered during a release - confirmed on real CI producing
   `dstu_core-0.1.0-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`, the tag itself
   checked, not assumed. A `supply-chain` job runs `cargo deny check`/`cargo audit` against this
   workspace.
2. `release.yml` gained a `build-python-wheels` job (same matrix/maturin-action recipe as
   `wheel-preview`, kept in sync by hand - no cross-workflow includes in GitHub Actions), added to
   `publish-release`'s `needs` so a wheel-build failure blocks the release, a deliberate choice
   recorded in-comment (same posture as `package-library`). No PyPI publish added - stays
   separately gated, same class of decision as T-17 for crates.io. `bindings/python/pyproject.toml`
   stays at its own `0.1.0`, deliberately decoupled from the Rust crates' `0.2.0` - this binding is
   still provisional/pre-1.0 and not lockstepped with the core crates' release cadence, noted
   in-comment so a future reader doesn't read the mismatch as a bug.

**Real bug found and fixed in the same pass, not a separate task**: running `cargo deny check`
with `bindings/python` as cwd for the first time (to close D-119's own recorded gap - root
`cargo deny`/`audit` not reaching this workspace) immediately flagged a wildcard-dependency error:
`bindings/python/Cargo.toml`'s `dstu-core = { path = "../../crates/dstu-core", ... }` had no
`version =` pin - the exact T-75/D-11 failure mode, just never checked here until now. Fixed by
adding `version = "0.2.0"`, matching `crates/uacrypt/Cargo.toml`'s existing pattern. Also
discovered: no second `deny.toml` was needed at all - cargo-deny walks up from its cwd looking for
the config file, so it already finds the root `deny.toml` and checks whichever workspace's
dependency tree is live in that cwd against the same policy. Confirmed by running it, not assumed;
`deny.toml`'s own header comment updated to say so. `cargo xtask`'s `audit()`/`deny()` now check
both workspaces; a new `cargo xtask python` best-effort subcommand (D-12 posture) runs
build+fmt+clippy+`maturin develop`+pytest for local iteration - verified locally, 57/57 passing
with the interop test genuinely running.

**Step 7 (examples/README)**: five runnable scripts under `bindings/python/examples/`
(`secretbox.py`, `secretstream_file.py`, `sign.py`, `password_hashing.py`, `misc.py` for
auth/kdf/generichash/stream/randombytes) - each run against the real built extension before
committing, not written from the API surface alone. `README.md` rewritten from its step-1
"scaffold only, selftest() only" state to a full module-by-example reference table; the
provisional-status banner stayed, reworded to match. Wiring `ruff` into a real CI gate for the
first time (step 5) surfaced two genuine `PYI034` findings in `secretstream.py`'s `__enter__`
methods (ruff wants `Self` as the return type) - fixed with an inline `noqa` rather than a
`typing_extensions` dependency, since this binding's `requires-python` floor is 3.9 and
`typing.Self` needs 3.11+.

**Step 8 (doc-map sweep)**: root `README.md`'s repo-tree line ("planned, not yet built") was stale,
fixed; `docs/dstu-crypto-project.md` and `docs/release-readiness.md` updated to say T-49 is done;
`docs/user-journey-gaps.md`/`docs/cross-language-style-guide.md` checked and had no T-49 references
to begin with, left untouched. `docs/bindings-strategy.md`'s resume point updated to point at T-50
next. `docs/TASKS.md` T-49 marked `[x]`.

**Step 9**: each piece above landed as its own commit, not one large drop (see `git log` for the
sequence: the wildcard-dependency fix + xtask wiring, the CI workflow, the autocrlf fix, the
release.yml wheel job, examples/README, this doc pass).

## D-121: Binding build order reordered — no-incumbent languages before Bouncy Castle/UAPKI-served ones

Requested 2026-08-02, right after T-49 (Python) shipped: the project owner asked whether it's worth
building bindings for languages Bouncy Castle/UAPKI already serve (Java, .NET), given those two
projects already ship real DSTU-adjacent support there, or whether effort is better spent on
languages with no existing binding at all.

**Reasoning**: `docs/bindings-strategy.md`'s original popularity analysis wasn't wrong, it was
answering a different question. It established Java/.NET first *because* UAPKI (Java/Kotlin) and
Bouncy Castle (.NET, already this project's own verification oracle) are direct evidence of real
Ukrainian-PKI demand in those two languages specifically. That evidence still stands - Bouncy
Castle covers low-level primitives/signatures the way OpenSSL does, not a unified, zero-config,
misuse-resistant `crypto_*` surface across Kalyna/Kupyna/Strumok plus non-DSTU pwhash/kdf in one
package, so this project's contribution there is still real. But it's a *smaller* gap than in a
language with no DSTU library at all - Node, Ruby, PHP have no incumbent competitor, so the same
"install and forget" reach (D-116) is currently unclaimed ground in those three, and shipping there
first reaches an audience with literally zero alternative rather than one already served, however
imperfectly.

**Order changed**: T-49 (Python, done) → T-50 (Node) → T-160 (Ruby) → T-159 (PHP) → T-158 (C ABI
crate) → T-52 (.NET) → T-51 (Java) → T-53 (C++) → T-163 (Go, see D-122) → T-162 (docs, last).
Node/Ruby moved up from their original "deliberately after Java/.NET" and "scheduled last"
positions respectively. PHP moved up too, with a firmer commitment: the original plan left
`ext-php-rs` vs. `FFI`-over-`bindings/capi` (T-158) open; this decision commits to `ext-php-rs`
specifically, making PHP a direct Rust binding like Python/Node/Ruby rather than one gated on the
C ABI crate - it genuinely doesn't need to wait for T-158 now, not just reordered on paper. C++
(T-53) is not reordered relative to .NET/Java specifically - no incumbent-competition argument
applies to it either way, and it still needs T-158 regardless of ordering philosophy, so it stays
grouped with that later tier by construction, not by a fresh decision.

**Not changed**: the underlying per-binding checklists, D-116/D-117/D-118's cross-cutting
requirements, and the Java/.NET `crypto_sign`-uses-own-Rust-implementation correction (D-115) all
still apply exactly as before - this decision is purely about sequencing, not scope or design.

**Original popularity analysis kept verbatim in `docs/bindings-strategy.md`**, not rewritten - it
was correct evidence for the question it was answering, just not the deciding factor for build
order anymore. A "Build order revised" note there and in `docs/TASKS.md` points at this entry
rather than silently re-deriving the same numbers with different conclusions.

## D-122: Go binding added to scope, Dart explicitly deferred

Same 2026-08-02 conversation as D-121: the project owner asked to add Go, flagging their own
uncertainty about Dart specifically ("тут я не впевнений" - "not sure about this one").

**Go added as T-163.** Same no-incumbent-competitor reasoning D-121 established for Node/Ruby/PHP -
no DSTU-specific Go library exists, and Go has a real DevSecOps/cloud-infrastructure/security-
tooling audience (the same class of evidence already used for Ruby's own ordering). **Placed
differently than Node/Ruby/PHP, though**: no Go binding toolchain exists with PyO3/napi-rs/magnus's
maturity (no mature direct-Rust-to-Go FFI generator comparable to those three), so Go binds through
the C ABI crate (`cgo` over `bindings/capi`'s `cbindgen`-generated header) the same way .NET/Java/
C++ do. It therefore builds alongside that group, after T-158, not ahead of it - the
no-incumbent argument justifies *including* Go, but doesn't override the separate technical
constraint that decides *where* it slots into the sequence.

**Dart explicitly deferred, not silently assumed either way** - the same treatment D-118 already
gave Node's own browser/WASM variant when that came up mid-conversation. Reasoning: Dart's primary
real-world audience (Flutter mobile/web apps) overlaps least with this project's demonstrated
PKI/enterprise/security-tooling demand, the same argument that already kept Node itself from being
built second despite matching Python's binding shape (see the popularity analysis in
`docs/bindings-strategy.md`). Not rejected outright - revisit if real demand evidence for Dart
specifically ever appears, the same standard any other currently-out-of-scope language would need
to meet.

## D-123: Go built ahead of C++ specifically (owner preference, no further rationale recorded)

Same 2026-08-02 conversation as D-121/D-122, immediately after Go (T-163) was added: the project
owner asked for Go to build before C++ specifically, within the C-ABI-dependent group (T-52/T-51/
T-163/T-53) D-121/D-122 already placed it in.

**Change**: T-163 (Go) now builds right after T-51 (Java), ahead of T-53 (C++) - order within that
group is now .NET → Java → Go → C++, not .NET → Java → C++ → Go. No incumbent-competition or
technical-dependency argument drives this specifically (unlike D-121's Node/Ruby/PHP-before-Java/
.NET reasoning, or D-122's Go-needs-the-C-ABI reasoning) - recorded here as the owner's explicit
ordering preference, not backfilled with a rationale that wasn't given.

**Unaffected**: Go still depends on T-158 (the C ABI crate) exactly as D-122 established - this
decision only reorders Go relative to C++ within that already-later group, not relative to T-158
itself or to .NET/Java.

## D-124: safe/simple/KISS code + cross-language test-first, made an explicit standing rule for every binding language

Same 2026-08-02 conversation, after D-121-D-123's ordering work: the project owner stated the rule
directly - for every binding language, write safe, simple, quality code (KISS), and tests come
first and must be cross-language. Flagged as probably already true somewhere, asked to make it
apply across all languages explicitly.

**This was already substantially in force, just split across files rather than stated as one
rule**: `docs/cross-language-style-guide.md` principle 10 already mandates KISS for every non-Rust
language in this project except the reference-crypto-implementation carve-out; `docs/TASKS.md`'s
D-64/D-65 three-category test standard and `docs/bindings-strategy.md`'s "Category 1 specifically
must run the actual official vectors... one source of truth" (shared JSON vector files under
`crates/dstu-core/tests/vectors/`) already make every binding's correctness tests cross-language by
construction - two languages testing against the same vector file is what "cross-language" means
here, not a separate parallel test suite that compares languages to each other directly. What was
missing: **test-first was only written down for T-161 (`selftest`) specifically**, not as a rule
for the standard nine-step template every other binding (T-49/T-50/T-51/T-52/T-53/T-158/T-159/
T-160/T-163) follows.

**Change**: `docs/bindings-strategy.md`'s standard-steps section now states explicitly that step 6
(the local test suite) is written test-first per sub-surface as steps 1-5 are implemented -
mirroring T-161's already-completed pattern and this project's own root "test-first, always" rule
(`CLAUDE.md`) - rather than read as "build everything, then backfill step 6's checkbox at the end."
The step numbering itself is unchanged (step 6 stays the checkbox marking the suite complete for
that binding), since splitting it into a written-first sub-test per step-1-5 item would fragment the
one-checkbox-per-task tracking this document already relies on for resumability across sessions.

**No scope change** - this generalizes and cross-references existing rules (KISS in
`cross-language-style-guide.md`, three test categories in `CLAUDE.md`/`docs/TASKS.md`, shared-vector
reuse already in `bindings-strategy.md`), it does not introduce a new one. Recorded as its own
decision because the owner asked for it to be explicit and to cover every future language, not just
Python (T-49, already built) where it happened to be followed by construction.

## D-125: Node.js binding (T-50) built via napi-rs, pinned to windows-msvc + napi-build 2.0.0 locally

T-50 step 1 (scaffold): `bindings/nodejs`, its own separate Cargo workspace (same D-119 reasoning
as `bindings/python`), napi-rs (`napi`/`napi-derive`/`napi-build`). Wraps only `selfTest()` for now,
matching T-49 step 1's own split (prove workspace -> build -> load -> call before wrapping the real
surface) - verified with `node -e "require('./index.js').selfTest()"` after `npm run build`.

**Real toolchain gotcha found building this, not assumed**: this dev machine's default Rust host is
`x86_64-pc-windows-gnu` (`rustc -vV`), but napi-build's Windows-`gnu` path
(`napi-build-2.4.0/src/windows.rs::setup_gnu`) requires a real `libnode.dll` discoverable on
`PATH`/`LIBPATH` - no prebuilt Windows Node.js distribution ships one (`node.exe` statically links
libnode), so the build panicked with "libnode.dll not found in any search path." Read the actual
source before working around it (this project's own standing rule) rather than guessing: the
Windows-`msvc` path in the same crate does nothing special at all - MSVC links via a generated
import stub, no real DLL needed at build time. Fixed with `bindings/nodejs/rust-toolchain.toml`
pinning `1.87.0-x86_64-pc-windows-msvc` specifically (this machine already had that toolchain
installed for the fuzz targets, per T-32's own precedent) - a directory-local override, same
mechanism as the "any CI step needing nightly must say `cargo +nightly` explicitly" rule, just via
a toolchain file instead of a flag since `napi build`'s own CLI shells out to bare `cargo`.

**Second, independent gotcha**: `napi-build` 2.1.0+ requires rustc >= 1.88, one minor ahead of this
crate's own `rust-version = "1.87.0"` floor (matching `dstu-core`'s MSRV policy) and ahead of the
`1.87.0-x86_64-pc-windows-msvc` toolchain actually available locally. Pinned to `napi-build = 2.0.0`
in `Cargo.lock` (`cargo update -p napi-build --precise 2.0.0`) rather than bumping this crate's own
MSRV to match a transitive build-dependency's newer floor - re-check this pin once the MSVC 1.88+
toolchain is actually installed, don't carry it forward by default once it's no longer needed.

**Corrected same session, before any CI was wired - see D-130**: the `rust-toolchain.toml` pin
described above was wrong to commit repo-wide (it would have forced a Windows-only MSVC toolchain
onto Linux/macOS CI runners too, breaking them). Replaced with a machine-local `rustup override
set`, not a tracked file - D-130 has the full reasoning.

**Generated-artifact convention, matching the C ABI header precedent already stated for T-158**:
`index.js`/`index.d.ts` (napi-rs's own generated JS/TS glue, from this crate's `#[napi]`
annotations) and the compiled `*.node` addon are gitignored, not committed - regenerated by
`napi build` every time, same reasoning as Python's `.pyd`/`.so` and the not-yet-built C ABI's own
`cbindgen`-generated header: no separate copy of the binding surface that can silently drift from
the Rust source of truth.

Verified: `cargo fmt --all -- --check` / `cargo clippy --all-targets -- -D warnings` clean under
the pinned msvc toolchain (both components installed fresh via `rustup component add
--toolchain 1.87.0-x86_64-pc-windows-msvc rustfmt clippy`); root `cargo build --workspace` from the
repo root confirmed unaffected (only sees `crates/dstu-core`/`crates/uacrypt`, same check T-49 step
1 already ran for Python).

## D-126: Node.js binding (T-50) step 2 - full `crypto_*` surface wrapped

Same 2026-08-02 session as D-125. Wraps every `crypto_*` module - `secretbox`, `sign`, `pwhash`,
`generichash` (one-shot + incremental `Kupyna256Hasher`/`Kupyna512Hasher`), `auth`, `kdf`, `stream`,
`randombytes` - plus `crypto_secretstream`'s raw `PushState`/`PullState` `push`/`pull` (the
idiomatic `stream.Transform` wrapper stays deferred to step 3, exactly mirroring `bindings/python`'s
own step 2/step 3 split, not a new decision). `PWHASH_*`/`SECRETSTREAM_TAG_*` module constants
exported via `#[napi] pub const`.

**Real API-shape findings from reading napi-rs's own source before guessing, not assumed:**
- **`Vec<u8>` is the wrong type for binary data in napi-rs.** Its generic `Vec<T>` impl
  (`bindgen_runtime/js_values/array.rs`) maps to a plain JS `Array` of boxed numbers, one call per
  element - not a `Buffer`/`Uint8Array`. Every byte parameter and return value here uses
  `napi::bindgen_prelude::Buffer` instead (a real Node `Buffer`, `Deref<Target = [u8]>` on the Rust
  side, `impl From<Vec<u8>> for Buffer`/reverse for easy conversion) - confirmed by reading
  `buffer.rs`'s `FromNapiValue`/`ToNapiValue` impls directly, not inferred from the type name alone.
- **napi-derive does not auto-convert Rust `snake_case` identifiers to JS `camelCase`** (no case-
  conversion utility exists anywhere in `napi-derive-backend`'s source, confirmed by grep) - unlike
  what a PyO3 comparison might suggest, since Python's own `snake_case` convention happens to need
  no conversion at all, masking that PyO3 doesn't auto-convert either. Every exported function here
  has an explicit `#[napi(js_name = "camelCase")]`; class/struct names were already `PascalCase` in
  Rust so needed none. Verified in the generated `index.d.ts` directly, not assumed correct.
- **napi-rs has no tuple `ToNapiValue` impl at all** (no `impl ToNapiValue for (A, B)` anywhere in
  the crate) - `crypto_secretstream`'s `push`/`pull`, which return two values each in the Rust API
  and as a Python tuple in T-49, instead return a `#[napi(object)]` struct with explicit
  `js_name`-cased fields (`SecretStreamPushResult { ciphertext, authTag }`,
  `SecretStreamPullResult { tag, plaintext }`). This is a genuine idiomatic improvement over a
  tuple, not just a technical workaround - a named-property result object is the conventional JS
  shape for a multi-value return, matching `docs/cross-language-style-guide.md` principle 2 (a name
  communicates intent) better than a positional tuple would have.
- **napi-rs has no `FromNapiValue` for `u64`/`i64`-as-`BigInt` on the input side** (only the output
  direction, `ToNapiValue`, via `napi_create_bigint_uint64` - confirmed in `bigint.rs`, which
  explicitly comments it does not implement the reverse for `u64`/`i64`/`u128`/`i128`). `kdf`'s
  `subkey_id` (a `u64` on the Rust side) is accepted as a plain `i64`/JS `number` instead, since
  every realistic subkey index fits well within `Number.MAX_SAFE_INTEGER` - with an explicit
  rejection of negative values (misuse-category, D-64/D-65) rather than a silent wraparound when
  cast to the underlying `u64`, matching this project's index/bounds-safety discipline.
- **`clippy::new_without_default` fires on `#[napi(constructor)] pub fn new() -> Self` the same way
  it would on a plain inherent `new()`** - napi-derive's macro expansion does not hide the original
  method signature from clippy the way PyO3's `#[new]` expansion apparently does (Python's own
  hasher classes needed no `Default` impl to pass clippy clean). Fixed with a real `impl Default`
  for both `Kupyna256Hasher`/`Kupyna512Hasher` (delegating to `Self::new()`), not a blanket
  `#[allow]`, since a genuine zero-argument constructor really does have an obvious `Default`.

Verified end-to-end with a real Node smoke script exercising every wrapped function once
(round-trip, tamper-rejection, and the `subkey_id < 0` misuse case) against the actual built
addon, plus `cargo fmt --all -- --check`/`cargo clippy --all-targets -- -D warnings` clean and root
`cargo build --workspace` unaffected - same verification bar as T-49 step 2's own Python pass.

## D-127: Node.js binding (T-50) step 3 - `crypto_secretstream` as an idiomatic `stream.Transform` pair

Same 2026-08-02 session as D-125/D-126. `SecretStreamEncryptor`/`SecretStreamDecryptor`
(`bindings/nodejs/js/secretstream.js`) - pure hand-written JS on top of step 2's raw
`SecretStreamPushState`/`PullState`, no new Rust glue, mirroring
`bindings/python/python/dstu_core/secretstream.py`'s design and wire format exactly: `header (32
bytes)` then one record per chunk, `tagByte (1) || chunkLenU32LE (4) || ciphertext || authTag
(16)`, chunks capped at 8 KiB (`SECRETSTREAM_CHUNK_BYTES`) - interoperable with `uacrypt encrypt`/
`decrypt` in both directions, verified against the real `uacrypt.exe` binary (encrypt with
`uacrypt`, decrypt with this binding and vice versa, byte-for-byte `cmp` match both ways), not just
self-consistently.

**Structural change to accommodate a hand-written entry point**: `napi build`'s generated
`index.js`/`index.d.ts`/`*.node` moved from the package root into `bindings/nodejs/native/` (`napi
build native --platform --release`, `package.json`'s `build`/`build:debug` scripts updated) so
`bindings/nodejs/js/index.js` (hand-written, committed) can own the package's public `main` entry
point without a regenerated file overwriting it on every build. `js/index.js` re-exports every
native function/class as-is plus the two `stream.Transform` classes - same split as Python's
`_dstu_core` (compiled, private) vs. `dstu_core/__init__.py` (public, hand-written).

**D-118's two standing pitfalls, re-checked for this port specifically, not assumed to carry over
automatically from Python:**
- **The language's own "always runs, even on error" cleanup hook must not finalize on the error
  path.** Node's Transform-stream equivalent of Python's `__exit__` is `_flush` - called by the
  stream machinery only when the writable side ends gracefully (`.end()`/pipeline success), never
  on `destroy()`/an upstream error (which instead calls `_destroy`, deliberately left alone here).
  `SecretStreamEncryptor` therefore only ever emits the `Final` chunk from `_flush`, so a pipeline
  that errors partway leaves the output without one - a `SecretStreamDecryptor` reading that
  truncated output fails closed in its own `_flush` ("stream ended before a Final chunk") rather
  than accepting a complete-looking but truncated file. Verified with a real test: `destroy()` an
  encryptor mid-write, decrypt the truncated output, confirm it throws naming the missing `Final`
  chunk specifically (not just "throws something").
- **The wire-format reader must itself bound the untrusted length-prefixed field and reject
  trailing data after `Final`.** `chunkLen` (the 4-byte little-endian field) is checked against
  `CHUNK_BYTES` the instant it's parsed in `_drain`, before any buffering up to its declared length
  - a genuinely necessary check here (unlike a synchronous Python `_read_exact`, this reader
  accumulates arbitrarily-chunked input across multiple `_transform` calls, so an unbounded
  `chunkLen` really could mean holding gigabytes in `this._buf` waiting for a socket/pipe to supply
  them). Trailing bytes after `Final` are rejected in two places: the top of `_drain`'s loop (bytes
  arriving in a later `_transform` call after `_done` was already set) and in `_flush` (bytes
  appended in the very same write as the `Final` record, which never reach `_drain`'s next-iteration
  check otherwise since there is no next iteration if the stream then ends). Verified with two
  separate tests, not one - an oversized `chunkLen` alone, and valid ciphertext with one trailing
  byte appended.

Verified end-to-end: a real smoke test covering round-trip (multi-chunk, >8 KiB), both pitfalls
above, and ciphertext-tamper rejection, all against the actual built addon; the bidirectional
`uacrypt` interop check above; `cargo fmt --all -- --check`/`cargo clippy --all-targets -- -D
warnings` clean (no Rust changed this step, re-run only to confirm); root `cargo build --workspace`
unaffected.

## D-128: Node.js binding (T-50) step 4 - Windows prebuilt artifact, verified via a real fresh install

Same 2026-08-02 session as D-125/D-126/D-127. This dev machine is Windows-only, the same
constraint `bindings/python`'s own step 4 hit - Linux/macOS builds genuinely need CI (deferred to
step 5), not something a local pass can shortcut.

**Real packaging gotcha found, not assumed to work**: `bindings/nodejs/native/` (napi's generated
`index.js`/`index.d.ts`/the compiled `*.node`) is gitignored from source control (D-127) - but `npm
pack`/`npm publish` fall back to `.gitignore` for their own file-inclusion decision *only when
`package.json` has no `files` field*. Without one, packing this crate as-is would have silently
produced a tarball missing the very runtime artifact the package needs to function - caught by
actually running `npm pack --dry-run` and reading its file list, not assumed correct from the
config. Fixed by adding an explicit `files` array (`js/`, `native/index.js`, `native/index.d.ts`,
`native/*.node`) - `files` overrides both `.gitignore` and any `.npmignore` once present, exactly
the mechanism needed to ship a build artifact that is rightfully excluded from version control but
must ship in the package.

**Verified with a genuine fresh-install round trip**, matching Python's own step-4 bar (a fresh
venv + `pip install` from the built wheel, not the editable/dev install): `npm pack` into a real
`.tgz`, `npm install <tarball path>` inside an unrelated temp directory (its own throwaway
`package.json`, no relation to the source repo), then `require('dstu-core')` there - resolving
through real `node_modules`, not a relative path into the source tree - and re-ran `selfTest`,
`secretbox`, and the `secretstream` `stream.Transform` pair against that installed copy. All
passed, confirming the packaged artifact is actually complete and self-contained, not just "the
source tree already works."

## D-129: Node.js binding (T-50) step 6 - local test suite, done before step 5 (tooling-forced reorder)

Same 2026-08-02 session as D-125/D-126/D-127/D-128. `bindings/nodejs/test/*.test.js` - one file
per `crypto_*` module (`selftest`, `secretbox`, `sign`, `auth`, `kdf`, `pwhash`, `randombytes`,
`generichash`, `stream`, `secretstream`), `node:test`/`node:assert/strict`, D-64/D-65's three
categories throughout, mirroring `bindings/python/tests/*.py` file-for-file and case-for-case.
`generichash.test.js` loads the same shared `crates/dstu-core/tests/vectors/kupyna/kupyna-256.json`
the Rust tests and Python binding both already use (D-124's cross-language-vectors requirement -
this is what makes it cross-language, not a separate suite comparing languages to each other
directly). `secretstream.test.js` re-verifies both D-118 pitfalls end to end through the public
Transform API and re-runs the bidirectional `uacrypt` interop check from D-127.

**Order swapped relative to the standard template, for a real tooling reason, not a preference**:
the standing nine-step template lists step 5 (xtask/CI wiring) before step 6 (test suite), and
Python's own T-49 followed that literal order (its CI workflow was wired before its pytest suite
existed - an empty/nonexistent pytest collection doesn't error). `node --test test/` does error
immediately if `test/` doesn't exist yet ("Could not find 'test/'") - confirmed by trying it, not
assumed - so wiring `npm test` into CI/xtask before any test file existed would have made the very
first CI run fail on a missing directory, not a meaningful red test. Step 6 was done first for this
binding specifically as a result; step 5 (next) wires up a `test/` directory that already has real
content. D-124's test-first principle is unaffected by this - it governs writing a test before its
own wrapper's code, not the standing-template's step numbering.

**A second tooling finding, more valuable than the reorder itself**: `node --test test/` (with an
explicit directory argument) does NOT behave the same as `node --test` (no argument) - the former
errors trying to `require()` the directory as a single module, the latter uses the documented
default discovery of `**/*.test.js` under a `test/` directory. `package.json`'s `test` script was
written as `"node --test test/"` initially (by analogy with typical test-runner CLIs) and had to be
corrected to `"node --test"` once this was actually run and failed - confirmed against the real
Node CLI's behavior, not the first guess.

**A real, `node:test`-runner-specific bug found and fixed while writing this suite, not a
pre-existing issue in the wrapper's design**: an early version of the "tampered chunk"/"oversized
chunk"/"trailing data" rejection tests intermittently made `node --test` hang indefinitely instead
of failing cleanly. Root cause, confirmed by isolating each helper in a standalone script with a
hard timeout rather than guessing: `SecretStreamEncryptor`/`Decryptor`'s `_transform`/`_flush`
methods called their `callback(err)` **synchronously** (no real async work happens inside them) -
Node's own stream documentation warns against this specifically, because when a `_write`/
`_transform` callback fires synchronously (`state.sync` still `true` at that point), a **error**
passed to it can throw synchronously out of the triggering `.write()` call instead of emitting
`'error'` asynchronously the documented way. Fixed by deferring every `_transform`/`_flush`
callback invocation through `process.nextTick(callback, err)` in both classes
(`bindings/nodejs/js/secretstream.js`) - confirmed stable across three repeated full `node --test`
runs afterward, not just the one run that happened to pass. A second, related finding from the
same debugging pass: `.write()` after `.end()`/`'finish'` on this stream does not reliably emit a
catchable `'error'` event at all (an earlier test version that `await`ed one hung forever) - the
actually-documented, synchronous contract is `.writableEnded` and `.write()`'s own boolean return
value, which is what the final test asserts against instead.

Verified: all 52 tests pass, confirmed stable across three consecutive full `node --test` runs
(not a single lucky pass); `cargo fmt --all -- --check` clean (no Rust changed this step); root
`cargo build --workspace` unaffected.

## D-130: Node.js binding's MSVC toolchain pin fixed - machine-local `rustup override`, not a committed `rust-toolchain.toml`

Found and fixed while starting T-50 step 5 (CI wiring), before any workflow was pushed - caught by
actually thinking through what the committed `bindings/nodejs/rust-toolchain.toml` (D-125) would do
on GitHub Actions' `ubuntu-latest`/`macos-latest` runners, not discovered from a failed CI run.

**The bug**: D-125 committed `bindings/nodejs/rust-toolchain.toml` pinning
`channel = "1.87.0-x86_64-pc-windows-msvc"` to fix a real local problem - this dev machine's
default Rust host is `x86_64-pc-windows-gnu`, a **deliberate machine-specific choice** (`.claude.
local.md`: "GNU host ... deliberately not MSVC, to avoid needing Visual Studio Build Tools"), not a
property of this project or of GitHub's own runners. GitHub Actions' hosted `windows-latest`
already defaults to an MSVC-host Rust toolchain - it never had this problem to begin with. A
repo-wide, committed toolchain file applies unconditionally on every machine/runner that checks the
repo out, though: on `ubuntu-latest`/`macos-latest`, rustup would try to install and invoke a
toolchain built for a *different host OS* (a Windows MSVC `rustc.exe`/`cargo.exe` cannot run on
Linux/macOS at all) - this would have broken both non-Windows legs of the very CI matrix this step
was about to add, the moment it was pushed.

**The fix**: removed `bindings/nodejs/rust-toolchain.toml` entirely. The actual fix for this
machine's local quirk is `rustup override set 1.87.0-x86_64-pc-windows-msvc --path
bindings/nodejs` - a directory-to-toolchain mapping stored in this machine's own `~/.rustup/
settings.toml`, invisible to git and to every other machine/runner, exactly the same
"machine-specific quirk stays in `.claude.local.md`, never committed" pattern this project already
uses for the broken `python`/`python3` PATH stubs (`.claude.local.md`) and the fuzz-target
`nightly-x86_64-pc-windows-msvc` toolchain (same file). Re-verified after the fix: `cargo fmt --all
-- --check`/`cargo clippy --all-targets -- -D warnings`/`npm run build`/`npm test` (52/52) all still
pass locally through the override, with nothing committed to the repo that a Linux/macOS CI runner
would trip over. `napi-build = 2.0.0`'s `Cargo.lock` pin (D-125's second, independent gotcha) is
unaffected - that one has nothing to do with the host OS and stays exactly as it was.

**Where this leaves CI** (T-50 step 5, next): `windows-latest`'s own already-MSVC-default
toolchain needs no special handling at all in `bindings-nodejs.yml` - the workflow can use the same
plain `dtolnay/rust-toolchain@stable` (no explicit host) every other binding's workflow already
uses, exactly like `bindings-python.yml`. This machine's override is a pure local build
convenience, not something CI needs to reproduce or even know about.

## D-131: Node.js binding (T-50) step 5 - `cargo xtask nodejs` + `bindings-nodejs.yml`

Same 2026-08-02 session. `xtask/src/main.rs` gains `nodejs()` (builds `uacrypt` from the repo root
first, `npm install`, `cargo fmt --check`/`clippy -D warnings`, `npm run build`, `npm test` -
mirrors `python()` exactly), wired into the command match arm, `print_usage()`'s help text, and
`ci()`'s best-effort optional-layers array. `audit()`/`deny()` extended to also check
`bindings/nodejs` (shares the root `deny.toml`, same D-119 mechanism already established for
`bindings/python` - `deny.toml`'s header comment updated to say so).

**Real, immediately-hit tool-resolution gotcha, same shape as the pre-existing `mvn`/`mvn.cmd`
case this file already handles**: a bare `Command::new("npm")` reports "not found on PATH" even
though `npm --version` works fine in a real shell - Windows ships `npm` as `npm.cmd`, and
`std::process::Command` does not resolve batch-script extensions the way a shell's own PATH lookup
does. `command_for()` extended to map `npm` -> `npm.cmd` on Windows alongside the existing `mvn`
case, confirmed by running `cargo xtask nodejs` before and after the fix (failed with the tool-not-
found message first, passed clean after).

New `.github/workflows/bindings-nodejs.yml`, mirroring `bindings-python.yml`'s shape: `test` job
(matrix ubuntu/macos/windows - fmt-check ubuntu-only per the same autocrlf false positive, clippy,
build `uacrypt` first so the secretstream interop test can't silently skip, `npm install`/`npm run
build`/`npm test` with an explicit `grep -q "not ok"` failure gate on top of the exit-code check,
`npm pack --dry-run` on every push to catch a broken `files` field - D-128's real gotcha -
immediately rather than only at release time) and `supply-chain` (`cargo deny check`/`cargo audit`
against `bindings/nodejs`, same mechanism as Python's). **No MSVC-specific step needed anywhere in
this workflow** - confirmed by D-130's own reasoning: `windows-latest` is MSVC-host by default, so
napi-build's Windows-gnu branch this local machine hit never executes there at all.

Verified locally before considering this done: `cargo xtask nodejs` runs clean end to end
(fmt/clippy/build/52 tests, confirmed idempotent on a second run, exit 0 both times);
`cargo deny check`/`cargo audit` both pass against `bindings/nodejs` directly and via `cargo xtask
deny`/`audit` from the repo root (checking root + both bindings in one invocation); `cargo fmt --all
-- --check`/`cargo clippy --all-targets -- -D warnings` clean for `xtask` itself (a pre-existing,
unrelated formatting diff in `xtask/src/main.rs`'s Kani block predates this session's changes -
confirmed via `git stash` - and is out of scope for this step, left alone per minimal-diff
discipline).

## D-132: Node.js binding (T-50) step 7 - examples + README

Same 2026-08-02 session. `bindings/nodejs/examples/{secretbox,secretstream-file,sign,
password-hashing,misc}.js`, mirroring `bindings/python/examples/*.py` one-for-one (same five
files, same split - `misc.js` covers `auth`/`kdf`/`generichash`/`stream`/`randombytes` together,
same as Python's `misc.py`). `README.md` rewritten from nothing (T-50 step 1 never created one, a
gap `bindings/python`'s own step 1 didn't have) to a full module-by-example reference table,
matching `bindings/python/README.md`'s structure and level of detail.

**One real design choice worth recording**: `secretstream-file.js`'s first draft used a multi-stage
`stream.promises.pipeline(readable, transform, writable)` call, which doesn't behave the same way
for a `Transform` as its final stage as it does for a plain `Writable` - genuinely more subtle than
the classic `.pipe()` chain shape. Simplified to the same idiom this project's own doc comments in
`secretstream.js` already recommend (`readStream.pipe(new SecretStreamEncryptor(key)).pipe(...)`)
plus `stream.promises.finished()` to await completion - more recognizable to a working Node
programmer reading an example than a multi-arg `pipeline()` call, and avoids a pipeline edge case
this step didn't need to fight.

Verified: all five examples run correctly against the real built addon
(`secretbox`/`sign`/`password-hashing`/`misc`/`secretstream-file`, output inspected, not just "exit
0"); `node --test` still reports 52/52 (examples aren't named `*.test.js`, so they don't interfere
with test discovery).

## D-133: Ruby binding (T-160) step 1 - `magnus`/`rb_sys` scaffold, several real toolchain gotchas found and fixed

2026-08-02. Ruby was not installed on this machine at all (unlike Python/Node, already present) -
installed via winget as the DevKit variant (`RubyInstallerTeam.RubyWithDevKit.3.3`, bundles a
matching MSYS2 + mingw-w64-ucrt toolchain) rather than the bare interpreter, since a plain Ruby
install has no C compiler wired up for native gem extensions at all. Full detail and exact commands:
`.claude.local.md`'s "Ruby toolchain for `bindings/ruby`" section.

`bundle gem dstu_core --ext=rust` (Bundler's own magnus-based Rust-extension generator, the obvious
first move) **hung indefinitely** even with every documented non-interactive flag
(`--no-ci --no-linter --no-coc --no-mit --test=rspec`) and stdin redirected from `/dev/null` -
confirmed via `Get-Process` CPU-time sampling showing zero progress across a 25-real-minute window,
not assumed from a timeout. Root cause not fully isolated (likely a Windows-Ruby console-handle
quirk bypassing redirected stdin for some remaining prompt), but rather than debugging Bundler's own
generator further, the gem skeleton was **hand-authored** instead - `Cargo.toml`/`build.rs`/
`extconf.rb`/`dstu_core.gemspec`/`Gemfile`/`Rakefile`/`lib/dstu_core.rb` - matching exactly how
`bindings/python`/`bindings/nodejs` were built (this project has never actually relied on a
framework generator for a binding scaffold; no reason to start here).

Getting `rake compile` to actually produce a working `.so` surfaced four distinct, real toolchain
issues, each confirmed by reading the actual failing source/generated file rather than guessed at:

1. **A `Cargo.toml` must exist at the gem root (`bindings/ruby/Cargo.toml`), not only inside
   `ext/dstu_core_rb/`.** `rb_sys`'s `Cargo::Metadata` shells out to a plain `cargo metadata` (no
   `--manifest-path`) from wherever `rake compile` runs (the gem root) - with none there, Cargo
   walks up and finds the *repo-root* workspace instead, and fails with `PackageNotFoundError`
   since `dstu_core_rb` isn't a member of that workspace. Fixed with a small workspace-root
   `Cargo.toml` (`members = ["ext/dstu_core_rb"]`) at the gem root - same D-119 "own separate
   workspace" posture as Python/Node, just split across two files instead of one; the actual crate's
   own `Cargo.toml` has no `[workspace]` of its own (a package can't be both a workspace member and
   a separate workspace root).
2. **`rb-sys-env` must be pinned to match the installed `rb_sys` gem's Makefile convention.** This
   machine's `rb_sys` gem (0.9.128) generates a Makefile exporting `RBCONFIG_*`-prefixed env vars
   (older convention); `rb-sys-env` crate 0.2.x expects a bare `RUBY_VERSION` var (newer convention)
   and panics - `Option::unwrap()` on `None`/an explicit `expect` failure, read directly from the
   crate's own source, not guessed from the error text alone. Pinned to `rb-sys-env = "0.1"`,
   matching the version `rb-sys` itself already resolves internally per `Cargo.lock`.
3. **`rb-sys` needs to be an explicit *direct* dependency**, not only pulled in transitively via
   `magnus`. Cargo's `DEP_<links>_<VAR>` build-script-output propagation (what
   `rb_sys_env::activate()` relies on to read the Makefile's `RBCONFIG_*` exports) only reaches a
   crate's own direct dependents of the crate declaring `links` - `magnus`'s internal use of
   `rb-sys` doesn't extend that propagation one level further out to our own build script. Added
   `rb-sys = "0.9"` alongside `magnus` to fix.
4. **`bindgen`/`libclang` mismatch**: this machine's pre-existing standalone Windows LLVM
   (`C:\Program Files\LLVM\bin\libclang.dll`, MSVC-oriented) is what `clang-sys` finds by default,
   and it parses Ruby's C headers with MSVC assumptions, failing on mingw-only headers. Fixed by
   installing the matching MSYS2 ucrt64 `clang` package (`pacman -S mingw-w64-ucrt-x86_64-clang`)
   and setting `LIBCLANG_PATH` at that package's `bin/` for any cargo invocation touching this
   crate - confirmed a naive `-I` include-path patch on top of the *wrong* libclang instead
   cascades into worse, unrelated parse errors (mingw's own headers assume `__GNUC__`-defined
   semantics an MSVC-mode clang doesn't provide), so redirecting to the right libclang entirely,
   not patching around the wrong one, is the correct fix.

Verified end-to-end, not just "compiles": `rake compile` succeeds from a fully clean tree (`rm -rf
target tmp lib/dstu_core/dstu_core_rb.so ext/dstu_core_rb/{target,Cargo.lock}`, rebuilt from
scratch, confirming reproducibility rather than a one-off fluke); `ruby -Ilib -e "require
'dstu_core'; DstuCore.self_test"` runs the real compiled Rust `dstu_core::selftest::run()` against
the live KAT vectors and returns cleanly (`nil`, i.e. `Ok(())` via magnus); `cargo fmt --all --
--check` and `cargo clippy --all-targets -- -D warnings` (with `LIBCLANG_PATH` set) both clean. Only
`selfTest`/`self_test` wrapped so far, matching Python/Node's own step-1 split - the full `crypto_*`
surface is step 2.

## D-134: Ruby binding (T-160) step 2 - full `crypto_*` surface wrapped

2026-08-02. One Rust module per `dstu_core::crypto_*` module (`secretbox`/`sign`/`auth`/`kdf`/
`generichash`/`stream`/`pwhash`/`randombytes`/`secretstream`), flat `DstuCore.secretbox_seal`-style
naming matching Python/Node's own step-2 posture (idiomatic restructuring is deliberately deferred
to a later step, `crypto_secretstream` specifically). Keys/ciphertexts/tags cross the boundary as
plain Ruby `String` (binary) via `RString`; a single `DstuCore::Error < StandardError` covers every
crypto-operation failure (tag mismatch, truncation, CSPRNG failure), Ruby's own `ArgumentError`
covers a caller-input mistake a fixed-size Rust array forecloses (wrong-length key/context/etc.) -
same two-exception-class split as Python's `DstuError`/`ValueError`, Ruby's own idiom for it.

Three real `magnus` API findings, each confirmed by reading the crate's own source rather than
guessed from the compiler error alone:

1. **`RString::to_bytes()` (the safe, owned-copy path to get plain bytes out of a Ruby `String`) is
   gated behind `magnus`'s own `"bytes"` Cargo feature**, off by default - the alternative,
   `RString::as_slice()`, is `unsafe` (a Ruby `String` is mutable/GC-movable, so a raw borrowed
   slice into it needs the caller to uphold invariants the wrapper wants no part of). Enabled
   `magnus = { version = "0.7", features = ["bytes"] }` instead of reaching for `unsafe`, keeping
   this binding's own wrapper code free of `unsafe` blocks entirely - a deliberate KISS/safety
   choice (D-124), not merely the path of least resistance.
2. **No `IntoValue` impl for Rust tuples** (the same gap Node's `napi-rs` had, D-126) - Ruby's own
   idiom for a multi-value return is an `Array` destructured positionally
   (`ciphertext, tag = state.push(...)`), a natural fit unlike JS's own preference for a named
   object there, so `secretstream`'s `push`/`pull` build a two-element `RArray` via
   `ruby.ary_new_capa(2)` + `.push(...)` rather than reaching for a `#[napi(object)]`-style named
   struct - the idiomatic choice differs by target language even though the underlying gap
   (no tuple support) is the same.
3. **`method!`'s trait bounds require a specific parameter order when a wrapped instance method also
   takes `&Ruby`**: `Fn(&Ruby, RbSelf, Args...)` - Ruby *before* the receiver - which cannot be
   expressed with idiomatic `&self`-sugar syntax (`self` must be the literal first parameter when
   using method-call sugar in Rust). Rather than dropping to `fn(ruby: &Ruby, this: &Self, ...)`
   (breaks `self.foo()` call-site ergonomics inside the impl block), every instance method
   (`Kupyna256Hasher::update`/`finalize`, `SecretStreamPushState::push`/`header`,
   `SecretStreamPullState::pull`, etc.) keeps plain `&self` and calls `Ruby::get().expect(...)`
   internally instead - matching the plain (non-`&Ruby`) `MethodN`/`Method0` trait shape, and the
   same pattern `self_test()` already used in step 1. Only `function!`-registered constructors/
   module-level functions (`SecretStreamPushState::new`, `secretbox_seal`, etc.) take `ruby: &Ruby`
   as their literal first parameter, since those really are free functions with no `self`-sugar
   constraint.

`crypto_pwhash`'s `strength` parameter has no default value (Python's own `#[pyo3(signature =
(password, strength=1))]` doesn't have a straightforward `magnus` equivalent for a plain
`function!`-wrapped function) - callers pass `DstuCore::PWHASH_MODERATE` explicitly. A minor,
documented UX simplification, not a functional gap; not worth the extra `RHash`/kwargs complexity
for a pre-1.0 binding's own step-2 pass.

Verified end-to-end: a full smoke script covering all nine `crypto_*` modules (round-trip,
tamper-rejection via `DstuCore::Error`, wrong-length-key via `ArgumentError`, incremental hasher
`finalize`-twice rejection, `secretstream` push/pull round-trip and tamper rejection) - 15/15 pass
against the live compiled `.so`, re-verified again after `cargo fmt --all` reformatted the four
touched files. `cargo clippy --all-targets -- -D warnings` clean.

## D-135: Ruby binding (T-160) step 3 - `crypto_secretstream` as `SecretStreamWriter`/`SecretStreamReader`

2026-08-02. Pure Ruby (`bindings/ruby/lib/dstu_core/secretstream.rb`) on top of step 2's raw
`SecretStreamPushState`/`PullState` - no new Rust glue, same choice Python/Node both made (file I/O
against an arbitrary caller-supplied object is more natural to write directly in the host language
than via FFI callbacks). **Idiom chosen after research, not assumed**: Ruby's own
`Zlib::GzipWriter`/`Zlib::GzipReader` (stdlib, bundled) is the closest native precedent - both wrap
an arbitrary `IO`-like object and transform chunks transparently, the same shape problem as this
wrapper, so `SecretStreamWriter`/`SecretStreamReader` mirror that pair's `write`/`<<`/`close` and
`each`/`Enumerable`/`close` surface respectively, rather than inventing a new shape. Wire format
matches `uacrypt encrypt`/`decrypt` exactly (8 KiB `SECRETSTREAM_CHUNK_BYTES`, same
`tag(1) || len_u32_le(4) || ciphertext || auth_tag(16)` framing as Python/Node) - verified
bidirectionally against the real built `uacrypt.exe` (encrypt one side, decrypt with the other,
byte-for-byte match both ways), not just self-consistently.

Both D-118 pitfalls re-checked for this port specifically, same as every prior binding:
- **The cleanup path must not finalize on the error path.** Ruby's own idiomatic block-form
  cleanup (`ensure`, the exact shape `File.open`/`Zlib::GzipWriter.wrap` both use) always runs even
  when the block raises - using that idiom naively for `SecretStreamWriter.open` would emit the
  `Final` chunk even after a partial write, producing a stream that looks complete but silently
  drops data (violates D-65). Fixed by **deliberately not using `ensure`** in
  `SecretStreamWriter.open` - it calls `writer.close` as the last statement of the block's own
  normal-return path, so an exception propagates before `close` ever runs, matching Python's
  `__exit__(exc_type, ...)` conditional-close and Node's `_flush`-not-`_destroy` fix exactly. This
  is the one place this binding deliberately diverges from "the idiomatic Ruby pattern" because the
  idiomatic pattern is wrong for this specific case - worth flagging explicitly since it is easy to
  reach for `ensure` here from muscle memory.
- **The wire-format reader bounds the untrusted `chunk_len` field and rejects trailing data after
  `Final`.** Ported explicitly (not inherited from the wire format matching) - `chunk_len > 
  SECRETSTREAM_CHUNK_BYTES` raises before reading, and `@inp.read(1)` after a `Final` tag raises if
  it returns anything, both matching `uacrypt decrypt`'s own
  `CliError::SecretstreamChunkTooLarge`/`CliError::SecretstreamTrailingData` checks.

`SecretStreamReader` includes `Enumerable` (`each` returns an `Enumerator` when no block is given,
the standard Ruby external-iterator idiom) - `read_all` is `each.to_a.join`, giving both a
chunk-at-a-time consumer and a whole-message convenience for free from one `each` implementation.

Verified: 8 real checks against the live compiled `.so` (round-trip at an arbitrary size, exact
8192-byte chunk-boundary sizing matching the Rust CLI's own one-chunk-ahead buffering exactly - the
last full chunk tagged `Final` directly, no spurious empty `Final` record, mirroring T-49 step 3's
own boundary-bug catch - multi-chunk `each`/`Enumerable` iteration, the `ensure`-avoidance pitfall
test specifically, oversized-`chunk_len` rejection, trailing-data rejection, and the two-directional
real `uacrypt.exe` interop). `rubocop` deliberately deferred to step 5, alongside `cargo xtask ruby`
wiring - matching where `bindings/python`'s own `ruff` gate landed (T-49 step 5), not introduced as
scope creep inside this step.

## D-136: Ruby binding (T-160) - advisor-review corrections to steps 2/3, then step 4 (prebuilt native gem)

2026-08-02. Before step 4, an `advisor()` review of steps 1-3 surfaced six real findings, none of
which the local smoke scripts had caught - fixed in their own commit, distinct from step 4's actual
new work, same discipline D-130 used correcting D-125:

1. **The gemspec `files` glob was single-level** (`Dir.glob("ext/dstu_core_rb/*.{rs,toml,rb}")`) -
   matched `Cargo.toml`/`build.rs`/`extconf.rb` but not `ext/dstu_core_rb/src/*.rs`, and omitted the
   gem-root `Cargo.toml`/`Cargo.lock` (the workspace anchor, D-133) entirely. The Node `files`
   gotcha (D-128) in Ruby form - fixed to a recursive `Dir.glob("ext/**/*.{rs,toml,rb}")` plus the
   two root files added explicitly.
2. **Text-mode `IO` silently corrupts binary data on Windows** (LF→CRLF translation applied to
   header/ciphertext/tag bytes) - `SecretStreamWriter`/`Reader` now call
   `@out.binmode if @out.respond_to?(:binmode)` (and the same for `@inp`) in their constructors,
   verified by an explicit test opening a file with plain `"w"`/`"r"` (not `"wb"`/`"rb"`) and
   confirming a correct round-trip despite the caller's own mode choice.
3. **Encoding of returned plaintext**: `RString`/`str_from_slice` produce/consume `ASCII-8BIT`
   (binary) `String`s throughout - documented explicitly in `secretstream.rb`'s module doc, since
   `"привіт".b == "привіт"` is `false` in Ruby (differing encodings) and every smoke test so far
   used ASCII-only fixtures, silently avoiding the question. Added an explicit non-ASCII UTF-8
   round-trip test asserting the binary contract.
4. **`is_finalized` is not a Ruby name** - inconsistent with the Ruby-layer's own `closed?`
   (`SecretStreamWriter`) written in the same session. Renamed the Rust-registered method to
   `finalized?` on both `SecretStreamPushState`/`PullState` (D-126's "casing is per-language" note
   applies to predicate-naming conventions too, not just casing).
5. **Write-after-close raised `ArgumentError`; Ruby's own `IO` contract for that is `IOError`**
   (`"closed stream"`) - aligned before step 6 could pin the wrong exception class in a misuse spec.
6. Two gaps flagged for step 6 to pre-plan rather than fix now: the future `uacrypt` interop spec
   must fail loudly on a silent `skip`/`pending` (RSpec's equivalent of Node's `grep -q "not ok"`
   gate), and locate the `uacrypt` binary relative to the repo root with an explicit `.exe` suffix
   rather than an absolute path. Verified now instead: the empty-input degenerate case (D-65) in
   both directions - `SecretStreamWriter.open(key, io) {}` alone produces a single empty `Final`
   chunk that round-trips, and a genuinely empty file through real `uacrypt encrypt` decrypts
   correctly through `SecretStreamReader`.

**Step 4 itself**: a *source* gem (`gem build dstu_core.gemspec`) cannot actually install standalone
- confirmed empirically, not assumed, by installing into a fresh, unrelated `GEM_HOME` and watching
`cargo` fail to resolve `ext/dstu_core_rb/Cargo.toml`'s `dstu-core = { path =
"../../../../crates/dstu-core" }` dependency, since that relative path only exists inside this
repo's own tree, not inside an arbitrary installed gem's directory. This is the reason
`docs/bindings-strategy.md`'s own per-binding checklist already says "a prebuilt extension binary
where the ecosystem supports it, source build only as a fallback" for Ruby specifically - a
precompiled, platform-tagged gem sidesteps the path dependency entirely by shipping the compiled
`.so` directly, no `ext/` source or `Cargo.toml` needed at install time. `rake-compiler`/`rb_sys`
already provide this mechanism (`RbSys::ExtensionTask` auto-defines a `native` task chain since the
gemspec's platform defaults to `"ruby"`) - `rake native gem` (both together, since `native` only
stages files and `gem` is the actual `Gem::Package.build` step, two separate `Gem::PackageTask`
targets) produces `pkg/dstu_core-0.1.0-x64-mingw-ucrt.gem`, its `cross_compiling_blocks` callback
automatically stripping `.rs`/`Cargo.{toml,lock}` files and the `rb_sys` dev-dependency from the
packaged spec. Verified with the same fresh-`GEM_HOME` install bar: `require "dstu_core"`,
`self_test`, and a `SecretStreamWriter`/`Reader` round-trip all pass against the installed gem, not
the source tree - matching Python/Node's own step-4 verification bar exactly. Linux/macOS
cross-compiled native gems (needing `rake-compiler-dock`/Docker, not set up on this Windows-only
machine) are deferred to CI, same "this machine is Windows-only" precedent Python/Node's own step 4
entries already recorded.

## D-137: Ruby binding (T-160) step 5 - `cargo xtask ruby` + `bindings-ruby.yml`, rubocop wired in

2026-08-02. `rubocop` (deferred from step 3, D-135's own note) added as a dev dependency and run
for the first time - 63 offenses on the first pass (mostly `Style/StringLiterals` defaulting to
single quotes and a Windows `core.autocrlf`-driven `Layout/EndOfLine` false positive, the same class
of finding ruff produced for Python at this exact step, T-49 step 5's own precedent). Settled in
`.rubocop.yml` rather than reflowing to rubocop's defaults: `Style/StringLiterals` set to
`double_quotes` (matching every other language's convention in this project), `Layout/EndOfLine`
disabled outright (the autocrlf false positive has no per-OS CI job to defer to the way `cargo fmt
--check` does), `Metrics/MethodLength` raised to 20 (the wire-format chunk-parsing methods are a few
lines over the default, genuinely sequential validation steps). Auto-correctable offenses fixed via
`rubocop -A`; the one substantive suggestion (`Gemspec/DevelopmentDependencies` - move dev
dependencies out of the gemspec) was taken by moving `rake-compiler`/`rb_sys`/`rspec`/`rubocop` into
the `Gemfile`'s own `:development` group instead of `add_development_dependency`, functionally
identical, matching rubocop's own modern convention rather than suppressing the cop.

**`command_for()`'s Windows batch-script mapping (D-12) extended a third time**: `bundle` ships as
`bundle.bat` on Windows RubyInstaller, same "`Command::new` doesn't try `.bat`/`.cmd` extensions
the way a shell does" gotcha `mvn`/`npm` already needed - `command_for()` now covers all three.

`cargo xtask ruby` mirrors `python()`/`nodejs()` exactly: builds `uacrypt --release` from the repo
root first (for the RSpec interop test, step 6), `bundle install`, `cargo fmt --all -- --check`/
`cargo clippy --all-targets -- -D warnings` against `bindings/ruby`'s own Cargo workspace,
`bundle exec rake compile`, `bundle exec rubocop`, `bundle exec rspec` - verified running clean
end-to-end on this machine (`LIBCLANG_PATH` still needed locally, D-133 - not anything `xtask`/CI
needs to special-case, matching how the MSVC `rustup override` for Node never entered `xtask`
either). `.github/workflows/bindings-ruby.yml` mirrors `bindings-python.yml`/`bindings-nodejs.yml`'s
shape (`test` matrix ubuntu/macos/windows, `supply-chain` deny/audit) with one addition no other
binding needs: a Windows-only step installing the matching MSYS2 `mingw-w64-ucrt-x86_64-clang`
package via `ridk exec pacman` and pointing `LIBCLANG_PATH` at it (`ridk exec cygpath -w
/ucrt64/bin`) - the exact fix D-133 found for this dev machine, now codified for CI's own
`windows-latest` runner rather than assumed to be unnecessary there. `cargo deny check`/`cargo
audit` both verified locally against `bindings/ruby`'s real dependency tree (magnus/rb-sys), clean
(one benign `license-not-encountered` advisory-info warning, not an error). `deny.toml`'s header
comment updated to mention all three bindings sharing the one policy file.

Not yet verified on real GitHub Actions (needs an explicit push, same gate every prior binding's CI
workflow went through) - the Windows-specific `ridk exec` steps are the one part of this workflow
with no local equivalent test, since this dev machine's own MSYS2 clang install used a plain
`pacman -S` directly rather than through `ridk exec` (both should be equivalent - `ridk exec` just
activates the same MSYS2 shell environment first - but this specific invocation form is unverified
until CI actually runs it).

## D-138: Ruby binding (T-160) step 6 - RSpec suite, D-64/D-65 categories, cross-language vectors

2026-08-02. 10 spec files, file-for-file mirroring `bindings/python/tests/*.py`/
`bindings/nodejs/test/*.test.js` (selftest, secretbox, auth, kdf, generichash, stream, pwhash,
randombytes, sign, secretstream) - 58 examples total, all passing against the live compiled `.so`.
Category-1 correctness loads the same shared vector JSON the Rust tests/`self_test` already use
(`crates/dstu-core/tests/vectors/kupyna/kupyna-256.json`, `generichash_spec.rb`) - the actual
mechanism that makes this cross-language per D-124, not a separately hand-transcribed number.

Confirmed empty (`bundle exec rspec` with zero spec files first, before writing any) - **RSpec
vacuously passes on an empty suite (`0 examples, 0 failures`, exit 0)**, matching pytest's own
behavior, unlike Node's `node --test test/` which errors on a nonexistent directory (D-129) - so
Ruby follows the standard step-5-before-step-6 template order, no tooling-forced reorder needed
here the way Node's own step 6 needed one.

`rubocop` flagged a second, smaller batch on the new spec files themselves once written:
`Metrics/BlockLength` on every `RSpec.describe`/`it` block (the standard shape this cop always
flags in real-world Ruby test suites) - excluded `spec/**/*.rb` in `.rubocop.yml` rather than
raising the limit project-wide, plus one auto-corrected `Style/StringConcatenation`.

`secretstream_spec.rb`'s real `uacrypt` interop test uses `if: uacrypt` metadata (a truthy/falsy
Ruby object, not a block) to conditionally run only when the binary is found - confirmed this
actually filters correctly by running `--format documentation` and counting: 15 of 16 written
examples ran when `uacrypt` was found (the complementary "documents the uacrypt-missing case"
example correctly excluded), not assumed from RSpec's docs alone. Chose `skip` (visible as "N
pending" in RSpec's own summary) over a silently smaller example count for the uacrypt-missing
case - `cargo xtask ruby`/CI always build `uacrypt --release` first (step 5), so this never
actually skips in the pipeline that matters; a bare local `bundle exec rspec` without that build
step is the only path where it does, and RSpec's own summary line makes that visible rather than
silent, addressing the same class of concern Node's own `grep -q "not ok"` gate (D-129) was built
for, via a different, RSpec-native mechanism.

Full `cargo xtask ruby` (fmt, clippy, `rake compile`, `rubocop`, `rspec`) verified clean end-to-end
with the real suite now in place, not just the vacuous empty-spec-dir pass step 5 originally
verified against.

## D-139: Ruby binding (T-160) step 7 - examples/ + README.md

2026-08-02. `examples/{secretbox,secretstream_file,sign,password_hashing,misc}.rb`, one-for-one
with Python's/Node's own five example files - each run against the real compiled `.so` before
committing, not just written from the API surface. `README.md` written from scratch (no README
existed after step 1, same gap Node's own step 1 had), documenting the full surface with a
module-by-example table, the DevKit/MSYS2-clang install steps (D-133), and the source-gem-can't-
install-standalone caveat (D-136) up front rather than leaving it to be discovered.

**One real fix found writing the examples**: `require_relative "../lib/dstu_core"` alone doesn't
work from an example script outside `lib/` - `lib/dstu_core.rb`'s own internal `require
"dstu_core/dstu_core_rb"` (a plain, non-relative require) needs `lib/` on `$LOAD_PATH`, which
`require_relative` never adds. Fixed by having every example do
`$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))` before `require "dstu_core"`, matching
how a real installed gem's own `require "dstu_core"` would resolve (this only matters for
`examples/`, which run against the source tree directly rather than an installed gem).

`rubocop` flagged two auto-correctable findings (`Style/StringLiteralsInInterpolation` in
`misc.rb`'s `#{...unpack1("H*")}` interpolations) - corrected via `rubocop -A`. Full `cargo xtask
ruby` re-verified clean with the new files in place.

## D-140: `bindings-ruby.yml` CI fixes - real first-run failures on all three OS legs

2026-08-02. T-160's own CI workflow (D-137) failed its first real run on all three OS legs -
confirmed via `gh run view`, two distinct root causes, both fixed rather than assumed correct from
local testing alone (this dev machine could never have caught either, since it only ever builds
for one OS/one Ruby install method):

1. **Windows: `ridk: command not found`.** D-137's workflow assumed `ridk exec pacman`/`ridk exec
   cygpath` the same way this dev machine's own manually-installed RubyInstaller-with-DevKit
   exposes `ridk`. `ruby/setup-ruby@v1`'s hosted Windows Ruby install does **not** put `ridk` on
   PATH at all (confirmed by the actual failure: `ridk: command not found`, exit 127) - it only
   sets an `RI_DEVKIT` env var pointing at the bundled MSYS2 tree. Fixed by dropping the `ridk
   exec` wrapper entirely: `ruby/setup-ruby`'s own `shell: bash` steps already run inside that
   bundled MSYS2's `bash.exe` (confirmed from the log's own `shell:` line), whose PATH already
   includes MSYS2's `usr/bin` - so `pacman`/`cygpath` work directly with no wrapper needed.
2. **Linux/macOS: `bundle install` refused to run** ("Your bundle only supports platforms
   ["x64-mingw-ucrt"]"). `Gemfile.lock` was generated exclusively on this Windows dev machine, so
   its `PLATFORMS` section only listed `x64-mingw-ucrt` - a lockfile with no platform for the
   `ubuntu-latest`/`macos-latest` runners' own gem resolution to use at all, not a build-tool
   problem. Fixed with `bundle lock --add-platform x86_64-linux arm64-darwin x86_64-darwin`
   (`arm64-darwin` specifically since GitHub's `macos-latest` runners are Apple Silicon, confirmed
   from the failure log's own `arm64-darwin23` Ruby build string, not assumed to still be Intel).

Neither gap could have been caught by this machine's own local `cargo xtask ruby` runs, which is
exactly why this project's own discipline (`docs/CLAUDE.md` "verify a CI job's real conclusion via
`gh run view`, never assume from a green badge") treats an unpushed CI workflow as unverified until
it actually runs - re-pushed to confirm the fix, not left at "should work."

## D-141: `bindings-ruby.yml` CI fix, round 2 - Windows needs the GNU-host Rust toolchain, not MSVC

2026-08-02. D-140's fixes got `ubuntu-latest`/`macos-latest` green; `windows-latest` still failed,
with a genuinely different root cause from either of D-140's two - confirmed via `gh run view`
again rather than assumed fixed by the earlier push.

**The mirror image of Node's own D-125/D-130 finding**: `windows-latest`'s default
`dtolnay/rust-toolchain@stable` installs the MSVC-host toolchain, but `rb_sys`'s generated Makefile
passes GNU/mingw-style linker flags (`-C linker=gcc`) matching Ruby's own `x64-mingw-ucrt` build -
an MSVC-host `rustc` invoking `gcc`/`ld.exe` as the linker still emits MSVC-style `/FLAG` arguments
(`/DEF:...`, `/NOLOGO`, `.lib` suffixes) that `ld.exe` can't parse (`cannot find /NOLOGO: No such
file or directory`, etc. - the exact failure signature, not a guess from reading the linker
invocation alone). Where Node's own local dev machine defaulted to GNU and needed forcing to MSVC
(D-125/D-130), here CI's `windows-latest` defaults to MSVC and needs forcing to GNU instead - same
underlying class of host-triple mismatch, opposite direction, confirming this is a real recurring
category for any Windows target needing to match Ruby's own mingw-ucrt build, not a one-off.

Fixed with `dtolnay/rust-toolchain@stable`'s `toolchain` input set conditionally on `matrix.os`:
`stable-x86_64-pc-windows-gnu` for `windows-latest` only, plain `stable` (host default) for
`ubuntu-latest`/`macos-latest` - no separate toolchain-selection step needed, `dtolnay/rust-
toolchain` accepts a full toolchain name including the target triple directly in that one input.

**Corrected the same day, round 3**: re-pushed and re-checked per this entry's own closing note -
`windows-latest` failed again, with the *identical* MSVC linker error, `rustup default` having no
effect at all. Root cause: this repo's root `rust-toolchain.toml` pins a bare `channel = "stable"`
with no host triple - that resolves against the machine's *default host* (MSVC, unrelated to
whatever `rustup default` was just set to) for any cargo invocation anywhere under this repo's
tree, silently overriding the toolchain step above. The exact class of gotcha `CLAUDE.md` already
documents for nightly (`cargo +nightly` needed explicitly for miri/fuzz) - confirmed here to apply
to host-triple selection too, not just channel selection, via this second real failure. Fixed with
`RUSTUP_TOOLCHAIN: stable-x86_64-pc-windows-gnu` set as a per-step `env:` (Windows-only, on the
`clippy` and `bundle exec rake compile` steps specifically) - `RUSTUP_TOOLCHAIN` overrides a
toolchain file outright, where `rustup default` does not. **Confirmed green on real CI** (run id
`30759971107`): all four jobs (`cargo deny / audit`, `build + test` on ubuntu/macos/windows-latest)
report `success` - three real CI round-trips total for this workflow (D-140's two fixes, this
entry's toolchain-file fix), each one a genuine finding this dev machine's own local `cargo xtask
ruby` runs could never have caught by construction (one OS, one pre-existing toolchain
configuration, no toolchain-file-vs-`rustup default` conflict to trigger).

## D-142: T-159 (PHP) steps 1-2 - `ext-php-rs` scaffold + full `crypto_*` surface, flat
`dstu_core_*` naming convention

PHP was not installed on this machine at all (unlike Python/Node/Ruby's own precedents).
`winget install --id PHP.PHP.NTS.8.3`/`8.4` both failed with a real 404 - their manifests pin a
specific patch version (`8.3.31`/`8.4.22`) php.net has already rotated out of its releases
directory (only the latest patch per minor version is kept there), confirmed by fetching
`windows.php.net/downloads/releases/` directly and finding `8.3.33`/`8.4.24` instead. Installed by
hand: `php-8.3.33-nts-Win32-vs16-x64.zip` extracted to `C:\Users\Pa\tools\php83` (`.claude.local.md`
has the exact commands/paths, same "installed outside winget, documented locally" shape as Python's
own precedent).

### Windows toolchain requirements (`ext-php-rs`'s own README, "Windows Requirements" section - read
directly, not assumed)

- **Nightly Rust required on Windows only** - some PHP internal functions use the `vectorcall`
  calling convention, a nightly-only unstable Rust feature (`#![cfg_attr(windows,
  feature(abi_vectorcall))]` at the crate root). Linux/macOS build on stable.
- **PHP's own Windows builds are MSVC** (`vs16`/`vs17` in the release filename identifies the
  Visual Studio toolset PHP itself was built with) - needs the MSVC host, not this machine's own
  GNU-host default (same class of mismatch as Node's D-130, opposite direction from Ruby's D-133:
  Node needed forcing to MSVC on a GNU-default machine to match a Windows-native dependency, PHP
  needs the same; Ruby instead needed to *match* the GNU default). Fixed identically - a
  machine-local `rustup override set nightly-x86_64-pc-windows-msvc --path bindings/php`, not a
  committed toolchain file (would break CI's Linux/macOS runners). The `nightly-x86_64-pc-windows-
  msvc` toolchain and its `rustfmt`/`clippy` components were already present on this machine
  (installed earlier for the ASan fuzz work) - no new toolchain install needed, just the mapping.
- **`rust-lld` linker recommended over the default MSVC `link.exe`** (`ext-php-rs`'s own README
  again: `link.exe`'s version may not be ABI-compatible with whatever linker built the target PHP
  install) - `bindings/php/.cargo/config.toml`, `[target.x86_64-pc-windows-msvc] linker =
  "rust-lld"`. Confirmed working, not just configured: `cargo build` links cleanly.
- **No manual devel-pack management needed**, confirmed by reading `ext-php-rs`'s own
  `windows_build.rs` directly rather than assuming: on Windows its build script downloads a
  matching `php-devel-pack-<version>-Win32-<vs>-<arch>.zip` from `windows.php.net` itself at build
  time (into `OUT_DIR`), keyed off the exact version/thread-safety/arch it detects from the
  `php.exe` on `PATH` (or the `PHP` env var). A separate manual devel-pack download+extract was
  tried first before finding this in the source - unnecessary, real projects don't need it.

First build (`cargo build`, self-test-only scaffold) succeeded on the first real attempt once the
above three were in place - confirmed end-to-end: `dstu_core_php.dll` loaded into a real `php.exe`
via `-d extension=...`, `self_test()` returned `true`.

### Naming convention: flat `dstu_core_*` global functions + a single `DstuCoreException` class,
not a namespace or a static-method class

PHP has no per-extension function scoping by default (every `#[php_function]` registers a global
function) and no strong ecosystem convention pushing toward a namespace for a native extension's
own functions (unlike a Composer-distributed pure-PHP library, where namespacing is the norm).
Rather than inventing a shape, this matched the closest real precedent instead: PHP's own bundled
`ext-sodium` extension (a crypto library, PECL-style native extension, exactly this binding's
domain) uses flat, snake_case, `sodium_`-prefixed global functions (`sodium_crypto_secretbox`,
`sodium_crypto_sign_keypair`, etc.) and a single flat `SodiumException` class, no namespace, no
per-construction exception subclass. Adopted directly: every function is `dstu_core_<module>_
<verb>` (`dstu_core_secretbox_seal`, `dstu_core_sign_verify`, ...), matching Ruby's/Node's own
snake_case-throughout convention rather than PHP's more common camelCase method style (chosen for
internal consistency with the flat-function shape, not because PHP prefers it) - `#[php(change_
method_case = "snake_case")]` set explicitly on every `#[php_impl]` block since ext-php-rs's own
default is camelCase. One shared exception class, `DstuCoreException extends \Exception`
(`#[php(name = "DstuCoreException")] #[php(extends(ce = ce::exception, stub = "\\Exception"))]`),
covers every crypto-operation failure, matching `SodiumException`'s own scope exactly. A
caller-input mistake a fixed-size Rust array forecloses (wrong-length key/context, negative
`subkey_id`) throws PHP's own built-in `\ValueError` instead (`ext_php_rs::zend::ce::value_error()`)
- not this class - the same two-different-failure-classes split this project's other bindings
already use (Ruby's `ArgumentError`, Python's `ValueError`).

Stateful classes (`Kupyna256Hasher`/`512Hasher`, `SecretStreamPushState`/`PullState`) have no
`ext-sodium` precedent to follow (`ext-sodium`'s own API is one-shot functions only, no incremental
hasher/stream classes) - prefixed `DstuCore*` (`DstuCoreKupyna256Hasher`,
`DstuCoreSecretStreamPushState`, etc.) rather than left bare, to avoid colliding with an unrelated
extension's own global class-table entry (PHP classes share one global namespace by default, same
risk a bare `Hasher` or `PushState` class name would create) while staying consistent with the flat
naming convention rather than switching to a real PHP namespace (`ext-php-rs` does support
namespaced class names via `#[php(name = "Foo\\Bar\\Baz")]`, confirmed in its own guide's
`Redis\Exception\RedisException` example - not used here, to keep one naming shape across
functions and classes rather than mixing flat functions with namespaced classes).

### `Binary<u8>`, not `String`/`Vec<u8>`, for every crypto byte parameter/return

Confirmed by reading `ext-php-rs`'s own `types/zval.rs`/`binary.rs` directly: `Zval::string() ->
Option<String>` requires the bytes to be valid UTF-8 (would silently mangle or reject arbitrary
key/ciphertext/hash bytes), while `Zval::binary::<T: Pack>() -> Option<Vec<T>>` (surfaced as the
`ext_php_rs::binary::Binary<T>` wrapper type) round-trips a PHP string's raw bytes exactly,
regardless of content - a PHP string is natively just a byte buffer, not UTF-8-validated, the same
property Ruby's own binary (`ASCII-8BIT`) `String`/Python's `bytes` already give this project's
other bindings. A bare `Vec<u8>` has its own, different `IntoZval`/`FromZval` impl (a PHP list array
of integers, not a binary string) - confirmed by reading `types/array/conversions/vec.rs`, not
assumed; using it by mistake for a key/ciphertext would silently produce the wrong PHP-side shape
rather than fail to compile.

### Three real build-error findings while wiring step 2's full surface, each confirmed by an actual
compiler/runtime failure, not predicted in advance

- **`wrap_function!(module::function_name)` does not resolve** - "Pass a PHP function name into
  `wrap_function!()`." `#[php_function]`'s own expansion generates a private companion item
  (`_internal_<fn_name>`) in the *same module* as the function; the macro looks this up by a bare
  identifier, so a module-qualified path from `lib.rs` never resolves, and `pub use module::*;`
  re-exports do not help either (the companion item itself is not `pub`). Fixed by giving every
  `crypto_*` module its own `pub fn register(module: ModuleBuilder) -> ModuleBuilder` that calls
  `wrap_function!` on its own bare function names from inside that same module, with `lib.rs`
  chaining `secretbox::register(module)` etc. rather than calling `wrap_function!` itself for
  every function from one place - the reverse of Ruby's/Node's own single-`lib.rs`-does-everything
  shape, forced by this macro's own resolution rule, not a style preference.
- **`u8` does not implement `IntoConst`** - only the signed integer/float types do (`i8`/`i16`/
  `i32`/`i64`/`f32`/`f64`), confirmed by the real compiler error listing them. PHP has no unsigned
  integer type at all (its own `int` is a 64-bit signed type), so this is not a limitation worth
  routing around - the `PWHASH_*`/`SECRETSTREAM_TAG_*` module constants (Ruby's `u8`, Node's `u8`)
  became `i32` here, small values (0-3) that fit either way.
- **`#[php_function]`'s default snake_case rename splits a letter-to-digit boundary** -
  `dstu_core_generichash_kupyna256` registered in PHP as `dstu_core_generichash_kupyna_256` (an
  extra underscore before `256`), caught by a real smoke-test call getting "Call to undefined
  function", not predicted from reading the derive macro's source. Fixed by pinning the exact name
  explicitly on both digit-suffixed functions: `#[php(name = "dstu_core_generichash_kupyna256")]`
  (the `Kupyna256Hasher`/`Kupyna512Hasher` *class* names were unaffected, since their own
  `#[php(name = ...)]` was already set explicitly from the start).

### Verification

`cargo build`/`cargo fmt --check`/`cargo clippy --all-targets -- -D warnings` all clean. Full
manual smoke test against the real compiled `dstu_core_php.dll` loaded into a real `php.exe`
(`-d extension=...`, no `php.ini` edit needed) covering every wrapped function and class:
`self_test`, `secretbox` round-trip plus tamper rejection plus wrong-length-key `\ValueError`,
`sign` keygen/verify (true and false cases), `Kupyna256Hasher` incremental vs. one-shot digest
match, and a full `secretstream` push/pull round-trip through the raw `PushState`/`PullState`
classes (the idiomatic file-like wrapper is step 3, not yet built).

## D-143: T-159 (PHP) step 3 - `crypto_secretstream` as plain PHP wrapper classes, not a stream
filter; a real ext-php-rs gap found along the way (a Rust-registered exception class cannot be
`new`-ed from pure PHP without its own `#[php_impl]` constructor)

### Stream-filter mechanism investigated and rejected

PHP does have a genuine idiomatic transparent-stream mechanism, `stream_filter_register`/
`php_user_filter` (confirmed real and pure-PHP-implementable: `stream_get_filters()` lists the
built-in `zlib.deflate`/`zlib.inflate` filters as the same-shape precedent, and `php_user_filter`
is a normal userland base class, not something needing native bucket-brigade FFI). Rejected anyway,
for two concrete reasons rather than a vague "too complex": (1) the filter framework's own
`filter($in, $out, &$consumed, $closing)` hook has no clean place to write a one-time 32-byte
header *before* any filtered bytes - it would have to be done lazily on the first call, entangling
header-writing with the per-call transform logic; (2) PHP's own internal stream buffer size (which
governs how much data reaches one `filter()` call) does not align with this wire format's fixed
8 KiB chunk boundary, so the filter would still need its own independent buffering layer on top -
at which point it is strictly more code than a plain wrapper class for no behavioral gain. Chosen
instead: `DstuCoreSecretStreamWriter`/`DstuCoreSecretStreamReader` (`bindings/php/lib/
DstuCoreSecretStream.php`), plain PHP classes over a `resource`, built on step 2's raw
`DstuCoreSecretStreamPushState`/`PullState` rather than new Rust glue - directly mirrors Python's
`SecretStreamEncryptor`/`Decryptor` and Ruby's `SecretStreamWriter`/`Reader`, this project's own
KISS-for-bindings instinct ([[feedback_binding_kiss_test_first]]).

### Design, matching Ruby's own shape closely

**Wire format matches `uacrypt encrypt`/`decrypt` exactly** (verified both directions against the
real built `uacrypt.exe`, not just self-consistently - see Verification below): 32-byte header,
then `tag(1) || chunk_len_u32_le(4) || ciphertext(chunk_len) || auth_tag(16)` records, chunks capped
at 8 KiB. `DstuCoreSecretStreamWriter::withStream($key, $out, fn($w) => ...)` runs the callback
then calls `close()` **only on the success path** - deliberately no `try`/`finally` wrapping, so an
exception thrown inside the callback skips `close()` entirely and the D-118 pitfall (a resource
cleanup hook finalizing a truncated write into a complete-looking stream) cannot occur; confirmed
by a real test (a callback that writes then throws, followed by attempting to read the resulting
truncated bytes back, which correctly fails with a truncation error rather than succeeding).
`DstuCoreSecretStreamReader` implements PHP's own `Iterator` interface (`foreach ($reader as
$chunk)` works directly) rather than a callback/block-only shape - forward-only, `rewind()`
raises if called a second time (mirrors `\Generator`'s own restriction, the closest stdlib
precedent for a single-pass iterator). The untrusted wire `chunk_len` field is bounds-checked
before being used to size a read, and trailing bytes after the `Final` chunk are rejected (D-118's
second pitfall) - both confirmed by real rejection tests, not assumed from matching the wire format
alone.

### A real ext-php-rs gap: `DstuCoreException` cannot be `new`-ed from pure PHP

Writing this wrapper in pure PHP surfaced a genuine limitation, not predicted from step 2's own
Rust-side-only exception usage: `new DstuCoreException($msg)` from PHP userland fails with "You
cannot instantiate this class from PHP." Root-caused by reading `ext-php-rs`'s own
`builders/class.rs` directly: a `#[php_class]`-registered class's PHP-visible constructor comes
*only* from a `#[php_impl] fn __construct(...)` block; without one, `T::constructor()` returns
`None` and the generated constructor trampoline throws that fixed string unconditionally.
`DstuCoreException` was deliberately built with no `#[php_impl]` at all (only `#[derive(Default)]`,
enough for `PhpException::from_class`'s own internal construction path, which bypasses PHP's
`__construct` entirely the same way `zend_throw_exception_ex` does) - correct for every Rust-side
throw site, but leaves pure PHP code with no way to raise the same class directly.

Fix: a small escape-hatch function, `dstu_core_throw_error(string $message)`
(`bindings/php/src/error.rs`) - its whole body is `Err(PhpException::from_class::<
DstuCoreException>(message))`, so calling it as a plain statement (`dstu_core_throw_error("...")`)
throws exactly like a `throw` statement would, reusing the identical working Rust-side construction
path rather than attempting to wire up a real `#[php_impl]` constructor that forwards to
`\Exception`'s own base constructor (no documented ext-php-rs helper for that found; the escape
hatch is simpler and sufficient). Every `dstu_core_throw_error`/would-be-`throw new
DstuCoreException` site are indistinguishable to a `catch (DstuCoreException $e)` block, confirmed
by every rejection test still passing unchanged after the swap.

### Verification

Real bidirectional wire-format interop against the actual built `uacrypt.exe` (`cargo build -p
uacrypt --release` from the repo root, not simulated): a file written by
`DstuCoreSecretStreamWriter` (multi-chunk, crossing the 8 KiB boundary mid-write) decrypted
correctly via `uacrypt decrypt`, byte-for-byte; a file produced by `uacrypt encrypt` decrypted
correctly via `DstuCoreSecretStreamReader::readAll()`, byte-for-byte. Six rejection/misuse cases,
all raising `DstuCoreException` with the expected message: tampered ciphertext byte, truncated
stream (mid-chunk cutoff), trailing data after `Final`, wrong key, write-after-close, and a
callback that throws partway through a write (confirming the D-118 no-finalize-on-error property
directly, not just by code inspection). `cargo fmt --check`/`cargo clippy --all-targets -D
warnings` clean; `php -l` confirms the PHP file itself has no syntax errors.

## D-144: T-159 (PHP) step 4 - packaging story, honestly: a prebuilt binary + a documented
`extension=` line, no PECL/Composer publish attempted

PHP's native-extension distribution story has no wheel/npm-pack/gem equivalent at all, for a
structural reason rather than a gap in this session's effort: **Composer never manages native
extensions** (a `.dll`/`.so` loaded by the Zend engine itself, before userland code runs) - it only
ever manages pure-PHP packages, so there is no "Composer package that contains a compiled binary"
shape to build toward, unlike Python's wheel/Node's npm-pack/Ruby's gem, each of which genuinely can
bundle a compiled artifact inside their own package format. The actual native-extension registry,
PECL, requires a `package.xml` manifest, a PECL account, and a public C-source review/build
process - a real publish pipeline, not a local packaging step, and out of scope for a provisional,
not-yet-published binding (matches this project's own MVP scope note that publishing anywhere is
explicitly gated on an owner request, same posture as `dstu-core`'s own crates.io non-publish).

The honest, real deliverable at this stage: a release-profile compiled binary (`cargo build
--release`, mirrors every other binding's own step-4 artifact) plus the documented `php.ini
extension = /path/to/dstu_core_php.dll` line (or `-d extension=...` for an ad hoc load) any real
PHP install already supports for a third-party compiled extension - no packaging format needed for
this to work at all. Verified with a genuine fresh-install-style check (the same bar Python's/
Node's own step 4 set): copied *only* the compiled `dstu_core_php.dll` (release build) into an
unrelated scratch directory with none of the source tree present, loaded it via `-d
extension=<full path>`, and re-ran a smoke check (`self_test`, `secretbox` round-trip) against that
standalone copy - proving the artifact itself is complete and self-contained, not proving anything
about a packaging format PHP's own ecosystem doesn't have.

## D-145: T-159 (PHP) step 5 - `cargo xtask php`, PHPUnit as a standalone PHAR (no Composer)

`cargo xtask php` mirrors `python()`/`nodejs()`/`ruby()` exactly: build `uacrypt --release` first
(real interop check inside `SecretstreamTest`), `cargo fmt --check`/`clippy --all-targets -D
warnings`/`cargo build` inside `bindings/php`, then run the PHPUnit suite against the freshly
built extension via `-d extension=<path>`.

**No Composer dependency added.** This binding has exactly one dev-time tool need (a test runner);
Composer would only exist here to install `phpunit/phpunit`, and PHPUnit itself already publishes
a standalone, dependency-free PHAR release (`phar.phpunit.de`) that runs via a bare `php
phpunit.phar` - adding a whole second PHP package manager just to fetch one tool would be the
premature-abstraction shape this project's own instincts warn against. `bindings/php/phpunit.phar`
is gitignored (fetched per-machine/CI: `curl -sL https://phar.phpunit.de/phpunit-11.phar -o
bindings/php/phpunit.phar`), matching how `rb_sys`'s own gem binary or `node_modules` are never
vendored either.

**`bootstrap.php`** requires the extension to already be loaded (checked via `extension_loaded()`,
a clear error otherwise) rather than trying to `dl()` it at runtime - PHP extensions load only at
SAPI startup (`-d extension=...`/`php.ini`), not on demand mid-script the way `require` works for
plain PHP files; `dl()` exists but is commonly disabled (`enable_dl=0`) and deprecated in practice.
The bootstrap's only real job is pulling in the pure-PHP wrapper layer (`lib/
DstuCoreSecretStream.php`, step 3) that isn't part of the compiled extension itself.

**PHPUnit itself needs `mbstring` (plus `ctype`/`dom`/`filter`/`json`/`libxml`/`tokenizer`/
`xmlwriter`), not bundled with this machine's raw PHP zip by default** - a real gap found running
PHPUnit for the first time, not predicted. Fixed locally via a `php.ini` (copied from the zip's own
`php.ini-development` template) enabling `mbstring` and pointing `extension_dir` at this machine's
actual install path (this exact PHP zip's own compiled-in default `extension_dir` is the
winget-conventional `C:\php\ext`, unrelated to wherever it's actually unzipped - `.claude.local.md`
has the full detail). CI's `shivammathur/setup-php` (below) configures a real install's `php.ini`
correctly out of the box, so this is a local-machine-only setup step, not something `cargo xtask
php` itself needs to special-case.

**macOS's own extension suffix is not yet confirmed on real CI.** `php_extension_path()` (in
`xtask/src/main.rs`) checks for `libdstu_core_php.so` first, falling back to `libdstu_core_php.dylib`
(Cargo's own `cdylib` default on macOS) - the Rust-PHP-extension ecosystem's own tooling (`cargo-php
install`) is documented to rename the build artifact to `.so` on macOS since PHP's own loader
conventionally expects that suffix there too, unlike a generic macOS shared library. This dev
machine is Windows-only, so this specific rename step is asserted from ecosystem convention, not
verified locally - `bindings-php.yml`'s own macOS leg (below) is the first real confirmation,
same "CI is the first real execution, not a second confirmation" posture this project's other
Windows-only-dev-machine findings already carry (D-109's Kani proof, D-133's Ruby toolchain notes).

### CI workflow (`bindings-php.yml`)

Uses `shivammathur/setup-php` (a well-established, widely-used community action) for the
Linux/macOS/Windows PHP install itself, rather than hand-rolling `windows.php.net`/apt/brew
downloads the way this machine's own local setup needed - it already configures `mbstring` and a
sane `php.ini` out of the box, sidestepping the exact gap found above. Toolchain axis is
**nightly-vs-stable and MSVC-vs-host-default, Windows-only** (re-derived from what this binding
actually needs, not copied from `bindings-ruby.yml`'s own GNU-vs-MSVC conditional, which solves a
different problem for a different binding): `dtolnay/rust-toolchain@nightly` with `toolchain:
nightly-x86_64-pc-windows-msvc` on Windows (matching this binding's own local `rustup override`,
D-142's "Windows toolchain requirements" section), plain `nightly` (host default, already MSVC on
GitHub's Windows runner and already GNU-compatible on Linux/macOS) elsewhere - `rust-lld` linker
config already committed in `bindings/php/.cargo/config.toml` needs no CI-specific handling.
`RUSTUP_TOOLCHAIN` is **not** set as a workaround here the way Ruby's CI needed (D-141) - that
gotcha was about a *committed* `rust-toolchain.toml` silently overriding `rustup default`; this
binding's own gotcha (D-146, immediately below) is about an *inherited environment variable* from
the outer `cargo xtask` invocation, which does not exist inside a CI job that never goes through
`cargo xtask` to reach `cargo build`/`clippy` directly.

## D-146: `xtask`'s own `run()` helper silently broke every binding-subdirectory `rustup override`
via inherited `RUSTUP_TOOLCHAIN` - found running `cargo xtask php` for the first time

The very first real `cargo xtask php` run failed with a genuinely confusing error: `ext-php-rs`'s
`wrapper.c` (a small C shim compiled via the `cc` crate) failed with dozens of header conflicts
(`__forceinline static` clashing with mingw's own declarations, an undefined `_InterlockedExchange8`
intrinsic, a `pid_t` redefinition) - the signature of PHP's MSVC-only devel-pack headers being
compiled by **`gcc.exe`**, not `cl.exe`. This was surprising because a direct, manual `cd
bindings/php && cargo build` (done repeatedly throughout steps 1-4 of this task) never reproduced
it - only `cargo xtask php`'s own invocation did.

Root-caused by reading how `cargo xtask` itself is invoked (`.cargo/config.toml`'s `xtask = "run
--manifest-path xtask/Cargo.toml --package xtask --"` alias): `cargo run` is itself resolved
through rustup's own `cargo` proxy shim, which sets `RUSTUP_TOOLCHAIN` as a real environment
variable in the process it execs (a well-documented rustup internal mechanism, not the bug itself)
- that variable then propagates, entirely ordinarily, into the compiled `xtask.exe` process's own
environment, and from there into *every child process `xtask` itself spawns* via
`Command::new(...).status()`, including the nested `cargo build`/`clippy` calls `python()`/
`nodejs()`/`ruby()`/`php()` all make with `current_dir` set to their own binding directory.
`RUSTUP_TOOLCHAIN`, per the same precedence rule this project's own `CLAUDE.md` already documents
for a committed `rust-toolchain.toml` (D-141: "`RUSTUP_TOOLCHAIN` overrides a toolchain file
outright, where `rustup default` does not"), overrides a directory-based `rustup override set`
mapping too, with the identical mechanism - so every nested `cargo build` inside `bindings/php`
silently ran under the *repo root's own* default toolchain (stable, GNU-host) instead of the
directory's pinned `nightly-x86_64-pc-windows-msvc` (D-142), with no error or warning that the
override was being ignored.

**This almost certainly affected `bindings/nodejs`'s own `cargo xtask nodejs` identically** (Node's
binding needs the exact same class of directory-scoped MSVC override, D-130) - not confirmed
broken here (Node's own build apparently tolerates a GNU-host compile better than `ext-php-rs`'s
raw-C-header wrapper does, or `cargo xtask nodejs` was simply never run end-to-end on this exact
machine before, only ever verified via a direct manual `cd bindings/nodejs && cargo build`), but
the root cause is identical and pre-existing, not something this task introduced. Not re-verified
against Node in this session (out of this task's own scope), flagged here so a future session
checks `cargo xtask nodejs` for real rather than assuming it was already covered.

**Fix**: `run()` (`xtask/src/main.rs`) now calls `.env_remove("RUSTUP_TOOLCHAIN")` on the child
`Command` whenever a `dir` is given - i.e., only for the binding-subcommand invocations that might
carry their own directory override, never for the top-level `build`/`test`/`clippy`/`fmt` calls
(which should keep using whatever the outer, already-correct toolchain resolved to). Confirmed
fixed empirically: `cargo xtask php` failed with the header-conflict error before this one-line
change and built + ran cleanly (58/58 PHPUnit tests) immediately after, no other change involved.

A second, smaller path bug found in the same debugging pass: `php_extension_path()`'s returned path
is prefixed with the binding directory (`bindings/php/target/debug/...`), but `run()`'s own `php`
invocation sets its *cwd* to that same directory - passing the prefixed path directly to `-d
extension=...` therefore resolved it a second time relative to `bindings/php`, doubling the prefix.
`Path::canonicalize()` was tried first and also rejected: it prepends Windows's `\\?\`
extended-length-path prefix, which this exact PHP build's library loader does not accept either (a
second real, confirmed failure). Fixed by prepending `env::current_dir()` manually instead, which
produces a plain absolute path with no `\\?\` prefix.

### Verification

`cargo xtask php` passes end-to-end on this dev machine: `cargo fmt --check`/`cargo clippy
--all-targets -D warnings` clean, `cargo build` succeeds (nightly-MSVC toolchain correctly
resolved after the D-146 fix), and the full PHPUnit suite (58 tests, 62 assertions, step 6 below)
passes with zero failures/errors/deprecations against the freshly built extension.

## D-147: `bindings-php.yml` confirmed green on real CI - three round-trips, none of them
predictable from this (Windows-only) dev machine alone

T-159's nine local steps (D-142-D-146) were all verified against a Windows-only dev machine; the
CI matrix (`ubuntu-latest`/`macos-latest`/`windows-latest`) was this workflow's first real
execution on any of the other two OSes, or on a genuine CI runner at all - per this project's own
standing rule, read the actual `gh run view`/job logs for each round rather than assume from the
fix alone. Two round-trips were needed after the initial push (run `30764356843`):

**Round 1** (run `30764775320`, 3 of 4 jobs fixed):
- `cargo-deny`: `ext-php-rs`'s own build-dependencies (`zip`/`ureq`, used only by its Windows
  build script to download the matching PHP devel pack - D-142) pull in four permissive licenses
  `deny.toml` didn't allow yet: `bzip2-1.0.6`, `CC0-1.0`, `MIT-0`, `CDLA-Permissive-2.0`, `Zlib`.
  Added to the allow list, re-confirmed locally with `cargo deny check` before pushing.
- `macos-latest` `cargo build`: failed linking on undefined Zend API symbols
  (`zend_ce_value_error`, `zend_throw_error`, ...) - symbols that only exist inside the `php`
  executable this `cdylib` gets `dlopen`'d into, never resolvable at link time. Linux's ELF `.so`
  tolerates undefined symbols by default (why `ubuntu-latest` was unaffected building the identical
  crate); macOS's Mach-O linker resolves everything at link time unless told otherwise - a standard
  gotcha for any Rust cdylib meant to be loaded as a plugin into a host process on macOS, not
  specific to `ext-php-rs`. Fixed with `-Wl,-undefined,dynamic_lookup` via
  `bindings/php/.cargo/config.toml`'s `rustflags`, for both `apple-darwin` targets - genuinely
  unreachable from this Windows-only dev machine, first real confirmation on real Apple hardware
  (well, a GitHub-hosted one).
- `windows-latest` `cargo clippy`: `error[E0554]: #![feature] may not be used on the stable
  release channel`, despite the toolchain step requesting `nightly-x86_64-pc-windows-msvc` - the
  identical gotcha `bindings-ruby.yml`'s own round-3 fix already found and documented (D-141): this
  repo's root `rust-toolchain.toml` (bare `channel = "stable"`, no host triple) silently overrides
  `dtolnay/rust-toolchain`'s own `rustup default` on the Windows runner specifically. Fixed with an
  explicit `RUSTUP_TOOLCHAIN` env var on the `clippy`/`build` steps, Windows-only - the *workflow*
  version of the same fix D-146 just made inside `xtask` itself, needed independently since CI
  doesn't go through `xtask` for these two steps.

**Round 2** (run `30765006443`, the remaining job): `windows-latest`'s PHPUnit step still failed
after round 1's fixes, a *different* problem from the same job - `cargo build` succeeded, but `php
-d extension=<path> phpunit.phar` couldn't load the extension: "The specified module could not be
found" for a path that genuinely existed on disk. Root cause: `windows-latest`'s default shell is
`pwsh`, but the *previous* step (which computes `EXT_PATH`) explicitly runs under `shell: bash`
and builds the path with `$(pwd)` - producing a POSIX-style value (`/d/a/uacrypt/...`). Git Bash's
own MSYS layer auto-translates a POSIX-style path argument into a real Windows path before handing
it to a native, non-MSYS executable (why the *build* steps, all `shell: bash`, never hit this);
`pwsh` performs no such translation and passed the literal POSIX string straight to `php.exe`,
which is a native Windows binary and can't resolve it. Fixed by adding `shell: bash` to the final
`php -d extension=...` step too, so the same MSYS translation applies there as well.

**Confirmed green on real CI**, `gh run view 30765006443 --json conclusion,status,jobs`: all four
jobs (`build + test` on `ubuntu-latest`/`macos-latest`/`windows-latest`, `cargo deny / audit`)
report `success`. Three real CI round-trips total for this workflow (one push, two fix rounds) -
same order of magnitude as Ruby's own three-round history (D-140/D-141) - each one a genuine
finding a Windows-only local machine could never have caught by construction (a macOS linker
default, a cross-OS license graph, and a shell/path-translation mismatch specific to the hosted
Windows runner's default shell).

## D-148: T-158 (C ABI crate) - design forks resolved before implementation

Settled 2026-08-03 via `advisor()` review before writing any code, following this project's own
"settle the fork, cite it, then implement" discipline (same posture as D-142's `Binary<u8>` finding
for PHP). Four forks, none with a DSTU citation to resolve them (this crate is pure ergonomics over
already-implemented primitives, D-47's tie-breaker doesn't even apply - there's no algorithm choice
here, only a C-API shape choice):

1. **Symbol prefix is `dstu_`, not `dstu_core_`** - already fixed by `selftest.rs`'s own module doc
   ("`dstu_selftest()` in the C ABI") and `docs/bindings-strategy.md`, not re-derived here. Every
   exported function/type/constant in `crates/dstu-core-capi` uses this prefix
   (`DstuStatus`/`DstuAuthKey`/`dstu_secretbox_seal`/...), deliberately different from PHP's
   `dstu_core_*` (PHP's own naming follows `ext-sodium`'s convention instead, D-142 - the two
   bindings had independent reasons to land on different prefixes, not an inconsistency).

2. **`cbindgen` is invoked via `cargo xtask capi`, never added as a `[build-dependencies]` entry.**
   The MSRV job (`cargo +1.87.0 build --workspace --all-features`, `rust.yml` line 190) now covers
   `dstu-core-capi` for free once it's a workspace member (D-119 already confirmed capi *is* a real
   member, unlike Python/Node/Ruby/PHP) - a build-dependency on `cbindgen` would drag cbindgen's own
   MSRV floor into that job for no reason `dstu-core-capi` itself needs. The generated header
   (`crates/dstu-core-capi/include/dstu_core.h`) is committed, with a `cargo xtask capi` step that
   regenerates it into a temp path and diffs against the committed copy (same drift-detection shape
   T-120/D-75 already uses for the Python README-vs-doctest check) - `dstu-core-capi` itself carries
   zero non-dev dependencies beyond `dstu-core`, matching `uacrypt`'s own zero-dependency posture.

3. **Output-buffer convention: caller-allocates, library never allocates or frees a Rust-owned
   buffer C could free with `free()`.** A Rust `Vec<u8>` handed to C and freed with libc `free()` is
   immediate UB (different allocators) - the one convention that avoids this entirely (ruled out:
   library-allocates + a `dstu_free`, and a two-call length-query pattern, both add a cross-language
   allocator-lifetime hazard or an extra round trip for no real benefit here). Matches libsodium's
   own `crypto_secretbox_easy` shape exactly: the caller supplies an output buffer sized
   `input_len + DSTU_*_OVERHEAD` (a named constant per variable-length construction -
   `DSTU_SECRETBOX_OVERHEAD` = 48 = 32-byte nonce + 16-byte tag, `DSTU_STREAM_OVERHEAD` = 32 = IV
   only, unauthenticated), plus an explicit `_cap` parameter checked against the actual required
   length before writing (`DSTU_ERR_BUFFER_TOO_SMALL` if too small) - a stricter check than
   libsodium itself does (which only documents the required size and trusts the caller), chosen
   because "provable from the line itself, not by hand-traced caller discipline" is this project's
   own standing bar (`CLAUDE.md`'s bounds-safety rule), not just a libsodium-parity choice.
   `crypto_pwhash`'s PHC string gets a fixed `DSTU_PWHASH_STRBYTES = 128` buffer instead (matches
   libsodium's own `crypto_pwhash_STRBYTES` numeric value exactly, confirmed by hand-counting the
   longest string this crate's own `Strength::Sensitive` preset can produce: `$argon2id$v=19$
   m=1048576,t=4,p=1$` (34 bytes) + 22-byte unpadded-base64 16-byte salt + `$` + 43-byte
   unpadded-base64 32-byte hash + NUL ≈ 102 bytes, comfortably inside 128). Fixed-size outputs
   (auth tags, KDF subkeys, signatures, hashes) need no convention at all - a caller-supplied
   fixed-size array is already exact.

4. **`dstu-core-capi`'s own `Cargo.toml` depends on `dstu-core` with `std`/`selftest`/`pwhash` all
   unconditionally on** (no `default-features = false`), matching `crates/uacrypt/Cargo.toml`'s own
   existing dependency line exactly - `catch_unwind` (needed at every `extern "C"` boundary per
   item 5 below) only exists in `std`, not `core`, so there is no genuine no_std path for this crate
   to preserve regardless. **Found while checking this against `docs/bindings-strategy.md`'s own
   T-158 instruction to "verify the existing 8-combination feature matrix still passes with this
   new workspace member present" (D-119's own cited reason capi must stay a real workspace
   member):** `cargo tree --workspace --no-default-features -f "{p} {f}"`, run *before* touching
   anything, already shows `dstu-core default,getrandom,std` - `crates/uacrypt/Cargo.toml`'s own
   `dstu-core = { path = "../dstu-core", version = "0.2.0" }` line (no `default-features = false`)
   already unifies `std` back on for every `--workspace` build via Cargo's additive feature
   unification, the exact mechanism this project's own agent-discipline notes already document for
   other crates (see the `argon2`/`rand_core` entry above). This means `rust.yml`'s `cargo build
   --workspace --no-default-features` (line 41) and `xtask`'s `build()` (`--workspace
   --no-default-features` step) have **not been proving a genuine no_std `dstu-core` build since
   `uacrypt` was added to the workspace** - confirmed pre-existing, not introduced by
   `dstu-core-capi`'s own addition (which needs `std` for the identical reason `uacrypt` does, and
   changes nothing about what was already true). Recorded here as an honest finding, not silently
   fixed as a drive-by: the actual no_std proof for `dstu-core` alone lives in `xtask`'s already-
   existing `-p dstu-core --no-default-features --features getrandom` step (scoped to the crate,
   not the workspace) - genuinely correct today, unaffected by this. Fixing the workspace-level
   lines to also scope to `-p dstu-core` is a separate, small, pre-existing-debt cleanup, out of
   scope for T-158 itself; left as a follow-up rather than expanding this task's diff.

5. **`unsafe` boundary hygiene, applied uniformly across every exported function** (not per-module
   judgment calls): `catch_unwind(AssertUnwindSafe(|| ...))` wraps every function body (an unwind
   crossing an `extern "C"` boundary aborts the process outright since Rust 1.81, so this is what
   converts an internal panic into `DSTU_ERR_PANIC` instead of taking the caller's whole process
   down with it); every raw pointer with an accompanying `len` branches to `&[]` for `len == 0`
   before ever calling `slice::from_raw_parts` (a null pointer with a nonzero declared length is
   rejected as `DSTU_ERR_NULL_POINTER`, `from_raw_parts(null, 0)` is itself UB regardless of the
   pointer's non-null-ness the C side happens to pass); in/out buffer pairs are documented
   non-overlapping (constructing a `&[u8]` and a `&mut [u8]` over the same bytes is UB even if
   nothing ever reads through the shared region); every opaque handle is `Box::into_raw`/
   `Box::from_raw`, so `dstu_*_free` is exactly `drop(Box::from_raw(ptr))` and the existing
   `Zeroize`-on-`Drop` impls (`SecretKey`/`Key`/`MasterKey`/`SigningKey`/`PushState`/`PullState`,
   all already `Drop`-wired in the wrapped `crypto_*` modules) fire for free, no separate zeroize
   call needed in the C-ABI layer itself. One real gap those `Drop` impls can't reach:
   `SigningKey::to_bytes()`/`Kupyna*Hasher`-style calls that copy secret bytes *out* into a
   caller-owned buffer leave that copy for the caller to wipe - `dstu_memzero(void *buf, size_t
   len)` (libsodium's `sodium_memzero` equivalent) is exported for exactly this, documented in the
   header comment next to every function that copies secret material outward.

6. **`crates/dstu-core-capi/Cargo.toml`'s `crate-type` includes `rlib` alongside `cdylib`/
   `staticlib`** (a small addition beyond what a "just ship a C library" crate strictly needs) so
   this crate's own `tests/` integration suite can call its `extern "C"` functions directly as a
   normal Rust dependency, rather than needing a separate C toolchain invocation just to exercise
   the FFI boundary. This is deliberate: `dstu-core-capi` has no external interpreter/runtime linked
   at build time (D-119's own distinguishing test for capi vs. Python/Node/Ruby/PHP), so it lands
   inside `cargo +nightly miri test --workspace` for free the moment it's a workspace member -
   writing the boundary tests (null pointers, zero-length slices, undersized output buffers,
   tamper/misuse cases) as ordinary `#[test]` functions against the `rlib` gets every one of them
   Miri-checked for aliasing/UB on every push, the highest-value correctness layer available for an
   `unsafe`-heavy crate like this one, at near-zero extra cost. The separate plain-C test harness
   (step 5 of the renumbered template) still exists on top of this - it proves the *generated
   header* and a real C compiler round-trip actually work, which a same-process Rust test cannot.

Full API surface (every exported function/type/constant) is specified in the implementation
itself, not duplicated here - `crates/dstu-core-capi/include/dstu_core.h` is the source of truth
once generated, cross-checked module-by-module against `crates/dstu-core/src/crypto_*.rs` and
`randombytes.rs`/`selftest.rs`.

## D-149: T-158 (C ABI crate) done in full - implementation, xtask/CI wiring, three findings beyond D-148

Implemented 2026-08-03, following D-148's six settled forks exactly (not re-derived). Full surface
(every function/type/constant D-148's own spec listed) built in `crates/dstu-core-capi`: `error.rs`
(`DstuStatus`), `util.rs` (`catch_unwind` guards, null/zero-length slice helpers, `dstu_memzero`),
`randombytes.rs`, `selftest.rs`, `auth.rs`, `kdf.rs`, `generichash.rs`, `secretbox.rs`,
`secretstream.rs`, `sign.rs`, `stream.rs`, `pwhash.rs`. All 17 Rust-side FFI tests
(`tests/ffi_tests.rs`, D-148 point 6's `rlib` rationale) and the plain-C harness
(`c-tests/test_capi.c`) pass; `cargo build/test/clippy/fmt --workspace --all-features` (and
`--no-default-features`) all clean; `cargo xtask capi` (new subcommand, see below) passes
end-to-end on this dev machine.

Three implementation-time findings not anticipated by D-148, each resolved rather than left
ambiguous:

1. **cbindgen config (`cbindgen.toml`)**: `usize_is_size_t = true` - without it, cbindgen's default
   maps Rust `usize`/`isize` to `uintptr_t`/`intptr_t` (technically precise, pointer-width-
   guaranteed) rather than `size_t`/`ptrdiff_t`, the idiomatic C type for a byte count/buffer
   length D-148's own spec pseudocode used throughout (`size_t len`). `cpp_compat = true` so the
   header also works included from C++ (`extern "C" { ... }` guarded by `#ifdef __cplusplus`) -
   free forward-compatibility for T-53 (C++), not exercised by this task itself. Fixed-size
   "array" parameters in D-148's own spec pseudocode (`uint8_t key[32]`) render as plain
   `const uint8_t *key` in the generated header, not literal C array syntax - functionally
   identical (a C array parameter decays to a pointer regardless), and cbindgen has no built-in
   mechanism to preserve array-parameter syntax for a Rust `*const u8` signature; every such
   parameter's doc comment states its exact required length instead. Opaque handles needed no
   extra `cbindgen.toml` configuration at all: a plain (non-`repr(C)`) Rust struct only ever
   referenced by pointer is cbindgen's own default "declare but don't define" behavior, confirmed
   by inspecting the generated header rather than assumed.
2. **Windows C-compiler dispatch: GNU (this dev machine's own actual default) vs. MSVC (D-148's
   own assumed CI environment), not anticipated as a fork at all until hit.** `cargo build -p
   dstu-core-capi --release` on this machine produced `libdstu_core_capi.a`/`libdstu_core_capi.dll.a`
   (GNU/MinGW static-lib and import-lib naming) rather than the `dstu_core_capi.lib`/
   `dstu_core_capi.dll.lib` (MSVC) D-148's own file-layout note assumed without stating the
   distinction explicitly - confirmed via `rustc -vV` (`host: x86_64-pc-windows-gnu`) and
   `README.md`'s own pre-existing "this project builds against the GNU host toolchain on Windows by
   default" line (a fact this task's own instructions didn't cross-reference). `xtask`'s new
   `capi()` therefore dispatches on `cfg!(target_env = "msvc")` (xtask's own compiled-in host
   triple, reliable since xtask is always built with the same toolchain as the rest of the
   workspace - not a runtime OS query) - `gcc`/`cc` (Windows-GNU/Linux/macOS, one shared code path,
   `capi_compile_unixlike`) linking against the cdylib's import library (`-ldstu_core_capi`,
   avoiding re-declaring Rust std's own transitive Windows-syscall dependencies at the C link step
   the way linking the true staticlib would require), versus `cl.exe` via `vcvars64.bat`
   (`capi_compile_msvc`, mirroring `fuzz_windows_msvc`'s own sourcing pattern) for a real MSVC host.
   Both branches must compile unconditionally regardless of the host platform xtask itself runs
   on (the `if`/`else` choosing between them is a runtime check, not a `#[cfg]` one) - `
   capi_compile_msvc` therefore has a `#[cfg(not(windows))] -> unreachable!()` twin so the
   Windows-only body (`std::os::windows::process::CommandExt::raw_arg`) never needs to compile on
   Linux/macOS. **The `rust.yml` `capi` job deliberately does not add `ilammy/msvc-dev-cmd`** -
   `capi_compile_msvc` already finds and sources `vcvars64.bat` itself per invocation (`vswhere.exe`
   is present on GitHub-hosted Windows runners), so a separate environment-setup action would only
   duplicate what `cargo xtask capi` already does on its own; confirmed by this exact code path
   already working locally against this machine's own GNU toolchain, the two branches sharing
   nothing but the `if` that selects between them.
3. **Prebuilt-libs packaging (step 4) deferred, not attempted this session** - `release.yml`
   cross-OS packaging (mirroring `build-binary`'s per-OS matrix) is real, separate work, and this
   session's own time budget went to steps 1-3/5-7 (the ones that block every later consumer -
   T-52/.NET, T-163/Go, T-53/C++ - from starting at all) rather than a packaging step none of them
   need yet. Local build only for now, confirmed working (see finding 2's exact filenames).

**CI status**: `capi` job added to `rust.yml` (matrix ubuntu-latest/macos-latest/windows-latest),
mirroring `bindings-php.yml`'s own MSVC-Windows-toolchain reasoning but folded into `rust.yml`
itself (D-119's own distinction: this crate is a real workspace member, not a separate Cargo
workspace the way Python/Node/Ruby/PHP are, so it doesn't need its own top-level workflow file).
**Not yet confirmed green on real CI** - only verified locally against this dev machine's own
GNU-hosted Windows toolchain (the `test`/`msrv`/`miri` jobs' existing `--workspace` coverage already
proves the Rust side; the new `capi` job's Linux/macOS legs and the MSVC branch of its Windows leg
are unverified until a real push, the same caveat every prior binding's first CI round-trip
carried, T-140/D-140-141/D-146-147's own precedent for "verify on real CI before calling a workflow
file done").

## D-150: T-158 - four fixes from advisor review before declaring the crate done

Found via `advisor()` review after D-149's implementation was already committed, before declaring
T-158 done - all four addressed in the same session, not deferred:

1. **Header-drift check (`xtask`'s `capi_header_up_to_date`) would have false-failed on a real
   Windows/macOS CI checkout.** The comparison was byte-for-byte against the *committed* file as
   read from this dev machine's own working tree - correct here, but a Windows/macOS CI runner's
   `actions/checkout` applies git's `core.autocrlf` translation to that same committed file
   (LF-stored, checked out as CRLF), while `cbindgen` always writes LF (confirmed in its own
   source, `LineEndingStyle::default() == LF`, not OS-dependent) - the same false-positive
   `rust.yml`'s own `fmt` job already documents for a different check. Fixed by normalizing both
   sides (`.replace("\r\n", "\n")`) before comparing, verified by actually reproducing the failure
   locally: converting the committed header to CRLF and re-running `cargo xtask capi` no longer
   reports drift. `cbindgen.toml` also now sets `line_endings = "LF"` explicitly (redundant with
   cbindgen's own default today, but pins the assumption the normalization fix's comment states -
   only the committed side needs normalizing - against a future cbindgen version changing that
   default).
2. **`dstu_auth_verify`'s NULL-handling was an undocumented, inconsistent divergence from this
   crate's own stated convention.** It returned `DSTU_ERR_TAG_MISMATCH` for a NULL `key`/`tag`
   rather than `DSTU_ERR_NULL_POINTER`, even though a `DstuStatus` channel exists here (unlike the
   bare-`bool` `dstu_verify`/`dstu_verify_digest`, where folding NULL into `false` is the only
   option) - `lib.rs`'s own doc comment states the opposite rule ("a NULL pointer for any required
   argument is rejected with `DSTU_ERR_NULL_POINTER` ... wherever a `DstuStatus` channel exists").
   Fixed to return `DSTU_ERR_NULL_POINTER`, header regenerated; no existing test asserted the old
   behavior, so nothing else needed to change.
3. **The C test harness had no known-answer vector**, despite `docs/bindings-strategy.md` step 5's
   own text ("official vectors, rejection, misuse") and this task's own instructions naming exactly
   this ("a real Kupyna-256 vector via `dstu_generichash_256`"). `dstu_selftest()` proves the
   underlying Rust primitive is correct but not that the C ABI's own byte plumbing (pointer/length
   handling in, buffer copy out) preserves it. Added `test_generichash_official_vector` to
   `c-tests/test_capi.c`, transcribing the single-byte (`0xFF`) case from
   `crates/dstu-core/tests/vectors/kupyna/kupyna-256.json` (itself cited to
   `docs/papers/Kupyna.pdf` Appendix B.2) directly as a C byte array - not copied from this
   session's own tool output (which would be circular).
4. **A `ffi_tests.rs` misuse assertion proved nothing about what its own name/comment claimed.**
   `secretstream_round_trip_tamper_and_finalize_rejection`'s "misuse: length mismatch" block ran
   against an already-finalized `PushState`, so it only ever exercised `DSTU_ERR_FINALIZED` (the
   finalized-check's priority over the length check) - a real instance of the D-21/D-25 pattern
   this project's own agent-discipline notes already warn about ("check what a fixed vector
   actually exercises, not just whether it passes"). Fixed by moving the wrong-length `push` call
   before the stream is finalized, so it now genuinely asserts `DSTU_ERR_INVALID_LENGTH`; the same
   gap existed in `c-tests/test_capi.c` (no `DSTU_ERR_INVALID_LENGTH` coverage at all), fixed the
   same way there.

Not fixed, flagged as CI risk instead (verifiable only on real CI, this machine being
Windows-GNU-only): the MSVC branch's `dstu_core_capi.dll.lib` import-library name (`D-149`'s own
finding 2 documents the GNU-vs-MSVC naming split but the MSVC path itself is unverified locally),
and whether `-Wl,-rpath` actually resolves `libdstu_core_capi.dylib` on macOS given rustc's default
bare-filename (not `@rpath`-prefixed) `install_name` for a cdylib there - the copy-next-to-exe step
in `capi_run_c_program` is the more likely reason it works, not the rpath flag, but this is
unverified without a real macOS runner.

## D-151: every binding + the C ABI crate re-checked on real aarch64 hardware (Raspberry Pi) - one genuine bug found

2026-08-03, user-requested extension of `docs/TASKS.md` T-35's existing "no CPU-family lock-in"
Pi re-check to cover the language bindings and T-158's C ABI crate for the first time - none of
that surface had ever been built on non-x86 hardware before. Full detail (toolchain-install steps,
per-binding pass/fail, exact commands) lives in T-35's own `docs/TASKS.md` entry and
`.claude.local.md`'s Pi section, not duplicated here; this entry records the one finding worth a
permanent citation and the process lesson.

**The finding**: `crates/dstu-core-capi/tests/ffi_tests.rs`'s `pwhash` test declared
`let mut out = [0i8; DSTU_PWHASH_STRBYTES]` for a buffer the production API (`pwhash.rs`) already
correctly types as `*mut c_char`. `c_char`'s signedness is platform-ABI-defined, not fixed by the
C standard - x86-64 Linux/Windows/macOS (every platform this project had built on before this
session) all define it as `i8`, so the hardcoded `i8` literal happened to match by coincidence on
every one of them. ARM Linux's own ABI makes plain `char` **unsigned by default**, so `c_char`
resolves to `u8` there - the test failed to *compile* the instant it hit real aarch64 hardware
(not a runtime bug, a type-checked compile error, `cargo build --workspace` on the Pi). Fixed by
using `std::os::raw::c_char` explicitly instead of a hardcoded signed integer type - the production
code never had this bug, only the test did, but an uncompilable test is exactly as blocking as a
wrong one. This is the T-158-era instance of the same class of thing `docs/TASKS.md` T-35 already
exists to catch (an x86-64-only dev machine cannot see a char-signedness, endianness, or word-size
assumption by construction) - previously caught for `hazmat` internals (Kalyna/Kupyna/Strumok),
this is the first time it caught something in a binding's own FFI-boundary code instead.

**Process lesson, not a project bug**: running two binding checks concurrently over separate SSH
sessions (`cargo xtask python` and `cargo xtask ruby` at the same time) raced on the Pi's shared
`~/.rustup` component-download cache and broke both (a `rust-src` partial-download file-rename
collision) - re-running them sequentially instead was the fix, not a code or CI change. Recorded so
a future Pi session doesn't re-lose time rediscovering this.

**Standing rule, added to `docs/bindings-strategy.md`'s "standard binding steps"**: every future
binding (T-52/.NET, T-51/Java, T-163/Go, T-53/C++) includes this same Pi ARM64 re-check as one of
its own numbered steps, not a separate ad hoc pass done only when someone happens to ask. **Result
this pass**: Python 57/57, Node.js 52/52, Ruby 58/58 (+ rubocop clean), PHP 58 tests/62 assertions,
and the C ABI crate's own header-drift check/C harness/all 4 examples - all green on real aarch64
Linux (Debian 12/bookworm) once the fix above and the toolchain installs in `.claude.local.md`
landed.

## D-152: T-52 (.NET binding) - P/Invoke marshalling findings, SafeHandle, packaging split

2026-08-03. `bindings/dotnet/DstuCore` wraps `crates/dstu-core-capi` (T-158) via P/Invoke -
the first binding in this project with no Cargo workspace of its own at all (Python/Node/Ruby/PHP
each wrap the Rust crate directly and are therefore their own `[workspace]`, D-119; .NET has
nothing to build on the Rust side beyond the already-built C ABI crate).

**Two P/Invoke marshalling defaults that would have been silently wrong, found by advisor review
before implementation, not after a failing test**: (1) C#'s default marshalling for a `bool`
P/Invoke return is the 4-byte Win32 `BOOL`; Rust's `extern "C" fn() -> bool` is one byte. Affects
`dstu_verify`/`dstu_verify_digest`/`dstu_pwhash_verify_password`/
`dstu_secretstream_{push,pull}_is_finalized` - a wrong `true` out of `dstu_verify` specifically
would have been a silent signature-verification bypass, not a test failure (the .NET analogue of
D-151's ARM `c_char`/`i8` finding). Fixed by using `[LibraryImport]` (source-generated interop, not
classic `DllImport`) throughout, which makes omitting `[return: MarshalAs(UnmanagedType.U1)]` a
**compile error** rather than a silently-wrong default - a stronger guarantee than a runtime test
could give, since it can't regress on a future edit that forgets the attribute. (2) every `size_t`
parameter/out-param is `nuint`, never `int`/`uint` - the header is built with
`usize_is_size_t = true`, and a 32-bit type would leave the upper half of a 64-bit slot undefined
on any 64-bit target.

**Every opaque `dstu_*` handle is a `SafeHandle` subclass** (`bindings/dotnet/DstuCore/Native/
NativeHandles.cs`), not a bare `IntPtr` - the CLR's own P/Invoke marshaller then keeps the handle
alive for the duration of each native call and guarantees the matching `dstu_*_free` runs exactly
once, even on an exception/finalizer path. This is the .NET-idiomatic form of
`cross-language-style-guide.md` principle 5 ("resources are released deterministically") - the
same role `IDisposable`/`using` already plays for every other resource in this binding, and gives a
free `ObjectDisposedException` if a caller tries to use an already-disposed key instead of
undefined behavior.

**`SecretStreamEncryptStream`/`DecryptStream` (`SecretStream.cs`) apply D-118's two pitfalls in
their C# form, with one deliberate deviation from `CryptoStream`/`GZipStream`'s own convention**:
`Dispose()` never emits a `Final` chunk. Python's `__exit__(exc_type, exc_value, traceback)` can
check whether it's unwinding from an exception and only skip finalization on that path (auto-
finalizing on a clean `with` exit); C#'s `Dispose()` takes no such parameter and has no way to
distinguish the two cases (same structural limitation C++ RAII destructors have, per
`bindings-strategy.md`'s own template text) - so finalization here is an explicit `Complete()` call
required on every success path, `Dispose()` alone only ever frees the native handle. A stream
disposed without `Complete()` is therefore always left without a `Final` chunk, by construction,
not just on the exception path - stronger than the Python guarantee, not weaker, and documented
inline so this doesn't read as a bug to a future C# reader expecting `CryptoStream`'s close-flushes
habit. The second pitfall (bounding the untrusted wire `chunkLen` field against
`DstuConstants.SecretstreamChunkBytes`, rejecting trailing bytes after `Final`) ports directly,
same as every other binding.

**Test-first landed together with the wrapper for this binding** (like Node/PHP, not split across
sessions like Python's original T-49) - `DstuCore.Tests` (xUnit) mirrors `bindings/python/tests`
file-for-file, 56 tests, all green against the real built `dstu_core_capi.dll` and a real
bidirectional `uacrypt.exe` interop round trip on the first full run. DSTU 4145 category-1
correctness is exercised via `Selftest.Run()` rather than re-deriving the Annex B.1 vector's own
hash-to-field convention per binding - matching `bindings/python/tests/test_sign.py`'s own stated
precedent, not a new shortcut invented here.

**Packaging (step 4) split the same way T-158's own step 4 did (D-149)**: `dotnet pack` produces a
real `DstuCore.0.1.0.nupkg` with `runtimes/win-x64/native/dstu_core_capi.dll` (this dev machine's
own RID; cross-OS RIDs are a `release.yml` job, not built here) via a `None`/`PackagePath` item in
`DstuCore.csproj`, gated behind `Exists()` checks per platform so the same project file works
un-modified on Linux/macOS CI once cross-compiled there. **Verified with a real fresh-install
check** (Python's/Node's own step-4 bar): packed into `bindings/dotnet/local-nuget-feed/` (a
gitignored local feed, not committed), installed via `dotnet add package --source
<local-feed>` into an unrelated temp console project, and `Selftest.Run()` + a `SecretboxKey`
round trip both ran successfully against the installed package - not the source tree - confirming
.NET's own native-library assembly-directory probing finds the packaged asset with zero extra
config on the consumer's side (no explicit `<RuntimeIdentifier>` needed). This one-time check is
not re-run by `cargo xtask dotnet` on every invocation (same posture `capi()`'s own step 4 already
established) - `bindings-dotnet.yml`'s CI job sanity-checks the `dotnet pack` step itself on every
push instead, catching a broken packaging *recipe* without re-doing the full fresh-install
round trip each time.

**Step 10 (Raspberry Pi ARM64 re-check, D-151's template) done the same day**: the Pi had no .NET
SDK at all before this - installed via Microsoft's official `dotnet-install.sh --channel 8.0`
(Debian isn't on `packages.microsoft.com`'s officially-supported apt-feed OS list the way Ubuntu is,
so the script-based install is the documented path, not a workaround). All 56 tests passed on the
first real aarch64 run, no bug found this time - unlike D-151's `c_char`/`i8` finding in the C ABI
crate's own test, this is genuine evidence that `[LibraryImport]`'s blittable marshalling for
`nuint`/`SafeHandle`/`byte[]` and the explicit `[MarshalAs(UnmanagedType.U1)]` `bool` attributes are
actually architecture-portable, not just correct by x86-64 coincidence.

## D-153: T-51 (Java) step 0 spike - `jni` crate wins over JNI-over-T-158, real prototypes built both ways

2026-08-03. `docs/bindings-strategy.md`'s Fork 1 left Java's shape genuinely open (unlike .NET/C++/
Go, which route through the C ABI crate purely because no direct-Rust-binding tool for those
languages has PyO3/napi-rs/magnus's maturity) - Java has such a tool (`jni` crate), so the fork had
to actually be spiked, not decided by analogy. Two real, runnable prototypes were built rather than
reasoned from memory, per this project's own "spike and read the actual output" discipline (the
same one that reversed two planned `hazmat` rewrites, T-139/T-129):

- **Spike A**: `jni = "0.21"` crate, Rust exposing `Java_SpikeA_*` symbols directly against
  `dstu_core`'s own Rust API (no C ABI crate involved at all) - a `cdylib` calling
  `dstu_core::selftest::run()` and `crypto_secretbox::{seal,open}`, loaded via
  `System.loadLibrary` from a plain `javac`-compiled class.
- **Spike B**: a hand-written `spike_b.c` JNI shim (`#include <jni.h>` + `dstu_core.h`) calling
  `dstu_selftest()` through the already-built T-158 C ABI crate (`libdstu_core_capi.dll.a`,
  mingw-compatible import lib), compiled with `gcc -shared`, loaded the same way.

Both worked end to end on the first real run (`selfTest()` returned `true` in both). The deciding
evidence wasn't "does it work" but what each path costs beyond that:

- **Spike B adds a third language to the binding** (C, on top of Rust-in-capi and Java) that no
  other direct-Rust binding (Python/Node/Ruby) needs, and it needs a real C compiler on every
  developer machine and CI runner *for the Java binding specifically*, not just for building capi
  itself. It also means **two native artifacts to package per platform** instead of one (the capi
  `.dll`/`.so`/`.dylib` *and* the compiled JNI shim) - working directly against the opposite of
  T-158's own point, which was to centralize the native surface for the C-ABI-consuming bindings,
  not multiply it.
- **Spike A avoids the C ABI's caller-allocated-out-buffer protocol entirely**
  (`dstu_secretbox_seal(key, msg, len, out, out_cap, out_len*)`) - binding against `dstu_core`'s
  native Rust API means a function just returns `Vec<u8>`, marshalled to a `jbyteArray` by the `jni`
  crate's own `byte_array_from_slice`. This is the exact same reason Python/Node/Ruby went direct
  instead of through capi, not a new argument invented for Java.
- Spike A was extended one step further (per advisor review) beyond the trivial nullary `selfTest`
  call: a real `byte[]`-in/`byte[]`-out round trip (`crypto_secretbox` seal/open) plus a genuine
  failure path (open with the wrong key), confirming `env.convert_byte_array`/
  `env.byte_array_from_slice`/`env.throw_new` all work as expected before committing to the shape -
  not just the easiest possible signature.

**Decision: Java joins Python/Node/Ruby/PHP's direct-binding group (via the `jni` crate), not the
.NET/C++/Go C-ABI group.** `bindings/java` will be its own `[workspace]` (D-119), same as Python/
Node/Ruby, wrapping `dstu_core` directly - not a consumer of `crates/dstu-core-capi`.

**Panama (JDK 22's Foreign Function & Memory API, JEP 454) was considered and rejected, not just
unspiked**: FFM-over-T-158 would need zero native glue at all, structurally identical to T-52's
P/Invoke shape. Rejected because a JDK 22+ baseline is too new for this binding's target audience
(enterprise/Bouncy-Castle-adjacent Java shops skew toward LTS releases, not the latest feature
release) - not evaluated further, but named here so a future reader doesn't wonder why it's absent.

**`jni` is pinned to `0.21`, not the newer `0.22.4`, as a deliberate choice, not a stale default**:
tried bumping the spike to `0.22` and it does not compile unchanged - `0.22` redesigned `JNIEnv`
ownership (an `extern "system" fn(JNIEnv, ...)` parameter now resolves to `EnvUnowned`, which lacks
`convert_byte_array`/`byte_array_from_slice`/`throw_new` entirely; a different attach/borrow pattern
is required). Staying on `0.21`'s stable, already-proven-out API avoids taking on that migration
before the real binding exists. Re-evaluate the `0.22` API once the binding is built and stable, not
mid-spike.

**JDK baseline: build/test on 17, but target bytecode 8 for the published artifact** - this dev
machine's only prior JDK was Oracle 1.8.0_211 (2019); installed Eclipse Temurin 17 LTS locally
(`winget install --id EclipseAdoptium.Temurin.17.JDK`) to match the Pi's Debian 12 apt-default
version, for step 10 parity. Spike A was re-verified compiling/running under 17 (`javac --release
17`) with no behavior difference from the original Java 8 run. **Owner-requested correction, same
day**: Java 8 still has genuine real-world footprint (legacy enterprise/PKI-adjacent shops, the
exact audience this binding's Bouncy-Castle-incumbent framing already targets - Fork 1) and
shouldn't be dropped just because the dev/CI machine defaults moved on - matches this project's own
"no CPU-family lock-in" instinct applied to JVM-version lock-in instead. **Verified empirically, not
assumed**: cross-compiled Spike A with `javac --release 8` (run from the JDK 17 install - `--release
8` is supported cross-targeting, not a same-JDK requirement) and ran the resulting class file
directly on the real local JDK 8 JVM - `selfTest`/`sealOpenRoundTrip`/the wrong-key exception path
all passed unchanged. **Resolution for the real binding**: the POM sets
`<maven.compiler.release>8</maven.compiler.release>` for the published API's bytecode target (JNI's
own C ABI is unaffected by JVM version either way - only the pure-Java wrapper class's bytecode
level matters for a consumer's JVM compatibility), while the build/test toolchain itself stays on a
modern JDK (17, matching the Pi) via Maven's cross-release compilation - not two separate JDKs
juggled by hand. CI should matrix at least JDK 8 and 17 for the test suite specifically (not just
building on 17 and assuming the 8-target bytecode behaves identically) - record this in step 5's
CI wiring, don't discover the gap after the fact.

**D-118's Java pitfall carries over unchanged from T-52's own resolution**: try-with-resources'
`close()` cannot see whether the block exited via exception or normally, the same structural
limitation as C#'s parameterless `Dispose()` (T-52/D-152) - the real `SecretStream` wrapper needs
the same explicit `complete()`-not-`close()` finalization split, not a fresh re-derivation.

Spike code lived in the session scratchpad only, not committed - the real `bindings/java` scaffold
starts fresh in step 1, following this decision.

**T-51 built in full the same day, steps 1-9 (step 10, the Raspberry Pi re-check, follows
separately per D-151's template)** - `bindings/java/native` (own `[workspace]`, D-119, split into
its own subdirectory rather than living at `bindings/java` directly since a root-level `Cargo.toml`
there would collide with Maven's own `src/main/java` layout) plus `bindings/java`'s Maven project
wrapping it. Full `crypto_*` surface (`Auth`/`Kdf`/`GenericHash`+`Kupyna{256,512}Hasher`/`Pwhash`/
`RandomBytes`/`SecretBox`/`StreamCipher`/`Sign`/`SecretStream`+`SecretStreamPushState`/
`PullState`/`SecretStreamEncryptor`/`Decryptor`/`Selftest`), 56 JUnit 5 tests (correctness/
rejection/misuse per D-64/D-65, including a real bidirectional `uacrypt` CLI interop test and a
chunk-boundary-size `@ParameterizedTest`), 5 runnable examples, `cargo xtask java`, a new
`bindings-java.yml` CI workflow, and this README - matching every other completed binding's own
final state, one commit per step.

**Package/class/method names deliberately avoid underscores anywhere** (`ua.dstucrypto.dstucore`,
`SecretBox`, `hashPassword`, etc.) - JNI encodes a literal `_` in a package/class/method name as
`_1` in the generated `Java_...` symbol, and mixing that escaping into already-underscore-heavy
generated names is a real source of hard-to-read mismatches; simpler to just not have any. Verified
mechanically, not just by eye: compiled every `.java` file with `javac -h` to generate the real JNI
header stubs, then diffed the resulting 39 expected `Java_ua_dstucrypto_dstucore_*` symbol names
against the Rust side's own function names - zero mismatches on the first attempt, confirming the
naming convention actually holds rather than assuming it from the spec alone.

**A three-way, not two-way, misuse/state/crypto exception split** - found by an actual smoke-test
failure, not designed in up front. The first cut only had `Failure::Misuse` (→
`IllegalArgumentException`) and `Failure::Crypto` (→ `DstuException`), mirroring Python's plain
`ValueError`/`DstuError` split; a hand-written smoke test's "double-finalize a `Kupyna256Hasher`"
case then threw `IllegalArgumentException` where the test expected `DstuException`, exposing that
neither was actually correct - "already finalized" is a call-*sequence* problem, not a bad-argument
or crypto-integrity one. T-52/D-152's C# binding had already made exactly this distinction
(`ArgumentException` vs. `InvalidOperationException`) for the identical case; Java has the same
built-in vocabulary (`IllegalArgumentException` vs. `IllegalStateException`), so `util.rs` gained a
third `Failure::State` variant afterward. Recorded here because it's a real instance of this
project's own "don't trust green tests alone" principle working as intended - the bug was caught by
writing and running a probe before committing to the design, not discovered later in review.

**JNI's stateful objects (the incremental hashers, `SecretStreamPushState`/`PullState`) are boxed
Rust structs referenced by an opaque `long` handle** (`Box::into_raw`/`Box::from_raw`), freed via an
explicit native `*_nativeFree` called from each Java wrapper's `close()` (`AutoCloseable`) - this
binding's hand-rolled equivalent of what `#[pyclass]`/`#[napi]`/`magnus::wrap` generate for
Python/Node/Ruby automatically, since plain `jni` has no such macro. `push`/`pull`'s two logical
return values are each concatenated into one `byte[]` before crossing the boundary
(`ciphertext || authTag`, `tagByte(1) || plaintext`) rather than using an out-parameter array,
since JNI has no native multi-value return - the Java side splits them back out immediately.

**`os-maven-plugin`'s OS/arch-classifier property does not resolve inside a raw `<build><resources>`
block, only inside an actual plugin execution's `<configuration>`** - found empirically, not assumed:
a first attempt at "bundle the just-built native library under `native/<os-arch classifier>/` on the
classpath" via a plain `<resources><resource><targetPath>${os.detected.classifier}</targetPath>`
copied the file into a directory literally named `${os.detected.classifier}` (the placeholder
string itself), even though `mvn help:evaluate -Dexpression=os.detected.classifier` resolved the
property correctly at the same point in the build. Root cause: raw-model `<resources>` values are
interpolated when the POM is first read, before the `os-maven-plugin` extension's session property
is set; a plugin execution's `<configuration>` is evaluated later, at mojo-execution time, by which
point the property genuinely is visible. Fixed by switching to an explicit
`maven-resources-plugin` `copy-resources` execution bound to `generate-resources` instead of a
passive `<resources>` block - this is the same underlying reason grpc-java-style projects only ever
use `os-maven-plugin` inside plugin executions, not raw resource blocks, confirmed the hard way
here rather than copied from precedent.

**CI cannot grep Surefire's console/report output for a specific JUnit 5 test method's name to
confirm the `uacrypt` interop test actually ran (not silently skipped)** - unlike `dotnet test`'s
verbose logger or `node --test`'s TAP output (both list every test by name, the pattern
`bindings-dotnet.yml`/`bindings-nodejs.yml` already grep for), Maven Surefire's default output only
ever gives a class-level `Tests run: N, Failures: 0, Errors: 0, Skipped: 0` summary line, confirmed
by inspecting both the live console output and `target/surefire-reports/*.txt` directly. Since
`interopWithUacryptCli` is the only test in `SecretStreamTest` that can skip
(`Assumptions.assumeTrue`), `bindings-java.yml` instead greps that one class's own surefire report
for `Skipped: 0` - equally rigorous, adapted to what Maven actually prints rather than forcing a
per-test-name log line to appear.

**Every `Java_...` entry point, including the two trivial `isFinalized` getters, goes through the
shared `guard` panic-catching wrapper** - initially written directly (no panic-catching) since a
raw-pointer dereference can't itself panic; corrected to match the crate's own stated invariant
("every entry point goes through `guard`", `lib.rs`'s doc comment) rather than leaving a documented
rule with two silent exceptions to it.

Verified end-to-end, not just unit-by-unit: all 56 JUnit tests pass against the real compiled
native library; a hand-run bidirectional interop check against the real `uacrypt.exe` (encrypt with
one side, decrypt with the other, plus tamper rejection confirmed by both `uacrypt` itself as an
independent oracle and this binding's own decryptor); a full `mvn package` produces a working
`dstu-core-0.1.0.jar` with `native/windows-x86_64/dstu_core_java.dll` on its classpath; a real
fresh-install check (installed into a scratch local Maven repo, consumed from an unrelated temp
project by Maven coordinates alone, `Selftest.run()` + a `SecretBox` round trip both passed with
zero extra consumer-side configuration) matching the bar T-52/T-158 already set, then cleaned up
afterward (`~/.m2/repository/ua/dstucrypto` removed, not left behind); `cargo deny check`/
`cargo audit` both clean against `bindings/java/native`'s dependency tree; all 5 example programs
run and produce correct output.

**Step 10 (Raspberry Pi ARM64 re-check, D-151's template) done the same day - one real bug found**:
installed OpenJDK 17 + Maven via `apt` (`openjdk-17-jdk`, `maven` - Debian 12's own packages, no
script-based install needed this time, unlike .NET/T-52). `cargo xtask java` initially **failed**
on `mvn test` with `Source option 5 is no longer supported. Use 7 or later.` - Debian's apt-packaged
Maven (3.8.7) defaults to a bundled `maven-compiler-plugin` version (3.1) old enough that it does
not understand `maven.compiler.release` at all, silently falling back to its own ancient default
`source`/`target` of 1.5, which JDK 17's `javac` outright refuses to compile. Not an ARM-specific
bug (the same failure would hit any machine whose installed Maven happens to default to an old
compiler-plugin binding) - a real reproducibility gap in the POM, caught only because this was the
first time the binding was built with a *different* locally installed Maven than this session's own
dev-machine Maven (3.9.16, whose newer defaults happened to paper over the same gap). **Fixed by
explicitly pinning `maven-compiler-plugin` to `3.13.0`** in `pom.xml` rather than relying on
whichever version the local Maven's own super-POM defaults to - re-verified clean on both the dev
machine and the Pi afterward. All 56 tests passed on the Pi on the very next run, no further issues
- genuine confirming evidence the `jni`/JNI layer itself (as opposed to the build tooling) is
architecture-portable by construction, the same conclusion T-52's own Pi run reached for
`[LibraryImport]`/`SafeHandle`/`nuint`.

## D-154: cppcrypto (kerukuro) evaluated as a Kalyna/Kupyna oracle candidate, plus binary-level perf

2026-08-03, user-requested (pasted `https://sourceforge.net/projects/cppcrypto/`, asked for an oracle
evaluation and a binary-level performance comparison "у відповідних режимах"). Full working files
(harness source, generated key/message data) live only in the session scratchpad, not committed -
this entry plus the `docs/ORACLES.md`/`docs/PERFORMANCE.md` updates are the durable record.

**What it is**: a C++ crypto library by a single maintainer ("kerukuro"), SourceForge-hosted, last
released 0.20 (2023-03-12). SourceForge's own project page states BSD License; the individual
`kalyna.cpp`/`kupyna.cpp` file headers instead say "released into public domain" - an observed
discrepancy, not resolved either way (both are portable-with-attribution-or-better, so D-06's
"never port source into `crates/`, only verify against it" model is unaffected regardless of which
governs).

**Coverage**: Kalyna - all 5 variants this project implements (`kalyna128_128`/`kalyna128_256`/
`kalyna256_256`/`kalyna256_512`/`kalyna512_512`, exact block/key-size match). Kupyna - 256/512 only
(matches this project's own scope; 224/384 excluded by cppcrypto's own docs for the same reason
this project excludes them - identical to a truncated 256/512 output). **No Strumok anywhere** -
confirmed by reading the full algorithm list on both the SourceForge project page and the GitHub
mirror's README, and by grepping the extracted source tree for `strumok`/`8845` (no hits). This
oracle candidate covers 2 of this project's 3 symmetric primitives, not all three.

**Build**: downloaded `cppcrypto-0.20-src.zip` (SourceForge's own signed mirror-redirect link,
18,132,877 bytes, sha256 `cb4d5b54540554b55261a53e5be4e21bfc99642bab154631edf26f29fde65fd5`).
The project's own `Makefile` refuses a native Windows build outright (`$(error Windows build is
supported only via Visual C++ project files, or run 'make UNAME=Cygwin')`) and most of its other
~50 algorithms need `yasm`-assembled `.asm` files. **Neither blocker applies to Kalyna/Kupyna
specifically**: `kalyna.cpp`/`kupyna.cpp` are pure C++ (`OBJS = ... kupyna.o ... kalyna.o ...` in
the Makefile, no matching `.asm` rule for either), so a standalone harness compiling just those two
files plus their small dependency set (`block_cipher.cpp`, `crypto_hash.cpp`, `cpuinfo.cpp`,
headers) against this project's already-installed WinLibs MinGW-w64 `g++` needed no new toolchain
install and no yasm at all - confirmed by a clean `g++ -O2 -std=gnu++11` build with zero errors.
`kalyna.cpp` internally shares Kupyna's fused S-box/MDS tables via `extern const uint64_t
KUPYNA_T[8][256]` (defined in `kupyna.cpp`) - the same shared-table pattern this project's own
`hazmat::tables` uses (D-13), so both files must be compiled together regardless of which one is
being exercised.

**Correctness - all 20 official vectors matched, byte-for-byte**: a throwaway harness
(`oracle_check.cpp`, scratchpad-only) hardcoded every case from this project's own
`crates/dstu-core/tests/vectors/{kalyna,kupyna}/*.json` (all 10 Kalyna encrypt/decrypt cases across
5 variants; all 10 byte-aligned Kupyna-256/512 cases) and called cppcrypto's `kalyna128_128::init`+
`encrypt_block`/`decrypt_block` and `kupyna(256|512)::init`+`update`+`final` directly. **20/20
passed.** This is the same official `Kalyna.pdf`/`Kupyna.pdf` Appendix B vector set already used
throughout `docs/ORACLES.md`, not new data - but a new *independent implementation* reproducing it
is real corroborating value per this project's own dual-oracle bar (`docs/SECURITY.md`).

**Independence assessment - deliberately hedged, not overclaimed**: this file's own history has
been burned three times on premature "independent" claims (BC-Java credits Oliynykov's C as its
source; BC-.NET is a structural port of BC-Java; outspace's Strumok shares `dstu8845_*`/`T0..T7`
naming with UAPKI) - see `docs/ORACLES.md`'s Kalyna/Kupyna/Strumok sections. Checked the same way
here rather than trusting a `WebFetch` summary's judgment (per this file's own standing "WebFetch
summarization is unreliable" note, `CLAUDE.md` Agent discipline): compared `kalyna.cpp`'s function
decomposition directly against `oracles/kalyna-reference/kalyna.c`'s. The reference is granular and
step-by-step (`SubBytes`/`InvSubBytes`/`ShiftRows`/`MixColumns`/`EncipherRound`/`KeyExpandKt`/
`KeyExpandEven`/... - separate named passes over a state array, matching D-104's own
"auditability-first, not speed-optimized" characterization of Oliynykov's style). `kalyna.cpp` is
the opposite shape - monolithic per-variant `encrypt_block`/`decrypt_block`/`init` methods with no
named sub-passes at all, instead indexing directly into fused S-box+shift+MDS tables (`IT[8][256]`
etc.) the same general technique class as UAPKI's own "combined S-box+permutation tables"
(`docs/PERFORMANCE.md` "Implementations compared"). **No shared function name, table name, or
step-decomposition found between cppcrypto and the reference C, or between cppcrypto and either
Bouncy Castle port.** This is a materially stronger independence signal than any of the three prior
false starts above (which all showed literal shared naming/structure on inspection) - but a
fused-table SPN implementation is also the single obvious way to write a fast Kalyna regardless of
whether it was independently derived from the paper or influenced by prior art in that same style,
so this does not rise to a provable clean-room claim. Recorded in `docs/ORACLES.md` as
"independence not established, not refuted" - deliberately short of "independent third oracle."

**Performance - binary-level, Ryzen 5 PRO 4650U dev machine (D-34 methodology)**: cppcrypto has no
CLI matching `uacrypt`'s file-based shape (its own `cryptor` tool is hardcoded to Serpent-256
CBC+HMAC, no Kalyna path at all), so a second throwaway harness (`bench.cpp`) called the library API
directly, matching this project's own timing conventions exactly (D-80): Kalyna's key schedule
(`init`) excluded from the timed window, encrypt/decrypt cached-schedule, N=20000; Kupyna's
`init`/`update`/`final` called fresh *inside* the timed loop every iteration, matching `uacrypt`'s
own `bench_in_memory!` macro, at 64 KB/1 MiB/10 MiB. `uacrypt`'s own numbers were re-measured fresh
in the same session (`target/release/uacrypt kalyna-block`/`kupyna-digest`, rebuilt immediately
before timing - `cargo build -p uacrypt --release` reported no recompilation needed, confirming the
existing binary was already current) rather than reused from `docs/PERFORMANCE.md`'s older entries,
so both sides of the comparison are from the same session on the same machine. Full tables in
`docs/PERFORMANCE.md`'s Kalyna and Kupyna sections. **Result: cppcrypto wins every one of the 10
Kalyna cells measured** (5 variants x encrypt/decrypt), by roughly 1.3-1.9x - unlike this project's
UAPKI comparison, where the Ryzen result usually favors this project. **Kupyna is much closer**:
cppcrypto leads by only ~5-9% at every message size, near parity rather than a wide gap. Not
root-caused further (no profiling done to isolate why cppcrypto's Kalyna specifically pulls ahead
by a wider margin than its Kupyna) - not undertaken this session, now tracked as `docs/TASKS.md`
T-168 (added 2026-08-03, user-requested).

**Not re-run on the Raspberry Pi this pass** - `yasm` is an x86/x64 NASM-syntax assembler with no
ARM target, so even though Kalyna/Kupyna themselves don't need it, cppcrypto's own Makefile has no
Windows-native path to mirror on a from-scratch aarch64 toolchain check without first confirming a
Linux build works at all; deferred rather than assumed to work, matching this project's own "verify
before claiming a platform is covered" discipline (`docs/TASKS.md` T-35). D-33 is the standing
reminder that a single-platform Kalyna/Kupyna performance number is not a general claim - if this
oracle is revisited for the Pi, expect the possibility of a reversed result there, the same way
UAPKI's comparison flips.

## D-157: T-168 finding - Kalyna's round-count loop is the concrete mechanism behind D-154's gap

2026-08-03, user-requested follow-up to D-154/T-168 ("read the actual code, don't stop at
'different implementation'"). Read `cppcrypto`'s `kalyna.cpp`/`kupyna.cpp` directly (source still on
disk from D-154's session, `scratchpad/cppcrypto/extracted/...`), read this project's own
`hazmat::kalyna`/`kupyna`, and cross-checked both against real `--emit=asm` output
(`RUSTFLAGS="--emit=asm -C debuginfo=0" cargo build --release -p dstu-core --lib`, this project's
own established method, D-89/T-139/T-129) - not assumed from source-level reading alone. No code
changed this pass (`git diff` empty) - this is the verify-only read T-168 asked for, not the
implementation.

**Table layout confirmed identical, not the cause**: `cppcrypto`'s `KUPYNA_T[8][256]` and this
project's `hazmat::tables::SBOX_MDS`/`SBOX_MDS_DEC` (`[[u64; 256]; ROWS]`) are the same fused
S-box+MDS idea, same shape - matches D-13's already-recorded shared-table observation.

**Kalyna's inner column/row gather loop is already optimal - confirmed in real asm, not assumed**:
T-128 made `NB` (block width in columns) a const generic on `encipher_round_n`/`fused_inv_round_n`.
The compiled `encrypt_with_scheduleKj2_` (Kalyna128_128/128_256's shared NB=2 instantiation) shows
the `row*NB/ROWS`/`src_col` arithmetic fully constant-folded away - no `mul`/`div` anywhere - each
output column is a straight chain of 8 XORs against hardcoded table byte-offsets
(`2048(%r10,%r9,8)`, `4096(...)`, ...), the identical shape to `cppcrypto`'s hand-unrolled
`G128`/`G256`/`G512` functions in `kalyna.cpp`. This part of the pipeline is not the gap.

**The real mechanism: Kalyna's outer per-round loop is a genuine runtime loop with a real
conditional branch, and structurally cannot be unrolled - unlike `cppcrypto`'s fully-unrolled
per-round call sequence** (`kalyna.cpp:594-620`: `G(t1,t2,&rk[8]); G(t2,t1,&rk[16]); ...`, one
literal call per round, no loop at all, since `G`/`GL` are `static inline` and each call site is a
distinct instantiation). The asm for `encrypt_with_scheduleKj2_` shows a real `.LBB8_1` loop with a
`jne` back-edge executed `nr-2` times. Root cause, confirmed by reading the macro invocations
(`kalyna_variant!(Kalyna128_128, ..., 2, 2, 10)` / `kalyna_variant!(Kalyna128_256, ..., 2, 4, 14)`,
`kalyna.rs:617-621`): `encrypt_with_schedule<const NB: usize>` takes round count `nr: usize` as a
plain runtime parameter, not a const generic - and it can't easily be one, because the *same*
monomorphized `NB=2` instantiation is genuinely shared by two variants with two different round
counts (Kalyna128_128's nr=10 and Kalyna128_256's nr=14; likewise `NB=4` is shared by Kalyna256_256's
nr=14 and Kalyna256_512's nr=18). One compiled function body serving two different trip counts
cannot be unrolled by the compiler, full stop - this is a structural fact about the code, not a
missed compiler flag.

**Why Kupyna's D-154 gap (~5-9%) is so much smaller than Kalyna's (~1.3-1.9x) - a real, verified
partial answer, not just noted as unexplained anymore**: `hazmat::kupyna`'s `t_transform_n`/
`t_plus_transform_n`/`compress_n` already take round count as a *second* const generic
(`t_transform_n<const COLUMNS: usize, const ROUNDS: usize>`), and the file's own comment
(`kupyna.rs:189`) already documents `ROUNDS` as "always 10 or 14, paired one-to-one with `COLUMNS`" -
unlike Kalyna's `NB`, Kupyna's `COLUMNS` never aliases two different round counts, so making
`ROUNDS` const-generic was always safe there. This asymmetry - Kupyna already structured the way
Kalyna isn't - lines up with Kupyna sitting much closer to `cppcrypto` in D-154's own numbers.

**One finding that complicates a too-simple "just unroll it" takeaway, checked rather than assumed**:
even with `ROUNDS` const-generic and known at compile time, Kupyna's own compiled
`t_transform_nKj10_Kje_` still keeps a real loop (`.LBB11_1`, real back-edge) - LLVM did not choose
to fully unroll a 10-iteration loop this large even when it structurally could. So "const-generic
round count" is a necessary condition for the compiler to even consider unrolling, but D-154's exact
gap-size difference between Kalyna and Kupyna is not fully explained by unroll-vs-loop alone; some
of it remains genuinely open, consistent with D-154's own "not root-caused further" framing - not
overclaiming a complete answer here.

**Concrete, legitimate lead for a future implementation pass (not done here - verify-only per
T-168, and any rewrite still needs its own `advisor()` + plan-mode pass per that task's own
precedent)**: make Kalyna's round count a const generic on `encrypt_with_schedule`/
`decrypt_with_schedule` (and their round-transform helpers), mirroring `hazmat::kupyna`'s own
already-proven `ROUNDS` pattern - the two variants sharing one `NB` would need per-variant
monomorphized entry points (e.g. keying off `(NB, NR)` instead of `NB` alone) rather than a single
shared function, since that sharing is exactly what blocks the compiler today.

## D-155: T-163 (Go) step 0 - hand-written `cgo`, not `c-for-go`

2026-08-03. `docs/bindings-strategy.md`'s T-163 step 1 left the generator-vs-hand-written fork open
("research rather than assume"), same as Java's Fork 1 required a real spike (D-153). Go's case
doesn't need two runnable prototypes to resolve, though - the shape of `bindings/capi`'s own surface
(T-158: opaque handles + `DstuStatus` codes, ~50 functions, already stable and unchanging) makes the
tradeoff decisive on inspection rather than only measurable by building both:

- A generator (`c-for-go`, the only actively-maintained option surveyed) would still need a
  hand-written idiomatic Go layer on top of its raw output for exactly the parts that matter most:
  the `io.Reader`/`io.Writer` `crypto_secretstream` wrapper (D-118, no generator produces this from a
  C header), the `Close()`/`Complete()` split, and the caller-allocated-out-buffer calling convention
  (`sealed_out`/`sealed_out_cap`/`sealed_len_out` triples) that reads far more naturally as idiomatic
  Go with `make([]byte, n)` and a slice return than as a mechanically-translated three-argument call.
- It adds a codegen tool (and its own Go/YAML config surface) to the CI matrix for a one-time,
  already-small, already-stable header - not the multi-hundred-function churn-prone surface
  `c-for-go` is meant to amortize.

**Decision: hand-written `cgo` over `bindings/capi`'s `dstu_core.h`**, same C-ABI-consumer group as
.NET/Java-spike-B-rejected/C++ (T-52/T-158's own group), package `dstu` under `bindings/go/dstu`
(directory `bindings/go`, since `go` alone is a reserved word and cannot be a package identifier).

**Link spike done before wrapping the full surface** (advisor-recommended vertical slice, same
"spike and read the actual output" discipline as T-139/T-129/D-153): a minimal `cgo` file exporting
only `Selftest()` over `C.dstu_selftest()`, one `go test` asserting it returns success.
`${SRCDIR}` (cgo's own path-substitution token) resolved correctly with no absolute-path hardcoding
needed for both `#cgo CFLAGS: -I${SRCDIR}/../../../crates/dstu-core-capi/include` and the `LDFLAGS`
below.

Two real findings from actually running this, not assumed:
- **Plain `-ldstu_core_capi` links dynamically** even with only `libdstu_core_capi.a` (static) and
  `libdstu_core_capi.dll.a` (import lib) both present - GNU `ld` prefers the import lib, so the test
  binary silently required `dstu_core_capi.dll` on `PATH` at run time (confirmed: it failed with
  `STATUS_DLL_NOT_FOUND`/`0xc0000135` until `target/release` was added to `PATH`, then passed).
  **Forcing genuine static linking needs `-Wl,-Bstatic -ldstu_core_capi -Wl,-Bdynamic`** explicitly -
  confirmed by re-running the test with `target/release` removed entirely from `PATH` afterward,
  still green.
- **Static linking then fails in two waves of `undefined reference` errors, resolved one library at
  a time rather than guessed all at once** - the Rust standard library's own `std::net`/
  `std::os::windows::net`/`std::sys::fs::windows`/`std::sys::process::windows` code is pulled into
  the staticlib transitively (`dstu-core-capi` itself never touches networking/process spawning),
  and MinGW's linker doesn't resolve these from the default library set the way MSVC's would:
  1. Winsock symbols first (`WSAGetLastError`, `closesocket`, `bind`, `connect`,
     `send`/`recv`/`WSASend`/`WSARecv`, `getsockname`/`getpeername`, `freeaddrinfo`, `accept`) -
     fixed with `-lws2_32`.
  2. Then `GetUserProfileDirectoryW` (`-luserenv`) and NT-native symbols
     (`NtOpenFile`/`NtCreateNamedPipeFile`/`RtlNtStatusToDosError`, from `std::fs::remove_dir_all`/
     temp-dir and child-process-pipe code paths) - fixed with `-lntdll`.
  All three of the advisor's suggested libraries were genuinely needed here (`-lws2_32 -luserenv
  -lntdll`); `-lbcrypt`/`-ladvapi32` were not required for this minimal surface and were not added
  speculatively - re-check if a future undefined reference appears once the full ~50-function surface
  is wrapped (`crypto_pwhash`/`randombytes` may pull in `bcrypt.dll` specifically).

Final working directive at the time: `#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -Wl,-Bstatic
-ldstu_core_capi -Wl,-Bdynamic -lws2_32 -luserenv -lntdll`. Static was tried first per the advisor's
recommendation and succeeded once all three libraries were added - no fallback to the dynamic path
was needed for the real binding.

**T-163 done in full 2026-08-03, steps 1-9 same session** (full `crypto_*` surface,
`CryptoError`/`ArgumentError`/`InternalError` split mirroring `bindings/dotnet`'s
`DstuException`/`ArgumentException`, `SecretStreamEncryptWriter`/`DecryptReader` with the
`Complete()`-not-`Close()` D-118 finalization split, `cargo xtask go` + `bindings-go.yml` CI,
full test suite, examples/README - see `docs/bindings-strategy.md`'s T-163 section for the
per-step detail, not repeated here).

**Step 10 (Raspberry Pi ARM64 re-check), same session**: the Windows-only LDFLAGS above are
platform-specific and were never going to work unmodified on Linux - confirmed exactly that on the
first real Pi run (`cargo xtask go` failed: `cannot find -lws2_32`/`-luserenv`/`-lntdll`, all three
Windows-only libraries). Fixed with cgo's own per-`GOOS` `#cgo` pragma syntax (a space-separated
platform-tag list before the `LDFLAGS:` keyword, not a Go build-constraint file suffix):
```
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release
#cgo windows LDFLAGS: -Wl,-Bstatic -ldstu_core_capi -Wl,-Bdynamic -lws2_32 -luserenv -lntdll
#cgo linux LDFLAGS: -Wl,-Bstatic -ldstu_core_capi -Wl,-Bdynamic -lpthread -ldl -lm
#cgo darwin LDFLAGS: -ldstu_core_capi
```
Linux needed the same `-Wl,-Bstatic`/`-Bdynamic` bracketing as Windows (plain `-ldstu_core_capi`
linked dynamically against the just-built `.so` there too, same GNU `ld` import-preference
behavior) plus `-lpthread -ldl -lm` for the Rust staticlib's own transitive libc dependencies -
found by linking, not guessed: the first attempt (`-ldstu_core_capi -lpthread -ldl -lm` without the
static bracketing) linked and ran, but only because it silently picked up the dynamic `.so`: a
second attempt confirmed genuine static linking by re-running `go test` with a minimal `env -i`
(no `LD_LIBRARY_PATH`, no `target/release` on `PATH`), which required adding the `-Wl,-Bstatic`
bracketing before it would pass. `darwin` is unverified (no macOS hardware in this project's fleet)
but written by the same reasoning as every other binding's own "structurally consistent, not yet
run" macOS entries - flag if a real failure surfaces there.

Go 1.26.5 (`linux-arm64` tarball from go.dev, matching the Windows dev machine's own version -
Debian 12's own `golang-go` apt package is a stale 1.19, below this module's `go 1.26.5` directive)
installed to `/usr/local/go` on the Pi, not previously present. **All tests green on the first real
aarch64 run after the LDFLAGS fix** - the secretstream/`uacrypt` interop test passed too (`uacrypt`
built fresh there first), and all 5 examples ran with output byte-identical to the Windows dev
machine's own run where comparable (the `misc` example's Kupyna-256 digest of `"hello world"`
matched exactly). Unlike D-151's Windows-`c_char`/`i8` finding or D-153's Java Maven-version gap,
no ARM-portability bug was found in the Go wrapper code itself this time - the one real gap was the
LDFLAGS' platform-specificity, which is a cross-OS problem, not a cross-architecture one (it would
have hit any non-Windows CI runner just as much as the Pi, x86-64 or ARM alike).

**Advisor review after step 10 found a real blocker in every handle type, caught before it shipped
as "done" - `runtime.SetFinalizer` as a "SafeHandle-style backstop" is not safe here, it's a
premature-free race.** Every wrapper method has the shape `C.dstu_auth(k.ptr, ...)` - once `k.ptr`
is loaded as the call argument, `k` itself is no longer referenced by anything the Go compiler must
keep alive, so the GC can (and will, under memory pressure) treat `k` as unreachable and run its
finalizer - freeing the native key - *while the C call using that same pointer is still in
flight*. `runtime.SetFinalizer`'s own documentation requires the caller to keep the object
reachable until finalization is safe (`runtime.KeepAlive`'s doc example is this exact shape:
a syscall using a value's field, then `runtime.KeepAlive(value)` afterward) - a plain
`defer key.Close()` around the *caller's* function does not establish this; it only proves `k` is
reachable at the defer's own scope, not through every intermediate call. This is genuinely
different from `bindings/dotnet`'s `SafeHandle`, despite reading as the same "backstop" pattern:
`SafeHandle` implements exactly this reachability guarantee internally (P/Invoke marshalling roots
the handle for the call's duration) - a bare Go finalizer does not, and the project's own git log
carries no record of that distinction being checked before this pass. Invisible to every test in
this binding's suite, since each one holds its key reachable via `defer key.Close()` across the
whole test function - exactly the "don't trust green tests alone for security-critical code"
scenario CLAUDE.md already warns about for DSTU 4145 (D-25).

**Fix: removed `runtime.SetFinalizer` from every handle type** (`AuthKey`, `KdfMasterKey`,
`Kupyna256Hasher`/`512Hasher`, `SecretboxKey`, `SigningKey`/`VerifyingKey`, `StreamCipherKey`,
`SecretstreamKey`, `SecretStreamEncryptWriter`/`DecryptReader`) rather than adding
`runtime.KeepAlive` after all ~30 call sites - `Close()` is now the only thing that frees, matching
what the binding's own README already documented and the explicit-`Close()`/`defer` idiom every
other part of this binding already follows. A second, independent reason this was the right call
for `SecretStreamEncryptWriter`/`DecryptReader` specifically: their `Close()` also closes the
caller's own `inner` file/stream when `leaveOpen` is false - a finalizer firing on an unreachable
writer would have closed the *caller's* file handle at an arbitrary GC-chosen time, a side effect
no caller would expect from "eventually get garbage collected." Verified the fix rather than
assumed it: `go vet`/`cargo xtask go` clean, full suite green under `GOGC=1 go test -count=3`
(aggressive GC, closest a test can get to exercising the race without the fix) and `go test -race`
on Windows (also green); re-ran on the Pi too (`-race` itself doesn't run there - ThreadSanitizer's
"unsupported VMA range" error, 47 bits vs. its compiled-in 48, a known ARM64-kernel/TSan mismatch
unrelated to this fix - but `GOGC=1 go test -count=3` passed there).

**Two smaller findings from the same review, both fixed**: `go.mod`'s `go 1.26.5` directive (auto-
written by `go mod init`) forces every consumer to resolve the exact patch toolchain for no benefit
- changed to the conventional `go 1.26`. `SecretStreamDecryptReader.Read` could return `(0, nil)`
for a zero-length `Final` chunk (the size-0 case this binding's own tests exercise) - `io.Reader`'s
contract discourages a no-data/no-error return even though `io.ReadAll` tolerates it; fixed by
looping past an empty fetched chunk instead of returning immediately.

**One CI-workflow finding, not yet re-verified on real CI**: `rustup default
stable-x86_64-pc-windows-gnu` alone does not change what a bare `channel = "stable"` in
`rust-toolchain.toml` resolves to - that resolves against rustup's separate "default host triple"
setting, changed only via `rustup set default-host`, not `rustup default`. This is the same class of
gotcha CLAUDE.md already records for `rust-toolchain.toml` silently overriding an installed
toolchain (there, a CI step's nightly; here, a CI step's GNU host). `bindings-go.yml`'s Windows leg
now calls both, plus a `rustc -vV` step immediately before `cargo xtask go` so a real CI log shows
the actual `host:` line rather than leaving this to surface as a cryptic link failure two steps
later. **Still needs a real `gh run view` confirmation round, same as D-147/D-149's own precedent -
not claimed fixed until that happens.**

**Second CI failure, next push, root cause unrelated to the above: `gofmt -l` flagged every single
`.go` file in the binding, not just files touched this session** (`bindings\dstu\auth.go` through
`bindings\examples\sign.go`, ~30 files at once). Root cause: `windows-latest`'s hosted image ships
`core.autocrlf=true` in its **system** gitconfig (`C:/Program Files/Git/etc/gitconfig`, confirmed by
`git config --system --get core.autocrlf`, not `--global`, which was unset) - `actions/checkout`
therefore converted every LF blob to CRLF on disk during checkout, even though the git blobs
themselves are LF-only (verified with `git show HEAD:<file> | xxd`). `gofmt` always emits LF, so
`gofmt -l` diffed CRLF-on-disk against its own LF output and flagged the entire tree, not a real
formatting regression in any file. Fixed with a repo-root `.gitattributes`: `* text=auto eol=lf` plus
`*.pdf binary` (the repo's only tracked binaries, `docs/papers/*.pdf`) - `eol=lf` overrides
`core.autocrlf` for matching paths regardless of the checkout machine's own git config. No
`git add --renormalize` was needed since the committed blobs were already LF-only; the fix only
changes what future checkouts produce on disk. **Confirmed green on real CI**: run 30806655799,
all three matrix legs (`ubuntu-latest`/`macos-latest`/`windows-latest`) passed, including the
`rustup set default-host` fix above (same run) - both open items from this entry are now closed.

## D-156: T-170 - `firmware/qemu-stm32-smoketest`, netduinoplus2 over an ESP32 fork

2026-08-03. Follow-up to a conversation about whether GitHub-hosted CI has any real-hardware
equivalent for microcontrollers - it doesn't (no hosted runner offers STM32/ESP32 silicon; the only
path to real hardware in CI is a self-hosted runner wired to a physical board, which this project
doesn't have, T-55/T-56 still open). Software emulation was raised as an additional, cheaper layer
that doesn't replace real-hardware validation but can catch a genuine cross-target correctness bug
before real hardware ever exists - explicitly scoped to **stock, no-fork-required** boards only per
the owner's own framing.

**Checked on the Raspberry Pi "uacipher" rig** (already the project's real ARM64 Linux test
machine) what Debian's own `qemu-system-arm`/`qemu-system-misc` packages (`apt`, no custom build)
actually support:
- **STM32-class Cortex-M: real board models exist** - `qemu-system-arm -machine help` lists
  `stm32vldiscovery` (Cortex-M3, STM32F100) and `netduinoplus2` (Cortex-M4F, STM32F405 - Netduino
  boards are STM32-based despite the third-party name). `netduinoplus2` matches this project's
  already-added `thumbv7em-none-eabihf` target (T-116, Cortex-M4/M7 hard-float) exactly, unlike
  `stm32vldiscovery` (Cortex-M3, no FPU, would need the not-yet-added `thumbv7m-none-eabi`).
- **ESP32: no real board in mainline/Debian QEMU at all**, either family - `qemu-system-xtensa`
  only has generic dc232b/de212 eval boards (`sim`, `virt`, `kc705`, `lx60`...), no `esp32`
  machine; `qemu-system-riscv32` only has `sifive_e`/`sifive_u`/`spike`/`virt`/`opentitan`, no
  `esp32c3`. Real ESP32 emulation needs Espressif's own QEMU fork, built from source - explicitly
  the "fork and dance" the owner asked to skip for this pass. Not attempted here; a candidate for a
  later, separately-scoped task if ever wanted.

**Decision: `netduinoplus2` only, ESP32 emulation out of scope for T-170.**

**Built `firmware/qemu-stm32-smoketest`**, its own Cargo workspace (not a root workspace member -
same D-119 reasoning as `bindings/*`: a `thumbv7em-none-eabihf` binary with its own linker script
and QEMU runner has no business in `dstu-core`'s host-targeted workspace). Depends on `dstu-core`
via a path dependency with `default-features = false` (genuine `no_std`, no `alloc`) plus
`cortex-m`/`cortex-m-rt`/`cortex-m-semihosting`/`panic-semihosting` (the last with its `exit`
feature). `memory.x` uses real STM32F405 sizes (1024K flash/128K RAM) - conservative for a binary
this small regardless of QEMU's exact modeled sizes. The firmware runs the exact same official DSTU
vectors the host test suite already uses (Kalyna-128/128 encryption, `docs/papers/Kalyna.pdf`
Appendix B.2.6; Kupyna-256 digest, `docs/papers/Kupyna.pdf` Appendix B.2, both already in
`crates/dstu-core/tests/vectors/`) rather than inventing a new unverified oracle, and reports
pass/fail via ARM semihosting's `SYS_EXIT` (`cortex-m-semihosting::debug::exit`) - QEMU translates
`EXIT_SUCCESS`/`EXIT_FAILURE` into its own process exit code, which `cargo run`'s own exit code
already propagates (the same mechanism the embedded Rust ecosystem's own QEMU-based CI examples
rely on), so no output-text parsing is needed. `.cargo/config.toml`'s `runner` string is
`qemu-system-arm -cpu cortex-m4 -machine netduinoplus2 -nographic -semihosting-config
enable=on,target=native -kernel` (cargo appends the built ELF path as the final argument).

**`cargo xtask qemu-stm32`** added (checks `qemu-system-arm` is on `PATH` first, same
`require()`/best-effort pattern as every other optional `xtask` command, then `cargo run --release`
inside the firmware directory) and wired into `cargo xtask ci`'s optional-layers list.

**Verified on the real Pi, both directions, not just the happy path** (D-25's own "don't trust
green tests alone" principle, applied to a smoke test rather than a primitive this time): a clean
run printed `PASS: Kalyna-128/128` / `PASS: Kupyna-256` and exited 0; a deliberately corrupted
expected ciphertext byte (`0x81` -> `0x00`) printed `FAIL: Kalyna-128/128 ciphertext mismatch` and
exited 1 - confirming the pass/fail signal is real, not a constant. Reverted after confirming.

**Explicitly not real-hardware validation** (T-55/T-56 unchanged, still open) - QEMU emulates
instruction semantics on the host CPU, not real silicon timing or side-channel behavior; this is an
additional correctness-only layer, cheaper to run than owning a board, not a substitute for one.

## D-158: T-53 (C++) step 0 - four forks resolved before writing code

2026-08-03. `docs/bindings-strategy.md`'s T-53 entry left four things open ("decide at
implementation time"). Resolved together per this file's own standing rule about surfacing
multiple implementation forks in one place, not one at a time:

1. **Stream finalization**: the `Complete()`-not-`Dispose()`/`Complete()`-not-`Close()` split
   D-152 (.NET)/D-155 (Go) already chose ports directly - a C++ RAII destructor genuinely cannot
   tell exception-unwind from normal scope exit without `std::uncaught_exceptions()` bookkeeping
   (and that API is fragile under nested exceptions besides), so avoiding the question entirely is
   the plainer fix, same reasoning Go's own doc comment already gives. `SecretStreamEncryptor`'s
   destructor only frees the native push state (RAII, D-118's non-negotiable half); emitting the
   `Tag::Final` chunk is a separate explicit `Finish()` call the caller makes on the success path.
   A write loop that throws mid-stream leaves no `Final` chunk behind - a reader fails closed on it
   (D-65), matching every other binding's own D-118 property test.
2. **Step 3 shape**: `std::ostream&`/`std::istream&`, not an iterator-of-buffers - matches Go's
   `io.Writer`/`io.Reader` and .NET's `Stream` precedent the advisor pointed at, and is the
   idiomatic C++ shape for "an open file or any other byte sink/source" (works unmodified with
   `std::ofstream`/`std::ifstream`, `std::stringstream`, or a caller's own `std::streambuf`).
3. **Step 4 packaging**: prebuilt lib + header, no CMake `FetchContent`. `crates/dstu-core-capi`
   already produces both a cdylib and a staticlib plus a committed `include/dstu_core.h` via
   `cargo xtask capi` - `FetchContent`ing a Rust crate from CMake has no real tooling support (no
   Rust equivalent of `corrosion` is already a project dependency), so the honest deliverable
   mirrors T-158's own header pattern: an `INTERFACE` CMake target that expects the caller to have
   already run `cargo xtask capi` and point `DSTU_CORE_CAPI_DIR` at the crate, same shape .NET's
   `Directory.Build.props`/Go's `#cgo LDFLAGS` already assume a prebuilt native artifact rather than
   building Rust from inside the other language's own build system.
4. **Step 6 test framework + vector loading**: hand-rolled `CHECK` macro mirroring
   `c-tests/test_capi.c` exactly, no Catch2/doctest/GoogleTest dependency - C++ has no stdlib JSON
   either, so `test_capi.c`'s own answer (hand-transcribe the single official Kupyna-256 vector as a
   byte array, `dstu_selftest()` covers the rest) carries over unchanged; matches
   cross-language-style-guide.md's "standard library over a third-party one" KISS principle
   (D-124), and a real JSON dependency buys nothing a C test harness didn't already need to solve
   without one.

**Linking, not left open, decided by reading the existing precedent rather than re-deriving it**:
`c-tests/test_capi.c` itself links `dstu-core-capi`'s **cdylib** (`-ldstu_core_capi` against the
import lib on Windows-GNU, `.so`/`.dylib` directly elsewhere), not the staticlib - simpler than
Go's D-155 static-link route (no `-Wl,-Bstatic`/`-Bdynamic` bracketing, no transitive
`-lws2_32 -luserenv -lntdll` needed, since the cdylib itself resolves those at its own link time).
`bindings/cpp`'s CMake follows the C test harness's own choice, not Go's - both are valid, but
matching the crate's own existing C consumer is less surface to get wrong than re-deriving Go's
static-link fixes for a case that does not need them.

No code written this entry - the four-fork record itself, per the project's "record multiple
resolved forks together" rule. Implementation follows in the same session's later commits.

**Addendum, same day, step 10 (Raspberry Pi ARM64 re-check)**: re-synced the repo, confirmed
`cmake` 3.25.1 and `g++` 12.2.0 were already present (no new toolchain install needed, unlike
Node/Ruby/PHP/.NET's own first Pi runs), ran `cargo xtask cpp` end-to-end. All green on the first
real aarch64 attempt - the CMakeLists' non-Windows branch (`libdstu_core_capi.so`, confirmed via
`file`, not assumed) exercised for the first time on real hardware, `TestUacryptInterop`'s
`std::system` call working over a plain POSIX `sh` (the Windows `cmd.exe` outer-quote-wrapping
workaround in `RunCommand` is a no-op there, guarded by `#ifdef _WIN32`), and
`GenericHash256("hello world")` verified byte-identical to the x86-64 Windows dev machine's own
digest. No ARM-portability bug found this time - unlike D-151's `c_char`/`i8` finding in the C ABI
crate itself, this is genuine confirming evidence (not just an absence of counter-evidence) that
the `unique_ptr`-based RAII/exception design has no hidden x86-64 assumption, matching T-52/.NET's
own clean first Pi pass rather than T-51/Java's (Maven plugin pin) or T-163/Go's (per-`GOOS`
LDFLAGS) own findings. T-53 is now done in full, all ten standard steps - every planned binding in
`docs/bindings-strategy.md`'s phased order has landed.

**Second addendum, same day, advisor review + real CI**: an advisor pass caught a real latent bug
before it shipped - `SecretStreamEncryptor`/`Decryptor`'s originally-defaulted move constructor/
assignment moved `state_`/`pending_` but copied `bufferLen_`/`pendingPos_` by value, leaving a
moved-from object's `buffer_.size() - bufferLen_` (or `pending_.size() - pendingPos_`) invariant
broken - `Write()`/`Read()` on that moved-from object would underflow a `size_t` subtraction.
Nothing in this codebase ever moves either type; fixed by deleting the move ops instead of writing
a correct custom move, per the advisor's own "smaller, safer surface" framing. Same pass added
`-Wall -Wextra`/`/W3` (PRIVATE, test/example targets only) - surfaced one real unused-function
warning, fixed - and closed two real test-coverage gaps: `SignDigest`/`VerifyDigest` had zero
coverage, and only `Kupyna256Hasher`'s double-`Finalize()` was tested, not `Kupyna512Hasher`'s. The
first draft of the new `VerifyDigest` tamper test flipped `digest[0]` and always "passed" without
testing anything - `dstu4145::hash_to_field` (`crates/dstu-core/src/hazmat/dstu4145/signature.rs`)
only consumes a digest's **low 21 bytes**, so tampering the first byte of a 32-byte digest is a
guaranteed no-op on the derived field element. Found by actually running the test, not by
inspection - fixed to tamper the last byte instead, which the function actually reads. Also
corrected an overclaim in `docs/bindings-strategy.md`'s step 5 write-up ("MSVC ... verified
locally" - it wasn't, `cl.exe` isn't on this dev machine's PATH) before pushing and confirming all
three `bindings-cpp.yml` legs (`ubuntu-latest`/GCC, `macos-latest`/Clang, `windows-latest`/MSVC) via
`gh run view`, run `30839873166`, all `success` - MSVC/Clang's only real confirmation, since neither
was ever exercised on this dev machine.

## D-159: full documentation cross-check after T-162 - a doc-map sweep failure mode the existing rule doesn't cover

2026-08-03, user-requested directly after T-162 landed ("документація уся закрита?... Проведи
крос перевірку усієї документації" - is all documentation actually closed/synced, cross-check
everything). Grepped "binding" across every doc file this project has
(`docs/*.md`/`README.md`/`CLAUDE.md`/`AGENTS.md`), not just the files each individual binding
task's own step 8 already touched.

**Real, previously-unflagged gaps found, all in `CLAUDE.md` itself** - the project's own
AI-agent-instructions file, auto-loaded every session, arguably the single highest-leverage doc to
keep accurate, and it had drifted silently through the *entire* T-49→T-53 binding-landing phase
(2026-08-02 through 2026-08-03):
1. **"root Cargo workspace with two crates"** - stale since T-158 (2026-08-03): `crates/dstu-core-capi`
   is a real third root-workspace member, not mentioned anywhere in `CLAUDE.md` at all (confirmed
   by grepping `dstu-core-capi`/`capi` across the whole file - zero hits).
2. **"`bindings/python` is the first, well underway (T-49)"** - stale since 2026-08-02: all eight
   bindings are done, not just Python "underway."
3. **The "Second priority" language-bindings line** - listed only five languages (Python,
   JavaScript, Java, .NET, C++), missing PHP/Ruby/Go entirely (added to scope the same day as each
   other, D-121/D-122, but only PHP/Ruby ever got added to this sentence - Go was missed even
   there). `docs/dstu-crypto-project.md`'s own parallel sentence had the identical gap, one
   language narrower (missing only Go).

All fixed this pass (see `CLAUDE.md`'s "Repo layout"/"Second priority" sections,
`docs/dstu-crypto-project.md`'s "Second priority").

**Why the existing rule didn't catch this**: CLAUDE.md's own "Agent discipline" section already
has a rule for this general class of problem - "grep its own task ID across every file the doc
map's 'Update when' column implicates" - and that rule genuinely worked for T-53 itself (this
session's own doc-map sweep, D-158/T-53 step 8, correctly found and fixed
`docs/dstu-crypto-project.md`/`docs/release-readiness.md`/`README.md`/`docs/bindings-strategy.md`
by grepping "T-53"). **The gap is a different shape**: none of the three sentences above ever
mention "T-49" or "T-53" by ID - they are free-standing state summaries ("two crates," "the first,
well underway") that go stale as an *indirect* consequence of a task landing, with no task-ID
string in the sentence itself for a grep to catch. A task-ID grep is necessary but not sufficient.
`docs/CHANGELOG.md`'s `[Unreleased]` section has the same shape (empty despite `dstu-core-capi`
landing as a real workspace member and eight bindings landing since the `v0.1.0` tag) - flagged to
the owner as an open scope question rather than silently edited, since it's genuinely ambiguous
whether un-registry-published bindings belong in a Keep-a-Changelog file scoped to what actually
gets released (crates.io/GitHub Releases), not decided here.

**New standing rule, added to `CLAUDE.md`'s "Agent discipline" section**: a task-ID grep sweep is
not sufficient by itself - before declaring any doc-map sweep complete, separately re-read
`CLAUDE.md`'s own "Project status"/"Second priority" sections (workspace crate count, binding-list
completeness) and `docs/CHANGELOG.md`'s `[Unreleased]` section for any change that adds a workspace
member or a headline-scope item, whether or not the sentence in question ever cites the task's own
ID.

**Also confirmed, not gaps**: `docs/user-journey-gaps.md` and `docs/CONTRIBUTING.md` genuinely have
zero binding-related content, but both are *already* tracked as their own open tasks (T-166/T-165
respectively, added 2026-08-03, before this cross-check) - not silently missed, just not yet done.
`docs/SECURITY.md`/`docs/PERFORMANCE.md`/`docs/resource-profiles.md`/`docs/ORACLES.md`/`AGENTS.md`
checked, nothing stale found (`ORACLES.md`'s two "binding" hits are D-115's already-accurate
historical record, not a status claim).

**Addendum, same conversation: the `CHANGELOG.md` scope question resolved, and a real gap found by
resolving it.** Owner's answer: "Тільки те що релізиться" (only what actually releases) - `docs/
CHANGELOG.md` tracks what ships in a tagged GitHub Release/crates.io publish, not every landed
change. Checking that rule against reality (`gh release list`, not assumed) found `v0.2.0` was
tagged and published 2026-08-02T01:04:25Z (`dstu-core`/`uacrypt` both at `0.2.0` in their own
`Cargo.toml`) with real, substantial content - DSTU 4145 signing commands (T-124), the
`scalar_multiply` correctness fix (D-110), the sign/verify perf work (D-108/D-109), a `getrandom`
no_std feature (T-123), Kani proofs (T-145), CodeQL/SonarCloud CI (T-140/T-143) - and
`docs/CHANGELOG.md` had **zero entry for it**: `[Unreleased]` sat empty, the file jumped straight
from nothing to `[0.1.0]`. A second, concrete instance of this entry's own "free-standing state
doesn't get caught by a task-ID grep" finding - nothing about "add a CHANGELOG entry" is gated on
any single task's own ID, so it silently fell through every prior session's own doc-map sweep.
Fixed: a real `[0.2.0] - 2026-08-02` entry added, sourced from the actual GitHub release notes and
cross-checked against the cited `D-108`/`D-109`/`D-110`/`D-74` entries for accuracy (not copied
verbatim). Per the owner's own scope answer, this entry's own "Notes" section states explicitly
that the language bindings and `dstu-core-capi` are deliberately excluded, not forgotten - they
have never shipped in a tagged release. **New standing rule**: check `gh release list` against
`docs/CHANGELOG.md`'s own entries as part of any full documentation cross-check, not just grep for
staleness in prose - a missing entire release entry doesn't "read" as stale prose, it reads as
nothing at all, which is easy to walk past.

## D-160: T-171 - const-generic `NR` spiked and reversed, no code change, negative asm result

2026-08-03, T-171's own gate (`docs/TASKS.md`/`CLAUDE.md`'s Tier C precedent): "Needs its own
`advisor()` consultation and plan-mode pass before implementation" - both done first. `advisor()`
flagged the load-bearing counter-evidence sitting in D-157's own text ("checked in asm: Kupyna's own
compiled loop isn't fully unrolled by LLVM even with `ROUNDS` const") and recommended a spike-first
plan rather than rewrite-first, per CLAUDE.md's standing rule to spike and read `--emit=asm` before
any `hazmat::{kalyna,kupyna,strumok}` perf rewrite, and the T-139/T-129 precedent of both being
reversed after spiking with "no code change" as a complete outcome.

**Spike**: patched only `Kalyna128_128` (`NB=2`, `NR=10` - the instantiation D-157 identified as
today's shared-`NB=2` culprit) - `encrypt_with_schedule`/`encrypt_generic` gained
`const NR: usize`, dropped the runtime `nr` parameter, all five `kalyna_variant!` call sites updated
to compile. Built with `RUSTFLAGS="--emit=asm -C debuginfo=0" cargo build --release -p dstu-core
--lib` and compared `encrypt_with_scheduleKj2_Kja_`'s (NB=2, NR=10, hex `a`) compiled body against
the pre-spike `encrypt_with_scheduleKj2_`'s (today's shared NB=2-only instantiation, runtime `nr`).

**Result: negative, matching D-157's own warning, not the hoped-for full unroll.** Both versions
compile to the identical shape - one `.LBB_1` loop, real conditional back-edge (`jne .LBB_1`), same
214-line function body, same per-round gather/XOR sequence. The *only* difference the const generic
bought: the loop-trip compare changed from a runtime value loaded off the stack (`cmpq 24(%rsp),
%rdx`) to a compile-time-immediate compare (`cmpq $655, %rbx`) - a real but minor codegen change,
nowhere near `cppcrypto`'s fully-unrolled, branch-free per-round call sequence T-168/D-157 found.
LLVM had every fact it needed to unroll (both `NB` and `NR` known at compile time) and chose not to,
the same outcome D-157 already saw on Kupyna's own already-const-generic `ROUNDS`.

**Decision, per this task's own plan-mode-approved decision gate**: no branch-loss / no unroll →
close T-171 without further implementation. Spike reverted via `git stash` + `git stash drop`
(`git diff` empty, confirmed) - the "reversed after spiking, no code change is the complete outcome"
precedent (T-139/T-129) applies here too, not a shortfall.

**What this leaves genuinely open**: D-157's gap-size asymmetry question (why Kupyna's own
const-generic `ROUNDS` sits much closer to full-unroll behavior in its smaller D-154 gap than this
result would suggest) is not resolved by this spike - this task only tested the mechanism T-168
proposed as a *lead*, and the lead didn't pan out empirically. The remaining ~1.3-1.9x Kalyna gap's
real cause is still open; a future task would need to test a different mechanism (e.g. actual
per-round unrolling via a macro/codegen approach that doesn't rely on LLVM choosing to unroll a
const-bounded loop on its own), not const-genericizing the trip count alone.

## D-161: T-172 - genuine per-round unrolling of Kalyna, macro-driven, `fused`-only

2026-08-03, user-requested direct follow-up to T-171/D-160's own closing note ("генерувати
straight-line-послідовність самостійно, а не сподіватись на LLVM"; "давай справжнє розгортання").
`advisor()` + plan-mode both done first, per this project's Tier C precedent. `advisor()`'s key
correction: test whether unrolling helps *at all* with a cheap `RUSTFLAGS`-only spike before
committing to a five-variant macro rewrite, rather than assuming T-168's cppcrypto-shaped lead was
right just because T-171's specific mechanism (const-generic `NR` alone) had failed.

**Stage A - flag spike, positive with a clear split by `NB`.** Restored T-171's const-`NR` patch
(one variant, `Kalyna128_128`), built twice - `RUSTFLAGS="--emit=asm -C debuginfo=0"` vs. the same
plus `-C llvm-args=-unroll-threshold=4000` - and confirmed in the asm that the forced build's
`encrypt_with_scheduleKj2_Kja_` genuinely loses its `.LBB`/`jne` back-edge (776-line straight-line
body vs. 214 lines before) while the untouched `decrypt_with_schedule` (still runtime-`nr`, a
control) stayed flat. Criterion (`kalyna` bench, `t172-unforced` vs `t172-forced` baselines)
confirmed a real split by block width: `NB=2`/`NB=4` (128-128, 128-256, 256-256, 256-512) gained
21-35%; `NB=8` (512-512) was flat (+0.4%, noise). Matches `advisor()`'s own predicted counter-
evidence (register spill already visible in `NB=2`'s asm, worse for `NB=8`'s larger state) -
positive enough to proceed, but with a heads-up that `NB=8` might not follow the others.

**Stage B - macro-driven real unroll, all five variants x encrypt+decrypt, deterministic (no
`RUSTFLAGS` dependency).** `crates/dstu-core/src/hazmat/kalyna.rs`:
- `unroll_rounds!` (new `macro_rules!`) emits one `$round_fn(state); xor_round_key(...)` pair per
  literal index in an explicit list, in exactly the order given - a genuine compile-time-generated
  straight-line sequence, never a `for` loop for LLVM to decide whether to unroll (the T-171
  failure mode). `encrypt_with_schedule`/`decrypt_with_schedule` both gained `const NR: usize`
  (encrypt already had it from the T-171 patch; decrypt gained it fresh, dropping its runtime `nr`
  parameter and propagating through `decrypt_generic` and all five `kalyna_variant!` call sites,
  mirroring T-171's own signature-change shape). Each function dispatches via `match NR { 10 =>
  ..., 14 => ..., 18 => ..., _ => unreachable!() }` to the right literal index list - ascending
  (`1..=NR-1`) for encrypt, descending (`NR-1..=1`) for decrypt, matching `dec_keys[1..nr]
  .iter().rev()`'s original walk order. Only three distinct `NR` values exist across all five
  variants (10/14/18), so three arms cover every `kalyna_variant!` call site - no arithmetic-on-
  const-generics needed (which stable Rust can't do without the unstable `generic_const_exprs`
  feature anyway), matching CLAUDE.md's own "three similar lines over a premature abstraction"
  preference.
- **Bounds provability**: `const { assert!(NR == 10 || NR == 14 || NR == 18) }` at the top of both
  functions, catching a bad future `kalyna_variant!` instantiation at compile time rather than
  leaving the match's `_ => unreachable!()` arm as the only guard (CLAUDE.md's "provable from the
  line itself, not a hand-traced invariant" rule, same SonarCloud-BLOCKER-motivated standard cited
  elsewhere in this file).
- **Correctness**: `decrypt_fusion_tests` updated for the new signature and extended with the
  previously-missing `nb2_nr14` (Kalyna128_256) case, found stale during T-171's own planning. A new
  sibling `encrypt_fusion_tests` module (same shape, differential against a runtime-`nr` reference
  built from the retained `#[allow(dead_code)]` `encipher_round`) covers all five `(NB, NR)` pairs
  for the encrypt side, which had no equivalent differential coverage before. All 10 official Kalyna
  vectors, the full `cargo xtask test` matrix (`--all-features`/`--no-default-features`/
  `--no-default-features --features getrandom`), `cargo xtask clippy`, `cargo xtask fmt --check` all
  green.
- **`encipher_round_n`'s `NB=8` instantiation does not get inlined by LLVM at any of its 17 call
  sites in `encrypt_with_scheduleKj8_Kj12_`** - confirmed in the release asm (18 real `callq`
  instructions to `encipher_round_nKj8_`, function body only 306 lines vs. 2842 for the equivalent
  `NB=4`/`NR=18` case) - LLVM's own inlining-cost heuristic backing off because the per-round body
  is too large to duplicate 17 times, not a bug in the unroll. This directly explains Stage A's
  `NB=8` flat result: the call/ret overhead survives even in the "unrolled" (branch-free) shape.
  `fused_inv_round_n`'s `NB=8` instantiation (decrypt) inlined more (913 lines), which is why
  `NB=8` decrypt shows a real win below despite `NB=8` encrypt not.

**Code size - real and material, resolved by asking rather than deciding unilaterally.** First
measured wrong, corrected same pass (flagged by `advisor()` on the completion-review call, not
found independently): the first pass summed `size`'s per-codegen-unit `.text` column across the
`dstu-core` release **rlib** (+21.7%, `fused`) - an overestimate, since an rlib retains
monomorphizations/dead code the linker later strips, and `docs/resource-profiles.md`'s own
established method for this exact comparison (three paragraphs above the original insertion point)
is the **linked `uacrypt` release binary**, not the rlib. Re-measured the doc's own way:

| Profile | Baseline (`uacrypt.exe`) | Stage B | Δ |
|---|---:|---:|---:|
| `fused` (default) | 1,706,093 B | 1,777,216 B | **+71,123 B (+4.17%)** |
| `small-tables` | 1,645,588 B | 1,654,815 B | **+9,227 B (+0.56%)** |

The **absolute** byte delta (+71 KB) barely moved from the flawed first estimate (+70.5 KB) - the
rlib method's error was almost entirely in the percentage (wrong denominator: Kalyna's own object
code vs. the whole linked binary including the standard library, every other algorithm, and the
full CLI), not in the raw size of what actually changed. Still real, still put to the owner
directly (`AskUserQuestion`, not decided unilaterally) before this correction was made, since the
qualitative call - "does a +4-20%-ish class of `.text` growth matter enough to gate" - was never
actually resting on the wrong percentage; the owner's answer stands unaffected. Decision:
**unconditional for `fused`, `small-tables` stays on the old runtime loop.** Implemented via
`#[cfg(not(feature = "small-tables"))]`/`#[cfg(feature = "small-tables")]` splits in both
`encrypt_with_schedule` and `decrypt_with_schedule`'s bodies (the `unroll_rounds!` macro definition
itself is `#[cfg(not(feature = "small-tables"))]` too, to avoid an `unused_macros` warning under
`small-tables` - D-74's "hidden in exactly one feature combination" pattern, checked explicitly
this time rather than found the hard way again). `small-tables`'s own binary grew only +0.56% - an
expected, minor side effect of `NR` becoming a const generic everywhere (T-171's signature change
alone, kept for both profiles to avoid maintaining two entirely separate function signatures)
rather than of unrolling itself, since `small-tables` never reaches the unrolled branch. Net effect
on the `fused`-vs-`small-tables` gap this project already exposes as a resource-profile choice: it
widened from ~60.5 KB (baseline `uacrypt.exe`, this session's own fresh measurement - doesn't need
to reconcile with `docs/resource-profiles.md`'s older, differently-sourced "~75 KB" figure, a
different build/toolchain snapshot) to ~122.4 KB (Stage B) - see `docs/resource-profiles.md` for
the full framing.

**Scope of what `small-tables` now means, recorded rather than left implicit**: before this task,
`fused`/`small-tables` only ever chose *which table data* links in (D-35/D-38/D-39) - correctness-
identical either way, purely a flash trade. As of this task, `small-tables` also selects *which
Kalyna round-sequence code compiles* (the old loop, not the new unroll). Output stays byte-identical
(the differential proptests above cover both paths against the same reference) so this is not a
correctness change, but because Cargo features are additive and workspace-wide, any crate anywhere
in a build graph that turns `small-tables` on de-optimizes Kalyna for every consumer in that build,
including one that only wanted the flash saving on an unrelated algorithm - worth knowing before
composing this feature into a larger dependency graph, not something to discover from a downstream
performance regression report.

**One more thing D-74's own "cfg gate = compiled-out code path" pattern implies, caught on the same
completion-review call**: `--all-features` (which also turns on `small-tables`) had silently become
the *only* thing this project's own `xtask test`/`xtask clippy` ran, so neither ever compiled or
linted the unrolled `fused` path this task shipped - the exact D-39 gap CI's `rust.yml` `test` job
already has an explicit default-only leg to avoid, but `xtask/src/main.rs`'s own `test()`/`clippy()`
functions had drifted out of sync with that CI pattern before this task ever touched them. Fixed in
this same pass: both gained a default-features-first leg (mirroring CI's own order), and the usage
text in `print_usage()` updated to describe it - re-ran `cargo xtask clippy`/`cargo xtask test`
after the fix and confirmed the default (`fused`, unrolled) path is now genuinely compiled, linted,
and tested by this project's single QA entry point, not just by ad hoc local commands during this
session.

**Measured results, both in-process (criterion, new `t172-stage-b` baseline) and binary-level
(`uacrypt kalyna-block`, this project's mandatory D-34 methodology, N=300000, single clean run with
no other CPU-heavy process active - the first attempt was contaminated by a concurrent `cargo xtask
test` run and discarded, same pitfall `docs/PERFORMANCE.md` already documents from D-30's own
measurement pass) - cross-checked, not just one or the other:**

| Variant | Direction | criterion Δ (`fused`) | `uacrypt` binary Δ (`fused`) |
|---|---|---|---|
| 128-128 | encrypt | -26.4% | -16.9% |
| 128-128 | decrypt | -26.2% | -28.2% |
| 128-256 | encrypt | -25.0% | -19.0% |
| 128-256 | decrypt | -26.7% | -25.4% |
| 256-256 | encrypt | -31.4% | -17.4% |
| 256-256 | decrypt | -23.6% | -25.2% |
| 256-512 | encrypt | -23.0% | -4.6% |
| 256-512 | decrypt | -2.2% | -3.2% |
| 512-512 | encrypt | +2.8%* | +1.5% |
| 512-512 | decrypt | -23.0% | -22.3% |

Binary-level deltas track criterion's direction on all ten cells and are the same order of
magnitude, though individually noisier (single-run OS-level timing vs. criterion's statistical
sampling) - 256-512 shows a smaller win binary-level than in criterion for both directions, and
256-256 the reverse, but neither flips sign or crosses into "contradicts the finding" territory.

**A `kalyna_256_256_encrypt_block_only` anomaly (~486-530 ns, vs. ~163 ns expected) surfaced on two
criterion reruns later in the same session and was chased down, not filed as an open question** -
`advisor()` correctly refused to accept an "icache pressure, not a code defect" hypothesis without
the isolating check: `cargo bench -p dstu-core --bench kalyna -- kalyna_256_256_encrypt_block_only`
run *alone* (nothing else in the binary's hot path) still reproduced ~480 ns, ruling out
cross-benchmark interference outright - the hypothesis this entry originally reached for was wrong.
**Root cause, found by disassembling the actual binary being measured**: `objdump -d` on the bench
executable showed `encrypt_with_scheduleKj2_`/`Kj4_`/`Kj8_` symbols *without* the `NR`-encoding
mangled suffix (`Kja_`/`Kje_`/`Kj12_`) - the pre-T171 signature shape. The binary being measured was
stale, left over from the `git stash`/`git stash pop` A/B dance used earlier in this same entry to
capture the "before" column of the cppcrypto/baseline comparison tables above - `cargo bench`'s own
change-detection didn't trigger a recompile across that stash/pop cycle in this instance. Forcing one
(`touch crates/dstu-core/src/hazmat/kalyna.rs`, then re-running) immediately produced ~156 ns, in
line with this entry's own originally-published ~163 ns finding - confirmed by a full baseline
re-save afterward, every cell landing within normal run-to-run noise of the numbers already
published above (58-486 ns range, all within a few percent). No code defect, no icache effect, no
open question - a build-hygiene gap in the investigation process itself, now closed. Lesson for any
future A/B comparison built on `git stash`/`git stash pop`: force a rebuild (`touch` the changed
file, or check the compiled binary's own symbol names) before trusting a benchmark number that
follows a stash cycle, don't assume `cargo`'s fingerprinting caught the change.

\* Within/near criterion's own 95% CI overlap for that one cell (unforced upper bound 481.2ns vs.
stage-b lower bound 482.4ns - a small but plausibly real regression, not pure noise), directly
explained by the `NB=8` non-inlining finding above, not a red flag on the rest of the result. Not
pursued further (e.g. forcing `#[inline(always)]` on `NB=8`'s `encipher_round_n`) since Stage A
already showed `NB=8` encrypt gets no benefit from unrolling and forcing the inline would only add
more code size for a variant that doesn't want it - consistent with, not contradicting, the
`small-tables` size decision above.

**Net**: T-172 answers its own question conclusively - genuine (never-a-loop) unrolling is a real,
substantial win (21-35%) for four of Kalyna's five variants and roughly neutral (one flat/slightly-
negative cell, one strong win) for the fifth, entirely explained by LLVM's per-instantiation
inlining-cost decision, not a mechanism failure.

**Re-measurement against D-154's own cppcrypto numbers, same session (user-requested follow-up,
"порівняння бінарників за нашим стандартом з cppcrypto")**: D-154's scratchpad harness didn't
survive across sessions, so re-built from scratch - re-downloaded `cppcrypto-0.20-src.zip`,
confirmed byte-identical to D-154's own pinned copy (sha256 `cb4d5b54...fde65fd5` matches exactly),
re-wrote a throwaway `bench.cpp` against the unmodified `kalyna.cpp`/`kupyna.cpp`/`block_cipher.cpp`
files, same D-34/D-80 methodology as D-154 (`init` excluded from the timed window, cached-schedule
encrypt/decrypt, N=300000 this time vs. D-154's N=20000). Correctness not independently re-verified
this pass (D-154's own 20/20-vector confirmation already covers this exact unmodified source), and
this bench run was deliberately sequenced *after* the concurrent Miri run above finished (D-30's own
documented CPU-contention pitfall) - both baseline and Stage B `uacrypt` numbers were re-measured
fresh in the same clean window, not reused from the table above, so this is a real same-session,
same-machine, all-three-way comparison:

| Variant | Direction | `uacrypt` before | `uacrypt` after (T-172) | cppcrypto | Gap before | Gap after |
|---|---|---:|---:|---:|---:|---:|
| 128-128 | encrypt | 71 ns | 59 ns | 44 ns | 1.61x | **1.34x** |
| 128-128 | decrypt | 85 ns | 61 ns | 57 ns | 1.49x | **1.07x** |
| 128-256 | encrypt | 100 ns | 81 ns | 61 ns | 1.64x | **1.33x** |
| 128-256 | decrypt | 114 ns | 85 ns | 75 ns | 1.52x | **1.13x** |
| 256-256 | encrypt | 218 ns | 180 ns | 127 ns | 1.72x | **1.42x** |
| 256-256 | decrypt | 210 ns | 157 ns | 148 ns | 1.42x | **1.06x** |
| 256-512 | encrypt | 281 ns | 268 ns | 166 ns | 1.69x | 1.61x |
| 256-512 | decrypt | 251 ns | 243 ns | 186 ns | 1.35x | 1.31x |
| 512-512 | encrypt | 459 ns | 466 ns | 348 ns | 1.32x | 1.34x |
| 512-512 | decrypt | 627 ns | 487 ns | 372 ns | 1.69x | **1.31x** |

**The gap genuinely closed on 7 of 10 cells**, most dramatically on `NB=2`/`NB=4` decrypt (128-128
and 256-256 decrypt both land near parity, 1.06-1.07x) - Kalyna is no longer "cppcrypto wins every
cell by 1.3-1.9x" (D-154's original framing); it's now a mixed picture matching the mechanism found
above almost exactly. The 3 cells that didn't move (256-512 both directions, 512-512 encrypt) are
precisely the ones this entry's own `NB=8`-non-inlining finding and Stage A's own flat result
predicted wouldn't - 256-512 pairs `NB=4` with `NR=18` (the largest per-round-count instantiation at
that width) and showed the smallest criterion win of the four `NB=2`/`NB=4` cells too (-23.0%/-2.2%,
smallest in that group), consistent rather than contradicting. Remaining gap is concentrated exactly
where the mechanism says it should be, not scattered randomly - real, if incomplete, confirmation
that the diagnosis is right, not just that the numbers moved.

## D-162: T-173 - local OCR transcript of DSTU 9041:2020, tooling gotchas

Owner asked to OCR-transcribe `docs/papers/DSTU_9041-2020.pdf` (the purchased/library-scanned
primary standard text, T-46's cited blocking source) locally, using Surya OCR, spot-checked
against PaddleOCR, saved as a page-numbered Markdown file and kept out of git (same redistribution
restriction as the source PDF itself). Full task record: `docs/TASKS.md` T-173. This entry is the
tooling/methodology detail T-173 points back to.

**Status of the standard itself is unchanged**: this is a reading aid, not a new oracle. It does
not unblock `hazmat::dstu9041` (D-08/T-46's "zero source material" framing stands), for the same
reason a transcript of a secondary source didn't unblock it in T-148/D-105 - a transcript of the
*primary* text still has no independent oracle to verify it against, and the OCR process itself
introduces its own error class on top.

**Tool choice and why it needed research first** (see also
`feedback_use_local_recognition_tools` in project memory): local tools were used instead of any
web-based OCR converter specifically to avoid uploading a redistribution-restricted state-standard
scan to a third party - the same reasoning already applied to the PDF itself never being committed.

**Gotchas hit, in the order they were found**:

1. **`surya-ocr`'s current PyPI release (0.2x) is architected around a VLM served through
   `llama.cpp`/`vLLM`**, not a local model call - it raised `SpawnError: llama-server binary not
   found` on first run. Neither backend is viable on this machine (no `llama-server` binary
   available for Windows without a separate manual build/download, and `vLLM` needs a GPU this
   machine doesn't have in a supported class - see gotcha 6 below). Fix: pin
   `surya-ocr==0.13.1`, the last release whose CLI (`surya_ocr --langs uk`) calls a local
   transformers recognition model directly, no server subprocess.

2. **A full 27-page run (`surya_ocr` given the whole PDF at once) segfaulted (exit 139) partway
   through the detection pass**, once resident memory passed roughly 11GB with only ~10GB free at
   the time - no Python traceback, a native-level crash invisible to any `except` block. Root cause
   not fully isolated (plausibly an internal allocation failure inside a native op, given each page
   image is 3893x5633px at the 150 DPI render used) - not filed upstream, out of scope for a
   one-off local task. Fix: split the run via the CLI's own `--page_range` flag into five
   sequential invocations (6 pages each except the last, 3), one `--output_dir` per chunk, merged
   back into page order by the chunk's known page range afterward. Peak RSS dropped to ~4.3GB per
   chunk; all five completed cleanly with `results.json` written each time.

3. **`paddleocr` 3.x's default pipeline** (`PaddleOCR(lang=...).predict(...)`, which runs on
   paddlepaddle's newer PIR-based CPU executor with oneDNN) **threw `NotImplementedError:
   ConvertPirAttribute2RuntimeAttribute not support [pir::ArrayAttribute<pir::DoubleAttribute>]`**
   on the very first real detection call - a genuine CPU-backend bug in that specific
   paddlepaddle/paddleocr version pairing on this machine, not a usage mistake (the same call
   pattern works in PaddleOCR's own documented examples). Fix: downgrade to the older, stable
   `paddlepaddle==2.6.2` + `paddleocr==2.9.1` pair, which uses the classic `.ocr(path, cls=False)`
   API and does not go through the PIR executor at all.

4. **PaddleOCR's bundled `cyrillic` recognition model's character dictionary**
   (`ppocr/utils/dict/cyrillic_dict.txt`, 164 entries) **includes `Є/є`, `І/і`, `Ґ/ґ` but has no
   entry for `Ї/ї` at all** - confirmed by reading the dict file directly, not inferred from
   output. Any Ukrainian word containing "ї" is therefore structurally miswritten by this model, a
   dictionary gap rather than a per-word confidence issue. Recorded so a future cross-check never
   trusts PaddleOCR's `cyrillic` model over Surya specifically on words containing "ї" - and so
   nobody re-diagnoses this same gap as a bug in the calling code.

5. **A first attempt at automatically flagging Surya's unreliable lines used raw per-line OCR
   confidence (`< 0.85`) as the threshold - far too broad**, flagging roughly 180 of ~2100 lines,
   the great majority of which were genuinely correct Ukrainian technical prose that merely scored
   lower because of interspersed formulas/numbers/single-letter math variables, not because they
   were wrong. Replaced with a detector targeting the two hallucination signatures actually
   observed by inspection: (a) any character outside an allowlist covering Cyrillic, Latin, Greek
   (used as math variable names throughout this standard), digits, and a fixed set of punctuation/
   math-operator characters (catches genuine script hallucination - Bengali, CJK, Japanese
   long-vowel marks used as filler/border lines - directly, since those scripts fall well outside
   the allowlist), and (b) a single token repeated across more than half of a line's tokens
   (catches degenerate `= = = = ...` / `1 1 1 1 ...` hallucinated tails). The allowlist needed two
   widening passes after the first result flagged legitimate content (Greek letters, curly
   quotes/apostrophes, √±·×÷ and similar math operators are genuine parts of this standard's own
   notation, not hallucination) before landing at 45 flagged lines across 15 of 27 pages - low
   enough to be a real signal rather than noise. Page 1 was spot-checked directly against its
   rendered scan image before trusting the detector across the rest of the document: all three
   flagged lines on that page were genuine problems (subscript digits `i₆`/`i₀` misread as `16`/
   `lo`, `∈` misread as `€`, and two hallucinated `= = = =` tails), and no unflagged line on that
   page was actually wrong in the sample checked - both the detector's positives and negatives held
   up under direct visual comparison.

6. **A whole-page `difflib.SequenceMatcher` character-ratio between Surya's and PaddleOCR's
   concatenated per-page text was tried first as an automatic per-page quality signal, and
   abandoned** - it returned a uniformly low ratio (0.01-0.20) across all 27 pages, including pages
   later confirmed clean by direct visual inspection. The metric appears to be dominated by
   line-ordering and formatting differences between the two engines' output rather than by real
   content divergence, making it useless as a quality signal at the whole-page-string level.
   Recorded so a future session doesn't reach for this same comparison shape without re-deriving
   whether it's actually informative first.

7. **AMD ROCm was investigated and ruled out** for this task before any OCR ran, in response to the
   owner surfacing a (correct-for-Linux, not-for-this-machine) suggestion to install ROCm-enabled
   PyTorch for GPU acceleration. This machine's GPU is an AMD Ryzen 5 PRO 4650U's integrated Radeon
   Graphics (Renoir, `gfx90c`). AMD's own Windows ROCm/PyTorch support matrix (checked directly,
   not from memory) covers only Radeon RX 9000/7000 discrete GPUs and Ryzen AI APUs with
   `gfx1150`/`gfx1151` (the 2025+ Ryzen AI 300/Max generation) - `gfx90c` is several generations
   older and absent from that list entirely, on Windows or otherwise; a documented Linux-only
   community workaround for `gfx90c` (forcing `HSA_OVERRIDE_GFX_VERSION=9.0.0`) does not apply here
   since this session runs on Windows. `torch-directml` (DirectX 12, cross-vendor) was named as the
   realistic alternative but not attempted - the owner declined once the CPU chunked pipeline
   (gotcha 2) was already working reliably, and DirectML's narrower op coverage plus this iGPU's
   modest compute budget made the expected win small relative to the setup/failure risk. A RunPod
   (rented cloud GPU) alternative was also proposed and declined for this task: real per-minute
   cost requiring a payment method and account setup neither available nor something to set up
   unilaterally, and - independently of cost - uploading a redistribution-restricted scan to a
   third-party cloud runtime reintroduces exactly the exposure gotcha-0's local-tooling choice was
   meant to avoid.

## D-163: T-174 - DSTU 9041 extraction/verification: copyright framing, curve math, erratum found

**Copyright framing, decided before any extraction work started**: the owner's own framing -
copyright covers the standard's specific prose/expression, not the algorithm, its parameters, or
its test vectors (facts) - is the same idea-expression distinction this project already relies on
throughout `docs/papers/*.pdf` handling (the PDFs themselves never committed; extracted vectors and
pseudocode committed freely, e.g. Kalyna/Kupyna/DSTU-4145's own `tests/vectors/*.json` and
`docs/pseudocode/*.md`). Applied here identically: `docs/papers/DSTU_9041-2020.pdf` and its OCR
transcript stay gitignored (T-173/D-162); `docs/pseudocode/dstu9041.md` (algorithm structure,
resolved ambiguities, cited clause numbers) and `crates/dstu-core/tests/vectors/dstu9041/*.json`
(curve parameters, worked-example data) are committed freely, following the exact precedent already
established for every other DSTU algorithm in this repo.

**Why direct page-image transcription was necessary, not OCR text order.** `advisor()` flagged this
before any numeric work started: cryptographic curve parameters need per-digit verification, and
the gitignored OCR transcript's own table cells come out of Surya in a scrambled column order for
multi-column tables (confirmed in D-162's own findings) - unusable for this without re-deriving
structure. Direct image transcription turned out to have the **same** failure mode OCR has for long
runs of an identical character: a first manual read of `p` (Table B.1/Annex Г.1's `l(p)=256` prime)
counted roughly 87 hex digits instead of the correct 64 (a leading run of 61 `F`s misjudged by
eye), and `n` similarly over-counted its zero-run by more than 50 digits. Both were only caught
because the resulting integers failed a primality check outright - **the empirical check is what
caught the transcription error, not increased care in reading**. Fixed by writing a small Python/
PIL script that binarizes a cropped page-image row and counts vertical whitespace gaps between
character strokes - an objective column-darkness stroke count, not a human/AI eyeball count -
which nailed both runs exactly (61 and 31 respectively) and let every subsequent check
(primality, curve-membership, scalar multiplication) pass cleanly. **Generalize this: any future
transcription of a long same-character run (repeated digit/zero/F runs, common in cryptographic
moduli) should be stroke-counted programmatically, never eyeballed, regardless of whether OCR or a
human/AI vision read produced the candidate value.**

**Curve equation form - a real, non-obvious pitfall, not a typo.** DSTU 9041's own equation is
`x²+a·y²=d·x²·y²+1` (clause 5.5, confirmed against the page image) - the *textbook* twisted-Edwards
form (Bernstein-Lange and most implementations, including what a search for "twisted Edwards
addition formula" returns) is `a·X²+Y²=1+d·X²·Y²`, with `a` attached to `X` (the *first* named
coordinate), not `Y` (the *second*, as DSTU 9041 has it). These are the same curve family with `x`
and `y` swapped - **applying the textbook addition formula directly, without noticing the swap,
produces a formula that looks plausible, runs without error, and returns wrong points for every
scalar multiplication.** This is exactly what happened on the first implementation attempt this
session: individual points (`P`, `Q`, `R`, `T` from Annex Г.1) all correctly satisfied the curve
equation (so the *equation* transcription was right), yet `7·P != R` and `7·Q != T` under the
naive formula. Re-derived properly by substitution (`X=y, Y=x` maps DSTU 9041's curve exactly onto
the textbook form) and re-verified: correct addition law is
`x3=(x1x2-a·y1y2)/(1-d·x1x2y1y2), y3=(x1y2+y1x2)/(1+d·x1x2y1y2)`, and the neutral element is
`(1,0)`, not `(0,1)` (also swapped). **The lesson generalizes beyond this one curve**: whenever a
non-normative-source curve equation doesn't match a well-known reference form character-for-
character, check for a coordinate swap or sign convention difference before assuming the textbook
addition law applies - a curve-membership check alone does not catch this, only testing actual
scalar multiplication against an independent worked example does. `docs/pseudocode/dstu9041.md`
now states the derivation and the citation (Додаток Б.4's own projective addition formula, present
in the primary text, independently confirms the same swapped form once derived) rather than only
the equation.

**`d`'s hex-vs-decimal convention almost caused a second false negative.** Annex Г's own intro
states every parameter in its worked examples is given in hex, "each four bits as one hex digit" -
but the *curve equation itself* (`x²+2y²=18x²y²+1`, printed inline in prose, not in the
hex-labeled numeric tables) doesn't repeat that label locally. Read `d=18` as decimal on the first
attempt (curve-membership check failed for every point); solving `d` directly from the base point's
own coordinates and the equation (`d = (x²+a·y²-1)·(x²y²)⁻¹ mod p`) gave `24` - i.e., `0x18` -
confirming the hex convention applies here too, silently, with no local label. **Any bare small
integer appearing inline in this standard's prose should be assumed hex, not decimal, unless
proven otherwise** - the reverse of most technical documents' convention, and easy to get backwards
without the equation-solving cross-check that caught it here.

**Addendum, same day: the "erratum" above was this project's own misread, not the standard's -
caught by following through on the owner's direct request to resolve `t` rather than leaving it
open.** Annex Г states plainly that every parameter in its worked examples is hex, four bits per
digit - already correctly applied to `d=0x18=24` earlier in the same verification pass - but a
first read of `e=25` didn't re-apply that same rule and flagged a false inconsistency instead.
`e=0x25=37` decimal, and `37·P == Q` holds exactly: **there is no `e`/`Q` erratum at all.** Left in
this log rather than deleted, because the failure mode is the actual lesson: finding a convention
once does not mean it gets applied every time it recurs in the same document - each occurrence
needs the same check applied fresh, not assumed carried-over from memory.

**The real erratum, found while resolving `t`: a single dropped hex digit in Annex Г.1's own
printed ciphertext, confirmed against this project's own `hazmat::kalyna_kw` - not left
unverified.** The prior version of this entry reported `t` as unverified (odd hex-digit count,
~190 digits, cause unisolated). Root cause found: the actual Kalyna-256/256-KW plaintext is **not**
`M'` alone (one 256-bit block) but `M' ‖ 0x00×32` - `M'` padded with a full second all-zero
256-bit block, making the real KW input 64 bytes (2 blocks), which correctly wraps to 96 bytes (3
blocks) per DSTU 7624's own `n=2(1+r)` block-count rule. Computing `Kalyna256_256Kw::wrap` (this
crate's own code, unmodified) on that 64-byte input reproduces the standard's own printed `t`
**exactly**, once one specific single hex digit the source is missing (`0`, silently dropped
between `...B3CE` and `F710...` in the printed text) is restored - confirmed by inserting the
digit back and diffing all 192 hex digits against this project's freshly-computed value: exact
match, not merely "looks close." **This is now a real, independently-confirmed second erratum in
the standard's own published informative annex** (a genuine single-character print/scan-level
drop, reproduced identically across repeated independent re-reads of the same page image before
concluding the source has the error, not this project's transcription) - and simultaneously the
strongest evidence yet that `hazmat::kalyna_kw`'s Kalyna-256/256-KW implementation is bit-exact
with the standard's own construction, not merely self-consistent. `t`/`C` are committed in
`crates/dstu-core/tests/vectors/dstu9041/g1-worked-example.json` with the digit restored and both
the erratum and the correction documented inline - not omitted, per the owner's explicit request to
resolve this rather than leave it as a standing gap.

**One genuine open question remains, clearly separated from the resolved erratum above**: *why*
the real Kalyna-KW input needs that second all-zero block at all - clause 5.7/5.8/Table 1 alone
only account for a 32-byte (1-block) `M'`, with nothing in the scanned text explaining the extra
block. Two live hypotheses, neither confirmed: DSTU 7624's own KW mode may have an unstated 2-block
minimum specific to how DSTU 9041 invokes it (Bouncy Castle's own `DSTU7624WrapEngine` imposes no
such minimum on generic KW, so this would be a DSTU 9041-specific rule, not inherited); or clause
11's own wording (not fully captured by this document's transcription) specifies an additional
padding field this pass missed. Needs either the still-missing clauses 6.5-6.12 or a fresh, careful
full re-read of clause 11 before this is settled - recorded as open, not guessed at, matching this
entry's own standard for every other gap.

**Scope deliberately not started this session, per the project's own Tier C precedent**: writing
`hazmat::dstu9041` (or its two real new prerequisites, `F_p` bignum arithmetic and
`hazmat::kalyna_kw_p`) needs its own `advisor()` + plan-mode pass first, same bar T-172 and earlier
primitive work already cleared before any code was written - this session's own scope was
extraction and verification only, per the owner's explicit sequencing request.

## D-164: T-175 - a genuinely stuck local `cargo miri test -p dstu-core-capi` process, two distinct
uncovered root causes, both fixed and confirmed by a clean re-run

**Found, not caused, by this session**: a `cargo +nightly miri test -p dstu-core-capi` process left
running from a previous session, flagged by the owner ("it's been going a long time, we were
measuring how long it takes so we could fix it"). Measured before touching anything: `miri.exe` had
accumulated 38468 CPU-seconds (~641 CPU-minutes, ~10.68 hours) over 649.3 minutes wall-clock and was
still climbing - roughly 7.6x D-59's own "~84 min measured locally" figure for the equivalent
`dstu-core` suite, on a C ABI crate whose own test file is a thin FFI wrapper layer, not new crypto
math.

**Root cause 1 (found first): the C ABI crate's own FFI tests never inherited D-59's `Point::
scalar_multiply` exemption.** `crates/dstu-core-capi/tests/ffi_tests.rs` has two tests routing
through `crypto_sign`'s FFI wrappers - `sign_verify_round_trip_and_forgery_rejection`
(`dstu_sign_key_generate` x2, `dstu_sign`, `dstu_verify` x2) and
`sign_digest_matches_sign_of_the_same_hash` (`dstu_sign_key_generate`, `dstu_sign_digest`,
`dstu_verify_digest`) - both reach DSTU 4145's 163-iteration EC ladder the same way `dstu-core`'s own
`crypto_sign.rs`/`dstu4145_signature.rs` tests do, but this file never got the identical
`#[cfg_attr(miri, ignore = "..."]` attribute those two files already carry. A real coverage gap
introduced when T-158 added the C ABI crate's FFI suite without carrying that exemption over - not a
new bug in the ladder itself. Fixed by adding the same attribute (same message, same T-100 citation)
to both tests.

**That fix alone was insufficient - a second, distinct root cause was still present.** Killed the
stale processes (`taskkill`) and re-ran with just that one fix; the new run reached ~103 CPU-minutes
before being killed again and re-diagnosed, because its output had been piped through `| tail -40`
(the same class of mistake previously fixed on an unrelated Surya-OCR run this session) - `tail`
buffers until EOF, so the run was invisible for its entire duration even though `target/miri`'s file
timestamps and `miri.exe`'s steadily climbing memory/CPU proved it was genuinely computing, not
hung. Re-run a second time with output redirected directly to a file (`> log 2>&1`, no pipe) and
`--test-threads=1`: the log showed execution stopped, unfinished, on test #8 of 17 -
`pwhash_hash_and_verify_round_trip_and_rejects_wrong_password`.

**Root cause 2: Argon2id under Miri, not the EC ladder.** `dstu-core-capi/Cargo.toml`
unconditionally enables dstu-core's `pwhash` feature (`features = ["std", "selftest", "pwhash"]`),
so this crate's FFI test suite runs an Argon2id hash (`Strength::Interactive`, m=65536 KiB) that
`dstu-core`'s own default-feature miri run never exercises (`pwhash` is opt-in there, off by
default - this asymmetry is why `dstu-core`'s ~84-minute figure never surfaced this problem: the
combination that triggers it only exists in `dstu-core-capi`, D-74's "an untested feature
combination can hide a real problem" pattern recurring). Argon2id's memory-hardness (64 MiB working
buffer by design) combined with Miri's own per-byte provenance tracking over that whole allocation
made this single test intractably slow to interpret - unrelated to `Point::scalar_multiply` and
needing its own citation, not a copy-pasted "163-iteration ladder" reason (D-25's discipline on
not reusing a wrong justification because it happens to produce a passing-looking fix). Fixed with
its own `#[cfg_attr(miri, ignore = "...")]`, citing the actual mechanism (memory-hard KDF + Miri
provenance tracking over a 64 MiB buffer), not the unrelated ladder.

**A third candidate was checked and cleared, not assumed safe.** `selftest_passes` calls
`dstu_selftest()`, which per this crate's own contract re-verifies DSTU 4145's Annex B.1 vector -
also a path through the EC ladder, and also missing any pre-existing exemption. Left deliberately
unflagged and verified empirically rather than pre-emptively ignored: the clean re-run's log shows
`test selftest_passes ... ok`, completing as part of the suite's overall 505.81s - a single
Annex-B.1-vector verify call is cheap enough under Miri that it does not need the same treatment as
the round-trip tests that call keygen/sign/verify multiple times each. Recorded here so a future
session doesn't have to re-derive this the same way, and doesn't mistakenly add an unneeded
exemption "to be safe."

**Confirmed by a real clean re-run, not assumed from the diagnosis**: `cargo +nightly miri test -p
dstu-core-capi`, redirected properly this time, finished in **505.81s (~8.4 minutes)** -
`ffi_tests.rs`: 14 passed, 0 failed, 3 ignored (the two `crypto_sign` tests plus the new `pwhash`
test), 0 measured, 0 filtered out. Down from a process that had already run 649.3 minutes / 10.68
CPU-hours without ever finishing. Same "verify, don't assume" standard as this file's own
CI-conclusion rule (T-100/D-59's own precedent) - the fix was not declared done until an actual green
run existed, not once the diagnosis merely looked right.

**Follow-on hardening, done the same session so this class of problem localizes faster next time**:
`cargo xtask miri` now takes an optional package argument (`cargo xtask miri dstu-core-capi` runs
`-p <pkg>` instead of `--workspace`), and `.github/workflows/rust.yml`'s `miri` job is now a
per-crate matrix (`dstu-core`, `uacrypt`, `dstu-core-capi`, `fail-fast: false`) instead of one
combined job/log - so a future stuck test in any one crate shows up as its own failing job instead
of being indistinguishable from the other two crates' results inside a single `--workspace` log, the
exact diagnostic friction this incident actually had.

## D-165: T-176 - targeted DSTU 9041 supplement purchase closes clauses 6.5-6.12, the biggest gap
D-163 left open

**What was bought and why.** D-163/T-174's extraction explicitly listed clauses 6.5-6.12 (the actual
random-element/modpow/sqrt/inverse/random-point/primality/MOV/scalar-mult algorithms) as the single
biggest hole in the scan - present only as call sites ("відповідно до 6.9/6.10/..."), never as
bodies. The owner bought a second, smaller, targeted set of pages from the same source (National
Library of Ukraine's electronic-document-delivery service) aimed specifically at that gap plus a
short prioritized list (section 3's remaining terms, Додаток Б.1/Б.2, Додаток А/Д for reference) -
not a re-purchase of the whole standard. Received as `docs/papers/DSTU_9041-2020_supplement.pdf`
(8 pages), gitignored under the same reasoning as the main scan (`.gitignore`'s existing DSTU 9041
block, extended). OCR-transcribed the same way as T-173 (same reused Surya venv,
`docs/papers/DSTU_9041-2020_supplement_ocr.md`, also gitignored) for searchability, but - per D-163's
own already-established rule - **the actual clause text going into `docs/pseudocode/dstu9041.md`
was read directly from the rendered page images, not the OCR transcript**, same discipline as
before.

**Confirming a supplier can genuinely target a gap, not just re-sell the same pages.** Before
trusting this was new material, checked page footers against the existing PDF's own page range
(4-30, missing exactly pages 8-10 where 6.5-6.12 live) - the supplement's images print footer page
numbers 1-3, 8-10, 15, 36, confirming deliberate curation around the documented gap list rather than
a random or duplicate page set. Worth recording as a general lesson: when a same-source
supplementary purchase arrives, verify its actual page numbers against what's already in hand before
assuming it's redundant or assuming it's exactly what was asked for - check, don't infer either way.

**Result: clauses 6.5-6.12 are now clause-cited in full**, not reconstructed from first principles.
Two genuinely new findings while cross-checking against the text (neither obvious from the equation
alone): (1) clause 6.9's random-curve-point algorithm retries when `d*u^2 mod p = a`, which is
exactly clause 3.18's singular-point exclusion (`D_{1,2}=(±sqrt(a/d),infinity)`) enforced by
construction - previously this project only inferred those points needed excluding, never saw the
standard actually do it; (2) clauses 6.6 and 6.12 both carry the standard's own explicit
side-channel warning, citing Joye & Yen's "The Montgomery Powering Ladder" (Додаток Д's bibliography
entry `[1]`, now also in hand) - the standard's own primary text making the same point this
project's `docs/SECURITY.md` constant-time rule already makes generally, which is a stronger
citation than this project had before (previously argued from general no-secret-branching principle
alone, now backed by the standard naming the exact same countermeasure).

**Also resolved, lower stakes**: Додаток А's RNG body (full Kalyna-l/k-CTR construction per DSTU
7624 §7, Table А.1's `l`/`k` choices per `λ`) - was previously title-only. Not adopted (this
project's existing `randombytes::randombytes_buf` remains simpler and clause 6.1 permits the
substitution explicitly), but now a documented option rather than an unknown. Section 3's remaining
terms (3.1-3.26) joined 3.27/3.28 already in hand - section 3 is now complete, though this was
always administrative/definitional, not implementation-blocking.

**Only partially resolved, and recorded honestly rather than overclaimed**: the one supplement page
touching Додаток Б only reached its introductory historical prose (a literature survey - Edwards,
Bernstein-Lange, Bessalov), cutting off mid-sentence before whatever Б.1/Б.2 themselves formally
define. The operative content of Додаток Б (Б.3's correctness proof, Б.4's projective addition law)
was already in hand from T-174 - this gap is now believed low-value even if eventually closed.

**What this task deliberately did not touch**: the open question of why Kalyna-KW's input needs an
extra all-zero block (that's clause 11, not 6.5-6.12), the missing `l(p)=768` worked example, `t`/`C`
arithmetic re-verification, `hazmat::kalyna_kw_p`, and the `F_p`/twisted-Edwards primitives
themselves. None of those are clauses 6.5-6.12, so closing this gap doesn't move them - per this
project's own Tier C precedent, no Rust implementation was started this session either.

## D-166: T-177 - E256/1's `p`/`n` were wrong in the committed vector JSON for two sessions; a
described fix that never reached the file

**What was found, and when.** While starting T-177's actual Rust implementation (plan-mode design
pass, before any code was written), re-deriving `p`/`n` as an independent sanity check turned up a
discrepancy: the committed `crates/dstu-core/tests/vectors/dstu9041/curve-E256-1.json` had
`p_hex` with **87 hex characters** (348 bits) and `n_hex` with **113 hex characters** (451 bits) -
neither anywhere close to the 256-bit field this curve is supposed to be (`l(p)=256`, E256/1,
λ=127). `docs/pseudocode/dstu9041.md`'s "Recommended curve" section had the identical wrong
strings (same source, copied at the same time).

**Why this passed every prior check.** All five of D-163's original `verified_checks` are
individually insensitive to exactly this class of error: `p mod 8 == 5` only depends on the last
hex digit, unaffected by how many extra `F`s precede it; a 3-base Fermat primality check has a
real (if small) false-positive rate and evidently hit one here; the on-curve/order checks
(`base_point` on curve, `n·base_point == neutral`) were run with `p`/`n` as read from memory
during that scratch session, not necessarily re-read from the file being written - so an internal
verification could have genuinely passed against correct in-memory values while a *different*,
wrong string got typed into the committed JSON afterward. Every check that could have caught a
wrong modulus either didn't exercise it or wasn't re-run against the file as committed.

**The actual bug: D-163 already found the correct lengths and never used them.** D-163's own prose
states the stroke-count exercise "nailed both runs exactly (61 and 31 respectively)" for `p`'s
`F`-run and `n`'s `0`-run. The committed file has 84 `F`s and 80 `0`s. **61 and 31 are the correct
values** - re-derived independently this session by a different method (Table В.1's own *decimal*
column, converted to hex, cross-checked against a real 40-round Miller-Rabin and the Hasse-interval
relationship `4n ≈ p+1`, not stroke-counted pixels) and landing on exactly the same answer D-163
already had. The lesson isn't "stroke-counting doesn't work" - it worked, twice, by two different
methods. **The lesson is that a documented fix needs to be verified as actually present in the
file it was fixing, not just correct in the reasoning that produced it** - D-163's own text
describes the right numbers; the JSON and the doc's code block simply never got updated to match,
and this went uncaught through T-175 and T-176 because neither of those tasks had a reason to
recompute `p`/`n` from scratch.

**How this was caught.** Not by re-reading the page image again first - by an arithmetic sanity
check (`p.bit_length()` computed as part of ordinary plan-mode research, expected 256, got 348)
that would have failed regardless of which session introduced the error. Confirms this project's
own standing lesson generalizes: *any* claimed cryptographic parameter should be sanity-checked
against an independent property (bit length, a known relationship like the Hasse bound, a real
primality test) before code is written against it - not just trusted because a prior session's
prose says it was already fixed.

**Verification performed on the correction** (not just on finding the bug): real Miller-Rabin
(40 rounds, not 3-base Fermat) confirms both corrected `p` and `n` are prime; `p mod 8 == 5` still
holds; `4n` sits within the Hasse-bound distance of `p+1` (previously off by roughly 10^76, now
off by roughly 2×10^38 ≈ 2^128, consistent with `p`'s own size); the base point and every point in
`g1-worked-example.json` (`Q`, `R`, `T`) satisfy the curve equation under the corrected `p`;
`n·P == neutral`; `37·P == Q`; `7·P == R`; `7·Q == T` - the entire worked example re-verified
end-to-end against the corrected values, not just the curve parameters in isolation.

**Fixed**: `curve-E256-1.json`'s `p_hex`/`n_hex`, `docs/pseudocode/dstu9041.md`'s "Recommended
curve" code block, both with an inline erratum note pointing here.
`g1-worked-example.json` needed no change - it stores points/messages/ciphertext, never `p`/`n`
directly.

## D-167: T-177 - `hazmat::dstu9041` (`l(p)=256`) implemented, plus two security findings beyond clause 12's literal text

**What was built.** `hazmat::dstu9041` (E256/1 only, D-47's "ship the recommended curve first"
precedent, same posture as `hazmat::dstu4145`'s m=163-only scope) is now implemented and
test-first, phased, one commit per phase: `message.rs` (`M'` formatting, the Kalyna-KW
`M'||0x00×32` zero-block quirk - an empirical fact confirmed against `hazmat::kalyna_kw`, not yet
explained from a cited clause, D-165's own open question), `fp256.rs` (`F_p` arithmetic for
`p=2^256-435`, a pseudo-Mersenne-adjacent prime - `multiply`/`square` via schoolbook wide-multiply
plus a Solinas-style reduction exploiting `2^256≡435 (mod p)`; `invert` via Fermat; `sqrt`/
`euler_criterion` via the `p≡5 (mod 8)` formula; `pow_mod` a fixed-256-iteration constant-time
ladder), `curve256.rs` (twisted Edwards point arithmetic, Додаток Б.4's complete addition law -
handles doubling/neutral uniformly since `d` is a non-square, fixed-256-iteration
`scalar_multiply`), `encryption.rs` (clauses 11/12's encrypt/decrypt composition). Verified
end-to-end against the standard's own Додаток Г worked example - the sole oracle for this
primitive (`docs/ORACLES.md`, no independent DSTU 9041 reference implementation exists anywhere,
confirmed again as part of this task's own closure). Plan-mode design pass with `advisor()`
consultations before Phase 2, after Phase 3/4, and at closure - not a single up-front review.

**Finding 1 - `r=p-1` reconstructs an order-2 point outside `⟨P⟩`.** Clause 12 step 2 rejects
`r=0`, `r=1`, and `r²=a·d⁻¹ (mod p)` - but not `r=p-1`, which reconstructs to `R'=(p-1,0)`, a
genuine order-2 point outside the base point's own subgroup (proved arithmetically in
`tests/dstu9041_curve.rs`'s `r_equals_p_minus_1_reconstructs_the_order_2_point`, and independently
by clause 12 step 4's own `euler_criterion` check, which happens to reject `δ=0` as a side effect).
Left unrejected, a chosen-ciphertext query with `r=p-1` would leak the private key's parity bit via
whether `T'=e·R'` lands on `R'` (e odd) or `NEUTRAL` (e even). Fixed as an explicit fourth rejection
case in step 2, kept even though step 4's stricter-than-literal form incidentally also catches it -
an explicit, self-documenting check rather than relying on an incidental side effect to carry the
argument.

**Finding 2 - the bigger one, found by a second `advisor()` review after Phase 3/4 landed: E256/1
has cofactor 4, so genuine order-4 points exist and are reachable via a crafted `r`.** `#E(F_p)=4n`
is the unique multiple of `2n` inside the Hasse interval (checked exhaustively for every `k` up to
20; only `k=2` lands `2n·k` in `[p+1-2√p, p+1+2√p]`). The curve's only `y=0` solutions are `x²=1`,
i.e. `x∈{1,p-1}` - exactly `NEUTRAL` and the order-2 point from Finding 1, no third one. A finite
abelian group of order `4n` (`n` an odd prime) has a 2-Sylow subgroup that is either cyclic (`Z/4`,
one non-trivial order-2 element) or Klein four (`Z/2×Z/2`, three) - since there is provably only
one order-2 element, the 2-Sylow subgroup is `Z/4`, making `E(F_p)` cyclic of order `4n` overall,
and a cyclic group of order `4n` genuinely has order-4 elements. An unrejected order-4 `R'` would
leak `e mod 4` (not just parity) through which of 3 distinguishable `κ` values (`x` of `NEUTRAL`/
the order-2 point/the order-4 point pair, the latter two sharing an `x` since `x_T=x_{-T}`) `T'=e·R'`
lands on. **A first numerical search (random points + cofactor-clearing) found none in 5000 tries
and briefly looked like it closed the question the other way - that search had an uncaught bug,
never isolated, superseded by the group-theory proof above, which doesn't depend on locating a
concrete example by coordinates.** Fixed with a general subgroup-membership check in `decrypt`
(`R'.scalar_multiply(&order()) == NEUTRAL`) rather than a curve-specific torsion patch - the
standard fix for any cofactor->1 curve, and the one that generalizes if this module is ever ported
to a different `l(p)`.

**Also fixed along the way**: `message.rs`'s `parse_m_prime` (reached from `decrypt` on
caller-secret-derived, KW-unwrapped data) used plain `!=`/short-circuiting comparisons for its hash
and zero-padding checks - not a documented constant-time primitive
(`docs/SECURITY.md`'s standing rule). Replaced with `subtle::ConstantTimeEq` for the hash comparison
and a fixed-iteration OR-fold (iterating the full `M_TILDE_BYTES` buffer regardless of the
attacker-influenced `bit_length`, not a `bit_length`-sized slice) for the padding check. Caught
before `decrypt` could safely call `parse_m_prime`, not after.

**`DecryptError` deliberately collapsed to one variant** (`InvalidCiphertext`): clause 12's
late-stage checks (hash mismatch, padding-not-zero, KW checksum mismatch) all depend on `κ=x_{T'}`,
itself derived from the caller's secret `e` - returning distinguishable errors or timing here is a
padding-oracle shape (Manger/Vaudenay-style), squarely in `docs/SECURITY.md`'s threat model. A
deliberate safe deviation from clause 12's literal per-step error naming, same category as
D-56/D-63's AEAD-binding fixes. `decrypt` also takes no public key parameter - genuinely unused
(clippy-caught): `T'=e·R'` needs only the secret `e` and the ciphertext's own `r`.

**QA-gate closure.** Full-workspace `clippy --all-features -- -D warnings`/`fmt --check` clean.
`cargo test --workspace --all-features` clean (115 lib/integration tests + 8 doc-tests across
`message.rs`/`fp256.rs`/`curve256.rs`/`encryption.rs`, including the standard's own worked-example
round-trip - independently re-verified via an unpiped log redirect after noticing the first run had
been piped through `tail`, which would have masked a real failure behind `tail`'s own exit code).
Scoped `cargo +nightly miri test -p dstu-core --test dstu9041_field --test dstu9041_curve --test
dstu9041_encryption --test dstu9041_message --lib` (CI's own invocation,
`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1` - proptest's failure-persistence lookup calls
`getcwd`, which Miri's isolation blocks by default, same pre-existing cross-platform gotcha T-81
already hit) ran fully clean end to end: `--lib` 74 passed/3 ignored, `dstu9041_curve` 16 passed,
`dstu9041_encryption` 19 passed/1 ignored, `dstu9041_field` 28 passed/3 ignored, `dstu9041_message`
9 passed - 0 failed across all five, ~2.2 CPU-hours total (encryption alone: 7273.62s). The
heaviest `fp256`/`encryption` proptests and the `pow_mod`/`sqrt` 256-iteration ladders are marked
`#[cfg_attr(miri, ignore)]` matching T-100's precedent (`37f7826`), so this exercises every
dstu9041 code path at least once under Miri without the interpretation cost of a full multi-case
proptest run or a fixed-256-iteration ladder. A Kani proof harness (`fp256.rs`'s `kani_proofs`
module, mirroring
`gf2m163.rs`'s D-102 precedent) was added for `select`/`conditional_sub_p`/`add`/`sub`/
`reduce_wide`'s boundedness and mask-select specs - the genuinely tractable "fixed shift/add/
multiply-by-constant" class; full `multiply`/`wide_mul` symbolic-times-symbolic equivalence was not
attempted, the same multiplier-equivalence class D-112 already found intractable for CBMC on a
much smaller field. **Kani itself cannot run on this Windows dev machine at all** (D-102's own
finding - `kani-verifier`'s source calls Unix-only std APIs - and no WSL is installed on this
machine either); CI (Linux, `.github/workflows/rust.yml`'s `kani` job, no `--harness` filter so new
proofs are auto-discovered) is the actual, unconditional venue for this, per this project's own
"verify a CI job's real conclusion via `gh run view`, never assume" standing rule - these proofs
are written and believed correct by construction (mirroring an already-accepted pattern) but not
yet independently confirmed by a real run at the time of this entry.

**Known accepted risk, same posture as the rest of this section**: no independent DSTU 9041
reference implementation exists anywhere (`docs/ORACLES.md`, 2026-07-21 search, re-confirmed at
this task's closure) - Додаток Г's own worked example is the sole oracle for this primitive.
`l(p)=384/512/768` (their own `F_p` modules, plus `hazmat::kalyna_kw_p` for the non-block-aligned
`M'` padding case) remain unimplemented, deliberately out of scope for this pass.

## D-168: T-182 - DSTU 9041's document is confirmed 36 pages total; `l(p)=768` has no worked example
anywhere in the standard, not just unpurchased

**What was found, and how.** D-165/T-176 left an open question: whether `l(p)=768`'s missing worked
example (Table В.4's parameters exist, but no Додаток Г.4 numeric walkthrough had been seen) was a
gap in what this project had purchased so far, or a genuine absence in the standard itself. The
owner directly answered this 2026-08-06 by supplying photos of the document's own final two pages
(35 and 36) from their own copy - primary-source evidence, not inference from footer-number
bookkeeping. Page 35 shows the middle of Додаток Г.3's `l(p)=512` decryption steps (computing `R'`,
`T'`, the recovered bit string, splitting `i_H`/`H'`/`M̃`); page 36 opens with `H'=H(...)` verification
and "Виводять результат роботи алгоритму розшифрування" - the example's own conclusion - and **page
36 is the document's last page**.

**Conclusion.** The standard's Додаток Г contains exactly three worked examples (`l(p)` = 256, 384,
512) and no fourth. This is not a gap this project can close by purchasing more pages - there is no
more document. The store's own listing (`docs/ORACLES.md`, `fnd-store.uas.gov.ua/documents/42241`)
states 40 pages; the physically obtained/confirmed document is 36 - most likely a cover/title-page
counting difference on the store's side (a discrepancy noted, not further chased, since the content
question it might have mattered for is now independently settled by direct observation of the last
page).

**Consequence for `docs/TASKS.md` T-182.** `l(p)=768`'s sub-item is downgraded from "blocked on
source material, open question" to "permanently oracle-less by design of the standard itself." If
this security level is ever implemented, it cannot follow T-177's verification pattern (worked
example as sole oracle) at all - it would need the same posture as `crypto_secretstream` (D-68) or
Strumok's provisional vectors (D-15): from-scratch derivation plus property/tamper/misuse tests
standing in for a vector that will never exist, not a temporary placeholder for one that might
still turn up. Any future decision to implement `l(p)=768` should account for this from the start of
its own plan-mode/`advisor()` pass, not discover it mid-implementation.

## D-169: T-178 - `crypto_box` (hybrid-via-KDF over `hazmat::dstu9041`) and its `uacrypt` CLI surface

**The fork, and why it needed an owner decision rather than an implementation call.** `l(p)=256`
caps a single ciphertext's payload at `L_MAX_P`=200 bits (25 bytes) - below this project's own
32-byte symmetric keys (`crypto_secretbox::SecretKey`, `crypto_secretstream::Key`), so no
high-level `crypto_box` wrapper could be built by direct analogy to those. An `advisor()` review
(2026-08-06) framed three honest options: cap `seal`/`open` at 25 bytes and name it a short-secret
wrap; build a hybrid (KEM wraps a random seed, KDF expands it, `crypto_secretstream` encrypts the
actual message); or block on `l(p)>=384` (T-182) giving enough room to embed a 32-byte key
directly. This is a genuine scope fork with no settling DSTU citation for the *composition* itself
(D-47's tie-breaker rule doesn't resolve which of three architectures to build, only how to resolve
ties within one) - put to the owner via `AskUserQuestion` rather than resolved by implementation,
per this project's own "ask, don't guess" standing rule. The owner picked hybrid-via-KDF, the same
shape OpenSSL's `EVP_Seal*`/`EVP_Open*` ("digital envelope") and libsodium's `crypto_box_seal` both
already use - the asymmetric step only ever establishes key material, never encrypts bulk data
itself, which is exactly what every KEM-shaped standard (RSA-OAEP, ECIES, RSA-KEM, and this one) is
actually for.

**What was built** (`docs/TASKS.md` T-178a/b, `68986b8`/`bebe4e3`): `dstu_core::crypto_box::{seal,
open, SecretKey, PublicKey}`. `seal` draws a random 25-byte seed, wraps it via
`hazmat::dstu9041::encryption::encrypt` under a freshly rejection-sampled ephemeral scalar, embeds
the seed into a zero-padded 32-byte buffer (`crypto_sign::derive_nonce`'s own embedding precedent),
derives a `crypto_secretstream::Key` from it via `hazmat::kupyna_kdf::Kupyna256Kdf::derive_subkey`
directly (not `crypto_kdf::MasterKey`, which requires an already-32-byte input), then encrypts the
actual message - any length - in one `Tag::Final` chunk. Wire format:
`dstu9041_ciphertext(128) || secretstream_header(32) || ciphertext || tag(16)`.

**`PublicKey` is 32 bytes - the curve point's `x`-coordinate only, not `x||y`.** Proven safe, not
assumed: this curve's negation is `-(x,y)=(x,-y)` (the swapped-Edwards form), so `x` alone never
distinguishes a point from its negation, and `x_T=x_{-T}` holds for any point `T` on this curve.
Since `k*(-Q)=-(k*Q)` for any scalar `k`, reconstructing `Q` from just `x_Q` - via either of the two
possible `sqrt` branches - yields the *same* `kappa=x_{epsilon*Q}` on `seal`'s own encrypt step.
Verified two ways: an explicit proof in `crypto_box.rs`'s own module doc, and a new curve-level test
(`point_from_x_gives_same_kappa_regardless_of_sqrt_branch`, `tests/dstu9041_curve.rs`) that computes
both `Q.scalar_multiply(epsilon).x` and `point_from_x(Q.x).scalar_multiply(epsilon).x` from the
worked example's own values and confirms they're identical. `PublicKey::from_bytes` runs the exact
same reconstruction gauntlet `hazmat::dstu9041::encryption::decrypt` already ran inline (reject `x
in {0,1,p-1}`, reject `x^2=a*d^-1`, `euler_criterion` before `sqrt`, subgroup check) - extracted into
a shared `curve256::point_from_x` helper (`626680a`) rather than a second, independently-maintained
copy of a security-critical check. No behavior change to `encrypt`/`decrypt` from this refactor -
confirmed by re-running every existing `dstu9041_*` test file unmodified before adding anything new.

**`OpenError` collapses KEM failure, secretstream tag failure, and a recovered-but-wrong-length
seed into one `InvalidCiphertext` variant** - same padding-oracle-avoidance posture as
`hazmat::dstu9041::encryption::DecryptError` (D-56/D-63 precedent). Only `Truncated` (a public
wire-length check, no secret-dependent data) stays distinguishable.

**`uacrypt` CLI** (T-178b): `box-keygen`/`box-pubkey`/`box-seal`/`box-open`, new verbs rather than
overloading `encrypt`/`decrypt` (would have been a breaking wire-format change), mirroring `sign`/
`sign-keygen`/`sign-pubkey`/`verify`'s own key-file convention (T-124). `box-seal`/`box-open` are
explicitly **not memory-bounded** - `crypto_box::seal`/`open` take `&[u8]`/`Vec<u8>`, not a chunked
interface, so `--in` is read whole into memory. Documented in both commands' own doc comments
(D-42's own "don't let this go unnoticed" standard) rather than silently inherited from the library
layer; fine for typical messages/keys, a real limitation for very large files until a genuinely
chunked `seal_stream`/`open_stream` pair exists in the library (noted as future work in
`crypto_box`'s own module doc, without changing the wire format's KEM prefix if it's ever added).

**QA.** 14 new library tests (round-trip including a message far larger than the 25-byte KEM
payload, every wire-segment tamper case, wrong key, misuse on out-of-range keys) plus 17 new CLI
tests (parse-arg coverage, a golden-path round trip both directly and through the top-level `run()`
dispatcher, wrong-key/tampered/truncated-file rejection). Heaviest proptests/tests marked
`#[cfg_attr(miri, ignore)]` up front, not discovered after a multi-hour miri run (T-100/T-177
precedent). Full `cargo test --workspace --all-features` re-run clean (42 test groups, 0 failed)
after landing; `cargo xtask clippy`/`fmt --check` clean; manually verified end-to-end via the actual
built `uacrypt` binary (a real keygen -> pubkey -> seal -> open round trip, plus wrong-key and
tampered-ciphertext rejection), not just the automated test suite.

**Known follow-up, not this task's scope**: T-178c (`dstu-core-capi` addition, a prerequisite for
T-181's .NET/Go/C++ bindings specifically - the other five binding languages don't need it);
`docs/PERFORMANCE.md` benchmarking (T-179); `README.md`/site/usage-example documentation (T-180);
language bindings (T-181).

## D-170: T-179 - `crypto_box` benchmarked against OpenSSL CMS, a same-regime comparison, not just `ecdh`

**Owner feedback (2026-08-06)**: T-179's original benchmark (`box-seal`/`box-open` ops/s vs.
`openssl speed ecdh`) compared the right dominant cost (EC scalar multiplication) but the wrong
*regime* - `ecdh` never touches a message, while `box-seal`/`box-open` are full hybrid
seal/open calls over an arbitrary-length message (KEM wrap, KDF, `crypto_secretstream`-chunked bulk
encryption, D-169). Directive: compare against a similar-mode binary operation, OpenSSL or LibreSSL.
`advisor()` identified the correct analog: `openssl cms -encrypt`/`-decrypt` with an EC recipient
does exactly the same kind of thing (ephemeral ECDH + KDF-derived content-encryption key + AES-256
bulk encryption of the actual payload) - not `pkeyutl` (OpenSSL has no ECIES there) and not `speed
rsa2048` (different algorithm family, still not an envelope). LibreSSL was the "or" alternative
offered by the owner, not an additional requirement - OpenSSL 3.5.5 (already on this machine)
satisfies the ask; nothing new was installed.

**Kept, not replaced, the original `ecdh` table** - demoted to an explicitly-labeled
"primitive-level" table, still useful for "how fast is our EC math" in isolation, with a new
same-regime "full sealed-box" table added alongside per the new `docs/PERFORMANCE.md` methodology
rule (below). Neither table substitutes for the other, per `advisor()`'s framing.

**D-34's 10 MiB-mandatory rule applies to the new table** - `crypto_box::seal`/`open` take an
arbitrary-length message, so the same policy that governs every symmetric mode's binary-level table
applies here too; MB/s (not ops/s) is the right unit once a real bulk payload is involved, matching
D-34's own scoping ("MB/s only meaningless for a *fixed-size* asymmetric op" - a full seal/open call
over 10 MiB is not fixed-size).

**Two real gotchas found empirically, not assumed, before trusting any number**:
1. **`openssl cms -encrypt`/`-decrypt` silently truncate binary input at the first `0x1A` byte
   without `-binary`** - caught by checking output size (a 10 MiB payload produced a 455-byte CMS
   structure) rather than trusting a clean exit code; a text-mode/S-MIME-oriented default, not a
   bug, but a sharp edge for any future binary-payload OpenSSL CLI comparison in this project.
   Recorded as a standing gotcha in `CLAUDE.md`'s Agent discipline section, not just here, since it
   will recur for any future `smime`/`cms` comparison.
2. **Git Bash's MSYS path conversion rewrites a leading `/CN=...` in `-subj` into a Windows
   filesystem path** - fixed with `MSYS_NO_PATHCONV=1`, same class of Windows/Git-Bash gotcha this
   project has hit before with other tools, not specific to OpenSSL.

**Process-spawn overhead was measured, not ignored**: `openssl cms` has no internal iteration flag
(unlike `uacrypt`'s own `--iterations`), so each timed call is a fresh process. Measured separately
at ~60 ms/spawn (N=20, `openssl version`) - ~21-22% of each ~270-280 ms CMS call at 10 MiB. Reported
as a caveat rather than subtracted out, since doing so would assume a trivial `openssl version` call
has the same startup cost as a real `cms` invocation (X.509 parsing, cipher init) - the honest
framing is that this makes the published OpenSSL numbers a conservative (slower than its true
crypto-only speed) estimate, so it does not change the comparison's direction.

**Result**: OpenSSL CMS is ~4.2x faster sealing (37.34 vs. 8.84 MB/s) and ~3.3x faster opening
(35.36 vs. 10.72 MB/s) at 10 MiB - a real, honestly-measured gap, unlike the primitive-level
table's "same order of magnitude" framing, which only holds for the sub-millisecond EC-only cost and
says nothing about bulk throughput. For context, not chased further this session: this project's own
`hazmat::kalyna_gcm::Kalyna256_256Gcm` alone reaches 17.09 MB/s at 10 MiB (this file's own
Kalyna-GCM 256-256 row) - `crypto_box`'s ~8.84/10.72 sit at roughly half that, meaning most of the
gap is `crypto_secretstream`/`crypto_box`'s own per-call framing/allocation overhead layered on top
of the underlying cipher, not the KEM's two scalar multiplications (negligible at 10 MiB) or the
block cipher itself - a lead worth investigating in a future performance pass, not this one.

**New standing methodology rule** (`docs/PERFORMANCE.md` "Methodology" section): any future
benchmark for a full construction (not a bare primitive) must include a same-regime comparison
binary doing the same *kind* of operation, not just share its dominant cost - recorded there as the
canonical home per the doc map, not duplicated here beyond this rationale.

## D-171: T-178c - `crypto_box` added to `dstu-core-capi`, unblocking T-181's .NET/Go/C++ bindings

**Why this, not a binding, was next.** T-181 (language bindings for `crypto_box`) was the next item
in the owner's "build a plan, then execute it" directive, but `advisor()` flagged a sequencing bug
before any binding work started: four of the eight binding languages (.NET, Go, C++, PHP - per
Fork 1's *planning-time* text in `docs/bindings-strategy.md`) were believed to consume
`dstu-core-capi` directly, and `crypto_box` was not yet in the C ABI. Writing T-181's phase plan
"eight languages, Python first" would have planned four languages that cannot compile until a task
marked as trailing (T-178c) actually lands. T-178c was promoted to the head of T-181's own work,
done this session rather than deferred further. **Correction, found a few hours later doing PHP's
own T-181 work**: PHP was never actually in that group - see this entry's "Unblocks" section below
for the real shape (`dstu-core` direct via `ext-php-rs`, only three languages genuinely needed
T-178c). The sequencing call itself was still right; only the language count was off by one.

**What was built**: `crates/dstu-core-capi/src/crypto_box.rs` - `DstuBoxSecretKey`/
`DstuBoxPublicKey` opaque handles (`Zeroize`-on-`Drop` via the wrapped `dstu_core::crypto_box` types,
same as every other opaque handle in this crate), `dstu_box_secretkey_generate`/`_from_bytes`/
`_bytes`/`_public_key`/`_free`, `dstu_box_publickey_from_bytes`/`_bytes`/`_free`, `dstu_box_seal`/
`_open`. Follows `secretbox.rs`'s own caller-allocates-output-buffer shape (D-148 point 3): a
`DSTU_BOX_SEAL_OVERHEAD = 176` constant (`128 (KEM) + 32 (secretstream header) + 16 (tag)`,
hand-maintained since `dstu_core::crypto_box`'s own equivalent constants are private - a Rust FFI
test asserts a real `seal` call's output length matches it, so the two can't silently drift apart
unnoticed) gates every output-capacity check *before* any crypto work runs, matching `secretbox`'s
own established pattern exactly.

**Naming fork: the module keeps the full `crypto_box` name, not `box`.** Every sibling module in
this crate drops the `crypto_` prefix from its own module/file name (`secretbox.rs`, `sign.rs`,
`stream.rs`, `auth.rs`, ...) - `box` alone is a reserved Rust keyword (usable only via the
`r#box` raw-identifier escape), so following that convention literally would require an ugly
workaround for no benefit. Resolution: keep `crypto_box.rs`/`pub mod crypto_box` (mirrors the
wrapped `dstu_core` module's own name, self-documenting the reason), while exported C symbols still
follow the sibling convention exactly (`dstu_box_*`, not `dstu_crypto_box_*` or `dstu_r#box_*`) -
`box` as a substring inside a longer identifier is never a problem, only the bare module-path
segment is.

**`OpenError::InvalidCiphertext` reuses `DSTU_ERR_TAG_MISMATCH`, not a new status code.**
`dstu_core::crypto_box::OpenError` already collapsed the distinction that matters at the Rust level
(KEM failure, secretstream tag failure, and a recovered-but-wrong-length seed all read as one
`InvalidCiphertext` case, D-169's "Error collapsing" section) - inventing a differently-named FFI
status for it would reopen exactly the padding-oracle-avoidance posture that collapse exists to
close, even though the *bucket* stays the same size either way. `TAG_MISMATCH`'s existing doc
comment ("wrong key, or tampered ciphertext/tag/nonce/header") already describes this class of
failure accurately enough to reuse rather than grow the enum for a distinction with no operational
difference - `Truncated` (a public wire-length check, no secret-dependent data) is the only variant
that stays separately visible, exactly mirroring `secretbox`'s own `TRUNCATED`/`TAG_MISMATCH` split.

**QA, mirroring `secretbox`'s own three-category coverage**: 3 new Rust FFI tests
(`tests/ffi_tests.rs` - round trip with an overhead self-check, tampered-ciphertext/wrong-key
rejection, undersized-buffer/truncated-input/invalid-key-encoding misuse) plus a `test_box()`
function in the plain-C harness (`c-tests/test_capi.c`) exercising the same three categories through
a real `gcc`-compiled program linked against the actual generated header, not just the Rust-side
`rlib` tests - `cargo xtask capi` regenerates `include/dstu_core.h` and diffs it (the diff was
exactly the eight new functions/three new constants/two new opaque types, nothing else touched) and
runs every existing C example unmodified as a regression check. `cargo xtask clippy`/`fmt --check`
clean; full `cargo test --workspace --all-features` re-run after landing.

**Unblocks**: T-181's .NET/Go/C++ bindings can now link a `crypto_box`-complete C ABI. **Correction,
found writing PHP's own `crypto_box.rs` later the same day**: PHP does not link `dstu-core-capi` at
all - its `Cargo.toml` depends on `dstu-core` directly (`ext-php-rs`, same direct-binding shape as
Python/Node/Ruby), contradicting this entry's own first-draft wording above and
`docs/bindings-strategy.md`'s original Fork 1 planning text (now fixed there too, and in this
entry's own title). D-121 had already recorded PHP's real direct-binding shape when T-159 actually
landed it - this entry's first draft simply didn't check that before repeating Fork 1's stale
planning-time claim. Python/Node/Ruby/PHP (direct FFI) and Java (pending its own `jni`-vs-C-ABI
spike) were never blocked by T-178c. `docs/bindings-strategy.md` now carries T-181's own phase entry
with the corrected ordering spelled out.

## D-172: T-189 - `hazmat::dstu4145::signature::verify` accepted an unvalidated public key, a real universal-forgery bug

**Found auditing T-183** (owner-directed adversarial-test-coverage audit of `crypto_box`/
`dstu9041`) - out of that task's own dstu9041-only scope, but the same shape of gap: `verify`'s `q`
parameter (`VerifyingKey::from_uncompressed_bytes` at the `crypto_sign` layer, and every direct
`hazmat` caller) was never checked to be a genuine, full-order point on the curve before being fed
into `curve163::verify_combine`'s `s*G + r*Q` combine step.

**Confirmed exploitable, not just bad hygiene.** `curve163::Point::double`'s group law branches on
`x == 0` alone (`if x1 == FieldElement::ZERO { return Infinity }`) and never checks the curve
equation `y^2 + xy = x^3 + x^2 + b` at all - it's a public-data addition-formula implementation,
correct for *any* point on *any* curve of this shape, not specifically the DSTU 4145 one. Any `q`
whose order divides 2 (the curve's own order-2 point at `x=0`, an off-curve `(0, y)` with `y^2 !=
b`, or `Point::Infinity` itself, order 1) collapses `r*q` to at most two possible values depending
only on `r`'s parity (or one value, for `Infinity`) - turning the verification equation into a
tractable search: pick trial `s`, compute `R = s*G (+ q)` for each parity branch via the existing
public `verify_combine`, and `r = truncate_162(h * R.x)` **is** a valid forged signature by
construction, no private key involved. `tests/dstu4145_signature.rs`'s `t189_public_key_validation`
module implements this search (`find_forgery`) and used it to forge a working `(r, s)` against all
three `q` shapes above - each forgery test failed (i.e. `verify` wrongly accepted the forgery)
against the pre-fix code, confirmed by running them before writing any fix, not assumed.

**Why a naive test wouldn't have caught this.** The first draft of these tests just substituted a
bad `q` into the vector's own *legitimate* `(r, s)` and asserted `verify` now returned `false` -
which it already did, before any fix, purely because a signature computed for a different `q`
fails the final equality check by numeric coincidence (~`2^-162` chance of accidentally matching).
That's the D-21/D-25 trap (`CLAUDE.md`) recurring at the key-input position rather than the
derivation step where it was first found: a test can pass while exercising nothing. Rewritten to
actively forge a signature (above) before landing.

**Cofactor confirmed h=2, dual-sourced**, settling how expensive the fix needs to be: Hasse's bound
for `n = 0x0400000000000000000002BEC12BE2262D39BCF14D` (`gf2m163.json`) over `GF(2^163)` admits
only `h=2` in its window (`h=1` falls far short of the window, `h>=3` overshoots it) - independently
confirmed against `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java:47` (`h_s[0] = TWO`). So
`{Infinity, (0, sqrt(b))}` is the curve's *only* non-prime-order subgroup - an on-curve check plus
an explicit `x != 0` rejection is complete; no expensive full subgroup-order scalar multiplication
(`n*Q == Infinity`) is needed.

**Fix**: `curve163::Point::is_on_curve` (new, mirrors `dstu9041::curve256::Point::is_on_curve`'s
existing shape) checks the affine curve equation directly, returning `false` for `Infinity` (not a
solution of the affine equation - callers needing to also reject the group identity do so
separately, as `verify` does here). `signature::verify` gained one guard clause right after its
existing `r`/`s` range checks: reject if `q`'s `x`-coordinate is `ZERO` or `!q.is_on_curve()`,
before any of `h`/`verify_combine` is computed.

**Where the check lives, and why not `from_uncompressed_bytes`.** `from_uncompressed_bytes` returns
`Self` (not `Result`) and this crate has shipped v0.2.0 to crates.io - adding validation there would
be a breaking API change on a published type. `hazmat::dstu4145::signature::verify` already returns
`bool` and is the single choke point every path funnels through (`crypto_sign::verify_digest`, the
C ABI, and all eight language bindings) - validating there is non-breaking and closes the hole for
every caller uniformly, not just the one high-level wrapper. `advisor()`-reviewed before writing any
code, per this project's standing rule for security-critical forks.

**Perf, measured not assumed** (T-153's methodology: fresh release build, `uacrypt verify
--iterations`, same machine, idle - not run concurrently with anything else, per D-161's stash-cycle
caution): a real `git stash`/rebuild A/B on this session's own machine measured **563.20 ops/s
before the fix, ~539 ops/s after** (two consistent post-fix runs, 538.84/540.29) - roughly a 4-5%
cost, higher than the "a few field multiplications should be sub-1%" naive estimate, but nowhere
near what a full extra `scalar_multiply` ladder would cost (that would roughly halve throughput, the
signal that would mean the wrong - expensive subgroup-check - fix had been built instead). The gap
is plausibly partly measurement/binary-layout noise (an earlier same-fix measurement taken while a
`cargo test` run was still active in the background read 450.15 ops/s, a ~14% apparent regression
that fully disappeared once the machine was actually idle) rather than a pure algorithmic cost of
`is_on_curve`'s 2 squarings + 2 multiplies. Not chased further - both numbers comfortably clear
T-153/D-109's own prior baseline (524.01 ops/s) within normal run-to-run variance, and the fix is
mandatory regardless of the exact overhead.

**Tests**: `t189_public_key_validation` (3 forgery tests above) plus the existing
`gf2m163_worked_example_verifies` as the other-direction regression guard (a genuine on-curve,
full-order key must still verify - unaffected by the fix). Full three-profile posture: default and
`--features small-tables` both green (`small-tables`'s own `verify_combine` still goes through
`scalar_multiply`, D-108 - a genuinely different code path from the default projective combine, not
a redundant re-run). `cargo test -p dstu-core` (full suite, all binaries), `-p dstu-core-capi`,
`-p uacrypt` all green; `clippy --all-features -D warnings` and `fmt --check` clean.

**Not yet done**: the four remaining real gaps T-183's own audit found in `dstu9041`/`crypto_box`
(order-4 subgroup regression test, `SecretKey`/length boundary tests, `euler_criterion`-ordering
property test, D-169/D-171 CCA-oracle-collapse invariant test) stay backlog items under T-183 -
this entry covers only the DSTU 4145 finding that was spun off as its own task, not the rest of
that audit.

## D-173: T-183 follow-up - three of the four remaining audit gaps closed; the fourth (order-4) hit a real dead end, not chased past it

**Three straightforward test additions**, all in `crates/dstu-core/tests/`, no production code
changed:

- `crypto_box.rs`: `secret_key_rejects_out_of_range_bytes_upper_boundary` (`e=n-1,n,n+1`, all-
  `0xFF`, mirroring `hazmat::dstu9041::curve256`'s own `is_valid_scalar_boundaries` but confirming
  `SecretKey::from_bytes` actually wires up to it, not re-testing the same math twice) and
  `trailing_garbage_after_valid_ciphertext_is_rejected` (append one byte past a valid `seal`
  output - `open`'s own `tag = &sealed[ciphertext_start + ciphertext_len..]` construction ties the
  tag window to `sealed.len()` directly, so trailing garbage shifts both the ciphertext and tag
  windows by one byte and fails the AEAD tag check for the ordinary reason, not an explicit
  length-prefix check - confirmed by reading `open`, not assumed).
- `dstu9041_curve.rs`: `point_from_x_rejects_a_non_residue_x` - finds a real non-residue `x` by
  sequential search from `x=2` (a negligible chance of coinciding with one of the four specifically
  -excluded values) and confirms `point_from_x` rejects it end to end. Complements, does not
  duplicate, `dstu9041_field.rs`'s pre-existing `sqrt_of_non_residue_does_not_square_back` (proves
  `sqrt` never self-validates a non-residue input, which is *why* checking `euler_criterion` first
  matters) - that test pins the field-level property, this one pins the real call site.
- `crypto_box.rs`: `kem_failure_and_secretstream_failure_are_indistinguishable` - a wrong-key
  failure (KEM-level, `dstu9041_decrypt` itself errors) and a tampered-tag failure (secretstream-
  level, KEM decrypt succeeds, `PullState::pull` fails) asserted to produce not just the same
  `OpenError` variant but identical `Debug` output. The third failure mode T-183 named (KEM success
  with a wrong-length recovered seed) was not constructed - `hazmat::dstu9041::decrypt`'s own
  `DecryptError` is already collapsed to one variant for the identical padding-oracle reason
  (D-167), so black-box-forging a ciphertext that passes KEM decryption yet yields a wrong `bit_len`
  may not be reachable at all without first breaking the KEM's own hash check - documented as
  foreclosed-by-contract (D-111's `dstu4145` precedent) rather than forced.

**The order-4 regression test was attempted and did not land - a real investigative dead end, not
an oversight.** Constructing a concrete order-4 point needs `curve256.rs`'s `pub(crate)`
`curve_a`/`curve_d`, invisible to the black-box `tests/` crate, so it needs an internal
`#[cfg(test)]` module (`fp256.rs`'s `private_constant_tests` precedent). Two things survive the
attempt even though the test itself doesn't exist:

1. **A genuine identity-representation hazard in `ProjectivePoint::to_affine`**, worth recording
   independent of order-4: `to_affine` has no `z == 0` special case, so a `scalar_multiply` result
   that reaches the group identity through a `z == 0` intermediate renders as `(0, 0)`, not
   `Point::NEUTRAL = (1, 0)` - confirmed directly against the real build (not assumed, not just a
   Node reimplementation artifact - initially mistaken for exactly that, see below).
   `n_times_base_point_is_neutral` only ever exercises the *base point's own* ladder for scalar
   `n`, which happens not to hit this path, so it never caught this. `point_from_x`'s own subgroup
   guard (`candidate.scalar_multiply(&order()) != Point::NEUTRAL`) **fails closed** on this - `(0,
   0) != (1, 0)` still correctly rejects - so it is not the security hole it looked like at first
   read. Worth a general caution for any future code comparing a `scalar_multiply` result against
   `NEUTRAL`: that comparison is not a reliable general-purpose "is this the identity" check on
   this curve.
2. **Whether a concrete order-4 point is reachable through `point_from_x`'s own reconstruction
   formula at all is an open question**, not confirmed either way. A corrected search (screening
   via a single fresh `2n*Y` ladder call, not by doubling an already-affine, possibly-degenerate
   `n*Y` - the bug that produced finding 1 above) found 0 order-4 candidates across 62 valid
   reconstructed points, against a 50/50 split D-167 Finding 2's own group theory predicts (a
   `~2^-62` coincidence if that theory's reachability assumption holds). This does not contradict
   D-167 Finding 2's *existence* proof (order-4 points genuinely exist - independently re-confirmed
   this session via Hasse's bound: `h=4` is the unique cofactor fitting the Hasse window for this
   curve's `p`/`n`, both re-derived from the actual `P_LIMBS`/`ORDER_N` bytes, not assumed from the
   prior entry). It does mean the *specific* attack D-167 describes (a crafted `r` reaching an
   order-4 point through this exact reconstruction path) may not be reachable the way that entry
   assumed - most likely because an order-4 point's own `x`-coordinate never happens to satisfy
   `euler_criterion` under this formula, making it unreachable by construction rather than merely
   untested. Unconfirmed either way; would need an analytic answer (does an order-4 point's `x`
   ever satisfy `euler_criterion`?), not more empirical search, to settle.

**Process note, since this investigation genuinely went sideways twice before landing on the above:**
first mistook the `(0, 0)` finding for a live completeness bug in `ProjectivePoint::add` (a
from-scratch Node.js reimplementation of the same formula reproduced the same anomaly, which felt
like independent confirmation but wasn't - both implementations shared the same flawed
`to_affine`-after-every-`.add()` test structure, not independently verified group arithmetic).
`advisor()` correctly identified this from the `to_affine` source alone. Second mistake, in the
corrected search: derived the `2n` scalar via `FieldElement::add` (which reduces mod the curve's
field prime `p`), not the group-order/scalar domain - numerically harmless here only because `2n <
p` (no wraparound), which is not a reason to use the wrong type; caught by a second `advisor()`
pass, fixed by hardcoding an externally-computed, independently re-verified constant instead
(`two_n_is_really_2n`, an from-scratch big-endian doubling check, not a re-assertion of the same
mistake). Both are concrete instances of this project's own standing rule about verifying claims
rather than trusting a computation that "looks" independent.

## D-174: T-190 sub-pass 1 (DSTU 4145) - Bouncy Castle parity confirmed, no `g`-side gap; a third-party finding handled privately

**Context**: T-190's first per-algorithm sub-pass, comparing DSTU 4145's defensive/stability code
in Bouncy Castle against `hazmat::dstu4145::signature`.

**1. Bouncy Castle - our T-189 fix has exact parity, no new gap.** The vendored
`oracles/bouncycastle-java` sparse checkout doesn't include `ECPublicKeyParameters`/`ECPoint`/
`ECCurve` (only the DSTU-specific files, `docs/ORACLES.md`'s own note on this), so these were
fetched read-only from `raw.githubusercontent.com/bcgit/bc-java/master/...` for reading, not
vendored into the repo. Trace: `ECPublicKeyParameters`'s constructor calls
`ECDomainParameters.validatePublicPoint`, which rejects `null`, infinity, and
`!ECPoint.isValid()`. `isValid()` (`implIsValid`, checkOrder=true) checks
`satisfiesCurveEquation()` **and** `satisfiesOrder()`; the F2m `satisfiesOrder()` override has an
explicit cofactor-2 branch (a trace-based halving test, `ECPoint.java:1444-1462`) that is the
general form of what `is_on_curve` + the explicit `x != 0` rejection do for this specific curve in
`signature::verify` (T-189/D-172). Confirmed via Bouncy Castle's own `DSTU4145NamedCurves`-derived
cofactor 2 (already cited in D-172) - no new action.

**2. The `g` (base point) side has no mirror exploit - checked, not fixed.** `verify`/`sign` take
`g: Point` as a caller-supplied parameter (hazmat's "no defaults chosen for you" design), and only
`q` was validated by T-189, not `g`. Bouncy Castle validates `G` too, but *once*, at
`ECDomainParameters` construction (`ECDomainParameters.java:64`) - a long-lived domain object, not
a per-call untrusted input - so this isn't evidence of a per-call `g` check being needed in our
shape. Analytic argument for why the T-189 exploit doesn't mirror: `find_forgery`'s trick works
because `r` - the exact value re-derived and checked against the candidate output - multiplies the
degenerate point (`q`), collapsing `r*q` to <=2 values as a function of `r`'s parity alone, so the
*other*, unconstrained variable (`s`) can be searched cheaply. With `g` degenerate instead, it's
`s*g` that collapses, but `s` is never checked against anything; the checked output (`r`) still
multiplies the honest, full-order `q`, so `r*q` still ranges over the full group and there's no
known cheap inversion. **Empirically probed** (temporary test, not committed - `git diff --stat`
confirmed the file was byte-identical to HEAD after removal): order-2 and `Infinity` `g`, honest
full-order `q` from the vector, brute-forced over 2 bad-`g` variants x 2000 `s` x 50 `r` = 200,000
`curve163::verify_combine` trials - **0 hits**. Conclusion: no exploit, no code change - adding a
`g` check now would be a behavior change to a `hazmat` function with no security justification,
against `CLAUDE.md`'s own "no speculative features" rule. `crypto_sign.rs` (the only wired public
entry point) always hardcodes `g = Point::generator()` regardless, so this is unreachable through
any shipped surface either way - `hazmat::dstu4145::signature::{sign,verify}` are the only place a
non-constant `g` could ever reach, for a downstream Rust consumer calling them directly.

**3. A third finding, in a third-party open-source reference implementation, not in this
project's own code.** The same class of bug T-189/D-172 fixed here (a public-key point accepted
without a point-order check, enabling universal signature forgery with no private key) was found
during this sub-pass in a different, independently-maintained open-source project - not detailed
here on purpose. Per this project's own established precedent for anything involving a third
party's own repository (see D-91), this is not this project's call to disclose publicly or act on
unilaterally: it was raised to the project owner as a private question, reproduced against that
project's own real compiled binary before any outreach (owner's explicit requirement - don't
report on a source-reading trace alone), and is being handled through private, responsible
disclosure to that project's own maintainers. Full technical detail (repository, exact file/line
trace, reproduction bytes) is intentionally not recorded in this public repository while disclosure
is pending - kept in local, untracked notes instead. See `docs/TASKS.md` T-190/T-191 for status.

**No change to our own code** - `signature::verify` already rejects both the on-curve failure and
the `x = 0` small-subgroup case (T-189/D-172). The third-party finding above is corroborating
evidence that T-189 was a real, exploitable bug class independently discoverable elsewhere, not
paranoia over a theoretical concern.

## D-175: T-191 - the third-party finding from D-174 independently reproduced against real running code, not just source reading

Per the owner's explicit order of operations (reproduce against the real, running third-party
binary before any disclosure contact - not a source-reading trace alone), built a standalone,
uncommitted C test harness against that project's own official prebuilt binary release, calling
its own exported public API functions directly, with no modification to that project's code.
Confirmed: a genuine, honestly-derived signature verifies correctly (control case), and the same
class of forged signature D-174 describes - a public key with no real private key behind it - is
also accepted by the real compiled binary, not just predicted from reading source. Two mechanical
false leads were hit and self-corrected along the way (an encoding/padding bug in the harness's own
hex parser, and an initial attempt to cross-check against a reference vector that turned out to use
a different base point than the target's own default curve parameters) - both resolved empirically,
not guessed past.

This closes T-191's reproduction step. Per D-91's standing rule for anything involving a specific
third-party repository, no public detail (project name, file/line trace, exact reproduction bytes)
is recorded here while private disclosure is pending - see local, untracked notes for the full
technical record kept for this project's own reference. Next step (per the owner's 2026-08-08
direction) is drafting the private disclosure itself for the owner's own review before anything is
sent anywhere - not this project's call to make unilaterally.

**No change to this project's own code or committed test suite** - the scratch harness used for
reproduction lives outside this repository entirely (session scratchpad only), matching this
project's established "scratch-only, not shipped" posture for throwaway investigation tooling in
general.
