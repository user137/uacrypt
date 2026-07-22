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

The official text was priced (2026-07-21) to check on this directly: 29,967.60 UAH for 227 pages
(includes Amendment No. 1:2016) via `fnd-store.uas.gov.ua/documents/4228` — see `ORACLES.md`
"Official DSTU text — purchase cost". Deemed cost-prohibitive for now; this tension stays open
until either the price becomes viable or another authoritative source turns up.

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
