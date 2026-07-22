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
