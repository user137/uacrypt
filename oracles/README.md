# Oracles — local-only, not part of this repository

This directory holds unmodified copies of third-party reference implementations, used only
as **oracles**: run/inspect their code locally, cross-check outputs and test vectors against
our own implementation. Never copy their source into `crates/`, regardless of license — this
project's Rust core is written from the DSTU spec text, with these as a verification aid (see
`../SECURITY.md` "Dual-oracle verification", `../DECISIONS.md` D-02/D-06).

For the trust ranking of each oracle below, which one is primary/secondary per algorithm, the
known gaps (Strumok, DSTU 9041), and the test-vector convention — see `../ORACLES.md`, the
canonical owner of that content. Not repeated here.

## No-license C references (unofficial reference implementations)

- `kalyna-reference/` — https://github.com/Roman-Oliynykov/Kalyna-reference (Kalyna author)
- `kupyna-reference/` — https://github.com/Roman-Oliynykov/Kupyna-reference (Kupyna author)
- `strumok-dstu8845/` — https://github.com/outspace/dstu8845 (unofficial Strumok implementation)

**None of these three repos has a LICENSE file** (verified via
`gh api repos/.../{repo} --jq .license` → `null` for all three, plus `ciphers-speed` on Roman
Oliynykov's account). No license means the default is full copyright with no redistribution
permission granted — a hard reason these must never be committed or published from here.

All three include their own `main.c` with built-in test vectors — the "tests" half of what was
pulled alongside each cipher/hash/stream-cipher implementation.

## Bouncy Castle DSTU implementations (MIT-licensed)

Selected files only (not a full clone — both repos are large, multi-module projects), covering
every DSTU standard Bouncy Castle implements: DSTU 4145 (signature), DSTU 7564 (Kupyna),
DSTU 7624 (Kalyna, incl. wrap/MAC modes).

- `bouncycastle-java/` — from https://github.com/bcgit/bc-java (`main` branch), MIT License.
  Mirrors the upstream path layout, e.g.
  `core/src/main/java/org/bouncycastle/crypto/signers/DSTU4145Signer.java`. Includes the ASN.1
  layer (`asn1/ua/`), the low-level `crypto/` primitives, the JCA provider wiring (`prov/`), and
  the corresponding tests under `core/src/test/...` and `prov/src/test/...`.
- `bouncycastle-dotnet/` — from https://github.com/bcgit/bc-csharp (`master` branch), MIT
  License. Same primitives (`crypto/src/crypto/{signers,digests,engines,macs,generators,
  parameters}/`) plus the ASN.1 layer (`crypto/src/asn1/ua/`) and tests
  (`crypto/test/src/crypto/test/`).

Unlike the no-license C repos above, MIT *would* permit vendoring this into our own tree with
attribution. It's still kept oracle-only and gitignored here, for consistency: these are Java/C#
files with no direct role in a Rust crate — their value is as an independently-audited
implementation to diff behavior against, not as code to build on. If Java/.NET bindings are
built later (per `../DECISIONS.md` D-02 — wrap Bouncy Castle rather than reimplement DSTU 4145),
that's a real dependency added to those bindings' own build files, not a copy from this folder.

**Correction, checked 2026-07-21 while auditing `docs/pseudocode/*.md` against these sources:**
"independently-audited" was previously written as if it also meant "independently implemented" —
that's only true for **DSTU 4145**. `DSTU7624Engine.java` (Kalyna) and `DSTU7564Digest.java`
(Kupyna) both carry a header comment crediting "Roman Oliynykov's native C implementation" as
their source — they are ports/adaptations of the same `kalyna-reference`/`kupyna-reference` C
code above, not independent re-derivations from the spec. `DSTU4145Signer.java` carries no such
comment and reads as Bouncy Castle's own implementation — genuinely independent of the C oracles
here. Matters for how much weight to give a Kalyna/Kupyna "the two oracles agree" observation
(same lineage, corroborates faithful porting — not a second independent reading) versus a DSTU
4145 one (actually independent). See the "Correction on provenance" note in
`../docs/pseudocode/kalyna.md` for where this mattered in practice.

## Cryptonite (PrivatBank, BSD-2-Clause)

`cryptonite/` — from https://github.com/privat-it/cryptonite (`master` branch), 2016-era code,
BSD-2-Clause per its root `LICENSE` file (verified via `gh api repos/privat-it/cryptonite
--jq .license`). Only the relevant C sources were pulled (not `libs/` — that's third-party
vendored code inside cryptonite itself: LibreSSL, bee2, cppcrypto, under their own separate
licenses, not PrivatBank's, and not relevant here):

- `dstu7624.c/.h` (Kalyna) + `atest_dstu7624.c`, `ptest_dstu7624.c`, `utest_dstu7624.c`
- `dstu7564.c/.h` (Kupyna) + `atest_dstu7564.c`, `ptest_dstu7564.c`, `utest_dstu7564.c`
- `dstu4145*.c/.h` (signature + params + PRNG internals) + `atest_dstu4145.c`,
  `ptest_dstu4145.c`, `utest_dstu4145.c`, `xtest_dstu4145.c`
- `hmac.c/.h` + `utest_hmac.c` — generic HMAC construction, relevant reference for the
  `crypto_auth` construction over Kupyna (see `../docs/dstu-crypto-project.md` libsodium mapping)
- `prng.c/.h` — reference only, for understanding cryptonite's own RNG design; per D-04 we still
  use the OS CSPRNG, not this

Deliberately **not** pulled: `ecdsa.c/.h` and `gost34_311.c/.h` (generic/legacy, out of this
project's scope), the `pkix`/`storage` ASN.1 and PKCS12-container code (X.509/PKI tooling, not a
crypto primitive), and anything under `libs/` (vendored third-party dependencies, not
cryptonite's own code).

**Notable finding, open question for `../DECISIONS.md` D-05:** `dstu7624.h` exposes
`dstu7624_init_ccm` / `dstu7624_init_gcm` and a paired `dstu7624_encrypt_mac` /
`dstu7624_decrypt_mac` API — i.e. Kalyna alone, in CCM/GCM-style modes, produces authenticated
ciphertext + MAC without involving Kupyna at all. This sits in tension with D-05's premise (that
DSTU 7624 requires combining with Kupyna for confidentiality + integrity, so AEAD must be a
custom Kalyna+Kupyna encrypt-then-MAC construction). Possible reconciliation: DSTU 7624's own
CCM/GCM modes may already satisfy AEAD using Kalyna as both cipher and MAC (CMAC/GMAC-style,
self-contained), and the Kupyna-combination advice may apply to a different mode or a distinct
security profile within the standard — unconfirmed either way without the official DSTU 7624
text (not among the PDFs in `../docs/papers/`). Do not resolve this from cryptonite's code alone
before checking the primary source; this needs a citation, not an inference from a 2016
third-party implementation. **Update 2026-07-22:** `uapki/` below independently exposes the same
CCM/GMAC/GCM self-test structure for Kalyna — still not a resolution (see the caveats in that
section), but a second data point for whichever direction D-05 is eventually settled.

## UAPKI (fork of Cryptonite, BSD-2-Clause, state-expertise pedigree)

`uapki/` — from https://github.com/specinfo-ua/UAPKI, pinned commit
`c64181c3b1cd437139119d83bffb5ab090b1cdd6` (2026-07-21). BSD-2-Clause per its root `LICENSE`
(verified via `gh api repos/specinfo-ua/UAPKI --jq .license`). Pruned to `library/uapkic/`
(the crypto-primitives library — symmetric/stream ciphers, hashes, MACs, signatures, the
GF(2^m)/EC math underneath DSTU 4145) plus the top-level `LICENSE`/`AUTHORS`/`README.md`; dropped
`uapkif` (ASN.1), `cm-pkcs11`/`cm-pkcs12` (private-key storage), `uapki` (the JSON-facing PKI
library), `hostapp`/`integration`/`doc`/`test` (browser messaging host, language bindings, the
higher-level PKI test app with its own certs/JKS fixtures) — none of that is a crypto-primitive
reference, same "selected files only" convention as Bouncy Castle/cryptonite above.

**Pedigree, stated precisely:** the repo's own README cites "Expert conclusion on the results of
the Ukrainian state expertise in the field of cryptographic protection of information No
04/05/02-2096 from 21.07.2021" for the UAPKI project generally. Per this project's own
`CLAUDE.md` ("State certification"), such certification is tied to the hash of a *specific build*
— the 2021 conclusion does not certify commit `c64181c3` (pushed 2026), which postdates it by
years. Treat this as "certified pedigree, plausibly reviewed by the same team/process," never as
"this exact clone is the certified artifact."

**Every DSTU primitive in this project's scope has a `*_self_test()` function with hardcoded
known-answer data** in `library/uapkic/src/`: `dstu4145_self_test` (signature),
`dstu7564_self_test` (Kupyna hash + KMAC), `dstu7624_self_test` (Kalyna — ECB/CBC/OFB/CFB/CTR/
CMAC/XTS/KW/CCM/GMAC/GCM, i.e. covers the D-05 tension directly), `dstu8845_self_test` (Strumok,
comment-attributed `// ДСТУ 8845:2019` in the source — the first Strumok KAT this project has
found anywhere, see `../DECISIONS.md` D-15 and
`crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json`).

**Cross-checked so far:**
- DSTU 4145: `dstu4145_self_test`'s `d`/`Q`/`r`/`s` (byte-reversed from UAPKI's little-endian
  storage) are byte-identical to `docs/papers/DSTU_4145-2002.pdf` Annex Б.1 and to Bouncy Castle's
  `DSTU4145Test.java` `test163()` — three independent sources now agree on this one example (see
  `../DECISIONS.md` D-14).
- Strumok: `dstu8845_self_test`'s 8 key/IV/keystream cases were reproduced byte-for-byte by
  running `../strumok-dstu8845/` (outspace) on the same inputs — see `../DECISIONS.md` D-15 for
  why this is a consistency bonus and *not* independent-oracle confirmation (outspace and UAPKI's
  `dstu8845.c` share identical internal function/table names — likely shared lineage, not two
  independent implementations of the standard).
- Kupyna: `dstu7564_self_test_hash`'s 12 cases (null/8/512/760/1024/2048-bit, both 256/512) are
  byte-for-byte identical to `crates/dstu-core/tests/vectors/kupyna/kupyna-{256,512}.json`
  (verified 2026-07-22) — same official vector set already exercised by `cargo test`, so this is a
  same-source confirmation, not a second independent reading. `dstu7564_self_test_kmac` (3 cases,
  KMAC-256/384/512) is genuinely new data not in this project's vectors at all — KMAC isn't
  implemented here yet, so it's unchecked, left for whenever `crypto_auth` gets built (see
  `../DECISIONS.md` D-16 update, `../TASKS.md`).
- Kalyna self-test data (ECB/CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM) not yet cross-checked
  against this project's own vectors/Rust output — worth doing before leaning on it further,
  directly relevant to the open D-05 tension (see `TASKS.md`).
