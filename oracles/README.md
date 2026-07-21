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
files with no direct role in a Rust crate — their value is as a second, independently-audited
implementation to diff behavior against, not as code to build on. If Java/.NET bindings are
built later (per `../DECISIONS.md` D-02 — wrap Bouncy Castle rather than reimplement DSTU 4145),
that's a real dependency added to those bindings' own build files, not a copy from this folder.

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
third-party implementation.
