# Changelog

All notable changes to this project are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Root `README.md` restructured following real-world convention from libsodium/age/RustCrypto:
  badges row, a short plain-language pitch, one verified code example, everything else linked to
  dedicated docs instead of inlined. The full CLI walkthrough moved to a new `docs/CLI.md`
  (published in the mdBook knowledge base); the repository-structure tree, dev-environment setup,
  and Windows-specific troubleshooting moved to `docs/CONTRIBUTING.md`. See `docs/DECISIONS.md`
  D-192.

## [0.3.8] - 2026-08-13

### Fixed

- `publish to RubyGems` failed instantly on v0.3.7's real release run (after all four
  `build-ruby-gems` platforms passed): `rubygems/configure-rubygems-credentials@v1` doesn't exist
  - that action only publishes full semver tags (`v1.0.0`/`v2.0.0`/`v2.1.0`), no floating `v1`/`v2`
  major alias. Pinned to the exact SHA `rubygems/release-gem`'s own `action.yml` uses internally
  for this same step (`v2.1.0`). See `docs/DECISIONS.md` D-190's second update.

## [0.3.7] - 2026-08-13

### Fixed

- Root `README.md`'s "Language bindings" table and the website's "Bindings" section both still
  said "not published to any package registry" and linked only this repo's own README, even though
  Python/Node.js were already live on PyPI/npm as of v0.3.6 - same class of bug as D-191, found
  while answering whether the site links registries as well as the repo. Both now link the README
  (full docs, every binding) and the registry page (the actual install command) side by side where
  a binding is published. See `docs/DECISIONS.md` D-191's addendum.
- `build-ruby-gems` failed on all four platforms on v0.3.6's actual release run: `magnus 0.7.1`
  doesn't support Ruby 4.0's changed C ABI, and `oxidize-rb/actions/cross-gem`'s default
  `ruby-versions` cross-compiled against Ruby 4.0 anyway. Pinned `ruby-versions` explicitly to
  `3.1,3.2,3.3,3.4`, matching what `bindings-ruby.yml`'s own test job and the gemspec's
  `required_ruby_version` already cover. See `docs/DECISIONS.md` D-190's update.
- The root `README.md` and website status banners had grown, release over release since v0.3.3,
  into a dense wall of text restating every past release's own detail. Shortened both to a single
  current-state line, pointing to `docs/CHANGELOG.md` for what changed each release instead of
  re-narrating it in the banner itself.

## [0.3.6] - 2026-08-13

### Added

- `build-ruby-gems`/`publish-rubygems` jobs in `release.yml` (T-164): cross-compiled RubyGems
  native gem publishing for `dstu_core` (`x86_64-linux`, `aarch64-linux`, `arm64-darwin`,
  `x64-mingw-ucrt`) via `oxidize-rb/actions/cross-gem`, OIDC Trusted Publishing against a
  pre-registered pending publisher. Dormant behind the `rubygems` GitHub Environment approval
  gate until the next tag. See `docs/DECISIONS.md` D-190.

### Fixed

- The already-live PyPI and npm package pages (`dstu-core`) still had README/description text
  written pre-publish, claiming "provisional, not yet published" and offering only from-source
  build instructions - no `pip install dstu-core`/`npm install dstu-core` anywhere. Fixed the
  README and every short description field (`pyproject.toml`, `package.json`, both crates'
  `Cargo.toml`, module doc comments) for both bindings, bumped both to `0.1.1` so the fix actually
  reaches the live registry page (PyPI/npm render metadata from the latest published version).
  `uacrypt`'s crates.io description ("CLI over dstu-core") replaced with a real sentence. Ruby's
  gemspec had a distinct, more serious bug caught in the same sweep: `README.md` was never in
  `spec.files` at all, so the gem would have shipped with no description page content on its first
  publish - fixed ahead of that first publish. See `docs/DECISIONS.md` D-191.

## [0.3.5] - 2026-08-13

### Added

- `dstu-core-linux-arm64-gnu` - a new npm platform package for the Node.js bindings
  (`aarch64-unknown-linux-gnu`), built natively on GitHub's `ubuntu-24.04-arm` hosted runner (GA for
  public repos since 2025-08-07), no cross-compile toolchain needed.

### Fixed

- v0.3.4's npm publish (with the idempotency fix from that release) correctly skipped the two
  already-published platform packages and reached `dstu-core-win32-x64-msvc`, but that package hit
  npm's own spam-detection block again - the same block from v0.3.3, confirmed not time-based (it
  reproduced identically after a 3+ hour wait). Deferred that one platform package explicitly
  (`publish-npm` now skips it outright rather than attempting and tolerating the failure) so the
  rest of the publish - root `dstu-core` and the two working platform packages - isn't blocked by
  it. See `docs/DECISIONS.md` D-189 for the full incident, the research into what actually resolves
  this class of npm block (contacting npm support - renaming doesn't, per a real precedent), and
  what un-defers it once support clears the name.

## [0.3.4] - 2026-08-13

### Fixed

- v0.3.3's npm publish got past the provenance/access fix but hit npm's own spam-detection
  heuristic on the 3rd platform subpackage (`dstu-core-win32-x64-msvc`) after two succeeded
  (`dstu-core-linux-x64-gnu`, `dstu-core-darwin-arm64` both published live). Retrying the same
  tag's job after waiting failed differently: `napi prepublish` (the `prepublishOnly` hook driving
  the whole publish) is not idempotent - its per-platform loop aborts the entire command, root
  package included, the instant `npm publish` fails on any one platform, with no tolerance for
  "this version already exists". The retry died on the 1st platform (already published from the
  prior attempt) and never reached the 3rd or the root package. Replaced the single
  `napi prepublish`-driven `npm publish --provenance` with explicit steps: set root
  `optionalDependencies` directly (the one other thing `napi prepublish` did), then publish each
  platform subpackage and finally the root package each tolerating an "already published" error
  instead of failing the whole job - so a partial-failure retry (the normal case here, given both
  npm's external spam heuristic and rate limits are outside this workflow's control) picks up
  wherever the previous attempt stopped.

## [0.3.3] - 2026-08-12

### Fixed

- `publish-npm`'s `napi prepublish` step failed publishing every platform subpackage
  (`Can't generate provenance for new or private package, you must set access to public`) - `npm
  publish --provenance` refuses to guess the intended access level for a package that's never been
  published, even unscoped ones. Added `"publishConfig": {"access": "public"}` to
  `bindings/nodejs/package.json` - `napi create-npm-dir` already copies that field into every
  generated subpackage (confirmed by reading its source), so this one line covers the root package
  and all three platform packages. Also added `--skip-gh-release` to the `prepublishOnly` script -
  `napi prepublish` tries to create/update a GitHub Release itself by default, redundant with (and,
  lacking `contents: write` in this job, failing 401 against) `release.yml`'s own
  `create GitHub release` job. Confirmed nothing had actually landed on the npm registry from the
  failed attempt before retrying (`registry.npmjs.org/dstu-core*` still 404).

## [0.3.2] - 2026-08-12

### Added

- `dstu-core` (Python bindings) is now genuinely live on [PyPI](https://pypi.org/project/dstu-core/)
  0.1.0 - the 0.3.1 tag's `publish-pypi` run actually went through (see Fixed, below), so this is
  the first release to reflect that as real instead of "prepared, not yet live."

### Fixed

- `environment: pypi`/`npm` in `release.yml` were referenced but never actually protected -
  GitHub auto-creates an environment with zero protection rules the first time a workflow
  references it, so the 0.3.1 tag's `publish-pypi` job ran straight through with no approval
  pause (harmless here - it was the intended package - but not the safety behavior this project
  claimed). Fixed via the GitHub API (`required_reviewers` added to both, project owner as
  reviewer) - not a file in this repo, recorded here so it isn't lost.
- `publish-npm`'s `npm install -g npm@latest` failed on Node 20 (`EBADENGINE` - npm's own latest
  version now requires Node >=22) before ever attempting a publish. Bumped to Node 22.
- npm (unlike PyPI) has no "pending trusted publisher" - a package that has never been published
  can't configure Trusted Publishing for itself at all (open upstream issue, `npm/cli#8544`,
  confirmed live 2026-08-12), so OIDC alone can never reach a first npm publish here. Added a
  one-time bootstrap path: `NODE_AUTH_TOKEN` from a repo secret (`NPM_TOKEN`, an npm token pasted
  directly into GitHub's own secret UI, never into any chat/session) covers only the first
  publish; once `dstu-core` exists on npm, Trusted Publishing takes over and both the env var and
  the secret get removed.
- `publish-pypi` had no `skip-existing`, so any future tag whose Python binding hasn't changed
  (its own version, 0.1.0, isn't lockstepped with the Rust crates' tag) would hard-fail
  re-uploading wheels PyPI already has, rather than skipping them.
- The 0.3.1 tag itself is stuck on an older commit that predates all of the above - none of these
  fixes could reach it by re-running its jobs (a git tag is a fixed pointer; re-running a job in
  an existing workflow run replays the workflow file as it existed at that commit, not the
  latest). This release exists specifically so npm's first real publish attempt runs against a
  workflow that has the fixes, not to add anything else on top of 0.3.1's own -
  crates.io/PyPI don't need re-publishing, just `dstu-core`/`uacrypt`'s version bumped to
  `0.3.2` so `cargo publish` has something new to accept.

## [0.3.1] - 2026-08-12

### Added

- `crypto_box512`/`crypto_sign257`: wired into `dstu-core-capi` and all eight language bindings
  (Python/Node.js/Ruby/Java/PHP/.NET/Go/C++) - both landed in `dstu-core` itself already, in 0.3.0
  above, without this wiring (`docs/TASKS.md` T-204, closed 2026-08-09/10). This release's Python
  wheel (and any other binding artifact attached to a GitHub Release) is the first to actually ship
  this surface outside the Rust crate itself.
- CI infrastructure for publishing the Python (`dstu-core`) and Node.js (`dstu-core`) bindings to
  PyPI and npm (`docs/TASKS.md` T-164/T-203) - both `publish-pypi`/`publish-npm` jobs in
  `release.yml` land dormant, gated behind their own GitHub Environment approval, and use OIDC
  Trusted Publishing exclusively (no token/secret stored anywhere) - the direct fix for a real
  crates.io token-leak incident T-203 records. **Intended as prepared-but-dormant** - see 0.3.2
  above for what actually happened (the dormancy itself had a real gap) and what shipped since.
  Packagist is deliberately not part of this pass -
  `bindings/php` is a compiled `ext-php-rs` extension, and Packagist only distributes Composer
  (PHP-source) packages (`docs/DECISIONS.md` D-144).

### Fixed

- `docs/TASKS.md` T-17 and `CLAUDE.md`'s "MVP scope" both still read "not started" for the
  crates.io publish that actually happened at 0.3.0 above - corrected to reflect reality
  (`docs/DECISIONS.md` D-159's stale-doc failure shape: no task-ID string in either sentence for a
  grep sweep to have caught).

## [0.3.0] - 2026-08-09

**First crates.io publish** (`docs/TASKS.md` T-17, `docs/DECISIONS.md` D-114) - both `dstu-core`
and `uacrypt`, completing the `publish-crates` CI job D-114 wired in for this exact tag. `uacrypt`
also stays available prebuilt via GitHub Releases as before - `cargo install uacrypt` is now an
additional option, not a replacement. This does not change the project's own honesty posture:
still pre-1.0, still not independently audited, and the headline provisional gaps tracked in
`docs/release-readiness.md` (D-05's Kalyna-alone AEAD assumption and Strumok's vectors, both not
yet confirmed against their primary DSTU texts) are unchanged by this release - see that document
and `docs/DECISIONS.md` for the full standing caveats, repeated here exactly as prominently as
0.2.0's own notes did below.

### Added

- `hazmat::dstu9041`: DSTU 9041:2020 hybrid (ECIES-style) asymmetric encryption over a twisted
  Edwards curve, `l(p)=256`/E256/1 only (D-47's "ship the recommended curve first" precedent) -
  `F_p` bignum arithmetic, twisted-Edwards point arithmetic, and encrypt/decrypt composition,
  verified against the standard's own worked example (`docs/TASKS.md` T-177).
- `crypto_box`: public-key encryption over `hazmat::dstu9041`, hybrid via KDF (a random seed sealed
  asymmetrically, expanded via `hazmat::kupyna_kdf`, then `crypto_secretstream` encrypts the actual
  message) - `seal`/`open`/`SecretKey`/`PublicKey` (32-byte compressed, `x`-coordinate only,
  `docs/TASKS.md` T-178, `docs/DECISIONS.md` D-169). `uacrypt box-keygen`/`box-pubkey`/`box-seal`/
  `box-open` CLI surface.
- `hazmat::dstu9041`: `l(p)=512`/E512/1, the second curve size after `l(p)=256` -
  `message512`/`fp512`/`curve512`/`encryption512`, same phased/test-first pattern, verified against
  the standard's own worked example; both `l(p)=256` security findings (an order-2 point, a
  cofactor-4 subgroup) independently re-derived and re-confirmed applicable, not assumed to carry
  over (`docs/TASKS.md` T-192).
- `crypto_box512`: direct `l(p)=512` sibling of `crypto_box`, `PublicKey`/`SecretKey` at 64 bytes,
  seed deliberately fixed at 32 bytes/256 bits (not `l(p)=512`'s full KEM capacity, D-182) -
  `seal`/`open`/`SecretKey`/`PublicKey`, `uacrypt box-keygen512`/`box-pubkey512`/`box-seal512`/
  `box-open512` CLI surface. Not yet wired into any language binding or `dstu-core-capi` (separate
  future task, T-193's own scope note) (`docs/TASKS.md` T-193, `docs/DECISIONS.md` D-182/D-183).
- `hazmat::dstu4145`: a second curve, `m=257` (`gf2m257`/`curve257`/`scalar257`/`signature257`) -
  what real Diia-issued qualified signatures actually use in production (confirmed from real
  issued certificates, not just the standard's own curve table), alongside the existing `m=163`.
  `crypto_sign257` wraps it as a full sibling of `crypto_sign` (`SigningKey`/`VerifyingKey`/
  `Signature`, deterministic Kupyna-KMAC nonce). `uacrypt sign-keygen257`/`sign-pubkey257`/
  `sign257` CLI surface; `uacrypt verify` reads a curve tag byte from `--key` and handles both
  `m=163` and `m=257` signatures through the one command (`docs/TASKS.md` T-199, `docs/DECISIONS.md`
  D-185/D-186).
- `uacrypt`: real binary-level (subprocess) smoke tests, `crates/uacrypt/tests/` - 75 tests
  spawning the actual compiled `uacrypt` binary (exit codes, stdout/stderr, real files), covering
  every leaf command's golden path plus targeted attack scenarios (T-199's tagged-verifying-key
  format, `crypto_secretstream`'s wire-format tamper resistance, cross-key-type confusion between
  same-length key files, `--in`==`--out` in-place usage, `--help` text checked as a pinned
  behavioral claim rather than prose, a constructed order-2/small-subgroup public key rejected by
  `verify --key` for both DSTU 4145 curves and by `box-open` for `crypto_box`/`dstu9041`
  (D-167 Finding 1's `r=p-1` case), an exhaustive missing-required-flag sweep across all ~34 leaf
  command shapes). Previously the entire 140-test suite only ever called the library's `run()`
  in-process (`docs/TASKS.md` T-200).
- `cargo xtask streaming-bounded`: release-build proof, against a real 200 MiB file, that
  `encrypt`/`decrypt`/`kupyna-digest`/`strumok-crypt` stay memory-bounded rather than buffering the
  whole input (D-42's claim, previously asserted only in a doc comment) - samples the real
  subprocess's OS-reported resident memory while it runs (`crates/uacrypt/tests/support/mod.rs`,
  one implementation per OS, no new dependency), with a `box-seal` control case proving the
  measurement can actually detect unbounded growth. `#[ignore]`d by default in a plain `cargo test`
  (needs a release build for realistic timing - a debug-profile run of the same property took over
  5 minutes and was killed before finishing); wired into `cargo xtask ci`'s optional layers and a
  new CI job matrixed across all three OSes (`docs/TASKS.md` T-200).

### Fixed

- `crypto_sign`/`hazmat::dstu4145` (`m=163`): `VerifyingKey::from_uncompressed_bytes` accepted a
  caller-supplied public key with no on-curve check, and `verify` never validated its own `q`
  parameter either - a signature could be forged against `Point::Infinity` or the curve's one
  order-2 point (cofactor `h=2`, confirmed dual-source against Bouncy Castle) without ever needing
  the real private key. Found auditing T-183, fixed immediately as a real vulnerability, not
  deferred to backlog. Three tests actively forge working `(r, s)` pairs against all three attack
  points to confirm rejection, rather than trusting a walkthrough (`docs/TASKS.md` T-189,
  `docs/DECISIONS.md` D-172).
- `uacrypt strumok-crypt`: `--in`==`--out` ("apply the keystream to this file in place") silently
  destroyed the input - exit code 0, 0-byte result, no error - instead of round-tripping. The
  streaming path opened `--out` via `File::create` (truncating it) before finishing reading `--in`.
  Found by T-200's own `--in`==`--out` smoke-test probe of the real binary, fixed with the same
  temp-file-then-rename discipline `encrypt`/`decrypt` already use (`docs/DECISIONS.md` D-187).

### Changed

- `hazmat::gf2m_wide`/`hazmat::dstu4145::gf2m163`: `multiply()` now dispatches to a hardware
  carry-less-multiply implementation (`PCLMULQDQ`/`PMULL`) at runtime when the CPU supports it and
  the `std` feature is enabled, falling back to the existing portable software path otherwise -
  `no_std`/embedded builds and CPUs without the instruction are unaffected. Real measured speedups:
  Kalyna-GCM 256-256 throughput up ~2.2-4.6x on top of the already-landed word-wise `reduce` fix,
  DSTU 4145 `sign`/`verify` up ~26-32x on the dev machine (`docs/TASKS.md` T-198,
  `docs/DECISIONS.md` D-184).

## [0.2.0] - 2026-08-02

Second tagged release - GitHub Releases only, no crates.io publish (`docs/TASKS.md` T-17 stays
separately gated, same posture as v0.1.0).

### Added

- `crypto_sign`/`uacrypt`: DSTU 4145 digital-signature CLI commands - `sign-keygen`, `sign-pubkey`,
  `sign`, `verify` (`docs/TASKS.md` T-124).
- `dstu-core`: `getrandom` Cargo feature - a `no_std`-compatible RNG path via `getrandom` 0.3's
  link-time custom backend, for targets without `std` (T-123, `docs/DECISIONS.md` D-74).
- Official Strumok-256/512 supplementary test vectors from two additional state-sourced supplements
  (beyond the existing UAPKI-attributed set), D-104.
- Kani bounded-model-check proofs for `gf2m163::reduce`'s two previously hand-argued claims,
  checked exhaustively over all 2^384 possible inputs (T-145).
- CodeQL advanced-setup CI migration, explicit least-privilege CI permissions (T-143); SonarCloud
  static analysis wired into CI (T-140).

### Fixed

- DSTU 4145 `scalar_multiply` returned a wrong result for scalars at/near the curve's own group
  order - reachable in-contract at exactly one boundary value (`k == n-1`). No forgery risk
  (confirmed via an independent Bouncy Castle cross-check), but a genuine correctness bug every
  `sign`/`verify` call went through. See `docs/DECISIONS.md` D-110.

### Changed

- Performance: DSTU 4145 `sign` ~2.6x faster, `verify` ~4.4x faster (cumulative) - bit-interleave
  GF(2^163) squaring and an Itoh-Tsujii addition-chain field inversion, plus a projective/Shamir's-
  trick fast path for `verify`'s public-scalar combine step. Narrows the gap to OpenSSL's
  `nistb163` from ~21-23x to ~5-8x slower. See `docs/DECISIONS.md` D-108/D-109, `docs/PERFORMANCE.md`.
- Kalyna: const-generic round functions close most of the block-cipher gap with the UAPKI reference
  (T-128); the GCM/GMAC field-multiply bottleneck closed via a 4-bit comb multiply (T-125);
  CMAC/GMAC/KW gain a cached-schedule API surface, XTS gains a faster `GF(2^m)` doubling
  (T-126/T-127).
- Kupyna gains a const-generic compression function (T-134); Strumok's keystream generation is
  batched/fixed-index (T-135).

### Notes

- No breaking changes in the public `crypto_*`/`hazmat` API surface. `uacrypt`'s on-disk
  `encrypt`/`decrypt` wire format was already changed pre-1.0 in a prior, unreleased state (the
  chunked `crypto_secretstream` format) - not part of this release specifically.
- **Language bindings (`bindings/`) and the C ABI crate (`crates/dstu-core-capi`) are not part of
  this release** - none of the eight bindings (Python/Node/Ruby/PHP/.NET/Java/Go/C++, all done as
  of 2026-08-03, `docs/bindings-strategy.md`) or the C ABI crate itself have ever shipped in a
  tagged GitHub Release; this file only records what actually releases (crates.io/GitHub Releases),
  not every landed change - per-binding status lives in `docs/TASKS.md`/`docs/bindings-strategy.md`
  instead.
- Still pre-1.0, not audited, and **not a claim of side-channel resistance**.

## [0.1.0] - 2026-07-26

First tagged release - GitHub Releases only (`docs/TASKS.md` T-18); not published to crates.io
(`docs/TASKS.md` T-17 stays separately gated on an explicit owner request). Everything below predates
this tag; there is no reconstructed per-commit history before it.

### Added

- `dstu-core`: `hazmat` primitives for all three in-scope DSTU algorithms - Kupyna (DSTU
  7564:2014, one-shot and streaming), Kalyna (DSTU 7624:2014, single-block encrypt/decrypt across
  all five key/block-size variants), and Strumok (DSTU 8845:2019, keystream generation).
- `dstu-core`: full DSTU 7624 mode-of-operation coverage over Kalyna - ECB, CBC, CFB, OFB, CTR,
  CMAC, KW, CCM, GCM/GMAC, and XTS.
- `dstu-core`: DSTU 4145-2002 digital signatures (`hazmat::dstu4145`, deterministic nonce
  derivation).
- `dstu-core`: libsodium-shaped high-level `crypto_*` frontend over the above -
  `crypto_secretbox`, `crypto_secretstream` (chunked/streaming AEAD), `crypto_generichash`,
  `crypto_auth`, `crypto_kdf`, `crypto_stream`, `crypto_sign`, `crypto_pwhash` (Argon2id, not a
  DSTU primitive), `randombytes`.
- `dstu-core`: `no_std`/`alloc`/`std` feature gating, plus an independent `small-tables` resource
  profile for constrained targets. Cross-compilation confirmed for `thumbv7em-none-eabihf`
  (STM32 Cortex-M) and `riscv32imc-unknown-none-elf` (ESP32-C3-class RISC-V).
- `uacrypt`: CLI binary over `dstu-core` - `keygen` (fresh 32-byte key from the OS CSPRNG),
  `encrypt`/`decrypt` (over `crypto_secretstream`, genuinely chunked disk I/O), `hash`
  (Kupyna-256), plus `hazmat`-scoped multi-variant tools (`kalyna-block`, `kalyna-ccm`,
  `kupyna-digest`, `strumok-crypt`). Plain-language `--help`/`-h` for every command, `--version`/
  `-V` at the top level.
- Official DSTU test vectors for Kalyna, Kupyna, and DSTU 4145; dual-oracle verification
  (Bouncy Castle Java/.NET harnesses) for Kalyna and Kupyna.

### Changed

- `uacrypt encrypt`/`decrypt`'s on-disk wire format changed twice pre-release: originally a
  single-shot `crypto_secretbox` blob (255-byte cap), then migrated to uncapped `crypto_secretbox`
  over Kalyna-GCM, then to the current genuinely chunked `crypto_secretstream` format. Each change
  is a breaking format change from the one before it - acceptable pre-1.0 and pre-publication, not
  covered by any compatibility guarantee.

### Notes

- Kalyna-alone AEAD mode-of-operation (D-05) and the Strumok test vectors (D-15) are provisional:
  adopted on corroborating evidence, not confirmed against the primary DSTU text. See
  `docs/SECURITY.md`/`docs/DECISIONS.md` for the full provisional-status caveats.
- No independent third-party security audit has been performed. `no_std` compiling is not a
  side-channel-resistance claim.
