# TASKS.md

Progress tracker and task backlog for this project, grouped by phase. Check items off as they're
done; add new items as they're discovered. This file tracks **what** and **status** — the
**why** behind any decision or blocker lives in `DECISIONS.md`/`ORACLES.md`/`SECURITY.md` and is
linked from here, not duplicated.

Per `CLAUDE.md`'s "Agent discipline": every implementation task below is test-first — the
test-vector check (or unit test) is written before the primitive it verifies, not after.

Every checklist item carries a stable `T-NN` ID (assigned in document order, added 2026-07-23) so
it can be referenced elsewhere without quoting its full text — new items get the next unused
number appended to the end of this list; existing IDs are never renumbered or reused, even if the
item they point to is later removed.

## Phase 0 — Scaffold (done)

- [x] **T-01** Cargo workspace (`dstu-core` + `dstutool`), dual MIT/Apache-2.0 licensing
- [x] **T-02** `no_std`/`alloc`/`std` feature flags in place from the first commit (D-01)
- [x] **T-03** Docs translated to English; repo structure split per GitHub/Rust-crypto conventions
- [x] **T-04** `SECURITY.md`, `DECISIONS.md`, `ORACLES.md` written
- [x] **T-05** Oracle infrastructure pulled and vetted: `kalyna-reference`, `kupyna-reference`,
      `outspace/dstu8845`, `bouncycastle-{java,dotnet}`, `cryptonite` (see `oracles/README.md`)
- [x] **T-06** `li0ard` excluded as untrusted supply chain (D-07)
- [x] **T-07** Kalyna (5 variants) + Kupyna (2 variants) official test vectors extracted from the
      designers' papers into `crates/dstu-core/tests/vectors/`
- [x] **T-08** Per-algorithm pseudocode docs: Kalyna, Kupyna, Strumok, DSTU 4145
      (`docs/pseudocode/*.md`)
- [x] **T-09** Post-quantum track (DSTU 8961/9212) explicitly excluded from scope (D-08)

## Phase 1 — MVP: Kalyna + Kupyna + Strumok core

- [x] **T-10** Implement Kalyna (all 5 block/key-size variants) — `dstu_core::hazmat::kalyna`
      (`Kalyna128_128`/`Kalyna128_256`/`Kalyna256_256`/`Kalyna256_512`/`Kalyna512_512`), citation
      in `DECISIONS.md` D-13. **Confirmed 2026-07-22**: `cargo test` (all 5 variants against the
      official vectors, first attempt, no debugging needed), `cargo clippy -- -D warnings`, `cargo
      fmt --check`, and the `no_std` build all pass. S-box/MDS tables shared with `hazmat::kupyna`
      via a new `hazmat::tables` module rather than duplicated (D-13). `cargo miri test` also
      confirmed clean (no UB, all 5 variants, ~158s). Same day (D-16 update): UAPKI's
      `dstu7624_ecb_self_test` (single-block case, all 5 variants × encrypt/decrypt) matches
      byte-for-byte too — same official vector set, not a new independent reading.
      **Independent second-oracle cross-check was actually already closed by T-77/T-78
      (2026-07-21/22, before this bullet was last edited) — this note was simply stale, not a real
      gap.** Re-confirmed fresh 2026-07-23: both the Java and .NET harnesses run real Bouncy
      Castle's `DSTU7624Engine` against all 5 Kalyna variants (10/10 cases each) — found and fixed
      a real bug doing so, see `xtask oracle-java`'s note below. Remaining gap, unchanged: no mode
      of operation confirmed against the primary text (D-05; `hazmat::kalyna_ccm`, D-41, is a
      provisional interim, not this) — UAPKI's CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM self-tests
      beyond what CCM already used are unused KAT data waiting for whenever more modes get built,
      same as Kupyna's KMAC below.
- [x] **T-11** Implement Kupyna (256/512) — `dstu_core::hazmat::kupyna` (`Kupyna256`/`Kupyna512`),
      citation in `DECISIONS.md` D-10. **Confirmed green 2026-07-22**: `cargo test`, `cargo miri
      test` (no UB), `cargo clippy -- -D warnings`, and `no_std` build all pass; independently
      cross-checked against real Bouncy Castle via the .NET and Java oracle harnesses, and (same
      day, D-16 update) UAPKI's `dstu7564_self_test_hash` matches byte-for-byte too — same
      official vector set, not a new independent reading, but confirms UAPKI's numbers agree.
      Still missing: `cargo fuzz` actually run (scaffold exists), the high-level API split (D-09)
      has no wrapper here yet — this is `hazmat` only — and KMAC (Kupyna-based MAC, see the
      `crypto_auth` line below) isn't implemented at all yet. **Streaming API added 2026-07-23,
      see T-83.**
- [x] **T-83** **Kupyna streaming API - `Kupyna256Hasher`/`Kupyna512Hasher` (`new`/`update`/
      `finalize`), closing T-11's last gap.** Refactored the shared `digest_generic` into a new
      internal `KupynaCore` (holds the chaining state `h`, a `MAX_BLOCK_BYTES`-sized partial-block
      buffer, and a running byte counter for the padding's length field) so the one-shot `digest()`
      path is now just `new` + one `update` + `finalize` over the same struct - one implementation
      of the padding/length-tracking logic, not two. No `alloc`/`Vec` used (buffer is a fixed-size
      array), so this stays `no_std`-compatible without any new `cfg` gating - confirmed by
      re-running the full 8-combination `no_std`/`alloc`/`std`/`small-tables` build matrix clean.
      **Test-first, and the discipline caught a real bug**: wrote the official-vector-via-streaming
      tests, a `Default`-matches-`new` test, a chunk-invariance test (mirroring T-24's Strumok
      pattern - splitting one message across `update` calls at non-block-aligned boundaries must
      match one `update` on the whole message), and a `proptest` (arbitrary message, arbitrary
      split point, streaming must match `digest()`) before writing `update`/`finalize` themselves.
      The chunk-invariance and `proptest` cases both failed on the first implementation attempt: a
      partial-fill case (message tail shorter than one block, spread across two `update` calls)
      was silently discarding the already-buffered bytes' length bookkeeping - the buffer's
      physical bytes were fine, but the trailing "write `buffer_len` from this call's leftover
      remainder" step unconditionally overwrote it to the wrong (too-small) value regardless of
      whether that step actually applied this call. Fixed by returning early after a partial,
      not-yet-block-full buffer fill instead of falling through to that overwrite - exactly the
      kind of boundary bug a single-`update`-only test (all the official vectors are, by
      construction) can never catch, confirming why T-24's pattern was worth copying here rather
      than skipping it as redundant with the vector tests. All 9 new/updated tests green after the
      fix, `cargo clippy -- -D warnings`/`cargo fmt --check` clean (one
      `#[allow(clippy::needless_range_loop)]` needed on the output-transform XOR loop - same
      lockstep-two-arrays false-positive family as D-39's three cases, `self.h`/`t_final` this
      time), `cargo miri test` run against the new test file specifically.
- [x] **T-84** **`uacrypt kupyna-digest`/`strumok-crypt` made genuinely streaming from disk
      (`DECISIONS.md` D-42), same day.** User asked directly whether T-83's streaming was
      "honest" - small bounded chunks in memory, nothing quietly buffered whole. Answer at the
      hazmat level was yes; at the CLI level, no - both commands still did one whole-file
      `std::fs::read`. Fixed for real single-pass use (`iterations <= 1`): `kupyna-digest` reads
      an 8 KiB chunk at a time via `Kupyna*Hasher`; `strumok-crypt` reads an 8 KiB chunk, applies
      the keystream in place, writes it, and discards it (chunking both read *and* write, since a
      cipher's output length equals its input length, unlike a hash) - relying on
      `Strumok::apply_keystream`'s own chunk-invariance (T-24) for correctness. The `--iterations`
      benchmark path for both commands deliberately still reads the whole file once up front (D-34:
      re-reading per iteration would put disk I/O noise into the timed MB/s figure), then re-hashes/
      re-applies through larger in-memory chunks. Verified: new multi-chunk tests for both commands
      (non-chunk-aligned message lengths, checked against `hazmat` directly) plus manual round-trips
      through the real release binary (kupyna-digest on 5 MiB+, strumok-crypt on 3 MiB+), all
      matching. Recorded as standing policy for any future streaming CLI work in `CLAUDE.md`'s
      Agent discipline section, not just a one-off fix.
- [x] **T-12** **Blocker lifted 2026-07-22 (D-15/D-16), not fully resolved:** found
      https://github.com/specinfo-ua/UAPKI (state-expertise pedigree, see `ORACLES.md`), whose
      `dstu8845.c` self-test is comment-attributed to `// ДСТУ 8845:2019` in its own source — the
      first real KAT found anywhere for this algorithm. Adopted as
      `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json` (an earlier, self-invented
      "gray vector" attempt from the same day was superseded and deleted, not kept). Cross-checked
      against `oracles/strumok-dstu8845/` (byte-identical, but treated as a lineage-sharing
      consistency bonus, not independent confirmation — see D-15) via
      `tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`. **Still not
      "official"**: not confirmed against the paid DSTU 8845:2019 text itself.
- [x] **T-13** Implement Strumok (256/512-bit key) — `dstu_core::hazmat::strumok` (`Strumok256`/
      `Strumok512`), citation in `DECISIONS.md` D-18. **Confirmed 2026-07-22**: all 8
      UAPKI-attributed keystream cases pass on the first attempt, `cargo test`, `cargo clippy -- -D
      warnings`, `cargo fmt --check`, `no_std` build, and `cargo miri test` all clean. Structurally
      cross-checked against both `outspace/dstu8845` and `oracles/uapki/.../dstu8845.c` per the
      pseudocode doc; the `T` substitution reuses the shared `hazmat::tables` (no new tables
      needed), `mul_alpha`/`mul_alpha_inv` tables transcribed and cross-checked byte-for-byte
      between the two oracles. **Status line, not to be dropped**: "UAPKI-attributed, not confirmed
      against the official text" (D-15) — implementing this did not change that provenance ceiling.
      `dstutool` doesn't call this yet.
- [x] **T-14** `cargo miri test` clean for all three primitives (Kalyna/Kupyna/Strumok, each confirmed
      individually above)
- [x] **T-15** `cargo fuzz` harnesses for all three primitives — `kalyna`, `kupyna`, and `strumok` targets
      all exist now (`crates/dstu-core/fuzz/fuzz_targets/`). **Cannot actually run locally**:
      `cargo-fuzz` installed fine (needed `mingw64/bin`'s `dlltool.exe` on PATH, same requirement
      as `cargo-audit`/`cargo-deny`, see `.claude.local.md`), but building any target fails two
      ways in a row on this environment's GNU/MinGW toolchain — first "address sanitizer is not
      supported for this target" (`x86_64-pc-windows-gnu`, ASan needs MSVC on Windows), then with
      `--sanitizer none`, `libfuzzer-sys`'s own `FuzzerExtFunctionsWindows.cpp` fails to compile
      under `g++` (`__pragma(comment(linker, ...))` is an MSVC-only compiler extension, confirmed
      by compiling that one file directly with `g++` and reading the real error past cc-rs's
      truncated one). **Not something to chase further here**: this project deliberately chose the
      GNU host toolchain specifically to avoid needing Visual Studio Build Tools/MSVC (see
      `.claude.local.md` "Toolchains"), and libFuzzer-on-Windows is an MSVC-only path upstream —
      same shape as the cryptonite C-harness being dropped below (a real, confirmed toolchain
      incompatibility, not a skipped step). CI (a Linux runner) remains the actual venue where
      these targets get run, same as this project already says for the fuzz scaffold generally.
      **Update, later the same day**: this machine turned out to already have Visual Studio
      installed for unrelated reasons, so the objection above ("would mean installing MSVC just for
      this") stopped applying here specifically — see "Testing & hardening" below and `DECISIONS.md`
      D-32 for how it was actually run.
- [x] **T-16** **Done 2026-07-24, same session as T-37, see `DECISIONS.md` D-52** — `uacrypt`'s
      reserved `encrypt`/`decrypt`/`hash` are real top-level commands now, mode/nonce/algorithm all
      hardcoded, no user-facing crypto knobs. `encrypt`/`decrypt` are a thin wrapper over
      `dstu_core::crypto_secretbox` (T-37/D-51): new `SecretboxArgs { key_path, in_path, out_path }`
      - no `--nonce`/`--tag`/`--aad`/`--variant`, since `crypto_secretbox` itself already removed
      every one of those knobs. **Approval checkpoint surfaced and resolved with the user before
      implementation**: `crypto_secretbox` caps messages at 255 bytes, and a command literally named
      `encrypt --in file --out file` silently failing past that would be a real usability trap,
      especially next to `hash` which handles files of any size — asked directly via
      `AskUserQuestion`, user chose **build all three now, cap made loud** (new
      `CliError::MessageTooLong` with an explicit "255-byte limit... see `TASKS.md` T-40" message,
      never silent truncation) over deferring `encrypt`/`decrypt` to `crypto_secretstream` (T-40).
      Two more new `CliError` variants (`Truncated`, `SecretboxVerifyFailed`) plus a
      `From<SecretboxError>` impl mirroring the existing `From<CcmError>` one — deliberately not
      reusing `PlaintextTooLong`/`CcmVerifyFailed`, whose `Display` text is hardcoded to say
      "kalyna-ccm" and would print a wrong command name. `hash` is fixed to Kupyna-256 (D-47's
      "no knob when a safe default exists"; `crypto_sign` already established Kupyna-256 as this
      project's own default message-hash choice) — new `HashArgs { in_path, out_path }`, no
      `--variant`/`--iterations`, implemented by **delegating to the existing `run_digest_command`**
      (`DigestArgs { variant: B256, iterations: 1, .. }`) rather than duplicating its
      already-tested, genuinely-streaming-from-disk (D-42) loop — `hash` inherits that
      memory-bounded property for free, no cap of its own. Test-first, 12 new tests (all green
      first attempt): `parse_secretbox_args`/`parse_hash_args` happy-path/missing-flag/
      unknown-flag, a round-trip test cross-checked against a direct `dstu_core::crypto_secretbox`
      call, fresh-nonce-per-call, tamper-rejection-without-writing-`--out`, oversized-input
      rejection, a multi-chunk streamed-hash check against `Kupyna256::digest` directly, and two
      tests calling the public `run()` dispatcher directly (not just the `run_*_command`
      functions) for both new command groups, since the three new top-level match arms are new
      wiring needing their own coverage. `cargo test --workspace --all-features`/`clippy -D
      warnings`/`fmt --check` all clean. Split into 3 commits per the user's request (`hash`;
      `encrypt`/`decrypt` + `CliError` plumbing; docs), not one combined commit like T-37's.
      README.md/`CLAUDE.md`/`docs/dstu-crypto-project.md` all updated to state the 255-byte cap
      loudly, not as a footnote — `CLAUDE.md`'s own MVP-scope example line previously read as
      implying arbitrary-file support, now corrected. No `uacrypt keygen` command added (out of
      this task's stated scope, same gap `kalyna-block`/`kalyna-ccm` already have).
- [ ] **T-17** Publish `dstu-core` to crates.io. **Readiness-checked (not performed) 2026-07-25,
      Step 4 of the roadmap, user explicitly asked to assess without actually publishing**:
      `cargo publish --dry-run -p dstu-core` packages, verifies, and compiles cleanly from the
      packaged tarball (130 files, 764.7 KiB / 184.6 KiB compressed). One warning, not a blocker:
      "manifest has no documentation, homepage or repository" (`repository`/`homepage`/
      `documentation` fields absent from `crates/dstu-core/Cargo.toml`). **Real gap found**:
      neither `crates/dstu-core/` nor `crates/uacrypt/` has its own `README.md`, and neither
      `Cargo.toml` sets a `readme` field - only the workspace-root `README.md` exists, which
      `cargo package` does not reach (packaging only includes files inside each crate's own
      directory) - so the crates.io page would render with **no README at all** as things stand,
      not a cosmetic issue for a crate whose entire pitch is "read this before you trust it with
      key material." Publish order also confirmed mechanically: `cargo publish --dry-run -p
      uacrypt` fails today with "no matching package named `dstu-core` found" (its path dependency
      can't resolve against the registry until `dstu-core` is actually published first) - expected,
      not a bug, just fixes the required order (`dstu-core` before `uacrypt`). None of this touched
      the actual crates.io registry - `--dry-run` uploads nothing.
- [ ] **T-18** Prebuilt Windows/Linux binaries via GitHub Releases. **Readiness-checked 2026-07-25**:
      zero infrastructure exists yet - `.github/workflows/` has only `rust.yml`/`oracle-harness.yml`,
      no release/cross-compilation/binary-packaging workflow at all. This is unstarted work, not a
      near-miss.
- [x] **T-107** Add a per-crate `README.md` to `crates/dstu-core/` and `crates/uacrypt/`, and set
      each crate's `readme` field in its own `Cargo.toml`. **Found during T-17's 2026-07-25
      readiness check**: only the workspace-root `README.md` exists; `cargo package` only reaches
      files inside each crate's own directory, so the crates.io page for either crate would
      currently render with no README at all - not cosmetic for a crypto library. Blocks T-17
      (do this before the real `cargo publish`, not after).
      **Done 2026-07-25 (Step 5 item 2 of the roadmap).** Each README is crate-scoped, not a copy
      of the root one: `dstu-core/README.md` covers the `hazmat`/`crypto_*` two-layer split, the
      feature-flag table (`std`/`alloc`/`small-tables`/`pwhash`), a `crypto_secretbox` usage
      example, and the same provisional-status/no-side-channel-claim safety framing the root
      README and `SECURITY.md` already carry; `uacrypt/README.md` covers the actual command set
      (`encrypt`/`decrypt`/`hash` plus the lower-level `kalyna-block`/`kalyna-ccm`/`kupyna-digest`/
      `strumok-crypt`) with real, verified flag names (cross-checked against `parse_*_args` in
      `crates/uacrypt/src/lib.rs` rather than copied from memory - `kupyna-digest`/`strumok-crypt`
      needed direct verification since the root README's own command walkthrough doesn't cover
      them). Neither README links a `LICENSE-MIT`/`LICENSE-APACHE` copy inside its own crate
      directory - no such physical copy exists yet, that's T-109's scope, not this task's; the
      wording says "in the project repository" rather than implying a local file. Both `Cargo.toml`
      files got `readme = "README.md"`. **Verified**: `cargo package --list -p dstu-core`/`-p
      uacrypt` both now include `README.md` in the packaged file list (confirmed via direct
      `grep`, not assumed); `cargo publish --dry-run -p dstu-core` re-run and its file count rose
      130 -> 133 (both new `README.md`s plus their surrounding directory listing), with the
      pre-existing "no documentation, homepage or repository" warning unchanged (that's T-109's
      metadata gap, not this one, correctly still open). `cargo xtask fmt --check`/`build`/`clippy`
      all clean - doc-only change, no source touched. No `DECISIONS.md` entry - packaging hygiene,
      nothing architectural to record (same call T-97 made for its own trivial doc fix).
- [x] **T-108** User-friendly `--help`/usage text for the `uacrypt` binary, in plain language a
      non-cryptographer can follow - requested 2026-07-25. **Confirmed gap**: `uacrypt`'s `run()`
      dispatcher (`crates/uacrypt/src/lib.rs`) has no `--help`/`-h` handling at all right now - an
      unrecognized argument (including `--help` itself) just falls through to
      `CliError::UnknownCommand`, and `None` (no args) does the same rather than printing usage.
      Scope: top-level `uacrypt --help`/`uacrypt` (no args) listing every command
      (`encrypt`/`decrypt`/`hash`/`kalyna-block`/`kalyna-ccm`/`kupyna-digest`/`strumok-crypt`) in
      plain terms (what it's for, when to reach for it vs. the plain `encrypt`/`decrypt`/`hash`
      trio), plus a per-command `uacrypt <command> --help` showing its actual flags with a short
      example invocation - not just a flag/type dump. Should explain the few hard, easy-to-miss
      constraints in the same plain language (`encrypt`/`decrypt` needs a 32-byte key; `--in`/
      `--out` can't be the same path for the `kalyna-*` raw commands; `hash` has no length cap).
      **Correction found while writing the help text, not assumed**: the "`--in`/`--out` can't be
      the same path for the `kalyna-*` raw commands" constraint above is actually false - empirically
      checked (not guessed) by building the release binary and running `kalyna-block encrypt`/
      `decrypt` and `kalyna-ccm encrypt`/`decrypt` with `--in`/`--out` pointing at the identical
      path: both round-trip correctly on every command, because every one of them fully reads its
      input into an owned buffer (`read_exact_file`/`std::fs::read`) before ever opening `--out` for
      writing. This constraint is *not* stated anywhere in the shipped help text, since it isn't
      real.
      **Done 2026-07-25.** Added `is_help_flag`, a `TOP_LEVEL_HELP` const plus one per-command help
      const (`ENCRYPT_HELP`/`DECRYPT_HELP`/`HASH_HELP`/`KALYNA_BLOCK_HELP`/`KALYNA_CCM_HELP`/
      `KUPYNA_DIGEST_HELP`/`STRUMOK_CRYPT_HELP`), and `print_command_help` (falls back to
      `TOP_LEVEL_HELP` for an unrecognized name - not reachable through `run()` itself, but tested
      directly rather than left an unverified assumption) to `crates/uacrypt/src/lib.rs`. `run()`
      now treats `uacrypt` with no args and `uacrypt --help`/`-h` identically - print
      `TOP_LEVEL_HELP`, return `Ok(())` (a deliberate behavior change from the old `None =>
      Err(CliError::UnknownCommand(...))`, confirmed via grep that no existing test relied on that
      arm before changing it). Every command checks its *entire* remaining argument list for
      `--help`/`-h` (not just the first token) before parsing, so e.g. `kalyna-block encrypt --key k
      --help` prints help instead of failing on the missing `--in`/`--out` - `kalyna-block`/
      `kalyna-ccm` also accept `--help` before the `encrypt`/`decrypt` sub-subcommand is even given.
      Help text plain-language notes cover the real constraints instead of the false one above:
      `encrypt`/`decrypt` need a 32-byte key and may safely share `--in`/`--out`; `kalyna-ccm` caps
      messages/AAD at 255 bytes; `strumok-crypt` is explicitly flagged as **not authenticated** with
      a key/IV-reuse warning; `hash` has no length cap. 8 new tests (all green): no-args and
      `--help`/`-h` at top level, an unknown command still errors, every one of the 7 top-level
      commands' `--help` succeeds without their other required flags, `kalyna-block`/`kalyna-ccm`
      accept `--help` both before and after the `encrypt`/`decrypt` sub-subcommand, `--help`
      alongside an otherwise-incomplete flag set still wins over `MissingFlag`, and the
      unrecognized-name fallback in `print_command_help` itself. Manually exercised the built debug
      binary for `uacrypt`, `uacrypt --help`, `kalyna-ccm --help`, `strumok-crypt -h`,
      `kalyna-block encrypt --key k --help`, and an unknown command, confirming both the printed
      text and exit codes (0 for help, 1 for `unknown command`) match what the tests check.
      Verified: full `cargo test --workspace --all-features` (55/55 `uacrypt` tests including the 8
      new ones, plus `dstu-core`'s own suite, all green, exit 0), `cargo clippy --workspace
      --all-features -- -D warnings` clean, `cargo fmt --all -- --check` clean. No `DECISIONS.md`
      entry - CLI ergonomics, nothing architectural.
- [x] **T-109** Complete `Cargo.toml` publish metadata for both crates - requested 2026-07-25
      (libsodium/crates.io best-practice review, see `docs/release-readiness.md` "Libsodium API
      surface and crates.io publishing audit"). Neither `dstu-core/Cargo.toml` nor
      `uacrypt/Cargo.toml` sets `repository`/`homepage`/`documentation`/`keywords`/`categories`/
      `rust-version` - confirmed by reading both files directly 2026-07-25, only `license` and
      `description` are present. **Not a hard `cargo publish` blocker** - `cargo publish --dry-run
      -p dstu-core` already succeeds today with just those two fields (T-17's readiness check),
      only warning about the missing `documentation`/`homepage`/`repository` trio - so this is a
      quality/discoverability gap, not a publish-blocking one, and any secondary-source claim that
      `repository` is mandatory (one research pass said so) is contradicted by that dry-run and
      should not be trusted over it. `categories` must be picked from crates.io's actual fixed
      taxonomy (e.g. a `cryptography` slug, a `no-std` slug if one exists) - verify the real slugs
      at publish time, don't guess from memory. Also add a physical `LICENSE-MIT`/`LICENSE-APACHE`
      copy inside `crates/dstu-core/` and `crates/uacrypt/` - confirmed via `cargo package --list`
      2026-07-25 that neither crate's packaged tarball currently includes either license file (they
      only exist at the repo root, which `cargo package` never reaches); the `license` SPDX field
      alone satisfies the registry, but shipping without the actual license text is not the
      ecosystem norm (RustCrypto crates ship a physical copy per crate). Blocks T-17 alongside
      T-107, same "do before the real publish" reasoning.
      **Done 2026-07-25.** `repository`/`homepage` both point at
      `https://github.com/user137/uacrypt` (the actual `git remote -v` origin - no separate project
      website exists, so homepage deliberately duplicates repository rather than being invented);
      `documentation` is the crate's own future docs.rs URL (`https://docs.rs/dstu-core` /
      `https://docs.rs/uacrypt`). `categories` slugs verified live against crates.io's real API
      (`GET /api/v1/categories`, not guessed from memory per this task's own instruction) -
      `dstu-core` = `["cryptography", "no-std", "algorithms"]`, `uacrypt` =
      `["cryptography", "command-line-utilities"]`. `keywords` (max 5, crates.io limit):
      `dstu-core` = `["dstu", "kalyna", "kupyna", "strumok", "cryptography"]`, `uacrypt` =
      `["dstu", "cli", "cryptography", "kalyna", "kupyna"]`. **`rust-version` deliberately left out
      of this task's scope** - T-111 owns picking and empirically verifying a real MSRV (not a
      guess), adding it there rather than here avoids recording an unverified number now and
      re-deriving it later. Physical `LICENSE-MIT`/`LICENSE-APACHE` copies added to both
      `crates/dstu-core/` and `crates/uacrypt/` (byte-identical copies of the repo-root files,
      confirmed plain ASCII, no encoding issues). Verified: `cargo publish --dry-run -p dstu-core
      --allow-dirty` succeeds with **no metadata warnings at all** now (the prior
      `documentation`/`homepage`/`repository` warning trio is gone), packaged file count rose 133 ->
      135 (the two new license files); `cargo publish --dry-run -p uacrypt --allow-dirty` still
      fails on `no matching package named dstu-core found in crates.io index`, expected and
      unchanged - `uacrypt` path-depends on unpublished `dstu-core`, same pre-existing gate T-17's
      own readiness check already documented, not a regression from this task.
      `cargo fmt --all -- --check`, `cargo clippy --workspace --all-features -- -D warnings`, and
      `cargo build --workspace --all-features` all clean (metadata-only change, no source touched,
      so `cargo test`/`no_std` build/Miri were not re-run - nothing in their scope changed).
- [x] **T-110** Add `[package.metadata.docs.rs]` with `all-features = true` to both `Cargo.toml`
      files, so docs.rs actually documents the `pwhash`/`alloc` (and `small-tables`) cfg-gated
      surface instead of only the `std`-only default build - requested 2026-07-25. **Checked
      2026-07-25, `small-tables` is safe to include**: grepped every `#[cfg(feature =
      "small-tables")]` site in `crates/dstu-core/src` - all of them are private items inside
      `hazmat::tables`/`hazmat::strumok` (internal S-box/MDS table-vs-`gf_mul` swap, D-35/D-38), none
      gate a `pub` item, so `all-features = true` cannot make docs.rs render the constrained-MCU
      path as if it were the default one - the concern that would have blocked this (CLAUDE.md's own
      "`small-tables` breaks `--all-features` as a stand-in for the default profile" CI note) turned
      out not to apply to *documented* surface, only to *tested* behavior.
      **Done 2026-07-25.** `[package.metadata.docs.rs]` with `all-features = true` added to both
      `crates/dstu-core/Cargo.toml` and `crates/uacrypt/Cargo.toml` (the latter has no features of
      its own today, added for consistency and so it's already correct if one is ever introduced).
      Metadata-only change, same class as T-109: `cargo build --workspace --all-features`, `cargo
      fmt --all -- --check`, and `cargo clippy --workspace --all-features -- -D warnings` all clean;
      `cargo test`/`no_std` build/Miri not re-run, nothing in their scope changed. No `DECISIONS.md`
      entry - packaging hygiene, nothing architectural (same call T-107/T-109 made).
- [x] **T-111** `CHANGELOG.md` (Keep a Changelog format) + a declared MSRV - requested 2026-07-25.
      **Done 2026-07-26, see `DECISIONS.md` D-69.** MSRV measured, not guessed: `cargo metadata
      --filter-platform` (both Linux and Windows-gnu targets) showed the dependency graph's own
      declared floors top out at 1.85 (`zeroize`, `base64ct` via `argon2`'s `pwhash` feature,
      `getrandom` via `proptest`/`rand`) and 1.86 (`criterion` and its `clap` bench-harness
      dependency, both dev-dep-only) - neither is the real constraint. Real-toolchain bisection
      (installed `1.85.0`/`1.86.0`/`1.87.0` via `rustup`, built with each) found the actual floor
      is this crate's own unconditional use of `u64`/`usize::is_multiple_of`
      (`hazmat::kalyna_kw`/`kalyna_cbc`/`kalyna_ecb`/`kalyna_ccm`), stabilized in **1.87.0**: 1.86
      fails with `E0658` at every call site, 1.87 builds and compiles the full `--all-features`
      test suite clean. `rust-version = "1.87.0"` added to both `Cargo.toml`s; a new `msrv` job in
      `.github/workflows/rust.yml` pins `dtolnay/rust-toolchain@1.87.0` and build-only-verifies
      (`--all-features` + `--no-default-features`) on `ubuntu-latest`, explicitly `cargo +1.87.0`
      to avoid `rust-toolchain.toml`'s `stable` pin silently swallowing it (the known T-85 trap this
      task's own text warned about). `CHANGELOG.md` added at the repo root, Keep a Changelog
      format, one `[Unreleased]` section (0.1.0 is still unpublished) - Added/Changed only, not a
      reconstructed per-commit history; the `uacrypt encrypt`/`decrypt` wire-format's two breaking
      changes this session (`crypto_secretbox` -> Kalyna-GCM -> `crypto_secretstream`) are the one
      real piece of history worth recording under Changed. Verified: `cargo fmt --all -- --check`,
      `cargo build --workspace --all-features`, `cargo clippy --workspace --all-features -- -D
      warnings` all clean on the default `stable` toolchain; MSRV floor itself confirmed via direct
      `cargo +1.87.0-x86_64-pc-windows-msvc build --workspace --all-features --target
      x86_64-pc-windows-msvc` (the `-msvc` host triple, not `-gnu` - `1.85.0`/`1.86.0` under
      `-gnu` hit an unrelated `dlltool.exe`-not-found link error on this dev machine, see D-69's
      toolchain note; CI's own `ubuntu-latest` runner doesn't have this quirk).
- [x] **T-112** Crate-level `#![doc]` provisional-status warning for both crates - requested
      2026-07-25. `README.md` already has a pre-release/WIP banner (T-86/D-43: version, "not
      audited," Strumok/Kalyna-CCM/D-05's provisional status), but a docs.rs visitor who never opens
      the GitHub repo never sees it - rustdoc's own generated landing page is the only thing they're
      guaranteed to see. Scope: a short top-of-crate doc comment (`dstu_core::lib.rs` and
      `uacrypt::main.rs`/`lib.rs`) stating the same provisional facts (D-05 Kalyna-alone is an
      adopted assumption not a primary-text confirmation, Strumok is UAPKI-attributed not
      DSTU-8845-confirmed per D-15, no independent third-party audit) - point back at `SECURITY.md`/
      `DECISIONS.md` rather than re-arguing the citations inline.
      **Done 2026-07-25.** `crates/dstu-core/src/lib.rs` got a top `//!` block (before the existing
      `no_std`/lint attributes) naming D-05 (Kalyna-alone mode-of-operation is an adopted
      assumption, not primary-text confirmed), D-15 (Strumok is UAPKI-attributed only), and the
      no-side-channel-claim - pointing at `SECURITY.md`/`DECISIONS.md` rather than re-arguing them.
      `crates/uacrypt/src/lib.rs` got the same facts folded into its existing doc-comment block
      (which already covers `kalyna-block` naming), phrased for the CLI's own command names
      (`encrypt`/`decrypt`/`kalyna-ccm`, `strumok-crypt`). `crates/uacrypt/src/main.rs` had no doc
      comment at all before this - added a short one pointing at `lib.rs`'s fuller version rather
      than duplicating the same paragraph a third time. Verified: `cargo build --workspace
      --all-features`, `cargo build -p dstu-core --no-default-features`, `cargo clippy --workspace
      --all-features -- -D warnings` (checked specifically for the `doc_lazy_continuation`/
      `doc_markdown` gotcha this file's Agent-discipline section already flags - clean), and `cargo
      fmt --all -- --check` all pass. Doc-only change - `cargo test`/Miri not re-run. No
      `DECISIONS.md` entry - same packaging/doc-hygiene call as T-107/T-109/T-110.
- [x] **T-113** **DONE 2026-07-26, see `DECISIONS.md` D-70.** Multi-part/streaming `crypto_sign` for
      large messages - found during the 2026-07-25 libsodium API audit (see
      `docs/release-readiness.md`). Research done first, per this file's standing "no primitive
      written from memory" rule: `docs/pseudocode/dstu4145.md` §5.9/§9/§10 confirms DSTU 4145 signs
      a message digest directly (`h ← hash_to_field(H(T))`), not a domain-separated multi-part
      construction the way `crypto_sign_ed25519ph` is - so the task collapsed to
      `SigningKey::sign_digest`/`VerifyingKey::verify_digest` over an already-computed 32-byte
      Kupyna-256 digest, with `sign`/`verify` becoming thin wrappers over them. A caller with a
      large/streamed message hashes it themselves via the already-existing
      `hazmat::kupyna::Kupyna256Hasher` (T-83) and passes the digest straight in - the same
      memory-boundedness gap D-42 names for CLI commands, closed here without needing a new
      streaming construction. Full workspace test/clippy/fmt/`no_std` build all clean.
- [ ] **T-114** **Persona-based user-journey gap analysis - a hybrid state/interaction diagram, not
      a plain feature checklist** - requested 2026-07-25. Distinct from `docs/release-readiness.md`'s
      existing gap analysis (which is organized by *construction* - is this mode of operation
      current/safe) and from `docs/dstu-crypto-project.md`'s API-mapping table (organized by
      *libsodium function name*): this one is organized by *hypothetical engineer persona and the
      states/interactions they'd actually walk through* - discover, integrate, configure, verify,
      ship - to surface gaps neither of the other two views would catch (an existing feature can
      still leave a persona stuck if the doc/tooling connecting the steps around it is missing).
      Scope - three personas, each as its own state/interaction diagram (Mermaid `stateDiagram`/
      flowchart, per this project's usual doc conventions) with a paired want-vs-have-vs-gap table
      per state:
      1. **Binary user, performance-focused** - picks up `uacrypt` to encrypt/hash/benchmark files
         from the CLI, cares about throughput and prebuilt binaries, not Rust API ergonomics.
      2. **Library user, performance-focused** - depends on `dstu-core` directly from `Cargo.toml`,
         cares about the `crypto_*`/`hazmat` API split, `ExpandedKey`-style cached-schedule paths,
         and `PERFORMANCE.md`'s numbers.
      3. **Constrained-target (microcontroller) user** - needs the `no_std`/`small-tables` minimal
         footprint variant (STM32/ESP32-class targets, `docs/resource-profiles.md`), cares about
         flash/RAM budget and build-time feature selection, not raw throughput.
      For each persona, walk the realistic sequence (e.g. "find the project" -> "pick
      binary vs. library vs. minimal-footprint variant" -> "get a prebuilt artifact or add the
      dependency" -> "configure feature flags" -> "verify it does what's claimed (vectors/
      benchmarks/flash size)" -> "ship") and mark, per step, what already exists (cite the file/doc)
      versus what's missing - this should surface real, previously-uncatalogued gaps (a candidate
      one, not yet confirmed: T-18's prebuilt-binaries gap directly blocks step 1 of persona 1's
      journey, which the release-readiness doc's construction-level view doesn't frame the same
      way). Cross-reference `docs/release-readiness.md`, `docs/resource-profiles.md`,
      `docs/dstu-crypto-project.md`, `README.md`, and `PERFORMANCE.md` rather than re-deriving their
      content - this task's value is the persona/journey framing itself, not a fourth copy of the
      same feature list. Output as a new doc (exact filename/location TBD when started - candidate:
      `docs/user-journey-gaps.md`) added to `CLAUDE.md`'s documentation map once created. Not
      started.
- [x] **T-19** **Naming subtask, all three decisions made 2026-07-23** (T-20/T-21/T-22 below) -
      unblocks T-17/T-18, which are still separately open (a decided name isn't a crates.io
      publish or a built release binary):
  - [x] **T-20** Public name for the two resource profiles from `DECISIONS.md` D-35, decided
        2026-07-23 (`DECISIONS.md` D-38): the working name **is** the public name - Cargo feature
        `small-tables`, default/fused path stays nameless (no feature flag needed for it, it's
        just the absence of `small-tables`). Deliberately not given a branded name the way
        `uacrypt` (T-21/T-22) was - a `Cargo.toml` feature flag is a technical identifier, not a
        product name. Not checked further than the naming decision itself - the actual `cfg`-gated
        implementation is `TASKS.md` Phase 4's "Two-resource-profile split" item, still open.
  - [x] **T-21** `dstutool`'s real name is **`uacrypt`** (`DECISIONS.md` D-36, decided and
        executed 2026-07-23): `crates/dstutool` renamed to `crates/uacrypt` (`git mv`), package
        and `[lib]` name in `Cargo.toml` updated, root `Cargo.toml` workspace member, `deny.toml`
        comment, `main.rs`/`lib.rs` internal references, `README.md`, `SECURITY.md`,
        `docs/dstu-crypto-project.md`, `CLAUDE.md`, and `PERFORMANCE.md`'s canonical binary-level
        section all updated. `cargo build --workspace`/`test -p uacrypt` (15/15)/`clippy -D
        warnings`/`fmt --check` all pass post-rename. Historical entries in `DECISIONS.md`/
        `TASKS.md`/`PERFORMANCE.md`'s superseded "Results" section still say `dstutool` on
        purpose — that was the accurate name at the time, not left stale.
  - [x] **T-22** The project's own name for GitHub is **`uacrypt`** too (decided 2026-07-23, same
        session as T-21 - not a separate name). `README.md`'s title updated from
        "dstu-crypto (working name)" to `uacrypt`. No git remote exists yet to actually create/
        rename a GitHub repo against - this records the chosen name for whenever one is created,
        it doesn't perform any GitHub-side action.
- [x] **T-86** First real version number, `0.0.0` -> `0.1.0` for both `dstu-core` and `uacrypt`
      (`DECISIONS.md` D-43, 2026-07-23) - `0.0.0` was the unmodified Cargo scaffold default, not a
      real semver value, and not publishable to crates.io as-is. `0.1.0` chosen over a
      `-alpha.N` pre-release tag: the whole `0.x` range already signals "unstable, may break" under
      semver, which matches this project's actual state honestly; a pre-release suffix is deferred
      to the real crates.io publish (T-17) rather than decided now. Both crates' `version` bumped
      together, including `uacrypt`'s `dstu-core` path-dependency version (the same wildcard-dep
      spot T-75 fixed once already) - missing it would silently reintroduce that problem.
      `Cargo.lock` regenerated via a real build, not hand-edited. README.md got a pre-release/WIP
      banner at the top stating the version and the same safety caveats `SECURITY.md` already
      carries (not audited, no side-channel-resistance claim, Strumok/Kalyna-CCM still provisional,
      no file-level `encrypt`/`decrypt` yet) - a WIP notice on a crypto library is a safety
      statement, not cosmetics, so it states what's missing rather than reading as marketing.
- [ ] **T-87** **Release-readiness audit for a genuine libsodium-equivalent 1.0** (requested
      2026-07-23, same session as T-86): a full gap analysis of what exists vs. what a real release
      needs - libsodium-shaped API/command surface, matching documentation, a crates.io publish
      with the complete algorithm set built and tested, and critically every mode of operation in
      that set being a *current, safe* one (not provisional/unconfirmed). Written up as
      `docs/release-readiness.md` (new file, added to `CLAUDE.md`'s documentation map) rather than
      folded into `dstu-crypto-project.md`, so it's independently updatable as the gap closes.
      **Headline finding, not to be buried under an optimistic checklist**: this goal is currently
      blocked, not just incomplete - `DECISIONS.md` D-05 (Kalyna's mode-of-operation question) is
      still formally open pending the priced primary DSTU 7624:2014 text, Kalyna-CCM is provisional
      (D-41), Strumok is UAPKI-attributed not primary-confirmed (D-15), and there is no
      `crypto_secretbox`-equivalent AEAD yet (T-36/T-37, both blocked on D-05). A release that
      claims "current, safe modes" cannot honestly ship on top of provisional/unconfirmed
      constructions - see `docs/release-readiness.md` for the full breakdown and what would need to
      change first. **Refreshed 2026-07-24** (still open - headline finding unchanged, D-05 is
      still the blocker): updated to reflect `crypto_pwhash`/`randombytes` landing (T-71/T-72) and
      D-47's rule, and fixed two claims that had gone stale since T-48 landed (the doc incorrectly
      still said "no `crypto_sign` wrapper exists yet" and that `docs/dstu-crypto-project.md`'s own
      mapping table was out of date on that point - it wasn't).
      **Refreshed again, same day, after T-37 landed (`DECISIONS.md` D-51)**: a `crypto_secretbox`
      equivalent now exists, so "there is no `crypto_secretbox`-equivalent AEAD yet" above is stale
      - but the headline finding itself is otherwise unchanged, not weakened: what got built is
      still provisional (inherits `hazmat::kalyna_ccm`'s not-primary-text-confirmed status, D-41)
      and bounded to <=255-byte messages (T-40's `crypto_secretstream` remains open for the general
      case) - a release still cannot honestly claim "current, safe modes" on top of it. See
      `docs/release-readiness.md` for the updated breakdown.
- [ ] **T-23** Re-confirm the `no_std` build still passes (all feature-flag combinations) as each
      primitive lands — don't let this regress silently. Ongoing by design, not a one-time item —
      **last re-checked 2026-07-22** (post D-28/29/30/31): all four `dstu-core` feature
      combinations build clean — `--no-default-features` (bare no_std),
      `--no-default-features --features alloc` (no_std + alloc), `--features alloc` (std + alloc),
      `--all-features`. `alloc` remains an unused placeholder feature (no code gated on it yet, per
      D-01), so this confirms no regression rather than adding new coverage. `cargo xtask build`
      (workspace `--all-features` + `--no-default-features`, which also exercises `dstutool`
      linking against a no_std-built `dstu-core`) still passes too.

## Testing & hardening — deeper verification beyond test vectors

Test vectors answer one question: does the primitive produce the standard's expected output for a
handful of fixed inputs. They do not answer whether the *code* leaks secrets, runs at an acceptable
speed, or degrades safely on adversarial/malformed input — raised 2026-07-22 while reviewing what
"done" means for Kalyna/Kupyna/Strumok now that all three pass their vectors. Split deliberately
from Phase 1 above: none of this blocks calling the primitives implemented, but none of it should
be skipped before calling them *production-ready*. Two things are explicitly **not** goals here and
never will be, so as not to imply otherwise: cryptanalytic strength of the algorithms themselves
(that's the DSTU designers' responsibility, not this library's), and hardware side-channel
resistance (SPA/DPA — explicitly out of scope per `SECURITY.md`/`CLAUDE.md` "MVP scope").

- [x] **T-24** **Chunk/split-invariance test for `Strumok::apply_keystream`.** Added
      `strumok_{256,512}_chunk_invariance` in `crates/dstu-core/tests/strumok.rs` — splits a fixed
      total length into arbitrary, non-8-aligned chunks (including a zero-length one) and asserts
      byte-for-byte identity against one call on the concatenated buffer. **Passed on the first
      attempt** — no buffering bug found, but the path was genuinely untested before this.
- [x] **T-25** **Round-trip property tests.** `proptest` 1.11 added as a dev-dependency (`DECISIONS.md`
      D-21) — doesn't touch the `no_std` build. Kalyna: one `decrypt(encrypt(key, block)) == block`
      test per variant in `tests/kalyna.rs`. Strumok: `apply_keystream` applied twice with the same
      key/IV returns the original data, in `tests/strumok.rs`. All 16 property tests (256 generated
      cases each) passed on the first attempt. Kupyna intentionally skipped — no round-trip
      property exists for a hash; its `cargo fuzz` target covers the property that would matter.
- [x] **T-26** **Differential testing against a C oracle over many random inputs — done for all three.**
      Strumok first (the highest-value target — zero official vectors exist anywhere for it,
      D-15): `cargo run --example strumok_diff_cases -p dstu-core` piped into
      `tests/oracle-harness/strumok-differential/diff_against_outspace.c` (against
      `oracles/strumok-dstu8845/`) — **4000/4000 random cases matched**. `DECISIONS.md` D-22.
      Extended to Kalyna and Kupyna for parity (D-24), so the scrutiny is visibly even across all
      three rather than looking Strumok-only: `kalyna_diff_cases.rs` +
      `kalyna-differential/diff_against_reference.c` against `oracles/kalyna-reference/` —
      **2500/2500 matched**; `kupyna_diff_cases.rs` + `kupyna-differential/
      diff_against_reference.c` against `oracles/kupyna-reference/` — **2000/2000 matched**. All
      three carry the same "not independent, still useful" caveat (these are the same-lineage
      reference implementations already behind Bouncy Castle's own ports, not a new independent
      oracle) — the real independent second reading for Kalyna/Kupyna remains the Java/.NET
      Bouncy Castle harnesses, unchanged.
- [x] **T-27** **Actually run `cargo fuzz`** for all three primitives — attempted 2026-07-22, blocked by a
      confirmed GNU/MinGW-toolchain incompatibility (libFuzzer-on-Windows is MSVC-only upstream),
      not a skipped step; full detail in the Phase 1 line above. **Done later the same day, see
      `DECISIONS.md` D-32**: this machine turned out to already have Visual Studio 2022 (MSVC C++
      toolset) installed — not the upstream limitation being wrong, just no longer applicable here.
      Installed the `nightly-x86_64-pc-windows-msvc` rustup toolchain, ran each target through a
      `vcvars64.bat`-sourced shell with `--target x86_64-pc-windows-msvc` passed explicitly (both
      steps load-bearing, not optional — see D-32). **Result: all three targets ran a 60-second
      smoke each (matching CI's `fuzz-smoke` convention), zero crashes** — kupyna 182,746 runs
      (87/213 coverage), kalyna 169,851 runs (773/1341 coverage), strumok 1,466,215 runs (101/163
      coverage), all coverage plateaus reached well inside the 60s window. `xtask fuzz` updated to
      do this automatically on Windows when both prerequisites are present, falling back to a clean
      skip (same as every other optional tool) otherwise. CI's Linux `fuzz-smoke` job remains the
      actual per-push check; this closes the "never actually run anywhere" gap for local dev on a
      machine that happens to have Visual Studio, which isn't guaranteed for every contributor.
- [x] **T-28** **`Zeroize`/`ZeroizeOnDrop` on live key-material.** `zeroize` 1.9 added
      (`default-features = false, features = ["derive"]`, `no_std`-compatible — first real
      dependency in `dstu-core`, `DECISIONS.md` D-20). Strumok's `Core` (LFSR/FSM state) derives
      `ZeroizeOnDrop`; Kalyna's `encrypt_generic`/`decrypt_generic` call `round_keys.zeroize()`
      after last use. Kupyna intentionally untouched — its only API is unkeyed `digest()`, no key
      material exists yet (relevant again once KMAC lands). **Not exhaustive**: Kalyna's
      intermediate key-schedule scratch buffers (`kt`, `initial_data`/`tmv`, the rotation buffer in
      `key_expand_odd`) are still cleared only via the final `round_keys` zeroize, not individually
      — a deliberate scope cut, not an oversight, see D-20.
- [x] **T-29** **Constant-time audit + an explicit decision.** Confirmed the secret-dependent indexing
      exists in all three primitives (`SBOXES`/`SBOXES_DEC` in `kalyna.rs`/`kupyna.rs`/
      `strumok.rs`, plus `MUL_ALPHA`/`MUL_ALPHA_INV` in `strumok.rs`). Documented and scoped as an
      accepted software-timing exception in `DECISIONS.md` D-19 (same family as the already-out-
      of-scope SPA/DPA carve-out, since every reference C implementation makes the identical
      trade-off) — `SECURITY.md`'s hard-constraint wording updated to say this precisely instead of
      standing as an absolute "never" next to code that already violated it. Branching and
      comparisons on secret data remain prohibited without exception, unchanged.
- [x] **T-30** **`criterion` benchmarks.** Added as a dev-dependency, three bench targets
      (`crates/dstu-core/benches/{kalyna,kupyna,strumok}.rs`, `cargo bench -p dstu-core`) covering
      every variant of all three primitives. **Extended 2026-07-22**: numbers, machine, a named
      regression baseline (`--save-baseline initial-2026-07-22`), and a same-machine comparison
      against Oliynykov's reference C, UAPKI, and outspace all now live in `PERFORMANCE.md` (new
      canonical file, see `CLAUDE.md`'s documentation map) — this project's Rust beats the
      reference C (correctness/clarity-optimized) but is meaningfully slower than UAPKI/outspace
      (production-optimized), a real and now-quantified gap, not just a theoretical one. **Did not**
      implement a second Strumok state-transition form just to quantify the literal-shift-vs-ring-
      buffer tradeoff mentioned in D-18 — that would still mean maintaining a second implementation
      purely to benchmark it; outspace's own ~12-15x-faster numbers (likely using a rotating
      buffer, per `PERFORMANCE.md`) now give an *external* read on that tradeoff's rough scale
      without needing to build one ourselves.
- [x] **T-31** **Strumok: close the gap to UAPKI/outspace documented in `PERFORMANCE.md`**, root-caused by
      reading `oracles/strumok-dstu8845/strumok.c` directly (2026-07-22) rather than guessed at, then
      fixed the same day (`DECISIONS.md` D-26). Two distinct, additive causes, both closed: (1)
      outspace's `next_stream()` never physically shifts its 16-word state array — replaced this
      project's `s.copy_within(1..16, 0)`-per-step with a `head`-indexed ring buffer, no data
      movement. (2) outspace's `T(w)` is 8 precomputed combined tables
      (`T0[byte0]^...^T7[byte7]`) — transcribed those directly (same byte-for-byte cross-check
      already covering them), replacing the runtime 8-S-box-lookups-then-MDS-matrix-multiply.
      **Result: ~77-85% time reduction, now faster than UAPKI's Strumok, ~3.2x slower than outspace
      (was ~4-5x/~13-15x before)** — full before/after table in `PERFORMANCE.md`. Verified: all 6
      existing tests unchanged, the 4000-case outspace differential harness re-run fresh
      (4000/4000), `clippy`/`fmt`/`no_std` all pass. New `criterion` baseline saved
      (`strumok-optimized-2026-07-22`).
- [x] **T-32** **Kalyna/Kupyna: precomputed MDS tables** (`DECISIONS.md` D-27, same day). Narrower than the
      full UAPKI `p_boxrowcol` fusion (S-box + row/column permutation + MDS all combined) —
      `hazmat::tables::apply_matrix` alone was switched to precomputed `MDS_TABLE`/`MDS_INV_TABLE`
      (8 lookups + 7 XORs instead of up to 64 `gf_mul` calls per column), shared by both algorithms
      since `apply_matrix` already was. `sub_bytes`/`shift_rows` untouched — Kalyna's row-shift
      offset depends on block size, so fully fusing S-box+shift+MDS the way UAPKI does would need
      per-variant tables, a bigger change deliberately not attempted this pass. **Result: ~48-55%
      time reduction for every Kalyna variant/direction, ~60-65% for Kupyna** — roughly halves the
      gap to UAPKI without closing it (full before/after in `PERFORMANCE.md`). Verified: a new
      *exhaustive* unit test (`hazmat::tables::tests`, all 8x256 entries per table) plus every
      existing Kalyna/Kupyna vector/proptest/differential-harness check, all unchanged.
      `clippy`/`fmt`/`no_std` pass. New baseline: `kalyna-kupyna-optimized-2026-07-22`.
      **Not done**: the full S-box+shift+MDS fusion (per-`nb` tables) — sketched, not scheduled,
      would close the remaining gap but is a materially bigger change.
- [x] **T-33** **Kalyna/Kupyna: close the remaining gap to UAPKI** (planned 2026-07-22, stages 0-1 done the
      same day, see `DECISIONS.md` D-28 — stages 2-3 below still open).
      0. **Fixed the benchmark's methodology gap** — confirmed (temporary internal diagnostic,
         not committed) that `key_expand` was ~59-63% of Kalyna-128-128/512-512's per-call time,
         i.e. `benches/kalyna.rs` was indeed timing schedule+round together, matching the
         suspicion. Superseded by stage 3 (`ExpandedKey`) rather than patched as a standalone bench
         change, since that's the real fix, not just a measurement one.
      1. **Fused forward table, shared, done** (`SBOX_MDS`, `hazmat::tables`, D-28): D-27's stated
         blocker (full fusion needs per-`nb` tables) was wrong — `sub_bytes`/`shift_rows`/`shift_
         bytes` commute (S-box is row-indexed, the permutation preserves row), so one `nb`-
         independent table works; `nb`/`columns` dependence is only in the gather index. Replaced
         Kalyna's `encipher_round` (benefits encrypt *and* the key schedule, which calls it too)
         and Kupyna's new `sub_shift_mix` (both `t_transform`/`t_plus_transform`). **Kalyna decrypt
         deliberately NOT fused this pass** — `inv_sub_bytes` runs last in `decipher_round`, not
         first, so a direct table swap doesn't apply; needs an equivalent-inverse-cipher-style
         restructuring (transformed round keys), staged as its own follow-up.
         **Correctness/perf fix found during implementation**: the gather index's `% nb`/`%
         columns` cost a real per-byte integer division (LLVM can't prove a runtime value is a
         power of two), which alone made the first Kupyna version 5-8% *slower* than pre-fusion —
         fixed by replacing with `& (nb - 1)`/`& (columns - 1)` (always valid: `nb` is 2/4/8,
         `columns` is 8/16, both always powers of two by construction). Verified: two new
         `proptest` suites checking the fused round against a kept-for-reference naive three-pass
         version, a new exhaustive `SBOX_MDS` unit test, all official vectors/round-trips
         unchanged, both Oliynykov differential harnesses bit-identical (12500/12500 Kalyna
         including decrypt round-trips, 4000/4000 Kupyna), `clippy`/`fmt`/`no_std` all pass.
         **Result, far beyond this task's original "2-3x of UAPKI" expectation**: Kalyna encrypt
         -55% to -68% further (e.g. 128-128: 2354 ns -> 1041 ns, ~4.7x UAPKI, was ~10.6x); decrypt
         also -36% to -40% purely from the faster key schedule. **Kupyna -85% to -87%, now at or
         above UAPKI's own speed** (256: 1.03-1.45x faster; 512: roughly at parity) — full
         before/after in `PERFORMANCE.md`. New baseline: `kalyna-kupyna-fused-2026-07-22`.
      2. **Not done yet, and now lower priority than stage 4 below** — see stage 3's result: with
         the schedule cached, Kalyna encrypt is already faster than UAPKI, and Kupyna is at/above
         parity, so the remaining `[u8; 8]` -> `u64` conversion-churn cleanup has much smaller
         expected payoff than originally estimated (most of it was already implicitly removed by
         D-28's single-pass gather, which accumulates as `u64` internally already). Revisit only if
         stage 4 (decrypt fusion) doesn't close enough of the remaining gap on its own.
      3. [x] **`ExpandedKey`-equivalent for Kalyna, done, see `DECISIONS.md` D-29** — one
         `${Variant}ExpandedKey` struct per variant (`Kalyna128_128ExpandedKey`, etc., via the same
         macro), `::new(key)` runs `key_expand` once (`Zeroize`/`ZeroizeOnDrop`), `.encrypt_block`/
         `.decrypt_block` reuse the cached schedule. Raw `encrypt`/`decrypt` untouched (still the
         one-shot convenience path); both now call shared `encrypt_with_schedule`/`decrypt_with_
         schedule` helpers so there's one round-logic implementation, not two. Verified: new
         `proptest` suites (`ExpandedKey` matches raw functions for every random input; reused
         across multiple blocks correctly), Kalyna differential harness re-run fresh (7500/7500,
         bit-identical), `clippy`/`fmt`/`no_std` all pass. **Result, confirms the stage-0 diagnostic
         was right to prioritize this**: new `*_encrypt_block_only`/`*_decrypt_block_only` bench
         functions (key expanded once outside the timed loop) show Kalyna encrypt with a cached
         schedule is now **faster than UAPKI for every variant measured** (e.g. 128-128: 133 ns vs
         UAPKI's 222 ns). **Decrypt-block-only is 3.2-6.9x slower than encrypt-block-only** (e.g.
         512-512: 568 ns encrypt vs 3934 ns decrypt) — decrypt fusion (stage 4) is now clearly the
         single largest remaining gap, not the key schedule. New baseline:
         `kalyna-expandedkey-2026-07-22`.
      4. [x] **Decrypt-direction fusion, done, see `DECISIONS.md` D-30**. `decipher_round`'s
         mix-then-permute-then-substitute order isn't directly fusable (opposite of encrypt's
         substitute-first order) - fixed by regrouping the *whole* decrypt sequence (not just one
         round): `IS`/`IP` commute (same row-invariance as D-28) and the GF(2^8)-linear `IM`
         distributes over XOR, so `[IP;IS;XOR(K);IM]` = `[IS;IP;IM;XOR(IM(K))]` - substitute-
         permute-mix, `encipher_round`'s exact shape, using transformed interior keys `DK[j] =
         apply_matrix(K[j], MDS_INV_TABLE)`. New `tables::SBOX_MDS_DEC` (same `const fn` pattern),
         new `hazmat::kalyna::fused_inv_round` (gather direction is `inv_shift_rows`'s, opposite
         sign from `encipher_round`'s). `ExpandedKey` extended with a `dec_keys` field, precomputed
         once in `new()` so caching doesn't reintroduce `nr-1` `apply_matrix` calls into every
         `decrypt_block`. Verified: new `proptest` suite (4 cases spanning every real
         `(nb, nr)` pair) checking the restructured decrypt against a kept-for-reference naive
         three-pass version over **random round-key schedules and ciphertexts** (not just fixed
         vectors - this transform moves *where* keys apply, a subtler bug class than D-28's
         per-round fusion), a new exhaustive `SBOX_MDS_DEC` unit test, all official vectors
         (including real decrypt vectors)/proptests/`ExpandedKey` tests unchanged, Oliynykov
         differential harness re-run fresh (15000/15000 encrypt cases - this harness doesn't
         exercise `KalynaDecipher`, so it doesn't independently re-check decrypt beyond the vectors
         and naive-vs-fused proptest above; a cheap possible extension, not done), `clippy`/`fmt`/
         `no_std` all pass. **Result**: decrypt-block-only improved 66-82% (e.g. 512-512: 3934 ns ->
         691 ns) - **`ExpandedKey`'s encrypt and decrypt are both now faster than UAPKI across every
         variant measured**, closing essentially the entire gap for the schedule-cached API (the
         raw one-shot functions still trail UAPKI somewhat, an accepted tradeoff of that API shape).
         New baseline: `kalyna-decryptfusion-2026-07-22`.

      **Stage 2 (`Column` -> `u64` representation) remains not done** - given the results above
      (Kalyna at/above UAPKI parity for the cached-schedule API, Kupyna at/above parity), expected
      further payoff is small; revisit only if a future profiling pass shows it's still worth it.
- [x] **T-34** **Binary-level (process) comparison, done, see `DECISIONS.md` D-31**. The in-process numbers
      above don't reflect running the tool as an actual external process - added `dstutool`'s first
      real command, `kalyna-block encrypt`/`decrypt` (single block, file in/file out, deliberately
      not named `encrypt`/`decrypt` at the top level - that's reserved for the future file-plus-
      mode CLI, blocked below), plus scratchpad (uncommitted) comparison CLIs for Oliynykov's
      reference C and UAPKI with the same file interface, all three cross-checked byte-identical
      before timing. **Result**: `dstutool`'s per-op numbers (schedule cached) match the in-process
      `criterion` numbers within a few percent - full tables in `PERFORMANCE.md` "Binary-level
      (process) comparison". Process-spawn overhead (~60-63 ms on this machine) is roughly the
      same across all three binaries, confirming it reflects the OS, not the crypto.
      **Extended same day to Kupyna/Strumok** - neither has a mode-of-operation blocker (both
      already operate on arbitrary-length data at the public API level), so `kupyna-digest`/
      `strumok-crypt` are complete real commands, not scoped-down scaffolds. Comparison CLIs added
      for Oliynykov's Kupyna reference, UAPKI's `dstu7564`/`dstu8845`, and outspace's `dstu8845` -
      all cross-checked byte-identical before timing. **Result**: Kupyna's binary numbers land close
      to the in-process ones (94.14 MB/s here vs 98.60 MB/s in-process for Kupyna-256 @ 64 KB);
      Strumok's are somewhat lower (516-546 MB/s here vs 639 MB/s in-process for Strumok-256) but
      same order of magnitude and same relative ranking - not investigated further, most likely
      machine load during the run rather than a wrapper-specific issue (`kalyna-block`'s wrapper,
      same shape, matched closely). Full tables in `PERFORMANCE.md`.
- [ ] **T-35** **Build and test on a real ARM Linux machine (Raspberry Pi).** Distinct from Phase 4's
      STM32/ESP32 hardware validation below: a Raspberry Pi running Linux is a full `std` target
      (`aarch64-unknown-linux-gnu` here — 64-bit Raspberry Pi OS, Debian 12/bookworm, confirmed via
      `uname -a`), not the bare-metal `no_std` embedded path — this checks the "no CPU-family
      lock-in" half of `CLAUDE.md`'s MVP scope (no intrinsic or build assumption that quietly only
      works on x86-64), while the STM32/ESP32 line items check the no-OS half. **Ongoing by
      design, not a one-time item** — a standing rig now exists for this (access details, re-sync
      steps, and the full re-run command are in `.claude.local.md`, not here, since they're
      machine-specific/credentialed, not project-general) — re-run periodically, especially after
      any change touching `hazmat::kalyna`/`kupyna`/`strumok` internals that could hide an
      architecture-specific assumption an x86-64-only dev machine wouldn't catch.
      **First run, 2026-07-22, all green**: repo synced over SSH, `rustup` installed fresh
      (`stable-aarch64-unknown-linux-gnu` 1.97.1, matching this project's pinned `stable` channel),
      then the exact same commands as the x86-64 dev machine — no new script, per `DECISIONS.md`
      D-12. `cargo xtask build` (both `--all-features` and `--no-default-features`), `cargo xtask
      test` (11/11 test binaries passed, 0 failures — the DSTU 4145 signature roundtrip test took
      ~125s here vs a few seconds on the x86-64 dev machine, expected given the Pi's much lower
      clock speed, not a correctness concern), `cargo xtask fmt --check`, `cargo xtask clippy` (all
      clean), and all four `dstu-core` feature-flag combinations (bare no_std, no_std+alloc,
      std+alloc, all-features) built individually too. First real confirmation on non-x86 hardware
      for this project. **Same day, extended to performance**: `cargo bench -p dstu-core --bench
      kalyna --bench kupyna --bench strumok` also run on the Pi and added to `PERFORMANCE.md`
      alongside the existing Ryzen dev-machine numbers — this project's own code, no UAPKI/
      Oliynykov/outspace comparison there (those aren't built on the Pi). Result: the Pi is a
      consistent, unremarkable ~1.6-2.2x slower than the Ryzen dev machine across all three
      algorithms (Kalyna ~1.8-2.1x, Kupyna ~2.0-2.2x, Strumok ~1.6-1.7x) — no architecture-specific
      cliff or anomaly, just the expected gap between a Cortex-A76 and a modern desktop x86-64 core.
      **Extended again the same day**: user asked whether UAPKI itself was benchmarked on the Pi
      too, for a genuinely adequate cross-platform comparison of the same code (a fair point - the
      "we beat UAPKI" claim needs UAPKI measured on *both* machines, not just this project). Built
      UAPKI's `library/uapkic` natively on the Pi (plain `cmake`/`gcc`, same pinned commit as the
      Ryzen build) and reused the exact same scratchpad C timing harnesses that produced the
      original Ryzen UAPKI numbers. **Result, see `DECISIONS.md` D-33**: Kalyna and Kupyna's "we
      beat UAPKI" result *reverses* on the Pi - UAPKI is faster there by up to ~1.9x - while
      Strumok's holds on both platforms (smaller margin on the Pi). Three untested hypotheses
      recorded in D-33 (LLVM/aarch64 codegen quality for this dense bit-manipulation pattern being
      the most explanatory), not chased further this pass. `PERFORMANCE.md`'s Results tables and
      "What the gap is, honestly" section both got a scope correction noting the Ryzen-specific
      claim.
      **Re-run 2026-07-23, triggered by new `hazmat` changes since the last run** (`kalyna_ccm`,
      T-81, and Kupyna's streaming `KupynaCore`, T-83) - re-synced via the same tar+ssh approach,
      `cargo xtask ci` on the Pi. All mandatory checks green, including the new suites: 37
      `kalyna_ccm` tests and 9 Kupyna-streaming tests, both passing on `aarch64` with no
      architecture-specific surprise. Optional tools (miri/fuzz/audit/deny/Maven/.NET) still not
      installed on the Pi, same as before - not a new gap, unchanged from the first run.
      **Extended a third time, same day, see `DECISIONS.md` D-34**: user asked for one single
      testing method and metric going forward - a real built binary (`dstutool`, and an equivalent
      thin CLI wrapper for every oracle), MB/s only, for every algorithm/implementation/platform,
      no more in-process `criterion` numbers used as the cross-implementation comparison. Rebuilt
      the full binary-level matrix on **both** machines (Kalyna N=20000 cached+raw x 2 variants,
      Kupyna/Strumok N=2000 at 64 KB) for `dstutool` + UAPKI (+ outspace for Strumok) - Oliynykov's
      reference C stays excluded (unchanged decision, correctness oracle not a performance one).
      Confirmed D-33's Kalyna/Kupyna-flips-on-ARM finding survives the switch to the canonical
      method, and surfaced a further discrepancy: Kupyna's binary-level numbers show UAPKI ahead
      **on Ryzen too** (~10-17%), contradicting the in-process table's opposite claim - exactly the
      kind of cross-method disagreement that motivated standardizing on one method. `PERFORMANCE.md`
      restructured: "## Results" (in-process) marked superseded/historical with a dated banner, not
      deleted; "## Binary-level (process) comparison" is now the single canonical section with
      Ryzen+Pi columns for every implementation, MB/s only.
      **Re-run 2026-07-26, user-requested ("tests through building the binary and verifying it"),
      first run since T-111's MSRV/CHANGELOG change and the whole roadmap Step 3/5 surface
      (`crypto_secretbox`/`crypto_secretstream`/`crypto_auth`/`crypto_kdf`/`crypto_stream` etc.) -
      none of that had been re-checked on real ARM hardware yet.** Re-synced via the standard
      tar+ssh approach, `cargo xtask ci` on the Pi: all mandatory checks green (`fmt --check`,
      `build --workspace` both `--all-features` and `--no-default-features`, `test --workspace
      --all-features` - every suite passed, 0 failures, including the newer `crypto_secretstream`/
      `crypto_auth`/`crypto_kdf`/`crypto_stream` tests not present at the last Pi run - and `clippy
      --workspace --all-features -- -D warnings`); optional layers (miri/fuzz/audit/deny/mvn/dotnet)
      still not installed there, same as every prior run, not a new gap. **New for this pass, not
      done on a prior Pi re-run: an actual `cargo build --release -p uacrypt` on the Pi, then the
      resulting `target/release/uacrypt` binary (confirmed `file`-checked as a real `ARM aarch64`
      ELF, not just trusting the target triple) exercised directly** - `--help`, `hash` (32-byte
      Kupyna-256 digest, deterministic across two runs, and **byte-identical to the same input
      hashed by the x86-64 dev machine's own release binary** - `126d90...fcfd61a` on both,
      confirming Kupyna is bit-for-bit architecture-independent, not just "tests pass on both"),
      `encrypt`/`decrypt` round-trip (500 KB random file, plus the empty-file and same-path-`--in`/
      `--out` misuse-adjacent cases from D-65's convention), wrong-key rejection, and a tampered-
      ciphertext byte flip correctly rejected with no partial `--out` file written on disk failure -
      all matching the correctness/rejection/misuse categories D-64/D-65 already established, just
      re-verified against the real compiled artifact on real hardware instead of `cargo test`.
      Temp files cleaned up after (`/tmp/*.bin`/`*.enc`/`*.dec`/`*.log` on the Pi).
- [x] **T-103** **Adversarial-test coverage audit across every primitive, see `DECISIONS.md` D-64.**
      User-requested 2026-07-25, directly prompted by D-63's finding that a real
      nonce-authentication gap existed purely because a "does tampering get rejected" test was
      simply absent. Surveyed every `tests/*.rs` file for tamper/wrong-key/reject coverage before
      writing anything. Added: `wrong_key_is_rejected` to `kalyna_gcm`/`kalyna_gmac`/`kalyna_kw`/
      `kalyna_cmac`/`kupyna_kmac` (each had tampered-message/tag coverage but not this), plus
      `tampered_tag_is_rejected` to `kalyna_gcm` specifically (the current `crypto_secretbox`
      construction, highest priority); `single_bit_change_produces_a_different_digest` to `kupyna`;
      a new module-doc "Warning: never reuse the same key+IV pair" section plus
      `reusing_key_and_iv_leaks_plaintext_xor` (pins the two-time-pad property directly) and
      `different_key_produces_different_keystream` to `hazmat::strumok`/`tests/strumok.rs`;
      `tampered_ciphertext_does_not_error_but_produces_garbage` to `kalyna_xts` (pins its
      documented no-integrity-by-design property). `crypto_sign`/`hazmat::dstu4145` and
      `crypto_secretbox` reviewed, already solid, no additions. Plain confidentiality-only block
      modes (CBC/CFB/OFB/CTR/ECB) deliberately excluded - no tag, so no "reject tampering"
      semantics exist to test. All 12 new tests passed on first run - this closes coverage gaps, no
      bug found. Full workspace test/clippy/fmt all clean.
- [x] **T-104** **"Fool" (misuse-resistance) test coverage audit, complementing T-103, see
      `DECISIONS.md` D-65.** User-requested 2026-07-25, same day as T-103 - naive/incorrect *usage*
      rather than active tampering. `advisor()` consulted before scoping (user explicitly suggested
      this); its survey-first-and-check-type-signatures approach held up exactly. Library additions
      to `kalyna_gcm`: `tag_length_out_of_range_is_rejected` (parity with `kalyna_gmac`, which
      already had it), `all_zero_key_round_trips`. CLI additions to `uacrypt` (9 tests): wrong-length
      key files on `encrypt`/`kalyna-ccm` → `WrongLength`; nonexistent/directory `--in` → `Io`, not a
      panic; same-path `--in`/`--out` round-trips safely (read-before-write, confirmed not
      incidental); never-sealed garbage on `decrypt` fails clean with no partial `--out`; empty-file
      `hash` succeeds; `--iterations 0` behaves like `1`; wrong-length `--nonce` on `kalyna-ccm
      decrypt` → `WrongLength`. **Finding, not a gap**: most `hazmat`-level "wrong length" misuse is
      structurally foreclosed by fixed-size-array constructors (`[u8; N]`, not a slice) - recorded
      in D-65 rather than tested, per the new `CLAUDE.md` rule below. All 11 new tests passed on
      first run. `CLAUDE.md`'s "Test-first, always" bullet extended: every new primitive/command
      now ships correctness + rejection (D-64) + misuse (D-65) tests by default, with the
      type-signature-foreclosure and first-run-pass clauses spelled out so this doesn't read as a
      contradiction of test-first later. Full workspace test/clippy/fmt all clean.
- [x] **T-105** **`crypto_generichash`/`crypto_auth`/`crypto_kdf` high-level modules, roadmap
      Step 3 item 2, see `DECISIONS.md` D-66.** The roadmap left this step's shape as an open fork
      ("dedicated re-export module... or a table entry suffices") without the user resolving it in
      advance, unlike the roadmap's other three named forks - resolved this session by building the
      modules, on the reasoning that Step 3's own stated goal is discoverability under
      `dstu_core::crypto_*`, not just documentation accuracy; flag for confirmation if that reading
      is wrong. Two judgment calls made along the way: (1) `crypto_generichash` is a bare `pub use`
      of `hazmat::kupyna` (nothing to wrap - no knob to hide, no DSTU keyed/variable-length-output
      equivalent to re-derive), while `crypto_auth`/`crypto_kdf` are thin wrappers adding an opaque
      `Zeroize`-on-drop key type; (2) both wrappers expose only the 256-bit
      `Kupyna256Kmac`/`Kupyna256Kdf` variant (D-47's "delete the knob", matching
      `crypto_secretbox`'s single-Kalyna-variant precedent), leaving the 384/512-bit sizes
      `hazmat`-only. All three modules are unconditional (`no_std`-compatible), only each key
      type's `generate()` is `std`-gated. New tests (`tests/crypto_auth.rs`, `tests/crypto_kdf.rs`,
      `tests/crypto_generichash.rs`) follow the D-64/D-65 three-category convention where it
      applies. Verified: full workspace test/clippy/fmt clean, plus `no_std`/`no_std+alloc`/
      `no_std+small-tables` builds of `dstu-core`. Committed and pushed (`1578ea0`).
- [x] **T-106** **`crypto_stream` high-level module, roadmap Step 3 item 3, see `DECISIONS.md`
      D-67.** Unlike T-105's fork, this one *was* an explicit open fork in the roadmap's own text
      ("whether the IV is auto-generated ... or stays explicit is its own fork, decided when this
      is actually picked up") - put to the project owner directly via `AskUserQuestion` before
      implementing, not decided unilaterally. Chosen: hidden/internally-generated IV, matching
      `crypto_secretbox`'s nonce precedent (D-51). Single 256-bit variant (`Strumok256` only,
      D-47's "delete the knob", matching T-105's precedent), opaque `Zeroize`-on-drop `Key`,
      `iv (32) || ciphertext` wire format, **no authentication** (`hazmat::strumok` is a bare
      keystream generator - `decrypt` never fails on tampered input, mirrors
      `hazmat::kalyna_xts`'s documented no-integrity-by-design property) - functions named
      `encrypt`/`decrypt`, deliberately not `seal`/`open`, so the naming itself signals "this does
      not authenticate" the way `crypto_secretbox`'s `seal`/`open` signals that it does. Whole
      module `std`-gated (needs `Vec<u8>`, same reason as `crypto_secretbox`, unlike T-105's three
      fixed-array modules). New tests (`tests/crypto_stream.rs`) adapt `crypto_secretbox.rs`'s own
      test shape for zero authentication: no tamper-rejection tests exist (no tag to tamper),
      replaced with tests pinning the *absence* of rejection directly
      (`wrong_key_produces_different_plaintext_not_an_error`,
      `tampered_ciphertext_does_not_error_but_produces_garbage`), the same convention
      `tests/kalyna_xts.rs` already established. Verified: full workspace test/clippy/fmt clean,
      plus `no_std`/`no_std+alloc`/`no_std+small-tables` builds of `dstu-core` (confirms
      `crypto_stream` is correctly absent from all three). Scoped Miri run clean (9/9, 0 UB,
      119.85s, `MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8`). Committed and pushed
      (`82045cf`).

## A provisional Kalyna mode of operation - CCM (T-81), plus its nonce-strategy follow-up (T-82)

Originally flagged as blocked entirely on D-05 (2026-07-22 note, kept below for the record). User
asked 2026-07-23 for a real (not ad-hoc) interim mode instead of waiting indefinitely on the priced
primary text - the "do not build an ad-hoc/arbitrary mode just to have *something*" warning below
was heeded: what got built is dual-oracle-cited (UAPKI + Bouncy Castle), not invented. See
`DECISIONS.md` D-05 (revised) and D-41 for the full reasoning and citation.

- [x] **T-81** **`hazmat::kalyna_ccm` implemented - DSTU 7624 CCM, all 5 Kalyna variants,
      provisional pending the primary text** (`DECISIONS.md` D-41, 2026-07-23). Cited to
      `oracles/uapki/library/uapkic/src/dstu7624.c` (`dstu7624_init_ccm`/`ccm_padd`/
      `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm`/`gamma_gen`), cross-checked byte-for-byte
      against `oracles/bouncycastle-java`'s `DSTU7624Test.java` CCM vectors for 4 of 5 variants
      (128/256 has no BC vector - UAPKI-only, flagged in its vector file). New test vectors in
      `crates/dstu-core/tests/vectors/kalyna-ccm/*.json`; new integration test
      `crates/dstu-core/tests/kalyna_ccm.rs` (37 tests: official vectors, `proptest` round-trip,
      five independent tamper-rejection suites - ciphertext/tag/AAD/nonce/wrong-key - all green
      first attempt). New `uacrypt` subcommand `kalyna-ccm encrypt`/`decrypt` (deliberately not the
      reserved `encrypt`/`decrypt` names - see the CLI note below), round-tripped and tamper-tested
      through the real built release binary (`DECISIONS.md` D-34's policy). All 8 `no_std`/`alloc`/
      `std`/`small-tables` feature combinations re-confirmed clean; `cargo clippy -- -D warnings`/
      `cargo fmt --check` clean; re-confirmed on the Raspberry Pi rig too (`TASKS.md` T-35's
      standing "re-run after hazmat changes" rule).
      **`cargo fuzz` target added** (`crates/dstu-core/fuzz/fuzz_targets/kalyna_ccm.rs`, wired into
      `xtask fuzz`'s target list) - `open_in_place` is the first code in this crate that makes an
      authentication decision on fully attacker-controlled input, so the target feeds it
      never-produced-by-`seal_in_place` ciphertext/tag/AAD directly, not just round-tripped output.
      A 60s MSVC smoke run (same method as D-32) found zero crashes across all 5 variants (cov 801,
      110,542 execs) alongside the pre-existing kupyna/kalyna/strumok targets in the same run (all
      four together: exit 0, no crashes).
      **`cargo miri test`**: the full suite (including `proptest`) hits a pre-existing
      proptest+Miri directory-isolation interaction on this Windows dev machine
      (`GetCurrentDirectoryW` not available under Miri's isolation, from proptest's own
      failure-persistence file lookup) - confirmed this **already affects** the existing
      `kalyna.rs`/`strumok.rs` proptest suites too, not something this task introduced, and that
      the full run is impractically slow under Miri regardless (≈6400 proptest cases interpreted).
      Scoped instead to the five official-vector tests (`MIRIFLAGS=-Zmiri-disable-isolation cargo
      +nightly miri test -p dstu-core --test kalyna_ccm official_vector`), which exercises every
      buffer path for all 5 variants - clean, no UB, ~41s.
      **A real, sourced scope limit, not a design choice**: plaintext and AAD are each capped at
      255 bytes (`hazmat::kalyna_ccm::{MAX_PLAINTEXT_LEN, MAX_AAD_LEN}`) - `ccm_padd`'s header
      encodes both lengths as a single byte each, so this is a property of the construction as
      extracted, enforced with an error rather than silently truncated.
- [x] **T-82** **Kalyna-CCM nonce strategy resolved 2026-07-23: wide random nonce, no stateful
      counter** (`DECISIONS.md` D-40's resolution). D-40's original "11-55 bytes" nonce-width
      figure was a measurement error, not a real constraint - it was `tmp` (the CBC-MAC-header
      slice), not the caller-facing nonce parameter, which is the *full block* (16/16/32/32/64
      bytes = 128/128/256/256/512 bits). Even the narrowest case (128 bits) comfortably clears the
      birthday bound for a stated per-key rekey guideline (~2^48 messages), so the libsodium-style
      pattern was safe all along. Chose it over a TLS-1.3-style internal monotonic counter mainly
      because a counter's uniqueness guarantee depends on durable cross-reboot state, which this
      project's Phase-4 embedded targets (T-55/T-56) can't be assumed to have - a reset-to-zero
      counter would silently reintroduce nonce reuse. `hazmat::kalyna_ccm`'s own signature is
      unchanged (still `no_std`-compatible, caller-supplied full-block nonce - it can't call
      `getrandom` for an embedded caller). What changed: `uacrypt kalyna-ccm encrypt` no longer
      accepts `--nonce` as an input - it generates one via `getrandom` and writes it to `--nonce`,
      so there is nothing left for a CLI caller to reuse by mistake; `decrypt` is unchanged (still
      reads the value `encrypt` produced). New `CliError::Random`, `getrandom` added as a
      `uacrypt`-only dependency (std-only CLI, no `no_std` impact). Verified test-first: the
      existing CLI round-trip test rewritten to no longer assume a fixed nonce (compares against a
      direct `hazmat` call using the *generated* nonce instead), plus a new test asserting two
      encrypt calls on identical key/plaintext produce different nonces - both pass, plus a manual
      real-binary round-trip (two encrypts confirmed different nonce bytes, decrypt recovered the
      plaintext), `cargo clippy -- -D warnings`/`cargo fmt --check`/`cargo xtask build` all clean.

**Original 2026-07-22 blocked note, kept for the record, superseded by T-81 above**: "User flagged
this as the next priority (2026-07-22, same session as D-28/29/30/31) - but this is still gated on
D-05, unchanged: `DECISIONS.md` D-05 needs the official DSTU 7624 text or another authoritative
source before *any* mode of operation (CTR/CBC/GCM/whatever DSTU 7624 actually specifies) can be
chosen. Building `dstutool kalyna-block` (D-31) does not unblock this - it's still single-block-only
by design. Do not build an ad-hoc/arbitrary mode (e.g. naive ECB) just to have *something* - that
is exactly the failure mode this project's 'no homegrown primitives'/'research before
implementation' discipline (`CLAUDE.md`) exists to prevent." T-81 satisfies this bar by being
dual-oracle-cited rather than invented, while D-05 itself (the `crypto_secretbox`/`crypto_auth`
construction question) stays open - `dstutool`'s (now `uacrypt`'s) reserved `encrypt`/`decrypt`
command names (`CLAUDE.md` MVP scope) are still reserved for whenever that resolves, unchanged.

## Phase 2 — libsodium-equivalent construction layer, DSTU 4145 + 9041

- [x] **T-36** **Adopted as a working assumption 2026-07-24, see `DECISIONS.md` D-05's latest
      revision** — Kalyna-alone (CCM/GCM/KW, not Kalyna+Kupyna encrypt-then-MAC), on top of D-41's
      UAPKI+Bouncy-Castle evidence: this project's own already-vendored `oracles/uapki/`
      `dstu7624_self_test` ten-mode list and Ukrainian Wikipedia's independently-sourced ten-mode
      table for "Калина (шифр)" agree mode-for-mode. **Still not primary-text-confirmed** — the
      official DSTU 7624:2014 text remains priced/unpurchased (`ORACLES.md`); this is a decision to
      build forward on assumption, not a claim the question is settled, and gets revised again if
      the primary text ever contradicts it. Unblocks T-37/T-16/T-40 to *start* (design against a
      working hypothesis instead of no hypothesis at all) — none of those are built yet, only the
      blocker on starting them is resolved.
- [x] **T-37** **Done 2026-07-24, see `DECISIONS.md` D-51** — `dstu_core::crypto_secretbox::{seal,
      open, SecretKey, SecretboxError, MAX_MESSAGE_LEN}`, plan reviewed with the advisor first. A
      single fixed construction (`hazmat::kalyna_ccm::Kalyna256_256Ccm` — 256-bit key, widest nonce
      at that key size), never all five variants (D-47's "delete the knob" criterion, not
      `crypto_pwhash::Strength`'s "genuine tradeoff" shape); nonce generated internally via
      `randombytes_buf`, never caller-supplied; combined `nonce(32) || ciphertext || tag(16)`
      output; no AAD parameter (libsodium's own `crypto_secretbox` has none either — that's
      `crypto_aead`'s job, not folded in here). **Still bounded to ≤255-byte messages** — inherits
      `hazmat::kalyna_ccm`'s sourced cap (D-41); `seal` errors (`SecretboxError::MessageTooLong`),
      never truncates; this is the headline caveat, stated first in the module doc, not an
      afterthought. `open` rejects input shorter than 48 bytes before slicing (no panic on
      attacker-controlled truncated input). `SecretKey::generate()` added (libsodium's
      `crypto_secretbox_keygen` equivalent). Test-first, 12 tests in `tests/crypto_secretbox.rs`,
      all green after one derive fix (`SecretboxError` can't derive `Clone`/`Copy`/`PartialEq`/`Eq`
      since it wraps `RandomError`, which implements none of those — dropped to plain `Debug`,
      matching `PwHashError`'s precedent) — round-trip `proptest`, a byte-layout pin against a
      direct `hazmat::kalyna_ccm` call, fresh-nonce-per-call, 4-way tamper rejection, oversized/
      zero/max-length edges, truncated-input rejection. `cargo test --workspace --all-features`/
      `clippy -D warnings`/`fmt --check` all clean; all four `no_std`/`alloc`/`std`/`small-tables`-
      independent combinations re-confirmed, `crypto_secretbox` (folded into `std`, no dedicated
      feature — no new dependency) correctly absent everywhere `std` isn't enabled, confirmed via
      `cargo tree -e normal`. `cargo +nightly miri test` clean, ~146s, no UB. Still inherits
      `hazmat::kalyna_ccm`'s not-yet-primary-text-confirmed status (D-41) unchanged. **Unblocks
      T-16 to start** (its stated gate was `crypto_secretbox` existing, not D-05's status) — T-16
      itself not built.
- [x] **T-38** **`crypto_auth`/`crypto_onetimeauth` equivalent - Kupyna-based KMAC, implemented
      2026-07-23** (`DECISIONS.md` D-44, first item from `docs/release-readiness.md`'s ordered
      plan). Provisional (primary DSTU 7564:2014 text not read - `docs/papers/Kupyna.pdf` names the
      MAC mode but doesn't describe it), but on **stronger evidence than Strumok/Kalyna-CCM's
      equivalent caveats**: both `oracles/uapki/library/uapkic/src/dstu7564.c` (`dstu7564_init_kmac`
      et al.) and the fully independent `oracles/bouncycastle-java/.../macs/DSTU7564Mac.java` were
      read (not just one plus the other's vectors), and their self-test vectors for all three sizes
      (MAC-256/384/512) agree byte-for-byte -
      `crates/dstu-core/tests/vectors/kupyna-kmac/kmac-{256,384,512}.json`. New `hazmat::
      kupyna_kmac` module (`Kupyna256Kmac`/`Kupyna384Kmac`/`Kupyna512Kmac`, each `mac`/`verify`,
      the latter constant-time via `subtle::ConstantTimeEq`); required promoting `hazmat::kupyna`'s
      internal `KupynaCore` and its padding-tail formula to `pub(crate)` so the KMAC construction
      could drive the same running compression state directly (feeding `PAD(K)`, `M`, `PAD(M)`'s
      suffix, `~K` in sequence, then one ordinary `finalize`) rather than only through the public
      one-shot/streaming API. Test-first, **all 6 tests green on the first attempt** (3 official
      vectors including the MAC-384 truncation case - the only one of the three where `mac_len` is
      smaller than the underlying digest's natural size, non-negotiable per the advisor consult
      before implementation - plus wrong-key-length/tampered-MAC/tampered-message rejections).
      `cargo test --workspace`/`clippy -D warnings`/`fmt --check` clean; 6 of 8 feature
      combinations re-checked (no `alloc` used, no new `cfg`); `cargo +nightly miri test -p
      dstu-core --test kupyna_kmac` clean (~22s, no `proptest` in this file so none of the CI
      miri-slowness applies); existing `kupyna.rs` official-vector tests re-run under Miri too,
      confirming the `KupynaCore` refactor didn't disturb the pre-existing paths. No CLI wiring yet
      (not required by this task's own scope - `uacrypt` command surface, if wanted, is a separate
      follow-up).
- [x] **T-39** **`crypto_kdf` equivalent - Kupyna-based KDF, implemented 2026-07-24** (`DECISIONS.md`
      D-45, second item from `docs/release-readiness.md`'s ordered plan). **Different verification
      posture than T-38/T-81/Strumok**: no DSTU KDF standard exists, so no reference implementation
      to port and no oracle vector to check against, ever - not "provisional pending the primary
      text", genuinely un-anchored, stated plainly rather than hedged the same way as the others.
      Modeled after libsodium's `crypto_kdf_derive_from_key` *shape* (one keyed-hash call per
      subkey, no separate Extract stage) rather than full RFC 5869 HKDF - HKDF's security proof is
      stated in terms of HMAC specifically, and `hazmat::kupyna_kmac`'s construction isn't HMAC, so
      assuming that proof transfers without justification would itself be an unexamined-assumption
      failure; skipping Extract sidesteps the question (the only assumption made is that Kupyna-
      KMAC is a reasonable keyed PRF, already implicit in using it as a MAC) and avoids HKDF's
      Expand chaining-counter, whose off-by-one correctness nothing here could catch without a KAT.
      New `hazmat::kupyna_kdf` (`Kupyna256Kdf`/`Kupyna384Kdf`/`Kupyna512Kdf`, `derive_subkey`),
      built directly on `hazmat::kupyna_kmac` (T-38), `master_key` typed as `[u8; N]` (not `&[u8]`)
      so there's no wrong-key-length error path at all - more misuse-resistant than the layer it's
      built on, not just a copy of its API. Test-first, **all 7 tests green on the first attempt**
      (determinism, exact byte-layout pin against a manual `kupyna_kmac` call, three `proptest`
      distinctness suites - different `subkey_id`/`context`/`master_key` must each produce a
      different subkey, the actual property being claimed). `cargo test --workspace`/`clippy -D
      warnings`/`fmt --check` clean; 6 of 8 feature combinations re-checked (no new `cfg`). `cargo
      +nightly miri test` hit the same pre-existing proptest+Miri isolation crash as every other
      `proptest`-using file in this workspace (T-81/T-85) - confirmed clean (no UB) with the same
      local workaround (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=8`, ~174s).
- [x] **T-40** **Done 2026-07-25, see `DECISIONS.md` D-68.** `dstu_core::crypto_secretstream`
      (`PushState`/`PullState`/`Key`/`Tag`/`SecretstreamError`) landed - a from-scratch chunked AEAD
      (no DSTU citation exists, D-47's tie-breaker applied, libsodium's `crypto_secretstream_
      xchacha20poly1305` shape over `hazmat::kalyna_gcm`/`hazmat::kupyna_kmac` instead of
      ChaCha20-Poly1305) with the full libsodium tag set (`Message`/`Push`/`Rekey`/`Final`) and a
      caller-buffer, per-item-`std`-gated API (stricter `no_std` fit than any other high-level
      `crypto_*` module so far). `uacrypt encrypt`/`decrypt` rewired to it too, same session, per
      the user's chosen scope - a breaking wire-format change from the old `crypto_secretbox`-backed
      command, called out explicitly (D-68), acceptable pre-1.0. `crypto_secretbox` itself is not
      removed, stays a separate tested primitive. 22/22 library tests + 48/48 `uacrypt` tests passed
      first write; full workspace `cargo test`/`clippy -D warnings` (default and `small-tables`)/
      `fmt --check`/no_std feature matrix all clean; scoped Miri 22/22 passed, 0 UB, 1276.00s
      (~21.3 min, slower than `crypto_secretbox`'s ~19 min as advisor-predicted for a multi-chunk
      construction). A 10th `cargo fuzz` target (`fuzz_targets/crypto_secretstream.rs`, CLAUDE.md's
      "required layer" rule, D-61's precedent) fuzzes `PullState::pull` directly on
      attacker-controlled input - local MSVC smoke run 71,780 executions, 0 crashes (D-32's
      documented workflow). Post-first-draft `advisor()` review caught and fixed two real gaps
      before this was considered done: `docs/release-readiness.md`/`docs/dstu-crypto-project.md`/
      `README.md` all had stale "not started" T-40 mentions across several sections each (the doc
      map assigns exactly this update to those files, not just `TASKS.md`/`CLAUDE.md`), and D-68's
      own `no_std` claim overstated what's actually unconditional (`PushState::init` is
      `PushState`'s only constructor, so the module is decrypt-only without `std`) - both fixed, see
      `DECISIONS.md` D-68 for the full corrected write-up. The T-40/T-70 duplicate-numbering entries
      below/elsewhere are the same task - see T-70's own entry for its own closing note.
      **History below kept for the design-fork trail that led here, superseded by the "Done" note
      above, not deleted**: **D-05's blocker status changed 2026-07-24 (see T-36) - not unblocked
      in practice yet, though.** D-05 is now Kalyna-alone (CCM/GCM/KW) as a working assumption, not
      fully open -
      so the specific worry below (building this would silently resolve D-05 on the EtM side) no
      longer applies verbatim. But `hazmat::kalyna_ccm`'s own 255-byte plaintext/AAD cap (D-41)
      still makes it unusable for a realistic streaming chunk size as-is - a real `crypto_secretstream`
      needs either a widened/chunked Kalyna-AEAD construction or GCM (not yet built, needs new
      GF(2^128) arithmetic), not a straight reuse of the existing CCM module. Still not started;
      the paragraph below (originally written when D-05 was fully open) is kept for the
      "don't build an ad-hoc Strumok+KMAC EtM gap-fill" reasoning, which still holds regardless of
      D-05's status - Kalyna-alone is the adopted answer, an EtM composition still isn't:
      an unbounded/large chunk size - and this project's only AEAD construction, `hazmat::
      kalyna_ccm`, caps plaintext/AAD at 255 bytes each (D-41's sourced limit), too small for a
      realistic streaming chunk. The natural-looking gap-fill (a fresh Strumok-encrypt +
      Kupyna-KMAC-authenticate encrypt-then-MAC composition, since both primitives already exist)
      **is exactly the construction D-05 is the open question about** - building it under a
      "secretstream" banner would silently resolve D-05 on the EtM side without the primary text,
      the precise "don't build an ad-hoc mode just to have something" failure `CLAUDE.md` names.
      T-36/T-37 (`crypto_secretbox` = that same composition question) are explicitly blocked on
      D-05 already; T-40 sits on top of whichever answer T-37 lands on, so it can't be built first.
      **A user architecture question surfaced and answered while re-scoping this, worth recording**:
      is Strumok+KMAC EtM "the TLS 1.3 / safe-AES-modes architecture"? No - TLS 1.3 (RFC 8446)
      removed independently-composed encrypt-then-MAC entirely and allows only combined AEAD
      suites (AES-GCM, ChaCha20-Poly1305, **AES-CCM**) specifically because composing independent
      primitives was the surface behind BEAST/Lucky13/POODLE in TLS 1.2. Kalyna-CCM (D-41's
      provisional hypothesis) is structurally the *closer* match to that lineage - CCM is one of
      TLS 1.3's own three allowed suites - while a from-scratch Strumok+KMAC EtM would be the
      SSH-style independent-composition school instead, formally sound (Bellare-Namprempre) but a
      different, more implementation-surface-heavy design lineage, and not something to back into
      by default via a secretstream implementation. Chunked Kalyna-CCM (255-byte chunks) remains a
      possible, if impractical, way to build *something* here without taking a new D-05 stance -
      not chosen either, just not ruled out. See `TASKS.md` T-70 (the same task under the
      high-level-layer numbering) and `docs/release-readiness.md`.
      **Correction, same day, after T-37 landed (`DECISIONS.md` D-51)**: the line above saying
      "T-36/T-37 ... are explicitly blocked on D-05" is now stale - T-37 is done. T-40 remains
      blocked regardless, but on the reason already given earlier in this same entry
      (`hazmat::kalyna_ccm`'s 255-byte cap, not D-05's status) - unchanged by T-37 landing, since
      T-37 itself only wraps that same capped primitive rather than widening it.
      **Correction 2026-07-24 (this entry's own "needs GCM, not yet built" premise is now stale) -
      found during a full-project `advisor()` audit, not by returning to this task directly**: GCM
      landed this session (T-95, `DECISIONS.md` D-56) - and, materially, **`hazmat::kalyna_gcm` has
      no `MAX_PLAINTEXT_LEN`/`MAX_AAD_LEN` cap at all** (D-56 states this explicitly: "no
      `MAX_AAD_LEN`/`MAX_PLAINTEXT_LEN` cap was needed at all, unlike `kalyna_ccm`'s sourced
      255-byte limit," since `q` is a pure truncation of a full-block tag, not a length encoded into
      the construction the way CCM's single-byte length field is). This changes the shape of the fix,
      not just its blocker status: **the arbitrary-length problem `crypto_secretstream`/T-40 was
      scoped to solve via chunking may not need chunking at all** - swapping `crypto_secretbox`'s
      backing construction from `Kalyna256_256Ccm` to a `KalynaNNN_NNNGcm` variant would lift the
      255-byte cap directly, no per-chunk streaming design required for the message body itself (a
      practical streaming API for very large files - not re-buffering the whole plaintext in memory -
      is still a separate, real question, same as every other `uacrypt` command per D-42's standing
      policy, but that's an I/O-chunking problem, not a construction-capacity one). **Still not
      started, and still a real fork to resolve deliberately, not silently**: CCM-vs-GCM as
      `crypto_secretbox`'s construction has no settling DSTU citation either way (D-05's own
      ten-mode list treats both as legitimate combined AEAD modes), so D-47's tie-breaker governs -
      and GCM inherits D-56's own provisional status (uapki + BC-vector-only, same weaker-claim
      caveat as CCM/D-41), so switching constructions does not change the "provisional pending
      primary text" posture either way, only the length cap. Whether this becomes a straight
      construction swap inside the existing `crypto_secretbox`, a distinct new `crypto_secretbox_gcm`/
      renamed module, or the actual `crypto_secretstream` API T-40's name promises is an open design
      question for whenever this is picked up, not decided here.
- [x] **T-41** DSTU 4145: official standard text obtained (`docs/papers/DSTU_4145-2002.pdf`, 2026-07-22) —
      its Annex B.1 (GF(2^163), polynomial basis) worked example extracted into
      `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` and independently cross-checked
      byte-for-byte against Bouncy Castle's own hardcoded KAT (`DSTU4145Test.java` `test163()`) —
      see `DECISIONS.md` D-14 and `ORACLES.md`. A genuinely dual-sourced vector, not just a scan
      transcription.
- [x] **T-42** DSTU 4145: re-derive `docs/pseudocode/dstu4145.md` against the official text's Sections 5-13,
      rather than leaving it as a pure Bouncy Castle code-transcription. **Done 2026-07-22**: read
      Sections 5, 9, 11-13 directly (rendered PDF pages), every algorithm in the doc now cites its
      own section/page. **Found a second real bug doing this** (beyond the `Q = -d·G` one already
      found via the property test, below): `hash_to_field` had the wrong algorithm entirely (copied
      BC's byte-reversal without also adopting BC's reversed-input convention) — reading §5.9
      directly showed the correct algorithm needs no reversal at all. Fixed; full detail in
      `DECISIONS.md` D-25's follow-up entry and the pseudocode doc itself, not duplicated here.
- [x] **T-43** DSTU 4145: implement GF(2^m) binary-field + elliptic-curve arithmetic in Rust for the m=163
      curve (the actual prerequisite for a Rust port, bigger than just the signature logic
      itself). **Landed 2026-07-22**: `dstu_core::hazmat::dstu4145::gf2m163` (field add/multiply/
      square/invert) and `dstu_core::hazmat::dstu4145::curve163` (point double/add — public-data
      only — and a constant-time Montgomery-ladder `scalar_multiply`, safe for secret scalars).
      Citation and the branchless-posture decision in `DECISIONS.md` D-25. Test-first against
      generated unit-level vectors (`tests/vectors/dstu4145/gf2m163_arith.json`, Bouncy Castle as
      sole oracle at this granularity — see D-25), including a small-scalar (`k=1..=32`) check
      against repeated addition to exercise the ladder's leading-zero-bits path — all green first
      try (`cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `no_std` build;
      `cargo miri test` run separately, see below). **Still missing**: only the m=163 curve
      exists — the other 9 curve sizes in `DSTU4145NamedCurves.java` aren't wired up (not needed
      unless a use case calls for them).
- [x] **T-44** DSTU 4145: port the signature scheme to Rust from `docs/pseudocode/dstu4145.md`, verified
      against the `gf2m163.json` vector (D-02). **Landed 2026-07-22**:
      `dstu_core::hazmat::dstu4145::scalar::Scalar` (mod-`n` integer arithmetic, deliberately a
      distinct type from `gf2m163::FieldElement` — see D-25's follow-up entry on why) and
      `dstu_core::hazmat::dstu4145::signature::{sign, verify}`. Both directions verified against
      the official Annex B.1 worked example — `verify` accepts it, `sign` with the vector's pinned
      ephemeral reproduces `(r, s)` exactly — plus a `proptest` round trip over random keys/hashes.
      **Two real bugs found and fixed in the process** (full detail in D-25's follow-up entry, not
      duplicated here): a genuine doc error — `docs/pseudocode/dstu4145.md` said `Q = d·G`, but
      Bouncy Castle's own `DSTU4145KeyPairGenerator` negates it (`Q = -d·G`), confirmed against that
      source and, once the pseudocode re-derivation above happened, confirmed a second time directly
      from §9.2's own text — and a `hash_to_field` algorithm bug caught only by that re-derivation
      (see the item above). The round-trip property test is what caught the `Q` bug — the fixed
      vector alone never exercises key derivation. **Still not done**: the other 9 curve sizes.
- [ ] **T-45** **Not scheduled, sketched only:** replace `gf2m163`'s bit-serial field multiplication
      (163-iteration shift-and-mask, `DECISIONS.md` D-25 — deliberately correctness-first, not
      speed) with a comb method (`Guide to Elliptic Curve Cryptography` Algorithm 2.34/2.36, the
      same source already cited for the current reduction/ladder code) once correctness work here
      is otherwise done. Motivation: this is the main reason `cargo miri test` on
      `dstu4145_signature`'s `proptest` round trip is slow (a single `sign`+`verify` call runs
      `Point::scalar_multiply`'s 163-iteration ladder three times, each ladder step doing several
      163-iteration field multiplies). Purely a performance change — correctness and the
      branchless posture (D-25) must both still hold after it; no new test-vector work needed
      since the existing `gf2m163_arith.json`/`gf2m163.json` checks already pin the arithmetic's
      expected output.
- [ ] **T-46** **Blocked entirely:** DSTU 9041 — zero source material exists (no paper, no oracle, no
      pseudocode; see `ORACLES.md`). Nothing here can start until the official text is obtained
      or another authoritative source turns up
- [ ] **T-47** `crypto_kx` equivalent (Diffie–Hellman on the DSTU 4145/9041 curve — needs both to exist)
- [x] **T-48** **Done 2026-07-24** (`DECISIONS.md` D-46) - `crypto_sign` equivalent wrapping the
      Rust DSTU 4145 port, third of the T-38/39/40/48 working order (T-40 re-scoped as blocked, so
      this ran third rather than fourth). The first module in the high-level "easy" layer D-09
      planned but never built. **A real security-posture fork was surfaced and put to the project
      owner rather than picked silently** (same posture as T-40's re-scoping question): should the
      ephemeral signing nonce be caller-random (matching Bouncy Castle's `SecureRandom`-backed
      reference) or derived deterministically? Chosen: **deterministic**, RFC-6979-*style* (not a
      literal port - RFC 6979 is HMAC-specific, `hazmat::kupyna_kmac` isn't HMAC), keyed by the
      private key and seeded with the Kupyna-256 message hash, via a new `Scalar::reduce_wide_bytes`
      (`pub(crate)`, same bit-serial constant-time reduction style as `reduce_mod_n`). Eliminates
      nonce-reuse key recovery (the PS3/Bitcoin-wallet failure class) from the wrapper's caller
      surface entirely - matches Ed25519/libsodium's own misuse-resistant design, not the classical
      DSA-family default. No oracle exists for this specific derivation (same honest-scoping
      posture as D-45's KDF); what *is* oracle-checked is `Q = -d*G` against the official Annex B.1
      worked example. New `dstu_core::crypto_sign` module (`SigningKey`/`VerifyingKey`/`Signature`,
      `ed25519-dalek`-style naming per D-04's addendum) hashes raw messages internally with
      Kupyna-256 (libsodium `crypto_sign(message, ...)` ergonomics); `to_uncompressed_bytes` is a
      plain 42-byte `x || y` encoding, explicitly **not** the DSTU §6.9/§6.10 compressed point
      format (not implemented anywhere in this project, tracked separately). `Scalar` also gained
      `#[derive(Zeroize)]` (not `ZeroizeOnDrop` - incompatible with `Copy`, `E0184`), closing a
      pre-existing key-material-hygiene gap; `SigningKey` implements `Drop` zeroizing its inner
      scalar. Test-first: 9 new tests (determinism, official-vector `Q` cross-check, round-trip, 3
      tamper-rejection variants, 2 invalid-key rejections, 1 `proptest` sweep), all green after
      fixing test constants that initially exceeded the curve order (caught immediately by
      `from_bytes`'s own validation, not a construction bug). Full workspace `cargo test
      --all-features` green (no regressions), `clippy -D warnings` clean (two fixes:
      `expect_used` on the KMAC call resolved via `unreachable!()` behind `let...else`,
      `manual_let_else`), `fmt --check` clean, `no_std`/`alloc`-only/`small-tables` builds all
      clean. Local `cargo +nightly miri test` hit the same known slow-suite issue as
      `dstu4145_signature`'s own proptest (T-85) - 8 of 9 tests completed with no UB, the proptest
      itself was killed locally after ~21 minutes rather than left unbounded; CI's already-tuned
      job (`PROPTEST_CASES=1`, 30-min timeout) is the authoritative miri check for this file.

## Phase 3 — Language bindings (not MVP)

- [ ] **T-49** Python bindings
- [ ] **T-50** JavaScript bindings
- [ ] **T-51** Java binding (wraps Bouncy Castle `DSTU4145Signer` directly, per D-02 — does not use the
      Rust DSTU 4145 port)
- [ ] **T-52** .NET binding (wraps Bouncy Castle `Dstu4145Signer` directly, per D-02)
- [ ] **T-53** C++ bindings

## Phase 4 — Hardware validation (post-MVP)

- [x] **T-54** **Two-resource-profile split, done 2026-07-23 (`DECISIONS.md` D-35/D-38/D-39)** -
      `dstu-core`'s `small-tables` Cargo feature (independent of `std`/`alloc`, combines with
      either): `tables.rs`'s `MDS_TABLE`/`MDS_INV_TABLE`/`SBOX_MDS`/`SBOX_MDS_DEC` and Strumok's
      `T0..T7` (~86 KB total) are now `#[cfg(not(feature = "small-tables"))]` - not compiled at all
      under the feature, not just unused. In their place: `apply_matrix_via_gf_mul`/
      `mds_column_via_gf_mul` (promoted from D-27's kept-for-testing `gf_mul`/`MDS_MATRIX`/
      `MDS_INV_MATRIX` reference path) and Strumok's `t_function` reverted to its pre-D-26
      runtime-`SBOXES`+`apply_forward_matrix` form - ~2-6 KB of `const` data instead. `kalyna.rs`/
      `kupyna.rs`/`strumok.rs` call four small `cfg`-transparent wrapper functions
      (`apply_forward_matrix`/`apply_inverse_matrix`/`forward_sbox_mds`/`inverse_sbox_mds`, all in
      `tables.rs`) instead of the raw tables directly, so neither caller module needs its own
      `cfg` - the entire profile split is contained in `tables.rs` (+ `t_function`'s two variants
      in `strumok.rs`). **Verified**: both profiles' official vectors, `proptest` round-trips, and
      the fused-vs-naive/decrypt-fusion property tests (default profile only - `small-tables` has
      nothing to compare against since it computes the naive form directly) all pass; `cargo
      clippy -- -D warnings` and `cargo fmt --check` clean on both; the existing 4-combination
      `no_std`/`alloc`/`std` matrix (`TASKS.md` T-23) re-checked with `small-tables` added to each,
      8 combinations total, all build clean; `cargo xtask build` passes. **Three
      `#[allow(clippy::needless_range_loop)]` added** (`encipher_round`/`fused_inv_round`/
      `sub_shift_mix`'s gather loops, plus `mds_column_via_gf_mul`'s) - calling a function with the
      loop variable instead of directly indexing a second array changed clippy's needless-range-
      loop heuristic (false positive: `row` also drives `shift`/`src_col`, not a plain
      single-collection enumerate candidate; confirmed via `git stash` that the pre-existing code
      was clippy-clean and only the `SBOX_MDS[row]` -> `forward_sbox_mds(row, ...)` refactor
      triggered it). **CI updated** (`.github/workflows/rust.yml`): `--all-features` used to be a
      stand-in for "test the default profile" (since `alloc` is an inert placeholder) but now also
      flips on `small-tables`, which changes production behavior - added explicit default-profile
      steps (no extra features) alongside new `--features dstu-core/small-tables` steps and kept
      `--all-features` as a third, combined-everything pass; all four step groups verified locally
      before committing to the workflow file, not just written and assumed correct. **Not done**:
      `cargo miri test`/`cargo fuzz` under `small-tables` specifically (not required by D-35's
      verification bar, but not re-run either) - CI's `miri`/`fuzz-smoke` jobs still only run
      default-profile `cargo miri test --workspace`/`cargo fuzz run kupyna`, unchanged. **Same
      day, follow-up**: real measured memory/speed numbers for both profiles (per-algorithm,
      `uacrypt` release binary, same method as `PERFORMANCE.md`'s binary-level comparison)
      written up in the new `docs/resource-profiles.md`, plus a plain-language sizing guide
      mapping typical MCU flash budgets to which profile fits - linked from `README.md` and
      `CLAUDE.md`'s documentation map. Kalyna/Kupyna are ~20-43x slower under `small-tables`
      (their whole round is the swapped step); Strumok is only ~4-4.5x slower (the swapped step is
      a smaller fraction of its per-word cost). Measured once on the Ryzen dev machine only, not
      the full multi-baseline protocol - good enough to size the trade-off, not a tracked
      regression baseline.
- [ ] **T-55** STM32 (ARM Cortex-M) real-hardware validation - entry-level parts (L0/F0/G0, 16-64 KB flash)
      need the small-tables profile above; mid-range and up (F1/F3/G4/F4/F7/H7) have flash to
      spare for the default fused profile.
- [ ] **T-56** ESP32 (Xtensa/RISC-V) real-hardware validation - flash (4 MB+) and SRAM (320-520 KB) both
      comfortably cover the default fused profile; no need for small-tables here.
- [ ] **T-57** **Stretch goal, not a near-term target: Arduino Uno (ATmega328P, 8-bit AVR) — user has one
      available, 2026-07-22.** Raised as "could we hypothetically try this," not a firm ask.
      Materially harder than the STM32/ESP32 items above, for a concrete, measured reason, not a
      vague "8-bit is old" concern: Rust's AVR target is nightly-only/tier-3 (`avr-hal`/`ravedude`
      ecosystem), and this project's *current* Kalyna/Kupyna tables (`hazmat::tables::SBOX_MDS`/
      `SBOX_MDS_DEC`, added by D-28's fusion) are `[[u64; 256]; 8]` each — **16 KB per table, 32 KB
      for both, which alone equals the ATmega328P's entire flash (32 KB)**, before any actual code;
      naively RAM-resident (no `PROGMEM`-style placement) they'd also be ~16x the chip's 2 KB SRAM.
      Checked what the *pre-D-27* tables looked like for comparison: `SBOXES`/`SBOXES_DEC` (1 KB
      each) plus two 8x8-byte matrices (~2.1 KB total, `gf_mul` itself is a table-free bit loop) —
      an order of magnitude smaller and flash-plausible, but Strumok's `MUL_ALPHA`/`MUL_ALPHA_INV`
      (2 KB each, unrelated to the Kalyna/Kupyna fusion work, present since D-18) push even that
      older baseline past half the chip's flash on their own. **Bottom line**: even the smallest
      historical table set would need real AVR-specific work (constants placed in program memory
      via `avr-hal`'s progmem mechanisms, not just "add the target") to leave any RAM at all for
      the round-key schedule/state - not a quick add-a-target job, and today's fused tables make it
      substantially worse than when this was last measured. Revisit only if there's real interest,
      not opportunistically.
- [ ] **T-58** Keep the SPA/DPA non-claim intact throughout (`no_std` compiling ≠ side-channel resistance
      — see `CLAUDE.md` MVP scope section)
- [ ] **T-59** **Not scheduled, sketched only:** constant-time S-boxes (masked-select or bitsliced —
      `DECISIONS.md` D-19's "Future path" note has both options and why it's a bigger project than
      it looks), narrowing the software-timing exception D-19 documents. Natural place to revisit
      this alongside the hardware side-channel audit above, not before.

## Explicitly out of scope — not scheduled in any phase

- Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna) — per D-08, only with a
  separate explicit decision from the project owner

## API surface — `dstu_core::hazmat` module by module

Mirrors the table in `docs/dstu-crypto-project.md` "Concrete API shape" — that table is the
prose/rationale version, this is the checklist version. Keep both in sync when a status changes.
Two-layer split (`hazmat` now, high-level "easy" layer later) decided in `DECISIONS.md` D-09.

- [x] **T-60** `hazmat::kupyna` (`Kupyna256`, `Kupyna512`) — confirmed green, citation in D-10 (see Phase 1)
- [x] **T-61** `hazmat::kalyna` (5 variants) — confirmed green, citation in D-13 (see Phase 1)
- [x] **T-62** `hazmat::strumok` (`Strumok256`, `Strumok512`) — confirmed green, citation in D-18 (see
      Phase 1)
- [x] **T-63** `hazmat::dstu4145` — **done, see T-42/T-44/`DECISIONS.md` D-25** (`sign`/`verify` on the
      163-bit curve, dual-oracle verified). This entry predates T-42/T-44's numbering (same
      duplicate-numbering situation as T-67/T-68); not renumbered per the "IDs are never
      reused/renumbered" rule.
- [ ] **T-64** `hazmat::dstu9041` — hard-blocked, zero source material (see `ORACLES.md`)
- [ ] **T-65** high-level "easy" layer (name TBD) — not started; nothing needs it yet (no keyed/nonce-based
      primitive is implemented before Strumok or `crypto_secretbox`, both currently blocked)
- [x] **T-66** **Done, see T-37/`DECISIONS.md` D-51** (`hazmat::kalyna_ccm`-based, not
      `hazmat::kupyna` — D-05 was resolved toward Kalyna-alone, not the encrypt-then-MAC framing
      this entry's own text originally described). Same duplicate-numbering note as T-67/T-68.
- [x] **T-67** `crypto_auth`/`crypto_onetimeauth` construction (over `hazmat::kupyna`) — **done, see
      T-38/`DECISIONS.md` D-44** (`hazmat::kupyna_kmac`). This entry predates T-38's numbering
      (both track the same work); not renumbered per the "IDs are never reused/renumbered" rule.
- [x] **T-68** `crypto_kdf` construction (over `hazmat::kupyna`) — **done, see T-39/`DECISIONS.md`
      D-45** (`hazmat::kupyna_kdf`). Same duplicate-numbering note as T-67 above.
- [ ] **T-69** `crypto_kx` construction (over `hazmat::dstu4145`/`dstu9041`) — needs both curves; DSTU 9041
      side is hard-blocked
- [x] **T-70** **Done 2026-07-25 - same task as T-40, see that entry and `DECISIONS.md` D-68 for the
      full write-up.** Built over `hazmat::kalyna_gcm`/`hazmat::kupyna_kmac`, not
      `hazmat::strumok`/`hazmat::kalyna` as this stub originally guessed - Strumok has no place in
      an AEAD construction (it's a bare keystream generator, no tag), and Kalyna enters only via its
      already-built GCM mode, not a fresh composition. No longer blocked on D-05 either - that
      blocker was about *which* combined-AEAD mode to build (D-05 was later resolved to
      Kalyna-alone), and `crypto_secretstream` ended up using the already-decided GCM mode rather
      than re-opening that question.
- [x] **T-71** **Done 2026-07-24, see `DECISIONS.md` D-49 (crate vetting) and D-50
      (implementation)**: `dstu_core::crypto_pwhash::{hash_password, verify_password, Strength}`
      over `argon2` 0.5.3 (`RustCrypto/password-hashes`, dual MIT/Apache-2.0, MSRV 1.65 - D-49's
      initial "1.85" was the `master`/`0.6.0-rc` branch's figure, corrected). New dedicated
      `pwhash` Cargo feature (`= ["std", "dep:argon2"]`, off by default per D-50's reasoning - not
      folded into `std` the way `getrandom` was in D-48). Every constant cited to libsodium's real
      `crypto_pwhash_argon2id.h`/`pwhash_argon2id.c` source, not invented: `Strength::{Interactive,
      Moderate, Sensitive}` map exactly onto `OPSLIMIT`/`MEMLIMIT_*`, parallelism fixed at 1 lane
      (libsodium's own hardcoded choice, not a knob), 16-byte salt, 32-byte hash. Salt comes from
      this crate's own `randombytes_buf` (not `password_hash`'s `rand_core`-based
      `SaltString::generate`) - though `rand_core 0.6.4` still enters the dependency tree
      transitively regardless (argon2's own manifest enables `password-hash`'s default features,
      which include `rand_core`; genuinely unused by this project's own code, confirmed absent
      from every `no_std` build, see D-50 and the new `SECURITY.md` row). 7 new tests (5 in
      `tests/crypto_pwhash.rs`, 2 inline in `src/crypto_pwhash.rs`): round-trip,
      wrong-password-rejected, malformed-string-rejected, fresh-salt-per-call, each cheap
      `Strength`'s params actually appear in its own PHC string (not just a round-trip that would
      pass even if `Strength` were silently ignored), the RFC 9106 (IETF primary source) Argon2id
      test vector run directly against the `argon2` dependency (bypassing this module's own `p=1`
      wrapper), and `Sensitive`'s params checked directly (a real hash at that tier took ~85s in
      debug - too slow for every CI push, see D-50). Full workspace `cargo test --workspace
      --all-features` green, `cargo clippy --workspace --all-features -- -D warnings`/`cargo fmt
      --all -- --check` clean, all four `no_std`/`alloc`/`small-tables` combinations unaffected
      (`pwhash` never enabled there, confirmed via `cargo tree`). Targeted `cargo miri test`
      (RFC 9106 vector + params-only test) clean, ~55s - a full real-preset hash was not attempted
      under Miri, impractical for the same reason as D-41's kalyna_ccm proptest issue (see D-50).
      **Not built**: libsodium's raw `crypto_pwhash()` KDF form (no consumer yet, same deferral
      reasoning as D-48's `CryptoRng` trait) and no `uacrypt` CLI subcommand (core crate only, like
      `crypto_sign`'s own initial landing).
- [x] **T-72** **Done 2026-07-24, see `DECISIONS.md` D-48**: `dstu_core::randombytes::
      randombytes_buf(buf) -> Result<(), RandomError>` - `std`-gated over an optional `getrandom =
      "0.3.4"` dependency (`std = ["dep:getrandom"]`), confirmed absent from the `no_std`/`alloc`/
      `small-tables` build graphs. Deliberately minimal per D-47's libsodium-minimal-surface
      criterion and advisor review: no generic `CryptoRng` trait re-export, since nothing in this
      crate consumes one yet (`crypto_sign` is deterministic, `hazmat` is caller-supplies-
      everything, `crypto_secretbox`/DSTU-4145-keygen are blocked/nonexistent) - D-04's own
      trait-injection recommendation stays deferred to that trait's first real consumer, not built
      speculatively. The `rand_core`/`getrandom` `sys_rng`-feature research for that future
      consumer is recorded in D-48, not discarded. 4 new tests (buffer filled, two draws differ,
      zero-length ok, sub-slice write doesn't touch surrounding bytes) - no oracle exists for OS
      randomness by definition, same posture as `hazmat::kupyna_kdf`'s distinctness tests.

## Infrastructure — CI and oracle harnesses

Goal: make "is this primitive actually green" answerable without a human manually running
`cargo test` and reporting back every time (see Phase 1's Kupyna entry above for why this matters
right now). Every harness below consumes the same `crates/dstu-core/tests/vectors/<algo>/*.json`
files already used by the Rust tests — one vector format, multiple consumers, not a second
convention invented per language.

- [x] **T-73** Rust CI (`.github/workflows/rust.yml`) written and **locally confirmed green** (2026-07-22,
      after installing a Rust toolchain in this environment — see `.claude.local.md`): `cargo fmt
      --check` clean, `cargo build --workspace` (both `--all-features` and
      `--no-default-features`, confirming `no_std` still compiles), `cargo test --workspace`
      passes (Kupyna's two vector tests included), `cargo clippy --all-features -- -D warnings`
      clean after one fix (`manual_memcpy` in `shift_bytes`). **Kupyna is now confirmed correct**,
      not just written — see D-10 update. `cargo miri test` run separately (see below); CI itself
      still activates properly only once pushed to a GitHub remote.
- [x] **T-74** `cargo fuzz` scaffold added (`crates/dstu-core/fuzz/`, target `kupyna`) — required by
      `SECURITY.md`. Wired into the CI smoke job; a local nightly+miri toolchain now exists here
      too if a quick local run is ever wanted, though CI is still the primary path.
- [x] **T-75** `cargo audit` + `cargo deny` (2026-07-22, D-11) — elevated to the same required-CI standing
      as miri/fuzz in `SECURITY.md`; policy in `deny.toml`. Wired into `.github/workflows/rust.yml`
      via `rustsec/audit-check` / `EmbarkStudios/cargo-deny-action`. **Actually run locally, not
      just installed**: `cargo audit` — 0 vulnerabilities. `cargo deny check` — all four categories
      (`advisories`, `bans`, `licenses`, `sources`) pass, but only after a real fix: it caught
      `dstutool`'s `dstu-core = { path = "../dstu-core" }` dependency as a "wildcard dependency"
      (no `version` pinned — would also block publishing to crates.io as-is). Fixed by adding
      `version = "0.0.0"`. Genuine first catch from this tooling, not just a clean no-op.
- [x] **T-76** ~~C oracle harness~~ **dropped 2026-07-22.** Attempted against cryptonite (pinned commit
      `3618d340`) with a real, newly-installed GCC 16.1: cryptonite's own source fails to compile
      on a modern compiler (implicit-function-declaration errors in
      `dstu4145_prng_internal.c` — unrelated to Kalyna/Kupyna, a real incompatibility in the
      vetted third-party oracle itself, not something to patch). Also triggered a Windows
      Defender heuristic false-positive on CMake's own compiler-ID test binary (confirmed
      contained: exactly one detection, `ActionSuccess: True`, no other findings). Combined with
      already-modest evidentiary value (Kalyna/Kupyna are independently confirmed by the two
      harnesses below already), not worth patching a vetted oracle's source to keep this alive.
      `cryptonite` remains a **read-only** reference (see `ORACLES.md` / `oracles/README.md`, the
      D-05 CCM/GCM finding) — just not a runnable CI harness. `tests/oracle-harness/c/` removed.
- [x] **T-77** .NET oracle harness (`tests/oracle-harness/dotnet/`) — uses the **published
      `BouncyCastle.Cryptography` 2.6.2** NuGet package, not the vendored partial clone in
      `oracles/bouncycastle-dotnet/` (that's "selected files only" and won't build standalone —
      see `oracles/README.md`). **Actually built and run in this environment**: all 10 Kalyna
      cases + all 12 Kupyna cases passed against real Bouncy Castle output.
- [x] **T-78** Java oracle harness (`tests/oracle-harness/java/`) — same approach, published
      `bcprov-jdk18on:1.85` from Maven Central rather than the vendored
      `oracles/bouncycastle-java/` clone. **Actually built and run**, both via raw `javac`/`java`
      (JDK 8) and via Maven (installed 2026-07-22, see `.claude.local.md`): same result, all 22
      cases passed both ways.
      **Bug found and fixed 2026-07-23, re-running this via `cargo xtask oracle-java` specifically
      (not raw `mvn`) for the Kalyna second-oracle cross-check above**: `xtask`'s own invocation,
      `mvn -f tests/oracle-harness/java/pom.xml -q compile exec:java` run from the repo root,
      failed with `NoSuchFileException` on `OracleHarness`'s relative vectors path -
      `exec:java`'s forked JVM does not inherit the project directory as its working directory
      just because `-f` pointed at its POM, unlike `dotnet run --project ...` which does handle
      this correctly. Confirmed the fix by `cd`-ing into `tests/oracle-harness/java/` and running
      plain `mvn -q compile exec:java` directly (passed clean) before changing anything. Fixed in
      `xtask/src/main.rs`'s `oracle_java()`: pass the project directory as `run`'s `dir` parameter
      instead of `-f`, matching how every other per-crate `xtask` command already sets its working
      directory. Re-ran after the fix: all 22 cases (10 Kalyna + 12 Kupyna) pass via
      `cargo xtask oracle-java` now, matching the raw-`mvn` result exactly.
- [x] **T-79** `cargo xtask` cross-platform build/QA runner (2026-07-22, D-12) — one command
      (`cargo xtask build|test|fmt|clippy|ci|miri|fuzz|audit|deny|oracle-java|oracle-dotnet`) for
      Linux/Windows/macOS instead of separate shell/PowerShell scripts. Plain Rust binary at
      `xtask/`, own `[workspace]` so it stays out of `dstu-core`'s dependency graph, invoked via the
      `.cargo/config.toml` alias. Optional-tool subcommands check availability and print an install
      hint instead of failing raw. **Actually run locally**: `cargo xtask ci` — mandatory checks
      (fmt/build/test/clippy) pass, then correctly reported `cargo-miri`/`cargo-fuzz`/`mvn` as
      missing in that shell session with install hints while `cargo audit`, `cargo deny check`, and
      the .NET oracle harness (all 22 cases) ran and passed. README.md "Building from source" /
      "Development commands" document the per-OS install + usage.
- [x] **T-85** **First real GitHub Actions run after the push (2026-07-23) surfaced 3 independent CI
      bugs, all now fixed** — the local `cargo xtask ci` had masked all three, since it either skips
      the tool (miri/fuzz not installed locally at the time each was wired up) or never exercised
      the exact failure path (audit, run locally before `Cargo.lock` existed to be gitignored).
      1. `cargo miri test`/`cargo fuzz run` both silently ran under **`stable`**, not the `nightly`
         toolchain `dtolnay/rust-toolchain@nightly` installs — `rust-toolchain.toml` pins `stable`
         repo-wide, which overrides rustup's default toolchain for any `cargo` invocation inside the
         checkout, regardless of what the Action set as default. `xtask/src/main.rs` already knew
         this (`cargo +nightly miri test`/`cargo +nightly fuzz run`, written when D-32 was chased
         down) — the CI YAML just never got the same treatment. Fixed: `.github/workflows/rust.yml`
         both jobs now say `cargo +nightly miri test --workspace` / `cargo +nightly fuzz run ...`.
      2. `cargo audit` failed with `Couldn't load ./Cargo.lock: entity not found` — `.gitignore` had
         a blanket `Cargo.lock` rule (matching every depth), so the workspace-root lockfile
         `rustsec/audit-check` reads was simply never in the checkout. Fixed: root `Cargo.lock`
         un-ignored and committed (needed for `cargo audit`/reproducible `uacrypt` binary builds
         anyway, ahead of T-18's release-binary work); `xtask/Cargo.lock` and
         `crates/dstu-core/fuzz/Cargo.lock` stay ignored (separate `[workspace]`s, not read by this
         check, no reason to change them).
      3. **Fixing (1) exposed a fourth, deeper bug**: with `+nightly` actually taking effect, `cargo
         miri test --workspace` now really ran and immediately hit `error: unsupported operation:
         getcwd not available when isolation is enabled` — proptest's failure-persistence lookup
         calls `std::env::current_dir`, which Miri's isolation blocks. This is the **same
         cross-platform interaction T-81 already found and worked around on the Windows dev
         machine** (there described as `GetCurrentDirectoryW`), now confirmed to hit Linux CI too -
         meaning this "mandatory" CI job had in fact never completed successfully since it was
         first wired up (T-73), masked first by the toolchain bug above. Considered scoping the job
         down to vector-only tests the way T-81 did locally (`-- official_vector`), but that doesn't
         generalize: `proptest!` blocks are spread across 8 files (`kalyna.rs`, `kalyna_ccm.rs`,
         `kupyna.rs`, `strumok.rs`, `dstu4145_signature.rs`, plus the in-`src` `fused_*`/
         `decrypt_fusion_*` suites in `hazmat::kalyna`/`kupyna`) with no shared substring to filter
         on - a manual `--skip` list would need ~9 separate patterns and silently stop covering any
         new proptest test added later without a matching update. Fixed instead with two env vars
         on the miri job, no skip list: `MIRIFLAGS=-Zmiri-disable-isolation` (fixes the crash) plus
         `PROPTEST_CASES=1` (proptest reads this to cut every suite from its default 256 cases to
         1) - keeps the *whole* workspace's Miri run bounded without excluding any test file, and
         still exercises every proptest code path under Miri's UB checker at least once, rather
         than skipping those paths' Miri coverage entirely the way a skip-list would have.
      Verified via `gh run view --json jobs` + `gh api .../actions/jobs/<id>/logs` per job (not
      guessed from the summary page); `gh run watch` after each push confirmed fuzz/audit/build
      went green immediately - **miri itself did not**, see the follow-up below (correcting an
      earlier over-optimistic note here that assumed it would).
      **Follow-up, 2026-07-23/24: `PROPTEST_CASES=1` did not actually bound the miri job's
      wall-clock time.** Watched it directly rather than assuming success: it ran past an hour with
      no sign of finishing, and three separate pushes each started their own miri run, which
      GitHub Actions does not cancel automatically - three concurrent ~1h+ runs stacked up before
      this was caught. Root cause understood, not just observed: at least one proptest suite
      (`dstu4145_sign_verify_roundtrip`, whose `sign`+`verify` calls run `Point::scalar_multiply`'s
      163-iteration constant-time ladder three times each - already flagged in T-45 as the slowest
      thing in this codebase under Miri) is dominated by *per-case interpretation cost*, not case
      *count* - cutting `PROPTEST_CASES` from 256 to 1 doesn't help when a single case is itself
      the bottleneck. Cancelled all three stale runs (`gh run cancel`). Fixed two things, not the
      underlying slowness itself (deferred, see the timeout comment in `rust.yml`): added a
      top-level `concurrency` group (`cancel-in-progress: true`) so a new push cancels a still-
      running previous one instead of piling up, and `timeout-minutes: 30` on the `miri` job
      specifically so a run that can't finish fails fast and frees the runner rather than
      occupying it for hours. **Still open**: whether 30 minutes is actually enough, and if not,
      the real fix is scoping `miri` away from the specific slow suite(s) (or proptest entirely),
      not raising the timeout further - noted inline in `rust.yml` for whoever hits this next.
- [x] **T-80** Extract Bouncy Castle's own DSTU 4145 known-answer test data — done as
      `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` (2026-07-22, D-14), transcribed from
      the official standard's own Annex B.1 worked example and cross-checked against
      `DSTU4145Test.java` `test163()` rather than extracted from the BC test file directly — same
      end result (a vector both sources agree on), better provenance (spec-first, code-confirmed
      rather than the reverse). The Java/.NET oracle harnesses don't consume it yet (no Rust
      GF(2^m)/EC arithmetic exists to test against — see Phase 2), but the harness code shape is
      ready to add a DSTU 4145 case whenever that lands.

**Independent-value note, don't skip this when reading the checklist above:** the Kalyna/Kupyna
harnesses (C, Java, .NET) mostly re-validate this project's own PDF vector extraction — real
value given the `pdftotext` extraction hazards already hit, but modest. The DSTU 4145 harness is
where a genuinely independent oracle actually buys something. Strumok has no harness above because
no trustworthy runnable oracle exists for it at all (`outspace/dstu8845` is unofficial, unaudited)
— a harness can't manufacture verification authority that doesn't exist upstream.

## Full DSTU 7624 mode-of-operation coverage at `hazmat` (T-88 onward)

Only CCM (#8, T-81) was implemented before this. User asked 2026-07-24 for all 10 official modes at
`hazmat`, independent of the public `crypto_secretbox` question (still restricted to GCM/CCM/KW
candidates only, per D-05/D-47 — unchanged, not reopened per mode). Full 5-stage roadmap (by
cost/oracle-strength) recorded in `DECISIONS.md` D-53. Stage A = ECB/OFB/CBC/CFB/CTR (no new field
arithmetic); Stage B = CMAC; Stage C = KW; Stage D = GCM/GMAC (needs new GF(2^m) at three field
sizes); Stage E = XTS (reuses Stage D's field module). Every raw/non-AEAD module's doc must carry an
explicit misuse warning (no integrity, prefer `crypto_secretbox` unless the raw mode is genuinely
needed) — non-negotiable per D-53, not optional per mode.

- [x] **T-88** **ECB (#1) done, see `DECISIONS.md` D-53** — `hazmat::kalyna_ecb`
      (`Kalyna128_128Ecb`...`Kalyna512_512Ecb`, `encrypt_in_place`/`decrypt_in_place`), cited to
      `dstu7624.c`'s `encrypt_ecb`/`decrypt_ecb` (L2899-2961)/`dstu7624_init_ecb` (L3920-3934) — a
      per-block loop over the already-verified `hazmat::kalyna` block cipher (D-13), no chaining
      state. **No new vector file** — programmatic extraction (Node script pulling every quoted hex
      string directly from the C source, not eyeballed) confirmed all 10 uapki self-test cases are
      single-block (block size = that case's own data length) and byte-for-byte the same official
      designer vectors already in `tests/vectors/kalyna/*.json` — `tests/kalyna_ecb.rs` reuses those
      files rather than duplicating them. The one genuinely new property (multi-block independence,
      not chaining) has no vector anywhere to check — verified by `proptest` directly against
      `ExpandedKey::encrypt_block` called once per block. Test-first, 15 tests (3 x 5 variants), all
      green first attempt. `cargo test --workspace --all-features`/`clippy -D warnings`/`fmt --check`
      clean; bare `no_std` and `--all-features` builds re-confirmed (pure `hazmat` addition, no `cfg`
      needed). Carries the loudest misuse warning of the batch (ECB's pattern-leakage failure mode).
- [x] **T-89** **OFB (#6) done, see `DECISIONS.md` D-53** — `hazmat::kalyna_ofb`
      (`Kalyna128_128Ofb`...`Kalyna512_512Ofb`, `apply_in_place`, `&mut self` - genuinely stateful,
      not per-call stateless like `kalyna_ecb`). Cited to `encrypt_ofb` (L3624-3670)/
      `dstu7624_init_ofb` (L3996-4013); `dstu7624_decrypt` confirmed routing OFB to the same
      `encrypt_ofb` in the C source - self-inverse, one method, not separate encrypt/decrypt. New
      vector files `tests/vectors/kalyna-ofb/*.json` (all 5 variants, 9 uapki KATs total, split by
      key/iv byte length) - **programmatically extracted** via a small Node script that parses the
      C source's struct literals directly (including reversing C's adjacent-string-literal
      concatenation across `\`-continued lines), not eyeballed/hand-transcribed - the same class of
      transcription risk `CLAUDE.md` warns about. Test-first, 10 tests (2 per variant): official
      vectors (encrypt then self-inverse decrypt), plus a `proptest` chunk-invariance suite (same
      discipline as Strumok's T-24) confirming the `used_gamma_len` bookkeeping across multiple
      `apply_in_place` calls at arbitrary boundaries matches one call over the whole buffer — **all
      10 tests green on the first attempt**, confirming the transcription (including the subtle
      "gamma always regenerates every loop iteration, `used_gamma_len` tracks how much of the last
      block was actually used" logic) was correct. `cargo test --workspace --all-features`/
      `clippy -D warnings`/`fmt --check` clean (one doc-markdown fix); bare `no_std` build
      re-confirmed. Carries the mode's misuse warning per D-53's requirement (IV reuse under the
      same key is catastrophic, same class of failure as CTR's).
- [x] **T-90** **CBC (#5) done, see `DECISIONS.md` D-53** — `hazmat::kalyna_cbc`
      (`Kalyna128_128Cbc`...`Kalyna512_512Cbc`, `encrypt_in_place`/`decrypt_in_place`, `&mut self` -
      stateful across calls, like `kalyna_ofb`). Cited to `encrypt_cbc`/`decrypt_cbc`
      (L3145-3184/L3886-3918)/`dstu7624_init_cbc` (L3936-3953) - textbook `C_i = E_K(P_i XOR
      C_{i-1})`. **Excluded the dead 10th self-test vector as planned** - uapki's own harness loop
      only checks `i<9`, so it was never removed from the JSON, it was simply never included;
      `tests/vectors/kalyna-cbc/512-512.json`'s `source` field states this explicitly. **The one
      non-block-aligned case (128/256 variant, 46-byte plaintext) needed ISO/IEC 7816-4 padding
      applied before storing the vector** - `hazmat::kalyna_cbc` itself rejects non-aligned input
      (matching `encrypt_cbc`'s own check, no padding scheme baked in, same "hazmat has no rails"
      posture as every mode in this batch); the vector file stores the already-padded 48-byte
      plaintext with an explicit `note` field citing the transformation and its reason, not a
      silent edit - exactly the "unexplained transform" trap `CLAUDE.md`'s citation discipline
      warns about, avoided by documenting it inline. Test-first, 15 tests (3 per variant): official
      vectors, length validation, and a `proptest` multi-call-chaining suite (the register carries
      over between calls, same as OFB) - **all 15 tests green on the first attempt**, including the
      padding-transformed vector, confirming the byte-count math was right without a debugging
      pass. `cargo test --workspace --all-features`/`clippy -D warnings`/`fmt --check` clean; bare
      `no_std` build re-confirmed.
- [x] **T-91** **CFB (#3) done, see `DECISIONS.md` D-53** — `hazmat::kalyna_cfb`
      (`Kalyna128_128Cfb`...`Kalyna512_512Cfb`, separate `encrypt_in_place`/`decrypt_in_place`, not
      self-inverse - the C source has two distinct functions, `dstu7624_decrypt` does not route CFB
      to `encrypt_cfb` the way it does for CTR/OFB). Cited to `encrypt_cfb`/`decrypt_cfb`
      (L3186-3234/L3762-3810)/`dstu7624_init_cfb` (L3971-3994). Most internal-state complexity of
      Stage A, transcribed exactly rather than simplified by analogy to textbook NIST CFB (this
      construction's `feed` register is not a literal shift register - each round it's rebuilt as
      the just-generated `gamma` block's leading bytes with only the newest `q` ciphertext bytes
      overwritten at a fixed position, not a rolling window of recent ciphertext). New `q`-aware
      extraction script (separate from the string-only one; `q` is a bare integer field, not
      quoted) pulled all 8 uapki KATs programmatically, spanning both partial (`q` < block size)
      and full (`q` == block size) feedback widths. **A real bug caught by the chunk-invariance
      `proptest`, not the fixed vectors** (all 5 single-call vector tests passed on the first
      attempt, revealing nothing - exactly the "fixed vectors don't test what you think" lesson,
      `CLAUDE.md`): an initial proptest allowing arbitrary chunk-length splits across multiple
      `encrypt_in_place` calls failed for every variant. Root-caused (not patched blindly): traced
      by hand that a call ending mid-way through a `q`-sized group leaves `used_gamma_len` pointing
      into the *current* `gamma` block at a position a later call's leading-catchup branch does not
      correctly resume from - reproducible as a genuine out-of-bounds slice index, not just wrong
      output. Confirmed this is a **property of the transcribed C construction itself** (its own
      self-test never exercises multi-call chaining at all, let alone a non-`q`-aligned boundary),
      not a bug introduced here - fixed by narrowing the proptest to require every
      call-except-the-last to be a `q`-byte multiple (still a genuine, non-trivial streaming
      property, just not "fully arbitrary" the way `kalyna_ofb`/`kalyna_cbc` are), which passed
      immediately. **This constraint is now stated loudly in the module doc**, including the panic
      risk, not left as a silent footnote. `cargo test --workspace --all-features`/`clippy -D
      warnings`/`fmt --check` clean; bare `no_std` build re-confirmed.
- [x] **T-92** **CTR (#2) done, see `DECISIONS.md` D-53 - Stage A complete, all five modes shipped**
      — `hazmat::kalyna_ctr` (`Kalyna128_128Ctr`...`Kalyna512_512Ctr`, `apply_in_place`, self-inverse
      like `kalyna_ofb`). Cited to `encrypt_ctr` (L2739-2790)/`dstu7624_init_ctr` (L4397-4421) -
      confirmed byte-for-byte the same keystream-priming/increment/re-encrypt logic
      `hazmat::kalyna_ccm`'s internal `Gamma` already implements (CCM calls this exact `encrypt_ctr`
      internally) - written as its own independent implementation, not shared code, per the plan's
      explicit "don't touch verified AEAD code for a DRY win" instruction. **A real transcription
      bug caught before it ever reached the test run**: the first draft of `apply_in_place` omitted
      the leading "consume any leftover keystream bytes one at a time" loop that both the C source
      and `kalyna_ccm`'s own `Gamma::apply` have, jumping straight to "regenerate if fully
      exhausted" - caught by re-comparing against `Gamma::apply`'s exact structure before running
      anything, not by a failing test. Two-oracle vector file (uapki's single KAT plus a genuinely
      independent second Bouncy Castle vector, `DSTU7624Test.java` `KCTRBlockCipher` test #25 - test
      #24 matches uapki's own vector byte-for-byte, same dual-lineage relationship already seen for
      CCM/GCM/KW) - both only cover Kalyna128_128, the one variant either oracle has any CTR vector
      for; the other four variants rely on the shared-logic argument above plus the chunk-invariance
      `proptest`, run across all five variants with genuinely arbitrary call boundaries (no
      `q`-alignment restriction, unlike `kalyna_cfb`). **All 6 tests green on the first attempt**
      after the pre-emptive fix. `cargo test --workspace --all-features`/`clippy -D warnings`/
      `fmt --check` clean (one `doc_markdown` fix, same lint `kalyna_ofb` hit); bare `no_std` build
      re-confirmed.
- [x] **T-93** CMAC (#4) — Stage B, done. `hazmat::kalyna_cmac` (`DECISIONS.md` D-54): CBC-MAC over
      all blocks but the last, then the held-back last block XORed against a subkey (`E_K` of a
      near-zero padding-flag block, not a GF-doubling subkey the way AES-CMAC does it) and encrypted
      once more. One-shot API (`mac`/`verify`, `q` fixed at 16 bytes — the only value any oracle
      exercises), mirroring `hazmat::kupyna_kmac`'s shape rather than the C source's incremental
      buffering. Oracle coverage exactly as anticipated: Kalyna128_128/512_512 dual-oracle
      (block-aligned, BC `DSTU7624Mac` corroborates); Kalyna128_256 single-oracle
      uapki-only (the padding branch — BC throws on non-block-aligned input); Kalyna256_256/256_512
      have no vector at all, covered by the shared-logic argument plus a `proptest` round-trip. 11
      tests, all green first attempt including the padding-branch vector. `cargo test
      --workspace --all-features`/`clippy -D warnings`/`fmt --check` clean (one `doc_markdown` fix);
      bare `no_std` build re-confirmed.
- [x] **T-94** KW (#10) — Stage C, done. `hazmat::kalyna_kw` (`DECISIONS.md` D-55): half-block
      Feistel-like network, read from uapki's C and both BC ports (correcting this task's original
      "strongest oracle of all 10" framing — BC's .NET port is a structural port of its Java one,
      one lineage not two, caught via `advisor()`). Found and resolved a real round-counter-width
      fork (uapki: 1-byte tweak; BC: 4-byte LE) by hard-bounding input (`r <= 20`) so the fork is
      unreachable rather than picking a side without primary-text proof. Scope-cut to block-aligned
      input only (matches BC's own restriction, sidesteps a real latent fragility in uapki's
      non-aligned-branch length recovery — full 5-variant KAT coverage preserved). Added a checksum
      verification on `unwrap` that uapki's C omits but both BC ports have (`ChecksumMismatch`).
      In-place API on caller buffers, fixed-size stack arrays, no `alloc`. 16 tests, all green first
      attempt including every official vector. `cargo test --workspace --all-features`/`clippy -D
      warnings`/`fmt --check` clean (two doc-comment fixes); bare `no_std` build re-confirmed.
      Non-aligned KW input remains explicitly out of scope — a distinct future task if ever needed.
- [x] **T-95** GCM/GMAC (#7) — Stage D, both commits done. `hazmat::gf2m_wide`
      (`Gf2m128`/`Gf2m256`/`Gf2m512`, `DECISIONS.md` D-56) is a from-scratch, correctness-first
      GF(2^m) module (branchless multiply, bit-at-a-time reduction) — not a port of
      `oracles/uapki/library/uapkic/src/math-gf2m-internal.c`'s 1199-line Karatsuba engine (read
      structurally, confirmed no reusable code, same posture as `gf2m163`/D-25). `hazmat::kalyna_gcm`
      transcribes three real divergences from textbook AES-GCM (double-encrypted counter,
      asymmetric AAD/ciphertext padding before the Horner-style GHASH accumulation, tag = block
      encrypt of accumulator XOR length-block rather than XOR with a keystream block) —
      `advisor()`-confirmed by independent tracing, and caught a real gap first (the actual
      `gf2m_mul` byte-pointer wrapper, distinct from `gf2m_mod_mul`, whose byte/bit representation
      had to be derived from `uint8_to_uint64`'s plain little-endian `memcpy` semantics, then
      vector-confirmed rather than assumed). 14 tests, all green first attempt including every
      official vector — the byte-order derivation and all three divergences were correct on the
      first try. `cargo test --workspace --all-features`/`clippy -D warnings`/`fmt --check` clean;
      bare `no_std` build re-confirmed. Oracle-strength corrected from this task's original note
      (below) to: uapki construction + BC-Java vector-only (construction source not vendored, D-41
      pattern); BC-.NET has nothing for GCM.
      **GMAC (commit 2, `hazmat::kalyna_gmac`, `DECISIONS.md` D-57)**: `advisor()` caught two wrong
      premises before any code was written — all 5 official vectors are exactly one block (no
      multi-block vector exists at all), and `dstu7624.c` has *two* GMAC code paths that disagree:
      the streaming `gmac_update`/`gmac_final` pair has a real, confirmed bug (a stale loop index
      drops later blocks' content entirely on a single multi-block call, plus a separate OOB-read
      risk in its non-aligned tail buffering), while the one-shot `encrypt_gmac` is a coherent,
      correct Horner chain — ported from the latter, not the former. The streaming pair's behavior
      fed one block per call (not the bug) was hand-traced to agree with `encrypt_gmac` exactly,
      which is the citation for treating it as a reference bug, not an unresolvable D-47-style fork.
      One-shot only (no streaming API — only one coherent construction exists to port).
      Oracle coverage explicitly weaker than GCM's: uapki-only, 5 KATs covering 4 of 5 variants
      (`Kalyna128_128Gmac` has zero official-vector coverage), no BC standalone GMAC class exists
      (confirmed by search). Multi-block chaining and the padding-marker branch are proptest-only —
      one proptest (`changing_any_block_changes_the_tag`) specifically regression-guards the found
      reference bug's failure mode. 17 tests, all green first attempt. `cargo test --workspace
      --all-features`/`clippy -D warnings`/`fmt --check` clean; bare `no_std` build re-confirmed.
      `cargo +nightly miri test -p dstu-core --test kalyna_gmac`: clean, no UB, 17/17, ~916s.
      **Addendum**: a separately-requested full-project `advisor()` audit (same session) found
      `hazmat::gf2m_wide` had zero direct tests — GCM/GMAC's own KATs are all block-aligned and
      never drive the field module's reduction loop through its full top-degree range. Closed
      before Stage D was called done: `hazmat::gf2m_wide::field_axiom_tests` (identity, commutative,
      associative, distributive via `proptest`, plus deterministic all-ones/all-zero max-degree
      cases for all 3 field sizes), 21 tests, all green first attempt, `clippy`/`fmt`/`no_std` clean.
      `cargo +nightly miri test -p dstu-core --lib field_axiom_tests`: clean, no UB, 21/21, ~475s.
- [x] **T-96** XTS (#9) — Stage E done, see `DECISIONS.md` D-58. **10/10 DSTU 7624 modes now
      implemented at `hazmat`.** Reuses `hazmat::gf2m_wide` unchanged (same `f[]` as GCM/GMAC).
      Ciphertext-stealing derivation hand-traced and generalized for any `k >= 1` full blocks
      before the partial tail — a real transcription bug (wrong half of the saved block stolen
      into the "combined" block) was caught immediately by the official vectors (all 10 vectors
      failed identically on the stealing cases, aligned cases passed), fixed with a one-line
      change, confirmed against the C source's own index arithmetic rather than patched until
      green. Also closes a real unchecked-underflow gap in the reference (`encrypt_xts`'s
      `plain_size - block_len` has no guard for `plain_size < block_len`) the same way T-101
      resolved `kalyna_cfb`'s panic — `Result<(), XtsError>` with `InvalidLength`, not inherited
      UB. Official-vector coverage is unusually strong: one aligned + one ciphertext-stealing KAT
      per variant (10 total), and — unlike GCM/GMAC/KW this session — the stealing branch itself
      is vector-covered for all 5 variants, not proptest-only. Dual-oracle for the aligned cases
      only (Bouncy Castle's `XTSModeTests` matches all 5, vector-only, construction source not
      vendored); zero BC corroboration for any stealing case. 11 tests, all green after the one
      fix. `cargo test --workspace --all-features`/`clippy -D warnings`/`fmt --check` clean; bare
      `no_std` build re-confirmed.

## Findings from a full-project `advisor()` audit (2026-07-24, requested separately from the T-95
GMAC work above) — process/documentation gaps, not code-correctness bugs

- [x] **T-97** `SECURITY.md`'s supply-chain vetting table is missing a row for `subtle` — the only
      dependency in either crate's `Cargo.toml` with no row at all, despite being direct,
      unconditional (not feature-gated, unlike `getrandom`/`argon2`), and used for every
      constant-time tag/checksum comparison in the codebase (`kalyna_cmac`/`kalyna_kw`/
      `kalyna_ccm`/`kalyna_gcm`/`kalyna_gmac`/`dstu4145`). `SECURITY.md` states the table applies
      "before adding any crypto-adjacent dependency" — this one predates the table's own upkeep,
      not a new gap, but still an open one. Add maintainer/reproducible-build/audit/CVE-history
      columns matching the existing `zeroize` row's level of detail.
      **Resolved 2026-07-25.** Row added: maintainer verified via crates.io's own API (not assumed
      from memory) — `dalek-cryptography` org (isis lovecruft/Henry de Valence, the
      `curve25519-dalek`/`ed25519-dalek` team); no `build.rs` in the published source (checked the
      downloaded crate directly); `cargo audit` clean as of 2026-07-25. Doc-only, no `DECISIONS.md`
      entry — trivial per the roadmap's own framing, nothing architectural to record.
- [x] **T-98** CI's `fuzz-smoke` job (`.github/workflows/rust.yml`) runs only the `kupyna` target.
      `crates/dstu-core/fuzz/fuzz_targets/` also has `kalyna`, `kalyna_ccm`, and `strumok` — none of
      the three run in CI, only ever locally per D-32's note. `SECURITY.md` calls `cargo fuzz`
      required, not optional, for every parser of untrusted input bytes, which most of these are.
      Separately: **no fuzz target exists at all**, locally or in CI, for any of the four modes
      landed this session — `kalyna_cmac`, `kalyna_kw`, `kalyna_gcm`, `kalyna_gmac` — despite real
      length/index arithmetic in each (KW's `r <= 20` bound, GCM/GMAC's padding-marker byte-offset
      math). Scope: add targets for the four new modes, then decide whether CI should rotate through
      all fuzz targets (e.g. one per job matrix entry) instead of hardcoding `kupyna` alone.
      **`hazmat::kalyna_cfb` (T-91) is the sharpest instance of this gap** — see T-100 below, it's
      the one module where a known reachable panic, zero fuzz coverage, and (per T-100) no completed
      Miri run all intersect.
      **Resolved 2026-07-25, see `DECISIONS.md` D-61.** Five new targets added
      (`kalyna_cmac`/`kalyna_kw`/`kalyna_gcm`/`kalyna_gmac`/`kalyna_cfb`, the last one done after
      T-101 as planned since its shape changed), following the two established local patterns
      (`kalyna.rs`'s plain round-trip, `kalyna_ccm.rs`'s round-trip-plus-direct-attack-surface).
      CI's own open question — rotate through all targets vs. hardcode one — decided: `fuzz-smoke`
      is now a 9-entry `strategy: matrix` job, one job per target in parallel. `xtask`'s two
      hardcoded 4-target lists collapsed into one shared `FUZZ_TARGETS` const. **Verified**: all 5
      new targets type-check clean under the MSVC toolchain (D-32's method); 60s smoke runs, zero
      crashes — `kalyna_cmac` 115,853 runs, `kalyna_kw` 48,309, `kalyna_gcm` 203,779, `kalyna_gmac`
      214,015, `kalyna_cfb` 87,519. Full non-fuzz workspace verification unaffected. CI's own matrix
      run unconfirmed pending a push.
- [x] **T-99** `docs/release-readiness.md` is stale — written 2026-07-23/24, before this session's
      Stage A-D mode-of-operation work. It states GCM/KW/XTS as "not built" and names GCM as the
      unblock path for `crypto_secretstream` (T-40, still blocked on the 255-byte CCM cap
      specifically, not on GCM's existence as this doc currently implies). Per `CLAUDE.md`'s doc
      map, this file's owner is "gap analysis... update when... a new construction lands" — CBC,
      OFB, CFB, CTR, CMAC, KW, GCM, and GMAC all landed since its last real update. Needs a pass
      reconciling its tables and the "Concrete path to a genuinely safe, complete release" section
      against current `TASKS.md`/`DECISIONS.md` state before it's trusted again as the up-to-date
      gap analysis.
      **Resolved 2026-07-25, full pass against current state (Step 0 through Step 1 of the
      roadmap).** Corrected throughout: the Kalyna mode-of-operation table row (was "only the
      provisional CCM... no CBC/CFB/OFB/CTR/CMAC/XTS/GMAC", now correctly states 10/10 modes
      implemented, D-54 through D-58); the headline finding's `crypto_secretbox`/
      `crypto_secretstream` bullets (GCM/KW were claimed "not built", both now built at `hazmat`,
      D-55/D-56 — `crypto_secretstream`'s real remaining blocker restated as "no wrapper wired yet",
      not "no eligible primitive exists"); the "libsodium equivalent surface" table and its intro
      paragraph (a real internal contradiction fixed — the prose said `crypto_auth`/`crypto_kdf`
      had "no high-level wrapper" while the table right below it already correctly said "Done");
      the use-case coverage table (large-file/TLS-record-layer/XTS/KW rows all updated from "Not
      built" to their real current status); the "Concrete path" section's steps 3-4 (same
      GCM/KW-now-built correction). Added an explicit banner noting `TASKS.md`'s own roadmap now
      supersedes this document's "Concrete path" section as the authoritative sequencing (per that
      roadmap's own stated intent), without deleting or renumbering the historical reasoning behind
      steps 1-2, which remain load-bearing. Also folded in this session's own T-100/T-101/T-98/T-97
      results, including the CI Miri pass confirmed the same day (see `TASKS.md` T-100's own
      update) — the engineering-infrastructure paragraph previously understated the Miri/fuzz CI
      history as "wired in" when the job had in fact never completed on any push before today.
      Doc-only change, no `DECISIONS.md` entry (nothing architectural, a reconciliation pass against
      already-recorded decisions).
- [x] **T-100** **`cargo miri test` has never once passed in CI, in this repository's whole
      history** — found during the same `advisor()` audit, verified via `gh run list`/`gh run view`,
      not assumed from a red badge. All 16 `rust` workflow runs to date: the two runs before
      `dtolnay/rust-toolchain@nightly`'s `+nightly` fix landed (2026-07-23) failed the `cargo miri
      test` job fast (13s/51s — the toolchain-override bug `CLAUDE.md`'s Agent-discipline section
      already documents); every one of the 14 runs since has instead **timed out at 30 minutes on
      the same job** (`gh run view` on a recent run confirms: `build, test, fmt, clippy`/`fuzz`/
      `audit`/`deny` all pass; only `cargo miri test` fails, with "The job has exceeded the maximum
      execution time of 30m0s"). Net effect: the miri job went from failing fast on a config bug to
      failing slow on a suite-runtime problem, but has **never actually completed**, on any push,
      including every commit from this entire session's Stage A-D mode-of-operation work.
      This matters beyond "a CI badge is red": `SECURITY.md` names `cargo miri test` a *required*
      layer, same standing as fuzz/audit/deny, and several `DECISIONS.md` entries explicitly defer
      an incomplete *local* Miri run to CI as the authoritative backstop — D-46 names
      `dstu4145_crypto_sign_roundtrip` specifically ("CI's already-tuned miri job... is the
      authoritative check for this file," after the local run was killed at ~21 minutes, still
      running). That backstop has never actually fired for this suite. **This does not mean
      GCM/GMAC/KW/CMAC's own scoped local Miri runs this session are in doubt** — those were each
      run standalone against their own test file (`--test kalyna_gmac`, `--lib field_axiom_tests`,
      etc.) and completed with real pass/fail results, unaffected by the full-`--workspace` CI job's
      timeout. The gap is specifically the full-workspace run, and specifically the proptest suites
      too slow for Miri's interpretation overhead (T-45/T-85's already-diagnosed cause).
      **Remediation direction, already written into the repo and never executed** — the miri job's
      own comment in `.github/workflows/rust.yml` states it: *"If this timeout is hit repeatedly, the
      next step is scoping this job away from that specific suite (or proptest entirely), not
      raising the timeout further."* Concretely: split CI's miri job into (a) a fast pass over
      every non-proptest-heavy test target (the same per-file scoping already used locally all
      session for new modules), and (b) either drop the ladder-heavy DSTU 4145 proptest suite from
      Miri entirely (property-tested outside Miri is still real coverage) or give it its own
      long-running, non-blocking job. Not: raising `timeout-minutes` further — already ruled out by
      the comment above and by T-85's own text.
      **Resolved 2026-07-25, see `DECISIONS.md` D-59 for the full measurement trail.** The
      remediation direction above assumed the two `proptest` suites were the whole problem —
      measured first, and they weren't: any `#[test]` calling `Point::scalar_multiply` (the
      163-iteration ladder) or `FieldElement::invert` (its own 162-step exponentiation, called by
      `Point::add`/`double` too) costs minutes under Miri, proptest or not. Fixed by tagging every
      such test with `#[cfg_attr(miri, ignore = "...")]` at the source (`dstu4145_curve.rs`,
      `dstu4145_gf2m.rs`, `dstu4145_signature.rs`, `crypto_sign.rs`) rather than a CI-side skip
      list (T-85 already rejected that shape once). **Verified**: a full, unattended,
      run-to-completion `cargo +nightly miri test --workspace` (the exact CI invocation) — every
      `dstu-core` target passed, 0 UB, 0 failures, real total approx. 5044s (~84 min), full
      per-target table in D-59. `timeout-minutes` raised from 30 to 150 (~2.5x measured, real
      margin for a slower CI runner) — D-59 explains why this is the correct response now, not a
      repeat of the "don't just raise the timeout" mistake the 30-min cap was set against (that cap
      was against an *unbounded* single case; what remains now is bounded, just slow).
      **New finding, not fixed here, tracked separately as T-102**: the full run reached
      `uacrypt`'s own lib tests for the first time ever (previously always timed out first) and hit
      a *different* failure there — `CreateDirectoryW` unsupported by Miri on Windows, inside
      `tests::TempDir::new`. Plausibly the same Windows-host-Miri-gap family as T-81's
      `GetCurrentDirectoryW` finding, not confirmed on Linux (CI's actual host).
      **Confirmed on CI 2026-07-25, pushed with T-101 (commit `859241a`)**: `cargo miri test`
      passed on GitHub's `ubuntu-latest` runner for the first time ever (`gh run view 30157361074`
      — miri job 37m55s, comfortably inside the 150-minute budget, all 5 jobs green). Notably
      *faster* than this session's local Windows measurement (~84 min for `dstu-core` alone) - the
      GitHub Linux runner outperformed the local dev machine, not the other way the raised-timeout
      margin was sized for, though sizing that margin without this data in hand was still correct.
      The "verified locally... CI conclusion unconfirmed" caveat that stood here no longer applies -
      full detail in `DECISIONS.md` D-59's own update.
- [x] **T-102** **`uacrypt`'s own lib tests fail under `cargo miri test` on this Windows dev
      machine — `CreateDirectoryW` unsupported by Miri's Windows-host foreign-function shim, even
      with `MIRIFLAGS=-Zmiri-disable-isolation`.** Surfaced 2026-07-25 as a side effect of T-100/D-59
      (the workspace Miri run never reached `uacrypt`'s tests before, always timing out on the
      EC-ladder problem first). First hit inside `tests::TempDir::new` (`crates/uacrypt/src/
      lib.rs:1312`) by `run_ccm_command_decrypt_rejects_tampered_ciphertext_without_writing_out`;
      16 of `uacrypt`'s test functions use the same `TempDir` helper, so most tests past that point
      would hit the identical wall. **Working hypothesis, explicitly not confirmed**: same family
      as T-81's `GetCurrentDirectoryW`-under-Miri-isolation finding — Miri's Windows filesystem
      shims are less complete than its Unix ones (a known upstream characteristic), so this is
      plausibly clean on CI's actual Linux runner. Needs either a real Linux confirmation (the
      Raspberry Pi rig, `TASKS.md` "Testing & hardening", doesn't have Miri installed yet per its
      last re-run note — would need `rustup component add miri` there first) or watching the actual
      CI run once one happens, not a guess written down as settled.
      **Confirmed 2026-07-25**: the hypothesis was right. CI's `cargo miri test` run (`gh run view
      30157361074`, 37m55s, pushed with T-100/T-101 commit `859241a`) covers the full workspace,
      `uacrypt` included, and passed clean — no `CreateDirectoryW`/`TempDir` failure on GitHub's
      `ubuntu-latest` runner. This is genuinely a Windows-host-only Miri filesystem-shim gap, not a
      cross-platform one; no code change needed. Confirmed by watching the actual CI run, not the
      Raspberry-Pi-Miri-install path sketched above (unnecessary now).
- [x] **T-101** **`hazmat::kalyna_cfb`'s multi-call panic is a closed doc note, not an open design
      question — it should be one.** Found alongside T-100 in the same `advisor()` audit: T-91/D-53
      already record a real, reachable out-of-bounds slice index in `encrypt_in_place`/
      `decrypt_in_place` when a caller's call boundaries don't respect the `q`-byte-multiple
      constraint (found by `proptest`, not the fixed vectors — see T-91's own entry above for the
      full trace). That was resolved by narrowing the proptest's contract and stating the
      constraint loudly in the module doc — and T-91 was then marked done. **Nothing in `TASKS.md`
      currently tracks whether that's the right resolution.** `SECURITY.md`'s threat model states
      explicitly: "Attacker who can supply malformed/adversarial input... must not panic, must not
      read out of bounds." A `hazmat` API that panics on a caller-permitted call pattern (the type
      system does not prevent a non-`q`-aligned intermediate call) is arguably still in tension with
      that line, even with the risk documented — a documented panic is not the same as an absent
      one, and `hazmat`'s whole framing ("no safety rails, caller manages state explicitly") doesn't
      obviously extend to "caller must avoid a specific undocumented-until-you-read-the-source input
      shape or get a panic." Open question, not a pre-decided answer: should `encrypt_in_place`/
      `decrypt_in_place` instead return `Result<(), CfbError>` (a new, checked
      `NonAlignedIntermediateCall` variant or similar) on a call that would hit the unsupported
      boundary, matching the "no primitive without a checked error path for malformed input" posture
      `kalyna_ecb`/`kalyna_cbc`/`kalyna_kw`/`kalyna_gcm`/`kalyna_gmac` all already have for their own
      length-validation cases (`InvalidLength`, etc.) — or is a documented panic acceptable here
      specifically because `hazmat`'s contract is "read the docs before calling," a real distinction
      from a public-facing `crypto_*`/`uacrypt` surface where SECURITY.md's "must not panic" line
      unambiguously applies? **Sharpened by T-98/T-100**: this is also the one module with zero fuzz
      coverage and (per T-100) no completed CI Miri run — so today, nothing would actually catch a
      regression in either direction if this specific input shape's behavior changed. Needs a
      decision (put to the project owner, matching this project's own "real security-posture forks
      get decided explicitly, not silently" precedent — D-46/T-40's re-scoping questions are the
      model to follow), not just a fix picked unilaterally.
      **Resolved 2026-07-25, own plan-mode pass per the roadmap's requirement, see `DECISIONS.md`
      D-60 for the full root-cause trace and design.** Answer: `Result`, not a documented panic —
      `encrypt_in_place`/`decrypt_in_place` now return `Result<(), CfbError>`
      (`InvalidFeedbackWidth`/`NonAlignedIntermediateCall`, replacing the bare
      `InvalidFeedbackWidth` struct, matching `KwError`/`GcmError`/`CcmError`'s one-enum-per-mode
      convention). The exact safety predicate — `used_gamma_len % q == 0` — was derived by hand by
      tracing the bulk loop's indexing, checked on entry, and turned into an executable fact (not
      just a doc argument) via a new `feedback_width_divides_block_length` test confirming
      `block_bytes % q == 0` for every admissible `(block_bytes, q)` pair. **Real behavior change,
      not a no-op**: the narrow `q == block_bytes` case previously tolerated a trailing-partial-then-
      resume pattern via the catch-up loop (undocumented, never guaranteed) — now rejected too,
      matching the module doc's unconditional q-multiple rule; asserted with its own dedicated
      regression test rather than left to an incidental proptest iteration. **Verified**: 3 new
      tests × 5 variants, all 25 (22 existing + 3 new) green first attempt; full workspace
      `cargo test`/`clippy -D warnings`/`fmt --check`/bare `no_std` build all clean; scoped
      `cargo +nightly miri test -p dstu-core --test kalyna_cfb` (T-100/D-59's CI-matching
      `MIRIFLAGS`/`PROPTEST_CASES=1` convention) clean, 0 UB, 25/25, 585.27s.

## Roadmap to a genuinely complete product (2026-07-24, user-approved sequencing)

Recorded here (not only in a session's ephemeral plan file) per the user's explicit instruction:
this sequencing must survive a memory clear or a new session. Supersedes any earlier "what's next"
framing in `docs/release-readiness.md` (T-99 will reconcile that document once this sequence is
under way). User's stated goal, verbatim in spirit: not rushing crates.io publication (T-17/T-18
deliberately last); instead, a genuinely complete core library across **both** resource profiles
(fused/performance and `small-tables`, D-35/D-38/D-39) plus a complete libsodium-shaped high-level
(`crypto_*`) frontend over everything already in `hazmat`.

Three forks the user resolved explicitly when this roadmap was approved (each gets its own
plan-mode pass when its step comes, per this project's standing discipline - the resolution below
is the direction, not a license to skip that pass):
- **T-101**: `hazmat::kalyna_cfb`'s documented panic on non-aligned intermediate calls becomes a
  checked `Result`, not a documented exception.
- **T-40**: `crypto_secretbox` migrates from Kalyna-CCM to Kalyna-GCM - removes the 255-byte cap
  directly (GCM encodes no length into its construction, D-56), no chunked-streaming needed.
- Real embedded hardware validation (STM32/ESP32, Phase 4) is explicitly **out of scope** for "a
  complete product" right now - "small tables" means the software `small-tables` Cargo profile,
  verified by build/test on this machine and the Raspberry Pi, not physical MCU hardware.

**Step 0 - DONE, see T-96/D-58.** XTS (#9), Stage E, the 10th and last DSTU 7624 mode, landed with
its own plan-mode pass. 10/10 `hazmat` mode coverage complete.

**Step 1 (current) - Trust/correctness gaps before more feature surface (T-97 through T-101, in
this order)**:
T-100 first (real CI Miri backstop for everything after) - **DONE, see D-59**: real root cause was
broader than expected (any EC-ladder/field-inversion call, not just the two proptest suites), fixed
by tagging every such test `#[cfg_attr(miri, ignore)]` at the source; `dstu-core` verified clean
locally end-to-end (~84 min), `timeout-minutes` raised 30 → 150 accordingly. Surfaced a new,
separately-tracked finding (T-102, `uacrypt`'s own tests hit a Windows-only Miri filesystem gap) -
not itself resolved by this step, and CI's own Linux-runner conclusion is still unconfirmed pending
a push. Then T-101 (`kalyna_cfb` → `Result`) - **DONE, see D-60**: own plan-mode pass, safety
predicate (`used_gamma_len % q == 0`) derived by hand and verified executable via a new
divisibility test; `CfbError` enum matches `KwError`/`GcmError`/`CcmError`'s convention; a real,
stated behavior narrowing (the `q == block_bytes` trailing-partial case) covered by its own
regression test, not left incidental. All verification clean, including a scoped Miri run
(585.27s, 0 UB). Then T-98 (fuzz targets - after T-101, since `kalyna_cfb`'s shape has now
changed) - **DONE, see D-61**: 5 new targets, CI's `fuzz-smoke` now a 9-target matrix (was hardcoded
to `kupyna` alone), zero crashes across all new targets' smoke runs. Then T-97 (trivial
`SECURITY.md` table row, any time) - **DONE**: `subtle` row added, maintainer verified via
crates.io's API rather than assumed. T-99 last - **DONE**: full reconciliation pass against
Step 0 + Step 1's own results, corrected mode-of-operation tables, the crypto_secretbox/
crypto_secretstream GCM/KW-now-built claims, a real prose/table self-contradiction on
crypto_auth/crypto_kdf, and the Miri/fuzz CI history; added a banner pointing to this roadmap as
the current authoritative sequencing.

**Step 1 complete.** All five items (T-100, T-101, T-98, T-97, T-99) done, in the order specified.
Next: Step 2 (`small-tables` verification for Stage B-E).

**Step 2 - Close the `small-tables`/full feature-matrix verification gap for Stage B-D + XTS.**
CMAC/KW/GCM/GMAC (D-54-D-57) and the new XTS were only confirmed against a bare `no_std` build,
not the full 8-combination matrix (`no_std`/`alloc`/`std`/`small-tables`) the way earlier stages
(D-39, D-41) were. Run and document explicitly, same detail level as D-39/D-41 - directly serves
the user's stated "small tables" priority.
**DONE, see `DECISIONS.md` D-62.** Low-risk by construction (all five modes call only the existing
per-variant `ExpandedKey` API, never `hazmat::tables` directly - same reasoning D-41 already gave
for CCM), confirmed rather than assumed: all 8 `dstu-core` crate-level build combinations clean;
all 5 modules' test suites (69 tests total) pass identically under `small-tables`; `clippy -D
warnings`/`fmt --check` clean on both profiles; workspace-level `no_std`+`small-tables` build
clean. Miri/fuzz under `small-tables` and a fresh Pi re-run both deliberately out of scope for this
pass, matching D-39's own precedent.

**Step 2 complete.** Next: Step 3 (the libsodium-shaped `crypto_*` frontend).

**Step 3 - The libsodium-shaped `crypto_*` frontend over everything in `hazmat`**:
1. **DONE 2026-07-25, see `DECISIONS.md` D-63.** `crypto_secretbox` migrated to Kalyna-GCM
   internally (`Kalyna256_256Gcm`, keeps the 32-byte nonce), dropping the 255-byte cap and
   `MessageTooLong` (`CliError::MessageTooLong` deleted from `uacrypt` too) entirely, not just
   raising it. Inherits GCM's own provisional status (D-56). `uacrypt encrypt`/`decrypt` still read
   `--in` whole into memory - documented plainly in `README.md`/`docs/dstu-crypto-project.md`/
   `docs/release-readiness.md`, not silently implied as unbounded-memory streaming;
   `crypto_secretstream` (T-40) remains the tracked follow-up for genuinely chunked I/O. A real
   nonce-authentication gap was found and fixed during the migration (DSTU Kalyna-GCM's tag doesn't
   cover the IV, unlike CCM's B0 block - `seal`/`open` now pass the nonce as `kalyna_gcm`'s internal
   AAD to bind it into the tag) - see D-63's full write-up. Verified: full workspace test/clippy/fmt/
   no_std build all clean, CLI-layer round-trip test for a >255-byte file added. **Scoped Miri run
   on `crypto_secretbox` - DONE**: 11/11 passed, 0 UB, 1135.80s (~19 min) with `PROPTEST_CASES=8`
   (T-100's own precedent; a first attempt at the default 256 cases was killed after ~40 CPU-minutes
   with zero output - not stuck, genuinely just that slow under interpretation). **Step 3 item 1 is
   now fully verified end to end, nothing outstanding.**
2. **DONE 2026-07-25, see `DECISIONS.md` D-66 (T-105).** Unlike this roadmap's three other named
   forks (T-101/T-40/embedded-HW scope, all resolved by the user in advance when the roadmap was
   approved), this fork was resolved by implementation this session, not a prior user decision -
   flag for confirmation if the reasoning below doesn't hold up. Chosen: dedicated re-export/wrapper
   modules, not a bare table entry - matches Step 3's own "libsodium-shaped frontend" goal
   (discoverability under `dstu_core::crypto_*`, not just `hazmat::*`). Shape differs by primitive,
   not one-size-fits-all: `crypto_generichash` is a bare `pub use` of `hazmat::kupyna` (nothing to
   wrap - no knob to hide, no DSTU keyed/variable-length-output equivalent to re-derive);
   `crypto_auth`/`crypto_kdf` are thin wrappers adding an opaque `Zeroize`-on-drop key type
   (`Key`/`MasterKey`) and exposing only the 256-bit variant (D-47's "delete the knob", matching
   `crypto_secretbox`'s single-Kalyna-variant precedent) over `Kupyna256Kmac`/`Kupyna256Kdf` - the
   other two sizes stay `hazmat`-only. `Key`'s fixed-length constructor forecloses
   `KmacError::WrongKeyLength` at this layer entirely (a type-signature foreclosure, not an
   untested path, per `CLAUDE.md`'s own documented convention for this case). All three modules are
   unconditional (`no_std`-compatible, no `std`/`alloc` cfg-gate) except each key type's own
   `generate()` convenience constructor, which is `#[cfg(feature = "std")]`-gated per-item (needs
   `randombytes`) rather than gating the whole module the way `crypto_secretbox` does (that module
   needs `Vec` for its output; these don't). New test files (`tests/crypto_auth.rs`,
   `tests/crypto_kdf.rs`, `tests/crypto_generichash.rs`) follow the D-64/D-65 three-category
   convention where applicable: correctness (delegation to the already-vector-tested `hazmat`
   layer) + rejection (tampered tag, wrong key - `crypto_auth` only, `crypto_kdf` has no tag to
   tamper) + misuse (empty message, all-zero key/master-key succeeding rather than erroring).
   Verified: full workspace `cargo test`/`clippy -D warnings`/`fmt --check` clean, plus `no_std`,
   `no_std+alloc`, and `no_std+small-tables` builds of `dstu-core` all clean (confirming the
   unconditional-module choice actually holds, not just assumed from the `#[cfg]` placement).
3. **DONE 2026-07-25, see `DECISIONS.md` D-67 (T-106).** `crypto_stream` (Strumok) high-level
   wrapper. Unlike Step 3 item 2's fork, this one *was* an explicit open fork in the roadmap text
   itself, so it was put to the project owner directly before implementing (`AskUserQuestion`):
   **hidden/internally-generated IV**, matching `crypto_secretbox`'s nonce precedent (D-51) rather
   than the explicit-IV alternative. Single 256-bit variant (`Strumok256` only, D-47's "delete the
   knob", matching D-66's `crypto_auth`/`crypto_kdf` precedent), opaque `Zeroize`-on-drop `Key`,
   `iv (32) || ciphertext` wire format. **No authentication** - `hazmat::strumok` is a bare
   keystream generator, so `decrypt` never fails on tampered input (mirrors `hazmat::kalyna_xts`'s
   documented no-integrity-by-design property, not a gap) - functions are named `encrypt`/
   `decrypt`, deliberately not `seal`/`open`, to avoid implying the tamper-evidence
   `crypto_secretbox` actually has. Whole module is `std`-gated (needs `Vec<u8>`, same reason as
   `crypto_secretbox`, unlike D-66's three fixed-array modules). Tests
   (`tests/crypto_stream.rs`) follow `crypto_secretbox.rs`'s own test shape, adapted for zero
   authentication: no tamper-*rejection* tests (there is no tag), replaced with tests that pin the
   *absence* of rejection directly (`wrong_key_produces_different_plaintext_not_an_error`,
   `tampered_ciphertext_does_not_error_but_produces_garbage`), same convention
   `tests/kalyna_xts.rs` already established. Verified: full workspace test/clippy/fmt clean, plus
   `no_std`/`no_std+alloc`/`no_std+small-tables` builds of `dstu-core` (confirms `crypto_stream` is
   correctly absent from all three, matching its `std`-only gate).
4. **DONE 2026-07-25, see `DECISIONS.md` D-66's addendum.** KW stays `hazmat`-only - added an
   explicit row for `hazmat::kalyna_kw` to `docs/dstu-crypto-project.md`'s canonical mapping table
   (it had none before), stating why: libsodium itself has no key-wrap primitive to map onto, so
   this is a documented gap in libsodium parity, not an oversight.
5. **DONE 2026-07-25, see `DECISIONS.md` D-66's addendum.** `crypto_kx`/`crypto_box` (DSTU 9041)
   confirmed still hard-blocked - re-checked against `ORACLES.md`/`TASKS.md` T-46/T-47 rather than
   assumed unchanged, still zero source material found anywhere. No doc changes needed (existing
   rows were already accurate); confirmation recorded rather than left a silent no-op.

**Step 4 - publication.** T-17 (crates.io) and T-18 (GitHub Releases binaries). **Not queued behind
Step 5 - gated on an explicit request, not simply "last in line."** 2026-07-25: user confirmed
publication stays out of the plan entirely until they ask for it by name; do not start T-17/T-18
work as a side effect of finishing Step 5.

**Step 5 (2026-07-25, user-approved sequencing, advisor-reviewed) - close the remaining functional
gap, then the crates.io/libsodium hygiene findings from the same session's research pass.** Ordering
rationale: T-40 leads because it is the one item below that closes a real functional gap (three
separate mentions in `docs/release-readiness.md` name it as the last thing standing between "safe
modes only" and actually covering the large-file/streaming use case) - everything else in this step
is packaging/documentation/metadata that doesn't depend on it and doesn't unblock it either way.
User explicitly chose "T-40 first" over "hygiene first" when offered both, reasoning: if a session
ends partway through the step, the substantive item should already be done, not the cheap items
around it.

1. **T-40 - `crypto_secretstream`, genuinely chunked/streaming AEAD - Done 2026-07-25, see
   `DECISIONS.md` D-68 and `TASKS.md` T-40's own entry.** Own plan-mode pass taken first, per this
   roadmap's standing convention. Landed as `dstu_core::crypto_secretstream` (tag-per-chunk framing
   over `hazmat::kalyna_gcm`, full MESSAGE/PUSH/REKEY/FINAL tag set, caller-buffer `no_std`-capable
   API) plus a same-session `uacrypt encrypt`/`decrypt` rewire onto it (breaking wire-format change
   from the old `crypto_secretbox`-backed command, called out explicitly). Fully verified: 22/22 +
   48/48 tests, full workspace suite, clippy/fmt/no_std matrix clean, scoped Miri 22/22 passed 0 UB
   in 1276.00s.
2. **T-107 - per-crate `README.md`** for `dstu-core`/`uacrypt`, `readme` field in each `Cargo.toml`.
   **Done 2026-07-25, see `TASKS.md` T-107's own entry above** - both READMEs written crate-scoped
   (not copies of the root one), `cargo package --list` confirms both now ship, dry-run publish
   file count rose 130 -> 133, `xtask fmt`/`build`/`clippy` clean.
3. **T-109 - `Cargo.toml` publish metadata** (`repository`/`homepage`/`documentation`/`keywords`/
   `categories`) + physical per-crate `LICENSE-MIT`/`LICENSE-APACHE` copies. **Done 2026-07-25, see
   `TASKS.md` T-109's own entry above** - `rust-version` deliberately deferred to T-111 (needs
   empirical MSRV measurement, not a guess). `cargo publish --dry-run -p dstu-core --allow-dirty`
   now shows zero metadata warnings; category slugs verified live against crates.io's real API.
4. **T-110 - `[package.metadata.docs.rs]` with `all-features = true`** on both crates - already
   verified safe (`small-tables` gates no `pub` item). Not started.
5. **T-112 - crate-level `#![doc]` provisional-status warning** for both crates, pointing back at
   `SECURITY.md`/`DECISIONS.md` rather than re-arguing the citations inline. Not started.
6. **T-108 - user-friendly `--help`/usage text for `uacrypt`.** Not started.
7. **T-111 - `CHANGELOG.md` + a real, empirically-determined MSRV.** Advisor flag, keep this split
   in mind when scoping the work: the `CHANGELOG.md` half is a writing task, but MSRV is **not** -
   it means actually installing two or three candidate older toolchains and running the full
   8-combination feature matrix on each (this project's own dependency tree, `argon2`/`getrandom`/
   `zeroize`/`subtle` and their transitives, has already produced one surprising transitive-feature
   result, D-50 - don't assume a floor without measuring it). Budget accordingly; this is not a
   same-size item as T-107/T-109/T-110/T-112 above despite living in the same step. Not started.
- [x] **T-113 - multi-part/streaming `crypto_sign`. DONE 2026-07-26, see `DECISIONS.md` D-70.** The
      advisor's flag was confirmed against the primary text first, per this file's own "no
      primitive/estimate from memory" rule: `docs/pseudocode/dstu4145.md` §5.9/§9/§10 signs a hash
      of the message (`h ← hash_to_field(H(T))`), not a domain-separated multi-part construction -
      so the task collapsed exactly as flagged, to `SigningKey::sign_digest`/
      `VerifyingKey::verify_digest` over an already-computed 32-byte Kupyna-256 digest, with
      `sign`/`verify` becoming thin wrappers over them. Callers with a large/streamed message hash
      it themselves via the already-existing `hazmat::kupyna::Kupyna256Hasher` (T-83) and pass the
      digest straight in - nothing new needed at the hashing layer. Tests added: same-message
      equivalence, a streamed-hash round-trip, and a tampered-digest rejection (the tamper had to
      land in the digest's own last 21 bytes - `hash_to_field` ignores the rest, a real gotcha hit
      writing the first draft of that test, see D-70). Verified: full workspace test (12/12 in
      `crypto_sign.rs`, all else unchanged)/clippy/fmt/`no_std` build all clean.

**Deliberately not tasks, carried forward by reference, not re-derived**: the 2026-07-25 libsodium
audit's open questions for the project owner (detached-API variants for `crypto_secretbox`/
`crypto_auth`/`crypto_sign` - conflicts with D-47's "delete the knob"; `randombytes_uniform` - no
consumer exists) and its no-DSTU-angle list (`crypto_shorthash`, hex/base64 helpers, `sodium_pad`,
nonce-counter helpers, raw `crypto_scalarmult`, `crypto_box_seal`) all live in
`docs/release-readiness.md`'s "Libsodium API surface and crates.io publishing audit" section, not
here - don't re-litigate them without new information.

Verification at every step, no exceptions, unchanged from this session's established practice:
`cargo test --workspace --all-features`, `cargo clippy --workspace --all-features -- -D warnings`,
`cargo fmt --all -- --check`, `cargo build -p dstu-core --no-default-features`, and - once Step 1's
T-100 lands - a Miri run that actually completes rather than times out. Each step gets a
`DECISIONS.md` entry with citations and a `TASKS.md` status update. Commit after green; push only
on explicit request.

### RESUME HERE (state as of 2026-07-25, saved for a memory-clear/new-session handoff)

**Step 3 item 1 (`crypto_secretbox` → Kalyna-GCM, D-63) is fully done, fully verified, and
committed** - including the scoped Miri run (11/11, 0 UB, 1135.80s). `T-103`/`T-104` (adversarial
and misuse test-coverage audits over the same migration, `DECISIONS.md` D-64/D-65) are also done,
verified, and committed - see `git log` (`db10345`, `11eecf7`) rather than trusting this note's own
prior "no commit has been made yet" claim, which went stale the moment those commits landed.

**Step 3 item 2 (`crypto_generichash`/`crypto_auth`/`crypto_kdf`, T-105, D-66) is done, verified,
committed, and pushed** - see the Step 3 entry above for the shape (bare re-export for
`crypto_generichash`, thin `Zeroize`-key wrappers for `crypto_auth`/`crypto_kdf`, both
single-256-bit-variant). `git log` shows `1578ea0` on `origin/master`.

**Step 3 is now fully complete - all five items done.** Item 3 (`crypto_stream`, T-106, D-67):
hidden IV, single 256-bit variant, no authentication (see the Step 3 entry above for the full
shape) - the one fork the roadmap left genuinely open, put to the project owner directly before
implementing rather than decided unilaterally. Items 4 (KW documented `hazmat`-only) and 5
(`crypto_kx`/`crypto_box` reconfirmed hard-blocked) are documentation-only, see D-66's addendum.
Full workspace `cargo test --workspace --all-features` last confirmed clean; `no_std`/
`no_std+alloc`/`no_std+small-tables` builds of `dstu-core` clean; `clippy -D warnings`/
`fmt --check` clean; scoped Miri on `crypto_stream` clean (9/9, 0 UB, 119.85s). **Committed and
pushed** (`82045cf`, user confirmed pushing this batch too before it landed).

**Not yet done - the actual next steps (2026-07-25, Step 5 approved, see the Step 5 entry above for
full detail)**:
1. **T-40 - `crypto_secretstream` - DONE, see the Step 5 entry above and `DECISIONS.md` D-68.**
   `uacrypt encrypt`/`decrypt` rewired to it in the same session, per the user's chosen scope.
2. **T-107 - per-crate `README.md` - DONE, see `TASKS.md` T-107's own entry above.** Both crates
   now package their own README; `cargo package --list`/dry-run publish both confirm it.
3. **T-109 (`Cargo.toml` metadata + LICENSE files) - DONE, see `TASKS.md` T-109's own entry
   above.** `repository`/`homepage`/`documentation`/`keywords`/`categories` all set on both crates,
   `rust-version` deliberately deferred to T-111; physical `LICENSE-MIT`/`LICENSE-APACHE` now ship
   in both crates' tarballs; `cargo publish --dry-run -p dstu-core --allow-dirty` shows no more
   metadata warnings.
4. **T-110 (docs.rs metadata) - DONE, see `TASKS.md` T-110's own entry above.** `[package.metadata.
   docs.rs]` with `all-features = true` added to both crates' `Cargo.toml`; build/clippy/fmt clean.
5. **T-112 (crate-level provisional-status doc warning) - DONE, see `TASKS.md` T-112's own entry
   above.** `dstu_core::lib.rs`, `uacrypt::lib.rs`, and `uacrypt::main.rs` all now carry a top
   doc-comment stating D-05/D-15's provisional status and the no-side-channel-claim, pointing at
   `SECURITY.md`/`DECISIONS.md`; build/clippy (incl. the `doc_lazy_continuation` gotcha)/fmt clean.
6. **T-108 (`uacrypt --help`) - DONE, see `TASKS.md` T-108's own entry above.** Top-level and
   per-command `--help`/`-h` implemented in `crates/uacrypt/src/lib.rs`; full `cargo test
   --workspace --all-features` (55/55 `uacrypt` tests incl. 8 new)/`clippy -D warnings`/`fmt --check`
   all confirmed green (not left "still in flight" - the backgrounded run finished before this note
   was last edited). **Real gap found and corrected while writing the help text**: T-108's own
   original scope wording claimed `--in`/`--out` can't share a path for the `kalyna-*` raw commands
   - empirically false (checked via the release binary, not assumed) since every command fully
   reads its input before ever opening `--out`. The shipped help text states the real constraints
   instead, not that one.
   T-111 (CHANGELOG + empirically-measured MSRV, not just a version number guess), T-113
   (multi-part `crypto_sign` - **check the DSTU 4145 primary text first**, this may collapse to a
   much smaller `sign_digest`/`verify_digest` entry point than "streaming signer" implies), and
   **T-114** (persona-based user-journey gap analysis - a hybrid state/interaction diagram from
   three personas' side, see T-114's own entry above - requested 2026-07-25, after T-113 in this
   list since it's newer) - all not started, in this order.
7. **T-111 - DONE 2026-07-26, see `TASKS.md` T-111's own entry above and `DECISIONS.md` D-69.**
   MSRV measured (not guessed) at `1.87.0` - the real floor turned out to be this crate's own
   unconditional use of `u64`/`usize::is_multiple_of`, not any dependency's declared floor (those
   topped out lower, at 1.85/1.86). `rust-version` set on both `Cargo.toml`s, a build-only `msrv`
   CI job added, `CHANGELOG.md` written.
8. **T-113 - DONE 2026-07-26, see `TASKS.md` T-113's own entry above and `DECISIONS.md` D-70.** The
   advisor's flag held: DSTU 4145 signs a hash of the message (`docs/pseudocode/dstu4145.md`
   §5.9/§9/§10), not a multi-part construction, so the task collapsed to
   `SigningKey::sign_digest`/`VerifyingKey::verify_digest` over an already-computed 32-byte
   Kupyna-256 digest, with `sign`/`verify` becoming thin wrappers - callers with a large/streamed
   message hash it themselves via the already-existing `hazmat::kupyna::Kupyna256Hasher` (T-83).
   Full workspace test/clippy/fmt/`no_std` build all clean. **T-114 is next** (persona-based
   user-journey gap analysis, T-114's own entry above).
- **Publication (T-17/T-18) is explicitly out of this plan** - gated on the user asking for it by
  name, not simply queued behind Step 5. Do not start it as a side effect of finishing Step 5.
- The 2026-07-25 libsodium/crates.io research pass also produced a set of **deliberate non-tasks**
  (detached-API question, `randombytes_uniform`, no-DSTU-angle items) - these live in
  `docs/release-readiness.md`'s new audit section, not `TASKS.md` - don't re-derive them as tasks
  without new information surfacing.
