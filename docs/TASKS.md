# docs/TASKS.md

Progress tracker and task backlog for this project, grouped by phase. Check items off as they're
done; add new items as they're discovered. This file tracks **what** and **status** — the
**why** behind any decision or blocker lives in `docs/DECISIONS.md`/`docs/ORACLES.md`/`docs/SECURITY.md` and is
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
- [x] **T-04** `docs/SECURITY.md`, `docs/DECISIONS.md`, `docs/ORACLES.md` written
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
      in `docs/DECISIONS.md` D-13. **Confirmed 2026-07-22**: `cargo test` (all 5 variants against the
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
      citation in `docs/DECISIONS.md` D-10. **Confirmed green 2026-07-22**: `cargo test`, `cargo miri
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
      (`docs/DECISIONS.md` D-42), same day.** User asked directly whether T-83's streaming was
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
      https://github.com/specinfo-ua/UAPKI (state-expertise pedigree, see `docs/ORACLES.md`), whose
      `dstu8845.c` self-test is comment-attributed to `// ДСТУ 8845:2019` in its own source — the
      first real KAT found anywhere for this algorithm. Adopted as
      `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json` (an earlier, self-invented
      "gray vector" attempt from the same day was superseded and deleted, not kept). Cross-checked
      against `oracles/strumok-dstu8845/` (byte-identical, but treated as a lineage-sharing
      consistency bonus, not independent confirmation — see D-15) via
      `tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`. **Still not
      "official"**: not confirmed against the paid DSTU 8845:2019 text itself.
- [x] **T-13** Implement Strumok (256/512-bit key) — `dstu_core::hazmat::strumok` (`Strumok256`/
      `Strumok512`), citation in `docs/DECISIONS.md` D-18. **Confirmed 2026-07-22**: all 8
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
      this") stopped applying here specifically — see "Testing & hardening" below and `docs/DECISIONS.md`
      D-32 for how it was actually run.
- [x] **T-16** **Done 2026-07-24, same session as T-37, see `docs/DECISIONS.md` D-52** — `uacrypt`'s
      reserved `encrypt`/`decrypt`/`hash` are real top-level commands now, mode/nonce/algorithm all
      hardcoded, no user-facing crypto knobs. `encrypt`/`decrypt` are a thin wrapper over
      `dstu_core::crypto_secretbox` (T-37/D-51): new `SecretboxArgs { key_path, in_path, out_path }`
      - no `--nonce`/`--tag`/`--aad`/`--variant`, since `crypto_secretbox` itself already removed
      every one of those knobs. **Approval checkpoint surfaced and resolved with the user before
      implementation**: `crypto_secretbox` caps messages at 255 bytes, and a command literally named
      `encrypt --in file --out file` silently failing past that would be a real usability trap,
      especially next to `hash` which handles files of any size — asked directly via
      `AskUserQuestion`, user chose **build all three now, cap made loud** (new
      `CliError::MessageTooLong` with an explicit "255-byte limit... see `docs/TASKS.md` T-40" message,
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
- [x] **T-17** Publish `dstu-core` to crates.io. **Readiness-checked (not performed) 2026-07-25,
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
      **Actually done 2026-08-09**, via the `publish-crates` job `release.yml` already had
      (added at T-157/D-114) firing automatically on the `v0.3.0` tag push - `dstu-core` v0.3.0
      (crates.io `created_at` 2026-08-09T17:41:14Z) then `uacrypt` v0.3.0 (17:53:49Z), both
      confirmed live via crates.io's own API. This checkbox and `CLAUDE.md`'s "MVP scope" line
      had gone stale (D-159's failure shape - no task-ID string in either place for a grep to
      catch), found and fixed while starting T-164/T-203's binding-registry work.
- [x] **T-18/T-119** **DONE 2026-07-26.** Prebuilt Windows/Linux/macOS binaries via GitHub
      Releases, plus the `dstu-core` library source distribution attached to the same release -
      user-requested explicitly ("зроби реліз на гітхабі бінарника і самих бібліотек"), scoped down
      to GitHub-only first (crates.io/T-17 confirmed still separately gated - a different platform
      with a much less reversible publish step, `AskUserQuestion`-confirmed rather than assumed),
      then widened from "Windows now, other platforms later" to all three platforms in the same
      session per a follow-up correction.
      **Readiness-checked 2026-07-25**: zero infrastructure existed at that point - `.github/
      workflows/` had only `rust.yml`/`oracle-harness.yml`, no release/cross-compilation/
      binary-packaging workflow at all.
      **Pre-release gate, per `advisor()`'s explicit recommendation before touching any tag**:
      found `uacrypt` had no `--version`/`-V` at all (T-118, fixed first - a release binary that
      can't self-report its version is "the one defect actively embarrassing in a release
      artifact"). Re-ran the four mandatory checks directly after `cargo xtask ci` itself was
      interrupted mid-run (background process killed by an unrelated session interruption, exit
      code -1/"process exited while detached" - not trusted as a pass since it never reached its
      own completion, even though the fuzz/audit/deny/oracle-harness portions that did finish were
      all green) - `fmt --check`/`build --all-features`/`build --no-default-features`/
      `test --all-features` (64/64 `uacrypt` + full `dstu-core` suite)/`clippy -D warnings` all
      clean on the direct re-run.
      `.github/workflows/release.yml` added: on a `v*` tag push, three parallel jobs build
      `uacrypt --release` on `ubuntu-latest`/`macos-latest`/`windows-latest` (each packaged with
      `README.md`+both `LICENSE-*` files, `.tar.gz` on Unix/`.zip` on Windows via each runner's
      native tooling), a fourth packages `dstu-core` exactly the way `cargo publish` would
      (`cargo package -p dstu-core`, no `--no-verify` needed - `dstu-core` has zero path
      dependencies, unlike `uacrypt`) without actually publishing to crates.io, and a final job
      downloads every artifact and creates the GitHub Release via `softprops/action-gh-release`
      with auto-generated notes. `docs/CHANGELOG.md`'s `[Unreleased]` section split into a real
      `[0.1.0] - 2026-07-26` entry (Keep a Changelog convention, T-111's own precedent) plus a
      fresh empty `[Unreleased]` above it, with `keygen`/`--version`/the T-116 cross-compile
      confirmation folded into the `0.1.0` `### Added` list.
      Tag `v0.1.0` pushed, workflow run `30180682108` completed green end to end (all 5 jobs),
      release published (not draft) at 2026-07-26T00:10:48Z with 4 assets: `uacrypt-linux-x86_64.
      tar.gz`, `uacrypt-macos-aarch64.tar.gz`, `uacrypt-windows-x86_64.zip`, `dstu-core-0.1.0.
      crate`. **Verified against the real published assets, not just a green CI run**: downloaded
      `uacrypt-windows-x86_64.zip` and `dstu-core-0.1.0.crate` via `gh release download`, extracted,
      and ran the real binary standalone (no local `cargo`/toolchain in the extraction directory) -
      `--version` printed `uacrypt 0.1.0`, a full `keygen` -> `encrypt` -> `decrypt` round-trip
      matched byte-for-byte; the `.crate` tarball's file listing confirmed a real, complete
      `cargo package` output (`Cargo.toml`, `src/`, `benches/`, `examples/`, both `LICENSE-*`
      files, `README.md`). macOS asset is `aarch64` only (GitHub's `macos-latest` runner is Apple
      Silicon) - an Intel Mac build isn't covered, not previously scoped and not attempted here.
      Linux/macOS builds use each runner's default host toolchain (Linux GNU, macOS Apple-clang
      linker) - unlike this project's local Windows dev convention of `x86_64-pc-windows-gnu`, the
      Windows release asset is built with the runner's default `x86_64-pc-windows-msvc` toolchain
      specifically so end users need no separate MinGW runtime DLLs alongside the `.exe` - confirmed
      by the standalone-run smoke test above, not assumed. No `docs/DECISIONS.md` entry - release
      mechanics/CI plumbing, not an architectural decision about the library itself.
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
      README and `docs/SECURITY.md` already carry; `uacrypt/README.md` covers the actual command set
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
      all clean - doc-only change, no source touched. No `docs/DECISIONS.md` entry - packaging hygiene,
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
      --all-features -- -D warnings` clean, `cargo fmt --all -- --check` clean. No `docs/DECISIONS.md`
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
      `cargo test`/`no_std` build/Miri not re-run, nothing in their scope changed. No `docs/DECISIONS.md`
      entry - packaging hygiene, nothing architectural (same call T-107/T-109 made).
- [x] **T-111** `docs/CHANGELOG.md` (Keep a Changelog format) + a declared MSRV - requested 2026-07-25.
      **Done 2026-07-26, see `docs/DECISIONS.md` D-69.** MSRV measured, not guessed: `cargo metadata
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
      task's own text warned about). `docs/CHANGELOG.md` added at the repo root, Keep a Changelog
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
      DSTU-8845-confirmed per D-15, no independent third-party audit) - point back at `docs/SECURITY.md`/
      `docs/DECISIONS.md` rather than re-arguing the citations inline.
      **Done 2026-07-25.** `crates/dstu-core/src/lib.rs` got a top `//!` block (before the existing
      `no_std`/lint attributes) naming D-05 (Kalyna-alone mode-of-operation is an adopted
      assumption, not primary-text confirmed), D-15 (Strumok is UAPKI-attributed only), and the
      no-side-channel-claim - pointing at `docs/SECURITY.md`/`docs/DECISIONS.md` rather than re-arguing them.
      `crates/uacrypt/src/lib.rs` got the same facts folded into its existing doc-comment block
      (which already covers `kalyna-block` naming), phrased for the CLI's own command names
      (`encrypt`/`decrypt`/`kalyna-ccm`, `strumok-crypt`). `crates/uacrypt/src/main.rs` had no doc
      comment at all before this - added a short one pointing at `lib.rs`'s fuller version rather
      than duplicating the same paragraph a third time. Verified: `cargo build --workspace
      --all-features`, `cargo build -p dstu-core --no-default-features`, `cargo clippy --workspace
      --all-features -- -D warnings` (checked specifically for the `doc_lazy_continuation`/
      `doc_markdown` gotcha this file's Agent-discipline section already flags - clean), and `cargo
      fmt --all -- --check` all pass. Doc-only change - `cargo test`/Miri not re-run. No
      `docs/DECISIONS.md` entry - same packaging/doc-hygiene call as T-107/T-109/T-110.
- [x] **T-113** **DONE 2026-07-26, see `docs/DECISIONS.md` D-70.** Multi-part/streaming `crypto_sign` for
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
- [x] **T-114** **DONE 2026-07-26, see `docs/user-journey-gaps.md`.** **Persona-based user-journey
      gap analysis - a hybrid state/interaction diagram, not a plain feature checklist** - requested
      2026-07-25. Distinct from `docs/release-readiness.md`'s
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
         and `docs/PERFORMANCE.md`'s numbers.
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
      `docs/dstu-crypto-project.md`, `README.md`, and `docs/PERFORMANCE.md` rather than re-deriving their
      content - this task's value is the persona/journey framing itself, not a fourth copy of the
      same feature list. Output as a new doc (exact filename/location TBD when started - candidate:
      `docs/user-journey-gaps.md`) added to `CLAUDE.md`'s documentation map once created.
      **Done 2026-07-26** - written to the candidate filename, all three personas as Mermaid
      `stateDiagram-v2` diagrams with a per-state want-vs-have-vs-gap table, added to `CLAUDE.md`'s
      documentation map. The candidate gap named in this task's own text (T-18 blocking persona 1
      step 1) was confirmed, not just repeated, plus two more found the same way (previously
      uncatalogued at the construction level): no `uacrypt keygen` command blocks persona 1's very
      first action (both crate READMEs only say "generate one via any 32-byte-CSPRNG source," no
      worked example); no crates.io/docs.rs presence blocks persona 2's "add dependency" step and
      leaves T-110's `docs.rs` metadata inert; and, checked by grep rather than assumed (no
      `thumbv7em`/`xtensa`/`riscv32` string anywhere in the repo's CI config or `xtask`), no
      bare-metal cross-compile of `dstu-core` has ever actually been run for persona 3 - every
      `no_std` build checked in CI targets the host triple, which proves no `std`/`alloc` leaks
      through but not that the crate cross-compiles for a real MCU toolchain. None of the three are
      self-assigned new task numbers, per this task's own scope - recorded as candidates for the
      project owner to triage. Also fixed, found while cross-checking this task against the
      roadmap's own Step 5 text (`docs/TASKS.md` "Roadmap to a genuinely complete product," items 4-7):
      four lines there still said "Not started" for T-110/T-112/T-108/T-111 despite those tasks'
      own entries above being `[x]` done - the exact "stale 'not started' line next to a done line"
      failure mode `CLAUDE.md`'s agent-discipline section calls out by name, from the D-68 session.
- [x] **T-115** **DONE 2026-07-26.** `uacrypt keygen` command - triaged from a candidate gap T-114
      found (persona 1's very first action had no CLI path: both crate READMEs only said "generate
      one via any 32-byte-CSPRNG source," no worked example). `uacrypt keygen --out <path>` draws a
      fresh 32-byte key from the OS CSPRNG (`dstu_core::crypto_secretstream::Key::generate`, already
      existed as a library method - no new construction, purely a CLI wrapper) and writes it raw -
      the exact 32-byte format `encrypt`/`decrypt --key` already expect. No other flags: nothing to
      misconfigure about a random key. `--out` is written with a plain `std::fs::write` (no
      temp-file-then-rename), same convention as `kalyna-ccm`'s nonce/tag outputs and `hash`'s
      digest - a single small fixed-size write, not the larger streamed-output case that needs
      atomicity. Tests (7 new, all green): parse happy-path/missing-`--out`/unknown-flag; a
      correctness test that round-trips a generated key through real `encrypt`/`decrypt` (not just
      checking the output is 32 bytes); a distinctness test (two calls must not produce the same
      key, same convention as `kalyna-ccm`/`crypto_secretstream`'s fresh-nonce/fresh-header tests,
      since there's no oracle vector for "is this actually random"); a "fool" test (`--out` pointing
      at a directory is a clean `Io` error, not a panic); and a `run()`-level dispatch test.
      `--help`/top-level help text updated (`KEYGEN_HELP`, added to `TOP_LEVEL_HELP`'s EVERYDAY
      COMMANDS list and `print_command_help`'s match arm), `ENCRYPT_HELP`'s note pointing at
      `uacrypt keygen` instead of an external CSPRNG one-liner. `README.md`/both crate READMEs/
      `docs/user-journey-gaps.md` updated to match (the gap-analysis doc's persona-1 table row and
      diagram back-edge both updated to reflect the closed gap, not left stale). Verified: full
      `cargo test --workspace --all-features`/`clippy -D warnings`/`fmt --check` all clean. No
      `docs/DECISIONS.md` entry - CLI ergonomics exposing an already-decided construction
      (`crypto_secretstream::Key::generate`, D-68), nothing architectural, same call T-108 made for
      `--help` text.
- [x] **T-116** **DONE 2026-07-26.** Bare-metal cross-compile verification - triaged from a candidate
      gap T-114 found and confirmed by grep (no `thumbv7em`/`xtensa`/`riscv32` string anywhere in CI
      config or `xtask` before this task): every `no_std` build this project checks, in CI or
      locally, targets the **host** triple (`x86_64-*`), which proves no `std`/`alloc` API surface
      leaks through but never proved `dstu-core` actually cross-compiles for a real MCU toolchain
      (different linker, no host `libc`). Scope deliberately kept small per the candidate's own
      framing - a bare cross-compile check, not Phase 4's real-hardware validation (T-55/T-56,
      flashing/running on a physical board, still untouched and still post-MVP).
      `rustup target add thumbv7em-none-eabihf` (STM32 Cortex-M) and `rustup target add
      riscv32imc-unknown-none-elf` (ESP32-C3-class RISC-V) both installed with a plain `rustup`
      command - no custom toolchain/espup needed for either (Xtensa, the *other* ESP32 family, does
      need a custom toolchain and was not attempted here - out of scope for this pass). All 4
      `no_std`/`alloc`/`small-tables` feature combinations built clean for both targets (8 builds
      total, `cargo build -p dstu-core --no-default-features [--features alloc|small-tables|
      alloc,small-tables] --target <target>`), plus a release-profile build for
      `thumbv7em-none-eabihf`'s `fused`/`small-tables` pair specifically (1.4 MB / 1.2 MB `.rlib`
      size respectively) - **explicitly not a flash-size measurement**: an unlinked `.rlib` still
      carries every function plus debug metadata, not the dead-code-eliminated, linked output a real
      firmware image would produce, so this doesn't supersede `docs/resource-profiles.md`'s existing
      source-constant-derived table, only adds "and it really does cross-compile" evidence next to
      it. A true linked flash-size number would need an actual firmware binary crate (entry point,
      panic handler, `memory.x` linker script) that doesn't exist in this repo - not built here,
      flagged as a further candidate, not self-assigned. `README.md`'s "Embedded / `no_std` targets"
      section updated to cite this verification instead of only asserting compilability from the
      host build; `docs/user-journey-gaps.md`'s persona-3 row/bottom-line updated to match. No
      `docs/DECISIONS.md` entry - a verification pass, not an architectural decision.
- [x] **T-117** **DONE 2026-07-26.** Fixed a real doc bug in `crates/dstu-core/README.md`'s
      `## Example` block, found by actually walking persona 2's journey with real commands rather
      than re-reading the document (user-requested: "прогони віртуально... як реально поведеться
      програма, а не як ти хочеш щоб вона повелась"). The example as written did not compile:
      `SecretKey::generate()` returns `Result<SecretKey, SecretboxError>` and `seal()` returns
      `Result<Vec<u8>, SecretboxError>` (both can fail on an OS CSPRNG error - `crypto_secretbox.rs`
      lines 108/132), but the example used both as if they were the bare value, with no
      `.expect`/`?`. Confirmed empirically: created a scratch crate depending on `dstu-core` via a
      path dependency (the only way to depend on it at all pre-T-17) and pasted the example
      verbatim - `cargo build` failed with two `E0308` type-mismatch errors citing exactly this.
      **Never caught by `cargo test`** because the README isn't wired in via `include_str!`/
      `#[doc]` anywhere in `lib.rs`, so it's not a doctest - this is a class of bug the existing test
      suite structurally cannot catch, only an actual run can. Fixed by adding `.expect(...)` to
      both calls, then re-verified in the same scratch crate: builds and runs clean, prints the
      round-tripped plaintext. Also confirmed for the record during the same walkthrough (not new
      findings, re-confirming what T-17/T-114 already claimed): `gh release list` on the real repo
      returns empty (no GitHub Releases exist, persona 1's Acquire gap is real, not assumed) and
      `cargo add dstu-core` fails with "could not be found in registry index" (persona 2's Add
      Dependency gap is real). Persona 1's full CLI golden path (`keygen` -> `encrypt` -> `decrypt`
      round-trip, plus `hash`) and its two rejection paths (wrong key, single-byte-flip tamper) were
      also run against the actual release binary, not assumed from the unit tests - both correctly
      reject without writing `--out`, matching `crypto_secretstream`'s documented behavior. No
      `docs/DECISIONS.md` entry - a documentation correctness fix, not an architectural decision.
- [x] **T-120** Locally-verified, beginner-friendly usage examples across every doc surface, for
      every *safe* mode - requested 2026-07-26 by the project owner. Two distinct audiences, both
      in scope, not just one:
      1. **`uacrypt` binary users** - real, copy-pasteable examples for every top-level
         misuse-resistant command (`keygen`, `encrypt`/`decrypt`, `hash`) in `README.md`/
         `crates/uacrypt/README.md` (T-107). **Real gap surfaced while scoping this**: there is no
         `uacrypt sign`/`verify` CLI command at all - `dstu_core::crypto_sign` exists only as a
         library API (T-48, D-46), never wrapped for the CLI. This task does not silently assume
         that gap away or invent a CLI command as a side effect of writing docs (that would be a
         speculative feature, `CLAUDE.md`) - it documents sign/verify at the library level (below)
         and flags the missing CLI wrapper as a separate, explicitly out-of-scope-for-this-task
         finding for the project owner to triage into its own task, the same way T-114's candidate
         gaps were (`uacrypt keygen`, T-115; the cross-compile check, T-116).
      2. **`dstu-core` library users** - usage examples in `crates/dstu-core/README.md` (T-107)
         and/or rustdoc covering the full `crypto_*` high-level surface (`secretbox`,
         `secretstream`, `sign`/`verify`, `auth`, `kdf`, `generichash`, `stream`, `pwhash`), not
         just the one `crypto_secretbox` example that exists today - **and** both resource
         profiles: the default fused/performance-optimized build and `--features
         dstu-core/small-tables` (`docs/resource-profiles.md`) for constrained
         microcontroller targets, since a library user picking `small-tables` needs to see that the
         same API works identically, not guess. Written for engineers across the skill range, not
         assuming prior cryptography background - explain *what* each example protects against in
         plain terms (same register `--help`'s T-108 plain-language notes already established),
         not just the function calls.
      **Hard requirement, non-negotiable**: every single example must be **actually run on this
      machine** before being written into a doc, with an explicit, stated-in-advance pass
      criterion per example (exact command(s), expected exit code, expected output - byte-for-byte
      round-trip match for encrypt/decrypt, a `true`/valid signature for sign/verify, the specific
      digest value for hash, etc.) - not asserted from reading the API and assumed correct. This is
      not a new process invented for this task: it's T-117's own lesson, generalized - a
      `crypto_secretbox` README example silently failed to compile (`SecretKey::generate`/`seal`
      both return `Result`, the example didn't handle it) because it was never actually run, and
      `cargo test` structurally cannot catch a bug in a doc example that isn't wired in as a
      doctest. Prefer wiring examples in as real doctests (`cargo test --doc`) or a scratch-crate
      path-dependency run (T-117's own verification method) wherever the surface allows it, so this
      class of bug gets ongoing regression coverage instead of a one-time manual check.
      Sign/verify examples explicitly must show both the success path (valid signature verifies)
      and the failure path (a tampered message or wrong key fails verification) - a signature
      example that only shows the happy path doesn't demonstrate the primitive actually does what
      it claims, same reasoning as D-64's "attack pass" for AEAD tests.
      **DONE 2026-07-26, see `docs/DECISIONS.md` D-75.** The original scoping note above about a missing
      `uacrypt sign`/`verify` CLI was already stale by the time this task was picked up - T-124
      closed that gap earlier the same session, so this task documents a CLI surface that now fully
      exists (`sign-keygen`/`sign-pubkey`/`sign`/`verify` added to `README.md`'s "Using `uacrypt`"
      section, with a real captured transcript of `verify`'s exit-0/exit-1 behavior). Library-side:
      one real rustdoc doctest (`cargo test -p dstu-core --doc`) added per `crypto_*` module -
      `secretbox` (converts T-117's pre-existing README-only example into one with actual ongoing
      regression coverage), `secretstream`, `sign` (success **and** rejected-forgery paths, per this
      task's own explicit requirement), `auth`, `kdf`, `generichash`, `stream` (explicitly shows the
      *lack* of tamper detection, contrasting every other module's rejection behavior), `pwhash`
      (`Strength::Interactive` for doctest speed). Zero doctests existed anywhere in this crate
      before this task - a green field. Verified across every combination that matters: default
      features (7/7, `pwhash` correctly absent), `--all-features` (8/8), `--features small-tables`
      (7/7, confirming the "same API, both resource profiles" requirement). `crates/dstu-core/
      README.md`'s single-example section expanded to one subsection per module, code blocks
      copy-pasted verbatim from the doctests and diffed programmatically against the actual source
      to guarantee they can't silently drift - the diff itself caught one real omission (the
      README's `crypto_secretstream` example had dropped the tamper-rejection tail the doctest
      kept), fixed rather than left as an apparent intentional trim. Real bug caught while writing,
      not after: the first `crypto_auth` example draft tripped `clippy::doc_lazy_continuation`
      (`CLAUDE.md`'s own named gotcha), fixed by rewording immediately per that section's own
      prescribed prevention habit. Verified: full `cargo test --workspace --all-features` (including
      every new doctest), `clippy -D warnings` under default/`small-tables`/`--all-features`, `fmt
      --check`, and the `dstu-core` `no_std`/`alloc`/`small-tables`/`getrandom` build matrix, all
      clean.
- [x] **T-122** `dstu_core::crypto_sign::SigningKey` has no keypair-generation constructor - found
      2026-07-26 via a full libsodium-API-surface audit requested by the project owner
      (`docs/release-readiness.md` "round 2", triggered by the owner's frustration that gaps like
      this keep surfacing one at a time instead of being caught systematically). Confirmed by
      reading `crates/dstu-core/src/crypto_sign.rs` directly, not assumed: `SigningKey::from_bytes`
      is the *only* constructor, and it requires the caller to already have a valid raw 21-byte
      private scalar (`1 <= d < n`, `n` = the curve order) - there is no `generate()`/
      `crypto_sign_keypair()`-equivalent, and no public way to correctly rejection-sample a valid
      `d` without reaching into `hazmat` internals (`curve163::order()` isn't part of the public
      `crypto_sign` surface). Same class of gap T-115 closed for `crypto_secretstream::Key`
      (`uacrypt keygen`) - without this, nothing can actually start signing through the public API
      cold. Scope: a `std`-gated `SigningKey::generate()` (or `from_seed`-style deterministic
      variant, project owner's call which shape) drawing from `dstu_core::randombytes`, with proper
      rejection sampling against `curve163::order()` (uniform, not modulo-biased - the `subtle`/
      constant-time discipline `docs/SECURITY.md` already requires elsewhere should apply to the
      rejection loop too, not just the final scalar use). Needs its own test coverage per
      `CLAUDE.md`'s three-category rule: correctness (generated key signs/verifies successfully,
      property-tested over many generations), a distinctness property test (two generated keys
      differ), and misuse coverage for whatever's still reachable after `generate()`'s own type
      signature forecloses the rest.
      **DONE 2026-07-26, see `docs/DECISIONS.md` D-72.** Shape fork resolved by implementation (flagged
      for confirmation, not a prior user decision): plain OS-CSPRNG `SigningKey::generate()`,
      matching every other `crypto_*` module's own `Key::generate` convention with no exception so
      far. **Rejection sampling, not `reduce_wide_bytes`-style modulo reduction** - a candidate is
      21 fresh CSPRNG bytes with the top byte masked to its low 3 bits (`n`'s top byte `0x04` is a
      163-bit value inside 168 available bits), retried until it lands in `[1, n)`; the comparison
      itself goes through a new `pub(crate) Scalar::from_candidate_bytes`
      (`hazmat/dstu4145/scalar.rs`) built on the module's existing constant-time `sub3`
      subtract-with-borrow primitive, not a branching `>=`, per this task's own explicit ask to
      extend the constant-time discipline to the rejection loop. `Scalar::from_candidate_bytes` and
      `SigningKey::generate` are both `#[cfg(feature = "std")]`-gated (a `--no-default-features`
      dead-code warning caught the first pass missing this, fixed before calling it done). Tests:
      `generate_produces_a_key_that_signs_and_verifies` (20 fresh generations - no oracle vector
      exists for `generate`, so one success can't rule out "got lucky"), a distinctness test
      compared via the public `Q = -d*G` (matching the other `crypto_*` modules' own convention of
      comparing public/derived material rather than raw key bytes - a `to_bytes()` accessor was
      added later, T-124, but wasn't there yet when this test was written), and five new
      `Scalar::from_candidate_bytes` unit tests in `scalar.rs`'s own `#[cfg(test)]` module (rejects
      zero/`n`/above-`n`, accepts `n - 1`/`1`). No misuse test added - `generate()` takes no
      arguments, so the type signature forecloses that whole category, recorded rather than padded
      with a vacuous test. Verified: `cargo test -p dstu-core --lib` (39/39), the dedicated
      `crypto_sign` integration suite (14/14), full `cargo test --workspace`, `clippy -D warnings`
      under default/`small-tables`/`--all-features`, `fmt --check`, and the full `dstu-core`
      feature-combination build matrix, all clean with zero warnings.
- [x] **T-123** No pluggable/custom RNG backend for `no_std`/embedded `randombytes` - found
      2026-07-26, same libsodium-API-surface audit as T-122 (libsodium's own
      `randombytes_set_implementation()`/custom-RNG doc exists specifically for this). Today,
      `dstu_core::randombytes::randombytes_buf` is `std`-gated over `getrandom` with no equivalent
      hook - correctly absent from `no_std` builds (nothing currently promises otherwise), but there
      is no tracked path for a caller on real embedded hardware (STM32/ESP32, Phase 4 -
      `docs/TASKS.md` T-55/T-56) to get `randombytes`-shaped fresh key/nonce material at all once
      real-hardware validation starts needing it, since there's no host OS CSPRNG to call through
      `getrandom` on bare metal. **Phase-4-adjacent, not an MVP blocker** - MVP's own claim is only
      that the core `no_std`-compiles (`CLAUDE.md` MVP scope), never that `randombytes` works there.
      Revisit when T-55/T-56 (real hardware validation) is picked up, or sooner if a concrete
      embedded consumer needs it earlier.
      **DONE 2026-07-26 - user asked for it sooner than the Phase-4-adjacent deferral above
      anticipated, see `docs/DECISIONS.md` D-74.** `advisor()` consulted before touching `Cargo.toml`
      (own plan-mode pass, D-67/D-68's standing practice for a design fork): getrandom 0.3 already
      *is* the pluggable-RNG mechanism libsodium's `randombytes_set_implementation()` plays the same
      role for - decision is **capability parity, not mechanism parity** (getrandom's backend choice
      is a compile-time/link-time choice the final binary makes, not a runtime-swappable function
      pointer), so no home-grown registry was built on top - that would duplicate an established
      upstream primitive, the same class of risk D-03/D-04 already rejected for the RNG itself. New
      Cargo feature `getrandom = ["dep:getrandom"]` (independent of `std`, which now reads
      `std = ["getrandom"]`) makes `randombytes` and every `Key::generate`/`SigningKey::generate`
      reachable on a bare `no_std` build for a caller who configures one of getrandom's own non-OS
      backends themselves (typically `custom`). Widened `#[cfg(feature = "std")]` to
      `#[cfg(any(feature = "std", feature = "getrandom"))]` at every RNG-only gate, enumerated
      deliberately: `lib.rs`'s `pub mod randombytes`; `crypto_sign::SigningKey::generate` +
      `Scalar::from_candidate_bytes`; `crypto_auth::Key::generate`; `crypto_kdf::Key::generate`;
      `crypto_secretstream::Key::generate` **and** `PushState::init`; `SecretstreamError::Random`'s
      variant/`Display` arm/`From` impl (the exact "cfg-gated variant on an otherwise-unconditional
      enum" shape `CLAUDE.md` already flags by name from D-68). `crypto_secretbox`/`crypto_stream`
      untouched - their gate is `Vec`/alloc, not RNG. Verified empirically both directions on
      `thumbv7em-none-eabihf` (already installed for T-116): fails with getrandom's own
      `compile_error!` without a backend `--cfg`, succeeds with `getrandom_backend="custom"` set -
      re-confirming, not assuming, D-04's addendum still holds. End-to-end link-time+runtime proof
      (the T-117 "ran, not should-work" standard): a scratch crate with a real
      `__getrandom_v03_custom` extern fn, built and run on the host (the mechanism is target-
      agnostic), byte-for-byte matched its deliberately-fake fill pattern through both
      `randombytes_buf` and `crypto_auth::Key::generate()`. `randombytes.rs`'s module doc and the
      T-122-era stale "`std`-gated" doc comments in `crypto_sign.rs`/`scalar.rs` rewritten in the
      same pass. Not added as a `cargo test --no-default-features --features getrandom` CI step -
      unrelated pre-existing `proptest`/`Vec` strategies elsewhere need `alloc` regardless, matching
      why CI's own no_std check has only ever been build-only. Full `cargo test --workspace`
      (default features) unaffected, `clippy -D warnings` under default/`small-tables`/
      `--all-features`/`-p dstu-core --no-default-features --features getrandom`, `fmt --check`, and
      the build matrix (host + `thumbv7em-none-eabihf`, with/without the feature) all clean.
- [x] **T-124** `uacrypt` has no `sign`/`verify` CLI commands - found 2026-07-26, same audit as
      T-122/T-123. `dstu_core::crypto_sign` (T-48/D-46) exists only as a library API - confirmed via
      `grep` across `crates/uacrypt/src/lib.rs`'s command dispatch, no `sign`/`verify` arm anywhere.
      First surfaced as an explicit scoping note on T-120 (the doc-examples task documents this gap
      rather than closing it); this is the task that actually closes it. Scope: top-level
      `uacrypt sign --key ... --in ... --out ...` / `uacrypt verify --key ... --in ... --sig ...`,
      matching the plain-language, misuse-resistant shape of `encrypt`/`decrypt`/`hash` (not a
      hazmat-scoped tool like `kalyna-block`) - blocked on T-122 landing first, since there is
      currently no way to obtain a `SigningKey` through the public API to begin with. `--key` for
      `verify` is the 42-byte uncompressed `VerifyingKey` encoding; `SigningKey`'s own key file
      format is the project owner's call (raw 21-byte scalar vs. something else) once T-122 settles
      the generation shape. Three-category test coverage per `CLAUDE.md`: correctness (round-trip
      sign→verify), rejection (D-64 - tampered message, tampered signature, wrong key all fail
      verification, matching T-120's explicit "show the failure path too" requirement), misuse
      (D-65 - wrong-length key/signature file, missing `--in`).
      **DONE 2026-07-26, see `docs/DECISIONS.md` D-73.** Scope widened beyond the literal `sign`/
      `verify` text above - resolved by implementation, flagged for confirmation rather than a
      prior user decision (same posture D-72/D-66's own forks took): also added `sign-keygen`
      (generates a fresh signing key) and `sign-pubkey` (derives the matching verifying key), since
      `sign`/`verify` alone would have no CLI path to obtain key material at all - the exact class
      of gap T-115 already closed once for `encrypt`/`decrypt`/`keygen`. Not a `--type` flag on the
      existing `keygen` command - a flag picking between two incompatible key shapes (32-byte
      symmetric vs. 21-byte signing scalar) is exactly the knob D-47 avoids. Key file format:
      raw 21-byte private scalar (`sign-keygen`/`sign`'s `--key`) and raw 42-byte uncompressed `x ||
      y` (`sign-pubkey`'s `--out`, `verify`'s `--key`) - matching every other key/signature file in
      this project (all raw fixed-length, no envelope). `SigningKey::to_bytes()` added to
      `dstu-core` (`crypto_sign.rs`) to make this possible - `verifying_key().to_uncompressed_bytes()`
      already existed. `sign`/`verify` stream `--in` through Kupyna-256 in 8 KiB chunks
      (`hash_file_streamed`, matching `kupyna-digest`/`hash`'s own D-42 convention) then call
      `sign_digest`/`verify_digest` (T-113) rather than the whole-message `sign`/`verify`
      convenience wrappers - memory-bounded regardless of file size. `run()`'s four new match arms
      split into a `dispatch_sign_command` helper, same `clippy::pedantic` line-count reason
      D-71 already established for `dispatch_kalyna_mode`. 39 new tests (12 parse, 2 golden-path/
      cross-check correctness, 3 rejection - tampered message/signature/wrong key, D-64 - and the
      rest misuse - wrong-length key/signature file, a zero-scalar key that's the right length but
      not a valid private key, nonexistent `--in`, `--out` naming a directory, D-65 - plus dispatch
      and help-text tests), all green after fixing two test-setup bugs (not real code bugs): two
      misuse tests used `[0x11u8; 21]` as a "some signing key" fixture, which isn't actually a
      valid scalar (`d >= n`, since `n`'s top byte is `0x04`) - `SigningKey::from_bytes` correctly
      rejected it with `SignKeyInvalid` instead of the test's expected `Io`/directory error,
      caught immediately by running the tests rather than assumed passing. Fixed with a
      `small_signing_key` test helper (mirrors `dstu-core`'s own `small_scalar`). Verified: full
      `cargo test --workspace` (110/110 `uacrypt`, full `dstu-core` suite unaffected), `clippy -D
      warnings` under default/`small-tables`/`--all-features`, `fmt --check`, and the `dstu-core`
      build matrix (`--no-default-features`/`+alloc`/`--all-features`), all clean.
- [x] **T-118** **DONE 2026-07-26.** `uacrypt --version`/`-V` - found missing while preparing for
      T-19/T-119's GitHub release (user-requested: smoke-test advice from `advisor()` flagged this
      as the one defect "actively embarrassing in a release artifact" - a downloaded binary with no
      way to ask it what version it is). Prints `uacrypt <CARGO_PKG_VERSION>` and exits 0; checked
      only at the top level (`is_version_flag`, mirroring `is_help_flag`'s shape) since there is one
      binary, not a per-command version. `-V` matches `cargo -V`'s own short form. Added to
      `TOP_LEVEL_HELP`'s USAGE block. 2 new tests (dispatch succeeds for both spellings, a
      unit test pinning `is_version_flag`'s exact match set) - all green, plus manually run against
      the real release binary (`uacrypt --version`/`-V` both print `uacrypt 0.1.0`). No
      `docs/DECISIONS.md` entry - CLI ergonomics, same call T-108/T-115 made.
- [x] **T-121** **DONE 2026-07-26.** Expanded, retested binary-level performance comparison against
      UAPKI (`docs/PERFORMANCE.md` D-34's canonical methodology) - user-requested: broaden the existing
      four benchmark commands' file-size/variant coverage *and* add CLI exposure for the five DSTU
      7624 modes that had none at all (GCM, CMAC, KW, GMAC, XTS - all already implemented and
      dual-oracle-verified at `hazmat`, see `docs/dstu-crypto-project.md`'s API table), user's
      explicit choice over the narrower "just re-measure the existing four" option.
      **Five new `uacrypt` CLI commands** (`docs/DECISIONS.md` D-71, following D-31's precedent exactly -
      `hazmat`-scoped benchmarking/interop tools, not the safe top-level surface): `kalyna-gcm
      encrypt/decrypt`, `kalyna-cmac compute/verify`, `kalyna-gmac compute/verify`, `kalyna-kw
      wrap/unwrap`, `kalyna-xts encrypt/decrypt`. `kalyna-ccm` (pre-existing) also gained
      `--iterations` - it had none before, so its own per-op cost was previously unmeasurable
      through the binary at all. 17 new tests (round-trip against `hazmat` directly, D-64 tamper
      rejection wherever a tag/checksum exists, D-65 misuse coverage, dispatch smoke tests) - XTS has
      no rejection category by design (confidentiality-only mode, no tag - documented as a finding,
      not a gap, same pattern `CLAUDE.md` already establishes for other foreclosed categories).
      `run()`'s match arm split into a new `dispatch_kalyna_mode` helper to stay under
      `clippy::pedantic`'s line-count lint. Full workspace `fmt`/`clippy -D warnings`/
      `test --all-features` (81 `uacrypt` tests, up from 64)/`--no-default-features` build all clean.
      **UAPKI comparison**: `library/uapkic`'s prebuilt signed Windows DLL (`uapkic-v2.0.12`,
      `specinfo-ua/UAPKI` GitHub release) linked via a `gendef`/`dlltool`-generated import lib -
      faster and simpler than `docs/PERFORMANCE.md`'s documented CMake/`resource.rc` build-from-source
      path, skipped entirely this session. A one-off C wrapper (scratchpad-only, not committed, same
      convention as every other C comparison in this file) cross-checked byte-identical against the
      real `uacrypt` release binary before any timing run, for every mode except two, both found by
      reading UAPKI's own source, not assumed: **GMAC** disagrees with itself on multi-block input in
      one call (UAPKI's own `gmac_update`/`gmac_final` streaming path has a stale-index bug distinct
      from the coherent `encrypt_gmac` one-shot loop our `hazmat::kalyna_gmac` was ported from - this
      is `docs/DECISIONS.md` D-57's already-documented finding, re-confirmed empirically here, not a new
      bug) - worked around by benchmarking exactly one block, which sidesteps the buggy path cleanly;
      **CCM** turned out to use a different wire convention than ours (UAPKI's `cipher_data` output
      bundles an extra CTR-encrypted tag block onto the ciphertext rather than keeping tag separate,
      confirmed by reading `dstu7624_encrypt_ccm`/`decrypt_ccm` directly) - not a bug, just a
      different framing choice, so CCM's timing number is UAPKI-self-consistent (encrypt-then-decrypt
      round-trips through itself) rather than cross-tool-verified the way the other eight modes are.
      **New results in `docs/PERFORMANCE.md`'s "Binary-level (process) comparison" section**, dated
      2026-07-26: all 5 Kalyna variants (previously only 2) for block/CCM/GCM, new GCM/CMAC/GMAC/
      KW/XTS subsections, larger message sizes added to Kupyna/Strumok/CMAC/GCM (1 MiB, previously
      capped at 64 KB). Real finding, not assumed: **Kalyna-XTS on the 512-512 variant is this
      project's own implementation running 4-4.6x *slower* than UAPKI** (e.g. 4096 B: 492481 ns vs.
      107118 ns) - a much wider gap than any other variant/mode measured (most are within 2x either
      direction), flagged for follow-up, not root-caused in this session. This dev machine only
      (Ryzen 5 PRO 4650U) - the Raspberry Pi rig was out of scope for this pass, not re-run.
- [x] **T-125** **DONE 2026-07-26.** Investigate every mode/variant where this project runs more than 2x slower than
      UAPKI at the 1 MiB message size specifically - requested 2026-07-26, straight from T-121's own
      binary-level numbers (`docs/PERFORMANCE.md`, D-34 methodology, MB/s only). Scoped deliberately to
      the 1 MiB data points only (not the smaller 64 B/1 KB/64 KB/one-block/two-block points measured
      elsewhere in the same tables, several of which also show a >2x gap but at message sizes too
      small for per-call setup-cost noise to be ruled out as the cause - see T-121/D-71's own
      per-mode writeups for those). At 1 MiB, six cells across two modes cross the 2x line (computed
      from `docs/PERFORMANCE.md`'s actual published numbers, not re-measured here):
      - **Kalyna-GCM**: 256-256 (8.33 vs 18.12 MB/s, ~2.18x) and 256-512 (8.17 vs 17.48 MB/s, ~2.14x).
        128-128/128-256 stay under 2x (~1.19x/1.24x); 512-512 is not behind at all (this project
        actually leads, 5.41 vs 4.70).
      - **Kalyna-CMAC**: 128-128 (106.85 vs 235.47 MB/s, ~2.20x), 128-256 (77.19 vs 182.48 MB/s,
        ~2.36x), 256-256 (123.36 vs 265.00 MB/s, ~2.15x), 256-512 (97.26 vs 215.42 MB/s, ~2.22x).
        512-512 stays under 2x (~1.41x).
      - Kupyna-256/512 and Strumok-256/512's own 1 MiB points are all under 2x (~1.10-1.45x) - not in
        scope for this task, listed here only so a future pass doesn't re-derive the same negative
        result.
      **Pattern worth checking first, not yet confirmed as the actual cause**: every affected cell is
      a "256-*" key-size Kalyna variant for GCM and a "*-128"/"*-256" block-size variant for CMAC -
      512-512 is the one variant that stays under 2x in both modes. Whether this is the same
      per-byte-throughput bottleneck each mode's own `docs/PERFORMANCE.md` writeup already gestures at
      (GHASH-style field multiplication for GCM, `hazmat::kalyna_cmac`'s own per-round cost for CMAC)
      or something else entirely (table layout, codegen, cache behavior at the larger 1 MiB working
      set) is exactly what this task needs to determine - by profiling/reading the actual hot path,
      not guessing from the aggregate numbers alone, matching this project's own standing practice
      (`CLAUDE.md`: "read directly from the other implementation's source, not guessed at"). Kalyna-
      XTS's own 512-512 anomaly (~4.4-4.6x, flagged in T-121/D-71) is a related but *separate* finding
      - measured at 512 B/4096 B, not 1 MiB, so it's out of this task's literal scope even though it
      may turn out to share a root cause; cross-reference, don't silently fold the two together
      without confirming that first.

      **Partially resolved 2026-07-26, same day, user-requested follow-up with `advisor()` consulted
      twice (`docs/DECISIONS.md` D-76) - source reading plus arithmetic on already-published
      `docs/PERFORMANCE.md` numbers, no profiler used:**
      - **Kalyna-block's "rough parity with UAPKI" claim (the baseline this whole task measures
        against) is itself a measurement artifact, not a true round-function comparison.** UAPKI's
        `encrypt_ecb`/`decrypt_ecb` (`dstu7624.c:2916,2922`) does two heap allocations
        (`ba_to_uint64_with_alloc`, `ba_alloc_from_uint64`) plus one `free` per call - for a single
        16-64 byte block this dominates the measured time. Proof needs no new measurement: UAPKI's
        *own* CMAC-at-1-MiB throughput is 1.33-2.71x **faster** than UAPKI's *own* block-cached
        number for the same variant (e.g. 128-128: 235.47 vs 86.86 MB/s) - impossible for a
        construction built from chained calls to that same block cipher, unless the block number is
        artificially low. `cmac_update`/`cmac_final` do zero heap allocation (confirmed by reading
        the source), so CMAC's number is the clean one. Our own CMAC-at-1-MiB tracks our own
        block-cached number within ~1.5% on every variant (exactly what an allocation-free chain
        should do), confirming our block-level number was already clean and needs no correction.
        **Conclusion: the true core-round-function gap, with allocation removed on both sides, is
        larger than the block-level table suggested - UAPKI's round function is genuinely faster
        than ours by ~2.7x (128-128) down to ~1.3x (512-512, the one variant CMAC also shows as
        "under 2x").** This is a core Kalyna-cipher-level gap, not a mode-of-operation issue - see
        T-126's follow-up scope note below for why it isn't tackled as part of *this* task.
      - **Kalyna-GCM's non-monotonic 256-*/nb pattern stays genuinely open at this point.** Neither
        implementation uses a precomputed GHASH-style table (both do a real per-block multiply
        against the actual field element `H`, not a fixed sparse constant - a structurally different
        case from XTS's tweak-doubling, see T-126) - `advisor()` explicitly flagged the subagent's
        composite "two opposite trends compound at nb=4" narrative as unfalsifiable and directed
        cutting it from scope rather than writing an unproven mechanism into this file. **Root-caused
        with a real measurement later the same day** (see below) - not left open.
      - Two new, more actionable findings surfaced along the way, split into their own tasks since
        each has an independent, containable, safe fix: **T-126** (Kalyna-XTS's separate 512-512
        anomaly, now root-caused) and **T-127** (a real per-call key-schedule cost hiding in the
        `hazmat::kalyna_cmac`/`kalyna_gmac`/`kalyna_kw` API shape, not just this task's benchmark
        harness).

      **Fully resolved later the same day, user-requested continuation ("continue investigating
      where we still lag by a multiple"), `advisor()` consulted before and after implementing:**
      isolated timing (`hazmat::gf2m_wide::field_axiom_tests::isolated_timing_*`, comparing
      `Gf2m*::multiply` against a single `ExpandedKey::encrypt_block` in isolation) measured the
      field multiply at **89.6% (m=128), 91.8% (m=256), 94.3% (m=512) of GCM's per-block cost** -
      confirming with a real number, not an inference, that `poly_mul_wide`'s O(m²) bit-serial
      multiply was the bottleneck, not the block cipher (this is the `perf`-equivalent profiling
      this task's own text asked for). Fixed by replacing `poly_mul_wide` with a 4-bit-window comb
      method (`T[i] = a*i` precomputed for all 16 nibbles, walk the other operand's nibbles MSB-first
      - `m/4` accumulator iterations instead of `m`), verified against every existing GCM/GMAC/XTS
      official vector and the field-axiom property tests (a multiply-implementation swap needs no
      new correctness test - those already check exactly the property that would break). Measured
      ~1.8-2.3x faster on the multiply itself. **Re-measured GCM/GMAC binary throughput**: this
      project's own GCM improved ~1.7-2.3x across every variant; the 256-256/256-512 cells that
      triggered this task in the first place (>2x slower at 1 MiB) narrowed from ~2.14-2.18x to
      **~1.09-1.11x**, well under the 2x line; 128-128/128-256/512-512 flip from trailing/tied to
      clearly leading. GMAC (same field arithmetic) improved by the same mechanism, roughly doubling
      an already-large lead. Full numbers in `docs/PERFORMANCE.md`'s Kalyna-GCM/Kalyna-GMAC sections.
      **What remains genuinely open, stated as such**: why UAPKI specifically wins the mid-size
      (256-*) variants and loses at the extremes - a working hypothesis exists (UAPKI's own
      Karatsuba `gf2m_mul` pays 3 heap allocations per call, amortized differently across fewer,
      larger blocks at bigger `m`), but it was read from source, not measured - do not treat it as
      settled without independent confirmation. Full workspace `test --all-features` (every binary,
      0 failures)/`clippy -D warnings`/`fmt`/feature-matrix all clean throughout.
- [x] **T-126** **DONE 2026-07-26, fixed and re-measured, same session as T-125's follow-up.** `hazmat::gf2m_wide.rs` has no specialization
      for "multiply by the fixed generator `x`" (the constant literally named `two` in
      `kalyna_xts.rs`, e.g. line 100/113/134/161/170/182/193/195). Every tweak-doubling call -
      once per block, unavoidable in XTS's design - goes through the fully general
      `poly_mul_wide` (schoolbook shift-and-add, O(m²)) plus a bit-at-a-time `reduce`, when
      multiplying by `x` specifically is mathematically just a single left-shift of the whole
      element plus a conditional XOR of the reduction polynomial when the top bit was set - O(m/64)
      word ops (~16 for m=512) instead of O(m²) (~16,384 word-XORs for m=512, roughly 1000x more
      work than necessary). Cost scales as **O(m²) per multiply × O(1/m) multiplies per message ≈
      O(m) total waste per message** - worst at m=512 (the 512-512 variant), which is exactly the
      one variant that blows up; 128-128/256-256 pay proportionally far less of this tax. **Why this
      doesn't generalize to GCM's own field multiply** (T-125's still-open item above): XTS
      multiplies by a *fixed, sparse* constant (avoidable waste, unique to this specific call
      pattern), while GCM's Horner accumulation multiplies the running accumulator by `H`, a *dense,
      key-derived* operand - a genuinely general multiply in any implementation, nothing to
      specialize away. This asymmetry is what makes XTS containable and GCM not.
      **Fix**: add a `double()`/`mul_by_x` method to each `gf2m_field!` instantiation in
      `gf2m_wide.rs` (shift + conditional reduction-polynomial XOR), verified by a property test
      against the existing general `multiply(self, TWO)` before being wired into
      `kalyna_xts.rs`'s tweak update - must produce byte-identical output to the current path (this
      is a speed-only change to an internal helper, not a new field-arithmetic definition), so
      existing XTS official vectors and property tests are the correctness gate, not a new oracle.
      Does not touch `Gf2m128`/`Gf2m256`'s existing behavior at all.
      **Implemented and re-measured, same day**: `double()` added to each `gf2m_field!` instance
      (`crates/dstu-core/src/hazmat/gf2m_wide.rs`), verified byte-identical to `multiply(two)` by a
      new property test (`field_axiom_tests::double_matches_general_multiply_by_two`, all three
      field widths, plus an `ALL_ONES`-specific case for the carry-out-of-every-word edge), then
      `kalyna_xts.rs`'s tweak update switched to call it (the now-unused `$two` macro parameter
      removed from `kalyna_xts_variant!` and its 5 call sites). Full workspace test suite green
      (`cargo test --workspace --all-features`, every test binary 0 failures, including all 12
      `kalyna_xts` tests/vectors and the new `gf2m_wide` property tests), `clippy -D warnings`/`fmt`
      clean, `--no-default-features`/`--features alloc`/`--features small-tables` all build clean.
      **Re-measured at the exact 512 B/4096 B scale T-121 originally flagged**: 512-512 XTS goes
      from ~4.4-4.6x *slower* than UAPKI to **~2.4-2.5x faster** (97.92/104.19 vs. 39.27/43.97 MB/s,
      UAPKI's own numbers essentially unchanged); every other variant improved substantially too
      (this waste existed at every field width, not just m=512 - full numbers in `docs/PERFORMANCE.md`'s
      Kalyna-XTS section and its new "10 MiB re-measurement pass" subsection).
- [x] **T-127** **DONE 2026-07-26.** `hazmat::kalyna_cmac`/`kalyna_gmac`/`kalyna_kw`'s one-shot `mac`/`wrap`/`unwrap`
      functions re-expand the full Kalyna key schedule on every call - found 2026-07-26, same
      session as T-125's follow-up, `advisor()`-directed.** Confirmed by reading the source:
      `kalyna_cmac.rs:52` (`let cipher = super::kalyna::$expanded::new(key);` inside `mac`) and
      `kalyna_kw.rs:95` (same pattern inside `wrap`) both take raw `&[u8; N]` key bytes and build a
      fresh `ExpandedKey` internally every call - unlike `kalyna-block`/`kalyna-gcm`/`kalyna-xts`,
      which accept an already-expanded cipher object built once by the caller. This is not just a
      benchmark-harness quirk (though it is also that - `uacrypt`'s own `run_cmac_command`/
      `run_gmac_command`/`run_kw_command` `--iterations` loops call `mac()`/`wrap()`/`unwrap()` fresh
      every iteration, so they measure schedule-redone-every-call whether or not that's what the
      caller intended): **any real caller MACing or wrapping more than one message under the same
      key today pays a full key-schedule expansion per call**, with no way to avoid it at the
      current API surface. For CMAC's own 1-MiB benchmark this cost is amortized to near-nothing
      (tens of thousands of block-cipher calls per call, confirmed by T-125's finding that our
      CMAC-at-1-MiB tracks our own block-cached number within ~1.5%) - but for KW (2-20 block input,
      only ~30-240 block-cipher calls total per call) and GMAC (T-121 measured it at exactly one
      block) this cost is *not* amortized and is a plausible, previously-unexplained cause of KW's
      long-standing "we have zero heap allocations yet UAPKI still wins by 1.8-2.7x" result
      (`docs/PERFORMANCE.md`, "not root-caused" as of T-121/D-71). **Caveat, stated plainly**: confirmed
      only on our side - the UAPKI C benchmark wrapper isn't committed to this repo (per
      `docs/PERFORMANCE.md`'s "Reproducing" sections), so whether *its* KW/CMAC/GMAC wrapper caches its
      own schedule is inferred from `docs/PERFORMANCE.md`'s documented benchmarking convention, not
      independently verified.
      **Fix**: add `ExpandedKey`-accepting variants of `mac`/`wrap`/`unwrap` (mirroring the pattern
      `kalyna-block`/`gcm`/`xts` already use), with the existing raw-key-bytes functions becoming
      thin wrappers over them for source compatibility - a pure API addition/refactor, not a change
      to any construction's logic, so existing tests are the correctness gate. Update `uacrypt`'s
      three benchmark loops to use the cached-schedule entry point, matching the convention
      `docs/PERFORMANCE.md`'s "Methodology" section already documents for every other mode.
      **Implemented and re-measured, same day**: added `mac_with_cipher`/`verify_with_cipher` to
      `kalyna_cmac.rs`/`kalyna_gmac.rs` and `wrap_with_cipher`/`unwrap_with_cipher` to `kalyna_kw.rs`
      (existing `mac`/`verify`/`wrap`/`unwrap` now thin wrappers that build the `ExpandedKey` once
      and delegate); `uacrypt`'s `run_cmac_command`/`run_gmac_command`/`run_kw_command` benchmark
      loops rewired to build the cipher once outside `--iterations`. The "confirmed only on our
      side" caveat above is resolved for KW: read UAPKI's own `bench.c`'s `cmd_kw` directly and
      confirmed `dstu7624_init_kw` is called once, outside its own iteration loop - the asymmetry
      was real, not just inferred. Full workspace test suite green (every binary 0 failures),
      `clippy -D warnings`/`fmt` clean (two `clippy::doc_markdown` hits on "MACing" fixed per
      `CLAUDE.md`'s own named gotcha for this lint, one `clippy::cast_sign_loss` hit in the same
      session's `gf2m_wide.rs` change fixed by type-annotating the reduction-term array as `u32`).
      **Re-measured, same 2-block-key-material KW scale UAPKI's harness already used**: this
      project's own KW throughput improved 14-31% across all five variants purely from removing the
      redundant per-call schedule expansion (UAPKI's numbers unchanged, as expected), narrowing its
      lead from ~1.8-2.7x to ~1.4-2.2x without eliminating it - the residual matches D-76's
      core-round-function-gap finding, not a further KW-specific cause. CMAC's own numbers are
      unchanged at the 1-MiB scale already published, exactly as predicted (the schedule cost was
      already amortized to nothing there) - full numbers in `docs/PERFORMANCE.md`'s Kalyna-KW section.
- [x] **T-128** **DONE 2026-07-26.** `hazmat::kalyna.rs`'s `encipher_round`/`fused_inv_round` take
      `nb: usize` as a runtime parameter even though every real call site (`kalyna_variant!`'s five
      variant invocations) supplies a compile-time-known literal (2, 4, or 8) - user-requested,
      prompted by comparing this project's fused round functions directly against UAPKI's
      `p_boxrowcol`/`BT_xor128`/`BT_xor256`/`BT_xor512` macros (which are separately compiled per
      block size, no runtime branch at all). `advisor()` corrected the initial framing before any
      code was written: the five variants collapse to **three** block sizes (`nb=2`:
      Kalyna128_128/Kalyna128_256, `nb=4`: Kalyna256_256/Kalyna256_512, `nb=8`: Kalyna512_512) -
      `nk`/`nr` never reach the round function, so "5 hand-unrolled implementations" would have been
      two verbatim duplicate pairs, zero extra speed, two more places for encrypt/decrypt to
      silently diverge. The runtime `nb` causes three compounding costs simultaneously: the
      interior loop can't be unrolled by the compiler, every `state[..]` access is bounds-checked
      (a slice, not a fixed-size array), and the intermediate `result: [ZERO_COLUMN; MAX_NB]`
      buffer is always allocated/zeroed at the full 8-column width even for the most common
      `nb=2` variant (4x wasted zeroing).
      **Fix (`advisor()`-directed, "measure the cheap version before hand-unrolling")**: added
      `encipher_round_n<const NB: usize>`/`fused_inv_round_n<const NB: usize>` alongside the
      existing runtime-`nb` versions (kept, `#[allow(dead_code)]`, as the differential-test
      reference and for the rare key-schedule call sites that don't need this - `round_key_from`/
      `key_expand_kt` still use the original runtime-`nb` functions, since key expansion runs once
      per `ExpandedKey`/`encrypt_generic` call, not once per round). `encrypt_with_schedule`/
      `decrypt_with_schedule`/`encrypt_generic`/`decrypt_generic` became `<const NB: usize>` generic
      (one monomorphized instantiation per block size, matching UAPKI's per-size macro structure);
      `kalyna_variant!`'s call sites pass `$nb` via turbofish. A new `state_array_mut::<NB>` helper
      narrows the `[Column; MAX_NB]` scratch buffer's live prefix into `&mut [Column; NB]` via
      `TryFrom`, using `unreachable!` instead of `.unwrap()`/`.expect()` only because `lib.rs` denies
      both lints crate-wide (the conversion never actually fails - `NB <= MAX_NB` always holds by
      construction).
      **Safety net (`advisor()`-specified, all done before committing)**: a new `const_round_tests`
      proptest module checks `encipher_round`/`fused_inv_round` (old, runtime-`nb`) against
      `encipher_round_n`/`fused_inv_round_n` (new, const-generic) over random state, for all three
      `NB` values and both directions (6 tests) - this is the test that would catch a transposed
      gather index or off-by-one in the rewrite, distinct from the pre-existing `fused_round_tests`/
      `decrypt_fusion_tests` (which check the *algorithm*, not this refactor, against a from-scratch
      naive reference). Full workspace `cargo test --workspace --all-features` green (every binary),
      `clippy --workspace --all-features -- -D warnings`/`fmt --all -- --check` clean, and
      `--no-default-features`/`--features alloc`/`--features small-tables`/`--features pwhash` all
      build individually clean. The full 10-target `cargo xtask fuzz` smoke suite (via the Windows
      MSVC toolchain, `xtask`'s own `fuzz_windows_msvc`) ran clean, 0 crashes. **Scoped Miri on
      `hazmat::kalyna` did not complete this session - three different invocations all failed on
      the same Miri+proptest+Windows tooling interaction, not on anything in this change, split out
      to its own task, T-130, rather than blocking this commit on it** (user's explicit direction,
      given every other safety-net layer - differential tests, full workspace suite, clippy/fmt,
      feature matrix, fuzz - passed clean, and CI's own Miri job has never once passed anyway,
      T-100): (1) default isolation aborts on `GetCurrentDirectoryW not available` - proptest's
      failure-persistence file logic calls `std::env::current_dir()`; (2)
      `MIRIFLAGS=-Zmiri-disable-isolation` (the error message's own suggested fix) appeared to hang -
      ~35 minutes wall time with only ~0.8s of CPU actually accumulated on the `miri.exe` process
      (checked via `Get-Process -Id <pid> | Select CPU`, the diagnostic `docs/DECISIONS.md` already
      documents for telling "slow interpretation" from "genuinely stuck" - this was the latter, not
      the former, so it was killed rather than waited out further); (3)
      `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` with default isolation hit the *same* `current_dir()`
      error - Miri's default isolation evidently blocks environment-variable visibility from inside
      the interpreted program too, so proptest's own env-var-driven opt-out never took effect.
      **This does not weaken the change's own verification** - the 6 new differential-test proptest
      functions (`const_round_tests`) ran and passed under the normal (non-Miri) `cargo test`, along
      with every other correctness/regression gate; what's missing is Miri's specific UB-detection
      layer, not correctness confirmation.
      **Constant-time**: unaffected - same table lookups (`forward_sbox_mds`/`inverse_sbox_mds`),
      same D-19 exception, no new secret-dependent branch introduced; const-generic specialization
      only changes what the compiler knows about loop trip counts and buffer sizes, not what data
      drives any branch or index.
      **Measured** (`cargo bench -p dstu-core --bench kalyna -- --baseline pre-unroll-2026-07-26`,
      criterion, D-34's "internal regression tracking only, never a cross-implementation claim"
      caveat applies): block-only (cached-schedule, isolates the round function from key-expansion
      cost) time dropped **~51-54% at `nb=2`, ~19-41% at `nb=4`, ~15-22% at `nb=8`** - see
      `docs/PERFORMANCE.md`'s "Regression baseline" section for the full per-variant table. Full-call
      (`encrypt_generic`/`decrypt_generic`, key-expansion-dominated per the `kalyna_variant!` doc
      comment's own "~60-79% of single-call time is key schedule" note) improved by a much smaller,
      sometimes-noisy 0-12%, exactly as expected since key expansion still uses the unchanged
      runtime-`nb` round functions. **Binary-level (`uacrypt` vs UAPKI process comparison, D-34's
      canonical cross-implementation method) was not re-measured this session** - the UAPKI
      comparison wrapper isn't committed (rebuilt fresh each session per `docs/PERFORMANCE.md`'s
      "Reproducing" section) and wasn't rebuilt here; the criterion numbers above are a same-machine,
      same-binary before/after comparison only, not a new claim against UAPKI's own speed.
      **What this does not fix, split out to T-129**: the round function still gathers state
      byte-at-a-time (`state[src_col][row]`, recomputing `src_col`/`shift` every iteration) where
      UAPKI's `p_boxrowcol`+`BT_xor*` macros operate on whole 64-bit words - a structurally different,
      more invasive change not attempted here.
- [x] **T-129** **Investigated and closed 2026-07-27, no code change - see `docs/DECISIONS.md` D-88.**
      Written rationale was: `encipher_round_n`/`fused_inv_round_n` gather state one byte at a time
      via `state[src_col][row]`, recomputing `src_col` fresh every iteration, versus UAPKI's
      `p_boxrowcol`/`BT_xor128`/`BT_xor256`/`BT_xor512` loading/XOR-ing whole 64-bit words. **That
      premise was checked against the actual `--emit=asm` output before any plan-mode pass, per
      `advisor()`'s redirect (the same "test before you plan the rewrite" lesson T-139/D-87 already
      established for Strumok) - and found partly false**, the same way D-87 found for Strumok: at
      `NB=8` (the const-generic monomorphization examined), the compiled `encipher_round_n::<8>` is
      64 direct single-byte loads at **literal, compile-time-folded offsets** (no `src_col`
      recomputation survives - `NB` being const already eliminated it, same as T-128's own fix),
      **zero bounds-check branches** (each index is `u8`-derived, statically provable in
      `0..256`), and 8 interleaved XOR-accumulator chains for instruction-level parallelism across
      output columns - already a well-optimized, not naive, byte-wise gather. **A concrete "word-wide
      gather" spike was implemented and measured, not just reasoned about**: hoisting
      `let words: [u64; NB] = core::array::from_fn(|c| u64::from_le_bytes(state[c]));` once per
      round and reading `((words[src_col] >> (row * 8)) & 0xff) as u8` in place of
      `state[src_col][row]`. Result, compared byte-for-byte against the baseline `.s`: **`NB=2` -
      no change at all** (identical instruction count/shape - LLVM already promotes the two column
      words to registers and extracts bytes via register-resident shifts, confirmed by inspecting
      `encrypt_with_schedule::<2>`'s inlined body, which already used `movzbl %r11b, %r11d`-style
      register-to-register extraction, not memory reloads, even before the spike). **`NB=8` - a
      measurable regression**: the clean 64-load/0-spill baseline became 0 direct-memory byte loads
      but **34 new spill stores and 71 total stack references** (vs. 34 in the baseline, a ~2x
      increase in memory traffic) - holding 8 live 64-bit words simultaneously (on top of 8 output
      accumulators and round-key temporaries) exceeds the ~14-16 available GPRs, exactly the
      register-pressure failure mode `advisor()` predicted before the spike was run. **`NB=4` - the
      spike changed LLVM's inlining decision**: `encipher_round_n::<4>` stopped being inlined into
      `encrypt_with_schedule::<4>`'s round loop and became a real `callq`, introducing call overhead
      into what is currently a fully-inlined hot loop - a regression in kind, even though its exact
      magnitude wasn't separately measured. **No code change shipped** - three-for-three
      no-help-or-regression is a decisive result, not an inconclusive one; per `advisor()`'s framing
      for the analogous T-139 case, "the hypothesis was wrong" is the complete, valuable outcome
      here. `criterion` was deliberately not used to validate this (the session's own noise floor
      was ±5-9% at the time, per D-87 - unmeasurable at the 5-15% scale this change would plausibly
      have moved things, so asm/spill-count evidence is the basis for this conclusion, stated
      explicitly rather than dressed up with a noisy benchmark number). `hazmat::kalyna.rs` is
      unchanged - confirmed via `git diff` showing no delta, plus the existing `const_round_tests`/
      `fused_round_tests`/`decrypt_fusion_tests` (13/13) and `cargo fmt --all -- --check` passing
      clean. **This closes the entire Tier C perf/hygiene roadmap** (see the roadmap section
      below) - T-128/T-134/T-135 shipped real wins, T-136's asymmetry and T-129's gather both ended
      as investigated-and-explained rather than rewritten, which is a legitimate way for a
      perf-investigation roadmap to end, not a shortfall against it.
- [x] **T-130** **Resolved 2026-07-26, see `docs/DECISIONS.md` D-81.** Local `cargo +nightly miri test`
      on `hazmat::kalyna` failing/hanging on Windows, distinct from T-100's already-diagnosed cause
      (T-100 is CI's 30-minute timeout on the slow DSTU-4145 proptest suite; this was a
      Windows-specific Miri/proptest interaction blocking the run from completing at all). Found
      2026-07-26 investigating T-128: three attempts, all failed the same way (full detail in
      `docs/DECISIONS.md` D-77's Miri bullet) - (1) default isolation aborts because proptest's
      failure-persistence file logic calls `std::env::current_dir()`, which Miri's isolation blocks
      (`GetCurrentDirectoryW not available when isolation is enabled`); (2) the error's own
      suggested fix, `MIRIFLAGS=-Zmiri-disable-isolation`, appeared to hang instead of completing -
      ~35 minutes wall time against ~0.8s of actual CPU time on the `miri.exe` process, confirmed
      via `Get-Process -Id <pid> | Select CPU` rather than assumed, then killed; (3)
      `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` under default isolation (attempting to route around
      the file-persistence code path entirely rather than disabling isolation) hit the identical
      `current_dir()` error - implying Miri's default isolation hides environment variables from
      the interpreted program too, so proptest's own env-var-driven opt-out silently never took
      effect. **Attempt four (2026-07-26, `docs/DECISIONS.md` D-81)**: confirmed first, not assumed,
      that the hang is proptest-mechanism-wide, not Kalyna-specific - a single fast `hazmat::kupyna`
      proptest function under default isolation (no flags) hit the identical `current_dir()` abort.
      Then ran the one untried combination named above - `-Zmiri-disable-isolation` *and*
      `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` together, plus `PROPTEST_CASES=8` (D-63's precedent)
      - against both the Kupyna function and `hazmat::kalyna`'s own
      `fused_encipher_round_matches_naive_nb2`: **both completed cleanly in ~28-29s**, not stuck.
      Attempt 2's "~0.8s CPU in 35 min" read as stuck is now understood to have been genuinely slow,
      not deadlocked - a fresh disable-isolation run's `miri.exe` PID showed real CPU accumulating
      within the first 30s once checked properly this session. **Practical fix for future runs on
      this host**: set both env vars, keep `PROPTEST_CASES` low. **Full-`hazmat::kalyna`-module
      confirmation, same session**: all 13 existing proptest functions across
      `fused_round_tests`/`const_round_tests`/`decrypt_fusion_tests` passed under Miri with this
      combination - 13/13, 0 UB, 511.16s (~8.5 min) - see `docs/DECISIONS.md` D-81's follow-up. This is
      the Miri done-bar Tier C's own tasks (T-129/T-134/T-135) require, now actually achievable on
      this host. Does not block correctness work - the differential/property tests this would check
      layer is unavailable for this module until this is resolved.
- [x] **T-131** **DONE 2026-07-26.** **Policy made 2026-07-26, user-requested**: 10 MiB is now a mandatory
      message size for every binary-level (process) comparison table in `docs/PERFORMANCE.md`, not an
      ad hoc addition (`docs/PERFORMANCE.md`'s "Methodology" section has the durable policy text) - every
      variable-length-message mode's table must carry a 10 MiB row/column going forward. Exempt,
      matching the pre-existing "10 MiB re-measurement pass" section's own list: `kalyna-block`
      (single block, no variable-length mode), `kalyna-kw` (`MAX_R = 20` blocks, D-55 - key
      material, not a message), `kalyna-gmac` (one-block-only measurement, D-57's UAPKI streaming-
      bug workaround - an oracle limitation, not this project's own), `kalyna-ccm` (255-byte
      `MAX_PLAINTEXT_LEN` cap). **CMAC is not exempt** - it takes an arbitrary-length message like
      GCM/XTS and already has a published 10 MiB row. **Second policy, same day, also
      user-requested**: both directions are now standard too, not just the forward one - every
      table must measure `decrypt` alongside `encrypt`, `verify` alongside `compute`, `unwrap`
      alongside `wrap`, not whichever direction happened to be measured first (Strumok is exempt -
      `apply_keystream` is its own inverse; Kupyna has no inverse direction, being a hash).
      **This task is the deferred, expensive half**: a
      fresh UAPKI comparison-CLI wrapper rebuild (`gendef`/`dlltool` off the prebuilt `uapkic.dll`
      per T-121/D-71, or from-source CMake) plus per-mode wrapper code matching each mode's own
      quirks already documented (GMAC's one-block workaround for its streaming-path bug, D-57;
      CCM's different wire convention from D-71) - not committed to this repo per
      `docs/PERFORMANCE.md`'s "Reproducing" section, rebuilt fresh each time it's needed. **The
      `uacrypt`-only half is now fully done, same day**: all 7 Kalyna modes (block/CCM/GCM/CMAC/
      GMAC/KW/XTS) re-measured post-T-128, both directions each, at their policy-mandated sizes -
      see each mode's own `docs/PERFORMANCE.md` section for the numbers. What's left for this task is
      exactly the UAPKI-side rebuild and re-comparison, nothing more - `advisor()`'s explicit
      direction was not to publish a half-rebuilt UAPKI comparison next to fresh `uacrypt`-only
      numbers, so this stays a separate task rather than being folded into the sweep already done.
      **CMAC and XTS done, same day (`docs/DECISIONS.md` D-78)**: downloaded the signed
      `uapki-v2.0.12-win-amd64-signed.zip` release asset, `gendef`/`dlltool` to build an import lib
      against the prebuilt `uapkic.dll`, wrote a small C wrapper (`uapki_bench.exe`, scratch-only,
      not committed) calling `dstu7624_init_cmac`/`update_mac`/`final_mac` and
      `dstu7624_init_xts`/`encrypt`/`decrypt` directly, matching `uacrypt`'s own file-based
      `--variant`/`--key`/`--in`/`--out`/`--tag`/`--tweak`/`--iterations` CLI shape. Byte-for-byte
      cross-checked against the real `uacrypt` binary first (all 5 variants, both directions each -
      15 identity checks, all matched) before trusting any timing - this doubles as T-133's first
      concrete instance, not a separate effort. **`docs/PERFORMANCE.md`'s CMAC/XTS 10 MiB tables now
      carry a real UAPKI column**: CMAC - UAPKI still wins by ~1.1-1.9x (originally attributed to
      T-129's byte-wise-gather-vs-`BT_xor*` difference; T-129 itself was later investigated and
      closed 2026-07-27 without a code change, `docs/DECISIONS.md` D-88 - a measured spike showed the
      gather is already near-optimal or a regression to "fix," so this residual is not the
      straightforward fixable gap it was originally framed as). XTS - this project now leads UAPKI by a much
      wider margin than any other mode in this file (3.2-15.1x), root-caused by reading
      `dstu7624.c` directly: UAPKI's `encrypt_xts`/`decrypt_xts` call the fully generic `gf2m_mul`
      (three heap-allocated `WordArray`s, full O(m²) modular multiply) to do the tweak's
      "multiply by 2" every block, where this project's `Gf2m*::double()` (T-126/D-76) is an O(m),
      allocation-free shift-and-reduce - not a bug on UAPKI's side, just an unspecialized shared
      code path. **Remaining scope closed, same day (`docs/DECISIONS.md` D-80)**: extended
      `uapki_bench.exe` to block (ECB), GCM, GMAC, KW, and CCM. Block/GCM/GMAC/KW byte-for-byte
      cross-checked against `uacrypt` (both directions, all 5 variants each - 40 identity checks,
      all matched); CCM confirmed still not byte-comparable (same D-71 wire-convention finding,
      now root-caused directly from `dstu7624_encrypt_ccm`/`_decrypt_ccm`'s source rather than
      cited secondhand), kept self-consistent-only (5 own-round-trip checks, all passed). All 9
      Kalyna modes/primitives this project publishes now have a real, same-session, byte-verified
      UAPKI column except CCM (by design, wire-format mismatch) - T-131 is complete. **A real
      timing-methodology bug was found and fixed while extending to GMAC**: the wrapper's
      `run_gmac` (copied from `run_cmac`'s original structure) timed `dstu7624_alloc`/
      `dstu7624_init_gmac` inside the same window as the actual MAC computation, while `uacrypt`'s
      own GMAC command excludes schedule setup the same way every other mode does - for a
      one-block message this inflated UAPKI's apparent cost enough that the project's
      long-published "~4-24x uacrypt lead" GMAC conclusion was substantially an artifact of this
      asymmetry, not a real property of GMAC. Fixed (timer moved to after `init_gmac`); the real
      gap is **~1.1-2.9x**, not ~4-24x. CMAC was checked against the identical bug and found not
      materially affected (10 MiB bulk work dwarfs per-call setup cost the way one block cannot) -
      see `docs/PERFORMANCE.md`'s GMAC section for the full before/after. **Follow-up flagged, not
      chased here**: historical small-message CMAC (64 B) and CCM numbers, measured by an earlier
      uncommitted wrapper this session never inherited, could carry the same class of bug -
      tracked as T-138.
      **A real, unexplained finding surfaced doing the `uacrypt`-only half**: Kalyna-block/XTS/KW's
      decrypt/unwrap direction is *not* symmetric with encrypt/wrap the way GCM/CMAC/CCM's is - on
      some variants (256-256/256-512) the reverse direction now runs *faster*, not just similarly.
      Consistent with `encipher_round_n`/`fused_inv_round_n` (T-128/D-77) being genuinely different
      code paths that were never guaranteed to gain identically, but not root-caused further than
      that here - see each mode's own section for the actual numbers, not smoothed into a symmetric
      claim that isn't true.
- [x] **T-132** **DONE 2026-07-26.** Memory-requirements audit, user-requested, for both resource
      profiles (`fused`/`small-tables`) - `docs/resource-profiles.md` already covered flash/const-
      table footprint (D-35/D-38/D-39) but nothing about per-mode RAM/stack cost, a different axis
      the user specifically asked to fill in. Added a new "RAM/stack: what each mode costs beyond
      the table data above" section to `docs/resource-profiles.md`, computed from the actual struct/
      array definitions in the current tree (not profiled - stated as a weaker claim than the
      existing table's "measured directly"). **Key findings, none previously documented**: (1)
      `hazmat::kalyna.rs`'s `RoundKeys` (`[[Column; MAX_NB]; ROUND_KEYS_LEN]`) is 1216 bytes
      *regardless of variant* - a Kalyna128_128 caller pays the same footprint a Kalyna512_512
      caller does; `ExpandedKey` holds two (2432 bytes) - the same `MAX_NB`-oversizing pattern
      T-128 just fixed on the *compute* side, still present on the *storage* side, not fixed here
      (out of scope, noted only). (2) T-125's 4-bit comb multiply (`gf2m_wide.rs`) builds a
      transient 16-entry double-width table on the stack *per multiply call* - 512/1024/2048 bytes
      at m=128/256/512 respectively (verified against the actual `$limbs2` literals in
      `gf2m_field!`'s three instantiations, not derived from D-76's prose description) - a genuinely
      new stack cost since `resource-profiles.md` was first written, applying to GCM/GMAC and, by
      extension, `crypto_secretbox`/`crypto_secretstream` (both built on `Kalyna256_256Gcm`).
      Kalyna-XTS is the contrasting case: T-126's `double()` needs no such table, negligible stack
      cost regardless of variant. (3) `crypto_secretstream`'s `PushState`/`PullState` hold only a
      32-byte subkey (not a cached `ExpandedKey`), the smallest persistent state of any construction
      here, at the cost of re-expanding the full schedule every chunk rather than once per stream -
      a deliberate space/time trade, noted as a fact relevant to "how much RAM," not proposed as a
      change. **Confirmed and stated explicitly**: none of this differs between `fused` and
      `small-tables` - the profile split only swaps which table data is linked in, not any struct
      layout or working-set size, so a single RAM/stack table applies to both profiles (only the
      pre-existing flash/const-table row actually varies by profile).
- [x] **T-133** **Done 2026-07-26, see `docs/DECISIONS.md` D-83.** User-proposed additional verification layer, 2026-07-26: after a
      performance run, byte-for-byte-compare the actual ciphertext/tag files this project's
      `uacrypt` produced against UAPKI's own output for the same key/nonce-or-tweak/input, in every
      mode where both sides are deterministic given identical inputs - a stronger check than "both
      independently decrypt correctly," since it confirms the two implementations compute the
      *exact same* intermediate bytes, not just externally-compatible ones. **Correct and already
      practiced informally, just never as its own named/systematic step**: `docs/TASKS.md` T-34 and
      T-121 both already record "cross-checked byte-identical against UAPKI before timing" as a
      one-off pre-benchmark sanity check, for Kalyna-block/CCM/GCM/CMAC/GMAC/KW/XTS/Kupyna/Strumok -
      this task is to make that an explicit, repeatable verification step (e.g. a small script or
      documented procedure diffing output files) rather than an incidental habit buried in benchmark
      session notes, closer to `docs/ORACLES.md`'s "dual-oracle verification is mandatory" standing for
      test vectors. **Scope, precisely** - only valid where both sides are deterministic for the
      same inputs: the caller-supplied-nonce/tweak `uacrypt` benchmarking commands
      (`kalyna-gcm`/`kalyna-ccm`/`kalyna-xts`/`kalyna-cmac`/`kalyna-kw`, which take an explicit
      `--nonce`/`--tweak` rather than generating one internally, D-31/D-71) - **not** the safe
      top-level `encrypt`/`decrypt` (nonce/header generated internally per D-40/D-63/D-68, so two
      runs never produce the same ciphertext even under the same key+plaintext, by design, not a
      bug to chase here). **Two known, already-documented exceptions where byte-for-byte comparison
      will *not* match, and must not be read as a new bug if it doesn't**: `kalyna-gmac` (UAPKI's
      own multi-block streaming path has a stale-index bug distinct from the one-shot path, D-57 -
      already why GMAC is measured at exactly one block in every timing table) and `kalyna-ccm`
      (UAPKI's `cipher_data` bundles an extra CTR-encrypted tag block into the ciphertext rather
      than keeping tag separate, a different wire convention entirely, D-71 - CCM's timing numbers
      are already flagged "UAPKI-self-consistent, not cross-tool-verified" for this exact reason).
      Depends on the same UAPKI comparison-CLI wrapper T-131 needs - natural to build alongside that
      task rather than as a fully separate rebuild. **First concrete instance done 2026-07-26, as
      part of T-131's CMAC/XTS wrapper work (`docs/DECISIONS.md` D-78)**: byte-for-byte diffed
      `uacrypt`'s and the new UAPKI wrapper's CMAC tags and XTS ciphertext (all 5 variants, both
      directions) before any timing was trusted - all 15 pairs matched exactly. **Extended
      same day (`docs/DECISIONS.md` D-80) to block/GCM/GMAC/KW** - 40 more identity checks (both
      directions, all 5 variants each), all matched; CCM confirmed genuinely not comparable
      (D-71's wire-convention finding, root-caused directly this time) and kept self-consistent-only
      instead (5 own-round-trip checks). 100 total identity/consistency checks across all 9 Kalyna
      modes this project publishes, done in one session. Formalized as reusable shell sweeps
      (`uapki_compare.sh`/`uapki_compare2.sh`/`uapki_compare3.sh`, scratch-only), not committed.
      **Done 2026-07-26, see `docs/DECISIONS.md` D-83**: the "formalize into a committed, reusable
      script" half of this task conflicted with `docs/PERFORMANCE.md`'s own documented "C comparisons
      aren't committed" methodology policy - put to the project owner directly rather than decided
      unilaterally (`AskUserQuestion`). **Answer: commit it.** `tests/oracle-harness/
      uapki-cmac-bench/cmac_bench.c` is now committed (CMAC only, the mode this session's T-138
      work already needed) - source only, matching this repo's existing `tests/oracle-harness/*`
      convention, with a full doc-comment header (build recipe, usage, and D-82's CMAC-reuse-quirk
      finding inline so it isn't re-discovered later). Rebuilt from the committed copy and
      re-verified byte-identical against `uacrypt` before calling this done. **Scope deliberately
      narrow**: only CMAC, not all 9 modes - the other 8 stay scratch-only until one of them starts
      recurring the same way. `docs/PERFORMANCE.md`'s methodology text updated to describe this as a
      named exception, not a blanket reversal.
- [x] **T-134** **Done 2026-07-27, see `docs/DECISIONS.md` D-85.** `hazmat::kupyna.rs`'s `sub_shift_mix` (line 65) has the exact same
      shape T-128 just fixed in `hazmat::kalyna.rs`'s `encipher_round` - found 2026-07-26, checking
      whether Strumok/Kupyna share the same nuance T-128 fixed for Kalyna (they don't both: Strumok
      is unaffected, see below). `let columns = state.len()` reads a runtime `usize` even though
      only two values are ever real (Kupyna256 always constructs with `columns=8`, Kupyna512 always
      `columns=16` - `kupyna.rs:362,394`, no per-call variance the way Kalyna's `nb` at least varies
      per invocation site); the intermediate `result: [[0u8; ROWS]; MAX_COLUMNS]` buffer is always
      the full 16-column width regardless of the real `columns`, 2x wasted zeroing for Kupyna256 (the
      exact `MAX_NB`-oversizing pattern, here `MAX_COLUMNS`-oversizing); `state[..columns]` bounds-
      checks on every access. `sub_shift_mix` is Kupyna's single hottest function - called once per
      round inside `t_transform`/`t_plus_transform` (10 rounds for Kupyna-256, 14 for Kupyna-512),
      and `compress` (the per-block compression step) calls both once per block - directly
      analogous to `encipher_round`'s role in Kalyna. **Expected shape of the fix, by direct
      analogy to T-128/D-77** (not yet consulted with `advisor()` - do that before writing any
      code, same as T-128's own process): a `sub_shift_mix_n<const COLUMNS: usize>` alongside the
      retained runtime-`columns` version (kept for the `#[allow(dead_code)]` differential-test
      reference, matching `encipher_round`'s treatment), with `t_transform`/`t_plus_transform`/
      `compress`/`KupynaCore` becoming const-generic over `COLUMNS`, a new differential-test module
      checking old-vs-new for both `COLUMNS` values (8 and 16), full workspace test/clippy/fmt/
      feature-matrix pass, and a `criterion` before/after baseline (`benches/kupyna.rs` already
      exists per the "Regression baseline" section's `kalyna-kupyna-fused-2026-07-22` entry).
      **Predicted (not measured) direction**: Kupyna256 (8 of 16 columns, the "half-width" case)
      should see gains in the range T-128 measured for Kalyna's `nb=2`/`nb=4` (~20-55%); Kupyna512
      (already 16/16 columns, "full-width" already) should see smaller but still real gains in the
      range T-128 measured for Kalyna's `nb=8` (~15-22%, since even the already-full-width case
      benefited there from bounds-check elimination and loop unrolling, not just buffer reuse) -
      stated as a prediction from direct structural analogy, not to be treated as measured until an
      actual `criterion` run confirms it. **Strumok does not have this *specific* T-128-shaped
      nuance, checked and confirmed, not assumed**: `hazmat::strumok.rs`'s `Core` state
      (`s: [u64; 16]`) is already a fixed-size array regardless of the 256/512 key-size variant -
      DSTU 8845's LFSR size doesn't scale with key size, only `init_state`'s key-length branch
      differs (one-time setup, not per-step) - so `next_step`/`strm` never had a `MAX_NB`-style
      oversized buffer or a runtime block-size parameter to fix in the first place. **Strumok does
      have a different, separately-found performance nuance - see T-135 below.**
      **Resolution (2026-07-27, `docs/DECISIONS.md` D-85)**: matched the predicted analogy exactly -
      `advisor()`'s narrower design call was to keep `KupynaCore` itself runtime-parameterized
      (genericizing it would ripple into `kupyna_kmac.rs`/`kupyna_kdf.rs` for zero throughput gain,
      since its `buffer`/`total_len` fields are touched once per `update`, not once per round) and
      only const-genericize the hot path (`sub_shift_mix_n`, `add_round_constant_{xor,add}_n`,
      `t_transform_n`/`t_plus_transform_n`, `compress_n`, `bytes_to_columns_n`), dispatched via a
      2-arm `match self.columns` at both `compress_block` and `finalize`'s own `t_transform` call
      (the latter a second hot call site added during implementation, not in the original note).
      Measured: Kupyna-256 -29 to -31% (64B/1024B/65536B), Kupyna-512 -17 to -19%, both within the
      predicted ranges. Full verification bar passed (workspace tests incl. official
      `kupyna`/`kupyna-kmac` vectors, clippy/fmt, full feature matrix incl. `small-tables`, scoped
      Miri 8/8 0 UB). `KupynaCore` const-genericizing itself is flagged as a separate follow-up
      (a memory win for `resource-profiles.md`'s MCU tiers), not pursued here.
      **Binary-level UAPKI re-measurement added same day, on request** - `docs/PERFORMANCE.md`'s Kupyna
      section has the full table: `uacrypt`'s real throughput rose +41-47%/+21-29%, cross-validating
      the `criterion` numbers above; UAPKI's former ~1.1-1.5x lead is closed for Kupyna-256
      (~1.0-1.1x now) and narrowed but not closed for Kupyna-512 (~1.19-1.20x, was ~1.45x).
- [x] **T-135** **Done 2026-07-27, see `docs/DECISIONS.md` D-86.** Batched/fixed-index rewrite landed:
      a one-time array rotation normalizes `head` to `0` (rejected the T-128/T-134 const-generic-
      dispatch pattern specifically for code size), a new `next_block` function batch-generates a
      full 128-byte block with literal indices derived from this project's own `strm`+`next_step`
      order (not the oracle's), and `apply_keystream` became a three-phase drain/bulk/remainder
      loop with `block: [u8; 8]` left unwidened. `criterion`: no change at 64 B (below the bulk
      threshold), **-53.5 to -53.7% at 1024 B, -64.7% at 65536 B**. Binary-level (10 MiB vs.
      outspace): gap closed from ~3.2-3.9x to **~1.19-1.25x** (not fully eliminated - the FSM's
      serial dependency chain is unchanged). Correctness: new proptest/boundary/mid-word-carry unit
      tests inside `hazmat::strumok.rs` (integration tests can't reach the private old-vs-new
      comparison), full verification bar (workspace tests, default/`small-tables` individually,
      clippy, fmt, `no_std`/`getrandom` matrix, scoped Miri 4/4 0 UB), plus an independent re-run
      of the existing 4000-case outspace differential harness - 0 mismatches. `hazmat::strumok.rs`'s
      original text below is the pre-T-135 description, retained for the historical detail on what
      changed and why (D-26's ring buffer, the byte-at-a-time gap this task closed):
      `hazmat::strumok.rs`'s `apply_keystream` (line 923) works word-at-a-
      time then byte-at-a-time, where `oracles/strumok-dstu8845/strumok.c`'s equivalent path
      (`next_stream_full_crypt`, line 815, called from `dstu8845_crypt`'s main loop, line 1090)
      batch-generates and fuses the input XOR into one pass over a full 128-byte (16-word) block -
      found 2026-07-26 digging into the ~3.2-3.9x residual gap to outspace left open after D-26
      (ring buffer + precomputed `T0..T7` tables - both already landed, this is what's left).
      **Three compounding differences, read directly from `strumok.c`, not inferred**:
      (1) **No runtime ring-buffer indexing in outspace at all** - `next_stream_full_crypt` is 16
      fully-unrolled statements, each touching a *literal* `ctx->S[i]` array index (e.g.
      `ctx->S[3] = ... ^ ctx->S[0] ^ ... ctx->S[14]`), no modular arithmetic, no `head` pointer.
      This project's `next_step` (`strumok.rs:857`) takes a `head: &mut usize` and computes
      `(*head + 11) & 15`/`(*head + 13) & 15`/`(*head + 15) & 15` fresh on *every single step* -
      real masked-indexing/pointer-chasing overhead where outspace's compiler sees compile-time-
      known offsets instead (the D-26 ring-buffer fix removed the *data movement* `copy_within`
      cost, but not this indexing cost - a distinct, still-open overhead). (2) **Batch generation,
      not one word at a time**: outspace's function produces all 16 output words (128 bytes) per
      call; this project's `strm`/`next_step` (`strumok.rs:880`/`857`) are separate calls that
      together produce exactly one 8-byte word, called repeatedly. (3) **Fused input-XOR, not a
      separate apply pass**: outspace writes `out[i] = in[i] ^ (...)` directly inside the same
      unrolled loop that advances state - one `u64` XOR per word, no separate loop at all for the
      bulk (only outspace's own tail path, <128 B, falls back to a per-byte loop). This project's
      `apply_keystream` (`strumok.rs:923`) is a **byte-at-a-time** loop for the *entire* input, not
      just a tail: `if self.block_pos == 8 { regenerate 8 bytes }` then `*byte ^=
      self.block[self.block_pos]; block_pos += 1` for every single byte - one branch check plus one
      single-byte XOR per byte, versus outspace's one `u64` XOR per 8 bytes with zero per-byte
      branching in the bulk case. **Coherent with the measured gap size**: a "batch-generate,
      fixed-index, word-XOR-fused" design against a "one-word-at-a-time, masked-index, byte-XOR"
      design is exactly the shape of overhead that produces a 3-4x difference, not a smaller
      constant-factor gap - this is the leading candidate for D-26's still-open "remaining ~3.2x
      gap... a smaller, unchased residual" note, not confirmed by isolated measurement yet (same
      "read the source, then verify with a targeted measurement before treating it as settled"
      standard `docs/DECISIONS.md` D-76 already established for Kalyna-GCM's field-multiply finding).
      **Fix, by analogy to T-128's own process (not yet consulted with `advisor()` - do that
      before writing any code)**: a batched, fixed-index `next_stream_full_crypt`-equivalent that
      generates a whole 128-byte (16-word) block per call using literal (not `head`-indexed)
      state-slot references, with the input XOR fused into the same pass and applied word-at-a-
      time (`u64` XOR, not byte-at-a-time) for full blocks, falling back to the existing per-byte
      path only for a final partial block - mirroring `dstu8845_crypt`'s own two-tier structure
      exactly. **This changes the *scheduling/batching* of the same state-transition function, not
      the transition itself** - `next_step`'s underlying math (`mul_alpha`/`mul_alpha_inv`/
      `t_function`/`fsm`) is untouched, so the existing official test vectors, the
      `apply_keystream_is_involution` property tests, and the 4000-case outspace differential
      harness remain the correctness gate; a new differential test comparing the batched path
      against the current per-word path over random state/key/IV is still needed (same "new-vs-old,
      not just new-vs-naive" pattern T-128's `const_round_tests` established) before this can be
      called verified, not assumed correct because it's "just outspace's own approach transcribed."
      Same safety-net bar as T-128: full workspace test/clippy/fmt/feature-matrix pass, `criterion`
      before/after baseline, and note `hazmat::strumok.rs`'s existing `#[cfg(feature =
      "small-tables")]` branch on `t_function` - whatever batching shape is chosen must keep working
      under both resource profiles, not silently assume the default `fused` one.
- [x] **T-139** **Investigated and closed 2026-07-27, no code change - see `docs/DECISIONS.md` D-87.**
      User-asked follow-up to T-135/D-86: why outspace is still ~1.2x ahead after T-135. The
      hypothesis (a double memory round-trip through local `input`/`out: [u64; 16]` stack arrays in
      `apply_keystream`'s bulk loop, plus `next_block` lacking an `#[inline]` hint unlike the
      oracle's `static inline`) was **refuted by reading the actual generated assembly**
      (`RUSTFLAGS="--emit=asm"`), not assumed from source alone, per `advisor()`'s explicit
      "test the hypothesis before planning the rewrite" redirect: `next_block` has **no separate
      symbol at all** in the emitted `.s` (fully inlined into `Core::apply_keystream`, confirmed,
      not guessed), the `input`/`out` arrays do not appear as a literal write-then-read memory
      round-trip (SROA already promotes them into the same fused, interleaved register/spill
      computation LLVM builds for the whole unrolled step sequence), and the 128 `T0..T7`/
      `MUL_ALPHA`/`MUL_ALPHA_INV` table lookups per block carry **zero bounds-check branches** (each
      index is a `u8`-derived byte, provably in `0..256`, statically elided). The only `cmp`/`jae`
      inside the bulk-loop label is the outer `len - pos >= 128` loop condition itself, once per
      128 bytes. **Criterion couldn't resolve this directly** - a same-code, back-to-back rerun
      showed ~5-9% swings on this machine at the time, wider than the ±3% band `advisor()` expected,
      so the 2x2 (`#[inline(never)]` vs `#[inline(always)]` vs default) landed inside the noise
      floor and was inconclusive on its own; the asm reading is what actually settled it. **No
      fusion rewrite shipped** - per `advisor()`'s own framing, "the hypothesis was wrong" is a
      complete, valuable outcome here, not a reason to force a change that would measure as noise.
      `next_block` is unchanged (no stray `#[inline]` attribute left from the 2x2 experiment,
      verified). The remaining ~1.2x gap to outspace stays unexplained at the source-reading level -
      a future pass would need side-by-side GCC-vs-LLVM codegen comparison (register allocation/
      instruction scheduling differences), not another Rust-side hypothesis, if ever chased further.
- [x] **T-136** **Closed 2026-07-27, see `docs/DECISIONS.md` D-95.** User-requested 2026-07-26, after T-131/D-78's fresh 10 MiB tables kept
      surfacing the same unexplained shape: Kalyna-block/XTS/KW's decrypt (or unwrap) direction is
      *not* symmetric with encrypt (or wrap) the way GCM/CMAC/CCM's is - on some variants
      (256-256/256-512, consistently, across all three modes) the reverse direction runs *faster*
      than the forward one, not just similarly, and this survived T-128's own const-generic fix
      rather than being explained by it. Currently attributed only to "`encipher_round_n` and
      `fused_inv_round_n` are genuinely different code paths" (T-128/D-77) - true, but not itself an
      explanation of *why* the direction that wins flips specifically at the 256-256/256-512
      boundary and nowhere else, or why the effect is large enough to show up consistently across
      three structurally different modes (raw block cipher, disk-sector XTS, Feistel-like KW) built
      on the same two functions. **Needs actual investigation, not another restatement of the
      known-different-code-paths fact**: candidates worth checking before concluding anything -
      whether `fused_inv_round_n`'s inverse S-box/MDS table (`SBOX_MDS_DEC`, see
      `hazmat::tables.rs`) has different cache-line/lookup behavior than the forward table at
      `nb=4` specifically; whether the compiler's loop-unrolling/register-allocation choices for
      `encipher_round_n::<4>` vs `fused_inv_round_n::<4>` differ in a way visible in generated
      assembly (`cargo asm` or `objdump` on the release binary); whether this is instruction-cache
      or branch-predictor-related rather than a property of the algorithm at all (would predict the
      effect moving or disappearing on the Raspberry Pi's different microarchitecture - a concrete,
      checkable prediction, not just a hypothesis). A `criterion` differential benchmark isolating
      `encipher_round_n::<4>` against `fused_inv_round_n::<4>` alone (no surrounding mode-of-
      operation overhead) is the natural first measurement - if the asymmetry already shows up at
      that isolated level, the cause is in the round functions themselves; if it only shows up in
      the full CLI-level numbers, the cause is elsewhere (I/O, mode-of-operation bookkeeping, etc.).
      Not a correctness concern - encrypt/decrypt round-trip correctly on every existing test vector
      and property test regardless of which direction happens to run faster; this is purely a
      performance-curiosity task, not gating any release-readiness item.
      **First measurement done 2026-07-26, see `docs/DECISIONS.md` D-84** (perf/hygiene roadmap Tier B
      item 5): the isolated `criterion` differential benchmark this task asked for already existed
      - `benches/kalyna.rs`'s `_encrypt_block_only`/`_decrypt_block_only` pairs (T-128, cached
      schedule, no mode-of-operation overhead) are exactly that measurement, no new code needed.
      **Confirmed: the asymmetry already shows up at the isolated round-function level** - decrypt
      beats encrypt by ~14-15% at `nb=4` (256-256/256-512) specifically, while encrypt beats decrypt
      at both `nb=2` (~11-13%) and `nb=8` (~36%). This rules out a mode-of-operation-level cause
      directly (confirms it's in `encipher_round_n`/`fused_inv_round_n` themselves or their `nb=4`
      codegen) - but the actual *why* (table cache-line behavior, compiler codegen, branch
      predictor) remained open at that point, per this task's own remaining candidates.
      **Deeper root-cause pass, 2026-07-27, see `docs/DECISIONS.md` D-89** (same session as T-129/D-88,
      same `--emit=asm` method): read `encrypt_with_schedule::<4>`'s and `decrypt_with_schedule::
      <4>`'s inlined round-loop bodies directly (both fully inline at `NB=4` - no standalone
      symbols exist for either round function at this size) and isolated just the repeated loop
      body (excluding the one-time boundary passes `decrypt_with_schedule` also runs -
      `apply_inverse_matrix`/`inv_shift_rows`/`inv_sub_bytes` - which exist because decrypt's own
      whitening rounds can't reuse the fused-gather trick, D-30). **Rules out branch predictor and
      table cache-line behavior directly - neither loop contains a single conditional branch**
      (both are straight-line code between the loop's own back-edge jump), and both index the same
      shape of table (`SBOX_MDS`/`SBOX_MDS_DEC`, 8 contiguous 256-entry `[u64]` rows, one shared
      base register). **Points at register-allocation pressure specifically**: at `NB=4`, encrypt's
      isolated round-loop body has **20 spill stores and 77 total stack references**; decrypt's has
      **14 spill stores and 48 total stack references** - encrypt needs real to real ~40% more
      register-allocator spill traffic than decrypt for structurally symmetric work (both do the
      same count of gather-XOR operations per round, confirmed via matching XOR/pack instruction
      counts). This is a plausible, but not yet fully mechanistically explained, root cause: *why*
      LLVM's register allocator schedules the forward round's `(out_col + NB - shift) & nb_mask`
      arithmetic into more live, spill-forcing ranges than the inverse round's `(out_col + shift) &
      nb_mask` isn't itself derived here - would need an instruction-by-instruction diff of the two
      loop bodies to pin down precisely, not attempted this pass. **Still open**: the task's own
      predicted cross-check (does this move or disappear on the Raspberry Pi's different
      microarchitecture, since register-allocation-driven effects are less architecture-portable
      than an algorithmic one) was not run this session - flagged for whoever next has Pi access
      alongside this task. No code change made or considered - `advisor()` was unavailable this
      session ("temporarily overloaded") so this stayed a pure investigation, consistent with the
      task's own "performance-curiosity, not gating any release-readiness item" framing; a future
      session should still get an `advisor()` opinion before treating "narrow the arithmetic
      further" as an actionable next step, not just extrapolate from this asm reading alone.
      **Closing pass, 2026-07-27, see `docs/DECISIONS.md` D-95** (`advisor()` consulted first, per the
      note above): extended the same spill-count method to `nb=2`/`nb=8` (validated against D-89's
      own `nb=4` numbers first) - the winning direction has fewer stack references at all three
      points now, not one, plus a new `nb=8`-specific finding that LLVM simply doesn't inline
      `encipher_round_n::<8>` (standalone `callq`, zero internal spills) while it fully inlines
      `fused_inv_round_n::<8>` (a ~450-instruction loop, 151 stack refs) - an inlining-decision
      asymmetry, not just an index-arithmetic one. **Then ran the task's own predicted cross-check**
      on the Raspberry Pi "uacipher" rig (aarch64): confirmed the same inlining pattern holds there
      (so the code shape being compared is genuinely equivalent), then ran the same isolated
      `cargo bench -p dstu-core --bench kalyna -- block_only` on both machines. **`nb=4` flips
      winner between x86-64 (decrypt, ~5-12%) and aarch64 (encrypt, ~13-17%)** on code confirmed
      structurally identical on both platforms - this rules out an algorithmic cause outright and
      confirms D-89's register-allocation attribution as an **x86-64-specific LLVM codegen
      artifact**. `nb=2`/`nb=8` keep the same winner on both platforms but at very different
      magnitudes (e.g. `nb=2`: ~13%->~38%), consistent with the same category of cause scaled
      differently by each platform's register-file size. **Closed**: the category of cause is now
      established with real cross-architecture evidence, not just x86-side inference; the finer
      "why does LLVM's allocator treat the two index expressions differently" question stays
      unexplained but is explicitly out of scope for what this curiosity task asked. No code
      changed - `hazmat::kalyna.rs` untouched, `git diff` confirms.
- [x] **T-168** **Done 2026-08-03, see `docs/DECISIONS.md` D-157.** Root cause found and confirmed
      against real `--emit=asm` output, not just source-level reading: Kalyna's outer per-round loop
      (`encrypt_with_schedule`/`decrypt_with_schedule`) takes round count `nr` as a plain runtime
      `usize`, not a const generic, because the same `NB`-monomorphized function body is genuinely
      shared by two variants with different round counts (`NB=2`: Kalyna128_128's nr=10 *and*
      Kalyna128_256's nr=14) - so it compiles to a real loop with a real branch, unlike `cppcrypto`'s
      fully-unrolled per-round call sequence. The inner column/row gather (T-128's const-generic
      `NB`) was already confirmed optimal and branch-free in the asm - not the cause. Kupyna's much
      smaller D-154 gap (~5-9% vs Kalyna's ~1.3-1.9x) lines up with `hazmat::kupyna` already having
      round count as a *second* const generic (`ROUNDS`, safely 1:1 with `COLUMNS` there, unlike
      Kalyna's `NB`) - though full unroll-vs-loop doesn't turn out to fully explain the gap-size
      difference either (checked in asm: Kupyna's own compiled loop isn't fully unrolled by LLVM
      even with `ROUNDS` const), so some of D-154's gap stays genuinely open, not overclaimed as
      solved. Follow-up implementation (make Kalyna's round count const-generic, mirroring Kupyna's
      pattern) is tracked separately as **T-171** below, not done in this read-only pass. Read
      `cppcrypto` 0.20's actual Kalyna/Kupyna source (not just its output) to find out
      *why* it beats `uacrypt` — added 2026-08-03, user-requested, directly off D-154's finding.
      D-154 (`docs/DECISIONS.md`, `docs/ORACLES.md`, `docs/PERFORMANCE.md`) confirmed cppcrypto wins
      all 10 Kalyna binary-level cells (~1.3-1.9x) and both Kupyna variants (~5-9%, near parity) on
      the Ryzen dev machine, but only measured the *gap*, not its cause — this task is the read-the-
      actual-code follow-up, same shape as T-125's GCM field-multiply investigation and T-136 above
      (don't stop at "different implementation," find the concrete mechanism). Source is already on
      disk from D-154's session: `kalyna.cpp`/`kupyna.cpp` under the scratchpad's
      `cppcrypto-0.20-src/cppcrypto/` (re-download from the SourceForge link in D-154 if the
      scratchpad was cleared — sha256
      `cb4d5b54540554b55261a53e5be4e21bfc99642bab154631edf26f29fde65fd5`). Concrete angles worth
      checking, not just "it's faster, ship it": (1) table layout — cppcrypto's `IT[8][256]`-style
      fused tables vs. `hazmat::tables`' own `SBOX_MDS_ENC`/`SBOX_MDS_DEC` layout, same idea
      (D-13/D-28) but possibly different memory layout/alignment/cache-line packing; (2) whether
      cppcrypto's key schedule (`init`) does less redundant work per call than `ExpandedKey`'s own
      ~does, independent of the already-excluded-from-timing schedule cost; (3) `-msse2`/`-mssse3`
      flags the Makefile sets globally (`CXXFLAGS=... -msse2`) — check with `--emit=asm` (this
      project's own established method, D-89) whether the compiler auto-vectorizes the fused-table
      gather in a way `hazmat::kalyna`'s equivalent loop doesn't, before assuming hand-written SIMD;
      (4) why the Kupyna gap (~5-9%) is so much smaller than the Kalyna gap (~1.3-1.9x) specifically
      — if the cause is table-layout-related, Kupyna's own already-fused `KUPYNA_T` tables (shared
      with Kalyna, D-154) should show a similar effect size, and the fact that it doesn't is itself
      a clue worth chasing, not just an aside. **Verify-only, same as every oracle comparison in this
      project (D-06)** — the goal is finding a legitimate optimization to apply to `hazmat::kalyna`/
      `kupyna` on its own merits (cited and tested the normal way), never porting or copying
      cppcrypto's code directly. Any resulting rewrite still needs its own `advisor()` consultation
      and plan-mode pass before implementation, per this file's own Tier C precedent above, and must
      re-verify against all 10 official Kalyna vectors / all 12 Kupyna vectors before any new timing
      is trusted (this task's own D-154 already confirms cppcrypto's *output* is correct — a
      `hazmat` change inspired by reading its code still needs this project's own correctness bar,
      not cppcrypto's).
- [x] **T-171** **Closed 2026-08-03, no code change - see `docs/DECISIONS.md` D-160.** Make Kalyna's
      round count (`nr`) a const generic on `encrypt_with_schedule`/`decrypt_with_schedule` (and
      their round-transform helpers), mirroring `hazmat::kupyna`'s own already-proven `ROUNDS`
      const-generic pattern — added 2026-08-03, direct implementation follow-up to T-168/D-157's
      finding. Not just "port cppcrypto's shape" — the concrete blocker is that today's single
      `NB`-monomorphized instantiation is shared by two variants with different round counts
      (`NB=2`: nr=10 and nr=14; `NB=4`: nr=14 and nr=18), so the fix needs per-variant
      monomorphization keyed on `(NB, NR)` together, not `NB` alone. **Needs its own `advisor()`
      consultation and plan-mode pass before implementation**, per this file's own Tier C precedent
      and D-157's own closing note — this is a real hot-path rewrite of every Kalyna variant's
      encrypt/decrypt, not a mechanical one-liner. Must re-verify against all 10 official Kalyna
      vectors (`crates/dstu-core/tests/vectors/kalyna/*.json`) before any new timing is trusted, and
      re-measure against D-154's own cppcrypto numbers afterward to confirm the gap actually closes,
      not just assume it will from the asm reasoning alone.
      **Outcome**: `advisor()` + plan-mode both done first; the plan-approved Step 1 was a
      throwaway spike (Kalyna128_128 only, `NB=2`/`NR=10`) built with `--emit=asm` before touching
      the other four variants. Result was negative — the const-generic version compiled to the
      identical loop-with-branch shape as today's runtime-`nr` version (same 214-line body, same
      `.LBB_1`/`jne` back-edge), just an immediate-vs-memory-loaded compare bound, not the full
      unroll `cppcrypto` has. Matches D-157's own already-recorded warning (Kupyna's `ROUNDS` const
      doesn't fully unroll either) rather than the hoped-for result. Per the plan's own decision
      gate and the T-139/T-129 precedent, spike reverted (`git stash` + `git stash drop`, `git diff`
      empty) and the task closes with no code change — a complete outcome, not a shortfall. The
      remaining ~1.3-1.9x Kalyna-vs-cppcrypto gap stays open; D-160's closing note has the concrete
      next-mechanism-to-try pointer for any future task.
- [x] **T-175** **Done 2026-08-05, see `docs/DECISIONS.md` D-164.** Found and killed a real stuck
      `cargo +nightly miri test -p dstu-core-capi` job left running from a previous session -
      owner asked to check on it since "it's been going a long time," not something this session
      started. **Measured, not assumed**: the `miri.exe` child process had accumulated 38468 CPU
      seconds (~641 minutes, ~10.68 hours) and was still climbing when found, on a single test
      file (`crates/dstu-core-capi/tests/ffi_tests.rs`, 17 tests) - roughly 7.6x D-59's own "~84
      min measured locally" figure for the equivalent `dstu-core` suite. **Two distinct root
      causes, not one** - fixing the first alone left the process still stuck. (1) The C ABI
      crate's own FFI tests never got the same `#[cfg_attr(miri, ignore)]` exemption D-59 already
      applied to `dstu-core`'s own `crypto_sign.rs`/`dstu4145_signature.rs` tests for `Point::
      scalar_multiply`'s 163-iteration EC ladder - a coverage gap from T-158 adding the C ABI
      crate's FFI suite without carrying that exemption over
      (`sign_verify_round_trip_and_forgery_rejection`,
      `sign_digest_matches_sign_of_the_same_hash`). (2) `dstu-core-capi/Cargo.toml` unconditionally
      enables dstu-core's `pwhash` feature, so `pwhash_hash_and_verify_round_trip_and_rejects_
      wrong_password` runs Argon2id under Miri - a memory-hard KDF over a 64 MiB buffer, made
      intractably slow by Miri's own provenance tracking over that allocation, a combination
      `dstu-core`'s own miri run never exercises since `pwhash` is opt-in there (off by default).
      Found only after the first fix's re-verification run was itself piped through `| tail -40`
      (buffers until EOF, so it looked hung for ~103 CPU-minutes with zero visibility) - re-run
      redirected straight to a file instead, which showed execution stopped on test #8/17,
      `pwhash_hash_and_verify_round_trip_and_rejects_wrong_password`. Fixed both with their own
      cited `#[cfg_attr(miri, ignore = "..."]` (the pwhash one citing Argon2/Miri-provenance, not
      a copy-pasted ladder reason, per D-25's discipline). **Checked, not assumed, that a third
      candidate didn't need the same fix**: `selftest_passes` also reaches DSTU 4145's Annex B.1
      vector via the same ladder, but a single verify call proved cheap enough - confirmed `ok` in
      the clean re-run rather than pre-emptively ignored. **Confirmed by a real clean re-run**:
      `cargo +nightly miri test -p dstu-core-capi` finished in **505.81s (~8.4 min)** - 14 passed,
      0 failed, 3 ignored, down from a process that had already run 649.3 minutes without
      finishing. Also added, so this localizes faster next time: `cargo xtask miri [pkg]` now
      accepts an optional package name (`-p <pkg>` instead of `--workspace`), and
      `.github/workflows/rust.yml`'s `miri` job is now a per-crate matrix (`dstu-core`, `uacrypt`,
      `dstu-core-capi`, `fail-fast: false`) instead of one combined job/log.
- [x] **T-174** **Done 2026-08-04, see `docs/DECISIONS.md` D-163.** Extracted and arithmetically
      verified the DSTU 9041 curve/algorithm content from the OCR transcript T-173 produced,
      rewriting `docs/pseudocode/dstu9041.md` from a single-secondary-source ("zero source
      material, hard-blocked") document into a primary-source-cited one with a real (partial)
      worked-example oracle - owner-requested direct follow-up to T-173, framed explicitly as
      extract-then-document-then-implement, with the extraction/curve-parameter/test-vector data
      committable (copyright covers the standard's own prose, not the algorithm or its parameters -
      same reasoning already applied throughout this project's `docs/papers/*.pdf` handling).
      **Not extracted from OCR text order** - every numeric parameter re-read directly from
      rendered page images at heavy zoom, with long same-character runs (a 61-`F` prefix on `p`, a
      31-zero run in `n`) resolved via a column-darkness stroke-count script rather than eyeballing,
      after a first manual transcription silently over-counted both by more than 20 digits - same
      failure mode as OCR's own known weakness for repeated visual patterns, just from a human/AI
      reader instead of the OCR engine, confirming the project's own "verify per-digit, don't trust
      a document-scale read" rule applies to *any* transcription method, not just OCR specifically.
      **Real result: DSTU 9041 is no longer hard-blocked (D-08/T-46).** The scan (partial - see
      `docs/pseudocode/dstu9041.md`'s own "open gaps") includes Додаток Г, three full worked
      encrypt+decrypt examples for `l(p) ∈ {256,384,512}` - independently re-derived this curve's
      point-addition law (the standard's own form has `x`/`y` swapped relative to the textbook
      twisted-Edwards convention, missed on the first attempt, caught by testing against the
      example rather than trusting the equation alone) and verified end-to-end for the `l(p)=256`
      case: `p`/`n` prime, `p≡5 mod 8`, `P/Q/R/T` all on-curve, `R=7P`, `T=7Q`, `n*P=`neutral -
      four independent confirmations using one from-scratch Python reference implementation, plus
      `Kupyna256(l_M~||M~)` truncated to its **last** 4 bytes matching the example's stated hash
      (`hazmat::kupyna::Kupyna256`, this crate's own code, not a new implementation) - resolves
      clause 5.7's truncation-direction ambiguity empirically. **`t` resolved same day, in a direct
      follow-up requested by the owner** (see `docs/DECISIONS.md` D-163's addendum): the real
      Kalyna-256/256-KW input is `M' ‖ 0x00×32` (`M'` plus one extra all-zero 256-bit block, not
      `M'` alone) - `hazmat::kalyna_kw::Kalyna256_256Kw::wrap` (this crate's own unmodified code) on
      that input reproduces the standard's own printed `t` exactly once a single hex digit the
      source itself is missing (a dropped `0`) is restored - a second, independently-confirmed
      erratum in the standard's own Annex Г, and simultaneously bit-exact confirmation that this
      project's Kalyna-KW matches the standard's construction, not just internal self-consistency.
      Committed with the digit restored in `g1-worked-example.json`. **The earlier `e=25`
      "erratum" reported in this same task's first pass was this project's own misread, corrected
      in the same follow-up**: Annex Г's hex convention (already correctly applied to `d=0x18=24`)
      wasn't re-applied to `e` - `e=0x25=37` decimal, and `37P==Q` holds exactly; there was never a
      real inconsistency. **Genuinely open, not resolved**: why the KW input needs that second
      all-zero block at all - not explained by any scanned clause, needs 6.5-6.12 or a fresh
      re-read of clause 11. **Real, concrete gap list for the follow-on implementation phase**
      (deliberately not started this session - a
      brand-new prime-field/twisted-Edwards primitive clears the project's own Tier C bar, `T-172`'s
      precedent, by a wide margin): (1) `F_p` bignum arithmetic (new - `hazmat::dstu4145`'s existing
      field code is binary-field `GF(2^m)`, unrelated), (2) twisted-Edwards point arithmetic over
      it (Додаток Б.4's projective addition formula is implementation-grade and already
      citation-verified above), (3) `hazmat::kalyna_kw_p` - a padding variant of the existing
      `hazmat::kalyna_kw` (D-55), needed for any non-block-aligned case (the `l(p)=384` row uses it
      per Table 2, confirmed by checking `8+l_H+16+l_max(p)` against the Kalyna block length per
      row - clean multiple exactly when plain KW applies, not otherwise). Committed:
      `docs/pseudocode/dstu9041.md` (rewritten), `crates/dstu-core/tests/vectors/dstu9041/
      curve-E256-1.json` + `g1-worked-example.json` (curve params + example, `t`/`C` deliberately
      omitted pending re-verification). **Addendum 2026-08-05 (T-177/D-166)**: this task's own
      `p`/`n` values were wrong in the committed JSON/doc (an over-counted `F`-run and `0`-run) for
      two full sessions - this entry's own text already had the correct stroke-counted lengths
      (61/31), the fix just never reached the file. Caught starting T-177, fixed, re-verified with
      a real Miller-Rabin this time. See D-166 for the full account.
- [x] **T-177** **Done 2026-08-06.** `hazmat::dstu9041` implementation - the
      primitive itself, not just the source-material extraction T-174/T-176 already did. Scope:
      `l(p)=256`/E256/1 only (D-47 precedent - ship the recommended curve first). Plan saved at
      `C:\Users\Pa\.claude\plans\rosy-baking-teacup.md` (design-level `advisor()` consultation
      before Phase 2, a second `advisor()` review after Phase 2 landed, a third after Phase 4).
      Phased, tests written before each phase's implementation, one commit per phase:
      - **Phase 1** (`e198efb`) - `message.rs`: `M'` formatting, the Kalyna-KW `M'||0x00*32`
        zero-block quirk. 9 tests.
      - **Phase 2** (`4e6a3ea`) - `fp256.rs`: `F_p` arithmetic (`p=2^256-435`, a pseudo-Mersenne
        prime - `multiply`/`square` via schoolbook wide-multiply + a Solinas-style reduction
        exploiting `2^256≡435 mod p`; `invert` via Fermat; `sqrt`/`euler_criterion` via the
        `p≡5 mod 8` formula; `pow_mod` fixed-256-iteration constant-time). Advisor review caught
        every initial proptest masking the field's top bit off (never exercising `add`'s carry=1
        path or `reduce_wide`'s overflow near its ceiling) - fixed with six hand-derived vectors at
        `p-1` itself, sourced from `curve-E256-1.json` rather than hardcoded (D-166 was exactly "the
        committed `p_hex` was wrong for two sessions"). 31 tests.
      - **Phase 3** (`8cf744a`) - `curve256.rs`: twisted Edwards point arithmetic, complete
        Додаток Б.4 addition law (handles doubling/neutral uniformly, no exceptional cases since
        `d` is a non-square), fixed-256-iteration `scalar_multiply`. 16 tests, including the
        `ε=7` tripwire (253 leading zero bits) and the D-110/T-152-precedented boundary sweep
        (`k∈{0,1,n-1,n,n+1}`).
      - **Phase 4** (`77f53ca`, doc fix `762b149`) - `encryption.rs`: composes the above into
        clause 11/12. `decrypt` takes no public key (clippy caught it as genuinely unused - `T'=e*R'`
        needs only `e` and the ciphertext's own `r`). `DecryptError` collapsed to one
        `InvalidCiphertext` variant (padding-oracle-shaped threat model). 20 tests, full round-trip
        against the standard's own worked example (`encrypt` produces the exact 128-byte `C`,
        `decrypt` recovers the exact `M`).

      **Two security findings beyond clause 12's literal text, both fixed and documented in
      `encryption.rs`'s own module doc comment:**
      1. `r=p-1` reconstructs `R'=(p-1,0)`, a genuine order-2 point outside `⟨P⟩` - rejected
         explicitly in step 2 (also incidentally caught by step 4's stricter-than-literal
         `!euler_criterion()` form, kept as an explicit self-documenting check regardless).
      2. **Bigger finding, found by a second advisor review after Phase 3/4 landed**: E256/1 has
         cofactor 4 (`#E=4n`, the unique multiple of `2n` inside the Hasse interval), and - proven
         via clean 2-Sylow-subgroup theory (the curve's `y=0` equation has exactly one non-trivial
         solution, forcing the 2-Sylow subgroup to be cyclic `Z/4`, hence the whole group cyclic
         `Z/4n`) - **genuine order-4 points exist** on this curve, reachable via a crafted `r`, and
         would leak `e mod 4` (not just parity) if unrejected. A first numerical search (random
         points + cofactor-clearing) found none in 5000 tries and briefly looked like it closed the
         question the other way - that search had an uncaught bug (never isolated; superseded by
         the group-theory proof, which doesn't depend on locating a concrete example by
         coordinates). Fixed with a general subgroup-membership check in `decrypt`
         (`R'.scalar_multiply(&order()) == NEUTRAL`), independent of curve-specific torsion
         analysis - the correct, standard fix for any cofactor-`>1` curve.
      Also fixed along the way: `message.rs`'s hash/padding checks used plain `!=`/`.any()`
      (short-circuiting) over kappa-derived data - now constant-time
      (`subtle::ConstantTimeEq`/fixed-iteration OR-fold), caught before `decrypt` could safely call
      `parse_m_prime`.

      **QA-gate closure (2026-08-06)**: full-workspace `clippy`/`fmt` clean; full
      `cargo test --workspace --all-features` clean (115 lib/integration tests + 8 doc-tests, 0
      failed, independently re-verified via unpiped log redirect to avoid a `tail`-truncation false
      pass); scoped `cargo +nightly miri test` (`-p dstu-core --test dstu9041_field --test
      dstu9041_curve --test dstu9041_encryption --test dstu9041_message --lib`, with
      `MIRIFLAGS=-Zmiri-disable-isolation`/`PROPTEST_CASES=1` matching CI's own T-81-precedented
      invocation) ran fully clean across every dstu9041 test file: `--lib` 74 passed/3 ignored,
      `dstu9041_curve` 16 passed, `dstu9041_encryption` 19 passed/1 ignored, `dstu9041_field` 28
      passed/3 ignored, `dstu9041_message` 9 passed, 0 failed overall (ignored cases are the
      256-iteration `pow_mod`/`sqrt` ladders, too slow to interpret under Miri, matching T-100's
      precedent). A Kani proof harness (`fp256.rs`'s `kani_proofs` module: `conditional_sub_p`/
      `select`/`add`/`sub`/`reduce_wide` boundedness and select-spec proofs, deliberately scoped
      away from full `multiply`/`wide_mul` equivalence per D-112's CBMC-intractability precedent)
      is written and wired into `.github/workflows/rust.yml`'s `kani` job name, but **not
      independently confirmed** - `cargo kani` cannot run on this Windows dev machine at all
      (Unix-only std dependency in kani-verifier itself); CI (Linux) is the real verification venue
      for this harness. `docs/DECISIONS.md` D-167 bundles the two security fixes, the collapsed
      `DecryptError`, the single-oracle accepted risk, the constant-time `message.rs` fix, and this
      QA-gate summary. `docs/pseudocode/dstu9041.md`'s section was updated to reflect that
      `hazmat::dstu9041` (l(p)=256) now exists.
      Known accepted risk, documented at closure: no independent DSTU 9041 reference implementation
      exists anywhere (`docs/ORACLES.md`, 2026-07-21 search) - Додаток Г's own worked example is the
      sole oracle for this primitive.
- [x] **T-178** **Done 2026-08-06 - T-178a/b/c all landed.**
      `dstu_core::crypto_box` (new high-level module) plus its `uacrypt` CLI surface. Design settled
      with the owner 2026-08-06 after an `advisor()` review found `l(p)=256`'s `L_MAX_P=200` bits
      (25 bytes) can't hold this project's existing 32-byte symmetric keys directly - **hybrid via
      KDF**, chosen over a 25-byte-capped "short secret wrap" or waiting on `l(p)>=384` (T-182).
      - **T-178a - `dstu_core::crypto_box` library module. Done** (`68986b8`): `seal`/`open`,
        `SecretKey`/`PublicKey` (32-byte x-only compressed, verified by an explicit group-theory
        argument plus a dedicated `curve256` test - `point_from_x_gives_same_kappa_regardless_of_sqrt_branch`).
        `curve256::point_from_x` extracted from `encryption::decrypt`'s own inline reconstruction as
        a shared helper (`626680a`) - one security-critical gauntlet, not two copies. 14 new tests
        (round-trip incl. a message far larger than the 25-byte KEM payload, every wire-segment
        tamper case, wrong key, misuse), heaviest proptest `#[cfg_attr(miri, ignore)]` up front. Full
        `cargo test --workspace --all-features` re-run clean (42 test groups, 0 failed) after
        landing, `cargo xtask clippy`/`fmt --check` clean.
        - **Wire format**: `dstu9041_ciphertext(128) || secretstream_header(32) || ciphertext ||
          tag(16)` - v1 emits exactly one `Tag::Final` chunk (whole message in memory, matching
          `crypto_secretbox`'s own one-shot `Vec<u8>` convention), forward-compatible with a later
          genuinely multi-chunk `seal_stream`/`open_stream` pair without changing the KEM prefix.
        - **KEM step**: `seal` draws a random 25-byte (200-bit, `L_MAX_P` exactly - not an invented
          size) seed, `hazmat::dstu9041::encryption::encrypt`s it to the recipient's public point
          with a freshly rejection-sampled ephemeral `epsilon` (`is_valid_scalar`-gated loop,
          `crypto_sign::SigningKey::generate`'s own pattern). `open` recovers the seed via
          `encryption::decrypt`, checks the recovered bit length is exactly `L_MAX_P` (defense in
          depth - should be unreachable for an honestly-sealed ciphertext given the hash check
          already covers it, but not trusted blindly).
        - **KDF step**: embed the 25-byte seed into the low-order bytes of a zero-padded 32-byte
          buffer (`crypto_sign::derive_nonce`'s own `d`-embedding precedent - "an embedding, not a
          truncation, no information lost") and call `hazmat::kupyna_kdf::Kupyna256Kdf::derive_subkey`
          directly (not `crypto_kdf::MasterKey`, which requires an already-32-byte key) to get the
          `crypto_secretstream::Key`.
        - **Public key compression**: `PublicKey` is 32 bytes, the curve point's **x-coordinate
          only** - not `x||y` (64 bytes). Verified safe by an explicit group-theory argument (not
          assumed): this curve's negation is `-(x,y)=(x,-y)` (the swapped-Edwards form,
          `docs/pseudocode/dstu9041.md`), so `x` never distinguishes `Q` from `-Q`; since
          `k*(-Q)=-(k*Q)` for any scalar `k`, and `x_T=x_{-T}` always holds on this curve, the two
          possible reconstructions of `Q` from `x_Q` alone yield the *same* `kappa=x_{epsilon*Q}` on
          the encrypt side regardless of which square-root branch is chosen - cite this reasoning in
          the module doc, don't leave it implicit. `PublicKey::from_bytes` must run the **same
          reconstruction gauntlet `decrypt` already runs** (reject `x in {0,1,p-1}`, reject
          `x^2=a*d^-1`, `euler_criterion` before `sqrt`, subgroup check
          `scalar_multiply(&order())==NEUTRAL`) - extract this into a shared
          `curve256::point_from_x` helper used by both `encryption::decrypt` and
          `crypto_box::PublicKey::from_bytes`, not two independently-maintained copies of a
          security-critical check.
        - **Error collapsing**: `OpenError` stays a small, deliberately under-distinguished enum
          (KEM failure, secretstream tag failure, and a bad recovered bit-length all map to one
          "invalid ciphertext" case) - same padding-oracle-avoidance posture as `DecryptError`
          (D-56/D-63 precedent); a `Truncated` variant for the public wire-length check is fine to
          keep separate (no secret-dependent data involved in that check).
        - **Test-first, all three CLAUDE.md categories**: correctness (round-trip - no DSTU vector
          exists for this composite, property-tested only, `crypto_secretstream`'s own D-68
          posture); rejection (tampered KEM prefix, tampered header, tampered ciphertext/tag, wrong
          secret key - `tampered_kem_prefix_is_rejected` explicitly, per the D-63-style nonce/prefix-
          binding check); misuse (empty message, oversized/malformed `PublicKey` bytes, off-curve or
          wrong-subgroup `x` values). Mark the heaviest round-trip/keygen proptests
          `#[cfg_attr(miri, ignore)]` up front (T-100/T-177 precedent), not after a multi-hour miri
          run discovers it.
      - **T-178b - `uacrypt` CLI. Done** (`bebe4e3`): `box-keygen`/`box-pubkey`/`box-seal`/
        `box-open`, new verbs (not an overload of `encrypt`/`decrypt`), mirroring `sign`/`verify`'s
        key-file convention (T-124). `box-seal`/`box-open` are deliberately not memory-bounded (D-42
        note, documented in both commands' own doc comments) - `crypto_box::seal`/`open` take
        `&[u8]`/`Vec<u8>`, not a chunked interface, so `--in` is read whole into memory pending a
        future `seal_stream` library addition. 17 new tests (parse-arg coverage, a golden-path round
        trip both directly and through the top-level `run()` dispatcher, wrong-key/tampered/
        truncated-file rejection, misuse), heaviest tests `#[cfg_attr(miri, ignore)]`. Manually
        verified end-to-end via the actual built binary (keygen -> pubkey -> seal -> open round
        trip, plus wrong-key and tampered-ciphertext rejection), not just the test suite.
      - **T-178c - `dstu-core-capi` addition. Done 2026-08-06** (`docs/DECISIONS.md` D-171),
        prerequisite for T-181's .NET/Go/C++ bindings (they link `dstu-core-capi` directly - PHP
        turned out not to, see T-181's own entry below).
        `crates/dstu-core-capi/src/crypto_box.rs`: `DstuBoxSecretKey`/`DstuBoxPublicKey` opaque
        handles, `dstu_box_secretkey_generate`/`_from_bytes`/`_bytes`/`_public_key`/`_free`,
        `dstu_box_publickey_from_bytes`/`_bytes`/`_free`, `dstu_box_seal`/`_open` (caller-allocates
        output buffers, D-148 point 3 - capacity checked before any crypto work runs). Module kept
        the full `crypto_box` name (not `box`, every sibling module's own dropped-prefix
        convention) since `box` alone is a reserved Rust keyword; exported symbols still follow the
        `dstu_box_*` sibling pattern. `OpenError::InvalidCiphertext` reuses the existing
        `DSTU_ERR_TAG_MISMATCH` status rather than a new one - D-169's error-collapsing posture
        must not be reopened by inventing a differently-named status a caller could branch on. 3
        new Rust FFI tests (`tests/ffi_tests.rs`) plus a `test_box()` C-level test
        (`c-tests/test_capi.c`, real gcc compile against the regenerated header - `cargo xtask
        capi` clean). `include/dstu_core.h` regenerated and diffed (only the new surface changed).
- [x] **T-179** **Done 2026-08-06.** Performance benchmarking for `hazmat::dstu9041`/`crypto_box` -
      `docs/PERFORMANCE.md`'s new "DSTU 9041 / `crypto_box`" section (T-150's own ops/s-vs-OpenSSL
      precedent, not a D-34 MB/s cross-implementation case - no second DSTU 9041 implementation
      exists to compare against, and MB/s is meaningless for a fixed-size 128-byte asymmetric op).
      Added `--iterations` to `box-seal`/`box-open` (mirroring `sign`/`verify`) and measured the
      real release binary: `box-seal` 1305.66 ops/s, `box-open` 1072.53 ops/s, against `openssl
      speed ecdh`'s `brainpoolP256r1` (256-bit prime, field-size-matched - 1249.3 ops/s) and
      `X25519` (12537.4 ops/s). **Explicit caveat, not glossed over**: `seal`/`open` each perform
      *two* scalar multiplications per call (not one, like a single `ecdh` op) - the raw ops/s
      numbers are reported as measured, not further normalized per-scalar-mult, since OpenSSL's own
      `ecdh` benchmark internals weren't independently re-derived to confirm exactly what it counts
      as one op. **Addendum, 2026-08-06, owner feedback (`docs/DECISIONS.md` D-170)**: `ecdh` is the
      wrong *regime* for a full seal/open call (never touches a message) - added a same-regime 10 MiB
      MB/s table against `openssl cms -encrypt`/`-decrypt` with an EC recipient (real hybrid
      envelope: ECDH + AES-256-CBC bulk encrypt), the actual OpenSSL analog to `crypto_box`. Result:
      OpenSSL CMS is ~4.2x faster sealing (37.34 vs. 8.84 MB/s), ~3.3x faster opening (35.36 vs.
      10.72 MB/s). Found and fixed two real gotchas first (not assumed): `openssl cms` needs
      `-binary` or it silently truncates binary input at the first `0x1A` byte (also recorded in
      `CLAUDE.md`'s Agent discipline), and Git Bash needs `MSYS_NO_PATHCONV=1` for `-subj "/CN=..."`.
      New standing rule recorded in `docs/PERFORMANCE.md`'s Methodology section: a full-construction
      benchmark must include a same-regime comparison binary going forward, not just one sharing the
      dominant primitive cost.
- [x] **T-180** **Done 2026-08-06 - `README.md` and `gh-pages` both updated.** Documentation/site
      update for `hazmat::dstu9041`/`crypto_box`. `README.md`'s status paragraph (DSTU 9041/
      `crypto_box` no longer "no implementation yet"), `crypto_*` module list, and a `box-keygen`/
      `box-pubkey`/`box-seal`/`box-open` usage example block (commands actually run against the
      release binary first, matching this file's own "every command below was run for real" standing
      practice). `gh-pages` (`index.html`/`uk/index.html`, both languages) deliberately held for an
      explicit owner check-in first (a marketing-page edit pushed to a publicly-live branch, more
      delicate than a docs sweep) - confirmed after T-181 finished, then: the DSTU 9041 `algo-card`
      had gone stale to the point of being actively wrong ("not implemented, blocked on evidence" -
      predates T-177/T-178 entirely), fixed to "verified" with an honest caveat (`l(p)=256` only,
      `crypto_box`'s own composition has no vector oracle); hero eyebrow/lede, the `hazmat::*`/
      `crypto_*` layer descriptions, and a new row in the "closest global analog" table (`crypto_box_seal`,
      T-179's real ~3.3-4.2x-slower CMS-envelope numbers) all updated too. Sent both files to the
      owner for a real visual check before pushing (browser automation unavailable this session,
      same T-162 precedent) - confirmed, pushed to `gh-pages` (`60f09c2`). **Two example-coverage
      gaps found and closed in the same pass, owner-prompted ("чи є приклади усюди")**: `dstu-core-
      capi`'s own `examples/` had `secretbox.c` but no `box.c` (added, registered in
      `xtask::CAPI_EXAMPLES`); `crates/dstu-core/README.md`'s own doctest-walkthrough "Examples"
      section never got a `crypto_box` entry at all (added, byte-diffed against the real module
      doctest per D-75, not eyeballed).
- [x] **T-181** **Done 2026-08-06 - all eight bindings.** Language bindings for `crypto_box` across all eight binding
      languages. Phase/checklist entry in `docs/bindings-strategy.md` ("T-181 - `crypto_box` across
      all eight bindings") - **incremental**, not a from-scratch binding phase: each of the eight
      already exists (T-49 through T-163), this only adds one new module's surface to each. Order
      (per the phase entry, grouped by what each binding actually links, confirmed per binding, not
      assumed from `docs/bindings-strategy.md`'s original Fork 1 planning text - see PHP's own entry
      below for why that text was wrong): Python/Node/Ruby/PHP first (all four direct-bind via
      PyO3/napi-rs/magnus/ext-php-rs, no C ABI involved), then .NET/Go/C++ (consume
      `dstu-core-capi`'s now-done `crypto_box` wrapper), Java last (spike `jni`-direct vs.
      JNI-over-C-ABI same as the original Java phase did). Bindings wrap the high-level
      `crypto_box` surface, not raw `hazmat::dstu9041` directly, per the existing seven-language
      precedent (Fork 2).
      - **Python - done.** `bindings/python/src/crypto_box.rs`: `box_keygen`/`box_public_key`/
        `box_seal`/`box_open`, plain `bytes` in/out (no opaque handle - `Zeroize`-on-drop can't
        carry into a Python `bytes` object regardless of wrapper shape, `secretbox.rs`'s own
        precedent). Kept the full `crypto_box` module name, not `box` (`box` is a reserved Rust
        keyword) - same naming fork as `dstu-core-capi`'s own T-178c (D-171). 12 new pytest cases
        (round trip past the 25-byte KEM payload, ephemeral-material distinctness, tamper/wrong-key
        rejection, invalid-key-encoding misuse). Full `cargo xtask python` pipeline clean (69/69
        tests). Found and cleaned up a stale `cp312`-tagged `.pyd` build artifact in
        `python/dstu_core/` that was shadowing the freshly built `abi3` extension and hiding the new
        symbols on import - a local build-cache leftover (gitignored, never tracked), not a real bug.
        Not yet run on the Raspberry Pi cross-arch smoke check (step 10) - still open, doesn't block
        the next language.
      - **Node.js - done.** `bindings/nodejs/src/crypto_box.rs`: `boxKeygen`/`boxPublicKey`/
        `boxSeal`/`boxOpen` via napi-rs, mirroring Python's `crypto_box.rs` shape (plain `Buffer`
        in/out, same `crypto_box`-not-`box` naming fork). 12 new `node:test` cases mirroring
        Python's test suite exactly. Full suite 64/64 after `npm run build`. Not yet run on the Pi.
      - **Ruby - done.** `bindings/ruby/ext/dstu_core_rb/src/crypto_box.rs`: `box_keygen`/
        `box_public_key`/`box_seal`/`box_open` via magnus, same shape/naming fork again (plain
        `String` in/out). 12 new rspec examples. Full pipeline clean (70/70 rspec) using the
        project's own documented `LIBCLANG_PATH`/`PATH` fix for `rb-sys`'s `bindgen` step against
        Ruby's headers (`.claude.local.md`, D-133's own gotcha - confirmed still needed, not
        already resolved upstream). Not yet run on the Pi.
      - **PHP - done.** `bindings/php/src/crypto_box.rs`: `dstu_core_box_keygen`/`_public_key`/
        `_seal`/`_open` via `ext-php-rs`, `Binary<u8>` in/out, flat `dstu_core_*`-prefixed globals
        (D-142's `ext-sodium`-naming precedent). **Corrected a stale planning assumption while
        writing this**: `docs/bindings-strategy.md`'s original Fork 1 text said PHP would follow
        C++/.NET's C-ABI-consuming shape - the real T-159 implementation binds `dstu-core` directly
        (confirmed via `Cargo.toml`, not the plan), the same direct-`ext-php-rs` shape as Python/
        Node/Ruby, so PHP needed no `dstu-core-capi` work at all despite T-178c's own doc comment
        once claiming otherwise (fixed there and in `docs/bindings-strategy.md`'s Fork 1/T-181
        sections). 12 new PHPUnit tests. Full `cargo xtask php` pipeline clean (fmt/clippy/build/
        phpunit, 70/70) - needed `PHP` on `PATH` (`export PATH="/c/Users/Pa/tools/php83:$PATH"`,
        `.claude.local.md`'s own documented install). Not yet run on the Pi.
      - **.NET - done.** `bindings/dotnet/DstuCore/Box.cs`: `BoxSecretKey`/`BoxPublicKey` P/Invoke
        over `dstu-core-capi`'s now-complete `crypto_box` C ABI (T-178c), `SafeHandle`-based
        `BoxSecretKeyHandle`/`BoxPublicKeyHandle` mirroring every other opaque handle in
        `NativeHandles.cs`. No new `DstuStatus`/exception mapping needed - `ErrInvalidKey`/
        `ErrTagMismatch`/`ErrTruncated` already covered this construction's exact error surface. 12
        new xUnit facts. Full `cargo xtask dotnet` pipeline clean (`dotnet format` on both csproj,
        68/68 tests) - one real fix along the way, a doc-comment `cref="Seal"` that only resolved
        from `BoxPublicKey`'s own scope, not `BoxSecretKey`'s (CS1574 warning, now qualified).
      - **Go - done.** `bindings/go/dstu/box.go`: `BoxSecretKey`/`BoxPublicKey` via cgo directly
        over `dstu-core-capi`, constants pulled straight from the regenerated `dstu_core.h`.
        `ArgumentError`/`CryptoError` in `status.go` already covered this construction's exact
        `DstuStatus` surface, no new mapping needed. 12 new tests. Full `cargo xtask go` pipeline
        clean (`gofmt`, `go vet`, `go test`, 64/64).
      - **C++ - done.** `bindings/cpp/include/dstu/box.hpp`: `BoxSecretKey`/`BoxPublicKey`,
        header-only RAII (move-only `unique_ptr`) over `dstu-core-capi`, mirroring `secretbox.hpp`'s
        shape and `sign.hpp`'s own two-key friend-class split. New `TestBox()` in the shared
        plain-C++ harness (`tests/test_dstu.cpp`, D-158's no-third-party-framework convention), a
        `box.cpp` example registered in `CMakeLists.txt`'s example loop. Full `cargo xtask cpp`
        pipeline clean (zero compiler warnings, `ctest` 100%). **Real gotcha found and recorded in
        `CLAUDE.md`**: `ctest`/the test exe spuriously reported `STATUS_ENTRYPOINT_NOT_FOUND` when
        launched from Git Bash despite the DLL's exports being verified present with `objdump -p`
        first - re-running via the `PowerShell` tool showed a clean 100% pass, confirming this was
        a Git-Bash process-launch artifact, not a real bug.
      - **Java - done.** `bindings/java/native/src/crypto_box.rs`: `Java_ua_dstucrypto_dstucore_
        Box_{keygen,publicKey,seal,open}` via the `jni` crate directly, mirroring `secretbox.rs`'s
        own plain-`byte[]`-in/out shape and `sign.rs`'s own key-validation pattern. D-153's original
        `jni`-vs-JNI-over-C-ABI spike already settled the whole binding's shape when T-51 landed, so
        no new per-module spike was needed here - the Java-side class is plain `Box` (no `crypto_`
        prefix, no underscore, per `lib.rs`'s own JNI-symbol-naming convention). 12 new JUnit tests
        (misuse cases assert `IllegalArgumentException` via `Failure::Misuse`, matching
        `SecretBoxTest`'s own convention). Full `cargo xtask java` pipeline clean (native
        fmt/clippy, `mvn test`, 68/68).
      **T-181 all eight bindings done 2026-08-06** - every binding now exposes the same `crypto_*`
      surface uniformly (Fork 2's own standing rule extended to `crypto_box`). Remaining: the
      Raspberry Pi cross-arch smoke check (step 10) for all eight - not run yet for any of them this
      pass. T-180's `gh-pages` step landed right after, same day - see T-180's own entry above.
- [ ] **T-182** **Not started, no committed timeline - owner-requested backlog item, 2026-08-06.**
      Additional `l(p)` security levels for `hazmat::dstu9041`, beyond T-177's `l(p)=256`-only scope.
      Three genuinely different sub-items, not one task scaled up:
      - **`l(p)=512`** - the most tractable next step. Додаток Г's own worked example is already in
        hand (curve params, `Q`/`R`/`T`) from T-173/T-176's scan; only needs a new `fp512`/`curve512`
        module pair (mirroring `fp256.rs`/`curve256.rs`'s structure) plus checking `t`/`C` against
        plain Kalyna-512/512-KW (block-aligned, no new KW primitive needed) - see
        `docs/pseudocode/dstu9041.md`'s "Open gaps".
      - **`l(p)=384`** - same worked-example situation as 512, but blocked on a genuinely new
        primitive first: `hazmat::kalyna_kw_p`, the padding variant of Kalyna-KW for a
        non-block-aligned `M'` (`hazmat::kalyna_kw`'s own module doc is explicit it has no padding
        scheme of its own, D-55 - this isn't a parameter tweak, it's a new sibling primitive with its
        own test-first pass).
      - **`l(p)=768`** - **confirmed permanently oracle-less, not just unpurchased (resolved
        2026-08-06, owner-supplied page photos).** The document is genuinely 36 pages total, not the
        40 the store listing implies (`docs/ORACLES.md`) - page 36 is the last page, and it's the
        tail end of Додаток Г.3 (the `l(p)=512` decryption worked example's final steps) followed by
        Додаток Д's bibliography. **There is no fourth worked example for `l(p)=768` anywhere in this
        standard's text** - Table В.4's curve parameters exist, but Додаток Г only ever documented
        three worked examples (256/384/512). Buying more pages cannot resolve this; there are no more
        pages. If `l(p)=768` is ever implemented, it needs a from-scratch verification strategy with
        no vector oracle at all - the same posture as `crypto_secretstream` (D-68) or Strumok's
        provisional vectors (D-15), property/tamper tests standing in for a worked example that
        genuinely does not exist, not a temporary gap to fill later.
      Per this project's own Tier C precedent (T-172 and earlier), whichever of these is picked up
      first gets its own `advisor()` consultation and plan-mode pass before code, not a "small
      parameter tweak" treatment - same phased/tested-first pattern T-177 used.
- [ ] **T-183** **Not started, no committed timeline - owner-requested backlog item, 2026-08-06.**
      A meta-task: audit and extend `hazmat::dstu9041`/`crypto_box`'s adversarial test coverage
      beyond D-64/D-65's standard three categories, then spin off whichever of the four groups below
      turn out to have a real gap as their own task(s) - not one task scaled up, per an `advisor()`
      consultation on what the taxonomy for an ECIES-over-twisted-Edwards construction should even
      cover. **First step for whichever sub-item gets picked up: audit `tests/crypto_box.rs` and
      `tests/dstu9041_*.rs` for what's already covered - several items below likely already have a
      test, add only the real gaps, don't duplicate.**
      - **Group 1 - invalid/malformed input (misuse, D-65 category 3).** `PublicKey::from_bytes`
        with `x >= p` (not a valid field element), `x in {0,1,p-1}`, `x^2=a*d^-1`, a valid field
        element that's off-curve, and an on-curve point outside the base point's own prime-order
        subgroup (E256/1's cofactor-4 points). `SecretKey::from_bytes` at `0`, `1`, `n-1`, `n`,
        `n+1`, and all-`0xFF`. `open` at every length boundary around the 176-byte minimum
        (`dstu_core_capi::crypto_box::DSTU_BOX_SEAL_OVERHEAD` at the C ABI layer, unexported at the
        Rust `dstu_core::crypto_box` layer): `0`, `175`, `176`, `177`.
      - **Group 2 - poisoned/tampered wire data (rejection, D-65 category 2).** Independent
        per-segment tamper of each of the four wire regions (KEM prefix, secretstream header,
        ciphertext, tag) plus a bit-flip sweep at each region boundary (already partially covered by
        `tampered_kem_prefix_is_rejected` etc. - audit for the boundary-bit-flip case specifically).
        Substitution/splice attacks: graft the KEM prefix from one `seal` call onto a different
        call's header+body; reuse one KEM prefix with two different message bodies under the same
        recipient. Any length-field this wire format has must reject a lied-about value.
      - **Group 3 - active key/message-recovery attempts (the genuinely new category this task
        exists for, not already covered by categories 1-2 above).** Named attack classes specific to
        ECIES-over-twisted-Edwards:
        - **Invalid-curve/small-subgroup**: a `PublicKey` reconstructing to an order-2 or order-4
          point (E256/1's own cofactor 4) - T-177 already found and fixed two such cases; turn them
          into permanent regression tests, not one-time fixes that could silently regress.
        - **Twist attack**: an `x` whose corresponding RHS is a quadratic non-residue - assert
          `euler_criterion` rejects it *before* `sqrt` is ever called, not just that the end result
          is rejected (the order of operations is the actual security property here).
        - **Chosen-ciphertext oracle probing**: a test that actively *asserts the D-169/D-171
          collapse holds* - that `OpenError`/`DstuStatus` is indistinguishable across a KEM failure,
          a wrong-bit-length recovered seed, and a secretstream tag failure - since that collapse is
          currently a code property with no test pinning it in place against a future refactor.
        - **Ephemeral-scalar reuse**: extend the existing
          `two_calls_use_different_ephemeral_material` test to also assert the *derived stream key*
          differs between two `seal` calls to the same recipient, not just the KEM prefix.
        - **Seed-embedding boundary**: all-zero and all-`0xFF` seeds through `embed_seed` -> KDF,
          confirming no derived-key collision at either extreme.
      - **Group 4 - explicitly out of scope, state it in whichever sub-task actually gets written,
        don't let it drift in silently.** No wall-clock timing-measurement harness - this project's
        own standing rule is that constant-time discipline is never itself a side-channel-resistance
        claim without a real hardware audit (see "MVP scope" above), and a noisy timing harness would
        produce a false claim, not evidence. Scope any side-channel-adjacent check to *structural*
        review instead (no new secret-dependent branch, `subtle::ConstantTimeEq` used everywhere it's
        required) - already covered by this project's existing constant-time discipline, not a new
        test category to build.
      **Constraints for whichever sub-item becomes a real task**: mark any test driving a scalar
      multiplication `#[cfg_attr(miri, ignore)]` up front (T-100/T-177/T-178/T-178c precedent, hit
      three times already - don't discover it after a multi-hour miri run a fourth time). Category-1
      *correctness* (not the misuse cases above) needs no new work - Додаток Г is the sole oracle and
      is already fully verified (T-177). This task is backlog only - T-178/T-179/T-180/T-181's own
      plan is fully done as of 2026-08-06, this stays a backlog item with no committed timeline.
      **Audit done 2026-08-07** (a fork with full project context, not a subset read): went through
      `tests/crypto_box.rs`/`tests/dstu9041_*.rs` against Groups 1-3 above.
      - **Group 3 gaps, real:** order-4 (cofactor) subgroup points have no permanent regression test
        (only order-2/`r=p-1` does, `dstu9041_curve.rs:200,250` - T-177 found and fixed *two*
        invalid-curve bugs, only one has a guard); `euler_criterion`-before-`sqrt` ordering is
        correct in `curve256.rs:211` but untested as a property, only the end result is checked
        (`dstu9041_field.rs`); the D-169/D-171 CCA-oracle error-indistinguishability collapse holds
        today but isn't pinned by a single test asserting it across all three failure modes
        (KEM-failure / bad-seed-length / tag-failure) - a future refactor could silently split them.
      - **Group 1 gaps, real:** `SecretKey` boundary test only covers `e=0,1`, not `n-1`/`n`/`n+1`/
        all-`0xFF` (Group 1 explicitly lists these); no test at `MIN_SEALED_LEN+1` (trailing garbage
        after an otherwise-valid ciphertext - a "reject lied-about length" gap, Group 2).
      - **Group 1/2 confirmed already covered, not re-flagged:** KEM/header/ciphertext/tag
        independent tamper, ephemeral-material distinctness, wrong-key rejection, `x in {0,1,p-1}`.
      - **Out of T-183's own dstu9041-only scope, found during the same pass, spun off as T-189
        (below) rather than shoehorned in here:** DSTU 4145's `VerifyingKey::from_uncompressed_bytes`/
        `hazmat::dstu4145::signature::verify` accept an off-curve public key with no validation at
        all - a real vulnerability, not a missing-test gap. See T-189.
      - Kalyna-GCM/CCM/KW/`crypto_secretstream`'s own adjacent adversarial coverage was
        cross-checked in the same pass and found solid (D-63's nonce/tag divergence correctly
        documented not re-flagged; Kalyna-KW's `tampered_ciphertext_is_rejected` covers the IV/
        checksum block; `crypto_secretstream` has tag-forgery/reorder/truncation/rekey tests).
      **Not yet spun off as their own numbered tasks** - the four real Group 1/3 gaps above stay
      documented here pending owner prioritization, same backlog posture as the rest of T-183.

      **Three of the four closed 2026-08-07, done inline rather than spun off (small, self-
      contained test additions, no curve theory involved - full detail `docs/DECISIONS.md`
      D-173):**
      - `SecretKey`/`open` boundary gaps - closed: `secret_key_rejects_out_of_range_bytes_upper_
        boundary` (`e=n-1,n,n+1,` all-`0xFF`) and `trailing_garbage_after_valid_ciphertext_is_
        rejected` (`tests/crypto_box.rs`).
      - `euler_criterion`-before-`sqrt` ordering - closed: `point_from_x_rejects_a_non_residue_x`
        (`tests/dstu9041_curve.rs`), complementing the already-existing `dstu9041_field.rs`
        `sqrt_of_non_residue_does_not_square_back` (proves *why* the order matters) with a test
        that the real `point_from_x` call site gets it right end to end, not just the isolated
        field-level property.
      - D-169/D-171 CCA-oracle collapse - closed: `kem_failure_and_secretstream_failure_are_
        indistinguishable` (`tests/crypto_box.rs`) - asserts identical `Debug` output (not just the
        same enum variant) across a KEM-level and a secretstream-level failure. The third named
        failure mode (KEM success, wrong-length recovered seed) was not constructed - likely
        foreclosed by `hazmat::dstu9041::decrypt`'s own already-collapsed `DecryptError` (D-167),
        documented rather than forced, same posture as D-111's `dstu4145` findings.
      **The fourth (order-4 regression test) remains open** - see the note directly above this one
      for what was established and why it stopped short of a working test.

      **Order-4 regression test attempted 2026-08-07, not completed - genuinely the hardest of the
      four, budget-capped per `advisor()` guidance rather than pushed to a conclusion.** Tried to
      construct a concrete order-4 point test-side (`curve256.rs`'s own `curve_a`/`curve_d` are
      `pub(crate)`, invisible to the black-box `tests/` crate, so this needs an internal
      `#[cfg(test)]` module, `fp256.rs`'s `private_constant_tests` precedent). Two real findings
      survive even though the test itself doesn't exist yet:
      - **A genuine identity-representation hazard, worth its own note independent of whether
        order-4 ever gets a test**: `ProjectivePoint::to_affine` has no `z == 0` special case: a
        `scalar_multiply` result that reaches the group identity via a `z == 0` intermediate
        renders as `(0, 0)`, not `Point::NEUTRAL = (1, 0)` - confirmed directly in the real `dstu-
        core` build, not assumed. `n_times_base_point_is_neutral` only ever exercises the *base
        point's own* ladder for scalar `n`, which happens not to hit this path - it was never
        stress-tested against an arbitrary other point. `point_from_x`'s own subgroup guard
        (`candidate.scalar_multiply(&order()) != Point::NEUTRAL`) **fails closed** here: `(0,0) !=
        (1,0)` still correctly rejects, so this is not the security hole it looked like at first -
        but any *future* caller comparing a `scalar_multiply` result against `NEUTRAL` should not
        assume that comparison is reliable for detecting the identity in general.
      - **Whether a concrete order-4 point is even reachable through `point_from_x`'s own x-only
        reconstruction formula is an open question, not confirmed either way.** Screened 62 valid
        reconstructed candidates (via an independently-verified `2n*Y` single-ladder computation,
        checking for `2n*Y == ` the known order-2 point, which only holds when `Y`'s order is
        divisible by 4) - all 62 landed in the order-divides-`2n` class (30 as clean `NEUTRAL`, 32
        via the `(0,0)` hazard above), zero as order-4. Under the group-theoretic 50/50 split
        D-167 Finding 2 itself argues for, 0/62 is a ~`2^-62` coincidence - strongly suggesting a
        *structural* reason (e.g. order-4 points' own `x`-coordinates may simply never satisfy
        `euler_criterion` under this specific reconstruction formula, making them unreachable via
        `point_from_x`/`crypto_box::PublicKey::from_bytes` by construction, not merely untested).
        **This would not contradict D-167 Finding 2's existence proof** (order-4 points genuinely
        exist on the curve, confirmed independently via Hasse's bound: `h=4` is the unique cofactor
        fitting the Hasse window for this `p`/`n`) **but would mean the specific attack D-167
        itself describes (a crafted `r` reaching one through this reconstruction path) may not
        actually be reachable the way that entry assumes** - unconfirmed either way, needs its own
        focused investigation (ideally: determine analytically whether an order-4 point's `x`-
        coordinate can ever satisfy `euler_criterion`, rather than more empirical search) before
        being treated as settled in either direction. Filed here rather than chased further per
        `advisor()`'s explicit stop condition once the two-step diagnostic it prescribed (verify
        the `2n` scalar construction, then recount valid-candidate statistics) didn't resolve it -
        T-183 is backlog with no committed timeline, and diminishing effort on the hardest of four
        items isn't worth it uninstructed.
- [x] **T-189** **Done 2026-08-07, found auditing T-183, owner-directed to fix immediately
      (not backlog) - real vulnerability, not a missing-test gap. Full detail: `docs/DECISIONS.md`
      D-172.** `VerifyingKey::
      from_uncompressed_bytes` (`crypto_sign.rs:227-231`) builds `Point::Affine(x, y)` directly from
      caller-supplied bytes with **no on-curve check** - `curve163::Point`, unlike `dstu9041`'s
      `curve256::Point` (which has `is_on_curve`, `curve256.rs:67`), has no such method at all.
      `hazmat::dstu4145::signature::verify` (`signature.rs:65-84`) never validates its own `q`
      parameter either before feeding it straight into `curve163::verify_combine`'s (D-108)
      projective combine step. Any caller loading a `VerifyingKey` from an external source (cert,
      key file, wire protocol) can hand it an off-curve point, or - since this curve's `double()`
      shows `x=0` is a fixed order-2 point (`curve163.rs:87-89`) - the one small-subgroup point,
      with no rejection anywhere. **Cofactor confirmed h=2, dual-sourced**: Hasse's bound with
      `n=0x0400...BCF14D` (`gf2m163.json`) over `GF(2^163)` admits only `h=2` in its window (`h=1`
      falls far short, `h>=3` overshoots), independently confirmed against
      `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java:47` (`h_s[0] = TWO`) - so `{Infinity,
      (0, sqrt(b))}` is the *only* non-prime-order subgroup; no expensive full subgroup-order
      scalar multiplication is needed, an on-curve check plus an explicit `x != 0` rejection is
      complete. **Plan**: `advisor()`-reviewed before any code (per this project's standing rule for
      security-critical forks) - approved the plan below without changes given the confirmed
      cofactor. Test-first: three tests (`t189_public_key_validation` in
      `tests/dstu4145_signature.rs`) that *actively forge* a working `(r, s)` pair against
      `Point::Infinity`, the real order-2 point, and an off-curve `x=0` fake point - not a naive
      "swap in a bad `q`, reuse the real signature" test, which was tried first and found to pass
      *without any fix* (a coincidental numeric mismatch, not a real rejection - the same D-21/D-25
      vacuous-test trap `CLAUDE.md` already documents, recurring at the key-input position). All
      three forgery tests confirmed failing (i.e. the forgery succeeding) against the pre-fix code
      before any production change was made. **Fix landed**: `curve163::Point::is_on_curve` (new,
      mirrors `curve256`'s shape) plus an explicit `x != 0` guard in `signature::verify`, right
      after the existing `r`/`s` checks - not in `VerifyingKey::from_uncompressed_bytes`, which
      returns `Self` not `Result` and would be a breaking API change on an already-published crate;
      `verify` is the single non-breaking choke point every caller (`crypto_sign`, the C ABI, all
      eight bindings) funnels through anyway. All three forgery tests pass post-fix, both default
      and `--features small-tables` profiles; `gf2m163_worked_example_verifies` (genuine key) still
      passes as the other-direction regression guard. Full `cargo test -p dstu-core`/
      `dstu-core-capi`/`uacrypt`, `clippy --all-features -D warnings`, `fmt --check` all clean.
      **Perf, measured via a real same-machine `git stash` A/B** (T-153's `uacrypt verify
      --iterations` methodology, D-161's stash-rebuild caution applied): 563.20 ops/s before, ~539
      ops/s after (~4-5%, higher than the naive sub-1% estimate but nowhere near a full extra
      `scalar_multiply` ladder's cost, which would roughly halve throughput) - both numbers clear
      T-153/D-109's own 524.01 baseline within normal variance; not chased further, see D-172.
      **CI follow-up 2026-08-08**: the pushed commit's `cargo miri test (dstu-core)` job exceeded
      its 240-min cap and was cancelled - `gh run view --log` showed the regular `#[test]` suite
      finished normally (~2h32m, in line with T-156's own historical baseline), then **doctests**
      started and `crypto_sign.rs`'s own example (line 56, a full `SigningKey::generate`/`sign`/
      three `verify` calls - pre-existing, untouched by T-189 itself) was still running when the
      cap hit; `crypto_box.rs`'s own doctest had already taken ~5-6 min just before it. Root cause:
      an already-thin CI time margin (T-146/D-103's own prior "ordinary CI runner variance tipping
      an already-razor-thin margin" diagnosis) tipped over by this session's own small additions -
      one of which, `dstu9041_curve.rs`'s new `point_from_x_rejects_a_non_residue_x` (T-183), was
      missing its own `#[cfg_attr(miri, ignore)]` (an oversight - `point_from_x`'s rejection path
      still runs a 256-iteration `invert`/`euler_criterion` `pow_mod` pair even when it exits early,
      the same T-100/T-156 class as every other EC-heavy exclusion in that file). **Fixed**: added
      the missing exclusion, plus a `# if cfg!(miri) { return; }` hidden line in both `crypto_sign.rs`'s
      and `crypto_box.rs`'s own doc-comment examples (standard rustdoc hidden-line idiom - still
      type-checked and still run for real under plain `cargo test`/`cargo test --doc`, just not
      executed under Miri's interpreter). **Locally confirmed against real Miri** (installed on this
      dev machine, unlike Kani/D-102): `cargo +nightly miri test -p dstu-core --doc` dropped from
      "still running after 20+ minutes, uncompleted" to **14.29s for all 8 doctests** - not assumed
      from the fix's shape alone.
- [x] **T-190** **Done 2026-08-08, owner-requested.** Plan below written 2026-08-08,
      advisor()-reviewed per the note this task itself left; all four sub-passes closed the same
      day (DSTU 9041 correctly excluded, no reference exists in either oracle - see the coverage
      matrix). **Net result: zero new defensive/stability gaps in this project's own code** across
      DSTU 4145/Kalyna/Kupyna/Strumok - every mechanism found in Bouncy Castle/UAPKI was already
      present, several already exceed both references (constant-time comparisons, stricter length
      checks). The one real finding from this audit is in a third-party reference implementation's
      own code, not this project's - see T-191 for its still-open private-disclosure status,
      unaffected by T-190's own closure here.

      **Original plan** (kept below for reference, executed as written): a
      defense/stability-focused comparison audit against the vendored reference implementations
      (`oracles/bouncycastle-{java,dotnet}/`, `oracles/uapki/` - both already cloned locally, no new
      fetch needed). **Explicitly scoped to the defensive/stability layer, not correctness** -
      `docs/ORACLES.md`'s existing oracle map already covers vector-level correctness
      cross-checking; this is a different axis: for each standard, read the reference
      implementation(s)' own frontend (input parsing/validation) and backend (internal arithmetic
      guards - invalid-point/degenerate-value rejection, error handling, resource/DoS limits) code,
      build a simplified diagram or pseudocode of *just the protective parts* (not the full
      algorithm - `docs/pseudocode/*.md` already has full transcriptions where they exist), and
      compare against this crate's own equivalent surface.

      **Real coverage matrix** (confirmed 2026-08-08 via `find` over both oracle trees - the
      original draft assumed all five algorithms had both references; two don't):

      | Algorithm | Bouncy Castle | UAPKI | Sub-pass |
      |---|---|---|---|
      | DSTU 4145 (sign) | `DSTU4145Signer`, `DSTU4145KeyPairGenerator`, `DSTU4145PointEncoder`, `DSTU4145NamedCurves` (+ generic `ECPoint`/`ECCurve.validatePoint`) | `dstu4145.c` (+ shared `ec.c`, `ec-internal.c`, `math-ec-point-internal.c`, `ec-default-params.c`) | dual-source |
      | Kalyna / DSTU 7624 | `DSTU7624Engine`, `DSTU7624WrapEngine`, `DSTU7624Mac` | `dstu7624.c` | dual-source |
      | Kupyna / DSTU 7564 | `DSTU7564Digest`, `DSTU7564Mac` | `dstu7564.c` | dual-source |
      | Strumok / DSTU 8845 | *(absent - confirmed no BC coverage, matches D-15's own note)* | `dstu8845.c` | UAPKI-only |
      | DSTU 9041 | *(absent)* | *(absent - confirmed, no `9041`/`edwards` file anywhere in `uapkic/src`)* | **N/A - close as not-applicable, no reference exists in either oracle; its own protective-clause audit already happened directly against the primary spec text, D-165/D-167** |

      **Don't read only the top-level algorithm file** - for both BC and UAPKI, the actual
      validation/guard code often lives one layer down in shared code the top-level file delegates
      to (e.g. BC's `DSTU4145PointEncoder.decodePoint`/`ECCurve.validatePoint`, UAPKI's `ec.c`/
      `math-ec-point-internal.c`) - reading just `dstu4145.c` or `DSTU4145Signer.java` alone risks
      wrongly concluding "no checks exist." For Kalyna/Kupyna, BC's `DSTU7624WrapEngine` and the
      `Mac` classes are the validation-dense files (length/block-alignment/uninitialized-state
      checks), not the bare `Engine`/`Digest`.

      **Per-sub-pass steps** (repeat for DSTU 4145, Kalyna, Kupyna, Strumok - in that order, see
      below):
      1. Grep `docs/DECISIONS.md`/`docs/TASKS.md` for this algorithm's own D-xx/T-xx history first,
         so the pass adds new findings instead of re-discovering D-63 (Kalyna-GCM nonce-binding),
         D-167 Findings 1/2 (DSTU 9041 invalid-curve/small-subgroup - reference only, not a sub-pass
         target itself per the table above), T-183/D-173 (`crypto_box` adversarial coverage, order-4
         still open), or T-189/D-172 (DSTU 4145 `verify`'s missing on-curve check).
      2. Read the reference implementation(s)' protective code per the file list above (plus
         whatever it delegates to) and write a short pseudocode/note of *just the protective parts*
         - not a full algorithm transcription.
      3. Compare against this crate's equivalent surface across **every entry point**, not just the
         Rust API: `hazmat::*`, the matching `crypto_*` wrapper, the `uacrypt` CLI, and -
         importantly, easy to skip - `crates/dstu-core-capi`'s raw-pointer/length C ABI, since a
         precondition unreachable from Rust's typed API can still be reachable through the FFI
         boundary the eight language bindings all sit behind.
      4. For each protective mechanism the reference has and ours doesn't, apply one discriminating
         question, not a vibe check: **can an attacker reach this state through our public surface
         (`crypto_*`, `hazmat::*`, `uacrypt`, the C ABI, or any binding)?** If yes, it's a real gap.
         If no - our API shape structurally forecloses it (e.g. no caller-facing nonce/mode knob to
         misuse) - record *why* in one line and move on; that's a valid audit output, not a shortfall.
      5. **For every gap judged real: write a failing test for it first (same D-64/D-65 rejection/
         misuse discipline, plus the T-183 4th adversarial category where it applies), confirm it
         fails, only then implement the fix** - same order the user set for T-189 this session, not
         a one-off for that task. Consult `advisor()` before the fix, same as T-189/T-183's own
         gaps. Verify under `small-tables` and re-check perf impact if the fix touches a hot path
         (T-189's own precedent). Document in `docs/DECISIONS.md`; spin off as its own T-19x if it
         doesn't fit as a sub-bullet here.
      6. Update this task's own entry with the sub-pass's outcome before moving to the next
         algorithm - same "close per sub-pass, don't wait for all five" posture as T-183.

      **Order**: DSTU 4145 first (dual-source, EC, confirmed hit rate this session - T-189 was
      exactly a missing on-curve check found by this style of reasoning), then Kalyna
      (`DSTU7624WrapEngine` is the densest validation file in BC), then Kupyna, then Strumok
      (UAPKI-only, smaller surface). DSTU 9041 is not a sub-pass (table above) - do not spend time
      on it here.

      **Sub-pass 1 (DSTU 4145) closed 2026-08-08, findings in `docs/DECISIONS.md` D-174.**
      Bouncy Castle: T-189's fix has exact parity with `ECPublicKeyParameters` →
      `validatePublicPoint` → `isValid()`'s cofactor-2 `satisfiesOrder()` branch - no new gap.
      The `g` (base point) side: checked whether the missing per-call validation there mirrors
      T-189's `q` exploit - analytic argument plus an empirical 200,000-trial probe (0 hits, not
      committed) both say no; `crypto_sign.rs` hardcodes `g = Point::generator()` regardless, so
      this is unreachable through any shipped surface either way - no code change, documented as
      checked-not-needed per this task's own step 4. **A third finding, in a third-party
      open-source reference implementation, not in this project's own code** - the same bug class
      T-189 fixed here. Being handled through private, responsible disclosure to that project's own
      maintainers, per this project's standing policy for anything involving a specific third
      party's own repository (D-91) - not this project's own code, not detailed further in this
      public repository while disclosure is pending. See T-191 and D-174/D-175 for status (full
      technical detail kept in local, untracked notes, not committed here).

      **Sub-pass 2 (Kalyna / DSTU 7624) closed 2026-08-08, zero new findings.** Read BC's
      `DSTU7624Engine`/`DSTU7624WrapEngine`/`DSTU7624Mac` (Java) and UAPKI's `dstu7624.c` for
      protective code (block-alignment checks, checksum/tag verification on unwrap, tag-comparison
      constant-time-ness, state-machine guards), then compared against every entry point:
      `hazmat::kalyna_{ccm,cmac,kw,gcm,gmac,xts,cfb}`, `crypto_secretbox`/`crypto_secretstream`,
      `uacrypt`, and `dstu-core-capi::{secretbox,secretstream}` (the C ABI, checked directly this
      pass - NULL/length/capacity checks present before any crypto work in both). Every protective
      mechanism found in either reference was already discovered and closed in a prior stage
      (D-54 KW/CMAC block-alignment and checksum check, D-55 KW round-counter fork bounded out,
      D-56/D-57 GCM/GMAC three AES-GCM divergences plus constant-time tag compare, D-58 XTS, D-60
      CFB panic->`Result`) - each of those stages was already individually cross-checked against
      these same two references at write time, so this pass mostly re-confirmed prior work. One
      item worth noting for the record, not a gap on our side: UAPKI's own KW unwrap
      (`decrypt_kw`, `dstu7624.c` ~line 3917) has no checksum verification at all, and its CCM/GCM
      tag comparisons (`dstu7624.c:2881`/`:3466`) are raw `memcmp`, not constant-time - both already
      fixed on our side (D-55, D-41/D-56) before this pass, so not new. No code change, no new
      D-xx entry needed (nothing to cite beyond the existing D-54..D-60 chain).

      **Sub-pass 3 (Kupyna / DSTU 7564) closed 2026-08-08, zero new findings.** Read BC's
      `DSTU7564Digest`/`DSTU7564Mac` and UAPKI's `dstu7564.c` for protective code (init/finalize
      state guards, key-length restrictions, message-length-counter overflow handling), compared
      against `hazmat::kupyna`/`kupyna_kmac`/`kupyna_kdf`, `crypto_generichash`/`crypto_auth`/
      `crypto_kdf`, `uacrypt hash` (re-confirmed still chunked per D-42, not whole-file `fs::read`),
      and `dstu-core-capi`'s hash FFI state machine (checked directly this pass - update-after-
      finalize/double-finalize both correctly rejected, matching D-118's established binding
      pattern). Every mechanism either reference has is present on our side, several exceed both
      references: constant-time KMAC verify (`subtle::ConstantTimeEq`, neither BC nor UAPKI's own
      `Mac`/hash API offers a `verify` at all - tag comparison is left to the caller in both), and
      stricter KMAC key-length enforcement than BC (BC accepts any key length and silently
      block-pads it, untested by either oracle's own vectors; ours requires exact-length match,
      matching UAPKI's own stricter check). One parity note, not a gap: BC's own `DSTU7564Digest`
      has an explicit, unaddressed `// TODO Guard against 'inputBlocks' overflow (2^64 blocks)`;
      our `KupynaCore.total_len: u64` shares the same theoretical overflow class (UAPKI's own
      128-bit counter is stricter than both) but is unreachable on any real target at
      `u64::MAX` bytes (~18 exabytes) - same non-exploitable classification already applied to
      BC's own TODO, not treated as a new finding. No code change, no new D-xx entry needed.

      **Sub-pass 4 (Strumok / DSTU 8845) closed 2026-08-08, zero new findings - T-190's four
      sub-passes now all closed.** UAPKI-only per the coverage matrix (no BC coverage exists,
      matches D-15). Read `dstu8845.c`'s `dstu8845_init`/`dstu8845_set_iv`/`dstu8845_crypt` for
      protective code: key length restricted to 32/64 bytes, IV length fixed at 32 bytes, both via
      `CHECK_PARAM`/`SET_ERROR(RET_INVALID_{KEY,IV}_SIZE)`. Compared against `hazmat::strumok`
      (`Strumok256::new(key: &[u8; 32], iv: &[u8; 32])` - fixed-size arrays make wrong key/IV
      length a compile-time error, not a runtime check, same "N/A by design" pattern already
      applied to Kalyna/Kupyna's own fixed-size-type arguments), `crypto_stream::decrypt` (already
      has its own `sealed.len() < IV_LEN -> StreamError::Truncated` check before slicing), `uacrypt
      strumok-crypt` (re-confirmed `STRUMOK_STREAM_CHUNK_BYTES` 8 KiB chunking is real, D-42), and
      `dstu-core-capi::stream.rs` (checked directly this pass - NULL-pointer and
      `sealed_len < DSTU_STREAM_OVERHEAD` truncation checks both present before any crypto work).
      No nonce/IV-reuse counter exists in UAPKI either (inherent stream-cipher caller
      responsibility, not a mechanism either reference implements, so not a comparison gap).
      **D-90/T-137 status confirmed, not rediscovered as new**: the vendored `oracles/uapki`
      copy of `dstu8845_crypt` (~line 1013) still carries the local, uncommitted, not-opened-
      upstream batched-consumption patch from T-137 in its own comment - a performance/style
      parity fix (matches `hazmat::strumok`'s own T-135 batched rewrite and
      `outspace/dstu8845`'s fused loop), not a defensive/validation gap, so out of scope for this
      audit's own criteria; disclosure status unchanged (still local-only, not proposed upstream).
      No code change, no new D-xx entry needed.
- [ ] **T-191** **Not started, owner-requested 2026-08-08.** Private, responsible-disclosure
      follow-up to the third-party finding from T-190/D-174 (same bug class as T-189/D-172, found in
      a different open-source project's own code, not this project's). **Owner's explicit order of
      operations: reproduce the forgery against that project's own real compiled binary FIRST, only
      then contact its maintainers, privately, with the reproduction and an example fix - not a
      source-reading trace alone.** Per D-91's standing policy, no public detail (project name,
      file/line trace, reproduction bytes) is recorded in this task while disclosure is pending -
      see local, untracked notes for the full technical record.

      **Reproduction step done 2026-08-08, confirmed - see `docs/DECISIONS.md` D-175.** Built a
      small, uncommitted test harness against that project's own official prebuilt binary release
      and confirmed, against its real compiled code (not source reading): a genuine honest signature
      verifies correctly (control case), and the same class of forged signature - a public key with
      no real private key behind it - is **also accepted**. The vulnerability is real and reproduced
      at the running-code level, not just inferred from reading source.
      **Next: draft the private disclosure itself for the owner's own review before anything is sent
      anywhere** - not this project's call to make unilaterally, per D-91.
- [x] **T-192** **Done 2026-08-08, owner-requested.** Add `l(p)=512` support to
      `hazmat::dstu9041` (E512/1) - the second curve size after `l(p)=256` (T-177/D-167), following
      the same phased, test-first, `advisor()`-reviewed pattern T-177 used (per this project's own
      Tier C precedent: no new primitive gets written from a "small parameter tweak" assumption).
      `advisor()` itself was unreachable when this plan was drafted (tool returned unavailable) -
      re-consult before Phase 1 code is written, don't treat this plan as pre-reviewed.

      **Why 512 next, not 384**: per `docs/pseudocode/dstu9041.md`'s Table 1, `l(p)=512` uses plain
      Kalyna-512/512-**KW** (`M'` lands exactly 512 bits, no padding) - `Kalyna512_512Kw` already
      exists (`hazmat::kalyna_kw.rs:261`), confirmed by grep this session, so no new cipher-mode
      primitive is needed. `l(p)=384` needs Kalyna-256/256-**KW-p**, a padding variant
      (`hazmat::kalyna_kw_p`) that does not exist yet - strictly more work, its own future task, not
      this one. `l(p)=768` stays permanently blocked - no worked example exists anywhere in the
      standard for it (D-168), so it lacks even the one oracle DSTU 9041 has ever had.

      **Phase 0 done 2026-08-08 - see `docs/DECISIONS.md` D-176.** E512/1's curve parameters
      transcribed from Table В.3's own page images and independently verified (decimal->hex
      cross-check, real 40-round Miller-Rabin primality on both `p` and `n`, `P` confirmed on-curve,
      `n*P == NEUTRAL` via a from-scratch port of `curve256.rs`'s own addition law). Confirmed
      `p = 2^512 - 875` (`p mod 8 = 5`, same congruence `fp256.rs`'s `sqrt` formula needs - carries
      over, checked not assumed) and cofactor 4 (independently re-derived via the Hasse-interval
      method, not copied from E256/1's Finding 2). Phase 1 (`fp512.rs`) unblocked, starting now.

      **Phase 1 done 2026-08-08 - see `docs/DECISIONS.md` D-177.** `fp512.rs` implemented as a
      direct 8-limb sibling of `fp256.rs`, test-first (`tests/dstu9041_field_512.rs`, 31 tests,
      confirmed failing to compile before `fp512.rs` existed, all pass unmodified after). New
      `tests/vectors/dstu9041/curve-E512-1.json` holds D-176's verified curve parameters so the
      field test's `p_hex()` reads from it rather than a hardcoded copy. `cargo clippy --all-
      features -- -D warnings`/`fmt --check`/`no_std` (`--no-default-features --features alloc`)
      build all clean; Kani proofs added mirroring `fp256.rs`'s own tractable subset, not yet
      run locally (D-102), CI is the real venue. Phase 2 (`curve512.rs`) next.

      **Phase 2 done 2026-08-08 - see `docs/DECISIONS.md` D-178.** `curve512.rs` implemented as a
      direct sibling of `curve256.rs`, test-first (`tests/dstu9041_curve_512.rs`, 14 tests,
      confirmed failing to compile before `curve512.rs` existed). Two real `BASE_Y`/`ORDER_N`
      byte-transcription bugs from hand-deriving the `[u8; 64]` arrays were caught by the test
      suite itself (`n_times_base_point_is_neutral` et al. failing), not by review - fixed by
      regenerating both arrays programmatically from D-176's verified decimal integers instead of
      re-deriving by hand a second time. `point_from_x` closes Finding 1/2 the same unified way
      `curve256.rs`'s current shape does (subgroup-membership check catches both). `cargo clippy
      --all-features -- -D warnings`/`fmt --check`/`no_std` build all clean. Phase 3 (message
      formatting) next - `advisor()` still unavailable this session, proceeding with a
      `message512.rs` sibling (consistent with `fp512.rs`/`curve512.rs`'s own precedent) rather
      than genericizing `message.rs`, re-visit if a stronger reason to genericize appears.

      **Phase 3 done 2026-08-08 - see `docs/DECISIONS.md` D-179.** `message512.rs` implemented,
      test-first (`tests/dstu9041_message_512.rs`, 9 tests). `format_m_tilde`/`encode_l_m_tilde`/
      `build_m_prime`/`parse_m_prime` follow directly from clauses 5.7/5.8/Table 1 with no
      ambiguity. `kw_plaintext_from_m_prime` marked **provisional** - ports `l(p)=256`'s confirmed
      "append one all-zero block" convention as a working hypothesis, not yet vector-confirmed
      against a Додаток Г.3 worked example (none transcribed yet). `cargo clippy --all-features
      -- -D warnings`/`fmt --check`/`no_std` build all clean. Phase 4 next: find/transcribe
      Додаток Г.3, confirm or correct the provisional KW convention, write `encryption512.rs`.

      **Phase 4 done 2026-08-08 - see `docs/DECISIONS.md` D-180. T-192 fully closed.** Found
      Додаток Г.3 (physical pages 32-35 of the scan). Caught the same "e=25 is hex (=37 decimal),
      not decimal" trap `g1-worked-example.json` had already documented for `l(p)=256` - hit it
      independently before noticing that prior note. Verified `R`/`Q`/`T`/`kappa`/`H` all match the
      document's own printed hex **exactly** (computed via this crate's own already-tested
      `curve512`/`message512`, not hand-transcribed digit-by-digit - the D-163/D-166 risk class).
      Confirmed the Phase 3 "M' || one zero block" hypothesis correct (matches the document's `t`
      to within 2 of 384 hex digits, same already-documented printing-erratum pattern
      `g1-worked-example.json` found for `l(p)=256` - not chased further given three other
      zero-digit-difference matches on the same page). `encryption512.rs` implemented, test-first
      (`tests/dstu9041_encryption_512.rs`, 20 tests mirroring `dstu9041_encryption.rs`'s four
      categories), all pass including the full worked-example encrypt/decrypt round trip. Full
      `cargo test -p dstu-core --lib --tests` (whole crate, not just the new files) clean;
      clippy/fmt/`no_std` all clean. `hazmat::dstu9041` now supports `l(p) in {256, 512}`.
      `l(p)=384` (needs `hazmat::kalyna_kw_p`) and `l(p)=768` (no worked example exists, D-168)
      remain out of scope, per this task's own plan. Wiring `l(p)=512` into `crypto_box`/`uacrypt`
      is a separate future task (T-178/D-169's own precedent for `l(p)=256`).

      **Post-push CI check (2026-08-08)**: `gh run list` on commit `6565272` showed `sonarcloud`
      FAILED - a real `new_duplicated_lines_density` gate failure (22.1% vs. 3% threshold), not the
      already-fixed T-188 missing-wait false negative. Root cause: the new `l(p)=512` sibling
      modules genuinely duplicate their `l(p)=256` counterparts textually (87-93% on the field/curve
      pair). Owner chose (via AskUserQuestion) to exclude these eight files from Sonar's CPD check
      rather than refactor into a shared generic - see `docs/DECISIONS.md` D-181.

      **Phase 0 - curve parameter transcription/verification (prerequisite, blocks everything else).**
      `docs/pseudocode/dstu9041.md` line 172 flags that Table В.3 (`λ=255`, the `l(p)=512` row) "exist
      in the scan but their first entries were not independently arithmetically verified this pass" -
      unlike Table В.1 (`l(p)=256`), which got the full stroke-counted transcription D-163/D-166
      describe. Before any Rust is written: re-read Table В.3's page image directly (`pdftoppm` PNG,
      per D-163's method), transcribe `p`/`a=2`/`d`/`n`/`P`, and apply the exact same
      character-run-counting discipline D-163/D-166 already learned the hard way (a `p`/`n` erratum
      from a miscounted `F`/`0` run sat undetected for two sessions in the `l(p)=256` case) - do not
      assume this size is exempt just because it's a second pass at the same document. Cross-check
      the transcribed `p` for primality (real Miller-Rabin, not a 3-base Fermat check, same fix D-166
      already applied once) and cross-check `P` against Додаток Г.3's own worked example (`ε·P`,
      `ε·Q` computations) the same way `l(p)=256`'s Додаток Г.1 served as its check.

      **Phase 1 - `fp512.rs`.** Inspect the transcribed `p`'s actual bit structure once Phase 0 lands
      before choosing a reduction strategy - `fp256.rs`'s Solinas-style reduction exploited
      `2^256≡435 (mod p)` specifically because `p=2^256-435` has that pseudo-Mersenne-adjacent shape;
      do not assume the `l(p)=512` prime has an equally convenient form without checking - fall back
      to generic Barrett/Montgomery reduction if it doesn't. Same API shape as `fp256.rs`
      (`multiply`/`square`/`invert` via Fermat/`sqrt`+`euler_criterion` via `p≡5 (mod 8)` if that
      congruence still holds for this `p` - verify, don't assume/`pow_mod` fixed-iteration
      constant-time ladder, iteration count matching this `p`'s actual bit length).

      **Phase 2 - `curve512.rs`.** Same twisted-Edwards curve shape as `curve256.rs` (`a=2` fixed,
      the same x/y-role-swap relative to Bernstein-Lange - Додаток В's own convention, not size-
      dependent), Додаток Б.4's complete addition law, fixed-iteration `scalar_multiply`.
      **Independently re-derive the cofactor and small-subgroup structure for E512/1 - do not port
      Finding 2's "cofactor 4" conclusion from E256/1 by assumption.** D-167's Finding 2 proof
      (`#E(F_p)` is the unique multiple of `2n` inside the Hasse interval, checked exhaustively for
      small `k`) is a general method, not a size-specific result - re-run it against this curve's own
      `p`/`n`. Likewise re-derive whether `r=p-1` (or any other small closed-form `r`) reconstructs an
      order-2/order-4 point outside `⟨P⟩` for this curve's own parameters (Finding 1) - the *shape* of
      both findings likely recurs (same curve family, same construction), but the concrete guard
      conditions must be re-proved against E512/1's own numbers, not copy-pasted from `curve256.rs`.

      **Phase 3 - message formatting for `l(p)=512`.** `message.rs` is currently hardcoded to
      `l(p)=256` (`L_MAX_P=200` bits, `L_H_BYTES=4`, fixed `[u8; 32]` `M'` - confirmed by reading the
      file this session). For `l(p)=512`: `l_max(p)=424` bits, `l_H=64` bits (8 bytes), `M'` totals
      exactly 512 bits = 64 bytes (`8 + 64 + 16 + 424`, matching the KW no-padding row). Decide in
      this phase whether to genericize `message.rs` (const-generic over `M_TILDE_BYTES`/`L_H_BYTES`)
      or add a sibling `message512.rs` - a real design choice, not a foregone one; consult
      `advisor()` on it given both `fp256.rs`/`curve256.rs` and the message layer would otherwise
      diverge in shape (siblings) vs. converge (generics) for the first time this project has had two
      instances of a parametrized primitive to compare.

      **Phase 4 - `encryption512.rs` (or its generic equivalent per Phase 3's decision).** Clauses
      11/12 composition, wired to `Kalyna512_512Kw` (no new KW-p work, per the "why 512 next" note
      above). Verify end-to-end against Додаток Г.3 - the sole oracle for this primitive, same
      "no independent DSTU 9041 reference implementation exists anywhere" caveat D-167 already
      recorded, re-confirmed at this task's own closure too, not assumed still true from memory.

      **Every phase**: test-first per `docs/DECISIONS.md`'s standing D-64/D-65 rejection/misuse
      discipline, plus the T-183/D-173 4th "active-attack" category (invalid-curve, twist,
      boundary-seed inputs - `docs/TASKS.md`'s own memory note on this) since this is exactly the
      asymmetric/EC primitive class that category was written for. `advisor()` consultation before
      Phase 1 (blocked on Phase 0 landing) and after Phase 2/3 findings, same cadence T-177 used
      (before Phase 2, after Phase 3/4, at closure) - re-attempt the tool each time rather than
      treating today's outage as permanent.

      **QA gate** (mirrors T-177's own closure exactly, D-167): full-workspace
      `clippy --all-features -- -D warnings`/`fmt --check`; scoped `cargo +nightly miri test -p
      dstu-core --test dstu9041_field_512 --test dstu9041_curve_512 --test dstu9041_encryption_512
      --test dstu9041_message` (or the generic equivalent's test file names) with
      `PROPTEST_CASES` cut down per this project's own Miri-speed gotcha (`CLAUDE.md`'s "Agent
      discipline"); Kani proofs for `fp512.rs`'s bounded field ops (`select`/`conditional_sub_p`/
      `add`/`sub`/`reduce_wide`), same tractable subset `fp256.rs`'s Kani harness already covers, not
      full `multiply` symbolic equivalence (D-112's already-established intractability for this
      multiplier-equivalence class). Kani cannot run on this Windows dev machine (D-102) - CI is the
      real venue, verify its actual conclusion via `gh run view`, never assume from a green badge
      (`CLAUDE.md`'s own standing rule).

      **Explicitly out of scope for this task**: wiring `l(p)=512` into `crypto_box` or the `uacrypt`
      CLI (T-178/D-169 did this separately for `l(p)=256`, after `hazmat::dstu9041` itself landed -
      same split here, a later task if wanted); `l(p)=384`/`768` (see "why 512 next" above).
- [ ] **T-193** **Not started, owner-requested 2026-08-08.** Wire `l(p)=512`
      (`hazmat::dstu9041` E512/1, T-192) into `crypto_box`/`uacrypt`, mirroring what T-178/D-169 did
      for `l(p)=256` - the deferred item T-192 explicitly left out of scope. Prerequisite for T-194
      (the combined perf table the owner actually asked for); split into its own task ID rather than
      bundled, per the project's own "plans persist in repo, owner controls step ordering"
      precedent, and per `advisor()`'s explicit recommendation this session.

      **Phase 0 - seed/KDF design decision (resolve before any code, don't let copy-paste settle
      it, flagged by `advisor()` as the one blocking decision)**: `crypto_box.rs`'s `embed_seed`
      (`32 - SEED_LEN..`, `SEED_LEN = L_MAX_P/8 = 25` at `l(p)=256`) does not generalize to
      `l(p)=512` - `L_MAX_P512 = 424` bits / `SEED_LEN512 = 53` bytes is *larger* than the 32-byte
      `Kupyna256Kdf` input, so `32 - 53` underflows; a naive copy-paste panics in debug and is UB-
      adjacent in release. Resolution: don't use the full 424-bit KEM capacity at `l(p)=512` - draw
      a 32-byte seed directly (matching `Kupyna256Kdf`'s native width exactly, no embedding step
      needed at all), call `dstu9041_encrypt(&seed, 256, recipient, &epsilon)` (fixed
      `message_bits = 256`, not `L_MAX_P512`), and on `open`, check the returned bit length is
      `256` (not `L_MAX_P512`) before slicing the low-order 32 bytes of the recovered 53-byte
      `M~` out as the seed. Verify empirically first that `encryption512::decrypt` really does
      return the *encryptor-supplied* bit length (256), not the buffer width (424) - the module doc
      states this but confirm against the actual code/tests before relying on it. Record this as a
      `docs/DECISIONS.md` entry once resolved - a design choice, not an accident.

      **Phase 0 done 2026-08-08 - see `docs/DECISIONS.md` D-182.** Confirmed by reading
      `message512.rs` directly (not assumed from the doc comment): `format_m_tilde` requires an
      exact `message.len() == message_bits.div_ceil(8)` match, and `parse_m_prime`'s returned
      `bit_length` is read back from a hash-authenticated `l_m_tilde` field the encryptor itself
      set - genuinely encryptor-supplied, not the buffer's fixed width. Adopted the 32-byte/256-bit
      fixed-width seed design.

      **Phase 1 - `crypto_box512.rs`**: direct sibling of `crypto_box.rs` at `l(p)=512`'s widths
      (`SecretKey`/`PublicKey` as `[u8; 64]`, `KEM_CIPHERTEXT_LEN = 256`, everything else - `Vec<u8>`
      wire format, `crypto_secretstream` chunking, error collapsing posture (D-56/D-63), `PublicKey`
      compression argument - carries over unchanged, re-derive the `x`-only compression safety
      argument for E512/1 specifically per this project's own "don't assume it carries over"
      discipline (already done once for Finding 1/2 in D-176/D-178, same standard applies here).
      Test-first, mirroring `tests/crypto_box.rs`'s 17 tests (correctness/round-trip, rejection/
      tamper, misuse/degenerate) **plus the T-183 fourth "active-attack" category**
      (`feedback_active_attack_test_category` - invalid-curve/twist/boundary-seed cases,
      `PublicKey512::from_bytes` reusing `curve512::point_from_x`'s existing gauntlet rather than a
      second copy). Note the wire-format collision: a `box-open`-length-valid `l(p)=512` sealed blob
      also clears `box-open`'s own `MIN_LEN` check and falls through to `InvalidCiphertext` rather
      than a distinct "wrong curve size" error - defensible under the existing error-collapsing
      posture, but record it as a stated decision, not leave it to be found by surprise.

      **Phase 2 - CLI wiring**: new `uacrypt` subcommands `box-keygen512`/`box-pubkey512`/
      `box-seal512`/`box-open512` - distinct named subcommands, not a `--curve` flag on the existing
      ones (D-47 "delete the knob" - `advisor()` confirmed no argument against this).

      **Phase 3 - doc sync, done in the *same* commit as Phase 1/2, not a follow-up** (D-159's own
      failure class, flagged explicitly by `advisor()` this session):
      - `sonar-project.properties`'s `sonar.cpd.exclusions` (D-181) - add `crypto_box512.rs`, it
        will be a near-duplicate of `crypto_box.rs` just like the eight `hazmat::dstu9041` files
        already excluded.
      - `CLAUDE.md`'s `crypto_box` bullet ("`l(p)=256` only") - update or explicitly scope.
      - `CLAUDE.md`'s "every binding wraps the full `crypto_*` surface as of \[date\]" and the
        `dstu-core-capi` paragraph's "wraps the full `crypto_*` surface" - both go stale the moment
        a new `crypto_*` module exists that the eight bindings/capi don't wrap. State explicitly
        that binding/capi wiring for `crypto_box512` is out of scope for this task (a later task if
        wanted, same split T-181 already used for `crypto_box` itself), and correct both sentences
        to say so rather than leaving them silently wrong.
      - `docs/dstu-crypto-project.md`'s "Concrete API shape" checklist.

      **Explicitly out of scope**: binding/capi wiring for `crypto_box512` (separate future task,
      see Phase 3 above); `l(p)=384`/`768` (T-192's own scope note still applies).

      **T-193 done 2026-08-08 - see `docs/DECISIONS.md` D-182 (Phase 0) and D-183 (Phases 1-3).**
      `crypto_box512.rs` implemented (direct sibling of `crypto_box.rs` at 64-byte widths, fixed
      32-byte/256-bit seed per D-182), test-first (`tests/crypto_box512.rs`, 17 tests mirroring
      `tests/crypto_box.rs`'s own suite including the T-183 active-attack category - all passed on
      first run). `uacrypt box-keygen512`/`box-pubkey512`/`box-seal512`/`box-open512` CLI wired
      (distinct subcommands, not a `--curve` flag, per D-47) plus a dispatch-level integration
      test. `sonar-project.properties`/`CLAUDE.md`/`docs/dstu-crypto-project.md` all updated in the
      same pass, not deferred. Full `cargo test -p dstu-core`/`cargo test -p uacrypt` clean;
      `cargo clippy --all-features -- -D warnings` clean on both crates; `cargo fmt` clean
      (one auto-reformat applied, not reverted, per the project's own linter-output convention);
      `no_std`/`alloc` build clean. `hazmat`/`no_std` Kani/miri harnesses untouched by this task
      (`crypto_box512` is `std`-gated, same as `crypto_box`).
- [x] **T-194** **Done 2026-08-08, owner-requested. Was blocked on T-193, now unblocked -
      T-193 done.** Combined
      `l(p)=256`/`l(p)=512` performance table for `crypto_box`/`crypto_box512`, per owner's explicit
      choice (both sizes in one table, full `seal`/`open` regime, not a narrower hazmat-only
      benchmark) over `AskUserQuestion` this session. Extends T-179's own two-table pattern
      (primitive-level ops/s + full-construction MB/s, D-34/D-170) to cover both curve sizes at
      once, not a fresh methodology.

      **Do not reuse T-179's existing `l(p)=256` numbers as-is** - `advisor()` flagged this
      explicitly: they predate T-192/T-193 and several other commits, so splicing stale 256 numbers
      next to fresh 512 numbers is not a valid same-session comparison. Re-measure `l(p)=256`
      alongside `l(p)=512` in the same sitting, on the same machine, after a forced rebuild (D-161's
      stale-bench-binary trap - `touch` the changed file or verify binary symbols, don't trust
      `cargo`'s own change detection across any preceding `git stash`/branch-switch).

      **Primitive-level (ops/s)**: `uacrypt box-seal512`/`box-open512` (from T-193) vs. `openssl
      speed ecdh`'s closest ~512-bit row. Verify which curve `openssl speed ecdh` actually lists
      before designing the table - do not assume `brainpoolP512r1` is present; `secp521r1` (521-bit,
      closest available) is the fallback per `advisor()`.

      **Full-regime (MB/s, 10 MiB)**: `crypto_box512` `seal`/`open` vs. `openssl cms -encrypt`/
      `-decrypt` with an EC recipient sized to ~512 bits - **verify empirically which curve actually
      round-trips through `openssl cms`'s ECDH-KDF path** before committing to a table column
      (`secp521r1` is the safer bet than `brainpoolP512r1` per `advisor()` - don't assume either
      works without testing). Re-apply the already-learned gotchas without rediscovering them:
      `-binary` on both `-encrypt`/`-decrypt` (silent truncation at `0x1A` otherwise),
      `MSYS_NO_PATHCONV=1` on `-subj` in Git Bash, and a byte-for-byte `cmp` round-trip check before
      trusting any timing number.

      **Platform scope**: dev machine (Ryzen) **and** the Raspberry Pi
      (`[[raspberry-pi-uacipher]]`/`.claude.local.md`) - owner explicitly asked for the Pi row too
      via `AskUserQuestion` this session, not dev-machine-only like T-179's original table.

      **T-194 done 2026-08-08 - see `docs/PERFORMANCE.md`'s "DSTU 9041 / `crypto_box` +
      `crypto_box512`" section (T-179/T-194) for the full tables/methodology, `advisor()`
      consulted before starting per its own recommendation.** Both `l(p)=256` and `l(p)=512`
      re-measured fresh this session (old T-179 numbers not reused); dev-machine + Pi both
      confirmed via a fresh `cargo build --release -p uacrypt` and `--help | grep 512` before any
      number was trusted (the Pi's `tar`+`ssh`-synced copy had no `crypto_box512` at all until
      re-synced this session, since T-193 landed the same day). `openssl speed ecdh` confirmed
      `brainpoolP512r1` present on both machines (no `secp521r1` fallback needed); `openssl cms`
      confirmed to round-trip through `brainpoolP512r1` before timing anything. Two discriminating
      sanity checks both passed: MB/s at 10 MiB is flat between `l(p)=256`/`l(p)=512` on both
      `uacrypt` and OpenSSL's side (confirms `crypto_box512` genuinely reuses the D-182 bulk path,
      not a measurement artifact), and primitive-level ops/s drops substantially (~6.5-8x) from
      `l(p)=256` to `l(p)=512` (confirms the KEM work is actually inside the timed loop, not
      hoisted out, D-80's failure shape). The two-scalar-mult-per-call caveat was independently
      re-derived against `curve512.rs`/`encryption512.rs` directly, not assumed to carry over from
      the `l(p)=256` write-up - same shape confirmed. New finding not in the original task text:
      OpenSSL's own `openssl.exe` process-spawn overhead is roughly half of each Windows
      dev-machine CMS call's own wall-clock time (~40 ms of an ~83-91 ms 10 MiB call), but
      negligible on the Pi (~3.6 ms) - Linux process creation being far cheaper than Windows',
      explaining part of why the dev machine and Pi disagree on which side wins (OpenSSL ~7.5-8.7x
      faster on the dev machine, `uacrypt` roughly competitive - within ~10-20% - on the Pi, the
      same kind of platform reversal already seen for Kalyna/Kupyna vs. UAPKI, D-33) - not
      root-caused further, out of this measurement task's own scope. `cargo xtask docs-check`
      clean. **Not done this pass, flagged for the owner instead**: the gh-pages landing page
      (`index.html`, separate worktree/branch, `C:\Users\Pa\AppData\Local\Temp\uacrypt-ghpages`)
      has its own stale `crypto_box` perf line ("~3.3-4.2x slower [...] the raw elliptic-curve math
      alone is close to parity") and an outdated "the standard also defines 384/512/768-bit
      variants, not yet implemented" note (now wrong for `l(p)=512` since T-192/T-193) - both
      predate this task, not introduced by it, but surfaced by this session's grep sweep; left
      unedited since a published-site edit felt like it needed explicit sign-off rather than a
      silent same-pass fix, unlike `docs/PERFORMANCE.md`/this file.
- [x] **T-195** **Done 2026-08-08, owner-requested follow-up to T-194 - word-wise `reduce` landed as
      real code this session (see below); Tier 2 (EC windowing) remains plan-only, owner to decide.**
      Owner asked two things: (1) re-run the `crypto_box`/`crypto_box512` MB/s comparison with a
      large enough payload to neutralize `openssl.exe`'s own process-spawn overhead (T-194's 10 MiB
      pass had this confound; see `docs/PERFORMANCE.md`'s corrected table), and (2) investigate *why*
      this project is slower than OpenSSL with an actual algorithmic-complexity breakdown ("де ми
      платимо, де не платить опенссл") and draft an improvement plan mirroring the `fused`/
      `small-tables` space-vs-speed precedent ("так само як із смол тейблс, буде оця реалізація -
      повільна і перфоманс").

      **Payload-size history this session**: started at 1 GiB (fully neutralizes spawn overhead,
      confirmed - OpenSSL's reported MB/s roughly doubled vs. the 10 MiB pass once neutralized), but
      the Raspberry Pi ran out of disk space mid-run at that size (`[[raspberry-pi-uacipher]]`'s
      `/dev/mmcblk0p2` is a 28G card, was already at 100% after the 1 GiB scratch files) - owner then
      asked to drop to 100 MiB instead and clean up scratch files on both machines afterward.
      100 MiB is still ~2500x the ~40 ms dev-machine spawn-overhead floor, so it stays fully
      neutralized; freed the Pi's disk (`rm` on the 1 GiB scratch files, `df` confirmed 4.2G
      recovered) before re-running there. **`docs/PERFORMANCE.md`'s main `crypto_box` table keeps its
      already-good 1 GiB dev-machine numbers** (redoing already-correct, already-neutralized
      measurements just to shrink the file would have been pure waste) **and gets its Pi row filled
      in at 100 MiB instead** (both sizes independently confirmed spawn-neutralized, so mixing them
      across the two machine columns is an honest, explicitly-labeled choice, not a hidden regime
      mismatch). All scratch payload/output files deleted on both machines after use (dev machine:
      `rm payload1g* payload100m* payload10m* ...` in the scratchpad `perf194` dir; Pi: same, plus the
      benchmark shell script self-deletes its own scratch files at the end of its run) - `~/perf194`
      on the Pi now holds only the small persistent keys/certs, not any of the multi-hundred-MB
      payloads.

      **`advisor()` consulted before the complexity investigation and gave the load-bearing
      redirect**: the EC/KEM layer was the wrong axis entirely. At bulk-message scale the two KEM
      scalar multiplications cost ~0.3 ms each against a multi-second call (~0.001% of total time,
      confirmed against this task's own primitive-level ops/s table) - no EC-side optimization could
      move the bulk MB/s number, no matter how much faster it made the EC math. Also: at the
      primitive level this project is *already ahead* of OpenSSL's field-matched curve (`box-seal`
      3355.93 ops/s vs. `brainpoolP256r1`'s 2906.0, while doing two scalar mults per call to their
      one) - the EC layer is not where the gap is. Redirected to decompose the *symmetric* layer
      instead, and separately flagged that the CMS 1 GiB numbers might be an I/O ceiling rather than
      a crypto one, needing a raw-cipher check to rule out.

      **Tier 1 (explains the owner's actual MB/s number) - symmetric-layer decomposition, done and
      published, corrected mid-session after owner pushback**: see `docs/PERFORMANCE.md`'s "Where the
      gap actually comes from" subsection (T-194 follow-up) for the full table/method and the
      correction note. **First version of this analysis was wrong**: it stopped at Kalyna-GCM
      (14.25/15.90 MB/s) and concluded "Kalyna itself is the ceiling, an AES-NI-vs-no-hardware-
      instruction ISA gap" - the owner pushed back ("в нас калина була сотні мегабайт на секунду"),
      correctly, from memory. Adding a `kalyna-xts` row (no authentication tag at all - pure block
      cipher, same variant/payload) caught it: the bare cipher reaches **163.82/155.55 MB/s**, ~10x
      faster than Kalyna-GCM. **The actual bottleneck is Kalyna-GCM's own GF(2^256) authenticated-tag
      multiply** - `hazmat::gf2m_wide`'s field multiply, the GCM/GMAC accumulator against the real
      field element `H` (D-56 divergence 3) - already isolated-timing-measured at 89.6% (m=128) to
      94.3% (m=512) of GCM's entire per-block cost in an *earlier* session (T-125/D-76, 2026-07-26,
      already improved once there, ~1.8-2.3x, via a 4-bit-window comb multiply) that this session
      failed to reconnect to before writing the first version of this analysis - this session's own
      14.25-15.90 MB/s number matches the already-published post-T-125-fix 256-256 GCM number
      (17.09-17.17 MB/s at 10 MiB) within normal sampling noise, so it was a correct measurement with
      a wrong causal story attached, not a new bug. **Corrected conclusion**: `crypto_box`'s full
      stack (16.32/16.98 MB/s) is not measurably slower than bare Kalyna-GCM, confirming the KEM/
      framing are not the ceiling as before - but Kalyna-GCM itself is ~10x slower than the bare
      cipher specifically because of its tag multiply, not because Kalyna the cipher lacks hardware
      support. Symmetrically, raw `openssl enc -aes-256-cbc` (261.78/402.44 MB/s) being faster than
      full CMS (205.59/296.45 MB/s) still answers `advisor()`'s I/O-vs-crypto-bound question the same
      way as before (a real crypto/envelope gap, not an I/O ceiling). One small, real, secondary
      finding, unaffected by the correction: `crypto_secretstream`'s own decrypt path runs ~28%
      slower than raw Kalyna-GCM's own decrypt, reproduced independently at both 1 GiB and 100 MiB -
      a genuine small `crypto_secretstream` decrypt-path question worth a future look, but far too
      small to explain the overall gap on its own.

      **Tier 1 recommendation, corrected: the Kalyna-cipher-vs-AES-NI framing is retired - the cipher
      itself (~155-164 MB/s via XTS) is not the open question, and this project's own T-129/D-88 and
      T-139/D-87 already closed that specific investigation with no code change.** The real, corrected
      lever is the GCM/GMAC tag's own field multiply, and unlike the cipher question, **this is not a
      closed investigation** - `hazmat::gf2m_wide::poly_mul_wide`'s 4-bit-window comb method (T-125's
      own fix) was never compared against a hardware carry-less-multiply instruction (`PCLMULQDQ` on
      x86-64, `PMULL` on AArch64), which is exactly the mechanism AES-GCM's own GHASH uses on any
      x86-64 CPU built since ~2010 - a real, unexplored, precedented lever, not a dead end. **Not
      picked up as code this session** (a genuine new investigation - target-feature detection,
      `no_std`-compatibility of any `core::arch` intrinsics used, a fallback path for targets without
      the instruction, and its own `--emit=asm`/spike pass per T-129/T-139's standing precedent -
      needs its own scoping and `advisor()` consultation, not folded into this task's close-out).
      Document the corrected gap as: cipher vs. cipher is a modest, already-investigated, largely-
      closed gap (same class as the already-published Strumok-vs-AVX2-ChaCha20 ~1.6-1.7x gap); tag
      multiply vs. hardware GHASH is the real, larger, and still-open ISA-level lever.

      **Tier 1 spike, same session, `advisor()`-directed before touching `poly_mul_wide`**: before
      picking a hardware-CLMUL rewrite, checked whether `Self::reduce` is still "a small fraction" of
      `Gf2m256::multiply()` as `hazmat::gf2m_wide`'s own module doc claimed - that claim was measured
      against the *pre-T-125* bit-serial multiply (~16,384 word-ops at m=512), a comparison that no
      longer holds now that `poly_mul_wide` is the 4-bit comb method. Extended the existing
      `#[ignore]`d diagnostic harness (`isolated_timing_gf2m256_poly_mul_wide_vs_reduce_split`,
      `gf2m_wide.rs`) rather than building a new one - project-sanctioned shape, throwaway/manual-
      timing, no production code touched. **First version of this diagnostic was itself wrong**:
      timed `poly_mul_wide`/`reduce` on fixed, non-chained inputs, which let the CPU pipeline
      independent iterations and undercounted both terms by ~2x relative to the sibling test's
      chained `multiply()` number - fixed by chaining each sub-loop's output back into its own next
      input, matching `kalyna_gcm`'s real `acc = acc.add(...).multiply(h_key)` accumulator pattern.
      **Corrected, reproduced twice**: `reduce` is **~62-64% of `multiply()`'s total** at m=256 (two
      runs: 61.7%/63.6%, `poly_mul_wide` ~476-520 ns/op, `reduce` ~832-838 ns/op) - now the *larger*
      term, inverted from the stale doc-comment claim. Updated `hazmat::gf2m_wide`'s module doc
      comment in place to record this (it had explicitly said "revisit only if a future measurement
      shows otherwise" - this is that revisit).

      **Consequence for the Tier 1 recommendation above**: a hardware carry-less-multiply rewrite of
      `poly_mul_wide` alone, even at zero marginal cost, could only ever remove ~38% of `multiply()`'s
      current time - `reduce`'s bit-at-a-time top-down loop (up to `2m-1` iterations, each a
      conditional branch plus up to 4 word `XOR`s) is the bigger term. `advisor()`'s own suggested
      cheaper first lever: m=256's pentanomial terms are `10/5/2/0` and m=512's are `8/5/2/0` - all
      `< 64` - so a word-wise closed-form fold-down (the same shape `gf2m163::reduce` already uses,
      re-derived per field size rather than reused directly) replaces the bit-serial loop with pure
      Rust, no `target_feature`/`no_std` fork, no fallback-path design burden, and helps the
      Raspberry Pi row too (CLMUL requires `PMULL` detection there; a word-wise `reduce` doesn't).
      Order-of-operations: **word-wise `reduce` first, hardware CLMUL for `poly_mul_wide` second**
      (re-measure the split after the first lever lands, since it changes the ratio the second lever
      is evaluated against) - **picked up immediately, same session, owner asked "реалізуй word-wise
      reduce, test-first."**

      **Word-wise `reduce`, implemented test-first, `crates/dstu-core/src/hazmat/gf2m_wide.rs`**:
      - Added a free `const _: () = assert!($f1 > 0 && $f1 < 64 && ...)` per field-size
        instantiation - the word-wise fold-down's `t << shift` / `t >> (64 - shift)` split is only
        UB-free if every pentanomial term is strictly between 0 and 64; checked at compile time
        instead of trusted by inspection of the three macro invocations' literal arguments.
      - Renamed the old bit-serial `reduce` to `reduce_bit_serial_reference`, gated
        `#[cfg(any(test, kani))]` (dead code in a release build) - kept as the already-years-verified
        oracle for the new implementation rather than deleted, same "keep the old path as a test
        oracle" shape `gf2m163`'s own history uses.
      - New `reduce`: for word index `i` from `$limbs2 - 1` down to `$limbs`, the whole word
        `T = c[i]` folds down in one step (`base = i - $limbs`; XOR `T`, `T << f1`, `T << f2`,
        `T << f3` into `c[base]`, with each shift's carry-out XORed into `c[base + 1]`) instead of
        64 bit-at-a-time steps - top-down word order guarantees every word a later iteration reads
        has already received every contribution aimed at it, since a contribution from word `i`
        only ever lands in words strictly below `i` (`$limbs >= 2` in all three instantiations).
      - **Test-first**: wrote the differential proptest and two fixed-input regression tests
        (`reduce_matches_bit_serial_reference`, plus all-zero/all-ones wide-input edge cases) against
        `reduce_bit_serial_reference` in the same pass as the implementation, extending
        `field_axiom_tests`'s existing `arb_element()` pattern with a new `arb_wide()` strategy (the
        actual double-width input type `reduce` takes, which the old `arb_element()` never covered).
        All pass, all three field sizes, ~256 proptest cases each.
      - **Exhaustive verification**: added `#[cfg(kani)] mod kani_proofs` (new to this file, mirrors
        `gf2m163`'s own `kani_proofs` module) proving `reduce == reduce_bit_serial_reference` for
        *every* possible double-width input, all three field sizes - reusing the real, already-
        verified old implementation as the oracle rather than writing a fourth from-scratch
        reference. **Cannot run on Windows at all** (D-102) - written following the established
        macro/proof-shape precedent but not locally executed; CI (Linux) is the actual verification
        venue, not yet confirmed green as of this session's close (re-check via `gh run view` once
        pushed, per the standing "verify CI's real conclusion" rule).
      - **Regression check**: full `cargo test` (41 test binaries + doctests, 0 failures), the
        official Kalyna-GCM/GMAC/XTS vectors for all five variants (unaffected - GCM/GMAC's tag
        computation routes through the same `multiply()` call, just faster now), `clippy -D
        warnings`, `fmt --check`, and both feature-matrix builds (default, `small-tables`, `no_std`)
        all clean.
      - **Real, built-binary, measured result** (not projected): `uacrypt kalyna-gcm` at
        `--variant 256-256`, 100 MiB payload, 5 iterations, same machine/methodology as the pre-fix
        row in `docs/PERFORMANCE.md`'s layer-decomposition table - **14.25 -> 34.96 MB/s encrypt
        (~2.45x), 15.90 -> 30.16 MB/s decrypt (~1.90x)**. `reduce`'s own isolated cost (chained
        timing split, same diagnostic as the spike above) dropped from ~62-64% of `multiply()`'s
        total to ~2.7% (17.6 ns/op vs. ~832-838 ns/op at m=256). See `docs/PERFORMANCE.md`'s "T-195's
        word-wise `reduce` lever" subsection for the full table and the reopened-CLMUL-question note
        (`poly_mul_wide` is back to being ~97%+ of `multiply()`'s remaining cost now that `reduce`
        isn't competing for the larger share, closer to T-125's original ~89.6-94.3% estimate than
        this session's own pre-fix "at most 38%" spike number, which was only ever valid against the
        *unfixed* `reduce`).
      - Scratch payload/output files (`payload100m.bin`, `gcmkey.bin`, etc., dev-machine scratchpad
        `perf195` dir) deleted after use, matching this task's own established cleanup discipline
        from the payload-size-history section above; not run on the Raspberry Pi this pass (not
        asked, and the fix is machine-independent pure-Rust code with no platform-specific path to
        separately confirm - CLMUL, if picked up later, is the one that would need its own Pi check).

      **Tier 2 (the owner's actual "smol tables" analogy, and the right frame for the primitive-level
      table specifically - real, but does not move the bulk MB/s number, per the redirect above) -
      EC scalar-multiplication cost breakdown, plan only, no code changed**:
      - Read directly (`crates/dstu-core/src/hazmat/dstu9041/curve256.rs`/`curve512.rs`), counted by
        hand, not estimated: `scalar_multiply` is a fixed 256-iteration (512 at `l(p)=512`) double-
        and-select loop with **no separate doubling formula** - every iteration does an
        unconditional double (`acc.add(acc)`) *and* an unconditional candidate add (`acc.add(base)`),
        both routed through the same general "complete" projective addition law (Додаток Б.4),
        counted at **13 field multiplications per point operation** (`zz`, `b=square`, `c`, `dd`,
        `e=d*c*dd` (2), `cross`, `x_r` (3), `y_r` (2), `z_r` - 13 total). 256 iterations x 2 ops x 13
        mults = **6656 field multiplications per `l(p)=256` scalar-multiply call**, no windowing/NAF.
        `fp512.rs`'s 8-limb `wide_mul` (64 inner products vs. `fp256.rs`'s 4-limb/16) combined with
        512 iterations (2x) closely matches this task's own measured ~6.5-8x ops/s drop from
        `l(p)=256` to `l(p)=512` - the measured primitive-level gap is explained by this, not a
        separate mystery. `fp{256,512}.rs`'s modular reduction already exploits the friendly
        `p = 2^{256,512} - C` pseudo-Mersenne shape (cheap, not a target). `square()` calls
        `multiply(self, self)` with no dedicated squaring routine (a well-known ~30-40% multiply-
        count reduction is available and unclaimed here - the smallest, lowest-risk lever if this is
        ever picked up). `invert()` (Fermat via `pow_mod`, ~512 field ops) is called once per
        `scalar_multiply` in `to_affine` - ~7-8% of one call's cost, a real but secondary lever.
      - OpenSSL's own generic (non-assembly-optimized) EC path - confirmed via a direct source read
        of `crypto/ec/ec_mult.c` this session, not assumed from memory: constant-time single-scalar
        multiplication (the ECDH-shaped operation `openssl speed ecdh` measures) uses a Montgomery-
        ladder-with-conditional-swaps (`ossl_ec_scalar_mul_ladder`), and - the confirmed structural
        difference from this project's own code - `EC_POINT_dbl`/`EC_POINT_add` are **separate**,
        curve-method-specific formulas "potentially using different formulas for efficiency," i.e. a
        dedicated (cheaper) doubling exists there that this project's unified formula doesn't have.
        **Exact OpenSSL Jacobian-formula multiplication counts were NOT independently re-derived this
        session** (would need reading the actual brainpool-specific C path/asm, not just the
        dispatcher) - flagged explicitly as unverified, per this project's own "read the actual asm
        before proposing a fix" standing rule (T-129/T-139 precedent). The qualitative fact (a real,
        dedicated doubling formula gap) is confirmed; the exact quantitative multiplier is not, and
        any future implementation work must close that gap with a real spike before committing to a
        rewrite, not before this plan.

      **Both blockers this task was told to gate on (see T-193's own Phase-0-style caution) are now
      resolved or explicitly scoped**:
      1. *Is Додаток Б.4's addition-law formula normative (must-use-literally) or descriptive (one
         correct way to compute the group law)?* **Resolved while researching this task, from the
         project's own `docs/pseudocode/dstu9041.md`**: clause 6.12 (scalar multiplication)'s own
         transcription states the standard's own text disclaims its literal textbook double-and-add
         as side-channel-unsafe *as written* and directs implementers to a real citation (Joye & Yen,
         "The Montgomery Powering Ladder," CHES 2002) instead - meaning any correct, constant-time
         scalar-multiplication algorithm (windowed, ladder, or otherwise) already satisfies the
         standard, not just a literal transcription of 6.12. Separately, Додаток Б.4's projective
         formula is one concrete implementation of the *same* addition law already given in affine
         form immediately above it in the same document - any provably-equivalent formula (extended
         coordinates, a dedicated doubling formula, etc.) computes the identical mathematical point
         addition, so swapping the specific field-operation sequence stays "per Додаток Б.4" in the
         sense the citation requirement cares about (what operation is computed, not which exact
         sequence of field ops implements it) - the same principle already applied to choosing
         schoolbook vs. any other correct multiplication algorithm for the underlying `F_p` math.
         Record as its own `docs/DECISIONS.md` entry if this plan is ever picked up - resolved here,
         not yet written down as a citable decision.
      2. *Does a windowed/precomputed scheme's secret-indexed table lookup need its own documented
         exception?* **Still open, not resolved by this task.** D-19's Kalyna S-box/MDS carve-out is
         scoped specifically to that case and does not automatically extend to a new EC-scalar-mult
         table - a real `docs/DECISIONS.md` entry is required before any implementation, not just an
         assumption that D-19 already covers it.

      **Concrete levers, if this plan is ever picked up (ordered by effort/risk, smallest first)**:
      1. Dedicated squaring routine in `fp256.rs`/`fp512.rs` - lowest risk, fully isolated, no
         windowing/table-lookup question at all, ~30-40% fewer multiplications in every `square()`
         call.
      2. Fixed-width windowed scalar multiplication (e.g. a 4-bit window) with a constant-time
         table-indexed lookup, replacing today's bit-by-bit ladder - **the natural home for the
         owner's own "smol tables" analogy**: extend the *existing* `dstu-core/small-tables` Cargo
         feature (already governing Kalyna/Kupyna/Strumok and DSTU 4145's `verify`,
         `docs/resource-profiles.md`) rather than inventing a new flag, same default-fast/opt-in-
         small polarity as every other primitive already on it - `fused` gets the windowed/
         precomputed path, `small-tables` keeps today's zero-precompute ladder. Blocked on open
         blocker 2 above.
      3. A fixed-base precomputed table specifically for `base_point()` (used by every `seal`'s
         `R = epsilon * G`, and by DSTU 4145 signing's own base-point multiplication) - the single
         biggest per-call win available, since it only benefits fixed-base multiplication, not
         `seal`'s second, variable-base `T = epsilon * Q`. Same blocker as above.
      4. A dedicated (cheaper) doubling formula distinct from the general addition law - the largest
         but most invasive change: touches the proven-complete/branch-free correctness argument for
         both E256/1 and E512/1, needs its own completeness proof, not just a speed patch. Lowest
         priority of the four.

      **Verification requirements before any of this ships (existing project rules, not new ones,
      restated here so a future implementer doesn't have to rediscover them)**: the existing Додаток
      Г worked-example tests check the *result* of point addition/scalar multiplication, not the
      algorithm, so they remain valid oracles regardless of which formula computes it - no new oracle
      needed, but every existing test must still pass unchanged. A fresh Kani-tractable-subset check
      for whatever new bounded operations are added (mirroring `fp256.rs`/`fp512.rs`'s existing
      `conditional_sub_p`/`select`/`add`/`sub`/`reduce_wide` proofs). Per T-129/T-139's own precedent:
      a genuine `--emit=asm`/`criterion` spike *before* committing to any rewrite, not after -
      "the hypothesis was wrong" is a complete, valuable outcome there, not a failure to route
      around.

      **Hardware-`clmul` spike, same session, owner-requested ("досліди зараз як нам допоможе
      апаратна інструкція... на разбері - дві різні архітектури"), `advisor()`-directed design**:
      measured, not estimated, whether `PCLMULQDQ`/`PMULL` would actually move `multiply()`'s
      throughput (not `poly_mul_wide` alone - the mistake shape this task's own earlier "at most
      38%" estimate would have repeated). New `#[cfg(test)]` modules in `gf2m_wide.rs`:
      `clmul_native` (one per `target_arch`, `#[target_feature(enable = "pclmulqdq")]`/
      `enable = "aes"` on an `unsafe fn`, gated by a *runtime* `is_x86_feature_detected!`/
      `is_aarch64_feature_detected!` check at every call site - not `#[cfg(target_feature = ...)]`,
      which would be `false` on this project's actual baseline build and silently produce a false
      "no speedup" result) and `clmul_spike` (schoolbook - not Karatsuba, checkable limb-by-limb -
      combination of pairwise hardware clmuls, one macro instantiation per field size, mirroring
      `field_axioms!`'s own shape). **Correctness gated first**: `clmul_poly_mul_wide_matches_
      software_reference`, a proptest against the existing software `poly_mul_wide`, all three
      field sizes, both architectures - all green before any timing was trusted. Then timed feeding
      the *same production* word-wise `reduce` this task's own earlier fix landed (not a second
      reduce implementation).

      **Real, measured, both architectures - `docs/PERFORMANCE.md`'s "T-195 Tier 1 hardware-`clmul`
      spike" subsection has the full tables**: `Gf2m256::multiply()` (software vs. hardware-`clmul`,
      chained, same methodology as every other timing diagnostic in this file) - dev machine
      (Ryzen 5 PRO 4650U) **6.35x** (505.8 -> 79.7 ns/op), Raspberry Pi 5 (Cortex-A76) **4.16x**
      (487.2 -> 117.2 ns/op), both stable across repeated runs. m=128/512 measured too for
      completeness (dev 1.84x/11.61x, Pi 1.90x/5.35x - m=512's schoolbook cost scales as `limbs^2`,
      64 pairwise clmuls vs. m=256's 16, hence the larger win there) but m=256 is what
      `crypto_secretstream`/`crypto_box` actually run through, so it's the number that matters for
      the bulk-throughput tables.

      **Real second-architecture confirmation of the word-wise `reduce` fix itself, found while
      setting up this spike**: the Pi's `~/cipher_ua` copy predated T-195's `reduce` rewrite (last
      synced before this session) - re-synced (tar+ssh per `.claude.local.md`), then ran the actual
      `kalyna-gcm` 256-256 benchmark there for the first time post-fix, 100 MiB, same methodology as
      the dev-machine row: **12.35 -> 37.33 MB/s encrypt, 12.41 -> 37.04 MB/s decrypt, ~3.0x** - a
      real measured result on the second architecture, not projected, and a *bigger* relative win
      than the dev machine's own ~2.45x/1.90x (consistent with the old bit-serial `reduce` costing
      proportionally more per cycle on this CPU). Scratch files (`payload100m.bin`, `gcmkey.bin`,
      `~/perf195` dir) deleted immediately after, `df` confirmed no net disk growth on the Pi's
      already-tight card.

      **Projected (not measured end-to-end) effect on real Kalyna-GCM throughput if the hardware
      path were actually landed**: swapping each machine's measured software-vs-hardware
      `multiply()` delta into its own real GCM per-block time and holding cipher-block/framing cost
      fixed - dev machine ~34.96 -> ~68 MB/s encrypt, ~30.16 -> ~52 MB/s decrypt; Pi ~37.33 -> ~68
      MB/s encrypt, ~37.04 -> ~67 MB/s decrypt. Both comfortably under their XTS (bare-cipher)
      ceilings (163.82/155.55 MB/s dev; Pi's own XTS number not separately measured this session).
      The projection is *smaller* than the raw `multiply()` speedup suggests on its own, because
      Kalyna256-256's own `encrypt_block` (201.4 ns dev / 323.4 ns Pi) becomes the new floor once
      the tag multiply shrinks enough - expected diminishing returns once a two-term sum stops
      being dominated by one term, not a sign the projection method is wrong.

      **Not picked up as production code this session, per `advisor()`'s explicit instruction**: the
      spike lives entirely in `#[cfg(test)]` (`clmul_native`/`clmul_spike` in `gf2m_wide.rs`),
      `poly_mul_wide` itself untouched. A real landing still needs, and this session deliberately
      did not resolve: target-feature detection strategy for a `no_std` core (compile-time
      `#[cfg(target_feature = ...)]` fork vs. runtime dispatch - the same `fused`/`small-tables`-
      shaped decision the owner invoked by name), a software fallback path for CPUs without the
      instruction, and a real `--emit=asm` pass on the *wired-in* version before committing, per
      T-129/T-139's standing precedent. That's a decision for the owner to make, not something this
      spike should pre-empt.

      **Status: both Tier 1 levers are now real, measured findings, not plans** - word-wise `reduce`
      landed as production code this session (~2.0-3.0x Kalyna-GCM speedup, confirmed on two
      architectures); hardware `clmul` is spiked and measured on both architectures (a further
      ~1.9-2.0x projected on top, ~4-6x on `multiply()` alone) but not landed - the feature-
      detection/fallback design is a real decision still waiting on the owner. Tier 2 (EC
      scalar-multiplication windowing) remains plan-only, untouched this session.
- [x] **T-196** **Done 2026-08-08, owner-requested ("Ми можем ще десь застосувати апаратні команди
      на всіх наших алгоритмах? Розшири покриття") - hardware-`clmul` coverage extended from
      `gf2m_wide` (T-195) to the one other GF(2^m) binary-field algorithm in this project,
      `hazmat::dstu4145::gf2m163`; a software comb-method rewrite was also implemented, tested, and
      then reverted for a real security reason, recorded below rather than silently discarded.**

      **Survey first** (owner asked "де ще" - answered by algorithm, not assumed): only
      `gf2m_wide` (Kalyna-GCM/GMAC's tag, T-195) and `gf2m163` (DSTU 4145's field) do GF(2^m)
      carry-less-multiply arithmetic - the one class `PCLMULQDQ`/`PMULL` actually accelerates.
      `hazmat::dstu9041`'s `fp256`/`fp512` are prime-field `F_p` (regular modular integer
      multiply, not carry-less) - a different hardware lever would apply there if any
      (`MULX`/`ADCX`/`ADOX`, big-integer widening multiply, the mechanism real curve25519/P-256
      implementations use) - not the same instruction, not investigated this session, a separate,
      larger-scoped question the owner did not ask for. Kalyna/Kupyna/Strumok have no applicable
      hardware instruction at all - already closed (T-129/D-88, T-139/D-87): AES-NI is hardwired to
      AES's own S-box/MixColumns, Kalyna's S-box differs, the instruction simply doesn't map to a
      different cipher's math.

      **`advisor()` consulted before writing any code, gave the gating check that mattered**: count
      `multiply()` vs `square()` calls in `curve163::scalar_multiply`'s own per-iteration ladder
      before assuming the lever is real - `invert()` is square-dominated (9 multiplies vs. ~162
      squares, D-109's addition chain) and doesn't touch `poly_mul_wide` at all, so if
      `scalar_multiply` were similarly square-heavy, this whole investigation would be a small
      lever, not a real one. Counted directly from `curve163.rs`'s main ladder loop (lines
      157-162): **8 `multiply()` calls vs. 7 `square()` calls per iteration** - multiply is not a
      minority share, the lever is real. Proceeded.

      **Comb-method software rewrite - implemented, tested, reverted, not landed.** `gf2m163::
      poly_mul_wide` was still the *original* right-to-left shift-and-add method (`Guide to
      Elliptic Curve Cryptography` Algorithm 2.33) - it never received `gf2m_wide`'s own T-125
      comb-method upgrade at all. Wrote the same 4-bit-window comb method (`NIBBLES =
      163.div_ceil(4) = 41` - **163 is not a multiple of 4**, unlike `gf2m_wide`'s m in
      {128,256,512}, so the top nibble reads one bit past the field's own top meaningful bit,
      `advisor()`-flagged as the real risk in this specific rewrite - added both a proptest
      differential against the retained bit-serial reference and two fixed edge cases, top-bit-set
      and all-163-bits-set, mirroring this module's own existing `square_wide_matches_multiply_
      wide_*` edge-case pattern). **All tests passed, including both edge cases.** Then reverted
      (`git checkout --`, nothing had been committed) after re-reading this module's own doc
      comment: "**Branchless by construction**... no array indexing at all." The comb method's
      `T[nibble]` lookup is exactly the secret-indexed access that principle exists to rule out -
      acceptable for `gf2m_wide`'s GCM tag (`H` is key-derived, D-76 already accepted it there) but
      not here, where `multiply()` runs on `curve163::scalar_multiply`'s own secret-scalar
      intermediates (the signing nonce, the private key) - the highest-value secret in the project.
      Flagged to the owner mid-task rather than resolved unilaterally either direction (land-with-
      caveat vs. revert vs. skip `poly_mul_wide` entirely) - owner chose revert, proceed to CLMUL.
      **Not a wasted step**: caught before shipping, not after, and the reverted code's own
      existence is why the CLMUL path's "no secret-indexed lookup at all" property could be stated
      as a real, checked comparison rather than an assumption.

      **Hardware-`clmul` spike - reuses `gf2m_wide::clmul_native` directly** (widened from
      `pub(super)` to `pub(crate)`, the only change to already-landed T-195 code; two architecture-
      specific intrinsics, not reimplemented a third time). Schoolbook: 3 limbs -> 9 pairwise
      64x64->128 hardware clmuls (vs. `gf2m_wide`'s 16 at m=256) - correctness-proptested against
      the *original* `poly_mul_wide` (not the reverted comb method) first, all green both
      architectures, then timed feeding the same production `reduce`. Genuinely branchless *and*
      free of secret-indexed memory access - `clmul64` runs for a fixed 9 `(i, j)` pairs
      unconditionally, and the hardware instruction's own latency does not depend on operand bits
      (the actual property real GHASH implementations rely on) - a strict improvement over the
      bit-serial baseline on both the speed and the side-channel axis, unlike the comb method.

      **Real, measured, both architectures** (`docs/PERFORMANCE.md`'s T-196 subsection has the full
      table): `FieldElement::multiply()` (software bit-serial vs. hardware-`clmul`, chained, same
      methodology as every T-195 diagnostic) - dev machine (Ryzen 5 PRO 4650U) **~64-65x** (1264.6-
      1269.0 -> 19.4-19.9 ns/op), Raspberry Pi 5 (Cortex-A76) **~42x** (1013.3 -> 24.1-24.3 ns/op),
      both stable across repeated runs. Far larger than `gf2m_wide`'s own 6.35x/4.16x (T-195)
      *because* `gf2m163`'s software baseline is the un-upgraded bit-serial method, not because the
      hardware instruction behaves differently - this is hardware-vs-original, not hardware-vs-
      already-optimized-software the way the GCM number was.

      **Real sign/verify speedup: not measured this session, and not pinned down by the
      `multiply()` number alone.** `scalar_multiply`'s own per-iteration ladder is multiply-heavy
      (gating check above), but `scalar_multiply` also calls `invert()` two to three times for its
      own affine y-recovery, and `invert()` is square-dominated and never touches `poly_mul_wide`
      at all. The real `sign`/`verify` ops/s win from this lever sits somewhere between negligible
      and large, genuinely not measured - would need either wiring the hardware path into
      production (not done, same posture as T-195) or a dedicated `scalar_multiply`-level timing
      harness (also not built this session). `docs/PERFORMANCE.md`'s DSTU 4145-vs-OpenSSL section
      (T-150, `nistb163` row) is corrected in the same pass: its old "no CPU instruction-set
      asterisk to disclose here" line was accurate when written but is now factually wrong given
      this finding - fixed to say the algorithmic gap (no windowing/precomputation) is still the
      *dominant* cause, with a secondary, now-real hardware asterisk alongside it, not instead of
      it - avoiding the exact "wrong conclusion sitting two screens from the number that
      contradicts it" mistake T-194/T-195 already made once this session over Kalyna-GCM.

      **Not picked up as production code, same posture as T-195**: the spike lives in `gf2m163.rs`'s
      own `#[cfg(test)] mod clmul_spike`, `poly_mul_wide` itself untouched (back to the original
      bit-serial version after the comb-method revert). A real landing needs the same target-
      feature-detection/`no_std`/fallback design decision T-195 already scoped, still waiting on
      the owner - this task confirms the same lever exists on a second algorithm, with both a
      larger raw number and a concrete reason (not just caution) to prefer it over the cheaper
      software alternative here specifically.

      **Full regression, both architectures**: `dstu4145_curve`/`dstu4145_gf2m`/`dstu4145_signature`
      integration suites (official worked example, Bouncy Castle oracle harness, tampered-signature
      rejection, all three still green), `clippy -D warnings`, `fmt --check` - all clean on both
      the dev machine and the (re-synced) Raspberry Pi.
- [x] **T-197** **Done 2026-08-09, owner-requested, T-196's own explicitly-deferred question
      ("MULX/ADCX/ADOX теж досліди але врахуй щоб працювало і на арм... треба щось спільне") -
      picked up with the cross-architecture constraint stated up front this time, not discovered
      partway through. Clean negative result: no production change, unlike T-195/T-196.**

      `hazmat::dstu9041::{fp256,fp512}`'s `wide_mul`/`reduce_wide` (`F_p` schoolbook
      multiply-accumulate, DSTU 9041's/`crypto_box`'s hot path) is already plain portable
      `u128`-based Rust - unlike GF(2^m) carry-less multiplication (T-195/T-196), there's no missing
      stable-Rust primitive here forcing a choice between portable-slow and hardware-specific-fast.
      The question was only whether that portable code was already reaching BMI2/ADX-quality x86
      codegen, or leaving something on the table.

      **Asm spike first** (`--emit=asm`, this project's own precedent): baseline `x86_64` target
      compiles `multiply()` via legacy `mulq`/`adcq`/`addq` (20/37/26, 101 `movq`).
      `-C target-feature=+bmi2,+adx` swaps every `mulq` for `mulxq` and halves the `movq` count (48)
      by avoiding the `RAX`/`RDX` clobber - but the `adcq`/`addq` counts are **identical** either
      way. LLVM never emits `adcx`/`adox` from this code shape even with the feature enabled - the
      dual-independent-carry-chain restructuring ADX needs isn't something instruction selection
      does on its own from generic `u128`-carry Rust.

      **Whole-function timing (not just asm-reading) settles it**: a chained `acc =
      acc.multiply(x)` loop, 200k iterations, `hazmat::dstu9041::fp256::bmi2_adx_timing::
      isolated_timing_multiply_chain`, built twice with different `RUSTFLAGS` so there's no target-
      feature/inlining boundary inside one binary to confound the number (three repeated runs per
      row, both machines):

      | Build | Dev machine | Raspberry Pi 5 |
      |---|---|---|
      | Baseline | 21.3-23.6 ns/op | 72.2-72.5 ns/op |
      | `+bmi2,+adx` (x86) / `target-cpu=native` (ARM) | 24.4-27.0 ns/op (**slower**) | 75.3 ns/op (no real change) |

      The x86 regression is small but consistently in the same direction every run, not noise.
      **Root cause**: the accumulate chain is latency-bound (each `multiply()` waits on the previous
      one's full result), not throughput-bound - `MULX`'s actual benefit (freeing execution ports by
      not serializing through `RAX`/`RDX`) only pays off with independent work to overlap, and there
      isn't any in a serial dependency chain. Different register allocation under `+bmi2,+adx` came
      out a net loss here.

      **"Треба щось спільне" answer: the portable code already is the common answer.**
      `FieldElement::multiply()`'s baseline `aarch64` asm (`mul`+`umulh` for the widening multiply,
      `adds`/`adcs`/`adc` for the carry chain) is already AArch64's idiomatic bignum pattern - and
      unlike BMI2/ADX on x86, `mul`/`umulh`/`adds`/`adcs` are **base ISA**, not an optional
      extension, so the same portable `u128` source produces it with zero flags, on every ARM64
      target this project ships to (including the microcontroller-class ones with no `target-cpu`
      tuning available at all). There's no "did we leave an ARM lever unpulled" question to answer -
      the lever doesn't exist as a separate opt-in there the way it does on x86, and on x86 it was
      measured to help nothing (or slightly hurt). `fp512` shares `fp256`'s exact `wide_mul`/
      `reduce_wide` shape (`docs/DECISIONS.md` D-176, just 8 limbs not 4) so the same conclusion
      applies structurally - not separately re-measured.

      **No production code change** - the `RUSTFLAGS`-toggled timing test lives in `fp256.rs`'s own
      `#[cfg(test)] mod bmi2_adx_timing` (compiles on both `x86_64` and `aarch64`, kept for
      reproducibility per this project's own "Reproducing" convention), `wide_mul`/`reduce_wide`
      themselves untouched. `docs/PERFORMANCE.md` has the full write-up (new "T-197" subsection,
      right after the T-196 GF(2^163) section). Full `dstu9041_field`/`dstu9041_curve`/
      `dstu9041_encryption` regression, `clippy -D warnings`, `fmt --check` - all clean on both the
      dev machine and the (re-synced) Raspberry Pi.
- [x] **T-198** **Done 2026-08-09, owner-requested ("Тоді імплементуй попередні дослідження з
      апаратним прискоренням які працюють" - explicitly excludes T-197's negative result) - lands
      the two hardware-`clmul` levers T-195/T-196 measured but kept `#[cfg(test)]`-only pending a
      design decision. `advisor()` consulted before any code was written; full design/review detail
      in `docs/DECISIONS.md` D-184 (new), full measured numbers in `docs/PERFORMANCE.md`'s own
      T-198 section - this entry is the summary.**

      **Design**: `std`-gated runtime dispatch (`clmul_native::feature_available()`, needs a hosted
      environment - `is_x86_feature_detected!`/`is_aarch64_feature_detected!` aren't in `core`),
      unconditional portable fallback everywhere else - `no_std`/embedded/other-arch builds see zero
      behavior change. `multiply()` on `Gf2m128`/`Gf2m256`/`Gf2m512` and `gf2m163::FieldElement`
      both gained this dispatch; a new `poly_mul_wide_hw` per type does the actual hardware work.

      **`advisor()`'s pre-implementation review caught three things, all fixed before landing**:
      (1) the T-195/T-196 spikes called a separately-`#[target_feature]`-attributed `clmul_native::
      clmul64` for every `(i, j)` pair - a real non-inlinable call boundary baked into their own
      6.35x/4.16x numbers; production `poly_mul_wide_hw` inlines the whole schoolbook loop inside
      one `#[target_feature]` function instead, so those numbers are a floor, not a target, for the
      landed shape; (2) every dev machine and `x86_64`/`aarch64` CI runner has the hardware feature,
      so once `multiply()` dispatches, every pre-existing test calling `a.multiply(b)` silently
      stops exercising the portable path at all - closed by adding `multiply_sw`/
      `multiply_matches_explicit_software_path` (plus `multiply_sw_*` sibling axiom proptests in
      `gf2m_wide.rs`) that call `reduce(poly_mul_wide(...))` directly, bypassing dispatch; (3)
      grepped both crates' `kani_proofs` modules for any `.multiply()`/`.square()` call before
      assuming CBMC would reach the dispatch branch (neither does - `#[cfg(not(kani))]` on the
      dispatch is defensive, not an observed-failure fix), and verified Miri empirically rather than
      pre-emptively excluding it (`MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test`
      passes clean on both modules' dispatch-correctness tests - the `-Zmiri-disable-isolation` flag
      itself works around an unrelated, pre-existing Windows-Miri limitation in `proptest`'s failure
      persistence, confirmed by reproducing the identical error on an untouched pre-existing test).

      **A real, pre-existing `clippy -D warnings` gap, surfaced not introduced**: the T-195/T-196
      spike code's `_mm_storeu_si128`-into-a-byte-array-then-`try_into().unwrap()` pattern was
      always `cast_ptr_alignment`/`unwrap_used`-unclean, just never linted (`cargo xtask clippy`'s
      real gate has no `--all-targets`, so `#[cfg(test)]`-only code was never in scope). Promoting
      the equivalent code to unconditional (`std` + arch) production code put it in scope for the
      first time. Fixed by extracting both 64-bit halves via `_mm_cvtsi128_si64`/
      `_mm_srli_si128::<8>` instead (both SSE2, no pointer cast, no `Result` to unwrap) - verified
      not a regression on the same chained timing test afterward, not assumed.

      **Measured end-to-end, both real numbers now, not projections** (`docs/PERFORMANCE.md` has
      the full tables and reproduction commands): Kalyna-GCM 256-256 at 100 MiB - dev machine
      encrypt 34.96 -> ~132-134 MB/s, decrypt 30.16 -> ~135-139 MB/s (~3.8x/~4.6x); Raspberry Pi
      encrypt 37.33 -> 82.39 MB/s, decrypt 37.04 -> 85.75 MB/s (~2.21x/~2.31x) - both sanity-checked
      against each machine's own measured bare-cipher (Kalyna-XTS) ceiling (dev 163.82/155.55 MB/s
      pre-existing, Pi 93.78 MB/s measured this task) and land safely under it. DSTU 4145 `sign`/
      `verify` (fast-path build) - dev machine 667.39 -> ~17,250-17,680 ops/s (~26x) and
      524.01 -> ~16,745-17,000 ops/s (~32x); Raspberry Pi ~14,290-14,400/~14,930-16,040 ops/s (no
      prior Pi baseline existed to compare against - new data points). The DSTU 4145 speedup is far
      larger than T-196's own "expect modest" caveat, because that caveat only accounted for
      `invert()` (squaring-dominated, correctly excluded) and missed that `scalar_multiply`'s own
      multiply-heavy ladder (8 `multiply()` vs. 7 `square()` per iteration, T-196's own gating
      check) was paying the *old*, much larger `multiply()` cost on the majority of its work the
      whole time - `square_wide` was already known cheap (T-153/D-109), so a ~64x cheaper
      `multiply()` removes what was actually the dominant per-iteration term, not a minor one.

      **Full regression, both architectures**: `gf2m_wide`/`gf2m163` unit suites,
      `dstu4145_curve`/`dstu4145_gf2m`/`dstu4145_signature`/`kalyna_gcm`/`kalyna_gmac`/`kalyna_xts`
      integration suites, `cargo xtask clippy`/`fmt --check`, and the full `cargo xtask build`
      feature matrix (`--all-features`, `--no-default-features`,
      `-p dstu-core --no-default-features --features getrandom`) - all clean on both the dev machine
      and the (re-synced) Raspberry Pi.
- [x] **T-200** **Done 2026-08-09, owner-requested ("Давай 200 таску із смоук тестами для
      бінарника. Врахуй які в нас там реалізації і як їх атакувати найдоцільніше а не сліпо" - do
      T-200 now, ground it in what's actually implemented, attack it the most worthwhile way rather
      than blindly). All items landed, including the three the owner explicitly named as "all
      three" when asked which remaining ones counted toward "full implementation" for the push gate
      (2026-08-09): the rest of the misuse matrix, streaming-boundedness, and `dstu9041`/
      `crypto_box`'s own differently-shaped small-subgroup attack at the sealed-file level.**

      **Phase 4 addendum, `crates/uacrypt/tests/smoke_crypto_box_attack.rs` (1 test)**: the last of
      the "all three" items - `box-seal`/`box-open`'s own small-subgroup attack, grounded directly
      in D-167 Finding 1 (a real, already-fixed security bug, not a hypothetical): clause 12 step 2
      rejects `r=0`/`r=1`/`r^2=a*d^-1 (mod p)` but originally missed `r=p-1`, which reconstructs to
      a genuine order-2 point `R'=(p-1,0)` outside the base point's own subgroup - left unrejected,
      a chosen-ciphertext query with `r=p-1` would leak the private key's parity bit.
      `point_from_x` was fixed to reject it explicitly; this test re-exercises that fix through the
      real binary and sealed-file wire format, not just `hazmat`'s in-process API. Mechanics: seals
      a real message via `box-seal`, overwrites the sealed file's first 32 bytes (`r`, confirmed by
      reading both `crypto_box.rs`'s wire-format assembly and `hazmat::dstu9041::encryption::
      encrypt`'s `ciphertext[..32] = r_bytes`) with `p - 1` computed via `fp256::FieldElement::sub`
      at runtime (not hand-subtracted - mirrors `dstu9041_curve.rs`'s own `r_equals_p_minus_1_
      reconstructs_the_order_two_point` construction, avoiding exactly the hand-hex-arithmetic risk
      `CLAUDE.md` already warns about for transcription), then confirms `box-open` rejects it and
      writes nothing to `--out`. Passed on first run.
      - **Deliberately did not attempt an order-4 attack (D-167 Finding 2)**: `docs/DECISIONS.md`
        D-173 already investigated this directly inside `dstu-core` itself (full internal-crate
        access, a `#[cfg(test)]` module) and hit a genuine, still-open research question -
        "whether a concrete order-4 point is reachable through `point_from_x`'s own reconstruction
        formula at all is an open question, not confirmed either way." Existence is proven (Hasse's
        bound); reachability through the actual public API is not. Attacking it from the CLI
        subprocess boundary, with *less* internal access than D-173's own attempt had, cannot
        responsibly claim to succeed where that investigation left an open analytic question
        ("does an order-4 point's `x` ever satisfy `euler_criterion`?") - this needs a mathematical
        answer, not more engineering, and is out of scope for a smoke-test task. Surfaced explicitly
        rather than silently narrowing "the crypto_box attack" to only the order-2 case without
        saying so.

      **Phase 2 addendum, `crates/uacrypt/tests/smoke_misuse_matrix.rs` (8 test functions)**: the
      rest of the misuse matrix beyond `--in`==`--out` (`smoke_misuse.rs`) and `smoke_dispatch.rs`'s
      representative dispatch-level coverage.
      - `missing_required_flag_matrix` - **exhaustive, not representative**, across all ~34 leaf
        command shapes: a data table (`CASES`) built directly from each `parse_*_args` function's
        own `ArgScanner::scan`/`.path(...)`/`.variant(...)` calls (not assumed from `--help` text),
        removing one required flag at a time and asserting the specific `MissingFlag` name reported.
        Every case passed on first run, itself confirming the required-flag extraction from source
        was accurate. Deliberately used dummy (never-opened) path values throughout - confirmed by
        reading every `parse_*_args` function first that `MissingFlag` fires before any file I/O for
        every flag in this table, so no real fixture files were needed for it.
      - **`kalyna-cmac`/`kalyna-gmac`'s mode-specific `--out`(compute)/`--tag`(verify) requirement
        is a genuinely different code path**, found reading `run_cmac_command`/`run_gmac_command`
        directly: unlike every other required flag, this check happens *after* reading real `--key`/
        `--in` files (`args.tag_path.as_ref().ok_or(CliError::MissingFlag("tag"))?`, inside
        `run_*_command`, not `parse_*_args`) - so it needed real fixture files and its own four
        tests (`kalyna_{cmac,gmac}_{verify_without_tag,compute_without_out}_is_missing_flag`),
        outside the dummy-path table above.
      - `unknown_flag_is_rejected_across_representative_commands` - deliberately **not** a full
        34-command sweep: every command routes through the one shared `ArgScanner::scan`
        unknown-flag branch (that sharing is the entire point of `ArgScanner`, T-188/SonarCloud's
        ~918-duplicated-line finding it replaced) - there is no per-command variation left to catch,
        so 4 representative cases across different command shapes are the real coverage, not 34
        repeats of one 5-line `else` branch.
      - `directory_as_out_is_rejected_across_representative_commands` - same reasoning: `std::fs::
        write`/`File::create` on a directory path is uniform `std::io` behavior regardless of which
        command calls it, 3 representative cases (`keygen`/`hash`/`encrypt`), each also confirming
        the directory itself stays empty (nothing written inside it, not just a nonzero exit code).
      - `iterations_zero_behaves_like_one_across_representative_commands` - `kalyna-block`, byte-
        for-byte identical output for `--iterations 0` vs `--iterations 1` (every command's own
        `.max(1)` clamp is the same one-line idiom, so one representative case verifies the pattern
        rather than the specific command).

      **Phase 4 addendum, `crates/uacrypt/tests/smoke_streaming_boundedness.rs` (4 tests) +
      `cargo xtask streaming-bounded`**: proves D-42's claim ("a `hazmat` streaming API existing
      does not make the `uacrypt` command wrapping it memory-bounded") at the real process boundary
      instead of leaving it asserted only in doc comments - spawns the real binary against a
      genuinely large file (200 MiB) and samples its actual OS-reported resident memory while it
      runs (`support::uacrypt_with_peak_rss`), for `kupyna-digest`, `strumok-crypt`, and
      `encrypt`/`decrypt`. Includes a deliberate control case, `box_seal_is_not_memory_bounded_
      control_case`: `box-seal`'s own `--help` text already says it reads `--in` whole into memory,
      so this proves the measurement methodology can actually detect *unbounded* growth (peak RSS
      visibly scales with `--in`'s size, confirmed >2x proportional in a real run) - without this,
      "the streaming commands measured low" would be unfalsifiable, since an insensitive measurement
      would also read low. Real measured numbers on this dev machine (release build): the three
      bounded commands peaked at ~4.5-4.8 MiB against a 200 MiB input (the 60 MiB threshold has
      roughly 12x margin either direction); the control case peaked at ~89 MiB (40 MiB input) and
      ~526 MiB (180 MiB input) - unambiguous proportional growth, not noise.
      - **Real architecture decision, not left implicit**: this genuinely does not fit in the
        default `cargo test`/`cargo xtask test` path. Confirmed empirically, not assumed: the exact
        same property in a plain debug-profile `cargo test` run took over 5 minutes for a *single*
        test and was killed before finishing - this project's constant-time crypto paths are
        dramatically slower unoptimized, and this check specifically needs a large file (hundreds of
        MiB) for "peak stayed far below input size" to mean anything. `--release` alone brought the
        same four tests down to ~13s total. Fix: all four tests carry a plain `#[ignore = "..."]`
        (not the usual `#[cfg_attr(miri, ignore = ...)]` this file's siblings use - Miri already
        can't reach an `#[ignore]`d test either, so one attribute covers both reasons), and a new
        `cargo xtask streaming-bounded` subcommand runs them explicitly via
        `cargo test --release -p uacrypt --test smoke_streaming_boundedness -- --ignored
        --test-threads=1` (`xtask/src/main.rs`) - wired into `ci()`'s existing best-effort optional-
        layer array (same treatment as `miri`/`fuzz`/`qemu-stm32`), plus its own real CI job
        (`.github/workflows/rust.yml`'s new `streaming-bounded` job, matrixed across
        `ubuntu-latest`/`macos-latest`/`windows-latest` on purpose - the memory-sampling harness has
        a genuinely different implementation per OS, see the next bullet, so this is the first real
        confirmation the Linux/macOS paths work at all, not just compile).
      - **Cross-platform memory sampling, one implementation per OS, no new dependency**:
        `crates/uacrypt/tests/support/mod.rs`'s `uacrypt_with_peak_rss` spawns the target subprocess
        then samples its live OS-reported resident memory while it runs. Linux: a background thread
        re-reads `/proc/<pid>/status`'s `VmRSS:` line directly (cheap, no subprocess per sample,
        5ms interval). Windows: a helper `powershell` process polls `(Get-Process -Id
        <pid>).WorkingSet64` in a loop, one sample per stdout line - the same `Get-Process`-based
        liveness idiom `CLAUDE.md` already documents for watching a long-running process (there:
        CPU time; here: memory), applied for the first time to something other than a human
        watching it live. macOS: a helper shell loop polls `ps -o rss= -p <pid>` the same way (no
        `/proc` on macOS, and no long-poll mode for `ps`, so a per-sample subprocess is the standard
        idiom there). All three self-terminate once the target process is gone (`Get-Process`/
        `kill -0` failing), no explicit stop signal needed. Deliberately not a raw WinAPI/`libc`
        FFI approach (`GetProcessMemoryInfo`/`getrusage`) - considered and rejected: hand-rolling a
        `rusage`/`PROCESS_MEMORY_COUNTERS` struct layout from memory to call unsafe FFI is exactly
        the kind of homegrown-primitive risk this project's own hard constraints warn against
        (wrong field layout is silent undefined behavior, not a compile error), where shelling out
        to an OS-standard, already-present, well-documented text-output tool carries none of that
        risk for a test-only harness.
      - **Only the Windows path was empirically run locally** (this project's dev machine) - real
        measured numbers above are all from Windows. The Linux (`/proc/PID/status` field name) and
        macOS (`ps -o rss=` output format) paths rely on well-established, stable OS conventions but
        were written, not locally verified - the new CI job above is deliberately matrixed across
        all three OSes specifically so it's the first real confirmation for those two, not a second
        local run of the one already-proven platform.

      **Phase 4 addendum, `crates/uacrypt/tests/smoke_off_curve_attack.rs` (2 tests)**: attacker-
      supplied off-curve/small-subgroup public keys through `verify --key`, at the real CLI/file
      boundary - the one item this entry originally called "real further work, not a same-session
      extension" and turned out tractable once actually attempted. Both DSTU 4145 curves reject a
      small-subgroup public key via an explicit upfront `x == 0` check in
      `hazmat::dstu4145::signature{,257}::verify`, reached *before* `r`/`s` are ever examined - so
      any syntactically-valid signature bytes trigger the same rejection, no forgery search needed
      (T-189's original `x != 0` shortcut for m=163; D-186's general cofactor-independent check for
      m=257). Constructs the curve's own order-2 point (`x = 0`, `y = sqrt(b)`, `b^(2^(m-1))` via
      repeated squaring - the same construction `crates/dstu-core/tests/dstu4145_signature{,257}.rs`
      already use at the library level, `b`'s hex value copied from those tests' own vector files
      rather than read cross-crate), encodes it into the exact tagged-verifying-key file format,
      writes it as `--key`, and confirms the real binary rejects it for both curves. One real
      transcription near-miss caught mid-implementation, not left to chance: the m=163 `b` hex
      string is 41 digits (an odd length - the vector file drops the leading zero nibble rather than
      zero-padding to 42), miscounted by eye at first the exact failure mode `CLAUDE.md` already
      warns about for this project's own hex transcription; caught immediately by counting the
      string length programmatically instead, not by re-eyeballing it, and fixed by left-padding
      any odd-length hex string before decoding. **`dstu9041`/`crypto_box`'s own order-2/order-4
      finding (T-183, D-176) stays deferred, on purpose, not overlooked** - it is about a compressed
      x-only point reconstructing to a small-subgroup `R'` *inside `box-open`'s ciphertext decoding*
      (an encryption-protocol-internal value), not about `PublicKey` bytes fed to `box-seal --key`/
      `box-open --key` directly the way a DSTU 4145 verifying key is - attacking it at the CLI
      boundary means constructing a crafted *sealed file* in `crypto_box`'s own wire format, a
      genuinely separate, harder task from what this addendum did.

      **Phase 4 addendum, `crates/uacrypt/tests/smoke_help_claims.rs` (6 tests)**: `--help` text as
      a pinned claim, this entry's own "highest-value net-new angle, nothing today covers it" note
      acted on. Picked the claims that are genuinely behavioral (not policy/advice nothing enforces,
      e.g. `kalyna-cmac`'s "don't reuse this key for encryption" - untestable by construction) and
      checked the real binary against its own documented promise: `strumok-crypt`'s "NOT
      authenticated ... tampered output decrypts silently into wrong plaintext" (flip a ciphertext
      byte, confirm exit 0 with corrupted output, not a rejection - the mirror image of
      `smoke_secretstream_attack.rs`'s authenticated case); `verify`'s "prints nothing and exits 0
      on a valid signature" (asserts `stdout == ""`, not just success); `decrypt`'s "`--out` is only
      replaced after the whole file is written and verified" (tamper, confirm `--out` was never
      created); `kalyna-ccm`'s "capped at 255 bytes" (256-byte message, confirm the exact "255-byte
      limit" wording in stderr); `kalyna-xts`'s "`--in` must be at least one block long" (subprocess
      version of the existing in-process-only check); `box-open`'s "rejected ... before anything is
      written to `--out`" for a wrong secret key. All 6 passed on first run.

      **Phase 2 addendum, `crates/uacrypt/tests/smoke_misuse.rs` (5 tests)**: the `--in`==`--out`
      misuse case, scoped to the one sub-case with real teeth per an `advisor()` consultation - not
      the full missing/unknown-flag matrix (already representatively covered by `smoke_dispatch.rs`
      and the in-process suite). **Found a real data-destruction bug doing this, not just a coverage
      gap**: `strumok-crypt --in x --out x` exited 0 and silently produced a 0-byte file, destroying
      the input - confirmed by actually running the real binary (a 50000-byte probe file), not
      assumed. Root cause and fix: `run_strumok_command`'s streaming path opened `--out` via
      `File::create` (truncating it) before finishing reading `--in`; fixed with the same temp-file-
      then-rename discipline `run_secretstream_command` already used, extracted into a new
      `run_strumok_stream` function (also incidentally fixes a second gap - partial `--out` left
      behind on a mid-stream I/O error, D-65's own no-partial-output standard). Full writeup,
      including why this wasn't already caught by the one existing same-path test (that test covers
      `crypto_secretstream`, a different construction): `docs/DECISIONS.md` D-187. Regression
      coverage at both levels - in-process (`run_strumok_command_in_and_out_same_path_round_trips`)
      and subprocess (`smoke_misuse.rs`'s two `strumok_crypt_in_place_*` tests) - plus same-path
      sanity checks confirming (not assuming) the three command families that read the whole buffer
      before writing (`encrypt`/`decrypt`, `kupyna-digest`, `kalyna-block`) were never at risk.

      **What landed**: `crates/uacrypt/tests/support/mod.rs` (hand-rolled `std::process::Command`
      harness, `env!("CARGO_BIN_EXE_uacrypt")`, no new `[dev-dependencies]` - confirmed working via
      a throwaway probe before writing anything else, per this task's own harness decision below)
      plus eleven real-subprocess test files (`smoke_misuse.rs`/`smoke_help_claims.rs`/
      `smoke_off_curve_attack.rs`/`smoke_streaming_boundedness.rs`/`smoke_misuse_matrix.rs`/
      `smoke_crypto_box_attack.rs` added in the Phase 2/4 addenda above), 75 `#[test]` functions
      total (one of which, `missing_required_flag_matrix`, internally sweeps ~34 command shapes'
      worth of assertions; 4 of the 75 are `#[ignore]`d by default, see the streaming-boundedness
      addendum above - run via `cargo xtask streaming-bounded`, not a plain `cargo test`), all
      passing on first full
      workspace run
      (`cargo test --workspace --exclude dstu-core-capi`), `cargo clippy --all-features` (both the
      default gate and `--test <name>`-scoped `--all-targets` on just the new files, not the whole
      crate - see the Miri/clippy note below for why), and `cargo fmt --check` all clean:
      - `smoke_dispatch.rs` (11 tests) - top-level dispatch: no-args/`--help`/`-h`/`--version`/`-V`,
        unknown command, `kalyna-block` missing/unknown subcommand, per-subcommand `--help` priority
        over a missing required flag. First-ever coverage of `main.rs`'s own `ExitCode::FAILURE`
        mapping and `"uacrypt: {e}"` stderr prefix (17 lines, previously exercised by zero tests).
      - `smoke_golden_path.rs` (16 tests) - one real-subprocess round trip per leaf command,
        enumerated from `run()`'s own dispatch `match` in `lib.rs` (35 leaf commands total, not the
        ~28 this entry's own original plan estimated - `kalyna-block/-ccm/-gcm/-cmac/-gmac/-kw/-xts`
        each have two sub-modes, `sign`/`box`/`box512` each have their own multi-command families).
        Confirmed real per-command flag sets/key-length constants by reading `lib.rs` directly
        (`ArgScanner::scan` call sites, `read_exact_file` lengths) rather than assuming from doc
        comments alone - every one of the 16 tests passed on its first real run, which is itself
        confirmation the inventory was read correctly, not guessed.
      - `smoke_verify_key_tag.rs` (5 tests) - T-199's new tagged-verifying-key format (D-186
        Decision 1) attacked directly: tag `0x00`/`0x03`..`0xFF` -> the named
        `SignVerifyUnsupportedCurve` (not a generic failure or panic - Decision 3's whole point),
        cross-tag/cross-length bodies (`0x01`+66-byte body, `0x02`+42-byte body), empty file,
        tag-byte-with-no-body - all fully spec'd directly from `read_tagged_verifying_key`
        (lib.rs:2190-2233), no exploration needed.
      - `smoke_secretstream_attack.rs` (10 tests) - `decrypt`'s wire format
        (`[header:32][tag:1][len:4 LE][ciphertext][auth_tag:16]...`) attacked at the file layer:
        truncation (header/mid-chunk), an oversized length field (confirmed the
        `chunk_len > SECRETSTREAM_CHUNK_BYTES` rejection fires *before* allocating/reading that
        much - the actual memory-safety property, not just an error-path check), an unknown tag
        byte, trailing data after `Final`, and - the one genuine security-property test in this
        file - flipping `Final`'s tag byte to `Message` while leaving everything else
        byte-identical, confirming the module's own doc-comment claim that `tag_byte` is bound into
        the chunk's AEAD associated data (caught as `SecretstreamVerifyFailed`, not silently
        accepted) holds at the real CLI/file boundary, not just in the library's own unit tests.
      - `smoke_key_confusion.rs` (7 tests) - the cross-key-type confusion family (D-47's "no
        `--type` flag" tradeoff): `keygen`/`box-keygen`/`box-pubkey` all produce indistinguishable
        32-byte files, `box-keygen512`/`box-pubkey512` produce indistinguishable 64-byte files.
        **Every byte pattern used was picked by running the real binary first and observing what
        happened, per an `advisor()` consultation's explicit correction to an earlier draft plan
        that would have assumed a rejection instead of confirming one** - `SecretKey::from_bytes`'s
        check is magnitude-only (`0 < e < n`) and passes almost any generic-looking value,
        `PublicKey::from_bytes`'s check requires the bytes to actually decode a point on the curve
        (empirically close to a coin flip for an arbitrary value, confirmed by sampling ~15 fixed
        patterns). Found and pinned with fixed, reproducible byte patterns (never a real random
        `keygen` output, which would make a test's pass/fail depend on that run's own random key
        landing on the right side of the coin flip): `[0x11; 32]` parses as a valid secret key but
        not a public key; `[0x55; 32]` is the mirror image (valid public key, `box-seal` genuinely
        succeeds and produces real ciphertext sealed to a "recipient" nobody can prove they hold -
        the interesting *silent* case); `[0x00; 32]`/`[0xFF; 32]` are rejected in both slots
        (boundary values); `[0x02; 64]` for `crypto_box512` is the strongest finding - parses as
        **both** a valid secret key and a valid public key simultaneously, since `l(p)=512`'s
        subgroup order sits close enough to the field size (D-182) that this low-magnitude value
        clears both checks at once, with zero error in either direction.

      **Harness decision, resolved not left open**: hand-rolled `std::process::Command` over
      `assert_cmd`, per this entry's own original plan - confirmed `env!("CARGO_BIN_EXE_uacrypt")`
      is genuinely populated for this crate's integration tests via a real throwaway probe test
      before writing the harness (deleted once the real harness existed), so the `assert_cmd`
      fallback was never needed. **Miri**: also confirmed empirically, not assumed - a Miri run of
      the same throwaway probe aborted on a plain `Path::exists()` call under isolation (Miri
      cannot spawn processes at all), confirming every test that calls into the harness needs
      `#[cfg_attr(miri, ignore = "...")]`, which all 49 do. **CI**: no new job needed - these are
      ordinary `cargo test` integration targets, so `xtask`'s existing mandatory `test()` step picks
      them up for free, exactly as this entry's own original plan predicted. One real gap found
      applying `CLAUDE.md`'s own clippy discipline: `cargo clippy --all-targets` also re-lints
      `lib.rs`'s **existing** 140 in-process tests for the first time (356 pre-existing
      `clippy::expect_used`/`unwrap_used` violations, confirming T-188's own prediction that
      `--all-targets` was never part of the project's clippy gate) - unrelated to this task's own
      new files, so the new files were linted via `--test <name>` scoping instead of blanket
      `--all-targets`; the 356 pre-existing findings are a separate, not-yet-filed cleanup item, not
      part of T-200's own scope.

      **Closed 2026-08-09 - nothing left deferred that was in scope.** Every item this entry ever
      listed as deferred has since landed: the rest of the misuse matrix (`smoke_misuse_matrix.rs`),
      streaming-boundedness (`smoke_streaming_boundedness.rs` + `cargo xtask streaming-bounded`),
      `--help`-text-as-pinned-claim tests (`smoke_help_claims.rs`), `docs/SECURITY.md`'s "CLI/binary
      attack surface" section, `verify --key`'s off-curve/order-2 attack (`smoke_off_curve_attack.rs`),
      and `box-open`'s `crypto_box`/`dstu9041` order-2 sealed-file attack
      (`smoke_crypto_box_attack.rs`, above). `docs/SECURITY.md`'s CLI section should be revisited to
      drop its now-stale "off-curve-key gap" phrasing next time that file is touched - not urgent
      enough on its own to reopen this task purely to fix a doc-comment stale reference.
      **One item was named in the owner's "all three" scope and explicitly NOT attempted, on
      purpose, not by oversight**: an order-4 (not order-2) attack against `crypto_box`/`dstu9041`,
      D-167 Finding 2. `docs/DECISIONS.md` D-173 already tried this at the `dstu-core` level with
      full internal-crate access and left it a genuine open research question (order-4 point
      *existence* is proven, *reachability* through the public `point_from_x` API is not confirmed
      either way) - see the `smoke_crypto_box_attack.rs` addendum above for the full reasoning on
      why this is a real dead end today, not a shortfall in this task's own effort.

      Original plan follows, unchanged (historical record - see the summary above for what actually
      shipped and where it diverged):

      ("Додай таску на смоук
      тести саме бінарника, в усіх режимах з усіма можливими сценаріями правильного і неправильного
      використання в тому числі з намаганням зламу" - add a task for smoke tests of the binary
      itself, all modes, all scenarios of correct/incorrect use including hacking attempts).
      Investigated first: confirmed via a full-project-context audit that **no binary-level test
      exists anywhere in this repo.** All 140 `#[test]` fns in `crates/uacrypt/src/lib.rs` call
      `run(&args)` in-process, inside the test binary itself - never `std::process::Command`-spawning
      the real compiled `uacrypt.exe`/`uacrypt`. No `crates/uacrypt/tests/` directory, no
      `[dev-dependencies]` at all in `crates/uacrypt/Cargo.toml`, no `xtask` "smoke"/"e2e" subcommand,
      no CI job scripting real binary invocations for misuse/attack testing (the language-binding
      workflows shell out to the real binary, but only for byte-identical interop cross-checks, not
      CLI-scenario coverage). The `dstu-core/fuzz/` targets (10, all still relevant) all hit library
      primitives directly, none hit the `uacrypt` CLI/file-format/argv layer. `docs/SECURITY.md`
      never mentions "CLI" or "binary" at all.

      **Why in-process coverage doesn't substitute** (the concrete gap this task exists to close,
      per `advisor()` consultation) - things only a real subprocess boundary can catch:
      - **Exit codes.** `main.rs` (17 lines: `run()` -> `ExitCode::SUCCESS`/`FAILURE`) is currently
        executed by *zero* tests - every existing test asserts on the library's `Result`, never on
        what a shell/CI consumer actually sees.
      - **stdout/stderr routing** - the `uacrypt: ` error prefix, errors-to-stderr/help-to-stdout,
        `--iterations` timing output - all unverified at the process boundary.
      - **Pre-`run()` argv handling** - `std::env::args().skip(1)`: non-UTF-8 args, empty-string
        args, embedded spaces/quotes, Windows's own ~32k command-line-length ceiling.
      - **Real filesystem behavior** - Cyrillic filenames (a realistic input for this project
        specifically, and exactly where Windows + UTF-8 argv tends to break), directory-as-`--out`,
        read-only target, missing parent dir, `--in`==`--out` for every command (currently only
        tested for `crypto_secretstream`), UNC/`\\?\` paths, symlinks.
      - **Actual absence-of-partial-output** - D-65 claims failed commands leave no partial file and
        `encrypt`/`decrypt`'s temp-file-then-rename is atomic; only a real subprocess + real
        filesystem check can confirm the file genuinely doesn't exist after a killed/failed process,
        an in-process `Result` check cannot.
      - **`--help` text as a pinned claim, not prose** - the highest-value net-new angle, nothing
        today covers it. Each command's help text makes testable assertions ("exits with an error,
        nothing written", "NOT authenticated", "no message-length cap", "not memory-bounded, `--in`
        read whole into memory") - these rot silently; a subprocess test can grep real `--help`
        output and assert the claim still matches the real behavior it documents.

      **Enumeration source**: generate the scenario matrix from `run()`'s own match arms plus
      `print_command_help`'s match in `crates/uacrypt/src/lib.rs` (~28 top-level commands, several
      with their own sub-subcommands - `kalyna-block encrypt|decrypt`, `kalyna-ccm`, `kw wrap|unwrap`
      - and variant flags: five Kalyna variants, 256/512 for Kupyna/Strumok/`crypto_box`,
      `m=163`/`m=257` for `sign`/`verify`) - **not** README or the top-level `--help` text, both of
      which can drift from the real dispatch table; that drift is itself a finding worth a test, not
      a source to enumerate from. Don't hand-type the full per-command grid into this file - state
      the generation rule here, let implementation build the matrix off the live `match`.

      **Scenario categories, all four required per command where applicable** (mirrors D-64/D-65's
      three plus T-183/D-173's active-attack fourth, already this project's standing pattern for
      asymmetric primitives, extended here to the CLI/file-format boundary):
      1. **Typical/correct usage** - golden-path round trip for every command, real subprocess,
         real temp files (exit code 0, expected stdout shape, output file exists and round-trips).
      2. **Incorrect/malformed usage (misuse)** - missing/unknown flags, wrong arg count, invalid
         variant names, `--iterations 0`, nonexistent `--in`, `--out` pointing at a directory,
         zero-byte input, `--in`==`--out` (every command, not just secretstream today).
      3. **Toxic/malicious data (rejection + file-input taxonomy)** - truncated files, wrong magic/
         header bytes, huge files (streaming-boundedness claim, D-42's "hazmat streaming existing
         doesn't make the CLI wrapper memory-bounded" - only a real subprocess + real large file can
         prove this, not a mock), null bytes in filenames, path traversal (`../`) in `--in`/`--out`,
         extremely long argv, symlinked input/output, TOCTOU (swap the file between open and read
         where the command's own atomicity claim depends on it not mattering).
      4. **Active attack attempts** (T-183/D-173's fourth category, applied at the CLI boundary):
         - **Cross-key-type confusion** - `keygen`'s and `box-keygen`'s outputs are both 32 bytes;
           length validation alone can't tell them apart. Feed a `keygen` key to `box-seal --key`
           and vice versa - must fail cleanly, not silently produce garbage. Same check for every
           other same-length key-type pair in the surface (`sign-keygen` vs `sign-keygen257` output
           lengths, etc.).
         - **Tagged verifying-key format cross-length matrix** (T-199's new format) - tag `0x00`,
           `0x03`..`0xFF`, tag `0x01` with a 66-byte body, tag `0x02` with a 42-byte body, a tag
           byte alone with no body - only one `0xFF` case exists today, in-process.
         - **Attacker-supplied public keys through `verify --key`** - off-curve points, the order-2
           point, and (for `m=257`) an order-4 point - T-189/D-172's fix has never been exercised at
           the boundary where the bytes are genuinely untrusted argv/file input, not a Rust-typed
           test fixture.
         - **`crypto_secretstream` wire-format attacks at the file layer** - oversized chunk-length
           field, trailing data after `Final`, unknown tag byte, truncation mid-chunk, reordered/
           replayed chunks, a header swapped between two different files, `Message` tag flipped to
           `Final` - each should map to a specific named `CliError`; assert the exact error reaches
           stderr, not just a nonzero exit code.
         - **Documented-not-a-bug case**: `strumok-crypt`'s own `--help` already warns about
           key/IV two-time-pad reuse but the binary permits it - record this scenario as
           expected-by-design (with a test pinning that it's still permitted, and that the warning
           text still says so), so a future reader doesn't file it as an unfixed vulnerability.

      **Prior art researched** (background agent, full citations kept in this task's own history,
      condensed here):
      - **OpenSSL's own CLI suite** (`test/recipes/{nn}-test_*.t`, Perl `Test::More` + the
        `OpenSSL::Test` helper for spawning the real `openssl` binary and checking exit code/output) -
        organizes by two-digit numeric prefix per feature area (20-24 is `openssl`-command-level
        specifically), not by a happy-path-vs-attack axis; those live as separate assertions within
        the same recipe file, keyed by feature. Relevant precedent for *this* task: group by command/
        subsystem, not by scenario category, when laying out the actual test files.
      - **GnuPG** rewrote its own CLI test suite from shell to a custom Scheme interpreter
        specifically for cross-platform binary-level testing, and documents `--with-colons`/
        `--status-fd` as the machine-parseable surface scripts should target over human-readable
        output - no direct analog needed here (`uacrypt` has no colon-output mode), but the
        underlying lesson (script against a stable machine-checkable surface, not prose) applies to
        the `--help`-text-as-pinned-claim category above.
      - No canonical published test-matrix methodology found specific to age/minisign/signify/rage -
        a real gap in prior art, not a missed search.
      - **OWASP File Upload Cheat Sheet / WSTG "Test Upload of Malicious Files"** - the standard
        citable source for the toxic-file-input taxonomy above (path traversal, null-byte tricks,
        magic-bytes-not-extension validation); doesn't cover symlink/TOCTOU explicitly, those come
        from general secure-coding literature, cited as such, not overclaimed as OWASP's own.

      **Harness/dependency-policy decision, resolved here rather than left open** (the one genuine
      architectural fork `advisor()` flagged - `crates/uacrypt/Cargo.toml` currently has *zero*
      `[dev-dependencies]`, and this project gates all deps through `cargo deny`/`docs/SECURITY.md`,
      with `xtask` itself documented as "deliberately zero dependencies"): use **hand-rolled
      `std::process::Command`**, not `assert_cmd`+`predicates` (the standard Rust-ecosystem choice,
      confirmed via research - `assert_cmd` spawns `Command::cargo_bin(...)`, chains with
      `predicates::str::contains(...)` for stdout/stderr assertions; `trycmd` is a cram-style
      declarative alternative; `rexpect` is PTY-based, relevant only for interactive/prompting
      programs, not `uacrypt`'s pure argv/file-in-file-out shape). Reasons: (1) matches this
      project's own established zero-dependency posture for exactly this kind of harness code, same
      reasoning `xtask`'s own doc comment already states; (2) `env!("CARGO_BIN_EXE_uacrypt")` is a
      real, no-extra-dependency Cargo mechanism available to any integration test under
      `crates/uacrypt/tests/` - gives the exact built-binary path with no `target/debug`-vs-`release`
      guessing and no `.exe`-suffix special-casing, which is the actual hard part `assert_cmd` would
      otherwise be pulled in to solve. **Verify `CARGO_BIN_EXE_uacrypt` is genuinely populated for
      this package's own integration tests before committing to this path** (it should be - Cargo
      sets it automatically for any `[[bin]]` target in the same package as the test - but confirm
      empirically, don't assume). If a real ergonomic gap shows up once writing the ~28-command
      matrix by hand, re-open `assert_cmd` as a fallback rather than fighting the zero-dep posture
      past the point it's paying for itself - name that trade explicitly if it happens, don't let it
      drift in silently.

      **CI integration**: if this lands as an ordinary `cargo test` integration test target under
      `crates/uacrypt/tests/`, `xtask`'s existing mandatory `test()` step already picks it up for
      free - **no new CI job needed**, don't over-engineer a separate `xtask smoke`/gate for this.
      **Miri constraint**: Miri cannot spawn real processes at all - every test in this suite needs
      `#[cfg_attr(miri, ignore = "spawns the real uacrypt binary, not interpretable")]` from the
      first commit, same shape as the existing `scalar_multiply`-calling exclusions (T-100/T-156) -
      confirm this is actually required (vs. Miri simply never selecting this target) before writing
      the boilerplate, don't assume without checking.

      **Phasing** (per `advisor()` - an unbounded "enumerate everything up front" version of this
      task risks the same fate as T-183's own multi-month backlog sit): (1) harness plumbing +
      golden-path round trip for every command, exit-code and stdout/stderr assertions from day one;
      (2) misuse/malformed-usage matrix; (3) toxic-data and active-attack categories above; (4) docs/
      CI reconciliation (`docs/SECURITY.md` gains a "CLI/binary" mention, `docs/TASKS.md` closure).
      Each phase should be a real, independently landable state, not a partial step waiting on the
      rest - same discipline T-199 itself just used successfully. No committed timeline; owner
      prioritizes which phase starts first.
- [ ] **T-203** **Not started, owner-requested (2026-08-09) - per-registry package publishing for
      all eight language bindings (PyPI/npm/RubyGems/Packagist/NuGet), staged, one explicit go-ahead
      per stage, not a single blanket authorization.** Same class of gate as T-17/T-164 (crates.io
      required an explicit owner ask; this is the six-registry version of that ask), prompted
      directly by T-17/v0.3.0 landing this session and the owner asking to do the same for every
      binding "по єдиному плану." `advisor()`-reviewed before staging (2026-08-09): the single
      biggest risk is treating this as one six-registry action - each registry needs the owner to
      create an account and configure a trust policy in that platform's own web UI, which this
      session cannot do on the owner's behalf. The `cargo login` handoff for crates.io already
      misfired twice this session (interactive paste didn't work, direct-argument form leaked the
      token into the chat transcript twice, both revoked after) - six repeats of that exact pattern
      is the concrete failure mode this task's staging exists to avoid.

      **Research this session (not yet executed)**: four of six registries support Trusted
      Publishing via OIDC - PyPI, npm (GA since 2025-07), RubyGems, and NuGet all let a GitHub
      Actions workflow authenticate via a short-lived OIDC token instead of a long-lived API key,
      once the owner configures a trust policy (repo + workflow filename + environment) on that
      registry's own site. **This is the direct fix for the token-leak pattern above** - no secret
      ever enters the chat for these four, unlike the crates.io round. Packagist and Maven Central
      don't fit this shape: Packagist has no CI publish step at all (submit the repo URL once via
      its web UI, add a GitHub webhook, and it reads `composer.json`/tags directly from GitHub
      forever after - no token, no artifact, no version bump); Maven Central (via Sonatype's Central
      Portal) needs namespace verification (fast if claimed via GitHub as `io.github.<username>`,
      slow otherwise via DNS TXT record) plus PGP/Sigstore signing of every artifact (2025-2026
      security requirement) - real infrastructure work, not a single-session step.

      **Staged plan, tightest constraint first (advisor-recommended order)**:
      1. **Packagist (PHP)** - lowest risk: no credential, no build artifact, no version bump.
         `v0.3.0` already exists as a tag; Packagist reads it directly once the one-time webhook is
         set up.
      2. **PyPI (Python)** - the only one of the seven non-`uacrypt` bindings with prebuilt wheels
         already produced (`release.yml`'s `build-python-wheels` job, attached to the `v0.3.0`
         GitHub Release). Needs a pending trusted publisher configured on PyPI plus a new
         `publish-pypi` job in `release.yml`. **`bindings/python`'s own version is `0.1.0`, not
         lockstepped with `dstu-core`/`uacrypt`'s 0.3.0** (`bindings/python/Cargo.toml` and
         `pyproject.toml` both say so, deliberate per `release.yml`'s own comment) - a first PyPI
         publish burns `0.1.0` permanently, same irreversibility as crates.io.
      3. **npm / RubyGems / NuGet** - confirmed this session (grepped every `bindings-*.yml`
         workflow, none use `action-gh-release` or trigger on `v*` tags) that **none of the seven
         non-Python bindings produce any downloadable release artifact today** - real CI work
         (a prebuilt-artifact job per binding in `release.yml`, mirroring `build-python-wheels`'s
         shape) has to land before any of these three registries has anything to publish.
      4. **Maven Central** - separate, later, its own multi-session task once reached - not folded
         into this one's numbered stages.

      **Before any stage starts**: re-check package name availability live on that specific registry
      (`docs/bindings-strategy.md`'s existing name-check table, lines 126-134, only covers
      PyPI/npm/NuGet/Maven Central as of 2026-08-02 and is already stale - no RubyGems/Packagist row
      exists at all), and read that registry's actual current publish workflow requirements before
      writing any CI, the same "research before implementation" discipline `docs/CLAUDE.md` requires
      for primitives, applied here to release infrastructure instead.

      **Stage 1 started 2026-08-12 - see T-164's own entry for the live status.** Owner picked
      PyPI + npm first; re-checked names live (still free on both). Found this stage's own
      Packagist step didn't hold up - D-144 already ruled it out for this specific PHP binding
      (compiled extension, not Composer-manageable), not re-derived when this plan was written -
      deferred, not dropped.
- [x] **T-204** **Closed 2026-08-09/10, same session, three phases.** Found this session auditing binding coverage after the owner asked directly whether
      the new signature curve reached the bindings. `crypto_sign257` (DSTU 4145 `m=257`, T-199,
      landed 2026-08-08) was **not wired into any of the eight language bindings or
      `dstu-core-capi`** - confirmed by grepping actual binding source (not build artifacts) for
      `sign257`/`Sign257`/`m257` across `bindings/`: the only three hits were stale `.d`
      dependency-file paths under `target/debug`/`target/release` build output, zero real wrapper
      code in any binding or in `crates/dstu-core-capi/src`. This was the same shape of gap already
      flagged for `crypto_box512` (DSTU 9041 `l(p)=512`, T-193's own scope note: "binding/capi
      wiring for `crypto_box512` ... separate future task") - that note had no task number assigned
      either, so both newer primitives were tracked together here rather than as two separate
      half-tracked gaps.

      **`dstu-core-capi` phase done 2026-08-09**, following T-181's own `crypto_box`-to-all-eight
      precedent for shape (mirror the sibling module, don't invent a new one) and D-148's existing
      capi conventions throughout: `crates/dstu-core-capi/src/sign257.rs` (`dstu_sign257_*`/
      `dstu_verify257_*`, 33/66/66/32-byte constants, untagged - the curve-tag dispatch stays a
      `uacrypt`-layer-only concern per `crypto_sign257`'s own module doc, not duplicated into the C
      ABI, the D-118 lesson) and `crates/dstu-core-capi/src/box512.rs` (`dstu_box512_*`, 64/64-byte
      keys, `DSTU_BOX512_SEAL_OVERHEAD = 304` - confirmed against `crypto_box512::open`'s own
      `MIN_LEN`, not assumed from module-doc prose). No new `DstuStatus` variant needed for either -
      `DSTU_ERR_INVALID_KEY`/`NULL_POINTER`/`RANDOM`/`TRUNCATED`/`BUFFER_TOO_SMALL`/`TAG_MISMATCH`
      already cover both, `box512::OpenError::InvalidCiphertext` reusing `TAG_MISMATCH` exactly like
      `crypto_box.rs`'s own top doc comment argues. `box512.rs` (not `crypto_box512.rs`) matches
      `crypto_box.rs`'s dropped-`crypto_`-prefix file/symbol convention for consistency, even though
      `box512` isn't a reserved keyword the way bare `box` is - a deliberate choice, not a coin
      flip, recorded in the module's own top doc comment. Verified: both modules registered in
      `lib.rs`; D-64/D-65 rejection+misuse Rust FFI tests added to `tests/ffi_tests.rs` (8 new tests
      - tampered sealed blob, wrong key, NULL handles, `sealed_len < overhead`, buffer-too-small,
      zero-scalar/degenerate-point key rejection; `cargo test -p dstu-core-capi --release` 26/26
      pass); C-level `test_sign257`/`test_box512` added to `c-tests/test_capi.c` plus new
      `examples/sign257.c`/`examples/box512.c`, `xtask/src/main.rs`'s `CAPI_EXAMPLES` list extended
      to 7 (the sync point CLAUDE.md's own agent-discipline section warns is easy to miss) -
      `cargo xtask capi` passes end-to-end including the header-freshness diff (`include/dstu_core.h`
      regenerated and committed). `cargo clippy --all-features --all-targets -- -D warnings` and
      `cargo fmt --check` both clean. New scalar-multiply-heavy Rust FFI tests carry
      `#[cfg_attr(miri, ignore)]` (m=257 mirroring T-100/D-59's m=163 precedent; `l(p)=512`
      similarly, since it's roughly double `crypto_box`'s own `l(p)=256` width and that primitive's
      own capi tests are already an accepted, untimed cost) - **actual Miri wall-clock time for
      these two new suites has not been separately measured this session** (a full
      `cargo +nightly miri test --workspace` run is tens of minutes to hours; not run here), flagged
      as an open verification item rather than assumed safe.

      **Phase 2 (.NET/Go/C++) done 2026-08-09, same session, per owner's "продовжуй до кінця
      реалізуй для всіх мов" go-ahead.** Chosen order deliberately reversed from this entry's
      original text (advisor review: these three link `dstu-core-capi` directly, the exact surface
      Phase 1 just proved end-to-end via `xtask capi`, vs. the five direct-Rust bindings each
      needing a different macro system - front-load what's already de-risked). Each mirrors its
      own binding's existing `Box`/`Sign` (or `BoxSecretKey`/`SigningKey`, per binding) wrapper
      shape exactly, distinct types, no curve-tag byte (D-118):
      - **.NET**: `Box512.cs`/`Sign257.cs` (`Box512SecretKey`/`Box512PublicKey`,
        `SigningKey257`/`VerifyingKey257`), `NativeMethods.cs`/`NativeHandles.cs` P/Invoke +
        `SafeHandle` entries, `DstuConstants.cs` sizes. `Box512Tests.cs`/`Sign257Tests.cs` (18 new
        `[Fact]`s) - `dotnet test` 86/86 pass; `dotnet format --verify-no-changes` clean;
        `Box512Example.cs`/`Sign257Example.cs` added to `Program.cs`'s dispatch, both run
        successfully. SDK-style `.csproj` globs `*.cs` automatically - no project-file sync point.
      - **Go**: `box512.go`/`sign257.go` (cgo against `dstu_core.h` directly, no hand-copied
        prototypes to drift - confirmed reading `box.go`/`sign.go` first), `constants.go` sizes
        pulled straight from the C header's own macros. `box512_test.go`/`sign257_test.go` (18 new
        test functions) - `go vet`/`gofmt -l` clean, `go test ./...` full suite passes;
        `examples/box512.go`/`sign257.go` wired into `examples/main.go`'s dispatch, both run.
      - **C++**: `include/dstu/box512.hpp`/`sign257.hpp` (header-only, RAII move-only, mirrors
        `box.hpp`/`sign.hpp`), added to the `dstu.hpp` umbrella include, `constants.hpp` sizes.
        `TestBox512`/`TestSign257` added to the single shared `tests/test_dstu.cpp` (no per-binding
        test-file split in this binding) and called from `main()`; `CMakeLists.txt`'s example
        `foreach` list extended (`box512`/`sign257`, the sync point most likely to be missed
        silently, per advisor review - a name absent from that list just never builds, no error).
        `cmake --build` + `ctest` clean (1/1), both new example executables verified to run.

      Per-binding doc sweep done alongside each commit (not deferred): `dstu-core-capi/README.md`'s
      own gap (found only because it was actually opened and read, not assumed current, per
      advisor's earlier-round finding) plus each of `.NET`/Go/C++'s own `README.md` module table.

      **Phase 3 (Python/Node.js/Ruby/Java/PHP) done 2026-08-10, same session.** The five direct-Rust
      bindings each needed their own macro-system wrapper (pyo3/napi-rs/magnus/jni/ext-php-rs) - same
      mirror-the-sibling-module discipline, same distinct-type/no-curve-tag rule (D-118), each with
      its own new test file (D-64/D-65 correctness/rejection/misuse, not the primitive-level suite,
      which already lives in `dstu-core` for both primitives):
      - **Python**: `src/box512.rs`/`sign257.rs` (plain `bytes` across the boundary, matching every
        other function in this crate), registered in `lib.rs` and re-exported through
        `python/dstu_core/__init__.py`'s import/`__all__` lists (a sync point the capi-linked
        bindings don't have). `tests/test_box512.py`/`test_sign257.py` - 87/87 pytest pass (18 new);
        `cargo fmt`/`clippy` clean; both examples run.
      - **Node.js**: `src/box512.rs`/`sign257.rs` (napi `Buffer`, explicit `js_name` camelCase per
        D-126's own precedent), registered via `pub use` in `lib.rs` (napi-rs generates
        `js/index.js`/`.d.ts` at build time, no hand-written index to sync).
        `test/box512.test.js`/`sign257.test.js` - 82/82 `node --test` pass (18 new); `cargo fmt`/
        `clippy` clean; both examples run.
      - **Ruby**: `ext/dstu_core_rb/src/box512.rs`/`sign257.rs` (magnus `RString`), registered via
        `define_singleton_method` in `lib.rs`. Hit the same previously-diagnosed `rb-sys`/`libclang`
        build failure this session's own background `cargo xtask ci` run had already hit
        (`strings.h` not found) - **already had a documented fix** (`.claude.local.md`,
        `LIBCLANG_PATH` pointed at the MSYS2 ucrt64 clang, found during T-160/D-133) that just
        wasn't exported in this shell; applying it unblocked a full real verification, not a
        written-but-unverified phase. `spec/box512_spec.rb`/`sign257_spec.rb` - 88/88 rspec pass
        (18 new), rubocop clean, `cargo fmt`/`clippy` clean, both examples run.
      - **Java**: `native/src/box512.rs`/`sign257.rs` (JNI `byte[]`, `Java_ua_dstucrypto_dstucore_*`
        symbol naming per this binding's own no-underscore-in-names convention), new
        `Box512`/`Sign257` Java classes. `src/test/java/.../Box512Test.java`/`Sign257Test.java` -
        86/86 `mvn test` pass (18 new); both examples run. `native/Cargo.lock` was still pinned to
        `dstu-core` 0.2.0 - this session's earlier crates.io-publish version bump never touched this
        separate workspace (D-119) - regenerated as a byproduct. `cargo clippy --all-targets` in
        this workspace pre-existingly fails on unrelated `dstu-core` hazmat benchmark code
        (`gf2m_wide.rs`/`tables.rs`) - reproduced via `git stash` against master *before* this
        change too, so a pre-existing gap, not a T-204 regression; opened as **T-205**, not fixed
        here (out of scope, and `cargo clippy` without `--all-targets` on this crate's own code is
        clean).
      - **PHP**: `src/box512.rs`/`sign257.rs` (`ext_php_rs::binary::Binary<u8>`,
        `dstu_core_*`-prefixed flat naming). **Found and fixed a real `ext-php-rs` pitfall**:
        `#[php_function]`'s default `RenameRule::Snake` splits a letter/digit boundary, so
        `dstu_core_box512_keygen` silently registered as PHP-callable `dstu_core_box_512_keygen`
        instead - caught by an actual `function_exists()`/`get_extension_funcs()` check after the
        first build, not assumed from reading the derive macro's source, then fixed with an
        explicit `#[php(name = "dstu_core_box512_keygen")]` override on all 8 new functions (same
        override the derive macro itself supports for exactly this case, confirmed by reading
        `ext-php-rs-derive`'s own source, not guessed). `tests/Box512Test.php`/`Sign257Test.php` -
        88/88 phpunit pass (18 new), `cargo fmt`/`clippy` clean, both examples run. PHP itself
        turned out to already be installed on this machine (`C:\Users\Pa\tools\php83`, T-159's own
        setup) - just not on `PATH` in this shell, matching the Ruby pattern above: a documented
        fix existing but not applied in the current session, not a fresh toolchain install.

      **CLAUDE.md's two `crypto_box512`/`crypto_sign257` bullets updated to say all eight bindings
      are wired**, replacing the interim "three of eight, named" phrasing Phase 2 left there.

      Two reusable findings from this phase worth carrying forward: (1) a documented local-toolchain
      fix (`.claude.local.md`) can go stale in *this specific shell* even when correct and already
      applied elsewhere - always re-check `PATH`/env vars for a binding before concluding its build
      is actually broken, not just "known broken from an earlier session." (2) A derive/proc-macro's
      default case-conversion rule is a real, distinct risk surface from hand-written per-binding
      naming (Go/`.NET`/C++/Python/Ruby all pass identifiers through untouched or via an explicit
      per-function override already) - any *new* binding or macro system this project adopts later
      needs the same "does the auto-rename handle a digit-adjacent-to-letter identifier correctly"
      check `ext-php-rs` just failed, not an assumption it's fine because every other binding was.
- [ ] **T-205** **Not started, found during T-204 (2026-08-09/10) - `bindings/java/native`'s
      `cargo clippy --all-targets -- -D warnings` fails with 54 errors, all in `dstu-core`'s own
      hazmat benchmark code (`gf2m_wide.rs`'s `clippy::items_after_statements`/`cast_precision_loss`,
      `tables.rs`'s `clippy::needless_range_loop`), not in this binding's own `native/src/*.rs`.**
      Confirmed pre-existing, not a T-204 regression, via `git stash push -- bindings/java` against
      clean `master` (same 54 errors with zero T-204 changes present), `git stash pop` afterward to
      restore the work. Plain `cargo clippy` (no `--all-targets`) on this workspace is clean. Not
      fixed as part of T-204 - out of scope for a binding-wiring task, and the fix belongs in
      `dstu-core`'s own hazmat benchmark code, not in any binding.
- [~] **T-206** **Phase 1 done 2026-08-10 (m=257 root-cause fix), phase 2 done 2026-08-10 and
      disproved Phase 1's own sufficiency, Phase 2b (real fix) done same session, phases 3-4
      contingent on the next real CI number - `cargo miri test (dstu-core)` is
      exceeding its 240-min CI budget again (real timeout, not concurrency-group noise - confirmed
      via `gh run view` on run `31342605874`: job ran the full 240 min, `23:46:32`→`03:46:48`,
      `conclusion: cancelled`), the third time this exact job has hit its cap (150-min original
      overrun T-146/D-103 raised it to 240; this is the next one). Owner wants something structural,
      not a fourth timeout bump - this is the same band-aid twice already.**

      **Root cause found this session, verified by grep, not assumed** (the multi-line
      `#[cfg_attr(\n    miri,\n    ignore = "..."\n)]` form defeated a naive single-line grep on the
      first pass - re-ran with a form that actually spans the attribute before trusting a "0 matches"
      result). `dstu4145_curve.rs`/`dstu4145_gf2m.rs`/`dstu4145_signature.rs`/`crypto_sign.rs` (the
      `m=163` files) correctly carry `#[cfg_attr(miri, ignore)]` on every `Point::scalar_multiply`-
      heavy test (T-100/D-59's original fix, still genuinely in place - `rust.yml`'s own comment
      claiming this was accurate, an earlier single-line grep this session had wrongly cast doubt on
      it). `crypto_sign257.rs` correctly mirrors `crypto_sign.rs`'s own ignore pattern (12 of 13
      ignored vs. 13 of 21). **But `dstu4145_curve257.rs` and `dstu4145_signature257.rs` - the direct
      `m=257` siblings of the two hazmat-level files above, added in T-199 - have zero Miri-ignore
      attributes between them**, despite `dstu4145_curve257.rs` calling `scalar_multiply` directly
      (`curve257_generator_times_order_is_infinity`, `curve257_point_arithmetic_matches_bouncy_castle`)
      and every one of `dstu4145_signature257.rs`'s 6 real tests calling `sign()`/`verify()`, which
      internally scalar-multiply on the 257-bit curve (slower per call than `m=163`'s 163-iteration
      ladder, not faster). `dstu4145_gf2m257.rs`'s own `invert()` calls are correctly *not* ignored -
      confirmed its `FieldElement::invert` already uses the same fast 9-multiply addition-chain form
      D-109/T-153 gave `gf2m163` (`crates/dstu-core/src/hazmat/dstu4145/gf2m257.rs` lines 106-118),
      so that file needed no fix and none was assumed.

      **Plan (per advisor consult - measure before restructuring, don't guess the fix's shape)**:
      1. [x] **Done.** Added `#[cfg_attr(miri, ignore = "...")]` to `dstu4145_curve257.rs`'s 2
             scalar-multiply tests (one of which - `curve257_point_arithmetic_matches_bouncy_castle` -
             mixes cheap add/double/invert/multiply/square cases with `scalar_multiply` in one match,
             unlike `dstu4145_curve.rs`'s m=163 sibling which splits each `op` into its own filtered
             test function - ignoring the whole function trades away Miri coverage of the cheap cases
             too, same tradeoff the m=163 file already accepts elsewhere, not a new one; restructuring
             to split by `op` was out of scope for this fix) and `dstu4145_signature257.rs`'s 6 sign/
             verify tests. Verified two ways before committing: (a) plain `cargo test` on both files -
             9/9 pass, 0 ignored (the attribute is Miri-gated, inert otherwise); (b) a real scoped
             `cargo +nightly miri test -p dstu-core --test dstu4145_curve257 --test
             dstu4145_signature257` (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`, CI's own
             invocation) - dropped from an unbounded/hours-scale run to **2.01s** and **0.52s**
             respectively, all 8 newly-annotated tests showing `ignored, <reason>`, the 1 cheap test
             left in `dstu4145_curve257.rs` (`curve257_generator_is_on_curve`, no scalar_multiply)
             still actually ran under Miri, not skipped by accident.
      2. [x] **Done, and disproved Phase 1 as sufficient.** Real CI run `31396063454` (triggered by
             commit `523ca2a`, a later ruff-format fix pushed on top of the Phase 1 commit `0837911`
             - `git merge-base --is-ancestor 0837911 523ca2a` confirms Phase 1's own m=257 changes
             were present in the tested tree) hit the full 240-min cap exactly (`14:06:08`→
             `18:06:23`) and was cancelled - `gh run view --json jobs` showed every other job in the
             workflow (including `cargo miri test (uacrypt)`/`(dstu-core-capi)`) completed fine; only
             `cargo miri test (dstu-core)` was cancelled. Pulling the job's own log
             (`gh run view --log --job=<id>`) showed the m=257 fix worked exactly as measured locally
             (both files' tests flew by) but the *actual* cost center was never touched by Phase 1:
             `tests/crypto_box.rs` alone took 3608.94s (~60 min) for 17 tests, and
             `tests/crypto_box512.rs` was still running when the job was killed - 11 of 17 tests done
             in 158 min (`15:16:02`→`17:54:35`), each costing ~20-25 min, projecting to **~257 min for
             that one file alone** (advisor's own projection, confirmed against the log's per-test
             timestamp deltas). Neither file existed when D-59/T-100's original 84-min-local/143-min-CI
             baseline was measured (`crypto_box` landed T-178, `crypto_box512` landed T-193, both after
             2026-07-27) - the timeout kept recurring because each new `crypto_box*`-family addition
             quietly added tens of minutes of Miri cost that no one had re-measured against the budget.
      2b. [x] **Done, the actual fix.** Per advisor: every `crypto_box`/`crypto_box512` test that
             calls `seal()` pays the same ~1-unit scalar-multiply cost regardless of what it's
             *testing* (confirmed from the log's own per-test deltas - tamper/misuse tests cost the
             same as `round_trip` because the tamper happens after an identical full `seal()` call),
             and `hazmat::dstu9041`'s own `scalar_multiply` already has live, unignored Miri coverage
             via `tests/dstu9041_encryption{,_512}.rs`'s `encrypt_matches_worked_example_ciphertext`/
             `decrypt_matches_worked_example_message` - so re-interpreting the identical arithmetic
             through `crypto_box`'s wrapper in 15 near-identical ways is redundant for Miri's actual
             job (UB/aliasing detection, not functional re-verification; full functional/rejection
             coverage already runs every push under plain `cargo test`, unaffected by any of this).
             Kept exactly 2 tests live per file - `round_trip` (the success path) and
             `tampered_ciphertext_is_rejected` (the representative failure path, so Miri still
             interprets `open`'s error branch at least once) - and added
             `#[cfg_attr(miri, ignore = "...")]` citing this task to the other 10 full-cost tests per
             file (`zero_length_message_round_trips`, `message_far_larger_than_the_{25_byte,seed}_kem_
             payload_round_trips`, `two_calls_use_different_ephemeral_material`,
             `public_key_round_trips_through_bytes`, `wrong_secret_key_is_rejected`,
             `tampered_kem_prefix_is_rejected`, `tampered_secretstream_header_is_rejected`,
             `tampered_tag_is_rejected`, `kem_failure_and_secretstream_failure_are_indistinguishable`,
             `trailing_garbage_after_valid_ciphertext_is_rejected`). The 4 already-instant tests per
             file (no `seal()`/`open()` call - `truncated_input_is_rejected_not_a_panic`,
             `secret_key_rejects_out_of_range_bytes{,_upper_boundary}`,
             `public_key_rejects_degenerate_x_values`) and the already-ignored `round_trip_property`
             proptest were untouched. Verified: (a) plain `cargo test -p dstu-core --test crypto_box
             --test crypto_box512` - 34/34 pass, 0 ignored (Miri-gated attribute is inert otherwise);
             (b) a real scoped `cargo +nightly miri test -p dstu-core --test crypto_box --test
             crypto_box512` run (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`), timed
             locally before pushing: `crypto_box.rs` (6 live, 11 ignored) finished in **820.33s
             (~13.7 min)**, `crypto_box512.rs` (6 live, 11 ignored) in **3778.75s (~63 min)** -
             `real 76m42.5s` total for both files together, down from an unbounded run that hadn't
             finished `crypto_box512.rs` alone after 158 min on the real CI run above. Local numbers
             use the Windows GNU Miri backend (`x86_64-pc-windows-gnu`), not CI's Linux one
             (`x86_64-unknown-linux-gnu`) - not directly comparable 1:1 (this session's own D-59
             history shows CI running ~1.7x slower than local for the old pre-`crypto_box` baseline,
             84 min local vs. 143 min CI), but bounded-and-finishing at all is the material change
             from before this fix, where `crypto_box512.rs` alone was projected at ~257 min and
             hadn't completed within the entire 240-min CI budget.
      3. [ ] **Only if the next real CI run still shows a thin/exceeded margin**: split `dstu-core`'s
             Miri job into a bucketed matrix (a handful of legs grouping heavy EC/DSTU-9041 files vs.
             everything else, not a 43-way per-test-file matrix - advisor flagged that each matrix leg
             pays its own `cargo +nightly miri setup` sysroot-build tax from cold unless cached, which
             could dominate wall time for the ~30 fast `kalyna_*`/`kupyna_*`/`strumok` files and make a
             maximally-fine split a net loss, not a win) instead of raising `timeout-minutes` a fourth
             time. Also confirm any such split still reaches `--lib`'s own `#[cfg(test)]` module (a
             separate binary from every `tests/*.rs` file, easy to silently drop from a matrix built
             only around `--test <name>` legs).
      4. [ ] Once the next real run's actual duration is known, **tighten `timeout-minutes` from 240
             to a real number with margin** (not re-guessed - the whole point of this task per the
             owner's framing), and update `rust.yml`'s own Miri-job comment to document the
             `crypto_box`/`crypto_box512` cost story by name alongside the m=163/m=257 EC-ladder story
             it already names - deliberately not guessed now, since this session's own arithmetic
             (baseline ~143 min CI-measured pre-`crypto_box`, T-100/D-59, plus an estimated ~50-60 min
             for the trimmed `crypto_box`/`crypto_box512` pair, plus whatever else has been added to
             `dstu-core` since 2026-07-27 and never re-measured) is too uncertain to safely land under
             advisor's suggested ~120-min figure without risking another D-103-style thin-margin false
             failure - the same "verify a CI number via `gh run view`, don't assume" discipline this
             file already states applies to setting the number in the first place, not just to
             confirming a run's conclusion.
- [x] **T-207** **Done 2026-08-10, owner-requested - `cargo xtask python` was missing both `ruff
      check` and `ruff format --check`, even though CI's `bindings-python.yml` runs both as
      required steps.** Found the hard way, twice: the T-204/T-206 push failed CI's
      `bindings-python` job on `ruff check .` (import-sort), fixed and pushed without locally
      running the second check too; the very next push failed again on `ruff format --check .`
      (line length) for the same reason - no single local command covered both, so each fix was
      verified piecemeal instead of against the real CI surface. Owner asked directly whether every
      binding's own language-native linter is mirrored in `xtask` the same way, to close this class
      of gap for good rather than just patching Python.

      **Audited all eight bindings' CI workflows against their own `xtask` function** before
      changing anything, not assumed:
      - **Ruby** (`bundle exec rubocop`) and **.NET** (`dotnet format --verify-no-changes`, both
        `.csproj`s) - already correctly mirrored in `xtask ruby()`/`dotnet()`. No gap.
      - **Go** - `bindings-go.yml` calls `cargo xtask go` directly as its own build/test step (not a
        separate lint step CI runs independently) - structurally cannot drift from `xtask`.
      - **Node.js/PHP/Java/C++** - confirmed (via each binding's own `package.json`/(missing)
        `composer.json`/`pom.xml`/CI workflow) that **no language-native linter exists in CI for any
        of these four today** - no eslint/prettier config anywhere under `bindings/nodejs` (not even
        listed in `package.json`'s `devDependencies`), no `composer.json` for PHP, no checkstyle/
        spotbugs/PMD plugin in Java's `pom.xml`, no `.clang-tidy` for C++. Each of these four already
        gets its Rust-glue-layer `cargo fmt --check`/`clippy --all-targets -D warnings` from `xtask`,
        which *is* the entirety of what CI checks for them beyond build/test - nothing to mirror
        that isn't already there. **Not the same finding as Python's real gap** - a language having
        no dedicated linter in CI at all is a separate, bigger scope decision (whether to add one)
        the owner didn't ask for here; flagging it as an observation, not treating it as this task's
        own gap.
      - **Python** - the one real gap, fixed: `xtask python()` now `require()`s `ruff` (same pattern
        as its existing `maturin`/`pytest` checks) and runs `ruff check .` then
        `ruff format --check .` after `pytest -ra`, matching `bindings-python.yml`'s own step order
        exactly.

      Verified with a real full run, not just a compile check: `cargo xtask python` (venv activated,
      `bindings/python/.venv`, per `.claude.local.md`'s documented setup) now runs cleanly end to
      end - `cargo fmt`/`clippy` clean, 87/87 pytest pass, `ruff check .` and `ruff format --check .`
      both green - the same command that would have caught both of this session's CI failures
      before either push.
- [x] **T-208** **Closed 2026-08-10, same session, all four languages - owner-requested directly
      after T-207's audit - add a real
      language-native static analyzer (not just a formatter) to Node.js/PHP/Java/C++'s CI, the four
      bindings T-207 found have none at all, matching what Python (`ruff`)/Ruby (`rubocop`)/every
      Rust-side crate (`clippy`) already get.** Owner directly challenged the asymmetry ("подвійні
      стандарти") - correct to challenge: there is no `docs/DECISIONS.md` entry excluding these four
      from static analysis, it is a real historical gap (these bindings never had one added at
      scaffolding time, T-49-T-53/T-158-T-163), not a considered decision.

      **Per advisor consult: implement in priority order, one language at a time, not all four in
      one pass** - ranked by realistic bug-catching value for *this repo's actual code shape*, not
      by ecosystem-parity alone:
      1. [x] **C++ / `clang-tidy` + `cppcheck`** - highest value: `bindings/cpp` is hand-written RAII
             (`unique_ptr` custom deleters, `friend class` pairings) mirrored across sibling headers
             by hand, exactly the shape `bugprone-*` catches real mistakes in; `cppcheck` added
             alongside per a direct owner follow-up request, a second differently-engined analyzer
             for a complementary bug class. **Done this session** - see below.
      2. [x] **Java / `SpotBugs`, not Checkstyle** - Checkstyle is style-only (would mostly generate
             churn on a ~6-class binding, not the `clippy` analog); SpotBugs is a bug-pattern
             detector, the real match for JNI's manual `byte[]`/`convert_byte_array`/
             `byte_array_from_slice` pairing (`native/src/*.rs` calls it, `Box512.java`/`Sign257.java`
             etc. declare the native methods) - exactly the resource/null-handling shape SpotBugs
             finds bugs in. **Done this session** - see below.
      3. [x] **Node.js / `ESLint`** - modest value: plain JS (no TypeScript source, `native/index.d.ts`
             is napi-rs-generated, not hand-written), only `js/index.js`/`js/secretstream.js` as real
             hand-written source. `eslint.config.js` with `@eslint/js` recommended rules, cheap to add.
             **Done this session** - see below.
      4. [x] **PHP / `PHPStan`** - lowest value, highest friction: no `composer.json` exists by
             deliberate design (D-144, Composer never manages compiled binaries) - fetching
             `phpstan.phar` via `curl` mirrors `phpunit.phar`'s own existing pattern correctly, but
             every `dstu_core_*` function is defined by the compiled `ext-php-rs` extension, not PHP
             source, so PHPStan will flag every call as an unknown function without a stub file
             (`.phpstan/stubs/dstu_core.stub.php` or similar) - a real design problem to solve, not a
             one-line config addition. **Done this session** - see below.

      **C++ implementation (phase 1, done)**: `.clang-tidy` at `bindings/cpp/` root, curated check
      list (`bugprone-*`, `performance-*`, `clang-analyzer-*`, explicitly not `*` - advisor flagged
      that an unscoped `*` floods on MinGW system headers and this project's own header-only style,
      costing the whole turn to triage noise instead of real findings), `HeaderFilterRegex` scoped to
      `include/dstu/` only (excludes the `cbindgen`-generated `dstu_core.h` - not hand-fixable, and
      system headers). New `xtask` functions `cpp-tidy`/`cpp-cppcheck` (owner asked for `cppcheck`
      too, right after seeing the first tool's real findings - a second, differently-engined analyzer
      catching a complementary bug class, not a duplicate of clang-tidy's own checks), both wired as
      a real required CI job (`bindings-cpp.yml`'s new `static-analysis` job, Ubuntu-only - neither
      tool reliably ships on the `test` job's other two OSes' default toolchains, and a three-OS
      analyzer matrix isn't otherwise needed for a header-only binding with no OS-specific code
      paths) - fails the job on any finding, matching this project's own "CI must fail on problems,
      not warn" standard, not an advisory-only run.

      **Real findings fixed this session, not left as noise** - `cargo xtask cpp-tidy` caught 11 real
      issues on its first run against every example plus `tests/test_dstu.cpp`:
      - **9x `bugprone-exception-escape` on every example's/test's `main()`** - every `dstu::*`
        operation that can throw (`Generate()`/`Seal()`/`Open()`/etc., via `CheckStatus`) was called
        directly in `main()` with no top-level catch, so an unexpected failure would `std::terminate`
        with no clean message instead of the "error: <what>" a caller should see. Fixed by wrapping
        each `main()` body in `try { ... } catch (const dstu::DstuException &e) { Die(e.what()); }`
        (or the local equivalent). **A residual, structurally-inherent instance of the same warning
        remains even after that fix** - `std::cout`/`std::cerr`'s own `operator<<` can theoretically
        throw `std::ios_base::failure` (confirmed with an isolated repro this session, not assumed -
        clang-tidy's trace pointed at this, not at the `dstu::DstuException` path, once the real
        catch was in place), which no example's `try`/`catch` catches since it isn't a
        `dstu::DstuException` and isn't a realistic failure mode for a fixed-destination stream -
        suppressed with `// NOLINTNEXTLINE(bugprone-exception-escape)` directly on each `main()`,
        with a comment citing this exact finding rather than a bare suppression.
      - **1x `bugprone-command-processor`** (`test_dstu.cpp`'s `RunCommand`, the real `uacrypt.exe`
        interop test's `std::system()` call) - genuinely safe here (every `cmd` is built from a
        compile-time binary path plus this test's own temp-directory paths, never external input,
        and there's no portable process-spawning alternative in the standard library) - suppressed
        with a `NOLINTNEXTLINE` placed on the actual `std::system()` call itself (both `#ifdef`
        branches), not on the enclosing function - the first attempt at this suppression put the
        comment above the function signature instead of the throwing line, which doesn't suppress
        anything; caught by re-running `cargo xtask cpp-tidy` after the "fix" and seeing the same
        finding still present, not assumed fixed from reading the diff alone.
      - **1x `bugprone-unused-local-non-trivial-variable`** (`test_dstu.cpp:302`'s `cppDecPath`) - a
        real dead local, declared alongside four other path variables but never read anywhere in
        `TestUacryptInterop()` (the C++-decrypts-uacrypt.exe's-output direction reads the plaintext
        in-memory via `SecretStreamDecryptor` directly, never via a written-out `cpp.dec` file) -
        removed, not suppressed, since it was genuinely unused rather than a false positive.

      Verified two ways before committing, not assumed: `cargo xtask cpp-tidy`/`cargo xtask
      cpp-cppcheck` both clean (0 findings) after the fixes, and a full `cargo xtask cpp` (build +
      `ctest` + all 8 examples run manually via PowerShell, output inspected) still passes - the
      `main()` try/catch rewrite touched every example's control flow, not just its lint status.
      **PowerShell, not Git Bash, for the manual run**: `ctest`/the example `.exe`s reported a bogus
      `STATUS_ENTRYPOINT_NOT_FOUND`ish failure (exit `0xc0000139`) launched directly from Git Bash
      immediately after this change, matching an already-documented, unrelated MinGW-binary/Git-Bash
      process-launch quirk (T-181's own finding, `CLAUDE.md`'s Agent-discipline section) rather than
      a real regression - confirmed by re-running the identical binary via the `PowerShell` tool,
      which passed clean, before concluding the C++ changes themselves were correct.

      **Java implementation (phase 2, done)**: `pom.xml`'s new `spotbugs-maven-plugin` (`effort=Max`/
      `threshold=Medium`, bound to the `verify` phase - `mvn test` alone does not reach it, so
      `xtask java()`/`bindings-java.yml` both switched from `mvn test` to `mvn verify`, still reading
      the same surefire reports for the existing interop-skip check). `spotbugs-annotations`
      (`provided` scope - compile-time-only, not needed on a consumer's own classpath) for
      `@SuppressFBWarnings` where a finding is a justified false positive rather than a real bug.

      First `mvn verify` run found 4 real `EI_EXPOSE_REP`/`EI_EXPOSE_REP2` findings ("may expose
      internal representation" - a Java array stays mutable through a `final` field regardless of
      the modifier, so returning/storing one by reference breaks value-object immutability):
      - **3x real bugs, fixed with a defensive copy**: `SecretStreamPullResult.plaintext()`,
        `SecretStreamPushResult.ciphertext()`/`authTag()` all returned their internal `byte[]` field
        directly - two calls to the same getter returned the *same* mutable array, so a caller
        mutating one return value would silently corrupt what a later call returns. Fixed with
        `.clone()` in each getter (each result object is a one-shot value from a single JNI call, not
        reused internally, so cloning at read-time rather than construction-time is sufficient and
        avoids a wasted extra copy for the common single-read case).
      - **1x justified false positive, suppressed not changed**:
        `SecretStreamEncryptor`'s constructor storing the caller's `OutputStream` by reference
        (EI_EXPOSE_REP2) - a streaming encryptor's entire purpose is writing to that same sink
        repeatedly over its lifetime, the identical "hold the wrapped stream by reference" shape
        `java.io.FilterOutputStream`/`DeflaterOutputStream` use in the JDK itself; there is no
        meaningful defensive copy of an `OutputStream` to make. Suppressed with
        `@SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "...")`, not a bare
        annotation - the reasoning is in the source, not just in this task entry.

      Verified with a real `mvn verify` run, not just a compile check: 86/86 JUnit tests pass,
      SpotBugs reports 0 findings, `cargo xtask java` (Rust `fmt`/`clippy --all-targets` on
      `native/`, then `mvn verify`) exits 0 end to end.

      **Node.js implementation (phase 3, done)**: new `eslint.config.js` (flat config, ESLint 10) -
      `@eslint/js` recommended rules only, the whole scope for plain CommonJS `js/`/`test/`/
      `examples/` source with no TypeScript to add stricter rules for; `ignores: ['native/**']`
      excludes napi-rs-generated output. `eslint`/`@eslint/js`/`globals` added as `devDependencies`,
      new `npm run lint` script, wired into `xtask nodejs()` (after `npm test`) and
      `bindings-nodejs.yml` (after the packaging sanity check). **First run: 0 findings** - matches
      the "modest value" prediction going in (only two real hand-written source files), a genuine
      result, not a sign the tool was misconfigured to be silent.

      **A real, pre-existing, machine-local toolchain issue was found and ruled out as unrelated**,
      not chased or "fixed" as part of this task: a full `cargo xtask nodejs` run on this dev machine
      fails at the `napi build` step with `error[E0514]: found crate napi_build compiled by an
      incompatible version of rustc` - `@napi-rs/cli`'s own build step explicitly shells out to the
      `stable-x86_64-pc-windows-gnu` toolchain's `cargo.exe` by hardcoded path, bypassing this
      directory's own `rustup override` (`1.87.0-x86_64-pc-windows-msvc`, `.claude.local.md`'s
      already-documented 2026-08-02 fix for this exact binding, confirmed still active via
      `rustup show`) entirely. **Confirmed unrelated to this session's changes via `git stash`**: the
      identical failure reproduces on a clean `master` checkout with none of this task's edits
      present. Not investigated further (out of scope for a static-analysis task, and GitHub's
      hosted `windows-latest` CI runner defaults to MSVC already per D-125/D-130's own reasoning, so
      this local-only toolchain-resolution quirk does not affect the actual CI gate being added
      here) - `npm run lint` itself (the real T-208 deliverable) was verified directly and
      independently, not through the broken full chain: `cd bindings/nodejs && npm install && npm
      run lint` exits 0.

      **PHP implementation (phase 4, done - T-208 fully closed, all four languages)**: the
      predicted friction was real, worked through methodically rather than rushed:
      - `phpstan.phar` fetched via `curl` (`bindings-php.yml`/`xtask php()` both mirror
        `phpunit.phar`'s own existing pattern - same D-144 "no Composer" posture, added to
        `.gitignore` the same way).
      - New `phpstan-stubs/dstu_core.stub.php` declares all 30 real `dstu_core_*` functions plus 5
        classes (`DstuCoreException`, `DstuCoreKupyna256Hasher`/`512Hasher`,
        `DstuCoreSecretStreamPushState`/`PullState`) and 7 constants - the compiled `ext-php-rs`
        extension's entire surface, transcribed from `src/*.rs`'s own real signatures (every
        `Binary<u8>` param/return is PHP `string`, matching the README's own documented convention),
        not guessed.
      - **A real, non-obvious PHPStan mechanism mistake found and fixed before landing**: the
        obvious-looking `stubFiles` config key does *not* declare brand-new symbols from scratch -
        confirmed empirically with an isolated repro (a stub function/class in a `stubFiles` entry
        still reported "not found") - it only refines the *types* of symbols PHPStan already
        discovers some other way (autoloading, reflection). `bootstrapFiles` (real PHP, actually
        executed once at analysis start) is the correct mechanism for this exact case - re-verified
        with the same isolated repro before trusting it, not assumed correct from switching the key
        name alone.
      - **PHPUnit's own `PHPUnit\Framework\TestCase` (and everything `tests/*.php` extends/calls)
        was unknown for the same underlying reason** - no Composer autoload wires phpunit.phar's
        classes anywhere. Fixed by adding `phpunit.phar` itself to `bootstrapFiles` - `require`-ing
        the phar directly exposes its classes without invoking its own CLI runner (confirmed
        empirically: no stray output/exit), avoiding a `phpstan/phpstan-phpunit` Composer dependency
        this project's own no-Composer posture would reject anyway.
      - One real gap in the stub file itself, found by the tool rather than assumed complete:
        `dstu_core_throw_error` (used internally by `lib/DstuCoreSecretStream.php`, see
        `src/error.rs`'s own doc comment) was missing - added with a real `never` return type (not
        `void` - it always throws), verified PHP accepts declaring (not calling) a `never`-typed
        function with an empty body before relying on it.
      - `phpstan.neon`: `level: 5` (a solid, commonly-recommended baseline - not PHPStan's max
        strictness, matching every other language's own "curated, not everything" analyzer posture
        in this task, e.g. `.clang-tidy`'s own curated check list), `paths: [lib, examples, tests]`.
        Needed `--memory-limit=512M` explicitly - this dev machine's own default `php.ini`
        `memory_limit` (128M) genuinely wasn't enough, confirmed by a real crash, not assumed as a
        precaution.
      - Wired into `xtask php()` (after the `phpunit.phar` run) and `bindings-php.yml`. **Caught and
        fixed a YAML-editing mistake before committing**: an `Edit` inserted the new PHPStan step in
        the middle of the existing `phpunit.phar` step instead of after it, producing a duplicate
        `working-directory:` key - caught by re-reading the diff (`git diff`, not just trusting the
        edit succeeded) and independently confirmed valid YAML via `python -c "import yaml;
        yaml.safe_load(...)"` before moving on.

      Verified with a real `cargo xtask php` run, not just each tool run manually: 88/88 phpunit
      tests pass, PHPStan reports 0 errors, `cargo fmt`/`clippy --all-targets` on `src/` clean.
- [ ] **T-209** **Not started, owner-requested (2026-08-12) - ship `uacrypt` itself as a `pip
      install`-able CLI, separate from the `dstu-core` Python binding.** Raised while setting up
      T-164/T-203's PyPI publisher for `dstu-core` - the owner asked whether the CLI binary should
      go on PyPI too. It's a distinct package, not an addition to `dstu-core`'s existing one: a
      Python user who wants the `uacrypt` command has no `pip install` path today (only GitHub
      Releases or `cargo install`, crates.io - both outside the Python ecosystem entirely).
      **Shape** (well-trodden pattern - `ruff`/`maturin` themselves ship this way): reuse
      `release.yml`'s existing `build-binary` job outputs (Linux x86_64/macOS aarch64/Windows
      x86_64 - the exact three platforms already built) instead of adding a new build path; each
      platform gets a wheel bundling the prebuilt binary plus a thin Python shim exposing a
      `console_scripts` entry point that just execs it - no Rust/PyO3 involved, unlike `dstu-core`'s
      own maturin-based wheels. **New PyPI project, own pending-publisher registration** (name TBD,
      `uacrypt` unless taken - not yet live-checked) - does not reuse `dstu-core`'s trusted publisher
      or environment. Not started: no packaging code, no CI job, no name check yet.
- [ ] **T-210** **Not started, owner-requested (2026-08-13) - post-publish smoke tests for each
      published language binding: install the real published package from its official registry
      (not local source), run usage examples against it, and cross-check against that binding's own
      README/instructions.** Raised right after D-191 (found by hand: PyPI/npm's live pages still
      said "provisional, not yet published" and described no working install path, because nothing
      re-checks a live registry page against its own claims after a publish). This is that missing
      repeatable check, not another one-time manual sweep.
      **Scope, per binding with a live publish** (today: Python/PyPI, Node.js/npm; RubyGems
      pending T-164/D-190): (1) install the real published package via its own package manager
      (`pip install dstu-core`, `npm install dstu-core`, eventually `gem install dstu_core`) into a
      clean environment - not the repo's own `.venv`/`node_modules`, which only proves the local
      source works, never what a real user gets; (2) run a handful of the same usage snippets shown
      in that binding's own README (a `secretbox` round-trip, `selfTest`/`self_test`, one or two
      more modules) against the *installed* package; (3) flag it if the installed package's
      behavior, exports, or install instructions don't match what the README currently claims.
      Could run manually right after each publish, or as a CI job triggered after `publish-pypi`/
      `publish-npm`/`publish-rubygems` succeed - either way, closes the "standing gap" D-191 itself
      flagged. Not started: no script, no CI job, no chosen cadence yet.
- [x] **T-211** **Confirmed and fixed 2026-08-29 (D-195) - `cargo miri test (dstu-core)` genuinely
      cannot fit in one job, at any `timeout-minutes` value.** Run `33208446660` (2026-08-28, left
      uncancelled the whole way to the 360-min hard cap) confirmed the prediction below: it got
      through only ~21 of ~41 test files before being killed, with `tests/dstu9041_encryption_512.rs`
      alone still running past the +128min mark when the axe fell. Real per-file timing, pulled from
      that run's log the same way this task originally proposed: lib unittests 504s, `crypto_box.rs`
      549s, `crypto_box512.rs` 2384s, `dstu4145_curve.rs` 3323s (only 6 of ~15 EC-heavy tests carry
      `#[cfg_attr(miri, ignore)]`, contradicting `rust.yml`'s own old comment claiming full coverage
      - see D-195), `dstu4145_gf2m{,257}.rs` 274s/550s (zero ignores), `dstu9041_curve.rs` 724s,
      `dstu9041_curve_512.rs` 2683s, `dstu9041_encryption.rs` 2040s, `dstu9041_encryption_512.rs`
      >7682s and still running. Extrapolating the ~20 still-never-measured files (`dstu9041_field*`,
      `dstu9041_message*`, `kalyna_*`, `kupyna*`, `randombytes.rs`, `selftest.rs`, `strumok.rs`) from
      D-59's stale ~84-min figure, real total is ~9-10h - roughly 1.5-2.5x GitHub-hosted runners'
      hard per-job ceiling, so no `timeout-minutes` value could ever have worked. Fixed by splitting
      into a dynamically-discovered per-test-file matrix (`miri-dstu-core-discover` +
      `miri-dstu-core` in `.github/workflows/rust.yml`) instead of raising the number a fifth time -
      see D-195 for the full rationale and the deferred follow-up (tighten each shard's
      `timeout-minutes` and extend the `#[cfg_attr(miri, ignore)]` audit once this shard-level data
      exists for all 41 files, not just the ~21 this run reached).

      **First sharded run (`33262340361`, 2026-08-29): all 47 miri jobs green** (43 per-file shards
      + `lib` + `uacrypt` + `dstu-core-capi` + the discover job), the first time this suite has ever
      completed on CI. Real per-file wall time (job duration, not just test time - includes runner
      setup): `dstu9041_encryption_512` 8862s/147.7min (the single biggest unknown going in - fits
      with ~212min of headroom under the 360-min cap, no ignore pass needed after all, superseding
      D-195's hedge on this file), `dstu4145_curve` 3322s/55.4min, `dstu9041_curve_512` 2641s/44.0min,
      `crypto_box512` 2496s/41.6min, `dstu9041_encryption` 1974s/32.9min, then a steep drop-off - every
      other file finished in well under 11 min, most under 2 min. Confirms this project's own
      "measure, don't assume" pattern one more time: the ~9-10h total estimated from D-59's stale
      figure was the right call to act on (a single job could never have finished), but the *reason*
      turned out to be four to five outlier files, not uniform growth across all ~43 - the
      `#[cfg_attr(miri, ignore)]` follow-up in D-195's deferred (1) should target those specifically,
      and `dstu9041_encryption_512` can now be dropped from that list.
- [ ] **T-212** **Not started, not committed - decision gate (2026-08-28): should the `uacrypt` CLI
      binary also ship through npm and RubyGems, the way T-209 already plans for PyPI?** Raised by
      the owner asking whether a libsodium-style project's CLI even belongs in language registries.
      Conclusion reached in that conversation: the registries' native job in the libsodium model is
      the *library* wrapper (`dstu-core` per language), which is already published for Python/Node/
      Ruby - libsodium itself ships no CLI. Distributing a CLI via npm (`esbuild`/`biome`/`npx`),
      PyPI (`ruff`/`uv`/`pipx`) or RubyGems (`rubocop`, gem `bin/`) is a real, well-trodden pattern
      (unlike Packagist, foreclosed by D-144), but it is a secondary channel for a standalone crypto
      CLI - the natural homes for that reach are Homebrew / Scoop / winget / GitHub Releases (done) /
      `cargo install` (done). The only strong argument for it is the narrow persona already in a
      pip/npm/gem workflow who wants the command without leaving it - the exact bet T-209 makes for
      PyPI. **Gate**: do not open per-ecosystem CLI-packaging tasks for npm/RubyGems until either
      (a) T-209 actually ships and shows uptake, or (b) a concrete user request lands. If unblocked,
      each ecosystem gets its own task mirroring T-209's shape (reuse `release.yml`'s existing
      `build-binary` outputs + a thin native-language shim over a bundled prebuilt binary, no
      PyO3/napi-rs/magnus involved; new registry project, own name check). A separate, arguably
      higher-value track if standalone-CLI reach is the real goal: a Homebrew tap / Scoop manifest /
      winget submission - not tracked here yet.
- [ ] **T-202** **Not started, owner-requested (2026-08-09) - research spike: is a Strumok-keystream
      + MAC ("Encrypt-then-MAC") authenticated construction a faster-but-still-safe alternative to
      `crypto_secretstream`'s current Kalyna-GCM-based AEAD for `uacrypt encrypt`/`decrypt`?**
      Prompted by the owner noticing Strumok's raw keystream throughput (~1870-2000 MB/s,
      `docs/PERFORMANCE.md` "Strumok" sections) is far ahead of Kalyna-GCM's authenticated
      throughput (~130-140 MB/s, `docs/DECISIONS.md` D-184's post-hardware-clmul numbers) and asking
      whether the gap means Strumok should be preferred - clarified in conversation that "block vs.
      stream cipher" is not actually the axis of that gap (GCM already turns Kalyna into a stream
      cipher internally via counter mode, mechanically the same XOR-a-keystream shape Strumok uses
      directly) - the real axis is authenticated (GHASH tag) vs. unauthenticated raw keystream.

      **Research finding (this session, in-process spike only, not a `PERFORMANCE.md`-grade
      binary-level number per D-34/[[perf_testing_policy]] - purely to answer the bottleneck
      question before deciding whether a real spike is worth building)**: compared
      `Kupyna256::digest` against `hazmat::kupyna_kmac::Kupyna256Kmac::mac` over the same buffers
      (64 KiB/1 MiB/10 MiB, release build, `crates/dstu-core/examples/kmac_spike.rs`, written and
      deleted this session, not committed). Result: KMAC tracks the bare digest almost exactly
      (~130-135 MB/s at 64 KiB and 10 MiB, ratio 0.99; a 1 MiB dip to ~91 MB/s/ratio 0.71 is noise
      from a single run, not repeated at the other two sizes) - **not** meaningfully slower than the
      hash it's built on, as expected from its construction (one dominant Kupyna pass over
      `PAD(K) || M || PAD(M) || ~K`, `hazmat/kupyna_kmac.rs`). This settles the open question from
      this session's research: **a naive Strumok-keystream + Kupyna-KMAC Encrypt-then-MAC
      construction would be MAC-bound at roughly the same ~130-140 MB/s ceiling Kalyna-GCM already
      achieves**, despite Strumok's own keystream being ~14x faster in isolation - the MAC step, not
      the cipher, is Kalyna-GCM's actual bottleneck today, and swapping the cipher alone would not
      close it. No meaningful net speedup is expected from the naive version of this proposal.

      **Follow-up finding, same session (2026-08-09), owner asked to research the GHASH-reuse
      variant specifically**: Kupyna-KMAC isn't the only candidate MAC - `hazmat::kalyna_gcm`'s own
      `compute_tag` (the GHASH-equivalent accumulate-and-multiply step, `Gf2m256::multiply` under
      it) is a *separate* step from its CTR-mode keystream generation (`apply_keystream`), already
      hardware-`clmul`-accelerated (T-198/D-184) independent of which cipher generated the
      keystream. Isolated both steps directly (temporary `#[cfg(test)] mod` inside
      `crates/dstu-core/src/hazmat/kalyna_gcm.rs`, same "isolated timing diagnostic" pattern D-76/
      D-184 already used - written, run, then removed this session, not committed) at 1 MiB/10 MiB:
      `compute_tag` alone runs at **~950-960 MB/s**, `Strumok256::apply_keystream` alone at
      **~1930-1940 MB/s** (both release-build, in-process - same D-34 caveat as above). Run
      sequentially (as a real Encrypt-then-MAC construction would: keystream pass, then a separate
      tag pass over the ciphertext, matching `compute_tag`'s current non-fused shape) the implied
      combined throughput is **~637-642 MB/s** - **~4.6-4.9x faster than Kalyna-GCM's current
      ~132-139 MB/s ceiling** (`docs/PERFORMANCE.md` T-198 section), and consistent with that
      section's own observation that post-`clmul` GCM now runs at ~81-85% of Kalyna's *bare*
      cipher ceiling (163.82 MB/s) - meaning the block cipher itself, not GHASH, is Kalyna-GCM's
      remaining bottleneck, which a faster cipher (Strumok) directly attacks while reusing the
      already-fast tag mechanism. **This is the first concrete, empirically-grounded case in this
      task where a Strumok-based AEAD alternative shows a real, large projected win** - unlike the
      Kupyna-KMAC variant above, which showed none. **Still not a decision to implement**: an actual
      "Strumok + GHASH" construction needs its own from-scratch design (how the GHASH key `H` is
      derived without a block cipher's `E_K(0)` - e.g. from Strumok's own first keystream block, the
      way ChaCha20-Poly1305 derives its one-time Poly1305 key from ChaCha20's own first block - and
      how nonce/AAD binding is handled), its own misuse/rejection/active-attack test matrix per this
      project's standing test-first rules, and the D-47 tie-breaker below applies to that design the
      same as it would to the Kupyna-KMAC variant. Kalyna-GMAC's own docs numbers
      (`docs/PERFORMANCE.md` "Kalyna-GMAC" section, ~12-17 MB/s) are not a usable comparison point
      either way - that table is a fixed single-block benchmark (D-71, sidesteps a UAPKI streaming
      bug) and not representative of GMAC's real multi-block throughput.

      **D-47 tie-breaker applies before any implementation, not after**: no DSTU standard defines
      this specific Strumok+MAC composition (Strumok is only standardized as a bare keystream, DSTU
      8845:2019) - so if a genuinely faster composition is later found, its nonce/key-separation
      design has no settling citation and must be resolved via D-47's ranked tie-breaker (TLS 1.3/
      modern-AEAD consensus, then libsodium's API shape, then safe-modes-only) or asked directly of
      the owner, matching every other from-scratch construction in this project
      (`crypto_secretstream` itself, D-68). **Not picked up for implementation this session** - this
      entry is the research/documentation half of the owner's own framing ("оформимо таску і
      дослідимо" - formalize a task and research it), explicitly not a build-now request.
- [ ] **T-201** **Not started, owner-requested (2026-08-09) - PKCS#11 (Cryptoki) support, as a
      separate sibling project, not part of this repository.** `docs/DECISIONS.md` D-17 already
      excludes PKCS#11/12 from this project's own scope explicitly ("the layer above crypto
      primitives... not this project's job" - this repo is a libsodium-style primitives library,
      not a PKI/token-integration SDK, same reasoning that keeps ASN.1/X.509/CSR/browser-signing
      out too). Raised again directly by the owner asking to add a task for "safe/secure
      implementation" of PKCS#11; clarified in conversation that this means a new, separate
      repository that *depends on* this project, not a scope change to D-17 itself - consistent
      with D-17's own "not acted on now, noted for later" aside about a future C-ABI-consuming PKI
      stack.

      **The actual connection point already exists and needs no new work here**: `crates/
      dstu-core-capi` (D-119/D-148, T-158) already ships a stable C ABI - opaque handles, explicit
      `DstuStatus` error codes, `catch_unwind` at every boundary, zeroize-on-free, a `cbindgen`-
      generated `include/dstu_core.h`. A PKCS#11 module would link against the built `dstu_core`
      `.so`/`.dylib`/`.dll` exactly the way the .NET/Go/C++ bindings already do (`docs/
      bindings-strategy.md`), not reimplement Kalyna/Kupyna/Strumok/DSTU 4145/DSTU 9041.

      **What a PKCS#11 module actually is, so this isn't scoped naively**: mostly *not* crypto math
      - it's the Cryptoki C interface itself (`C_Initialize`/`C_GetSlotList`/`C_OpenSession`/
      `C_Login`/`C_Sign`/`C_Decrypt`/... - the full function table PKCS#11 v2.40/v3.0 mandates),
      plus session/slot/object/attribute-handle management, plus - the genuinely security-critical
      part the owner's "safe implementation" framing is really about - private-key custody:
      - **Real hardware/token backing** (a smart card, USB token, HSM): the private key never
        leaves the device at all: this project's own primitives are used for the *public*-facing
        operations (verify, maybe host-side hashing before a sign request), not for holding the
        secret.
      - **Software-emulated token** (no real hardware, PKCS#11 as a local API shim): must honor
        `CKA_SENSITIVE`/`CKA_EXTRACTABLE=false` for real, not just accept the attribute and ignore
        it - the key material must not be exportable through the API surface even though it lives
        in this process's own memory. Needs its own threat model pass (this repo's `docs/
        SECURITY.md` pattern is the template, not a copy of it): PIN handling/rate-limiting, secure
        erasure on session close, and being explicit that "software PKCS#11" is a weaker guarantee
        than real hardware - never marketed as equivalent.

      **Explicitly not scoped here beyond this pointer**: no design for the new repo's own
      architecture, module layout, or implementation plan - that's real work for when this task is
      actually picked up, likely its own `advisor()`-reviewed plan given the security stakes (D-17's
      own "ask, don't guess" standard for scope forks with no settling citation applies just as much
      to a new sibling project's design as to a change inside this one). No committed timeline.
- [x] **T-199** **Done 2026-08-09, owner-requested ("Так починай").** Full landing: `hazmat::
      dstu4145::{gf2m257, curve257, scalar257, signature257}` (field/point/scalar/sign-verify,
      test-first against BC-generated oracle vectors, `tests/vectors/dstu4145/gf2m257_arith.json`
      / `tests/oracle-harness/java/.../Dstu4145VectorGen257.java`), the additive
      `crypto_sign257`/`CurveId` library layer, and full `uacrypt` CLI wiring
      (`sign-keygen257`/`sign-pubkey257`/`sign257`, plus a tag-aware `verify` shared with `m=163`).
      `cargo clippy --all-features -- -D warnings`/`cargo fmt --check`/`--no-default-features`
      clean throughout; `dstu-core-capi` confirmed still compiles unaffected (the point of the
      additive-sibling design, see below). Two real correctness/design findings from this pass,
      full detail in `docs/DECISIONS.md` D-186's addenda:
      1. **`signature257`'s `truncate` bug**: used `m-1=256` bits instead of the actually-correct
         `n.bit_length()-1=255` (`n.bit_length() == m` holds for `m=163` only by coincidence of
         that curve's specific order) - `sign` matched the BC oracle regardless (an over-wide `r`
         round-trips through `sign`'s own output unchanged), but `verify` rejected nearly every
         valid signature until fixed. Caught by the oracle's independent `verify`-direction check,
         not `sign` alone - closed with both an empirical fix and a second, *provable* test
         (`truncate_255_output_is_always_below_n`: `n >= 2^255` unconditionally, `truncate_255`'s
         output is always `< 2^255` by construction, so `r < n` holds for every input, not just
         ones a random sample happened to cover).
      2. **`advisor()`-caught architecture reversal**: this entry's own earlier Decisions 1-3 (a
         curve-tagged `enum SigningKey`/`VerifyingKey`/`Signature` replacing `crypto_sign`'s
         existing types) would have broken `dstu-core-capi/src/sign.rs`'s C ABI for no benefit the
         alternative doesn't also deliver - found only once the real fan-out
         (`grep -rl "crypto_sign::"`) was checked, after which `crypto_box512`/T-193's own
         already-established precedent (additive sibling module, capi wiring deferred) applied
         directly. `crypto_sign257` ships as a full sibling of `crypto_sign`, not a breaking
         rewrite of it - see D-186's addendum for the complete reasoning, now the actual shipped
         design, not just a proposal.
      Also closed under `advisor()` review before any CLI verify path shipped: `curve257`'s
      cofactor-4 small-subgroup gap (flagged open in this entry's own earlier draft, step 6) -
      `signature257::verify` now checks `q.scalar_multiply(&order()) == Infinity` (the general,
      cofactor-independent SP-800-56A-style check, not `m=163`'s cofactor-2-specific `x == 0`
      shortcut), proven against a real constructed order-2 point in
      `tests/dstu4145_signature257.rs`.
      Nonce derivation (D-186 Decision 5) resolved with `Kupyna384Kmac` (48-byte key/output, 128
      bits of margin over `curve257::order()`'s ~256-bit width) instead of `crypto_sign`'s
      `Kupyna256Kmac`.
      Original plan follows, unchanged (historical record - see the summary above for what
      actually shipped and where it diverged):

      ("Так давай зразу таску на те. З
      тестами першими" - "yes, let's make a task for that right away, tests first"). Add `m=257` as
      a second `hazmat::dstu4145` curve, alongside the existing `m=163` (not replacing it - `m=163`
      stays the `crypto_sign` default per D-46, this is a new `hazmat`-level option). Domain
      parameters, provenance, and the privacy constraint on any committed test vector are all in
      `docs/DECISIONS.md` D-185 - read that first, don't re-derive.

      **Why this curve specifically, not another of the 9 unimplemented sizes**: `m=257` is what
      Diia's own qualified-trust infrastructure actually issues today, confirmed from two
      independent real certificates (D-185) plus Bouncy Castle's `DSTU4145NamedCurves.java`
      `curves[6]` as a third match - not an arbitrary standard-compliant pick.

      **Scope decided 2026-08-09 (owner follow-up, `docs/DECISIONS.md` D-186 has the full
      reasoning - read that before implementing, don't re-derive)**: this ships in the `uacrypt`
      binary, not `hazmat`-only. `crypto_sign` supports `m=257` as a first-class signing option
      alongside `m=163` (not a replacement); `verify` self-determines which curve a given
      key/signature uses via an explicit one-byte tag prefix (`0x01`=m=163, `0x02`=m=257,
      D-186 Decision 1), verifies if the curve is supported and reports **which** curve validated
      it (`Result<CurveId, VerifyError>`, D-186 Decision 2 - a policy-sensitive caller must be able
      to reject a weaker-curve signature where a stronger one was expected, this is a real
      downgrade-shaped concern, not just ergonomics), and returns a specific
      `VerifyError::UnsupportedCurve(tag)` - not a generic parse failure or silent `false` - for any
      unrecognized tag (D-186 Decision 3).

      **Test-first plan, in order** (owner's explicit ask - tests before the implementation they
      exercise, same discipline `CLAUDE.md`'s "Test-first, always" already requires project-wide,
      stated here because this task starts from zero for `m=257`, nothing to retrofit):
      1. **Field arithmetic vectors first** (`gf2m257` or equivalent, mirroring `gf2m163`'s own
         `multiply`/`square`/`reduce`/`invert` shape - D-25's "no reusable code, only a reusable
         style reference" note applies again here, this is a new module, not a generalization of
         `gf2m163`). Generate unit-level arithmetic vectors the same way `gf2m163_arith.json` was
         made (Bouncy Castle as the sole oracle at this granularity, `oracles/bouncycastle-java`) -
         write the failing test against those vectors before writing `multiply`/`reduce` themselves.
         **Software and hardware paths land together, not sequentially** (D-186 Decision 4 -
         `m=163`'s own hardware dispatch, D-184/T-198, only arrived as a later task because the
         design wasn't proven yet; it is now): `poly_mul_wide`/`reduce` first against the BC
         vectors, then `poly_mul_wide_hw` (`PCLMULQDQ`/`PMULL`, `std`-gated runtime dispatch, same
         `clmul_native::feature_available()` pattern), plus the `multiply_sw`/
         `multiply_matches_explicit_software_path` coverage-gap tests from day one so the portable
         path stays under real test pressure on every capable CI runner.
      2. **Curve point arithmetic vectors next** (`curve257` or equivalent, mirroring `curve163`'s
         `Point::add`/`double`/`scalar_multiply`/`negate`) - same BC-oracle-generation approach as
         `curve163`'s own arithmetic tests, written failing before the point-arithmetic code exists.
      3. **Sign/verify oracle - no official worked example exists for `m=257`** (unlike `m=163`'s
         Annex B.1) so the D-14/D-25-style "official vector" tier isn't available here; two options,
         pick one or both before writing `sign`/`verify`:
         - A Bouncy-Castle-generated sign/verify vector (`DSTU4145Signer` against this curve's
           parameters), same dual-oracle posture already used elsewhere in this project when no
           primary-text worked example exists.
         - The **test**-CA signature from D-185's `czo.gov.ua` download (`ДП "ДІЯ" (ТЕСТ)` issuer,
           already public/disposable by design, safe to vendor into `tests/vectors/`) - verify
           against its real public key and real signature bytes. **Never** the owner's own
           production certificate/signature from the same investigation - D-185's privacy note is
           binding, not optional, for whatever gets committed here.
         Nonce derivation for this curve's own ~256-bit order needs its own re-derivation, not a
         copy of `m=163`'s KMAC-reduction constants (D-186 Decision 5) - test that reduction against
         its own boundary cases before trusting `sign`'s output.
      4. **Tag-byte round trip and unsupported-curve dispatch, written as tests before the dispatch
         code**: `SigningKey`/`VerifyingKey`/`Signature` parse to the right curve variant for
         `0x01`/`0x02`, and a crafted `0x00`/`0x03`/`0xFF`-tagged input produces
         `VerifyError::UnsupportedCurve(tag)` specifically (not a generic error, not a panic) -
         this is the "якщо ні - повідомлення" requirement, verify it's an actual typed error a
         caller can match on, not just that verification fails.
      5. Only after 1-4 have failing tests in place: implement `gf2m257`/`curve257`/the tagged
         key-and-signature format/wire the new curve into `dstu4145`'s `sign`/`verify` until
         everything passes.
      6. Full three-category coverage per `CLAUDE.md`'s standing rule once sign/verify exist:
         correctness (step 3's oracle), rejection (tampered signature/wrong key), misuse (invalid
         lengths, degenerate scalars, malformed tag byte) - plus the active-attack category T-183
         already established for asymmetric primitives (invalid-curve/twist/boundary-scalar checks,
         mirroring what T-189/D-172 already found for `m=163`'s own `verify` - re-derive for this
         curve's own cofactor/subgroup structure, don't assume it carries over unchanged).

      **Resolved (see the completion summary above for the actual shipped shape)**: the type-shape
      question landed on distinct sibling types (`crypto_sign257`, not a curve-tagged enum) and
      `uacrypt` grew `sign-keygen257`/`sign-pubkey257`/`sign257` as separate subcommands (matching
      `box-keygen512`'s own already-established precedent) - `verify` alone stays unified and
      curve-tag-aware, since that's the one surface that actually receives curve-unknown-in-advance
      input.
- [x] **T-188** **Done 2026-08-07, owner-requested.** SonarCloud Quality Gate was
      `ERROR` on `new_duplicated_lines_density` (3.0% actual vs. `<=3%` required) - missed in T-187's
      own SonarCloud check because that check only queried `api/issues/search` (rule-violation
      issues), and duplication isn't reported as an issue in this project's active ruleset, only as
      a separate measure/Quality Gate condition; the CI job itself doesn't fail on this either,
      since `.github/workflows/sonarcloud.yml` has no `-Dsonar.qualitygate.wait=true`, so a green
      GitHub Actions run doesn't mean the gate passed. Two duplication sources found via
      `api/measures/component_tree`: `crates/dstu-core/src/hazmat/tables.rs` (92.6%, 4292 lines,
      S-box/MDS constant-array literals - inherent to a duplication *line* detector looking at data
      tables, not a real code smell, not touched) and `crates/uacrypt/src/lib.rs` (13.4%, 918 lines,
      34 real duplicate groups via `api/duplications/show` - every `parse_*_args` function
      hand-rolled an identical `while i < args.len() { match args[i].as_str() { "--flag" => ... } }`
      token-scanning loop, differing only in which flags/types each command needs). Fix: a shared
      `ArgScanner` helper (new, `crates/uacrypt/src/lib.rs`) doing the scan/dispatch mechanics once;
      each of the 19 `parse_*_args` functions now just declares its own flag list and builds its
      struct from typed accessors (`.path()`/`.path_opt()`/`.variant()`/`.iterations()`/
      `.bool_flag()`) - same `CliError` variants, same messages, same left-to-right error precedence
      (including which `MissingFlag` fires first when several required flags are absent, since
      accessor calls run in the same struct-field order the original `Ok(Struct { ... })` blocks
      already had). Existing `#[cfg(test)]` suite already asserts exact `CliError` values per
      command (missing/unknown flag, invalid variant/iterations) - that coverage is the safety net
      for this refactor, not new tests written for it. **Verified**: `cargo test -p uacrypt` -
      135/135 pass, unchanged, including the specific tests that pin exact `CliError` precedence
      (`parse_ccm_args_requires_nonce_and_tag`, `run_help_flag_takes_priority_over_missing_required_
      flags`, etc.) - the concrete evidence the refactor didn't silently change behavior, not just
      "it compiles". `cargo clippy -p uacrypt --all-features -- -D warnings`/`cargo fmt --check`
      clean, `cargo xtask build`/`docs-check` clean. Net effect: `crates/uacrypt/src/lib.rs` 6871 ->
      6280 lines (848 deletions/257 insertions) - real reduction, not just moved code, since 19
      near-identical scanning loops collapsed into one shared implementation. Confirmed on
      SonarCloud's own API after pushing: `api/qualitygates/project_status` went from `ERROR`
      (`new_duplicated_lines_density` 3.0) to `OK` (1.1); project-wide `duplicated_lines_density`
      24.4% -> 22.0%. **Follow-up done the same session, owner-requested**: `sonarcloud.yml`'s scan
      step now passes `-Dsonar.qualitygate.wait=true` - without it the action uploads the analysis
      and exits 0 immediately, before the Quality Gate is evaluated server-side, so the job never
      actually saw the result (confirmed the hard way: the real `ERROR` gate above sat undetected
      through a fully green CI run). This step now polls and fails the job itself on a non-OK gate.
- [x] **T-187** **Done 2026-08-07, owner-requested follow-up to T-186.** `docs/PERFORMANCE.md`
      "vs. international-standard analogs" (D-106) has five hand-measured, hand-typed comparisons -
      one per in-scope DSTU standard (Kalyna vs AES, Kupyna vs Whirlpool, Strumok vs ChaCha20,
      DSTU 4145 vs ECDSA, DSTU 9041/`crypto_box` vs ECDH+CMS) - each its own manual `openssl speed`/
      `openssl cms` recipe, different units, different setup steps. Owner wants one `cargo xtask`
      command, one code path, one consistent table style covering all five DSTU standards actually
      implemented, instead of re-typing five different recipes from doc-embedded instructions every
      refresh. Scope confirmed explicitly: the five DSTU-standard-level rows only (Kalyna's
      individual modes - CCM/GMAC/KW/etc. - stay compared against UAPKI, a separate, already-covered
      axis, not part of this task); OpenSSL only, no real libsodium build (X25519/brainpoolP256r1 via
      OpenSSL stay the existing "closest analog" stand-in, matching D-106 exactly, no new toolchain
      dependency this project would then have to vet per `docs/SECURITY.md`/`docs/ORACLES.md`).
      New `xtask/src/bench.rs` module (`cargo xtask bench-compare`, optional/best-effort like every
      other tool-dependent command, **not** in `ci()`'s loop - this project's own stated methodology
      says perf numbers need a real, uncontested dev machine, never a noisy shared CI runner, and no
      perf comparison has ever run in CI here). Methodology, one code path for all five: `uacrypt`
      side always wall-clocks the real `target/release/uacrypt <cmd> --iterations N` process (the
      same canonical D-34 "binary-level" approach this file already uses everywhere, just automated);
      OpenSSL side parses `openssl speed`'s own self-reported `N ops in T s` line directly (not
      reimplementing its internal timing loop - it's the already-validated tool this project's
      published numbers are measured against) for the four `openssl speed`-supported cases, and
      wall-clocks external `openssl cms` invocations itself for the fifth (CMS has no `speed`
      support, matching the existing hand-documented recipe). One shared table-printing function
      emits every case in the same `| Metric | uacrypt | OpenSSL analog | Ratio |` shape regardless
      of whether the unit is MB/s (bulk ciphers/hashes) or ops/s (fixed-size signature/KEM ops) -
      "unified style" means one path and one visual shape, not literally one unit, since MB/s for a
      signature op or ops/s for bulk throughput would both be meaningless, per the existing DSTU
      9041 table's own "two tables, two different questions" framing. Output prints to stdout in
      the exact markdown shape `docs/PERFORMANCE.md` already uses - copy/pasted in by hand on a
      refresh, same as today; deliberately not auto-editing the doc itself, since the prose caveats
      around each table are load-bearing, not decoration, and a script clobbering them silently
      would be worse than the manual-recipe problem this task exists to fix.
      **Built and run for real** (`cargo xtask bench-compare`), not just compiled - per
      `CLAUDE.md`'s own "spike, read the actual output" discipline. First run silently produced
      zero data rows for every case except the CMS one - found by adding temporary debug output
      rather than guessing: `openssl speed`'s own `Doing ... ops in Ts` progress line is written to
      **stderr**, not stdout (only the final rounded summary table is on stdout) - invisible in
      every manual spike this task's own design phase did, since those all used a `2>&1`-merged
      shell redirect. Fixed by parsing `stderr` instead; a real run afterward produced sane numbers
      matching the existing published magnitudes closely (DSTU 4145 `sign` 685.27 ops/s here vs.
      667.39 in the last committed T-153/D-109 measurement, well within normal machine-load
      variance) across all six tables (Kalyna/AES, Kupyna/Whirlpool, Strumok/ChaCha20, DSTU 4145/
      ECDSA, DSTU 9041 ops/s vs ECDH, DSTU 9041 MB/s vs CMS). `cargo clippy -- -D warnings`/
      `cargo fmt --check` clean on the new module. `docs/PERFORMANCE.md` itself was not touched by
      this task - refreshing its committed numbers with this tool's output is a separate, future
      action, not implied by building the tool.
- [x] **T-185** **Done 2026-08-07, owner-requested.** Owner flagged the `gh-pages` landing page
      (both `index.html`/`uk/index.html`) as carrying stale facts and asked for a full pass over
      GitHub-facing docs, not just a spot fix. Full enumeration of every quantitative/version claim
      in the site (not a keyword grep) found: (1) version badge said `v0.1.0` in three places (hero
      status-note EN/UK, Status-section EN/UK) though the real tagged release is `v0.2.0`
      (2026-08-02) - fixed to state `v0.2.0` as the released version *plus* an explicit note that
      DSTU 9041/`crypto_box`'s CLI surface (`box-keygen`/`box-pubkey`/`box-seal`/`box-open`) is
      `master`-only, still in `CHANGELOG.md`'s `[Unreleased]` section, not in the v0.2.0 tag - the
      page already described `crypto_box` as done, so silently stamping `v0.2.0` on the whole page
      would have told a reader to download the v0.2.0 release binary and run a verb it doesn't have.
      (2) `<meta name="description">`/`og:*`/`twitter:*`/JSON-LD blocks (both files' `<head>`) still
      listed only "Kalyna, Kupyna, Strumok, DSTU 4145", omitting DSTU 9041 that the visible body
      copy already covers - fixed all four EN copies + four UK copies (8 total). (3) The "Try it"
      section's heading ("The CLI has three verbs to remember") and code sample were already stale
      before DSTU 9041 (the sample showed 8 commands, not 3) and omitted the `box-*` verbs entirely
      after T-178 - reworded the heading and extended the code sample.
      README.md's own `v0.1.0` header line got the same released-vs-unreleased framing fix (not a
      bare version bump) for consistency with the site.
      **The DSTU 4145 perf numbers the owner also flagged turned out to be current** (~7.9x/~5.2x
      vs. `nistb163`, matches `docs/PERFORMANCE.md`'s T-153/D-109 entry, the page's own most recent
      perf update) - no change needed there, noted so a future session doesn't re-flag it blind.
      **Also fixed while auditing**: `docs/user-journey-gaps.md`'s Persona 1 table quoted the same
      stale `v0.1.0` README banner text and pinned the Acquire row to "GitHub Release `v0.1.0`"
      specifically - reworded both to describe the current release generically (so a future v0.3.0
      doesn't make this table stale again the same way) and flagged that `box-*` isn't in any
      tagged release yet.
      **Found, not changed - flagged for the owner instead of auto-edited**:
      `docs/release-readiness.md`'s "What's missing for the CLI / release-mechanics surface" section
      calls the C ABI crate (`crates/dstu-core-capi`) one of "all nine bindings done", while
      `CLAUDE.md`'s own already-current "Second priority" section (and this file's own binding tasks)
      count eight language bindings with the C ABI as a separate, distinct thing it's built on - not
      itself a "binding". Not a factual error (all nine things it lists are genuinely done), just an
      inconsistent label; left alone rather than auto-edited since it's a wording judgment call, not
      a stale fact.
      **The gh-pages edits above live in the existing local worktree
      (`C:/Users/Pa/AppData/Local/Temp/uacrypt-ghpages`, branch `gh-pages`) only - not committed or
      pushed.** Publishing a live site is shared-state/hard-to-reverse, so that step needs the
      owner's explicit go-ahead, same standing rule as any other push.
      **Audit scope note**: `docs/DECISIONS.md` (11.6k lines)/`docs/TASKS.md` (5.2k lines) are
      append-only logs by design - per the global "never silently deprecate a document" rule,
      compressing them wasn't attempted here; only *current-state* surfaces (README, the site,
      `docs/dstu-crypto-project.md`, `docs/release-readiness.md`, `docs/user-journey-gaps.md`,
      `docs/bindings-strategy.md`, `docs/ORACLES.md`, `docs/resource-profiles.md`,
      `docs/CHANGELOG.md`, `CLAUDE.md`'s own "Project status"/"Second priority") were read end to
      end for drift. See the follow-up findings this pass surfaced, if any, appended immediately
      below or as a new backlog item - do not assume this task means "all docs are now current
      forever," only that this specific pass is complete.
- [x] **T-186** **Done 2026-08-07, owner-requested follow-up to T-185.** Asked what other projects
      do about doc bloat/staleness and a knowledge base usable by both humans and AI; chose two of
      the four options presented (ADR-per-file and `llms.txt` were the other two, not picked):
      mdBook for the existing `docs/*.md` corpus, plus a mandatory `cargo xtask` freshness lint.
      **mdBook** (`book.toml`, new, repo root; `docs/SUMMARY.md`, new; `docs/introduction.md`, new,
      `{{#include ../README.md}}` so README stays the single source of truth) - `src` points
      straight at the existing `docs/` directory, **no existing file moved or renamed**, so none of
      the many `docs/DECISIONS.md`-style cross-references anywhere in the repo needed touching.
      Grouped into Project & roadmap / Engineering / Algorithm pseudocode / History / Contributing,
      mirroring `CLAUDE.md`'s own "Documentation map" table (that table already had the right
      taxonomy, just not machine-readable). Spiked for real per `CLAUDE.md`'s own "read the actual
      output, don't plan from config alone" rule: `cargo install mdbook --locked`, `mdbook build`
      against the real tree - found and fixed a real issue, not a hypothetical one: README.md's
      repo-relative links (`bindings/*/README.md`, `docs/CONTRIBUTING.md`/`CODE_OF_CONDUCT.md`)
      resolve correctly on GitHub (README lives at repo root there) but wrong once transcluded into
      `docs/introduction.md` (relative to `docs/` instead) - fixed by switching those 10 links to
      absolute `github.com/user137/uacrypt/blob/master/...` URLs, which read identically on GitHub
      and now also resolve correctly inside the book; no other `docs/*.md` file had this pattern
      (checked directly, not assumed). New `cargo xtask book` subcommand (optional/best-effort,
      same `require("mdbook", ...)` pattern as `miri`/`kani`, added to `ci()`'s best-effort loop
      too). New `.github/workflows/docs-book.yml`: builds on every push to `master` touching
      `docs/**`/`book.toml`/`README.md` (owner's explicit choice: automatic, not
      `workflow_dispatch`-gated), publishes `target/book/` into the existing `gh-pages` branch
      under a new `/book/` subdirectory via plain git commands (not a third-party gh-pages action -
      `cargo install mdbook --locked` from crates.io plus `git push` using the job's own
      `GITHUB_TOKEN`, matching this project's existing supply-chain posture and the fact that
      T-185 already published `gh-pages` by hand the same way) - the hand-crafted landing page
      (`index.html`/`uk/index.html`) is never read or written by this workflow, only `book/` is
      replaced each run. **This specific workflow's actual GitHub Actions run could not be
      end-to-end-verified from this session** (no way to trigger/observe a real Actions run here) -
      flagged honestly rather than claimed as tested; needs a first real push to confirm. Added a
      "Docs" link (`book/` EN, `../book/` UK) to the landing page's existing footer, both languages
      - the one hand-authored-content touch in this task, everything else about the site was
      additions (marker comments) or new files.
      **Freshness lint** (`cargo xtask docs-check`, new `docs_check()` in `xtask/src/main.rs`,
      zero-dependency per `xtask`'s own stated design) - catches exactly the class of bug T-185
      fixed by hand: (1) `crates/dstu-core`'s and `crates/uacrypt`'s `Cargo.toml` `[package]
      version` must match (CLAUDE.md's own "bump it in two places" rule, now checked not just
      documented); (2) a new canonical `<!-- uacrypt-version: X.Y.Z -->` HTML-comment marker (one
      in `README.md`, one each in gh-pages `index.html`/`uk/index.html`) must equal the Cargo.toml
      version - a fixed marker deliberately, not a regex over the human-facing prose sentence
      around it, since that prose got reworded twice in T-185's own session alone and would need
      chasing forever otherwise. The gh-pages half resolves a `gh-pages` git ref (local, then
      `origin/gh-pages`, then a one-time `git fetch origin gh-pages --depth=1` + `FETCH_HEAD`) and
      reads both HTML files via `git show` against that ref - no HTML parser, no new dependency. **Owner's
      explicit choice: mandatory, not a warning** - wired into `ci()`'s existing `mandatory` chain
      alongside `fmt`/`build`/`test`/`clippy`, and into `.github/workflows/rust.yml`'s `test` job
      right after the `fmt --check` step. Verified for real, not just "it compiles": ran clean
      against the actual repo state (exit 0), then a deliberate marker mismatch was introduced and
      confirmed to fail with an actionable message and exit 1, then restored and reconfirmed clean.
      A separate CI-workflow step to pre-fetch `gh-pages` (originally planned) turned out
      unnecessary once `docs_check()`'s own self-fetch fallback was written and tested - one code
      path handles both the local-dev-machine case (ref already exists) and the fresh-CI-checkout
      case (fetches it), so the workflow file doesn't need its own separate fetch step.
      **Deliberately not done this pass, per the owner's own "audit, don't restructure" framing
      from T-185**: `docs/DECISIONS.md`/`docs/TASKS.md` are unchanged in structure or content -
      mdBook renders them exactly as they are, an ADR-per-file split (the road not taken from the
      four options presented) would be a separate, larger, explicitly-owner-gated decision, not a
      side effect of this task.
- [ ] **T-184** **Not started, no committed timeline - owner-requested backlog item, 2026-08-06.**
      Investigate why `crypto_box::seal`/`open`'s own bulk throughput (~8.84/10.72 MB/s at 10 MiB,
      `docs/PERFORMANCE.md`'s T-179 same-regime table) sits at roughly **half** the raw
      `hazmat::kalyna_gcm::Kalyna256_256Gcm` cipher's own throughput (17.09 MB/s at the same 10 MiB
      scale, same file's Kalyna-GCM 256-256 row) - noted at the time as "not chased further this
      session," never actually profiled.
      - **What's already ruled out, don't re-derive**: the two KEM scalar multiplications
        (sub-millisecond, negligible next to a 10 MiB bulk operation) and the underlying block
        cipher itself (already measured separately at 17.09 MB/s). The remaining suspect, stated
        but not verified, is `crypto_secretstream`/`crypto_box`'s own per-call framing and
        allocation overhead - `seal`/`open` are one-shot (`Tag::Final`, no real chunking, D-169's
        own module doc), so this isn't chunking overhead in the usual streaming sense; more likely
        candidates are the `Vec<u8>` allocations `crypto_box::seal`/`open` and
        `crypto_secretstream::push`/`pull` each do internally, and/or AAD/tag-construction
        overhead per call that a raw `Kalyna256_256Gcm::encrypt`/`decrypt` benchmark wouldn't hit.
      - **How to actually find out, not guess**: per `CLAUDE.md`'s own standing rule, spike first
        and read real `--emit=asm`/profiler output before proposing a fix - a `criterion` benchmark
        isolating `crypto_secretstream::PushState::push`/`PullState::pull` alone (same message
        size, same subkey derivation already done) would separate "the streaming/AEAD-framing
        layer costs this much" from "the KDF/seed-embedding step costs this much," the same
        isolated-timing technique T-125/D-76 used to find Kalyna-GCM's own field-multiply
        bottleneck instead of guessing.
      - **Scope note**: this is a performance investigation, not a correctness or security task -
        no test-first requirement in the usual D-64/D-65 sense, but any resulting code change still
        needs its own tests per this project's standing discipline once a fix is actually proposed.
- [x] **T-176** **Done 2026-08-05.** Closed the single biggest gap T-174 left open: bought a
      targeted 8-page supplement from the same source (National Library of Ukraine EDD service,
      `docs/papers/DSTU_9041-2020_supplement.pdf`, gitignored, same reasoning as the main scan) and
      OCR-transcribed it the same way as T-173 (Surya OCR, reused the same local venv;
      `docs/papers/DSTU_9041-2020_supplement_ocr.md`, gitignored). **Clauses 6.5-6.12 - the priority
      item, previously only reachable via call sites referencing them - are now fully present and
      read directly from the page images** (random field element, modular exponentiation, `F_p`
      square root for `p≡5 mod 8`, modular inverse via extended Euclid, random curve point,
      Miller-Rabin primality, MOV condition check, scalar multiplication): see
      `docs/pseudocode/dstu9041.md`'s new "Computational algorithms, clauses 6.4-6.12" section.
      Also resolved: Додаток А's RNG body (Kalyna-l/k-CTR per DSTU 7624 §7, previously title-only),
      and section 3's remaining terms 3.1-3.26 (joining 3.27/3.28 already in hand - section 3 is now
      complete). **Notable finds while cross-checking against the new text**: clause 6.9's random
      curve-point algorithm explicitly retries when `d*u^2 mod p = a`, confirming this is exactly
      the exclusion of clause 3.18's singular points `D_{1,2}=(±sqrt(a/d),infinity)` by construction
      rather than by luck (previously only inferred); `w=2^((p-1)/4) mod p` is a formally named
      general system parameter (3.23), not just a table column; clauses 6.6/6.12 both carry the
      standard's own side-channel warning citing Joye & Yen's Montgomery Powering Ladder (Додаток
      Д's ref `[1]`) - the standard's own text making the same constant-time point this project's
      `docs/SECURITY.md` already makes generally, now with a citation. **Only partially resolved**:
      Додаток Б.1/Б.2 came back as the appendix's introductory historical prose only (Edwards/
      Bernstein-Lange/Bessalov literature survey), not whatever Б.1/Б.2 themselves actually define -
      likely low-value regardless, since Б.3/Б.4 (the operative proof and addition law) were already
      in hand from T-174. **Still open, unchanged by this task**: why Kalyna-KW's input needs the
      extra all-zero block (that's clause 11, not 6.5-6.12); `l(p)=768` worked example; `t`/`C`
      arithmetic verification; `hazmat::kalyna_kw_p`; the new `F_p`/twisted-Edwards primitives
      themselves - none of those needed clauses 6.5-6.12 specifically, so this task doesn't move
      them. No Rust implementation started (same Tier C posture as T-174).
- [x] **T-173** **Done 2026-08-04.** OCR-transcribed `docs/papers/DSTU_9041-2020.pdf` locally
      (Surya OCR 0.13.1, CPU-only, transformers-backend recognition model; PaddleOCR 2.9.1 classic
      API, `cyrillic` model, as a second-engine cross-check) - owner-requested, so the standard's
      36-page primary text (purchased/library-scanned, T-46's blocking source, D-05-style "no oracle
      exists" still applies) has a searchable working transcript instead of only a scanned PDF.
      Output: `docs/papers/DSTU_9041-2020_ocr.md`, gitignored right next to the source PDF -
      **explicitly not an oracle, not vector-verified, a reading aid only**; still does not unblock
      `hazmat::dstu9041` (same posture T-148/D-105 already established for the Skorobahatko-thesis
      pseudocode - a transcript of the primary text has the same single-source problem as a
      secondary source once no independent oracle exists to check it against).
      **Tooling gotchas hit and fixed, worth re-checking before any future local-OCR task in this
      project** (see `docs/DECISIONS.md` D-162 for full detail; also
      [[feedback_use_local_recognition_tools]] in project memory):
      - Current `surya-ocr` (0.2x on PyPI) rearchitected around a VLM served through
        `llama.cpp`/`vLLM`, neither viable here (no `llama-server` binary on this Windows machine,
        no supported GPU for `vLLM`) - pinned to `surya-ocr==0.13.1`, the last release using a local
        transformers recognition model directly, no server subprocess needed.
      - A full-batch `surya_ocr` CLI run over all 27 pages (large scans, 3893x5633px each)
        segfaulted (exit 139) partway through detection once RSS passed ~11GB with only ~10GB free -
        not caught by any Python exception (a native-side crash, no traceback). Fixed by chunking
        via `--page_range` (6 pages/chunk, one process per chunk, separate `--output_dir` each) -
        peak RSS dropped to ~4.3GB, all 5 chunks completed cleanly, results merged by page number
        afterward. No fix attempted upstream in Surya itself - out of scope for this task.
      - `paddleocr` 3.x's default pipeline (`PaddleOCR(lang=...).predict(...)`, PIR/oneDNN CPU
        executor) threw `NotImplementedError: ConvertPirAttribute2RuntimeAttribute not support
        [pir::ArrayAttribute<pir::DoubleAttribute>]` on this machine - a real CPU-backend
        incompatibility in that specific paddlepaddle build, not a usage error. Fixed by downgrading
        to the older, stable `paddlepaddle==2.6.2` + `paddleocr==2.9.1` pair (classic `.ocr()` API,
        no PIR executor).
      - `paddleocr`'s bundled `cyrillic` recognition model's character dictionary
        (`ppocr/utils/dict/cyrillic_dict.txt`) has `Є/є`, `І/і`, `Ґ/ґ` but is **missing `Ї/ї`
        entirely** - any Ukrainian word containing "ї" is systematically miswritten by this model
        (structural gap, not a confidence issue) - recorded so PaddleOCR's output is never trusted
        over Surya's on exactly those words in any future cross-check.
      - A first attempt at flagging Surya's own hallucinated lines by raw confidence score (<0.85)
        was far too broad (flagged ~180 lines, most just genuinely hard-to-OCR formula/number
        content, not actually wrong) - replaced with a targeted detector for the two concrete
        hallucination signatures actually observed (characters outside an allowlist covering
        Cyrillic/Latin/Greek/digits/common math symbols - catches Bengali/CJK/Japanese-script
        hallucination directly - plus single-token repetition exceeding 50% of a line's tokens,
        catching degenerate `= = = = ...`/`1 1 1 1 ...` tails). Landed at 45 flagged lines across 15
        of 27 pages after two allowlist-widening passes (Greek letters and curly quotes/math
        operators are legitimate in this standard's own notation, not hallucination). One page
        (page 1) spot-checked directly against the rendered scan to confirm the detector's
        precision/recall qualitatively before trusting it across all 27 pages - both its true
        positives (subscript-digit misreads, hallucinated repetition tails) and its true negatives
        (correctly left unflagged) matched the real page content.
      - A whole-page character-level `difflib.SequenceMatcher` ratio between the two engines'
        concatenated text was tried first as a per-page quality signal and abandoned - it returned a
        uniformly low ratio (0.01-0.20) even on pages later confirmed clean by direct visual
        inspection, evidently dominated by line-ordering/formatting differences between the two
        engines rather than real content divergence. Recorded so a future session doesn't re-trust
        this metric without re-deriving it.
- [x] **T-172** **Done 2026-08-03, see `docs/DECISIONS.md` D-161.** Genuine per-round unrolling of
      Kalyna's encrypt/decrypt hot loop - added 2026-08-03,
      user-requested direct follow-up to T-171/D-160's own closing note ("а future task would need
      to test a different mechanism ... that doesn't rely on LLVM choosing to unroll a
      const-bounded loop on its own"). T-171 confirmed that making `nr` a const generic is not
      sufficient - LLVM kept a real loop-with-branch even with both `NB` and `NR` known at compile
      time. This task's premise is the opposite lever: don't ask the compiler to unroll a loop at
      all - generate the straight-line per-round call sequence directly (macro-driven, one call per
      round per `(NB, NR)` instantiation), the same shape `cppcrypto`'s hand-written
      `G(t1,t2,&rk[8]); G(t2,t1,&rk[16]); ...` sequence already uses (`kalyna.cpp:594-620`, cited in
      D-157). **Needs its own `advisor()` consultation and plan-mode pass before implementation**,
      per this file's own Tier C precedent (T-168/T-171 before it) - a real hot-path rewrite of
      every Kalyna variant's encrypt/decrypt, not a mechanical one-liner. There is a cheap spike
      before committing to the macro rewrite: restore T-171's const-`NR` patch and force LLVM's
      hand with `-C llvm-args=-unroll-threshold=4000`, confirm in the asm that the loop actually
      disappears, then bench that - isolates "does unrolling help at all" from "write the macro" in
      one build instead of five variants' worth of rewrite. Must re-verify against all 10 official
      Kalyna vectors before any new timing
      is trusted, and re-measure against D-154's own cppcrypto numbers afterward (binary-level/MB/s
      only, D-34) to confirm the gap actually closes.
      **Outcome**: `advisor()` + plan-mode both done first. Stage A (flag spike,
      `-unroll-threshold=4000`) confirmed unrolling helps `NB=2`/`NB=4` (21-35% in criterion) but is
      flat for `NB=8` - proceeded to Stage B on that evidence. Stage B shipped a `unroll_rounds!`
      macro + `match NR { 10 | 14 | 18 => ... }` dispatch (no loop, no `RUSTFLAGS` dependency,
      3 literal-index arms since only 3 distinct `NR` values exist across all 5 variants) in both
      `encrypt_with_schedule` and `decrypt_with_schedule`, with a `const { assert!(...) }` bounds
      guard, extended differential tests (`encrypt_fusion_tests` new, `decrypt_fusion_tests` gained
      the missing `nb2_nr14` case), all 10 vectors + full `cargo xtask test`/`clippy`/`fmt` green.
      Real code-size cost found (+21.7% `dstu-core` `.text` for `fused`) - put to the owner directly
      rather than decided silently; answer was unconditional-for-`fused`,
      `small-tables`-keeps-the-old-loop, implemented via `#[cfg(feature = "small-tables")]` splits.
      Code size measured the wrong way first (rlib `.text` sum, an overestimate) and corrected same
      pass once `advisor()` flagged it on the completion-review call - real cost, measured
      `docs/resource-profiles.md`'s own established way (linked `uacrypt.exe`): `fused` +4.17%
      (+71.1 KB), `small-tables` +0.56% (+9.2 KB, an `NR`-const-generic side effect, not unrolling).
      Net measured win: 21-35% for four of five variants (criterion + binary-level
      `uacrypt kalyna-block`, cross-checked), roughly neutral for the fifth (512-512: encrypt flat/
      +2%, decrypt -23%), explained by `NB=8`'s `encipher_round_n` not getting inlined by LLVM at
      any of its 17 call sites (asm-confirmed, a real `callq` chain, not a code bug). Re-measured
      against D-154's own cppcrypto numbers same session (user-requested, "порівняння бінарників за
      нашим стандартом з cppcrypto") - gap closed materially on 7 of 10 cells (128-128/256-256
      decrypt now near parity, ~1.06-1.07x, down from ~1.5x), the 3 that didn't move being exactly
      the cells the `NB=8`-non-inlining/Stage-A findings predicted wouldn't. `advisor()`'s
      completion-review call also caught that `xtask test`/`clippy` had silently become
      `--all-features`-only, meaning neither had compiled/linted the new default (`fused`, unrolled)
      code path this task shipped - fixed same pass, both gained a default-features-first leg
      mirroring `rust.yml` CI's own already-existing D-39 pattern. Full detail, all numbers, and the
      size/perf/cppcrypto tables: D-161.
- [x] **T-137** **Done 2026-07-27 - PR `specinfo-ua/UAPKI#30`, CI fully green (SonarCloud Code
      Analysis + SonarCloud checks both passing), see `docs/DECISIONS.md` D-90/D-91/D-92.**
      Hypothetical/goodwill task, proposed by the user 2026-07-26 directly off T-131/D-78's XTS
      finding ("XTS: цей проєкт випереджає UAPKI у 3.2-15.1x") - since UAPKI is a real dependency of
      this project's own verification story (an oracle, `docs/ORACLES.md`), fixing root causes found
      here and sending them back upstream as a small, welcome contribution ("as a thank-you to
      them," the user's framing) rather than just quietly benefiting from having found them.
      **Fix 1 - Kalyna XTS's tweak-doubling** (the original finding): `oracles/uapki/library/
      uapkic/src/dstu7624.c`'s `encrypt_xts`/`decrypt_xts` call the fully generic `gf2m_mul` (3
      heap-allocated `WordArray`s, full O(m²) modular multiply) every block to multiply the tweak
      by the fixed generator `2` - mathematically just an O(m) shift-plus-conditional-XOR-
      reduction, the identical technique and identical field/reduction-polynomial constants already
      shipped in `dstu-core`'s own `hazmat::gf2m_wide.rs` `Gf2m128/256/512::double()` (cross-checked:
      XTS's own `f[]` triples in `dstu7624_init_xts` are byte-identical to `dstu7624_init_gmac`'s).
      Added a new sibling function `gf2m_double(ctx, block_len, arg, out)` right after `gf2m_mul` in
      the same file - does not touch `gf2m_mul` itself or any GCM/GMAC call site, only the 5 XTS
      call sites that multiplied by the fixed `two` constant.
      **Fix 2 - Strumok's byte-at-a-time consumption, user-requested 2026-07-27 same session,
      extending this task's scope**: `oracles/uapki/library/uapkic/src/dstu8845.c`'s
      `dstu8845_crypt` already batch-generates a full 128-byte gamma block via `next_gamma()`, but
      still consumed it one byte at a time (`gamma[ctx->gamma_cntr++]`, a bounds check every byte)
      - the same class of gap `dstu-core`'s own `hazmat::strumok.rs` `apply_keystream` had before
      T-135's batched/fixed-index rewrite. Restructured into the same drain/bulk/remainder shape
      T-135 established: drain to an 8-byte boundary byte-at-a-time, then XOR whole `uint64_t`
      words directly against `ctx->gamma[]` (a real `uint64_t[16]` struct field - no alignment
      concern) while a full aligned word remains in the current 128-byte buffer, remainder
      byte-at-a-time. Does not touch `next_gamma`, key schedule, or IV setup.
      **Verification, both fixes, done locally** (compiled with gcc/MinGW, whole `uapkic/src/*.c`
      tree linked directly - no CMake needed, `rc-version.h.in` is missing from this partial
      vendored clone and blocks the CMake path):
      - `dstu7624_self_test()` (covers ECB/CBC/CFB/OFB/CTR/CMAC/KW/CCM/GCM/GMAC/XTS, including
        `dstu7624_xts_self_test`'s 10 official fixed vectors) and `dstu8845_self_test()` (8 fixed
        Strumok vectors) both return `RET_OK` with both fixes applied together.
      - **Each fix's self-test-catches-a-real-bug property confirmed directly, not assumed**: a
        deliberately wrong constant in `gf2m_double`'s reduction step made `dstu7624_self_test()`
        fail (return 33, not 0); a deliberately wrong word index in the Strumok bulk loop made
        `dstu8845_self_test()` fail the same way - both reverted immediately after confirming.
      - **Strumok fix additionally cross-checked against outspace directly** (`dstu8845_crypt`
        renamed via `-D` compile flags to link both implementations in one binary, avoiding a
        symbol clash) over 16 one-shot lengths straddling 128 (1/7/8/9/63/64/65/127/128/129/135/
        200/256/260/384/500) x 2 key sizes, plus 2 multi-call chunk-split cases crossing the
        128-byte gamma-regeneration boundary mid-call and mid-drain - all matched byte-for-byte
        (one initial "mismatch" traced to a hand-typed arithmetic error in the test harness itself,
        not the fix - confirmed by isolating against a frozen copy of the original byte-at-a-time
        algorithm, corrected, re-ran clean).
      - `dstu7624_xts_self_test`'s own official vectors passing is itself the confirmation that
        GCM/GMAC's `gf2m_mul` call sites are unaffected (that self-test suite covers GCM/GMAC too,
        in the same `dstu7624_self_test()` call).
      **PR opened 2026-07-27, on explicit user request ("зроби пул реквест"), see `docs/DECISIONS.md`
      D-91 for the full mechanics**: no `CONTRIBUTING.md`/PR template exists in the upstream repo
      (checked via `gh api`, not assumed) - forked `specinfo-ua/UAPKI` to `user137/UAPKI`, cloned it
      fresh rather than reusing the stale local `oracles/uapki/` vendor (which turned out to be a
      different snapshot - same code, but the vendor predates recent upstream formatting/CRLF
      changes, caught by diffing before assuming the vendor was current), re-applied both patches
      against the actual current upstream source, re-verified both self-tests and the outspace
      differential clean against that fresh copy, added the new 200-byte self-test case there too,
      pushed branch `fix/xts-strumok-fast-path`, opened
      **https://github.com/specinfo-ua/UAPKI/pull/30**. `oracles/uapki/` in this repo is unaffected
      (still gitignored, untouched) - the PR's source lives entirely in the separate fork clone.
- [x] **T-138** **Done 2026-07-26, see `docs/DECISIONS.md` D-82.** Follow-up flagged by D-80's GMAC finding, 2026-07-26: the wrapper bug
      found there (timing a per-call `alloc`/`init_*` setup cost inside the same window as the
      actual operation, while `uacrypt`'s own command excludes it) was specific to this session's
      freshly-written `run_gmac`/`run_cmac` functions, both now fixed and re-verified. But
      **historical small-message CMAC (64 B) and CCM numbers already published in `docs/PERFORMANCE.md`
      were measured by an earlier, uncommitted UAPKI wrapper this session never inherited or
      inspected** - there is no way to confirm from here whether that wrapper placed its timer
      correctly (matching `uacrypt`'s cached-schedule convention) or made the same mistake D-80
      found and fixed in `run_gmac`. Given GMAC's real gap turned out to be ~1.1-2.9x rather than
      the previously-believed ~4-24x, a similar correction to CMAC's 64 B row or CCM's small-message
      numbers (currently self-consistent-only anyway, so less exposed) is plausible, not confirmed.
      **Action**: re-measure CMAC at 64 B using the now-fixed, extended `uapki_bench.exe`
      (`kalyna-cmac compute/verify` already supports arbitrary message sizes - just re-run at 64 B
      instead of only 10 MiB), byte-identity already established for this wrapper, so only the
      timing needs re-taking. Compare against the existing "~6-8x, small-message crossover" claim in
      `docs/PERFORMANCE.md`'s CMAC section and correct it if the real number differs materially, the same
      way D-80 corrected GMAC's.
      **Done, `docs/DECISIONS.md` D-82**: rebuilt the wrapper fresh (prior one was scratch-only, gone),
      timer placed after `alloc`/`init_cmac` per D-80's fix, byte-identity re-verified at
      `--iterations 1` (all 5 variants match `uacrypt` exactly). **Found and confirmed via a
      standalone probe a real UAPKI API footgun in the process**: reusing a `ctx` across
      `update_mac`/`final_mac` calls without re-`init_cmac` silently accumulates stale CBC-MAC
      chaining state (`cmac_final` never resets `ctx->state`) - each repeated call on the same
      message returned a different tag. Confirmed this doesn't invalidate throughput timing (Kalyna's
      block cipher does constant work regardless of input value, D-19) - only correctness needed the
      fresh-`ctx` `--iterations 1` check. **Real result: the small-message lead is ~1.0-1.45x, not
      the previously-published ~6-8x** - same corrective shape as D-80's GMAC finding, more
      pronounced here. `docs/PERFORMANCE.md`'s CMAC section updated with the corrected table.
- [x] **T-19** **Naming subtask, all three decisions made 2026-07-23** (T-20/T-21/T-22 below) -
      unblocks T-17/T-18, which are still separately open (a decided name isn't a crates.io
      publish or a built release binary):
  - [x] **T-20** Public name for the two resource profiles from `docs/DECISIONS.md` D-35, decided
        2026-07-23 (`docs/DECISIONS.md` D-38): the working name **is** the public name - Cargo feature
        `small-tables`, default/fused path stays nameless (no feature flag needed for it, it's
        just the absence of `small-tables`). Deliberately not given a branded name the way
        `uacrypt` (T-21/T-22) was - a `Cargo.toml` feature flag is a technical identifier, not a
        product name. Not checked further than the naming decision itself - the actual `cfg`-gated
        implementation is `docs/TASKS.md` Phase 4's "Two-resource-profile split" item, still open.
  - [x] **T-21** `dstutool`'s real name is **`uacrypt`** (`docs/DECISIONS.md` D-36, decided and
        executed 2026-07-23): `crates/dstutool` renamed to `crates/uacrypt` (`git mv`), package
        and `[lib]` name in `Cargo.toml` updated, root `Cargo.toml` workspace member, `deny.toml`
        comment, `main.rs`/`lib.rs` internal references, `README.md`, `docs/SECURITY.md`,
        `docs/dstu-crypto-project.md`, `CLAUDE.md`, and `docs/PERFORMANCE.md`'s canonical binary-level
        section all updated. `cargo build --workspace`/`test -p uacrypt` (15/15)/`clippy -D
        warnings`/`fmt --check` all pass post-rename. Historical entries in `docs/DECISIONS.md`/
        `docs/TASKS.md`/`docs/PERFORMANCE.md`'s superseded "Results" section still say `dstutool` on
        purpose — that was the accurate name at the time, not left stale.
  - [x] **T-22** The project's own name for GitHub is **`uacrypt`** too (decided 2026-07-23, same
        session as T-21 - not a separate name). `README.md`'s title updated from
        "dstu-crypto (working name)" to `uacrypt`. No git remote exists yet to actually create/
        rename a GitHub repo against - this records the chosen name for whenever one is created,
        it doesn't perform any GitHub-side action.
- [x] **T-86** First real version number, `0.0.0` -> `0.1.0` for both `dstu-core` and `uacrypt`
      (`docs/DECISIONS.md` D-43, 2026-07-23) - `0.0.0` was the unmodified Cargo scaffold default, not a
      real semver value, and not publishable to crates.io as-is. `0.1.0` chosen over a
      `-alpha.N` pre-release tag: the whole `0.x` range already signals "unstable, may break" under
      semver, which matches this project's actual state honestly; a pre-release suffix is deferred
      to the real crates.io publish (T-17) rather than decided now. Both crates' `version` bumped
      together, including `uacrypt`'s `dstu-core` path-dependency version (the same wildcard-dep
      spot T-75 fixed once already) - missing it would silently reintroduce that problem.
      `Cargo.lock` regenerated via a real build, not hand-edited. README.md got a pre-release/WIP
      banner at the top stating the version and the same safety caveats `docs/SECURITY.md` already
      carries (not audited, no side-channel-resistance claim, Strumok/Kalyna-CCM still provisional,
      no file-level `encrypt`/`decrypt` yet) - a WIP notice on a crypto library is a safety
      statement, not cosmetics, so it states what's missing rather than reading as marketing.
- [x] **T-87** **Release-readiness audit for a genuine libsodium-equivalent 1.0** (requested
      2026-07-23, same session as T-86): a full gap analysis of what exists vs. what a real release
      needs - libsodium-shaped API/command surface, matching documentation, a crates.io publish
      with the complete algorithm set built and tested, and critically every mode of operation in
      that set being a *current, safe* one (not provisional/unconfirmed). Written up as
      `docs/release-readiness.md` (new file, added to `CLAUDE.md`'s documentation map) rather than
      folded into `dstu-crypto-project.md`, so it's independently updatable as the gap closes.
      **Headline finding, not to be buried under an optimistic checklist**: this goal is currently
      blocked, not just incomplete - `docs/DECISIONS.md` D-05 (Kalyna's mode-of-operation question) is
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
      **Refreshed again, same day, after T-37 landed (`docs/DECISIONS.md` D-51)**: a `crypto_secretbox`
      equivalent now exists, so "there is no `crypto_secretbox`-equivalent AEAD yet" above is stale
      - but the headline finding itself is otherwise unchanged, not weakened: what got built is
      still provisional (inherits `hazmat::kalyna_ccm`'s not-primary-text-confirmed status, D-41)
      and bounded to <=255-byte messages (T-40's `crypto_secretstream` remains open for the general
      case) - a release still cannot honestly claim "current, safe modes" on top of it. See
      `docs/release-readiness.md` for the updated breakdown.
      **Verified current 2026-07-26, per the perf/hygiene roadmap's Tier A item 1**: this task's own
      narrative above wasn't kept in sync (still frames D-05 as "still the blocker" and Kalyna-CCM
      as the live construction), but `docs/release-readiness.md`'s actual headline finding was kept
      current by each landing task's own session in the meantime (D-05's 2026-07-24
      resolution-on-assumption, `crypto_secretbox`'s D-63 Kalyna-CCM->GCM migration removing the
      255-byte cap, `crypto_secretstream`'s D-68 landing) - not by a dedicated T-87 refresh pass.
      Grepped `255-byte`, `no crypto_secretbox`, `D-05 is still the blocker`, `not started` across
      `docs/release-readiness.md`, `docs/dstu-crypto-project.md`, and `README.md`: no stale hits -
      every "not started" line remaining (crates.io/T-17, `crypto_box`/`crypto_kx` on hard-blocked
      DSTU 9041) is genuinely still true, not overtaken by later work. **Closing this task as
      verified-current rather than requiring a rewrite** - the premise that these docs had drifted
      stale did not hold when checked directly, only this entry's own text had.
- [ ] **T-23** Re-confirm the `no_std` build still passes (all feature-flag combinations) as each
      primitive lands — don't let this regress silently. Ongoing by design, not a one-time item —
      **last re-checked 2026-07-22** (post D-28/29/30/31): all four `dstu-core` feature
      combinations build clean — `--no-default-features` (bare no_std),
      `--no-default-features --features alloc` (no_std + alloc), `--features alloc` (std + alloc),
      `--all-features`. `alloc` remains an unused placeholder feature (no code gated on it yet, per
      D-01), so this confirms no regression rather than adding new coverage. `cargo xtask build`
      (workspace `--all-features` + `--no-default-features`, which also exercises `dstutool`
      linking against a no_std-built `dstu-core`) still passes too.
      **Re-checked again 2026-07-26** (perf/hygiene roadmap Tier A item 3, overdue by this task's
      own trigger since T-128's const-generic Kalyna refactor touched `hazmat::kalyna` internals
      directly): all four base combinations still build clean individually
      (`--no-default-features`, `--no-default-features --features alloc`, `--features alloc`,
      `--all-features`), `cargo xtask build`'s three checks (workspace `--all-features`, workspace
      `--no-default-features`, `dstu-core --no-default-features --features getrandom`, per D-74's
      own lesson about narrower combinations hiding `dead_code`) all clean, and - per D-39/D-74's
      standing "check every entry individually, not just the two usual profiles" lesson -
      `--features pwhash`, `--features small-tables`, and
      `--no-default-features --features small-tables` each individually confirmed clean too. No
      regression from T-128's const-generic round functions.

## Testing & hardening — deeper verification beyond test vectors

Test vectors answer one question: does the primitive produce the standard's expected output for a
handful of fixed inputs. They do not answer whether the *code* leaks secrets, runs at an acceptable
speed, or degrades safely on adversarial/malformed input — raised 2026-07-22 while reviewing what
"done" means for Kalyna/Kupyna/Strumok now that all three pass their vectors. Split deliberately
from Phase 1 above: none of this blocks calling the primitives implemented, but none of it should
be skipped before calling them *production-ready*. Two things are explicitly **not** goals here and
never will be, so as not to imply otherwise: cryptanalytic strength of the algorithms themselves
(that's the DSTU designers' responsibility, not this library's), and hardware side-channel
resistance (SPA/DPA — explicitly out of scope per `docs/SECURITY.md`/`CLAUDE.md` "MVP scope").

- [x] **T-24** **Chunk/split-invariance test for `Strumok::apply_keystream`.** Added
      `strumok_{256,512}_chunk_invariance` in `crates/dstu-core/tests/strumok.rs` — splits a fixed
      total length into arbitrary, non-8-aligned chunks (including a zero-length one) and asserts
      byte-for-byte identity against one call on the concatenated buffer. **Passed on the first
      attempt** — no buffering bug found, but the path was genuinely untested before this.
- [x] **T-25** **Round-trip property tests.** `proptest` 1.11 added as a dev-dependency (`docs/DECISIONS.md`
      D-21) — doesn't touch the `no_std` build. Kalyna: one `decrypt(encrypt(key, block)) == block`
      test per variant in `tests/kalyna.rs`. Strumok: `apply_keystream` applied twice with the same
      key/IV returns the original data, in `tests/strumok.rs`. All 16 property tests (256 generated
      cases each) passed on the first attempt. Kupyna intentionally skipped — no round-trip
      property exists for a hash; its `cargo fuzz` target covers the property that would matter.
- [x] **T-26** **Differential testing against a C oracle over many random inputs — done for all three.**
      Strumok first (the highest-value target — zero official vectors exist anywhere for it,
      D-15): `cargo run --example strumok_diff_cases -p dstu-core` piped into
      `tests/oracle-harness/strumok-differential/diff_against_outspace.c` (against
      `oracles/strumok-dstu8845/`) — **4000/4000 random cases matched**. `docs/DECISIONS.md` D-22.
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
      `docs/DECISIONS.md` D-32**: this machine turned out to already have Visual Studio 2022 (MSVC C++
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
      dependency in `dstu-core`, `docs/DECISIONS.md` D-20). Strumok's `Core` (LFSR/FSM state) derives
      `ZeroizeOnDrop`; Kalyna's `encrypt_generic`/`decrypt_generic` call `round_keys.zeroize()`
      after last use. Kupyna intentionally untouched — its only API is unkeyed `digest()`, no key
      material exists yet (relevant again once KMAC lands). **Not exhaustive**: Kalyna's
      intermediate key-schedule scratch buffers (`kt`, `initial_data`/`tmv`, the rotation buffer in
      `key_expand_odd`) are still cleared only via the final `round_keys` zeroize, not individually
      — a deliberate scope cut, not an oversight, see D-20.
- [x] **T-29** **Constant-time audit + an explicit decision.** Confirmed the secret-dependent indexing
      exists in all three primitives (`SBOXES`/`SBOXES_DEC` in `kalyna.rs`/`kupyna.rs`/
      `strumok.rs`, plus `MUL_ALPHA`/`MUL_ALPHA_INV` in `strumok.rs`). Documented and scoped as an
      accepted software-timing exception in `docs/DECISIONS.md` D-19 (same family as the already-out-
      of-scope SPA/DPA carve-out, since every reference C implementation makes the identical
      trade-off) — `docs/SECURITY.md`'s hard-constraint wording updated to say this precisely instead of
      standing as an absolute "never" next to code that already violated it. Branching and
      comparisons on secret data remain prohibited without exception, unchanged.
- [x] **T-30** **`criterion` benchmarks.** Added as a dev-dependency, three bench targets
      (`crates/dstu-core/benches/{kalyna,kupyna,strumok}.rs`, `cargo bench -p dstu-core`) covering
      every variant of all three primitives. **Extended 2026-07-22**: numbers, machine, a named
      regression baseline (`--save-baseline initial-2026-07-22`), and a same-machine comparison
      against Oliynykov's reference C, UAPKI, and outspace all now live in `docs/PERFORMANCE.md` (new
      canonical file, see `CLAUDE.md`'s documentation map) — this project's Rust beats the
      reference C (correctness/clarity-optimized) but is meaningfully slower than UAPKI/outspace
      (production-optimized), a real and now-quantified gap, not just a theoretical one. **Did not**
      implement a second Strumok state-transition form just to quantify the literal-shift-vs-ring-
      buffer tradeoff mentioned in D-18 — that would still mean maintaining a second implementation
      purely to benchmark it; outspace's own ~12-15x-faster numbers (likely using a rotating
      buffer, per `docs/PERFORMANCE.md`) now give an *external* read on that tradeoff's rough scale
      without needing to build one ourselves.
- [x] **T-31** **Strumok: close the gap to UAPKI/outspace documented in `docs/PERFORMANCE.md`**, root-caused by
      reading `oracles/strumok-dstu8845/strumok.c` directly (2026-07-22) rather than guessed at, then
      fixed the same day (`docs/DECISIONS.md` D-26). Two distinct, additive causes, both closed: (1)
      outspace's `next_stream()` never physically shifts its 16-word state array — replaced this
      project's `s.copy_within(1..16, 0)`-per-step with a `head`-indexed ring buffer, no data
      movement. (2) outspace's `T(w)` is 8 precomputed combined tables
      (`T0[byte0]^...^T7[byte7]`) — transcribed those directly (same byte-for-byte cross-check
      already covering them), replacing the runtime 8-S-box-lookups-then-MDS-matrix-multiply.
      **Result: ~77-85% time reduction, now faster than UAPKI's Strumok, ~3.2x slower than outspace
      (was ~4-5x/~13-15x before)** — full before/after table in `docs/PERFORMANCE.md`. Verified: all 6
      existing tests unchanged, the 4000-case outspace differential harness re-run fresh
      (4000/4000), `clippy`/`fmt`/`no_std` all pass. New `criterion` baseline saved
      (`strumok-optimized-2026-07-22`).
- [x] **T-32** **Kalyna/Kupyna: precomputed MDS tables** (`docs/DECISIONS.md` D-27, same day). Narrower than the
      full UAPKI `p_boxrowcol` fusion (S-box + row/column permutation + MDS all combined) —
      `hazmat::tables::apply_matrix` alone was switched to precomputed `MDS_TABLE`/`MDS_INV_TABLE`
      (8 lookups + 7 XORs instead of up to 64 `gf_mul` calls per column), shared by both algorithms
      since `apply_matrix` already was. `sub_bytes`/`shift_rows` untouched — Kalyna's row-shift
      offset depends on block size, so fully fusing S-box+shift+MDS the way UAPKI does would need
      per-variant tables, a bigger change deliberately not attempted this pass. **Result: ~48-55%
      time reduction for every Kalyna variant/direction, ~60-65% for Kupyna** — roughly halves the
      gap to UAPKI without closing it (full before/after in `docs/PERFORMANCE.md`). Verified: a new
      *exhaustive* unit test (`hazmat::tables::tests`, all 8x256 entries per table) plus every
      existing Kalyna/Kupyna vector/proptest/differential-harness check, all unchanged.
      `clippy`/`fmt`/`no_std` pass. New baseline: `kalyna-kupyna-optimized-2026-07-22`.
      **Not done**: the full S-box+shift+MDS fusion (per-`nb` tables) — sketched, not scheduled,
      would close the remaining gap but is a materially bigger change.
- [x] **T-33** **Kalyna/Kupyna: close the remaining gap to UAPKI** (planned 2026-07-22, stages 0-1 done the
      same day, see `docs/DECISIONS.md` D-28 — stages 2-3 below still open).
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
         before/after in `docs/PERFORMANCE.md`. New baseline: `kalyna-kupyna-fused-2026-07-22`.
      2. **Not done yet, and now lower priority than stage 4 below** — see stage 3's result: with
         the schedule cached, Kalyna encrypt is already faster than UAPKI, and Kupyna is at/above
         parity, so the remaining `[u8; 8]` -> `u64` conversion-churn cleanup has much smaller
         expected payoff than originally estimated (most of it was already implicitly removed by
         D-28's single-pass gather, which accumulates as `u64` internally already). Revisit only if
         stage 4 (decrypt fusion) doesn't close enough of the remaining gap on its own.
      3. [x] **`ExpandedKey`-equivalent for Kalyna, done, see `docs/DECISIONS.md` D-29** — one
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
      4. [x] **Decrypt-direction fusion, done, see `docs/DECISIONS.md` D-30**. `decipher_round`'s
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
- [x] **T-34** **Binary-level (process) comparison, done, see `docs/DECISIONS.md` D-31**. The in-process numbers
      above don't reflect running the tool as an actual external process - added `dstutool`'s first
      real command, `kalyna-block encrypt`/`decrypt` (single block, file in/file out, deliberately
      not named `encrypt`/`decrypt` at the top level - that's reserved for the future file-plus-
      mode CLI, blocked below), plus scratchpad (uncommitted) comparison CLIs for Oliynykov's
      reference C and UAPKI with the same file interface, all three cross-checked byte-identical
      before timing. **Result**: `dstutool`'s per-op numbers (schedule cached) match the in-process
      `criterion` numbers within a few percent - full tables in `docs/PERFORMANCE.md` "Binary-level
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
      same shape, matched closely). Full tables in `docs/PERFORMANCE.md`.
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
      then the exact same commands as the x86-64 dev machine — no new script, per `docs/DECISIONS.md`
      D-12. `cargo xtask build` (both `--all-features` and `--no-default-features`), `cargo xtask
      test` (11/11 test binaries passed, 0 failures — the DSTU 4145 signature roundtrip test took
      ~125s here vs a few seconds on the x86-64 dev machine, expected given the Pi's much lower
      clock speed, not a correctness concern), `cargo xtask fmt --check`, `cargo xtask clippy` (all
      clean), and all four `dstu-core` feature-flag combinations (bare no_std, no_std+alloc,
      std+alloc, all-features) built individually too. First real confirmation on non-x86 hardware
      for this project. **Same day, extended to performance**: `cargo bench -p dstu-core --bench
      kalyna --bench kupyna --bench strumok` also run on the Pi and added to `docs/PERFORMANCE.md`
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
      original Ryzen UAPKI numbers. **Result, see `docs/DECISIONS.md` D-33**: Kalyna and Kupyna's "we
      beat UAPKI" result *reverses* on the Pi - UAPKI is faster there by up to ~1.9x - while
      Strumok's holds on both platforms (smaller margin on the Pi). Three untested hypotheses
      recorded in D-33 (LLVM/aarch64 codegen quality for this dense bit-manipulation pattern being
      the most explanatory), not chased further this pass. `docs/PERFORMANCE.md`'s Results tables and
      "What the gap is, honestly" section both got a scope correction noting the Ryzen-specific
      claim.
      **Re-run 2026-07-23, triggered by new `hazmat` changes since the last run** (`kalyna_ccm`,
      T-81, and Kupyna's streaming `KupynaCore`, T-83) - re-synced via the same tar+ssh approach,
      `cargo xtask ci` on the Pi. All mandatory checks green, including the new suites: 37
      `kalyna_ccm` tests and 9 Kupyna-streaming tests, both passing on `aarch64` with no
      architecture-specific surprise. Optional tools (miri/fuzz/audit/deny/Maven/.NET) still not
      installed on the Pi, same as before - not a new gap, unchanged from the first run.
      **Extended a third time, same day, see `docs/DECISIONS.md` D-34**: user asked for one single
      testing method and metric going forward - a real built binary (`dstutool`, and an equivalent
      thin CLI wrapper for every oracle), MB/s only, for every algorithm/implementation/platform,
      no more in-process `criterion` numbers used as the cross-implementation comparison. Rebuilt
      the full binary-level matrix on **both** machines (Kalyna N=20000 cached+raw x 2 variants,
      Kupyna/Strumok N=2000 at 64 KB) for `dstutool` + UAPKI (+ outspace for Strumok) - Oliynykov's
      reference C stays excluded (unchanged decision, correctness oracle not a performance one).
      Confirmed D-33's Kalyna/Kupyna-flips-on-ARM finding survives the switch to the canonical
      method, and surfaced a further discrepancy: Kupyna's binary-level numbers show UAPKI ahead
      **on Ryzen too** (~10-17%), contradicting the in-process table's opposite claim - exactly the
      kind of cross-method disagreement that motivated standardizing on one method. `docs/PERFORMANCE.md`
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
      **Re-run again 2026-07-26, perf/hygiene roadmap Tier A item 3, specifically to catch T-128's
      const-generic `hazmat::kalyna` refactor** (the standing "re-run after any change touching
      `hazmat::kalyna`/`kupyna`/`strumok` internals" trigger, and this is exactly that kind of
      change): re-synced via the standard tar+ssh approach, `cargo xtask ci` on the Pi. All
      mandatory checks green - `fmt --all -- --check`, `build --workspace` (`--all-features`,
      `--no-default-features`, and `dstu-core --no-default-features --features getrandom`),
      `test --workspace --all-features` (every suite passed including the newer T-128 const-generic
      differential tests and the 8 `dstu-core` doctests), `clippy --workspace --all-features -- -D
      warnings` clean. Optional layers (miri/fuzz/audit/deny/mvn/dotnet) still not installed there,
      unchanged from every prior run. No architecture-specific regression from T-128's const-generic
      round functions on `aarch64`.
      **Re-run 2026-08-03, user-requested extension to cover every language binding + T-158's C ABI
      crate, first time any of that surface has been checked on non-x86 hardware.** Re-synced,
      `cargo xtask` core baseline (`fmt --check`/`build`/`test`/`clippy`) green first, then each
      binding's own `cargo xtask <name>` in turn (run sequentially, not concurrently - two
      simultaneous `cargo`/`rustup`-touching SSH sessions raced on `~/.rustup`'s shared component
      cache and broke both, `rust-src` component download failing a file rename; not a project bug,
      just a lesson for running this check faster in the future). New toolchain installs needed on
      this Pi, none previously required for the core-only check: `nodejs`/`npm` (apt, 18.20.4),
      `ruby-full` (apt, 3.1.2) + `bundler` (`sudo gem install` - the system gem dir isn't
      user-writable, matching the `pip`/PEP 668 restriction Python already needed working around)
      + `bundle config set --local path vendor/bundle` in `bindings/ruby` (installing gems as a
      non-root user needs a local vendor path, not the system one bundler defaults to), `php-dev`
      (apt - Debian splits `php-config`/`phpize` out of the base `php` package, `ext-php-rs`'s build
      script needs `php-config` specifically), `php-mbstring`/`php-xml`/`php-dom` (apt - PHPUnit's
      own floor), `cbindgen` (`cargo install --locked`, ~2m41s), and a Python `.venv` with
      `maturin`/`pytest` installed inside it (`maturin develop` requires an active virtualenv, not
      just the interpreter on `PATH` - a bare `pip install --break-system-packages` alone, as tried
      first, isn't sufficient). **Result: all five bindings plus the C ABI crate pass in full on
      real aarch64 Linux** - Python 57/57 (`pytest`, genuine `linux_aarch64` wheel), Node.js 52/52
      (`node --test`), Ruby 58/58 examples (`rspec` + `rubocop` clean), PHP 58 tests/62 assertions
      (`phpunit`), C ABI crate's own header-drift check + C test harness + all 4 examples (matching
      x86-64's own `misc.c` Kupyna-256 "hello world" digest exactly, cross-architecture bit-for-bit
      as every prior Kupyna cross-check already established for the core crate).
      **One real, genuine finding, not an environment gap**: `crates/dstu-core-capi/tests/
      ffi_tests.rs`'s `pwhash` test hardcoded a `[0i8; DSTU_PWHASH_STRBYTES]` stack buffer for what
      the production API correctly types as `*mut c_char` - harmless on every platform this project
      had built on so far (x86-64 Linux/Windows/macOS all define `c_char` as `i8`), but ARM Linux's
      own ABI makes plain `char` **unsigned** by default (`c_char` resolves to `u8` there), so the
      test failed to compile the moment it hit real aarch64 hardware. Fixed by using
      `std::os::raw::c_char` explicitly instead of a hardcoded signed type - exactly the kind of
      "no CPU-family lock-in" assumption this Pi rig exists to catch, this time on the C ABI
      surface rather than `hazmat` internals. **New standing rule recorded, `docs/bindings-strategy.md`'s
      "standard binding steps"**: every future binding (T-52/.NET, T-51/Java, T-163/Go, T-53/C++)
      gets this same Pi re-check as one of its own steps, not deferred to a separate ad hoc pass.
- [x] **T-103** **Adversarial-test coverage audit across every primitive, see `docs/DECISIONS.md` D-64.**
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
      `docs/DECISIONS.md` D-65.** User-requested 2026-07-25, same day as T-103 - naive/incorrect *usage*
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
      Step 3 item 2, see `docs/DECISIONS.md` D-66.** The roadmap left this step's shape as an open fork
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
- [x] **T-106** **`crypto_stream` high-level module, roadmap Step 3 item 3, see `docs/DECISIONS.md`
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
`docs/DECISIONS.md` D-05 (revised) and D-41 for the full reasoning and citation.

- [x] **T-81** **`hazmat::kalyna_ccm` implemented - DSTU 7624 CCM, all 5 Kalyna variants,
      provisional pending the primary text** (`docs/DECISIONS.md` D-41, 2026-07-23). Cited to
      `oracles/uapki/library/uapkic/src/dstu7624.c` (`dstu7624_init_ccm`/`ccm_padd`/
      `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm`/`gamma_gen`), cross-checked byte-for-byte
      against `oracles/bouncycastle-java`'s `DSTU7624Test.java` CCM vectors for 4 of 5 variants
      (128/256 has no BC vector - UAPKI-only, flagged in its vector file). New test vectors in
      `crates/dstu-core/tests/vectors/kalyna-ccm/*.json`; new integration test
      `crates/dstu-core/tests/kalyna_ccm.rs` (37 tests: official vectors, `proptest` round-trip,
      five independent tamper-rejection suites - ciphertext/tag/AAD/nonce/wrong-key - all green
      first attempt). New `uacrypt` subcommand `kalyna-ccm encrypt`/`decrypt` (deliberately not the
      reserved `encrypt`/`decrypt` names - see the CLI note below), round-tripped and tamper-tested
      through the real built release binary (`docs/DECISIONS.md` D-34's policy). All 8 `no_std`/`alloc`/
      `std`/`small-tables` feature combinations re-confirmed clean; `cargo clippy -- -D warnings`/
      `cargo fmt --check` clean; re-confirmed on the Raspberry Pi rig too (`docs/TASKS.md` T-35's
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
      counter** (`docs/DECISIONS.md` D-40's resolution). D-40's original "11-55 bytes" nonce-width
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
D-05, unchanged: `docs/DECISIONS.md` D-05 needs the official DSTU 7624 text or another authoritative
source before *any* mode of operation (CTR/CBC/GCM/whatever DSTU 7624 actually specifies) can be
chosen. Building `dstutool kalyna-block` (D-31) does not unblock this - it's still single-block-only
by design. Do not build an ad-hoc/arbitrary mode (e.g. naive ECB) just to have *something* - that
is exactly the failure mode this project's 'no homegrown primitives'/'research before
implementation' discipline (`CLAUDE.md`) exists to prevent." T-81 satisfies this bar by being
dual-oracle-cited rather than invented, while D-05 itself (the `crypto_secretbox`/`crypto_auth`
construction question) stays open - `dstutool`'s (now `uacrypt`'s) reserved `encrypt`/`decrypt`
command names (`CLAUDE.md` MVP scope) are still reserved for whenever that resolves, unchanged.

## Phase 2 — libsodium-equivalent construction layer, DSTU 4145 + 9041

- [x] **T-36** **Adopted as a working assumption 2026-07-24, see `docs/DECISIONS.md` D-05's latest
      revision** — Kalyna-alone (CCM/GCM/KW, not Kalyna+Kupyna encrypt-then-MAC), on top of D-41's
      UAPKI+Bouncy-Castle evidence: this project's own already-vendored `oracles/uapki/`
      `dstu7624_self_test` ten-mode list and Ukrainian Wikipedia's independently-sourced ten-mode
      table for "Калина (шифр)" agree mode-for-mode. **Still not primary-text-confirmed** — the
      official DSTU 7624:2014 text remains priced/unpurchased (`docs/ORACLES.md`); this is a decision to
      build forward on assumption, not a claim the question is settled, and gets revised again if
      the primary text ever contradicts it. Unblocks T-37/T-16/T-40 to *start* (design against a
      working hypothesis instead of no hypothesis at all) — none of those are built yet, only the
      blocker on starting them is resolved.
- [x] **T-37** **Done 2026-07-24, see `docs/DECISIONS.md` D-51** — `dstu_core::crypto_secretbox::{seal,
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
      2026-07-23** (`docs/DECISIONS.md` D-44, first item from `docs/release-readiness.md`'s ordered
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
- [x] **T-39** **`crypto_kdf` equivalent - Kupyna-based KDF, implemented 2026-07-24** (`docs/DECISIONS.md`
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
- [x] **T-40** **Done 2026-07-25, see `docs/DECISIONS.md` D-68.** `dstu_core::crypto_secretstream`
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
      map assigns exactly this update to those files, not just `docs/TASKS.md`/`CLAUDE.md`), and D-68's
      own `no_std` claim overstated what's actually unconditional (`PushState::init` is
      `PushState`'s only constructor, so the module is decrypt-only without `std`) - both fixed, see
      `docs/DECISIONS.md` D-68 for the full corrected write-up. The T-40/T-70 duplicate-numbering entries
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
      not chosen either, just not ruled out. See `docs/TASKS.md` T-70 (the same task under the
      high-level-layer numbering) and `docs/release-readiness.md`.
      **Correction, same day, after T-37 landed (`docs/DECISIONS.md` D-51)**: the line above saying
      "T-36/T-37 ... are explicitly blocked on D-05" is now stale - T-37 is done. T-40 remains
      blocked regardless, but on the reason already given earlier in this same entry
      (`hazmat::kalyna_ccm`'s 255-byte cap, not D-05's status) - unchanged by T-37 landing, since
      T-37 itself only wraps that same capped primitive rather than widening it.
      **Correction 2026-07-24 (this entry's own "needs GCM, not yet built" premise is now stale) -
      found during a full-project `advisor()` audit, not by returning to this task directly**: GCM
      landed this session (T-95, `docs/DECISIONS.md` D-56) - and, materially, **`hazmat::kalyna_gcm` has
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
      see `docs/DECISIONS.md` D-14 and `docs/ORACLES.md`. A genuinely dual-sourced vector, not just a scan
      transcription.
- [x] **T-42** DSTU 4145: re-derive `docs/pseudocode/dstu4145.md` against the official text's Sections 5-13,
      rather than leaving it as a pure Bouncy Castle code-transcription. **Done 2026-07-22**: read
      Sections 5, 9, 11-13 directly (rendered PDF pages), every algorithm in the doc now cites its
      own section/page. **Found a second real bug doing this** (beyond the `Q = -d·G` one already
      found via the property test, below): `hash_to_field` had the wrong algorithm entirely (copied
      BC's byte-reversal without also adopting BC's reversed-input convention) — reading §5.9
      directly showed the correct algorithm needs no reversal at all. Fixed; full detail in
      `docs/DECISIONS.md` D-25's follow-up entry and the pseudocode doc itself, not duplicated here.
- [x] **T-43** DSTU 4145: implement GF(2^m) binary-field + elliptic-curve arithmetic in Rust for the m=163
      curve (the actual prerequisite for a Rust port, bigger than just the signature logic
      itself). **Landed 2026-07-22**: `dstu_core::hazmat::dstu4145::gf2m163` (field add/multiply/
      square/invert) and `dstu_core::hazmat::dstu4145::curve163` (point double/add — public-data
      only — and a constant-time Montgomery-ladder `scalar_multiply`, safe for secret scalars).
      Citation and the branchless-posture decision in `docs/DECISIONS.md` D-25. Test-first against
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
      (163-iteration shift-and-mask, `docs/DECISIONS.md` D-25 — deliberately correctness-first, not
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
      pseudocode; see `docs/ORACLES.md`). Nothing here can start until the official text is obtained
      or another authoritative source turns up
- [ ] **T-47** `crypto_kx` equivalent (Diffie–Hellman on the DSTU 4145/9041 curve — needs both to exist)
- [x] **T-48** **Done 2026-07-24** (`docs/DECISIONS.md` D-46) - `crypto_sign` equivalent wrapping the
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

**Full rationale/order/per-binding checklist now lives in `docs/bindings-strategy.md`** (written
2026-08-02, `docs/DECISIONS.md` D-115) — this section tracks status only, per this file's own header
convention; read that document before starting any item below, don't re-derive the reasoning here.
**The granular, checkable, cross-session step list — the "resume point" for exactly where work left
off — lives in `docs/bindings-strategy.md`'s "Cross-session execution plan" section; read the resume
line there first when picking this phase back up in a new session.**
**Build order revised 2026-08-02, see `docs/DECISIONS.md` D-121/D-122/D-123** (original order below
kept for the historical record, not deleted): T-161 (shared `selftest` module, prerequisite, done)
→ T-49 (Python, the template, done) → T-50 (Node) → T-160 (Ruby) → T-159 (PHP, via `ext-php-rs` - a
direct Rust binding, not the C-ABI path, so it doesn't wait on T-158 either) → T-158 (C ABI crate,
built once actually needed) → T-52 (.NET) → T-51 (Java) → T-163 (Go, via the C ABI - no
direct-Rust-binding toolchain for Go has PyO3/napi-rs/magnus's maturity, so it waits on T-158 same
as .NET/Java/C++, but built ahead of C++ specifically per the owner's explicit preference, D-123)
→ T-53 (C++) → T-162 (docs, last). Rationale: Bouncy Castle (Java/.NET) and UAPKI (Java/Kotlin)
already serve real DSTU-consuming demand in those two languages specifically - this project's own
zero-config `crypto_*` surface is still a genuine gap there, but a smaller one than in a language
with no DSTU library at all. Node/Ruby/PHP/Go have no equivalent incumbent, so the same "install
and forget" reach is currently unclaimed ground in those four - build the three direct-binding ones
(Node/Ruby/PHP) first since they don't need T-158 at all; Go still needs it, so it naturally lands
alongside .NET/Java/C++ rather than ahead of them, but before C++ specifically (D-123). Dart was
raised in the same conversation and explicitly deferred (D-122), not added here.

**Original order (superseded by D-121, kept for the record):** T-161 → T-49 (Python, the template)
→ T-158 (C ABI crate) → T-52 (.NET) → T-51 (Java) → T-50 (Node) → T-53
(C++) → T-159 (PHP) → T-160 (Ruby) → T-162 (GitHub-facing docs/`gh-pages` site refresh, last);
publishing to any registry is a separate, explicitly owner-gated step per registry (same class of
decision as T-17 for crates.io), tracked once actually requested, not scheduled here. **Every task below also carries D-116's "install and forget"
requirement** — zero-config API (no nonce/mode/IV parameter exposed) and prebuilt binaries (no
local Rust toolchain needed by the binding's own consumer) — **and D-117's requirement to expose
`dstu_core::selftest` (T-161) with an idiomatic wrapper, plus a local test suite that runs the same
official vectors through the binding's own API** — none of this is optional polish, all of it is a
completion bar same as the three test categories. **And D-118's requirement**: every binding's
`crypto_secretstream` exposure is an idiomatic stream/pipe wrapper (`.NET Stream`-shaped, Node
`stream.Transform`, Python file-like object, Java `InputStream`/`OutputStream`, C++
`istream`/`ostream`) — not a raw push/pull loop left for the consumer to assemble — with no new
configuration surface added in the process (D-47 still holds).

- [x] **T-161** **Done 2026-08-02, see `docs/DECISIONS.md` D-117.** `dstu_core::selftest` — shared
      runtime KAT self-check module, a prerequisite for every binding below. New `selftest` Cargo
      feature (requires `std`, off by default). `run()` re-checks one official vector per primitive
      (Kalyna-128/128 encrypt+decrypt, Kupyna-256 digest, Strumok-256 keystream, DSTU 4145's Annex
      B.1 worked-example `verify`) against the live compiled build, embedded via `include_str!` from
      the same `crates/dstu-core/tests/vectors/*.json` files `cargo test` already uses (a small
      hand-rolled string/hex scanner, no `serde` dependency, matching every other vector reader in
      this crate) — returns `Ok(())` or a `Report` naming which primitive(s) failed. Test-first:
      `tests/selftest.rs` was written before `src/selftest.rs` existed. Unit tests cover the parsing
      helpers' own failure-detection path (a mismatch is actually caught, not just the golden path)
      since `run()` itself takes no caller input for a rejection/misuse category to apply to -
      recorded here rather than skipped silently, per this file's own test-category discipline.
      Verified: `cargo test --features selftest` (workspace default run unaffected), `cargo clippy
      --features selftest --all-targets -- -D warnings` clean for the new files (two documented
      `#[allow]`s: `type_complexity` resolved via a type alias, `similar_names` allowed for `qx`/`qy`
      matching `tests/dstu4145_signature.rs`'s own naming), `cargo fmt --check` clean, and the
      existing `no_std`/`no_std+alloc`/default build combinations all still build with the new
      feature absent. One real bug caught during this work, not by inspection: the DSTU 4145 vector's
      `qy`/`r`/`s` hex strings are sometimes one nibble short of a full byte (the standard's worked
      example trims a leading zero nibble) - the first parser draft rejected odd-length hex outright
      and failed with `MalformedEmbeddedVector`; fixed by auto-padding a leading zero, the same
      convention `tests/dstu4145_signature.rs`'s own `decode_hex` helper already uses. Every
      pre-existing clippy warning seen while testing this (`gf2m_wide.rs`/`tables.rs`
      `needless_range_loop`/`cast_precision_loss`, `crypto_sign.rs` `doc_lazy_continuation`) was
      confirmed via `git stash` to already exist on `master` without this change (a clippy-version
      drift, not something this task introduced) and is out of this task's scope. **Original
      "Confirmed as a genuine gap" note, kept for the historical record**: the project
      owner asked whether everything the bindings plan leans on actually exists in stock Rust yet,
      not just described in docs — checked directly (`find crates/dstu-core/src/hazmat -maxdepth 1
      -name "*.rs"`, a `grep -i selftest` across `crates/dstu-core/src`) rather than trusted from
      memory. Result: every `crypto_*` module the bindings checklist references
      (`crypto_auth`/`crypto_generichash`/`crypto_kdf`/`crypto_pwhash`/`crypto_secretbox`/
      `crypto_secretstream`/`crypto_sign`/`crypto_stream`/`randombytes`) is real, and
      `crypto_secretstream`'s `PushState`/`PullState` chunked construction and all 10 `hazmat`
      Kalyna modes (including the combined CCM/GCM/KW ones) are real and documented — but no
      `selftest`/`self_test` module or function exists anywhere in `dstu-core` today. This task is
      the only piece of this phase that is genuinely new Rust-core work, not something bindings can
      wrap around existing functionality — which is exactly why it's sequenced first, not
      discovered as a surprise mid-binding. Re-runs the official test vectors (Kalyna/Kupyna/
      Strumok/DSTU 4145, the same `crates/dstu-core/tests/vectors/*.json` data, embedded rather
      than hand-copied) against the live compiled implementation, returns pass/fail naming which
      primitive failed if any. New Cargo feature (binary-size cost, off by default in the bare
      crate, on by default in every
      binding's `Cargo.toml`). Built once here, every binding (T-49/T-50/T-51/T-52/T-53/T-158/T-159/
      T-160) wraps it thin rather than reimplementing it — see D-117 for the precedent this follows
      (D-13's shared S-box/MDS tables).
- [x] **T-49** **Done 2026-08-02, see `docs/DECISIONS.md` D-120.** Python binding (`bindings/python`,
      PyO3 + maturin) — the template every later binding instantiates. **Own `[workspace]` table,
      not a root-workspace member (D-119)** — two CI jobs use `--workspace` explicitly (Miri, the
      MSRV-pinned build) and neither is equipped for a PyO3 `cdylib`; a path dependency on
      `dstu-core` still resolves across separate workspaces. Exposes the full `crypto_*` surface
      (not a subset). All nine standard steps done: scaffold; full surface; file-like
      `crypto_secretstream` pipeline byte-compatible with `uacrypt encrypt`/`decrypt`; prebuilt
      wheels (local Windows verified, manylinux/macOS/Windows via CI); own CI (per-push regression
      gate plus release-time wheel building, D-120); a 57-test `pytest` suite (correctness/
      rejection/misuse, D-64/D-65); `bindings/python/examples/`; doc-map sweep; each step its own
      commit. `cargo xtask python` is the best-effort local entry point (D-12's miri/fuzz/audit
      posture, not mandatory). See `docs/bindings-strategy.md`'s T-49 section for the full
      step-by-step record, "Phase 1."
- [x] **T-50** **Done in full 2026-08-02, see D-125 through D-132.** Node.js binding
      (`bindings/nodejs`, napi-rs) — same `crypto_*` surface and template as
      T-49, `node:test` suite. **Reordered 2026-08-02, see D-121: now built right after T-49, not
      after T-52/T-51** — Node has no incumbent DSTU library the way Java/.NET have Bouncy Castle,
      so its direct-Rust-binding shape (matching Python's) is no longer held back for an
      incumbent-demand ordering that no longer applies to it. **Node-only,
      confirmed 2026-08-02 (D-118)** — a browser/WASM target was raised and explicitly deferred, not
      silently assumed either way; would need `wasm-bindgen`, a distinct toolchain from `napi-rs`.
      See "Phase 5." **Step 1 (scaffold) done 2026-08-02, see D-125/D-130** — wraps only
      `selfTest()` so far; `napi-build = 2.0.0` pinned in `Cargo.lock` (real MSRV constraint,
      D-125); the MSVC toolchain fix is a machine-local `rustup override`, not a committed file
      (D-130 corrects D-125's original approach, which would have broken Linux/macOS CI). **Step 2 done
      2026-08-02, see D-126** — full `crypto_*` surface wrapped (every byte param/return uses
      `napi::bindgen_prelude::Buffer`, not `Vec<u8>`; explicit `js_name` camelCase on every export;
      `secretstream` push/pull return a `#[napi(object)]` result struct, not a tuple - napi-rs has
      none). **Step 3 done 2026-08-02, see D-127** — `SecretStreamEncryptor`/`SecretStreamDecryptor`
      as a `stream.Transform` pair (`bindings/nodejs/js/secretstream.js`, pure JS, no new Rust
      glue), mirroring Python's own wire format and both D-118 pitfalls re-checked (`_flush` not
      `_destroy` emits `Final`; `chunkLen` bounds-checked before use; trailing-after-`Final`
      rejected) - verified against the real `uacrypt` binary bidirectionally, not just
      self-consistently. **Step 4 done 2026-08-02, see D-128** — Windows prebuilt artifact only
      (Linux/macOS need CI, deferred to step 5, same constraint Python's step 4 hit); found and
      fixed a real gotcha where `package.json` needed an explicit `files` field to make `npm pack`
      include the gitignored `native/` build output at all; verified with a genuine fresh-install
      round trip (`npm pack` → `npm install <tarball>` in an unrelated temp dir → require as a real
      dependency → re-run the full smoke suite), matching Python's own fresh-venv-install bar.
      **Step 6 done 2026-08-02, see D-129 — done before step 5** (`node --test test/` errors on a
      nonexistent directory, unlike pytest's vacuous pass on an empty collection Python's own
      step-5-before-6 order relied on; not a preference change). `node:test` suite, one file per
      `crypto_*` module mirroring Python's own file-for-file, `generichash` loading the same shared
      Kupyna vector JSON. Found and fixed a real `node:test` hang: `_transform`/`_flush` callbacks
      invoked synchronously could throw an error out of `.write()` instead of emitting it, per
      Node's own documented warning - fixed via `process.nextTick`, confirmed stable across three
      repeated runs. **Step 5 done 2026-08-02, see D-131** — `cargo xtask nodejs` +
      `.github/workflows/bindings-nodejs.yml`, mirroring Python's own step 5 shape; no
      MSVC-specific CI step needed (`windows-latest` is MSVC-host by default, D-130); fixed a real
      `Command::new("npm")` resolution gotcha on Windows (needed `.cmd`, same as the pre-existing
      `mvn` case). **Step 7 done 2026-08-02, see D-132** — five example scripts one-for-one with
      Python's own, and a `README.md` written from scratch (step 1 never created one). **Step 8
      done 2026-08-02** — swept `README.md` (repo-tree line), `docs/dstu-crypto-project.md`,
      `docs/release-readiness.md` (all had stale "T-50 onward haven't started" framing);
      `docs/user-journey-gaps.md`/`docs/cross-language-style-guide.md` checked, no T-50 references
      existed to update (same as T-49's own step 8 finding) - this entry itself is that step's mark-
      done. **Step 9**: each step above landed as its own commit throughout, matching the template.
- [x] **T-51** Java binding — **Done in full 2026-08-03, steps 1-9 (step 10, the Raspberry Pi
      re-check, tracked separately per D-151's template) - see `docs/DECISIONS.md` D-153.**
      **reordered 2026-08-02 (D-121): now built after T-50/T-160/T-159, not
      before them** — Bouncy Castle and UAPKI already ship real Java/Kotlin DSTU support, so this
      binding's own gap here is real but smaller than in a language with no incumbent at all.
      **correction 2026-08-02, see D-115**: the D-02-based instruction below
      ("wraps Bouncy Castle `DSTU4145Signer` directly, does not use the Rust DSTU 4145 port") is
      stale — it predates `hazmat::dstu4145`/`dstu_core::crypto_sign` actually existing and being
      dual-oracle-verified against real Bouncy Castle (D-25/D-46). This binding now exposes the same
      full `crypto_*` surface as every other binding, `crypto_sign` included, calling this project's
      own Rust implementation like everything else — Bouncy Castle stays the verification oracle
      only, same role it already has in `tests/oracle-harness/`. **Original text, kept for the
      historical record, not deleted**: "Java binding (wraps Bouncy Castle `DSTU4145Signer`
      directly, per D-02 — does not use the Rust DSTU 4145 port)." **Step 0 done 2026-08-03, see
      `docs/DECISIONS.md` D-153**: spiked the `jni` crate (Rust-side JNI, no hand-written C shim)
      against JNI-over-`bindings/capi` (T-158) with two real runnable prototypes, not reasoned from
      memory — both worked, **chose the `jni` crate** (direct-Rust binding, own `[workspace]` per
      D-119, joining Python/Node/Ruby/PHP's group rather than .NET/C++/Go's C-ABI group). JNI-over-
      capi would have added a third language (C) to the binding and doubled the packaged native
      surface per platform for no benefit the direct binding doesn't already give. Panama (JEP 454)
      named and rejected (JDK 22+ baseline too new for this audience). `jni` pinned to `0.21`, not
      `0.22` (a real breaking `JNIEnv`/`EnvUnowned` API change, confirmed by trying the bump).
      **JDK baseline**: build/test on Temurin 17 (installed this session, matches the Pi's Debian 12
      default), published artifact targets `<maven.compiler.release>8</maven.compiler.release>` —
      Java 8 still has real enterprise/PKI-adjacent footprint (owner-requested correction),
      verified empirically by cross-compiling the spike with `--release 8` and running it on a real
      local JDK 8 JVM, all paths unchanged. CI matrixes JDK 8 and 17 (build/test on 17, published
      bytecode targets 8). See `docs/bindings-strategy.md` "Phase 4" and its own T-51 section for
      the full per-step plan and status. **Steps 1-9 done 2026-08-03**: `bindings/java/native`
      (own `[workspace]`) wraps the full `crypto_*` surface via the `jni` crate; `SecretStream`'s
      `OutputStream`/`InputStream` pair (D-118); native library bundled on the classpath under
      `native/<os-arch classifier>/` (`os-maven-plugin` + an explicit `maven-resources-plugin`
      execution, a real gotcha found empirically, D-153); `cargo xtask java` + `bindings-java.yml`
      CI; 56 JUnit 5 tests (D-64/D-65, real `uacrypt` interop, chunk-boundary parametrized round
      trips); 5 examples + README. A real design bug (a two-way, not three-way, exception split)
      was found and fixed via a hand-run smoke test before the JUnit suite was even written - see
      D-153's "Failure::State" paragraph. **Step 10 done 2026-08-03 too - T-51 is now done in
      full, all ten standard steps.** Raspberry Pi re-check found one real bug (not ARM-specific):
      Debian 12's apt-packaged Maven (3.8.7) defaults to an old `maven-compiler-plugin` (3.1) that
      doesn't understand `maven.compiler.release` and silently falls back to an ancient
      source/target level modern `javac` refuses - fixed by pinning the plugin to `3.13.0`
      explicitly in `pom.xml`. All 56 tests passed on the Pi afterward. See `docs/DECISIONS.md`
      D-153's own step-10 paragraph.
- [x] **T-52** .NET binding — **reordered 2026-08-02, same rationale as T-51 (D-121)**: Bouncy
      Castle .NET already serves this language, so it now builds after T-50/T-160/T-159.
      **same correction as T-51, see D-115**: exposes the full `crypto_*`
      surface including `crypto_sign` via this project's own Rust implementation, not a Bouncy
      Castle wrap. **Original text, kept for the historical record**: ".NET binding (wraps Bouncy
      Castle `Dstu4145Signer` directly, per D-02)." P/Invoke over `bindings/capi` (T-158) — no new
      Rust-side glue beyond the C ABI crate itself. See `docs/bindings-strategy.md` "Phase 3."
      **Done in full 2026-08-03 — see D-152.** `bindings/dotnet/DstuCore` — the first binding with
      no Cargo workspace of its own (pure C# P/Invoke over T-158's already-built C ABI). Uses
      `[LibraryImport]` (source-generated interop), not classic `DllImport`, specifically because it
      forces `[MarshalAs(UnmanagedType.U1)]` on every `bool`-returning export at compile time — C#'s
      default `bool` marshalling is the 4-byte Win32 `BOOL` against Rust's 1-byte `bool`, and getting
      this wrong on `dstu_verify`/`dstu_verify_digest` would have been a silent signature-
      verification bypass (the .NET analogue of D-151's ARM `c_char`/`i8` finding, caught by advisor
      review before implementation). Every opaque handle is a `SafeHandle` subclass. Full `crypto_*`
      surface wrapped; `SecretStreamEncryptStream`/`DecryptStream` (`Stream`-derived) apply both
      D-118 pitfalls, with `Dispose()` deliberately never finalizing (C# has no exception-vs-clean-
      exit signal, unlike Python's `__exit__` — `Complete()` is an explicit required call instead).
      56 xUnit tests (D-64/D-65, real `uacrypt` interop), `dotnet pack` + a real fresh-install check
      from a local NuGet feed, `cargo xtask dotnet` + `bindings-dotnet.yml` CI (ubuntu/macos/
      windows), five examples + README. Step 10 (Raspberry Pi ARM64 re-check) also done the same
      day - all 56 tests passed on the first real aarch64 run, no ARM-portability bug found this
      time (unlike D-151's `c_char`/`i8` finding in the C ABI crate).
- [x] **T-53** **Done in full 2026-08-03, all ten standard steps, see `docs/DECISIONS.md` D-158.**
      C++ binding (`bindings/cpp`) — thin RAII header-only wrapper
      over `crates/dstu-core-capi` (T-158), no separate Rust glue. No incumbent-competition reason
      to reorder this one relative to .NET/Java (D-121 didn't touch it specifically), but it still
      needed T-158 first same as T-51/T-52, so it landed in that same later group by construction.
      **Reordered again 2026-08-02, see D-123: built after T-163 (Go), not before it** — the
      owner's explicit preference, no further rationale recorded beyond that. Four step-0 forks
      resolved together (D-158): `Finish()`-not-destructor Final emission (a C++ destructor can't
      reliably tell exception-unwind from normal scope exit without `std::uncaught_exceptions()`
      bookkeeping, so the `Complete()`-not-`Dispose()`/`Close()` split D-152/D-155 already used
      ports directly), `std::ostream&`/`std::istream&` for step 3 (matches Go's `io.Writer`/
      `io.Reader` and .NET's `Stream`), prebuilt-lib-plus-header CMake packaging (no `FetchContent`
      for the Rust side), and a hand-rolled `CHECK`-macro test harness mirroring
      `c-tests/test_capi.c` (no Catch2/doctest dependency, C++ has no stdlib JSON either so the
      single official Kupyna-256 vector is hand-transcribed the same way the C harness already does
      it). Links `dstu-core-capi`'s cdylib (matching the C test harness's own existing choice, not
      Go's static-link route, D-158). Full `crypto_*` surface via `unique_ptr`-backed move-only
      RAII handles, `dstu::CryptoError`/`ArgumentError`/`InternalError` exception hierarchy
      (cross-language-style-guide.md principle 4), real bidirectional `uacrypt` CLI interop in the
      test suite (`std::system`, with the documented Windows `cmd.exe` outer-quote workaround),
      `cargo xtask cpp` + `bindings-cpp.yml` CI (ubuntu/macos/windows, no Windows GNU-forcing needed
      unlike Go - `xtask` branches on `target_env` the same way `capi_compile_msvc` already does),
      five examples + README. Step 10 (Raspberry Pi ARM64 re-check) also done the same day - all
      builds/tests green on the first real aarch64 run (`libdstu_core_capi.so`, not the Windows
      `.dll` branch; Kupyna-256("hello world") byte-identical to the x86-64 dev machine's own
      digest), no ARM-portability bug found this time (unlike D-151's `c_char`/`i8` finding in the
      C ABI crate itself, or matching T-52/.NET's own clean first pass). See
      `docs/bindings-strategy.md` "Phase 6" / its own T-53 entry.
- [x] **T-158** C ABI crate (`crates/dstu-core-capi` workspace member) — opaque
      handles, explicit error codes, `catch_unwind` at every boundary call, zeroize-on-free,
      `cbindgen`-generated header. The shared foundation T-52/T-163/T-53 consume (T-159 no longer
      does, see its own entry below - D-121 committed it to `ext-php-rs` instead); verify the existing
      8-combination `no_std`/`alloc`/`std`/`small-tables` feature matrix still passes with this new
      workspace member present (D-12). See `docs/bindings-strategy.md` "Phase 2."
      **Done in full 2026-08-03 — see D-148 (pre-implementation design forks) and D-149 (the
      implementation itself: cbindgen config, GNU-vs-MSVC C-compiler dispatch in `xtask`, C test
      harness, examples, README, CI job).**
- [x] **T-159** PHP binding (`bindings/php`) — added to scope 2026-08-02 at the owner's request.
      **Done in full 2026-08-02 — see D-142 through D-146.**
      **Reordered 2026-08-02, see D-121**: moved up to build right after T-50/T-160, ahead of
      T-158/T-52/T-51/T-53 — same no-incumbent reasoning as Node/Ruby. **Committed to `ext-php-rs`
      specifically (not the `FFI`-over-`bindings/capi` alternative originally left open)** so this
      binding is a direct Rust binding like Python/Node/Ruby and genuinely doesn't wait on T-158.
      **Original text, kept for the historical record, not deleted**: "deliberately after
      T-49/T-158/T-52/T-51/T-50/T-53, not interleaved with them (no equivalent Ukrainian-PKI demand
      evidence exists for PHP the way UAPKI/Bouncy-Castle-.NET give Java/.NET). `ext-php-rs`
      extension or a plainer `FFI`-extension path over `bindings/capi` (T-158)." PHPUnit suite, same
      per-binding checklist as every other language. See `docs/bindings-strategy.md` "Phase 8."
      **Step 1 done 2026-08-02, see D-142**: PHP 8.3.33 installed by hand (winget's own packages
      404'd on a stale manifest patch version). `bindings/php/` scaffolded, own `[workspace]`, no
      `ext/` split needed (unlike Ruby's `rb_sys` quirk). Windows needs nightly Rust
      (`abi_vectorcall`) + the MSVC host (PHP's own Windows builds are MSVC) + `rust-lld` - a
      machine-local `rustup override`. `ext-php-rs`'s own Windows build script downloads a matching
      devel pack from `windows.php.net` automatically. Wraps only `self_test`, verified end-to-end.
      **Step 2 done 2026-08-02, see D-142**: full `crypto_*` surface, flat `dstu_core_*`-prefixed
      global functions + a single `DstuCoreException` class modeled on PHP's own bundled
      `ext-sodium` extension (the closest same-domain precedent), not a namespace or static-method
      class. `Binary<u8>` for every crypto byte parameter/return (PHP strings are raw byte buffers,
      not UTF-8-validated). Three real build-error findings fixed (`wrap_function!()`'s
      same-module requirement, `u8` not implementing `IntoConst`, a letter-to-digit rename split).
      **Step 3 done 2026-08-02, see D-143**: `stream_filter_register`/`php_user_filter` investigated
      and rejected (no clean header-write hook, buffer-size mismatch) - a plain
      `DstuCoreSecretStreamWriter`/`Reader` over a `resource`, implementing `Iterator`, matching
      Python's/Ruby's own choice. Found and fixed a real `ext-php-rs` gap: a Rust-registered
      exception class with no `#[php_impl]` constructor can't be `new`-ed from pure PHP - a
      `dstu_core_throw_error()` escape hatch. Verified bidirectionally against the real
      `uacrypt.exe`, six rejection/misuse cases including D-118's no-finalize-on-error property.
      **Step 4 done 2026-08-02, see D-144**: no PECL/Composer publish attempted (Composer never
      manages native extensions; PECL needs its own account/manifest pipeline) - a release-profile
      binary + documented `php.ini extension=` line, verified via a fresh-install-style check.
      **Step 5 done 2026-08-02, see D-145/D-146**: `cargo xtask php` + `bindings-php.yml`
      (`shivammathur/setup-php`). PHPUnit as a standalone PHAR, no Composer added. Found and fixed
      a real `xtask`-level bug (D-146, not PHP-specific): `run()`'s child cargo invocations
      inherited `RUSTUP_TOOLCHAIN` from the outer `cargo xtask` process, silently overriding any
      binding's own directory-scoped `rustup override` - almost certainly affects `cargo xtask
      nodejs` identically, not yet re-verified there. **Not yet confirmed on real CI** - needs a
      push first.
      **Step 6 done 2026-08-02, see D-145**: 58 PHPUnit tests across all 10 `crypto_*` modules,
      mirroring Ruby's/Node's own suites file-for-file, the real official Kupyna-256 vector
      (D-124), real bidirectional `uacrypt` interop, D-64/D-65's three categories throughout.
      **Step 7 done 2026-08-02**: five example scripts one-for-one with Python/Node/Ruby, README.md
      with a module-by-example table and the honest packaging story.
- [x] **T-160** Ruby binding (`bindings/ruby`) — added to scope 2026-08-02 at the owner's request.
      **Done in full 2026-08-02 — see D-133 through D-139.**
      **Reordered 2026-08-02, see D-121: no longer scheduled last** — moved up to build right after
      T-50, ahead of T-159/T-158/T-52/T-51/T-53, same no-incumbent reasoning as Node/PHP. Direct
      Rust binding (`magnus`/`rb-sys`), like T-49/T-50, not through the C ABI. RSpec/Minitest suite,
      same per-binding checklist. See `docs/bindings-strategy.md` "Phase 9."
      **Step 1 done 2026-08-02, see D-133**: Ruby+MSYS2-devkit installed on this machine (wasn't
      present at all), gem skeleton hand-authored (not via `bundle gem --ext=rust`, which hung),
      three real `rb_sys`/`bindgen` toolchain issues found and fixed (workspace-root `Cargo.toml`
      placement, `rb-sys-env` version pin, `rb-sys` as an explicit direct dependency, `LIBCLANG_PATH`
      pointed at a matching mingw `clang`). Wraps only `self_test`, verified via a full clean
      rebuild + a real self-test call against the live compiled build.
      **Step 2 done 2026-08-02, see D-134**: full `crypto_*` surface wrapped, flat naming matching
      Python/Node. Three real `magnus` findings (`RString::to_bytes()` needs the `"bytes"` feature;
      no tuple `IntoValue`, so `secretstream` returns a 2-element `RArray`; `method!`'s Ruby-first
      parameter order is incompatible with `&self` sugar, worked around via `Ruby::get()` inside
      instance methods). 15-check smoke script passing against the live compiled `.so`.
      **Step 3 done 2026-08-02, see D-135**: `SecretStreamWriter`/`SecretStreamReader`, modeled on
      stdlib `Zlib::GzipWriter`/`GzipReader` (researched, not assumed). Both D-118 pitfalls
      re-checked - `.open`'s block form deliberately avoids Ruby's own `ensure` idiom to not
      finalize on the error path; the reader bounds `chunk_len`/rejects trailing data. Verified
      bidirectionally against the real `uacrypt.exe`.
      **Step 4 done 2026-08-02, see D-136**: an advisor review first caught and fixed five real
      gaps in steps 2/3 (gemspec `files` glob, missing `binmode`, binary-string encoding contract,
      `is_finalized` → `finalized?`, `ArgumentError` → `IOError`). Step 4 itself found a genuine
      packaging gap - a source gem can't install standalone (the `ext/` Cargo.toml's path
      dependency on `crates/dstu-core` only resolves inside this repo) - fixed via `rake native gem`
      producing a precompiled, platform-tagged gem instead, verified against a fresh `GEM_HOME`.
      **Step 5 done 2026-08-02, see D-137/D-140/D-141**: `cargo xtask ruby` + `bindings-ruby.yml`.
      `rubocop` (deferred from step 3) wired in, 63 offenses settled via `.rubocop.yml`. Three real
      CI round-trips needed before actually green (`ridk` not on the hosted runner's PATH,
      `Gemfile.lock` missing non-Windows platforms, the root `rust-toolchain.toml` silently
      overriding `rustup default` on Windows) - **confirmed green on real GitHub Actions**, run id
      `30759971107`, all four jobs `success`.
      **Step 6 done 2026-08-02, see D-138**: 10 spec files (58 examples) mirroring Python/Node's
      own suites file-for-file, D-64/D-65 categories, the shared Kupyna-256 vector JSON, real
      `uacrypt` interop gated on `if:` metadata (confirmed filtering correctly, not assumed) with a
      visible `skip` (not a silent omission) for the uacrypt-missing case.
      **Step 7 done 2026-08-02, see D-139**: five example scripts one-for-one with Python/Node,
      README.md written from scratch. One real fix: examples need `lib/` on `$LOAD_PATH` explicitly
      since `require_relative` alone doesn't satisfy `lib/dstu_core.rb`'s own internal require.
- [x] **T-163** Go binding (`bindings/go`) — added to scope 2026-08-02 at the owner's request, on
      the same no-incumbent-competitor footing as Node/Ruby/PHP (no DSTU-specific Go library exists,
      real DevSecOps/cloud-infra audience). **Unlike Node/Ruby/PHP, this one goes through the C ABI
      (`cgo` over `bindings/capi`'s generated header, T-158)** — no direct-Rust-binding toolchain for
      Go exists with PyO3/napi-rs/magnus's maturity, so this binding waits on T-158 same as
      T-51/T-52/T-53. Builds after T-158 alongside that group, not before it - but **ahead of T-53
      (C++) specifically, reordered 2026-08-02 per the owner's explicit preference (D-123)**. Same
      per-binding
      checklist (correctness/rejection/misuse, D-64/D-65; zero-config, D-116; `selftest` wrapper,
      D-117; idiomatic `crypto_secretstream` wrapper, D-118), Go's own `testing` package suite. See
      `docs/bindings-strategy.md`'s T-163 section (added same session) for the concrete shape.
      Dart was raised in the same conversation and **explicitly deferred, not silently assumed
      either way** (D-122) — its primary audience (Flutter mobile/web) overlaps least with this
      project's demonstrated PKI/enterprise demand, the same reasoning that scoped Node down to
      Node-only (D-118).
      **Done in full 2026-08-03, steps 0-9 - see D-155.** Step 0: hand-written `cgo` decided on
      inspection (not a full spike, unlike Java's Fork 1) plus a real selftest-only link spike that
      found genuine Windows-GNU static-linking gaps (`-Wl,-Bstatic`/`-Bdynamic` bracketing needed, plus
      `-lws2_32 -luserenv -lntdll` for Rust-stdlib symbols pulled in transitively). Full `crypto_*`
      surface wrapped, `CryptoError`/`ArgumentError`/`InternalError` split (cross-language style guide
      principle 4), `SecretStreamEncryptWriter`/`DecryptReader` (`io.Writer`/`io.Reader`-shaped,
      `Complete()`-not-`Close()` finalization split same as .NET's D-152). `cargo xtask go` +
      `bindings-go.yml` CI (Windows leg forces the GNU-hosted Rust toolchain + installs MinGW via
      `choco` since `cgo` can't link MSVC output - **unconfirmed on real CI as of this writing**).
      Full test suite (official vector, real `uacrypt` interop, rejection, misuse), 5 examples,
      README with the provisional-status banner **and a real limitation no other binding has**: the
      `#cgo LDFLAGS`' `${SRCDIR}`-relative path means this binding only builds from inside a checkout
      of this repo, not as a standalone `go get`-able module (T-164 territory). **Step 10 (Raspberry
      Pi re-check) done same session** - found the Windows-only LDFLAGS (`-lws2_32 -luserenv
      -lntdll`) didn't link at all on Linux, fixed with cgo's own per-`GOOS` `#cgo` pragma syntax
      (one line per platform, not a shared base plus negation); all tests green afterward on real
      aarch64, including `uacrypt` interop and all 5 examples, no ARM-portability bug found this
      time (the gap was cross-OS, would have hit any non-Windows CI runner too). **Post-completion
      advisor review found and fixed a real blocker before this task was truly done**: every handle
      type's `runtime.SetFinalizer` "backstop" was a premature-free race, not a `SafeHandle`
      equivalent (a bare Go finalizer can fire mid-call, since the last live reference to the
      wrapper becomes the call argument itself, not the struct) - removed from all nine handle
      types, `Close()` is now the only thing that frees, verified with `GOGC=1 go test -count=3` and
      `go test -race` (both platforms; `-race` itself doesn't run on the Pi, a known
      ThreadSanitizer/ARM64-kernel VMA-bits mismatch, unrelated). Also fixed: `go.mod`'s
      `go 1.26.5` → `go 1.26`, `SecretStreamDecryptReader.Read`'s `(0, nil)` return on an empty
      `Final` chunk, and `bindings-go.yml`'s Windows leg needing `rustup set default-host` (not just
      `rustup default`) to actually change what a bare `channel = "stable"` resolves to - see D-155.
- [x] **T-162** **Done 2026-08-03.** GitHub-facing docs + `gh-pages` site refresh — added to scope
      2026-08-02 at the owner's request, explicitly last, after every binding above (T-49/T-50/
      T-160/T-159/T-158/T-52/T-51/T-163/T-53, per D-121/D-123's reordering) landed. Documentation-
      only, no primitive/binding code. `README.md`: new "Language bindings" section (all eight,
      one line + README link each, honest "not published to any registry yet" status) right after
      "Using `uacrypt`" — the repo tree already listed all eight (done incidentally in T-53's own
      step 8). `docs/dstu-crypto-project.md`'s "Second priority" section was already current (same
      T-53 step 8 sweep); `docs/release-readiness.md`'s "Phase 3" line had one stale phrase
      ("First two bindings done") left over from Python/Node's own landing, fixed to the accurate
      count. `docs/user-journey-gaps.md`/`docs/cross-language-style-guide.md` checked, nothing
      stale found. **`gh-pages` branch updated** (real new content existed - the live site never
      mentioned any binding, Rust/CLI only) - a new bilingual "Eight languages, one C ABI" section
      (`check-grid` cards, one per language, linking each binding's own README on GitHub;
      `callout.neutral` explaining the C ABI itself is usable from any C-FFI-capable language, not
      just the three that consume it directly) inserted into both `index.html` and `uk/index.html`
      identically (the two files share body content, differ only in `<head>` metadata + the
      language-switch link - confirmed by diffing before editing, not assumed) between the
      existing "Try it" and "Status" sections. Previewed locally (sent the edited file to the
      owner) before pushing - confirmed live on `gh-pages` (commit `43e8022`).
- [ ] **T-164** **Per-binding registry publishing (PyPI/npm/RubyGems/Packagist) — owner-gated
      decision, added 2026-08-03.** Found via a build-path analysis (simplest → most complex build,
      requested by the owner) run across every binding: today, a Python/Node/Ruby/PHP consumer sits
      at the *same* complexity rung as a contributor — clone the repo, install Rust, install that
      language's own toolchain, run `cargo xtask <lang>`. There is no "just `pip install`/`npm
      install`/`gem install`/`composer require`" rung below that for any of the four, unlike
      `uacrypt`'s own prebuilt-binary path (T-18/T-119, closed) or a hypothetical crates.io
      `dstu-core` (T-17). This is the exact same class of gate T-17 already sits behind — an
      explicit publish decision per registry, not something new documentation can close (see
      `docs/user-journey-gaps.md`'s persona-2 "Add dependency" row for why T-17 alone already reads
      this way). **In progress 2026-08-12, per T-203's staged plan** — owner picked PyPI + npm to
      start (explicit go-ahead), deferred Packagist for now: `bindings/php` is a compiled
      `ext-php-rs` native extension, and Packagist only distributes Composer (PHP-source) packages
      — D-144 already made this exact call ("Composer never manages native extensions at all"),
      which T-203's "Packagist — lowest risk" framing hadn't re-derived. Needs its own future
      decision (a composer.json installer-script shim fetching a prebuilt binary vs. PECL vs. skip
      permanently) before it's revisited, not a silent drop. **This session**: `publish-pypi`/
      `publish-npm` jobs landed in `release.yml`, both dormant behind their own GitHub Environment
      approval gate (`pypi`/`npm`) until the owner configures Trusted Publishing (OIDC) on each
      registry's own web UI — no token pasted anywhere, the direct fix for T-203's crates.io
      token-leak incident. `bindings/nodejs/package.json`'s `napi.triples` also fixed from
      `defaults: true` (which assumes `x86_64-apple-darwin`) to the explicit
      `x86_64-unknown-linux-gnu`/`aarch64-apple-darwin`/`x86_64-pc-windows-msvc` triple this
      project's own 3-OS CI actually builds (`macos-latest` is Apple Silicon, same target
      `uacrypt`'s own release binary already uses) — the mismatched default would have scaffolded a
      platform package CI could never produce a matching binary for. Actual first publish to either
      registry is a separate, later, explicit go-ahead — not implied by this CI plumbing landing.
      **Status as of v0.3.5 (2026-08-13)**: PyPI (`dstu-core`) fully live. npm: root `dstu-core`,
      `dstu-core-linux-x64-gnu`, `dstu-core-darwin-arm64` live; `dstu-core-linux-arm64-gnu` added as
      a new platform this release; `dstu-core-win32-x64-msvc` deliberately deferred, blocked by
      npm's own spam detection (external, confirmed not time-based) — see D-189 for the incident and
      the real fix (npm support, not a retry/rename). **RubyGems CI plumbing landed same day**
      (`build-ruby-gems`/`publish-rubygems` in `release.yml`, cross-compiled via
      `oxidize-rb/actions/cross-gem`/`rb-sys-dock` for `x86_64-linux`/`aarch64-linux`/
      `arm64-darwin`/`x64-mingw-ucrt`, OIDC Trusted Publishing against a pending publisher the
      owner already registered for `dstu_core` — see D-190) — dormant behind the `rubygems`
      GitHub Environment approval gate until the next tag, same "land ahead of first publish"
      posture PyPI/npm used. NuGet/Maven Central/Packagist not started.
      **v0.3.6 (2026-08-13)**: fixed a real bug on the already-live PyPI/npm pages - stale
      pre-publish "provisional, not yet published" README/description text, no `pip install`/
      `npm install` instructions anywhere. Fixed for both bindings (bumped `0.1.0`→`0.1.1` so the
      fix actually reaches the registry), plus `uacrypt`'s crates.io description and a distinct
      Ruby gemspec bug (`README.md` missing from `spec.files` entirely) caught in the same sweep,
      ahead of Ruby's own first publish. See D-191.
      **v0.3.6's actual release run then failed `build-ruby-gems` on all four platforms** -
      `magnus 0.7.1` doesn't support Ruby 4.0's changed C ABI, and `cross-gem`'s default
      `ruby-versions` cross-compiled against it anyway. **v0.3.7 (2026-08-13)** pins
      `ruby-versions: "3.1,3.2,3.3,3.4"` explicitly (D-190's update) - RubyGems' first real publish
      attempt is this tag. Also shortened the README/website status banners, which had grown into
      a wall of text restating every past release since v0.3.3 instead of just linking
      `docs/CHANGELOG.md`.
      **v0.3.7's `build-ruby-gems` all passed, but `publish to RubyGems` itself failed instantly**
      - `rubygems/configure-rubygems-credentials@v1` doesn't exist, no floating major tag on that
      action. **v0.3.8 (2026-08-13)** pins the exact SHA (`v2.1.0`) `rubygems/release-gem` uses
      internally - RubyGems' first real publish attempt is now this tag.
- [x] **T-165** **Done 2026-08-03.** **`docs/CONTRIBUTING.md` has zero mentions of `bindings/`/`dstu-core-capi` anywhere
      (confirmed by grep, not assumed), added 2026-08-03.** It was written entirely for core-crate
      contributors (a new primitive/mode) and predates all of Phase 3 — a contributor who wants to
      fix or extend an existing binding, or add a sixth one, has no single doc to read start-to-
      finish; today they'd have to reconstruct the process from `docs/bindings-strategy.md`'s
      per-task sections, which are written as a dated decision log (why each choice was made), not
      an onboarding checklist. Add a "Working on a language binding" section to
      `docs/CONTRIBUTING.md` itself (extending its existing owner, per this project's own doc-map
      convention, rather than a new file) covering: the per-binding toolchain setup, `cargo xtask
      <lang>`, D-64/D-65's three test categories applied through that binding's own API, D-118's two
      standing `crypto_secretstream` pitfalls, and (as of `docs/bindings-strategy.md`'s step 10,
      D-151) the Raspberry Pi ARM64 re-check every binding now gets. Point to
      `docs/bindings-strategy.md`'s "standard binding steps" template for the authoritative step
      list rather than duplicating it. **Done**: added the section, covering `cargo xtask <lang>`
      per binding, the D-64/D-65 three test categories through the binding's own API, D-118's two
      `crypto_secretstream` pitfalls, D-151's Pi ARM64 cross-arch check, and a doc-map-sweep
      reminder — pointing to `docs/bindings-strategy.md`'s standard steps rather than duplicating
      them.
- [x] **T-166** **Done 2026-08-03.** **`docs/user-journey-gaps.md`'s three personas predate every language binding,
      added 2026-08-03.** Same build-path analysis as T-164 above. The existing personas (binary
      user, library user, constrained-target user) were written 2026-07-25/26, before Node/Ruby/
      PHP/the C ABI crate existed — there is no persona for "a Python/Node/Ruby/PHP/C developer who
      wants to use `uacrypt` from their own language" (persona 4) or "a contributor who wants to add
      or fix a language binding" (persona 5), even though this document's own stated value is
      "framing surfaces gaps a construction-level view wouldn't" — exactly the gap this session's
      build-path analysis found by walking the journey directly (same methodology T-117's follow-up
      pass already validated for personas 1-3). Add both personas following the existing
      state-diagram + table format; persona 4's "Add dependency" row will read as blocked pending
      T-164 above, same as persona 2's already does pending T-17 — expected, not a new finding to
      resolve here.
      *(Note: the root `README.md`'s stale repo tree — missing `bindings/ruby`/`bindings/php`/
      `crates/dstu-core-capi` — is already tracked as part of T-162 above, deliberately deferred
      until every binding lands; no new task needed for that specific fix.)*
      **Done**: added persona 4 (binding user, non-Rust developer) and persona 5 (binding
      contributor), same state-diagram + table format as personas 1-3. Persona 4's "Install" gap
      is the same shape as persona 2's crates.io gap, tracked at T-164 (owner-gated, mirrors T-17).
      Persona 5's only real gap — no onboarding entry point — closed in the same session via T-165
      above. Cross-persona findings section updated with a new bullet for this pass.
- [x] **T-169** **DONE 2026-08-03 - confirmed green on real CI (run 30809387350, both
      `cross-platform core test (macos-latest)`/`(windows-latest)` succeeded).** `rust.yml`'s own `test` job (`cargo build`/`test`/`clippy`/`fmt` for `dstu-core`/
      `uacrypt`) runs on `ubuntu-latest` only — added 2026-08-03, found answering the owner's own
      question about macOS CI coverage.** Every language binding's CI (`bindings-*.yml`) and the
      `capi`/`release` jobs in `rust.yml` already run a real `[ubuntu-latest, macos-latest,
      windows-latest]` matrix; the core crates' own correctness (unit tests, proptest, `miri`,
      `kani`, `fuzz-smoke`, MSRV) never has, on either macOS or Windows — this dev machine's own
      manual local testing is Windows-only, and the Raspberry Pi rig is aarch64 *Linux*, not macOS,
      so no CI or manual run has ever exercised `dstu-core`'s real test suite on Apple hardware.
      Given this project's own "no hardware/OS lock-in" MVP goal, this is a real gap, not cosmetic.
      **Fix, not a full 3x duplication of the heavy `test` job** (fmt/clippy are lint-only and
      OS-independent for this no-OS-specific-code-path core, so tripling them would just add CI time
      for zero new coverage) — add a lean `cross-platform-test` job, matrix `[macos-latest,
      windows-latest]` (`ubuntu-latest` already fully covered), running `cargo xtask build` +
      `cargo xtask test` (the existing cross-platform entry points, D-12) rather than hand-repeating
      individual `cargo` invocations in YAML.

## Phase 4 — Hardware validation (post-MVP)

- [x] **T-170** **DONE 2026-08-03 (`docs/DECISIONS.md` D-156).** QEMU-emulated STM32 smoke test -
      an additional, cheaper correctness layer raised while discussing whether GitHub CI has any
      real-microcontroller equivalent (it doesn't - only a self-hosted runner wired to physical
      hardware would, which this project doesn't have). Scoped to stock, no-fork-required boards
      only per the owner's explicit framing ("без форків та танцями з бубном"). Checked on the
      Raspberry Pi what Debian's own `qemu-system-arm`/`qemu-system-misc` support: real STM32-class
      boards exist (`netduinoplus2` - Cortex-M4F/STM32F405, matches the already-added
      `thumbv7em-none-eabihf` target from T-116 exactly; `stm32vldiscovery` - Cortex-M3), but ESP32
      has **no real board in mainline QEMU at all**, either Xtensa or RISC-V-C3 (needs Espressif's
      own fork - explicitly out of scope here). New `firmware/qemu-stm32-smoketest` crate (own
      Cargo workspace, D-119-style), runs the exact official Kalyna-128/128 and Kupyna-256 DSTU
      vectors already used by the host test suite, reports pass/fail via ARM semihosting's
      `SYS_EXIT` (becomes the process's real exit code - no text-parsing needed). New
      `cargo xtask qemu-stm32` command (best-effort, checks `qemu-system-arm` first), added to
      `cargo xtask ci`'s optional layers. **Verified on the real Pi in both directions**: a clean
      run exits 0 with both `PASS:` lines; a deliberately corrupted expected-ciphertext byte exits 1
      with a `FAIL:` line - confirms the signal is real, not a constant (reverted after confirming).
      **Also confirmed green on real CI** (the new `qemu-stm32` job in `rust.yml`, run 30809387350).
      **Explicitly not real-hardware validation** - T-55/T-56 (STM32/ESP32 real silicon) are
      unchanged, still not started; this only proves the emulated instruction semantics produce the
      right bytes, not real timing/side-channel behavior.
- [x] **T-54** **Two-resource-profile split, done 2026-07-23 (`docs/DECISIONS.md` D-35/D-38/D-39)** -
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
      `no_std`/`alloc`/`std` matrix (`docs/TASKS.md` T-23) re-checked with `small-tables` added to each,
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
      `uacrypt` release binary, same method as `docs/PERFORMANCE.md`'s binary-level comparison)
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
      `docs/DECISIONS.md` D-19's "Future path" note has both options and why it's a bigger project than
      it looks), narrowing the software-timing exception D-19 documents. Natural place to revisit
      this alongside the hardware side-channel audit above, not before.
- [ ] **T-167** **`cargo-call-stack` worst-case stack-usage proof for the eventual real firmware
      binary — added 2026-08-03, owner-requested follow-up to a question about `no_std`'s stack-
      overflow-protection gap** (the Rust Embedded Book's own `no_std` overview table states this
      plainly). Checked before filing, not assumed: the OS-level guard-page protection that table
      row refers to is a property of the *hosted execution environment*, not of `dstu-core`'s own
      `no_std` Cargo feature — `uacrypt`/every language binding/the C ABI crate all run as ordinary
      OS processes today (Windows/Linux/macOS), so they already have it regardless of `dstu-core`
      internally being `no_std`-compatible. The gap is only real once a genuine bare-metal firmware
      *binary* exists (T-55/T-56 above) — which doesn't yet, per `docs/user-journey-gaps.md`
      persona 3's own "VerifyFlashSize... needs an actual firmware binary crate that doesn't exist
      in this repo" finding. Confirmed no recursion anywhere in `dstu-core` (`curve163::
      scalar_multiply`, the crate's most complex control flow, is a fixed 163-iteration `for` loop,
      not recursive; Kalyna/Kupyna/Strumok are all fixed-round-count loops) and
      `clippy::large_stack_arrays`/`clippy::large_stack_frames` both pass clean on `dstu-core
      --all-features` — a design-level argument plus a spot-check, not a formal bound. `cargo
      miri test` does **not** cover this class of bug (its interpreter doesn't model the real
      machine stack for overflow purposes) — don't rely on the existing Miri job as if it did.
      **Not started, blocked on T-55/T-56** (needs a real linked firmware binary, `memory.x`, an
      entry point/panic handler to actually measure against) — `cargo-call-stack` (LLVM-based
      static worst-case stack-depth analysis, the standard tool for this in bare-metal Rust) is the
      concrete next step once that exists, not before.

## Explicitly out of scope — not scheduled in any phase

- Post-quantum DSTU 8961:2019 (Skelya) / DSTU 9212:2023 (Vershyna) — per D-08, only with a
  separate explicit decision from the project owner

## API surface — `dstu_core::hazmat` module by module

Mirrors the table in `docs/dstu-crypto-project.md` "Concrete API shape" — that table is the
prose/rationale version, this is the checklist version. Keep both in sync when a status changes.
Two-layer split (`hazmat` now, high-level "easy" layer later) decided in `docs/DECISIONS.md` D-09.

- [x] **T-60** `hazmat::kupyna` (`Kupyna256`, `Kupyna512`) — confirmed green, citation in D-10 (see Phase 1)
- [x] **T-61** `hazmat::kalyna` (5 variants) — confirmed green, citation in D-13 (see Phase 1)
- [x] **T-62** `hazmat::strumok` (`Strumok256`, `Strumok512`) — confirmed green, citation in D-18 (see
      Phase 1)
- [x] **T-63** `hazmat::dstu4145` — **done, see T-42/T-44/`docs/DECISIONS.md` D-25** (`sign`/`verify` on the
      163-bit curve, dual-oracle verified). This entry predates T-42/T-44's numbering (same
      duplicate-numbering situation as T-67/T-68); not renumbered per the "IDs are never
      reused/renumbered" rule.
- [ ] **T-64** `hazmat::dstu9041` — hard-blocked, zero source material (see `docs/ORACLES.md`)
- [ ] **T-65** high-level "easy" layer (name TBD) — not started; nothing needs it yet (no keyed/nonce-based
      primitive is implemented before Strumok or `crypto_secretbox`, both currently blocked)
- [x] **T-66** **Done, see T-37/`docs/DECISIONS.md` D-51** (`hazmat::kalyna_ccm`-based, not
      `hazmat::kupyna` — D-05 was resolved toward Kalyna-alone, not the encrypt-then-MAC framing
      this entry's own text originally described). Same duplicate-numbering note as T-67/T-68.
- [x] **T-67** `crypto_auth`/`crypto_onetimeauth` construction (over `hazmat::kupyna`) — **done, see
      T-38/`docs/DECISIONS.md` D-44** (`hazmat::kupyna_kmac`). This entry predates T-38's numbering
      (both track the same work); not renumbered per the "IDs are never reused/renumbered" rule.
- [x] **T-68** `crypto_kdf` construction (over `hazmat::kupyna`) — **done, see T-39/`docs/DECISIONS.md`
      D-45** (`hazmat::kupyna_kdf`). Same duplicate-numbering note as T-67 above.
- [ ] **T-69** `crypto_kx` construction (over `hazmat::dstu4145`/`dstu9041`) — needs both curves; DSTU 9041
      side is hard-blocked
- [x] **T-70** **Done 2026-07-25 - same task as T-40, see that entry and `docs/DECISIONS.md` D-68 for the
      full write-up.** Built over `hazmat::kalyna_gcm`/`hazmat::kupyna_kmac`, not
      `hazmat::strumok`/`hazmat::kalyna` as this stub originally guessed - Strumok has no place in
      an AEAD construction (it's a bare keystream generator, no tag), and Kalyna enters only via its
      already-built GCM mode, not a fresh composition. No longer blocked on D-05 either - that
      blocker was about *which* combined-AEAD mode to build (D-05 was later resolved to
      Kalyna-alone), and `crypto_secretstream` ended up using the already-decided GCM mode rather
      than re-opening that question.
- [x] **T-71** **Done 2026-07-24, see `docs/DECISIONS.md` D-49 (crate vetting) and D-50
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
      from every `no_std` build, see D-50 and the new `docs/SECURITY.md` row). 7 new tests (5 in
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
- [x] **T-72** **Done 2026-07-24, see `docs/DECISIONS.md` D-48**: `dstu_core::randombytes::
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
      `docs/SECURITY.md`. Wired into the CI smoke job; a local nightly+miri toolchain now exists here
      too if a quick local run is ever wanted, though CI is still the primary path.
- [x] **T-75** `cargo audit` + `cargo deny` (2026-07-22, D-11) — elevated to the same required-CI standing
      as miri/fuzz in `docs/SECURITY.md`; policy in `deny.toml`. Wired into `.github/workflows/rust.yml`
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
      `cryptonite` remains a **read-only** reference (see `docs/ORACLES.md` / `oracles/README.md`, the
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

- [x] **T-140** **Done 2026-07-27 - account/token/properties wired up (D-93), first two real
      findings fixed (D-94).** User-proposed 2026-07-27, directly off watching SonarCloud catch a
      real BLOCKER-severity finding on the T-137 UAPKI PR (`specinfo-ua/UAPKI#30`) that neither
      `cargo clippy` nor manual review had surfaced for the analogous Rust code: add SonarQube
      Cloud (SonarCloud) analysis to this project's own GitHub Actions CI, for Rust.
      **Confirmed, not assumed, before proposing this as free**: SonarCloud is free for public
      repositories (`uacrypt` is public) - checked via web search, not recalled from training data,
      per this project's own "verify current state, don't guess" discipline. **Rust support exists
      since April 2025**, but works by wrapping ~85 `clippy` lints as SonarQube-managed findings
      plus adding complexity/coverage metrics - not an independent from-scratch Rust analyzer.
      Since `cargo clippy -- -D warnings` already runs in CI (T-73) and fails the build on any
      warning, the marginal *new-finding* value here is smaller than it was for UAPKI's C code
      (which had no equivalent lint gate before this project's PR) - the real value-add is PR-level
      dashboards/comments and tracking code-quality metrics over time, not catching new bugs
      `clippy` would have missed. **"Automatic Analysis" (SonarCloud's zero-config mode) does not
      support Rust** - needs an explicit `sonar-scanner` step in a new/modified GitHub Actions
      workflow. **Hard blocker on the account-creation step**: linking a SonarCloud organization/
      project to `user137/uacrypt` requires OAuth authorization of the user's own GitHub account -
      this is not something Claude Code can do on the user's behalf (no browser OAuth flow
      available to the agent). **Concrete next steps, in order**: (1) user creates the SonarCloud
      org/project via sonarcloud.io's GitHub OAuth sign-in and generates a project token; (2)
      user adds that token as a `SONAR_TOKEN` repo secret (or Claude can, via `gh secret set`, once
      handed the token value - never ask the user to paste a secret value into chat in plaintext if
      avoidable, prefer they set it directly via `gh secret set SONAR_TOKEN` themselves or via the
      GitHub web UI); (3) Claude adds the `sonar-scanner` CI step (installing a Rust toolchain +
      clippy if not already present in that job, running `cargo clippy --message-format=json` or
      the scanner's own Rust/clippy ingestion convention - confirm the exact expected input format
      from Sonar's own docs at implementation time, don't guess it from this task's summary) plus a
      `sonar-project.properties` file. Local pre-check option confirmed available on this machine
      in the meantime: `cppcheck` (2.21.0, already installed) for C-style local static analysis
      patterns, and `cargo clippy` itself (already required in CI) as the direct local equivalent
      of what SonarCloud's Rust analysis actually runs under the hood.
      **Step (3) done ahead of the account existing, 2026-07-27**: `.github/workflows/
      sonarcloud.yml` (new, separate job from `rust.yml` - installs `dtolnay/rust-toolchain@stable`
      with `clippy`, full git history via `fetch-depth: 0` for SonarCloud's "New Code"/blame
      needs, runs `SonarSource/sonarqube-scan-action@v7` - confirmed via web search that
      `SonarSource/sonarcloud-github-action` is now deprecated in favor of this one, not assumed
      from an older example) and `sonar-project.properties` at repo root (`sonar.sources`/
      `sonar.tests` pointing at both crates, `oracles/**`/`target/**` excluded) are both written
      and committed. **`sonar.projectKey`/`sonar.organization` are explicit placeholders** -
      confirmed via checking `specinfo-ua/UAPKI`'s own workflows that they have *no* Sonar CI step
      at all for their C code (they rely on SonarCloud's zero-config "Automatic Analysis" GitHub
      App mode, which Rust can't use - explains why this project genuinely needs the explicit
      workflow this task adds, not an assumption). The analyzer runs its own `cargo clippy` pass
      by default (`sonar.rust.clippy.enabled`) - no separate JSON-report-generation/import step
      wired in for this first pass, per the docs' own simpler primary path; the
      `sonar.rust.clippy.reportPaths`/`cargo-sonar` external-report alternative (reusing one of
      `rust.yml`'s existing 4 clippy invocations instead of a 5th one) is a possible future
      refinement, not needed to get a first green run.
      **Steps (1)/(2) done 2026-07-27, same day**: user created the SonarCloud org/project via
      GitHub OAuth and handed the generated token directly in chat (not the recommended
      `gh secret set`-yourself path this task's own text called for, but already done by the time
      it happened - the token was never echoed back or logged in any tool output, set via
      `printf '%s' "$TOKEN" | gh secret set SONAR_TOKEN --repo user137/uacrypt` reading from stdin,
      not passed as a literal CLI argument, to avoid it showing in a process listing). Confirmed
      set via `gh secret list` (name/date only, never re-displays the value).
      `sonar.projectKey=user137_uacrypt`/`sonar.organization=user137` filled in by querying
      SonarCloud's own API (`api/organizations/search?member=true`, `api/projects/search`) with
      the now-configured token, rather than guessed from the GitHub-username convention (which
      happened to match here, but wasn't assumed).
      **Actually run end-to-end, not left as "should work in theory"**: the push that added the
      resolved `projectKey`/`organization` triggered the workflow for real - it failed immediately
      (`sonar.tests` pointed at `crates/uacrypt/tests`, which doesn't exist - `uacrypt`'s own tests
      live inline in `src/` as `#[cfg(test)]` modules, unlike `dstu-core`'s real `tests/` dir;
      assumed the same layout applied to both crates without checking, caught by the actual run).
      Fixed, pushed again - `success`, confirmed via `gh run list`. Verified it's a genuine
      analysis, not just "the scanner didn't crash", by querying the API directly:
      `api/measures/component` returned real numbers (14197 `ncloc`, 0 bugs, 0 vulnerabilities, 2
      code smells), not zeros/nulls. The user separately rotated `SONAR_TOKEN` afterward (set
      directly via `gh secret set`, not pasted in chat this time) - re-ran the same workflow run
      (`gh run rerun`, no new commit needed) to confirm the new token also works, which it did.
      **The 2 code-smell findings themselves, and their fixes, are their own entry - D-94.**

## Full DSTU 7624 mode-of-operation coverage at `hazmat` (T-88 onward)

Only CCM (#8, T-81) was implemented before this. User asked 2026-07-24 for all 10 official modes at
`hazmat`, independent of the public `crypto_secretbox` question (still restricted to GCM/CCM/KW
candidates only, per D-05/D-47 — unchanged, not reopened per mode). Full 5-stage roadmap (by
cost/oracle-strength) recorded in `docs/DECISIONS.md` D-53. Stage A = ECB/OFB/CBC/CFB/CTR (no new field
arithmetic); Stage B = CMAC; Stage C = KW; Stage D = GCM/GMAC (needs new GF(2^m) at three field
sizes); Stage E = XTS (reuses Stage D's field module). Every raw/non-AEAD module's doc must carry an
explicit misuse warning (no integrity, prefer `crypto_secretbox` unless the raw mode is genuinely
needed) — non-negotiable per D-53, not optional per mode.

- [x] **T-88** **ECB (#1) done, see `docs/DECISIONS.md` D-53** — `hazmat::kalyna_ecb`
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
- [x] **T-89** **OFB (#6) done, see `docs/DECISIONS.md` D-53** — `hazmat::kalyna_ofb`
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
- [x] **T-90** **CBC (#5) done, see `docs/DECISIONS.md` D-53** — `hazmat::kalyna_cbc`
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
- [x] **T-91** **CFB (#3) done, see `docs/DECISIONS.md` D-53** — `hazmat::kalyna_cfb`
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
- [x] **T-92** **CTR (#2) done, see `docs/DECISIONS.md` D-53 - Stage A complete, all five modes shipped**
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
- [x] **T-93** CMAC (#4) — Stage B, done. `hazmat::kalyna_cmac` (`docs/DECISIONS.md` D-54): CBC-MAC over
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
- [x] **T-94** KW (#10) — Stage C, done. `hazmat::kalyna_kw` (`docs/DECISIONS.md` D-55): half-block
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
      (`Gf2m128`/`Gf2m256`/`Gf2m512`, `docs/DECISIONS.md` D-56) is a from-scratch, correctness-first
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
      **GMAC (commit 2, `hazmat::kalyna_gmac`, `docs/DECISIONS.md` D-57)**: `advisor()` caught two wrong
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
- [x] **T-96** XTS (#9) — Stage E done, see `docs/DECISIONS.md` D-58. **10/10 DSTU 7624 modes now
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

- [x] **T-97** `docs/SECURITY.md`'s supply-chain vetting table is missing a row for `subtle` — the only
      dependency in either crate's `Cargo.toml` with no row at all, despite being direct,
      unconditional (not feature-gated, unlike `getrandom`/`argon2`), and used for every
      constant-time tag/checksum comparison in the codebase (`kalyna_cmac`/`kalyna_kw`/
      `kalyna_ccm`/`kalyna_gcm`/`kalyna_gmac`/`dstu4145`). `docs/SECURITY.md` states the table applies
      "before adding any crypto-adjacent dependency" — this one predates the table's own upkeep,
      not a new gap, but still an open one. Add maintainer/reproducible-build/audit/CVE-history
      columns matching the existing `zeroize` row's level of detail.
      **Resolved 2026-07-25.** Row added: maintainer verified via crates.io's own API (not assumed
      from memory) — `dalek-cryptography` org (isis lovecruft/Henry de Valence, the
      `curve25519-dalek`/`ed25519-dalek` team); no `build.rs` in the published source (checked the
      downloaded crate directly); `cargo audit` clean as of 2026-07-25. Doc-only, no `docs/DECISIONS.md`
      entry — trivial per the roadmap's own framing, nothing architectural to record.
- [x] **T-98** CI's `fuzz-smoke` job (`.github/workflows/rust.yml`) runs only the `kupyna` target.
      `crates/dstu-core/fuzz/fuzz_targets/` also has `kalyna`, `kalyna_ccm`, and `strumok` — none of
      the three run in CI, only ever locally per D-32's note. `docs/SECURITY.md` calls `cargo fuzz`
      required, not optional, for every parser of untrusted input bytes, which most of these are.
      Separately: **no fuzz target exists at all**, locally or in CI, for any of the four modes
      landed this session — `kalyna_cmac`, `kalyna_kw`, `kalyna_gcm`, `kalyna_gmac` — despite real
      length/index arithmetic in each (KW's `r <= 20` bound, GCM/GMAC's padding-marker byte-offset
      math). Scope: add targets for the four new modes, then decide whether CI should rotate through
      all fuzz targets (e.g. one per job matrix entry) instead of hardcoding `kupyna` alone.
      **`hazmat::kalyna_cfb` (T-91) is the sharpest instance of this gap** — see T-100 below, it's
      the one module where a known reachable panic, zero fuzz coverage, and (per T-100) no completed
      Miri run all intersect.
      **Resolved 2026-07-25, see `docs/DECISIONS.md` D-61.** Five new targets added
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
      against current `docs/TASKS.md`/`docs/DECISIONS.md` state before it's trusted again as the up-to-date
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
      GCM/KW-now-built correction). Added an explicit banner noting `docs/TASKS.md`'s own roadmap now
      supersedes this document's "Concrete path" section as the authoritative sequencing (per that
      roadmap's own stated intent), without deleting or renumbering the historical reasoning behind
      steps 1-2, which remain load-bearing. Also folded in this session's own T-100/T-101/T-98/T-97
      results, including the CI Miri pass confirmed the same day (see `docs/TASKS.md` T-100's own
      update) — the engineering-infrastructure paragraph previously understated the Miri/fuzz CI
      history as "wired in" when the job had in fact never completed on any push before today.
      Doc-only change, no `docs/DECISIONS.md` entry (nothing architectural, a reconciliation pass against
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
      This matters beyond "a CI badge is red": `docs/SECURITY.md` names `cargo miri test` a *required*
      layer, same standing as fuzz/audit/deny, and several `docs/DECISIONS.md` entries explicitly defer
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
      **Resolved 2026-07-25, see `docs/DECISIONS.md` D-59 for the full measurement trail.** The
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
      full detail in `docs/DECISIONS.md` D-59's own update.
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
      Raspberry Pi rig, `docs/TASKS.md` "Testing & hardening", doesn't have Miri installed yet per its
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
      constraint loudly in the module doc — and T-91 was then marked done. **Nothing in `docs/TASKS.md`
      currently tracks whether that's the right resolution.** `docs/SECURITY.md`'s threat model states
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
      from a public-facing `crypto_*`/`uacrypt` surface where docs/SECURITY.md's "must not panic" line
      unambiguously applies? **Sharpened by T-98/T-100**: this is also the one module with zero fuzz
      coverage and (per T-100) no completed CI Miri run — so today, nothing would actually catch a
      regression in either direction if this specific input shape's behavior changed. Needs a
      decision (put to the project owner, matching this project's own "real security-posture forks
      get decided explicitly, not silently" precedent — D-46/T-40's re-scoping questions are the
      model to follow), not just a fix picked unilaterally.
      **Resolved 2026-07-25, own plan-mode pass per the roadmap's requirement, see `docs/DECISIONS.md`
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
`docs/SECURITY.md` table row, any time) - **DONE**: `subtle` row added, maintainer verified via
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
**DONE, see `docs/DECISIONS.md` D-62.** Low-risk by construction (all five modes call only the existing
per-variant `ExpandedKey` API, never `hazmat::tables` directly - same reasoning D-41 already gave
for CCM), confirmed rather than assumed: all 8 `dstu-core` crate-level build combinations clean;
all 5 modules' test suites (69 tests total) pass identically under `small-tables`; `clippy -D
warnings`/`fmt --check` clean on both profiles; workspace-level `no_std`+`small-tables` build
clean. Miri/fuzz under `small-tables` and a fresh Pi re-run both deliberately out of scope for this
pass, matching D-39's own precedent.

**Step 2 complete.** Next: Step 3 (the libsodium-shaped `crypto_*` frontend).

**Step 3 - The libsodium-shaped `crypto_*` frontend over everything in `hazmat`**:
1. **DONE 2026-07-25, see `docs/DECISIONS.md` D-63.** `crypto_secretbox` migrated to Kalyna-GCM
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
2. **DONE 2026-07-25, see `docs/DECISIONS.md` D-66 (T-105).** Unlike this roadmap's three other named
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
3. **DONE 2026-07-25, see `docs/DECISIONS.md` D-67 (T-106).** `crypto_stream` (Strumok) high-level
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
4. **DONE 2026-07-25, see `docs/DECISIONS.md` D-66's addendum.** KW stays `hazmat`-only - added an
   explicit row for `hazmat::kalyna_kw` to `docs/dstu-crypto-project.md`'s canonical mapping table
   (it had none before), stating why: libsodium itself has no key-wrap primitive to map onto, so
   this is a documented gap in libsodium parity, not an oversight.
5. **DONE 2026-07-25, see `docs/DECISIONS.md` D-66's addendum.** `crypto_kx`/`crypto_box` (DSTU 9041)
   confirmed still hard-blocked - re-checked against `docs/ORACLES.md`/`docs/TASKS.md` T-46/T-47 rather than
   assumed unchanged, still zero source material found anywhere. No doc changes needed (existing
   rows were already accurate); confirmation recorded rather than left a silent no-op.

**Step 4 - publication.** T-17 (crates.io) and T-18 (GitHub Releases binaries). **Not queued behind
Step 5 - gated on an explicit request, not simply "last in line."** 2026-07-25: user confirmed
publication stays out of the plan entirely until they ask for it by name; do not start T-17/T-18
work as a side effect of finishing Step 5.
**2026-07-26: T-18 explicitly requested and done, see `docs/TASKS.md` T-18/T-119** - GitHub Release
`v0.1.0` with binaries for all three platforms plus the `dstu-core` source distribution. **T-17
explicitly re-confirmed as still separately gated in the same request** (`AskUserQuestion` offered
both "GitHub only" and "GitHub + crates.io"; the owner chose GitHub only) - do not start T-17 work
as a side effect of T-18 having landed.

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
   `docs/DECISIONS.md` D-68 and `docs/TASKS.md` T-40's own entry.** Own plan-mode pass taken first, per this
   roadmap's standing convention. Landed as `dstu_core::crypto_secretstream` (tag-per-chunk framing
   over `hazmat::kalyna_gcm`, full MESSAGE/PUSH/REKEY/FINAL tag set, caller-buffer `no_std`-capable
   API) plus a same-session `uacrypt encrypt`/`decrypt` rewire onto it (breaking wire-format change
   from the old `crypto_secretbox`-backed command, called out explicitly). Fully verified: 22/22 +
   48/48 tests, full workspace suite, clippy/fmt/no_std matrix clean, scoped Miri 22/22 passed 0 UB
   in 1276.00s.
2. **T-107 - per-crate `README.md`** for `dstu-core`/`uacrypt`, `readme` field in each `Cargo.toml`.
   **Done 2026-07-25, see `docs/TASKS.md` T-107's own entry above** - both READMEs written crate-scoped
   (not copies of the root one), `cargo package --list` confirms both now ship, dry-run publish
   file count rose 130 -> 133, `xtask fmt`/`build`/`clippy` clean.
3. **T-109 - `Cargo.toml` publish metadata** (`repository`/`homepage`/`documentation`/`keywords`/
   `categories`) + physical per-crate `LICENSE-MIT`/`LICENSE-APACHE` copies. **Done 2026-07-25, see
   `docs/TASKS.md` T-109's own entry above** - `rust-version` deliberately deferred to T-111 (needs
   empirical MSRV measurement, not a guess). `cargo publish --dry-run -p dstu-core --allow-dirty`
   now shows zero metadata warnings; category slugs verified live against crates.io's real API.
4. **T-110 - `[package.metadata.docs.rs]` with `all-features = true`** on both crates - already
   verified safe (`small-tables` gates no `pub` item). **Done 2026-07-25, see `docs/TASKS.md` T-110's own
   entry above.**
5. **T-112 - crate-level `#![doc]` provisional-status warning** for both crates, pointing back at
   `docs/SECURITY.md`/`docs/DECISIONS.md` rather than re-arguing the citations inline. **Done 2026-07-25, see
   `docs/TASKS.md` T-112's own entry above.**
6. **T-108 - user-friendly `--help`/usage text for `uacrypt`.** **Done 2026-07-25, see `docs/TASKS.md`
   T-108's own entry above.**
7. **T-111 - `docs/CHANGELOG.md` + a real, empirically-determined MSRV.** Advisor flag, keep this split
   in mind when scoping the work: the `docs/CHANGELOG.md` half is a writing task, but MSRV is **not** -
   it means actually installing two or three candidate older toolchains and running the full
   8-combination feature matrix on each (this project's own dependency tree, `argon2`/`getrandom`/
   `zeroize`/`subtle` and their transitives, has already produced one surprising transitive-feature
   result, D-50 - don't assume a floor without measuring it). Budget accordingly; this is not a
   same-size item as T-107/T-109/T-110/T-112 above despite living in the same step. **Done
   2026-07-26, see `docs/DECISIONS.md` D-69 and `docs/TASKS.md` T-111's own entry above** - MSRV
   empirically measured at 1.87.0.
- [x] **T-113 - multi-part/streaming `crypto_sign`. DONE 2026-07-26, see `docs/DECISIONS.md` D-70.** The
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
`docs/DECISIONS.md` entry with citations and a `docs/TASKS.md` status update. Commit after green; push only
on explicit request.

### RESUME HERE (state as of 2026-07-25, saved for a memory-clear/new-session handoff)

**Step 3 item 1 (`crypto_secretbox` → Kalyna-GCM, D-63) is fully done, fully verified, and
committed** - including the scoped Miri run (11/11, 0 UB, 1135.80s). `T-103`/`T-104` (adversarial
and misuse test-coverage audits over the same migration, `docs/DECISIONS.md` D-64/D-65) are also done,
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
1. **T-40 - `crypto_secretstream` - DONE, see the Step 5 entry above and `docs/DECISIONS.md` D-68.**
   `uacrypt encrypt`/`decrypt` rewired to it in the same session, per the user's chosen scope.
2. **T-107 - per-crate `README.md` - DONE, see `docs/TASKS.md` T-107's own entry above.** Both crates
   now package their own README; `cargo package --list`/dry-run publish both confirm it.
3. **T-109 (`Cargo.toml` metadata + LICENSE files) - DONE, see `docs/TASKS.md` T-109's own entry
   above.** `repository`/`homepage`/`documentation`/`keywords`/`categories` all set on both crates,
   `rust-version` deliberately deferred to T-111; physical `LICENSE-MIT`/`LICENSE-APACHE` now ship
   in both crates' tarballs; `cargo publish --dry-run -p dstu-core --allow-dirty` shows no more
   metadata warnings.
4. **T-110 (docs.rs metadata) - DONE, see `docs/TASKS.md` T-110's own entry above.** `[package.metadata.
   docs.rs]` with `all-features = true` added to both crates' `Cargo.toml`; build/clippy/fmt clean.
5. **T-112 (crate-level provisional-status doc warning) - DONE, see `docs/TASKS.md` T-112's own entry
   above.** `dstu_core::lib.rs`, `uacrypt::lib.rs`, and `uacrypt::main.rs` all now carry a top
   doc-comment stating D-05/D-15's provisional status and the no-side-channel-claim, pointing at
   `docs/SECURITY.md`/`docs/DECISIONS.md`; build/clippy (incl. the `doc_lazy_continuation` gotcha)/fmt clean.
6. **T-108 (`uacrypt --help`) - DONE, see `docs/TASKS.md` T-108's own entry above.** Top-level and
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
7. **T-111 - DONE 2026-07-26, see `docs/TASKS.md` T-111's own entry above and `docs/DECISIONS.md` D-69.**
   MSRV measured (not guessed) at `1.87.0` - the real floor turned out to be this crate's own
   unconditional use of `u64`/`usize::is_multiple_of`, not any dependency's declared floor (those
   topped out lower, at 1.85/1.86). `rust-version` set on both `Cargo.toml`s, a build-only `msrv`
   CI job added, `docs/CHANGELOG.md` written.
8. **T-113 - DONE 2026-07-26, see `docs/TASKS.md` T-113's own entry above and `docs/DECISIONS.md` D-70.** The
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
  `docs/release-readiness.md`'s new audit section, not `docs/TASKS.md` - don't re-derive them as tasks
  without new information surfacing.

## Roadmap: perf/hygiene/investigation cluster (2026-07-26, user-approved sequencing)

Recorded here, not only in a session's ephemeral plan, per the same standing instruction as the
Step 0-5 roadmap above: this sequencing must survive a memory clear or a new session. Scope is
every task open as of 2026-07-26 **except** T-17 (crates.io - separately gated on an explicit
request, see above, not part of this sequence at all). Four tiers, not a flat list - later tiers
depend on earlier ones, items within a tier don't depend on each other.

**Open question, resolved 2026-07-26 (see `docs/DECISIONS.md` D-81)**: T-130's Miri/Windows proptest
hang was diagnosed against `hazmat::kalyna`'s suite specifically; confirmed **mechanism-wide, not
Kalyna-specific** (reproduced identically on a `hazmat::kupyna` proptest under default isolation),
and then resolved outright - attempt four's combination (`-Zmiri-disable-isolation` +
`PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` + `PROPTEST_CASES=8`) works on both modules, and the full
13-function `hazmat::kalyna` proptest suite passed under Miri (0 UB, 511.16s). **T-130 does not
move ahead of Tier C - it's fully closed before Tier C starts**, which is better than the
conditional reordering this question originally anticipated: Tier C's own Miri done-bar is now
achievable, not merely gated on a still-open investigation.

**Tier A - cheap, no `hazmat` risk, fixes the repo's own documentation honesty:**
1. **T-87** - refresh `docs/release-readiness.md`. Its own headline text still reads as if D-05 is
   unresolved and no `crypto_secretbox`/streaming AEAD exists - both stale, superseded by D-63/
   D-66/D-67/D-68 and D-05's 2026-07-24 resolution-on-assumption. Grep the stale phrases
   (`255-byte`, `no crypto_secretbox`, `D-05 is still the blocker`, `not started`) across
   `docs/release-readiness.md`, `docs/dstu-crypto-project.md`, `README.md` before rewriting -
   same "grep your own task ID across every doc-map file" discipline `CLAUDE.md` already states.
2. **T-138 + T-133, one session** - both need the same scratch-only `uapki_bench.exe`; doing them
   together avoids rebuilding it twice. Re-measure CMAC at 64 B for D-80's timer-placement bug
   (T-138), and formalize the byte-for-byte UAPKI comparison into a committed, reusable
   script/procedure rather than an ad hoc habit (T-133).
   **T-138 done 2026-07-26, `docs/DECISIONS.md` D-82. T-133 done 2026-07-26, `docs/DECISIONS.md` D-83** -
   the project owner chose "commit it" when asked; `tests/oracle-harness/uapki-cmac-bench/
   cmac_bench.c` is now committed (CMAC only, deliberately narrow scope).
3. **T-23 + T-35, re-run now** - both say "ongoing by design" but both were last checked
   2026-07-22, before T-128's const-generic Kalyna refactor. Not ambient hygiene right now -
   overdue by their own stated trigger ("any change touching `hazmat::kalyna`/`kupyna`/`strumok`
   internals"). Re-run the full feature matrix locally (T-23) and the Raspberry Pi rig (T-35)
   before trusting either as current.

**Tier B - investigation that gates Tier C:**
4. **T-130** - **Done 2026-07-26, see `docs/DECISIONS.md` D-81.** Resolved via attempt four
   (`-Zmiri-disable-isolation` + `PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` + `PROPTEST_CASES=8`),
   confirmed mechanism-wide (not Kalyna-specific) and confirmed at full-module scale (13/13
   `hazmat::kalyna` proptests, 0 UB). Tier C's Miri done-bar is now achievable.
5. **T-136** - **First measurement done 2026-07-26, see `docs/DECISIONS.md` D-84.** An isolated
   `criterion` differential benchmark of `encipher_round_n::<4>` against `fused_inv_round_n::<4>`
   alone (the existing `benches/kalyna.rs` block-only pair already was this measurement) confirmed
   the decrypt/encrypt asymmetry shows up at the round-function level itself, before T-129 touches
   either function's internals. Root cause (why, not just where) is still open - T-136 itself
   stays open for that, this roadmap's own narrower ask (measure it now, before it's lost) is met.

**Tier C - perf rewrites, each gets its own `advisor()` consultation and its own plan-mode pass
before any code is written (this roadmap's own sequencing call does not substitute for either -
write that into each step's own session, don't read "advisor was consulted" as already satisfied):**
6. **T-134** - **Done 2026-07-27, see `docs/DECISIONS.md` D-85.** Kupyna `sub_shift_mix`
   const-generic-over-`COLUMNS`, `advisor()`-consulted and plan-mode-approved before implementation.
   Measured -29 to -31% (Kupyna-256) / -17 to -19% (Kupyna-512), matching the predicted ranges.
7. **T-135** - **Done 2026-07-27, see `docs/DECISIONS.md` D-86.** Strumok `apply_keystream` batched/
   fixed-index rewrite, `advisor()`-consulted and plan-mode-approved before implementation.
   `criterion` -53.5 to -64.7% at 1024/65536 B; binary-level gap to outspace closed from ~3.2-3.9x
   to ~1.19-1.25x.
8. **T-129** - **Investigated and closed 2026-07-27, `docs/DECISIONS.md` D-88.** A measured spike (not
   just reasoning) showed the word-wide gather is a no-op at `NB=2` (LLVM already does it) and a
   regression at `NB=4`/`NB=8` (lost inlining / new register spills). No code change shipped.

**Tier D - gated on the user, not to be executed unilaterally:**
9. **T-137** - investigate and verify the UAPKI XTS `gf2m_mul`-specialization fix locally (against
   `dstu7624_xts_self_test`) freely; **opening an issue or PR on `specinfo-ua/UAPKI` needs its own
   explicit go-ahead when this step is reached** - do not treat "the fix works locally" as
   authorization to publish it upstream.

**Excluded from this sequence entirely, with reason (not "later steps" - re-adding any of these
without new information re-litigates a decision already made):** `T-45` (sketched only, not
scheduled) - `T-46`/`T-47`/`T-64`/`T-65`/`T-69` (DSTU 9041, zero source material, hard-blocked) -
`T-49`-`T-53` (language bindings, second priority per `CLAUDE.md`) - `T-55`-`T-59` (Phase 4
hardware validation, the Step 0-5 roadmap already resolved this out of scope for "a complete
product" right now) - `T-58` (a standing non-claim to keep intact, not a task with an end state).

Verification bar per tier, unchanged from the Step 0-5 roadmap's own established practice:
`cargo test --workspace --all-features`, `cargo clippy --workspace --all-features -- -D
warnings`, `cargo fmt --all -- --check`, the `no_std` feature matrix, and - for Tier C only - a
Miri run that actually completes (gated on Tier B's T-130 finding, not assumed). Each completed
item gets its own `docs/DECISIONS.md` entry with citations and a status update at its own `T-NN` line
above; this section only tracks sequencing, not outcomes - don't duplicate result detail here that
belongs at the task's own entry.

### RESUME HERE (state as of 2026-07-27, saved for a memory-clear/new-session handoff)

**This entire roadmap (Tiers A-C) is now closed.** Tier A/B closed in prior sessions (T-130 Miri
fix, T-87/T-23/T-35 doc/hygiene re-checks, T-138/T-133 CMAC re-measurement, T-136's first asymmetry
measurement - T-136's own deeper root-cause investigation stays open as its own standalone task,
the roadmap's own narrower ask was already met). Tier C: **T-134** (Kupyna `sub_shift_mix`
const-generic-over-`COLUMNS`, `docs/DECISIONS.md` D-85, -29 to -31%/-17 to -19%) and **T-135** (Strumok
`apply_keystream` batched/fixed-index rewrite, `docs/DECISIONS.md` D-86, `criterion` -53.5 to -64.7%,
binary-level gap to outspace ~3.2-3.9x -> ~1.19-1.25x) both shipped real, measured wins. **T-129**
(this session) was investigated and closed *without* a code change, `docs/DECISIONS.md` D-88: a
measured spike (hoisting whole-`u64` column loads, not just reasoning about it) showed the proposed
"word-wide gather" is a no-op at `NB=2` (LLVM's own optimizer already does the equivalent) and a
real regression at `NB=4` (lost inlining) and `NB=8` (34 new register spills, ~2x more memory
traffic than the already-clean baseline) - the same "test the hypothesis via `--emit=asm` before
planning a rewrite" method `advisor()` established for T-139/D-87 (Strumok's own analogous
follow-up, also closed without a code change the same day). **Nothing is queued next from this
roadmap** - T-136's deeper root-cause (why Kalyna decrypt is asymmetrically faster on some variants)
is the one still-open standalone investigation, not part of this roadmap's own sequencing, and
Tier D (T-137, the UAPKI XTS upstream fix) remains gated on explicit user request before opening
anything upstream - investigating/verifying locally is fine, that gate is unchanged.

### RESUME HERE (state as of 2026-07-27, later same day - saved for a memory-clear/new-session handoff)

Since the note directly above was written: **T-137 is done** (PR `specinfo-ua/UAPKI#30` opened,
both UAPKI-side CI checks green, D-90/D-91/D-92) - still awaiting upstream maintainer review, out of
this project's control. **T-140 is done** (SonarCloud+Rust wired up for this repo's own CI, D-93;
its first two real findings - Cognitive Complexity in `Core::apply_keystream` and `uacrypt::run` -
fixed and verified with no regression, D-94; reconfirmed on a real push, `8e5a2a8`, all three
workflows green including a genuinely-passing `cargo miri test` in 2h23m). **T-136 is now also
closed** (D-95) - the `nb=4` asymmetry was cross-checked on the Raspberry Pi rig and confirmed to be
an x86-64-specific LLVM codegen artifact (winner flips between x86-64 and aarch64 on structurally
identical fully-inlined code), not a portable property of the algorithm.

**Nothing is queued next.** Every item this session's roadmap and its two follow-on investigations
named is either done or explicitly, deliberately gated (T-17 crates.io publish - owner request only;
Tier D upstream work - same gate). The next session should ask the project owner what to prioritize
rather than assume a next task - see the open, unstarted, unblocked items list further up this file
(T-23/T-35 re-checks, or genuinely new-scope items like language bindings/hardware validation, all
Phase 2+ and none currently in flight).

## Repo hygiene: root markdown declutter (2026-07-28, owner-requested)

- [x] **T-141** **Done 2026-07-28, see `docs/DECISIONS.md` D-96.** Root directory had 8 markdown
  files (`CHANGELOG.md`, `CLAUDE.md`, `DECISIONS.md`, `ORACLES.md`, `PERFORMANCE.md`, `README.md`,
  `SECURITY.md`, `TASKS.md`) cluttering the GitHub landing page. Owner wanted only `README.md`
  (GitHub's own landing-page file) and `CLAUDE.md` (Claude Code's project-instructions file) left
  at root; moved `CHANGELOG.md`/`DECISIONS.md`/`ORACLES.md`/`PERFORMANCE.md`/`SECURITY.md`/
  `TASKS.md` into `docs/`, and rewrote every repo-wide citation of those six filenames
  (prose/backtick mentions in `.md`/`.rs`/`.toml`/`.properties`/`.gitignore` files - confirmed by
  survey there are zero actual markdown-link-syntax references anywhere in this repo to these
  files, and exactly one file, `oracles/README.md`, uses a real `../` relative path) to carry a
  uniform `docs/` prefix, including the six files' own cross-citations of each other post-move
  (matches this repo's pre-existing convention of always citing `docs/*.md` files repo-root-
  relative, even from siblings in the same directory - see D-96). Executed via a one-off Python
  script (not by hand) given the reference count (132 files cite `DECISIONS.md` alone) - a
  CRLF-line-ending bug the script's first pass introduced (Windows text-mode write) was caught by
  `cargo fmt --check` and fixed in the same session, see D-96 for the full story and
  before/after verification (`cargo build`/`clippy --all-features`/`fmt --check` clean, `cargo
  test --workspace` re-run to confirm no functional regression).

- [x] **T-142** **Done 2026-07-28, see `docs/DECISIONS.md` D-97.** Owner asked to close the
  remaining gaps on GitHub's "Community Standards" checklist (screenshot showed Description/
  README/License/Security policy already green; Code of conduct, Contributing, Issue templates,
  Pull request template still missing). Added all four, tailored to this project rather than
  generic boilerplate: `docs/CODE_OF_CONDUCT.md` (Contributor Covenant v2.1, enforcement via
  opening a GitHub issue - owner's explicit choice over a private email contact, see D-97),
  `docs/CONTRIBUTING.md` (open-project/PRs-welcome stance - owner's explicit choice over a
  solo-project framing; cites the real test-first/dual-oracle/three-test-category bar from
  `docs/SECURITY.md`/`docs/TASKS.md` rather than generic advice), `.github/ISSUE_TEMPLATE/`
  (bug report + feature request + a `config.yml` redirecting security reports to GitHub Security
  Advisories instead of a public issue, consistent with `docs/SECURITY.md`'s existing policy), and
  `.github/PULL_REQUEST_TEMPLATE.md` (checklist mirroring `docs/CONTRIBUTING.md`'s verification
  bar). `README.md`'s repository-structure tree and a new short "Contributing" section were updated
  to point at all four. `CODE_OF_CONDUCT.md`/`CONTRIBUTING.md` placed in `docs/` (not root),
  consistent with T-141/D-96's just-established convention and GitHub's own recognition of
  community-health files in `docs/` as well as root/`.github/`.

- [x] **T-143** **Fully done 2026-07-29, see `docs/DECISIONS.md` D-98 (triage) and D-99 (migration,
  disposition of the open question below).** Owner
  surfaced a GitHub Code Scanning screenshot: 80 open alerts from CodeQL **default setup** (enabled
  outside this session, distinct from T-140's SonarCloud), 69 `rust/hard-coded-cryptographic-value`
  (critical) + 11 `actions/missing-workflow-permissions` (medium). Triaged both rule types
  separately rather than treating "80 alerts" as one problem:
  - **11 `missing-workflow-permissions`: real, fixed.** Added an explicit `permissions: contents:
    read` workflow-level default to all four `.github/workflows/*.yml` files, with per-job
    overrides only where actually needed (`rust.yml`'s `audit` job needs `checks: write` for
    `rustsec/audit-check`'s annotation; `release.yml`'s `publish-release` already correctly had
    `contents: write` and was left alone) - confirmed per-job need by reading each job's steps and
    the two third-party actions' own READMEs, not blanket-copied.
  - **69 `hard-coded-cryptographic-value`: confirmed false positives across three distinct
    mechanisms** (test-vector files/test modules; byte-length literals in variant-dispatch macros
    misread as key material; zero-init buffers immediately overwritten with real runtime/PRNG
    data), **plus a fourth, more careful pass on `crypto_secretstream.rs:244`** (`chunk_iv`'s
    constant-zero high bytes are provably harmless by the module's own counter-never-resets +
    per-stream-subkey design, not just "overwritten later" like the others). See D-98 for the full
    per-bucket evidence. No code changed - there is no real secret to remove.
  - **Owner chose migration over bulk-dismissal** (dismissal doesn't scale - this project keeps
    adding DSTU test vectors, so bucket-1 false positives would keep recurring forever, one alert
    at a time). Added `.github/workflows/codeql.yml` (advanced setup, adapted from GitHub's own
    generated template) + `.github/codeql/codeql-config.yml` (one `query-filters: exclude` entry
    for `rust/hard-coded-cryptographic-value`, nothing else changed). Verified before disabling
    anything: confirmed via `gh api .../code-scanning/analyses` that default setup's `c-cpp`/
    `csharp`/`java-kotlin` runs were genuine (`build-mode: none`, real non-zero `rules_count`), not
    silent build failures, so all 5 languages were kept in the migration with no build steps needed
    anywhere; pushed the new workflow with default setup still enabled, watched it run green, then
    confirmed the config was actually honored (Rust's `rules_count` 25->24, `results_count` 69->0,
    every other language's `rules_count` unchanged) before disabling default setup
    (`state: not-configured`, confirmed via a follow-up `GET`). Result: 0 open code-scanning alerts,
    full 5-language coverage preserved, the false-positive rule structurally silenced going forward
    instead of requiring repeated manual dismissal. See D-99 for the full verification chain.

- [x] **T-144** **Done, then reversed, 2026-07-29 - see `docs/DECISIONS.md` D-100 (built) and D-101
  (removed).** Owner asked about enabling Dependabot version updates after seeing the "Enable"
  prompt on the repo's Security settings - built a real checked-in `.github/dependabot.yml` with
  deliberate settings (four `updates:` entries covering `cargo` for `/`/`xtask`/`fuzz` plus
  `github-actions`, weekly schedule, capped PR limits, grouping, commit-message prefixes) rather
  than the bare toggle. Took two rounds of real friction to get right (D-100's amendments: a
  schema-rejected `versioning-strategy` value, a `dtolnay/rust-toolchain` MSRV-pin false bump that
  broke its own CI check, a `getrandom` major-version bump worth blocking automatically). Owner then
  asked whether Dependabot could be scoped to "only an explicit vulnerability, ignore the rest" -
  checked first rather than hand-building that behavior: **Dependabot Security Updates + Alerts
  were already enabled independently of this file** (`gh api .../automated-security-fixes` ->
  `enabled: true`; confirmed via API, not assumed) and already do exactly that, with no config file
  needed at all. `.github/dependabot.yml` (the *Version Updates* feature - "a newer release exists,
  security-relevant or not" - a different, more opinionated feature than what the owner actually
  wanted) was **deleted entirely**. Net state: Dependabot Security Updates/Alerts (zero-maintenance,
  vulnerability-only) are the sole automated dependency mechanism now, alongside `cargo audit`
  (`rust.yml`) as the independent CI-side check.

- [x] **T-145** **Done 2026-07-29, see `docs/DECISIONS.md` D-102.** Owner asked where Kani (bounded
  model checking) would add real value beyond the existing miri/fuzz/proptest stack, "точково" -
  precisely, not broadly. Surveyed `hazmat` against two fit criteria (compile-time-fixed loop
  bounds, a property currently only hand-argued) and picked `dstu4145::gf2m163::reduce` as the one
  strong match - its own doc comment claims "provably enough"/"provably sufficient" for its cleanup
  passes, never checked by anything wider than a few hand-picked property tests, and it's on every
  DSTU 4145 sign/verify path. Piloted on a throwaway branch/workflow before committing to anything:
  local Windows can't compile `kani-verifier` at all (Unix-only APIs in its own source), the
  project's aarch64 Raspberry Pi's glibc 2.36 is older than the prebuilt bundle's `GLIBC_2.39`
  requirement, but `ubuntu-latest` (Kani's actual supported platform) ran both pilot harnesses to
  `VERIFICATION:- SUCCESSFUL` in ~1m22s total. Landed for real: `#[cfg(kani)] mod kani_proofs` in
  `gf2m163.rs` (kept from the pilot, unchanged), a `[lints.rust] unexpected_cfgs` registration in
  `dstu-core`'s `Cargo.toml` (`kani` is a compiler-shim cfg, not a Cargo feature), a new mandatory
  `kani` job in `rust.yml` (same standing as `miri`/`fuzz-smoke`, not best-effort), and a
  best-effort `cargo xtask kani` subcommand (prints the specific Windows-incompatibility reason,
  not `require`'s generic message, since no install step would fix it there). `README.md`/
  `docs/SECURITY.md` updated to match. Not extended to `gf2m_wide.rs` or any other module this pass
  - a possible future follow-up, not a commitment made here.

- [x] **T-146** **Fix landed 2026-07-29, see `docs/DECISIONS.md` D-103 - confirmed 2026-07-30 on
  the next real `master` push.** Owner noticed `rust` showing `cancelled` on `master`'s HEAD and
  asked to investigate. Checked via `gh run view` before guessing: the `cargo miri test` job
  genuinely exceeded its own `timeout-minutes: 150` cap (not a concurrency-cancel - it's the
  current HEAD, nothing could have preempted it). Root-caused via history, not the diff alone: the
  last run that actually completed (commit `8e5a2a8`, 2026-07-27) already used 2h23m of the
  150-min budget (~95% utilized), and `git log 8e5a2a8..HEAD -- crates/` shows exactly one
  intervening commit touching `crates/` at all (`ebbb11b`/T-141, a pure doc-citation-path rewrite,
  no source/test change). Conclusion: organic margin erosion from everything landed since D-59's
  original 150-min budget (`crypto_secretbox`/`crypto_secretstream`/`crypto_auth`/`crypto_kdf`/
  `crypto_stream`/`crypto_pwhash`/`crypto_sign` and `uacrypt`'s own CLI suite, T-102), tipped over by
  ordinary CI runner variance - not a regression from any specific commit. `timeout-minutes` raised
  150 → 240 in `rust.yml`. **Confirmed via `gh run view` on the very next `master` push** (commit
  `812d2d8`, run `30453610223`): `cargo miri test` completed in 2h50m10s, well inside the new
  240-min cap, and every other job (including the new `kani` job from T-145, 1m31s) passed too -
  full run green.

- [x] **T-147** **Official supplementary Strumok-256/512 test vectors received from
  Держспецзв'язку - implemented and passing, see `docs/DECISIONS.md` D-104.** Owner's
  public-information request drew a response attaching two
  ДНДІ ТКЗІ-sourced test examples (Strumok-256/512), supplementary to DSTU 8845:2019's own Annex Д,
  used in real conformance expert examinations - a genuinely independent, state-sourced oracle
  distinct from UAPKI/outspace. Transcribed exactly as printed and verified in
  `crates/dstu-core/tests/strumok.rs`'s new `official_letter_vectors` module - both variants pass,
  after deriving (not assuming) two distinct byte-order transforms from the letter's own notation
  (D-104 has the full derivation and the empirical confirmation that ruled out flip-until-green).
  `docs/ORACLES.md`'s Strumok section updated: status upgraded from "UAPKI-attributed only" but
  **not** closed to "confirmed against the official text" - Annex Д itself is still unpurchased.
  **PDF storage resolved with the owner**: only the appendix (Key/IV/RandBlock, no personal data)
  is committed, as `docs/papers/Strumok_official_test_vectors_2026-07-31.pdf`; the cover letter
  itself carries the owner's own name/email and stays local, cited by number/date only. DSTU
  9041:2020 untouched - the same letter confirms no oracle exists for it either, consistent with
  the existing `docs/ORACLES.md` entry.

- [x] **T-148** **Corrected a false "font-encoding failure" claim across 5 PDFs; wrote
  `docs/pseudocode/dstu9041.md`; surfaced 3 unread cryptanalysis papers - see `docs/DECISIONS.md`
  D-105.** Owner asked why the Skorobahatko DSTU 9041 thesis PDF "doesn't get recognized" -
  re-checked directly with `pdftotext -layout` instead of trusting the standing `docs/ORACLES.md`
  note, and the note was wrong: this thesis, `Dolgov_5-22.pdf`, `Strumok_verilog.pdf`, and both
  Kalyna comparison papers all extract clean Ukrainian prose (only cosmetic defect: Cyrillic `і` as
  Latin `i`). `docs/ORACLES.md` corrected in five places. The thesis itself turned out to contain a
  complete encrypt/decrypt algorithm for DSTU 9041:2020 (two independently-phrased forms) -
  transcribed into `docs/pseudocode/dstu9041.md` with every internal inconsistency flagged inline,
  not silently resolved (single secondary source, no oracle anywhere - does **not** unblock
  `hazmat::dstu9041`, `docs/dstu-crypto-project.md`'s hard-blocked framing deliberately left
  as-is). Owner also asked whether other previously-unprocessed files (Kupyna and others) had more
  to extract - found three cryptanalysis papers (`Kalyna_attacks.pdf`,
  `Kalyna_improved_MITM_attacks.pdf`, `Kupyna_analysis.pdf`) sitting in `docs/papers/` completely
  unreferenced anywhere in this project's docs; surfaced their round-reduced attack results (best
  known: 9-11 of Kalyna's 14-18 rounds, 5-6 of Kupyna's 10-14 rounds, none reaching the full
  cipher) in a new `docs/SECURITY.md` "Known cryptanalysis" section.

- [x] **T-149** **Benchmarked Kalyna/Kupyna/Strumok against AES/Whirlpool/ChaCha20 (OpenSSL) - see
  `docs/DECISIONS.md` D-106, `docs/PERFORMANCE.md`'s new "vs. international-standard analogs"
  section.** Owner asked for a speed comparison against the same role-analogs the gh-pages landing
  page's orientation table already names, at matching key/block sizes where one exists; left the
  choice of reference binary to the assistant - OpenSSL alone (already on this machine) covers AES,
  Whirlpool (legacy provider), and ChaCha20, so libsodium wasn't needed. Measured via `openssl
  speed -elapsed -bytes N` (a different harness from this file's usual D-34 wrapper, disclosed as
  such) against `uacrypt`'s own `--iterations` numbers, same dev machine, same day. AES-NI reported
  both on and off (`OPENSSL_ia32cap` mask, confirmed to actually change the number) since
  `dstu-core` has no SIMD; Kalyna-vs-AES-software is ~1.7x, Kupyna-vs-Whirlpool (no ISA-acceleration
  confound on either side) is ~1.5-2.1x, Strumok-vs-ChaCha20 (AVX2, no clean off-toggle found) is
  ~1.6-1.7x. Variants with no size-matched counterpart (Kalyna 256-256/256-512/512-512 vs AES's
  fixed 128-bit block; Strumok-512 vs ChaCha20's fixed 256-bit key) are flagged, not forced or
  silently dropped. `docs/ORACLES.md` untouched - OpenSSL is a speed baseline here, not a
  correctness oracle for any DSTU standard.

- [x] **T-150** **Benchmarked DSTU 4145 against ECDSA (OpenSSL nistb163/nistp256) - see
  `docs/DECISIONS.md` D-106's extension note, `docs/PERFORMANCE.md`'s new "DSTU 4145 vs. ECDSA"
  subsection.** Owner asked to extend T-149's comparison to the signature primitive, the one card
  the gh-pages table left as "not yet benchmarked." `sign`/`verify` had no `--iterations` flag
  (unlike every other benchmarkable command) - added first, test-first (parse happy-path/rejection
  tests plus a round-trip behavioral test), following the existing `kupyna-digest`/`kalyna-kw`
  no-`--raw-schedule` precedent exactly. Message hashed once outside the timed loop (confirmed
  negligible: 5-byte vs 64 KiB input gave 255.98 vs 254.51 ops/s, within 0.6%). Result: `nistb163`
  (field-size-matched, `GF(2^163)`, but a different curve and no CI/CD `--iterations` numbers
  compared before) is ~21-23x faster; `nistp256` is ~136-188x faster but explicitly flagged as not
  the same security level (P-256 ~128-bit vs. this curve's ~80-bit), so that ratio is not read as a
  pure implementation-quality gap. Root-caused: `curve163.rs`'s scalar multiplication is a plain
  163-iteration constant-time double-and-add ladder with no windowing/precomputation, unlike
  OpenSSL's - an algorithmic gap, not a CPU-instruction-set one like D-106's AES-NI/AVX2 findings.
  `cargo clippy --workspace --all-features -- -D warnings` and `cargo fmt --all` clean; all 115
  `uacrypt` tests pass.

- [x] **T-151** **Done - see `docs/DECISIONS.md` D-108, `docs/PERFORMANCE.md`'s extended "DSTU 4145
  vs. ECDSA" subsection, `docs/resource-profiles.md`.** Owner asked what could be optimized in
  DSTU 4145's `verify` (following T-150's finding that it's 20-190x slower than OpenSSL) and
  whether it would be safe, then explicitly decided: keep `scalar_multiply` (used by `sign`/
  `verifying_key()` for secret-scalar multiplication) completely unchanged, add a faster
  implementation only for `verify`'s `s*G + r*Q` (public-data-only), reusing the existing
  `small-tables` Cargo feature for the split (same polarity as Kalyna/Kupyna/Strumok's own use of
  it), with an advisor-reviewed plan first. A naive "compose windowed multiply from the existing
  affine `double`/`add`" approach was spiked and rejected (measured ~20x *regression*, since each
  `double`/`add` call pays its own field inversion - measured `FieldElement::invert()` at 338.7x a
  single `multiply()`). Landed instead: López-Dahab projective coordinates (formulas cited from the
  Bernstein/Lange Explicit-Formulas Database, cross-checked via raw `curl` against the source HTML
  rather than trusted from an AI-summarized `WebFetch` read) + Shamir's trick, deferring every
  inversion in the combine step to one at the end. New differential proptest + hand-constructed
  mid-loop-infinity test in `dstu4145_curve.rs`, all existing `verify`/`sign` tests unchanged and
  still passing (transitively re-verify the new path). Full test matrix green on all three profiles
  (default / `small-tables` / `--all-features`), `clippy`/`fmt` clean. Measured (not estimated)
  result: **~1.99x** (239.31 ops/s default vs. 120.06 ops/s `small-tables`, fresh release builds,
  `uacrypt verify --iterations`) - close to the ~1.9x arithmetic estimate worked out beforehand.
  Miri: measured, not assumed, that the three `verify`-only tests still don't finish in a bounded
  run even with the faster path - their `#[cfg_attr(miri, ignore)]` stays unconditional, unchanged.
  Surfaced T-152 (below) as a side effect - filed separately, not fixed in this pass.

- [x] **T-152** **Done - see `docs/DECISIONS.md` D-110.** Found (as a side effect of T-151/D-108's
  differential tests, filed separately rather than chased then) and, this session, root-caused,
  oracle-confirmed, and fixed. Root cause: `scalar_multiply`'s final projective-to-affine recovery
  needs both `kP` and `(k+1)P` to be finite points, but never checked - `FieldElement::invert(ZERO)`
  returning `ZERO` (a deliberate convention, not a panic) silently corrupted the result instead of
  signaling infinity. Two distinct sub-bugs, confirmed algebraically and by a scratch probe (deleted
  before commit) before any fix: `z1 == ZERO` (`k == 0`/`k == ord(self)`) gave `(0, x^2)` instead of
  `Infinity`; `z2 == ZERO` (`k == ord(self) - 1`, genuinely inside the documented `k < n` contract)
  gave `q` verbatim instead of `q.negate()`. Independently confirmed against Bouncy Castle
  (`tests/oracle-harness/java/.../Dstu4145T152Oracle.java`, new one-off oracle program, same
  precedent as `Dstu4145Debug.java`) before trusting the expected values. Impact check (advisor
  flagged, then verified by reading `signature.rs`): under `small-tables`, `r`/`s` are only bounded
  to `(0, n)`, so `s = n-1` does reach this path - but only affects whether a signature whose *own*
  `s`/`r` equals `n-1` verifies (probability `~2^-163`, same as hitting the scalar at all), not
  something an attacker can use against someone else's valid signature; no forgery vector either
  (final `r' == r` check unaffected). **Net: real in-contract correctness bug at one boundary
  scalar, no realistic security consequence either direction.** Default profile was never affected
  (`ProjectivePoint::to_affine` already guards `Z == ZERO`). **Fix** (two different shapes, per
  advisor review - not the same bug): `z1 == ZERO` gets an explicit early-return branch (a
  different enum variant, `Point::Infinity` vs. `Point::Affine`, can't be branchlessly selected
  between; only fires for `k == 0`/`k >= ord(self)`, outside real callers' range) - the zero test
  itself uses the new `is_zero_mask` helper, not `==`, per a second advisor pass that caught a
  first draft comparing secret-derived `z1` via `FieldElement`'s derived (non-constant-time)
  `PartialEq`; `z2 == ZERO` gets a branchless masked select (`is_zero_mask`/`select`, new private
  helpers matching `curve163.rs`'s existing `cswap` idiom) between the formula's `y` and the correct
  `x + y`, since `z2` is secret-scalar-derived and must stay constant-time. New regression tests:
  `scalar_multiply_at_order_boundary_matches_bouncy_castle`,
  `verify_combine_matches_classic_at_order_boundary` (`dstu4145_curve.rs`, both carrying the same
  Miri exclusion as the file's existing `scalar_multiply`-based tests, T-100) - confirmed via
  `git stash` to genuinely fail pre-fix, not pass vacuously; the second test only discriminates
  under the default profile (trivially self-consistent under `small-tables`, same caveat the file's
  other tests already carry). Full workspace `cargo test` (all green), `clippy --all-features`/
  default/`small-tables` all `-D warnings` clean, `cargo fmt --all --check` clean, `no_std` build
  passes.

- [x] **T-153** **Done - see `docs/DECISIONS.md` D-109, `docs/PERFORMANCE.md`'s extended "DSTU 4145
  vs. ECDSA" subsection.** Owner felt T-151/D-108's ~1.99x `verify` gain was too small ("надто малий,
  ми відстаємо на порядок") and asked for a bigger win, floating table-based squaring/caching. An
  advisor-reviewed cost analysis found table-based squaring reintroduces exactly the secret-indexing
  question D-19/D-25 carefully scoped (a byte-keyed lookup on a *secret* field element inside
  `scalar_multiply`'s ladder, not covered by D-19's S-box/MDS-only exception) and would likely cost
  *more* than today's `multiply(self,self)`-based `square()` once masked for constant time - and
  that windowing `verify_combine` alone has a low ceiling (~1.1-1.2x, since it only cuts
  point-*additions*, not the ~163 point-*doublings* that dominate cost). The analysis surfaced a
  better, unconditional lever instead, needing no new constant-time exception at all: `square()` was
  `self.multiply(self)` (zero shortcut) and `invert()` was a direct 162-multiply exponentiation
  despite its own doc comment citing Itoh-Tsujii as the intended approach. **Landed**: (1)
  bit-interleave squaring (`spread32to64`/`square_wide` in `gf2m163.rs`) - GF(2) squaring is a pure
  bit-spread (`a(x)^2 = a(x^2)`, char-2 cross terms vanish), fixed shift/AND/OR only, no array
  indexing at all; (2) an Itoh-Tsujii-style addition-chain `invert()`, derived directly
  (`162 = 2*81 = 2*(80+1)`, chain `1->2->3->6->12->24->27->54->81->162`, `T_(i+j) = T_i^(2^j)*T_j`) -
  9 multiplies instead of 162, same ~162 total squarings either way. Both differential-tested against
  their prior forms (kept as test-only oracles, `invert_direct`) rather than derived-and-trusted;
  `square_wide` additionally checked against `poly_mul_wide(a,a)` at the pre-`reduce` wide-output
  level specifically (bit 63/64/162 boundaries), not just the final reduced result. Zero changes
  needed to any existing vector/KAT test in `dstu4145_gf2m.rs`/`dstu4145_signature.rs`/
  `dstu4145_curve.rs` - all transitively re-verify. Full three-profile test matrix
  (default/`small-tables`/`--all-features`) green, `clippy`/`fmt` clean on all four CI feature
  combinations - one pre-existing `clippy::cast_possible_truncation` finding in `curve163.rs`
  (D-108's own `shamir_double_scalar_multiply`, only visible under the default no-features profile,
  not `--all-features`) was fixed in the same pass per this project's "CI analyzer findings get
  fixed now" rule, unrelated to this task's own scope. **Measured** (fresh release builds, same
  methodology as T-150/T-151): `sign` **667.39 ops/s** (was 255.98, **~2.61x**, close to the ~2.3x
  estimate); `verify` (default/fast path) **524.01 ops/s** (was 239.31 post-D-108, **~2.19x** more on
  top of D-108 alone, **~4.37x** cumulative over the original pre-D-108 classic baseline of 120.06).
  Applied the plan's pre-committed Phase D threshold (pursue windowing only if **total default-path
  throughput vs. the 120.06 pre-D-108 baseline** lands *below* ~3.5x - not this entry's own isolated
  increment, which would misleadingly read as satisfying the gate): **4.37x already exceeds it, so
  Phase D (windowed Shamir table) is explicitly not pursued** - documented as a deliberate stop, not
  an oversight (the threshold's second AND'd condition, a batch-inversion cost spike, was never run
  either, since the first condition alone already settled it). `sign`/`verify` are now ~7.9x/~5.2x
  slower than OpenSSL's `nistb163` (down from T-150's ~20.7x/~22.6x). One Kani proof **written**,
  `square_wide_matches_poly_mul_wide_self` (constrained to the real `FieldElement` invariant rather
  than the unconstrained `[u64;3]` space) - **not compiled or run locally**: `#[cfg(kani)]` is gated
  out of every local build/test/clippy/fmt invocation, and the `kani` crate isn't a dev-dependency
  here for `--cfg kani` to even resolve outside the real tool. `cargo kani` is Linux/macOS-only
  (`xtask::kani`, D-102), so CI is this proof's first actual execution, not a second confirmation of
  a local one - its real pass/fail must be read from the CI run, not assumed from a clean local
  build. `invert()`'s own addition-chain proof was deliberately not even written (would need to
  symbolically execute the full unrolled ~162-squaring, 9-multiply chain, not a fixed bit-shuffle
  like `reduce`/`square_wide` - recorded as "not attempted, expected intractable," the same T-100
  precedent for Miri applied to Kani). Re-measuring the pre-existing T-100 Miri exclusions this
  change touched (rather than leaving their now-false "as expensive as `scalar_multiply`'s ladder"
  rationale stale) found four of them no longer apply -
  `gf2m163_field_arithmetic_matches_bouncy_castle`/`gf2m163_invert_is_involution_via_reciprocal`
  (`dstu4145_gf2m.rs`) and `gf2m163_point_double_matches_bouncy_castle`/`gf2m163_point_add_matches_
  bouncy_castle` (`dstu4145_curve.rs`) now complete in ~76-230s each and had their exclusions
  removed - real Miri coverage gained, not just preserved. `scalar_multiply`-based exclusions
  (including every `sign`/`verify`/`crypto_sign` round-trip test) are unaffected and correctly stay,
  re-confirmed by re-running `gf2m163_scalar_multiply_matches_bouncy_castle` itself, which still
  doesn't finish in 300s - that cost is `scalar_multiply`'s own 163-iteration ladder, untouched here.

- [x] **T-154** **Done - see `docs/DECISIONS.md` D-111.** Owner asked directly, after D-110: do
  Kalyna/Kupyna/Strumok need the same kind of boundary tests as the `scalar_multiply` fix? Surveyed
  by the actual bug *shape* (a formula, not a branch, whose correctness silently depends on avoiding
  a `~2^-163`-probability input set that no random sampling can hit), advisor-reviewed before
  concluding. **Result: the bug class doesn't exist outside DSTU 4145** - Kalyna/Kupyna/Strumok have
  no field inversion and no "point at infinity" concept anywhere (confirmed by grep, one false
  positive ruled out by reading it). Counter wraparound in Kalyna-GCM/CCM/CTR is a different,
  lesser category (unreachable by construction at `2^128` blocks, not unreachable by improbability).
  `curve163::ProjectivePoint`'s own infinity guards already have a deliberately hand-constructed
  test (`verify_combine_handles_mid_loop_infinity`, D-108) - cited as the precedent, not a gap.
  **One smaller, real analogue found and closed**: `signature::sign`'s three `None`-returning
  degenerate branches split three ways once actually checked (not the T-152 shape itself - these
  are explicit branches, not silent formulas, so the real question was reachability, not
  correctness). `Point::Infinity` and `fe_x == ZERO` are both provably unreachable given
  `g = generator()` (the latter via a non-obvious order-theoretic argument - the curve's one
  order-2 point can't be a multiple of a point of odd prime order `n` - confirmed computationally
  via a scratch probe, not just algebraically) - documented, not tested, per this project's own
  "foreclosed by contract" rule. `is_zero(r)`/`s.is_zero()` genuinely are reachable and, unlike the
  T-152 case, deliberately constructible by solving backward (`h = 2^162 * fe_x^{-1}`, `d = -e *
  r^{-1} mod n`) using arithmetic this crate already exposes - two new permanent tests,
  `sign_rejects_when_r_would_be_zero`/`sign_rejects_when_s_would_be_zero` (`dstu4145_signature.rs`).
  **Generalizable rule** added to `CLAUDE.md`'s agent-discipline list (cross-referencing, not
  duplicating, the existing D-64/D-65 three-test-category rule): random sampling is structurally
  blind to algebraic-precondition boundaries; they need explicit enumeration or exhaustive (Kani)
  proof, and Kani's own tractability is the actual signal for where this can hide (`reduce`/
  `square_wide` are immune, `scalar_multiply` wasn't - D-109's own "expected intractable" call).
  Full test suite (7/7 in `dstu4145_signature.rs`, full workspace), `clippy --all-features`,
  `fmt --check` all clean. Both scratch probes deleted before commit.

- [x] **T-155** **Done - see `docs/DECISIONS.md` D-112.** Found running the release checklist
  before tagging v0.2.0: `cargo kani` on `master` had actually been **red** since T-153/D-109's own
  commit, three commits in a row (T-153, T-152, T-154), never caught because the job's real
  pass/fail wasn't re-checked via `gh run view` after each push - the same lesson `CLAUDE.md`
  already states for the Miri job (T-100/D-59), missed once here. Root cause: D-109's own
  `square_wide_matches_poly_mul_wide_self` proof asked Kani to prove two different multiplier
  constructions (`poly_mul_wide(a,a)` vs. `square_wide(a)`) agree over the *same* symbolic operand -
  a well-known hard SAT class (multiplier equivalence checking), not "same shape as `reduce`'s
  proofs" as originally (wrongly) claimed. CI's job log confirmed CBMC was still working, not stuck
  or crashed, when the 20-minute timeout killed it. **Fix: a different proof, not a longer
  timeout** - raising the budget was rejected since the underlying SAT instance is the genuinely
  expensive kind, unlike T-146/D-103's Miri timeout raise (against a job already known to
  complete). Replaced with `spread32to64_is_exact_bit_doubling`, which proves the one genuinely
  novel arithmetic (bit `i` of a symbolic `u32` lands at bit `2*i`, every other bit zero) directly
  against its own spec - no multiplication of symbolic operands anywhere, same tractable shape as
  `reduce`'s two proofs. `square_wide`'s limb-placement composition is left to the existing
  differential unit tests/proptest, not re-proven exhaustively - the same Kani-for-tractable-parts/
  differential-testing-for-chained-parts split this project already applies to `invert()`'s own
  addition chain. Cannot be verified locally (Kani is Linux/macOS-only, D-102) - `cargo build`/
  `test`/`clippy` all pass (the most checkable without the real tool); the new proof's actual
  pass/fail must be confirmed on the next CI run via `gh run view`, not assumed.

- [x] **T-156** **Done - see `docs/DECISIONS.md` D-113.** Found preparing the same v0.2.0 release
  checklist as T-155, one commit later: `cargo miri test` hung twice in a row (~171min then
  ~188min of total silence, both cut short only by the job's 240min timeout, `conclusion:
  cancelled` not a real pass) instead of completing in the ~2h23m the last known-good run
  (`8e5a2a8`) took. Both hangs stopped printing test results at the exact same point in
  `dstu4145_curve.rs` - looked at first like a harness-transition deadlock, but counting the
  file's 12 declared `#[test]` fns against the 10 that actually printed a result in the log showed
  two tests silently never finishing: `verify_combine_matches_classic_for_small_scalars` (an 8x8
  loop, 128 `scalar_multiply` calls via `classic_combine`) and
  `verify_combine_matches_classic_when_r_eq_s_eq_one` (2 calls). Both were added by T-150/T-151
  (D-108) without the `#[cfg_attr(miri, ignore = "...")]` attribute every sibling
  `scalar_multiply`-calling test in the same file already carries - exactly the drift
  `.github/workflows/rust.yml`'s own comment on the `miri` job predicted ("a new EC-heavy test
  added later without the attribute silently reintroduces the timeout"). Not a deadlock, not a
  regression in `gf2m163.rs`'s D-109 arithmetic - just uncounted-for compute (each ladder call
  already costs minutes under Miri per the file's own other exclusions; 128 of them is hours).
  Fixed by adding the same attribute to both tests, citing T-100 like their neighbors. Confirmed
  locally (`cargo test -p dstu-core --test dstu4145_curve`, all 12 tests pass outside Miri where
  the attribute has no effect) - actual Miri pass/fail must be confirmed on the next CI run via
  `gh run view`, not assumed, before tagging v0.2.0. **Confirmed on CI 2026-08-02**: run
  30720207523's `cargo miri test` job completed in 2h44m18s, `conclusion: success` - the fix held.

- [x] **T-157** **Done 2026-08-02, see `docs/DECISIONS.md` D-114.** v0.2.0 released: full CI green
  (T-156's fix confirmed), tagged and pushed, `.github/workflows/release.yml` built all three
  `uacrypt` binaries plus the `dstu-core` source distribution and published the GitHub Release with
  prepared notes. Same session, added a `publish-crates` job to `release.yml` (publishes
  `dstu-core` then `uacrypt` to crates.io via the already-stored `CARGO_REGISTRY_TOKEN` secret,
  gated `needs: publish-release`, a 30s sleep between the two publishes for crates.io's index to
  pick up `dstu-core` before `uacrypt`'s packaged manifest resolves it as a registry dependency) -
  in a commit made *after* the v0.2.0 tag, so the existing tag (pointing at the pre-this-commit
  history) never picks it up; only `v*` tags from here on will. Matches the owner's explicit,
  twice-confirmed scope split: v0.2.0 stays GitHub-only, automatic crates.io publication begins
  with the next tag. T-17 itself stays open - this is the automation, not the first actual publish.

## FFI/security test-coverage roadmap (2026-08-31, from a QA/AppSec coverage audit)

Owner asked for a Staff QA/AppSec-style test-coverage audit across all four layers (Core/CLI/
C ABI/8 bindings), then to turn the findings into tracked tasks with an execution plan, saved so a
future session starts from this without re-deriving it. Full matrices (per-primitive Core table,
per-command CLI table, C ABI lifecycle table, 8-language cross-binding table) were built during the
audit as a Claude artifact (private, not committed - see RESUME HERE below); this section is the
actionable backlog, not a restatement of the matrices.

Two facts anchored the priority ordering below, per the owner's own explicit criterion ("найвищий
пріоритет - витоки пам'яті в FFI та захист ключів", i.e. memory leaks in FFI and key protection are
the top priority): 0/8 language bindings have any memory-leak test, and 0/28 `uacrypt` subcommands
verify a key never reaches stderr. Everything else is lower priority by comparison, including gaps
that look severe in isolation (double-free, GC premature collection) - none of them is untested
*and* actively suspected broken; all are untested *and* structurally mitigated already by the
language's own ownership mechanism (`SafeHandle`, `unique_ptr`, RAII, cgo pinning). The risk is a
silent regression in that mitigation, not a known-live bug.

**Strict-layering check, done during the audit, not re-litigated here**: no violation found - CLI
and all 8 bindings test round-trip/marshalling/rejection only, never DSTU math directly; the
ownership split (D-64/D-65's three test categories belong to Core; CLI/bindings own I/O, exit
codes, and memory lifecycle) stays intact and doesn't need its own task.

### Step 1 (P0) - memory leaks and key protection, do these first

- [x] **T-213** FFI memory-leak test for all 8 language bindings (Python/Node.js/Ruby/PHP/.NET/
  Java/Go/C++) - done 2026-08-31. Actual mechanism per binding differs from what was planned here,
  discovered mid-implementation, not guessed up front: Python `tracemalloc`, Node
  `process.memoryUsage().heapUsed` (+`--expose-gc`), Ruby `GC.stat[:heap_live_slots]`, and PHP all
  validated by an explicit negative-control spike (hold N handles alive, confirm the metric moves) -
  PHP's own spike caught a real instrument-blindness bug first (`memory_get_usage(true)`, the
  originally-planned mechanism, showed 0 growth for a 2000-handle deliberate leak; switched to
  `memory_get_usage(false)` before committing). Java and .NET turned out to need a different
  mechanism entirely: both wrap a native handle via the C ABI with no finalizer/Cleaner reliably
  observable from managed-heap counters - `Runtime.totalMemory()-freeMemory()` /
  `GC.GetTotalMemory` were confirmed empirically blind, and a Windows in-process
  `WorkingSet64`/RSS-sampling follow-up attempt was too noisy to trust even with warmup + N=20000
  (three-attempts rule invoked, stopped chasing a Windows-local signal). Landed on `/proc/self/status`'s
  `VmRSS`, Linux-only, skipped/no-op on Windows/macOS - same mechanism then reused for Go (cgo
  allocations invisible to `runtime.ReadMemStats`) and C++ (no GC at all, RAII already guarantees
  release for correct code; kept as a regression backstop, not a real discriminator today). No CI-only
  valgrind job was added for Go/C++ as this section originally sketched - the VmRSS mechanism covers
  the same ground as a committed, always-running test instead. 8 commits, one per binding.
- [x] **T-214** CLI: no key/secret material in stderr or a crash artifact, across all 28
  subcommands - done 2026-08-31. `crates/uacrypt/tests/smoke_no_secret_in_stderr.rs`, 13 tests
  covering every keyed command family via a forced error path (wrong key length or a tamper that
  trips authentication), checking both raw bytes (on the unconverted byte stream, not the lossy-UTF8
  `String`) and hex encoding. Sanity-checked as a real assertion (not a no-op) by temporarily
  injecting a fake leak into `CliError::WrongLength`'s `Display` impl and confirming the test caught
  it, reverted before commit.
- [x] **T-215** C ABI: zeroize-on-free test - done 2026-08-31, redesigned from this entry's original
  sketch ("read freed memory") after the pre-implementation `advisor` pass flagged that approach as
  UB that wouldn't survive Miri. Actual mechanism: `crates/dstu-core-capi/tests/zeroize_on_free.rs`
  installs a `#[global_allocator]` in that test binary only, capturing a matching pointer's bytes
  inside `dealloc()` itself (after `Drop`/zeroize has run, before the real allocator reclaims the
  page - legal, not UB), filtered by exact pointer address to avoid cross-test false positives.
  Covers the 5 uniform-shape key handles (auth/secretbox/sign/stream/secretstream); includes a
  negative control (a plain `Box` with no zeroize-on-drop) proving the harness detects non-zeroized
  memory, not just that it never fails. The originally-planned compile-time `ZeroizeOnDrop`
  trait-bound assertion doesn't apply - this crate's key types hand-roll `Drop`+`zeroize()` rather
  than implementing that trait.
- [x] **T-216** C ABI: harden the double-free contract - done 2026-08-31, both parts. (1)
  `include/dstu_core.h`'s 17 per-handle free doc comments now explicitly name double-free as UB the
  function cannot detect, not just an implicit "not already freed" precondition; header regenerated
  via `cargo xtask capi` cbindgen check. (2) `capi-double-free-asan` CI job
  (`.github/workflows/rust.yml`, Linux-only) plus `c-tests/test_capi_double_free_asan.c`, a
  standalone program (not merged into `test_capi.c`'s `CHECK`/failures-counter harness, since an
  ASan abort doesn't fit that shape) whose success condition is ASan catching the deliberate
  double-free and aborting with a nonzero exit. Not verifiable end-to-end on this project's own
  Windows dev machine (confirmed: `gcc -fsanitize=address` fails with "cannot find -lasan" for the
  installed MinGW toolchain) - YAML syntax checked via Ruby's YAML parser, CI itself is the first
  real confirmation this job catches what it's meant to.

### Step 2 (P1) - other FFI lifecycle robustness

- [x] **T-217** .NET binding: add tests for the 47 existing `ArgumentNullException.ThrowIfNull(...)`
  call sites across all 11 wrapper classes - implemented, zero test coverage today. One
  `[Theory]`-per-class covering its public entry points is enough; don't need 47 separate tests.
  Done 2026-08-31: one `NullArgumentCases` `[Theory]`/`[MemberData]` added per existing `*Tests.cs`
  file (41 rows total covering every `ThrowIfNull` site). Each lambda body is wrapped in a block
  (`() => { Expr(...); }`) rather than left as a bare expression - a bare non-void expression lambda
  assigned into an `object[]` array literal has no target-type context, so the compiler infers its
  natural type as `Func<T>` instead of `Action` and every such row throws
  `ArgumentException: Object of type 'Func\`1[...]' cannot be converted to type 'System.Action'` at
  runtime instead of running the intended check - caught by actually running the suite (41/137
  failures) before this was understood, not by inspection. `xUnit1026` (unused `description`
  parameter - it exists purely to label the Theory row in test output) suppressed via a documented
  `#pragma warning disable/restore` around the shared `NullArgumentThrows` method in each file.
  `dotnet build` 0 warnings, `dotnet test` 137/137 passed.
- [x] **T-218** GC-premature-collection stress test for .NET and Java (the two bindings whose own
  wrapper code - `SafeHandle`, native handle + `synchronized` loader - is explicitly designed
  against this failure mode but has never been stress-tested against it). Wrap an in-flight
  `crypto_secretstream` push/pull in a loop that forces `GC.Collect()` / `System.gc()` between calls
  and confirms no crash/corruption. Done 2026-08-31:
  `bindings/dotnet/DstuCore.Tests/GcStressTests.cs` (`GC.Collect(GC.MaxGeneration,
  GCCollectionMode.Forced, blocking: true)` + `GC.WaitForPendingFinalizers()` around every
  `Write`/`Read` call across 40 chunks spanning several real `SecretstreamChunkBytes` boundaries) and
  `bindings/java/src/test/java/.../GcStressTest.java` (`System.gc()` + `System.runFinalization()`
  around every `write`/`read` call, same shape, `String.repeat` avoided - `maven.compiler.release`
  is 8). Both round-trip correctly under forced collection; `dotnet test` 138/138, `mvn test` green.
  Java's own case is a documentation-by-test of T-213's finding, not a live premature-finalization
  risk: `SecretStreamPushState`/`PullState` hold their handle in a plain `long` with no finalizer/
  `Cleaner`, so native memory here is never tied to Java object GC timing at all - `close()` is the
  only release path, unlike .NET's `SafeHandle` where the marshaller's keep-alive-during-the-call
  guarantee is the actual mechanism under test.
- [ ] **T-219** Thread-safety/concurrency tests across all 8 bindings. Minimum bar: for each
  binding, either (a) a test demonstrating concurrent calls from multiple threads/tasks are safe, or
  (b) if the wrapper type isn't meant to be shared across threads, a doc comment/README line saying
  so explicitly and a test confirming the *type itself* isn't silently `Send`/`Sync`/thread-
  shareable where that would be wrong. Don't skip a language as "obviously fine" - decide per
  language, record it either way.
- [x] **T-220** C++ binding: add the missing `TestSecretstreamOversizedDeclaredChunkLength` case to
  `test_dstu.cpp`'s `TestSecretstream` - the bounds check is implemented (mirrors `uacrypt`'s own
  `CliError::SecretstreamChunkTooLarge`) but C++ is the only one of 8 bindings without a dedicated
  test for it (all 7 others have one). Done 2026-08-31: new `TestSecretstreamOversizedDeclaredChunkLength`
  function mirrors the Java binding's equivalent test (zero header + `Final` tag byte + declared
  chunk length `0xFFFFFFFF`), asserts `dstu::CryptoError`. Verified locally via PowerShell (MinGW
  `.exe` under Git Bash gives a bogus exit 127, per this file's own noted pitfall) -
  `dstu_core_cpp_tests.exe` passes clean.

### Step 3 (P2) - Core/CLI robustness beyond FFI

- [ ] **T-221** C ABI: a real panic-injection test across the `catch_unwind` boundary (`util.rs`'s
  `guard_status` family). Every exported function is wrapped, but nothing in `ffi_tests.rs`/
  `test_capi.c` actually forces a Rust panic and asserts it surfaces as a `DstuStatus` error code
  rather than unwinding into C. Needs a debug-only injection hook (e.g. a `#[cfg(test)]`-gated
  function that deliberately panics) since production inputs shouldn't be able to trigger one at
  all.
- [ ] **T-222** CLI: SIGINT / interrupted-write safety test. `uacrypt`'s streaming commands already
  use temp-file-then-rename atomicity (per `CLAUDE.md`) specifically so an interrupted write can't
  corrupt the real output file - untested. Black-box test: spawn the process, send SIGINT mid-write
  (a large enough input to guarantee the process is still writing), confirm the real output path
  either doesn't exist or is the pre-existing file untouched, and no stray temp file survives.
  Windows-vs-Unix signal-delivery differences apply here - confirm the test's mechanism works on
  this project's actual CI runners, not just locally.
- [ ] **T-223** Core: fuzz targets for the primitives that currently have none - highest value
  first: `crypto_secretbox` and `crypto_box`/`crypto_box512` (parse untrusted wire-format bytes
  directly from CLI/binding callers, unlike the hazmat-level primitives which already get fuzzed
  indirectly through their AEAD/MAC/KW callers), then `crypto_stream`/`crypto_sign`/`crypto_sign257`,
  then the `hazmat` primitives that still have none at all (`dstu4145`, `dstu9041`, `kalyna_cbc`/
  `ctr`/`ecb`/`ofb`, `kupyna_kmac`/`kupyna_kdf`). Sync all three required spots per `CLAUDE.md`'s own
  reminder: `fuzz/Cargo.toml`'s `[[bin]]`, `.github/workflows/rust.yml`'s `fuzz-smoke` matrix,
  `xtask/src/main.rs`'s `FUZZ_TARGETS` array.
- [ ] **T-224** Bindings: an oversized/near-32-bit-boundary length-prefix test per binding (not a
  literal 2GB allocation - a crafted declared-length field just past a 32-bit boundary, same shape
  as the existing "oversized declared chunk length" secretstream tests). Java int-indexed arrays and
  historically-32-bit `Buffer` lengths in Node.js are the two languages where this class of bug is
  most plausible - do those two first if sequencing this incrementally.

### RESUME HERE (state as of 2026-08-31, saved for a memory-clear/new-session handoff)

**Step 1 / P0 (T-213 through T-216) is done** - one `advisor`-reviewed plan-mode pass covered all
four, implemented and committed as a single batch (2026-08-31, ~20 commits: T-214, T-215, T-216
parts 1/2, then T-213's 8 per-binding commits plus 2 threshold-correction follow-ups for
Node.js/Ruby found while measuring). Full `cargo fmt --check` + `cargo clippy --workspace -- -D
warnings` + `cargo test --workspace` all green after the batch. See each task's own entry above for
what was actually built - several mechanisms differ from what this roadmap originally sketched,
discovered mid-implementation via empirical spikes rather than assumed:
- T-213's biggest finding: a JVM/CLR managed-heap counter (`Runtime.totalMemory()-freeMemory()`,
  `GC.GetTotalMemory`) is *structurally blind* to a native handle with no finalizer/Cleaner - true
  for Java and .NET both, confirmed empirically, not assumed from the task text's own framing. A
  Windows in-process RSS-sampling follow-up was tried for both and was too noisy to trust (three-
  attempts rule invoked) - landed on `/proc/self/status`'s `VmRSS`, Linux-only, reused for Go/C++
  too instead of the originally-sketched CI-only valgrind job.
- T-215 was redesigned before implementation (advisor caught that "read memory after free" is UB)
  to a `#[global_allocator]`-based capture instead.
- No language needed the plain "hold the wrapper alive, `tracemalloc`/`GC.stat`/etc. sees it" path
  without first spiking a negative control - do this for any future binding's own leak test rather
  than trusting a plausible-sounding managed-heap mechanism.

**Step 2 (P1, T-217..T-220) and Step 3 (P2, T-221..T-224) have not been started** - this was
consciously scoped as Batch 1 = P0 only (surfaced and approved in the pre-implementation plan), P1/P2
deferred to a later session as "Batch 2" material. Start with T-217 or T-220 (both "one test file,
one pattern," no full plan-mode+advisor gate needed) or T-218/T-219 next; T-221 and T-223 are the two
in this remaining set that likely still warrant the full structural-change gate given T-213/T-215's
own experience of the sketched mechanism not surviving first contact with implementation. Full
per-primitive/per-command/per-binding matrices this roadmap was originally derived from live in a
private Claude artifact (not committed to the repo) - if it's no longer reachable, the fastest
re-derivation path is the same two-agent survey approach (Core+CLI+capi inventory, bindings
inventory) rather than re-reading this section's summaries as ground truth.
