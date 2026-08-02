# Language bindings strategy (Phase 3)

Requested 2026-08-02 by the project owner: an analysis of which languages actually benefit from a
`dstu-core` binding, what to bind and how, what engineers need to consume it, a project-structure
placement, and a phased roadmap built with `advisor()` input, executed in small committed steps.
This document is the durable record of that analysis — `docs/TASKS.md` tracks the same work at the
task-checklist level (Phase 3 section, `T-158` onward); this file is the reasoning behind it, not a
duplicate of the checklist.

`docs/dstu-crypto-project.md`'s "Second priority" section already named the five core languages
(Python, JavaScript, Java, .NET, C++) before this document existed — this is the plan for *how*,
not a re-litigation of *whether*.

## Popularity analysis — why this order, not TIOBE rank alone

TIOBE (July 2026): Python #1 (18.9%), C #2, C++ #3, Java #4, C# #5, JavaScript #6, Rust newly #10.
Raw rank is a weak signal for *this specific* library's audience, though — a DSTU crypto library's
real consumers skew toward PKI/enterprise/security tooling, not general web/app development. Two
pieces of direct evidence from this project's own oracle map (`docs/ORACLES.md`) outweigh TIOBE rank
for ordering Java/.NET: UAPKI (a real Ukrainian PKI stack, state-expertise-certified once) already
ships Java/Kotlin bindings, and Bouncy Castle .NET is already a verification oracle used in this
repo's own test harnesses. That is direct evidence of where real DSTU-consuming demand already
sits, not a rank-based guess.

Net ordering, and why each sits where it does:

1. **Python** — not chosen for TIOBE rank #1 alone, but because PyO3 + maturin is the most mature
   direct-Rust-binding toolchain that exists today, so it validates the whole pipeline (workspace
   member → build → package → local test → examples → CI) with the least incidental FFI complexity.
   Every later binding reuses this template rather than re-deriving it.
2. **A C ABI crate** — not a language binding itself, but the shared foundation C++, .NET, and
   (pending a spike, see below) Java need. This is `dstu-crypto-project.md`'s "On the horizon" C-ABI
   idea finally becoming real, but scoped strictly as "serves our own bindings" — the speculative
   "UAPKI itself could adopt this instead of its own C implementation" idea stays exactly as
   speculative and unscheduled as that section already states; this document does not schedule it.
3. **.NET** — P/Invoke over the C ABI crate. No new Rust-side glue beyond the C ABI itself.
4. **Java** — real Ukrainian-PKI demand evidence (UAPKI), but needs one implementation-choice spike
   first (below) before locking an approach.
5. **JavaScript (Node)** — napi-rs, a direct-Rust binding shaped like Python's, deliberately not
   built second despite the shape match, because Node's actual audience (web/app dev) overlaps
   least with this project's demonstrated demand (PKI/enterprise). **Scope explicitly Node-only,
   confirmed with the project owner 2026-08-02, see D-118**: a browser-usable target (Web Crypto
   API-style in-browser TLS/signing was the concrete comparison raised) needs a genuinely different
   toolchain (WASM via `wasm-bindgen`, not napi-rs — napi-rs binaries don't run in a browser at
   all) and is deliberately not scheduled now, not silently assumed either way.
6. **C++** — consumes the same C ABI crate/header directly; no separate Rust glue needed.

Two additional languages the project owner asked to include, deliberately placed after the original
five and not interleaved with them (no equivalent Ukrainian-PKI demand evidence exists for either):

7. **PHP** (Phase 8) — TIOBE ~#8, large web-backend footprint (Laravel/WordPress), essentially no
   presence in crypto/PKI tooling. Rides the already-built C ABI (`ext-php-rs` as a real extension,
   or a plainer `FFI`-extension path over the same header) rather than justifying its own Rust-side
   binding.
8. **Ruby** (Phase 9) — smaller than PHP by TIOBE rank (~#12-15), but a somewhat stronger
   security/ops-tooling footprint (Metasploit, DevSecOps scripting) than PHP has. Binds the Rust
   crate directly, like Python/Node, via `magnus`/`rb-sys` — the current standard for
   production Rust-backed gems, not through the C ABI.

### Build order revised 2026-08-02 (D-121/D-122) — the analysis above stays, the ordering it drove doesn't

The popularity analysis above is kept verbatim, not rewritten — it was correct evidence, just aimed
at the wrong question. It asked "where does real DSTU demand already exist," and answered
Java/.NET via UAPKI/Bouncy Castle. The better question for *this project's own* ordering is "where
does a gap exist that only this project's zero-config `crypto_*` surface fills" — and Bouncy
Castle/UAPKI already serving Java/.NET means this project's marginal contribution there is real but
smaller than in a language with no DSTU library at all (Node, Ruby, PHP, and now Go — none of which
have an incumbent the way Java/.NET do).

**Revised order**: T-49 (Python, done) → T-50 (Node) → T-160 (Ruby) → T-159 (PHP, committed to
`ext-php-rs` specifically so it's a direct binding like Node/Ruby, not gated on the C ABI crate
below) → T-158 (C ABI crate, built once actually needed by the group below) → T-52 (.NET) → T-51
(Java) → T-163 (Go, new - see its own section below; needs the C ABI too, since no Go binding
toolchain matches PyO3/napi-rs/magnus's maturity) → T-53 (C++, reordered again same day - D-123 -
to build after Go specifically, the owner's explicit preference) → T-162 (docs, last).

**Dart, raised in the same conversation, is explicitly deferred, not silently assumed either way**
(D-122) — same reasoning as Node's own browser/WASM scoping (D-118): Dart's primary audience
(Flutter mobile/web) overlaps least with this project's demonstrated PKI/enterprise/security-
tooling demand, so it doesn't earn a place ahead of the languages that do.

## What to bind and how — the three forks, resolved

### Fork 1 — C ABI vs. native FFI, resolved by tooling maturity, not preference

Python (PyO3) and Node (napi-rs) bind the `dstu-core` Rust crate directly — routing either through a
C ABI would double-marshal data for no benefit and lose idiomatic types (Python `bytes`, JS
`Uint8Array`) for nothing. C++ and .NET consume the C ABI crate directly instead: C++ via the
generated header + link, .NET via P/Invoke. Java gets an explicit spike step (Phase 4, step 1)
comparing the `jni` crate (write the JNI layer directly in Rust, no hand-written C shim) against
JNI-over-the-C-ABI, before committing to either — record the outcome in `docs/DECISIONS.md` when
that spike runs. Ruby follows Python/Node's direct-binding shape (`magnus`); PHP follows C++/.NET's
C-ABI-consuming shape (`ext-php-rs` or the `FFI` extension).

### Fork 2 — `crypto_sign` (DSTU 4145) exposure: uniform across every binding

`dstu-crypto-project.md`'s original "Second priority" text says: "Do not separately reimplement DSTU
4145 in the native core — for Java/.NET, integrate/wrap Bouncy Castle... for Rust, port it while
relying on Bouncy Castle as a second verification oracle." That guidance predates
`hazmat::dstu4145`/`dstu_core::crypto_sign` actually existing — they're now fully implemented and
verified in Rust (per-Annex-B.1 worked example, dual-oracle cross-checked against real Bouncy
Castle Java/.NET, `docs/DECISIONS.md` D-25/D-46). Bouncy Castle's role today is *verification oracle*
only, already used that way in `tests/oracle-harness/`. There is no remaining reason for a Java or
.NET binding to route signing through Bouncy Castle instead of this project's own audited
`crypto_sign` — a binding that silently omits `crypto_sign`, or reimplements it against a different
library per language, is strictly worse than one that calls the same Rust implementation every other
binding calls. **Resolution: every binding exposes the same `crypto_*` surface, `crypto_sign`
included, uniformly.** See `docs/DECISIONS.md` D-115 for the citation.

### Fork 3 — package naming: `uacrypt` / `dstu-core` everywhere

Confirmed with the project owner this session: match the existing CLI binary (`uacrypt`, D-36) and
crate (`dstu-core`) names on every registry, using each registry's own idiomatic spelling
(underscore vs. hyphen) rather than inventing a new brand or an artificial `dstu-ua-` prefix.
Checked exact-name availability directly against each registry's own API (not a search engine, which
under-indexes empty results) on 2026-08-02:

| Registry | Name checked | Result |
|---|---|---|
| PyPI | `uacrypt` | `404` — free |
| PyPI | `dstu-core` | `404` — free |
| PyPI | `dstu_core` | `404` — free |
| npm | `uacrypt` | `404` — free |
| npm | `dstu-core` | `404` — free |
| NuGet | `uacrypt` | `404` — free |
| NuGet | `dstu-core` | `404` — free |
| Maven Central | artifactId `uacrypt` | `numFound: 0` — free |
| Maven Central | artifactId `dstu-core` | `numFound: 0` — free |

No collision with `li0ard` (D-07, excluded as an untrusted supply-chain source): their TypeScript
packages live under the npm scope `@li0ard/kalyna`, `@li0ard/kupyna`, `@li0ard/strumok` — a
different namespace entirely from the unscoped `dstu-core`/`uacrypt` names this project would use.
A future consumer typing the unscoped name has no path to land on `@li0ard/*` by mistake.

## What engineers need — the per-binding checklist

Every binding, regardless of language, ships all of the following before it's considered done —
this is the template every phase below instantiates:

- **The same `crypto_*` API surface** (`secretbox`, `secretstream`, `auth`, `kdf`, `generichash`,
  `stream`, `sign`, `pwhash` where the feature is enabled, `randombytes`) — not a subset, per Fork 2.
- **Idiomatic to the target language**, per `docs/cross-language-style-guide.md` (casing, error
  shape, resource cleanup, doc-comment format) — that document is the style authority; this document
  doesn't re-derive its conventions.
- **"Install and forget" — zero-config API, no knobs to misconfigure.** Same libsodium-style hard-
  defaults philosophy the core already applies (`crypto_secretbox`/`crypto_secretstream`'s
  internally-generated nonce, D-47's "delete the knob"). A binding's public surface takes a key and
  a message and returns a result — no mode/nonce/IV/padding parameter for the consumer to get wrong,
  no setup step beyond `import`/`require`/`using` + one key-generation call. This is a functional
  requirement, not just documentation quality — if a binding needs a config object or an init call
  beyond constructing a key, that's a design defect to fix before the binding ships, not something
  to explain away in a README.
- **Prebuilt binaries — never "clone and build it yourself" for the binding's own consumer.** Same
  bar `uacrypt` itself already clears (T-18/T-119: GitHub Release binaries for Windows/Linux/macOS,
  "no Rust toolchain required on their side" per D-12's own scope note) — a consumer of the binding
  installs a package and never invokes `cargo build` themselves. Per language: Python — manylinux/
  macOS/Windows wheels via `maturin`; Node — prebuilt `.node` binaries per platform via napi-rs's
  cross-compile; Java — a native library bundled per OS/arch classifier (or one fat JAR); .NET — a
  package with `runtimes/{rid}/native/` per platform; C++ — prebuilt static/dynamic libs alongside
  the header, or a one-line CMake `FetchContent`; PHP/Ruby — a prebuilt extension binary where the
  ecosystem supports it, source build only as a fallback. This is about the *packaging mechanism*
  and applies to local/CI-artifact installs immediately — it is independent of, and does not wait
  on, the separate registry-publish authorization gate below.
- **`crypto_secretstream` gets an idiomatic stream/pipe wrapper per language, not a raw push/pull
  loop the consumer manages themselves.** See D-118: the same ".NET `CryptoStream`/`GZipStream`,
  Node `stream.Transform`, Python file-like object, Java `InputStream`/`OutputStream`, C++
  `istream`/`ostream`" shape every one of those ecosystems already has for exactly this kind of
  transform-a-stream operation. A consumer wires a source stream to a destination stream (or
  `File.Encrypt(inPath, outPath, key)`-style helper for the common case) and chunking, tag framing,
  and rekeying stay entirely invisible — this extends the "install and forget" requirement above to
  the *mechanics* of streaming, not just to the absence of crypto knobs. **This adds no new
  configuration surface** — D-47's "delete the knob" still holds; the "wider" instinct that
  prompted this is satisfied by which primitive to call (`secretbox` for one message,
  `secretstream` for a file/stream, `sign` for a signature — already all in scope), not by new
  tunables inside any one of them.
- **Three test categories** (already this project's standing rule, D-64/D-65): (1) correctness
  against the same vectors/oracles the Rust core already uses, (2) rejection — tampered
  ciphertext/tag/nonce, wrong key, (3) misuse — bad lengths/paths, empty input, no partial output on
  failure. "Round-trip works" alone is category 1 only, not sufficient coverage.
- **Category 1 specifically must run the actual official vectors, not just round-trip against
  itself.** Each binding's local test suite loads and runs the same
  `crates/dstu-core/tests/vectors/{kalyna,kupyna,strumok,dstu4145}/*.json` files the Rust tests
  already use, through the binding's own public API — one source of truth, no hand-copied duplicate
  vector data per language to drift out of sync (the same "test-vector fix needs a citation, not
  just matching numbers" discipline `CLAUDE.md` already applies to the Rust tests themselves).
  Where a language's ecosystem makes reading JSON test fixtures awkward, generate that language's
  fixture format from the JSON at test-build time — never hand-transcribe the numbers.
- **A runtime self-test function the binding's own consumer can call, not just a dev-time test
  suite.** See D-117: `dstu_core` gains one shared `selftest` module that re-runs the official KAT
  vectors against the live compiled code and reports pass/fail (which primitive failed, if any).
  Every binding exposes a thin, idiomatically-named wrapper around that single implementation
  (`dstu_core.selftest()` in Python, `selfTest()` in Node/Java/.NET, `dstu_selftest()` in the C ABI)
  — built once at the core, not reimplemented per language. This lets a consumer verify their exact
  installed binary is producing correct outputs on their exact platform before trusting it with real
  data, the same "don't just trust it compiled" instinct this project already applies to itself via
  dual-oracle verification.
- **A local test suite in that language's native framework** (pytest, xUnit, JUnit, `node:test`, a
  small C/C++ harness, PHPUnit, RSpec/Minitest) — runnable without any other binding installed.
- **Accessible examples for a working programmer**, not API reference restated: real recipes
  ("encrypt a file," "hash a string," "sign/verify a message"), comment-light, in an `examples/`
  directory.
- **The same provisional-status banner** the root README/crate docs already carry (T-112) — a
  binding that omits "Kalyna modes not primary-text-confirmed / Strumok vectors UAPKI-attributed"
  would be less honest than the Rust crate it wraps.
- **A `cargo xtask` subcommand**, not a one-off shell/PowerShell script (D-12 — `xtask` is the single
  cross-platform QA entry point) — wired into CI the same way every other target already is.
- **Build/test only, never publish**, until publishing that specific registry is separately,
  explicitly requested — the same gating T-17 already applies to crates.io (still not requested as
  of this document). PyPI/npm/Maven Central/NuGet/RubyGems/Packagist are five more instances of the
  same class of decision, not a bundle to authorize once.

## Project structure

New top-level `bindings/` directory, sibling to `crates/`:

```
bindings/
  python/       # PyO3 crate + maturin config, pytest suite, examples/
  capi/         # C ABI crate (cdylib+staticlib), generated header, C smoke test, examples/
  dotnet/       # P/Invoke wrapper over capi, xUnit suite, examples/
  java/         # JNI (jni crate or over capi, per Phase 4 spike), JUnit suite, examples/
  nodejs/       # napi-rs crate, node:test suite, examples/
  cpp/          # thin C++ header-only RAII wrapper over capi, a small test, examples/
  php/          # ext-php-rs extension (or FFI-extension over capi), PHPUnit suite, examples/
  ruby/         # magnus/rb-sys crate, RSpec/Minitest suite, examples/
```

Each binding directory carries its own `README.md` (provisional-status banner + quickstart), its
own test suite in the language's native layout, and its own `examples/` directory — see the
checklist above for what each of those must contain.

## Phased roadmap

Full phase-by-phase task breakdown, with commit points, lives in `docs/TASKS.md`'s "Phase 3 —
Language bindings" section (`T-158` onward) — this document states the reasoning and order; that
document tracks live status so it doesn't drift from this analysis. Summary:

| Phase | Deliverable | Depends on |
|---|---|---|
| 0 | This document + tracking + naming check (done this session) | — |
| 1 | Python binding (the template) | Phase 0 |
| 2 | C ABI crate | Phase 1's pipeline lessons |
| 3 | .NET binding | Phase 2 |
| 4 | Java binding (spike first) | Phase 2 |
| 5 | Node.js binding | Phase 1's pipeline lessons |
| 6 | C++ binding | Phase 2 |
| 7 | Publishing to each registry — owner-gated, one explicit ask per registry | Phases 1-6 |
| 8 | PHP binding | Phase 2 |
| 9 | Ruby binding | Phase 1's pipeline lessons |
| 10 | GitHub-facing docs + `gh-pages` site refresh | Phases 1-9 |
| 11 | Go binding (T-163, added 2026-08-02) | Phase 2 (C ABI - no direct-Rust-binding toolchain for Go has PyO3/napi-rs/magnus's maturity) |

**Phase numbers above are dependency labels, not the current build sequence** — D-121/D-122/D-123
reordered the actual sequence (Node/Ruby/PHP before the C ABI group; Go added, needing the C ABI,
built ahead of C++ specifically; Dart deferred). `docs/TASKS.md`'s "Build order revised 2026-08-02"
line is the current
authoritative sequence; this table stays as originally written since the *dependency* relationships
it states (what needs what) are still accurate, only the *order* changed.

## Cross-session execution plan

Requested 2026-08-02: a granular, checkable, per-task step list that survives a memory clear or a
new session — this section is the one to update as work lands, and the one to read first when
resuming. **Update the resume line below every time a step is checked off**; a stale resume line is
worse than no resume line, since it actively misdirects the next session.

**Resume point: T-161 done (2026-08-02). T-49 (Python) done in full 2026-08-02 - see D-120. Next:
T-50 (Node.js), not started.**

### The standard binding steps

Every binding task (T-49/T-50/T-51/T-52/T-53/T-158/T-159/T-160) follows this same nine-step
template unless its own entry below says otherwise — written once here rather than repeated nine
times, per this project's own "three similar lines beat a premature abstraction, but don't
duplicate a real invariant" instinct:

1. [ ] Scaffold the binding crate/project, wired into the Cargo workspace where applicable.
2. [ ] Wrap the full `crypto_*` surface, zero-config (D-116), including a `selftest()` wrapper
       around T-161.
3. [ ] Wrap `crypto_secretstream` in the language's idiomatic stream/pipe primitive (D-118).
       **Two pitfalls found by advisor review while building T-49's own wrapper — check both
       again for every later binding, not just Python (see T-49 step 3's own entry below for the
       concrete Python bugs and fixes):**
       - **The language's own "always runs, even on error" resource-cleanup hook must NOT
         finalize (emit the `Final` chunk) on the error/exception path.** Python's
         `__exit__(exc_type, ...)` was the concrete case (T-49) — it originally called `close()`
         unconditionally, so a write loop that raised partway still produced a stream with a
         `Final` chunk, and a reader saw a complete-looking file instead of failing closed
         (violates D-65's "no partial output treated as valid on failure", the same property
         `uacrypt encrypt`'s own temp-file-then-rename gets for free). Every language's equivalent
         hook has the same shape and needs the same check: C#'s `using`/`IDisposable.Dispose()`,
         Node's `stream.Transform` `_flush`/`'error'` vs. `'end'` event, Java's
         try-with-resources `close()`, C++ RAII destructors (which can't even see whether
         unwinding is due to an exception without extra machinery — decide the mechanism
         deliberately, don't assume the default is correct).
       - **The wire-format reader must validate untrusted length-prefixed fields itself, not just
         copy the encoder's happy path.** Python's decoder read the wire `chunk_len` field
         (attacker-controlled, read before any tag verification) and used it directly to size a
         read, with no upper bound — for a file this just hits EOF, but the language's own
         file-like abstraction may also have to accept a socket/pipe, where an oversized declared
         length means accumulating gigabytes before ever failing. Also missed: rejecting trailing
         bytes after the `Final` chunk (silently ignored instead of erroring). Both are checks
         `uacrypt decrypt` already has (`CliError::SecretstreamChunkTooLarge`/
         `CliError::SecretstreamTrailingData`, `crates/uacrypt/src/lib.rs`) — port them explicitly
         into every language's own reader, they don't come for free from the wire format matching.
4. [ ] Prebuilt-artifact packaging for the target platform(s) (D-116) — build/local-install only,
       no registry publish.
5. [ ] `cargo xtask` subcommand + CI wiring (D-12).
6. [ ] Local test suite: official vectors through the binding's own API (category 1), rejection
       (category 2), misuse (category 3) — D-64/D-65 plus this session's official-vectors
       requirement.
7. [ ] `examples/` + `README.md` with the provisional-status banner (T-112).
8. [ ] Doc-map sweep (`README.md`/`dstu-crypto-project.md`/`release-readiness.md`/
       `user-journey-gaps.md`/`cross-language-style-guide.md`) + mark the task done in
       `docs/TASKS.md`.
9. [ ] Commit — each numbered step above is its own commit, not one large drop.

### T-161 — `dstu_core::selftest` (first; nothing below can start without it)

No binding exists yet at this point, so the standard template above doesn't apply — this is real
Rust-core work, confirmed as a genuine gap (see `docs/TASKS.md` T-161's own note).

**Done 2026-08-02.**

1. [x] Test-first: write the test asserting `selftest::run()` reports success, before the module
       exists.
2. [x] New Cargo feature (`selftest`), off by default in the bare crate.
3. [x] Embed the official vectors (build-time include from `crates/dstu-core/tests/vectors/*.json`,
       not hand-copied).
4. [x] Implement `run()` — **scope note**: one vector per *primitive* (Kalyna, Kupyna, Strumok,
       DSTU 4145), not one per every `hazmat` mode/`crypto_*` wrapper — a fast spot check of the
       underlying algorithm each of those builds on, not a re-run of the full `tests/vectors/`
       corpus (the module's own doc comment says this explicitly, so a future reader doesn't assume
       broader coverage than exists). The report names which primitive(s) failed, if any.
5. [x] Verify: `cargo test --features selftest` (workspace-default run unaffected), `cargo clippy
       --features selftest --all-targets -- -D warnings` clean for the new files, `cargo fmt
       --check` clean, `no_std`/`no_std+alloc`/default builds all still succeed with the feature
       absent.
6. [x] Mark T-161 done in `docs/TASKS.md`, note in D-117 that it landed.
7. [x] Commit.

### T-49 — Python (the template every later task assumes)

Standard steps above, with:
- Step 1: `bindings/python/`, PyO3 + maturin. **Corrected 2026-08-02, see D-119**: its own
  `[workspace]` table, a path dependency on `dstu-core`, *not* added to the root `Cargo.toml`'s
  `members` - two existing CI jobs (`cargo +nightly miri test --workspace`, the MSRV-pinned
  `--workspace` build) would otherwise silently start covering a PyO3 `cdylib` neither job is
  equipped for. Same shape applies to T-50/T-160 (Node/Ruby, also direct Rust bindings) - T-158 (C
  ABI) is unaffected and stays a real workspace member, see D-119 for why the two cases differ.
  **Done 2026-08-02**: `dstu_core_py` crate (`cdylib`, `pyo3 = "0.26"`, `extension-module`
  feature), mixed maturin layout (`python/dstu_core/__init__.py` pure-Python package wrapping the
  compiled `_dstu_core` extension). Wraps only `selftest()` so far, as this scaffold's own pipeline
  proof - the full `crypto_*` surface is step 2, not yet done. Verified end-to-end, not just
  "compiles": `cargo build`/`clippy --all-targets -- -D warnings`/`fmt --check` all clean; `maturin
  develop` (in a `.venv`, real Python 3.12.10 resolved via `PYO3_PYTHON` - see `.claude.local.md`,
  `python`/`python3` on PATH are broken Store stubs on this machine) builds and installs the wheel;
  `python -c "import dstu_core; dstu_core.selftest()"` runs the real Rust self-check and returns
  cleanly. Confirmed the root workspace is unaffected: `cargo build --workspace` from the repo root
  still only sees `crates/dstu-core`/`crates/uacrypt` (this is the concrete case D-119 was written
  to prevent - `cargo init` inside `bindings/python` had in fact auto-added itself to the root
  `Cargo.toml`'s `members` before this was caught and reverted). Follow-up fix same day: `pyo3`
  bumped `"0.26"` → `"0.29"` (the version actually resolved, caught in self-review) plus a
  `PYO3_PYTHON` build-prerequisite note added to `bindings/python/README.md`.
- Step 2: **Done 2026-08-02.** One Rust module per `dstu_core::crypto_*` module -
  `secretbox`/`secretstream`/`auth`/`kdf`/`generichash`/`stream`/`sign`/`pwhash`/`randombytes` -
  plus `pwhash` turned on in `bindings/python/Cargo.toml` (it's `std`-gated only, no reason to
  withhold it from a binding whose whole point is a full-surface wheel). Keys/ciphertexts/tags
  cross the FFI boundary as plain Python `bytes`, not an opaque handle type - `SecretKey`'s
  `Zeroize`-on-drop guarantee can't reach a `bytes` object regardless of wrapper shape, so an
  opaque type would buy nothing here (PyNaCl's own libsodium bindings make the same call). A
  single `DstuError` exception class covers every crypto-operation failure (tag mismatch,
  truncation, CSPRNG failure); the stdlib `ValueError` covers caller-input mistakes a fixed-size
  Rust array forecloses (wrong-length key/context/etc.) - two different failure classes, not one
  exception type doing both jobs. `crypto_secretstream`'s `PushState`/`PullState` are wrapped as
  thin `#[pyclass]`es mirroring the Rust API 1:1 (tag as a plain `int`, `SECRETSTREAM_TAG_*` module
  constants) - the idiomatic file-like wrapper is deliberately step 3, not built here.
  `crypto_generichash`'s streaming `Kupyna{256,512}Hasher` are `#[pyclass]`es holding
  `Option<Hasher>`, `.take()`n on `finalize()` since the wrapped Rust `finalize(self)` consumes
  ownership - a second `finalize()` call raises `ValueError` rather than panicking. Verified
  end-to-end via `maturin develop` + a real Python smoke script exercising every wrapped function,
  including tamper rejection (`secretbox`/`auth`/`secretstream`), wrong-message/wrong-key signature
  rejection, and a wrong-length-key `ValueError` - not just "it compiles." `cargo build`/
  `clippy --all-targets -- -D warnings`/`fmt --check` all clean; root `cargo build --workspace`
  reconfirmed unaffected.
- Step 3: **Done 2026-08-02.** `SecretStreamEncryptor`/`SecretStreamDecryptor`
  (`bindings/python/python/dstu_core/secretstream.py`) - pure Python, built on step 2's
  `SecretStreamPushState`/`PullState` rather than new Rust glue (native-language idiom is exactly
  what D-118 asks for, and file I/O against arbitrary Python file-like objects is more natural to
  write directly in Python than via PyO3 callbacks). `write()`/iterate hide chunk/tag/header
  bookkeeping entirely. **Wire format matches `uacrypt encrypt`/`decrypt` exactly** (8 KiB chunks,
  `tag || len_u32_le || ciphertext || auth_tag` records after a 32-byte header) - a deliberate
  choice, not required by D-118 itself, verified with a real interop test in both directions
  against the built `uacrypt` binary (not just self-consistency): a file `SecretStreamEncryptor`
  wrote round-tripped through `uacrypt decrypt`, and a file `uacrypt encrypt` wrote round-tripped
  through `SecretStreamDecryptor`. Also verified: exact-chunk-boundary plaintext sizes (e.g.
  exactly 2×8192 bytes) produce the identical byte layout to the Rust CLI's own one-chunk-ahead
  buffering - the last full chunk is tagged `Final` directly, not followed by a spurious empty
  `Final` record (a real bug caught and fixed during this step, not assumed correct); tamper and
  truncation both raise `DstuError`. `ruff check --fix`/`ruff format --check` clean (installed into
  the `.venv` for this check - not yet wired into `xtask`/CI, that's step 5).
- Step 4: **Windows wheel done locally 2026-08-02** (this machine is Windows-only - manylinux/
  macOS builds genuinely need CI, not a local shortfall; deferred to step 5, reusing
  `.github/workflows/release.yml`'s existing `matrix.os: [ubuntu-latest, macos-latest,
  windows-latest]`/tag-trigger/artifact-upload conventions rather than inventing a parallel
  scheme). `maturin build --release --out dist` produces `dstu_core-0.1.0-cp39-abi3-win_amd64.whl`
  (one wheel for all supported CPython versions - see step 1's `abi3-py39` note); installed into a
  **fresh** venv via `pip install` (not the editable `.venv` every other check in this file used)
  and re-run against the full smoke suite (`selftest`, `secretbox`, the `secretstream` file-like
  pipeline, `sign`) - a materially different check than `maturin develop`, since it proves
  `secretstream.py` (added in step 3, after the previous packaging check) actually ships inside the
  wheel rather than only ever having been exercised through the source tree. manylinux/macOS wheels
  are folded into step 5 below, not a separate step - they need CI, not a local shortfall.
- Step 5: **Done 2026-08-02, see D-120.** Two distinct CI pieces, not one (advisor review): (1)
  `.github/workflows/bindings-python.yml`, own job (D-119) - `test` (matrix ubuntu/macos/windows:
  fmt-check ubuntu-only per the autocrlf false-positive rust.yml's own fmt job already avoids the
  same way, clippy, build `uacrypt` first from the repo root so the pytest interop test can't
  silently skip, `maturin build`+`pip install --find-links` rather than `maturin develop` since
  `develop` needs a virtualenv a bare `actions/setup-python` interpreter isn't, then pytest with an
  explicit grep-for-`SKIPPED` failure gate, then ruff), `wheel-preview` (the real
  `PyO3/maturin-action@v1`/`manylinux: auto` recipe, run on every push so a broken recipe is caught
  immediately - confirmed on real CI producing `dstu_core-0.1.0-cp39-abi3-manylinux_2_17_x86_64.
  manylinux2014_x86_64.whl`, the tag actually verified, not assumed), and `supply-chain` (`cargo
  deny check`/`cargo audit` against this workspace). (2) `release.yml`'s `build-python-wheels` job,
  same matrix/maturin-action recipe, added to `publish-release`'s `needs` (wheel-build failure
  blocks the release, a deliberate choice). `cargo xtask python` added (best-effort, D-12 posture:
  build `uacrypt`, fmt/clippy, `maturin develop`, pytest - verified locally, all 57 tests passing
  with the interop test actually running). Also closed in this pass: D-119's own recorded
  consequence that root `cargo deny`/`audit` didn't reach `bindings/python`'s dependency tree -
  turned out cargo-deny already walks up and finds the root `deny.toml` with no second file needed,
  and running it for the first time caught a real wildcard-dependency bug (missing `version =` on
  the `dstu-core` path dependency, T-75/D-11's exact failure mode), fixed in the same pass.
- Step 6: **Done 2026-08-02, out of order (before step 5, advisor review)** - a CI job wired to an
  empty test directory passes vacuously, so writing the suite first gives step 5 something real to
  fail on. 57 tests across every module, D-64/D-65's three categories - see the T-49 section above
  for the concrete shape (a real Kupyna-256 vector, live `uacrypt` CLI interop, the two rejection
  gaps an earlier advisor pass caught). `[project.optional-dependencies]` `dev` group pins
  `maturin`/`pytest`/`ruff` to the versions verified this session.
- Step 7: **Done 2026-08-02.** `examples/` (`secretbox.py`, `secretstream_file.py`, `sign.py`,
  `password_hashing.py`, `misc.py` for auth/kdf/generichash/stream/randombytes) - each run against
  the real built extension before committing, not just written from the API surface. `README.md`
  rewritten from its step-1 "scaffold only" state to document the full surface with a
  module-by-example table; provisional-status banner kept, reworded to match. Wiring ruff into a
  real gate for the first time (step 5) surfaced two real `PYI034` findings in `secretstream.py`'s
  `__enter__` methods, fixed with an inline `noqa` (this binding's `requires-python` floor is 3.9,
  `typing.Self` needs 3.11+, no `typing_extensions` dependency wanted for a pre-1.0 zero-dependency
  binding).
- Step 8: **Done 2026-08-02, this entry.** Doc-map sweep: `README.md` (root repo-tree line was
  still "planned, not yet built"), `docs/dstu-crypto-project.md`, `docs/release-readiness.md`
  updated; `docs/user-journey-gaps.md`/`docs/cross-language-style-guide.md` checked, no T-49
  references existed to update. T-49 marked done in `docs/TASKS.md`, D-120 added.
- Step 9: each step above landed as its own commit (see `git log` for the exact sequence) - no
  large single drop.

### T-158 — C ABI crate (foundation for C++/.NET, maybe Java)

Not a language binding itself — no idiomatic-language step 2/3 the way the others have; steps
1/4/5/6/7/8/9 of the standard template, renumbered for what this crate actually needs:

1. [ ] Scaffold `crates/dstu-core-capi` (cdylib+staticlib) — opaque handles, explicit error codes,
       `catch_unwind` at every boundary call, zeroize-on-free. Verify the existing 8-combination
       feature matrix still passes with this new workspace member present.
2. [ ] `cbindgen`-generated header, including a `dstu_selftest()` export (T-161).
3. [ ] `xtask`/CI wiring.
4. [ ] Prebuilt dynamic/static libs per platform (D-116).
5. [ ] A small C test harness: official vectors, rejection, misuse.
6. [ ] `examples/` (plain C) + `README.md` banner.
7. [ ] Doc-map sweep + mark T-158 done.
8. [ ] Commit per step.

### T-52 — .NET

Standard steps, consuming T-158's header via P/Invoke:
- Step 1: P/Invoke wrapper project.
- Step 3: a `Stream`/`CryptoStream`-shaped class.
- Step 4: a NuGet package with `runtimes/{rid}/native/`.
- Step 6: xUnit.

### T-51 — Java

Standard steps, plus an upfront spike before step 1 (see `docs/bindings-strategy.md` Fork 1):
- Step 0: spike the `jni` crate (Rust-side JNI) against JNI-over-T-158; record the choice in
  `docs/DECISIONS.md` before writing the real implementation.
- Step 1: per whichever approach the spike picks.
- Step 3: an `InputStream`/`OutputStream` pair.
- Step 4: a native library bundled per OS/arch classifier (or one fat JAR).
- Step 6: JUnit.

### T-50 — Node.js

Standard steps:
- Step 1: `bindings/nodejs/`, napi-rs, own `[workspace]` table per D-119 (not a root workspace
  member).
- Step 3: a `stream.Transform`.
- Step 4: prebuilt `.node` binaries per platform via napi-rs's cross-compile.
- Step 6: `node:test`.
- **Node-only** (D-118) — browser/WASM is explicitly deferred; don't reinterpret this task as
  covering it.

### T-53 — C++ (reordered 2026-08-02, D-123: now builds after T-163/Go)

Standard steps, consuming T-158's header:
- Step 1: a thin RAII header-only wrapper.
- Step 3: `istream`/`ostream`, or an iterator-of-buffers if that fits the header-only shape
  better — decide at implementation time, don't assume upfront.
- Step 4: prebuilt static/dynamic libs alongside the header, or a one-line CMake `FetchContent`.
- Step 5: at least one of MSVC/GCC/Clang, matching this project's existing toolchain posture.
- Step 6: a small C++ test.

### T-159 — PHP (reordered 2026-08-02, D-121: builds right after T-49/T-50/T-160, not deferred)

**No longer consumes T-158.** Original plan left `ext-php-rs` vs. `FFI`-over-the-C-ABI open;
D-121 commits to `ext-php-rs` specifically so this binding is a direct Rust binding like
Python/Node/Ruby and doesn't wait on the C ABI crate at all.

Standard steps:
- Step 1: `ext-php-rs` extension, own `[workspace]` table per D-119's reasoning (a direct Rust
  binding, same shape as Python/Node/Ruby).
- Step 3: PHP's own stream-wrapper/filter mechanism if one genuinely fits; otherwise a documented
  exception — research this when the task starts, don't assume the idiom exists going in.
- Step 4: a prebuilt extension binary where the ecosystem supports it, source build as fallback.
- Step 6: PHPUnit.

### T-160 — Ruby (reordered 2026-08-02, D-121: builds right after T-50, no longer last)

Standard steps:
- Step 1: `magnus`/`rb-sys`, a direct Rust binding like Python/Node's, own `[workspace]` table per
  D-119.
- Step 3: an `IO`-like or `Enumerable`/`Enumerator` wrapper — research Ruby's own idiom when the
  task starts.
- Step 4: a prebuilt extension binary where the ecosystem supports it.
- Step 6: RSpec/Minitest.

### T-163 — Go (added 2026-08-02, D-122; builds alongside T-52/T-51, needs the C ABI)

No incumbent DSTU library exists for Go, and it has a real DevSecOps/cloud-infra audience (same
class of reasoning as Ruby's own security/ops-tooling footprint) — but unlike Node/Ruby/PHP, no
Go binding toolchain matches PyO3/napi-rs/magnus's maturity, so this one goes through the C ABI
crate (`cgo` over `bindings/capi`'s `cbindgen`-generated header) same as .NET/Java/C++. Builds
after T-158 lands, alongside that group, not ahead of it. **Reordered again 2026-08-02 (D-123):
built ahead of T-53 (C++) specifically** — the owner's explicit preference, no further rationale
recorded beyond that.

Standard steps, consuming T-158's header:
- Step 1: a `cgo`-based package (`bindings/go`), wrapping the C ABI's opaque handles - decide at
  implementation time whether a hand-written `cgo` layer or a generator (e.g. `c-for-go`) fits
  better, research rather than assume.
- Step 3: Go's `io.Writer`/`io.Reader` interfaces for the `crypto_secretstream` wrapper - the
  idiomatic fit here, same reasoning as C++'s `istream`/`ostream`.
- Step 4: prebuilt static/dynamic libs alongside the generated Go package, matching T-158's own
  per-platform artifacts.
- Step 5: `go test`-driven CI, own job (not folded into the Rust matrix, same D-119 reasoning as
  every other binding).
- Step 6: Go's own `testing` package, three categories (D-64/D-65).

**Dart — raised in the same conversation, explicitly deferred (D-122), not scheduled.** Same
reasoning as Node's own browser/WASM scoping (D-118): Dart's primary audience (Flutter mobile/web)
overlaps least with this project's demonstrated PKI/enterprise/security-tooling demand. Revisit if
real demand evidence appears, same as any other out-of-scope language would need.

### Publishing (all registries) — separate, owner-gated, not scheduled

One explicit ask per registry (PyPI/npm/Maven Central/NuGet/RubyGems/Packagist), the same class of
decision T-17 already applies to crates.io. Not started, not broken into steps above — tracked only
once actually requested.

### T-162 — GitHub-facing docs + `gh-pages` site refresh (last, after every binding lands)

Requested 2026-08-02: once all bindings above exist, the project's public-facing surfaces —
`README.md`, the doc set under `docs/`, and the separate `gh-pages` branch site (the landing page
`docs/PERFORMANCE.md`/`docs/TASKS.md` already reference, e.g. its orientation table naming
AES/Whirlpool/ChaCha20 as role-analogs) — need a pass to actually mention the bindings, not just the
Rust crate/CLI. This is a documentation-only task, no primitive/binding code changes.

1. [ ] Re-read the `gh-pages` branch's current content (checkout or `git show gh-pages:<path>`) to
       see what it says today before editing — don't assume its current shape from memory.
2. [ ] Update `README.md`'s repo tree and quickstart to mention the bindings that now exist
       (`bindings/` is no longer "planned, not yet built").
3. [ ] Update `docs/dstu-crypto-project.md` ("Second priority") and `docs/release-readiness.md`
       ("Phase 3") to reflect actually-shipped bindings, not planning-stage language.
4. [ ] Update the `gh-pages` site itself **only if there's real new content it should carry** — a
       bindings section/links, install snippets per language — not a mechanical sync for its own
       sake; skip anything the site doesn't need (this step is the "запотреби"/"if needed" the owner
       asked for, not an unconditional rewrite).
5. [ ] Doc-map sweep (same file list as every other task) + mark T-162 done in `docs/TASKS.md`.
6. [ ] Commit — same one-step-per-commit discipline as every other task above.

## Doc-map sweep discipline

Landing any phase above touches more than `docs/TASKS.md` — grep that phase's task ID across
`README.md` (repo tree), `docs/dstu-crypto-project.md` ("Second priority" line),
`docs/release-readiness.md` ("Phase 3" line), `docs/user-journey-gaps.md` (new persona per binding),
and `docs/cross-language-style-guide.md`'s "applies today to" line, before calling that phase done —
`CLAUDE.md`'s own agent-discipline notes record this exact failure mode happening once already for
`crypto_secretstream` (D-68) and warn against repeating it here at five-times the scale.
