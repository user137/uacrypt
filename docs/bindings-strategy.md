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

## Doc-map sweep discipline

Landing any phase above touches more than `docs/TASKS.md` — grep that phase's task ID across
`README.md` (repo tree), `docs/dstu-crypto-project.md` ("Second priority" line),
`docs/release-readiness.md` ("Phase 3" line), `docs/user-journey-gaps.md` (new persona per binding),
and `docs/cross-language-style-guide.md`'s "applies today to" line, before calling that phase done —
`CLAUDE.md`'s own agent-discipline notes record this exact failure mode happening once already for
`crypto_secretstream` (D-68) and warn against repeating it here at five-times the scale.
