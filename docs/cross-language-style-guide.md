# Cross-language style/naming — Rust, C++, C#, Java, Python

Goal: a developer coming from any one of these languages reads the code and immediately
understands "what this is and why," without knowing the local idioms of the others. Achieved
**not** by writing the same way everywhere (impossible without violating each language's own
linter) but by the same **principles**, each expressed in the idiom native to its own language.

Applies to this project's non-Rust code — currently `tests/oracle-harness/{java,dotnet}/`, and
whichever language bindings from `TASKS.md` Phase 3 (Python, JavaScript, Java, .NET, C++) get
built first. For Rust specifically, `docs/rust_ai_ruleset.md` is the canonical, deeper ruleset —
this file generalizes the same underlying principles across languages rather than replacing it.

---

## Principles (language-independent — always apply; the form is native to each language)

1. **Casing is always native to the file's language, never imported from another.** A
   `PascalCase` method in Rust or a `snake_case` variable in C# isn't "cross-language unity" —
   it's a bug: the first gets flagged by `clippy`, the second looks broken to any .NET developer.
   Unity lives in the shape of the solution, not in the letters.
2. **A name communicates intent, not implementation.** `RetryCount` / `retry_count` /
   `retryCount` are equally clear ideas in three different spellings. `Flag2` / `tmpData` are
   unclear in any language.
3. **One main type/construct per file, filename matches it.** Java's compiler requires this
   (`public class Foo` → `Foo.java`); Rust names the module/file after what it exports; C++/C#/
   Python treat it as convention rather than compiler enforcement, but it's followed just as
   strictly.
4. **Errors are an explicit, typed result at the public API boundary, never a "raw" exception
   without context.** The mechanism differs (`Result<T, E>` in Rust, a structured error type in
   C#/Java, a custom exception class in Python); the invariant is the same: the caller sees
   *what* went wrong and *where*, without having to read the implementation's stack trace.
5. **Resources are released deterministically, never a manual "don't forget to close."** Rust:
   ownership + `Drop`. C++: RAII/smart pointers. C#: `IDisposable`/`using`. Java:
   `AutoCloseable`/try-with-resources. Python: context manager (`with`, `__exit__`). Five
   different syntaxes, one invariant.
6. **Public API is documented in the language's native doc format**, not an arbitrary comment:
   Rust `///`/`//!` (+ `cargo doc`), C# XML doc comments, Java Javadoc, Python docstrings. The
   format is always whichever one that language's own tooling actually parses.
7. **Unsafe/low-level code is isolated in small, separately-reviewed modules, with an explicit
   comment on why it's safe here.** Rust: minimal `unsafe` block with a `// SAFETY:` comment
   immediately before it, per `SECURITY.md`'s hard constraint. C++: raw pointers/manual memory
   only inside a RAII wrapper. C#/Java: `unsafe`/JNI/native calls as a separate, clearly marked
   layer. Python: C extensions/`ctypes` as a separate module, not smeared through the codebase.
   Matters concretely here once FFI-boundary bindings (Phase 3) get built.
8. **A comment explains WHY, not WHAT.** The one rule that needs no translation and stays
   identical for every language — same as this project's own global response-style rule.
9. **Formatting is done by the language's own tool, not by hand.** `cargo fmt` + `clippy -D
   warnings`, `.editorconfig` + Roslyn analyzers, `black`/`ruff`, `checkstyle`/`spotbugs` — style
   is measured by that language's linter; a manual code-review comment about whitespace is a
   signal the linter isn't configured, not that the developer "wrote it wrong."
10. **KISS everywhere except the one case of the reference crypto implementation itself**
    (extended carve-out below). For every other kind of code in this project — API wrappers,
    CLI, error handling, configuration, infrastructure like the oracle harnesses:
    - A design pattern (Strategy/Factory/Builder/DI container, etc.) is used only when there's a
      direct, current need — never "pattern for the pattern's sake" or "because the textbook
      says so."
    - Code structure complexity matches the complexity of the problem it solves — no more.
      Don't reach for generalization/abstraction without an explicit current need; "might need
      it later" is not an explicit need.
    - Three similar lines of code beat a premature abstraction — the same principle already
      stated for this project's general codebase conventions.
11. **Minimizing third-party dependencies is a supply-chain defense vector.** For Rust: prefer
    `std`/`core`/the official Rust toolchain stack over a third-party crate doing the same thing,
    wherever the task is solvable without meaningful loss of functionality. Every added
    dependency is new attack surface (compromised crate, typosquatting, maintainer-account
    takeover — real precedents on crates.io just as on npm/PyPI). Same idea in other languages:
    C++ — standard library over a third-party one; C# — the BCL over a NuGet package; Java — the
    JDK over a Maven dependency; Python — stdlib over a PyPI package.
    - **Important clarification specific to crypto primitives — don't confuse this with "write
      your own crypto from scratch for zero-dependencies' sake."** This principle is about
      *helper* code (serialization, CLI parsing, logging, configuration) — there, `std` genuinely
      is almost always enough. For the crypto primitives themselves, the priority is the
      opposite, and is already stated separately: `docs/rust-crypto-claude-advice.md` — its
      crypto-specific content is distributed into `SECURITY.md`/`DECISIONS.md`/`CLAUDE.md`, see
      that file's own status banner — a trusted, audited implementation is always safer than an
      unaudited one you wrote yourself. "Minimum dependencies" is never a reason to implement
      AES/SHA/ECC yourself outside the actual "this is the reference implementation we're
      writing" task. Any crypto dependency that *is* added still goes through the same
      supply-chain vetting `SECURITY.md` already requires (maintainer, reproducible builds,
      independent audit, CVE history) — *before* adding it, not after.

---

## For reference implementations of crypto algorithms — refinement to principle 10

When code implements the algorithm itself (a cipher, hash, mode of operation) as a reference
implementation against a specification — not a wrapper/API around it — principle 10 (KISS,
patterns only when needed) still applies, with two refinements specific to this case:

- **Code structure mirrors the structure of the specification, not "clean architecture."** A
  reference implementation exists to be easily checked against its source document, line by line.
  A complex algorithm (e.g. elliptic-curve pairing) can be split into functions along the spec's
  own logical steps — but without "just in case" abstractions the spec doesn't call for, since
  those are exactly what makes checking the code against its source harder. This is why
  `dstu_core::hazmat::kupyna` mirrors `oracles/kupyna-reference/kupyna.c`'s byte-matrix layout
  directly rather than an optimized, word-packed representation (see `DECISIONS.md` D-10) —
  transcription-safety over elegance, precisely per this principle.
- **The one exception that always outweighs KISS:** explicit security requirements — constant-time
  execution, side-channel resistance, zeroizing secrets. These aren't stylistic preferences; they
  *are* an "explicit need" in principle 10's own terms, so they're never sacrificed for simplicity
  or readability. KISS operates *inside* the space of solutions that already satisfy the
  crypto-specific hard constraints (`SECURITY.md`) — not instead of them.

---

## Reference table by language

| What | Rust | C++ | C# | Java | Python |
|---|---|---|---|---|---|
| Type/class | `UpperCamelCase` | `PascalCase` | `PascalCase` | `PascalCase` | `PascalCase` |
| Trait/Interface | `UpperCamelCase` (no `I` prefix) | no direct equivalent (abstract class/concept) | `IPascalCase` | `PascalCase` (often `-able` suffix) | `PascalCase` (protocol/ABC) |
| Function/method | `snake_case` | `PascalCase` (project convention) or `camelCase` (STL-style) | `PascalCase` | `camelCase` | `snake_case` |
| Variable/parameter | `snake_case` | `camelCase` | `camelCase` | `camelCase` | `snake_case` |
| Constant | `SCREAMING_SNAKE_CASE` (`const`/`static`) | `SCREAMING_SNAKE_CASE` or `kPascalCase` | `PascalCase` | `SCREAMING_SNAKE_CASE` (`static final`) | `SCREAMING_SNAKE_CASE` |
| Private field | plain `snake_case` via `self.`, no prefix | `m_camelCase` | `_camelCase` | `camelCase` | `_snake_case` (convention, not enforced) |
| Module/file | `snake_case.rs`, module name = file name | filename = main class name | filename = type name | filename = `public` class name (enforced) | `snake_case.py` |
| Errors | `Result<T, E>`, `E: std::error::Error` (often `thiserror`) | exception or return code at module boundary | structured error type / exception | checked/unchecked exception | custom `Exception` subclass |
| Async marker | self-marking (`async fn`), no suffix | no single idiom (C++20 coroutines or callback) | `Async` suffix (historical .NET convention) | usually no suffix (`CompletableFuture`-typed signature) | self-marking (`async def`) |
| Resource/cleanup | ownership + `Drop` | RAII / smart pointers | `IDisposable` + `using` | `AutoCloseable` + try-with-resources | `with` + `__exit__` |
| Doc comment | `///` / `//!` | `///` (Doxygen) | `/// <summary>` (XML) | `/** ... */` (Javadoc) | `"""docstring"""` |
| Null/absence of value | `Option<T>` (no null) | `nullptr`/`std::optional<T>` | `T?` (nullable) | `null` / `Optional<T>` | `None` |
| Unsafe code | `unsafe { }` + `// SAFETY:` comment | raw pointers isolated in a RAII wrapper | `unsafe`/P-Invoke, separate layer | JNI/`sun.misc.Unsafe`, separate module | C extensions/`ctypes`, separate module |
| Linter/formatter | `rustfmt` + `clippy` | `.clang-format` + `clang-tidy` | `.editorconfig` + Roslyn analyzers | `checkstyle`/`spotbugs` | `black`/`ruff` |

---

## How this fits with this project's other docs

- `docs/rust_ai_ruleset.md` stays the canonical, deeper ruleset for Rust specifically (per
  `CLAUDE.md`'s doc map, treated as canonical as-is) — this file doesn't replace or restate it,
  it generalizes the same underlying principles to the other languages this project touches.
- `SECURITY.md` and `DECISIONS.md` remain canonical for crypto-specific hard constraints
  (constant-time, `Zeroize`, dual-oracle verification, supply-chain vetting) — principle 11's
  crypto carve-out and the reference-implementation section above point there rather than
  restating it.
- Applies today to `tests/oracle-harness/{java,dotnet}/` (already follows this — `OracleHarness`
  in PascalCase with `camelCase` methods, `Program.cs`'s local functions in `PascalCase`,
  matching the table above) and will apply to `TASKS.md` Phase 3 language bindings when built.
