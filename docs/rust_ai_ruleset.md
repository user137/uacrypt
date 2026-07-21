# Rust Best Practices & Architecture Ruleset
Comprehensive System Prompt / Ruleset for AI Assistants (Claude Code, Cursor)

## 1. Fundamental Memory & Ownership Patterns
* **RAII (Resource Acquisition Is Initialization)**:
  * Encapsulate resources (files, sockets, locks) in structs. Always rely on the automatic `Drop` call instead of manual closing/freeing.
* **Borrow Checker-Friendly Design**:
  * Follow the **Single Ownership** principle. Avoid cyclic references.
  * If a break in ownership is possible, prefer **Arena Allocation** (e.g. via the `typed-arena` crate or index-based arrays) over a cascade of `Arc<Mutex<T>>`.
* **Zero-Cost Abstractions & Zero-Copy**:
  * Use **`Cow<'a, T>`** (Clone-On-Write) for cases where data is read more often than it's modified.
  * Accept borrowed types by their **Deref Target** in functions (`&str` instead of `&String`, `&[T]` instead of `&Vec<T>`).

## 2. Type System & Compile-Time Guarantees
* **Type-State Pattern (Compile-Time State Machine)**:
  * Encode system state via Generics and Zero-Sized Types (`PhantomData<T>`). Transitions between states must consume the object via `self` (move semantics).
* **Newtype Pattern**:
  * Wrap primitive types in tuple structs (`struct UserId(u64);`) to rule out the classic `Primitive Obsession` mistake and mixed-up arguments.
* **Exhaustive Pattern Matching & Algebraic Data Types (ADT)**:
  * Model mutually exclusive data via `enum`.
  * Don't use a wildcard `_` in `match` without critical need, so that extending the `enum` automatically triggers compile errors at every handling site.
* **Make Illegal States Unrepresentable**:
  * Design structs so that an invalid state of the object is impossible at the type level (no `is_valid`, `is_connected` "flags" inside structs).

## 3. API Conventions & Standard Traits
* **C-CONVENTION (Rust API Guidelines)**:
  * `to_` — an expensive conversion (`to_string()`).
  * `as_` — a free borrow (`as_bytes()`).
  * `into_` — a conversion that consumes ownership (`into_vec()`).
* **Canonical Trait Implementations**:
  * For all public types, it's mandatory to implement or derive: `Debug`, `Send`, `Sync` (if safe), `Default`.
  * Instead of `parse()` or `from_...()` methods, implement the canonical traits `From<T>`, `TryFrom<T>`, `FromStr`.

## 4. Error Handling Architecture
* **Panic-Free Production Code**:
  * Full ban on `.unwrap()`, `.expect()`, `panic!()`, and `unreachable!()` in production code.
* **Error Separation (Libraries vs Applications)**:
  * **Library Errors (Domain Errors)**: Use `thiserror` to create strictly typed `enum Error` types.
  * **Application Errors (Contextual Errors)**: Use `anyhow::Result` or `eyre::Result` with added context via `.context("...")`.

## 5. Idiomatic Performance & Functional Pipeline
* **Internal Iteration & Bound-Check Elimination**:
  * Prefer iterator chains (`map`, `filter`, `fold`, `collect`) over explicit `for i in 0..len` loops — this lets the compiler eliminate bounds checks.
* **Small-Buffer Optimization (SBO)**:
  * Use `SmallVec` or `ArrayVec` for collections where the average element count is small and known at compile time.

## 6. Safety & Unsafe Code Boundaries
* **Encapsulated Unsafe & Soundness**:
  * All `unsafe` code must be isolated in the smallest possible module with a safe wrapper.
* **Safety Invariant Documentation**:
  * Every `unsafe fn` or `unsafe` block must carry a comment in the format:
    `// SAFETY: <justification for why memory invariants are upheld>`.

## 7. Concurrency & Async
* **Send & Sync Boundaries**:
  * Check thread safety at the type level: `Send` (transfer between threads), `Sync` (access from multiple threads via a reference).
* **Non-Blocking Async Execution**:
  * Avoid any synchronous/blocking I/O or long-running CPU-bound computation inside async tasks. Use `tokio::task::spawn_blocking` for computation.

## 8. Visibility & Modularity (Encapsulation)
* **Principle of Least Privilege**:
  * `pub` by default is forbidden. All internal structs and functions must be `pub(crate)`, `pub(super)`, or private.
  * Export outward (via `pub`) only the crate's final public API.
* **Workspace Pattern**:
  * For medium and large projects, split the monolith into independent crates via `[workspace]`. Each crate should own one domain.

## 9. Lints & Static Analysis (Quality Control)
* **Clippy as a Compiler**:
  * The AI must generate code that passes review with pedantic lints enabled.
  * The following directives are required at the `lib.rs` / `main.rs` level:
    ```rust
    #![warn(clippy::pedantic)]
    #![deny(clippy::unwrap_used, clippy::expect_used)]
    ```

## 10. Documentation & Doc-tests
* **Executable Documentation**:
  * All public structs, traits, and functions (marked `pub`) must have a `///` Rustdoc comment.
  * Documentation for key functions **must include code examples** in ` ```rust ` blocks, which automatically become integration tests (doc-tests).
* **Enforce Documentation**:
  * For library crates, use the `#![warn(missing_docs)]` directive.

## 11. Testing Conventions
* **Inline Unit Tests**:
  * Unit tests for verifying private logic should live in the same file as the code under test, in a `#[cfg(test)] mod tests { ... }` module.
* **Black-Box Integration Tests**:
  * Testing of the public API should be moved to a separate `tests/` directory at the project root.
* **Trait-based Dependency Injection**:
  * To make dependencies mockable in tests (e.g. DB or network access), abstract them behind traits, accepting them as `&dyn Trait` or `impl Trait`.

## 12. Macros Boundaries
* **Compile-Time Awareness**:
  * Creating new custom **procedural macros** is forbidden without a critical need for it, since they dramatically increase compile time.
  * For code generation or avoiding duplication (boilerplate), prefer declarative macros (`macro_rules!`) or the Generics/Traits system.
