# AGENTS.md

This file has no content of its own — it exists only so an AI coding agent that doesn't
specifically know Claude Code's `CLAUDE.md` convention (Cursor, Copilot, another agentic CLI, a
different Claude session reading this repo cold) still finds the right entry point. Claude Code
itself auto-loads `CLAUDE.md` and does not need this file.

**Read these, in this order, before making any change:**

1. [`CLAUDE.md`](CLAUDE.md) — this project's own AI-agent operating guide: project status, hard
   constraints, and the accumulated "found the hard way" engineering discipline. Supersedes generic
   default behavior for this repo.
2. [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and hard constraints. Required reading
   before touching any cryptographic primitive or adding a dependency.
3. [`docs/DECISIONS.md`](docs/DECISIONS.md) — architectural decisions already made, with the
   rejected alternatives. Check here before proposing an API shape or algorithmic choice — it may
   already be decided (or explicitly rejected) with the reasoning recorded.
4. [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — the test/verification bar, commit style, and
   PR workflow.
5. [`docs/rust_ai_ruleset.md`](docs/rust_ai_ruleset.md) — generic Rust engineering conventions.
6. [`docs/cross-language-style-guide.md`](docs/cross-language-style-guide.md) — if the change
   touches anything outside `crates/` (a language binding under `bindings/`, an oracle harness under
   `tests/oracle-harness/`).

`CLAUDE.md`'s own "Documentation map" section is the authoritative index of every other doc in this
repo (when to read it, when to update it, what it owns) — this file is a router to *that* table, not
a duplicate of it. If this file and `CLAUDE.md` ever disagree, `CLAUDE.md` wins.
