# Advice for CLAUDE.md — Rust cryptographic library

> **Status: distributed.** The crypto-specific content from Part 1 has been moved into
> `SECURITY.md` (hard constraints, threat model, supply-chain) and `DECISIONS.md` (D-01…D-06).
> Agent discipline (three-attempts rule, research before implementation, distrust of "green"
> tests) is in `CLAUDE.md` ("Agent discipline"). Part 2 (context economy) is already covered by
> harness practices from `~/.claude/CLAUDE.md` and the global instructions — not duplicated here
> separately. This file remains as the original source/rationale, not as the canonical document to
> read up front.

Extracted from experience on the Pakko project (a Windows archiver, C#/C++). Part 1 — engineering
conventions worth carrying over/adapting. Part 2 — how Claude Code should read files and make
changes to save context/tokens.

---

## Part 1 — Documentation structure and engineering discipline

### Documentation

- **A single index file (`CLAUDE.md`)** that lists every other `.md` file with "Read when /
  Update when" columns and a **canonical owner** for each topic. If a topic is already described
  in one file, other files only link to it, never duplicate the table.
- **`DECISIONS.md`** — architectural decisions *together with the rejected alternatives and the
  reason for rejection*. For a crypto library: why a specific set of primitives/curves was chosen,
  why legacy mode isn't supported, why a dependency was accepted or rejected. Write it at the
  moment of the decision, not after the fact.
- **`SECURITY.md`** — threat model, explicit out-of-scope, a supply-chain dependency-assessment
  table (developer, reproducible builds, independent audit, CVE history) — apply it to every
  crypto crate before adding it. A "Reporting Vulnerabilities" section — private disclosure
  (GitHub Security Advisories), never a public issue.
- **`TASKS.md` / `TASKS_DONE.md`** — end-to-end task numbering (`T-xx`), acceptance criteria for
  each. A task moves to "done" NOT because `cargo test` is green — separate verification is
  needed (for crypto: cross-verification against test vectors + an independent implementation).
- **`CHANGELOG.md`** — one section per release, written at release time with the list of tasks
  since the previous tag.
- **A "Known test gaps" section** — document flaky tests and the rule "one isolated rerun before
  treating it as a regression", instead of silently ignoring it or endlessly rerunning without
  investigation.

### Agent discipline

- **Three-attempts rule**: if the same problem isn't solved after 3 different approaches — stop,
  report what was tried and what's unknown, and wait for direction. Don't try a 4th approach on
  your own initiative. Especially for toolchain/build/CI problems.
- **Research before implementation**: no primitive is written "from memory" — check against the
  primary source (a specific section of an RFC/NIST document, real reference-implementation code),
  not a paraphrase. Record the citation in `DECISIONS.md`.
- **Don't trust "green tests" for security-critical code.** Your own implementation must be
  cross-checked against test vectors (NIST CAVP/RFC) **and** an independent crate (`ring`,
  RustCrypto) — not just self-consistency. A bug can slip past your own tests but fail against an
  independent reader/implementation.
- **Grep the whole repository, not just the plan**, before changing a public API — the plan may
  have been written before a new consumer of that API appeared.
- Minimal diffs, no speculative abstractions. Comments only for WHY, when non-obvious (a
  workaround, a side-channel reason, an invariant), never WHAT.

### Specific to a crypto library

- An explicit hard-constraints list: "no primitive is written without citing a specific section
  of the specification", "no secret-dependent branch/array indexing", "all comparisons of secrets
  via `subtle::ConstantTimeEq`, never `==`", "all key-material types are
  `Zeroize`/`ZeroizeOnDrop`", "no logging of secret material", "no homegrown crypto primitives
  invented from scratch".
- **`unsafe` policy**: `unsafe` only in isolated, separately reviewed modules, with a comment
  stating exactly which invariant guarantees safety. `cargo miri test` is a required layer for UB
  detection (the analogue of the independent WACK check in Pakko: the tool catches what ordinary
  tests miss).
- **Benchmark methodology**: ratio-based comparison on the same machine, in the same run, against
  a reference implementation (`criterion` + comparison with `ring`/OpenSSL in the same benchmark),
  with a tolerance (e.g. 3x) — NOT an absolute time threshold. This is the only approach that
  generalizes to an arbitrary machine (confirmed by BenchmarkDotNet/criterion.rs/benchstat
  research).
- **Fuzzing is a required layer**, not optional: `cargo fuzz` for every parser of untrusted input
  bytes (DER/ASN.1, message formats).
- **Supply-chain check** of every crypto crate before adding it as a dependency — the same table
  as in `SECURITY.md` (developer, reproducible builds, audit, CVE history).

---

## Part 2 — How to read files and make changes to save context

These practices directly reduce the number of tokens/tool calls per session — critical for long
sessions and for cost (API/keys).

- **Search instead of full reads.** For finding a symbol/pattern — `Grep`/`rg`, not reading whole
  files "by eye". For finding files by name/pattern — `Glob`, not a recursive directory listing.
- **Read a file in full only when needed.** If you know which part of the file is needed (e.g.
  after `Grep` gave a line number) — read with `offset`/`limit`, not the whole file, especially
  for large logs/generated code.
- **Don't re-read a file right after Edit/Write "to check".** The Edit tool itself throws an error
  if the replacement didn't happen (`old_string` not found) — a successful call is already proof
  the change applied. Re-reading is a wasted call.
  Exception: when you need to verify the *result of running* code (a test, a build), not the mere
  fact the file was written — then trust the command's exit code/output, not your own "eyeball"
  read. The compiler/test exit status is the authoritative source of truth about correctness, not
  a human (or agent) re-reading the source file.
  ```
  In short: Edit --> (success) --> do NOT re-read the file --> continue.
  Edit --> error --> read the current content --> understand why it didn't match --> retry Edit.
  ```
- **`Edit`, not `Write`, for existing files.** `Edit` sends only the diff (old_string/new_string);
  `Write` requires the file's entire content in the request — on a large file this is orders of
  magnitude more expensive in tokens. `Write` is only for new files or a genuine full rewrite
  "from scratch" on an explicit request.
- **Batch independent tool calls into one turn.** Several `Read`/`Grep` calls with no dependency
  on each other — run them in parallel in one message, not one after another sequentially — this
  saves not tokens directly but round-trips/latency, and also reduces the number of intermediate
  system messages that accumulate in context.
  Sequential — only when the result of one call is needed as input for the next.
  Rule: independent → parallel; dependent → sequential, never the other way around.
- **Fork/delegate "research" work whose raw output won't be needed later.** If the task is to read
  a bunch of files and return a conclusion (not the files themselves), it's better to run a
  fork/subagent that returns a condensed summary than to drag the entire raw output (hundreds of
  lines of logs, diffs, directory trees) into the main context.
- **Don't dump entire large logs/build output.** Filter for relevant lines (`Grep` by an error
  keyword) instead of printing all of `cargo build`/`cargo test` stdout, when the file is large
  and the nature of the error is already known.
- **Don't keep documents in context that are already stale/not needed for the current step.** For
  a very large decisions file (`DECISIONS.md`, which keeps growing) — grep for the heading of the
  specific section instead of re-reading the whole file every time.
- **Load tools for the task, not all at once**, when tools are available via deferred loading
  (search-by-name) — request the whole needed set in one call up front, rather than one at a time
  with each new subtask.
