---
name: Bug report
about: Something in dstu-core / uacrypt doesn't work as expected
title: ""
labels: bug
assignees: ""
---

**Do not use this template for a security vulnerability** — see
[`docs/SECURITY.md`](../../docs/SECURITY.md) "Reporting vulnerabilities" (private disclosure via
GitHub Security Advisories, never a public issue).

## Describe the bug

A clear, concise description of what's wrong.

## To reproduce

Steps to reproduce, ideally a minimal code snippet or exact `uacrypt` command + flags. If it
involves a specific input (key/nonce/message), include it if it isn't secret, or a synthetic
equivalent that still triggers the issue.

## Expected behavior

What you expected to happen instead.

## Environment

- `uacrypt`/`dstu-core` version (or commit hash if built from source):
- OS/architecture (e.g. Windows x86-64, Linux aarch64):
- Cargo features enabled, if non-default (e.g. `small-tables`, `pwhash`, `getrandom`):
- Rust toolchain version (`rustc --version`), if relevant:

## Additional context

Anything else — stack trace, `RUST_BACKTRACE=1` output, whether it reproduces under
`cargo test`/`cargo miri test`, etc.
