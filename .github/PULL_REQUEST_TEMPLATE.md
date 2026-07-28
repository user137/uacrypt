## What this changes and why

<!-- One or two sentences. Link the docs/TASKS.md item (T-NN) if there is one. -->

## Checklist

- [ ] `cargo xtask fmt` / `cargo xtask clippy` / `cargo xtask test` all pass locally
      (`cargo xtask ci` if you have the optional tools installed)
- [ ] If this adds/changes a cryptographic primitive, mode, or wrapper: **three test categories**
      are covered — correctness (vector/oracle), rejection (tamper), misuse (invalid input) — see
      `docs/CONTRIBUTING.md`. If a category is foreclosed by the type signature, note that instead
      of a test that only proves the compiler works.
- [ ] Dual-oracle verification (official vector *and* an independent reference implementation) for
      any new/changed primitive — or explicitly noted as provisional with why, per
      `docs/ORACLES.md`.
- [ ] No secret-dependent branching introduced; secret comparisons use `subtle::ConstantTimeEq`,
      not `==`; new key material is `Zeroize`/`ZeroizeOnDrop`.
- [ ] `docs/DECISIONS.md` updated if this makes (or resolves) an architectural choice, with a
      citation (DSTU clause or reference-implementation source).
- [ ] `docs/TASKS.md` updated (task started/finished/newly discovered) if applicable.
- [ ] Feature matrix checked beyond `--all-features` if this touches anything feature-gated
      (e.g. `--no-default-features --features dstu-core/small-tables`).
- [ ] No unrelated formatting/refactoring bundled in — keep the diff focused on the stated change.

## Anything reviewers should pay special attention to

<!-- e.g. "this changes wire format", "this is the first user of feature X", a known limitation -->
