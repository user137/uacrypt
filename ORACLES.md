# ORACLES.md

Which sources this project trusts for verifying correctness, how much, and why — and where
test vectors will come from once primitives exist. Canonical owner of the oracle trust matrix
and test-vector convention (`oracles/README.md` links here instead of duplicating this content).

## Two axes that don't line up

Every oracle sits on two independent scales, and for this project they're inverted rather than
correlated — that inversion is the main thing this document has to make explicit.

**Verification authority** (how much do we trust its numbers are algorithmically correct):
1. The standard's own author's reference implementation (Roman Oliynykov for Kalyna/Kupyna).
2. The official standard text / designers' published paper itself.
3. A mature, independently audited library (Bouncy Castle).
4. A production library whose audit has lapsed (cryptonite — certified 2016–2021, nothing since).
5. An unofficial, single-maintainer, unaudited implementation (outspace/dstu8845).
6. Excluded — untrusted provenance (`li0ard`, see D-07 in `DECISIONS.md`).

**Legal portability** (can code be copied/ported, or only used to check numbers):
- MIT / BSD-2-Clause (Bouncy Castle, cryptonite) — portable with attribution.
- No LICENSE file (Roman Oliynykov's repos, outspace/dstu8845) — full copyright, no permission
  granted, verification-only, copying is not legally available regardless of code quality.

**The inversion:** the highest-verification-authority sources — the standard authors' own code —
are exactly the ones with zero legal portability. The one source that's both audited and
portable, Bouncy Castle, is Java/C#, so using it means re-deriving the algorithm's logic in Rust,
not a mechanical port, and it only covers DSTU 4145 (plus Kalyna/Kupyna, which turned out to also
be implemented there).

## Committed development model

This project's own `SECURITY.md` and `DECISIONS.md` (D-06) already settled how oracles get used:
**implement each primitive from the official DSTU spec text, citing the clause, then verify
against oracles.** Never port or copy oracle source into `crates/`, regardless of the oracle's
license. Everything below assumes that model — oracles here answer "who do we check our numbers
against," not "what do we translate into Rust."

## Per-algorithm oracle map

### Kalyna (DSTU 7624)
- **Primary:** `oracles/kalyna-reference/` (Roman Oliynykov, the standard's author) — verify-only,
  no license.
- **Secondary:** `oracles/cryptonite/` (BSD-2-Clause). Also the source of the still-open D-05
  question (its native CCM/GCM `encrypt_mac` API on Kalyna alone).
- **Tertiary:** `oracles/bouncycastle-{java,dotnet}/` (MIT, actively maintained, audited) — good
  cross-check on modes and wrap behavior.
- **Test vectors:** `oracles/kalyna-reference/main.c` has vectors published by the author —
  highest-trust source available for this algorithm.

### Kupyna (DSTU 7564)
- **Primary:** `oracles/kupyna-reference/` (Roman Oliynykov, author) — verify-only, no license.
- **Secondary:** `oracles/cryptonite/`, `oracles/bouncycastle-{java,dotnet}/`.
- **Test vectors:** `oracles/kupyna-reference/main.c`.

### Strumok (DSTU 8845)
- **No trustworthy code oracle exists.** `oracles/strumok-dstu8845/` (outspace) is unofficial —
  not written by the standard's designers, no independent audit, no license. `li0ard/strumok` is
  excluded outright (D-07).
- Test vectors must be sourced from `docs/papers/Strumok.pdf` (the designers' own paper),
  wherever it publishes them — not from outspace's code, whose numbers are only as trustworthy as
  outspace itself.
- **Gap, stated plainly:** of the three MVP algorithms, Strumok has the weakest verification
  story. Confirming vectors against the paper is a prerequisite before implementation, not an
  afterthought.

### DSTU 4145 (signature)
- **Primary:** `oracles/bouncycastle-{java,dotnet}/` (MIT, audited, decades in production) — the
  best-supported algorithm in this project by oracle quality.
- **Secondary:** `oracles/cryptonite/dstu4145*` (BSD-2-Clause, stale since 2016).
- Per D-02, Bouncy Castle is also the actual dependency wrapped for the Java/.NET bindings there
  — not just an oracle in that context.

### DSTU 9041 (asymmetric encryption, twisted Edwards curves)
- **No oracle exists anywhere.** The standard is from 2020, newer than every reference
  implementation surveyed (Kalyna/Kupyna-reference predate it, cryptonite is 2016, Bouncy Castle
  doesn't implement it). When this algorithm is reached, it starts from spec text alone with no
  cross-check available, unless one is found or built first.

## Test-vector convention

Not built yet — no primitive exists to test against. Decided now so the first primitive follows
it from day one, per the test-first rule in `CLAUDE.md`:

- Vectors live at `crates/dstu-core/tests/vectors/<algorithm>/<case>.json` — one file per case,
  plain hex fields, human-diffable, not a binary blob.
- Every vector file records its **source** (which oracle, or which spec section) — an
  unattributed vector is not admissible, by the same logic as `SECURITY.md`'s "no primitive
  without a cited spec section."
- Integration tests in `crates/dstu-core/tests/<algorithm>.rs` load these files and assert against
  the implementation — black-box, per `docs/rust_ai_ruleset.md` §11.
- Illustrative shape only (not a real vector):
  ```json
  {
    "source": "oracles/kalyna-reference/main.c, author test case 1",
    "key_hex": "...",
    "plaintext_hex": "...",
    "ciphertext_hex": "..."
  }
  ```

Building the actual `tests/vectors/` tree and loader waits for the first primitive — an empty
scaffold or a `todo!()` harness would be speculative ahead of any code to test.
