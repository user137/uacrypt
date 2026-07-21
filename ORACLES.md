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
- **Highest-trust source: `docs/papers/Kalyna.pdf`**, Appendix B — "A New Encryption Standard of
  Ukraine: The Kalyna Block Cipher" (Oliynykov et al.), the designers' own published paper.
  Ranks above the reference-implementation oracles below: it's the formal specification itself,
  not a third-party implementation of it. **Test vectors extracted and verified** (full round
  traces cross-checked for hex validity and expected byte length) into
  `crates/dstu-core/tests/vectors/kalyna/{128-128,128-256,256-256,256-512,512-512}.json` —
  encryption and decryption KEY/PLAINTEXT/CIPHERTEXT triples for all five variants.
- **Secondary code oracle:** `oracles/kalyna-reference/` (Roman Oliynykov, same author) — same
  vectors re-derivable from `main.c`, verify-only, no license.
- **Tertiary:** `oracles/cryptonite/` (BSD-2-Clause). Also the source of the still-open D-05
  question (its native CCM/GCM `encrypt_mac` API on Kalyna alone).
- **Quaternary:** `oracles/bouncycastle-{java,dotnet}/` (MIT, actively maintained, audited) — good
  cross-check on modes and wrap behavior.
- Supplementary, not authoritative: `docs/papers/Dolgov_5-22.pdf` contains a C-like pseudocode
  description of Kalyna (`Kalyna_Cipher`, `Kalyna_InvCipher`, `Kalyna_S_boxes`,
  `Kalyna_KeyExpansion_Ksigma`), but its surrounding Ukrainian prose doesn't extract cleanly via
  `pdftotext` (font-encoding issue with no ToUnicode CMap) and it carries no test vectors of its
  own — `Kalyna.pdf` remains the reference; this one is a secondary read if the pseudocode angle
  is ever needed, not transcribed here to avoid injecting OCR/extraction errors into a crypto spec.

### Kupyna (DSTU 7564)
- **Highest-trust source: `docs/papers/Kupyna.pdf`**, Appendix B — "A New Standard of Ukraine:
  The Kupyna Hash Function" (Oliynykov et al.), same standing as the Kalyna paper above.
  **Test vectors extracted and verified** into
  `crates/dstu-core/tests/vectors/kupyna/{kupyna-256,kupyna-512}.json` — six byte-aligned
  message-length cases each (0, 8, 512, 760/1536, 1024, 2048 bits). The paper also publishes
  bit-level (non-byte-aligned) cases at N=510/655 (both variants) and N=33/1 (Kupyna-512 only);
  deliberately not transcribed — see the `note` field in those JSON files for why.
- **Secondary code oracle:** `oracles/kupyna-reference/` (Roman Oliynykov, author) — verify-only,
  no license.
- **Tertiary:** `oracles/cryptonite/`, `oracles/bouncycastle-{java,dotnet}/`.

### Strumok (DSTU 8845)
- **No trustworthy code oracle exists, and no test vectors have been found anywhere in this
  project's holdings.** Checked directly (not assumed): `docs/papers/Strumok.pdf` (the designers'
  paper, Gorbenko/Kuznetsov et al.) gives the full algorithmic description — Init/Next/Strm/FSM/T
  functions, GF(2^64) arithmetic — but contains zero test vectors (confirmed by scanning for
  hex runs of 16+ characters; the only hex-like hit is a bitmask constant, not a vector).
  `docs/papers/Strumok_verilog.pdf` (Ukrainian, Verilog HDL implementation writeup) and
  `docs/papers/Speed_of_modern_stream_ciphers.pdf` (benchmarking paper, same author group) were
  also scanned the same way — no hex runs in either.
- `oracles/strumok-dstu8845/` (outspace) is unofficial — not written by the standard's designers,
  no independent audit, no license. `li0ard/strumok` is excluded outright (D-07).
- **Gap, stated plainly and now confirmed by direct search, not assumption:** of the three MVP
  algorithms, Strumok has the weakest verification story, with no official test vectors located
  in any source surveyed so far. Locating or generating trustworthy Strumok vectors (the official
  DSTU 8845 text itself, an NDA'd/paywalled version of the standard, or a state-certified
  implementation) is a prerequisite before implementation, not an afterthought.

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

Populated for Kalyna and Kupyna; the loader still waits for the first primitive (a `tests/*.rs`
harness calling `dstu_core` functions that don't exist yet would break the buildable skeleton —
that part is genuinely premature, the data is not).

- Vectors live at `crates/dstu-core/tests/vectors/<algorithm>/<case>.json` — one file per
  block/key-size or hash-size variant, plain hex fields, human-diffable, not a binary blob.
- Every vector file records its **source** (which paper/oracle, down to the appendix section) —
  an unattributed vector is not admissible, by the same logic as `SECURITY.md`'s "no primitive
  without a cited spec section." Every hex field has been length/validity-checked programmatically
  against its declared bit size before being committed here — see the PDF extraction notes below.
- Integration tests in `crates/dstu-core/tests/<algorithm>.rs` will load these files and assert
  against the implementation — black-box, per `docs/rust_ai_ruleset.md` §11 — once a primitive
  exists to test.
- Real shape, from `crates/dstu-core/tests/vectors/kalyna/128-128.json`:
  ```json
  {
    "algorithm": "Kalyna-128/128",
    "block_bits": 128,
    "key_bits": 128,
    "source": "docs/papers/Kalyna.pdf, Appendix B.2.6 (...)",
    "cases": [
      { "name": "encryption", "key_hex": "...", "plaintext_hex": "...", "ciphertext_hex": "..." }
    ]
  }
  ```

**PDF extraction notes (for re-deriving or extending these):** `docs/papers/*.pdf` were converted
with `pdftotext -layout` (Cyrillic-only PDFs like `Dolgov_5-22.pdf` and `Strumok_verilog.pdf` lose
their prose to a font-encoding issue — no ToUnicode CMap — but English papers and embedded hex
survive intact). Page-footer numbers routinely get injected mid-hex-block by `pdftotext`
(observed and corrected during extraction: stray `"64"`, `"96"`, `"36"`, `"18"`, `"34"` splitting
what should have been one contiguous hex run) — always re-verify against a wide context window
around each value, and length-check every field against its declared bit size before trusting it;
a plausible-looking but truncated or corrupted vector is worse than no vector, since it fails a
correct implementation silently.
