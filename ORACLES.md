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
4. A production library whose audit has lapsed (cryptonite — certified 2016–2021, nothing since) —
   **UAPKI (added 2026-07-22) is a fork of this same lineage**, with an additional cited Ukrainian
   state crypto-expertise conclusion for the UAPKI project specifically (2021; see `DECISIONS.md`
   D-16 for exactly what that does and doesn't certify — the conclusion predates and doesn't cover
   this project's pinned commit). Treat it as sitting at this tier for Kalyna/Kupyna/DSTU 4145
   (same underlying lineage as cryptonite), except for **Strumok, where it's the only source found
   at all** — no cryptonite equivalent exists to compare it against, so its self-declared
   `// ДСТУ 8845:2019` attribution is taken on the library's word, not cross-tiered against
   anything above it.
5. An unofficial, single-maintainer, unaudited implementation (outspace/dstu8845).
6. Excluded — untrusted provenance (`li0ard`, see D-07 in `DECISIONS.md`).

**Legal portability** (can code be copied/ported, or only used to check numbers):
- MIT / BSD-2-Clause (Bouncy Castle, cryptonite, UAPKI) — portable with attribution.
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

## Official DSTU text — purchase cost (checked 2026-07-21)

Official texts are sold per-page via `fnd-store.uas.gov.ua` (see also the free catalog at
`uas.gov.ua/natsionalnyi-fond-nd/kataloh-natsionalnykh-standartiv-ta-k` to confirm validity before
paying). Checked listings for the three standards this project would most benefit from:

| Standard | Pages | Price (UAH) | Listing |
|---|---|---|---|
| ДСТУ 9041:2020 | 40 | 5,304.00 | `fnd-store.uas.gov.ua/documents/42241` |
| ДСТУ 8845:2019 (Strumok) | 53 | 7,027.80 | `fnd-store.uas.gov.ua/documents/39053` |
| ДСТУ 7624:2014 (Kalyna, incl. Amendment No. 1:2016) | 227 | 29,967.60 | `fnd-store.uas.gov.ua/documents/4228` |

All three land at roughly the same ≈132.6 UAH/page rate (the state-set per-page tariff for
official reproduction) — Kalyna's total is simply large because the document is large (227
pages, folding in its 2016 amendment), not a different rate. **Verdict: cost-prohibitive for this
project at this time** — combined total is ~42,300 UAH (~$1,000 USD) for all three, against a
volunteer open-source project's budget. Not pursued for now; each per-algorithm section below
notes what specifically the official text would have resolved, so this can be revisited if
project funding changes rather than re-researched from scratch.

## Per-algorithm oracle map

### Kalyna (DSTU 7624)
- **Pseudocode:** `docs/pseudocode/kalyna.md` — transcribed from the paper below, cross-checked
  against the reference C oracle. Its k=2l key-schedule branch (originally ambiguous from the
  paper's own notation) is read as a word-rotation rather than arithmetic addition, corroborated
  by `bouncycastle-java`'s `DSTU7624Engine.java` — **note this is not a second independent
  reading**: that file's own header credits Oliynykov's C code as its source, so it's a faithful
  port, not an independent implementation (same is true of `DSTU7564Digest.java` for Kupyna
  below). See the "Correction on provenance" note in `docs/pseudocode/kalyna.md` for why this
  still has some value (rules out a C-specific transcription slip) without being the strong
  cross-check it was first described as.
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
- **Added 2026-07-22: `oracles/uapki/`** (fork of Cryptonite, state-expertise pedigree — see
  `oracles/README.md` for the exact caveat on what that does and doesn't certify). Its
  `dstu7624_self_test` covers ECB/CBC/OFB/CFB/CTR/CMAC/XTS/KW/CCM/GMAC/GCM — directly relevant to
  the still-open D-05 question — but **not yet cross-checked** against this project's own vectors
  or Rust output; treat as an available-but-unverified data point until that happens.
- Supplementary, not authoritative: `docs/papers/Dolgov_5-22.pdf` contains a C-like pseudocode
  description of Kalyna (`Kalyna_Cipher`, `Kalyna_InvCipher`, `Kalyna_S_boxes`,
  `Kalyna_KeyExpansion_Ksigma`), but its surrounding Ukrainian prose doesn't extract cleanly via
  `pdftotext` (font-encoding issue with no ToUnicode CMap) and it carries no test vectors of its
  own — `Kalyna.pdf` remains the reference; this one is a secondary read if the pseudocode angle
  is ever needed, not transcribed here to avoid injecting OCR/extraction errors into a crypto spec.

### Kupyna (DSTU 7564)
- **Pseudocode:** `docs/pseudocode/kupyna.md` — transcribed from the paper below, cross-checked
  against the reference C oracle; one extraction gap (the IV formula) resolved from the oracle
  and flagged as such. Additionally checked (2026-07-21) against
  `bouncycastle-java/.../DSTU7564Digest.java` — same structure confirmed (`state[0] = blockSize`
  for the IV; `P`/`Q` constant-addition and the fused S-box/shift/mix T-tables match), but this is
  the same "not independent" caveat as Kalyna: that file's header also credits Oliynykov's
  `Kupyna-reference` C code as its source. Treat as corroboration of a faithful port, not a second
  independent reading.
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
- **Added 2026-07-22:** `oracles/uapki/`'s `dstu7564_self_test` — same official vector set as
  `Kupyna.pdf` by the look of it (identical message patterns: `0xFF`, sequential `0x00..0xFF`,
  same bit-length cases), not yet diffed byte-for-byte against our JSON vectors. See
  `oracles/README.md` for the state-expertise pedigree caveat.

### Strumok (DSTU 8845)
- **Pseudocode:** `docs/pseudocode/strumok.md` — transcribed from `Strumok.pdf`, cross-checked
  structurally against the outspace oracle; one FSM-update ambiguity in the paper's extraction
  resolved from the oracle and flagged as such.
- **No test vectors in `docs/papers/`.** Checked directly (not assumed): `docs/papers/Strumok.pdf`
  (the designers' paper, Gorbenko/Kuznetsov et al.) gives the full algorithmic description but
  contains zero test vectors (confirmed by scanning for hex runs of 16+ characters — the only hit
  is a bitmask constant, not a vector). `docs/papers/Strumok_verilog.pdf` (Verilog HDL writeup,
  re-checked 2026-07-22 specifically for a hardware testbench KAT — has a real text layer,
  searched for test-vector/testbench/keystream sections, nothing beyond module signal
  declarations) and `docs/papers/Speed_of_modern_stream_ciphers.pdf` were also scanned — no hex
  runs in either. The official standard text itself was priced (2026-07-21) at 7,027.80 UAH for
  53 pages — see "Official DSTU text — purchase cost" above; not purchased.
- **Test vectors found 2026-07-22 in `oracles/uapki/`** (D-15):
  `crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json`, transcribed from
  `library/uapkic/src/dstu8845.c`'s `dstu8845_self_test()`, whose source comments the block
  `// ДСТУ 8845:2019` — i.e. attributed by UAPKI's own authors to the standard, not invented by
  this project. **Not the same as having the official text**: this project has not independently
  confirmed these values against the paid DSTU 8845:2019 document itself, only against UAPKI's
  claim about them. Every vector file's `"status"` field says so plainly. See `oracles/README.md`
  for UAPKI's pedigree (state-expertise conclusion, fork of Cryptonite) and its exact limits (tied
  to a specific certified build, not this cloned commit).
- **Cross-check, not independent confirmation:** the UAPKI values were reproduced byte-for-byte by
  running `oracles/strumok-dstu8845/` (outspace, unofficial, no license) on the same inputs
  (`tests/oracle-harness/strumok-cross-check/cross_check_against_uapki.c`). This is *not* treated
  as two independent implementations agreeing — outspace's `strumok.c` and UAPKI's `dstu8845.c`
  share identical internal function/table names (`dstu8845_init`, `dstu8845_crypt`, `T0..T7`),
  which reads as shared lineage rather than independent authorship from the spec (the same trap
  D-07/the Kalyna provenance correction caught elsewhere in this file). Treat it as a consistency
  bonus on top of the UAPKI attribution, not a second oracle. `li0ard/strumok` remains excluded
  outright (D-07).
- **Status, stated plainly:** better than "no vectors, self-invented gray inputs" (this project's
  own 2026-07-22 earlier attempt, since superseded), still short of "official." Locating the
  standard text itself, or a source that independently transcribes its own annexed vectors the
  way `DSTU_4145-2002.pdf` Annex Б does, remains open — see `TASKS.md`.

### DSTU 4145 (signature)
- **Official text now in hand** (`docs/papers/DSTU_4145-2002.pdf`, added 2026-07-22) — corrects the
  earlier "no spec paper exists" claim below and in `docs/pseudocode/dstu4145.md`'s header; this
  algorithm is no longer the BC-only exception to the "cited spec section" hard constraint. Sections
  1-13 are the algorithm text (data representation, computational algorithms, parameter/key
  generation and verification, pre-signature/signature computation and verification); Annex B
  (Додаток Б, pages 18-21) is a full worked example with real numbers in both polynomial basis
  (GF(2^163)) and optimal normal basis (GF(2^173)); Annex D (Додаток Г) lists recommended curves.
  The PDF is a scan with no text layer (`pdftotext` yields nothing) — rendered to PNG via
  `pdftoppm` (poppler, installed 2026-07-22, see `.claude.local.md`) and read visually page by page.
- **Test vector:** `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json` — the Annex B.1
  (GF(2^163), polynomial basis) worked example, transcribed from the scan and **independently
  cross-checked byte-for-byte against `oracles/bouncycastle-java/.../DSTU4145Test.java`'s
  `test163()`** (a hardcoded KAT that does not derive from this PDF) — every field matches exactly,
  which is what makes this a genuinely dual-sourced vector rather than a single by-eye
  transcription off a 150 DPI scan. This also upgrades Bouncy Castle's own standing for this one
  algorithm: `test163()` passing is now confirmed DSTU-conformant against the standard's own
  example, not just an internally-consistent BC fixture. **Triple-checked 2026-07-22:**
  `oracles/uapki/library/uapkic/src/dstu4145.c`'s `dstu4145_self_test()` (explicitly commented
  `// ДСТУ 4145-2002. Додаток Б` in its own source) carries the same `d`/`Q`/`r`/`s` values —
  byte-identical once UAPKI's little-endian storage is reversed. Three sources (the standard
  text itself, Bouncy Castle, and a state-expertise-pedigreed library) now agree on this one
  example — about as solid as a single test vector gets without running the paid official text
  through this project's own eyes. The Annex B.2 (optimal normal basis, GF(2^173)) example was
  **not** cross-checked this way — BC's `test173()` uses different curve parameters (a separate,
  unrelated KAT), so that example currently rests on the scan transcription alone; treat it as
  unverified-transcription if it's ever extracted.
- **Pseudocode:** `docs/pseudocode/dstu4145.md` — still transcribed from the Bouncy Castle Java
  signer as of this writing; re-deriving it against the official spec sections above (now that they
  exist) is a follow-up, not yet done — see `TASKS.md`.
- **Primary:** `oracles/bouncycastle-{java,dotnet}/` (MIT, audited, decades in production) — the
  best-supported algorithm in this project by oracle quality, and per the vector cross-check above,
  the one primitive here with genuine double confirmation (official worked example + independent
  hardcoded KAT) rather than a single source.
- **Secondary:** `oracles/cryptonite/dstu4145*` (BSD-2-Clause, stale since 2016).
- Per D-02, Bouncy Castle is also the actual dependency wrapped for the Java/.NET bindings there
  — not just an oracle in that context.

### DSTU 9041 (asymmetric encryption, twisted Edwards curves)
- **No oracle exists anywhere.** The standard is from 2020, newer than every reference
  implementation surveyed (Kalyna/Kupyna-reference predate it, cryptonite is 2016, Bouncy Castle
  doesn't implement it). When this algorithm is reached, it starts from spec text alone with no
  cross-check available, unless one is found or built first.
- **Web search performed (2026-07-21), no GitHub implementation found** for DSTU 9041:2020 in any
  language — confirms the above is not just an unsearched gap.
- **Two candidate papers checked for pseudocode, both dead ends:**
  - Skorobahatko, bachelor's thesis, KPI, 2023 ("Аналіз стійкості алгоритму гібридного шифрування
    за ДСТУ 9041:2020 та його модифікацій до розрізнювальних атак") — the one paper found that
    actually analyzes *this* algorithm's steps (its abstract explicitly frames it as chosen-
    plaintext/chosen-ciphertext resistance analysis of the DSTU 9041:2020 hybrid encryption
    scheme, referencing DSTU 7624:2014 too). Downloaded from
    `https://ela.kpi.ua/server/api/core/bitstreams/12932ea1-d36a-468a-b4a0-504309a90fbd/content`
    and run through `pdftotext -layout` — same font-encoding failure as `Dolgov_5-22.pdf` and
    `Strumok_verilog.pdf` (no ToUnicode CMap): every word of Ukrainian prose extracts as blank
    space, only section numbers and the odd English loanword survive. Unusable for transcription
    as-is; would need a different extraction path (OCR on rendered pages, or a
    manually-copy-pasted version) before it could feed a pseudocode doc.
  - Ivanov/Kuznetsov et al., ITCE 2020 №1 (`itce.vntu.edu.ua`, downloaded and extracted cleanly —
    English abstract intact) — topically adjacent but not this algorithm: it's about base-point
    selection algorithms for Edwards curves in the context of the **DSTU 4145-2002 signature**
    standard, not the DSTU 9041:2020 hybrid short-message-encryption algorithm. Useful background
    on Edwards-curve arithmetic in the Ukrainian standards ecosystem, not a source to transcribe
    pseudocode from for this algorithm.
- No `docs/pseudocode/dstu9041.md` exists as a result — there is currently nothing credibly
  sourceable to write one from. Revisit if the actual DSTU 9041:2020 standard text is ever
  obtained, or if a legibly-OCR'd copy of the Skorobahatko thesis surfaces.
- **The official text was priced (2026-07-21): 5,304.00 UAH for 40 pages** — see "Official DSTU
  text — purchase cost" above. This is the only algorithm in this project with zero sources of
  any kind, so it's the strongest case for revisiting the purchase if budget ever allows — but
  deemed cost-prohibitive for now, same as the other two.

## Test-vector convention

Populated for Kalyna and Kupyna. The Rust loader exists now (`crates/dstu-core/tests/kupyna.rs`,
per D-10) — the earlier "waits for the first primitive" caveat no longer applies to Kupyna.

- Vectors live at `crates/dstu-core/tests/vectors/<algorithm>/<case>.json` — one file per
  block/key-size or hash-size variant, plain hex fields, human-diffable, not a binary blob.
- Every vector file records its **source** (which paper/oracle, down to the appendix section) —
  an unattributed vector is not admissible, by the same logic as `SECURITY.md`'s "no primitive
  without a cited spec section." Every hex field has been length/validity-checked programmatically
  against its declared bit size before being committed here — see the PDF extraction notes below.
- Integration tests in `crates/dstu-core/tests/<algorithm>.rs` load these files and assert against
  the Rust implementation — black-box, per `docs/rust_ai_ruleset.md` §11.
- **Same files, consumed cross-language too:** `tests/oracle-harness/{java,dotnet}/` run these
  vectors against real Bouncy Castle directly (not the Rust port), via the published Maven/NuGet
  packages — one vector format, multiple independent consumers. Both actually run and pass (all
  10 Kalyna + all 12 Kupyna cases). No cryptonite/C harness — tried on 2026-07-22 with a real
  local GCC and dropped: cryptonite's own source doesn't compile clean on a modern compiler
  (unrelated to Kalyna/Kupyna — an error in `dstu4145_prng_internal.c`), and the added value was
  already modest given the two harnesses above already independently confirm these vectors. See
  `TASKS.md` "Infrastructure" for the full note; `cryptonite` is still used as a read-only
  reference (e.g. the D-05 CCM/GCM finding below), just not a runnable harness.
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
