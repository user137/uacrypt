# Strumok (DSTU 8845:2019) — pseudocode

Transcribed from `docs/papers/Strumok.pdf` (Gorbenko, Kuznetsov, et al., "'Strumok' Stream
Cipher"), Sections 2–9 — the designers' own paper, not the DSTU standard text itself (no copy of
that has been located; see `ORACLES.md`). Cross-checked structurally against
`oracles/strumok-dstu8845/strumok.c` (outspace, unofficial, unaudited, no license — the weakest
oracle in this project per `ORACLES.md`). From-spec restatement for implementation planning, not a
source to copy from (`DECISIONS.md` D-06).

**Update, 2026-07-22:** at the time the paragraph above was written, no test vectors existed
anywhere in this project's holdings, so the oracle cross-check confirmed structure only, never
numeric correctness. That gap is closed — see "Test vectors" below and `DECISIONS.md` D-15/D-18 —
and `dstu_core::hazmat::strumok` now passes all of them. The provenance ceiling is unchanged
though: those vectors are UAPKI-attributed, not the official DSTU 8845:2019 text itself.

## Parameters (Section 2)

- Word size: 64 bits (unlike SNOW 2.0's 32-bit words).
- State `S_i = (s^(i), r^(i))`: 16 LFSR words `s^(i) = (s0, ..., s15)` + 2 FSM words
  `r^(i) = (r1, r2)` — 18 words total.
- Key `K`: 256 or 512 bits (Strumok-256 / Strumok-512). IV: 256 bits, always.
- LFSR feedback polynomial over GF(2⁶⁴): `f(x) = x¹⁶ + α¹¹·x¹³ + α⁻¹`, giving the field tower
  GF(2) ⊂ GF(2⁸) ⊂ GF(2⁶⁴) ⊂ GF(2¹⁰²⁴), base field polynomial
  `p(y) = y⁸ + y⁴ + y³ + y² + 1` (same reduction polynomial as Kalyna/Kupyna, `0x11D`).

Three functions make up the cipher: `Init(K, IV) → S0`, `Next(S_i, mode) → S_{i+1}`,
`Strm(S_i) → Z_i` (64-bit keystream word).

## `FSM(x, y, z)` (Section 6)

```
FSM(x, y, z) = (x +64 y) ⊕ z          // +64 = addition modulo 2^64
```

## `T` — nonlinear substitution on a 64-bit word (Section 7)

Byte-slice the word into `w7..w0`, substitute each byte through one of four DSTU-7624-style
S-boxes (`S_(j mod 4)`, same Appendix-A S-boxes as Kalyna/Kupyna), then apply the Kalyna/Kupyna
MDS linear layer (`μ = (01,01,05,01,08,06,07,04)` over GF(2⁸), modulus `0x11D`) to the substituted
byte vector — i.e. `T` is exactly one Kalyna/Kupyna round's η∘τ (no π, since it operates on a
single word, not a row-structured state), precomputed as eight lookup tables `T0..T7` so that
`T(w) = T0[w0] ⊕ T1[w1] ⊕ ... ⊕ T7[w7]` (matches oracle macro
`T(w) = T0[byte(0,w)]^T1[byte(1,w)]^...^T7[byte(7,w)]`).

## `α` / `α⁻¹` multiplication in GF(2⁶⁴) (Sections 8–9)

Table-driven, same shift-and-lookup shape as Kalyna's byte-level GF(2⁸) multiply but lifted to
64-bit words via the LFSR's feedback polynomial:

```
mul_alpha(w)     = (w << 8) ⊕ Mul_alpha[w >> 56]         // 256-entry, 64-bit-value table
mul_alpha_inv(w) = (w >> 8) ⊕ Mul_alpha_inv[w & 0xFF]    // 256-entry, 64-bit-value table
```

matches oracle macros `a_mul` / `ainv_mul` against `strumok_alpha_mul` / `strumok_alphainv_mul`.

## `Next(S_i, mode)` (Section 4)

```
r2_new ← T(r1)                          // step 1: nonlinear FSM update, uses OLD r1
r1_new ← r2_old + s13                   // step 2: see "ambiguity" note below — uses OLD r2
for j in 0..14:
    s_new[j] ← s[j+1]                   // LFSR shift
if mode == NORMAL:
    s_new[15] ← mul_alpha(s0) ⊕ mul_alpha_inv(s11) ⊕ s13
else  // mode == INIT
    s_new[15] ← FSM(s15, r1, r2) ⊕ mul_alpha(s0) ⊕ mul_alpha_inv(s11) ⊕ s13
S_{i+1} ← (s_new, (r1_new, r2_new))
```

**Ambiguity flagged, not silently resolved:** the paper's step-2 formula for `r1_new` is one of
the lines lost to `pdftotext`'s columnar-extraction damage on multi-line subscript/superscript
math (see `ORACLES.md`'s extraction-notes convention) — it renders as
`r₂^(i+1) = r?^(i+1) +64 s13^(i)`, ambiguous on whether the first term on the RHS is `r2`'s *old*
or *newly-computed* value. The oracle (`oracles/strumok-dstu8845/strumok.c`, function
`next_stream`, lines ~719–721) resolves this unambiguously in code: `fsmtmp` (the new `r1`) is
computed from the **pre-update** `r[1]` (old `r2`), before `r[1]` is overwritten with `T(r[0])`.
Used here as the authoritative structural source for this one step, per the same convention
applied to Kupyna's IV. **This is a structural reading only** — with zero test vectors available
for Strumok anywhere, there is no numeric cross-check to confirm this interpretation once
implemented; re-verify against the actual DSTU 8845:2019 text if it is ever located.

The ring-buffer indexing in the oracle (16-way unrolled, reusing `S[j]` in place rather than
shifting all 16 words each step) is an implementation optimization equivalent to the shift shown
above — confirmed by checking that `S[j]_new = mul_alpha(S[j]) ⊕ S[j+13 mod 16] ⊕
mul_alpha_inv(S[j+11 mod 16])`, i.e. the same feedback formula applied at a rotating origin.

## `Strm(S_i)` (Section 5)

```
Z_i ← FSM(s15, r1, r2) ⊕ s0
```

## `Init(K, IV)` (Section 3)

```
1. Load K (and IV, XORed into specific words) into the 16 LFSR words s^(0)_0..15
   per the fixed key/IV-to-word mapping given in Section 3 (differs for the
   256-bit vs. 512-bit key case — transcribe directly from the paper's two
   enumerated assignment lists when implementing; not restated here to avoid
   transcription error on a 16-way index mapping).
2. Run 32 iterations of Next in INIT mode, discarding output:
       S1 ← Next^32(S_33, mode=INIT)
3. Run one more Next in NORMAL mode to get the working initial state:
       S0 ← Next(S1, mode=NORMAL)
4. Output S0.
```

The exact key/IV word-assignment table (step 1) should be transcribed directly from
`docs/papers/Strumok.pdf` Section 3 at implementation time rather than copied through this
summary — it's a dense 16-entry mapping the paper gives as two explicit lists (256-bit and
512-bit key cases) and is exactly the kind of place a paraphrase could silently drop an index.

## Test vectors

**Update, 2026-07-22:** the "none exist" finding below was true when this doc was first written;
it no longer is. `oracles/uapki/library/uapkic/src/dstu8845.c`'s `dstu8845_self_test` supplied the
first real KAT data found anywhere for this algorithm (`DECISIONS.md` D-15), adopted into
`crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json` and implemented against
test-first (`DECISIONS.md` D-18, `dstu_core::hazmat::strumok`). Still not confirmed against the
paid official DSTU 8845:2019 text itself — "UAPKI-attributed", not "official". Original note,
kept for context:

**None exist** in `docs/papers/` at the time this doc was written. Confirmed by direct hex-run
scan of every Strumok-related PDF there — see `ORACLES.md`'s Strumok section. Implementing this
primitive without official vectors was a known, accepted gap, not an oversight; locating or
generating trustworthy vectors was treated as a prerequisite, not an afterthought.
