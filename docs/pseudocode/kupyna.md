# Kupyna (DSTU 7564:2014) — pseudocode

Transcribed from `docs/papers/Kupyna.pdf` (Oliynykov et al., "A New Standard of Ukraine: The
Kupyna Hash Function"), Sections 3–6. Cross-checked structurally against
`oracles/kupyna-reference/kupyna.c` (Roman Oliynykov, verify-only, no license — see
`docs/ORACLES.md`). From-spec restatement for implementation planning, not a source to copy from
(`docs/DECISIONS.md` D-06).

## Parameters (Section 3, Table 1)

| Hash length `n` | internal state `l` | rounds `t` | state columns `c` |
|---|---|---|---|
| 8 ≤ n ≤ 256 (Kupyna-256) | 512 | 10 | 8 |
| 256 < n ≤ 512 (Kupyna-512) | 1024 | 14 | 16 |

State is an 8×`c` byte matrix, filled column-by-column (Section 6.1, Fig. 2), same convention as
Kalyna.

## Padding (Section 5)

Input message of `N` bits is padded with: one `1` bit, then `d = (-N - 97) mod l` zero bits, then
96 bits of the message length `N` (little-endian). Result is a multiple of `l` bits.

```
padded ← message ‖ 0x80-style '1' bit ‖ zero_bits(d) ‖ N as 96-bit little-endian integer
```

matches oracle `Pad()` exactly, including the `(-msg_nbits - 97) % (nbytes*8)` zero-count formula.

## Initial value

**Extraction note:** the paper's IV formula (Section 4) did not survive `pdftotext` cleanly at
this specific line — it renders as `IV = 1‖0^510` / `1‖0^1023`, ambiguous between "IV is the
integer 1 followed by zero bits" and something else. The oracle resolves it unambiguously:
`ctx->state[0][0] = nbytes` (i.e. the first byte of the all-zero state is set to `l/8` — 64 for
Kupyna-256, 128 for Kupyna-512), everything else zero. Used here as the authoritative source for
this one detail per `docs/ORACLES.md`'s extraction-limitation convention; flagged, not silently
assumed.

```
h0 ← state of l bits, all zero except byte[0] = l / 8
```

## Compression (Section 4)

```
for each l-bit block m_i of the padded message:
    h_i ← T⁺(m_i) ⊕ T(h_{i-1} ⊕ m_i) ⊕ h_{i-1}
H(M) ← R_n(T(h_k) ⊕ h_k)     // R_n = take the n most-significant bits
```

matches oracle `Digest()`: `temp1 = state XOR block` then `P(temp1)`; `temp2 = block` then
`Q(temp2)`; `state ^= temp1 ^ temp2` — i.e. `T(h⊕m)` is `P`, `T⁺(m)` is `Q`. Finalization
(`OutputTransformation`) applies `P` once more to the final state and XORs it in before
truncating (`Trunc`) to the requested hash length — matching `R_n(T(h_k) ⊕ h_k)`.

## `T` / `T⁺` transformations (Section 6.1)

Each is `t` iterations of round-constant-add → S-box → row-permute → MDS-linear, differing only
in which constant-addition function is used:

```
T(state):                              T+(state):
  for round in 0 .. t-1:                 for round in 0 .. t-1:
      state ← addConstXor(state, round)      state ← addConstAdd(state, round)
      state ← subBytes(state)                state ← subBytes(state)
      state ← shiftRows(state)               state ← shiftRows(state)
      state ← mixColumns(state)              state ← mixColumns(state)
```

Per Section 6.1's own definition, `T_l` uses the XOR-based constant addition (`ψ⊕`) and `T_l⁺`
uses the mod-2⁶⁴-add-based one (`ψ⊞`) — so `T_l` = oracle `P()` (`AddRoundConstantP`, XOR) and
`T_l⁺` = oracle `Q()` (`AddRoundConstantQ`, mod-add). This lines up with `Digest()`: it runs `P`
on `state XOR block` (= `T(h⊕m)`) and `Q` on `block` alone (= `T⁺(m)`), matching Section 4's
`h_i = T(h_{i-1}⊕m_i) ⊕ T⁺(m_i) ⊕ h_{i-1}` term for term.

### Round-constant addition (Section 6.2)

- **XOR variant** (`ψ⁺` in the paper, oracle `AddRoundConstantP`): column `j` gets
  `state[j][0] ^= (j·0x10) ^ round` — only the top byte of each column is touched, XOR.
- **Mod-2⁶⁴-add variant** (oracle `AddRoundConstantQ`): column `j`'s 64-bit word gets
  `+= 0x00F0F0F0F0F0F0F3 ^ (((c-1-j)·0x10) ^ round) << 56`.

### S-box, permutation, linear layer (Sections 6.3–6.5)

Identical in structure to Kalyna's η/π/τ: four S-boxes `S0..S3` from Appendix A indexed by
`i mod 4`; row `i` (`i` = 0..6) rotated right by `i`, row 7 rotated right by 7 (`l=512`) or 11
(`l=1024`); MDS linear layer over GF(2⁸) (modulus `0x11D`) with the same vector
`μ = (01,01,05,01,08,06,07,04)` as Kalyna.

## Test vectors

Kupyna-256 and Kupyna-512 byte-aligned cases already extracted and verified:
`crates/dstu-core/tests/vectors/kupyna/*.json` (see `docs/ORACLES.md`). Bit-level (non-byte-aligned)
cases from the paper are deliberately not transcribed — see the `note` field in those files.
