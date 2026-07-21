# Kalyna (DSTU 7624:2014) — pseudocode

Transcribed from `docs/papers/Kalyna.pdf` (Oliynykov et al., "A New Encryption Standard of
Ukraine: The Kalyna Block Cipher"), Sections 3–7. Cross-checked structurally against
`oracles/kalyna-reference/kalyna.c` (Roman Oliynykov, verify-only, no license — see
`ORACLES.md`). Not a source to copy from — this is a from-spec restatement for implementation
planning, per `DECISIONS.md` D-06.

## Parameters (Section 3, Table 1)

| Kalyna variant | block bits `l` | key bits `k` | rounds `t` | state columns `c` |
|---|---|---|---|---|
| 128/128 | 128 | 128 | 10 | 2 |
| 128/256 | 128 | 256 | 14 | 2 |
| 256/256 | 256 | 256 | 14 | 4 |
| 256/512 | 256 | 512 | 18 | 4 |
| 512/512 | 512 | 512 | 18 | 8 |

State is an 8×`c` byte matrix `G = (g[i][j])`, `i` = row 0..7, `j` = column 0..c-1, filled
column-by-column from the input block (Section 4).

## Building blocks (Section 5)

- **κ(K)** — add the round key to the state, per 64-bit column word, modulo 2⁶⁴, little-endian
  (Section 5.2 / matches `AddRoundKey`/`AddRoundKeyExpand` in the oracle).
- **η** — S-box layer: `g[i][j] ← S_(i mod 4)(g[i][j])`, four fixed 8-bit S-boxes `S0..S3` from
  Appendix A (Section 5.3 / oracle `SubBytes`).
- **π** — row permutation: row `i` is circularly shifted right by `⌊i·l/512⌋` elements
  (Section 5.4 / oracle `ShiftRows`).
- **τ** — linear layer: each output column `W_j = (μ ⊗ i) · G_j` over GF(2⁸) with modulus
  `0x11D`, MDS vector `μ = (01,01,05,01,08,06,07,04)` (Section 5.5 / oracle `MixColumns`,
  `mds_matrix`).
- **ψ(K)** — XOR the round key into the state (Section 5.6 / oracle `XorRoundKey`).

Decryption (Section 6) uses the inverse of each: κ⁻¹ (mod 2⁶⁴ subtraction), η⁻¹ (inverse S-boxes),
π⁻¹ (left shift), τ⁻¹ (MDS⁻¹ vector `(AD,95,76,A8,2F,49,D7,CA)`), ψ⁻¹ (XOR is its own inverse).

## Encryption transformation `T(K)` (Section 5.1)

```
state ← input_block               // filled column-by-column
state ← κ(state, K0)              // pre-whitening: mod-2^64 add, round key 0
for round in 1 .. t-1:
    state ← η(state)              // S-box layer
    state ← π(state)              // row permutation
    state ← τ(state)              // MDS linear layer
    state ← ψ(state, K_round)     // XOR round key (NOT mod-add for interior rounds)
state ← η(state)
state ← π(state)
state ← τ(state)
state ← κ(state, Kt)              // post-whitening: mod-2^64 add, final round key
output ← state
```

Cross-check: the oracle's `KalynaEncipher` does exactly this — `AddRoundKey(0)`, then
`EncipherRound` (SubBytes→ShiftRows→MixColumns) + `XorRoundKey(round)` for rounds `1..t-1`, then
one more `EncipherRound` + `AddRoundKey(t)`. Confirms κ (mod-add) is used only at round 0 and
round `t`; all interior round-key additions are ψ (XOR).

## Decryption transformation `U(K)` (Section 6.1)

Structural mirror, run in reverse:

```
state ← input_block
state ← κ⁻¹(state, Kt)
for round in t-1 .. 1 (descending):
    state ← τ⁻¹(state)
    state ← π⁻¹(state)
    state ← η⁻¹(state)
    state ← ψ(state, K_round)     // XOR is self-inverse
state ← τ⁻¹(state)
state ← π⁻¹(state)
state ← η⁻¹(state)
state ← κ⁻¹(state, K0)
output ← state
```

## Round key generation (Section 7)

**Intermediate key `Kσ`** (Section 7.1): with `K'=K''=K` if `k=l`, or `K'‖K''=K` (left/right
halves) if `k=2l`:

```
tmv ← l-bit value of (l + k + 64) / 64, little-endian
Kσ ← κ(K')                // add K' (mod-2^64)
Kσ ← η(π(τ(Kσ)))
Kσ ← ψ(Kσ, K'')            // XOR K''
Kσ ← η(π(τ(Kσ)))
Kσ ← κ(Kσ, K')             // add K' again (mod-2^64)
Kσ ← η(π(τ(Kσ)))
```

(This matches oracle `KeyExpandKt`: `AddRoundKeyExpand(k0) → EncipherRound → XorRoundKeyExpand(k1)
→ EncipherRound → AddRoundKeyExpand(k0) → EncipherRound`, where the "tmv" input is
`⌊(nb+nk+1)⌋` in the first state word, matching the paper's `(l+k+64)/64` constant.)

**Even-indexed round keys `K_i`, `i` = 0, 2, 4, ..., t** (Section 7.2): built from a running
constant `φ` (initialized to `0x0001000100010001` repeated per state word, doubled — shifted left
by 1 bit — once per round key generated) and a rotating view of the encryption key. The paper's
notation (`L_{k,l}(K ⊞ 16i)` / `R_{k,l}(K ⊞ 64⌊i/4⌋)`, Section 7.2) denotes this as arithmetic
addition on `K`, but both code oracles agree the actual mechanism is a word-level rotation, not
arithmetic addition — `oracles/kalyna-reference/kalyna.c`'s `Rotate()` (C, Roman Oliynykov) and
`oracles/bouncycastle-java/.../DSTU7624Engine.java`'s `workingKeyExpandEven` (Java, MIT) both
rotate the whole key buffer by one 64-bit word per round-key pair rather than adding a constant.

**Correction on provenance:** an earlier draft of this document treated the Java/C agreement as
two *independent* implementations converging on the same reading of the ambiguous spec text —
that overstated it. `DSTU7624Engine.java`'s own header comment credits
"Roman Oliynykov's native C implementation" as its source, i.e. it is a port/adaptation of the
same C reference, not an independent-from-spec reimplementation (confirmed by reading the file:
it uses `Pack.littleEndianToLong`-style plumbing on top of the same round/key-schedule structure,
right down to variable naming). So this is one lineage read twice, not two lineages agreeing —
weaker evidence than originally claimed, though still useful: it confirms the *port* preserved
the mechanism faithfully rather than reinterpreting the paper's notation differently, which rules
out a transcription slip specific to the C code. The rotate-vs-addition reading is kept as the
working interpretation on that basis, not on a since-withdrawn "two independent oracles" claim.
The `⊞`/`L`/`R` notation in the paper most likely denotes this rotate-and-split operation and
lost fidelity in `pdftotext` extraction (consistent with the systemic notation-symbol loss already
documented in `ORACLES.md`), rather than describing a different operation the code doesn't
implement — but this rests on one lineage, and re-deriving it from the DSTU 7624 standard text
itself (not currently in `docs/papers/`) would be worth doing before relying on it for a
security-critical implementation detail.

Helper — one round-key computation from a base value and the round constant:

```
round_key_from(base, tmp):
    state ← κ(base, tmp)        // base + tmp, mod-2^64
    state ← η(π(τ(state)))
    state ← ψ(state, tmp)       // XOR tmp
    state ← η(π(τ(state)))
    state ← κ(state, tmp)       // + tmp, mod-2^64
    return state
```

**Case k = l** (key buffer is `nb` words = one block):

```
key_buf ← K                                    // nb words
φ ← (0x0001000100010001, ...)                  // one word per state column
for i = 0, 2, 4, ..., t (step 2):
    tmp ← κ(Kσ, φ)                              // Kσ + φ, mod-2^64
    K_i ← round_key_from(key_buf, tmp)
    φ ← φ << 1
    key_buf ← RotateWordsLeft(key_buf, 1)       // rotate the nb-word key by one 64-bit word
```

**Case k = 2·l** (key buffer is `2·nb` words = `K' ‖ K''`, rotated as one ring):

```
key_buf ← K' ‖ K''                             // 2·nb words total
φ ← (0x0001000100010001, ...)
for i = 0, 4, 8, ..., t (step 4):
    tmp   ← κ(Kσ, φ)
    K_i   ← round_key_from(key_buf[0 .. nb], tmp)      // first half — indexes divisible by 4
    φ     ← φ << 1
    tmp   ← κ(Kσ, φ)
    K_i+2 ← round_key_from(key_buf[nb .. 2·nb], tmp)   // second half — indexes ≡ 2 mod 4
    φ     ← φ << 1
    key_buf ← RotateWordsLeft(key_buf, 1)              // rotate the full 2·nb-word buffer
```

Both branches confirmed structurally identical across `kalyna-reference/kalyna.c` and
`bouncycastle-java/.../DSTU7624Engine.java`.

**Odd-indexed round keys `K_i`, `i` = 1, 3, ..., t-1** (Section 7.3):

```
K_i ← RotateLeft_bytes(K_{i-1}, 2·(l/64) + 3)   // rotate the even key below it by (2c+3) bytes
```

matching oracle `KeyExpandOdd` / `RotateLeft` (`rotate_bytes = 2*state_size + 3`).

## Test vectors

All five variants already extracted and verified: `crates/dstu-core/tests/vectors/kalyna/*.json`
(see `ORACLES.md`).
