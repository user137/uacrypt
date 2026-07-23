# Kalyna-CCM — pseudocode

**Provisional, not confirmed against the primary DSTU 7624:2014 text** — same posture as
`strumok.md`'s UAPKI-attributed caveat (D-15). Transcribed from
`oracles/uapki/library/uapkic/src/dstu7624.c` (a from-code restatement, not from-spec — the
official standard text is not currently among `docs/papers/`, see `DECISIONS.md` D-05/D-41), and
cross-checked byte-for-byte for 4 of the 5 Kalyna variants against
`oracles/bouncycastle-java`'s `DSTU7624Test.java` CCM vectors (BC's own `KCCMBlockCipher`/
`KGCMBlockCipher` construction source is not present in this project's vendored sparse checkout —
the cross-check is against BC's vector *outputs* only). Not a source to copy from — this is a
from-code restatement for implementation planning, per `DECISIONS.md` D-06's principle applied to
a C reference instead of a paper.

## Parameters, per Kalyna variant

`block_len`/`ccm_nb`/`q` (tag length) are cross-oracle-vector-confirmed for these five combinations
— `ccm_nb` and `q` are otherwise tunable parameters of the construction (`dstu7624_init_ccm`'s
`n_max`/`q` arguments), not fixed constants of the standard (`DECISIONS.md` D-40).

| Kalyna variant | `block_len` (bytes) | `ccm_nb` (bytes) | `q` tag length (bytes) | nonce field width (`block_len - ccm_nb - 1`) |
|---|---|---|---|---|
| 128/128 | 16 | 4 | 16 | 11 |
| 128/256 | 16 | 4 | 16 | 11 |
| 256/256 | 32 | 4 | 16 | 27 |
| 256/512 | 32 | 6 | 32 | 25 |
| 512/512 | 64 | 8 | 64 | 55 |

The caller supplies a full `block_len`-byte nonce (matching the vectors, which give a full-block
IV) even though the CBC-MAC header (below) only consumes the first `block_len - ccm_nb - 1` bytes
of it — the rest still feeds the CTR keystream (see "Keystream generation" below).

## Hard length limit — sourced, not chosen

The CBC-MAC header encodes both the plaintext length and the AAD length as a **single byte each**
(`G1[tmp] = p_data_len as u8`, `G2[0] = a_data_len as u8` in `ccm_padd`, `dstu7624.c:2660`/`2690`).
This construction, as extracted, therefore only correctly authenticates messages where **both
plaintext and AAD are at most 255 bytes** — a property of the source, not a design choice. This is
also, concretely, why this is a genuine *short-message* mode.

## CBC-MAC tag computation (`ccm_padd`, `dstu7624.c:2621`)

Given `block_len`, `ccm_nb`, `q`, `nonce` (`block_len` bytes), `aad`, `plaintext`:

```
tmp = block_len - ccm_nb - 1

G1 = zeros(block_len)
G1[0..tmp] = nonce[0..tmp]
G1[tmp] = len(plaintext) as u8                          # single-byte length field
G1[block_len - 1] = flags, where:
    bit 7            = 1 if len(plaintext) > 0 else 0
    bits 4..6         = tag_length_code(q)                # 8->2, 16->3, 32->4, 48->5, 64->6
    bits 0..2 (etc.)  = ccm_nb - 1

G2 = zeros(block_len)
G2[0] = len(aad) as u8                                    # single-byte length field

aad_rem = len(aad) mod block_len
H = G1 ++ G2[0 .. block_len - aad_rem] ++ aad             # header, padded G2 slice, then AAD
    # (H's length is always a multiple of block_len: two fixed blocks' worth plus AAD
    # rounded up to the next block boundary)

B = zeros(block_len)
for each block_len-sized chunk C of H:
    B = encrypt_block(B xor C)                            # CBC-MAC, no separate IV

padded_plaintext = plaintext, then if len(plaintext) mod block_len != 0:
    append 0x80, then zeros up to the next block_len boundary  # ISO/IEC 7816-4-style pad
    # (if len(plaintext) mod block_len == 0, including the empty-plaintext case, no pad is added)

for each block_len-sized chunk C of padded_plaintext:
    B = encrypt_block(B xor C)

raw_tag = B[0..q]                                          # first q bytes of the final CBC-MAC block
```

## Keystream generation (`gamma_gen`/`encrypt_ctr`/`dstu7624_init_ctr`, `dstu7624.c:2730`/`2739`/`4397`)

A stateful running CTR keystream, seeded from the **encrypted** nonce rather than the raw nonce —
transcribed as-is, not simplified to textbook CTR:

```
counter = encrypt_block(nonce)     # this value is never itself used as keystream output
keystream = counter
used = block_len                  # forces regeneration before the first real byte is consumed

# to XOR keystream into a buffer `buf` (used for both the plaintext and, continuing the same
# state, the raw tag — see "Overall construction" below):
for each byte position in buf, in order:
    if `used` has reached block_len:
        counter = increment_little_endian(counter)   # byte 0 is least-significant; carries forward
        keystream = encrypt_block(counter)
        used = 0
    buf[position] ^= keystream[used]
    used += 1
```

## Overall construction

**Seal** (`dstu7624_encrypt_ccm`, `dstu7624.c:2792`):

```
raw_tag = ccm_padd(nonce, aad, plaintext)          # computed over the ORIGINAL plaintext
ciphertext = plaintext                              # copy
apply_keystream(ciphertext)                         # in place, continuing state across calls
masked_tag = raw_tag[0..q]
apply_keystream(masked_tag)                         # continues the SAME keystream state — not reset
output = ciphertext ++ masked_tag                   # what gets transmitted
```

**Open** (`dstu7624_decrypt_ccm`, `dstu7624.c:2849`, restructured into a self-contained shape — see
"API-shape deviation" below):

```
plaintext = ciphertext                              # copy
apply_keystream(plaintext)                          # recovers the tentative plaintext
recovered_raw_tag = masked_tag                       # copy
apply_keystream(recovered_raw_tag)                  # continues the same keystream — unmasks it
expected_raw_tag = ccm_padd(nonce, aad, plaintext)   # recomputed over the RECOVERED plaintext
if recovered_raw_tag != expected_raw_tag (constant-time compare):
    zero the plaintext buffer; reject
else:
    accept; plaintext is now trusted
```

### API-shape deviation from UAPKI's own function signatures

UAPKI's `dstu7624_decrypt_mac` takes the plaintext (unmasked) tag as a separate caller-supplied
parameter, and its internal check compares a freshly recomputed tag against *that* parameter — it
never actually uses the trailing masked-tag bytes of the received ciphertext blob for verification.
That shape only works if the caller already independently knows the correct plaintext tag (as
UAPKI's own self-test does, having just received it from the paired encrypt call) — not reproducible
by a real receiver who only has the transmitted ciphertext+masked-tag blob and the AAD.
`hazmat::kalyna_ccm::open_in_place` instead recovers the tag by continuing the CTR keystream over
the transmitted masked-tag bytes itself (mathematically identical, since XOR-masking is its own
inverse) and verifies against that — a standard, self-contained AEAD shape (ciphertext+tag as one
transmitted unit), not a deviation in the cryptographic construction itself, only in which value the
public function signature expects the caller to supply.

## Rust implementation

`crates/dstu-core/src/hazmat/kalyna_ccm.rs` — see its module doc comment for the exact citation
line numbers (kept in sync with this document) and `DECISIONS.md` D-41 for the verification
summary.
