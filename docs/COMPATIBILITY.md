# Compatibility with other DSTU implementations

`dstu-core` implements the DSTU standards as written. Where another implementation reads a clause
differently, we follow the standard's text and its own worked examples, and record the difference
here. We don't copy the other implementation's behaviour.

Compared against:

- **UAPKI**: `library/uapkic/src/dstu7624.c` (vendored under `oracles/uapki/`), the one-shot
  `encrypt_gmac` path. Its self-test vectors are the annex examples of DSTU 7624:2014. Evidence comes
  from `dstu-core` ≤ 0.3, a line-by-line port of that file, run on the same inputs before this
  change. That is uapkic 2.0.2, the version in every tagged UAPKI release up to v2.0.17.
- **UAPKI 2.0.3**: uapkic as rewritten on 2026-09-29 (`deffe4a`, "Fix Kalyna GCM, GMAC and CCM
  modes"), not yet in a tagged release. Built from `master` `0bf2b68` and run directly against
  `dstu-core` on Kalyna-128/128 only (2026-10-03); `dstu7624_self_test` passes.
- **Bouncy Castle**: `bcprov-jdk18on` 1.85 (`KGCMBlockCipher`, `KGMac`, `KCCMBlockCipher`,
  `DSTU7624Mac`), run directly.
- **Standard**: DSTU 7624:2014 (draft edition), DSTU 7564:2014 (draft edition), DSTU 4145-2002.

"Same" means byte-identical output on the tested inputs. Details and citations are in
[DECISIONS.md](DECISIONS.md) D-204–D-206.

## Kalyna (DSTU 7624:2014) modes

| Mode | Input class | dstu-core | UAPKI ≤ 2.0.2 | UAPKI 2.0.3 | Bouncy Castle 1.85 |
|---|---|---|---|---|---|
| Block cipher, ECB, CBC, CFB, OFB, CTR, XTS, KW | annex В examples | standard | same | same (self-test) | same where tested |
| GCM / GMAC | AAD and ciphertext block-aligned, not both empty (all annex examples) | standard | same | same | same |
| GCM / GMAC | AAD **and** data both empty | rejected (§12.1: AAD and data must not both be empty) | accepted: the tag is `E_K(0)`, the GHASH key itself | rejected | same as UAPKI ≤ 2.0.2 |
| GCM / GMAC | AAD not block-aligned | `0x80` pad, true length (§12.2) | zero pad | same as dstu-core | zero pad |
| GCM | ciphertext not block-aligned | `0x80` pad, true length | `0x80` pad, **padded** length | same as dstu-core | zero pad, true length |
| CCM | AAD and plaintext block-aligned (annex В.9) | standard | same | same | same |
| CCM | empty AAD | flag bit 7 = 0, `B = T(G1)` | bit 7 = 1, extra G2 block | bit 7 = 0, `B = G1` read literally (no `T`), so the tag differs | same as dstu-core when the plaintext is block-aligned; differs otherwise |
| CCM | plaintext not block-aligned (e.g. annex В.9.2) | standard | same | same | **differs**: fails annex В.9.2 |
| CCM | `AAD mod l > l/8 − N_Б` (e.g. 13–15 bytes for a 128-bit block) | G2 per §13.2 | shorter G2 | same as dstu-core | different G2 layout |
| CCM | AAD not block-aligned, otherwise | standard | same | same | differs (`len‖AAD‖0`, not `len‖0‖AAD`) |
| CCM | empty plaintext | rejected (outside §13.1's domain) | accepted | rejected | accepted |
| CMAC | message not block-aligned (annex В.5.2) | standard | same | same | throws |
| CMAC | empty message | rejected (outside §9's domain) | `MAC(ε) = MAC(0^l)` | `MAC(ε) = MAC(0^l)` (unchanged) | `MAC(ε) = MAC(0^l)` |

Practical consequence: for GCM/GMAC/CCM with arbitrary-length data, UAPKI ≤ 2.0.2, Bouncy Castle and
dstu-core produce different tags, so tags exchanged between them only verify on block-aligned inputs.
UAPKI 2.0.3 matches dstu-core on every tested GCM/GMAC/CCM input except CCM with an empty AAD, where
it reads §13.2's "B = G1" literally (D-205 (b) explains why we read it as `T(G1)`).

`crypto_secretbox`, `crypto_secretstream` and `crypto_box` use Kalyna-GCM with a non-block-aligned
internal AAD, so their output is not reproducible with UAPKI ≤ 2.0.2's or Bouncy Castle's GCM. That
doesn't matter for them: these are this library's own formats, not a standard interchange format.

## Kupyna (DSTU 7564:2014)

| Function | dstu-core | UAPKI | Bouncy Castle |
|---|---|---|---|
| Kupyna-256/512 (byte input, annex Б examples) | standard | same | same where tested |
| Kupyna-48/304/384 (annex Б) | rightmost bytes of the 256/512 cores match; no public API yet (T-254) | - | - |
| Kupyna-KMAC 256/384/512 (annex В.5) | standard | same | same |

## DSTU 4145-2002

The curve parameters for `m = 163` and `m = 257` (annex Г) match the standard exactly.
