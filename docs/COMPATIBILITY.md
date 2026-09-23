# Compatibility with other DSTU implementations

`dstu-core` implements the DSTU standards as written. Where another implementation reads a clause
differently, we follow the standard's text and its own worked examples, and record the difference
here. We don't copy the other implementation's behaviour.

Compared against:

- **UAPKI**: `library/uapkic/src/dstu7624.c` (vendored under `oracles/uapki/`), the one-shot
  `encrypt_gmac` path. Its self-test vectors are the annex examples of DSTU 7624:2014. Evidence comes
  from `dstu-core` ≤ 0.3, a line-by-line port of that file, run on the same inputs before this
  change.
- **Bouncy Castle**: `bcprov-jdk18on` 1.85 (`KGCMBlockCipher`, `KGMac`, `KCCMBlockCipher`,
  `DSTU7624Mac`), run directly.
- **Standard**: DSTU 7624:2014 (draft edition), DSTU 7564:2014 (draft edition), DSTU 4145-2002.

"Same" means byte-identical output on the tested inputs. Details and citations are in
[DECISIONS.md](DECISIONS.md) D-204–D-206.

## Kalyna (DSTU 7624:2014) modes

| Mode | Input class | dstu-core | UAPKI | Bouncy Castle 1.85 |
|---|---|---|---|---|
| Block cipher, ECB, CBC, CFB, OFB, CTR, XTS, KW | annex В examples | standard | same | same where tested |
| GCM / GMAC | AAD and ciphertext block-aligned (all annex examples) | standard | same | same |
| GCM / GMAC | AAD not block-aligned | `0x80` pad, true length (§12.2) | zero pad | zero pad |
| GCM | ciphertext not block-aligned | `0x80` pad, true length | `0x80` pad, **padded** length | zero pad, true length |
| CCM | AAD and plaintext block-aligned (annex В.9) | standard | same | same |
| CCM | empty AAD | flag bit 7 = 0, `B = T(G1)` | bit 7 = 1, extra G2 block | same as dstu-core |
| CCM | plaintext not block-aligned (e.g. annex В.9.2) | standard | same | **differs**: fails annex В.9.2 |
| CCM | `AAD mod l > l/8 − N_Б` (e.g. 13–15 bytes for a 128-bit block) | G2 per §13.2 | shorter G2 | different G2 layout |
| CCM | AAD not block-aligned, otherwise | standard | same | differs (`len‖AAD‖0`, not `len‖0‖AAD`) |
| CCM | empty plaintext | rejected (outside §13.1's domain) | accepted | accepted |
| CMAC | message not block-aligned (annex В.5.2) | standard | same | throws |
| CMAC | empty message | rejected (outside §9's domain) | `MAC(ε) = MAC(0^l)` | `MAC(ε) = MAC(0^l)` |

Practical consequence: for GCM/GMAC/CCM with arbitrary-length data, the three produce different tags,
so tags exchanged between them only verify on block-aligned inputs.

`crypto_secretbox`, `crypto_secretstream` and `crypto_box` use Kalyna-GCM with a non-block-aligned
internal AAD, so their output is not reproducible with UAPKI's or Bouncy Castle's GCM. That doesn't
matter for them: these are this library's own formats, not a standard interchange format.

## Kupyna (DSTU 7564:2014)

| Function | dstu-core | UAPKI | Bouncy Castle |
|---|---|---|---|
| Kupyna-256/384/512 (byte input, annex Б examples) | standard | same | same where tested |
| Kupyna-KMAC 256/384/512 (annex В.5) | standard | same | same |

## DSTU 4145-2002

The curve parameters for `m = 163` and `m = 257` (annex Г) match the standard exactly.
