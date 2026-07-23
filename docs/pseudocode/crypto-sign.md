# `crypto_sign` (DSTU 4145 wrapper) - deterministic nonce derivation

**The sign/verify math itself is not re-derived here** - `dstu_core::crypto_sign` calls
`hazmat::dstu4145::signature::sign`/`verify` directly, unchanged; those are transcribed from Bouncy
Castle's `DSTU4145Signer` and re-derived against the official text (`DECISIONS.md` D-02/D-14/D-25,
`docs/pseudocode/dstu4145.md`). What's new here, and needs its own citation posture, is the one
thing the wrapper adds: how the ephemeral nonce `e` is produced, since `hazmat`'s `sign` takes it as
a caller-supplied parameter and does not generate it.

**Not a DSTU-specified construction, and not oracle-verified for the derivation itself** - same
honest-scoping posture as `docs/pseudocode/kupyna-kdf.md`, stated precisely rather than reused
wording. No reference implementation derives DSTU 4145 nonces deterministically; Bouncy Castle's
`DSTU4145Signer` uses `SecureRandom`. What follows is a design decision (`DECISIONS.md` D-46), not a
transcription.

## Design choice: deterministic, RFC-6979-*style*, not caller-random

Two paths were weighed (full security-posture reasoning in `DECISIONS.md` D-46, not duplicated
here): caller/RNG-supplied random `e` (faithful to Bouncy Castle's reference) vs. a nonce derived
deterministically from `(d, message)`, so signing needs no randomness at all. **Chosen:
deterministic** - matches Ed25519/libsodium's own signing design, and structurally removes nonce
reuse (this signature family's real-world catastrophic failure mode) from the wrapper's caller
surface, rather than documenting the risk and hoping callers manage entropy correctly.

RFC 6979 is the established international pattern for deterministic DSA-family nonces, but its
construction and security proof are **HMAC-specific** (an HMAC-DRBG-style `V`/`K` iteration).
`hazmat::kupyna_kmac`'s construction (`H(PAD(K) || PAD(M) || ~K)`, DSTU 7564:2014's own MAC mode) is
not HMAC - assuming RFC 6979's proof transfers to a different keyed PRF without justification would
be the same unexamined-assumption failure D-45 already flagged for HKDF-over-Kupyna-KMAC. What's
kept from RFC 6979 is the *shape* - PRF keyed by the private key, seeded by the message hash,
rejection-sampled into range - not its specific HMAC-DRBG iteration machinery, which has no obvious
KMAC-based equivalent and would be new unverified machinery invented for no demonstrated benefit.

## Construction

Given a private key `d` (a `Scalar`, `[u8; 21]` big-endian, `0 < d < n`) and a 32-byte message hash
`H` (this wrapper's own Kupyna-256 hash of the caller's message - see below):

```
key         = zero_pad_left(d.to_be_bytes(), 32)        [32 bytes - Kupyna256Kmac's required key length]
counter     = 0
loop:
    message = H || counter                              [33 bytes: 32-byte hash + 1-byte counter]
    mac     = Kupyna256Kmac::mac(key, message)           [32 bytes]
    e       = reduce_mod_n(mac)                          [Scalar::reduce_wide_bytes]
    (r, s)  = hazmat::dstu4145::signature::sign(H, d, e, g)
    if (r, s) is Some:
        return (r, s)
    counter += 1                                         # ~2^-163 probability, same class as
                                                           # hazmat sign()'s own degenerate rejections
```

`d`'s 21-byte value is **left-padded** with zeros to reach Kupyna256Kmac's fixed 32-byte key
requirement - an embedding of the smaller integer into the wider field, not a truncation, so no
bits of `d` are lost. `reduce_mod_n` here is `Scalar::reduce_wide_bytes` (new, `pub(crate)`,
`hazmat::dstu4145::scalar`): a bit-serial, constant-time reduction that processes every bit of the
32-byte KMAC output regardless of value - a direct generalization of the existing
`reduce_mod_n(product: [u64; 6])` (used for multiplication) to an arbitrary-length input, same
technique (double-and-conditionally-subtract, always run in full).

`e = 0` is not checked explicitly in the derivation loop - `hazmat::dstu4145::signature::sign`
already rejects it (`g.scalar_multiply(&[0; 21])` yields `Point::Infinity`, which `sign` maps to
`None`), so the existing retry loop covers it without a redundant check.

## Message hashing

`crypto_sign::SigningKey::sign`/`VerifyingKey::verify` take a raw `message: &[u8]`, not a
pre-computed digest, and hash it internally with `hazmat::kupyna::Kupyna256::digest` - matching
libsodium's own `crypto_sign(message, ...)` ergonomics (`hazmat::dstu4145::signature` itself is, and
stays, digest-agnostic - its own doc comment's stated design, unaffected by this wrapper's choice of
which hash to use).

## Public key encoding

`VerifyingKey::to_uncompressed_bytes`/`from_uncompressed_bytes` use a plain 42-byte `x || y`
encoding (each `FieldElement`'s existing 21-byte big-endian form, concatenated) - **not** the DSTU
4145 standard's own compressed point encoding (official text §6.9/§6.10, Bouncy Castle's
`DSTU4145PointEncoder.java`/`DSTU4145ECBinary.java`). That encoding is not implemented anywhere in
this project (`docs/pseudocode/dstu4145.md` already flagged compressed point encoding as unbuilt,
separate-concern future work relative to sign/verify). Anyone needing interoperable, spec-compliant
public-key serialization must wait for that; this wrapper's 42-byte form is an internal convenience,
not a claim of standard conformance, and is stated as such in `crypto_sign.rs`'s own module doc.

## What testing here can and cannot show

No oracle exists for the nonce derivation itself (see above), so tests are limited to:

- **Determinism**: identical `(SigningKey, message)` always produces the identical signature.
- **Round-trip**: `verify(message, sign(message))` holds, over both fixed keys and a `proptest`
  sweep of random `(d, message)` pairs.
- **Tamper rejection**: a changed message, a changed signature byte, or the wrong verifying key
  must each fail verification.
- **`Q = -d*G` cross-check against an external oracle**: `SigningKey::verifying_key()`'s output is
  checked against the official Annex B.1 worked example's own `(private_key_d, public_key_q)` pair
  (`tests/vectors/dstu4145/gf2m163.json`) - this exercises `hazmat`'s already-vector-confirmed point
  arithmetic, a genuine external check, but of key derivation, not of the nonce construction.

None of this can catch "the nonce derivation itself is a bad PRF instantiation" the way a
purpose-built KAT for *this exact construction* would - there is no such KAT, because no reference
implementation of this exact scheme exists anywhere to have generated one from. The mitigant is
construction conservatism (reusing T-38's already-analyzed-as-a-keyed-PRF Kupyna-KMAC, matching an
established shape) rather than test coverage.
