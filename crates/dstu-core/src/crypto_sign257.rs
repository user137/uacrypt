//! `crypto_sign` equivalent for DSTU 4145's `m=257` curve - additive sibling of
//! [`crate::crypto_sign`], mirroring its shape exactly (`SigningKey`/`VerifyingKey`/`Signature`,
//! deterministic nonce derivation, `sign`/`sign_digest`/`verify`/`verify_digest`), built on
//! `hazmat::dstu4145::{gf2m257, curve257, scalar257, signature257}` instead of the `m=163`
//! modules. `docs/TASKS.md` T-199, `docs/DECISIONS.md` D-185/D-186.
//!
//! **Why a separate module, not a curve-selecting `crypto_sign`** (`docs/DECISIONS.md` D-186's own
//! addendum, reversing that entry's original Decisions 1-3): converting `crypto_sign`'s
//! `SigningKey`/`VerifyingKey`/`Signature` into curve-tagged enums would break
//! `dstu-core-capi/src/sign.rs`'s C ABI (a separate root-workspace crate wrapping these exact
//! types) for no benefit the additive-sibling shape doesn't also deliver - and matches the
//! project's own established precedent for exactly this situation (`crypto_box512`, T-193:
//! additive sibling module, capi/binding wiring explicitly deferred as a separate task). This
//! shape is also *stronger* on the original downgrade concern D-186 Decision 2 raised: with
//! distinct types, a caller wanting `m=257`-level assurance cannot accidentally accept an `m=163`
//! signature at all - the compiler forbids it, rather than relying on a caller to inspect a
//! returned `CurveId` and not ignore it.
//!
//! **The curve-tag byte (`docs/DECISIONS.md` D-186 Decision 1) lives at the `uacrypt`
//! serialization layer, not here** - this module's own `to_bytes`/`from_bytes` are plain
//! fixed-width encodings (33/66 bytes), same convention as `crypto_sign`'s untagged 21/42-byte
//! ones. A shared `CurveId`/tagged-blob reader belongs where untrusted, curve-unknown-in-advance
//! input is actually parsed (`uacrypt verify`, T-199's own remaining scope) - duplicating a tag
//! byte into every language binding's own hand-rolled parser is exactly the D-118 lesson
//! (`crypto_secretstream`'s wire-format validation) this project already learned once.
//!
//! `VerifyingKey::verify`/`verify_digest` return a plain `bool`, same ergonomics as `crypto_sign`,
//! not `Result<CurveId, _>` (D-186 Decision 2's original text): once a caller holds a
//! `crypto_sign257::VerifyingKey` rather than `crypto_sign::VerifyingKey`, the curve is already
//! known statically, nothing to report back.
//!
//! Nonce derivation uses `hazmat::kupyna_kmac::Kupyna384Kmac` (48-byte key/output), **not**
//! `crypto_sign`'s `Kupyna256Kmac`: `curve257::order()` is itself ~256 bits, so folding a
//! same-width 256-bit KMAC output mod it (as `crypto_sign`'s 256-bit-output-mod-~163-bit-`n` does
//! safely, that ratio being wide enough for the bias to be cryptographically negligible) would
//! reintroduce real bias here - flagged as unresolved in `docs/DECISIONS.md` D-186 Decision 5,
//! closed by widening to a 384-bit KMAC output instead (128 bits of margin over `n`'s ~256 bits).
//!
//! See [`crate::crypto_sign`]'s own module doc for the full design rationale this mirrors
//! (deterministic-nonce misuse-resistance argument, the `Q = -d*G` convention, the `sign`/
//! `sign_digest` split for large/streamed messages) - not restated here.
//!
//! # Example
//!
//! ```rust
//! use dstu_core::crypto_sign257::SigningKey;
//!
//! # if cfg!(miri) { return; } // scalar_multiply calls - minutes each under Miri's interpreter
//! let signing_key = SigningKey::generate().expect("OS CSPRNG should not fail");
//! let verifying_key = signing_key.verifying_key();
//!
//! let message = b"a message whose origin and integrity matter";
//! let signature = signing_key.sign(message);
//! assert!(verifying_key.verify(message, &signature));
//!
//! assert!(!verifying_key.verify(b"a different message", &signature));
//! let other_key = SigningKey::generate().expect("OS CSPRNG should not fail");
//! assert!(!other_key.verifying_key().verify(message, &signature));
//! ```

use crate::hazmat::dstu4145::curve257::{self, Point};
use crate::hazmat::dstu4145::gf2m257::FieldElement;
use crate::hazmat::dstu4145::scalar257::Scalar;
use crate::hazmat::dstu4145::signature257;
use crate::hazmat::kupyna::Kupyna256;
use crate::hazmat::kupyna_kmac::Kupyna384Kmac;
use zeroize::Zeroize;

/// A DSTU 4145 `m=257` signature, `r || s` (33 bytes each, 66 total).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 33],
    s: [u8; 33],
}

impl Signature {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.r);
        out[33..].copy_from_slice(&self.s);
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut r = [0u8; 33];
        let mut s = [0u8; 33];
        r.copy_from_slice(&bytes[..33]);
        s.copy_from_slice(&bytes[33..]);
        Signature { r, s }
    }
}

/// A DSTU 4145 `m=257` private key - see [`crate::crypto_sign::SigningKey`]'s own doc comment for
/// why signing itself needs no RNG.
pub struct SigningKey(Scalar);

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A DSTU 4145 `m=257` public key `Q = -d*G` (same convention as `crypto_sign::VerifyingKey`).
#[derive(Clone, Copy)]
pub struct VerifyingKey(Point);

impl SigningKey {
    /// Builds a signing key from a big-endian 33-byte scalar. Returns `None` if `d` is zero or
    /// not less than the curve order `n` - same validation as `crypto_sign::SigningKey::from_bytes`.
    #[must_use]
    pub fn from_bytes(d: &[u8; 33]) -> Option<Self> {
        let n = curve257::order();
        if d.iter().all(|&b| b == 0) || d >= &n {
            return None;
        }
        Some(SigningKey(Scalar::from_be_bytes(d)))
    }

    /// Generates a fresh signing key from the OS CSPRNG - same rejection-sampling approach as
    /// `crypto_sign::SigningKey::generate` (`docs/TASKS.md` T-122), re-derived for this curve's
    /// own order rather than assumed to carry over: `curve257::order()`'s top byte is `0x00`
    /// (D-185 - unlike `m=163`'s `0x04`), so masking each 33-byte candidate's top byte down to
    /// zero and its second byte to its low bit (`n`'s own bit-length is 256, one bit narrower than
    /// the 33-byte/264-bit draw) keeps the rejection rate near 50%, the same target
    /// `crypto_sign`'s own masking hits for `m=163`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::randombytes::RandomError`] if the OS CSPRNG fails while drawing a
    /// candidate.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn generate() -> Result<Self, crate::randombytes::RandomError> {
        loop {
            let mut candidate = [0u8; 33];
            crate::randombytes::randombytes_buf(&mut candidate)?;
            candidate[0] = 0;
            candidate[1] &= 0x01;
            let scalar = Scalar::from_candidate_bytes(&candidate);
            candidate.zeroize();
            if let Some(scalar) = scalar {
                return Ok(SigningKey(scalar));
            }
        }
    }

    /// Returns `d`'s big-endian 33-byte encoding - see `crypto_sign::SigningKey::to_bytes`'s own
    /// doc comment for the caller-zeroizes-it convention this matches.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.to_be_bytes()
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let g = Point::generator();
        let q = g.scalar_multiply(&self.0.to_be_bytes()).negate();
        VerifyingKey(q)
    }

    /// Signs `message` - see `crypto_sign::SigningKey::sign`'s own doc comment.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_digest(&Kupyna256::digest(message))
    }

    /// Signs an already-computed 32-byte Kupyna-256 digest directly - see
    /// `crypto_sign::SigningKey::sign_digest`'s own doc comment (T-113's streaming-message note).
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Signature {
        let g = Point::generator();
        let mut counter: u8 = 0;
        loop {
            let e = derive_nonce(self.0, digest, counter);
            if let Some((r, s)) = signature257::sign(digest, self.0, e, g) {
                return Signature { r, s };
            }
            counter = counter.wrapping_add(1);
        }
    }
}

impl VerifyingKey {
    #[must_use]
    pub fn to_uncompressed_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        match self.0 {
            Point::Affine(x, y) => {
                out[..33].copy_from_slice(&x.to_be_bytes());
                out[33..].copy_from_slice(&y.to_be_bytes());
            }
            Point::Infinity => {} // never produced by verifying_key() for a valid SigningKey
        }
        out
    }

    #[must_use]
    pub fn from_uncompressed_bytes(bytes: &[u8; 66]) -> Self {
        let x = FieldElement::from_be_bytes(&bytes[..33]);
        let y = FieldElement::from_be_bytes(&bytes[33..]);
        VerifyingKey(Point::Affine(x, y))
    }

    /// See `crypto_sign::VerifyingKey::verify`'s own doc comment.
    #[must_use]
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.verify_digest(&Kupyna256::digest(message), sig)
    }

    /// See `crypto_sign::VerifyingKey::verify_digest`'s own doc comment (T-113's streaming-message
    /// note). Full public-key validation, including the general small-subgroup rejection
    /// `hazmat::dstu4145::signature257::verify` itself performs (cofactor 4, not `m=163`'s 2 - see
    /// that function's own module doc).
    #[must_use]
    pub fn verify_digest(&self, digest: &[u8; 32], sig: &Signature) -> bool {
        let g = Point::generator();
        signature257::verify(digest, &sig.r, &sig.s, self.0, g)
    }
}

/// Deterministic ephemeral-nonce derivation, `m=257` - see the module doc for why
/// `Kupyna384Kmac` (48-byte key/output) replaces `crypto_sign`'s `Kupyna256Kmac` here. `d`'s
/// 33-byte big-endian value is left-padded with zeros to the 48-byte key length - an embedding,
/// not a truncation.
fn derive_nonce(d: Scalar, hash: &[u8; 32], counter: u8) -> Scalar {
    let mut key = [0u8; 48];
    key[15..].copy_from_slice(&d.to_be_bytes());
    let mut message = [0u8; 33];
    message[..32].copy_from_slice(hash);
    message[32] = counter;

    let Ok(mac) = Kupyna384Kmac::mac(&key, &message) else {
        unreachable!("key is always exactly 48 bytes, Kupyna384Kmac's required length")
    };
    key.zeroize();
    Scalar::reduce_wide_bytes(&mac)
}
