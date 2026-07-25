//! `crypto_sign` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `TASKS.md` T-48) - a libsodium-ergonomics wrapper over `hazmat::dstu4145::signature`. The first
//! module in the high-level layer D-09 planned but never built (`docs/release-readiness.md` step
//! 4) - this session's shape for it: `SigningKey`/`VerifyingKey`/`Signature`, `ed25519-dalek`-style
//! naming (`DECISIONS.md` D-04's addendum cites that crate's convention).
//!
//! Two departures from `hazmat::dstu4145::signature`'s raw API, both documented in `DECISIONS.md`
//! D-46:
//! - **The ephemeral nonce is derived deterministically** from `(d, message)` via
//!   `hazmat::kupyna_kmac` (an RFC-6979-style adaptation, not a literal port - RFC 6979 is
//!   HMAC-specific, `hazmat::kupyna_kmac`'s construction is not HMAC). No RNG dependency anywhere
//!   in this module, unlike Bouncy Castle's `DSTU4145Signer` (which uses `SecureRandom`) - a
//!   deliberate, user-confirmed deviation from the reference, matching Ed25519/libsodium's own
//!   misuse-resistant signing design rather than the DSA-family default of caller-supplied
//!   randomness (whose reuse is a real-world catastrophic key-recovery class: PS3, several Bitcoin
//!   wallet thefts).
//! - **`sign`/`verify` take a raw `message: &[u8]`, not a pre-computed digest** - this module
//!   hashes it internally with Kupyna-256 (`hazmat::kupyna::Kupyna256`), matching libsodium's own
//!   `crypto_sign(message, ...)` ergonomics. `hazmat::dstu4145::signature` itself stays
//!   digest-agnostic (its own doc comment's stated design), unaffected by this choice.
//!
//! **Large/streamed messages (`TASKS.md` T-113): `sign_digest`/`verify_digest`.** DSTU 4145 signs
//! a hash of the message, not a domain-separated multi-part construction (`docs/pseudocode/
//! dstu4145.md` §5.9/§9/§10: `h ← hash_to_field(H(T))`) - so there is no "streaming signer" to
//! build, only a need to let the hash itself be computed incrementally. `sign`/`verify` above
//! still take the whole message and hash it with one `Kupyna256::digest` call, which needs it all
//! in memory at once; `sign_digest`/`verify_digest` instead take an already-computed 32-byte
//! Kupyna-256 digest directly, so a caller with a large or streamed message can hash it themselves
//! via `hazmat::kupyna::Kupyna256Hasher::{new, update, finalize}` (already `no_std`-compatible,
//! bounded memory regardless of message size) and pass the result in. `sign`/`verify` are now thin
//! wrappers over these two.
//!
//! `VerifyingKey::to_uncompressed_bytes`/`from_uncompressed_bytes` use a plain 42-byte `x || y`
//! encoding, **not** the DSTU 4145 standard's own compressed point encoding (official text
//! §6.9/§6.10, `DSTU4145PointEncoder.java` in Bouncy Castle) - that encoding isn't implemented
//! anywhere in this project yet (`docs/pseudocode/dstu4145.md`'s existing note lists it as future
//! work, unrelated to sign/verify itself). Anyone needing interoperable, spec-compliant public-key
//! serialization must wait for that, tracked separately in `TASKS.md`.

use crate::hazmat::dstu4145::curve163::{self, Point};
use crate::hazmat::dstu4145::gf2m163::FieldElement;
use crate::hazmat::dstu4145::scalar::Scalar;
use crate::hazmat::dstu4145::signature;
use crate::hazmat::kupyna::Kupyna256;
use crate::hazmat::kupyna_kmac::Kupyna256Kmac;
use zeroize::Zeroize;

/// A DSTU 4145 signature, `r || s` (21 bytes each, 42 total - `hazmat::dstu4145::signature`'s own
/// byte convention).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 21],
    s: [u8; 21],
}

impl Signature {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 42] {
        let mut out = [0u8; 42];
        out[..21].copy_from_slice(&self.r);
        out[21..].copy_from_slice(&self.s);
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; 42]) -> Self {
        let mut r = [0u8; 21];
        let mut s = [0u8; 21];
        r.copy_from_slice(&bytes[..21]);
        s.copy_from_slice(&bytes[21..]);
        Signature { r, s }
    }
}

/// A DSTU 4145 private key. Signing needs no RNG (see the module doc) - only key generation from
/// external entropy is the caller's concern, same posture as `hazmat::kalyna_ccm`'s nonce
/// (`DECISIONS.md` D-40): this module takes `d` as given rather than generating it.
pub struct SigningKey(Scalar);

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A DSTU 4145 public key `Q = -d*G` (`hazmat::dstu4145::signature`'s module doc / `DECISIONS.md`
/// D-25's follow-up entry on the sign convention).
#[derive(Clone, Copy)]
pub struct VerifyingKey(Point);

impl SigningKey {
    /// Builds a signing key from a big-endian 21-byte scalar. Returns `None` if `d` is zero or
    /// not less than the curve order `n` - both invalid private keys, rejected here rather than
    /// left to silently misbehave later (`hazmat::dstu4145::scalar::Scalar::from_be_bytes` itself
    /// does not validate, by its own documented convention).
    #[must_use]
    pub fn from_bytes(d: &[u8; 21]) -> Option<Self> {
        let n = curve163::order();
        if d.iter().all(|&b| b == 0) || d >= &n {
            return None;
        }
        Some(SigningKey(Scalar::from_be_bytes(d)))
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let g = Point::generator();
        let q = g.scalar_multiply(&self.0.to_be_bytes()).negate();
        VerifyingKey(q)
    }

    /// Signs `message`, hashing it with Kupyna-256 and deriving the ephemeral nonce
    /// deterministically (see the module doc, `DECISIONS.md` D-46). A thin wrapper over
    /// [`Self::sign_digest`] - see that method, and the module doc's T-113 note, for signing a
    /// message too large to hold in memory whole.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_digest(&Kupyna256::digest(message))
    }

    /// Signs an already-computed 32-byte Kupyna-256 digest directly - for messages hashed
    /// incrementally via `hazmat::kupyna::Kupyna256Hasher` rather than held whole in memory (see
    /// the module doc's T-113 note). The hazmat-level degenerate rejections (`F_e == 0`, `r == 0`,
    /// `s == 0`, each ~`2^-163`) are retried here with the next nonce-derivation counter rather
    /// than surfaced to the caller - safe to retry because the nonce is re-derived, not reused.
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Signature {
        let g = Point::generator();
        let mut counter: u8 = 0;
        loop {
            let e = derive_nonce(self.0, digest, counter);
            if let Some((r, s)) = signature::sign(digest, self.0, e, g) {
                return Signature { r, s };
            }
            counter = counter.wrapping_add(1);
        }
    }
}

impl VerifyingKey {
    #[must_use]
    pub fn to_uncompressed_bytes(&self) -> [u8; 42] {
        let mut out = [0u8; 42];
        match self.0 {
            Point::Affine(x, y) => {
                out[..21].copy_from_slice(&x.to_be_bytes());
                out[21..].copy_from_slice(&y.to_be_bytes());
            }
            Point::Infinity => {} // never produced by verifying_key() for a valid SigningKey
        }
        out
    }

    #[must_use]
    pub fn from_uncompressed_bytes(bytes: &[u8; 42]) -> Self {
        let x = FieldElement::from_be_bytes(&bytes[..21]);
        let y = FieldElement::from_be_bytes(&bytes[21..]);
        VerifyingKey(Point::Affine(x, y))
    }

    /// A thin wrapper over [`Self::verify_digest`] - see that method, and the module doc's T-113
    /// note, for verifying a message too large to hold in memory whole.
    #[must_use]
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.verify_digest(&Kupyna256::digest(message), sig)
    }

    /// Verifies against an already-computed 32-byte Kupyna-256 digest directly - for messages
    /// hashed incrementally via `hazmat::kupyna::Kupyna256Hasher` rather than held whole in memory
    /// (see the module doc's T-113 note).
    #[must_use]
    pub fn verify_digest(&self, digest: &[u8; 32], sig: &Signature) -> bool {
        let g = Point::generator();
        signature::verify(digest, &sig.r, &sig.s, self.0, g)
    }
}

/// Deterministic ephemeral-nonce derivation (`DECISIONS.md` D-46): `e = reduce_mod_n(KMAC(key =
/// zero-padded d, message = hash || counter))`, retried with an incremented `counter` on the
/// ~`2^-163`-probability chance of a zero result or a hazmat-level degenerate rejection. `d`'s
/// 21-byte big-endian value is left-padded with zeros to `Kupyna256Kmac`'s required 32-byte key
/// length (`hazmat::kupyna_kmac`'s key length must equal its `mac_len`) - an embedding, not a
/// truncation, so no information about `d` is lost.
fn derive_nonce(d: Scalar, hash: &[u8; 32], counter: u8) -> Scalar {
    let mut key = [0u8; 32];
    key[11..].copy_from_slice(&d.to_be_bytes());
    let mut message = [0u8; 33];
    message[..32].copy_from_slice(hash);
    message[32] = counter;

    let Ok(mac) = Kupyna256Kmac::mac(&key, &message) else {
        unreachable!("key is always exactly 32 bytes, Kupyna256Kmac's required length")
    };
    key.zeroize();
    Scalar::reduce_wide_bytes(&mac)
}
