//! `crypto_box` equivalent at `l(p)=512` (E512/1, `docs/TASKS.md` T-193) - direct sibling of
//! [`crate::crypto_box`] (`l(p)=256`, T-178) at this curve size's own widths. Matches this
//! project's established per-curve-size sibling-module precedent (`hazmat::dstu9041::curve512`
//! etc., D-181), not a generic-over-width merge.
//!
//! # Seed width - fixed at 32 bytes, not `l(p)=512`'s full 424-bit KEM capacity
//!
//! `crypto_box`'s own `embed_seed` (`l(p)=256`, `SEED_LEN = L_MAX_P/8 = 25`) does not generalize
//! here: `l(p)=512`'s `L_MAX_P = 424` bits (53 bytes) exceeds `Kupyna256Kdf`'s 32-byte input
//! width, so a literal copy-paste underflows. `docs/DECISIONS.md` D-182 resolved this: the seed
//! stays a fixed 32 bytes (`Kupyna256Kdf`'s own native width, no embedding/padding step needed at
//! all), wrapped via `dstu9041_encrypt(&seed, 256, ...)` (`message_bits` fixed at `256`, not
//! `L_MAX_P`). `open` requires the recovered bit length to be exactly `256` before trusting the
//! recovered seed - confirmed against `message512.rs` directly (not assumed) that `decrypt`
//! genuinely returns the encryptor-supplied bit length, not the buffer's fixed width (D-182).
//! Leaving most of `L_MAX_P`'s 424 bits of KEM capacity unused is deliberate: the seed only ever
//! needs to reach `Kupyna256Kdf`'s fixed input, matching `crypto_box`'s own "asymmetric step only
//! ever establishes key material" framing.
//!
//! # `PublicKey` is 64 bytes - the curve point's `x`-coordinate only
//!
//! Independently re-derived for E512/1 rather than assumed to carry over from `crypto_box`'s own
//! `l(p)=256` argument (this project's standing "don't assume a security argument carries over
//! unchecked" discipline, D-176/D-178's own precedent): the compression-safety argument is a
//! curve-family property (twisted Edwards negation `-(x,y) = (x,-y)` in this standard's own
//! swapped-Edwards convention), not a `p`/`d`/`n`-value-dependent one, so it holds identically for
//! E512/1 - `x_T = x_{-T}` for any point `T`, hence `k*(-Q) = -(k*Q)` gives the same
//! `kappa = x_{epsilon*Q}` regardless of which square-root branch
//! [`crate::hazmat::dstu9041::curve512::point_from_x`] returns. `PublicKey::from_bytes` reuses
//! that function's own rejection gauntlet directly, not a second copy.
//!
//! # Error collapsing, wire format
//!
//! Same posture as [`crate::crypto_box`] - [`OpenError`] deliberately does not distinguish a KEM
//! failure from a secretstream tag failure (D-56/D-63 precedent); only [`OpenError::Truncated`]
//! stays separate. Wire format: `dstu9041_ciphertext (256 bytes) || secretstream_header (32
//! bytes) || ciphertext (message.len() bytes) || tag (16 bytes)`.
//!
//! A `box-open`-length-valid `l(p)=512` sealed blob also clears [`crate::crypto_box::open`]'s own
//! `MIN_LEN` check (176 bytes) and vice versa - both fall through to their own
//! `InvalidCiphertext`/authentication-failure path rather than a distinct "wrong curve size"
//! error. Defensible under the shared error-collapsing posture (recorded here, not left to be
//! found by surprise): a curve-size mismatch is just another way for the KEM decrypt to fail.
//!
//! # Provenance
//!
//! Not itself DSTU-specified, like `crypto_box` - no vector oracle exists or ever will for this
//! composite; verified by property/tamper/misuse tests only (`tests/crypto_box512.rs`).
//! `hazmat::dstu9041::encryption512` itself remains verified against Додаток Г.3 (T-192).

use crate::crypto_secretstream::{Key, PullState, PushState, SecretstreamError, Tag};
use crate::hazmat::dstu9041::curve512::{base_point, is_valid_scalar, point_from_x, Point};
use crate::hazmat::dstu9041::encryption512::{
    decrypt as dstu9041_decrypt, encrypt as dstu9041_encrypt,
};
use crate::hazmat::dstu9041::fp512::from_candidate_bytes;
use crate::randombytes::{randombytes_buf, RandomError};
use core::fmt;
use zeroize::Zeroize;

/// Fixed seed width - `Kupyna256Kdf`'s own native input size, see the module doc's "Seed width"
/// section for why this, not `l(p)=512`'s full `L_MAX_P` capacity, is correct.
const SEED_LEN: usize = 32;
/// The fixed `message_bits` value passed to `dstu9041_encrypt`/checked on `dstu9041_decrypt` -
/// `SEED_LEN * 8`, deliberately far below `L_MAX_P` (424).
const SEED_BITS: usize = SEED_LEN * 8;
const KEM_CIPHERTEXT_LEN: usize = 256;
const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Domain-separation context for the seed-to-stream-key derivation - distinct from `crypto_box`'s
/// own `KDF_CONTEXT` (different KEM ciphertext shape, different `PublicKey`/`SecretKey` widths -
/// a caller using both `crypto_box` and `crypto_box512` must never be able to conflate contexts).
const KDF_CONTEXT: &[u8; 8] = b"cryptbx5";

use crate::hazmat::kupyna_kdf::Kupyna256Kdf;

/// `crypto_box512` can fail while sealing for one reason: the OS CSPRNG.
#[derive(Debug)]
pub enum SealError {
    Random(RandomError),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Random(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for SealError {}

impl From<RandomError> for SealError {
    fn from(e: RandomError) -> Self {
        SealError::Random(e)
    }
}

/// `crypto_box512` can fail while opening for reasons beyond a wrong key.
#[derive(Debug)]
pub enum OpenError {
    /// `sealed` is shorter than a KEM ciphertext plus a secretstream header and tag (304 bytes) -
    /// too short to have ever been produced by [`seal`].
    Truncated,
    /// Any late-stage failure: wrong secret key, a tampered KEM prefix/header/ciphertext/tag, or a
    /// recovered seed whose bit length isn't exactly `SEED_BITS` - deliberately collapsed, see the
    /// module doc's "Error collapsing" section.
    InvalidCiphertext,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Truncated => write!(f, "input too short to contain a sealed message"),
            OpenError::InvalidCiphertext => write!(f, "authentication failed"),
        }
    }
}

impl core::error::Error for OpenError {}

/// Rejection-samples a scalar in `{2, ..., n-2}` (`is_valid_scalar`) - shared by
/// [`SecretKey::generate`] (a long-term key) and [`seal`] (a fresh ephemeral key per call).
/// Mirrors `crypto_box`'s own `random_valid_scalar`: zeroize each rejected candidate immediately,
/// never a modulo reduction (`n` is not a power of two - that would bias small residues).
fn random_valid_scalar() -> Result<[u8; 64], RandomError> {
    loop {
        let mut candidate = [0u8; 64];
        randombytes_buf(&mut candidate)?;
        if is_valid_scalar(&candidate) {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
}

/// A `crypto_box512` private key - the DSTU 9041 scalar `e`.
pub struct SecretKey([u8; 64]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    /// Builds a secret key from a big-endian 64-byte scalar. Returns `None` if it's outside the
    /// valid range `{2, ..., n-2}` (`hazmat::dstu9041::curve512::is_valid_scalar`).
    #[must_use]
    pub fn from_bytes(e: &[u8; 64]) -> Option<Self> {
        if is_valid_scalar(e) {
            Some(SecretKey(*e))
        } else {
            None
        }
    }

    /// Generates a fresh secret key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] if the OS CSPRNG fails while drawing a candidate.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn generate() -> Result<Self, RandomError> {
        random_valid_scalar().map(SecretKey)
    }

    /// Returns `e`'s big-endian 64-byte encoding, so a generated key can be persisted and later
    /// reloaded via [`Self::from_bytes`]. The caller becomes responsible for zeroizing the
    /// returned array once done with it.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(base_point().scalar_multiply(&self.0))
    }
}

/// A `crypto_box512` public key - a curve point's `x`-coordinate only (64 bytes), see the module
/// doc's own section on why this compression is safe.
#[derive(Clone, Copy)]
pub struct PublicKey(Point);

impl PublicKey {
    /// Reconstructs a public key from its compressed 64-byte `x`-coordinate encoding. Returns
    /// `None` if `bytes` isn't a valid field element, or doesn't reconstruct to a point inside the
    /// base point's own prime-order subgroup (`curve512::point_from_x`'s own rejection gauntlet).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        from_candidate_bytes(bytes)
            .and_then(point_from_x)
            .map(PublicKey)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.x.to_be_bytes()
    }
}

/// Encrypts `message` (any length) to `recipient`, drawing a fresh random seed and ephemeral key
/// internally - see the module doc's "Seed width" section.
///
/// # Errors
///
/// Returns [`SealError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn seal(message: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, SealError> {
    let mut seed = [0u8; SEED_LEN];
    randombytes_buf(&mut seed)?;

    let mut epsilon = random_valid_scalar()?;
    // Unreachable in practice: `seed` is always exactly SEED_LEN bytes at message_bits=SEED_BITS
    // (can't trigger `InvalidMessage`), and `epsilon` is already validated by
    // `random_valid_scalar` (can't trigger `InvalidEphemeralKey`).
    let Ok(kem_ciphertext) = dstu9041_encrypt(&seed, SEED_BITS, recipient.0, &epsilon) else {
        unreachable!("seed/epsilon are always valid by construction")
    };
    epsilon.zeroize();

    let mut stream_key_bytes = Kupyna256Kdf::derive_subkey(&seed, 0, KDF_CONTEXT);
    seed.zeroize();
    let key = Key::from_bytes(stream_key_bytes);
    stream_key_bytes.zeroize();

    let (mut push, header) = match PushState::init(&key) {
        Ok(ok) => ok,
        Err(SecretstreamError::Random(e)) => return Err(SealError::Random(e)),
        // `PushState::init`'s only documented failure mode is the OS CSPRNG call for its header -
        // see `crypto_secretstream::SecretstreamError`'s own doc comment.
        Err(_) => unreachable!("PushState::init only ever fails via SecretstreamError::Random"),
    };

    let mut ciphertext = vec![0u8; message.len()];
    let Ok(tag) = push.push(Tag::Final, message, &mut ciphertext) else {
        unreachable!(
            "ciphertext.len() == message.len() by construction; stream freshly initialized, \
             never finalized yet"
        )
    };

    let mut out = Vec::with_capacity(KEM_CIPHERTEXT_LEN + HEADER_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&kem_ciphertext);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts `sealed` (as produced by [`seal`]) under `secret`.
///
/// # Errors
///
/// Returns [`OpenError::Truncated`] if `sealed` is shorter than the minimum possible length, or
/// [`OpenError::InvalidCiphertext`] for any other failure - see the module doc's "Error collapsing"
/// section.
pub fn open(sealed: &[u8], secret: &SecretKey) -> Result<Vec<u8>, OpenError> {
    const MIN_LEN: usize = KEM_CIPHERTEXT_LEN + HEADER_LEN + TAG_LEN;
    if sealed.len() < MIN_LEN {
        return Err(OpenError::Truncated);
    }

    let mut kem_ciphertext = [0u8; KEM_CIPHERTEXT_LEN];
    kem_ciphertext.copy_from_slice(&sealed[..KEM_CIPHERTEXT_LEN]);
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&sealed[KEM_CIPHERTEXT_LEN..KEM_CIPHERTEXT_LEN + HEADER_LEN]);
    let ciphertext_len = sealed.len() - MIN_LEN;
    let ciphertext_start = KEM_CIPHERTEXT_LEN + HEADER_LEN;
    let ciphertext = &sealed[ciphertext_start..ciphertext_start + ciphertext_len];
    let tag = &sealed[ciphertext_start + ciphertext_len..];

    let (m_tilde, bit_len) =
        dstu9041_decrypt(&kem_ciphertext, &secret.0).map_err(|_| OpenError::InvalidCiphertext)?;
    // Defense in depth: an honestly-sealed ciphertext always has bit_len == SEED_BITS (the hash
    // check inside `decrypt` already makes forging a different-but-valid bit_length as hard as a
    // Kupyna-256 preimage), but this is never trusted blindly.
    if bit_len != SEED_BITS {
        let mut m_tilde = m_tilde;
        m_tilde.zeroize();
        return Err(OpenError::InvalidCiphertext);
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&m_tilde[m_tilde.len() - SEED_LEN..]);
    let mut m_tilde = m_tilde;
    m_tilde.zeroize();

    let mut stream_key_bytes = Kupyna256Kdf::derive_subkey(&seed, 0, KDF_CONTEXT);
    seed.zeroize();
    let key = Key::from_bytes(stream_key_bytes);
    stream_key_bytes.zeroize();

    let mut pull = PullState::init(&key, &header);
    let mut plaintext = vec![0u8; ciphertext_len];
    pull.pull(Tag::Final.to_byte(), ciphertext, tag, &mut plaintext)
        .map_err(|_| OpenError::InvalidCiphertext)?;

    Ok(plaintext)
}
