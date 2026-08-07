//! `crypto_box` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` T-178) - public-key encryption over `hazmat::dstu9041` (`l(p)=256`, E256/1
//! only, T-177).
//!
//! # Hybrid via KDF - why, not just "how"
//!
//! `hazmat::dstu9041`'s `l(p)=256` variant caps a single ciphertext's payload at `L_MAX_P` = 200
//! bits (25 bytes, Table 1) - far below this project's existing 32-byte symmetric keys
//! (`crypto_secretbox::SecretKey`, `crypto_secretstream::Key`). This is not a defect: every
//! asymmetric-encryption standard of this shape (RSA-OAEP, ECIES, RSA-KEM) is a **KEM**, meant to
//! wrap a short secret, not to encrypt bulk data directly - OpenSSL's own `EVP_Seal*`/`EVP_Open*`
//! ("digital envelope") and libsodium's `crypto_box_seal` both follow exactly this shape: the
//! asymmetric step only ever establishes key material, a symmetric cipher does the actual work.
//! `seal` draws a fresh random 25-byte (200-bit, `L_MAX_P` exactly) seed, wraps it to the
//! recipient with `hazmat::dstu9041::encryption::encrypt`, then derives a 32-byte
//! `crypto_secretstream::Key` from that seed via `hazmat::kupyna_kdf::Kupyna256Kdf::derive_subkey`
//! (embedding the 25-byte seed into the low-order bytes of a zero-padded 32-byte buffer -
//! `crypto_sign::derive_nonce`'s own "an embedding, not a truncation, no information lost"
//! precedent - rather than calling `hazmat::kupyna_kdf` on an already-32-byte key, which this
//! seed isn't). `crypto_secretstream` then encrypts the actual message, of any length, in one
//! `Tag::Final` chunk (`seal`/`open` are one-shot, matching `crypto_secretbox`'s own `Vec<u8>`
//! convention - a later genuinely multi-chunk `seal_stream`/`open_stream` pair could reuse this
//! same KEM-prefix format without changing it).
//!
//! Wire format: `dstu9041_ciphertext (128 bytes) || secretstream_header (32 bytes) ||
//! ciphertext (message.len() bytes) || tag (16 bytes)`.
//!
//! # `PublicKey` is 32 bytes - the curve point's `x`-coordinate only
//!
//! Not `x || y` (64 bytes). This is safe by an explicit group-theory argument, not an assumption:
//! this curve's negation is `-(x,y) = (x,-y)` (the swapped-Edwards form, `docs/pseudocode/
//! dstu9041.md`), so `x` never distinguishes a point `Q` from its negation `-Q`, and `x_T = x_{-T}`
//! holds for any point `T` on this curve. Since `k*(-Q) = -(k*Q)` for any scalar `k`, the two
//! possible reconstructions of `Q` from just `x_Q` give the *same* `kappa = x_{epsilon*Q}` on
//! `seal`'s own encrypt step, regardless of which square-root branch
//! [`crate::hazmat::dstu9041::curve256::point_from_x`] happens to return - see that function's own
//! doc comment, and `tests/dstu9041_curve.rs`'s `point_from_x_gives_same_kappa_regardless_of_sqrt_branch`
//! for the arithmetic proof. `PublicKey::from_bytes` runs the exact same reconstruction gauntlet
//! `hazmat::dstu9041::encryption::decrypt` already runs (reject `x in {0,1,p-1}`, reject
//! `x^2=a*d^-1`, `euler_criterion` before `sqrt`, subgroup check) via that shared helper - not a
//! second, independently-maintained copy of a security-critical check.
//!
//! # Error collapsing
//!
//! [`OpenError`] deliberately does not distinguish a KEM failure from a secretstream tag failure
//! from a recovered-but-wrong-length seed - same padding-oracle-avoidance posture as
//! `hazmat::dstu9041::encryption::DecryptError` (D-56/D-63 precedent). Only [`OpenError::Truncated`]
//! (a public wire-length check, no secret-dependent data involved) stays a separate variant.
//!
//! # Provenance
//!
//! This composite construction (KEM + KDF + secretstream) is not itself DSTU-specified - like
//! `crypto_secretstream` (D-68), there is no vector oracle for it, ever; verified by
//! property/tamper/misuse tests only. `hazmat::dstu9041::encryption` itself remains verified
//! against the standard's own worked example (T-177).
//!
//! # Example
//!
//! ```rust
//! use dstu_core::crypto_box::{seal, open, SecretKey};
//!
//! # if cfg!(miri) { return; } // several 256-iteration curve256::Point::scalar_multiply calls
//! # // (keygen, KEM encrypt/decrypt) - minutes each under Miri's interpreter, same reasoning as
//! # // crypto_sign's own doctest guard; type-checked normally, just not executed there.
//! let secret = SecretKey::generate().expect("OS CSPRNG should not fail");
//! let public = secret.public_key(); // safe to share/publish
//!
//! let sealed = seal(b"a message for the public key's holder only", &public)
//!     .expect("OS CSPRNG should not fail");
//! let opened = open(&sealed, &secret).expect("authentic ciphertext under the matching key");
//! assert_eq!(opened, b"a message for the public key's holder only");
//!
//! // Tampering with the sealed blob (KEM prefix, header, ciphertext, or tag) is detected.
//! let mut tampered = sealed.clone();
//! let last = tampered.len() - 1;
//! tampered[last] ^= 1;
//! assert!(open(&tampered, &secret).is_err());
//! ```

use crate::crypto_secretstream::{Key, PullState, PushState, SecretstreamError, Tag};
use crate::hazmat::dstu9041::curve256::{base_point, is_valid_scalar, point_from_x, Point};
use crate::hazmat::dstu9041::encryption::{
    decrypt as dstu9041_decrypt, encrypt as dstu9041_encrypt,
};
use crate::hazmat::dstu9041::fp256::from_candidate_bytes;
use crate::hazmat::dstu9041::message::L_MAX_P;
use crate::hazmat::kupyna_kdf::Kupyna256Kdf;
use crate::randombytes::{randombytes_buf, RandomError};
use core::fmt;
use zeroize::Zeroize;

const SEED_LEN: usize = L_MAX_P / 8;
const KEM_CIPHERTEXT_LEN: usize = 128;
const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Domain-separation context for the seed-to-stream-key derivation - distinct from every other
/// `Kupyna256Kdf::derive_subkey` call site in this crate (`crypto_kdf`'s own callers choose their
/// own contexts; this one is fixed since `crypto_box` has exactly one derivation to make).
const KDF_CONTEXT: &[u8; 8] = b"cryptbox";

/// `crypto_box` can fail while sealing for one reason: the OS CSPRNG.
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

/// `crypto_box` can fail while opening for reasons beyond a wrong key.
#[derive(Debug)]
pub enum OpenError {
    /// `sealed` is shorter than a KEM ciphertext plus a secretstream header and tag (176 bytes) -
    /// too short to have ever been produced by [`seal`].
    Truncated,
    /// Any late-stage failure: wrong secret key, a tampered KEM prefix/header/ciphertext/tag, or a
    /// recovered seed whose bit length isn't exactly `L_MAX_P` - deliberately collapsed, see the
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

/// Rejection-samples a scalar in `{2, ..., n-2}` (`is_valid_scalar`) - shared by [`SecretKey::generate`]
/// (a long-term key) and [`seal`] (a fresh ephemeral key per call). Mirrors
/// `crypto_sign::SigningKey::generate`'s own pattern: zeroize each rejected candidate immediately,
/// never a modulo reduction (`n` is not a power of two - that would bias small residues).
fn random_valid_scalar() -> Result<[u8; 32], RandomError> {
    loop {
        let mut candidate = [0u8; 32];
        randombytes_buf(&mut candidate)?;
        if is_valid_scalar(&candidate) {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
}

/// Embeds a 25-byte seed into the low-order bytes of a zero-padded 32-byte buffer - see the module
/// doc's "Hybrid via KDF" section for why this, not a fresh KDF variant, is the right fix for the
/// length mismatch.
fn embed_seed(seed: &[u8; SEED_LEN]) -> [u8; 32] {
    let mut embedded = [0u8; 32];
    embedded[32 - SEED_LEN..].copy_from_slice(seed);
    embedded
}

/// A `crypto_box` private key - the DSTU 9041 scalar `e`.
pub struct SecretKey([u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    /// Builds a secret key from a big-endian 32-byte scalar. Returns `None` if it's outside the
    /// valid range `{2, ..., n-2}` (`hazmat::dstu9041::curve256::is_valid_scalar`).
    #[must_use]
    pub fn from_bytes(e: &[u8; 32]) -> Option<Self> {
        if is_valid_scalar(e) {
            Some(SecretKey(*e))
        } else {
            None
        }
    }

    /// Generates a fresh secret key from the OS CSPRNG - libsodium's `crypto_box_keypair()`
    /// equivalent (its public-key half is [`Self::public_key`]).
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] if the OS CSPRNG fails while drawing a candidate.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn generate() -> Result<Self, RandomError> {
        random_valid_scalar().map(SecretKey)
    }

    /// Returns `e`'s big-endian 32-byte encoding, so a generated key can be persisted and later
    /// reloaded via [`Self::from_bytes`]. The caller becomes responsible for zeroizing the
    /// returned array once done with it.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(base_point().scalar_multiply(&self.0))
    }
}

/// A `crypto_box` public key - a curve point's `x`-coordinate only (32 bytes), see the module
/// doc's own section on why this compression is safe.
#[derive(Clone, Copy)]
pub struct PublicKey(Point);

impl PublicKey {
    /// Reconstructs a public key from its compressed 32-byte `x`-coordinate encoding. Returns
    /// `None` if `bytes` isn't a valid field element, or doesn't reconstruct to a point inside the
    /// base point's own prime-order subgroup (`curve256::point_from_x`'s own rejection gauntlet).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        from_candidate_bytes(bytes)
            .and_then(point_from_x)
            .map(PublicKey)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.x.to_be_bytes()
    }
}

/// Encrypts `message` (any length) to `recipient`, drawing a fresh random seed and ephemeral key
/// internally - see the module doc's "Hybrid via KDF" section.
///
/// # Errors
///
/// Returns [`SealError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn seal(message: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, SealError> {
    let mut seed = [0u8; SEED_LEN];
    randombytes_buf(&mut seed)?;

    let mut epsilon = random_valid_scalar()?;
    // Unreachable: `seed` is always exactly SEED_LEN bytes at message_bits=L_MAX_P (can't trigger
    // `InvalidMessage`), and `epsilon` is already validated by `random_valid_scalar` (can't
    // trigger `InvalidEphemeralKey`).
    let Ok(kem_ciphertext) = dstu9041_encrypt(&seed, L_MAX_P, recipient.0, &epsilon) else {
        unreachable!("seed/epsilon are always valid by construction")
    };
    epsilon.zeroize();

    let mut embedded = embed_seed(&seed);
    seed.zeroize();
    let mut stream_key_bytes = Kupyna256Kdf::derive_subkey(&embedded, 0, KDF_CONTEXT);
    embedded.zeroize();
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

    let (mut seed_padded, bit_len) =
        dstu9041_decrypt(&kem_ciphertext, &secret.0).map_err(|_| OpenError::InvalidCiphertext)?;
    // Defense in depth: an honestly-sealed ciphertext always has bit_len == L_MAX_P (the hash
    // check inside `decrypt` already makes forging a different-but-valid bit_length as hard as a
    // Kupyna-256 preimage), but this is never trusted blindly.
    if bit_len != L_MAX_P {
        seed_padded.zeroize();
        return Err(OpenError::InvalidCiphertext);
    }

    let mut embedded = embed_seed(&seed_padded);
    seed_padded.zeroize();
    let mut stream_key_bytes = Kupyna256Kdf::derive_subkey(&embedded, 0, KDF_CONTEXT);
    embedded.zeroize();
    let key = Key::from_bytes(stream_key_bytes);
    stream_key_bytes.zeroize();

    let mut pull = PullState::init(&key, &header);
    let mut plaintext = vec![0u8; ciphertext_len];
    pull.pull(Tag::Final.to_byte(), ciphertext, tag, &mut plaintext)
        .map_err(|_| OpenError::InvalidCiphertext)?;

    Ok(plaintext)
}
