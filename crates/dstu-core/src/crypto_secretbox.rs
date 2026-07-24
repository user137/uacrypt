//! `crypto_secretbox` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `TASKS.md` T-37, `DECISIONS.md` D-51) - a single fixed `hazmat::kalyna_ccm::Kalyna256_256Ccm`
//! construction (D-47's tie-breaker rule: no algorithm knob when one safe default exists) with an
//! internally-generated nonce (never caller-supplied, extending the pattern `uacrypt kalyna-ccm
//! encrypt`'s CLI layer already used, D-40/T-82) and a combined `nonce || ciphertext || tag` wire
//! format, matching libsodium's own `crypto_secretbox_easy` ergonomics.
//!
//! # This is bounded to messages of at most [`MAX_MESSAGE_LEN`] (255) bytes
//!
//! Not a general-purpose secretbox. `hazmat::kalyna_ccm` caps its plaintext/AAD at 255 bytes each
//! (D-41 - `ccm_padd`'s header encodes both lengths as a single byte, a real construction limit,
//! not a choice made here). [`seal`] returns [`SecretboxError::MessageTooLong`] on oversized
//! input, never truncates. `crypto_secretstream` (`TASKS.md` T-40) remains the tracked follow-up
//! for arbitrary-length messages; this module does not attempt it.
//!
//! # No AAD
//!
//! libsodium's own `crypto_secretbox` has no associated-data parameter (that's `crypto_aead`'s
//! job) - `hazmat::kalyna_ccm` takes AAD, but exposing it here would quietly turn this into a
//! different primitive than its name promises. Empty AAD is passed to `kalyna_ccm` internally.
//!
//! # Provenance
//!
//! Inherits `hazmat::kalyna_ccm`'s own provisional status (D-41): not yet confirmed against the
//! primary DSTU 7624:2014 text, dual-oracle-cited (UAPKI + Bouncy Castle vectors) in the meantime.
//! `Kalyna256_256Ccm` was chosen over the other four Kalyna-CCM variants as the sole construction
//! here (256-bit key, the widest nonce available at that key size, best random-nonce safety
//! margin) - see D-51 for the full reasoning, including why the `Strength`-enum precedent from
//! `crypto_pwhash` does not apply (a Kalyna variant is exactly the knob D-47 says to delete, not a
//! genuine per-context tradeoff the caller must make).

use crate::hazmat::kalyna_ccm::{CcmError, Kalyna256_256Ccm};
use crate::randombytes::{randombytes_buf, RandomError};
use core::fmt;
use zeroize::Zeroize;

const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// The sourced limit inherited from `hazmat::kalyna_ccm::MAX_PLAINTEXT_LEN` (D-41) - see the
/// module doc's "This is bounded to..." section.
pub use crate::hazmat::kalyna_ccm::MAX_PLAINTEXT_LEN as MAX_MESSAGE_LEN;

/// `crypto_secretbox` can fail for reasons beyond a wrong key.
#[derive(Debug)]
pub enum SecretboxError {
    /// `plaintext` (to [`seal`]) or the recovered ciphertext (from [`open`]) exceeds
    /// [`MAX_MESSAGE_LEN`].
    MessageTooLong,
    /// The input to [`open`] is shorter than a nonce plus a tag (48 bytes) - too short to have
    /// ever been produced by [`seal`].
    Truncated,
    /// Authentication failed: wrong key, or `sealed` was tampered with.
    TagMismatch,
    /// The OS CSPRNG failed while generating a nonce (see [`crate::randombytes`]).
    Random(RandomError),
}

impl fmt::Display for SecretboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretboxError::MessageTooLong => {
                write!(f, "message exceeds the {MAX_MESSAGE_LEN}-byte limit")
            }
            SecretboxError::Truncated => write!(f, "input too short to contain a nonce and tag"),
            SecretboxError::TagMismatch => write!(f, "authentication failed"),
            SecretboxError::Random(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for SecretboxError {}

impl From<RandomError> for SecretboxError {
    fn from(e: RandomError) -> Self {
        SecretboxError::Random(e)
    }
}

/// A `crypto_secretbox` key. Always exactly 32 bytes - `Kalyna256_256Ccm`'s key length, this
/// module's one fixed construction (see the module doc).
pub struct SecretKey([u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    /// Generates a fresh key from the OS CSPRNG - libsodium's `crypto_secretbox_keygen`
    /// equivalent, so "how do I make a key" is never a caller decision.
    ///
    /// # Errors
    ///
    /// Returns [`SecretboxError::Random`] if the OS CSPRNG fails.
    pub fn generate() -> Result<Self, SecretboxError> {
        let mut bytes = [0u8; 32];
        randombytes_buf(&mut bytes)?;
        Ok(SecretKey(bytes))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypts and authenticates `plaintext` under `key`, drawing a fresh random nonce internally.
/// Returns `nonce (32 bytes) || ciphertext (plaintext.len() bytes) || tag (16 bytes)` - see the
/// module doc's "This is bounded to..." section for the 255-byte cap.
///
/// # Errors
///
/// Returns [`SecretboxError::MessageTooLong`] if `plaintext` exceeds [`MAX_MESSAGE_LEN`], or
/// [`SecretboxError::Random`] if the OS CSPRNG fails.
pub fn seal(key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, SecretboxError> {
    if plaintext.len() > MAX_MESSAGE_LEN {
        return Err(SecretboxError::MessageTooLong);
    }

    let mut nonce = [0u8; NONCE_LEN];
    randombytes_buf(&mut nonce)?;

    let cipher = Kalyna256_256Ccm::new(key.as_bytes());
    let mut buf = plaintext.to_vec();
    let Ok(tag) = cipher.seal_in_place(&nonce, &[], &mut buf) else {
        unreachable!("plaintext length checked above; AAD is always empty, within its own limit")
    };

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len() + TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Verifies and decrypts `sealed` (as produced by [`seal`]) under `key`.
///
/// # Errors
///
/// Returns [`SecretboxError::Truncated`] if `sealed` is shorter than a nonce plus a tag,
/// [`SecretboxError::MessageTooLong`] if the recovered ciphertext exceeds [`MAX_MESSAGE_LEN`], or
/// [`SecretboxError::TagMismatch`] if authentication fails (wrong key, or `sealed` was tampered
/// with) - `sealed` is never partially trusted on a mismatch.
pub fn open(key: &SecretKey, sealed: &[u8]) -> Result<Vec<u8>, SecretboxError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(SecretboxError::Truncated);
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ciphertext_len = sealed.len() - NONCE_LEN - TAG_LEN;
    let mut buf = sealed[NONCE_LEN..NONCE_LEN + ciphertext_len].to_vec();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&sealed[NONCE_LEN + ciphertext_len..]);

    let cipher = Kalyna256_256Ccm::new(key.as_bytes());
    cipher
        .open_in_place(&nonce, &[], &mut buf, &tag)
        .map_err(|e| match e {
            CcmError::PlaintextTooLong => SecretboxError::MessageTooLong,
            CcmError::TagMismatch => SecretboxError::TagMismatch,
            CcmError::AadTooLong => {
                unreachable!("AAD is always empty, within its own limit")
            }
        })?;
    Ok(buf)
}
