//! `crypto_secretbox` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51) - a single fixed `hazmat::kalyna_gcm::Kalyna256_256Gcm`
//! construction (D-47's tie-breaker rule: no algorithm knob when one safe default exists) with an
//! internally-generated nonce (never caller-supplied, extending the pattern `uacrypt kalyna-ccm
//! encrypt`'s CLI layer already used, D-40/T-82) and a combined
//! `version || nonce || ciphertext || tag` wire format, matching libsodium's own
//! `crypto_secretbox_easy` ergonomics. The 1-byte version (currently `2`; 0.3.x blobs had none,
//! T-232/D-202) lets a future format change fail with [`SecretboxError::UnsupportedVersion`]
//! instead of an unexplained [`SecretboxError::TagMismatch`].
//!
//! # No message-length cap
//!
//! Migrated from Kalyna-CCM to Kalyna-GCM 2026-07-25 (roadmap Step 3 item 1, `docs/DECISIONS.md`
//! D-63) - the original Kalyna-CCM construction capped plaintext/AAD at 255 bytes each (D-41,
//! `ccm_padd`'s header encoding). GCM encodes no length into its construction at all, so that cap
//! and `SecretboxError::MessageTooLong` are gone entirely, not just raised. This does not make
//! disk-file encryption memory-bounded, though: an AEAD tag needs the full plaintext/ciphertext,
//! so a large message still means a correspondingly large in-memory buffer (see `uacrypt`'s own
//! `run_secretbox_command` doc comment for the concrete consequence at the CLI layer).
//! `crypto_secretstream` (`docs/TASKS.md` T-40) remains the separately-tracked follow-up for a
//! genuinely chunked/streaming construction; this module still does not attempt that.
//!
//! # No AAD (caller-facing) - but the version, nonce and length are bound into the tag internally
//!
//! libsodium's own `crypto_secretbox` has no associated-data parameter (that's `crypto_aead`'s
//! job) - `hazmat::kalyna_gcm` takes AAD, but exposing it here would quietly turn this into a
//! different primitive than its name promises. No caller-supplied AAD exists.
//!
//! Internally, though, `seal`/`open` pass the nonce itself as `kalyna_gcm`'s AAD (never empty).
//! This is not optional: unlike NIST AES-GCM, DSTU 7624's Kalyna-GCM tag is computed purely from
//! AAD and ciphertext (`E_K(accumulator XOR length_block)`, D-56 divergence 3) and never mixes in
//! the IV/nonce at all - the nonce only seeds the keystream. For a combined
//! `nonce || ciphertext || tag` blob, an unauthenticated nonce means an attacker can flip bits in
//! the nonce prefix of a sealed message and `open` will still "succeed", just against a different
//! (attacker-uncontrolled but unverified-as-original) keystream - a real tamper-evidence gap the
//! previous CCM-based construction did not have (CCM's B0 formatting block ties the nonce into its
//! CBC-MAC). Passing the nonce as AAD closes it using the construction's own designed mechanism
//! for authenticating out-of-band data, the same way a caller would bind a header to an AEAD tag.
//! Caught by `tampered_nonce_is_rejected` during this migration, not assumed - see `docs/DECISIONS.md`
//! D-63.
//!
//! The internal AAD is `version || nonce || (ciphertext_len as u64).to_le_bytes()`. The length was
//! added by T-232 (audit F-01, `docs/DECISIONS.md` D-200) because `kalyna_gcm` then tagged only the
//! padded ciphertext length, so `ct` and `ct || 80 00..` shared a tag. Since T-234 (D-204)
//! `kalyna_gcm` binds the true length itself, per DSTU 7624:2014 §12.2; the AAD keeps it as defence
//! in depth, so this format never depends on one hazmat detail for that property.
//!
//! # Provenance
//!
//! Inherits `hazmat::kalyna_gcm`'s provenance: checked against DSTU 7624:2014 (draft edition) §12.2
//! and its annex В.8 examples (T-234, D-204). Because this module's AAD is never block-aligned, its
//! tags differ from what UAPKI or Bouncy Castle 1.85 would compute (`docs/COMPATIBILITY.md`).
//! `Kalyna256_256Gcm` was chosen over the other four Kalyna-GCM variants as the sole construction
//! here (256-bit key, matching the previous CCM construction's key/nonce width exactly) - see D-51
//! for the fuller reasoning behind fixing one variant rather than exposing all five, including why
//! the `Strength`-enum precedent from `crypto_pwhash` does not apply (a Kalyna variant is exactly the knob D-47 says to delete, not a
//! genuine per-context tradeoff the caller must make). The 16-byte tag (truncated from GCM's own
//! full 32-byte tag, via the same prefix-comparison convention `hazmat::kalyna_gcm`/`kalyna_gmac`
//! already support) matches the previous construction's tag length and libsodium's own
//! `crypto_secretbox` tag size - a fixed choice, not a new knob.
//!
//! # Example
//!
//! Encrypts a whole in-memory message under a freshly generated key. `seal`/`open` protect both
//! confidentiality (nobody without the key can read the message) and integrity (`open` rejects
//! anything tampered with, rather than returning wrong plaintext) - see below for the "tampered
//! ciphertext is rejected" case, `docs/TASKS.md` T-120's own required failure-path example.
//!
//! ```rust
//! use dstu_core::crypto_secretbox::{seal, open, SecretKey};
//!
//! let key = SecretKey::generate().expect("OS CSPRNG should not fail");
//! let sealed = seal(&key, b"message").expect("OS CSPRNG should not fail");
//! let opened = open(&key, &sealed).expect("authentic ciphertext");
//! assert_eq!(opened, b"message");
//!
//! // Tampering with the sealed blob (ciphertext, tag, or nonce) is detected, not silently
//! // "decrypted" into wrong plaintext.
//! let mut tampered = sealed.clone();
//! let last = tampered.len() - 1;
//! tampered[last] ^= 1;
//! assert!(open(&key, &tampered).is_err());
//! ```

use crate::hazmat::kalyna_gcm::{GcmError, Kalyna256_256Gcm};
use crate::randombytes::{randombytes_buf, RandomError};
use core::fmt;
use zeroize::Zeroize;

/// Wire-format version, the blob's first byte (T-232; 0.3.x blobs had no version byte).
const FORMAT_VERSION: u8 = 2;
const NONCE_LEN: usize = 32;
const HEADER_LEN: usize = 1 + NONCE_LEN;
const TAG_LEN: usize = 16;

/// `crypto_secretbox` can fail for reasons beyond a wrong key.
#[derive(Debug)]
pub enum SecretboxError {
    /// The input to [`open`] is shorter than a version byte, a nonce and a tag (49 bytes) - too
    /// short to have ever been produced by [`seal`].
    Truncated,
    /// Authentication failed: wrong key, or `sealed` was tampered with.
    TagMismatch,
    /// The input to [`open`] starts with a format version byte this build does not read - a blob
    /// from an older or newer `crypto_secretbox` wire format, not a tampered one (the version byte
    /// is public and also bound into the tag).
    UnsupportedVersion,
    /// The OS CSPRNG failed while generating a nonce (see [`crate::randombytes`]).
    Random(RandomError),
}

impl fmt::Display for SecretboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretboxError::Truncated => write!(f, "input too short to contain a nonce and tag"),
            SecretboxError::TagMismatch => write!(f, "authentication failed"),
            SecretboxError::UnsupportedVersion => write!(f, "unsupported secretbox format version"),
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

/// `version || nonce || ciphertext_len as u64 LE` - binds the version, the nonce (D-63) and the
/// true ciphertext length into the tag. `hazmat::kalyna_gcm` binds the true length too since T-234
/// (D-204); the copy here is defence in depth from T-232 (audit F-01, D-200).
fn aad(nonce: &[u8; NONCE_LEN], ciphertext_len: usize) -> [u8; HEADER_LEN + 8] {
    let Ok(len) = u64::try_from(ciphertext_len) else {
        unreachable!("a slice length always fits in u64 on every supported target")
    };
    let mut aad = [0u8; HEADER_LEN + 8];
    aad[0] = FORMAT_VERSION;
    aad[1..HEADER_LEN].copy_from_slice(nonce);
    aad[HEADER_LEN..].copy_from_slice(&len.to_le_bytes());
    aad
}

/// Encrypts and authenticates `plaintext` under `key`, drawing a fresh random nonce internally.
/// Returns `version (1 byte) || nonce (32 bytes) || ciphertext (plaintext.len() bytes) || tag (16
/// bytes)` - no message-length cap (see the module doc comment).
///
/// # Errors
///
/// Returns [`SecretboxError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn seal(key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, SecretboxError> {
    let mut nonce = [0u8; NONCE_LEN];
    randombytes_buf(&mut nonce)?;

    let cipher = Kalyna256_256Gcm::new(key.as_bytes());
    let mut buf = vec![0u8; plaintext.len()];
    let Ok(full_tag) = cipher.encrypt(&nonce, &aad(&nonce, plaintext.len()), plaintext, &mut buf)
    else {
        unreachable!("ciphertext_out.len() == plaintext.len() by construction")
    };

    let mut out = Vec::with_capacity(HEADER_LEN + buf.len() + TAG_LEN);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&full_tag[..TAG_LEN]);
    Ok(out)
}

/// Verifies and decrypts `sealed` (as produced by [`seal`]) under `key`.
///
/// # Errors
///
/// Returns [`SecretboxError::Truncated`] if `sealed` is shorter than a version byte, a nonce and a
/// tag, [`SecretboxError::UnsupportedVersion`] if its version byte is not this build's format, or
/// [`SecretboxError::TagMismatch`] if authentication fails (wrong key, or `sealed` was tampered
/// with) - `sealed` is never partially trusted on a mismatch.
pub fn open(key: &SecretKey, sealed: &[u8]) -> Result<Vec<u8>, SecretboxError> {
    if sealed.len() < HEADER_LEN + TAG_LEN {
        return Err(SecretboxError::Truncated);
    }
    if sealed[0] != FORMAT_VERSION {
        return Err(SecretboxError::UnsupportedVersion);
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[1..HEADER_LEN]);
    let ciphertext_len = sealed.len() - HEADER_LEN - TAG_LEN;
    let ciphertext = &sealed[HEADER_LEN..HEADER_LEN + ciphertext_len];
    let tag = &sealed[HEADER_LEN + ciphertext_len..];

    let cipher = Kalyna256_256Gcm::new(key.as_bytes());
    let mut buf = vec![0u8; ciphertext_len];
    cipher
        .decrypt(&nonce, &aad(&nonce, ciphertext_len), ciphertext, tag, &mut buf)
        .map_err(|e| match e {
            GcmError::TagMismatch => SecretboxError::TagMismatch,
            GcmError::InvalidLength | GcmError::EmptyInput => {
                unreachable!(
                    "tag.len() == TAG_LEN (16, within 8..=block_bytes) and plaintext_out.len()                      == ciphertext.len() by construction"
                )
            }
        })?;
    Ok(buf)
}
