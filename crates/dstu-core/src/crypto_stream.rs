//! `crypto_stream` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` roadmap Step 3 item 3, `docs/DECISIONS.md` D-67) - a libsodium-ergonomics wrapper over
//! [`hazmat::strumok::Strumok256`](crate::hazmat::strumok::Strumok256).
//!
//! # No authentication whatsoever
//!
//! Strumok is a bare keystream generator - XOR-ing it into a message provides confidentiality
//! only, never integrity (`hazmat::strumok`'s own module doc, `docs/release-readiness.md`'s
//! "Streaming audio, confidentiality only" use-case row). Unlike [`crate::crypto_secretbox`],
//! [`decrypt`] **never fails on tampered input** - it has no tag to check, so a modified
//! `sealed` value decrypts to different, silently-wrong plaintext instead of an error, the same
//! documented no-integrity-by-design property `hazmat::kalyna_xts` already has
//! (`tests/kalyna_xts.rs`'s `tampered_ciphertext_does_not_error_but_produces_garbage`). This is
//! why this module's functions are named `encrypt`/`decrypt`, not `seal`/`open` -
//! `crypto_secretbox` reserves `seal`/`open` specifically to signal "this authenticates," and
//! this primitive does not. Callers needing integrity must wrap each message in
//! [`crate::crypto_secretbox`] (or a chunked `crypto_secretstream`, once T-40 exists) instead of,
//! or on top of, this module - never rely on this module alone where tamper-detection matters.
//!
//! # Hidden IV
//!
//! Confirmed with the project owner (roadmap Step 3 item 3 was left as an explicit open fork,
//! unlike this roadmap's other named forks): the IV is generated internally from the OS CSPRNG,
//! the same choice `crypto_secretbox` made for its nonce (D-51), never caller-supplied. This
//! matters more here than for most primitives: `hazmat::strumok`'s own module doc carries a
//! "never reuse the same key+IV pair" warning, backed by a dedicated test
//! (`reusing_key_and_iv_leaks_plaintext_xor`, `docs/TASKS.md` T-103) pinning the catastrophic two-time-
//! pad property directly - reusing a key+IV pair XORs the two plaintexts together, recoverable
//! without ever breaking the cipher itself. Hiding IV generation removes that footgun from the
//! caller's surface entirely, at the cost of matching libsodium's own lower-level
//! `crypto_stream_xor(c, m, mlen, n, k)` C signature (`n` is a caller-supplied parameter there) -
//! a deliberate divergence, not an oversight, matching `crypto_secretbox`'s own precedent of
//! prioritizing misuse-resistance over raw-API parity (D-47's tie-breaker).
//!
//! # Variant
//!
//! Only `Strumok256` is exposed here (D-47's "delete the knob", matching `crypto_auth`/
//! `crypto_kdf`'s single-256-bit-variant choice, D-66) - `Strumok512` stays `hazmat`-only.
//!
//! # Provenance
//!
//! Inherits `hazmat::strumok`'s own D-18 status: vectors are UAPKI-attributed, not confirmed
//! against the primary DSTU 8845:2019 text.
//!
//! # Example
//!
//! Confidentiality only, **no integrity** (see the "No authentication whatsoever" section above) -
//! prefer [`crate::crypto_secretbox`]/[`crate::crypto_secretstream`] unless you specifically need a
//! bare keystream cipher and are handling authentication yourself. Note what tampering does here,
//! in contrast to `crypto_secretbox`'s example above: `decrypt` never errors, it just returns
//! different, silently-wrong plaintext.
//!
//! ```rust
//! use dstu_core::crypto_stream::{encrypt, decrypt, Key};
//!
//! let key = Key::generate().expect("OS CSPRNG should not fail");
//! let sealed = encrypt(&key, b"message").expect("OS CSPRNG should not fail");
//! let opened = decrypt(&key, &sealed).expect("sealed is at least IV-length");
//! assert_eq!(opened, b"message");
//!
//! // Tampering is not detected - decrypt "succeeds" with garbage plaintext instead of erroring.
//! let mut tampered = sealed.clone();
//! let last = tampered.len() - 1;
//! tampered[last] ^= 1;
//! let garbage = decrypt(&key, &tampered).expect("still at least IV-length, so still Ok");
//! assert_ne!(garbage, b"message");
//! ```

use crate::hazmat::strumok::Strumok256;
use crate::randombytes::{randombytes_buf, RandomError};
use core::fmt;
use zeroize::Zeroize;

const IV_LEN: usize = 32;

/// `crypto_stream` can fail only if the OS CSPRNG fails while generating a fresh IV - there is no
/// tag to mismatch (see the module doc's "No authentication" section).
#[derive(Debug)]
pub enum StreamError {
    /// The input to [`decrypt`] is shorter than an IV (32 bytes) - too short to have ever been
    /// produced by [`encrypt`].
    Truncated,
    /// The OS CSPRNG failed while generating an IV (see [`crate::randombytes`]).
    Random(RandomError),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Truncated => write!(f, "input too short to contain an IV"),
            StreamError::Random(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for StreamError {}

impl From<RandomError> for StreamError {
    fn from(e: RandomError) -> Self {
        StreamError::Random(e)
    }
}

/// A `crypto_stream` key. Always exactly 32 bytes - `Strumok256`'s key length (see the module
/// doc).
pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    /// Generates a fresh key from the OS CSPRNG - libsodium's `crypto_stream_keygen` equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] if the OS CSPRNG fails.
    pub fn generate() -> Result<Self, RandomError> {
        let mut bytes = [0u8; 32];
        randombytes_buf(&mut bytes)?;
        Ok(Key(bytes))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv (32 bytes) || ciphertext (plaintext.len() bytes)` - no authentication (see the module
/// doc's "No authentication" section).
///
/// # Errors
///
/// Returns [`StreamError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>, StreamError> {
    let mut iv = [0u8; IV_LEN];
    randombytes_buf(&mut iv)?;

    let mut buf = plaintext.to_vec();
    let mut cipher = Strumok256::new(key.as_bytes(), &iv);
    cipher.apply_keystream(&mut buf);

    let mut out = Vec::with_capacity(IV_LEN + buf.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Reverses [`encrypt`] under `key` - XOR is its own inverse
/// ([`hazmat::strumok`](crate::hazmat::strumok)'s `apply_keystream`), so this recovers the
/// original plaintext bit-for-bit when `sealed` is exactly [`encrypt`]'s own output. **Never
/// fails on tampered input** - see the module doc's "No authentication" section; a modified
/// `sealed` decrypts to different, silently-wrong plaintext, not an error.
///
/// # Errors
///
/// Returns [`StreamError::Truncated`] if `sealed` is shorter than an IV (32 bytes) - the only
/// possible error, since there is no tag to fail.
pub fn decrypt(key: &Key, sealed: &[u8]) -> Result<Vec<u8>, StreamError> {
    if sealed.len() < IV_LEN {
        return Err(StreamError::Truncated);
    }

    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&sealed[..IV_LEN]);

    let mut buf = sealed[IV_LEN..].to_vec();
    let mut cipher = Strumok256::new(key.as_bytes(), &iv);
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}
