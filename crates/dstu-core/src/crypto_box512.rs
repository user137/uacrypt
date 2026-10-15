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
//! stays a fixed 32 bytes (the stream-key derivation's own native key width - originally
//! `Kupyna256Kdf`, `Kupyna256Kmac` since T-248 - no embedding/padding step needed at all),
//! wrapped via `dstu9041_encrypt(&seed, 256, ...)` (`message_bits` fixed at `256`, not
//! `L_MAX_P`). `open` requires the recovered bit length to be exactly `256` before trusting the
//! recovered seed - confirmed against `message512.rs` directly (not assumed) that `decrypt`
//! genuinely returns the encryptor-supplied bit length, not the buffer's fixed width (D-182).
//! Leaving most of `L_MAX_P`'s 424 bits of KEM capacity unused is deliberate: the seed only ever
//! needs to reach that derivation's fixed 32-byte key input, matching `crypto_box`'s own
//! "asymmetric step only ever establishes key material" framing.
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
//! and [`OpenError::UnsupportedVersion`] stay separate. Wire format (version 3, T-265/D-239):
//! `version (1 byte, 3) || dstu9041_ciphertext (256 bytes) || <D-208 stream file>`, written and
//! read by [`seal_stream`]/[`open_stream`] (bounded memory) or [`seal`]/[`open`] (one call); the
//! one-chunk version 2 of 0.4-0.6 is read only by [`open_v2_legacy`]. The stream key is
//! `Kupyna256Kmac(key = seed, message = b"cryptbx5" || version || kem_ciphertext ||
//! recipient_public_key)` - the same
//! RFC 9180 §4.1 `kem_context` binding as [`crate::crypto_box`] (T-248, `docs/DECISIONS.md`
//! D-201).
//!
//! A `box-open`-length-valid `l(p)=512` sealed blob also clears [`crate::crypto_box::open`]'s own
//! minimum-length check (183 bytes) - it falls through to its own
//! `InvalidCiphertext`/authentication-failure path rather than a distinct "wrong curve size"
//! error. Defensible under the shared error-collapsing posture (recorded here, not left to be
//! found by surprise): a curve-size mismatch is just another way for the KEM decrypt to fail.
//!
//! # Provenance
//!
//! Not itself DSTU-specified, like `crypto_box` - no vector oracle exists or ever will for this
//! composite; verified by property/tamper/misuse tests only (`tests/crypto_box512.rs`).
//! `hazmat::dstu9041::encryption512` itself remains verified against Додаток Г.3 (T-192).

use crate::crypto_secretstream::{
    open_all, seal_all, FileDecryptor, FileEncryptor, FileError, Key, PullState, Tag, CHUNK_BYTES,
    FILE_PREFIX_BYTES, RECORD_OVERHEAD_BYTES,
};
use crate::hazmat::dstu9041::curve512::{base_point, is_valid_scalar, point_from_x, Point};
use crate::hazmat::dstu9041::encryption512::{
    decrypt as dstu9041_decrypt, encrypt as dstu9041_encrypt,
};
use crate::hazmat::dstu9041::fp512::from_candidate_bytes;
use crate::hazmat::kupyna_kmac::Kupyna256Kmac;
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
/// Wire-format version, the sealed blob's first byte (T-265, D-239: a D-208 stream file follows
/// the KEM ciphertext).
const FORMAT_VERSION: u8 = 3;
/// The one-chunk format 0.4-0.6 wrote (T-232/T-248), read only by [`open_v2_legacy`].
const LEGACY_FORMAT_VERSION: u8 = 2;
/// `version || kem_ciphertext` - everything in front of the stream file.
const PREFIX_LEN: usize = 1 + KEM_CIPHERTEXT_LEN;
/// The bytes [`open_stream`] takes: the version byte and the KEM ciphertext.
pub const OPEN_STREAM_PREFIX_BYTES: usize = PREFIX_LEN;
/// The bytes [`seal_stream`] returns to write first: [`OPEN_STREAM_PREFIX_BYTES`], then the stream
/// file's own version byte and header.
pub const SEAL_STREAM_PREFIX_BYTES: usize = PREFIX_LEN + FILE_PREFIX_BYTES;
/// The shortest sealed message: the prefix and one empty `Final` record.
const MIN_SEALED_LEN: usize = SEAL_STREAM_PREFIX_BYTES + RECORD_OVERHEAD_BYTES;
const PUBLIC_KEY_LEN: usize = 64;
/// Domain-separation label for the stream-key derivation - distinct from `crypto_box`'s own label.
const KDF_LABEL: &[u8; 8] = b"cryptbx5";
const KDF_MESSAGE_LEN: usize = KDF_LABEL.len() + 1 + KEM_CIPHERTEXT_LEN + PUBLIC_KEY_LEN;

/// Derives the secretstream key as `Kupyna256Kmac(key = seed, message = label || version ||
/// kem_ciphertext || recipient_public_key)`, binding the KEM ciphertext and the recipient into
/// the key - RFC 9180 §4.1's DHKEM `kem_context = concat(enc, pkRm)` (T-248, `docs/DECISIONS.md`
/// D-201). A plain `Kupyna256Kdf::derive_subkey` can't carry this: its context is a fixed 8 bytes.
/// `version` is the wire format's, so a v2 and a v3 blob never share a stream key (D-239).
fn stream_key(
    seed: &[u8; 32],
    kem_ciphertext: &[u8; KEM_CIPHERTEXT_LEN],
    recipient: &[u8; PUBLIC_KEY_LEN],
    version: u8,
) -> Key {
    let mut message = [0u8; KDF_MESSAGE_LEN];
    let (label, rest) = message.split_at_mut(KDF_LABEL.len());
    label.copy_from_slice(KDF_LABEL);
    let (version_byte, rest) = rest.split_at_mut(1);
    version_byte[0] = version;
    let (kem, pk) = rest.split_at_mut(KEM_CIPHERTEXT_LEN);
    kem.copy_from_slice(kem_ciphertext);
    pk.copy_from_slice(recipient);
    let Ok(mut key_bytes) = Kupyna256Kmac::mac(seed, &message) else {
        unreachable!("seed is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
    };
    let key = Key::from_bytes(key_bytes);
    key_bytes.zeroize();
    key
}

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
    /// `sealed` is shorter than the prefix and one empty record (311 bytes; 305 for
    /// [`open_v2_legacy`]), or its stream ends before a verified `Final` record - it was cut.
    Truncated,
    /// `sealed` starts with a format version byte this build does not read - a blob from an older
    /// or newer wire format. The byte is public, so this reveals nothing about the key.
    UnsupportedVersion,
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
            OpenError::UnsupportedVersion => write!(f, "unsupported sealed-box format version"),
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

/// The KEM half of every sealing entry point: a fresh random 32-byte seed wrapped to `recipient`
/// under a fresh ephemeral key, and the stream key derived from it for wire format `version` -
/// see the module doc's "Seed width" section.
fn encapsulate(
    recipient: &PublicKey,
    version: u8,
) -> Result<([u8; KEM_CIPHERTEXT_LEN], Key), RandomError> {
    let mut seed = [0u8; SEED_LEN];
    randombytes_buf(&mut seed)?;
    let mut epsilon = match random_valid_scalar() {
        Ok(epsilon) => epsilon,
        Err(e) => {
            seed.zeroize();
            return Err(e);
        }
    };
    // Unreachable in practice: `seed` is always exactly SEED_LEN bytes at message_bits=SEED_BITS
    // (can't trigger `InvalidMessage`), and `epsilon` is already validated by
    // `random_valid_scalar` (can't trigger `InvalidEphemeralKey`).
    let Ok(kem_ciphertext) = dstu9041_encrypt(&seed, SEED_BITS, recipient.0, &epsilon) else {
        unreachable!("seed/epsilon are always valid by construction")
    };
    epsilon.zeroize();

    let key = stream_key(&seed, &kem_ciphertext, &recipient.to_bytes(), version);
    seed.zeroize();
    Ok((kem_ciphertext, key))
}

/// The KEM half of every opening entry point: recovers the seed under `secret` and derives the
/// stream key for wire format `version`. Every failure is [`OpenError::InvalidCiphertext`].
fn decapsulate(
    kem_ciphertext: &[u8; KEM_CIPHERTEXT_LEN],
    secret: &SecretKey,
    version: u8,
) -> Result<Key, OpenError> {
    let (mut m_tilde, bit_len) =
        dstu9041_decrypt(kem_ciphertext, &secret.0).map_err(|_| OpenError::InvalidCiphertext)?;
    // Defense in depth: an honestly-sealed ciphertext always has bit_len == SEED_BITS (the hash
    // check inside `decrypt` already makes forging a different-but-valid bit_length as hard as a
    // Kupyna-256 preimage), but this is never trusted blindly.
    if bit_len != SEED_BITS {
        m_tilde.zeroize();
        return Err(OpenError::InvalidCiphertext);
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&m_tilde[m_tilde.len() - SEED_LEN..]);
    m_tilde.zeroize();

    let key = stream_key(
        &seed,
        kem_ciphertext,
        &secret.public_key().to_bytes(),
        version,
    );
    seed.zeroize();
    Ok(key)
}

/// Starts sealing a message of any length to `recipient` as a stream (T-265): returns the
/// [`FileEncryptor`] for its records and the [`SEAL_STREAM_PREFIX_BYTES`]-byte prefix to write
/// first. Drive the encryptor as the stream-file codec documents (every full
/// [`CHUNK_BYTES`] chunk with `seal_chunk`, the last `0..=CHUNK_BYTES` bytes with `seal_final`);
/// the bytes are then exactly what [`seal`] returns, and [`open`]/[`open_stream`] read them. The
/// stream key never leaves the library.
///
/// # Errors
///
/// Returns [`SealError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn seal_stream(
    recipient: &PublicKey,
) -> Result<(FileEncryptor, [u8; SEAL_STREAM_PREFIX_BYTES]), SealError> {
    let (kem_ciphertext, key) = encapsulate(recipient, FORMAT_VERSION)?;
    let (enc, file_prefix) = match FileEncryptor::init(&key) {
        Ok(ok) => ok,
        Err(FileError::Random(e)) => return Err(SealError::Random(e)),
        // `FileEncryptor::init`'s only failure mode is the OS CSPRNG call for its header.
        Err(_) => unreachable!("FileEncryptor::init only ever fails via FileError::Random"),
    };
    let mut prefix = [0u8; SEAL_STREAM_PREFIX_BYTES];
    prefix[0] = FORMAT_VERSION;
    prefix[1..PREFIX_LEN].copy_from_slice(&kem_ciphertext);
    prefix[PREFIX_LEN..].copy_from_slice(&file_prefix);
    Ok((enc, prefix))
}

/// Starts opening a message sealed by [`seal`] or [`seal_stream`] (T-265): `prefix` is its first
/// [`OPEN_STREAM_PREFIX_BYTES`] bytes. Feed the returned [`FileDecryptor`] everything after them,
/// as the stream-file codec documents: a record's plaintext comes out only once it verifies, the
/// `Final` record's only from `finish`, once the input is known to end there.
///
/// # Errors
///
/// Returns [`OpenError::UnsupportedVersion`] if `prefix` does not start with this format's version
/// byte (checked before `secret` is used), or [`OpenError::InvalidCiphertext`] if the KEM
/// ciphertext does not open under `secret`.
pub fn open_stream(
    prefix: &[u8; OPEN_STREAM_PREFIX_BYTES],
    secret: &SecretKey,
) -> Result<FileDecryptor, OpenError> {
    if prefix[0] != FORMAT_VERSION {
        return Err(OpenError::UnsupportedVersion);
    }
    let mut kem_ciphertext = [0u8; KEM_CIPHERTEXT_LEN];
    kem_ciphertext.copy_from_slice(&prefix[1..]);
    let key = decapsulate(&kem_ciphertext, secret, FORMAT_VERSION)?;
    Ok(FileDecryptor::new(&key))
}

/// The exact length [`seal`] returns for a `message_len`-byte message, or `None` if it overflows
/// `usize`: the prefix, the message, and one record overhead per started [`CHUNK_BYTES`] chunk -
/// at least one, since an empty message is one empty `Final` record.
#[must_use]
pub fn sealed_len(message_len: usize) -> Option<usize> {
    let records = message_len.div_ceil(CHUNK_BYTES).max(1);
    records
        .checked_mul(RECORD_OVERHEAD_BYTES)?
        .checked_add(message_len)?
        .checked_add(SEAL_STREAM_PREFIX_BYTES)
}

/// Encrypts `message` (any length) to `recipient`, drawing a fresh random seed and ephemeral key
/// internally - see the module doc's "Seed width" section. The in-memory form of
/// [`seal_stream`]; the result is [`sealed_len`]`(message.len())` bytes.
///
/// # Errors
///
/// Returns [`SealError::Random`] if the OS CSPRNG fails - the only way this can fail.
pub fn seal(message: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, SealError> {
    let (mut enc, prefix) = seal_stream(recipient)?;
    let mut out = Vec::with_capacity(sealed_len(message.len()).unwrap_or(0));
    out.extend_from_slice(&prefix);
    if seal_all(&mut enc, message, &mut out).is_err() {
        unreachable!(
            "a fresh encryptor over an in-memory message: never finalized, chunks exact by \
             construction, far below the record counter's limit"
        )
    }
    Ok(out)
}

/// Decrypts `sealed` (as produced by [`seal`] or [`seal_stream`]) under `secret` - the in-memory
/// form of [`open_stream`]. Partially decrypted plaintext is zeroized before an error returns.
///
/// # Errors
///
/// Returns [`OpenError::UnsupportedVersion`] if `sealed`'s first byte is not this build's format
/// version (a blob from 0.4-0.6 included - see [`open_v2_legacy`]), [`OpenError::Truncated`] if
/// it is shorter than the minimum possible length or its stream ends before a verified `Final`
/// record, or [`OpenError::InvalidCiphertext`] for any other failure - see the module doc's
/// "Error collapsing" section.
pub fn open(sealed: &[u8], secret: &SecretKey) -> Result<Vec<u8>, OpenError> {
    let Some(&version) = sealed.first() else {
        return Err(OpenError::Truncated);
    };
    if version != FORMAT_VERSION {
        return Err(OpenError::UnsupportedVersion);
    }
    if sealed.len() < MIN_SEALED_LEN {
        return Err(OpenError::Truncated);
    }
    let (prefix, file) = sealed.split_at(PREFIX_LEN);
    let Ok(prefix) = <&[u8; PREFIX_LEN]>::try_from(prefix) else {
        return Err(OpenError::Truncated);
    };
    let mut dec = open_stream(prefix, secret)?;
    open_all(&mut dec, file).map_err(|e| match e {
        FileError::Truncated => OpenError::Truncated,
        _ => OpenError::InvalidCiphertext,
    })
}

/// Decrypts a blob in the one-chunk format 0.4-0.6 wrote (version byte 2: `version || kem
/// ciphertext (256) || secretstream header (32) || ciphertext || tag (16)`). It exists for
/// `uacrypt box-open`, which still opens files sealed before T-265 (owner decision 2026-10-15,
/// D-239); it is not memory-bounded and not wired into the C ABI or any binding. [`seal`] never
/// writes this format.
///
/// # Errors
///
/// Returns [`OpenError::Truncated`] if `sealed` is shorter than 305 bytes,
/// [`OpenError::UnsupportedVersion`] if its first byte is not 2, or
/// [`OpenError::InvalidCiphertext`] for any other failure.
pub fn open_v2_legacy(sealed: &[u8], secret: &SecretKey) -> Result<Vec<u8>, OpenError> {
    const MIN_LEN: usize = PREFIX_LEN + HEADER_LEN + TAG_LEN;
    if sealed.len() < MIN_LEN {
        return Err(OpenError::Truncated);
    }
    if sealed[0] != LEGACY_FORMAT_VERSION {
        return Err(OpenError::UnsupportedVersion);
    }

    let mut kem_ciphertext = [0u8; KEM_CIPHERTEXT_LEN];
    kem_ciphertext.copy_from_slice(&sealed[1..PREFIX_LEN]);
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&sealed[PREFIX_LEN..PREFIX_LEN + HEADER_LEN]);
    let ciphertext_len = sealed.len() - MIN_LEN;
    let ciphertext_start = PREFIX_LEN + HEADER_LEN;
    let ciphertext = &sealed[ciphertext_start..ciphertext_start + ciphertext_len];
    let tag = &sealed[ciphertext_start + ciphertext_len..];

    let key = decapsulate(&kem_ciphertext, secret, LEGACY_FORMAT_VERSION)?;
    let mut pull = PullState::init(&key, &header);
    let mut plaintext = vec![0u8; ciphertext_len];
    pull.pull(Tag::Final.to_byte(), ciphertext, tag, &mut plaintext)
        .map_err(|_| OpenError::InvalidCiphertext)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-248: the KEM ciphertext (first, middle and last byte), the recipient key (first and last
    /// byte) and the seed all feed the stream key - the property a round-trip test cannot show.
    #[test]
    fn stream_key_binds_kem_ciphertext_recipient_and_seed() {
        let seed = [0x11u8; 32];
        let kem = [0x22u8; KEM_CIPHERTEXT_LEN];
        let pk = [0x33u8; PUBLIC_KEY_LEN];
        let base = *stream_key(&seed, &kem, &pk, FORMAT_VERSION).as_bytes();

        for i in [0, KEM_CIPHERTEXT_LEN / 2, KEM_CIPHERTEXT_LEN - 1] {
            let mut kem2 = kem;
            kem2[i] ^= 1;
            assert_ne!(
                *stream_key(&seed, &kem2, &pk, FORMAT_VERSION).as_bytes(),
                base,
                "kem byte {i}"
            );
        }
        for i in [0, PUBLIC_KEY_LEN - 1] {
            let mut pk2 = pk;
            pk2[i] ^= 1;
            assert_ne!(
                *stream_key(&seed, &kem, &pk2, FORMAT_VERSION).as_bytes(),
                base,
                "pk byte {i}"
            );
        }
        let mut seed2 = seed;
        seed2[0] ^= 1;
        assert_ne!(
            *stream_key(&seed2, &kem, &pk, FORMAT_VERSION).as_bytes(),
            base
        );
        assert_eq!(
            *stream_key(&seed, &kem, &pk, FORMAT_VERSION).as_bytes(),
            base
        );
    }

    /// D-239: the format version is bound into the key, so a v2 and a v3 blob over the same KEM
    /// output never share a stream key.
    #[test]
    fn stream_key_separates_the_format_versions() {
        let seed = [0x11u8; 32];
        let kem = [0x22u8; KEM_CIPHERTEXT_LEN];
        let pk = [0x33u8; PUBLIC_KEY_LEN];
        assert_ne!(
            *stream_key(&seed, &kem, &pk, FORMAT_VERSION).as_bytes(),
            *stream_key(&seed, &kem, &pk, LEGACY_FORMAT_VERSION).as_bytes()
        );
    }
}
