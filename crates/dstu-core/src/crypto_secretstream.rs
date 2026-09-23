//! `crypto_secretstream` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium
//! API", `docs/TASKS.md` T-40/T-70, roadmap Step 5 item 1 - `docs/DECISIONS.md` D-68) - a chunked/streaming
//! AEAD construction so a large message never needs to fit in memory all at once, unlike
//! [`crate::crypto_secretbox`] (whose underlying AEAD tag needs the whole plaintext/ciphertext up
//! front).
//!
//! # From-scratch construction - no DSTU standard, no oracle vector, ever
//!
//! No DSTU standard defines a streaming/chunked AEAD mode. Per `docs/DECISIONS.md` D-47's tie-breaker
//! rule (no citation exists, so: TLS 1.3/modern-AEAD lessons, then libsodium's own API shape), this
//! follows libsodium's `crypto_secretstream_xchacha20poly1305` shape - tag-per-chunk framing with a
//! `FINAL` tag whose absence before end-of-input signals truncation - built on this crate's own
//! primitives ([`crate::hazmat::kalyna_gcm::Kalyna256_256Gcm`] for chunk encryption,
//! [`crate::hazmat::kupyna_kmac::Kupyna256Kmac`] for subkey derivation) instead of
//! `ChaCha20-Poly1305`. Same posture as [`crate::hazmat::kupyna_kdf`] (D-45): verified by property test only,
//! never citable as vector-verified.
//!
//! # Construction
//!
//! [`PushState::init`] draws a random 32-byte `header` and derives the stream's initial subkey as
//! `Kupyna256Kmac::mac(key = master_key, message = header)`. This is the nonce/IV-coverage rule
//! (see [`crate::crypto_secretbox`]'s D-63 precedent) applied at stream setup instead of per-chunk
//! AAD: the subkey itself is a function of the header, so a tampered header derives the wrong
//! subkey and the very first chunk's tag fails closed - no separate binding needed.
//!
//! Each chunk is encrypted with [`Kalyna256_256Gcm`](crate::hazmat::kalyna_gcm::Kalyna256_256Gcm)
//! under a 32-byte IV that is all-zero except its low 8 bytes, which hold a `u64` counter -
//! monotonically increasing per chunk, tracked identically on both sides, **never transmitted and
//! never reset** (including across a [`Tag::Rekey`], the simplest safe choice). The chunk's
//! [`Tag`] byte, the counter and the chunk's true ciphertext length are passed together as
//! `kalyna_gcm`'s `aad` parameter (`counter.to_le_bytes() || [tag_byte] ||
//! (ciphertext_len as u64).to_le_bytes()`) - the same "bind out-of-band data into the tag via
//! AEAD's own AAD mechanism" pattern D-63 established for `crypto_secretbox`'s nonce. Binding the
//! counter into the AAD, rather than trusting a transmitted position, is what defeats reordering,
//! interior chunk drops, and splicing a chunk from a different stream: a receiver always verifies
//! against *its own* expected counter, so anything that isn't exactly next-in-sequence fails its
//! tag check. Splicing from a different stream under the same master key fails for a second,
//! independent reason too: that stream has its own random header, hence its own derived subkey.
//!
//! Tampering the transmitted `tag_byte` itself (e.g. flipping [`Tag::Final`] to [`Tag::Message`]
//! to hide truncation) is caught the same way: [`PullState::pull`] uses the wire-read `tag_byte`
//! directly as part of the AAD it verifies against, so a flipped byte changes the AAD and fails the
//! tag check before the (wrong) [`Tag`] is ever trusted or returned to the caller.
//!
//! The length went into the AAD with T-232 (audit F-01, `docs/DECISIONS.md` D-200), when
//! `kalyna_gcm` tagged only the padded length and a chunk shared a tag with the same chunk extended
//! by `80 00..`. Since T-234 (D-204) `kalyna_gcm` binds the true length itself (DSTU 7624:2014
//! §12.2); the AAD keeps it as defence in depth. Every received `auth_tag` must also be exactly 16 bytes (T-238).
//!
//! # Tags
//!
//! Byte values match libsodium's own encoding (`MESSAGE=0x00`, `PUSH=0x01`, `REKEY=0x02`,
//! `FINAL=0x03`) - no DSTU reason to diverge, purely familiarity:
//! - [`Tag::Message`] - an ordinary chunk, no special handling.
//! - [`Tag::Push`] - marks a logical sub-message boundary within one continuous stream, for a
//!   caller multiplexing more than one logical message into a single stream.
//! - [`Tag::Rekey`] - after this chunk, both sides derive a fresh subkey:
//!   `new_subkey = Kupyna256Kmac::mac(key = current_subkey, message = b"DSTU-secretstream-rekey")`.
//!   One-way (KMAC), so a compromised later subkey does not recover earlier chunks' key - the
//!   forward-secrecy property libsodium's own rekey exists for.
//! - [`Tag::Final`] - after this chunk, the state is marked finalized
//!   ([`PushState::is_finalized`]/[`PullState::is_finalized`]); any further [`PushState::push`]/
//!   [`PullState::pull`] call on that state returns [`SecretstreamError::StreamFinalized`]. This is
//!   what makes truncation detectable: a caller who reaches end-of-input without ever having seen
//!   `Final` knows the stream was cut short - the check itself lives in the caller's I/O loop
//!   ([`PullState::is_finalized`] is the primitive this module provides for it), since only the
//!   caller knows when its input is exhausted.
//!
//! # `no_std` posture
//!
//! Per-item `std` gating (the [`crate::crypto_auth`]/[`crate::crypto_kdf`] pattern, not
//! [`crate::crypto_stream`]'s whole-module gating): only [`PushState::init`] (needs
//! [`crate::randombytes::randombytes_buf`] for the header) is `#[cfg(feature = "std")]`.
//! [`PullState::init`], [`PushState::push`], and [`PullState::pull`] are unconditional - caller-
//! supplied buffers mean no `Vec`/`alloc` is needed anywhere in the actual push/pull path. The
//! `push`/`pull` step machinery itself is a stricter `no_std` fit than any other high-level
//! `crypto_*` module's equivalent step, **but `PushState::init` is `PushState`'s only
//! constructor**, so under `no_std` a caller can build a [`PullState`] but has no way to start a
//! new stream - this module is decrypt-only without `std` (D-09's "`hazmat` never generates its
//! own randomness" reasoning, unchanged, but worth stating plainly rather than implying the whole
//! module is symmetric under `no_std`).
//!
//! # Example
//!
//! A real caller processes a large file one bounded-size chunk at a time (see `uacrypt`'s own
//! `encrypt`/`decrypt` commands for that shape); this example uses one chunk for clarity. Each
//! chunk is authenticated individually - a tampered chunk, a dropped/reordered chunk, or one
//! spliced from a different stream all fail closed at [`PullState::pull`], never producing wrong
//! plaintext silently.
//!
//! ```rust
//! use dstu_core::crypto_secretstream::{Key, PushState, PullState, Tag};
//!
//! let key = Key::generate().expect("OS CSPRNG should not fail");
//! let plaintext = b"a whole file, conceptually split into chunks";
//!
//! // Sender side: one chunk, marked Final since it's the only (and therefore last) one.
//! let (mut push, header) = PushState::init(&key).expect("OS CSPRNG should not fail");
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! let tag = push
//!     .push(Tag::Final, plaintext, &mut ciphertext)
//!     .expect("push before finalization");
//!
//! // Receiver side: needs the key and the transmitted header, ciphertext, and tag.
//! let mut pull = PullState::init(&key, &header);
//! let mut decrypted = vec![0u8; ciphertext.len()];
//! let read_tag = pull
//!     .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut decrypted)
//!     .expect("authentic chunk");
//! assert_eq!(read_tag, Tag::Final);
//! assert_eq!(decrypted, plaintext);
//!
//! // A tampered ciphertext byte is rejected, not silently decrypted into garbage.
//! let mut tampered = ciphertext.clone();
//! tampered[0] ^= 1;
//! let mut pull2 = PullState::init(&key, &header);
//! let mut out = vec![0u8; tampered.len()];
//! assert!(pull2
//!     .pull(Tag::Final.to_byte(), &tampered, &tag, &mut out)
//!     .is_err());
//! ```

use crate::hazmat::kalyna_gcm::{GcmError, Kalyna256_256Gcm};
use crate::hazmat::kupyna_kmac::Kupyna256Kmac;
use core::fmt;
use zeroize::Zeroize;

const TAG_LEN: usize = 16;
const REKEY_CONTEXT: &[u8] = b"DSTU-secretstream-rekey";

/// A `crypto_secretstream` master key. Always exactly 32 bytes - [`Kupyna256Kmac`]'s fixed
/// key/MAC length (see the module doc).
pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    /// Generates a fresh key from the OS CSPRNG - libsodium's `crypto_secretstream_keygen`
    /// equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::randombytes::RandomError`] if the OS CSPRNG fails.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn generate() -> Result<Self, crate::randombytes::RandomError> {
        let mut bytes = [0u8; 32];
        crate::randombytes::randombytes_buf(&mut bytes)?;
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

/// A chunk's role in the stream - see the module doc's "Tags" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Message,
    Push,
    Rekey,
    Final,
}

impl Tag {
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Tag::Message => 0x00,
            Tag::Push => 0x01,
            Tag::Rekey => 0x02,
            Tag::Final => 0x03,
        }
    }

    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Tag::Message),
            0x01 => Some(Tag::Push),
            0x02 => Some(Tag::Rekey),
            0x03 => Some(Tag::Final),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum SecretstreamError {
    /// `ciphertext_out.len() != plaintext.len()` (or the `plaintext_out`/`ciphertext` equivalent
    /// on [`PullState::pull`]), or an `auth_tag` passed to [`PullState::pull`] that isn't exactly
    /// 16 bytes.
    InvalidLength,
    /// Authentication failed: wrong key, wrong header, tampered ciphertext/tag/tag-byte, or a
    /// chunk out of sequence (wrong counter) - reordered, dropped, or spliced from another stream.
    TagMismatch,
    /// `tag_byte` passed to [`PullState::pull`] was not one of the four values [`Tag::to_byte`]
    /// produces.
    UnknownTag,
    /// [`PushState::push`]/[`PullState::pull`] called again after a [`Tag::Final`] chunk already
    /// closed this state.
    StreamFinalized,
    /// The per-chunk counter (it is also the chunk's IV) has no next value: 2^64 - 1 chunks were
    /// already processed on this state. Unreachable in practice, but checked so the counter can
    /// never wrap and reuse an IV (T-245a).
    CounterExhausted,
    /// [`PushState::init`]'s OS CSPRNG call failed while generating a header.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    Random(crate::randombytes::RandomError),
}

impl fmt::Display for SecretstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretstreamError::InvalidLength => write!(f, "buffer length mismatch"),
            SecretstreamError::TagMismatch => write!(f, "authentication failed"),
            SecretstreamError::UnknownTag => write!(f, "unrecognized chunk tag byte"),
            SecretstreamError::StreamFinalized => {
                write!(f, "stream already finalized, no more chunks accepted")
            }
            SecretstreamError::CounterExhausted => {
                write!(f, "chunk counter exhausted, no more chunks accepted")
            }
            #[cfg(any(feature = "std", feature = "getrandom"))]
            SecretstreamError::Random(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for SecretstreamError {}

#[cfg(any(feature = "std", feature = "getrandom"))]
impl From<crate::randombytes::RandomError> for SecretstreamError {
    fn from(e: crate::randombytes::RandomError) -> Self {
        SecretstreamError::Random(e)
    }
}

fn rekey(subkey: &mut [u8; 32]) {
    let Ok(new_subkey) = Kupyna256Kmac::mac(subkey, REKEY_CONTEXT) else {
        unreachable!("subkey is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
    };
    subkey.zeroize();
    *subkey = new_subkey;
}

fn chunk_iv(counter: u64) -> [u8; 32] {
    let mut iv = [0u8; 32];
    iv[..8].copy_from_slice(&counter.to_le_bytes());
    iv
}

/// `counter LE || tag_byte || ciphertext_len as u64 LE`. The length is defence in depth:
/// `hazmat::kalyna_gcm` binds the true length itself since T-234 (D-204), and it was added here by
/// T-232 (audit F-01, D-200) when that was not yet so.
fn chunk_aad(counter: u64, tag_byte: u8, ciphertext_len: usize) -> [u8; 17] {
    let Ok(len) = u64::try_from(ciphertext_len) else {
        unreachable!("a slice length always fits in u64 on every supported target")
    };
    let mut aad = [0u8; 17];
    aad[..8].copy_from_slice(&counter.to_le_bytes());
    aad[8] = tag_byte;
    aad[9..].copy_from_slice(&len.to_le_bytes());
    aad
}

/// Encrypting half of a `crypto_secretstream` session - produced by [`PushState::init`], driven
/// one chunk at a time by [`PushState::push`].
pub struct PushState {
    subkey: [u8; 32],
    counter: u64,
    finalized: bool,
}

impl Drop for PushState {
    fn drop(&mut self) {
        self.subkey.zeroize();
    }
}

impl PushState {
    /// Starts a new stream under `key`, drawing a fresh random header from the OS CSPRNG. The
    /// returned header must be transmitted/stored alongside the chunks - [`PullState::init`]
    /// needs it to re-derive the same initial subkey.
    ///
    /// # Errors
    ///
    /// Returns [`SecretstreamError::Random`] if the OS CSPRNG fails.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn init(key: &Key) -> Result<(Self, [u8; 32]), SecretstreamError> {
        let mut header = [0u8; 32];
        crate::randombytes::randombytes_buf(&mut header)?;
        let Ok(subkey) = Kupyna256Kmac::mac(key.as_bytes(), &header) else {
            unreachable!("Key::as_bytes() is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
        };
        Ok((
            PushState {
                subkey,
                counter: 0,
                finalized: false,
            },
            header,
        ))
    }

    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Encrypts `plaintext` into `ciphertext_out` (same length) and returns the 16-byte
    /// authentication tag for this chunk. `tag` becomes part of this chunk's AAD (see the module
    /// doc) - the caller must transmit both the ciphertext, the returned tag, *and* `tag.to_byte()`
    /// for [`PullState::pull`] to recover the plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`SecretstreamError::InvalidLength`] if `ciphertext_out.len() != plaintext.len()`,
    /// [`SecretstreamError::StreamFinalized`] if a previous chunk already used [`Tag::Final`], or
    /// [`SecretstreamError::CounterExhausted`] after 2^64 - 1 chunks.
    pub fn push(
        &mut self,
        tag: Tag,
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SecretstreamError> {
        if self.finalized {
            return Err(SecretstreamError::StreamFinalized);
        }
        if ciphertext_out.len() != plaintext.len() {
            return Err(SecretstreamError::InvalidLength);
        }
        let Some(next_counter) = self.counter.checked_add(1) else {
            return Err(SecretstreamError::CounterExhausted);
        };

        let cipher = Kalyna256_256Gcm::new(&self.subkey);
        let iv = chunk_iv(self.counter);
        let aad = chunk_aad(self.counter, tag.to_byte(), plaintext.len());
        let Ok(full_tag) = cipher.encrypt(&iv, &aad, plaintext, ciphertext_out) else {
            unreachable!("ciphertext_out.len() == plaintext.len() checked above")
        };

        self.counter = next_counter;
        match tag {
            Tag::Rekey => rekey(&mut self.subkey),
            Tag::Final => self.finalized = true,
            Tag::Message | Tag::Push => {}
        }

        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&full_tag[..TAG_LEN]);
        Ok(out)
    }
}

/// Decrypting half of a `crypto_secretstream` session - built from the master key and the header
/// [`PushState::init`] produced, driven one chunk at a time by [`PullState::pull`].
pub struct PullState {
    subkey: [u8; 32],
    counter: u64,
    finalized: bool,
}

impl Drop for PullState {
    fn drop(&mut self) {
        self.subkey.zeroize();
    }
}

impl PullState {
    /// Re-derives the stream's initial subkey from `key` and `header` (as produced by
    /// [`PushState::init`]). Infallible - deriving the wrong subkey from a tampered `header` is
    /// not detected here, only once the first chunk's tag fails to verify (see the module doc).
    #[must_use]
    pub fn init(key: &Key, header: &[u8; 32]) -> Self {
        let Ok(subkey) = Kupyna256Kmac::mac(key.as_bytes(), header) else {
            unreachable!("Key::as_bytes() is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
        };
        PullState {
            subkey,
            counter: 0,
            finalized: false,
        }
    }

    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Verifies and decrypts one chunk. `tag_byte` is untrusted wire input - it is folded into the
    /// AAD verified against `auth_tag`, so a value that doesn't match what [`PushState::push`]
    /// actually used fails the tag check (see the module doc). Returns the authenticated [`Tag`]
    /// on success.
    ///
    /// # Errors
    ///
    /// Returns [`SecretstreamError::UnknownTag`] if `tag_byte` isn't a value [`Tag::to_byte`]
    /// produces, [`SecretstreamError::InvalidLength`] if `plaintext_out.len() != ciphertext.len()`
    /// or `auth_tag.len() != 16`,
    /// [`SecretstreamError::StreamFinalized`] if a previous chunk already used [`Tag::Final`],
    /// [`SecretstreamError::CounterExhausted`] after 2^64 - 1 chunks, or
    /// [`SecretstreamError::TagMismatch`] if authentication fails - `plaintext_out` is left
    /// all-zero on any authentication failure, never unverified plaintext.
    pub fn pull(
        &mut self,
        tag_byte: u8,
        ciphertext: &[u8],
        auth_tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<Tag, SecretstreamError> {
        if self.finalized {
            return Err(SecretstreamError::StreamFinalized);
        }
        let Some(tag) = Tag::from_byte(tag_byte) else {
            return Err(SecretstreamError::UnknownTag);
        };
        // Pinned to exactly what `push` emits: `kalyna_gcm::decrypt` alone accepts the
        // DSTU-permitted 8..=32, which would let an 8-byte tag prefix verify (T-238).
        if plaintext_out.len() != ciphertext.len() || auth_tag.len() != TAG_LEN {
            return Err(SecretstreamError::InvalidLength);
        }
        let Some(next_counter) = self.counter.checked_add(1) else {
            return Err(SecretstreamError::CounterExhausted);
        };

        let cipher = Kalyna256_256Gcm::new(&self.subkey);
        let iv = chunk_iv(self.counter);
        let aad = chunk_aad(self.counter, tag_byte, ciphertext.len());

        // `Kalyna256_256Gcm::decrypt` already uses `subtle::ConstantTimeEq` internally (D-56).
        match cipher.decrypt(&iv, &aad, ciphertext, auth_tag, plaintext_out) {
            Ok(()) => {}
            Err(GcmError::TagMismatch) => return Err(SecretstreamError::TagMismatch),
            // `EmptyInput` cannot happen: `chunk_aad` is never empty.
            Err(GcmError::InvalidLength | GcmError::EmptyInput) => {
                return Err(SecretstreamError::InvalidLength)
            }
        }

        self.counter = next_counter;
        match tag {
            Tag::Rekey => rekey(&mut self.subkey),
            Tag::Final => self.finalized = true,
            Tag::Message | Tag::Push => {}
        }

        Ok(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-245a: the chunk counter is the IV, so it must never wrap. Once it is exhausted, push and
    // pull must refuse before touching their output buffer.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    #[test]
    fn push_and_pull_refuse_to_wrap_the_chunk_counter() {
        let key = Key::from_bytes([7u8; 32]);
        let (mut push, header) = PushState::init(&key).expect("OS CSPRNG available");
        push.counter = u64::MAX - 1;
        let mut ciphertext = [0u8; 3];
        let auth_tag = push
            .push(Tag::Message, b"abc", &mut ciphertext)
            .expect("the last usable counter still encrypts");
        let mut unused = [0u8; 3];
        assert!(matches!(
            push.push(Tag::Message, b"abc", &mut unused),
            Err(SecretstreamError::CounterExhausted)
        ));
        assert_eq!(unused, [0u8; 3]);

        let mut pull = PullState::init(&key, &header);
        pull.counter = u64::MAX - 1;
        let mut plaintext = [0u8; 3];
        pull.pull(
            Tag::Message.to_byte(),
            &ciphertext,
            &auth_tag,
            &mut plaintext,
        )
        .expect("the last usable counter still decrypts");
        assert_eq!(&plaintext, b"abc");
        let mut unused = [0u8; 3];
        assert!(matches!(
            pull.pull(Tag::Message.to_byte(), &ciphertext, &auth_tag, &mut unused),
            Err(SecretstreamError::CounterExhausted)
        ));
        assert_eq!(unused, [0u8; 3]);
    }
}
