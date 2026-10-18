//! The passphrase file (`docs/DECISIONS.md` D-219, moved from `uacrypt` into the core by T-269): a
//! 28-byte header in front of an ordinary stream file (D-208), so `uacrypt encrypt --passphrase`
//! and every binding read and write the same bytes.
//!
//! ```text
//! 0x50 || 0x01 (container version) || 0x01 (Argon2id v1.3)
//!   || m_cost KiB (u32 LE) || t_cost (u32 LE) || p_cost (u8) || salt (16) || <stream file, D-208>
//! ```
//!
//! The stream key is [`derive_key`]`(passphrase, salt, Moderate)`. The header carries no tag of
//! its own: a changed salt gives another key and the first record fails, and a changed marker,
//! version, KDF id or cost is refused by name. Only the costs [`seal_stream`] writes are accepted,
//! and that check happens in [`Header::parse`], before any Argon2 memory is allocated - a file
//! cannot make its reader allocate 1 GiB. No oracle exists for the header: it is this project's
//! own format; [`derive_key`] itself equals libsodium's `crypto_pwhash`.
//!
//! ```rust,no_run
//! use dstu_core::crypto_pwhash::passphrase_file::{seal_stream, Header, HEADER_BYTES};
//!
//! let (mut enc, prefix) = seal_stream(b"correct horse battery staple")?;
//! let mut file = prefix.to_vec();
//! let mut record = [0u8; dstu_core::crypto_secretstream::MAX_RECORD_BYTES];
//! let n = enc.seal_final(b"short message", &mut record).expect("fits in one record");
//! file.extend_from_slice(&record[..n]);
//!
//! let header = Header::parse(file[..HEADER_BYTES].try_into().expect("28 bytes"))?;
//! let decryptor = header.open_stream(b"correct horse battery staple")?;
//! // feed `decryptor` everything after the header (the stream-file codec's reader contract)
//! # let _ = decryptor;
//! # Ok::<(), dstu_core::crypto_pwhash::passphrase_file::PassphraseFileError>(())
//! ```

use super::{derive_key, PwHashError, Strength, SALT_BYTES};
use crate::crypto_secretstream::{FileDecryptor, FileEncryptor, FileError, Key, FILE_PREFIX_BYTES};
use crate::randombytes::randombytes_buf;
use core::fmt;

/// First byte of a passphrase file. A key-encrypted stream file starts with its own format
/// version (`2`) instead, so a reader can tell the two apart from byte 0.
pub const CONTAINER_TYPE: u8 = 0x50;
const CONTAINER_VERSION: u8 = 0x01;
const KDF_ARGON2ID13: u8 = 0x01;
const PREFIX_LEN: usize = 3 + 4 + 4 + 1;
/// Length of the header in front of the stream file.
pub const HEADER_BYTES: usize = PREFIX_LEN + SALT_BYTES;
/// The bytes [`seal_stream`] returns to write first: the header, then the stream file's own
/// version byte and header.
pub const SEAL_STREAM_PREFIX_BYTES: usize = HEADER_BYTES + FILE_PREFIX_BYTES;
const _: () = assert!(HEADER_BYTES == 28);

/// The one preset written and accepted (D-219's F3: libsodium `MODERATE`, 256 MiB, t=3).
const STRENGTH: Strength = Strength::Moderate;

/// Why a passphrase file cannot be written or opened. A wrong passphrase is not here: it shows up
/// as the stream's first record failing ([`FileError::Auth`]).
#[derive(Debug)]
pub enum PassphraseFileError {
    /// Byte 0 is not [`CONTAINER_TYPE`] - for example a key-encrypted stream file.
    NotPassphraseFile,
    /// Another container version or key-derivation function than this build writes.
    UnsupportedFormat { version: u8, kdf: u8 },
    /// Argon2 costs other than the one preset this format uses; refused before Argon2 runs.
    UnsupportedParams {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    /// An empty passphrase - refused on both sides.
    EmptyPassphrase,
    /// The salt's CSPRNG, or Argon2 itself (its memory), failed.
    PwHash(PwHashError),
}

impl fmt::Display for PassphraseFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassphraseFileError::NotPassphraseFile => write!(f, "not a passphrase file"),
            PassphraseFileError::UnsupportedFormat { version, kdf } => write!(
                f,
                "unsupported passphrase file format (container version {version}, KDF {kdf})"
            ),
            PassphraseFileError::UnsupportedParams {
                m_cost,
                t_cost,
                p_cost,
            } => write!(
                f,
                "unsupported Argon2 parameters (m={m_cost} KiB, t={t_cost}, p={p_cost})"
            ),
            PassphraseFileError::EmptyPassphrase => write!(f, "the passphrase is empty"),
            PassphraseFileError::PwHash(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for PassphraseFileError {}

fn stream_key(passphrase: &[u8], salt: &[u8; SALT_BYTES]) -> Result<Key, PassphraseFileError> {
    if passphrase.is_empty() {
        return Err(PassphraseFileError::EmptyPassphrase);
    }
    let key = derive_key(passphrase, salt, STRENGTH).map_err(PassphraseFileError::PwHash)?;
    Ok(Key::from_bytes(*key))
}

/// Starts writing a passphrase file: draws a fresh salt, runs Argon2 (256 MiB, t=3), and returns
/// the [`FileEncryptor`] for the records plus the [`SEAL_STREAM_PREFIX_BYTES`]-byte prefix to
/// write first. Drive the encryptor as the stream-file codec documents.
///
/// # Errors
///
/// [`PassphraseFileError::EmptyPassphrase`], or [`PassphraseFileError::PwHash`] if the CSPRNG
/// fails or Argon2's memory cannot be allocated.
pub fn seal_stream(
    passphrase: &[u8],
) -> Result<(FileEncryptor, [u8; SEAL_STREAM_PREFIX_BYTES]), PassphraseFileError> {
    let mut salt = [0u8; SALT_BYTES];
    randombytes_buf(&mut salt).map_err(|e| PassphraseFileError::PwHash(PwHashError::Random(e)))?;
    let key = stream_key(passphrase, &salt)?;
    let (enc, file_prefix) = match FileEncryptor::init(&key) {
        Ok(ok) => ok,
        Err(FileError::Random(e)) => {
            return Err(PassphraseFileError::PwHash(PwHashError::Random(e)))
        }
        // `FileEncryptor::init`'s only failure mode is the OS CSPRNG call for its header.
        Err(_) => unreachable!("FileEncryptor::init only ever fails via FileError::Random"),
    };
    let (m_cost, t_cost, p_cost) = STRENGTH.cost();
    let mut prefix = [0u8; SEAL_STREAM_PREFIX_BYTES];
    prefix[..3].copy_from_slice(&[CONTAINER_TYPE, CONTAINER_VERSION, KDF_ARGON2ID13]);
    prefix[3..7].copy_from_slice(&m_cost.to_le_bytes());
    prefix[7..11].copy_from_slice(&t_cost.to_le_bytes());
    // `Strength::cost`'s p_cost is always 1 (libsodium's fixed lane count).
    prefix[11] = u8::try_from(p_cost).unwrap_or(u8::MAX);
    prefix[PREFIX_LEN..HEADER_BYTES].copy_from_slice(&salt);
    prefix[HEADER_BYTES..].copy_from_slice(&file_prefix);
    Ok((enc, prefix))
}

/// A checked passphrase-file header: everything but the passphrase is known to be acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    salt: [u8; SALT_BYTES],
}

impl Header {
    /// Checks a file's first [`HEADER_BYTES`] bytes without running Argon2, so a reader can refuse
    /// a wrong file before asking for a passphrase.
    ///
    /// # Errors
    ///
    /// [`PassphraseFileError::NotPassphraseFile`], [`PassphraseFileError::UnsupportedFormat`], or
    /// [`PassphraseFileError::UnsupportedParams`] for any cost but the one preset.
    pub fn parse(header: &[u8; HEADER_BYTES]) -> Result<Self, PassphraseFileError> {
        let [kind, version, kdf, m0, m1, m2, m3, t0, t1, t2, t3, p, salt @ ..] = *header;
        if kind != CONTAINER_TYPE {
            return Err(PassphraseFileError::NotPassphraseFile);
        }
        if version != CONTAINER_VERSION || kdf != KDF_ARGON2ID13 {
            return Err(PassphraseFileError::UnsupportedFormat { version, kdf });
        }
        let m_cost = u32::from_le_bytes([m0, m1, m2, m3]);
        let t_cost = u32::from_le_bytes([t0, t1, t2, t3]);
        if Strength::from_cost(m_cost, t_cost, u32::from(p)) != Some(STRENGTH) {
            return Err(PassphraseFileError::UnsupportedParams {
                m_cost,
                t_cost,
                p_cost: p,
            });
        }
        Ok(Header { salt })
    }

    /// Runs Argon2 (256 MiB, t=3) and returns the [`FileDecryptor`] for everything after the
    /// header. A wrong passphrase is reported by the decryptor, at the first record.
    ///
    /// # Errors
    ///
    /// [`PassphraseFileError::EmptyPassphrase`], or [`PassphraseFileError::PwHash`] if Argon2's
    /// memory cannot be allocated.
    pub fn open_stream(&self, passphrase: &[u8]) -> Result<FileDecryptor, PassphraseFileError> {
        let key = stream_key(passphrase, &self.salt)?;
        Ok(FileDecryptor::new(&key))
    }
}
