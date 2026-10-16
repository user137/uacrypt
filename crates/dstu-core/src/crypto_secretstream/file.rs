//! The stream-file codec (T-284, D-208's format): the one implementation of the framing that
//! `uacrypt` and every language binding drive, so a framing rule is written once instead of nine
//! times (D-220's O-C). The caller does only I/O.
//!
//! A file is `FORMAT_VERSION || header (32) || records`; a record is
//! `tag (1) || len (u32 LE) || ciphertext (len) || auth tag (16)`. Every non-final record is
//! exactly [`CHUNK_BYTES`] long, no record is longer, the `Final` record is the last byte of the
//! file, and a file that ends before a verified `Final` is truncated.
//!
//! Writer: [`FileEncryptor::init`] gives the 33-byte prefix; seal every full chunk with
//! [`FileEncryptor::seal_chunk`] and the last `0..=CHUNK_BYTES` bytes with
//! [`FileEncryptor::seal_final`]. An input that is an exact multiple of [`CHUNK_BYTES`] ends in a
//! full `Final` record, so a writer holds the last chunk back until it knows no more input comes.
//!
//! Reader: loop - read exactly [`FileDecryptor::next_len`] bytes and pass them to
//! [`FileDecryptor::feed`]; if the input ends before that many arrive, call
//! [`FileDecryptor::finish`] instead. End of input is always this explicit call, never inferred
//! from a short slice. Non-final plaintext comes out of `feed` once its record verifies; the
//! `Final` record's plaintext is held and released only by `finish`, after the input is known to
//! end there - so a stream with trailing data never yields its last chunk. After any error every
//! later call fails with [`FileError::Finished`].

use super::{Key, PullState, PushState, SecretstreamError, Tag, FORMAT_VERSION, TAG_LEN};
use core::fmt;
use zeroize::Zeroize;

/// Plaintext bytes in every non-final record.
pub const CHUNK_BYTES: usize = 8192;
const HEADER_BYTES: usize = 32;
/// The format version byte plus the 32-byte header.
pub const FILE_PREFIX_BYTES: usize = 1 + HEADER_BYTES;
const RECORD_HEAD_BYTES: usize = 1 + 4;
/// A record's bytes beyond its ciphertext: tag byte, length, auth tag.
pub const RECORD_OVERHEAD_BYTES: usize = RECORD_HEAD_BYTES + TAG_LEN;
/// The longest record: a full chunk plus [`RECORD_OVERHEAD_BYTES`].
pub const MAX_RECORD_BYTES: usize = CHUNK_BYTES + RECORD_OVERHEAD_BYTES;

/// Why a stream file was rejected, or a codec call refused. The messages are the phrases every
/// consumer reports (T-277's error classes).
#[derive(Debug)]
pub enum FileError {
    /// The first byte is not [`FORMAT_VERSION`].
    UnsupportedVersion(u8),
    /// The input ended before a verified `Final` record.
    Truncated,
    /// A record declares more than [`CHUNK_BYTES`] bytes.
    ChunkTooLarge(u32),
    /// A non-final record is not exactly [`CHUNK_BYTES`] long.
    BadChunkLength(u32),
    /// A record's tag byte is none of the four tags.
    UnknownTag,
    /// Bytes follow the `Final` record.
    TrailingData,
    /// A record failed authentication: wrong key, tampered or reordered data.
    Auth,
    /// The codec already finished or failed; it accepts no more calls.
    Finished,
    /// A caller error: an input of the wrong length or an output buffer too small.
    InvalidLength,
    /// 2^64 - 1 records were already processed (T-245a).
    CounterExhausted,
    /// The OS CSPRNG failed while generating a header.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    Random(crate::randombytes::RandomError),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::UnsupportedVersion(v) => write!(
                f,
                "unsupported stream format version {v} (this build reads {FORMAT_VERSION})"
            ),
            FileError::Truncated => {
                write!(
                    f,
                    "truncated secretstream: the input ended before its Final chunk"
                )
            }
            FileError::ChunkTooLarge(len) => write!(
                f,
                "secretstream chunk too large: declared {len} bytes, max {CHUNK_BYTES}"
            ),
            FileError::BadChunkLength(len) => write!(
                f,
                "non-final chunk of {len} bytes, must be exactly {CHUNK_BYTES} (D-208)"
            ),
            FileError::UnknownTag => write!(f, "unrecognized chunk tag byte"),
            FileError::TrailingData => {
                write!(f, "trailing data after the secretstream's Final chunk")
            }
            FileError::Auth => write!(f, "authentication failed"),
            FileError::Finished => write!(f, "secretstream file already finished or failed"),
            FileError::InvalidLength => write!(f, "buffer length mismatch"),
            FileError::CounterExhausted => {
                write!(f, "chunk counter exhausted, no more chunks accepted")
            }
            #[cfg(any(feature = "std", feature = "getrandom"))]
            FileError::Random(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for FileError {}

impl From<SecretstreamError> for FileError {
    fn from(e: SecretstreamError) -> Self {
        match e {
            SecretstreamError::InvalidLength => FileError::InvalidLength,
            SecretstreamError::TagMismatch => FileError::Auth,
            SecretstreamError::UnknownTag => FileError::UnknownTag,
            SecretstreamError::StreamFinalized => FileError::Finished,
            SecretstreamError::CounterExhausted => FileError::CounterExhausted,
            #[cfg(any(feature = "std", feature = "getrandom"))]
            SecretstreamError::Random(e) => FileError::Random(e),
        }
    }
}

/// Writes stream-file records - see the module doc.
pub struct FileEncryptor {
    push: PushState,
}

impl FileEncryptor {
    /// Starts a stream under a fresh random header. Returns the encryptor and the
    /// [`FILE_PREFIX_BYTES`]-byte prefix to write first.
    ///
    /// # Errors
    ///
    /// [`FileError::Random`] if the OS CSPRNG fails.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn init(key: &Key) -> Result<(Self, [u8; FILE_PREFIX_BYTES]), FileError> {
        let (push, header) = PushState::init(key)?;
        let mut prefix = [0u8; FILE_PREFIX_BYTES];
        prefix[0] = FORMAT_VERSION;
        prefix[1..].copy_from_slice(&header);
        Ok((FileEncryptor { push }, prefix))
    }

    /// Seals one full non-final chunk into `out`, which then holds exactly one record.
    ///
    /// # Errors
    ///
    /// [`FileError::Finished`] after [`FileEncryptor::seal_final`], or
    /// [`FileError::CounterExhausted`].
    pub fn seal_chunk(
        &mut self,
        chunk: &[u8; CHUNK_BYTES],
        out: &mut [u8; MAX_RECORD_BYTES],
    ) -> Result<(), FileError> {
        self.seal(Tag::Message, chunk, out).map(|_| ())
    }

    /// Seals the last `0..=CHUNK_BYTES` bytes as the `Final` record. Returns the record's length
    /// (`last.len() + RECORD_OVERHEAD_BYTES`), written to the start of `out`.
    ///
    /// # Errors
    ///
    /// [`FileError::InvalidLength`] if `last` is longer than [`CHUNK_BYTES`] or `out` is shorter
    /// than the record; [`FileError::Finished`] if the stream was already finalized.
    pub fn seal_final(&mut self, last: &[u8], out: &mut [u8]) -> Result<usize, FileError> {
        self.seal(Tag::Final, last, out)
    }

    fn seal(&mut self, tag: Tag, plaintext: &[u8], out: &mut [u8]) -> Result<usize, FileError> {
        if self.push.is_finalized() {
            return Err(FileError::Finished);
        }
        let record_len = plaintext.len() + RECORD_OVERHEAD_BYTES;
        if plaintext.len() > CHUNK_BYTES || out.len() < record_len {
            return Err(FileError::InvalidLength);
        }
        let Ok(len) = u32::try_from(plaintext.len()) else {
            return Err(FileError::InvalidLength);
        };
        let (head, body) = out[..record_len].split_at_mut(RECORD_HEAD_BYTES);
        let (ciphertext, auth_tag) = body.split_at_mut(plaintext.len());
        auth_tag.copy_from_slice(&self.push.push(tag, plaintext, ciphertext)?);
        head[0] = tag.to_byte();
        head[1..].copy_from_slice(&len.to_le_bytes());
        Ok(record_len)
    }
}

enum State {
    Version,
    Header,
    RecordHead,
    RecordBody { tag_byte: u8, len: usize },
    AfterFinal,
    Done,
}

/// Reads a stream file - see the module doc for the calling contract.
pub struct FileDecryptor {
    key: [u8; 32],
    pull: Option<PullState>,
    state: State,
    final_plaintext: [u8; CHUNK_BYTES],
    final_len: usize,
}

impl Drop for FileDecryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.final_plaintext.zeroize();
    }
}

impl FileDecryptor {
    #[must_use]
    pub fn new(key: &Key) -> Self {
        FileDecryptor {
            key: *key.as_bytes(),
            pull: None,
            state: State::Version,
            final_plaintext: [0u8; CHUNK_BYTES],
            final_len: 0,
        }
    }

    /// How many bytes [`FileDecryptor::feed`] wants next; 0 once finished or failed.
    #[must_use]
    pub fn next_len(&self) -> usize {
        match self.state {
            State::Version | State::AfterFinal => 1,
            State::Header => HEADER_BYTES,
            State::RecordHead => RECORD_HEAD_BYTES,
            State::RecordBody { len, .. } => len + TAG_LEN,
            State::Done => 0,
        }
    }

    /// Consumes exactly [`FileDecryptor::next_len`] bytes. Returns how many plaintext bytes it
    /// wrote to the start of `plaintext_out` (a verified non-final record), else 0.
    ///
    /// # Errors
    ///
    /// [`FileError::InvalidLength`] if `input` is not `next_len()` bytes or `plaintext_out` is
    /// shorter than [`CHUNK_BYTES`] (the call is then ignored); [`FileError::Finished`] after
    /// [`FileDecryptor::finish`] or an earlier error; otherwise the format or authentication
    /// error, after which the decryptor is failed.
    pub fn feed(&mut self, input: &[u8], plaintext_out: &mut [u8]) -> Result<usize, FileError> {
        if matches!(self.state, State::Done) {
            return Err(FileError::Finished);
        }
        if input.len() != self.next_len() || plaintext_out.len() < CHUNK_BYTES {
            return Err(FileError::InvalidLength);
        }
        let result = self.step(input, plaintext_out);
        if result.is_err() {
            self.fail();
        }
        result
    }

    /// Call when the input ended before `next_len()` bytes arrived (drop any partial bytes).
    /// Returns the `Final` record's plaintext length, written to `plaintext_out`.
    ///
    /// # Errors
    ///
    /// [`FileError::Truncated`] if no `Final` record verified yet; [`FileError::InvalidLength`]
    /// if `plaintext_out` is shorter than [`CHUNK_BYTES`]; [`FileError::Finished`] after an
    /// earlier `finish` or error.
    pub fn finish(&mut self, plaintext_out: &mut [u8]) -> Result<usize, FileError> {
        match self.state {
            State::Done => Err(FileError::Finished),
            _ if plaintext_out.len() < CHUNK_BYTES => Err(FileError::InvalidLength),
            State::AfterFinal => {
                let len = self.final_len;
                plaintext_out[..len].copy_from_slice(&self.final_plaintext[..len]);
                self.fail();
                Ok(len)
            }
            _ => {
                self.fail();
                Err(FileError::Truncated)
            }
        }
    }

    fn step(&mut self, input: &[u8], plaintext_out: &mut [u8]) -> Result<usize, FileError> {
        match self.state {
            State::Version => {
                if input[0] != FORMAT_VERSION {
                    return Err(FileError::UnsupportedVersion(input[0]));
                }
                self.state = State::Header;
                Ok(0)
            }
            State::Header => {
                let mut header = [0u8; HEADER_BYTES];
                header.copy_from_slice(input);
                self.pull = Some(PullState::init(&Key::from_bytes(self.key), &header));
                self.key.zeroize();
                self.state = State::RecordHead;
                Ok(0)
            }
            State::RecordHead => {
                let tag_byte = input[0];
                let declared = u32::from_le_bytes([input[1], input[2], input[3], input[4]]);
                let Ok(len) = usize::try_from(declared) else {
                    return Err(FileError::ChunkTooLarge(declared));
                };
                if len > CHUNK_BYTES {
                    return Err(FileError::ChunkTooLarge(declared));
                }
                let Some(tag) = Tag::from_byte(tag_byte) else {
                    return Err(FileError::UnknownTag);
                };
                if tag != Tag::Final && len != CHUNK_BYTES {
                    return Err(FileError::BadChunkLength(declared));
                }
                self.state = State::RecordBody { tag_byte, len };
                Ok(0)
            }
            State::RecordBody { tag_byte, len } => {
                let (ciphertext, auth_tag) = input.split_at(len);
                let Some(pull) = self.pull.as_mut() else {
                    return Err(FileError::Finished);
                };
                if tag_byte == Tag::Final.to_byte() {
                    pull.pull(
                        tag_byte,
                        ciphertext,
                        auth_tag,
                        &mut self.final_plaintext[..len],
                    )?;
                    self.final_len = len;
                    self.state = State::AfterFinal;
                    Ok(0)
                } else {
                    pull.pull(tag_byte, ciphertext, auth_tag, &mut plaintext_out[..len])?;
                    self.state = State::RecordHead;
                    Ok(len)
                }
            }
            State::AfterFinal => Err(FileError::TrailingData),
            State::Done => Err(FileError::Finished),
        }
    }

    fn fail(&mut self) {
        self.state = State::Done;
        self.pull = None;
        self.key.zeroize();
        self.final_plaintext.zeroize();
        self.final_len = 0;
    }
}

/// Appends the records for an in-memory `plaintext` to `out` - the writer contract above, for the
/// one-shot `crypto_box::seal`/`crypto_box512::seal` (T-265).
#[cfg(feature = "std")]
pub(crate) fn seal_all(
    enc: &mut FileEncryptor,
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), FileError> {
    let mut record = [0u8; MAX_RECORD_BYTES];
    let mut rest = plaintext;
    while rest.len() > CHUNK_BYTES {
        let (chunk, tail) = rest.split_at(CHUNK_BYTES);
        let Ok(chunk) = <&[u8; CHUNK_BYTES]>::try_from(chunk) else {
            return Err(FileError::InvalidLength);
        };
        enc.seal_chunk(chunk, &mut record)?;
        out.extend_from_slice(&record);
        rest = tail;
    }
    let n = enc.seal_final(rest, &mut record)?;
    out.extend_from_slice(&record[..n]);
    Ok(())
}

/// Reads an in-memory stream file to its end - the reader contract above, for the one-shot
/// `crypto_box::open`/`crypto_box512::open` (T-265). On any error the plaintext gathered so far is
/// zeroized before it is dropped (D-65); its capacity is reserved up front so no reallocation
/// leaves a copy behind.
#[cfg(feature = "std")]
pub(crate) fn open_all(dec: &mut FileDecryptor, file: &[u8]) -> Result<Vec<u8>, FileError> {
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut plaintext = Vec::with_capacity(file.len());
    let mut pos = 0;
    let result = loop {
        let want = dec.next_len();
        let Some(input) = file.get(pos..pos + want) else {
            break dec.finish(&mut chunk).map(|n| {
                plaintext.extend_from_slice(&chunk[..n]);
            });
        };
        match dec.feed(input, &mut chunk) {
            Ok(n) => plaintext.extend_from_slice(&chunk[..n]),
            Err(e) => break Err(e),
        }
        pos += want;
    };
    chunk.zeroize();
    match result {
        Ok(()) => Ok(plaintext),
        Err(e) => {
            plaintext.as_mut_slice().zeroize();
            Err(e)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([0x5a; 32])
    }

    /// T-265: the in-memory helpers behind `crypto_box::seal`/`open` round-trip at the chunk
    /// boundaries and fail closed on a cut, a flipped byte and trailing data. Cheap enough for
    /// Miri, unlike the `crypto_box` tests that call them through the KEM.
    #[test]
    fn seal_all_and_open_all_round_trip_and_fail_closed() {
        for len in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1] {
            let plaintext: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let (mut enc, prefix) = FileEncryptor::init(&key()).unwrap();
            let mut file = prefix.to_vec();
            seal_all(&mut enc, &plaintext, &mut file).unwrap();
            assert_eq!(
                open_all(&mut FileDecryptor::new(&key()), &file).unwrap(),
                plaintext,
                "len = {len}"
            );

            assert!(matches!(
                open_all(&mut FileDecryptor::new(&key()), &file[..file.len() - 1]),
                Err(FileError::Truncated)
            ));
            let mut flipped = file.clone();
            *flipped.last_mut().unwrap() ^= 1;
            assert!(matches!(
                open_all(&mut FileDecryptor::new(&key()), &flipped),
                Err(FileError::Auth)
            ));
            let mut trailing = file.clone();
            trailing.push(0);
            assert!(matches!(
                open_all(&mut FileDecryptor::new(&key()), &trailing),
                Err(FileError::TrailingData)
            ));
        }
    }
}
