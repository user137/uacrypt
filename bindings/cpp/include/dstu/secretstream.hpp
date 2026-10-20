#ifndef DSTU_CPP_SECRETSTREAM_HPP
#define DSTU_CPP_SECRETSTREAM_HPP

#include "box.hpp"
#include "box384.hpp"
#include "box512.hpp"
#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <algorithm>
#include <cstdint>
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace dstu {

/// The plaintext chunk size uacrypt encrypt's own wire format frames at - mirrors
/// bindings/go/dstu/secretstream.go's SecretstreamChunkBytes and
/// crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES.
inline constexpr std::size_t kSecretstreamChunkBytes = 8192;

/// The first byte of every stream file - matches dstu-core's crypto_secretstream::FORMAT_VERSION
/// (D-208); the shared vectors pin it.
inline constexpr std::uint8_t kSecretstreamFormatVersion = 2;

/// A genuinely chunked/streaming AEAD master key (crypto_secretstream). Move-only, same
/// handle-ownership shape as AuthKey.
class SecretstreamKey {
 public:
  /// Generates a fresh key from the OS CSPRNG.
  static SecretstreamKey Generate() {
    DstuSecretstreamKey *out = nullptr;
    CheckStatus(dstu_secretstream_key_generate(&out));
    return SecretstreamKey(out);
  }

  /// Builds a key from exactly kSecretstreamKeyBytes bytes.
  static SecretstreamKey FromBytes(ByteView key) {
    if (key.size() != kSecretstreamKeyBytes) {
      throw ArgumentError("key must be exactly kSecretstreamKeyBytes bytes");
    }
    return SecretstreamKey(dstu_secretstream_key_from_bytes(key.data()));
  }

  SecretstreamKey(const SecretstreamKey &) = delete;
  SecretstreamKey &operator=(const SecretstreamKey &) = delete;
  SecretstreamKey(SecretstreamKey &&) noexcept = default;
  SecretstreamKey &operator=(SecretstreamKey &&) noexcept = default;
  ~SecretstreamKey() = default;

  /// Copies out this key's raw kSecretstreamKeyBytes-byte encoding.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSecretstreamKeyBytes);
    dstu_secretstream_key_bytes(ptr_.get(), out.data());
    return out;
  }

  DstuSecretstreamKey *native_handle() const { return ptr_.get(); }

 private:
  explicit SecretstreamKey(DstuSecretstreamKey *ptr) : ptr_(ptr, &dstu_secretstream_key_free) {}

  std::unique_ptr<DstuSecretstreamKey, void (*)(DstuSecretstreamKey *)> ptr_;
};

/// Encrypts writes into uacrypt encrypt's own wire format: a version byte and a
/// kSecretstreamHeaderBytes-byte header, then tag(1) || len_u32_le(4) || ciphertext ||
/// authTag(kSecretstreamTagBytes) records. Every record but the Final one carries exactly
/// kSecretstreamChunkBytes bytes (part of the format since D-208). The framing is dstu-core's
/// stream-file codec (T-284) through the C ABI; this class only buffers and writes, to a
/// caller-owned std::ostream& (never opened or closed here - the idiomatic C++ shape for "any byte
/// sink", D-158 point 2).
///
/// Deliberately does not flush a Final chunk from the destructor - unlike a typical RAII type's
/// "cleanup does everything" convention. Call Finish() explicitly once all plaintext has been
/// written; a destructor cannot reliably distinguish normal scope exit from exception unwinding
/// without std::uncaught_exceptions() bookkeeping (D-158 point 1), so an encryptor destroyed
/// without Finish() is deliberately left without a Final chunk - a reader fails closed on it
/// instead of accepting a truncated stream as complete (D-65, same D-118 property every other
/// binding's own secretstream wrapper proves).
class SecretStreamEncryptor {
 public:
  /// Starts a new stream under key, writing the version byte and header to out immediately.
  SecretStreamEncryptor(std::ostream &out, const SecretstreamKey &key)
      : SecretStreamEncryptor(out, StartWithKey(key)) {}

  /// crypto_box sealed to recipient as a stream (format v3, T-265/T-269): the same bytes
  /// BoxPublicKey::Seal returns, written chunk by chunk. Finish() rules as for a key stream.
  static SecretStreamEncryptor ForBox(std::ostream &out, const BoxPublicKey &recipient) {
    Started started{nullptr, std::vector<std::uint8_t>(DSTU_BOX_SEAL_STREAM_PREFIX_BYTES)};
    CheckStatus(dstu_box_seal_stream(recipient.native_handle(), started.prefix.data(), &started.enc));
    return SecretStreamEncryptor(out, started);
  }

  /// crypto_box384 counterpart of ForBox.
  static SecretStreamEncryptor ForBox384(std::ostream &out, const Box384PublicKey &recipient) {
    Started started{nullptr, std::vector<std::uint8_t>(DSTU_BOX384_SEAL_STREAM_PREFIX_BYTES)};
    CheckStatus(dstu_box384_seal_stream(recipient.native_handle(), started.prefix.data(), &started.enc));
    return SecretStreamEncryptor(out, started);
  }

  /// crypto_box512 counterpart of ForBox.
  static SecretStreamEncryptor ForBox512(std::ostream &out, const Box512PublicKey &recipient) {
    Started started{nullptr, std::vector<std::uint8_t>(DSTU_BOX512_SEAL_STREAM_PREFIX_BYTES)};
    CheckStatus(dstu_box512_seal_stream(recipient.native_handle(), started.prefix.data(), &started.enc));
    return SecretStreamEncryptor(out, started);
  }

  /// A passphrase file (D-219/D-240) - the bytes `uacrypt encrypt --passphrase` writes. Runs
  /// Argon2id (256 MiB, t=3, about a second) on the calling thread before writing anything.
  /// Throws ArgumentError for an empty passphrase.
  static SecretStreamEncryptor ForPassphrase(std::ostream &out, ByteView passphrase) {
    if (passphrase.size() == 0) {
      throw ArgumentError("the passphrase is empty");
    }
    Started started{nullptr, std::vector<std::uint8_t>(DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES)};
    CheckStatus(dstu_passphrase_file_seal_stream(passphrase.data(), passphrase.size(), started.prefix.data(),
                                                 &started.enc));
    return SecretStreamEncryptor(out, started);
  }

  // Not movable, unlike this file's other RAII types: a defaulted move would move buffer_ but
  // copy bufferLen_ by value, leaving the moved-from object's buffer_.size() - bufferLen_
  // invariant broken (buffer_ now empty, bufferLen_ unchanged) - a real underflow in Write() if
  // that moved-from object is ever used again. Deleting is a smaller, safer surface than writing a
  // correct custom move that also resets bufferLen_.
  SecretStreamEncryptor(const SecretStreamEncryptor &) = delete;
  SecretStreamEncryptor &operator=(const SecretStreamEncryptor &) = delete;
  SecretStreamEncryptor(SecretStreamEncryptor &&) = delete;
  SecretStreamEncryptor &operator=(SecretStreamEncryptor &&) = delete;
  ~SecretStreamEncryptor() = default;

  /// Buffers data, sealing every full kSecretstreamChunkBytes chunk that is certain not to be the
  /// last one; the last (even a full one) waits for Finish(). Full chunks are sealed straight
  /// from data.
  void Write(ByteView data) {
    if (completed_) {
      throw ArgumentError("this encryptor has already been Finish()ed");
    }
    const std::uint8_t *p = data.data();
    std::size_t remaining = data.size();
    if (bufferLen_ + remaining <= kSecretstreamChunkBytes) {
      std::copy_n(p, remaining, buffer_.begin() + static_cast<std::ptrdiff_t>(bufferLen_));
      bufferLen_ += remaining;
      return;
    }
    if (bufferLen_ > 0) {
      const std::size_t taken = kSecretstreamChunkBytes - bufferLen_;
      std::copy_n(p, taken, buffer_.begin() + static_cast<std::ptrdiff_t>(bufferLen_));
      p += taken;
      remaining -= taken;
      SealChunk(buffer_.data());
      bufferLen_ = 0;
    }
    while (remaining > kSecretstreamChunkBytes) {
      SealChunk(p);
      p += kSecretstreamChunkBytes;
      remaining -= kSecretstreamChunkBytes;
    }
    std::copy_n(p, remaining, buffer_.begin());
    bufferLen_ = remaining;
  }

  /// Writes all buffered plaintext as the Final record and marks this encryptor complete. Must be
  /// called once, on the success path - see the class doc comment for why the destructor itself
  /// never does this.
  void Finish() {
    if (completed_) {
      return;
    }
    std::size_t recordLen = 0;
    CheckStatus(dstu_secretstream_file_encryptor_seal_final(enc_.get(), buffer_.data(), bufferLen_, record_.data(),
                                                             record_.size(), &recordLen));
    WriteToStream(record_.data(), recordLen);
    bufferLen_ = 0;
    completed_ = true;
  }

 private:
  /// A native encryptor and the bytes to write before its first record.
  struct Started {
    DstuFileEncryptor *enc = nullptr;
    std::vector<std::uint8_t> prefix;
  };

  static Started StartWithKey(const SecretstreamKey &key) {
    Started started{nullptr, std::vector<std::uint8_t>(DSTU_SECRETSTREAM_FILE_PREFIX_BYTES)};
    CheckStatus(dstu_secretstream_file_encryptor_new(key.native_handle(), started.prefix.data(), &started.enc));
    return started;
  }

  SecretStreamEncryptor(std::ostream &out, const Started &started)
      : out_(&out), enc_(started.enc, &dstu_secretstream_file_encryptor_free) {
    buffer_.resize(kSecretstreamChunkBytes);
    record_.resize(DSTU_SECRETSTREAM_MAX_RECORD_BYTES);
    WriteToStream(started.prefix.data(), started.prefix.size());
  }

  void SealChunk(const std::uint8_t *chunk) {
    CheckStatus(dstu_secretstream_file_encryptor_seal_chunk(enc_.get(), chunk, kSecretstreamChunkBytes,
                                                             record_.data(), record_.size()));
    WriteToStream(record_.data(), record_.size());
  }

  void WriteToStream(const void *data, std::size_t len) {
    if (len == 0) {
      return;
    }
    out_->write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(len));
    if (!*out_) {
      throw CryptoError("secretstream: write to the output stream failed");
    }
  }

  std::ostream *out_;
  std::unique_ptr<DstuFileEncryptor, void (*)(DstuFileEncryptor *)> enc_;
  std::vector<std::uint8_t> buffer_;
  std::size_t bufferLen_ = 0;
  std::vector<std::uint8_t> record_;
  bool completed_ = false;
};

/// Decrypts a read side produced by SecretStreamEncryptor or uacrypt encrypt, from a
/// caller-owned std::istream& (never opened or closed by this wrapper). Every check - the
/// untrusted length field, the 8 KiB rule, truncation, trailing bytes after the Final chunk - is
/// dstu-core's stream-file codec (T-284); this class only reads, and reports the codec's own
/// message. The Final chunk is returned only once the input is known to end right after it, so a
/// stream with trailing data never yields its last chunk.
class SecretStreamDecryptor {
 public:
  /// Reads the version byte and the kSecretstreamHeaderBytes-byte header from in immediately.
  SecretStreamDecryptor(std::istream &in, const SecretstreamKey &key)
      : SecretStreamDecryptor(in, dstu_secretstream_file_decryptor_new(key.native_handle())) {}

  /// Reads a crypto_box stream (or a BoxPublicKey::Seal blob) with bounded memory.
  static SecretStreamDecryptor ForBox(std::istream &in, const BoxSecretKey &secret) {
    const auto prefix = ReadPrefix(in, DSTU_BOX_OPEN_STREAM_PREFIX_BYTES, "sealed message");
    DstuFileDecryptor *dec = nullptr;
    CheckStatus(dstu_box_open_stream(secret.native_handle(), prefix.data(), &dec));
    return SecretStreamDecryptor(in, dec);
  }

  /// crypto_box384 counterpart of ForBox.
  static SecretStreamDecryptor ForBox384(std::istream &in, const Box384SecretKey &secret) {
    const auto prefix = ReadPrefix(in, DSTU_BOX384_OPEN_STREAM_PREFIX_BYTES, "sealed message");
    DstuFileDecryptor *dec = nullptr;
    CheckStatus(dstu_box384_open_stream(secret.native_handle(), prefix.data(), &dec));
    return SecretStreamDecryptor(in, dec);
  }

  /// crypto_box512 counterpart of ForBox.
  static SecretStreamDecryptor ForBox512(std::istream &in, const Box512SecretKey &secret) {
    const auto prefix = ReadPrefix(in, DSTU_BOX512_OPEN_STREAM_PREFIX_BYTES, "sealed message");
    DstuFileDecryptor *dec = nullptr;
    CheckStatus(dstu_box512_open_stream(secret.native_handle(), prefix.data(), &dec));
    return SecretStreamDecryptor(in, dec);
  }

  /// Reads a passphrase file. The header is checked before Argon2 runs (on the calling thread);
  /// a wrong passphrase throws CryptoError at the first record. Throws ArgumentError for an empty
  /// passphrase.
  static SecretStreamDecryptor ForPassphrase(std::istream &in, ByteView passphrase) {
    if (passphrase.size() == 0) {
      throw ArgumentError("the passphrase is empty");
    }
    const auto header = ReadPrefix(in, DSTU_PASSPHRASE_FILE_HEADER_BYTES, "passphrase file header");
    DstuFileDecryptor *dec = nullptr;
    CheckStatus(dstu_passphrase_file_open_stream(header.data(), passphrase.data(), passphrase.size(), &dec));
    return SecretStreamDecryptor(in, dec);
  }

  // Not movable - same reasoning as SecretStreamEncryptor: a defaulted move would move
  // plaintext_ but copy pendingPos_/pendingLen_ by value, leaving a moved-from object's
  // invariants broken if it were ever used again after the move.
  SecretStreamDecryptor(const SecretStreamDecryptor &) = delete;
  SecretStreamDecryptor &operator=(const SecretStreamDecryptor &) = delete;
  SecretStreamDecryptor(SecretStreamDecryptor &&) = delete;
  SecretStreamDecryptor &operator=(SecretStreamDecryptor &&) = delete;
  ~SecretStreamDecryptor() = default;

  /// Decrypts and copies up to n bytes of plaintext into out, feeding records from the input
  /// stream as needed. Returns the number of bytes written - 0 means a Final chunk was verified
  /// and no trailing data follows (clean end of stream). Throws CryptoError if the stream ends
  /// before a Final chunk is seen, on any authentication failure, or on trailing data after
  /// Final.
  std::size_t Read(std::uint8_t *out, std::size_t n) {
    while (pendingPos_ == pendingLen_) {
      if (done_) {
        return 0;
      }
      pendingLen_ = Step();
      pendingPos_ = 0;
    }
    const std::size_t take = std::min(n, pendingLen_ - pendingPos_);
    std::copy_n(plaintext_.begin() + static_cast<std::ptrdiff_t>(pendingPos_), take, out);
    pendingPos_ += take;
    return take;
  }

  /// Convenience: decrypts and returns every remaining plaintext byte.
  std::vector<std::uint8_t> ReadAll() {
    std::vector<std::uint8_t> result;
    std::vector<std::uint8_t> buf(kSecretstreamChunkBytes);
    std::size_t n = 0;
    while ((n = Read(buf.data(), buf.size())) > 0) {
      result.insert(result.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
    }
    return result;
  }

 private:
  SecretStreamDecryptor(std::istream &in, DstuFileDecryptor *dec)
      : in_(&in), dec_(dec, &dstu_secretstream_file_decryptor_free) {
    plaintext_.resize(kSecretstreamChunkBytes);
    Step();
    Step();
  }

  /// The bytes in front of the stream file; a shorter input cannot be opened at all.
  static std::vector<std::uint8_t> ReadPrefix(std::istream &in, std::size_t size, const char *what) {
    std::vector<std::uint8_t> prefix(size);
    in.read(reinterpret_cast<char *>(prefix.data()), static_cast<std::streamsize>(size));
    if (static_cast<std::size_t>(in.gcount()) < size) {
      throw CryptoError(std::string("input too short to contain a ") + what);
    }
    return prefix;
  }

  /// Feeds the codec one next_len read; returns how many plaintext bytes that released into
  /// plaintext_ (at end of input, the Final chunk's).
  std::size_t Step() {
    const std::size_t want = dstu_secretstream_file_decryptor_next_len(dec_.get());
    std::vector<std::uint8_t> data(want);
    std::size_t got = 0;
    if (want > 0) {
      in_->read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(want));
      got = static_cast<std::size_t>(in_->gcount());
    }
    std::size_t len = 0;
    DstuStatus status = DSTU_OK;
    if (got < want) {
      done_ = true;
      status = dstu_secretstream_file_decryptor_finish(dec_.get(), plaintext_.data(), plaintext_.size(), &len);
    } else {
      status = dstu_secretstream_file_decryptor_feed(dec_.get(), data.data(), data.size(), plaintext_.data(),
                                                     plaintext_.size(), &len);
    }
    if (status != DSTU_OK) {
      if (const char *message = dstu_secretstream_file_decryptor_last_error(dec_.get())) {
        throw CryptoError(message);
      }
      CheckStatus(status);
    }
    return len;
  }

  std::istream *in_;
  std::unique_ptr<DstuFileDecryptor, void (*)(DstuFileDecryptor *)> dec_;
  std::vector<std::uint8_t> plaintext_;
  std::size_t pendingPos_ = 0;
  std::size_t pendingLen_ = 0;
  bool done_ = false;
};

}  // namespace dstu

#endif  // DSTU_CPP_SECRETSTREAM_HPP
