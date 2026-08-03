#ifndef DSTU_CPP_SECRETSTREAM_HPP
#define DSTU_CPP_SECRETSTREAM_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>

namespace dstu {

/// The plaintext chunk size uacrypt encrypt's own wire format frames at - mirrors
/// bindings/go/dstu/secretstream.go's SecretstreamChunkBytes and
/// crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES.
inline constexpr std::size_t kSecretstreamChunkBytes = 8192;

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

/// Encrypts writes into uacrypt encrypt's own wire format: a kSecretstreamHeaderBytes-byte
/// header, then tag(1) || len_u32_le(4) || ciphertext || authTag(kSecretstreamTagBytes) records
/// framed at kSecretstreamChunkBytes-byte plaintext boundaries. Writes to a caller-owned
/// std::ostream& (this wrapper never opens or closes it - the idiomatic C++ shape for "any byte
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
  /// Starts a new stream under key, writing the header to out immediately.
  SecretStreamEncryptor(std::ostream &out, const SecretstreamKey &key)
      : out_(&out), state_(nullptr, &dstu_secretstream_push_free) {
    buffer_.resize(kSecretstreamChunkBytes);
    std::vector<std::uint8_t> header(kSecretstreamHeaderBytes);
    DstuPushState *state = nullptr;
    CheckStatus(dstu_secretstream_push_init(key.native_handle(), &state, header.data()));
    state_.reset(state);
    WriteToStream(header.data(), header.size());
  }

  // Not movable, unlike this file's other RAII types: a defaulted move would move state_/pending_
  // but copy bufferLen_ by value, leaving the moved-from object's buffer_.size() - bufferLen_
  // invariant broken (buffer_ now empty, bufferLen_ unchanged) - a real underflow in Write() if
  // that moved-from object is ever used again. Deleting is a smaller, safer surface than writing a
  // correct custom move that also resets bufferLen_.
  SecretStreamEncryptor(const SecretStreamEncryptor &) = delete;
  SecretStreamEncryptor &operator=(const SecretStreamEncryptor &) = delete;
  SecretStreamEncryptor(SecretStreamEncryptor &&) = delete;
  SecretStreamEncryptor &operator=(SecretStreamEncryptor &&) = delete;
  ~SecretStreamEncryptor() = default;

  /// Buffers data, encrypting and emitting a Message chunk each time kSecretstreamChunkBytes of
  /// plaintext accumulate.
  void Write(ByteView data) {
    if (completed_) {
      throw ArgumentError("this encryptor has already been Finish()ed");
    }
    const std::uint8_t *p = data.data();
    std::size_t remaining = data.size();
    while (remaining > 0) {
      std::size_t take = std::min(remaining, buffer_.size() - bufferLen_);
      std::memcpy(buffer_.data() + bufferLen_, p, take);
      bufferLen_ += take;
      p += take;
      remaining -= take;
      if (bufferLen_ == buffer_.size()) {
        FlushPendingAsMessage();
        pending_.assign(buffer_.begin(), buffer_.end());
        bufferLen_ = 0;
      }
    }
  }

  /// Flushes all buffered plaintext as a Final chunk and marks this encryptor complete. Must be
  /// called once, on the success path - see the class doc comment for why the destructor itself
  /// never does this.
  void Finish() {
    if (completed_) {
      return;
    }
    if (bufferLen_ > 0) {
      FlushPendingAsMessage();
      WriteChunk(SecretstreamTag::kFinal, ByteView(buffer_.data(), bufferLen_));
    } else if (!pending_.empty()) {
      std::vector<std::uint8_t> pending = std::move(pending_);
      pending_.clear();
      WriteChunk(SecretstreamTag::kFinal, pending);
    } else {
      WriteChunk(SecretstreamTag::kFinal, ByteView());
    }
    completed_ = true;
  }

 private:
  void FlushPendingAsMessage() {
    if (pending_.empty()) {
      return;
    }
    std::vector<std::uint8_t> pending = std::move(pending_);
    pending_.clear();
    WriteChunk(SecretstreamTag::kMessage, pending);
  }

  void WriteChunk(SecretstreamTag tag, ByteView plaintext) {
    std::vector<std::uint8_t> ciphertext(plaintext.size());
    std::vector<std::uint8_t> tagOut(kSecretstreamTagBytes);
    CheckStatus(dstu_secretstream_push(state_.get(), static_cast<DstuTag>(tag), plaintext.data(),
                                        plaintext.size(), ciphertext.data(), ciphertext.size(), tagOut.data()));

    std::uint8_t header[5];
    header[0] = static_cast<std::uint8_t>(tag);
    auto len = static_cast<std::uint32_t>(plaintext.size());
    header[1] = static_cast<std::uint8_t>(len);
    header[2] = static_cast<std::uint8_t>(len >> 8);
    header[3] = static_cast<std::uint8_t>(len >> 16);
    header[4] = static_cast<std::uint8_t>(len >> 24);
    WriteToStream(header, sizeof(header));
    WriteToStream(ciphertext.data(), ciphertext.size());
    WriteToStream(tagOut.data(), tagOut.size());
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
  std::unique_ptr<DstuPushState, void (*)(DstuPushState *)> state_;
  std::vector<std::uint8_t> buffer_;
  std::size_t bufferLen_ = 0;
  std::vector<std::uint8_t> pending_;
  bool completed_ = false;
};

/// Decrypts a read side produced by SecretStreamEncryptor or uacrypt encrypt, from a
/// caller-owned std::istream& (never opened or closed by this wrapper). Bounds every untrusted
/// length-prefixed chunk-length field against kSecretstreamChunkBytes before using it to size a
/// read, and rejects trailing bytes after the Final chunk - both checks the wire format's own
/// framing does not provide for free (D-118's second pitfall; mirrors uacrypt's own
/// CliError::SecretstreamChunkTooLarge/SecretstreamTrailingData).
class SecretStreamDecryptor {
 public:
  /// Reads the kSecretstreamHeaderBytes-byte header from in immediately and re-derives the
  /// stream's initial subkey.
  SecretStreamDecryptor(std::istream &in, const SecretstreamKey &key)
      : in_(&in), state_(nullptr, &dstu_secretstream_pull_free) {
    std::vector<std::uint8_t> header = ReadExactly(kSecretstreamHeaderBytes);
    state_.reset(dstu_secretstream_pull_init(key.native_handle(), header.data()));
  }

  // Not movable - same reasoning as SecretStreamEncryptor: a defaulted move would move pending_
  // but copy pendingPos_ by value, leaving a moved-from object's pending_.size() - pendingPos_
  // invariant broken if it were ever used again after the move.
  SecretStreamDecryptor(const SecretStreamDecryptor &) = delete;
  SecretStreamDecryptor &operator=(const SecretStreamDecryptor &) = delete;
  SecretStreamDecryptor(SecretStreamDecryptor &&) = delete;
  SecretStreamDecryptor &operator=(SecretStreamDecryptor &&) = delete;
  ~SecretStreamDecryptor() = default;

  /// Decrypts and copies up to n bytes of plaintext into out, pulling and verifying chunks from
  /// the input stream as needed. Returns the number of bytes written - 0 means a Final chunk was
  /// verified and no trailing data follows (clean end of stream). Throws CryptoError if the
  /// stream ends before a Final chunk is seen, on any authentication failure, or on trailing data
  /// after Final.
  std::size_t Read(std::uint8_t *out, std::size_t n) {
    while (pendingPos_ == pending_.size()) {
      if (finalized_) {
        return 0;
      }
      if (!ReadNextChunk()) {
        throw CryptoError("secretstream ended before a Final chunk was seen - the input is truncated");
      }
    }
    std::size_t take = std::min(n, pending_.size() - pendingPos_);
    std::memcpy(out, pending_.data() + pendingPos_, take);
    pendingPos_ += take;
    return take;
  }

  /// Convenience: decrypts and returns every remaining plaintext byte.
  std::vector<std::uint8_t> ReadAll() {
    std::vector<std::uint8_t> result;
    std::uint8_t buf[kSecretstreamChunkBytes];
    std::size_t n;
    while ((n = Read(buf, sizeof(buf))) > 0) {
      result.insert(result.end(), buf, buf + n);
    }
    return result;
  }

 private:
  /// Reads and decrypts the next chunk into pending_/pendingPos_. Returns false only when the
  /// stream had no bytes at all left to start a new chunk (genuine truncation, handled by the
  /// caller). Sets finalized_ (and checks for trailing data) once a Final chunk verifies.
  bool ReadNextChunk() {
    std::uint8_t tagByte = 0;
    in_->read(reinterpret_cast<char *>(&tagByte), 1);
    if (in_->gcount() == 0) {
      return false;
    }

    std::vector<std::uint8_t> lenBytes = ReadExactly(4);
    auto length = static_cast<std::uint32_t>(lenBytes[0]) | (static_cast<std::uint32_t>(lenBytes[1]) << 8) |
                  (static_cast<std::uint32_t>(lenBytes[2]) << 16) | (static_cast<std::uint32_t>(lenBytes[3]) << 24);
    if (length > kSecretstreamChunkBytes) {
      throw CryptoError("secretstream chunk length exceeds the maximum kSecretstreamChunkBytes - the input is corrupted");
    }

    std::vector<std::uint8_t> ciphertext = ReadExactly(length);
    std::vector<std::uint8_t> authTag = ReadExactly(kSecretstreamTagBytes);

    std::vector<std::uint8_t> plaintextOut(length);
    DstuTag outTag;
    CheckStatus(dstu_secretstream_pull(state_.get(), tagByte, ciphertext.data(), ciphertext.size(), authTag.data(),
                                        plaintextOut.data(), plaintextOut.size(), &outTag));

    pending_ = std::move(plaintextOut);
    pendingPos_ = 0;
    if (static_cast<SecretstreamTag>(outTag) == SecretstreamTag::kFinal) {
      finalized_ = true;
      std::uint8_t probe = 0;
      in_->read(reinterpret_cast<char *>(&probe), 1);
      if (in_->gcount() != 0) {
        throw CryptoError("secretstream has trailing data after its Final chunk");
      }
    }
    return true;
  }

  std::vector<std::uint8_t> ReadExactly(std::size_t n) {
    std::vector<std::uint8_t> buf(n);
    if (n == 0) {
      return buf;
    }
    in_->read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(n));
    if (static_cast<std::size_t>(in_->gcount()) != n) {
      throw CryptoError("secretstream ended unexpectedly mid-chunk - the input is truncated");
    }
    return buf;
  }

  std::istream *in_;
  std::unique_ptr<DstuPullState, void (*)(DstuPullState *)> state_;
  std::vector<std::uint8_t> pending_;
  std::size_t pendingPos_ = 0;
  bool finalized_ = false;
};

}  // namespace dstu

#endif  // DSTU_CPP_SECRETSTREAM_HPP
