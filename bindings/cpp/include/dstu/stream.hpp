#ifndef DSTU_CPP_STREAM_HPP
#define DSTU_CPP_STREAM_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

/// An unauthenticated keystream cipher key (crypto_stream, Strumok-256, internal random IV).
/// Decrypt never fails on tampered input - there is no tag to verify, and a modified sealed
/// message silently decrypts to different, wrong plaintext instead of erroring. Move-only, same
/// handle-ownership shape as AuthKey.
class StreamCipherKey {
 public:
  /// Generates a fresh key from the OS CSPRNG.
  static StreamCipherKey Generate() {
    DstuStreamKey *out = nullptr;
    CheckStatus(dstu_stream_key_generate(&out));
    return StreamCipherKey(out);
  }

  /// Builds a key from exactly kStreamKeyBytes bytes.
  static StreamCipherKey FromBytes(ByteView key) {
    if (key.size() != kStreamKeyBytes) {
      throw ArgumentError("key must be exactly kStreamKeyBytes bytes");
    }
    return StreamCipherKey(dstu_stream_key_from_bytes(key.data()));
  }

  StreamCipherKey(const StreamCipherKey &) = delete;
  StreamCipherKey &operator=(const StreamCipherKey &) = delete;
  StreamCipherKey(StreamCipherKey &&) noexcept = default;
  StreamCipherKey &operator=(StreamCipherKey &&) noexcept = default;
  ~StreamCipherKey() = default;

  /// Copies out this key's raw kStreamKeyBytes-byte encoding.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kStreamKeyBytes);
    dstu_stream_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// XORs plaintext with a fresh keystream, drawing a random IV internally. The returned vector
  /// is exactly plaintext.size() + kStreamOverhead bytes.
  std::vector<std::uint8_t> Encrypt(ByteView plaintext) const {
    std::vector<std::uint8_t> sealedOut(plaintext.size() + kStreamOverhead);
    std::size_t sealedLen = 0;
    CheckStatus(dstu_stream_encrypt(ptr_.get(), plaintext.data(), plaintext.size(), sealedOut.data(),
                                     sealedOut.size(), &sealedLen));
    sealedOut.resize(sealedLen);
    return sealedOut;
  }

  /// Reverses Encrypt. Throws CryptoError only if sealed is shorter than kStreamOverhead - there
  /// is no tag, so tampered input decrypts silently to wrong plaintext.
  std::vector<std::uint8_t> Decrypt(ByteView sealed) const {
    if (sealed.size() < kStreamOverhead) {
      throw CryptoError("input is shorter than the minimum valid length for this construction");
    }
    std::vector<std::uint8_t> plaintextOut(sealed.size() - kStreamOverhead);
    std::size_t plaintextLen = 0;
    CheckStatus(dstu_stream_decrypt(ptr_.get(), sealed.data(), sealed.size(), plaintextOut.data(),
                                     plaintextOut.size(), &plaintextLen));
    plaintextOut.resize(plaintextLen);
    return plaintextOut;
  }

 private:
  explicit StreamCipherKey(DstuStreamKey *ptr) : ptr_(ptr, &dstu_stream_key_free) {}

  std::unique_ptr<DstuStreamKey, void (*)(DstuStreamKey *)> ptr_;
};

}  // namespace dstu

#endif  // DSTU_CPP_STREAM_HPP
