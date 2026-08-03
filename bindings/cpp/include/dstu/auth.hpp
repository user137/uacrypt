#ifndef DSTU_CPP_AUTH_HPP
#define DSTU_CPP_AUTH_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

/// A Kupyna-KMAC message-authentication key (crypto_auth). Move-only: the wrapped native handle's
/// own Zeroize-on-Drop fires exactly once, when the last owner is destroyed.
class AuthKey {
 public:
  /// Generates a fresh key from the OS CSPRNG.
  static AuthKey Generate() {
    DstuAuthKey *out = nullptr;
    CheckStatus(dstu_auth_key_generate(&out));
    return AuthKey(out);
  }

  /// Builds a key from exactly kAuthKeyBytes bytes.
  static AuthKey FromBytes(ByteView key) {
    if (key.size() != kAuthKeyBytes) {
      throw ArgumentError("key must be exactly kAuthKeyBytes bytes");
    }
    return AuthKey(dstu_auth_key_from_bytes(key.data()));
  }

  AuthKey(const AuthKey &) = delete;
  AuthKey &operator=(const AuthKey &) = delete;
  AuthKey(AuthKey &&) noexcept = default;
  AuthKey &operator=(AuthKey &&) noexcept = default;
  ~AuthKey() = default;

  /// Copies out this key's raw kAuthKeyBytes-byte encoding.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kAuthKeyBytes);
    dstu_auth_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Computes the MAC of message under this key.
  std::vector<std::uint8_t> Compute(ByteView message) const {
    std::vector<std::uint8_t> tag(kAuthTagBytes);
    dstu_auth(ptr_.get(), message.data(), message.size(), tag.data());
    return tag;
  }

  /// Verifies tag against message under this key. Throws CryptoError on a mismatch.
  void Verify(ByteView message, ByteView tag) const {
    if (tag.size() != kAuthTagBytes) {
      throw ArgumentError("tag must be exactly kAuthTagBytes bytes");
    }
    CheckStatus(dstu_auth_verify(ptr_.get(), message.data(), message.size(), tag.data()));
  }

 private:
  explicit AuthKey(DstuAuthKey *ptr) : ptr_(ptr, &dstu_auth_key_free) {}

  std::unique_ptr<DstuAuthKey, void (*)(DstuAuthKey *)> ptr_;
};

}  // namespace dstu

#endif  // DSTU_CPP_AUTH_HPP
