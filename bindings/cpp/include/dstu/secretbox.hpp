#ifndef DSTU_CPP_SECRETBOX_HPP
#define DSTU_CPP_SECRETBOX_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

/// An authenticated single-message encryption key (crypto_secretbox, Kalyna-256-256-GCM,
/// internal random nonce). Move-only, same handle-ownership shape as AuthKey.
class SecretboxKey {
 public:
  /// Generates a fresh key from the OS CSPRNG.
  static SecretboxKey Generate() {
    DstuSecretboxKey *out = nullptr;
    CheckStatus(dstu_secretbox_key_generate(&out));
    return SecretboxKey(out);
  }

  /// Builds a key from exactly kSecretboxKeyBytes bytes.
  static SecretboxKey FromBytes(ByteView key) {
    if (key.size() != kSecretboxKeyBytes) {
      throw ArgumentError("key must be exactly kSecretboxKeyBytes bytes");
    }
    return SecretboxKey(dstu_secretbox_key_from_bytes(key.data()));
  }

  SecretboxKey(const SecretboxKey &) = delete;
  SecretboxKey &operator=(const SecretboxKey &) = delete;
  SecretboxKey(SecretboxKey &&) noexcept = default;
  SecretboxKey &operator=(SecretboxKey &&) noexcept = default;
  ~SecretboxKey() = default;

  /// Copies out this key's raw kSecretboxKeyBytes-byte encoding.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSecretboxKeyBytes);
    dstu_secretbox_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Encrypts and authenticates plaintext, drawing a fresh random nonce internally. The returned
  /// vector is exactly plaintext.size() + kSecretboxOverhead bytes.
  std::vector<std::uint8_t> Seal(ByteView plaintext) const {
    std::vector<std::uint8_t> sealedOut(plaintext.size() + kSecretboxOverhead);
    std::size_t sealedLen = 0;
    CheckStatus(dstu_secretbox_seal(ptr_.get(), plaintext.data(), plaintext.size(), sealedOut.data(),
                                     sealedOut.size(), &sealedLen));
    sealedOut.resize(sealedLen);
    return sealedOut;
  }

  /// Verifies and decrypts sealed as produced by Seal. Throws CryptoError on a tag mismatch or
  /// truncated input.
  std::vector<std::uint8_t> Open(ByteView sealed) const {
    if (sealed.size() < kSecretboxOverhead) {
      throw CryptoError("input is shorter than the minimum valid length for this construction");
    }
    std::vector<std::uint8_t> plaintextOut(sealed.size() - kSecretboxOverhead);
    std::size_t plaintextLen = 0;
    CheckStatus(dstu_secretbox_open(ptr_.get(), sealed.data(), sealed.size(), plaintextOut.data(),
                                     plaintextOut.size(), &plaintextLen));
    plaintextOut.resize(plaintextLen);
    return plaintextOut;
  }

 private:
  explicit SecretboxKey(DstuSecretboxKey *ptr) : ptr_(ptr, &dstu_secretbox_key_free) {}

  std::unique_ptr<DstuSecretboxKey, void (*)(DstuSecretboxKey *)> ptr_;
};

}  // namespace dstu

#endif  // DSTU_CPP_SECRETBOX_HPP
