#ifndef DSTU_CPP_BOX_HPP
#define DSTU_CPP_BOX_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

class BoxPublicKey;

/// A crypto_box secret key (hybrid via KDF over hazmat::dstu9041, D-169). Move-only, same
/// handle-ownership shape as AuthKey.
class BoxSecretKey {
 public:
  /// Generates a fresh secret key from the OS CSPRNG.
  static BoxSecretKey Generate() {
    DstuBoxSecretKey *out = nullptr;
    CheckStatus(dstu_box_secretkey_generate(&out));
    return BoxSecretKey(out);
  }

  /// Builds a secret key from a big-endian kBoxSecretKeyBytes-byte scalar. Throws ArgumentError
  /// if it's outside the valid range {2, ..., n-2}.
  static BoxSecretKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBoxSecretKeyBytes) {
      throw ArgumentError("bytes must be exactly kBoxSecretKeyBytes bytes");
    }
    DstuBoxSecretKey *out = nullptr;
    CheckStatus(dstu_box_secretkey_from_bytes(bytes.data(), &out));
    return BoxSecretKey(out);
  }

  BoxSecretKey(const BoxSecretKey &) = delete;
  BoxSecretKey &operator=(const BoxSecretKey &) = delete;
  BoxSecretKey(BoxSecretKey &&) noexcept = default;
  BoxSecretKey &operator=(BoxSecretKey &&) noexcept = default;
  ~BoxSecretKey() = default;

  /// Copies out this key's big-endian kBoxSecretKeyBytes-byte scalar encoding. The caller is
  /// responsible for wiping the returned vector once done (see Memzero) - this copies secret
  /// material into a caller-owned buffer the wrapped native key's own zeroize-on-drop cannot
  /// reach.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBoxSecretKeyBytes);
    dstu_box_secretkey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives the public key for this secret key - safe to share/publish.
  BoxPublicKey Public() const;

  /// Decrypts sealed as produced by BoxPublicKey::Seal. Throws CryptoError if authentication
  /// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
  /// dstu_core::crypto_box::OpenError's own doc comment) or sealed is too short to be valid.
  std::vector<std::uint8_t> Open(ByteView sealed) const {
    if (sealed.size() < kBoxSealOverhead) {
      throw CryptoError("input is shorter than the minimum valid length for this construction");
    }
    std::vector<std::uint8_t> plaintextOut(sealed.size() - kBoxSealOverhead);
    std::size_t plaintextLen = 0;
    CheckStatus(dstu_box_open(ptr_.get(), sealed.data(), sealed.size(), plaintextOut.data(),
                               plaintextOut.size(), &plaintextLen));
    plaintextOut.resize(plaintextLen);
    return plaintextOut;
  }

 private:
  explicit BoxSecretKey(DstuBoxSecretKey *ptr) : ptr_(ptr, &dstu_box_secretkey_free) {}

  std::unique_ptr<DstuBoxSecretKey, void (*)(DstuBoxSecretKey *)> ptr_;
};

/// A crypto_box public key - a curve point's x-coordinate only, see dstu_core::crypto_box's own
/// module doc for why this compression is safe. Move-only, same handle-ownership shape as
/// AuthKey.
class BoxPublicKey {
 public:
  /// Builds a public key from its compressed kBoxPublicKeyBytes-byte x-coordinate encoding.
  /// Throws ArgumentError if it isn't a valid field element, or doesn't reconstruct to a point
  /// inside the base point's own prime-order subgroup.
  static BoxPublicKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBoxPublicKeyBytes) {
      throw ArgumentError("bytes must be exactly kBoxPublicKeyBytes bytes");
    }
    DstuBoxPublicKey *out = nullptr;
    CheckStatus(dstu_box_publickey_from_bytes(bytes.data(), &out));
    return BoxPublicKey(out);
  }

  BoxPublicKey(const BoxPublicKey &) = delete;
  BoxPublicKey &operator=(const BoxPublicKey &) = delete;
  BoxPublicKey(BoxPublicKey &&) noexcept = default;
  BoxPublicKey &operator=(BoxPublicKey &&) noexcept = default;
  ~BoxPublicKey() = default;

  /// Copies out this key's kBoxPublicKeyBytes-byte encoding - not secret, no wiping needed
  /// afterward.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBoxPublicKeyBytes);
    dstu_box_publickey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Encrypts message (any length) to the holder of this public key, drawing a fresh random seed
  /// and ephemeral key internally.
  std::vector<std::uint8_t> Seal(ByteView message) const {
    std::vector<std::uint8_t> sealedOut(message.size() + kBoxSealOverhead);
    std::size_t sealedLen = 0;
    CheckStatus(dstu_box_seal(ptr_.get(), message.data(), message.size(), sealedOut.data(),
                               sealedOut.size(), &sealedLen));
    sealedOut.resize(sealedLen);
    return sealedOut;
  }

  friend class BoxSecretKey;

 private:
  explicit BoxPublicKey(DstuBoxPublicKey *ptr) : ptr_(ptr, &dstu_box_publickey_free) {}

  std::unique_ptr<DstuBoxPublicKey, void (*)(DstuBoxPublicKey *)> ptr_;
};

inline BoxPublicKey BoxSecretKey::Public() const {
  return BoxPublicKey(dstu_box_secretkey_public_key(ptr_.get()));
}

}  // namespace dstu

#endif  // DSTU_CPP_BOX_HPP
