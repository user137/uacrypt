#ifndef DSTU_CPP_BOX384_HPP
#define DSTU_CPP_BOX384_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

class Box384PublicKey;

/// The l(p)=384 (E384/1) sibling of BoxSecretKey (crypto_box384, T-297). Same shape, a
/// distinct type - not interchangeable with crypto_box. Move-only, same handle-ownership shape as
/// AuthKey.
class Box384SecretKey {
 public:
  /// Generates a fresh secret key from the OS CSPRNG.
  static Box384SecretKey Generate() {
    DstuBox384SecretKey *out = nullptr;
    CheckStatus(dstu_box384_secretkey_generate(&out));
    return Box384SecretKey(out);
  }

  /// Builds a secret key from a big-endian kBox384SecretKeyBytes-byte scalar. Throws
  /// ArgumentError if it's outside the valid range {2, ..., n-2}.
  static Box384SecretKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBox384SecretKeyBytes) {
      throw ArgumentError("bytes must be exactly kBox384SecretKeyBytes bytes");
    }
    DstuBox384SecretKey *out = nullptr;
    CheckStatus(dstu_box384_secretkey_from_bytes(bytes.data(), &out));
    return Box384SecretKey(out);
  }

  Box384SecretKey(const Box384SecretKey &) = delete;
  Box384SecretKey &operator=(const Box384SecretKey &) = delete;
  Box384SecretKey(Box384SecretKey &&) noexcept = default;
  Box384SecretKey &operator=(Box384SecretKey &&) noexcept = default;
  ~Box384SecretKey() = default;

  /// Copies out this key's big-endian kBox384SecretKeyBytes-byte scalar encoding. The caller is
  /// responsible for wiping the returned vector once done (see Memzero) - this copies secret
  /// material into a caller-owned buffer the wrapped native key's own zeroize-on-drop cannot
  /// reach.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBox384SecretKeyBytes);
    dstu_box384_secretkey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives the public key for this secret key - safe to share/publish.
  Box384PublicKey Public() const;

  /// Decrypts sealed as produced by Box384PublicKey::Seal. Throws CryptoError if authentication
  /// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
  /// dstu_core::crypto_box384::OpenError's own doc comment) or sealed is too short to be valid.
  std::vector<std::uint8_t> Open(ByteView sealed) const {
    // The core checks the version byte before the length (T-269): a short 0.4-0.6 blob is
    // reported as an unsupported version, not as too short.
    std::vector<std::uint8_t> plaintextOut(sealed.size() > kBox384OpenMinOverhead ? sealed.size() - kBox384OpenMinOverhead : 0);
    std::size_t plaintextLen = 0;
    CheckStatus(dstu_box384_open(ptr_.get(), sealed.data(), sealed.size(), plaintextOut.data(),
                                  plaintextOut.size(), &plaintextLen));
    plaintextOut.resize(plaintextLen);
    return plaintextOut;
  }

  /// The C ABI handle, for the streaming constructors in secretstream.hpp (T-269).
  const DstuBox384SecretKey *native_handle() const { return ptr_.get(); }

 private:
  explicit Box384SecretKey(DstuBox384SecretKey *ptr) : ptr_(ptr, &dstu_box384_secretkey_free) {}

  std::unique_ptr<DstuBox384SecretKey, void (*)(DstuBox384SecretKey *)> ptr_;
};

/// A crypto_box384 public key - a curve point's x-coordinate only, see
/// dstu_core::crypto_box384's own module doc for why this compression is safe. Move-only, same
/// handle-ownership shape as AuthKey.
class Box384PublicKey {
 public:
  /// Builds a public key from its compressed kBox384PublicKeyBytes-byte x-coordinate encoding.
  /// Throws ArgumentError if it isn't a valid field element, or doesn't reconstruct to a point
  /// inside the base point's own prime-order subgroup.
  static Box384PublicKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBox384PublicKeyBytes) {
      throw ArgumentError("bytes must be exactly kBox384PublicKeyBytes bytes");
    }
    DstuBox384PublicKey *out = nullptr;
    CheckStatus(dstu_box384_publickey_from_bytes(bytes.data(), &out));
    return Box384PublicKey(out);
  }

  Box384PublicKey(const Box384PublicKey &) = delete;
  Box384PublicKey &operator=(const Box384PublicKey &) = delete;
  Box384PublicKey(Box384PublicKey &&) noexcept = default;
  Box384PublicKey &operator=(Box384PublicKey &&) noexcept = default;
  ~Box384PublicKey() = default;

  /// Copies out this key's kBox384PublicKeyBytes-byte encoding - not secret, no wiping needed
  /// afterward.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBox384PublicKeyBytes);
    dstu_box384_publickey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Encrypts message (any length) to the holder of this public key, drawing a fresh random seed
  /// and ephemeral key internally.
  std::vector<std::uint8_t> Seal(ByteView message) const {
    std::size_t sealedCap = 0;
    CheckStatus(dstu_box384_sealed_len(message.size(), &sealedCap));
    std::vector<std::uint8_t> sealedOut(sealedCap);
    std::size_t sealedLen = 0;
    CheckStatus(dstu_box384_seal(ptr_.get(), message.data(), message.size(), sealedOut.data(),
                                  sealedOut.size(), &sealedLen));
    sealedOut.resize(sealedLen);
    return sealedOut;
  }

  friend class Box384SecretKey;

  /// The C ABI handle, for the streaming constructors in secretstream.hpp (T-269).
  const DstuBox384PublicKey *native_handle() const { return ptr_.get(); }

 private:
  explicit Box384PublicKey(DstuBox384PublicKey *ptr) : ptr_(ptr, &dstu_box384_publickey_free) {}

  std::unique_ptr<DstuBox384PublicKey, void (*)(DstuBox384PublicKey *)> ptr_;
};

inline Box384PublicKey Box384SecretKey::Public() const {
  return Box384PublicKey(dstu_box384_secretkey_public_key(ptr_.get()));
}

}  // namespace dstu

#endif  // DSTU_CPP_BOX384_HPP
