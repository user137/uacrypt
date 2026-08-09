#ifndef DSTU_CPP_BOX512_HPP
#define DSTU_CPP_BOX512_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

class Box512PublicKey;

/// The l(p)=512 (E512/1) sibling of BoxSecretKey (crypto_box512, T-193/T-204). Same shape, a
/// distinct type - not interchangeable with crypto_box. Move-only, same handle-ownership shape as
/// AuthKey.
class Box512SecretKey {
 public:
  /// Generates a fresh secret key from the OS CSPRNG.
  static Box512SecretKey Generate() {
    DstuBox512SecretKey *out = nullptr;
    CheckStatus(dstu_box512_secretkey_generate(&out));
    return Box512SecretKey(out);
  }

  /// Builds a secret key from a big-endian kBox512SecretKeyBytes-byte scalar. Throws
  /// ArgumentError if it's outside the valid range {2, ..., n-2}.
  static Box512SecretKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBox512SecretKeyBytes) {
      throw ArgumentError("bytes must be exactly kBox512SecretKeyBytes bytes");
    }
    DstuBox512SecretKey *out = nullptr;
    CheckStatus(dstu_box512_secretkey_from_bytes(bytes.data(), &out));
    return Box512SecretKey(out);
  }

  Box512SecretKey(const Box512SecretKey &) = delete;
  Box512SecretKey &operator=(const Box512SecretKey &) = delete;
  Box512SecretKey(Box512SecretKey &&) noexcept = default;
  Box512SecretKey &operator=(Box512SecretKey &&) noexcept = default;
  ~Box512SecretKey() = default;

  /// Copies out this key's big-endian kBox512SecretKeyBytes-byte scalar encoding. The caller is
  /// responsible for wiping the returned vector once done (see Memzero) - this copies secret
  /// material into a caller-owned buffer the wrapped native key's own zeroize-on-drop cannot
  /// reach.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBox512SecretKeyBytes);
    dstu_box512_secretkey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives the public key for this secret key - safe to share/publish.
  Box512PublicKey Public() const;

  /// Decrypts sealed as produced by Box512PublicKey::Seal. Throws CryptoError if authentication
  /// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
  /// dstu_core::crypto_box512::OpenError's own doc comment) or sealed is too short to be valid.
  std::vector<std::uint8_t> Open(ByteView sealed) const {
    if (sealed.size() < kBox512SealOverhead) {
      throw CryptoError("input is shorter than the minimum valid length for this construction");
    }
    std::vector<std::uint8_t> plaintextOut(sealed.size() - kBox512SealOverhead);
    std::size_t plaintextLen = 0;
    CheckStatus(dstu_box512_open(ptr_.get(), sealed.data(), sealed.size(), plaintextOut.data(),
                                  plaintextOut.size(), &plaintextLen));
    plaintextOut.resize(plaintextLen);
    return plaintextOut;
  }

 private:
  explicit Box512SecretKey(DstuBox512SecretKey *ptr) : ptr_(ptr, &dstu_box512_secretkey_free) {}

  std::unique_ptr<DstuBox512SecretKey, void (*)(DstuBox512SecretKey *)> ptr_;
};

/// A crypto_box512 public key - a curve point's x-coordinate only, see
/// dstu_core::crypto_box512's own module doc for why this compression is safe. Move-only, same
/// handle-ownership shape as AuthKey.
class Box512PublicKey {
 public:
  /// Builds a public key from its compressed kBox512PublicKeyBytes-byte x-coordinate encoding.
  /// Throws ArgumentError if it isn't a valid field element, or doesn't reconstruct to a point
  /// inside the base point's own prime-order subgroup.
  static Box512PublicKey FromBytes(ByteView bytes) {
    if (bytes.size() != kBox512PublicKeyBytes) {
      throw ArgumentError("bytes must be exactly kBox512PublicKeyBytes bytes");
    }
    DstuBox512PublicKey *out = nullptr;
    CheckStatus(dstu_box512_publickey_from_bytes(bytes.data(), &out));
    return Box512PublicKey(out);
  }

  Box512PublicKey(const Box512PublicKey &) = delete;
  Box512PublicKey &operator=(const Box512PublicKey &) = delete;
  Box512PublicKey(Box512PublicKey &&) noexcept = default;
  Box512PublicKey &operator=(Box512PublicKey &&) noexcept = default;
  ~Box512PublicKey() = default;

  /// Copies out this key's kBox512PublicKeyBytes-byte encoding - not secret, no wiping needed
  /// afterward.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kBox512PublicKeyBytes);
    dstu_box512_publickey_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Encrypts message (any length) to the holder of this public key, drawing a fresh random seed
  /// and ephemeral key internally.
  std::vector<std::uint8_t> Seal(ByteView message) const {
    std::vector<std::uint8_t> sealedOut(message.size() + kBox512SealOverhead);
    std::size_t sealedLen = 0;
    CheckStatus(dstu_box512_seal(ptr_.get(), message.data(), message.size(), sealedOut.data(),
                                  sealedOut.size(), &sealedLen));
    sealedOut.resize(sealedLen);
    return sealedOut;
  }

  friend class Box512SecretKey;

 private:
  explicit Box512PublicKey(DstuBox512PublicKey *ptr) : ptr_(ptr, &dstu_box512_publickey_free) {}

  std::unique_ptr<DstuBox512PublicKey, void (*)(DstuBox512PublicKey *)> ptr_;
};

inline Box512PublicKey Box512SecretKey::Public() const {
  return Box512PublicKey(dstu_box512_secretkey_public_key(ptr_.get()));
}

}  // namespace dstu

#endif  // DSTU_CPP_BOX512_HPP
