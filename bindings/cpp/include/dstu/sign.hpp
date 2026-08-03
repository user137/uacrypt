#ifndef DSTU_CPP_SIGN_HPP
#define DSTU_CPP_SIGN_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

class VerifyingKey;

/// A DSTU 4145 signing key (crypto_sign). Signing is deterministic (Kupyna-KMAC-derived nonce) -
/// no RNG dependency beyond key generation. Move-only, same handle-ownership shape as AuthKey.
class SigningKey {
 public:
  /// Generates a fresh signing key from the OS CSPRNG.
  static SigningKey Generate() {
    DstuSigningKey *out = nullptr;
    CheckStatus(dstu_sign_key_generate(&out));
    return SigningKey(out);
  }

  /// Builds a signing key from a big-endian kSignPrivateKeyBytes-byte scalar d. Throws
  /// ArgumentError if d is zero or >= the curve order.
  static SigningKey FromBytes(ByteView d) {
    if (d.size() != kSignPrivateKeyBytes) {
      throw ArgumentError("d must be exactly kSignPrivateKeyBytes bytes");
    }
    DstuSigningKey *out = nullptr;
    CheckStatus(dstu_sign_key_from_bytes(d.data(), &out));
    return SigningKey(out);
  }

  SigningKey(const SigningKey &) = delete;
  SigningKey &operator=(const SigningKey &) = delete;
  SigningKey(SigningKey &&) noexcept = default;
  SigningKey &operator=(SigningKey &&) noexcept = default;
  ~SigningKey() = default;

  /// Copies out this key's big-endian kSignPrivateKeyBytes-byte scalar encoding. The caller is
  /// responsible for wiping the returned vector once done (see Memzero) - this copies secret
  /// material into a caller-owned buffer the wrapped native key's own zeroize-on-drop cannot
  /// reach.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSignPrivateKeyBytes);
    dstu_sign_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives the public verifying key for this signing key.
  VerifyingKey Verifying() const;

  /// Signs message, hashing it with Kupyna-256 internally.
  std::vector<std::uint8_t> Sign(ByteView message) const {
    std::vector<std::uint8_t> sig(kSignSignatureBytes);
    dstu_sign(ptr_.get(), message.data(), message.size(), sig.data());
    return sig;
  }

  /// Signs an already-computed kSignDigestBytes-byte Kupyna-256 digest directly - for a message
  /// hashed incrementally rather than held whole in memory.
  std::vector<std::uint8_t> SignDigest(ByteView digest) const {
    if (digest.size() != kSignDigestBytes) {
      throw ArgumentError("digest must be exactly kSignDigestBytes bytes");
    }
    std::vector<std::uint8_t> sig(kSignSignatureBytes);
    dstu_sign_digest(ptr_.get(), digest.data(), sig.data());
    return sig;
  }

  DstuSigningKey *native_handle() const { return ptr_.get(); }

 private:
  explicit SigningKey(DstuSigningKey *ptr) : ptr_(ptr, &dstu_sign_key_free) {}

  std::unique_ptr<DstuSigningKey, void (*)(DstuSigningKey *)> ptr_;
};

/// A DSTU 4145 public verifying key. Move-only, same handle-ownership shape as AuthKey.
class VerifyingKey {
 public:
  /// Builds a verifying key from kSignPublicKeyBytes bytes of plain x || y encoding - no
  /// validation that the point is on the curve, matching the wrapped native function's own
  /// convention.
  static VerifyingKey FromBytes(ByteView b) {
    if (b.size() != kSignPublicKeyBytes) {
      throw ArgumentError("b must be exactly kSignPublicKeyBytes bytes");
    }
    return VerifyingKey(dstu_verifying_key_from_bytes(b.data()));
  }

  VerifyingKey(const VerifyingKey &) = delete;
  VerifyingKey &operator=(const VerifyingKey &) = delete;
  VerifyingKey(VerifyingKey &&) noexcept = default;
  VerifyingKey &operator=(VerifyingKey &&) noexcept = default;
  ~VerifyingKey() = default;

  /// Copies out this key's plain x || y kSignPublicKeyBytes-byte encoding (not the DSTU 4145
  /// standard's own compressed point encoding).
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSignPublicKeyBytes);
    dstu_verifying_key_to_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Verifies sig over message.
  bool Verify(ByteView message, ByteView sig) const {
    if (sig.size() != kSignSignatureBytes) {
      throw ArgumentError("sig must be exactly kSignSignatureBytes bytes");
    }
    return dstu_verify(ptr_.get(), message.data(), message.size(), sig.data());
  }

  /// Verifies sig over an already-computed kSignDigestBytes-byte digest directly.
  bool VerifyDigest(ByteView digest, ByteView sig) const {
    if (digest.size() != kSignDigestBytes) {
      throw ArgumentError("digest must be exactly kSignDigestBytes bytes");
    }
    if (sig.size() != kSignSignatureBytes) {
      throw ArgumentError("sig must be exactly kSignSignatureBytes bytes");
    }
    return dstu_verify_digest(ptr_.get(), digest.data(), sig.data());
  }

  friend class SigningKey;

 private:
  explicit VerifyingKey(DstuVerifyingKey *ptr) : ptr_(ptr, &dstu_verifying_key_free) {}

  std::unique_ptr<DstuVerifyingKey, void (*)(DstuVerifyingKey *)> ptr_;
};

inline VerifyingKey SigningKey::Verifying() const {
  return VerifyingKey(dstu_sign_verifying_key(ptr_.get()));
}

}  // namespace dstu

#endif  // DSTU_CPP_SIGN_HPP
