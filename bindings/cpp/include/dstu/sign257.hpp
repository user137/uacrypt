#ifndef DSTU_CPP_SIGN257_HPP
#define DSTU_CPP_SIGN257_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

class VerifyingKey257;

/// A DSTU 4145 m=257 signing key (crypto_sign257, T-199/T-204) - the curve real Diia-issued
/// qualified signatures use. Same shape as SigningKey, a distinct type - not interchangeable with
/// crypto_sign's m=163. Signing is deterministic (Kupyna-KMAC-derived nonce) - no RNG dependency
/// beyond key generation. Move-only, same handle-ownership shape as AuthKey.
class SigningKey257 {
 public:
  /// Generates a fresh signing key from the OS CSPRNG.
  static SigningKey257 Generate() {
    DstuSigningKey257 *out = nullptr;
    CheckStatus(dstu_sign257_key_generate(&out));
    return SigningKey257(out);
  }

  /// Builds a signing key from a big-endian kSign257PrivateKeyBytes-byte scalar d. Throws
  /// ArgumentError if d is zero or >= the curve order.
  static SigningKey257 FromBytes(ByteView d) {
    if (d.size() != kSign257PrivateKeyBytes) {
      throw ArgumentError("d must be exactly kSign257PrivateKeyBytes bytes");
    }
    DstuSigningKey257 *out = nullptr;
    CheckStatus(dstu_sign257_key_from_bytes(d.data(), &out));
    return SigningKey257(out);
  }

  SigningKey257(const SigningKey257 &) = delete;
  SigningKey257 &operator=(const SigningKey257 &) = delete;
  SigningKey257(SigningKey257 &&) noexcept = default;
  SigningKey257 &operator=(SigningKey257 &&) noexcept = default;
  ~SigningKey257() = default;

  /// Copies out this key's big-endian kSign257PrivateKeyBytes-byte scalar encoding. The caller is
  /// responsible for wiping the returned vector once done (see Memzero) - this copies secret
  /// material into a caller-owned buffer the wrapped native key's own zeroize-on-drop cannot
  /// reach.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSign257PrivateKeyBytes);
    dstu_sign257_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives the public verifying key for this signing key.
  VerifyingKey257 Verifying() const;

  /// Signs message, hashing it with Kupyna-256 internally.
  std::vector<std::uint8_t> Sign(ByteView message) const {
    std::vector<std::uint8_t> sig(kSign257SignatureBytes);
    dstu_sign257(ptr_.get(), message.data(), message.size(), sig.data());
    return sig;
  }

  /// Signs an already-computed kSign257DigestBytes-byte Kupyna-256 digest directly - for a
  /// message hashed incrementally rather than held whole in memory.
  std::vector<std::uint8_t> SignDigest(ByteView digest) const {
    if (digest.size() != kSign257DigestBytes) {
      throw ArgumentError("digest must be exactly kSign257DigestBytes bytes");
    }
    std::vector<std::uint8_t> sig(kSign257SignatureBytes);
    dstu_sign257_digest(ptr_.get(), digest.data(), sig.data());
    return sig;
  }

  DstuSigningKey257 *native_handle() const { return ptr_.get(); }

 private:
  explicit SigningKey257(DstuSigningKey257 *ptr) : ptr_(ptr, &dstu_sign257_key_free) {}

  std::unique_ptr<DstuSigningKey257, void (*)(DstuSigningKey257 *)> ptr_;
};

/// A DSTU 4145 m=257 public verifying key. No curve-tag byte at this layer - the tag/dispatch
/// mechanism lives at the uacrypt serialization layer only (D-118), the same convention the
/// underlying C ABI's own module doc documents. Move-only, same handle-ownership shape as AuthKey.
class VerifyingKey257 {
 public:
  /// Builds a verifying key from kSign257PublicKeyBytes bytes of plain x || y encoding - no
  /// validation that the point is on the curve, matching the wrapped native function's own
  /// convention.
  static VerifyingKey257 FromBytes(ByteView b) {
    if (b.size() != kSign257PublicKeyBytes) {
      throw ArgumentError("b must be exactly kSign257PublicKeyBytes bytes");
    }
    return VerifyingKey257(dstu_verifying_key257_from_bytes(b.data()));
  }

  VerifyingKey257(const VerifyingKey257 &) = delete;
  VerifyingKey257 &operator=(const VerifyingKey257 &) = delete;
  VerifyingKey257(VerifyingKey257 &&) noexcept = default;
  VerifyingKey257 &operator=(VerifyingKey257 &&) noexcept = default;
  ~VerifyingKey257() = default;

  /// Copies out this key's plain x || y kSign257PublicKeyBytes-byte encoding (not the DSTU 4145
  /// standard's own compressed point encoding).
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kSign257PublicKeyBytes);
    dstu_verifying_key257_to_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Verifies sig over message.
  bool Verify(ByteView message, ByteView sig) const {
    if (sig.size() != kSign257SignatureBytes) {
      throw ArgumentError("sig must be exactly kSign257SignatureBytes bytes");
    }
    return dstu_verify257(ptr_.get(), message.data(), message.size(), sig.data());
  }

  /// Verifies sig over an already-computed kSign257DigestBytes-byte digest directly.
  bool VerifyDigest(ByteView digest, ByteView sig) const {
    if (digest.size() != kSign257DigestBytes) {
      throw ArgumentError("digest must be exactly kSign257DigestBytes bytes");
    }
    if (sig.size() != kSign257SignatureBytes) {
      throw ArgumentError("sig must be exactly kSign257SignatureBytes bytes");
    }
    return dstu_verify257_digest(ptr_.get(), digest.data(), sig.data());
  }

  friend class SigningKey257;

 private:
  explicit VerifyingKey257(DstuVerifyingKey257 *ptr) : ptr_(ptr, &dstu_verifying_key257_free) {}

  std::unique_ptr<DstuVerifyingKey257, void (*)(DstuVerifyingKey257 *)> ptr_;
};

inline VerifyingKey257 SigningKey257::Verifying() const {
  return VerifyingKey257(dstu_sign257_verifying_key(ptr_.get()));
}

}  // namespace dstu

#endif  // DSTU_CPP_SIGN257_HPP
