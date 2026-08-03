#ifndef DSTU_CPP_CONSTANTS_HPP
#define DSTU_CPP_CONSTANTS_HPP

#include "dstu_core.h"

#include <cstddef>

/// Fixed byte lengths mirroring the DSTU_* macros in dstu_core.h.
namespace dstu {

inline constexpr std::size_t kAuthKeyBytes = DSTU_AUTH_KEY_BYTES;
inline constexpr std::size_t kAuthTagBytes = DSTU_AUTH_TAG_BYTES;
inline constexpr std::size_t kGenericHash256Bytes = DSTU_GENERICHASH_256_BYTES;
inline constexpr std::size_t kGenericHash512Bytes = DSTU_GENERICHASH_512_BYTES;
inline constexpr std::size_t kKdfKeyBytes = DSTU_KDF_KEY_BYTES;
inline constexpr std::size_t kKdfContextBytes = DSTU_KDF_CONTEXT_BYTES;
inline constexpr std::size_t kKdfSubkeyBytes = DSTU_KDF_SUBKEY_BYTES;
/// Fixed buffer size for a PHC string produced by HashPassword.
inline constexpr std::size_t kPwhashStrBytes = DSTU_PWHASH_STRBYTES;
inline constexpr std::size_t kSecretboxKeyBytes = DSTU_SECRETBOX_KEY_BYTES;
/// 32-byte nonce + 16-byte tag added by SecretboxKey::Seal.
inline constexpr std::size_t kSecretboxOverhead = DSTU_SECRETBOX_OVERHEAD;
inline constexpr std::size_t kSecretstreamKeyBytes = DSTU_SECRETSTREAM_KEY_BYTES;
inline constexpr std::size_t kSecretstreamHeaderBytes = DSTU_SECRETSTREAM_HEADER_BYTES;
inline constexpr std::size_t kSecretstreamTagBytes = DSTU_SECRETSTREAM_TAG_BYTES;
inline constexpr std::size_t kSignPrivateKeyBytes = DSTU_SIGN_PRIVATE_KEY_BYTES;
inline constexpr std::size_t kSignPublicKeyBytes = DSTU_SIGN_PUBLIC_KEY_BYTES;
inline constexpr std::size_t kSignSignatureBytes = DSTU_SIGN_SIGNATURE_BYTES;
inline constexpr std::size_t kSignDigestBytes = DSTU_SIGN_DIGEST_BYTES;
inline constexpr std::size_t kStreamKeyBytes = DSTU_STREAM_KEY_BYTES;
/// 32-byte IV added by StreamCipherKey::Encrypt - no tag, unauthenticated.
inline constexpr std::size_t kStreamOverhead = DSTU_STREAM_OVERHEAD;

/// Argon2id cost preset - mirrors DstuPwhashStrength in dstu_core.h and libsodium's own named
/// OPSLIMIT/MEMLIMIT_* constants.
enum class PwhashStrength {
  kInteractive = DSTU_PWHASH_INTERACTIVE,
  kModerate = DSTU_PWHASH_MODERATE,
  kSensitive = DSTU_PWHASH_SENSITIVE,
};

/// A chunk's role in a secretstream - mirrors DstuTag in dstu_core.h.
enum class SecretstreamTag {
  kMessage = DSTU_TAG_MESSAGE,
  kPush = DSTU_TAG_PUSH,
  kRekey = DSTU_TAG_REKEY,
  kFinal = DSTU_TAG_FINAL,
};

}  // namespace dstu

#endif  // DSTU_CPP_CONSTANTS_HPP
