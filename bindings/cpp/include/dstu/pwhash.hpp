#ifndef DSTU_CPP_PWHASH_HPP
#define DSTU_CPP_PWHASH_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace dstu {

/// Hashes password into a PHC-formatted string, using strength as the Argon2id cost preset.
/// Throws CryptoError on OS CSPRNG or internal Argon2 failure.
inline std::string HashPassword(ByteView password, PwhashStrength strength) {
  std::vector<char> out(kPwhashStrBytes);
  CheckStatus(dstu_pwhash_hash_password(password.data(), password.size(),
                                         static_cast<std::uint32_t>(strength), out.data()));
  return std::string(out.data());  // NUL-terminated by the callee; stops at the first NUL.
}

/// Verifies password against a PHC string produced by HashPassword. Returns false for a wrong
/// password or a malformed hash - there is nothing for a caller to branch differently on between
/// those two cases.
inline bool VerifyPassword(ByteView password, const std::string &hash) {
  return dstu_pwhash_verify_password(password.data(), password.size(), hash.c_str());
}

/// Derives a DSTU_PWHASH_KEYBYTES-byte key from password and a DSTU_PWHASH_SALTBYTES-byte salt -
/// libsodium's crypto_pwhash (Argon2id v1.3), byte for byte (T-269). Runs on the calling thread.
/// Throws ArgumentError for a wrong-length salt or an unknown strength, CryptoError if Argon2
/// cannot get its memory.
inline std::vector<std::uint8_t> DeriveKey(ByteView password, ByteView salt, PwhashStrength strength) {
  if (salt.size() != DSTU_PWHASH_SALTBYTES) {
    throw ArgumentError("salt must be exactly DSTU_PWHASH_SALTBYTES bytes");
  }
  std::vector<std::uint8_t> key(DSTU_PWHASH_KEYBYTES);
  CheckStatus(dstu_pwhash_derive_key(password.data(), password.size(), salt.data(),
                                      static_cast<std::uint32_t>(strength), key.data()));
  return key;
}

}  // namespace dstu

#endif  // DSTU_CPP_PWHASH_HPP
