#ifndef DSTU_CPP_PWHASH_HPP
#define DSTU_CPP_PWHASH_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <string>
#include <vector>

namespace dstu {

/// Hashes password into a PHC-formatted string, using strength as the Argon2id cost preset.
/// Throws CryptoError on OS CSPRNG or internal Argon2 failure.
inline std::string HashPassword(ByteView password, PwhashStrength strength) {
  std::vector<char> out(kPwhashStrBytes);
  CheckStatus(dstu_pwhash_hash_password(password.data(), password.size(),
                                         static_cast<DstuPwhashStrength>(strength), out.data()));
  return std::string(out.data());  // NUL-terminated by the callee; stops at the first NUL.
}

/// Verifies password against a PHC string produced by HashPassword. Returns false for a wrong
/// password or a malformed hash - there is nothing for a caller to branch differently on between
/// those two cases.
inline bool VerifyPassword(ByteView password, const std::string &hash) {
  return dstu_pwhash_verify_password(password.data(), password.size(), hash.c_str());
}

}  // namespace dstu

#endif  // DSTU_CPP_PWHASH_HPP
