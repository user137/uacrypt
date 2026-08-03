// crypto_pwhash: hash a password into a PHC string, then verify both a correct and a wrong guess
// against it.

#include "dstu/dstu.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Die(const std::string &what) {
  std::cerr << "error: " << what << "\n";
  std::exit(1);
}
std::vector<std::uint8_t> ToBytes(const std::string &s) { return std::vector<std::uint8_t>(s.begin(), s.end()); }
}  // namespace

int main() {
  const std::string password = "correct horse battery staple";
  // kInteractive is the cheapest of the three presets - appropriate for an example that must
  // finish quickly; a real login flow would still use it, a data-at-rest key derivation would
  // pick kSensitive.
  std::string hash;
  try {
    hash = dstu::HashPassword(ToBytes(password), dstu::PwhashStrength::kInteractive);
  } catch (const dstu::CryptoError &) {
    Die("pwhash failed (OS CSPRNG unavailable or an internal Argon2 error)");
  }
  std::cout << "PHC string: " << hash << "\n";

  bool ok = dstu::VerifyPassword(ToBytes(password), hash);
  bool rejectsWrong = !dstu::VerifyPassword(ToBytes("wrong guess"), hash);
  std::cout << "correct password verified = " << (ok ? "true" : "false")
            << ", wrong password rejected = " << (rejectsWrong ? "true" : "false") << "\n";
  if (!ok || !rejectsWrong) {
    Die("pwhash did not behave as expected");
  }
  return 0;
}
