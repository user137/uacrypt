// crypto_sign: DSTU 4145 sign/verify - both the success path and a rejected forgery, since a
// signature example that only shows the happy path doesn't demonstrate the primitive actually
// does what it claims.

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

// bugprone-exception-escape flags every std::cout/cerr use in main (ostream::operator<<'s own
// theoretical ios_base::failure, unrelated to this example's dstu::DstuException catch below,
// same as box.cpp's own comment on this) - inherent to any example that prints anything.
// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  try {
    auto signingKey = dstu::SigningKey::Generate();
    auto verifyingKey = signingKey.Verifying();  // safe to share/publish

    const std::string message = "a message whose origin and integrity matter";
    auto signature = signingKey.Sign(ToBytes(message));

    if (!verifyingKey.Verify(ToBytes(message), signature)) {
      Die("verify rejected our own signature");
    }
    std::cout << "signature verified OK\n";

    // A different message, or a signature from a different key, must fail to verify.
    const std::string otherMessage = "a different message";
    if (verifyingKey.Verify(ToBytes(otherMessage), signature)) {
      Die("verify incorrectly accepted a different message");
    }

    auto otherKey = dstu::SigningKey::Generate();
    auto otherVerifyingKey = otherKey.Verifying();
    if (otherVerifyingKey.Verify(ToBytes(message), signature)) {
      Die("verify incorrectly accepted a signature from a different key");
    }
    std::cout << "forged message and wrong-key forgery both correctly rejected\n";
    return 0;
  } catch (const dstu::DstuException &e) {
    Die(e.what());
  }
}
