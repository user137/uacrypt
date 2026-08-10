// crypto_box512 (l(p)=512 sibling of crypto_box, T-193/T-204): generate a keypair, seal a message
// to the public key, open it with the secret key.

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
}  // namespace

// bugprone-exception-escape flags every std::cout/cerr use in main (ostream::operator<<'s own
// theoretical ios_base::failure, unrelated to this example's dstu::DstuException catch below,
// same as box.cpp's own comment on this) - inherent to any example that prints anything.
// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  try {
    auto secretKey = dstu::Box512SecretKey::Generate();
    auto publicKey = secretKey.Public();  // safe to share/publish

    const std::string message = "a message for the public key's holder only";
    std::vector<std::uint8_t> plaintext(message.begin(), message.end());
    auto sealed = publicKey.Seal(plaintext);

    auto opened = secretKey.Open(sealed);
    std::cout << "sealed " << opened.size() << " bytes -> " << sealed.size() << " bytes, round-tripped OK\n";

    sealed.back() ^= 1;
    try {
      secretKey.Open(sealed);
      Die("tampered ciphertext was NOT rejected");
    } catch (const dstu::CryptoError &) {
      std::cout << "tampered ciphertext correctly rejected\n";
    }
    return 0;
  } catch (const dstu::DstuException &e) {
    Die(e.what());
  }
}
