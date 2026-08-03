// crypto_secretbox: seal/open a single in-memory message with a symmetric key.

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

int main() {
  auto key = dstu::SecretboxKey::Generate();

  const std::string message = "a message worth protecting";
  std::vector<std::uint8_t> plaintext(message.begin(), message.end());
  auto sealed = key.Seal(plaintext);

  auto opened = key.Open(sealed);
  std::cout << "sealed " << opened.size() << " bytes -> " << sealed.size() << " bytes, round-tripped OK\n";

  // Tampering with the sealed blob (ciphertext, tag, or nonce) is detected, not silently
  // "decrypted" into wrong plaintext.
  sealed.back() ^= 1;
  try {
    key.Open(sealed);
    Die("tampered ciphertext was NOT rejected");
  } catch (const dstu::CryptoError &) {
    std::cout << "tampered ciphertext correctly rejected\n";
  }
  return 0;
}
