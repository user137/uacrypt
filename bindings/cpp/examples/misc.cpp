// Smaller primitives that don't need their own dedicated example file: crypto_auth, crypto_kdf,
// crypto_generichash, crypto_stream, randombytes.

#include "dstu/dstu.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Die(const std::string &what) {
  std::cerr << "error: " << what << "\n";
  std::exit(1);
}
std::vector<std::uint8_t> ToBytes(const std::string &s) { return std::vector<std::uint8_t>(s.begin(), s.end()); }

void DemoRandombytes() {
  auto buf = dstu::RandomBytes(16);
  std::cout << "RandomBytes: filled " << buf.size() << " random bytes\n";
}

void DemoAuth() {
  auto key = dstu::AuthKey::Generate();
  const std::string message = "a message both parties want to confirm is unmodified";
  auto tag = key.Compute(ToBytes(message));
  bool ok = true;
  try {
    key.Verify(ToBytes(message), tag);
  } catch (const dstu::CryptoError &) {
    ok = false;
  }
  std::cout << "crypto_auth: tag verified = " << (ok ? "true" : "false") << "\n";
}

void DemoKdf() {
  auto key = dstu::KdfMasterKey::Generate();
  auto encryptSubkey = key.DeriveSubkey(0, ToBytes("encrypt_"));
  auto macSubkey = key.DeriveSubkey(1, ToBytes("mac_key_"));
  (void)macSubkey;
  std::cout << "crypto_kdf: derived two distinct " << encryptSubkey.size() << "-byte subkeys from one master key\n";
}

void DemoGenerichash() {
  auto digest = dstu::GenericHash256(ToBytes("hello world"));
  std::cout << "crypto_generichash: Kupyna-256(\"hello world\") = " << std::hex << std::setfill('0');
  for (auto b : digest) {
    std::cout << std::setw(2) << static_cast<int>(b);
  }
  std::cout << std::dec << "\n";
}

void DemoStream() {
  auto key = dstu::StreamCipherKey::Generate();
  const std::string message = "message";
  auto sealed = key.Encrypt(ToBytes(message));
  auto plaintext = key.Decrypt(sealed);
  std::cout << "crypto_stream: round-tripped " << plaintext.size()
            << " bytes (confidentiality only, no authentication)\n";
}
}  // namespace

int main() {
  DemoRandombytes();
  DemoAuth();
  DemoKdf();
  DemoGenerichash();
  DemoStream();
  return 0;
}
