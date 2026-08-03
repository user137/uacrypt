// crypto_secretstream: a real file, encrypted and decrypted one bounded-size chunk at a time -
// the shape a caller needs for a large file that must not be held whole in memory (unlike
// crypto_secretbox, whose AEAD tag needs the whole plaintext/ciphertext up front).

#include "dstu/dstu.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {
void Die(const std::string &what) {
  std::cerr << "error: " << what << "\n";
  std::exit(1);
}
}  // namespace

int main() {
  const std::string plainPath = "dstu_cpp_example_plain.tmp";
  const std::string encryptedPath = "dstu_cpp_example_encrypted.tmp";
  const std::string decryptedPath = "dstu_cpp_example_decrypted.tmp";

  // Create a source file a bit larger than one chunk, so the encryptor's own internal buffering
  // spans more than one Message chunk before the Final.
  {
    std::ofstream src(plainPath, std::ios::binary);
    if (!src) {
      Die("could not create the example source file");
    }
    for (int i = 0; i < static_cast<int>(dstu::kSecretstreamChunkBytes) + 1000; i++) {
      src.put(static_cast<char>('A' + (i % 26)));
    }
  }

  auto key = dstu::SecretstreamKey::Generate();

  // --- encrypt ---
  {
    std::ifstream in(plainPath, std::ios::binary);
    std::ofstream out(encryptedPath, std::ios::binary);
    if (!in || !out) {
      Die("could not open example files for encryption");
    }
    dstu::SecretStreamEncryptor encryptor(out, key);
    char buf[4096];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
      encryptor.Write(dstu::ByteView(reinterpret_cast<const std::uint8_t *>(buf), static_cast<std::size_t>(in.gcount())));
    }
    encryptor.Finish();
  }
  std::cout << "encrypted " << plainPath << " into " << encryptedPath << "\n";

  // --- decrypt ---
  {
    std::ifstream in(encryptedPath, std::ios::binary);
    std::ofstream out(decryptedPath, std::ios::binary);
    if (!in || !out) {
      Die("could not open example files for decryption");
    }
    dstu::SecretStreamDecryptor decryptor(in, key);
    std::uint8_t buf[4096];
    std::size_t n;
    while ((n = decryptor.Read(buf, sizeof(buf))) > 0) {
      out.write(reinterpret_cast<const char *>(buf), static_cast<std::streamsize>(n));
    }
  }
  std::cout << "decrypted " << encryptedPath << " into " << decryptedPath << "\n";

  // Verify the round trip actually reproduced the original file byte-for-byte.
  std::ifstream a(plainPath, std::ios::binary);
  std::ifstream b(decryptedPath, std::ios::binary);
  bool same = std::equal(std::istreambuf_iterator<char>(a), std::istreambuf_iterator<char>(),
                          std::istreambuf_iterator<char>(b), std::istreambuf_iterator<char>());
  a.close();
  b.close();
  if (!same) {
    Die("round trip did not reproduce the original file");
  }
  std::cout << "round trip verified byte-for-byte OK\n";

  std::remove(plainPath.c_str());
  std::remove(encryptedPath.c_str());
  std::remove(decryptedPath.c_str());
  return 0;
}
