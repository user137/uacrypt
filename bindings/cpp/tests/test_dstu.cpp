// C++ test suite for bindings/cpp (docs/bindings-strategy.md T-53, step 6). Covers D-64/D-65's
// three categories per primitive: (1) correctness against a real official vector or a documented
// round trip, (2) rejection of tampered/wrong input wherever a tag/signature exists, (3) misuse
// (wrong lengths, double-finalize, degenerate input). Mirrors
// crates/dstu-core-capi/c-tests/test_capi.c's own structure and hand-rolled CHECK macro (D-158
// point 4: no third-party test framework, C++ has no stdlib JSON either, so the official vector
// is hand-transcribed the same way the C harness already does it).

#include "dstu/dstu.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;

#define CHECK(cond, msg)                                                                     \
  do {                                                                                        \
    if (!(cond)) {                                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));                    \
      failures++;                                                                             \
    }                                                                                          \
  } while (0)

template <typename Exc, typename Fn>
bool Throws(Fn &&fn) {
  try {
    fn();
  } catch (const Exc &) {
    return true;
  } catch (...) {
    return false;
  }
  return false;
}

std::vector<std::uint8_t> ToBytes(const std::string &s) {
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

void TestSelftest() {
  CHECK(!Throws<dstu::CryptoError>([] { dstu::Selftest(); }), "selftest should pass on a correct build");
}

void TestRandombytesAndMemzero() {
  auto buf = dstu::RandomBytes(32);
  bool allZero = true;
  for (auto b : buf) {
    if (b != 0) {
      allZero = false;
    }
  }
  CHECK(!allZero, "RandomBytes should not leave the buffer all-zero (astronomically unlikely)");

  auto empty = dstu::RandomBytes(0);
  CHECK(empty.empty(), "RandomBytes(0) should be a no-op success returning an empty vector");

  std::vector<std::uint8_t> secret(16, 0xAA);
  dstu::Memzero(secret);
  bool allZero2 = true;
  for (auto b : secret) {
    if (b != 0) {
      allZero2 = false;
    }
  }
  CHECK(allZero2, "Memzero should wipe the buffer");
}

void TestAuth() {
  auto key = dstu::AuthKey::Generate();
  const std::string message = "a message both parties want to confirm is unmodified";
  auto tag = key.Compute(ToBytes(message));

  CHECK(!Throws<dstu::CryptoError>([&] { key.Verify(ToBytes(message), tag); }), "Verify should accept its own tag");

  const std::string other = "a different message";
  CHECK(Throws<dstu::CryptoError>([&] { key.Verify(ToBytes(other), tag); }), "Verify should reject a tampered message");

  auto badTag = tag;
  badTag[0] ^= 1;
  CHECK(Throws<dstu::CryptoError>([&] { key.Verify(ToBytes(message), badTag); }), "Verify should reject a tampered tag");

  CHECK(Throws<dstu::ArgumentError>([&] { key.Verify(ToBytes(message), std::vector<std::uint8_t>{1, 2, 3}); }),
        "Verify should reject a wrong-length tag before ever calling native code");

  std::vector<std::uint8_t> rawKey(dstu::kAuthKeyBytes, 0x42);
  auto fromBytes = dstu::AuthKey::FromBytes(rawKey);
  CHECK(fromBytes.Bytes() == rawKey, "AuthKey::Bytes should round-trip FromBytes");

  CHECK(Throws<dstu::ArgumentError>([] { dstu::AuthKey::FromBytes(std::vector<std::uint8_t>{1, 2, 3}); }),
        "FromBytes should reject a wrong-length key");
}

void TestKdf() {
  auto key = dstu::KdfMasterKey::Generate();
  std::vector<std::uint8_t> ctx = ToBytes("encrypt_");
  auto sub0 = key.DeriveSubkey(0, ctx);
  auto sub1 = key.DeriveSubkey(1, ctx);
  auto sub0Again = key.DeriveSubkey(0, ctx);

  CHECK(sub0 != sub1, "different subkeyId should derive distinct subkeys");
  CHECK(sub0 == sub0Again, "the same subkeyId/context should be deterministic");
  CHECK(Throws<dstu::ArgumentError>([&] { key.DeriveSubkey(0, std::vector<std::uint8_t>{1}); }),
        "DeriveSubkey should reject a wrong-length context");
}

// Official DSTU 7564:2014 Kupyna-256 test vector (docs/papers/Kupyna.pdf, Appendix B.2 - Oliynykov
// et al.; also crates/dstu-core/tests/vectors/kupyna/kupyna-256.json and
// crates/dstu-core-capi/c-tests/test_capi.c's own copy). Single-byte message 0xFF.
void TestGenerichashOfficialVector() {
  const std::vector<std::uint8_t> message = {0xFF};
  const std::vector<std::uint8_t> expected = {0xEA, 0x76, 0x77, 0xCA, 0x45, 0x26, 0x55, 0x56, 0x80, 0x44,
                                               0x1C, 0x11, 0x79, 0x82, 0xEA, 0x14, 0x05, 0x9E, 0xA6, 0xD0,
                                               0xD7, 0x12, 0x4D, 0x6E, 0xCD, 0xB3, 0xDE, 0xEC, 0x49, 0xE8,
                                               0x90, 0xF4};
  auto actual = dstu::GenericHash256(message);
  CHECK(actual == expected, "GenericHash256(0xFF) should match the official DSTU 7564:2014 Kupyna-256 vector");
}

void TestGenerichash() {
  const std::string message = "hello world";
  auto whole = dstu::GenericHash256(ToBytes(message));

  dstu::Kupyna256Hasher hasher;
  hasher.Update(ToBytes("hello "));
  hasher.Update(ToBytes("world"));
  auto streamed = hasher.Finalize();
  CHECK(whole == streamed, "one-shot and streaming should agree");
  CHECK(Throws<dstu::ArgumentError>([&] { hasher.Finalize(); }), "a second Finalize() should throw, not misbehave");

  auto whole512 = dstu::GenericHash512(ToBytes(message));
  dstu::Kupyna512Hasher hasher512;
  hasher512.Update(ToBytes(message));
  auto streamed512 = hasher512.Finalize();
  CHECK(whole512 == streamed512, "512 one-shot and streaming should agree");
  CHECK(Throws<dstu::ArgumentError>([&] { hasher512.Finalize(); }),
        "a second Finalize() on the 512 hasher should throw too, not just the 256 one");
}

void TestSecretbox() {
  auto key = dstu::SecretboxKey::Generate();
  const std::string plaintext = "a message worth protecting";
  auto sealed = key.Seal(ToBytes(plaintext));
  CHECK(sealed.size() == plaintext.size() + dstu::kSecretboxOverhead,
        "sealed size should equal plaintext size + overhead exactly");

  auto opened = key.Open(sealed);
  CHECK(opened == ToBytes(plaintext), "opened plaintext should match the original");

  auto tampered = sealed;
  tampered.back() ^= 1;
  CHECK(Throws<dstu::CryptoError>([&] { key.Open(tampered); }), "Open should reject a tampered ciphertext");

  CHECK(Throws<dstu::CryptoError>([&] { key.Open(std::vector<std::uint8_t>{1, 2, 3}); }),
        "Open should reject input shorter than the nonce+tag overhead");
}

void TestBox() {
  auto secretKey = dstu::BoxSecretKey::Generate();
  auto publicKey = secretKey.Public();
  const std::string message = "a message for the public key's holder only";
  auto sealed = publicKey.Seal(ToBytes(message));
  CHECK(sealed.size() == message.size() + dstu::kBoxSealOverhead,
        "sealed size should equal message size + DSTU_BOX_SEAL_OVERHEAD exactly");

  auto opened = secretKey.Open(sealed);
  CHECK(opened == ToBytes(message), "opened plaintext should match the original message");

  auto tampered = sealed;
  tampered.back() ^= 1;
  CHECK(Throws<dstu::CryptoError>([&] { secretKey.Open(tampered); }), "Open should reject a tampered ciphertext");

  auto otherSecretKey = dstu::BoxSecretKey::Generate();
  CHECK(Throws<dstu::CryptoError>([&] { otherSecretKey.Open(sealed); }),
        "Open should reject the correct sealed message under the wrong secret key");

  CHECK(Throws<dstu::CryptoError>([&] { secretKey.Open(std::vector<std::uint8_t>{1, 2, 3}); }),
        "Open should reject input shorter than DSTU_BOX_SEAL_OVERHEAD");

  CHECK(Throws<dstu::ArgumentError>([&] { dstu::BoxSecretKey::FromBytes(std::vector<std::uint8_t>(32, 0)); }),
        "BoxSecretKey::FromBytes should reject a zero scalar");
  CHECK(Throws<dstu::ArgumentError>([&] { dstu::BoxPublicKey::FromBytes(std::vector<std::uint8_t>(32, 0)); }),
        "BoxPublicKey::FromBytes should reject x = 0");
}

void TestBox512() {
  auto secretKey = dstu::Box512SecretKey::Generate();
  auto publicKey = secretKey.Public();
  const std::string message = "a message for the public key's holder only";
  auto sealed = publicKey.Seal(ToBytes(message));
  CHECK(sealed.size() == message.size() + dstu::kBox512SealOverhead,
        "sealed size should equal message size + DSTU_BOX512_SEAL_OVERHEAD exactly");

  auto opened = secretKey.Open(sealed);
  CHECK(opened == ToBytes(message), "opened plaintext should match the original message");

  auto tampered = sealed;
  tampered.back() ^= 1;
  CHECK(Throws<dstu::CryptoError>([&] { secretKey.Open(tampered); }), "Open should reject a tampered ciphertext");

  auto otherSecretKey = dstu::Box512SecretKey::Generate();
  CHECK(Throws<dstu::CryptoError>([&] { otherSecretKey.Open(sealed); }),
        "Open should reject the correct sealed message under the wrong secret key");

  CHECK(Throws<dstu::CryptoError>([&] { secretKey.Open(std::vector<std::uint8_t>{1, 2, 3}); }),
        "Open should reject input shorter than DSTU_BOX512_SEAL_OVERHEAD");

  CHECK(Throws<dstu::ArgumentError>([&] { dstu::Box512SecretKey::FromBytes(std::vector<std::uint8_t>(64, 0)); }),
        "Box512SecretKey::FromBytes should reject a zero scalar");
  CHECK(Throws<dstu::ArgumentError>([&] { dstu::Box512PublicKey::FromBytes(std::vector<std::uint8_t>(64, 0)); }),
        "Box512PublicKey::FromBytes should reject x = 0");
}

void TestSecretstream() {
  auto key = dstu::SecretstreamKey::Generate();
  const std::string plaintext = "a whole file, conceptually split into chunks, larger than one buffer";

  std::ostringstream sink;
  {
    dstu::SecretStreamEncryptor enc(sink, key);
    enc.Write(ToBytes(plaintext));
    enc.Finish();
  }
  std::string wire = sink.str();

  std::istringstream source(wire);
  dstu::SecretStreamDecryptor dec(source, key);
  auto decrypted = dec.ReadAll();
  CHECK(decrypted == ToBytes(plaintext), "decrypted plaintext should match the original");

  // misuse: Write after Finish
  std::ostringstream sink2;
  dstu::SecretStreamEncryptor enc2(sink2, key);
  enc2.Finish();
  CHECK(Throws<dstu::ArgumentError>([&] { enc2.Write(ToBytes("x")); }), "Write after Finish should throw");

  // property: destroying an encryptor without Finish() leaves no Final chunk - a reader must fail
  // closed on it (D-118's own pitfall, D-158 point 1).
  std::ostringstream sink3;
  {
    dstu::SecretStreamEncryptor enc3(sink3, key);
    enc3.Write(ToBytes("never finished"));
  }
  std::istringstream source3(sink3.str());
  dstu::SecretStreamDecryptor dec3(source3, key);
  CHECK(Throws<dstu::CryptoError>([&] { dec3.ReadAll(); }),
        "a stream whose encryptor was destroyed without Finish() should fail closed, not decode as complete");

  // rejection: tampered ciphertext byte right after the header
  std::string tamperedWire = wire;
  tamperedWire[dstu::kSecretstreamHeaderBytes + 5] ^= 1;
  std::istringstream tamperedSource(tamperedWire);
  dstu::SecretStreamDecryptor tamperedDec(tamperedSource, key);
  CHECK(Throws<dstu::CryptoError>([&] { tamperedDec.ReadAll(); }), "decryption should reject a tampered chunk");

  // misuse: trailing data after the Final chunk
  std::string trailingWire = wire + "x";
  std::istringstream trailingSource(trailingWire);
  dstu::SecretStreamDecryptor trailingDec(trailingSource, key);
  CHECK(Throws<dstu::CryptoError>([&] { trailingDec.ReadAll(); }), "decryption should reject trailing data after Final");

  // misuse: truncated stream (no Final chunk ever seen)
  std::string truncatedWire = wire.substr(0, dstu::kSecretstreamHeaderBytes + 3);
  std::istringstream truncatedSource(truncatedWire);
  dstu::SecretStreamDecryptor truncatedDec(truncatedSource, key);
  CHECK(Throws<dstu::CryptoError>([&] { truncatedDec.ReadAll(); }), "decryption should reject a truncated stream");
}

// T-220: oversized declared chunk-length field. All 7 other bindings in this batch already have
// this test; C++ was the one gap. A garbage header is fine here - dstu_secretstream_pull_init
// derives a subkey from whatever bytes it's given and doesn't validate them, so the malicious
// chunk-length field is what the decoder actually reads and rejects first (mirrors the Java
// binding's SecretStreamTest.oversizedDeclaredChunkLengthIsRejected).
void TestSecretstreamOversizedDeclaredChunkLength() {
  auto key = dstu::SecretstreamKey::Generate();

  std::string malicious(dstu::kSecretstreamHeaderBytes, '\0');  // header - unread past this
  malicious.push_back(static_cast<char>(dstu::SecretstreamTag::kFinal));
  malicious.append({static_cast<char>(0xFF), static_cast<char>(0xFF), static_cast<char>(0xFF),
                     static_cast<char>(0xFF)});  // declared chunk length 0xFFFFFFFF, little-endian

  std::istringstream source(malicious);
  dstu::SecretStreamDecryptor dec(source, key);
  CHECK(Throws<dstu::CryptoError>([&] { dec.ReadAll(); }),
        "decryption should reject a declared chunk length exceeding kSecretstreamChunkBytes");
}

// T-213: FFI memory-leak smoke test. Unlike the other seven bindings in this batch, this one has
// no GC/refcounting at all - every wrapper here (SecretstreamKey, BoxSecretKey, BoxPublicKey,
// SecretStreamEncryptor/Decryptor) holds its native handle in a std::unique_ptr with a custom
// deleter (dstu_*_free), so RAII already guarantees deterministic release at scope exit for
// correctly-written code; this loop can't demonstrate anything close to what the Java/.NET/Go
// tests in this same batch demonstrate (a GC/managed-heap counter provably blind to an off-heap
// handle). Kept anyway as a living regression backstop - the value here is a future refactor that
// accidentally moves a handle out of RAII (a raw pointer escape, a std::move bug, a destructor that
// forgets to run) has some test noticing, not a claim that this loop is a meaningful discriminator
// today. Linux-only VmRSS reading (matches the mechanism this batch's Java/.NET/Go tests already
// settled on for the languages where it *is* the only reliable local signal - consistent story
// across the batch rather than a one-off for this file). Not run on this project's own Windows dev
// machine's build of this test binary (MinGW here, no /proc anyway) - CI's Linux leg is the real
// exercise of this path, same documented-precedent posture as uacrypt_with_peak_rss.
#ifdef __linux__
std::int64_t CurrentVmRssBytes() {
  std::ifstream status("/proc/self/status");
  std::string line;
  while (std::getline(status, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      std::istringstream iss(line.substr(6));
      std::int64_t kb = 0;
      iss >> kb;
      return kb * 1024;
    }
  }
  throw std::runtime_error("VmRSS line not found in /proc/self/status");
}

void RunSecretstreamAndBoxLoop(const dstu::SecretstreamKey &key, const dstu::BoxSecretKey &boxSecret,
                                const dstu::BoxPublicKey &boxPublic, int n) {
  for (int i = 0; i < n; i++) {
    std::ostringstream sink;
    {
      dstu::SecretStreamEncryptor enc(sink, key);
      enc.Write(ToBytes(std::string("leak-check chunk")));
      enc.Finish();
    }
    std::istringstream source(sink.str());
    dstu::SecretStreamDecryptor dec(source, key);
    auto decrypted = dec.ReadAll();
    CHECK(decrypted == ToBytes(std::string("leak-check chunk")), "secretstream round trip should match in leak loop");

    auto sealed = boxPublic.Seal(ToBytes(std::string("leak-check message")));
    auto opened = boxSecret.Open(sealed);
    CHECK(opened == ToBytes(std::string("leak-check message")), "box round trip should match in leak loop");
  }
}

void TestMemoryLeak() {
  const int warmup = 2000;
  const int n = 20000;
  // Comfortable margin above normal churn but far below what N leaked handles would show at this
  // scale - same order of magnitude as this batch's Java/.NET/Go thresholds.
  const std::int64_t maxAcceptableGrowthBytes = 8LL * 1024 * 1024;

  auto key = dstu::SecretstreamKey::Generate();
  auto boxSecret = dstu::BoxSecretKey::Generate();
  auto boxPublic = boxSecret.Public();

  RunSecretstreamAndBoxLoop(key, boxSecret, boxPublic, warmup);
  std::int64_t before = CurrentVmRssBytes();

  RunSecretstreamAndBoxLoop(key, boxSecret, boxPublic, n);

  std::int64_t after = CurrentVmRssBytes();
  std::int64_t growth = after - before;
  CHECK(growth < maxAcceptableGrowthBytes, "VmRSS growth over the leak-check loop should stay below threshold");
}
#else
void TestMemoryLeak() {
  // VmRSS-based leak check only runs on Linux - see the #ifdef __linux__ block above for why the
  // GC/managed-heap-counter alternatives this batch tried for Java/.NET were rejected as blind,
  // and process-RSS-via-repeated-sampling was rejected as too noisy on Windows specifically.
}
#endif

#ifdef DSTU_UACRYPT_EXE
// std::system() shells out via `cmd.exe /c <command>` on Windows, which has a documented quirk:
// when the command string's first character is a `"`, cmd.exe strips the outer first/last quote
// pair before parsing rather than treating it as delimiting the executable path - wrapping the
// whole command in one more pair of quotes is the standard workaround. No-op on POSIX (sh has no
// such quirk).
// Every `cmd` this is called with is built from a compile-time binary path (DSTU_UACRYPT_EXE) and
// this test's own temp-directory file paths, never external/untrusted input - the real compiled
// uacrypt.exe is the thing under test here (D-64/D-65 category 1's cross-binary interop check),
// and there's no portable process-spawning alternative in the standard library that would avoid
// this shell-out.
int RunCommand(const std::string &cmd) {
#ifdef _WIN32
  // NOLINTNEXTLINE(bugprone-command-processor)
  return std::system(("\"" + cmd + "\"").c_str());
#else
  // NOLINTNEXTLINE(bugprone-command-processor)
  return std::system(cmd.c_str());
#endif
}

// Real bidirectional uacrypt interop (D-64/D-65 category 1, cross-language-style-guide.md's
// "shared vector/binary" reuse) - encrypts with this wrapper, decrypts with the real uacrypt.exe,
// and vice versa.
void TestUacryptInterop() {
  namespace fs = std::filesystem;
  fs::path dir = fs::temp_directory_path() / "dstu_cpp_uacrypt_interop";
  fs::create_directories(dir);
  fs::path keyPath = dir / "key.bin";
  fs::path plainPath = dir / "plain.bin";
  fs::path cppEncPath = dir / "cpp.enc";
  fs::path cliEncPath = dir / "cli.enc";
  fs::path cliDecPath = dir / "cli.dec";

  auto key = dstu::SecretstreamKey::Generate();
  auto keyBytes = key.Bytes();
  {
    std::ofstream f(keyPath, std::ios::binary);
    f.write(reinterpret_cast<const char *>(keyBytes.data()), static_cast<std::streamsize>(keyBytes.size()));
  }
  const std::string plaintext = "real uacrypt.exe interop, both directions";
  {
    std::ofstream f(plainPath, std::ios::binary);
    f.write(plaintext.data(), static_cast<std::streamsize>(plaintext.size()));
  }

  // C++ encrypts, real uacrypt.exe decrypts.
  {
    std::ofstream out(cppEncPath, std::ios::binary);
    dstu::SecretStreamEncryptor enc(out, key);
    enc.Write(ToBytes(plaintext));
    enc.Finish();
  }
  std::string cmd1 = "\"" DSTU_UACRYPT_EXE "\" decrypt --key \"" + keyPath.string() + "\" --in \"" +
                      cppEncPath.string() + "\" --out \"" + cliDecPath.string() + "\"";
  CHECK(RunCommand(cmd1) == 0, "uacrypt.exe decrypt should accept output encrypted by this C++ wrapper");
  {
    std::ifstream f(cliDecPath, std::ios::binary);
    std::string got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    CHECK(got == plaintext, "uacrypt.exe's decrypted output should match the original plaintext");
  }

  // real uacrypt.exe encrypts, C++ decrypts.
  std::string cmd2 = "\"" DSTU_UACRYPT_EXE "\" encrypt --key \"" + keyPath.string() + "\" --in \"" +
                      plainPath.string() + "\" --out \"" + cliEncPath.string() + "\"";
  CHECK(RunCommand(cmd2) == 0, "uacrypt.exe encrypt should succeed");
  {
    std::ifstream in(cliEncPath, std::ios::binary);
    dstu::SecretStreamDecryptor dec(in, key);
    auto got = dec.ReadAll();
    CHECK(got == ToBytes(plaintext), "this C++ wrapper should decrypt uacrypt.exe's own output");
  }

  std::error_code ec;
  fs::remove_all(dir, ec);
}
#endif  // DSTU_UACRYPT_EXE

void TestSign() {
  auto key = dstu::SigningKey::Generate();
  auto verifying = key.Verifying();

  const std::string message = "a message whose origin and integrity matter";
  auto sig = key.Sign(ToBytes(message));
  CHECK(verifying.Verify(ToBytes(message), sig), "Verify should accept its own signature");

  const std::string other = "a different message";
  CHECK(!verifying.Verify(ToBytes(other), sig), "Verify should reject a different message");

  auto otherKey = dstu::SigningKey::Generate();
  auto otherVerifying = otherKey.Verifying();
  CHECK(!otherVerifying.Verify(ToBytes(message), sig), "Verify should reject a signature from a different key");

  std::vector<std::uint8_t> zero(dstu::kSignPrivateKeyBytes, 0);
  CHECK(Throws<dstu::ArgumentError>([&] { dstu::SigningKey::FromBytes(zero); }),
        "FromBytes should reject an all-zero scalar");

  auto pubBytes = verifying.Bytes();
  auto roundTripped = dstu::VerifyingKey::FromBytes(pubBytes);
  CHECK(roundTripped.Bytes() == pubBytes, "VerifyingKey::Bytes should round-trip FromBytes");

  // SignDigest/VerifyDigest: signing is deterministic, so signing the message directly and
  // signing its pre-computed Kupyna-256 digest must produce the identical signature - this pins
  // the digest path against the whole-message path in one assertion, not just "it runs."
  auto digest = dstu::GenericHash256(ToBytes(message));
  auto digestSig = key.SignDigest(digest);
  CHECK(digestSig == sig, "SignDigest(GenericHash256(msg)) should equal Sign(msg) exactly - both are deterministic");
  CHECK(verifying.VerifyDigest(digest, digestSig), "VerifyDigest should accept its own digest signature");

  // Tamper the *last* byte, not the first: dstu4145::hash_to_field only consumes a digest's low
  // 21 bytes (see its own doc comment) - flipping a byte outside that window would be a no-op
  // test that always "passes" without exercising rejection at all (found by actually running
  // this, not assumed - CLAUDE.md's own "check what a vector actually exercises" rule).
  auto tamperedDigest = digest;
  tamperedDigest.back() ^= 1;
  CHECK(!verifying.VerifyDigest(tamperedDigest, digestSig), "VerifyDigest should reject a tampered digest");

  CHECK(Throws<dstu::ArgumentError>([&] { key.SignDigest(std::vector<std::uint8_t>{1, 2, 3}); }),
        "SignDigest should reject a wrong-length digest");
  CHECK(Throws<dstu::ArgumentError>([&] { verifying.VerifyDigest(std::vector<std::uint8_t>{1, 2, 3}, sig); }),
        "VerifyDigest should reject a wrong-length digest");
}

void TestSign257() {
  auto key = dstu::SigningKey257::Generate();
  auto verifying = key.Verifying();

  const std::string message = "a message whose origin and integrity matter";
  auto sig = key.Sign(ToBytes(message));
  CHECK(verifying.Verify(ToBytes(message), sig), "Verify should accept its own signature");

  const std::string other = "a different message";
  CHECK(!verifying.Verify(ToBytes(other), sig), "Verify should reject a different message");

  auto otherKey = dstu::SigningKey257::Generate();
  auto otherVerifying = otherKey.Verifying();
  CHECK(!otherVerifying.Verify(ToBytes(message), sig), "Verify should reject a signature from a different key");

  std::vector<std::uint8_t> zero(dstu::kSign257PrivateKeyBytes, 0);
  CHECK(Throws<dstu::ArgumentError>([&] { dstu::SigningKey257::FromBytes(zero); }),
        "FromBytes should reject an all-zero scalar");

  auto pubBytes = verifying.Bytes();
  auto roundTripped = dstu::VerifyingKey257::FromBytes(pubBytes);
  CHECK(roundTripped.Bytes() == pubBytes, "VerifyingKey257::Bytes should round-trip FromBytes");

  auto digest = dstu::GenericHash256(ToBytes(message));
  auto digestSig = key.SignDigest(digest);
  CHECK(digestSig == sig, "SignDigest(GenericHash256(msg)) should equal Sign(msg) exactly - both are deterministic");
  CHECK(verifying.VerifyDigest(digest, digestSig), "VerifyDigest should accept its own digest signature");

  auto tamperedDigest = digest;
  tamperedDigest.back() ^= 1;
  CHECK(!verifying.VerifyDigest(tamperedDigest, digestSig), "VerifyDigest should reject a tampered digest");

  CHECK(Throws<dstu::ArgumentError>([&] { key.SignDigest(std::vector<std::uint8_t>{1, 2, 3}); }),
        "SignDigest should reject a wrong-length digest");
  CHECK(Throws<dstu::ArgumentError>([&] { verifying.VerifyDigest(std::vector<std::uint8_t>{1, 2, 3}, sig); }),
        "VerifyDigest should reject a wrong-length digest");
}

void TestStream() {
  auto key = dstu::StreamCipherKey::Generate();
  const std::string plaintext = "message";
  auto sealed = key.Encrypt(ToBytes(plaintext));
  auto opened = key.Decrypt(sealed);
  CHECK(opened == ToBytes(plaintext), "decrypted plaintext should match the original");

  // contrast with secretbox: tampering does NOT error, it silently changes the plaintext.
  auto tampered = sealed;
  tampered.back() ^= 1;
  CHECK(!Throws<dstu::CryptoError>([&] { key.Decrypt(tampered); }),
        "stream decrypt never fails on tampered input - no tag to check");
  CHECK(key.Decrypt(tampered) != ToBytes(plaintext), "tampered decryption should produce different plaintext");

  CHECK(Throws<dstu::CryptoError>([&] { key.Decrypt(std::vector<std::uint8_t>{1, 2, 3}); }),
        "stream decrypt should reject input shorter than the IV");
}

void TestPwhash() {
  const std::string password = "correct horse battery staple";
  auto hash = dstu::HashPassword(ToBytes(password), dstu::PwhashStrength::kInteractive);
  CHECK(dstu::VerifyPassword(ToBytes(password), hash), "VerifyPassword should accept the correct password");

  const std::string wrong = "wrong guess";
  CHECK(!dstu::VerifyPassword(ToBytes(wrong), hash), "VerifyPassword should reject the wrong password");
  CHECK(!dstu::VerifyPassword(ToBytes(password), "not a real phc string"),
        "VerifyPassword should reject a malformed hash string, not crash");
}

}  // namespace

// bugprone-exception-escape flags std::cout/cerr use reachable from main (ostream::operator<<'s
// own theoretical ios_base::failure), unrelated to the dstu::DstuException catch below - same
// false-positive shape as every example's own main(), see bindings/cpp/examples/box.cpp's comment.
// NOLINTNEXTLINE(bugprone-exception-escape)
int main() {
  try {
    TestSelftest();
    TestRandombytesAndMemzero();
    TestAuth();
    TestKdf();
    TestGenerichashOfficialVector();
    TestGenerichash();
    TestSecretbox();
    TestBox();
    TestBox512();
    TestSecretstream();
    TestSecretstreamOversizedDeclaredChunkLength();
    TestMemoryLeak();
#ifdef DSTU_UACRYPT_EXE
    TestUacryptInterop();
#endif
    TestSign();
    TestSign257();
    TestStream();
    TestPwhash();
  } catch (const dstu::DstuException &e) {
    std::fprintf(stderr, "uncaught dstu::DstuException: %s\n", e.what());
    return 1;
  }

  if (failures == 0) {
    std::printf("all dstu-core C++ binding tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d dstu-core C++ binding test(s) failed\n", failures);
  return 1;
}
