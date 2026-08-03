#ifndef DSTU_CPP_KDF_HPP
#define DSTU_CPP_KDF_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace dstu {

/// A Kupyna-KDF master key (crypto_kdf). Move-only, same handle-ownership shape as AuthKey.
class KdfMasterKey {
 public:
  /// Generates a fresh master key from the OS CSPRNG.
  static KdfMasterKey Generate() {
    DstuKdfMasterKey *out = nullptr;
    CheckStatus(dstu_kdf_master_key_generate(&out));
    return KdfMasterKey(out);
  }

  /// Builds a master key from exactly kKdfKeyBytes bytes.
  static KdfMasterKey FromBytes(ByteView key) {
    if (key.size() != kKdfKeyBytes) {
      throw ArgumentError("key must be exactly kKdfKeyBytes bytes");
    }
    return KdfMasterKey(dstu_kdf_master_key_from_bytes(key.data()));
  }

  KdfMasterKey(const KdfMasterKey &) = delete;
  KdfMasterKey &operator=(const KdfMasterKey &) = delete;
  KdfMasterKey(KdfMasterKey &&) noexcept = default;
  KdfMasterKey &operator=(KdfMasterKey &&) noexcept = default;
  ~KdfMasterKey() = default;

  /// Copies out this key's raw kKdfKeyBytes-byte encoding.
  std::vector<std::uint8_t> Bytes() const {
    std::vector<std::uint8_t> out(kKdfKeyBytes);
    dstu_kdf_master_key_bytes(ptr_.get(), out.data());
    return out;
  }

  /// Derives a kKdfSubkeyBytes-byte subkey from subkeyId/context (exactly kKdfContextBytes bytes).
  std::vector<std::uint8_t> DeriveSubkey(std::uint64_t subkeyId, ByteView context) const {
    if (context.size() != kKdfContextBytes) {
      throw ArgumentError("context must be exactly kKdfContextBytes bytes");
    }
    std::vector<std::uint8_t> out(kKdfSubkeyBytes);
    dstu_kdf_derive_subkey(ptr_.get(), subkeyId, context.data(), out.data());
    return out;
  }

 private:
  explicit KdfMasterKey(DstuKdfMasterKey *ptr) : ptr_(ptr, &dstu_kdf_master_key_free) {}

  std::unique_ptr<DstuKdfMasterKey, void (*)(DstuKdfMasterKey *)> ptr_;
};

}  // namespace dstu

#endif  // DSTU_CPP_KDF_HPP
