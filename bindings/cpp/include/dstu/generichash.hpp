#ifndef DSTU_CPP_GENERICHASH_HPP
#define DSTU_CPP_GENERICHASH_HPP

#include "bytes.hpp"
#include "constants.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <memory>
#include <vector>

namespace dstu {

/// Computes the one-shot Kupyna-256 digest of message.
inline std::vector<std::uint8_t> GenericHash256(ByteView message) {
  std::vector<std::uint8_t> out(kGenericHash256Bytes);
  dstu_generichash_256(message.data(), message.size(), out.data());
  return out;
}

/// Computes the one-shot Kupyna-512 digest of message.
inline std::vector<std::uint8_t> GenericHash512(ByteView message) {
  std::vector<std::uint8_t> out(kGenericHash512Bytes);
  dstu_generichash_512(message.data(), message.size(), out.data());
  return out;
}

/// An incremental Kupyna-256 hasher for data too large to hold in memory at once. For a one-shot
/// digest, use GenericHash256. Move-only, same handle-ownership shape as AuthKey.
class Kupyna256Hasher {
 public:
  Kupyna256Hasher() : ptr_(dstu_kupyna256_hasher_new(), &dstu_kupyna256_hasher_free) {}

  Kupyna256Hasher(const Kupyna256Hasher &) = delete;
  Kupyna256Hasher &operator=(const Kupyna256Hasher &) = delete;
  Kupyna256Hasher(Kupyna256Hasher &&) noexcept = default;
  Kupyna256Hasher &operator=(Kupyna256Hasher &&) noexcept = default;
  ~Kupyna256Hasher() = default;

  /// Feeds data into the hasher.
  void Update(ByteView data) {
    if (finalized_) {
      throw ArgumentError("this hasher has already been finalized");
    }
    dstu_kupyna256_hasher_update(ptr_.get(), data.data(), data.size());
  }

  /// Consumes the hasher's accumulated state into a kGenericHash256Bytes-byte digest. May only be
  /// called once.
  std::vector<std::uint8_t> Finalize() {
    if (finalized_) {
      throw ArgumentError("this hasher has already been finalized");
    }
    std::vector<std::uint8_t> out(kGenericHash256Bytes);
    CheckStatus(dstu_kupyna256_hasher_finalize(ptr_.get(), out.data()));
    finalized_ = true;
    return out;
  }

 private:
  std::unique_ptr<DstuKupyna256Hasher, void (*)(DstuKupyna256Hasher *)> ptr_;
  bool finalized_ = false;
};

/// An incremental Kupyna-512 hasher. Same shape as Kupyna256Hasher.
class Kupyna512Hasher {
 public:
  Kupyna512Hasher() : ptr_(dstu_kupyna512_hasher_new(), &dstu_kupyna512_hasher_free) {}

  Kupyna512Hasher(const Kupyna512Hasher &) = delete;
  Kupyna512Hasher &operator=(const Kupyna512Hasher &) = delete;
  Kupyna512Hasher(Kupyna512Hasher &&) noexcept = default;
  Kupyna512Hasher &operator=(Kupyna512Hasher &&) noexcept = default;
  ~Kupyna512Hasher() = default;

  void Update(ByteView data) {
    if (finalized_) {
      throw ArgumentError("this hasher has already been finalized");
    }
    dstu_kupyna512_hasher_update(ptr_.get(), data.data(), data.size());
  }

  std::vector<std::uint8_t> Finalize() {
    if (finalized_) {
      throw ArgumentError("this hasher has already been finalized");
    }
    std::vector<std::uint8_t> out(kGenericHash512Bytes);
    CheckStatus(dstu_kupyna512_hasher_finalize(ptr_.get(), out.data()));
    finalized_ = true;
    return out;
  }

 private:
  std::unique_ptr<DstuKupyna512Hasher, void (*)(DstuKupyna512Hasher *)> ptr_;
  bool finalized_ = false;
};

}  // namespace dstu

#endif  // DSTU_CPP_GENERICHASH_HPP
