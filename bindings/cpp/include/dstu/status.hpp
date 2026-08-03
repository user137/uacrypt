#ifndef DSTU_CPP_STATUS_HPP
#define DSTU_CPP_STATUS_HPP

#include "dstu_core.h"

#include <stdexcept>
#include <string>

namespace dstu {

/// Base of every exception this binding throws. Never thrown directly - always one of the two
/// subclasses below (mirrors bindings/dotnet's DstuException/ArgumentException split and
/// bindings/go's CryptoError/ArgumentError split, cross-language-style-guide.md principle 4).
class DstuException : public std::runtime_error {
 public:
  explicit DstuException(const std::string &message) : std::runtime_error(message) {}
};

/// A genuine crypto-operation/data-integrity failure: wrong key, tampered
/// ciphertext/tag/nonce/header, an incomplete secretstream (no Final chunk seen), or pwhash's
/// internal Argon2 failure.
class CryptoError : public DstuException {
 public:
  explicit CryptoError(const std::string &message) : DstuException(message) {}
};

/// A caller-input mistake this wrapper can check before ever calling into native code (wrong
/// key/tag/context length, a null span where one is required).
class ArgumentError : public DstuException {
 public:
  explicit ArgumentError(const std::string &message) : DstuException(message) {}
};

/// Can only happen if this wrapper itself computed a buffer size or handle wrong - not a public
/// failure mode a caller is expected to handle.
class InternalError : public DstuException {
 public:
  explicit InternalError(DstuStatus status)
      : DstuException("internal error in the DstuCore C++ binding (status " +
                       std::to_string(static_cast<int>(status)) + ") - please report this") {}
};

/// Maps a raw DstuStatus to the typed exception a caller should actually see, throwing it. A
/// no-op for DSTU_OK.
inline void CheckStatus(DstuStatus status) {
  switch (status) {
    case DSTU_OK:
      return;
    case DSTU_ERR_RANDOM:
      throw CryptoError("OS CSPRNG failure while generating random data");
    case DSTU_ERR_TAG_MISMATCH:
      throw CryptoError("authentication failed: wrong key, or tampered ciphertext/tag/nonce/header");
    case DSTU_ERR_TRUNCATED:
      throw CryptoError("input is shorter than the minimum valid length for this construction");
    case DSTU_ERR_UNKNOWN_TAG:
      throw CryptoError("secretstream chunk has an invalid tag byte - the stream is corrupted or truncated");
    case DSTU_ERR_FINALIZED:
      throw CryptoError("this secretstream state has already emitted/consumed a Final chunk");
    case DSTU_ERR_SELFTEST_FAILED:
      throw CryptoError("dstu_selftest: a known-answer self-check failed against the compiled build");
    case DSTU_ERR_HASH_ERROR:
      throw CryptoError("crypto_pwhash: internal Argon2/PHC-encoding failure");
    case DSTU_ERR_INVALID_KEY:
      throw ArgumentError("invalid key material (e.g. a DSTU 4145 scalar that is zero or >= the curve order)");
    default:  // DSTU_ERR_BUFFER_TOO_SMALL, DSTU_ERR_NULL_POINTER, DSTU_ERR_INVALID_LENGTH, DSTU_ERR_PANIC
      throw InternalError(status);
  }
}

}  // namespace dstu

#endif  // DSTU_CPP_STATUS_HPP
