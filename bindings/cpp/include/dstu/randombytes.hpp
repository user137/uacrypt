#ifndef DSTU_CPP_RANDOMBYTES_HPP
#define DSTU_CPP_RANDOMBYTES_HPP

#include "bytes.hpp"
#include "dstu_core.h"
#include "status.hpp"

#include <cstdint>
#include <vector>

namespace dstu {

/// Fills a fresh length-byte vector from the OS CSPRNG.
inline std::vector<std::uint8_t> RandomBytes(std::size_t length) {
  std::vector<std::uint8_t> buf(length);
  CheckStatus(dstu_randombytes_buf(buf.empty() ? nullptr : buf.data(), buf.size()));
  return buf;
}

}  // namespace dstu

#endif  // DSTU_CPP_RANDOMBYTES_HPP
