#ifndef DSTU_CPP_MEMZERO_HPP
#define DSTU_CPP_MEMZERO_HPP

#include "bytes.hpp"
#include "dstu_core.h"

namespace dstu {

/// Overwrites buf with zero bytes in a way the compiler cannot optimize away as dead -
/// libsodium's sodium_memzero equivalent. Secret material copied out into a caller-owned buffer
/// (e.g. SigningKey::Bytes) is the caller's own responsibility to wipe once done; the native
/// zeroize-on-drop wrapped by every RAII handle below cannot reach a copy made outside it.
inline void Memzero(MutableByteView buf) { dstu_memzero(buf.data(), buf.size()); }

}  // namespace dstu

#endif  // DSTU_CPP_MEMZERO_HPP
