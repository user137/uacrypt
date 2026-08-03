#ifndef DSTU_CPP_SELFTEST_HPP
#define DSTU_CPP_SELFTEST_HPP

#include "dstu_core.h"
#include "status.hpp"

namespace dstu {

/// Re-verifies one official test vector per primitive (Kalyna, Kupyna, Strumok, DSTU 4145)
/// against the live compiled build. Throws CryptoError if any check fails.
inline void Selftest() { CheckStatus(dstu_selftest()); }

}  // namespace dstu

#endif  // DSTU_CPP_SELFTEST_HPP
