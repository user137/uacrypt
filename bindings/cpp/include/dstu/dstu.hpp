#ifndef DSTU_CPP_DSTU_HPP
#define DSTU_CPP_DSTU_HPP

/// A C++ (RAII, header-only) binding for dstu-core (Ukrainian DSTU cryptographic standards -
/// Kalyna, Kupyna, Strumok, DSTU 4145), over crates/dstu-core-capi's C ABI (T-158).
///
/// Pre-release and provisional - see docs/SECURITY.md and docs/DECISIONS.md in the project
/// repository (https://github.com/user137/uacrypt) for the full threat model and
/// per-construction status.

#include "auth.hpp"
#include "bytes.hpp"
#include "constants.hpp"
#include "generichash.hpp"
#include "kdf.hpp"
#include "memzero.hpp"
#include "pwhash.hpp"
#include "randombytes.hpp"
#include "secretbox.hpp"
#include "secretstream.hpp"
#include "selftest.hpp"
#include "sign.hpp"
#include "status.hpp"
#include "stream.hpp"

#endif  // DSTU_CPP_DSTU_HPP
