# dstu (C++ binding)

**Provisional — not published anywhere, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
This binding wraps the full `dstu_core::crypto_*` surface as a thin, header-only RAII wrapper over
`crates/dstu-core-capi`'s C ABI (T-158, `docs/bindings-strategy.md` T-53, `docs/DECISIONS.md`
D-158) — build from source as shown below.

Like `bindings/dotnet`/`bindings/go`, `dstu` has no Cargo workspace of its own — there is no Rust
code here beyond what T-158 already builds. Header-only, C++17: `#include "dstu/dstu.hpp"` and
link against the prebuilt `dstu-core-capi` shared library (no CMake `FetchContent`-ing the Rust
side — D-158 point 3).

## Building

```sh
cargo build -p dstu-core-capi --release   # from the repo root - builds the native library this binding links against
cd bindings/cpp
cmake -S . -B build            # add -G "MinGW Makefiles" on a GNU-hosted Windows toolchain
cmake --build build --config Release
```

```cpp
#include "dstu/dstu.hpp"

dstu::Selftest();  // re-verifies official KAT vectors against this exact compiled build - throws on failure

auto key = dstu::SecretboxKey::Generate();
auto sealed = key.Seal(std::vector<std::uint8_t>{/* ... */});
```

Errors are C++ exceptions, not return codes (`docs/cross-language-style-guide.md`'s "exception or
return code at module boundary" — this binding picks exceptions, matching `bindings/python`'s own
choice): `dstu::CryptoError` for a genuine crypto/data-integrity failure, `dstu::ArgumentError` for
a caller-input mistake this wrapper catches before ever calling into native code, both deriving
from `dstu::DstuException` (see `include/dstu/status.hpp`).

## Usage

See `examples/` for complete, runnable programs, and `tests/test_dstu.cpp` for the full
correctness/rejection/misuse suite each surface is verified against (D-64/D-65), including real
bidirectional `uacrypt` CLI interop.

| Type | Members | Notes |
|---|---|---|
| `SecretboxKey` | `Generate`, `FromBytes`, `Bytes`, `Seal`, `Open` | Single-message authenticated encryption. `examples/secretbox.cpp`. |
| `BoxSecretKey`, `BoxPublicKey` | `Generate`, `FromBytes`, `Bytes`, `Public`, `Seal`, `Open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `Seal`/`Open` are not memory-bounded — the whole message is held in memory. `examples/box.cpp`. |
| `SecretstreamKey`, `SecretStreamEncryptor`, `SecretStreamDecryptor` | `Generate`, `FromBytes`, `Bytes` | Chunked streaming AEAD, over a caller-owned `std::ostream&`/`std::istream&` (never opened or closed by this wrapper). Wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). The destructor deliberately never emits the Final chunk — call `Finish()` explicitly on the success path; see the class doc comment and D-158 point 1. `examples/secretstream_file.cpp`. |
| `SigningKey`, `VerifyingKey` | `Generate`, `FromBytes`, `Bytes`, `Sign`, `SignDigest`, `Verifying`, `Verify`, `VerifyDigest` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples/sign.cpp`. |
| `HashPassword`, `VerifyPassword` | `PwhashStrength::{kInteractive,kModerate,kSensitive}` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/password_hashing.cpp`. |
| `AuthKey` | `Generate`, `FromBytes`, `Bytes`, `Compute`, `Verify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.cpp`. |
| `KdfMasterKey` | `Generate`, `FromBytes`, `Bytes`, `DeriveSubkey` | Deterministic subkey derivation. `examples/misc.cpp`. |
| `GenericHash256`, `GenericHash512`, `Kupyna256Hasher`, `Kupyna512Hasher` | `Update`, `Finalize` | One-shot and streaming Kupyna hashing. `examples/misc.cpp`. |
| `StreamCipherKey` | `Generate`, `FromBytes`, `Bytes`, `Encrypt`, `Decrypt` | Strumok-256 keystream — **unauthenticated**, `Decrypt` never fails on tampered input. `examples/misc.cpp`. |
| `RandomBytes` | — | CSPRNG-backed random bytes. `examples/misc.cpp`. |
| — | `Selftest`, `Memzero`, `CryptoError`, `ArgumentError`, `InternalError` | Runtime KAT self-check (T-161); the three error types every failure surfaces as (cross-language style guide principle 4) — see `include/dstu/status.hpp`. |

## Testing

```sh
cargo build -p dstu-core-capi -p uacrypt --release   # from the repo root - the secretstream/uacrypt interop test needs uacrypt too
cd bindings/cpp
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

Or via the project's own cross-platform QA entry point: `cargo xtask cpp` (from the repo root) —
builds `dstu-core-capi`+`uacrypt`, configures, builds, and runs `ctest`.

## Examples

```sh
cmake --build build --config Release   # builds tests/ and examples/ together
./build/dstu_core_cpp_example_secretbox
./build/dstu_core_cpp_example_box
./build/dstu_core_cpp_example_secretstream_file
./build/dstu_core_cpp_example_sign
./build/dstu_core_cpp_example_password_hashing
./build/dstu_core_cpp_example_misc
```
