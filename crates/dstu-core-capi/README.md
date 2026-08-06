# dstu-core (C ABI)

**Provisional — not independently audited, no prebuilt binaries published yet.** See the root
project's `docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and
per-construction status. This crate (`docs/bindings-strategy.md` T-158) is the foundation
C++/.NET/Java(-via-JNI)/Go bindings build on next — build from source and link the compiled
library directly, as shown below.

Unlike `bindings/python`/`bindings/nodejs`/`bindings/ruby`/`bindings/php` (each its own separate
Cargo workspace, `docs/DECISIONS.md` D-119), `dstu-core-capi` links no external language runtime
at build time — it **is** a real member of the repo-root Cargo workspace, so `cargo build`/`test`/
`clippy`/`fmt` from the repo root already cover it.

## Building (from source)

```sh
cargo build -p dstu-core-capi --release
```

Produces (Windows-GNU host, this dev machine's own default — see `.claude.local.md`;
Windows-MSVC/Linux/macOS filenames differ, see the table below):

| Platform | Dynamic library | Import/static library |
|---|---|---|
| Windows (GNU host) | `target/release/dstu_core_capi.dll` | `target/release/libdstu_core_capi.dll.a` (import), `target/release/libdstu_core_capi.a` (static) |
| Windows (MSVC host) | `target/release/dstu_core_capi.dll` | `target/release/dstu_core_capi.dll.lib` (import), `target/release/dstu_core_capi.lib` (static) |
| Linux | `target/release/libdstu_core_capi.so` | `target/release/libdstu_core_capi.a` (static) |
| macOS | `target/release/libdstu_core_capi.dylib` | `target/release/libdstu_core_capi.a` (static) |

The generated header is committed at `include/dstu_core.h` (regenerated via `cbindgen`, never a
build-dependency of this crate itself — `docs/DECISIONS.md` D-148 point 2). `cargo xtask capi`
regenerates it into a temp path and diffs against the committed copy, failing loudly on drift, then
compiles and runs the C test harness (`c-tests/`) and every example (`examples/`) against the
just-built library.

Minimal usage, linking against the dynamic library (Linux shown; see `examples/` for the exact
compiler invocation this crate's own CI uses on each platform):

```sh
cc -Iinclude your_program.c -o your_program -L target/release -ldstu_core_capi
LD_LIBRARY_PATH=target/release ./your_program
```

## Conventions (full detail: `docs/DECISIONS.md` D-148)

- Every exported symbol uses the `dstu_`/`Dstu` prefix (not `dstu_core_` — a deliberate difference
  from the PHP binding's own `ext-sodium`-modeled naming).
- Fallible functions return `DstuStatus` (`DSTU_OK` on success); a `verify`-shaped function
  mirroring a Rust `bool` return (`dstu_verify`/`dstu_verify_digest`) returns plain C `bool`
  instead — a signature either verifies or it doesn't, that's the actual answer, not an error code.
- **Caller-allocates**: this library never allocates or frees a Rust-owned buffer C could free with
  `free()`. Variable-length outputs (`crypto_secretbox`/`crypto_stream`'s sealed blobs) take an
  explicit `_cap` parameter, checked against the exact required length *before* any crypto work
  runs — `DSTU_ERR_BUFFER_TOO_SMALL` if insufficient, never a partial write.
- **Opaque handles** (`DstuAuthKey`, `DstuSecretboxKey`, `DstuPushState`, ...) cross the boundary
  only as pointers; `dstu_*_free` fires the wrapped type's own `Zeroize`-on-`Drop` impl. A value
  copied *out* into a caller-owned buffer (e.g. `dstu_sign_key_bytes`) is the caller's own
  responsibility to wipe with `dstu_memzero` once done.
- Every exported function is `catch_unwind`-wrapped — an internal panic (should never happen)
  becomes `DSTU_ERR_PANIC` (or a documented safe default — NULL/`false`/no-op — where no
  `DstuStatus` channel exists) instead of aborting the caller's whole process.
- Null/zero-length hygiene: a `(ptr, len)` pair with `len == 0` never touches `ptr`; a NULL pointer
  for any required argument is rejected with `DSTU_ERR_NULL_POINTER` wherever a `DstuStatus`
  channel exists to report it through.

## Usage

```c
#include "dstu_core.h"

DstuSecretboxKey *key = NULL;
dstu_secretbox_key_generate(&key);

const char *message = "a message worth protecting";
size_t sealed_cap = strlen(message) + DSTU_SECRETBOX_OVERHEAD;
uint8_t *sealed = malloc(sealed_cap);
size_t sealed_len = 0;
dstu_secretbox_seal(key, (const uint8_t *)message, strlen(message), sealed, sealed_cap, &sealed_len);

uint8_t *plaintext = malloc(strlen(message));
size_t plaintext_len = 0;
dstu_secretbox_open(key, sealed, sealed_len, plaintext, strlen(message), &plaintext_len);
/* plaintext[0..plaintext_len] == message */

dstu_secretbox_key_free(key);
```

| Module | Functions/types | Notes |
|---|---|---|
| `crypto_secretbox` | `dstu_secretbox_key_generate`, `_from_bytes`, `_bytes`, `_free`, `dstu_secretbox_seal`, `_open` | Single-message authenticated encryption. `examples/secretbox.c`. |
| `crypto_box` | `dstu_box_secretkey_*`, `DstuBoxPublicKey`/`dstu_box_publickey_*`, `dstu_box_seal`, `_open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `dstu_box_seal`/`_open` are not memory-bounded — the whole message is held in memory. `examples/box.c`. |
| `crypto_secretstream` | `dstu_secretstream_key_*`, `DstuPushState`/`dstu_secretstream_push_*`, `DstuPullState`/`dstu_secretstream_pull_*`, `DstuTag` | Raw chunked/streaming AEAD push/pull — no idiomatic-C stream wrapper here (a later consumer's own job). `examples/secretstream_file.c`. |
| `crypto_sign` | `dstu_sign_key_*`, `DstuVerifyingKey`/`dstu_verifying_key_*`, `dstu_sign`, `_digest`, `dstu_verify`, `_digest` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency for signing). `examples/sign.c`. |
| `crypto_pwhash` | `dstu_pwhash_hash_password`, `_verify_password`, `DstuPwhashStrength` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/misc.c`. |
| `crypto_auth` | `dstu_auth_key_*`, `dstu_auth`, `_verify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.c`. |
| `crypto_kdf` | `dstu_kdf_master_key_*`, `dstu_kdf_derive_subkey` | Deterministic subkey derivation. `examples/misc.c`. |
| `crypto_generichash` | `dstu_generichash_256`, `_512`, `DstuKupyna256Hasher`/`512Hasher` | One-shot and streaming Kupyna hashing. `examples/misc.c`. |
| `crypto_stream` | `dstu_stream_key_*`, `dstu_stream_encrypt`, `_decrypt` | Strumok-256 keystream — **unauthenticated**, `_decrypt` never fails on tampered input. `examples/misc.c`. |
| `randombytes` | `dstu_randombytes_buf` | CSPRNG-backed random bytes. `examples/misc.c`. |
| — | `dstu_selftest`, `dstu_memzero`, `DstuStatus` | Runtime KAT self-check (T-161); `dstu_memzero` is libsodium's `sodium_memzero` equivalent. |

## Testing

```sh
cargo install cbindgen --locked
cargo xtask capi
```

Runs, in order: the header drift check, `cargo build -p dstu-core-capi --release`, the plain-C
test harness (`c-tests/test_capi.c` — correctness/rejection/misuse per D-64/D-65), and every
example under `examples/`. A real C compiler is required: MSVC (`cl.exe`, via `vcvars64.bat`) on a
Windows-MSVC host, `gcc` on Windows-GNU, `cc` on Linux/macOS.
