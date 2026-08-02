# dstu-core (PHP bindings)

**Provisional — not published to PECL/Packagist, not independently audited.** See the root
project's `docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and
per-construction status. This binding wraps the full `dstu_core::crypto_*` surface
(`docs/bindings-strategy.md` T-159) — build from source and load the compiled extension
directly, as shown below. PHP has no wheel/npm-pack/gem equivalent for a native extension
(Composer never manages compiled binaries; PECL needs its own separate publish pipeline, out of
scope for a provisional binding) — see `docs/DECISIONS.md` D-144 for the full reasoning.

## Building (from source)

```sh
cargo build --release
```

This produces `target/release/dstu_core_php.dll` (Windows) or `target/release/
libdstu_core_php.so` (Linux; macOS produces `.dylib`, renamed to `.so` to match PHP's own
loader convention — see D-145). Load it either ad hoc:

```sh
php -d extension=/path/to/dstu_core_php.dll -r 'var_dump(dstu_core_self_test());'
```

or permanently via `php.ini`:

```ini
extension = /path/to/dstu_core_php.dll
```

**`ext-php-rs` needs PHP 8.1+ (built from a real `windows.php.net` release on Windows
specifically — not manually), Clang 5.0+ for `bindgen`, and on Windows, nightly Rust** (some PHP
internal functions use the `vectorcall` calling convention, a nightly-only unstable Rust feature)
**plus the MSVC host toolchain** (PHP's own Windows builds are MSVC — this repo's own
`bindings/php/.cargo/config.toml` already configures `rust-lld` as the linker to avoid an
MSVC-linker-version mismatch, and a machine-local `rustup override set
nightly-x86_64-pc-windows-msvc --path bindings/php` is needed the first time — see
`.claude.local.md` for the exact commands and gotchas found getting this working). On Windows,
`ext-php-rs`'s own build script downloads a matching PHP devel pack from `windows.php.net`
automatically at build time — no manual devel-pack management needed, just a real `php.exe` on
`PATH`.

This crate is its own Cargo workspace (`docs/DECISIONS.md` D-119), separate from the repo root —
build/test it from inside this directory, not from the repo root. It depends on this repo's own
`crates/dstu-core` by relative path, so it cannot build standalone outside this repo.

## Usage

Every function below is a flat, global, `dstu_core_`-prefixed function (no namespace or class,
except for the few stateful classes listed below) — matching the naming convention PHP's own
bundled `ext-sodium` extension already uses (`sodium_crypto_secretbox`, `SodiumException`), the
closest same-domain, same-runtime precedent (`docs/DECISIONS.md` D-142). Every byte
parameter/return (keys, ciphertexts, tags, hashes) is a real PHP binary string, not
UTF-8-validated. See `examples/` for complete, runnable scripts, and `tests/` for the full
correctness/rejection/misuse suite each one is verified against (D-64/D-65).

```php
<?php
$key = dstu_core_secretbox_keygen();
$sealed = dstu_core_secretbox_seal($key, 'a message worth protecting');
assert(dstu_core_secretbox_open($key, $sealed) === 'a message worth protecting');
```

| Module | Functions/classes | Notes |
|---|---|---|
| `crypto_secretbox` | `dstu_core_secretbox_keygen`, `_seal`, `_open` | Single-message authenticated encryption. `examples/secretbox.php`. |
| `crypto_secretstream` | `dstu_core_secretstream_keygen`, `DstuCoreSecretStreamPushState`, `DstuCoreSecretStreamPullState`, `DstuCoreSecretStreamWriter`, `DstuCoreSecretStreamReader` | Chunked streaming AEAD. `Writer`/`Reader` (`lib/DstuCoreSecretStream.php`, plain PHP over a `resource`, implementing `Iterator`) wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118/D-143). `examples/secretstream-file.php`. |
| `crypto_sign` | `dstu_core_sign_keygen`, `_verifying_key`, `_message`, `_verify` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples/sign.php`. |
| `crypto_pwhash` | `dstu_core_pwhash_hash_password`, `_verify_password`, `DSTU_CORE_PWHASH_INTERACTIVE`/`_MODERATE`/`_SENSITIVE` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/password-hashing.php`. |
| `crypto_auth` | `dstu_core_auth_keygen`, `dstu_core_auth`, `_auth_verify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.php`. |
| `crypto_kdf` | `dstu_core_kdf_keygen`, `_derive_subkey` | Deterministic subkey derivation. `examples/misc.php`. |
| `crypto_generichash` | `dstu_core_generichash_kupyna256`, `_kupyna512`, `DstuCoreKupyna256Hasher`, `DstuCoreKupyna512Hasher` | One-shot and streaming Kupyna hashing. `examples/misc.php`. |
| `crypto_stream` | `dstu_core_stream_keygen`, `_encrypt`, `_decrypt` | Strumok-256 keystream — **unauthenticated**, `_decrypt` never fails on tampered input. `examples/misc.php`. |
| `randombytes` | `dstu_core_randombytes_buf` | CSPRNG-backed random bytes. `examples/misc.php`. |
| — | `dstu_core_self_test`, `DstuCoreException`, `\ValueError` | Runtime KAT self-check (T-161); `DstuCoreException` is the one exception class every crypto-operation failure throws (PHP's own built-in `\ValueError` covers caller-input mistakes like a wrong-length key instead). |

## Testing

```sh
curl -sL https://phar.phpunit.de/phpunit-11.phar -o phpunit.phar
cargo build -p uacrypt --release   # from the repo root, for tests/SecretstreamTest.php's real CLI interop
cargo build
php -d extension=target/debug/dstu_core_php.dll phpunit.phar
```

`cargo xtask php` (from the repo root) runs this whole sequence in one command.
