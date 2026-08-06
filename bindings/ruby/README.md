# dstu-core (Ruby bindings)

**Provisional — not published to RubyGems, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
This binding wraps the full `dstu_core::crypto_*` surface (`docs/bindings-strategy.md` T-160) —
install from source as shown below.

## Installing (from source)

```sh
gem install bundler
bundle install
bundle exec rake compile
ruby -Ilib -e 'require "dstu_core"; DstuCore.self_test'
```

`magnus`/`rb_sys` need a matching Ruby + C toolchain to build the native extension — a real
`gcc`/`clang` install, not just Ruby itself. On Windows specifically, install the **DevKit**
variant of Ruby (bundles a matching MSYS2/mingw-w64-ucrt toolchain — a plain Ruby install has no
compiler wired up at all):

```
winget install --id RubyInstallerTeam.RubyWithDevKit.3.3 --exact
```

`rb-sys`'s `bindgen` step also needs a `libclang` that matches Ruby's own mingw-ucrt target — a
generic pre-existing Windows LLVM install parses Ruby's headers incorrectly. Install the matching
MSYS2 package and point `LIBCLANG_PATH` at it:

```
pacman -S --needed mingw-w64-ucrt-x86_64-clang   # via `ridk` or an MSYS2 shell
export LIBCLANG_PATH="/path/to/msys64/ucrt64/bin"
```

`bundle exec rake compile` builds the Rust extension and copies it into `lib/dstu_core/`.
`DstuCore.self_test` re-runs `dstu_core::selftest::run()` (`docs/TASKS.md` T-161) against the
exact compiled build and raises `DstuCore::Error` if anything official-vector-level is wrong — the
first thing to run after any build to confirm it actually works, not just compiled.

This crate is its own Cargo workspace, split across `Cargo.toml` (the workspace root) and
`ext/dstu_core_rb/Cargo.toml` (the actual crate) — separate from the repo root
(`docs/DECISIONS.md` D-119) — build/test it from inside this directory, not from the repo root.
A **source** install (the steps above) needs this repo's own `crates/dstu-core` alongside it, since
`ext/dstu_core_rb/Cargo.toml` depends on it by relative path — it cannot install standalone outside
this repo. `rake native gem` instead builds a precompiled, platform-tagged gem that ships the
compiled extension directly and installs anywhere (see `docs/DECISIONS.md` D-136).

## Usage

Every method/class below lives directly on the `DstuCore` module (no further nesting). Every
`String` this binding touches is binary (`ASCII-8BIT`) — `.b`/`force_encoding("BINARY")` a UTF-8
string before comparing it against a decrypted result. See `examples/` for complete, runnable
scripts, and `spec/` for the full correctness/rejection/misuse suite each one is verified against
(D-64/D-65).

```ruby
require "dstu_core"

key = DstuCore.secretbox_keygen
sealed = DstuCore.secretbox_seal(key, "a message worth protecting")
raise unless DstuCore.secretbox_open(key, sealed) == "a message worth protecting"
```

| Module | Methods/classes | Notes |
|---|---|---|
| `crypto_secretbox` | `secretbox_keygen`, `secretbox_seal`, `secretbox_open` | Single-message authenticated encryption. `examples/secretbox.rb`. |
| `crypto_box` | `box_keygen`, `box_public_key`, `box_seal`, `box_open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `box_seal`/`box_open` are not memory-bounded — the whole message is held in memory. `examples/box.rb`. |
| `crypto_secretstream` | `secretstream_keygen`, `SecretStreamPushState`, `SecretStreamPullState`, `SecretStreamWriter`, `SecretStreamReader` | Chunked streaming AEAD. `SecretStreamWriter`/`Reader` (modeled on stdlib's own `Zlib::GzipWriter`/`GzipReader`) wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `examples/secretstream_file.rb`. |
| `crypto_sign` | `sign_keygen`, `sign_verifying_key`, `sign_message`, `sign_verify` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples/sign.rb`. |
| `crypto_pwhash` | `pwhash_hash_password`, `pwhash_verify_password`, `PWHASH_INTERACTIVE`/`PWHASH_MODERATE`/`PWHASH_SENSITIVE` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/password_hashing.rb`. |
| `crypto_auth` | `auth_keygen`, `auth`, `auth_verify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.rb`. |
| `crypto_kdf` | `kdf_keygen`, `kdf_derive_subkey` | Deterministic subkey derivation. `examples/misc.rb`. |
| `crypto_generichash` | `kupyna256`, `kupyna512`, `Kupyna256Hasher`, `Kupyna512Hasher` | One-shot and streaming Kupyna hashing. `examples/misc.rb`. |
| `crypto_stream` | `stream_keygen`, `stream_encrypt`, `stream_decrypt` | Strumok-256 keystream — **unauthenticated**, `stream_decrypt` never fails on tampered input. `examples/misc.rb`. |
| `randombytes` | `randombytes_buf` | CSPRNG-backed random bytes. `examples/misc.rb`. |
| — | `self_test`, `DstuCore::Error` | Runtime KAT self-check (T-161); the one exception class every crypto-operation failure raises (`ArgumentError` covers caller-input mistakes like a wrong-length key instead). |

## Testing

```sh
bundle exec rubocop
bundle exec rspec
```

`cargo build -p uacrypt --release` (from the repo root) first if you want
`spec/secretstream_spec.rb`'s live `uacrypt` CLI interop test to actually run instead of being
`skip`ped. `cargo xtask ruby` (from the repo root) runs this whole sequence, including that build
step and `rake compile`, in one command.
