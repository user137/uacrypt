# dstu-core (Node.js bindings)

**Provisional — not published to npm, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
This binding wraps the full `dstu_core::crypto_*` surface (`docs/bindings-strategy.md` T-50) —
install from source as shown below.

## Installing (from source)

```sh
npm install
npm run build
node -e "require('./js/index.js').selfTest()"
```

`npm run build` (`napi build native --platform --release`) compiles the Rust addon and generates
`native/index.js`/`native/index.d.ts`/the platform-specific `*.node` binary — all gitignored,
regenerated fresh every build (never hand-edited or committed). `js/index.js` is the hand-written
public entry point: every native export re-exported as-is, plus the idiomatic
`stream.Transform`-based `SecretStreamEncryptor`/`SecretStreamDecryptor` (D-118) built in pure JS on
top of them.

`selfTest()` re-runs `dstu_core::selftest::run()` (`docs/TASKS.md` T-161) against the exact
compiled build and throws if anything official-vector-level is wrong — the first thing to run
after any build to confirm it actually works, not just compiled.

This crate is its own Cargo workspace, separate from the repo root (`docs/DECISIONS.md` D-119) —
build/test it from inside this directory, not from the repo root. On Windows, `napi-build`'s
`gnu`-host path needs a real `libnode.dll` that no prebuilt Node.js distribution ships — if your
own Rust toolchain defaults to a `-gnu` host (uncommon, but possible), switch to an MSVC toolchain
for this directory specifically: `rustup override set stable-x86_64-pc-windows-msvc` (see
`docs/DECISIONS.md` D-125/D-130 for why this is a machine-local fix, not something committed here).

## Usage

Every function/class below is a named export of `js/index.js` (`require('dstu-core')` once
published, `require('../js/index.js')` from inside this repo). See `examples/` for complete,
runnable scripts, and `test/` for the full correctness/rejection/misuse suite each one is verified
against (D-64/D-65).

```js
const dstu = require('./js/index.js');

const key = dstu.secretboxKeygen();
const sealed = dstu.secretboxSeal(key, Buffer.from('a message worth protecting'));
console.log(dstu.secretboxOpen(key, sealed).toString()); // "a message worth protecting"
```

| Module | Functions/classes | Notes |
|---|---|---|
| `crypto_secretbox` | `secretboxKeygen`, `secretboxSeal`, `secretboxOpen` | Single-message authenticated encryption. `examples/secretbox.js`. |
| `crypto_box` | `boxKeygen`, `boxPublicKey`, `boxSeal`, `boxOpen` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `boxSeal`/`boxOpen` are not memory-bounded — the whole message is held in memory. `examples/box.js`. |
| `crypto_secretstream` | `secretstreamKeygen`, `SecretStreamPushState`, `SecretStreamPullState`, `SecretStreamEncryptor`, `SecretStreamDecryptor` | Chunked streaming AEAD. The `stream.Transform` `SecretStreamEncryptor`/`SecretStreamDecryptor` wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `examples/secretstream-file.js`. |
| `crypto_sign` | `signKeygen`, `signVerifyingKey`, `signMessage`, `signVerify` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples/sign.js`. |
| `crypto_pwhash` | `pwhashHashPassword`, `pwhashVerifyPassword`, `PWHASH_INTERACTIVE`/`PWHASH_MODERATE`/`PWHASH_SENSITIVE` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/password-hashing.js`. |
| `crypto_auth` | `authKeygen`, `auth`, `authVerify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.js`. |
| `crypto_kdf` | `kdfKeygen`, `kdfDeriveSubkey` | Deterministic subkey derivation. `subkeyId` is a plain non-negative `number`, not `BigInt`. `examples/misc.js`. |
| `crypto_generichash` | `kupyna256`, `kupyna512`, `Kupyna256Hasher`, `Kupyna512Hasher` | One-shot and streaming Kupyna hashing. `examples/misc.js`. |
| `crypto_stream` | `streamKeygen`, `streamEncrypt`, `streamDecrypt` | Strumok-256 keystream — **unauthenticated**, `streamDecrypt` never fails on tampered input. `examples/misc.js`. |
| `randombytes` | `randombytesBuf` | CSPRNG-backed random bytes. `examples/misc.js`. |
| — | `selfTest` | Runtime KAT self-check (T-161). Every crypto-operation failure throws a plain `Error` carrying the underlying cause's message. |

## Testing

```sh
node --test
```

`cargo build -p uacrypt --release` (from the repo root) first if you want
`test/secretstream.test.js`'s live `uacrypt` CLI interop test to actually run instead of skipping.
`cargo xtask nodejs` (from the repo root) runs this whole sequence, including that build step, in
one command.
