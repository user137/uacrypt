# DstuCore (.NET binding)

**Provisional — not published to NuGet.org, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
This binding P/Invokes the full `dstu_core::crypto_*` surface via `crates/dstu-core-capi`'s C ABI
(T-158, `docs/bindings-strategy.md` T-52) — build from source as shown below.

Unlike the Python/Node/Ruby/PHP bindings, `DstuCore` has no Cargo workspace of its own — there is
no Rust code here beyond what T-158 already builds. This project is pure C#, P/Invoking into the
already-built `dstu_core_capi` shared library.

## Building

```sh
cargo build -p dstu-core-capi --release   # from the repo root - builds the native library this binding P/Invokes
cd bindings/dotnet
dotnet build DstuCore/DstuCore.csproj
```

`Directory.Build.props` in this directory copies whichever platform's `dstu_core_capi.{dll,so,dylib}`
exists under the repo's `target/release/` into every project's own build output automatically —
`dotnet build`/`dotnet test`/`dotnet run` all find the native library with no manual copy step or
`PATH`/`LD_LIBRARY_PATH` change.

```csharp
using DstuCore;

Selftest.Run(); // re-verifies official KAT vectors against this exact compiled build, throws on any mismatch

using var key = SecretboxKey.Generate();
var sealedMessage = key.Seal("a message worth protecting"u8.ToArray());
var plaintext = key.Open(sealedMessage);
```

## Usage

See `examples/` for complete, runnable programs, and `DstuCore.Tests/` for the full
correctness/rejection/misuse suite each surface is verified against (D-64/D-65).

| Type | Members | Notes |
|---|---|---|
| `SecretboxKey` | `Generate`, `FromBytes`, `ToBytes`, `Seal`, `Open` | Single-message authenticated encryption. `examples secretbox`. |
| `BoxSecretKey`, `BoxPublicKey` | `Generate`, `FromBytes`, `ToBytes`, `PublicKey`, `Seal`, `Open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `Seal`/`Open` are not memory-bounded — the whole message is held in memory. `examples box`. |
| `SecretstreamKey`, `SecretStreamEncryptStream`, `SecretStreamDecryptStream` | `Generate`, `FromBytes`, `ToBytes` | Chunked streaming AEAD, `Stream`-derived (matches `CryptoStream`/`GZipStream`'s own shape). Wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `Dispose()` deliberately never emits the final chunk — call `Complete()` explicitly on the success path; see the class doc comment. `examples secretstream-file`. |
| `SigningKey`, `VerifyingKey` | `Generate`, `FromBytes`, `ToBytes`, `Sign`, `SignDigest`, `Verify`, `VerifyDigest` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples sign`. |
| `Pwhash` | `HashPassword`, `VerifyPassword`, `PwhashStrength.{Interactive,Moderate,Sensitive}` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples password-hashing`. |
| `AuthKey` | `Generate`, `FromBytes`, `ToBytes`, `Compute`, `Verify` | Keyed message authentication (Kupyna-KMAC). `examples misc`. |
| `KdfMasterKey` | `Generate`, `FromBytes`, `ToBytes`, `DeriveSubkey` | Deterministic subkey derivation. `examples misc`. |
| `GenericHash`, `Kupyna256Hasher`, `Kupyna512Hasher` | `Hash256`, `Hash512`, `Update`, `Finalize` | One-shot and streaming Kupyna hashing. `examples misc`. |
| `StreamCipherKey` | `Generate`, `FromBytes`, `ToBytes`, `Encrypt`, `Decrypt` | Strumok-256 keystream — **unauthenticated**, `Decrypt` never fails on tampered input. Named to avoid colliding with `System.IO.Stream`. `examples misc`. |
| `RandomBytes` | `Buf` | CSPRNG-backed random bytes. `examples misc`. |
| — | `Selftest.Run`, `DstuException` | Runtime KAT self-check (T-161); the exception type every crypto-operation failure raises (`ArgumentException` covers caller-input mistakes instead — see `Native/NativeStatus.cs`). |

## Testing

```sh
cargo build -p uacrypt --release   # from the repo root - the SecretStream/uacrypt interop test needs this
cd bindings/dotnet
dotnet test DstuCore.Tests/DstuCore.Tests.csproj
```

Or via the project's own cross-platform QA entry point: `cargo xtask dotnet` (from the repo root).

## Examples

```sh
cd bindings/dotnet/examples
dotnet run -- secretbox
dotnet run -- box
dotnet run -- secretstream-file
dotnet run -- sign
dotnet run -- password-hashing
dotnet run -- misc
```

## Packaging

`dotnet pack DstuCore/DstuCore.csproj -c Release` produces a `.nupkg` carrying
`runtimes/{rid}/native/` for whichever platform ran the pack (D-152) — not published to
NuGet.org (T-164 gates that on an explicit owner request, same as every other binding's own
registry).
