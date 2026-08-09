# dstu (Go binding)

**Provisional — not published as a versioned, tagged Go module, not independently audited.** See
the root project's `docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and
per-construction status. This binding wraps the full `dstu_core::crypto_*` surface via `cgo` over
`crates/dstu-core-capi`'s C ABI (T-158, `docs/bindings-strategy.md` T-163, `docs/DECISIONS.md`
D-155) — build from source as shown below.

Like `bindings/dotnet`/`bindings/java`, `dstu` has no Cargo workspace of its own — there is no Rust
code here beyond what T-158 already builds. **Unlike every other binding in this project, this one
is repo-relative by construction, not a standalone package a consumer can `go get` on its own**:
the `#cgo LDFLAGS` directive in `dstu/dstu.go` points at `${SRCDIR}/../../../target/release`, so
`bindings/go` only builds from inside a checkout of this repository, with `dstu-core-capi` already
built there. A real, independently-installable package would need the native library packaged and
located a different way (T-164 territory — see `docs/bindings-strategy.md`'s "Publishing" section
for the same gate every other binding's registry step already sits behind).

## Building

```sh
cargo build -p dstu-core-capi --release   # from the repo root - builds the native library this binding links against
cd bindings/go
go build ./...
```

On Windows, `cgo` needs a MinGW-w64 `gcc` toolchain (it cannot link against an MSVC-built import
library) — see `docs/DECISIONS.md` D-155 for the exact `-Wl,-Bstatic ... -lws2_32 -luserenv
-lntdll` flags this required, found by actually linking, not assumed.

```go
import "github.com/user137/uacrypt/bindings/go/dstu"

if err := dstu.Selftest(); err != nil {
    // re-verifies official KAT vectors against this exact compiled build
    panic(err)
}

key, err := dstu.GenerateSecretboxKey()
if err != nil {
    panic(err)
}
defer key.Close()
sealed, err := key.Seal([]byte("a message worth protecting"))
```

## Usage

See `examples/` for complete, runnable programs, and `dstu/*_test.go` for the full
correctness/rejection/misuse suite each surface is verified against (D-64/D-65).

| Type | Members | Notes |
|---|---|---|
| `SecretboxKey` | `GenerateSecretboxKey`, `SecretboxKeyFromBytes`, `Bytes`, `Seal`, `Open` | Single-message authenticated encryption. `examples secretbox`. |
| `BoxSecretKey`, `BoxPublicKey` | `GenerateBoxSecretKey`, `BoxSecretKeyFromBytes`, `BoxPublicKeyFromBytes`, `Bytes`, `PublicKey`, `Seal`, `Open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, `l(p)=256`, D-169). `Seal`/`Open` are not memory-bounded — the whole message is held in memory. `examples box`. |
| `Box512SecretKey`, `Box512PublicKey` | Same members as `BoxSecretKey`/`BoxPublicKey` | `l(p)=512`/E512/1 sibling of `crypto_box` (T-193/T-204) — distinct type, not interchangeable. `examples box512`. |
| `SecretstreamKey`, `SecretStreamEncryptWriter`, `SecretStreamDecryptReader` | `GenerateSecretstreamKey`, `SecretstreamKeyFromBytes`, `Bytes` | Chunked streaming AEAD, `io.Writer`/`io.Reader`-shaped. Wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `Close()` deliberately never emits the Final chunk — call `Complete()` explicitly on the success path; see the type doc comment. `examples secretstream-file`. |
| `SigningKey`, `VerifyingKey` | `GenerateSigningKey`, `SigningKeyFromBytes`, `Bytes`, `Sign`, `SignDigest`, `Verify`, `VerifyDigest` | DSTU 4145 `m=163` digital signatures, deterministic nonce (no RNG dependency). `examples sign`. |
| `SigningKey257`, `VerifyingKey257` | Same members as `SigningKey`/`VerifyingKey` | `m=257` sibling of `crypto_sign` (T-199/T-204) — the curve real Diia-issued qualified signatures use. Distinct type, untagged (curve dispatch stays a `uacrypt`-layer concern, D-118). `examples sign257`. |
| `HashPassword`, `VerifyPassword` | `PwhashInteractive`/`PwhashModerate`/`PwhashSensitive` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples password-hashing`. |
| `AuthKey` | `GenerateAuthKey`, `AuthKeyFromBytes`, `Bytes`, `Compute`, `Verify` | Keyed message authentication (Kupyna-KMAC). `examples misc`. |
| `KdfMasterKey` | `GenerateKdfMasterKey`, `KdfMasterKeyFromBytes`, `Bytes`, `DeriveSubkey` | Deterministic subkey derivation. `examples misc`. |
| `GenericHash256`, `GenericHash512`, `Kupyna256Hasher`, `Kupyna512Hasher` | `Update`, `Finalize` | One-shot and streaming Kupyna hashing. `examples misc`. |
| `StreamCipherKey` | `GenerateStreamCipherKey`, `StreamCipherKeyFromBytes`, `Bytes`, `Encrypt`, `Decrypt` | Strumok-256 keystream — **unauthenticated**, `Decrypt` never fails on tampered input. `examples misc`. |
| `RandomBytes` | — | CSPRNG-backed random bytes. `examples misc`. |
| — | `Selftest`, `CryptoError`, `ArgumentError`, `InternalError` | Runtime KAT self-check (T-161); the three error types every failure surfaces as (cross-language style guide principle 4) — see `dstu/status.go`. |

## Testing

```sh
cargo build -p uacrypt --release   # from the repo root - the secretstream/uacrypt interop test needs this
cd bindings/go
go test ./...
```

Or via the project's own cross-platform QA entry point: `cargo xtask go` (from the repo root) —
builds `dstu-core-capi`, runs `gofmt -l` (fails on any unformatted file), `go vet`, `go test`.

## Examples

```sh
cd bindings/go/examples
go run . secretbox
go run . box
go run . secretstream-file
go run . sign
go run . password-hashing
go run . misc
```
