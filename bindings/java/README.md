# dstu-core (Java binding)

**Provisional — not published to Maven Central, not independently audited.** See the root
project's `docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and
per-construction status. This binding exposes the full `dstu_core::crypto_*` surface via a direct
Rust JNI wrapper (the `jni` crate, `bindings/java/native/`, `docs/bindings-strategy.md` T-51) — not
through `crates/dstu-core-capi`'s C ABI. See `docs/DECISIONS.md` D-153 for the step-0 spike that
made this choice: it joins Python/Node/Ruby/PHP's direct-binding group rather than .NET/C++/Go's
C-ABI-consuming one, avoiding a third language (C) and a doubled native-artifact packaging surface.

Build/test toolchain is a modern JDK (17 recommended, matching this project's Raspberry Pi rig's
Debian 12 default); the *published* artifact still targets **Java 8** bytecode
(`maven.compiler.release` in `pom.xml`) — Java 8 has real, ongoing enterprise/PKI-adjacent
footprint, the same audience this binding's Bouncy-Castle-incumbent framing already targets.

## Building

```sh
cd bindings/java/native
cargo build --release        # builds the native dstu_core_java.{dll,so,dylib}
cd ..
mvn compile                  # copies the native library onto the classpath, compiles the Java sources
```

```java
import ua.dstucrypto.dstucore.Selftest;
import ua.dstucrypto.dstucore.SecretBox;

Selftest.run(); // re-verifies official KAT vectors against this exact compiled build, throws on any mismatch

byte[] key = SecretBox.keygen();
byte[] sealed = SecretBox.seal(key, "a message worth protecting".getBytes("UTF-8"));
byte[] plaintext = SecretBox.open(key, sealed);
```

## Usage

See `examples/` for complete, runnable programs, and `src/test/java/` for the full
correctness/rejection/misuse suite each surface is verified against (D-64/D-65).

| Type | Members | Notes |
|---|---|---|
| `SecretBox` | `keygen`, `seal`, `open` | Single-message authenticated encryption. `examples secretbox`. |
| `SecretStream`, `SecretStreamEncryptor`, `SecretStreamDecryptor` | `keygen`; `OutputStream`/`InputStream` subclasses | Chunked streaming AEAD. Wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `close()` deliberately never emits the `Final` chunk — call `complete()` explicitly on the success path; see the class doc comment. `examples secretstream-file`. |
| `Sign` | `keygen`, `verifyingKey`, `sign`, `verify` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples sign`. |
| `Pwhash`, `PwhashStrength` | `hashPassword`, `verifyPassword`, `{INTERACTIVE,MODERATE,SENSITIVE}` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples password-hashing`. |
| `Auth` | `keygen`, `auth`, `verify` | Keyed message authentication (Kupyna-KMAC). `examples misc`. |
| `Kdf` | `keygen`, `deriveSubkey` | Deterministic subkey derivation. `examples misc`. |
| `GenericHash`, `Kupyna256Hasher`, `Kupyna512Hasher` | `hash256`, `hash512`, `update`, `finish` | One-shot and streaming Kupyna hashing. `examples misc`. |
| `StreamCipher` | `keygen`, `encrypt`, `decrypt` | Strumok-256 keystream — **unauthenticated**, `decrypt` never fails on tampered input. Named to avoid colliding with `java.util.stream.Stream`. `examples misc`. |
| `RandomBytes` | `buf` | CSPRNG-backed random bytes. `examples misc`. |
| — | `Selftest.run`, `DstuException` | Runtime KAT self-check (T-161); the exception type every crypto-operation failure raises (`IllegalArgumentException`/`IllegalStateException` cover caller-input/call-sequence mistakes instead — see `native/src/util.rs`). |

## Testing

```sh
cargo build -p uacrypt --release   # from the repo root - the SecretStream/uacrypt interop test needs this
cd bindings/java/native && cargo build --release && cd ..
mvn test
```

Or via the project's own cross-platform QA entry point: `cargo xtask java` (from the repo root).

## Examples

```sh
cd bindings/java
mvn compile
javac -cp target/classes -d target/examples-classes examples/*.java
java -cp "target/classes;target/examples-classes" Main secretbox          # Windows (`;` separator)
java -cp "target/classes:target/examples-classes" Main secretbox          # Linux/macOS (`:` separator)
# ... secretstream-file, sign, password-hashing, misc
```

## Packaging

`mvn package` produces a `dstu-core-<version>.jar` carrying `native/<os-arch classifier>/` for
whichever platform ran the build (this build machine's own classifier only — cross-OS packaging is
a future `release.yml` job, same posture T-52/T-158's own step 4 took) — not published to Maven
Central (gated on an explicit owner request, same as every other binding's own registry).
