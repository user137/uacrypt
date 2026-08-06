# dstu-core

Rust implementations of Ukrainian DSTU cryptographic standards — Kalyna (DSTU 7624:2014, block
cipher), Kupyna (DSTU 7564:2014, hash), and Strumok (DSTU 8845:2019, stream cipher) — in the
spirit of **libsodium** (hard, safe defaults, hard to misuse) rather than OpenSSL.

**v0.1.0 — pre-release / work in progress.** Not audited, not a claim of side-channel resistance.
Kalyna and Kupyna are dual-oracle-verified against official test vectors; Strumok and every Kalyna
mode of operation are provisional — not yet confirmed against their primary standard text (see
`docs/DECISIONS.md`/`docs/SECURITY.md` in the project repository, not shipped in this package, for the full
citation trail and threat model). `crypto_secretstream`/`crypto_kdf` have no oracle vector at all
and never will, since no DSTU standard defines an equivalent construction — verified by property,
tamper, and misuse tests instead.

## Two layers

- **`dstu_core::hazmat::*`** — direct algorithm implementations. No forced RNG dependency, no
  auto-generated nonces; the caller passes keys/nonces/IVs explicitly. `no_std`-compatible.
  Covers Kalyna (all 5 block/key-size variants) and its 10 DSTU 7624 modes of operation
  (ECB/CBC/OFB/CFB/CTR/CMAC/KW/GCM/GMAC/XTS), Kupyna (256/512, one-shot and streaming), Kupyna-KMAC
  and Kupyna-KDF, Strumok (256/512-bit key), DSTU 4145 (m=163 curve only), and DSTU 9041 hybrid
  asymmetric encryption over a twisted Edwards curve (`l(p)=256`/E256/1 only).
- **`dstu_core::crypto_*`** — libsodium-style ergonomic wrappers over `hazmat`: auto-generated
  nonces where the construction needs one, misuse-resistant defaults, a single safe variant per
  primitive instead of every knob `hazmat` exposes. Covers `crypto_secretbox`, `crypto_secretstream`,
  `crypto_box`, `crypto_sign`, `crypto_stream`, `crypto_auth`, `crypto_kdf`, `crypto_generichash`,
  and `crypto_pwhash` (Argon2id, not DSTU).

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `std` | on | Enables `getrandom`-backed key/nonce generation and any module needing `Vec`/`String` (`crypto_secretbox`, `crypto_secretstream`, `crypto_stream`). Assumes a real OS — `getrandom` picks its OS backend automatically. |
| `getrandom` | off | The narrower half of `std`'s RNG support, without pulling in `std`/`alloc`: enables `randombytes`/`Key::generate`-style key generation on a `no_std` target that has configured one of `getrandom`'s own non-OS backends (most commonly `custom` — `--cfg getrandom_backend="custom"` plus your own `extern "Rust" fn __getrandom_v03_custom`; see [`getrandom`'s own docs](https://docs.rs/getrandom/latest/getrandom/#custom-backend)). `std` implies this. |
| `alloc` | off | Placeholder for `alloc`-only (no `std`) builds — not yet load-bearing for any code path. |
| `small-tables` | off | Swaps the fused S-box+MDS lookup tables (~86 KB) for a smaller `gf_mul`-based path (~6 KB), for flash-constrained microcontroller targets. Real memory/speed trade-off, same output. Combines with any of the above. |
| `pwhash` | off | Enables `crypto_pwhash` (Argon2id via the `argon2` crate). Off by default — most targets have no use for a password-hashing KDF and its heavier dependency surface. |

`cargo build --no-default-features` builds a bare `no_std` core with no allocator dependency at
all — this crate targets both full OSes (Windows/Linux/macOS) and bare-metal microcontrollers from
the same codebase, no CPU-family or OS lock-in by design.

## Examples

Every example below is wired in as a real rustdoc doctest (`cargo test -p dstu-core --doc`), so it
is compiled and run on every test pass, not just eyeballed once and left to bit-rot — copy-pasted
here verbatim, not paraphrased. `pwhash`'s example needs `--features pwhash` to compile; all others
run under the default build, and identically under `--features small-tables` too (the two resource
profiles are drop-in swaps for each other — same API, same output, only internal table size and
speed differ, `docs/resource-profiles.md`).

### `crypto_secretbox` — encrypt a whole message

Confidentiality *and* integrity for a single in-memory message: nobody without the key can read it,
and any tampering is rejected rather than silently producing wrong plaintext.

```rust
use dstu_core::crypto_secretbox::{seal, open, SecretKey};

let key = SecretKey::generate().expect("OS CSPRNG should not fail");
let sealed = seal(&key, b"message").expect("OS CSPRNG should not fail");
let opened = open(&key, &sealed).expect("authentic ciphertext");
assert_eq!(opened, b"message");

// Tampering with the sealed blob (ciphertext, tag, or nonce) is detected, not silently
// "decrypted" into wrong plaintext.
let mut tampered = sealed.clone();
let last = tampered.len() - 1;
tampered[last] ^= 1;
assert!(open(&key, &tampered).is_err());
```

### `crypto_secretstream` — encrypt a large/streamed file

Like `crypto_secretbox`, but processes data in bounded-size chunks instead of holding the whole
message in memory — see `uacrypt`'s own `encrypt`/`decrypt` commands for the real chunked-file-I/O
shape. Each chunk is authenticated individually.

```rust
use dstu_core::crypto_secretstream::{Key, PushState, PullState, Tag};

let key = Key::generate().expect("OS CSPRNG should not fail");
let plaintext = b"a whole file, conceptually split into chunks";

// Sender side: one chunk, marked Final since it's the only (and therefore last) one.
let (mut push, header) = PushState::init(&key).expect("OS CSPRNG should not fail");
let mut ciphertext = vec![0u8; plaintext.len()];
let tag = push
    .push(Tag::Final, plaintext, &mut ciphertext)
    .expect("push before finalization");

// Receiver side: needs the key and the transmitted header, ciphertext, and tag.
let mut pull = PullState::init(&key, &header);
let mut decrypted = vec![0u8; ciphertext.len()];
let read_tag = pull
    .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut decrypted)
    .expect("authentic chunk");
assert_eq!(read_tag, Tag::Final);
assert_eq!(decrypted, plaintext);

// A tampered ciphertext byte is rejected, not silently decrypted into garbage.
let mut tampered = ciphertext.clone();
tampered[0] ^= 1;
let mut pull2 = PullState::init(&key, &header);
let mut out = vec![0u8; tampered.len()];
assert!(pull2
    .pull(Tag::Final.to_byte(), &tampered, &tag, &mut out)
    .is_err());
```

### `crypto_sign` — prove a message's origin and integrity

Unlike `crypto_secretbox`, a signature does not hide the message — it only attests to who signed it
and that it hasn't changed since.

```rust
use dstu_core::crypto_sign::SigningKey;

let signing_key = SigningKey::generate().expect("OS CSPRNG should not fail");
let verifying_key = signing_key.verifying_key(); // safe to share/publish

let message = b"a message whose origin and integrity matter";
let signature = signing_key.sign(message);
assert!(verifying_key.verify(message, &signature));

// A different message, or a signature from a different key, must fail to verify.
assert!(!verifying_key.verify(b"a different message", &signature));
let other_key = SigningKey::generate().expect("OS CSPRNG should not fail");
assert!(!other_key.verifying_key().verify(message, &signature));
```

### `crypto_box` — public-key encryption, no shared secret needed

Unlike `crypto_secretbox`, the sender only needs the recipient's *public* key — no symmetric key
ever has to be exchanged first. Hybrid via KDF over `hazmat::dstu9041` (a KEM wraps a random seed,
which then derives a `crypto_secretstream` key for the actual message, of any length).

```rust
use dstu_core::crypto_box::{seal, open, SecretKey};

let secret = SecretKey::generate().expect("OS CSPRNG should not fail");
let public = secret.public_key(); // safe to share/publish

let sealed = seal(b"a message for the public key's holder only", &public)
    .expect("OS CSPRNG should not fail");
let opened = open(&sealed, &secret).expect("authentic ciphertext under the matching key");
assert_eq!(opened, b"a message for the public key's holder only");

// Tampering with the sealed blob (KEM prefix, header, ciphertext, or tag) is detected.
let mut tampered = sealed.clone();
let last = tampered.len() - 1;
tampered[last] ^= 1;
assert!(open(&tampered, &secret).is_err());
```

### `crypto_auth` — a shared-secret message authentication code

Both parties hold the same key, so unlike `crypto_sign` this proves "someone who has the key", not
"specifically you".

```rust
use dstu_core::crypto_auth::{auth, verify, Key};

let key = Key::generate().expect("OS CSPRNG should not fail");
let message = b"a message both parties want to confirm is unmodified";

let tag = auth(&key, message);
assert!(verify(&key, message, &tag).is_ok());

// A tampered message, or the wrong key, is rejected.
assert!(verify(&key, b"a different message", &tag).is_err());
```

### `crypto_kdf` — derive many subkeys from one master key

Useful when you want, say, a separate encryption key and MAC key derived from one secret rather
than managing two unrelated secrets.

```rust
use dstu_core::crypto_kdf::MasterKey;

let master_key = MasterKey::generate().expect("OS CSPRNG should not fail");

let encryption_subkey = master_key.derive_subkey(0, b"encrypt_");
let mac_subkey = master_key.derive_subkey(1, b"mac_key_");

// Different subkey_id (holding context fixed) gives a different, unrelated-looking subkey.
assert_ne!(encryption_subkey, mac_subkey);
// Deterministic: the same id/context always re-derives the same subkey.
assert_eq!(encryption_subkey, master_key.derive_subkey(0, b"encrypt_"));
```

### `crypto_generichash` — a fixed-size fingerprint, no secret key

Useful for checking a file wasn't corrupted or changed, but (unlike `crypto_auth`) it needs no
secret key, so anyone can compute or forge one — it is not proof of origin. One-shot for a whole
in-memory message, or incremental for a large/streamed one (both produce the same digest).

```rust
use dstu_core::crypto_generichash::{Kupyna256, Kupyna256Hasher};

let whole = Kupyna256::digest(b"hello world");

let mut hasher = Kupyna256Hasher::new();
hasher.update(b"hello ");
hasher.update(b"world");
let streamed = hasher.finalize();

assert_eq!(whole, streamed);
```

### `crypto_stream` — a bare keystream cipher, **no authentication**

Confidentiality only — prefer `crypto_secretbox`/`crypto_secretstream` unless you specifically need
a bare keystream cipher and are handling authentication yourself. Note the contrast with
`crypto_secretbox` above: `decrypt` never errors on tampered input, it just returns different,
silently-wrong plaintext.

```rust
use dstu_core::crypto_stream::{encrypt, decrypt, Key};

let key = Key::generate().expect("OS CSPRNG should not fail");
let sealed = encrypt(&key, b"message").expect("OS CSPRNG should not fail");
let opened = decrypt(&key, &sealed).expect("sealed is at least IV-length");
assert_eq!(opened, b"message");

// Tampering is not detected - decrypt "succeeds" with garbage plaintext instead of erroring.
let mut tampered = sealed.clone();
let last = tampered.len() - 1;
tampered[last] ^= 1;
let garbage = decrypt(&key, &tampered).expect("still at least IV-length, so still Ok");
assert_ne!(garbage, b"message");
```

### `crypto_pwhash` — hashing passwords before storing them (needs `--features pwhash`)

Deliberately slow and memory-hard, unlike every hash above — the whole point is making guessing many
candidate passwords against a stolen hash expensive. `Strength::Interactive` is the fastest of the
three presets; a real login system would usually want `Moderate` or `Sensitive` instead.

```rust
use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};

let stored_hash = hash_password(b"correct horse battery staple", Strength::Interactive)
    .expect("OS CSPRNG should not fail");

assert!(verify_password(b"correct horse battery staple", &stored_hash));
assert!(!verify_password(b"wrong guess", &stored_hash));
```

## Status and safety

This is pre-1.0, unaudited software. See the project repository's `docs/SECURITY.md` for the full
threat model and hard constraints, `docs/DECISIONS.md` for every architectural decision with its
citation, and `docs/TASKS.md` for what is and isn't done yet. No claim of hardware side-channel
(SPA/DPA) resistance is made or implied anywhere in this crate.

## License

Dual-licensed under MIT / Apache-2.0, at your choice. See `LICENSE-MIT` and `LICENSE-APACHE` in
the project repository.
