# uacrypt

CLI over `dstu-core` — Ukrainian DSTU cryptographic standards (Kalyna, Kupyna, Strumok), in the
spirit of **libsodium**: mode, nonce, and algorithm choices are hardcoded per command, nothing for
the caller to misconfigure.

**v0.1.0 — pre-release / work in progress.** Not audited, not a claim of side-channel resistance.
See `dstu-core`'s README (or the project repository's `SECURITY.md`) for the underlying primitives'
verification status — every command below inherits it.

## Commands

```
cargo build -p uacrypt --release

uacrypt keygen --out key.bin
uacrypt encrypt --key key.bin --in message.bin --out sealed.bin
uacrypt decrypt --key key.bin --in sealed.bin --out message.bin
uacrypt hash --in file.bin --out digest.bin

uacrypt sign-keygen --out signing.key
uacrypt sign-pubkey --key signing.key --out verifying.key
uacrypt sign --key signing.key --in file.bin --out file.bin.sig
uacrypt verify --key verifying.key --in file.bin --sig file.bin.sig
```

`encrypt`/`decrypt` have no message-length cap and stream `--in`/`--out` in fixed-size chunks —
built over `dstu_core::crypto_secretstream`, a genuinely chunked AEAD construction, not a
whole-buffer one. `--key` is a raw 32-byte file; `encrypt` draws a fresh random header internally
on every call and embeds it in `--out` — there is no `--nonce`/`--header` flag to supply or reuse
by mistake. `hash` streams `--in` from disk in fixed-size chunks regardless of size, fixed to
Kupyna-256 (32-byte digest, no `--variant` choice).

`sign`/`verify` are the DSTU 4145 digital-signature equivalent, built over `dstu_core::crypto_sign`
(deterministic nonce — no RNG involved in signing itself, only in `sign-keygen`). Both stream
`--in` through Kupyna-256 in fixed-size chunks before signing/checking the digest, so file size is
not a memory concern. `--key` for `sign` is a raw 21-byte private scalar (`sign-keygen`'s output);
`--key` for `verify` is a raw 42-byte uncompressed public point (`sign-pubkey`'s output, safe to
share); the signature itself is a raw 42-byte file. `verify` prints nothing and exits 0 on a valid
signature, or exits with an error (nothing written) if the message, signature, or key don't match.

Lower-level, `hazmat`-scoped commands also exist for anyone who wants direct control instead of the
misuse-resistant trio above:

```
uacrypt kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out ct.bin
uacrypt kalyna-ccm encrypt --variant 128-128 --key key.bin --nonce nonce.bin --aad aad.bin --in msg.bin --out ct.bin --tag tag.bin
uacrypt kupyna-digest --variant 256 --in file.bin --out digest.bin
uacrypt strumok-crypt --variant 256 --key key.bin --iv iv.bin --in file.bin --out out.bin
```

`kalyna-block` operates on exactly one block (no mode, no padding). `kalyna-ccm` additionally
encrypts/authenticates arbitrary-length **short** messages (plaintext and `--aad` each capped at
255 bytes, a sourced property of the construction) using a provisional, dual-oracle-verified
Kalyna-alone CCM mode, not yet confirmed against the primary DSTU 7624:2014 text.

`uacrypt keygen --out key.bin` generates a fresh 32-byte key from the OS CSPRNG, in the exact
format `encrypt`/`decrypt --key` expect.

## Status and safety

This is pre-1.0, unaudited software. See the project repository's `SECURITY.md` for the full
threat model, `DECISIONS.md` for every architectural decision with its citation, and `TASKS.md`
for what is and isn't done yet.

## License

Dual-licensed under MIT / Apache-2.0, at your choice. See `LICENSE-MIT` and `LICENSE-APACHE` in
the project repository.
