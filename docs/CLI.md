# Using `uacrypt`

`uacrypt encrypt`/`decrypt`/`hash` (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52) are the real,
misuse-resistant top-level commands — mode, nonce, and algorithm are all hardcoded, nothing to
misconfigure:

```
cargo build -p uacrypt --release
uacrypt keygen --out key.bin
uacrypt encrypt --key key.bin --in message.bin --out sealed.bin
uacrypt decrypt --key key.bin --in sealed.bin --out message.bin
uacrypt hash --in file.bin --out digest.bin
```

**`encrypt`/`decrypt` have no message-length cap and stream `--in`/`--out` in fixed-size chunks** —
as of 2026-07-25 they're built over `dstu_core::crypto_secretstream` (`docs/TASKS.md` T-40/T-70,
`docs/DECISIONS.md` D-68), a genuinely chunked construction over `hazmat::kalyna_gcm`, not the earlier
whole-buffer `crypto_secretbox` (`docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51/D-63) - a large input file no
longer means a correspondingly large in-memory buffer. **Breaking wire-format change**: a file the
prior `crypto_secretbox`-backed `encrypt` produced cannot be read by this `decrypt`, and vice versa
- acceptable pre-1.0. `crypto_secretbox` itself is unchanged and still available as a library
primitive for whole-message use, just no longer what this CLI command uses. `--key` is a raw
32-byte file (`crypto_secretstream::Key`'s size) — `uacrypt keygen --out key.bin` generates one from
the OS CSPRNG (`docs/TASKS.md` T-115). Like every `*-keygen` command, it refuses to overwrite an
existing `--out`, so a repeated run cannot destroy a key, and on Unix it writes the key with mode
`0600` (T-241). `encrypt` draws a fresh random header internally on every call
and embeds it in `--out`; there is no `--nonce`/`--header` flag to supply or reuse by mistake.
**0.4.0 changed the `encrypt`/`box-seal`/`box-seal512` file formats** (T-232/T-248,
`docs/DECISIONS.md` D-200-D-202). Files written by 0.3.x don't open with 0.4.0. `box-open` almost
always reports them as a different format version; ~1 in 256 happen to start with the current
version byte and report an authentication failure instead. Decrypt them with the release that
wrote them, then re-encrypt.
**`hash` has no such limit either** — it streams `--in` from disk in fixed-size chunks regardless of
size, fixed to Kupyna-256 (32-byte digest, no `--variant` choice).

`uacrypt sign-keygen`/`sign-pubkey`/`sign`/`verify` (`docs/TASKS.md` T-124, `docs/DECISIONS.md` D-73) are the
digital-signature equivalent, built over `dstu_core::crypto_sign` (DSTU 4145): a signature proves a
file came from whoever holds the signing key and hasn't been changed since — unlike `encrypt`, it
does not hide the file's contents, only attests to who signed it and that it's unmodified. Every
command below was run for real against the release binary before being written here:

```
uacrypt sign-keygen --out signing.key
uacrypt sign-pubkey --key signing.key --out verifying.key
uacrypt sign --key signing.key --in message.bin --out message.bin.sig
uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
```

`sign-keygen`'s output (`signing.key`, 21 raw bytes) is secret — keep it like any other private key.
`sign-pubkey` derives the matching `verifying.key` (42 raw bytes) from it, safe to share or publish.
`verify` prints nothing and exits `0` on a valid signature; on a tampered file, a tampered signature,
or the wrong verifying key, it exits `1` with an error and writes nothing — it does not, and cannot,
silently accept a mismatch:

```
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
$ echo $?
0

$ echo "tampered" > message.bin
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
uacrypt: verify: signature does not verify - message, signature, or key do not match
$ echo $?
1
```

`uacrypt sign-keygen257`/`sign-pubkey257`/`sign257` (`docs/TASKS.md` T-199, `docs/DECISIONS.md`
D-185/D-186) mirror the four commands above exactly, over DSTU 4145's `m=257` curve instead of
`m=163` - a separate set of commands, not a `--curve` flag, since the two produce distinct,
incompatible key shapes. `m=257` is what real Diia-issued qualified signatures use in production
(confirmed from an actual issued certificate) - `m=163` stays the default (`sign-keygen`) only
because it shipped first, not because it's recommended over `m=257`. `verify` is shared - it reads
a curve-tag byte from `--key` and handles both curves, so there is no separate `verify257`:

```
uacrypt sign-keygen257 --out signing257.key
uacrypt sign-pubkey257 --key signing257.key --out verifying257.key
uacrypt sign257 --key signing257.key --in message.bin --out message.bin.sig257
uacrypt verify --key verifying257.key --in message.bin --sig message.bin.sig257
```

`uacrypt box-keygen`/`box-pubkey`/`box-seal`/`box-open` (`docs/TASKS.md` T-178, `docs/DECISIONS.md`
D-169) are public-key encryption, built over `dstu_core::crypto_box` (DSTU 9041, hybrid via KDF):
unlike `encrypt` (which needs a shared symmetric key both sides already have), `box-seal` only needs
the recipient's public key — anyone can seal a message only the matching secret key can open:

```
uacrypt box-keygen --out box.key
uacrypt box-pubkey --key box.key --out box.pub
uacrypt box-seal --key box.pub --in message.bin --out message.bin.box
uacrypt box-open --key box.key --in message.bin.box --out message.bin
```

`box-keygen`'s output (`box.key`, 32 raw bytes) is secret. `box-pubkey` derives the matching
`box.pub` (32 raw bytes, the curve point's `x`-coordinate only) from it, safe to share or publish.
`box-seal`/`box-open` are **not memory-bounded** yet — `--in` is read whole into memory, unlike
`encrypt`/`decrypt`'s bounded-chunk streaming (see `crypto_box`'s own module doc for why).

`uacrypt box-keygen512`/`box-pubkey512`/`box-seal512`/`box-open512` (`docs/TASKS.md` T-193,
`docs/DECISIONS.md` D-182) mirror the four commands above exactly, over DSTU 9041's `l(p)=512`
curve (E512/1) instead of `l(p)=256` - a separate set of commands, not a `--curve` flag, since the
two produce distinct, incompatible key shapes (64-byte keys instead of 32-byte):

```
uacrypt box-keygen512 --out box512.key
uacrypt box-pubkey512 --key box512.key --out box512.pub
uacrypt box-seal512 --key box512.pub --in message.bin --out message.bin.box512
uacrypt box-open512 --key box512.key --in message.bin.box512 --out message.bin
```

What exists below this level: `kalyna-block`, `kupyna-digest`, and `strumok-crypt`, all
`hazmat`-scoped commands added for binary-level performance comparisons
(`docs/PERFORMANCE.md`, `docs/DECISIONS.md` D-31/D-34) rather than everyday use - `hash` and
`encrypt`/`decrypt` above are what most users want.

`kalyna-block` is a single block (no mode, no padding):

```
uacrypt kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out ct.bin
uacrypt kalyna-block decrypt --variant 128-128 --key key.bin --in ct.bin --out pt.bin
```

`--key`/`--in`/`--out` are raw binary files of the variant's exact byte length (16/32/64 bytes
depending on variant — see `--variant`'s five values).

`kupyna-digest` hashes with a selectable variant (`hash` above is simpler for everyday use - fixed
to Kupyna-256, no `--variant` flag):

```
uacrypt kupyna-digest --variant 512 --in report.pdf --out report.pdf.kupyna512
```

`strumok-crypt` is the bare Strumok keystream cipher (XOR-based) - **not authenticated**: a
tampered output decrypts silently into wrong plaintext, there is no tag to detect it. Never reuse
the same `--key`/`--iv` pair for two different messages - doing so lets an attacker recover both
messages by XORing the two ciphertexts together. Use `encrypt`/`decrypt` instead for a file cipher
that detects tampering:

```
uacrypt strumok-crypt --variant 256 --key key.bin --iv iv.bin --in message.bin --out sealed.bin
```

`--variant` is the key size in bits (256 or 512); `--iv` is always exactly 32 bytes regardless of
variant.

`kalyna-ccm` (`docs/DECISIONS.md` D-41/D-205) additionally encrypts/authenticates **short**
messages (plaintext and `--aad` each capped at 255 bytes, see `hazmat::kalyna_ccm`'s doc comment)
using Kalyna-CCM as DSTU 7624:2014 §13 defines it. An empty `--in` is rejected: the standard does not
define CCM for an empty message. Tags differ from UAPKI's and Bouncy Castle's on some inputs, for
example when `--aad` is omitted (see `COMPATIBILITY.md`):

```
uacrypt kalyna-ccm encrypt --variant 128-128 --key key.bin --nonce nonce.bin --aad aad.bin --in msg.bin --out ct.bin --tag tag.bin
uacrypt kalyna-ccm decrypt --variant 128-128 --key key.bin --nonce nonce.bin --aad aad.bin --in ct.bin --out pt.bin --tag tag.bin
```

`--nonce` is a raw file of exactly the variant's block length (16/32/64 bytes) — but it's an
**output** on `encrypt`, not an input: `encrypt` generates a fresh random nonce itself (via the OS
CSPRNG) and writes it there, so there is nothing for you to supply or accidentally reuse. `decrypt`
reads `--nonce` back (the value `encrypt` produced) as an input, same as `--tag`. `--aad` is
optional (an empty AAD is used if omitted); `decrypt` verifies the tag before writing `--out` and
fails without writing anything on a mismatch. The standard requires only the nonce's first
`block − N_Б − 1` bytes to be unique per key (11 bytes for a 128-bit block), so a random nonce is good
for roughly 2^44 messages per key there (`docs/DECISIONS.md` D-40/D-205).

Five more `hazmat`-scoped, per-mode benchmarking/interop commands exist alongside `kalyna-ccm`
(`docs/DECISIONS.md` D-31/D-71), all with the same `--variant` (one of the five Kalyna block/
key-size combinations) and `--iterations` (benchmark timing) flags:

- `kalyna-gcm encrypt`/`decrypt` — Kalyna-GCM (`--nonce`/`--tag` files, `--aad` optional), the same
  construction `crypto_secretbox`/`crypto_secretstream` build on internally (DSTU 7624:2014 §12,
  D-204), exposed here with no message-length cap and no hidden nonce.
- `kalyna-cmac compute`/`verify` — Kalyna-CMAC, a 16-byte tag, no encryption.
- `kalyna-gmac compute`/`verify` — Kalyna-GMAC, a full-block tag, no encryption, no nonce.
- `kalyna-kw wrap`/`unwrap` — Kalyna key wrap (1..=20 block-aligned blocks in, one block longer
  out, checksummed).
- `kalyna-xts encrypt`/`decrypt` — Kalyna-XTS disk-sector mode (confidentiality only, no tag — the
  correct design for this use case, not a gap; caller supplies the `--tweak` block).

Run any of them with no arguments (or `--help`) for the full flag reference and an example -
covered here at a summary level since their shape mirrors `kalyna-ccm`/`kalyna-block` above rather
than needing separate full walkthroughs.

None of `kalyna-block`/`kupyna-digest`/`strumok-crypt`/`kalyna-ccm`/`kalyna-gcm`/`kalyna-cmac`/
`kalyna-gmac`/`kalyna-kw`/`kalyna-xts` is the `encrypt`/`decrypt`/`hash` surface above - all nine
stay as lower-level, hazmat-scoped tools for anyone who explicitly wants that level of control, or
is benchmarking a specific primitive directly.

## File formats

What each command writes, byte by byte. Sizes are in bytes, `||` means concatenation, and
multi-byte integers are little-endian. `uacrypt --version` prints the container format version
next to the release version (currently `2`, D-202).

**Why containers.** Every everyday command writes a self-describing container, not a bare
ciphertext. The container holds what decryption needs (the header, the KEM ciphertext), a format
version where one exists, and the true ciphertext length inside every authentication tag. Since
T-234 (`docs/DECISIONS.md` D-204) the Kalyna-GCM/GMAC tag in `hazmat` binds the exact length itself,
as DSTU 7624:2014 §12 specifies; the containers bind it a second time, which D-200 added when that
was not yet so.

| Command | File | Layout |
|---|---|---|
| `keygen` | symmetric key | 32 raw bytes |
| `encrypt` | encrypted file | `header (32)`, then one or more records, each `chunk tag (1) \|\| ciphertext length (4) \|\| ciphertext \|\| auth tag (16)` |
| `box-keygen` / `box-pubkey` | secret / public key | 32 raw bytes each (the public key is the curve point's `x`-coordinate) |
| `box-seal` | sealed file | `version (1) \|\| KEM ciphertext (128) \|\| header (32) \|\| ciphertext \|\| auth tag (16)`: 177 bytes of overhead |
| `box-keygen512` / `box-pubkey512` | secret / public key | 64 raw bytes each |
| `box-seal512` | sealed file | `version (1) \|\| KEM ciphertext (256) \|\| header (32) \|\| ciphertext \|\| auth tag (16)`: 305 bytes of overhead |
| `sign-keygen` / `sign-keygen257` | signing key | the scalar `d`, big-endian: 21 / 33 raw bytes |
| `sign-pubkey` / `sign-pubkey257` | verifying key | `curve byte (1: 01 = m=163, 02 = m=257) \|\| x \|\| y`: 43 / 67 bytes |
| `sign` / `sign257` | signature | 42 / 66 raw bytes; `verify` picks the curve from the verifying key's curve byte |
| `hash` | digest | 32 raw bytes (Kupyna-256) |

The `encrypt` record rules:
- the plaintext is split into 8192-byte chunks, one record each;
- the chunk tag byte is `0` (message) for every record but the last, and `3` (final) for the last;
- an empty input still produces one final record with a zero-length ciphertext;
- `decrypt` rejects a record longer than 8192 bytes, a missing final record (a truncated file) and
  any bytes after the final record;
- every record's auth tag covers its position in the stream, its chunk tag and its exact length,
  so records cannot be reordered, dropped, cut or extended.

**Raw, uncontained outputs.** `kalyna-gcm` writes the ciphertext, nonce and tag as separate raw
files, and `kalyna-gmac` writes a bare tag. They carry no format version and no nonce binding
(`kalyna-gcm`'s tag does not cover the nonce, D-63). For files, use `encrypt` or `box-seal`.
