# Using `uacrypt`

**Command line rules (0.5.0, T-255).** Every input is a named flag: `--key k` or `--key=k`. A flag
given twice, a flag with no value (`--key --in x` does not make `--in` the key path), a value on a
flag that takes none, an unknown flag and a bare positional argument are all usage errors, with a
"did you mean" suggestion for a near-miss command, subcommand or flag. A path that really starts
with `--` can be passed as `--in=--odd-name`. `uacrypt help` prints the overview and `uacrypt help
<command>` the same text as `uacrypt <command> --help`.

**Exit status.**

| Code | Meaning | Examples |
|---|---|---|
| 0 | success | also `--help`, `help`, `--version` |
| 1 | the input was checked and rejected | authentication failed, bad signature, truncated or malformed ciphertext, an empty or over-long message for a mode that forbids it, a wrong-length signature or tag, a `hash --check` file that is malformed or lists a file that does not match or cannot be read |
| 2 | usage error | unknown command or flag, missing/repeated flag, missing value, missing subcommand |
| 3 | a file or key could not be used | missing or unreadable file, a key file of the wrong kind, damaged or not typed (see [Key files](#key-files)), wrong-size or invalid key/nonce/IV/tweak, an `--out` that already exists (see below) |

A script can therefore tell "this file was forged" (1) from "I typed the command wrong" (2).

**Existing output files (0.5.0, T-258, `docs/DECISIONS.md` D-214).** No command replaces an
existing file unless you pass `--force`; without it an existing `--out` (or `--nonce`/`--tag` on
`kalyna-ccm`/`kalyna-gcm encrypt`) is refused with exit 3 before any work is done, and the message
says when it is the `--in` file itself. `--in` and `--out` may name the same file (encrypt or
decrypt in place) only with `--force`. An output naming another output or one of the command's
key inputs (`--key`, `--iv`, `--tweak`, or a decrypt-side `--nonce`/`--tag`) is a usage error
(exit 2), with or without `--force`, so `decrypt --key k.key --out k.key --force` cannot replace
the key with plaintext. The result is written to a temp file next to the
output and renamed onto it only when the command succeeds, so a failed command leaves no output file,
no temp file and, with `--force`, the old file unchanged. `--force` replaces a symlink at the
output path, never the file it points to. On Unix every output file is created with mode `0600`
(owner only), also when `--force` replaces a `0644` file; `chmod` it to share it. Key files
(`*-keygen`, `sign-pubkey`, `box-pubkey`, `key-import`) are never replaced at all and do not
accept `--force`: `box-pubkey --key box.key --out box.key` would otherwise destroy the secret key.
No other command replaces an existing key file either, with or without `--force` (T-268,
`docs/DECISIONS.md` D-216): an `--out` that starts like a typed key line (`UACRYPT-SECRET-...:`
or `uacrypt-...-public:`) is refused with exit 3, and so is an existing output that cannot be read
to check. Delete the file yourself if you really mean to replace it. Raw keys of the lower-level
commands are not recognised.
A killed process (power loss, `kill -9`) can leave an empty output file, which the next run
refuses until you delete it or pass `--force`.

**stdin and stdout (0.5.0, T-260, `docs/DECISIONS.md` D-217).** `--in -` reads stdin in
`encrypt`, `decrypt`, `hash`, `sign`, `verify`, `box-seal` and `box-open`; `--out -` writes stdout
in `encrypt`, `decrypt`, `sign`, `box-seal` and `box-open`, and prints the public key line of
`sign-pubkey`, `box-pubkey` and `key-import` (public kinds only):

```
tar c docs | uacrypt encrypt --key key.bin --in - --out docs.tar.enc
uacrypt decrypt --key key.bin --in docs.tar.enc --out - | tar x
uacrypt sign-pubkey --key signing.key --out -
cat report.pdf | uacrypt hash --in -          # prints "<hex>  -"
```

- Binary output (everything above except the public keys) is refused with exit 2 when stdout is a
  terminal - it would garble the screen. To read a decrypted text on screen, pipe it: `--out - |
  more`. Checked in cmd, PowerShell 7, Git Bash (mintty) and a Linux terminal.
- Secret keys are never written to stdout: `--out -` on every `*-keygen` command and on a secret
  `key-import` is a usage error. `--key` never reads stdin.
- `hash --check -` reads the checksum list from stdin (like `sha256sum -c -`, same 16 MiB cap and
  grammar). A line for `-` inside any list is never read from stdin - an untrusted list must not
  consume or wait on your script's stdin - so it is reported as `-: FAILED (stdin is not read from
  a check list ...)` and counts as a failure; a file really named `-` is listed as `./-`.
- Every other path flag (`--key`, `--sig`, `key-import --in`, and all paths of
  the lower-level `kalyna-*`/`kupyna-digest`/`strumok-crypt` commands) refuses `-` as a usage
  error, so `-` never silently names a file. A file really named `-` is `./-`.
- `--force` with `--out -` is a usage error: there is no file to replace.
- **`decrypt --out -` can print part of a message.** Each chunk is written once its tag verifies,
  so nothing unauthenticated is ever printed, but a stream cut short or tampered with halfway
  prints its verified beginning before the error. The error then ends with "the output already
  written to stdout is INCOMPLETE - discard it", and the exit status is non-zero (1 for a bad
  file, 3 if stdout itself failed). Check it: in a shell pipeline such as `... --out - | tar x`
  the pipeline's status is `tar`'s unless you `set -o pipefail`. With `--out <file>` nothing is
  written unless the whole file verifies. `box-open` decrypts the whole message before printing
  anything, so it never prints part of one.
- Windows (measured 2026-09-24): cmd and PowerShell 7.6 passed a 100 kB `encrypt --out -` through
  `>` and through `| uacrypt decrypt --in -` byte for byte. Windows PowerShell 5.1 re-encodes a
  native command's output as text, which corrupts binary data: its `>` turned a 310-byte output
  into 594 bytes starting `FF FE` (UTF-16), and its `|` fed `decrypt` data starting `EF` (a UTF-8
  byte-order mark). `decrypt` names this cause when it sees such a start. From 5.1, use
  `--out <file>` or `cmd /c "..."`.
- A closed pipe is an error, not a silent stop: `decrypt ... --out - | head -c 100` makes
  `decrypt` exit 3 with the INCOMPLETE message once `head` exits, which fails a `set -o pipefail`
  pipeline.
- `box-seal`/`box-open` read all of stdin into memory, as they do a file (not bounded yet, T-265);
  `encrypt`/`decrypt`/`hash`/`sign`/`verify` read stdin in the same fixed-size chunks as a file.

**Progress (0.5.0, T-261, `docs/DECISIONS.md` D-218).** When stderr is a terminal and `--in` is
a file of 64 MiB or more, `encrypt`, `decrypt`, `hash`, `sign` and `verify` show one line on
stderr, such as `uacrypt: 1.2 GiB / 4.0 GiB (30%)`. It is redrawn at most 10 times a second and
erased before the command prints its result or its error. For stdin, where the size is unknown, it
is a byte counter (`uacrypt: 96.0 MiB read`) that appears once 64 MiB have been read. There is no
flag: with stderr redirected or piped (`2>file`, `2>&1 | ...`, a script, CI) nothing is printed at
all. `box-seal`/`box-open` show none until they stop reading `--in` whole (T-265), and the
lower-level `kalyna-*`/`kupyna-digest`/`strumok-crypt` commands never do. Known cosmetic limit:
in `decrypt --out - | more` on a large file, the line is drawn over the pager's screen, because
both share the terminal (do not silence it with `2>/dev/null` - that hides the INCOMPLETE warning
too). Ctrl-C leaves the last line on screen without a newline.

`uacrypt encrypt`/`decrypt`/`hash` (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52) are the real,
misuse-resistant top-level commands — mode, nonce, and algorithm are all hardcoded, nothing to
misconfigure:

```
cargo build -p uacrypt --release
uacrypt keygen --out key.bin
uacrypt encrypt --key key.bin --in message.bin --out sealed.bin
uacrypt decrypt --key key.bin --in sealed.bin --out decrypted.bin
uacrypt hash --in file.bin > file.bin.kupyna256
uacrypt hash --check file.bin.kupyna256
```

**`encrypt`/`decrypt` have no message-length cap and stream `--in`/`--out` in fixed-size chunks** —
as of 2026-07-25 they're built over `dstu_core::crypto_secretstream` (`docs/TASKS.md` T-40/T-70,
`docs/DECISIONS.md` D-68), a genuinely chunked construction over `hazmat::kalyna_gcm`, not the earlier
whole-buffer `crypto_secretbox` (`docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51/D-63) - a large input file no
longer means a correspondingly large in-memory buffer. **Breaking wire-format change**: a file the
prior `crypto_secretbox`-backed `encrypt` produced cannot be read by this `decrypt`, and vice versa
- acceptable pre-1.0. `crypto_secretbox` itself is unchanged and still available as a library
primitive for whole-message use, just no longer what this CLI command uses. `--key` is a typed
key file ([Key files](#key-files)) holding a 32-byte `crypto_secretstream::Key` — `uacrypt keygen
--out key.bin` generates one from the OS CSPRNG (`docs/TASKS.md` T-115). Like every `*-keygen` command, it refuses to overwrite an
existing `--out` (with no `--force` to override it), so a repeated run cannot destroy a key, and on Unix it writes the key with mode
`0600` (T-241). `encrypt` draws a fresh random header internally on every call
and embeds it in `--out`; there is no `--nonce`/`--header` flag to supply or reuse by mistake.
**0.4.0 changed the `encrypt`/`box-seal` file formats (both curves)** (T-232/T-248,
`docs/DECISIONS.md` D-200-D-202). Files written by 0.3.x don't open with 0.4.0. `box-open` almost
always reports them as a different format version; ~1 in 256 happen to start with the current
version byte and report an authentication failure instead. Decrypt them with the release that
wrote them, then re-encrypt.

**A passphrase instead of a key file** (0.5.0, T-262, `docs/DECISIONS.md` D-219), like `age -p`:

```
uacrypt encrypt --passphrase --in report.pdf --out report.pdf.enc   # asks twice, no echo
uacrypt decrypt --in report.pdf.enc --out report.pdf                # asks once
uacrypt encrypt --passphrase-file pass.txt --in report.pdf --out report.pdf.enc   # scripts
```

`decrypt` tells a passphrase file from a key-encrypted one by its first byte and says which one
it needs when given the other. The passphrase goes through Argon2id (`dstu_core::crypto_pwhash::
derive_key`, libsodium's `crypto_pwhash` with its `MODERATE` limits: 256 MiB of memory, t=3), so
each `encrypt` or `decrypt` with a passphrase takes about a second and 256 MiB on purpose; the
streaming itself stays bounded as above. The prompt appears only when stderr is a terminal; with
stderr redirected, pass `--passphrase-file`. In Git Bash's mintty window the prompt is refused
(it would go to a hidden console): use `winpty uacrypt ...`, cmd, PowerShell or Windows Terminal,
or `--passphrase-file`. A passphrase file holds one line; a trailing newline (`\n` or `\r\n`) and a
leading UTF-8 BOM are dropped, nothing else, and a file longer than 1024 bytes, with a second
line, or not UTF-8 is refused. The passphrase is used as UTF-8 bytes with no Unicode
normalisation: a letter such as `й` typed as one precomposed character and as `и` plus a combining
mark are different passphrases. An empty passphrase is refused.

**`hash` has no such limit either** — it streams `--in` from disk in fixed-size chunks regardless of
size, fixed to Kupyna-256 (no `--variant` choice). Since 0.5.0 it works like `sha256sum` (T-259,
`docs/DECISIONS.md` D-215): `hash --in <path>` prints one line, `<64 hex digits>  <path>`, to
stdout (the path exactly as given), and writes no file. `hash --check <file>` reads such lines,
hashes every listed file and prints `<path>: OK` or `<path>: FAILED`; it exits 1 if any file does
not match or cannot be read. The check file is validated whole before anything is hashed: every
line must be exactly `<64 hex digits><two spaces><path>` (CRLF line ends and upper-case hex are
accepted, a blank line or GNU's `*` binary marker is not), at most 16 MiB, or `--check` exits 1
naming the line and checks nothing. Relative paths are resolved against the current directory, not
the check file's. `hash --in` refuses a path that is not UTF-8 or contains a control character
(exit 2): it could not be read back as one line, and a terminal escape in a path would be echoed
back by `--check`. The digests are Kupyna-256, so a `sha256sum` file reports every line as
FAILED. On Windows, PowerShell 7 and cmd write `>` as plain UTF-8; Windows PowerShell 5.1 writes it
as UTF-16 (which `--check` names as such and refuses) and garbles non-ASCII paths even with
`Out-File -Encoding utf8`, so from 5.1 use `cmd /c "uacrypt hash --in <file> > <list>"`. One
leading UTF-8 BOM is accepted. For a raw binary digest file (the 0.4 `hash --out` output), use
`kupyna-digest --variant 256 --out`.

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

`sign-keygen`'s output (`signing.key`) is secret — keep it like any other private key.
`sign-pubkey` derives the matching `verifying.key` from it, safe to share or publish. Both are typed
key files ([Key files](#key-files)); `verify` reads the curve from the verifying key's own line.
`verify` prints `Signature OK (DSTU 4145, m=163)` (or `m=257`) to stderr, nothing to stdout, and
exits `0` on a valid signature; on a tampered file, a tampered signature,
or the wrong verifying key, it exits `1` with an error and writes nothing — it does not, and cannot,
silently accept a mismatch:

```
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
Signature OK (DSTU 4145, m=163)
$ echo $?
0

$ echo "tampered" > message.bin
$ uacrypt verify --key verifying.key --in message.bin --sig message.bin.sig
uacrypt: verify: signature does not verify - message, signature, or key do not match
$ echo $?
1
```

For DSTU 4145's `m=257` curve (`docs/TASKS.md` T-199, `docs/DECISIONS.md` D-185), generate the
key with `sign-keygen257` instead; the other three commands are the same. The curve is chosen once,
at key generation, and recorded in the key: `sign-pubkey`, `sign` and `verify` read it from there
(T-257, D-213), and `sign` writes a 66-byte signature instead of 42. `m=257` is what real
Diia-issued qualified signatures use in production (confirmed from an actual issued certificate) -
`m=163` is the plain `sign-keygen` only because it shipped first, not because it's recommended
over `m=257`:

```
uacrypt sign-keygen257 --out signing257.key
uacrypt sign-pubkey --key signing257.key --out verifying257.key
uacrypt sign --key signing257.key --in message.bin --out message.bin.sig257
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
uacrypt box-open --key box.key --in message.bin.box --out opened.bin
```

`box-keygen`'s output (`box.key`) is secret. `box-pubkey` derives the matching `box.pub` (the
curve point's `x`-coordinate only) from it, safe to share or publish. Both are typed key files
([Key files](#key-files)), so `box-seal` refuses a secret key by name instead of sealing to it.
`box-seal`/`box-open` are **not memory-bounded** yet — `--in` is read whole into memory, unlike
`encrypt`/`decrypt`'s bounded-chunk streaming (see `crypto_box`'s own module doc for why).

For DSTU 9041's `l(p)=512` curve (E512/1, `docs/TASKS.md` T-193, `docs/DECISIONS.md` D-182),
generate the key with `box-keygen512` instead; `box-pubkey`, `box-seal` and `box-open` read the
curve from the key (T-257, D-213). Keys are 64 bytes instead of 32, and a sealed file has 305
bytes of overhead instead of 177. A file sealed to one curve's key is refused by the other
curve's key like any other wrong key:

```
uacrypt box-keygen512 --out box512.key
uacrypt box-pubkey --key box512.key --out box512.pub
uacrypt box-seal --key box512.pub --in message.bin --out message.bin.box512
uacrypt box-open --key box512.key --in message.bin.box512 --out opened512.bin
```

Up to 0.4, the non-keygen commands had curve twins (`sign-pubkey257`, `sign257`, `box-pubkey512`,
`box-seal512`, `box-open512`). They are gone in 0.5.0; each name now fails as a usage error
(exit 2) that names the command to use instead.

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
example when `--aad` is omitted (see [COMPATIBILITY.md](COMPATIBILITY.md)):

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
  D-204), exposed here with no message-length cap and no hidden nonce. An empty `--in` with no
  `--aad` is rejected (D-207).
- `kalyna-cmac compute`/`verify` — Kalyna-CMAC, a 16-byte tag, no encryption. An empty `--in` is
  rejected (DSTU 7624:2014 §9 does not define CMAC for an empty message, D-206).
- `kalyna-gmac compute`/`verify` — Kalyna-GMAC, a full-block tag, no encryption, no nonce. An empty
  `--in` is rejected (D-207).
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

## Verifying a downloaded release

From 0.4.0 on, every GitHub Release carries `SHA256SUMS`, its Sigstore signature bundle
`SHA256SUMS.sigstore.json`, and a CycloneDX SBOM (`uacrypt.cdx.json`); every asset also has a
GitHub build-provenance attestation (T-252). Download the asset plus the two `SHA256SUMS` files into
one directory, then:

```sh
# 1. The checksum file was signed by this repository's release workflow, from a release tag
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/user137/uacrypt/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 2. The asset matches the signed checksum (--ignore-missing: only the files you downloaded)
sha256sum --ignore-missing -c SHA256SUMS
#    macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
#    Windows PowerShell: compare (Get-FileHash <file> -Algorithm SHA256).Hash with its line in SHA256SUMS

# 3. Optional, independent of 1-2: GitHub's provenance record for the asset
gh attestation verify uacrypt-linux-x86_64.tar.gz --repo user137/uacrypt \
  --signer-workflow user137/uacrypt/.github/workflows/release.yml --source-ref refs/tags/v0.4.0
```

In step 3, `--source-ref` accepts only an asset built from that release tag, not from a branch; put
your version there.

The binaries are built with `cargo auditable`, so `cargo audit bin uacrypt` checks the dependency
versions compiled into a downloaded binary against the RustSec advisory database.

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
| `keygen` | symmetric key | a key line, see [Key files](#key-files) |
| `encrypt` | encrypted file | `version (1) \|\| header (32)`, then one or more records, each `chunk tag (1) \|\| ciphertext length (4) \|\| ciphertext \|\| auth tag (16)` |
| `encrypt --passphrase` / `--passphrase-file` | encrypted file | `0x50 \|\| 0x01 \|\| 0x01 \|\| m_cost KiB (4) \|\| t_cost (4) \|\| p_cost (1) \|\| salt (16)`, then the `encrypt` layout above |
| `box-keygen` / `box-keygen512` / `box-pubkey` | secret / public key | a key line each (the public key is the curve point's `x`-coordinate) |
| `box-seal` | sealed file | `version (1) \|\| KEM ciphertext (128, or 256 for an l(p)=512 key) \|\| header (32) \|\| ciphertext \|\| auth tag (16)`: 177 or 305 bytes of overhead |
| `sign-keygen` / `sign-keygen257` | signing key | a key line (the scalar `d`, big-endian) |
| `sign-pubkey` | verifying key | a key line (`x \|\| y`) of the signing key's curve |
| `sign` | signature | 42 raw bytes for an m=163 key, 66 for m=257; `verify` picks the curve from the verifying key's kind |
| `hash` | digest line (stdout) | `<64 lower-case hex digits>  <path>` and a newline (Kupyna-256); `kupyna-digest --out` writes the raw 32 or 64 bytes |

The `encrypt` record rules:
- the version byte is currently `2` and is bound into the stream's key derivation, so a changed
  version byte never decrypts; `decrypt` names an unsupported version instead of reporting an
  authentication failure. Files from `uacrypt` 0.3.x and earlier have no version byte and cannot
  be read;
- the plaintext is split into 8192-byte chunks, one record each; every record but the last is
  exactly 8192 bytes, so the chunk size is part of the format;
- the chunk tag byte is `0` (message) for every record but the last, and `3` (final) for the last;
- an empty input still produces one final record with a zero-length ciphertext;
- `decrypt` rejects a record longer than 8192 bytes, a non-final record of any other length than
  8192, a missing final record (a truncated file) and any bytes after the final record;
- every record's auth tag covers its position in the stream, its chunk tag and its exact length,
  so records cannot be reordered, dropped, cut or extended.

The passphrase header (D-219):
- `0x50` marks a passphrase file (a key-encrypted file starts with its version byte, `2`), then
  the passphrase container version `1` and the KDF id `1` (Argon2id v1.3);
- the Argon2id costs are `m_cost = 262144` KiB, `t_cost = 3`, `p_cost = 1`; `decrypt` refuses any
  other values before running Argon2, so a changed header cannot make it allocate more memory;
- the stream key is Argon2id(passphrase, salt) with no secret and no associated data, 32 bytes -
  the same bytes libsodium's `crypto_pwhash` gives, so any Argon2id library can recompute it;
- the header itself carries no tag: a changed salt gives a different key and the first record
  fails (reported as a wrong passphrase, or a changed file); a changed marker, version, KDF id or
  cost is refused by name.

### Key files

Since 0.5.0 (`docs/TASKS.md` T-256, `docs/DECISIONS.md` D-212) every key a `uacrypt` command writes
or reads (`keygen`, `sign-*`, `box-*`, `encrypt`/`decrypt`, `verify`) is one ASCII text line:

```
<prefix>:<key as lower-case hex>:<check as lower-case hex>
```

followed by one `\n` (a `\r\n` from a Windows editor is accepted too). Nothing else is allowed: no
spaces, no second line, no byte-order mark, no upper-case hex. The prefix names the kind:

| Kind (`key-import --kind`) | Prefix | Key bytes | Made by |
|---|---|---|---|
| `symmetric` | `UACRYPT-SECRET-SYMMETRIC` | 32 | `keygen` |
| `sign163-secret` / `sign163-public` | `UACRYPT-SECRET-SIGN163` / `uacrypt-sign163-public` | 21 / 42 | `sign-keygen` / `sign-pubkey` |
| `sign257-secret` / `sign257-public` | `UACRYPT-SECRET-SIGN257` / `uacrypt-sign257-public` | 33 / 66 | `sign-keygen257` / `sign-pubkey` |
| `box256-secret` / `box256-public` | `UACRYPT-SECRET-BOX256` / `uacrypt-box256-public` | 32 / 32 | `box-keygen` / `box-pubkey` |
| `box512-secret` / `box512-public` | `UACRYPT-SECRET-BOX512` / `uacrypt-box512-public` | 64 / 64 | `box-keygen512` / `box-pubkey` |

Secret keys have an upper-case prefix so they are hard to mistake for something to share; public
keys are short enough to paste into an email or chat. The check is the first 4 bytes of
Kupyna-256 over `"uacrypt-key-v1" || 0x00 || prefix || 0x00 || key bytes`, so a mistyped or
edited key is reported as damaged instead of becoming a key nobody holds. For example, the 32-byte
key `00 01 .. 1f` as a box public key is:

```
uacrypt-box256-public:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:4614d28c
```

A command given a key of another kind stops before doing any work and names both kinds and the
command that makes the right one (exit 3). A key file is at most a few hundred bytes; a larger
file is refused without being read whole. The lower-level commands (`kalyna-*`, `strumok-crypt`,
`kupyna-digest`) keep taking raw key bytes, for interop with other DSTU implementations.

**Keys from uacrypt 0.4 or older** are raw bytes and are refused with a pointer to `key-import`,
which converts one file:

```
uacrypt key-import --kind box256-secret --in old-box.key --out box.key
```

`--kind` is the only place a key's kind is ever typed by hand, so the raw bytes are checked exactly
as the commands that use them check them (a verifying key must still start with the curve byte
0.4 wrote: `01` for m=163, `02` for m=257). `key-import` prints the new file's check value and, for
a secret key, the check value of its public key - compare it with the last field of the public key
file you already shared. Like every keygen, it never overwrites an existing file.

**Raw, uncontained outputs.** `kalyna-gcm` writes the ciphertext, nonce and tag as separate raw
files, and `kalyna-gmac` writes a bare tag. They carry no format version and no nonce binding
(`kalyna-gcm`'s tag does not cover the nonce, D-63). For files, use `encrypt` or `box-seal`.
