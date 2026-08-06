# dstu-core (Python bindings)

**Provisional — not published to PyPI, not independently audited.** See the root project's
`docs/SECURITY.md` and `docs/DECISIONS.md` for the full threat model and per-construction status.
This binding wraps the full `dstu_core::crypto_*` surface (`docs/bindings-strategy.md` T-49) —
install from source as shown below.

## Installing (from source)

```sh
python -m venv .venv
source .venv/bin/activate        # or .venv\Scripts\activate on Windows
pip install maturin
maturin develop --release
python -c "import dstu_core; dstu_core.selftest()"
```

`pyo3` needs a real Python interpreter to link against at build time. Plain `python`/`python3` may
not be enough to find one — on Windows in particular, those names can resolve to non-functional
Microsoft Store alias stubs instead of a real install. If `cargo build`/`maturin develop` fails to
find (or finds the wrong) Python, point it at one explicitly:

```sh
export PYO3_PYTHON=/path/to/a/real/python3   # POSIX
$env:PYO3_PYTHON = "C:\path\to\python.exe"   # PowerShell
```

`maturin develop` builds the Rust extension and installs it into the active virtualenv as an
editable package. `dstu_core.selftest()` re-runs `dstu_core::selftest::run()` (`docs/TASKS.md`
T-161) against the exact compiled build and raises `RuntimeError` if anything official-vector-level
is wrong — the first thing to run after any build to confirm it actually works, not just compiled.

This crate is its own Cargo workspace, separate from the repo root (`docs/DECISIONS.md` D-119) —
build/test it from inside this directory, not from the repo root.

## Usage

Every function/class below lives directly on the `dstu_core` module (no submodules). See
`examples/` for complete, runnable scripts, and `tests/` for the full correctness/rejection/misuse
suite each one is verified against (D-64/D-65).

```python
import dstu_core as d

key = d.secretbox_keygen()
sealed = d.secretbox_seal(key, b"a message worth protecting")
assert d.secretbox_open(key, sealed) == b"a message worth protecting"
```

| Module | Functions/classes | Notes |
|---|---|---|
| `crypto_secretbox` | `secretbox_keygen`, `secretbox_seal`, `secretbox_open` | Single-message authenticated encryption. `examples/secretbox.py`. |
| `crypto_box` | `box_keygen`, `box_public_key`, `box_seal`, `box_open` | Public-key encryption (hybrid via KDF over `hazmat::dstu9041`, D-169). `box_seal`/`box_open` are not memory-bounded — the whole message is held in memory. `examples/box.py`. |
| `crypto_secretstream` | `secretstream_keygen`, `SecretStreamPushState`, `SecretStreamPullState`, `SecretStreamEncryptor`, `SecretStreamDecryptor` | Chunked streaming AEAD. The file-like `SecretStreamEncryptor`/`SecretStreamDecryptor` wire format matches `uacrypt encrypt`/`decrypt` exactly (D-118). `examples/secretstream_file.py`. |
| `crypto_sign` | `sign_keygen`, `sign_verifying_key`, `sign_message`, `sign_verify` | DSTU 4145 digital signatures, deterministic nonce (no RNG dependency). `examples/sign.py`. |
| `crypto_pwhash` | `pwhash_hash_password`, `pwhash_verify_password`, `PWHASH_INTERACTIVE`/`PWHASH_MODERATE`/`PWHASH_SENSITIVE` | Argon2id (the one deliberately non-DSTU component, D-49/D-50). `examples/password_hashing.py`. |
| `crypto_auth` | `auth_keygen`, `auth`, `auth_verify` | Keyed message authentication (Kupyna-KMAC). `examples/misc.py`. |
| `crypto_kdf` | `kdf_keygen`, `kdf_derive_subkey` | Deterministic subkey derivation. `examples/misc.py`. |
| `crypto_generichash` | `kupyna256`, `kupyna512`, `Kupyna256Hasher`, `Kupyna512Hasher` | One-shot and streaming Kupyna hashing. `examples/misc.py`. |
| `crypto_stream` | `stream_keygen`, `stream_encrypt`, `stream_decrypt` | Strumok-256 keystream — **unauthenticated**, `stream_decrypt` never fails on tampered input. `examples/misc.py`. |
| `randombytes` | `randombytes_buf` | CSPRNG-backed random bytes. `examples/misc.py`. |
| — | `selftest`, `DstuError` | Runtime KAT self-check (T-161); the one exception type every crypto-operation failure raises. |

## Testing

```sh
pip install pytest ruff
pytest
ruff check .
ruff format --check .
```

`cargo build -p uacrypt --release` (from the repo root) first if you want
`tests/test_secretstream.py`'s live `uacrypt` CLI interop test to actually run instead of skipping.
`cargo xtask python` (from the repo root) runs this whole sequence, including that build step, in
one command.
