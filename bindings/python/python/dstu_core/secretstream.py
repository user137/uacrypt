"""File-like `crypto_secretstream` pipeline (docs/DECISIONS.md D-118, docs/bindings-strategy.md
T-49 step 3) - hides chunk/tag/counter bookkeeping behind write()/iterate, built in pure Python on
top of the low-level SecretStreamPushState/SecretStreamPullState the compiled extension already
exposes (step 2), rather than new Rust glue.

**Wire format matches `uacrypt encrypt`/`decrypt` exactly**
(crates/uacrypt/src/lib.rs's `run_secretstream_encrypt`/`run_secretstream_decrypt`, D-68):
`header (32 bytes)` followed by one record per chunk, `tag_byte (1) || chunk_len_u32_le (4) ||
ciphertext (chunk_len) || auth_tag (16)`, chunks capped at 8 KiB (matching
`SECRETSTREAM_CHUNK_BYTES`, not an independent choice) - a file `SecretStreamEncryptor` writes is
decryptable by `uacrypt decrypt` and vice versa.
"""

from __future__ import annotations

from typing import Protocol

from ._dstu_core import (
    SECRETSTREAM_TAG_FINAL,
    SECRETSTREAM_TAG_MESSAGE,
    DstuError,
    SecretStreamPullState,
    SecretStreamPushState,
)

# Matches crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES exactly - required for wire-format
# interop with `uacrypt encrypt`/`decrypt`, not an independent choice.
_CHUNK_BYTES = 8 * 1024

_AUTH_TAG_BYTES = 16


class _Writable(Protocol):
    def write(self, data: bytes) -> object: ...


class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


class SecretStreamEncryptor:
    """Write-only, file-like wrapper: buffers input and pushes each full 8 KiB chunk to `out` as
    it fills, hiding the header/tag/framing bookkeeping entirely.

    Usage::

        with open("out.bin", "wb") as f, SecretStreamEncryptor(key, f) as enc:
            enc.write(b"a whole file, incrementally")
    """

    def __init__(self, key: bytes, out: _Writable) -> None:
        self._out = out
        self._push = SecretStreamPushState(key)
        self._out.write(self._push.header)
        self._buf = bytearray()
        self._closed = False

    def _push_chunk(self, tag: int, data: bytes) -> None:
        ciphertext, auth_tag = self._push.push(tag, data)
        self._out.write(bytes([tag]))
        self._out.write(len(data).to_bytes(4, "little"))
        self._out.write(ciphertext)
        self._out.write(auth_tag)

    def write(self, data: bytes) -> int:
        """Buffers `data`, pushing any now-complete 8 KiB chunks immediately. The trailing partial
        (or exactly-8-KiB) chunk is always held back until `close()`, since only `close()` knows
        no more data is coming - the same one-chunk-ahead reasoning `uacrypt encrypt` itself uses
        to tag the true last chunk `Final`, not an extra empty one after it."""
        if self._closed:
            raise ValueError("write to closed SecretStreamEncryptor")
        self._buf.extend(data)
        while len(self._buf) > _CHUNK_BYTES:
            chunk = bytes(self._buf[:_CHUNK_BYTES])
            del self._buf[:_CHUNK_BYTES]
            self._push_chunk(SECRETSTREAM_TAG_MESSAGE, chunk)
        return len(data)

    def close(self) -> None:
        """Flushes any buffered bytes as the stream's Final chunk. Idempotent - safe to call more
        than once, matching normal Python file-object `close()` semantics."""
        if self._closed:
            return
        self._push_chunk(SECRETSTREAM_TAG_FINAL, bytes(self._buf))
        self._buf.clear()
        self._closed = True

    def __enter__(self) -> SecretStreamEncryptor:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Finalizes (pushes the `Final` chunk) only on the success path. If the `with` block
        raised, the stream is deliberately left unfinalized - a `SecretStreamDecryptor` reading
        the partial output never sees a `Final` chunk and fails closed with `DstuError`, matching
        this project's standing "no partial output treated as valid on failure" rule (D-65) the
        same way `uacrypt encrypt`'s own temp-file-then-rename does. Call `close()` explicitly
        inside an `except` block if a truncated-but-decryptable prefix is genuinely wanted."""
        if exc_type is None:
            self.close()


def _read_exact(inp: _Readable, size: int, what: str) -> bytes:
    pieces = []
    remaining = size
    while remaining > 0:
        piece = inp.read(remaining)
        if not piece:
            break
        pieces.append(piece)
        remaining -= len(piece)
    data = b"".join(pieces)
    if len(data) != size:
        raise DstuError(
            f"truncated secretstream: expected {size} bytes for {what}, got {len(data)}"
        )
    return data


class SecretStreamDecryptor:
    """Read-only, chunk-iterating file-like wrapper: reads and decrypts one chunk from `inp` at a
    time. Iterate for plaintext chunks, or use `read_all()` for the whole message at once (bounded
    only by available memory, the same caveat `crypto_secretbox` already carries). Raises
    `DstuError` on authentication failure or truncation - a dropped/tampered/reordered chunk, or a
    stream that ends before a Final chunk, both fail closed rather than yielding wrong plaintext.

    Usage::

        with open("out.bin", "rb") as f, SecretStreamDecryptor(key, f) as dec:
            plaintext = dec.read_all()
    """

    def __init__(self, key: bytes, inp: _Readable) -> None:
        header = _read_exact(inp, 32, "header")
        self._inp = inp
        self._pull = SecretStreamPullState(key, header)
        self._done = False

    def __iter__(self) -> SecretStreamDecryptor:
        return self

    def __next__(self) -> bytes:
        if self._done:
            raise StopIteration
        tag_byte = _read_exact(self._inp, 1, "chunk tag")[0]
        chunk_len = int.from_bytes(_read_exact(self._inp, 4, "chunk length"), "little")
        ciphertext = _read_exact(self._inp, chunk_len, "chunk ciphertext")
        auth_tag = _read_exact(self._inp, _AUTH_TAG_BYTES, "chunk auth tag")
        tag, plaintext = self._pull.pull(tag_byte, ciphertext, auth_tag)
        if tag == SECRETSTREAM_TAG_FINAL:
            self._done = True
        return plaintext

    def read_all(self) -> bytes:
        return b"".join(self)

    def close(self) -> None:
        """No-op - present for file-like/context-manager symmetry with `SecretStreamEncryptor`."""

    def __enter__(self) -> SecretStreamDecryptor:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
