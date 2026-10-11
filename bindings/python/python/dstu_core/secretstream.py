"""File-like `crypto_secretstream` pipeline (docs/DECISIONS.md D-118, docs/bindings-strategy.md
T-49 step 3) - hides chunk/tag/counter bookkeeping behind write()/iterate. The framing itself
(record layout, length rules, Final, trailing data) is dstu-core's stream-file codec, exposed as
SecretStreamFileEncryptor/SecretStreamFileDecryptor (T-284); this module does only I/O.

**Wire format matches `uacrypt encrypt`/`decrypt` exactly**
(crates/uacrypt/src/lib.rs's `run_secretstream_encrypt`/`run_secretstream_decrypt`, D-68):
`version (1) || header (32 bytes)` followed by one record per chunk, `tag_byte (1) ||
chunk_len_u32_le (4) || ciphertext (chunk_len) || auth_tag (16)`. Every record but the Final one is
exactly 8 KiB (matching `SECRETSTREAM_CHUNK_BYTES`, part of the format since D-208, not an
independent choice) - a file `SecretStreamEncryptor` writes is decryptable by `uacrypt decrypt` and
vice versa. The shared vectors in `crates/dstu-core/tests/vectors/secretstream-file/` pin this.
"""

from __future__ import annotations

from typing import Protocol

from ._dstu_core import SecretStreamFileDecryptor, SecretStreamFileEncryptor

# dstu-core's `crypto_secretstream::CHUNK_BYTES` (D-208): the codec seals and checks it; this
# module only needs it to cut the caller's data into chunks.
_CHUNK_BYTES = 8 * 1024


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
        self._enc = SecretStreamFileEncryptor(key)
        self._out.write(self._enc.prefix)
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        """Buffers `data`, sealing every full 8 KiB chunk that is certain not to be the last one.
        The trailing partial (or exactly-8-KiB) chunk is held back until `close()`, since only
        `close()` knows no more data is coming - an exact multiple of 8 KiB must end in a full
        Final record, not an extra empty one (D-208). Full chunks are cut from `data` by offset,
        so one large write costs linear time (T-276)."""
        if self._closed:
            raise ValueError("write to closed SecretStreamEncryptor")
        view = memoryview(data)
        size = len(view)
        if len(self._buf) + size <= _CHUNK_BYTES:
            self._buf.extend(view)
            return size
        pos = 0
        if self._buf:
            pos = _CHUNK_BYTES - len(self._buf)
            self._buf.extend(view[:pos])
            self._out.write(self._enc.seal_chunk(bytes(self._buf)))
            self._buf.clear()
        while size - pos > _CHUNK_BYTES:
            self._out.write(self._enc.seal_chunk(bytes(view[pos : pos + _CHUNK_BYTES])))
            pos += _CHUNK_BYTES
        self._buf.extend(view[pos:])
        return size

    def close(self) -> None:
        """Flushes any buffered bytes as the stream's Final chunk. Idempotent - safe to call more
        than once, matching normal Python file-object `close()` semantics."""
        if self._closed:
            return
        self._out.write(self._enc.seal_final(bytes(self._buf)))
        self._buf.clear()
        self._closed = True

    # `Self` (ruff's PYI034 suggestion) needs Python 3.11+; requires-python is ">=3.9" and this
    # project takes no typing_extensions dependency for a pre-1.0 zero-dependency binding.
    def __enter__(self) -> SecretStreamEncryptor:  # noqa: PYI034
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


def _read_up_to(inp: _Readable, size: int) -> bytes:
    """Reads until `size` bytes arrived or `inp` ended; a short result means end of input."""
    pieces = []
    remaining = size
    while remaining > 0:
        piece = inp.read(remaining)
        if not piece:
            break
        pieces.append(piece)
        remaining -= len(piece)
    return b"".join(pieces)


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
        self._inp = inp
        self._dec = SecretStreamFileDecryptor(key)
        self._done = False
        # The version byte and header, read now so a wrong version fails at construction.
        for _ in range(2):
            self._step()

    def _step(self) -> bytes:
        """Feeds the codec one `next_len()` read: the plaintext that read released (possibly
        empty), or at end of input the Final chunk's (after which the stream is done)."""
        want = self._dec.next_len()
        data = _read_up_to(self._inp, want)
        if len(data) < want:
            self._done = True
            return self._dec.finish()
        return self._dec.feed(data)

    def __iter__(self) -> SecretStreamDecryptor:
        return self

    def __next__(self) -> bytes:
        while not self._done:
            plaintext = self._step()
            if plaintext:
                return plaintext
        raise StopIteration

    def read_all(self) -> bytes:
        return b"".join(self)

    def close(self) -> None:
        """No-op - present for file-like/context-manager symmetry with `SecretStreamEncryptor`."""

    # See SecretStreamEncryptor.__enter__'s own comment above - same 3.9-floor reasoning applies.
    def __enter__(self) -> SecretStreamDecryptor:  # noqa: PYI034
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
