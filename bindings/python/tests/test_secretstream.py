"""`crypto_secretstream` - both the low-level `SecretStreamPushState`/`PullState` (step 2) and the
file-like `SecretStreamEncryptor`/`SecretStreamDecryptor` pipeline (step 3, D-118). Three
categories per D-64/D-65: correctness (round trip across chunk-boundary sizes, plus real
byte-for-byte interop with `uacrypt encrypt`/`decrypt`'s own wire format), rejection (tamper,
oversized chunk, trailing data), misuse (wrong-length key, write-after-close).
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path

import dstu_core as d
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UACRYPT_CANDIDATES = [
    _REPO_ROOT / "target" / "debug" / "uacrypt.exe",
    _REPO_ROOT / "target" / "release" / "uacrypt.exe",
    _REPO_ROOT / "target" / "debug" / "uacrypt",
    _REPO_ROOT / "target" / "release" / "uacrypt",
]


def _find_uacrypt() -> Path | None:
    for candidate in _UACRYPT_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


@pytest.mark.parametrize(
    "size",
    [0, 1, 100, 8 * 1024, 8 * 1024 + 1, 8 * 1024 * 3, 8 * 1024 * 3 + 777],
)
def test_round_trip_across_chunk_boundaries(size: int) -> None:
    key = d.secretstream_keygen()
    plaintext = os.urandom(size)

    out = io.BytesIO()
    with d.SecretStreamEncryptor(key, out) as enc:
        step = 777
        for i in range(0, len(plaintext), step):
            enc.write(plaintext[i : i + step])

    encrypted = out.getvalue()
    with d.SecretStreamDecryptor(key, io.BytesIO(encrypted)) as dec:
        assert dec.read_all() == plaintext


@pytest.mark.skipif(
    _find_uacrypt() is None, reason="uacrypt binary not built (cargo build -p uacrypt)"
)
def test_interop_with_uacrypt_cli(tmp_path: Path) -> None:
    """A file this binding encrypts is decryptable by `uacrypt decrypt`, and vice versa - the
    concrete claim `docs/bindings-strategy.md`'s T-49 step 3 entry makes about the wire format."""
    uacrypt = _find_uacrypt()
    assert uacrypt is not None

    key = d.secretstream_keygen()
    key_path = tmp_path / "key.bin"
    key_path.write_bytes(key)
    plaintext = os.urandom(8 * 1024 * 2 + 555)
    plain_path = tmp_path / "plain.bin"
    plain_path.write_bytes(plaintext)

    py_encrypted_path = tmp_path / "py_encrypted.bin"
    with py_encrypted_path.open("wb") as f, d.SecretStreamEncryptor(key, f) as enc:
        enc.write(plaintext)

    uacrypt_decrypted_path = tmp_path / "uacrypt_decrypted.bin"
    subprocess.run(
        [
            str(uacrypt),
            "decrypt",
            "--key",
            str(key_path),
            "--in",
            str(py_encrypted_path),
            "--out",
            str(uacrypt_decrypted_path),
        ],
        check=True,
    )
    assert uacrypt_decrypted_path.read_bytes() == plaintext

    uacrypt_encrypted_path = tmp_path / "uacrypt_encrypted.bin"
    subprocess.run(
        [
            str(uacrypt),
            "encrypt",
            "--key",
            str(key_path),
            "--in",
            str(plain_path),
            "--out",
            str(uacrypt_encrypted_path),
        ],
        check=True,
    )
    with uacrypt_encrypted_path.open("rb") as f, d.SecretStreamDecryptor(key, f) as dec:
        assert dec.read_all() == plaintext


def test_tampered_chunk_is_rejected() -> None:
    key = d.secretstream_keygen()
    out = io.BytesIO()
    with d.SecretStreamEncryptor(key, out) as enc:
        enc.write(b"secret message")
    data = bytearray(out.getvalue())
    data[-1] ^= 1  # last byte of the Final chunk's auth tag
    with (
        pytest.raises(d.DstuError),
        d.SecretStreamDecryptor(key, io.BytesIO(bytes(data))) as dec,
    ):
        dec.read_all()


def test_truncated_stream_is_rejected() -> None:
    key = d.secretstream_keygen()
    out = io.BytesIO()
    with d.SecretStreamEncryptor(key, out) as enc:
        enc.write(b"x" * 20000)
    truncated = out.getvalue()[:100]
    with (
        pytest.raises(d.DstuError),
        d.SecretStreamDecryptor(key, io.BytesIO(truncated)) as dec,
    ):
        dec.read_all()


def test_oversized_declared_chunk_length_is_rejected() -> None:
    key = d.secretstream_keygen()
    malicious = bytes(32) + bytes([0x03]) + (0xFFFFFFFF).to_bytes(4, "little")
    with (
        pytest.raises(d.DstuError, match="too large"),
        d.SecretStreamDecryptor(key, io.BytesIO(malicious)) as dec,
    ):
        dec.read_all()


def test_trailing_data_after_final_is_rejected() -> None:
    key = d.secretstream_keygen()
    out = io.BytesIO()
    with d.SecretStreamEncryptor(key, out) as enc:
        enc.write(b"msg")
    data = out.getvalue() + b"unexpected trailing bytes"
    with (
        pytest.raises(d.DstuError, match="trailing"),
        d.SecretStreamDecryptor(key, io.BytesIO(data)) as dec,
    ):
        dec.read_all()


def test_exception_mid_write_leaves_stream_unfinalized() -> None:
    key = d.secretstream_keygen()
    out = io.BytesIO()
    with pytest.raises(RuntimeError), d.SecretStreamEncryptor(key, out) as enc:
        enc.write(b"chunk one")
        raise RuntimeError("simulated failure mid-stream")

    with (
        pytest.raises(d.DstuError),
        d.SecretStreamDecryptor(key, io.BytesIO(out.getvalue())) as dec,
    ):
        dec.read_all()


def test_wrong_length_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.SecretStreamPushState(b"too short")


def test_write_after_close_is_rejected() -> None:
    key = d.secretstream_keygen()
    out = io.BytesIO()
    enc = d.SecretStreamEncryptor(key, out)
    enc.write(b"data")
    enc.close()
    with pytest.raises(ValueError):
        enc.write(b"more data")
