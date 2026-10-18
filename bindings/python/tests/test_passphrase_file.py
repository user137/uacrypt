"""Passphrase files (D-219, moved into the core by T-269/D-240): `PassphraseEncryptor`/
`PassphraseDecryptor`, the same bytes `uacrypt encrypt --passphrase-file` writes. Argon2 is
256 MiB, t=3 per run, so only the shared-vector test and the `uacrypt` interop run it; every
header refusal stops before Argon2. Happy path: the 0.6.0 vectors, interop both ways. Security:
wrong passphrase, tampered record. Misuse: empty passphrase, a key-encrypted stream, a cut
header. Error path: a failing sink.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import dstu_core as d
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = (
    _REPO_ROOT
    / "crates"
    / "dstu-core"
    / "tests"
    / "vectors"
    / "pwhash"
    / "passphrase_file.json"
)
_UACRYPT_CANDIDATES = [
    _REPO_ROOT / "target" / "debug" / "uacrypt.exe",
    _REPO_ROOT / "target" / "release" / "uacrypt.exe",
    _REPO_ROOT / "target" / "debug" / "uacrypt",
    _REPO_ROOT / "target" / "release" / "uacrypt",
]


def _pattern(n: int) -> bytes:
    return bytes((i * 31 + 7) % 256 for i in range(n))


def _cases(argon2: bool) -> list[dict]:
    cases = json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]
    return [c for c in cases if c["argon2"] is argon2]


def _open(passphrase: bytes, data: bytes) -> bytes:
    return d.PassphraseDecryptor(passphrase, io.BytesIO(data)).read_all()


def test_header_vectors_are_refused_before_argon2() -> None:
    messages = {
        "not_passphrase_file": "not a passphrase file",
        "unsupported_format": "unsupported passphrase file format",
        "unsupported_params": "unsupported Argon2 parameters",
        "truncated": "too short",
    }
    cases = _cases(False)
    assert len(cases) == 6
    for case in cases:
        with pytest.raises(d.DstuError, match=messages[case["expect"]]):
            _open(
                bytes.fromhex(case["passphrase_hex"]), bytes.fromhex(case["sealed_hex"])
            )


def test_files_written_by_uacrypt_0_6_0_give_their_expected_outcome() -> None:
    cases = _cases(True)
    assert len(cases) == 4
    for case in cases:
        passphrase = bytes.fromhex(case["passphrase_hex"])
        sealed = bytes.fromhex(case["sealed_hex"])
        if case["expect"] == "ok":
            assert _open(passphrase, sealed) == _pattern(case["plaintext_len"]), case[
                "name"
            ]
        else:
            with pytest.raises(d.DstuError):
                _open(passphrase, sealed)


def test_empty_passphrase_is_refused_on_both_sides() -> None:
    with pytest.raises(d.DstuError, match="empty"):
        d.PassphraseEncryptor(b"", io.BytesIO())
    sealed = bytes.fromhex(_cases(True)[0]["sealed_hex"])
    with pytest.raises(d.DstuError, match="empty"):
        _open(b"", sealed)


def test_a_key_encrypted_stream_is_not_a_passphrase_file() -> None:
    out = io.BytesIO()
    with d.SecretStreamEncryptor(d.secretstream_keygen(), out) as enc:
        enc.write(b"x")
    with pytest.raises(d.DstuError, match="not a passphrase file"):
        _open(b"pw", out.getvalue())


def test_a_failing_sink_raises_before_argon2() -> None:
    class Failing:
        def write(self, data: bytes) -> int:
            raise OSError("disk full")

    # The prefix is written right after Argon2 in the constructor; its error is the sink's own.
    with pytest.raises(OSError, match="disk full"):
        d.PassphraseEncryptor(b"pw", Failing())


def _uacrypt() -> Path:
    for candidate in _UACRYPT_CANDIDATES:
        if candidate.is_file():
            return candidate
    pytest.skip("uacrypt binary not built (cargo build -p uacrypt)")


def test_interop_with_uacrypt_both_ways(tmp_path: Path) -> None:
    uacrypt = _uacrypt()
    message = _pattern(8 * 1024 + 9)
    passphrase = "спільний пароль".encode()
    pw_file = tmp_path / "pw.txt"
    pw_file.write_bytes(passphrase)

    ours = tmp_path / "ours.uac"
    with ours.open("wb") as f, d.PassphraseEncryptor(passphrase, f) as enc:
        enc.write(message)
    back = tmp_path / "ours.back"
    subprocess.run(
        [
            str(uacrypt),
            "decrypt",
            "--passphrase-file",
            str(pw_file),
            "--in",
            str(ours),
            "--out",
            str(back),
        ],
        check=True,
        capture_output=True,
    )
    assert back.read_bytes() == message

    plain = tmp_path / "plain.bin"
    plain.write_bytes(message)
    theirs = tmp_path / "theirs.uac"
    subprocess.run(
        [
            str(uacrypt),
            "encrypt",
            "--passphrase-file",
            str(pw_file),
            "--in",
            str(plain),
            "--out",
            str(theirs),
        ],
        check=True,
        capture_output=True,
    )
    with theirs.open("rb") as f:
        assert d.PassphraseDecryptor(passphrase, f).read_all() == message
