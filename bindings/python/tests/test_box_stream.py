"""Streaming `crypto_box`/`crypto_box512` (T-265 format v3, T-269): `BoxEncryptor`/`BoxDecryptor`
and the 512 pair over the core's `seal_stream`/`open_stream`. Happy path: the shared v3 vectors
(one-shot `box_open` and the streaming reader), a round trip across record boundaries, and the
one-shot/streaming byte equivalence. Security: tampering and a wrong key. Misuse: wrong-length
keys, a cut prefix, write after close, the 0.4-0.6 format. Error path: a failing sink.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import dstu_core as d
import pytest

_VECTORS = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "dstu-core"
    / "tests"
    / "vectors"
    / "box"
)


def _pattern(n: int) -> bytes:
    return bytes((i * 31 + 7) % 256 for i in range(n))


def _load(name: str) -> dict:
    return json.loads((_VECTORS / name).read_text(encoding="utf-8"))


_CURVES = {
    256: (
        d.box_open,
        d.BoxEncryptor,
        d.BoxDecryptor,
        d.box_keygen,
        d.box_public_key,
        "box256_secret_key_hex",
    ),
    512: (
        d.box512_open,
        d.Box512Encryptor,
        d.Box512Decryptor,
        d.box512_keygen,
        d.box512_public_key,
        "box512_secret_key_hex",
    ),
}


def _stream_open(decryptor: type, secret: bytes, sealed: bytes) -> bytes:
    return decryptor(secret, io.BytesIO(sealed)).read_all()


@pytest.mark.parametrize("curve", [256, 512])
def test_shared_v3_vectors_give_their_expected_outcome(curve: int) -> None:
    vectors = _load("v3.json")
    box_open, _, decryptor, _, _, secret_field = _CURVES[curve]
    secret = bytes.fromhex(vectors[secret_field])
    seen = 0
    for case in (c for c in vectors["cases"] if c["curve"] == curve):
        sealed = bytes.fromhex(case["sealed_hex"])
        if case["expect"] == "ok":
            expected = _pattern(case["plaintext_len"])
            assert box_open(secret, sealed) == expected, case["name"]
            assert _stream_open(decryptor, secret, sealed) == expected, case["name"]
        else:
            with pytest.raises(d.DstuError):
                box_open(secret, sealed)
            with pytest.raises(d.DstuError):
                _stream_open(decryptor, secret, sealed)
        seen += 1
    assert seen > 0


@pytest.mark.parametrize("curve", [256, 512])
def test_the_0_6_format_is_refused_as_unsupported(curve: int) -> None:
    vectors = _load("legacy_v2.json")
    box_open, _, decryptor, _, _, secret_field = _CURVES[curve]
    secret = bytes.fromhex(vectors[secret_field])
    for case in (c for c in vectors["cases"] if c["curve"] == curve):
        sealed = bytes.fromhex(case["sealed_hex"])
        with pytest.raises(d.DstuError, match="version"):
            box_open(secret, sealed)
        with pytest.raises(d.DstuError, match="version"):
            _stream_open(decryptor, secret, sealed)


@pytest.mark.parametrize("curve", [256, 512])
@pytest.mark.parametrize("size", [0, 1, 8 * 1024, 8 * 1024 + 1, 3 * 8 * 1024 + 5])
def test_stream_round_trip_and_one_shot_reader(curve: int, size: int) -> None:
    box_open, encryptor, decryptor, keygen, public_key, _ = _CURVES[curve]
    secret = keygen()
    message = _pattern(size)
    out = io.BytesIO()
    with encryptor(public_key(secret), out) as enc:
        enc.write(message[:7])
        enc.write(message[7:])
    sealed = out.getvalue()
    assert _stream_open(decryptor, secret, sealed) == message
    assert box_open(secret, sealed) == message


@pytest.mark.parametrize("curve", [256, 512])
def test_tampered_and_wrong_key_fail_closed(curve: int) -> None:
    _, encryptor, decryptor, keygen, public_key, _ = _CURVES[curve]
    secret = keygen()
    out = io.BytesIO()
    with encryptor(public_key(secret), out) as enc:
        enc.write(_pattern(100))
    sealed = bytearray(out.getvalue())
    with pytest.raises(d.DstuError):
        _stream_open(decryptor, keygen(), bytes(sealed))
    for index in (1, len(sealed) // 2, len(sealed) - 1):
        bad = bytearray(sealed)
        bad[index] ^= 0x01
        with pytest.raises(d.DstuError):
            _stream_open(decryptor, secret, bytes(bad))
    with pytest.raises(d.DstuError):
        _stream_open(decryptor, secret, bytes(sealed) + b"\x00")


@pytest.mark.parametrize("curve", [256, 512])
def test_misuse_is_refused(curve: int) -> None:
    _, encryptor, decryptor, keygen, public_key, _ = _CURVES[curve]
    secret = keygen()
    with pytest.raises(ValueError):
        encryptor(b"\x01" * 3, io.BytesIO())
    with pytest.raises(ValueError):
        decryptor(b"\x01" * 3, io.BytesIO(b"\x03" * 400))
    out = io.BytesIO()
    enc = encryptor(public_key(secret), out)
    enc.close()
    with pytest.raises(ValueError):
        enc.write(b"late")
    sealed = out.getvalue()
    for cut in (0, 1, 50):
        with pytest.raises(d.DstuError):
            _stream_open(decryptor, secret, sealed[:cut])


class _FailingSink:
    def __init__(self, fail_after: int) -> None:
        self._left = fail_after

    def write(self, data: bytes) -> int:
        if self._left == 0:
            raise OSError("disk full")
        self._left -= 1
        return len(data)


@pytest.mark.parametrize("curve", [256, 512])
def test_a_failing_sink_raises_its_own_error(curve: int) -> None:
    _, encryptor, _, keygen, public_key, _ = _CURVES[curve]
    with pytest.raises(OSError, match="disk full"):
        encryptor(public_key(keygen()), _FailingSink(0))
    enc = encryptor(public_key(keygen()), _FailingSink(1))
    with pytest.raises(OSError, match="disk full"):
        enc.write(_pattern(3 * 8 * 1024))
