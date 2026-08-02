"""`crypto_secretbox` - three test categories per D-64/D-65: correctness (round trip - no official
vector exists for this construction, same posture as the Rust crate's own tests, D-51), rejection
(tamper/wrong key), misuse (wrong-length key, truncated input).
"""

import dstu_core as d
import pytest


def test_seal_open_round_trips() -> None:
    key = d.secretbox_keygen()
    sealed = d.secretbox_seal(key, b"a message worth protecting")
    assert d.secretbox_open(key, sealed) == b"a message worth protecting"


def test_seal_handles_empty_message() -> None:
    key = d.secretbox_keygen()
    sealed = d.secretbox_seal(key, b"")
    assert d.secretbox_open(key, sealed) == b""


def test_tampered_ciphertext_is_rejected() -> None:
    key = d.secretbox_keygen()
    sealed = bytearray(d.secretbox_seal(key, b"message"))
    sealed[-1] ^= 1
    with pytest.raises(d.DstuError):
        d.secretbox_open(key, bytes(sealed))


def test_tampered_nonce_is_rejected() -> None:
    key = d.secretbox_keygen()
    sealed = bytearray(d.secretbox_seal(key, b"message"))
    sealed[0] ^= 1  # first byte of the nonce
    with pytest.raises(d.DstuError):
        d.secretbox_open(key, bytes(sealed))


def test_wrong_key_is_rejected() -> None:
    key = d.secretbox_keygen()
    other_key = d.secretbox_keygen()
    sealed = d.secretbox_seal(key, b"message")
    with pytest.raises(d.DstuError):
        d.secretbox_open(other_key, sealed)


def test_wrong_length_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.secretbox_seal(b"too short", b"message")


def test_truncated_sealed_input_is_rejected() -> None:
    key = d.secretbox_keygen()
    with pytest.raises(d.DstuError):
        d.secretbox_open(key, b"short")
