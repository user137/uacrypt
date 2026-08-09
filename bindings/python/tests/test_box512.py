"""`crypto_box512` - `l(p)=512` sibling of `crypto_box` (T-193/T-204). No official vector exists
for this composite construction (same posture as `crypto_box`) - correctness (round trip),
rejection (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings,
truncated input).
"""

import dstu_core as d
import pytest


def test_seal_open_round_trips() -> None:
    secret_key = d.box512_keygen()
    public_key = d.box512_public_key(secret_key)
    message = b"a message for the public key's holder only"
    sealed = d.box512_seal(public_key, message)
    assert d.box512_open(secret_key, sealed) == message


def test_seal_handles_empty_message() -> None:
    secret_key = d.box512_keygen()
    public_key = d.box512_public_key(secret_key)
    sealed = d.box512_seal(public_key, b"")
    assert d.box512_open(secret_key, sealed) == b""


def test_two_seals_use_different_ephemeral_material() -> None:
    secret_key = d.box512_keygen()
    public_key = d.box512_public_key(secret_key)
    message = b"same message twice"
    assert d.box512_seal(public_key, message) != d.box512_seal(public_key, message)


def test_tampered_ciphertext_is_rejected() -> None:
    secret_key = d.box512_keygen()
    public_key = d.box512_public_key(secret_key)
    sealed = bytearray(d.box512_seal(public_key, b"message"))
    sealed[-1] ^= 1
    with pytest.raises(d.DstuError):
        d.box512_open(secret_key, bytes(sealed))


def test_wrong_secret_key_is_rejected() -> None:
    secret_key = d.box512_keygen()
    public_key = d.box512_public_key(secret_key)
    other_secret_key = d.box512_keygen()
    sealed = d.box512_seal(public_key, b"message")
    with pytest.raises(d.DstuError):
        d.box512_open(other_secret_key, sealed)


def test_wrong_length_secret_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box512_public_key(b"too short")


def test_zero_secret_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box512_public_key(bytes(64))


def test_wrong_length_public_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box512_seal(b"too short", b"message")


def test_degenerate_public_key_x_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box512_seal(bytes(64), b"message")  # x = 0, explicitly rejected


def test_truncated_sealed_input_is_rejected() -> None:
    secret_key = d.box512_keygen()
    with pytest.raises(d.DstuError):
        d.box512_open(secret_key, b"short")
