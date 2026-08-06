"""`crypto_box` - no official vector exists for this composite construction (same posture as
`crypto_secretbox`, D-51/D-169's own "Provenance" section) - correctness (round trip, including a
message larger than the 25-byte KEM payload), rejection (tampered wire segments, wrong key),
misuse (wrong-length/invalid key encodings, truncated input).
"""

import dstu_core as d
import pytest


def test_seal_open_round_trips() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    message = b"a message for the public key's holder only"
    sealed = d.box_seal(public_key, message)
    assert d.box_open(secret_key, sealed) == message


def test_seal_handles_empty_message() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    sealed = d.box_seal(public_key, b"")
    assert d.box_open(secret_key, sealed) == b""


def test_seal_handles_message_larger_than_the_kem_payload() -> None:
    """L_MAX_P is 25 bytes at the KEM step - seal/open must still work for an arbitrary-length
    message via the crypto_secretstream layer on top."""
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    message = b"x" * 10_000
    sealed = d.box_seal(public_key, message)
    assert d.box_open(secret_key, sealed) == message


def test_two_seals_use_different_ephemeral_material() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    message = b"same message twice"
    assert d.box_seal(public_key, message) != d.box_seal(public_key, message)


def test_tampered_kem_prefix_is_rejected() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    sealed = bytearray(d.box_seal(public_key, b"message"))
    sealed[0] ^= 1
    with pytest.raises(d.DstuError):
        d.box_open(secret_key, bytes(sealed))


def test_tampered_ciphertext_is_rejected() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    sealed = bytearray(d.box_seal(public_key, b"message"))
    sealed[-1] ^= 1
    with pytest.raises(d.DstuError):
        d.box_open(secret_key, bytes(sealed))


def test_wrong_secret_key_is_rejected() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)
    other_secret_key = d.box_keygen()
    sealed = d.box_seal(public_key, b"message")
    with pytest.raises(d.DstuError):
        d.box_open(other_secret_key, sealed)


def test_wrong_length_secret_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box_public_key(b"too short")


def test_zero_secret_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box_public_key(bytes(32))


def test_wrong_length_public_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box_seal(b"too short", b"message")


def test_degenerate_public_key_x_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.box_seal(bytes(32), b"message")  # x = 0, explicitly rejected


def test_truncated_sealed_input_is_rejected() -> None:
    secret_key = d.box_keygen()
    with pytest.raises(d.DstuError):
        d.box_open(secret_key, b"short")
