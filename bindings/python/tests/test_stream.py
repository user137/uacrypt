"""`crypto_stream` (Strumok-256 keystream) - **no authentication** (see
`dstu_core::crypto_stream`'s own module doc): no rejection category, since there is no tag to
tamper with - `stream_decrypt` never fails on tampered input, it silently returns different,
wrong plaintext instead. Correctness: round trip. Misuse: wrong-length key, truncated input.
"""

import dstu_core as d
import pytest


def test_encrypt_decrypt_round_trips() -> None:
    key = d.stream_keygen()
    sealed = d.stream_encrypt(key, b"message")
    assert d.stream_decrypt(key, sealed) == b"message"


def test_tampering_is_not_detected_but_produces_wrong_plaintext() -> None:
    """Documents the no-integrity property explicitly, per this project's own precedent
    (`hazmat::kalyna_xts`'s `tampered_ciphertext_does_not_error_but_produces_garbage`) - a
    deliberate design property, not a missing rejection test."""
    key = d.stream_keygen()
    sealed = bytearray(d.stream_encrypt(key, b"message"))
    sealed[-1] ^= 1
    garbage = d.stream_decrypt(key, bytes(sealed))
    assert garbage != b"message"


def test_wrong_length_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.stream_encrypt(b"too short", b"message")


def test_truncated_sealed_input_is_rejected() -> None:
    key = d.stream_keygen()
    with pytest.raises(d.DstuError):
        d.stream_decrypt(key, b"short")
