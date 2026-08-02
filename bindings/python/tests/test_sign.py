"""`crypto_sign` (DSTU 4145) - the official Annex B.1 verify vector is already covered by
`selftest()` (`test_selftest.py`); this file covers what that single vector doesn't reach:
correctness (round trip, determinism of the nonce derivation), rejection (wrong message/wrong
key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
"""

import dstu_core as d
import pytest


def test_sign_verify_round_trips() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)
    message = b"a message whose origin and integrity matter"
    signature = d.sign_message(signing_key, message)
    assert d.sign_verify(verifying_key, message, signature)


def test_signing_is_deterministic() -> None:
    """D-46: the ephemeral nonce is derived deterministically, not from an RNG - the same
    (key, message) pair always produces the same signature."""
    signing_key = d.sign_keygen()
    message = b"same message every time"
    assert d.sign_message(signing_key, message) == d.sign_message(signing_key, message)


def test_wrong_message_is_rejected() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)
    signature = d.sign_message(signing_key, b"original message")
    assert not d.sign_verify(verifying_key, b"a different message", signature)


def test_wrong_key_is_rejected() -> None:
    signing_key = d.sign_keygen()
    other_verifying_key = d.sign_verifying_key(d.sign_keygen())
    message = b"message"
    signature = d.sign_message(signing_key, message)
    assert not d.sign_verify(other_verifying_key, message, signature)


def test_zero_signing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign_verifying_key(bytes(21))


def test_wrong_length_signing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign_message(b"too short", b"message")


def test_wrong_length_verifying_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign_verify(b"too short", b"message", bytes(42))


def test_wrong_length_signature_is_rejected() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)
    with pytest.raises(ValueError):
        d.sign_verify(verifying_key, b"message", b"too short")
