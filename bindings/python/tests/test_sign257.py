"""`crypto_sign257` (DSTU 4145 `m=257`) - `m=257` sibling of `crypto_sign` (T-199/T-204).
Correctness (round trip, determinism of the nonce derivation), rejection (wrong message/wrong
key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
"""

import dstu_core as d
import pytest


def test_sign_verify_round_trips() -> None:
    signing_key = d.sign257_keygen()
    verifying_key = d.sign257_verifying_key(signing_key)
    message = b"a message whose origin and integrity matter"
    signature = d.sign257_message(signing_key, message)
    assert d.sign257_verify(verifying_key, message, signature)


def test_signing_is_deterministic() -> None:
    signing_key = d.sign257_keygen()
    message = b"same message every time"
    assert d.sign257_message(signing_key, message) == d.sign257_message(
        signing_key, message
    )


def test_wrong_message_is_rejected() -> None:
    signing_key = d.sign257_keygen()
    verifying_key = d.sign257_verifying_key(signing_key)
    signature = d.sign257_message(signing_key, b"original message")
    assert not d.sign257_verify(verifying_key, b"a different message", signature)


def test_wrong_key_is_rejected() -> None:
    signing_key = d.sign257_keygen()
    other_verifying_key = d.sign257_verifying_key(d.sign257_keygen())
    message = b"message"
    signature = d.sign257_message(signing_key, message)
    assert not d.sign257_verify(other_verifying_key, message, signature)


def test_zero_signing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign257_verifying_key(bytes(33))


def test_wrong_length_signing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign257_message(b"too short", b"message")


def test_wrong_length_verifying_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.sign257_verify(b"too short", b"message", bytes(66))


def test_wrong_length_signature_is_rejected() -> None:
    signing_key = d.sign257_keygen()
    verifying_key = d.sign257_verifying_key(signing_key)
    with pytest.raises(ValueError):
        d.sign257_verify(verifying_key, b"message", b"too short")
