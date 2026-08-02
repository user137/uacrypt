"""`crypto_auth` - three categories per D-64/D-65: correctness (round trip), rejection (tampered
message, wrong key), misuse (wrong-length key/tag - foreclosed at the Rust layer by fixed-size
arrays, D-66, so `auth` itself is infallible; only the Python-boundary length checks are testable
here).
"""

import dstu_core as d
import pytest


def test_auth_verify_round_trips() -> None:
    key = d.auth_keygen()
    tag = d.auth(key, b"a message both parties want to confirm is unmodified")
    d.auth_verify(key, b"a message both parties want to confirm is unmodified", tag)


def test_tampered_message_is_rejected() -> None:
    key = d.auth_keygen()
    tag = d.auth(key, b"original message")
    with pytest.raises(d.DstuError):
        d.auth_verify(key, b"a different message", tag)


def test_wrong_key_is_rejected() -> None:
    key = d.auth_keygen()
    other_key = d.auth_keygen()
    tag = d.auth(key, b"message")
    with pytest.raises(d.DstuError):
        d.auth_verify(other_key, b"message", tag)


def test_wrong_length_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.auth(b"too short", b"message")


def test_wrong_length_tag_is_rejected() -> None:
    key = d.auth_keygen()
    with pytest.raises(ValueError):
        d.auth_verify(key, b"message", b"too short")
