"""`crypto_pwhash` (Argon2id, the one deliberately non-DSTU component, D-49/D-50). Correctness:
round trip. Rejection: wrong password, malformed hash string. Misuse: invalid `strength` value.
`PWHASH_INTERACTIVE` is used throughout (not the default `PWHASH_MODERATE`) so this file's own
tests stay fast - `Strength::Sensitive` alone takes real seconds, per the Rust crate's own test
comments.
"""

import dstu_core as d
import pytest


def test_hash_verify_round_trips() -> None:
    stored = d.pwhash_hash_password(
        b"correct horse battery staple", d.PWHASH_INTERACTIVE
    )
    assert d.pwhash_verify_password(b"correct horse battery staple", stored)


def test_wrong_password_is_rejected() -> None:
    stored = d.pwhash_hash_password(
        b"correct horse battery staple", d.PWHASH_INTERACTIVE
    )
    assert not d.pwhash_verify_password(b"wrong guess", stored)


def test_malformed_hash_string_is_rejected() -> None:
    assert not d.pwhash_verify_password(b"anything", "not a real PHC string")


def test_invalid_strength_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.pwhash_hash_password(b"password", 255)
