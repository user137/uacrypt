"""`crypto_kdf` - no official vector exists for this construction (D-45: no DSTU KDF standard or
reference implementation exists at all). Correctness here means determinism/distinctness, matching
the Rust crate's own property-test posture. Misuse: wrong-length master key/context (infallible
otherwise, D-66 - no rejection category, there is no tag to tamper with).
"""

import dstu_core as d
import pytest


def test_derive_subkey_is_deterministic() -> None:
    master_key = d.kdf_keygen()
    assert d.kdf_derive_subkey(master_key, 0, b"encrypt_") == d.kdf_derive_subkey(
        master_key, 0, b"encrypt_"
    )


def test_different_subkey_id_gives_different_subkey() -> None:
    master_key = d.kdf_keygen()
    a = d.kdf_derive_subkey(master_key, 0, b"context1")
    b = d.kdf_derive_subkey(master_key, 1, b"context1")
    assert a != b


def test_different_context_gives_different_subkey() -> None:
    master_key = d.kdf_keygen()
    a = d.kdf_derive_subkey(master_key, 0, b"context1")
    b = d.kdf_derive_subkey(master_key, 0, b"context2")
    assert a != b


def test_wrong_length_master_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        d.kdf_derive_subkey(b"too short", 0, b"context1")


def test_wrong_length_context_is_rejected() -> None:
    master_key = d.kdf_keygen()
    with pytest.raises(ValueError):
        d.kdf_derive_subkey(master_key, 0, b"short")
