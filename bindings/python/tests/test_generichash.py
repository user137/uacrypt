"""`crypto_generichash` (Kupyna-256/512) - three categories per D-64/D-65: correctness against a
real official Kupyna-256 vector (loaded directly from the same JSON the Rust crate's own tests and
`selftest()` use - `crates/dstu-core/tests/vectors/kupyna/kupyna-256.json`, not just round-trip
self-consistency) plus one-shot/streaming agreement, misuse (calling `finalize()` twice - there is
no rejection category, a hash has no key/tag to tamper with).
"""

from __future__ import annotations

import json
from pathlib import Path

import dstu_core as d
import pytest

_VECTOR_PATH = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "dstu-core"
    / "tests"
    / "vectors"
    / "kupyna"
    / "kupyna-256.json"
)


def test_kupyna256_matches_official_vector() -> None:
    vectors = json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))
    case = vectors["cases"][0]
    message = bytes.fromhex(case["message_hex"])
    expected = bytes.fromhex(case["hash_hex"])
    assert d.kupyna256(message) == expected


def test_streaming_hasher_matches_one_shot() -> None:
    whole = d.kupyna256(b"hello world")
    hasher = d.Kupyna256Hasher()
    hasher.update(b"hello ")
    hasher.update(b"world")
    assert hasher.finalize() == whole


def test_kupyna512_streaming_hasher_matches_one_shot() -> None:
    whole = d.kupyna512(b"hello world")
    hasher = d.Kupyna512Hasher()
    hasher.update(b"hello ")
    hasher.update(b"world")
    assert hasher.finalize() == whole


def test_finalize_twice_is_rejected() -> None:
    hasher = d.Kupyna256Hasher()
    hasher.update(b"data")
    hasher.finalize()
    with pytest.raises(ValueError):
        hasher.finalize()


def test_update_after_finalize_is_rejected() -> None:
    hasher = d.Kupyna256Hasher()
    hasher.finalize()
    with pytest.raises(ValueError):
        hasher.update(b"more data")
