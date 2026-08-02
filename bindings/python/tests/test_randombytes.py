"""`randombytes` - no rejection/misuse category (a single `size: int` parameter, no key/tag to
tamper with or malform beyond what Python's own type system already forecloses). Correctness:
returns the requested length, and two calls are not identical.
"""

import dstu_core as d


def test_returns_requested_length() -> None:
    assert len(d.randombytes_buf(32)) == 32


def test_zero_length_returns_empty() -> None:
    assert d.randombytes_buf(0) == b""


def test_two_calls_are_not_identical() -> None:
    assert d.randombytes_buf(32) != d.randombytes_buf(32)
