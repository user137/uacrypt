"""T-213: FFI memory-leak smoke test. Loops `crypto_secretstream` push/pull (the most stateful,
longest-lived native object this binding wraps - `SecretStreamPushState`/`PullState`) and
`crypto_box` seal/open (a keyed one-shot primitive) N=1000+ times with normal cleanup, then asserts
`tracemalloc`'s traced-memory delta stays far below what a real leak of that many iterations would
show.

Instrument validated, not assumed: a throwaway negative-control spike (not committed - see
`docs/TASKS.md`'s T-213 entry) confirmed `tracemalloc` DOES observe a leak of this object class -
holding 1000 `SecretStreamPushState`/`PullState` pairs alive produced a ~241 KB snapshot delta vs
~1 KB for the same loop with normal `del`+`gc.collect()` cleanup. That's because these wrapper
objects are direct PyO3 handles around a Rust struct with no separate C ABI `free()` call - once
the Python wrapper is collected, Rust's own `Drop` is guaranteed to run correctly (memory safety by
construction), so "the wrapper object never gets collected" (a held reference, a reference cycle,
D-118's cleanup-hook-not-firing pitfall) is the entire native-leak risk surface for this binding,
and `tracemalloc` genuinely observes it.
"""

from __future__ import annotations

import gc
import tracemalloc

import dstu_core as d

N = 1000
# Real regression signal, not a hair-trigger: the validated negative control showed ~241 bytes per
# leaked (push, pull) pair. This threshold is well below "N leaked handles" but well above normal
# per-iteration Python-level bookkeeping noise (observed ~1 byte/iteration in the release case).
MAX_ACCEPTABLE_GROWTH_BYTES = N * 40


def test_secretstream_and_box_loop_does_not_leak() -> None:
    key = d.secretstream_keygen()
    box_secret = d.box_keygen()
    box_public = d.box_public_key(box_secret)

    gc.collect()
    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    for _ in range(N):
        push = d.SecretStreamPushState(key)
        header = push.header
        ciphertext, auth_tag = push.push(
            d.SECRETSTREAM_TAG_MESSAGE, b"leak-check chunk"
        )
        pull = d.SecretStreamPullState(key, header)
        pull.pull(d.SECRETSTREAM_TAG_MESSAGE, ciphertext, auth_tag)
        del push, pull, ciphertext, auth_tag, header

        sealed = d.box_seal(box_public, b"leak-check message")
        opened = d.box_open(box_secret, sealed)
        assert opened == b"leak-check message"
        del sealed, opened

    gc.collect()
    snap_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    diff = snap_after.compare_to(snap_before, "lineno")
    total_growth = sum(stat.size_diff for stat in diff)
    assert total_growth < MAX_ACCEPTABLE_GROWTH_BYTES, (
        f"traced-memory grew by {total_growth} bytes over {N} iterations "
        f"(threshold {MAX_ACCEPTABLE_GROWTH_BYTES}) - possible native handle leak; "
        f"top allocations:\n" + "\n".join(str(s) for s in diff[:10])
    )
