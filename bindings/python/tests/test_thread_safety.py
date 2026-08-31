"""T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
than assumed.

- `sign_keygen`/`sign_verifying_key`/`sign_message`/`sign_verify` are plain functions over
  immutable `bytes` keys - no PyO3 object holds native state across calls at all, so there is
  nothing to race on regardless of the GIL. Verified below with real concurrent Python threads
  calling `sign_verify`/`sign_message` on the SAME key bytes.
- `SecretStreamPushState`/`PullState` DO hold native state (a `&mut self` Rust struct behind a
  PyO3 handle) that advances with every `push`/`pull` call. This binding does not add any locking
  of its own - the GIL happens to serialize individual calls (no `py.allow_threads` release in
  `push`/`pull`), so two threads racing the SAME session can't corrupt memory, but the resulting
  interleaving of chunks would still be logically wrong for a single stream. The supported
  concurrency model is one stream (one `PushState`/`PullState` pair) per thread - verified below
  with many threads each driving an independent stream concurrently, not by racing a shared one.
"""

from __future__ import annotations

import queue
import threading

import dstu_core as d


def _run_concurrently(thread_count: int, target) -> None:
    """Runs `target(thread_index)` on `thread_count` real Python threads, re-raising the first
    exception/assertion failure any of them hit."""
    errors: queue.Queue = queue.Queue()

    def wrapper(index: int) -> None:
        try:
            target(index)
        except Exception as exc:  # noqa: BLE001 - re-raised on the main thread below
            errors.put(exc)

    threads = [threading.Thread(target=wrapper, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not errors.empty():
        raise errors.get()


def test_concurrent_verify_on_shared_key_is_safe() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)
    message = b"shared-key concurrent verify"
    signature = d.sign_message(signing_key, message)

    def worker(_index: int) -> None:
        for _ in range(200):
            assert d.sign_verify(verifying_key, message, signature)

    _run_concurrently(16, worker)


def test_concurrent_sign_on_shared_key_is_safe() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)
    message = b"shared-key concurrent sign"

    def worker(_index: int) -> None:
        for _ in range(50):
            sig = d.sign_message(signing_key, message)
            assert d.sign_verify(verifying_key, message, sig)

    _run_concurrently(16, worker)


def test_concurrent_independent_secretstream_loops_are_safe() -> None:
    def worker(thread_index: int) -> None:
        key = d.secretstream_keygen()
        chunks = [f"thread {thread_index} chunk {i}".encode("ascii") for i in range(20)]

        push = d.SecretStreamPushState(key)
        header = push.header
        pulled = []
        for chunk in chunks:
            ciphertext, auth_tag = push.push(d.SECRETSTREAM_TAG_MESSAGE, chunk)
            pulled.append((ciphertext, auth_tag))

        pull = d.SecretStreamPullState(key, header)
        for chunk, (ciphertext, auth_tag) in zip(chunks, pulled):
            _tag, plaintext = pull.pull(
                d.SECRETSTREAM_TAG_MESSAGE, ciphertext, auth_tag
            )
            assert plaintext == chunk

    _run_concurrently(8, worker)
