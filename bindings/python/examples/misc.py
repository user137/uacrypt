"""The remaining crypto_* modules, each small enough to share one file:

- crypto_auth (Kupyna-KMAC): keyed message authentication.
- crypto_kdf: deterministic subkey derivation from a master key.
- crypto_generichash (Kupyna-256/512): one-shot and streaming hashing.
- crypto_stream (Strumok-256): unauthenticated keystream cipher - no integrity, wrong key/tampered
  ciphertext silently decrypts to different, wrong plaintext instead of raising.
- randombytes: CSPRNG-backed random bytes.

Run: python examples/misc.py
"""

import dstu_core as d


def auth_example() -> None:
    key = d.auth_keygen()
    message = b"a message both parties want to confirm is unmodified"
    tag = d.auth(key, message)
    d.auth_verify(key, message, tag)
    print("auth: tag verified")


def kdf_example() -> None:
    master_key = d.kdf_keygen()
    subkey_a = d.kdf_derive_subkey(master_key, 0, b"encrypt_")
    subkey_b = d.kdf_derive_subkey(master_key, 1, b"encrypt_")
    assert subkey_a != subkey_b
    print("kdf: subkey 0 and subkey 1 differ, as expected")


def generichash_example() -> None:
    one_shot = d.kupyna256(b"hello world")
    hasher = d.Kupyna256Hasher()
    hasher.update(b"hello ")
    hasher.update(b"world")
    assert hasher.finalize() == one_shot
    print(f"generichash: kupyna256(b'hello world') = {one_shot.hex()}")


def stream_example() -> None:
    key = d.stream_keygen()
    sealed = d.stream_encrypt(key, b"a message")
    assert d.stream_decrypt(key, sealed) == b"a message"
    print("stream: round-tripped (note: unauthenticated, no tamper detection)")


def randombytes_example() -> None:
    a = d.randombytes_buf(16)
    b = d.randombytes_buf(16)
    assert a != b
    print(f"randombytes: two independent 16-byte draws, e.g. {a.hex()}")


if __name__ == "__main__":
    auth_example()
    kdf_example()
    generichash_example()
    stream_example()
    randombytes_example()
