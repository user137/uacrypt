"""crypto_secretbox: seal/open a single message with a symmetric key.

Run: python examples/secretbox.py
"""

import dstu_core as d


def main() -> None:
    key = d.secretbox_keygen()
    sealed = d.secretbox_seal(key, b"a message worth protecting")
    plaintext = d.secretbox_open(key, sealed)
    assert plaintext == b"a message worth protecting"
    print(f"sealed {len(plaintext)} bytes -> {len(sealed)} bytes, round-tripped OK")

    tampered = bytearray(sealed)
    tampered[-1] ^= 1
    try:
        d.secretbox_open(key, bytes(tampered))
    except d.DstuError:
        print("tampered ciphertext correctly rejected")


if __name__ == "__main__":
    main()
