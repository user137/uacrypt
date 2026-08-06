"""crypto_box: generate a keypair, seal a message to the public key, open it with the secret key.

Run: python examples/box.py
"""

import dstu_core as d


def main() -> None:
    secret_key = d.box_keygen()
    public_key = d.box_public_key(secret_key)  # safe to share/publish

    message = b"a message for the public key's holder only"
    sealed = d.box_seal(public_key, message)
    opened = d.box_open(secret_key, sealed)
    assert opened == message
    print(f"sealed {len(message)} bytes -> {len(sealed)} bytes, round-tripped OK")

    tampered = bytearray(sealed)
    tampered[-1] ^= 1
    try:
        d.box_open(secret_key, bytes(tampered))
    except d.DstuError:
        print("tampered ciphertext correctly rejected")


if __name__ == "__main__":
    main()
