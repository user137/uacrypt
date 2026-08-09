"""crypto_sign257 (DSTU 4145 m=257, T-199/T-204): generate a signing keypair, sign a message,
verify it.

Run: python examples/sign257.py
"""

import dstu_core as d


def main() -> None:
    signing_key = d.sign257_keygen()
    verifying_key = d.sign257_verifying_key(signing_key)

    message = b"a message whose origin and integrity matter"
    signature = d.sign257_message(signing_key, message)
    assert d.sign257_verify(verifying_key, message, signature)
    print(f"signed and verified a {len(message)}-byte message")

    if not d.sign257_verify(verifying_key, b"a different message", signature):
        print("signature over a different message correctly rejected")


if __name__ == "__main__":
    main()
