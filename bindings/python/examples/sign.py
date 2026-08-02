"""crypto_sign (DSTU 4145): generate a signing keypair, sign a message, verify it.

Run: python examples/sign.py
"""

import dstu_core as d


def main() -> None:
    signing_key = d.sign_keygen()
    verifying_key = d.sign_verifying_key(signing_key)

    message = b"a message whose origin and integrity matter"
    signature = d.sign_message(signing_key, message)
    assert d.sign_verify(verifying_key, message, signature)
    print(f"signed and verified a {len(message)}-byte message")

    if not d.sign_verify(verifying_key, b"a different message", signature):
        print("signature over a different message correctly rejected")


if __name__ == "__main__":
    main()
