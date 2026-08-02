"""crypto_pwhash (Argon2id): hash and verify a password.

`PWHASH_INTERACTIVE` is used here so the example runs fast - `PWHASH_MODERATE` (the default
strength most applications should use) and `PWHASH_SENSITIVE` both take real seconds by design.

Run: python examples/password_hashing.py
"""

import dstu_core as d


def main() -> None:
    password = b"correct horse battery staple"
    stored = d.pwhash_hash_password(password, d.PWHASH_INTERACTIVE)
    print(f"stored hash: {stored}")

    assert d.pwhash_verify_password(password, stored)
    print("correct password accepted")

    assert not d.pwhash_verify_password(b"wrong guess", stored)
    print("wrong password correctly rejected")


if __name__ == "__main__":
    main()
