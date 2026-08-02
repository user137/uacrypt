"""crypto_secretstream: encrypt/decrypt a file incrementally, chunk by chunk, via the file-like
SecretStreamEncryptor/SecretStreamDecryptor wrapper (docs/DECISIONS.md D-118). The wire format
matches `uacrypt encrypt`/`decrypt` exactly - a file this writes is decryptable by the `uacrypt`
CLI and vice versa.

Run: python examples/secretstream_file.py
"""

import tempfile
from pathlib import Path

import dstu_core as d


def main() -> None:
    key = d.secretstream_keygen()
    plaintext = b"a message spread across more than one 8 KiB chunk\n" * 1000

    with tempfile.TemporaryDirectory() as tmp:
        encrypted_path = Path(tmp) / "message.enc"
        decrypted_path = Path(tmp) / "message.dec"

        with (
            encrypted_path.open("wb") as f,
            d.SecretStreamEncryptor(key, f) as enc,
        ):
            enc.write(plaintext)

        with (
            encrypted_path.open("rb") as f,
            d.SecretStreamDecryptor(key, f) as dec,
        ):
            recovered = dec.read_all()

        assert recovered == plaintext
        print(
            f"{len(plaintext)} bytes -> {encrypted_path.stat().st_size} bytes on disk, "
            "round-tripped OK"
        )
        decrypted_path.write_bytes(recovered)


if __name__ == "__main__":
    main()
