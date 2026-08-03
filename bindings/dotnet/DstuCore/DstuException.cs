namespace DstuCore;

/// <summary>
/// A crypto-operation failure: wrong key, tampered ciphertext/tag/nonce/header, an incomplete
/// <see cref="SecretStreamDecryptStream"/> (no <see cref="SecretStreamTag.Final"/> chunk seen), or
/// <see cref="Pwhash"/>'s internal Argon2 failure. Distinct from <see cref="ArgumentException"/>,
/// which covers a caller-input mistake a fixed-length array can't forecheck at compile time (wrong
/// key length, negative buffer offsets) - mirrors <c>bindings/python</c>'s own
/// <c>DstuError</c>/<c>ValueError</c> split (cross-language style guide principle 4).
/// </summary>
public sealed class DstuException : Exception
{
    public DstuException(string message)
        : base(message)
    {
    }
}
