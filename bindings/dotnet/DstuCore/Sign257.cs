using System.Security.Cryptography;
using DstuCore.Native;

namespace DstuCore;

/// <summary>DSTU 4145 <c>m=257</c> signing key (<c>crypto_sign257</c>, T-199/T-204) - the curve
/// real Diia-issued qualified signatures use. Same shape as <see cref="SigningKey"/>, a distinct
/// type - not interchangeable with <c>crypto_sign</c>'s <c>m=163</c>. Signing is deterministic
/// (Kupyna-KMAC-derived nonce) - no RNG dependency beyond key generation.</summary>
public sealed class SigningKey257 : IDisposable
{
    private readonly SigningKey257Handle _handle;

    private SigningKey257(SigningKey257Handle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh signing key from the OS CSPRNG.</summary>
    public static SigningKey257 Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_sign257_key_generate(out var handle));
        return new SigningKey257(handle);
    }

    /// <summary>Builds a signing key from a big-endian <see cref="DstuConstants.Sign257PrivateKeyBytes"/>-byte
    /// scalar. Throws <see cref="ArgumentException"/> if the scalar is zero or >= the curve order.</summary>
    public static SigningKey257 FromBytes(byte[] d)
    {
        ArgumentNullException.ThrowIfNull(d);
        if (d.Length != DstuConstants.Sign257PrivateKeyBytes)
        {
            throw new ArgumentException($"d must be exactly {DstuConstants.Sign257PrivateKeyBytes} bytes", nameof(d));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_sign257_key_from_bytes(d, out var handle));
        return new SigningKey257(handle);
    }

    /// <summary>Copies out this key's big-endian <see cref="DstuConstants.Sign257PrivateKeyBytes"/>-byte
    /// scalar encoding. <b>The caller is responsible for wiping the returned array once done</b>
    /// (e.g. via <see cref="CryptographicOperations.ZeroMemory"/>) - this copies secret material
    /// into a managed buffer the wrapped Rust key's own zeroize-on-drop cannot reach.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Sign257PrivateKeyBytes];
        NativeMethods.dstu_sign257_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives the public verifying key for this signing key.</summary>
    public VerifyingKey257 VerifyingKey() => new(NativeMethods.dstu_sign257_verifying_key(_handle));

    /// <summary>Signs <paramref name="message"/>, hashing it with Kupyna-256 internally.</summary>
    public byte[] Sign(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var sig = new byte[DstuConstants.Sign257SignatureBytes];
        NativeMethods.dstu_sign257(_handle, message, (nuint)message.Length, sig);
        return sig;
    }

    /// <summary>Signs an already-computed <see cref="DstuConstants.Sign257DigestBytes"/>-byte
    /// Kupyna-256 digest directly - for a message hashed incrementally rather than held whole in
    /// memory.</summary>
    public byte[] SignDigest(byte[] digest)
    {
        ArgumentNullException.ThrowIfNull(digest);
        if (digest.Length != DstuConstants.Sign257DigestBytes)
        {
            throw new ArgumentException($"digest must be exactly {DstuConstants.Sign257DigestBytes} bytes", nameof(digest));
        }

        var sig = new byte[DstuConstants.Sign257SignatureBytes];
        NativeMethods.dstu_sign257_digest(_handle, digest, sig);
        return sig;
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary>DSTU 4145 <c>m=257</c> public verifying key. No curve-tag byte at this layer - the
/// tag/dispatch mechanism lives at the <c>uacrypt</c> serialization layer only (D-118), the same
/// convention the underlying C ABI's own module doc documents.</summary>
public sealed class VerifyingKey257 : IDisposable
{
    private readonly VerifyingKey257Handle _handle;

    internal VerifyingKey257(VerifyingKey257Handle handle)
    {
        _handle = handle;
    }

    /// <summary>Builds a verifying key from <see cref="DstuConstants.Sign257PublicKeyBytes"/> bytes
    /// of plain <c>x || y</c> encoding - no validation that the point is on the curve, matching the
    /// wrapped Rust function's own convention.</summary>
    public static VerifyingKey257 FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.Sign257PublicKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.Sign257PublicKeyBytes} bytes", nameof(bytes));
        }

        return new VerifyingKey257(NativeMethods.dstu_verifying_key257_from_bytes(bytes));
    }

    /// <summary>Copies out this key's plain <c>x || y</c> <see cref="DstuConstants.Sign257PublicKeyBytes"/>-byte
    /// encoding (<b>not</b> the DSTU 4145 standard's own compressed point encoding).</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Sign257PublicKeyBytes];
        NativeMethods.dstu_verifying_key257_to_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Verifies <paramref name="sig"/> over <paramref name="message"/>.</summary>
    public bool Verify(byte[] message, byte[] sig)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(sig);
        if (sig.Length != DstuConstants.Sign257SignatureBytes)
        {
            throw new ArgumentException($"sig must be exactly {DstuConstants.Sign257SignatureBytes} bytes", nameof(sig));
        }

        return NativeMethods.dstu_verify257(_handle, message, (nuint)message.Length, sig);
    }

    /// <summary>Verifies <paramref name="sig"/> over an already-computed
    /// <see cref="DstuConstants.Sign257DigestBytes"/>-byte digest directly.</summary>
    public bool VerifyDigest(byte[] digest, byte[] sig)
    {
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(sig);
        if (digest.Length != DstuConstants.Sign257DigestBytes)
        {
            throw new ArgumentException($"digest must be exactly {DstuConstants.Sign257DigestBytes} bytes", nameof(digest));
        }

        if (sig.Length != DstuConstants.Sign257SignatureBytes)
        {
            throw new ArgumentException($"sig must be exactly {DstuConstants.Sign257SignatureBytes} bytes", nameof(sig));
        }

        return NativeMethods.dstu_verify257_digest(_handle, digest, sig);
    }

    public void Dispose() => _handle.Dispose();
}
