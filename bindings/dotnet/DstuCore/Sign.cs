using System.Security.Cryptography;
using DstuCore.Native;

namespace DstuCore;

/// <summary>DSTU 4145 signing key (<c>crypto_sign</c>). Signing is deterministic (Kupyna-KMAC-derived
/// nonce) - no RNG dependency beyond key generation.</summary>
public sealed class SigningKey : IDisposable
{
    private readonly SigningKeyHandle _handle;

    private SigningKey(SigningKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh signing key from the OS CSPRNG.</summary>
    public static SigningKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_sign_key_generate(out var handle));
        return new SigningKey(handle);
    }

    /// <summary>Builds a signing key from a big-endian <see cref="DstuConstants.SignPrivateKeyBytes"/>-byte
    /// scalar. Throws <see cref="ArgumentException"/> if the scalar is zero or >= the curve order.</summary>
    public static SigningKey FromBytes(byte[] d)
    {
        ArgumentNullException.ThrowIfNull(d);
        if (d.Length != DstuConstants.SignPrivateKeyBytes)
        {
            throw new ArgumentException($"d must be exactly {DstuConstants.SignPrivateKeyBytes} bytes", nameof(d));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_sign_key_from_bytes(d, out var handle));
        return new SigningKey(handle);
    }

    /// <summary>Copies out this key's big-endian <see cref="DstuConstants.SignPrivateKeyBytes"/>-byte
    /// scalar encoding. <b>The caller is responsible for wiping the returned array once done</b>
    /// (e.g. via <see cref="CryptographicOperations.ZeroMemory"/>) - this copies secret material
    /// into a managed buffer the wrapped Rust key's own zeroize-on-drop cannot reach.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.SignPrivateKeyBytes];
        NativeMethods.dstu_sign_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives the public verifying key for this signing key.</summary>
    public VerifyingKey VerifyingKey() => new(NativeMethods.dstu_sign_verifying_key(_handle));

    /// <summary>Signs <paramref name="message"/>, hashing it with Kupyna-256 internally.</summary>
    public byte[] Sign(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var sig = new byte[DstuConstants.SignSignatureBytes];
        NativeMethods.dstu_sign(_handle, message, (nuint)message.Length, sig);
        return sig;
    }

    /// <summary>Signs an already-computed <see cref="DstuConstants.SignDigestBytes"/>-byte
    /// Kupyna-256 digest directly - for a message hashed incrementally rather than held whole in
    /// memory.</summary>
    public byte[] SignDigest(byte[] digest)
    {
        ArgumentNullException.ThrowIfNull(digest);
        if (digest.Length != DstuConstants.SignDigestBytes)
        {
            throw new ArgumentException($"digest must be exactly {DstuConstants.SignDigestBytes} bytes", nameof(digest));
        }

        var sig = new byte[DstuConstants.SignSignatureBytes];
        NativeMethods.dstu_sign_digest(_handle, digest, sig);
        return sig;
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary>DSTU 4145 public verifying key.</summary>
public sealed class VerifyingKey : IDisposable
{
    private readonly VerifyingKeyHandle _handle;

    internal VerifyingKey(VerifyingKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Builds a verifying key from <see cref="DstuConstants.SignPublicKeyBytes"/> bytes
    /// of plain <c>x || y</c> encoding - no validation that the point is on the curve, matching the
    /// wrapped Rust function's own convention.</summary>
    public static VerifyingKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.SignPublicKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.SignPublicKeyBytes} bytes", nameof(bytes));
        }

        return new VerifyingKey(NativeMethods.dstu_verifying_key_from_bytes(bytes));
    }

    /// <summary>Copies out this key's plain <c>x || y</c> <see cref="DstuConstants.SignPublicKeyBytes"/>-byte
    /// encoding (<b>not</b> the DSTU 4145 standard's own compressed point encoding).</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.SignPublicKeyBytes];
        NativeMethods.dstu_verifying_key_to_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Verifies <paramref name="sig"/> over <paramref name="message"/>.</summary>
    public bool Verify(byte[] message, byte[] sig)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(sig);
        if (sig.Length != DstuConstants.SignSignatureBytes)
        {
            throw new ArgumentException($"sig must be exactly {DstuConstants.SignSignatureBytes} bytes", nameof(sig));
        }

        return NativeMethods.dstu_verify(_handle, message, (nuint)message.Length, sig);
    }

    /// <summary>Verifies <paramref name="sig"/> over an already-computed
    /// <see cref="DstuConstants.SignDigestBytes"/>-byte digest directly.</summary>
    public bool VerifyDigest(byte[] digest, byte[] sig)
    {
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(sig);
        if (digest.Length != DstuConstants.SignDigestBytes)
        {
            throw new ArgumentException($"digest must be exactly {DstuConstants.SignDigestBytes} bytes", nameof(digest));
        }

        if (sig.Length != DstuConstants.SignSignatureBytes)
        {
            throw new ArgumentException($"sig must be exactly {DstuConstants.SignSignatureBytes} bytes", nameof(sig));
        }

        return NativeMethods.dstu_verify_digest(_handle, digest, sig);
    }

    public void Dispose() => _handle.Dispose();
}
