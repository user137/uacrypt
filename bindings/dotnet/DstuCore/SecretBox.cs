using DstuCore.Native;

namespace DstuCore;

/// <summary>Authenticated single-message encryption (<c>crypto_secretbox</c>, Kalyna-256-256-GCM,
/// internal random nonce).</summary>
public sealed class SecretboxKey : IDisposable
{
    private readonly SecretboxKeyHandle _handle;

    private SecretboxKey(SecretboxKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh key from the OS CSPRNG.</summary>
    public static SecretboxKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretbox_key_generate(out var handle));
        return new SecretboxKey(handle);
    }

    /// <summary>Builds a key from exactly <see cref="DstuConstants.SecretboxKeyBytes"/> bytes.</summary>
    public static SecretboxKey FromBytes(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != DstuConstants.SecretboxKeyBytes)
        {
            throw new ArgumentException($"key must be exactly {DstuConstants.SecretboxKeyBytes} bytes", nameof(key));
        }

        return new SecretboxKey(NativeMethods.dstu_secretbox_key_from_bytes(key));
    }

    /// <summary>Copies out this key's raw <see cref="DstuConstants.SecretboxKeyBytes"/>-byte encoding.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.SecretboxKeyBytes];
        NativeMethods.dstu_secretbox_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Encrypts and authenticates <paramref name="plaintext"/>, drawing a fresh random
    /// nonce internally. Returned array is exactly <c>plaintext.Length + DstuConstants.SecretboxOverhead</c>.</summary>
    public byte[] Seal(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var cap = plaintext.Length + DstuConstants.SecretboxOverhead;
        var sealedOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretbox_seal(
            _handle, plaintext, (nuint)plaintext.Length, sealedOut, (nuint)cap, out var sealedLen));
        return Trim(sealedOut, sealedLen);
    }

    /// <summary>Verifies and decrypts <paramref name="sealedMessage"/> as produced by
    /// <see cref="Seal"/>. Throws <see cref="DstuException"/> on a tag mismatch or truncated input.</summary>
    public byte[] Open(byte[] sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);
        if (sealedMessage.Length < DstuConstants.SecretboxOverhead)
        {
            throw new DstuException("input is shorter than the minimum valid length for this construction");
        }

        var cap = sealedMessage.Length - DstuConstants.SecretboxOverhead;
        var plaintextOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretbox_open(
            _handle, sealedMessage, (nuint)sealedMessage.Length, plaintextOut, (nuint)cap, out var plaintextLen));
        return Trim(plaintextOut, plaintextLen);
    }

    private static byte[] Trim(byte[] buffer, nuint length)
    {
        return (int)length == buffer.Length ? buffer : buffer[..(int)length];
    }

    public void Dispose() => _handle.Dispose();
}
