using DstuCore.Native;

namespace DstuCore;

/// <summary>Kupyna-KMAC message-authentication key (<c>crypto_auth</c>).</summary>
public sealed class AuthKey : IDisposable
{
    private readonly AuthKeyHandle _handle;

    private AuthKey(AuthKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh key from the OS CSPRNG.</summary>
    public static AuthKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_auth_key_generate(out var handle));
        return new AuthKey(handle);
    }

    /// <summary>Builds a key from exactly <see cref="DstuConstants.AuthKeyBytes"/> bytes.</summary>
    public static AuthKey FromBytes(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != DstuConstants.AuthKeyBytes)
        {
            throw new ArgumentException($"key must be exactly {DstuConstants.AuthKeyBytes} bytes", nameof(key));
        }

        var handle = NativeMethods.dstu_auth_key_from_bytes(key);
        return new AuthKey(handle);
    }

    /// <summary>Copies out this key's raw <see cref="DstuConstants.AuthKeyBytes"/>-byte encoding.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.AuthKeyBytes];
        NativeMethods.dstu_auth_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Computes the MAC of <paramref name="message"/> under this key.</summary>
    public byte[] Compute(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var tag = new byte[DstuConstants.AuthTagBytes];
        NativeMethods.dstu_auth(_handle, message, (nuint)message.Length, tag);
        return tag;
    }

    /// <summary>Verifies <paramref name="tag"/> against <paramref name="message"/> under this key.
    /// Throws <see cref="DstuException"/> on a mismatch.</summary>
    public void Verify(byte[] message, byte[] tag)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(tag);
        if (tag.Length != DstuConstants.AuthTagBytes)
        {
            throw new ArgumentException($"tag must be exactly {DstuConstants.AuthTagBytes} bytes", nameof(tag));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_auth_verify(_handle, message, (nuint)message.Length, tag));
    }

    public void Dispose() => _handle.Dispose();
}
