using DstuCore.Native;

namespace DstuCore;

/// <summary>Unauthenticated keystream cipher (<c>crypto_stream</c>, Strumok-256, internal random
/// IV). <b>Never fails on tampered input</b> - <see cref="Decrypt"/> has no tag to verify, and
/// silently returns different, wrong plaintext instead of throwing. Named <c>StreamCipher</c>
/// rather than <c>Stream</c> to avoid colliding with <see cref="System.IO.Stream"/>.</summary>
public sealed class StreamCipherKey : IDisposable
{
    private readonly StreamKeyHandle _handle;

    private StreamCipherKey(StreamKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh key from the OS CSPRNG.</summary>
    public static StreamCipherKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_stream_key_generate(out var handle));
        return new StreamCipherKey(handle);
    }

    /// <summary>Builds a key from exactly <see cref="DstuConstants.StreamKeyBytes"/> bytes.</summary>
    public static StreamCipherKey FromBytes(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != DstuConstants.StreamKeyBytes)
        {
            throw new ArgumentException($"key must be exactly {DstuConstants.StreamKeyBytes} bytes", nameof(key));
        }

        return new StreamCipherKey(NativeMethods.dstu_stream_key_from_bytes(key));
    }

    /// <summary>Copies out this key's raw <see cref="DstuConstants.StreamKeyBytes"/>-byte encoding.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.StreamKeyBytes];
        NativeMethods.dstu_stream_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>XORs <paramref name="plaintext"/> with a fresh keystream, drawing a random IV
    /// internally. Returned array is exactly <c>plaintext.Length + DstuConstants.StreamOverhead</c>.</summary>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var cap = plaintext.Length + DstuConstants.StreamOverhead;
        var sealedOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_stream_encrypt(
            _handle, plaintext, (nuint)plaintext.Length, sealedOut, (nuint)cap, out var sealedLen));
        return (int)sealedLen == cap ? sealedOut : sealedOut[..(int)sealedLen];
    }

    /// <summary>Reverses <see cref="Encrypt"/>. Throws <see cref="DstuException"/> only if
    /// <paramref name="sealedMessage"/> is shorter than <see cref="DstuConstants.StreamOverhead"/> -
    /// there is no tag, so tampered input decrypts silently to wrong plaintext.</summary>
    public byte[] Decrypt(byte[] sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);
        if (sealedMessage.Length < DstuConstants.StreamOverhead)
        {
            throw new DstuException("input is shorter than the minimum valid length for this construction");
        }

        var cap = sealedMessage.Length - DstuConstants.StreamOverhead;
        var plaintextOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_stream_decrypt(
            _handle, sealedMessage, (nuint)sealedMessage.Length, plaintextOut, (nuint)cap, out var plaintextLen));
        return (int)plaintextLen == cap ? plaintextOut : plaintextOut[..(int)plaintextLen];
    }

    public void Dispose() => _handle.Dispose();
}
