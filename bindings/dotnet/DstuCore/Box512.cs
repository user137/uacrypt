using DstuCore.Native;

namespace DstuCore;

/// <summary><c>l(p)=512</c> (E512/1) sibling of <see cref="BoxSecretKey"/>/<see cref="BoxPublicKey"/>
/// (<c>crypto_box512</c>, T-193/T-204). Same shape, distinct types - not interchangeable with
/// <c>crypto_box</c>, matching <c>dstu_core::crypto_box512</c>'s own module doc.
/// <see cref="Box512PublicKey.Seal"/>/<see cref="Open"/> are not memory-bounded - the whole message
/// is held in memory.</summary>
public sealed class Box512SecretKey : IDisposable
{
    private readonly Box512SecretKeyHandle _handle;

    private Box512SecretKey(Box512SecretKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh secret key from the OS CSPRNG.</summary>
    public static Box512SecretKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_secretkey_generate(out var handle));
        return new Box512SecretKey(handle);
    }

    /// <summary>Builds a secret key from a big-endian <see cref="DstuConstants.Box512SecretKeyBytes"/>-byte
    /// scalar. Throws <see cref="ArgumentException"/> if it's outside the valid range
    /// <c>{2, ..., n-2}</c>.</summary>
    public static Box512SecretKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.Box512SecretKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.Box512SecretKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_secretkey_from_bytes(bytes, out var handle));
        return new Box512SecretKey(handle);
    }

    /// <summary>Copies out this key's big-endian <see cref="DstuConstants.Box512SecretKeyBytes"/>-byte
    /// scalar encoding. <b>The caller is responsible for wiping the returned array once done</b> -
    /// this copies secret material into a managed buffer the wrapped Rust key's own zeroize-on-drop
    /// cannot reach.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Box512SecretKeyBytes];
        NativeMethods.dstu_box512_secretkey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives the public key for this secret key - safe to share/publish.</summary>
    public Box512PublicKey PublicKey() => new(NativeMethods.dstu_box512_secretkey_public_key(_handle));

    /// <summary>Decrypts <paramref name="sealedMessage"/> as produced by <see cref="Box512PublicKey.Seal"/>.
    /// Throws <see cref="DstuException"/> if authentication fails (wrong key, or any tampered wire
    /// segment - deliberately not distinguished further, see <c>dstu_core::crypto_box512::OpenError</c>'s
    /// own doc comment) or the input is too short to be valid.</summary>
    public byte[] Open(byte[] sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);
        if (sealedMessage.Length < DstuConstants.Box512SealOverhead)
        {
            throw new DstuException("input is shorter than the minimum valid length for this construction");
        }

        var cap = sealedMessage.Length - DstuConstants.Box512SealOverhead;
        var plaintextOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_open(
            _handle, sealedMessage, (nuint)sealedMessage.Length, plaintextOut, (nuint)cap, out var plaintextLen));
        return Trim(plaintextOut, plaintextLen);
    }

    private static byte[] Trim(byte[] buffer, nuint length)
    {
        return (int)length == buffer.Length ? buffer : buffer[..(int)length];
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary><c>crypto_box512</c> public key - a curve point's <c>x</c>-coordinate only, see
/// <c>dstu_core::crypto_box512</c>'s own module doc for why this compression is safe.</summary>
public sealed class Box512PublicKey : IDisposable
{
    private readonly Box512PublicKeyHandle _handle;

    internal Box512PublicKey(Box512PublicKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Builds a public key from its compressed <see cref="DstuConstants.Box512PublicKeyBytes"/>-byte
    /// <c>x</c>-coordinate encoding. Throws <see cref="ArgumentException"/> if it isn't a valid
    /// field element, or doesn't reconstruct to a point inside the base point's own prime-order
    /// subgroup.</summary>
    public static Box512PublicKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.Box512PublicKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.Box512PublicKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_publickey_from_bytes(bytes, out var handle));
        return new Box512PublicKey(handle);
    }

    /// <summary>Copies out this key's <see cref="DstuConstants.Box512PublicKeyBytes"/>-byte encoding -
    /// not secret, no wiping needed afterward.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Box512PublicKeyBytes];
        NativeMethods.dstu_box512_publickey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Encrypts <paramref name="message"/> (any length) to the holder of this public key,
    /// drawing a fresh random seed and ephemeral key internally.</summary>
    public byte[] Seal(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var cap = message.Length + DstuConstants.Box512SealOverhead;
        var sealedOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_seal(
            _handle, message, (nuint)message.Length, sealedOut, (nuint)cap, out var sealedLen));
        return (int)sealedLen == sealedOut.Length ? sealedOut : sealedOut[..(int)sealedLen];
    }

    public void Dispose() => _handle.Dispose();
}
