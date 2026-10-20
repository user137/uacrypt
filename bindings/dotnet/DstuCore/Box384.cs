using DstuCore.Native;

namespace DstuCore;

/// <summary><c>l(p)=384</c> (E384/1) sibling of <see cref="BoxSecretKey"/>/<see cref="BoxPublicKey"/>
/// (<c>crypto_box384</c>, T-297). Same shape, distinct types - not interchangeable with
/// <c>crypto_box</c>, matching <c>dstu_core::crypto_box384</c>'s own module doc.
/// <see cref="Box384PublicKey.Seal"/>/<see cref="Open"/> are not memory-bounded - the whole message
/// is held in memory.</summary>
public sealed class Box384SecretKey : IDisposable
{
    private readonly Box384SecretKeyHandle _handle;

    internal Box384SecretKeyHandle Handle => _handle;

    private Box384SecretKey(Box384SecretKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh secret key from the OS CSPRNG.</summary>
    public static Box384SecretKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_secretkey_generate(out var handle));
        return new Box384SecretKey(handle);
    }

    /// <summary>Builds a secret key from a big-endian <see cref="DstuConstants.Box384SecretKeyBytes"/>-byte
    /// scalar. Throws <see cref="ArgumentException"/> if it's outside the valid range
    /// <c>{2, ..., n-2}</c>.</summary>
    public static Box384SecretKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.Box384SecretKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.Box384SecretKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_secretkey_from_bytes(bytes, out var handle));
        return new Box384SecretKey(handle);
    }

    /// <summary>Copies out this key's big-endian <see cref="DstuConstants.Box384SecretKeyBytes"/>-byte
    /// scalar encoding. <b>The caller is responsible for wiping the returned array once done</b> -
    /// this copies secret material into a managed buffer the wrapped Rust key's own zeroize-on-drop
    /// cannot reach.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Box384SecretKeyBytes];
        NativeMethods.dstu_box384_secretkey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives the public key for this secret key - safe to share/publish.</summary>
    public Box384PublicKey PublicKey() => new(NativeMethods.dstu_box384_secretkey_public_key(_handle));

    /// <summary>Decrypts <paramref name="sealedMessage"/> as produced by <see cref="Box384PublicKey.Seal"/>.
    /// Throws <see cref="DstuException"/> if authentication fails (wrong key, or any tampered wire
    /// segment - deliberately not distinguished further, see <c>dstu_core::crypto_box384::OpenError</c>'s
    /// own doc comment) or the input is too short to be valid.</summary>
    public byte[] Open(byte[] sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);
        // The core checks the version byte before the length (T-269): a short 0.4-0.6 blob is
        // reported as an unsupported version, not as too short.
        var cap = Math.Max(0, sealedMessage.Length - DstuConstants.Box384OpenMinOverhead);
        var plaintextOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_open(
            _handle, sealedMessage, (nuint)sealedMessage.Length, plaintextOut, (nuint)cap, out var plaintextLen));
        return Trim(plaintextOut, plaintextLen);
    }

    private static byte[] Trim(byte[] buffer, nuint length)
    {
        return (int)length == buffer.Length ? buffer : buffer[..(int)length];
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary><c>crypto_box384</c> public key - a curve point's <c>x</c>-coordinate only, see
/// <c>dstu_core::crypto_box384</c>'s own module doc for why this compression is safe.</summary>
public sealed class Box384PublicKey : IDisposable
{
    private readonly Box384PublicKeyHandle _handle;

    internal Box384PublicKeyHandle Handle => _handle;

    internal Box384PublicKey(Box384PublicKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Builds a public key from its compressed <see cref="DstuConstants.Box384PublicKeyBytes"/>-byte
    /// <c>x</c>-coordinate encoding. Throws <see cref="ArgumentException"/> if it isn't a valid
    /// field element, or doesn't reconstruct to a point inside the base point's own prime-order
    /// subgroup.</summary>
    public static Box384PublicKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.Box384PublicKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.Box384PublicKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_publickey_from_bytes(bytes, out var handle));
        return new Box384PublicKey(handle);
    }

    /// <summary>Copies out this key's <see cref="DstuConstants.Box384PublicKeyBytes"/>-byte encoding -
    /// not secret, no wiping needed afterward.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.Box384PublicKeyBytes];
        NativeMethods.dstu_box384_publickey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Encrypts <paramref name="message"/> (any length) to the holder of this public key,
    /// drawing a fresh random seed and ephemeral key internally.</summary>
    public byte[] Seal(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_sealed_len((nuint)message.Length, out var cap));
        var sealedOut = new byte[(int)cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box384_seal(
            _handle, message, (nuint)message.Length, sealedOut, cap, out var sealedLen));
        return (int)sealedLen == sealedOut.Length ? sealedOut : sealedOut[..(int)sealedLen];
    }

    public void Dispose() => _handle.Dispose();
}
