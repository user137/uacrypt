using DstuCore.Native;

namespace DstuCore;

/// <summary>Public-key encryption (<c>crypto_box</c>, hybrid via KDF over <c>hazmat::dstu9041</c>,
/// D-169). <see cref="BoxPublicKey.Seal"/>/<see cref="Open"/> are not memory-bounded - the whole message is
/// held in memory.</summary>
public sealed class BoxSecretKey : IDisposable
{
    private readonly BoxSecretKeyHandle _handle;

    private BoxSecretKey(BoxSecretKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh secret key from the OS CSPRNG.</summary>
    public static BoxSecretKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_box_secretkey_generate(out var handle));
        return new BoxSecretKey(handle);
    }

    /// <summary>Builds a secret key from a big-endian <see cref="DstuConstants.BoxSecretKeyBytes"/>-byte
    /// scalar. Throws <see cref="ArgumentException"/> if it's outside the valid range
    /// <c>{2, ..., n-2}</c>.</summary>
    public static BoxSecretKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.BoxSecretKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.BoxSecretKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box_secretkey_from_bytes(bytes, out var handle));
        return new BoxSecretKey(handle);
    }

    /// <summary>Copies out this key's big-endian <see cref="DstuConstants.BoxSecretKeyBytes"/>-byte
    /// scalar encoding. <b>The caller is responsible for wiping the returned array once done</b> -
    /// this copies secret material into a managed buffer the wrapped Rust key's own zeroize-on-drop
    /// cannot reach.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.BoxSecretKeyBytes];
        NativeMethods.dstu_box_secretkey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives the public key for this secret key - safe to share/publish.</summary>
    public BoxPublicKey PublicKey() => new(NativeMethods.dstu_box_secretkey_public_key(_handle));

    /// <summary>Decrypts <paramref name="sealedMessage"/> as produced by <see cref="BoxPublicKey.Seal"/>.
    /// Throws <see cref="DstuException"/> if authentication fails (wrong key, or any tampered wire
    /// segment - deliberately not distinguished further, see <c>dstu_core::crypto_box::OpenError</c>'s
    /// own doc comment) or the input is too short to be valid.</summary>
    public byte[] Open(byte[] sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(sealedMessage);
        if (sealedMessage.Length < DstuConstants.BoxSealOverhead)
        {
            throw new DstuException("input is shorter than the minimum valid length for this construction");
        }

        var cap = sealedMessage.Length - DstuConstants.BoxSealOverhead;
        var plaintextOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box_open(
            _handle, sealedMessage, (nuint)sealedMessage.Length, plaintextOut, (nuint)cap, out var plaintextLen));
        return Trim(plaintextOut, plaintextLen);
    }

    private static byte[] Trim(byte[] buffer, nuint length)
    {
        return (int)length == buffer.Length ? buffer : buffer[..(int)length];
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary><c>crypto_box</c> public key - a curve point's <c>x</c>-coordinate only, see
/// <c>dstu_core::crypto_box</c>'s own module doc for why this compression is safe.</summary>
public sealed class BoxPublicKey : IDisposable
{
    private readonly BoxPublicKeyHandle _handle;

    internal BoxPublicKey(BoxPublicKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Builds a public key from its compressed <see cref="DstuConstants.BoxPublicKeyBytes"/>-byte
    /// <c>x</c>-coordinate encoding. Throws <see cref="ArgumentException"/> if it isn't a valid
    /// field element, or doesn't reconstruct to a point inside the base point's own prime-order
    /// subgroup.</summary>
    public static BoxPublicKey FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != DstuConstants.BoxPublicKeyBytes)
        {
            throw new ArgumentException($"bytes must be exactly {DstuConstants.BoxPublicKeyBytes} bytes", nameof(bytes));
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_box_publickey_from_bytes(bytes, out var handle));
        return new BoxPublicKey(handle);
    }

    /// <summary>Copies out this key's <see cref="DstuConstants.BoxPublicKeyBytes"/>-byte encoding -
    /// not secret, no wiping needed afterward.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.BoxPublicKeyBytes];
        NativeMethods.dstu_box_publickey_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Encrypts <paramref name="message"/> (any length) to the holder of this public key,
    /// drawing a fresh random seed and ephemeral key internally.</summary>
    public byte[] Seal(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var cap = message.Length + DstuConstants.BoxSealOverhead;
        var sealedOut = new byte[cap];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box_seal(
            _handle, message, (nuint)message.Length, sealedOut, (nuint)cap, out var sealedLen));
        return (int)sealedLen == sealedOut.Length ? sealedOut : sealedOut[..(int)sealedLen];
    }

    public void Dispose() => _handle.Dispose();
}
