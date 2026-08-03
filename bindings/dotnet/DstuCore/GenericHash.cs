using DstuCore.Native;

namespace DstuCore;

/// <summary>One-shot Kupyna hashing (<c>crypto_generichash</c>). For incremental hashing of data
/// that shouldn't be held whole in memory, see <see cref="Kupyna256Hasher"/>/
/// <see cref="Kupyna512Hasher"/>.</summary>
public static class GenericHash
{
    /// <summary>One-shot Kupyna-256 digest of <paramref name="message"/>.</summary>
    public static byte[] Hash256(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var outBytes = new byte[DstuConstants.GenericHash256Bytes];
        NativeMethods.dstu_generichash_256(message, (nuint)message.Length, outBytes);
        return outBytes;
    }

    /// <summary>One-shot Kupyna-512 digest of <paramref name="message"/>.</summary>
    public static byte[] Hash512(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var outBytes = new byte[DstuConstants.GenericHash512Bytes];
        NativeMethods.dstu_generichash_512(message, (nuint)message.Length, outBytes);
        return outBytes;
    }
}

/// <summary>Incremental Kupyna-256 hasher for data too large to hold in memory at once.</summary>
public sealed class Kupyna256Hasher : IDisposable
{
    private readonly Kupyna256HasherHandle _handle;
    private bool _finalized;

    public Kupyna256Hasher()
    {
        _handle = NativeMethods.dstu_kupyna256_hasher_new();
    }

    /// <summary>Feeds <paramref name="data"/> into the hasher.</summary>
    public void Update(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (_finalized)
        {
            throw new InvalidOperationException("this hasher has already been finalized");
        }

        NativeMethods.dstu_kupyna256_hasher_update(_handle, data, (nuint)data.Length);
    }

    /// <summary>Consumes the hasher's accumulated state into a
    /// <see cref="DstuConstants.GenericHash256Bytes"/>-byte digest. May only be called once.</summary>
    public byte[] Finalize()
    {
        if (_finalized)
        {
            throw new InvalidOperationException("this hasher has already been finalized");
        }

        var outBytes = new byte[DstuConstants.GenericHash256Bytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_kupyna256_hasher_finalize(_handle, outBytes));
        _finalized = true;
        return outBytes;
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary>Incremental Kupyna-512 hasher. Same shape as <see cref="Kupyna256Hasher"/>.</summary>
public sealed class Kupyna512Hasher : IDisposable
{
    private readonly Kupyna512HasherHandle _handle;
    private bool _finalized;

    public Kupyna512Hasher()
    {
        _handle = NativeMethods.dstu_kupyna512_hasher_new();
    }

    public void Update(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (_finalized)
        {
            throw new InvalidOperationException("this hasher has already been finalized");
        }

        NativeMethods.dstu_kupyna512_hasher_update(_handle, data, (nuint)data.Length);
    }

    public byte[] Finalize()
    {
        if (_finalized)
        {
            throw new InvalidOperationException("this hasher has already been finalized");
        }

        var outBytes = new byte[DstuConstants.GenericHash512Bytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_kupyna512_hasher_finalize(_handle, outBytes));
        _finalized = true;
        return outBytes;
    }

    public void Dispose() => _handle.Dispose();
}
