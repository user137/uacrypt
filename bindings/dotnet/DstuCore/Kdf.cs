using DstuCore.Native;

namespace DstuCore;

/// <summary>Kupyna-KDF master key (<c>crypto_kdf</c>).</summary>
public sealed class KdfMasterKey : IDisposable
{
    private readonly KdfMasterKeyHandle _handle;

    private KdfMasterKey(KdfMasterKeyHandle handle)
    {
        _handle = handle;
    }

    /// <summary>Generates a fresh master key from the OS CSPRNG.</summary>
    public static KdfMasterKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_kdf_master_key_generate(out var handle));
        return new KdfMasterKey(handle);
    }

    /// <summary>Builds a master key from exactly <see cref="DstuConstants.KdfKeyBytes"/> bytes.</summary>
    public static KdfMasterKey FromBytes(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != DstuConstants.KdfKeyBytes)
        {
            throw new ArgumentException($"key must be exactly {DstuConstants.KdfKeyBytes} bytes", nameof(key));
        }

        return new KdfMasterKey(NativeMethods.dstu_kdf_master_key_from_bytes(key));
    }

    /// <summary>Copies out this key's raw <see cref="DstuConstants.KdfKeyBytes"/>-byte encoding.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.KdfKeyBytes];
        NativeMethods.dstu_kdf_master_key_bytes(_handle, outBytes);
        return outBytes;
    }

    /// <summary>Derives a <see cref="DstuConstants.KdfSubkeyBytes"/>-byte subkey from
    /// <paramref name="subkeyId"/>/<paramref name="context"/> (exactly
    /// <see cref="DstuConstants.KdfContextBytes"/> bytes).</summary>
    public byte[] DeriveSubkey(ulong subkeyId, byte[] context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Length != DstuConstants.KdfContextBytes)
        {
            throw new ArgumentException($"context must be exactly {DstuConstants.KdfContextBytes} bytes", nameof(context));
        }

        var outBytes = new byte[DstuConstants.KdfSubkeyBytes];
        NativeMethods.dstu_kdf_derive_subkey(_handle, subkeyId, context, outBytes);
        return outBytes;
    }

    public void Dispose() => _handle.Dispose();
}
