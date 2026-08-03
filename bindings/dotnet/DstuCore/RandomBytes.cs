using DstuCore.Native;

namespace DstuCore;

/// <summary>OS CSPRNG access (<c>dstu_core::randombytes</c>), for a caller who needs random bytes
/// outside of a key-generation call.</summary>
public static class RandomBytes
{
    /// <summary>Fills a fresh <paramref name="length"/>-byte array from the OS CSPRNG.</summary>
    public static byte[] Buf(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        var buf = new byte[length];
        NativeStatus.ThrowIfError(NativeMethods.dstu_randombytes_buf(buf, (nuint)length));
        return buf;
    }
}
