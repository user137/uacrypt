using DstuCore.Native;

namespace DstuCore;

/// <summary>Runtime known-answer self-check (T-161/D-117) - lets a consumer verify their exact
/// installed native library is producing correct outputs on their exact platform, without
/// trusting "it compiled" alone.</summary>
public static class Selftest
{
    /// <summary>Re-verifies one official test vector per primitive (Kalyna, Kupyna, Strumok, DSTU
    /// 4145) against the live compiled <c>dstu_core_capi</c> native library. Throws
    /// <see cref="DstuException"/> if any primitive fails.</summary>
    public static void Run()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_selftest());
    }
}
