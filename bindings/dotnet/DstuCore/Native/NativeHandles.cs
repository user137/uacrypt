using System.Runtime.InteropServices;

namespace DstuCore.Native;

/// <summary>
/// Common base for every opaque <c>dstu_*</c> pointer handle. <see cref="SafeHandle"/> (not a
/// bare <see cref="IntPtr"/>) so the CLR's own P/Invoke marshaller keeps the handle alive for the
/// duration of each native call and guarantees <c>ReleaseHandle</c> runs exactly once, even
/// on an exception/finalizer path - the ".NET native-handle resource is released deterministically"
/// idiom (cross-language style guide principle 5), same role <c>IDisposable</c>/<c>using</c> plays
/// everywhere else in this binding.
/// </summary>
internal abstract class DstuNativeHandle : SafeHandle
{
    protected DstuNativeHandle()
        : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    public override bool IsInvalid => handle == IntPtr.Zero;
}

internal sealed class AuthKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_auth_key_free(handle);
        return true;
    }
}

internal sealed class KdfMasterKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_kdf_master_key_free(handle);
        return true;
    }
}

internal sealed class Kupyna256HasherHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_kupyna256_hasher_free(handle);
        return true;
    }
}

internal sealed class Kupyna512HasherHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_kupyna512_hasher_free(handle);
        return true;
    }
}

internal sealed class PushStateHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_secretstream_push_free(handle);
        return true;
    }
}

internal sealed class PullStateHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_secretstream_pull_free(handle);
        return true;
    }
}

internal sealed class SecretboxKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_secretbox_key_free(handle);
        return true;
    }
}

internal sealed class SecretstreamKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_secretstream_key_free(handle);
        return true;
    }
}

internal sealed class SigningKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_sign_key_free(handle);
        return true;
    }
}

internal sealed class StreamKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_stream_key_free(handle);
        return true;
    }
}

internal sealed class VerifyingKeyHandle : DstuNativeHandle
{
    protected override bool ReleaseHandle()
    {
        NativeMethods.dstu_verifying_key_free(handle);
        return true;
    }
}
