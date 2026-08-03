namespace DstuCore.Native;

/// <summary>
/// Maps a raw <see cref="DstuStatus"/> to the public exception a caller should actually see
/// (cross-language style guide principle 4 - a typed result at the API boundary, not a raw native
/// code). <see cref="DstuException"/> covers a genuine crypto-operation/data-integrity failure
/// (wrong key, tampered/truncated/corrupted input, environment failure); <see cref="ArgumentException"/>
/// covers a caller-supplied value that is well-formed C# but invalid crypto input (a DSTU 4145
/// scalar out of range). The remaining statuses (<see cref="DstuStatus.ErrBufferTooSmall"/>,
/// <see cref="DstuStatus.ErrNullPointer"/>, <see cref="DstuStatus.ErrInvalidLength"/>,
/// <see cref="DstuStatus.ErrPanic"/>) can only happen if this wrapper itself computed a buffer
/// size or handle wrong - they surface as <see cref="InvalidOperationException"/> ("internal
/// error") rather than a public failure mode a caller is expected to handle, mirroring
/// <c>bindings/python</c>'s own <c>DstuError</c>/<c>ValueError</c> split.
/// </summary>
internal static class NativeStatus
{
    internal static void ThrowIfError(DstuStatus status)
    {
        switch (status)
        {
            case DstuStatus.Ok:
                return;
            case DstuStatus.ErrRandom:
                throw new DstuException("OS CSPRNG failure while generating random data");
            case DstuStatus.ErrTagMismatch:
                throw new DstuException("authentication failed: wrong key, or tampered ciphertext/tag/nonce/header");
            case DstuStatus.ErrTruncated:
                throw new DstuException("input is shorter than the minimum valid length for this construction");
            case DstuStatus.ErrUnknownTag:
                throw new DstuException("secretstream chunk has an invalid tag byte - the stream is corrupted or truncated");
            case DstuStatus.ErrFinalized:
                throw new InvalidOperationException("this secretstream state has already emitted/consumed a Final chunk");
            case DstuStatus.ErrSelftestFailed:
                throw new DstuException("dstu_selftest: a known-answer self-check failed against the compiled build");
            case DstuStatus.ErrHashError:
                throw new DstuException("crypto_pwhash: internal Argon2/PHC-encoding failure");
            case DstuStatus.ErrInvalidKey:
                throw new ArgumentException("invalid key material (e.g. a DSTU 4145 scalar that is zero or >= the curve order)");
            case DstuStatus.ErrBufferTooSmall:
            case DstuStatus.ErrNullPointer:
            case DstuStatus.ErrInvalidLength:
            case DstuStatus.ErrPanic:
            default:
                throw new InvalidOperationException($"internal error in the DstuCore .NET binding ({status}) - please report this");
        }
    }
}
