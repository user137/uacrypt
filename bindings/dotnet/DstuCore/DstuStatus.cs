namespace DstuCore;

/// <summary>
/// Mirrors <c>DstuStatus</c> in <c>dstu_core.h</c>. Internal - a caller sees a
/// <see cref="DstuException"/>/<see cref="ArgumentException"/> at the public API boundary
/// instead (cross-language style guide principle 4), never this raw native code.
/// </summary>
internal enum DstuStatus
{
    Ok = 0,
    ErrRandom = 1,
    ErrTagMismatch = 2,
    ErrTruncated = 3,
    ErrInvalidLength = 4,
    ErrBufferTooSmall = 5,
    ErrUnknownTag = 6,
    ErrFinalized = 7,
    ErrSelftestFailed = 8,
    ErrHashError = 9,
    ErrInvalidKey = 10,
    ErrNullPointer = 11,
    ErrPanic = 12,
}

/// <summary>Argon2id cost preset - mirrors <c>DstuPwhashStrength</c> in <c>dstu_core.h</c>, and
/// libsodium's own named <c>OPSLIMIT</c>/<c>MEMLIMIT_*</c> constants.</summary>
public enum PwhashStrength
{
    Interactive = 0,
    Moderate = 1,
    Sensitive = 2,
}

/// <summary>A chunk's role in a <see cref="SecretstreamKey"/> stream - mirrors <c>DstuTag</c> in
/// <c>dstu_core.h</c>.</summary>
public enum SecretStreamTag
{
    Message = 0,
    Push = 1,
    Rekey = 2,
    Final = 3,
}
