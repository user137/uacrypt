namespace DstuCore;

/// <summary>
/// Fixed sizes mirroring the <c>DSTU_*</c> macros in <c>crates/dstu-core-capi/include/dstu_core.h</c>.
/// </summary>
public static class DstuConstants
{
    public const int AuthKeyBytes = 32;
    public const int AuthTagBytes = 32;

    public const int BoxSecretKeyBytes = 32;
    public const int BoxPublicKeyBytes = 32;

    /// <summary>The shortest sealed message (format v3, T-265): <see cref="BoxSecretKey.Open"/>'s
    /// plaintext is at most the sealed length minus this.</summary>
    public const int BoxOpenMinOverhead = 183;

    public const int Box512SecretKeyBytes = 64;
    public const int Box512PublicKeyBytes = 64;

    /// <summary>The <c>l(p)=512</c> sibling of <see cref="BoxOpenMinOverhead"/>.</summary>
    public const int Box512OpenMinOverhead = 311;

    // T-269: the bytes in front of a box stream file (D-239) and the passphrase-file header
    // (D-240) - the C ABI's DSTU_BOX*_SEAL/OPEN_STREAM_PREFIX_BYTES and
    // DSTU_PASSPHRASE_FILE_*_BYTES. The native side reads/writes exactly this many bytes.
    internal const int BoxSealStreamPrefixBytes = 162;
    internal const int BoxOpenStreamPrefixBytes = 129;
    internal const int Box512SealStreamPrefixBytes = 290;
    internal const int Box512OpenStreamPrefixBytes = 257;
    internal const int PassphraseFileHeaderBytes = 28;
    internal const int PassphraseFileSealStreamPrefixBytes = 61;
    public const int PwhashSaltBytes = 16;
    public const int PwhashKeyBytes = 32;

    public const int GenericHash256Bytes = 32;
    public const int GenericHash512Bytes = 64;

    public const int KdfKeyBytes = 32;
    public const int KdfContextBytes = 8;
    public const int KdfSubkeyBytes = 32;

    /// <summary>Fixed buffer size for a PHC string produced by <see cref="Pwhash.HashPassword"/>.</summary>
    public const int PwhashStrBytes = 128;

    public const int SecretboxKeyBytes = 32;

    /// <summary>1-byte format version + 32-byte nonce + 16-byte tag.</summary>
    public const int SecretboxOverhead = 49;

    public const int SecretstreamKeyBytes = 32;
    public const int SecretstreamHeaderBytes = 32;
    public const int SecretstreamTagBytes = 16;

    /// <summary>Plaintext chunk size this binding's stream wrapper frames at - matches every other
    /// binding's own <c>SECRETSTREAM_CHUNK_BYTES</c> and <c>uacrypt</c>'s own CLI chunking.</summary>
    public const int SecretstreamChunkBytes = 8192;

    /// <summary>First byte of every stream file - matches dstu-core's
    /// <c>crypto_secretstream::FORMAT_VERSION</c> (D-208); the shared vectors pin it.</summary>
    public const byte SecretstreamFormatVersion = 2;

    /// <summary>A stream file's first bytes: the format version byte plus the 32-byte header
    /// (T-284).</summary>
    public const int SecretstreamFilePrefixBytes = 33;

    /// <summary>The longest stream-file record: a full chunk plus tag, length and auth tag.</summary>
    public const int SecretstreamMaxRecordBytes = 8213;

    public const int SignPrivateKeyBytes = 21;
    public const int SignPublicKeyBytes = 42;
    public const int SignSignatureBytes = 42;
    public const int SignDigestBytes = 32;

    public const int Sign257PrivateKeyBytes = 33;
    public const int Sign257PublicKeyBytes = 66;
    public const int Sign257SignatureBytes = 66;
    public const int Sign257DigestBytes = 32;

    public const int StreamKeyBytes = 32;

    /// <summary>IV only - no tag, this primitive is unauthenticated by design.</summary>
    public const int StreamOverhead = 32;
}
