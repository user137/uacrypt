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

    /// <summary>128-byte KEM ciphertext + 32-byte secretstream header + 16-byte tag.</summary>
    public const int BoxSealOverhead = 176;

    public const int Box512SecretKeyBytes = 64;
    public const int Box512PublicKeyBytes = 64;

    /// <summary>256-byte KEM ciphertext + 32-byte secretstream header + 16-byte tag.</summary>
    public const int Box512SealOverhead = 304;

    public const int GenericHash256Bytes = 32;
    public const int GenericHash512Bytes = 64;

    public const int KdfKeyBytes = 32;
    public const int KdfContextBytes = 8;
    public const int KdfSubkeyBytes = 32;

    /// <summary>Fixed buffer size for a PHC string produced by <see cref="Pwhash.HashPassword"/>.</summary>
    public const int PwhashStrBytes = 128;

    public const int SecretboxKeyBytes = 32;

    /// <summary>32-byte nonce + 16-byte tag.</summary>
    public const int SecretboxOverhead = 48;

    public const int SecretstreamKeyBytes = 32;
    public const int SecretstreamHeaderBytes = 32;
    public const int SecretstreamTagBytes = 16;

    /// <summary>Plaintext chunk size this binding's stream wrapper frames at - matches every other
    /// binding's own <c>SECRETSTREAM_CHUNK_BYTES</c> and <c>uacrypt</c>'s own CLI chunking.</summary>
    public const int SecretstreamChunkBytes = 8192;

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
