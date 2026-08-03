package ua.dstucrypto.dstucore;

/**
 * {@code crypto_sign} - DSTU 4145, deterministic nonce, no RNG dependency for signing itself (only
 * {@link #keygen} touches the OS CSPRNG). Keys are fixed-length byte encodings: a 21-byte signing
 * key, a 42-byte uncompressed verifying key ({@code x || y}), a 42-byte signature ({@code r || s}).
 */
public final class Sign {
    static {
        NativeLoader.ensureLoaded();
    }

    private Sign() {
    }

    /** Generates a fresh 21-byte signing key from the OS CSPRNG, uniform over the valid key range. */
    public static native byte[] keygen();

    /** Derives the 42-byte public verifying key for {@code signingKey} - safe to share/publish. */
    public static native byte[] verifyingKey(byte[] signingKey);

    /** Signs {@code message} under {@code signingKey}. Returns a 42-byte signature. */
    public static native byte[] sign(byte[] signingKey, byte[] message);

    /** Verifies {@code signature} against {@code message} under {@code verifyingKey}. Returns {@code true}/{@code false} rather than throwing. */
    public static native boolean verify(byte[] verifyingKey, byte[] message, byte[] signature);
}
