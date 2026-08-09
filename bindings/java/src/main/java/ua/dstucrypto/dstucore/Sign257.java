package ua.dstucrypto.dstucore;

/**
 * {@code crypto_sign257} - DSTU 4145 {@code m=257} (T-199/T-204), the curve real Diia-issued
 * qualified signatures use. Same shape as {@link Sign}, a distinct class - not interchangeable
 * with {@code crypto_sign}'s {@code m=163}. Deterministic nonce, no RNG dependency for signing
 * itself (only {@link #keygen} touches the OS CSPRNG). Keys are fixed-length byte encodings: a
 * 33-byte signing key, a 66-byte uncompressed verifying key ({@code x || y}), a 66-byte signature
 * ({@code r || s}).
 */
public final class Sign257 {
    static {
        NativeLoader.ensureLoaded();
    }

    private Sign257() {
    }

    /** Generates a fresh 33-byte signing key from the OS CSPRNG, uniform over the valid key range. */
    public static native byte[] keygen();

    /** Derives the 66-byte public verifying key for {@code signingKey} - safe to share/publish. */
    public static native byte[] verifyingKey(byte[] signingKey);

    /** Signs {@code message} under {@code signingKey}. Returns a 66-byte signature. */
    public static native byte[] sign(byte[] signingKey, byte[] message);

    /** Verifies {@code signature} against {@code message} under {@code verifyingKey}. Returns {@code true}/{@code false} rather than throwing. */
    public static native boolean verify(byte[] verifyingKey, byte[] message, byte[] signature);
}
