package ua.dstucrypto.dstucore;

/**
 * {@code crypto_secretstream} - see {@link SecretStreamPushState}/{@link SecretStreamPullState}
 * for the raw, function-for-function state machine, or {@link SecretStreamEncryptor}/
 * {@link SecretStreamDecryptor} for the idiomatic {@code OutputStream}/{@code InputStream} pair
 * built on top of it.
 */
public final class SecretStream {
    static {
        NativeLoader.ensureLoaded();
    }

    private SecretStream() {
    }

    /** Generates a fresh 32-byte master key from the OS CSPRNG. */
    public static native byte[] keygen();
}
