package ua.dstucrypto.dstucore;

/**
 * {@code crypto_auth} - Kupyna-256-KMAC.
 */
public final class Auth {
    static {
        NativeLoader.ensureLoaded();
    }

    private Auth() {
    }

    /** Generates a fresh 32-byte key from the OS CSPRNG. */
    public static native byte[] keygen();

    /** Computes the 32-byte MAC of {@code message} under {@code key}. */
    public static native byte[] auth(byte[] key, byte[] message);

    /** Verifies {@code tag} against {@code message} under {@code key}. Throws {@link DstuException} on mismatch. */
    public static native void verify(byte[] key, byte[] message, byte[] tag);
}
