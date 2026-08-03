package ua.dstucrypto.dstucore;

/**
 * {@code crypto_generichash} - Kupyna-256/512. One-shot methods for a whole in-memory message;
 * see {@link Kupyna256Hasher}/{@link Kupyna512Hasher} for an incremental, streamed digest of the
 * same construction.
 */
public final class GenericHash {
    static {
        NativeLoader.ensureLoaded();
    }

    private GenericHash() {
    }

    /** Computes the 32-byte Kupyna-256 digest of {@code message}. */
    public static native byte[] hash256(byte[] message);

    /** Computes the 64-byte Kupyna-512 digest of {@code message}. */
    public static native byte[] hash512(byte[] message);
}
