package ua.dstucrypto.dstucore;

/**
 * {@code crypto_box512} - the {@code l(p)=512} (E512/1) sibling of {@link Box} (T-193/T-204).
 * Same shape, a distinct class - not interchangeable with {@code crypto_box}. {@link #seal} and
 * {@link #open} are not memory-bounded - the whole message is held in memory.
 */
public final class Box512 {
    static {
        NativeLoader.ensureLoaded();
    }

    private Box512() {
    }

    /** Generates a fresh 64-byte secret key from the OS CSPRNG. */
    public static native byte[] keygen();

    /**
     * Derives the 64-byte public key for {@code secretKey} - safe to share/publish (the curve
     * point's {@code x}-coordinate only, see {@code dstu_core::crypto_box512}'s own module doc for
     * why this is a safe compression).
     */
    public static native byte[] publicKey(byte[] secretKey);

    /**
     * Encrypts {@code message} (any length) to the holder of {@code publicKey}, drawing a fresh
     * random seed and ephemeral key internally.
     */
    public static native byte[] seal(byte[] publicKey, byte[] message);

    /**
     * Decrypts {@code sealed} (as produced by {@link #seal}) under {@code secretKey}. Throws
     * {@link DstuException} if authentication fails (wrong key, or any tampered wire segment -
     * deliberately not distinguished further) or {@code sealed} is too short to be valid.
     */
    public static native byte[] open(byte[] secretKey, byte[] sealed);
}
