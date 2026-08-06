package ua.dstucrypto.dstucore;

/**
 * {@code crypto_box} - public-key encryption (hybrid via KDF over {@code hazmat::dstu9041},
 * D-169). {@link #seal} and {@link #open} are not memory-bounded - the whole message is held in
 * memory.
 */
public final class Box {
    static {
        NativeLoader.ensureLoaded();
    }

    private Box() {
    }

    /** Generates a fresh 32-byte secret key from the OS CSPRNG. */
    public static native byte[] keygen();

    /**
     * Derives the 32-byte public key for {@code secretKey} - safe to share/publish (the curve
     * point's {@code x}-coordinate only, see {@code dstu_core::crypto_box}'s own module doc for
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
