package ua.dstucrypto.dstucore;

/**
 * {@code crypto_secretbox} - Kalyna-256/256-GCM, internal nonce, no caller-facing AAD.
 */
public final class SecretBox {
    static {
        NativeLoader.ensureLoaded();
    }

    private SecretBox() {
    }

    /** Generates a fresh 32-byte key from the OS CSPRNG. */
    public static native byte[] keygen();

    /** Encrypts and authenticates {@code plaintext} under {@code key}. Returns {@code nonce || ciphertext || tag}. */
    public static native byte[] seal(byte[] key, byte[] plaintext);

    /**
     * Verifies and decrypts {@code sealed} (as produced by {@link #seal}) under {@code key}.
     * Throws {@link DstuException} if authentication fails or {@code sealed} is too short.
     */
    public static native byte[] open(byte[] key, byte[] sealed);
}
