package ua.dstucrypto.dstucore;

/**
 * {@code crypto_stream} - Strumok-256 keystream, internal IV. <strong>No authentication</strong> -
 * {@link #decrypt} never fails on tampered input, it returns different, silently-wrong plaintext
 * instead. Prefer {@link SecretBox}/{@link SecretStream} unless integrity is handled elsewhere.
 * Named {@code StreamCipher}, not {@code Stream}, to avoid colliding with
 * {@code java.util.stream.Stream}.
 */
public final class StreamCipher {
    static {
        NativeLoader.ensureLoaded();
    }

    private StreamCipher() {
    }

    /** Generates a fresh 32-byte key from the OS CSPRNG. */
    public static native byte[] keygen();

    /** XORs {@code plaintext} with a fresh keystream under {@code key}. Returns {@code iv || ciphertext}. */
    public static native byte[] encrypt(byte[] key, byte[] plaintext);

    /** Reverses {@link #encrypt} under {@code key}. Throws {@link DstuException} only if {@code sealed} is too short to contain an IV. */
    public static native byte[] decrypt(byte[] key, byte[] sealed);
}
