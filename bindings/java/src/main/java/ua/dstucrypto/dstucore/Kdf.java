package ua.dstucrypto.dstucore;

/**
 * {@code crypto_kdf} - Kupyna-256-KDF.
 */
public final class Kdf {
    static {
        NativeLoader.ensureLoaded();
    }

    private Kdf() {
    }

    /** Generates a fresh 32-byte master key from the OS CSPRNG. */
    public static native byte[] keygen();

    /**
     * Derives a 32-byte subkey from {@code masterKey}. {@code context} must be exactly 8 bytes.
     * Different {@code subkeyId}/{@code context} values (holding the others fixed) produce
     * different, unrelated-looking subkeys; the same inputs always re-derive the same subkey.
     */
    public static native byte[] deriveSubkey(byte[] masterKey, long subkeyId, byte[] context);
}
