package ua.dstucrypto.dstucore;

/**
 * {@code crypto_pwhash} - Argon2id, the one deliberately non-DSTU component.
 */
public final class Pwhash {
    static {
        NativeLoader.ensureLoaded();
    }

    private Pwhash() {
    }

    /** Hashes {@code password} into a self-describing PHC string, using a fresh random salt. */
    public static String hashPassword(byte[] password, PwhashStrength strength) {
        return nativeHashPassword(password, strength.ordinal());
    }

    /** Verifies {@code password} against a PHC string produced by {@link #hashPassword}. Returns {@code false} for both a wrong password and a malformed hash string. */
    public static native boolean verifyPassword(byte[] password, String hash);

    /**
     * Derives a 32-byte key from {@code password} and a 16-byte {@code salt} - libsodium's
     * {@code crypto_pwhash} (Argon2id v1.3), byte for byte (T-269). Runs on the calling thread.
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, PwhashStrength strength) {
        return nativeDeriveKey(password, salt, strength.ordinal());
    }

    private static native String nativeHashPassword(byte[] password, int strength);

    private static native byte[] nativeDeriveKey(byte[] password, byte[] salt, int strength);
}
