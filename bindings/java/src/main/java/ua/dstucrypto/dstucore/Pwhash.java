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

    private static native String nativeHashPassword(byte[] password, int strength);
}
