package ua.dstucrypto.dstucore;

/**
 * OS CSPRNG access, via {@code getrandom}.
 */
public final class RandomBytes {
    static {
        NativeLoader.ensureLoaded();
    }

    private RandomBytes() {
    }

    /**
     * Returns {@code size} cryptographically secure random bytes from the OS CSPRNG.
     */
    public static native byte[] buf(int size);
}
