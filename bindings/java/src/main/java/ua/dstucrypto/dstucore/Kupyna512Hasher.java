package ua.dstucrypto.dstucore;

/**
 * Incremental Kupyna-512 hasher - see {@link Kupyna256Hasher} for the full explanation of the
 * native-handle shape; identical except for the 64-byte digest.
 */
public final class Kupyna512Hasher implements AutoCloseable {
    static {
        NativeLoader.ensureLoaded();
    }

    private long handle;

    public Kupyna512Hasher() {
        this.handle = nativeCreate();
    }

    public void update(byte[] data) {
        checkOpen();
        nativeUpdate(handle, data);
    }

    /**
     * Consumes the accumulated state and returns the 64-byte digest. Throws
     * {@link IllegalStateException} if called more than once. Does not itself release the native
     * handle - call {@link #close}
     * (or use try-with-resources) regardless of whether {@link #finish} was called.
     */
    public byte[] finish() {
        checkOpen();
        return nativeFinalize(handle);
    }

    private void checkOpen() {
        if (handle == 0) {
            throw new IllegalStateException("Kupyna512Hasher already closed");
        }
    }

    @Override
    public void close() {
        if (handle != 0) {
            nativeFree(handle);
            handle = 0;
        }
    }

    private static native long nativeCreate();

    private static native void nativeUpdate(long handle, byte[] data);

    private static native byte[] nativeFinalize(long handle);

    private static native void nativeFree(long handle);
}
