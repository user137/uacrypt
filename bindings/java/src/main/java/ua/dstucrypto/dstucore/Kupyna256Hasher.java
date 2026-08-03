package ua.dstucrypto.dstucore;

/**
 * Incremental Kupyna-256 hasher - call {@link #update} any number of times, then {@link #finish}
 * once. Holds a native handle (the first genuinely stateful object in this binding - plain
 * {@code jni} has no {@code #[pyclass]}/{@code #[napi]}-style generated wrapper, so the Rust
 * hasher state is boxed and referenced here by an opaque {@code long}, freed explicitly via
 * {@link #close}).
 */
public final class Kupyna256Hasher implements AutoCloseable {
    static {
        NativeLoader.ensureLoaded();
    }

    private long handle;

    public Kupyna256Hasher() {
        this.handle = nativeCreate();
    }

    public void update(byte[] data) {
        checkOpen();
        nativeUpdate(handle, data);
    }

    /**
     * Consumes the accumulated state and returns the 32-byte digest. Throws
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
            throw new IllegalStateException("Kupyna256Hasher already closed");
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
