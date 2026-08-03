package ua.dstucrypto.dstucore;

import java.util.Arrays;

/**
 * Decrypting half of a {@code crypto_secretstream} session - a direct, function-for-function
 * wrapper of the Rust {@code PullState} API. See {@link SecretStreamDecryptor} for the idiomatic
 * {@code InputStream} built on top of this.
 */
public final class SecretStreamPullState implements AutoCloseable {
    static {
        NativeLoader.ensureLoaded();
    }

    private long handle;

    /** Re-derives the stream's initial subkey from {@code key} and {@code header} (as produced by {@link SecretStreamPushState#header}). */
    public SecretStreamPullState(byte[] key, byte[] header) {
        this.handle = nativeInit(key, header);
    }

    public boolean isFinalized() {
        checkOpen();
        return nativeIsFinalized(handle);
    }

    /**
     * Verifies and decrypts one chunk. Throws {@link DstuException} if authentication fails - a
     * tampered, reordered, dropped, or spliced-from-another-stream chunk all fail here rather
     * than returning wrong plaintext.
     */
    public SecretStreamPullResult pull(int tagByte, byte[] ciphertext, byte[] authTag) {
        checkOpen();
        byte[] combined = nativePull(handle, tagByte, ciphertext, authTag);
        SecretStreamTag tag = SecretStreamTag.values()[combined[0]];
        byte[] plaintext = Arrays.copyOfRange(combined, 1, combined.length);
        return new SecretStreamPullResult(tag, plaintext);
    }

    private void checkOpen() {
        if (handle == 0) {
            throw new IllegalStateException("SecretStreamPullState already closed");
        }
    }

    @Override
    public void close() {
        if (handle != 0) {
            nativeFree(handle);
            handle = 0;
        }
    }

    private static native long nativeInit(byte[] key, byte[] header);

    private static native boolean nativeIsFinalized(long handle);

    private static native byte[] nativePull(long handle, int tagByte, byte[] ciphertext, byte[] authTag);

    private static native void nativeFree(long handle);
}
