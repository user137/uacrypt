package ua.dstucrypto.dstucore;

import java.util.Arrays;

/**
 * Encrypting half of a {@code crypto_secretstream} session - a direct, function-for-function
 * wrapper of the Rust {@code PushState} API. See {@link SecretStreamEncryptor} for the idiomatic
 * {@code OutputStream} built on top of this.
 */
public final class SecretStreamPushState implements AutoCloseable {
    private static final int AUTH_TAG_BYTES = 16;

    static {
        NativeLoader.ensureLoaded();
    }

    private long handle;

    /** Starts a new stream under {@code key}. */
    public SecretStreamPushState(byte[] key) {
        this.handle = nativeInit(key);
    }

    /**
     * This stream's 32-byte header - must be transmitted/stored alongside the encrypted chunks;
     * a {@link SecretStreamPullState} needs it to decrypt them.
     */
    public byte[] header() {
        checkOpen();
        return nativeHeader(handle);
    }

    public boolean isFinalized() {
        checkOpen();
        return nativeIsFinalized(handle);
    }

    /**
     * Encrypts {@code plaintext}. The caller must transmit the returned ciphertext, auth tag, and
     * {@code tag} itself for {@link SecretStreamPullState#pull} to recover the plaintext.
     */
    public SecretStreamPushResult push(SecretStreamTag tag, byte[] plaintext) {
        checkOpen();
        byte[] combined = nativePush(handle, tag.ordinal(), plaintext);
        int ciphertextLen = combined.length - AUTH_TAG_BYTES;
        byte[] ciphertext = Arrays.copyOfRange(combined, 0, ciphertextLen);
        byte[] authTag = Arrays.copyOfRange(combined, ciphertextLen, combined.length);
        return new SecretStreamPushResult(ciphertext, authTag);
    }

    private void checkOpen() {
        if (handle == 0) {
            throw new IllegalStateException("SecretStreamPushState already closed");
        }
    }

    @Override
    public void close() {
        if (handle != 0) {
            nativeFree(handle);
            handle = 0;
        }
    }

    private static native long nativeInit(byte[] key);

    private static native byte[] nativeHeader(long handle);

    private static native boolean nativeIsFinalized(long handle);

    private static native byte[] nativePush(long handle, int tagByte, byte[] plaintext);

    private static native void nativeFree(long handle);
}
