package ua.dstucrypto.dstucore;

/**
 * The result of {@link SecretStreamPushState#push} - a named-field result object rather than a
 * raw pair, matching this project's Node.js binding's own {@code SecretStreamPushResult} shape
 * (D-127).
 */
public final class SecretStreamPushResult {
    private final byte[] ciphertext;
    private final byte[] authTag;

    SecretStreamPushResult(byte[] ciphertext, byte[] authTag) {
        this.ciphertext = ciphertext;
        this.authTag = authTag;
    }

    public byte[] ciphertext() {
        return ciphertext;
    }

    public byte[] authTag() {
        return authTag;
    }
}
