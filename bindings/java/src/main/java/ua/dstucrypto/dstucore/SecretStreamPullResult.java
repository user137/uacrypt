package ua.dstucrypto.dstucore;

/**
 * The result of {@link SecretStreamPullState#pull} - a named-field result object, matching
 * {@link SecretStreamPushResult}.
 */
public final class SecretStreamPullResult {
    private final SecretStreamTag tag;
    private final byte[] plaintext;

    SecretStreamPullResult(SecretStreamTag tag, byte[] plaintext) {
        this.tag = tag;
        this.plaintext = plaintext;
    }

    public SecretStreamTag tag() {
        return tag;
    }

    public byte[] plaintext() {
        return plaintext;
    }
}
