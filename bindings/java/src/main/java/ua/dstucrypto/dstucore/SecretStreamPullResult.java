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

    // Defensive copy (SpotBugs EI_EXPOSE_REP, T-208): a Java array stays mutable through a `final`
    // field, so returning `plaintext` directly would let a caller mutate this otherwise-immutable
    // value object's internal state via the returned reference.
    public byte[] plaintext() {
        return plaintext.clone();
    }
}
