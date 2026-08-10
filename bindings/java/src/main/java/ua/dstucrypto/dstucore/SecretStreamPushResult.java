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

    // Defensive copies (SpotBugs EI_EXPOSE_REP, T-208) - see SecretStreamPullResult's own comment
    // on this for the reasoning.
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    public byte[] authTag() {
        return authTag.clone();
    }
}
