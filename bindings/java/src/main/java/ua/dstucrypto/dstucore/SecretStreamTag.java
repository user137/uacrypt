package ua.dstucrypto.dstucore;

/**
 * A chunk's role in a {@code crypto_secretstream} session - mirrors
 * {@code dstu_core::crypto_secretstream::Tag} exactly. The ordinal (declaration order) is the
 * wire byte value - do not reorder these constants.
 */
public enum SecretStreamTag {
    MESSAGE,
    PUSH,
    REKEY,
    FINAL
}
