package ua.dstucrypto.dstucore;

/**
 * {@link Pwhash} cost preset - mirrors {@code dstu_core::crypto_pwhash::Strength}'s three named
 * presets exactly (libsodium's own constants). The ordinal (declaration order) is the wire value
 * the native layer expects - do not reorder these constants.
 */
public enum PwhashStrength {
    INTERACTIVE,
    MODERATE,
    SENSITIVE
}
