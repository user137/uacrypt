package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code crypto_sign} (DSTU 4145) - the official Annex B.1 verify vector is already covered by
 * {@link Selftest}; this class covers what that single vector doesn't reach: correctness (round
 * trip, determinism of the nonce derivation), rejection (wrong message/wrong key), misuse
 * (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
 */
class SignTest {
    @Test
    void signVerifyRoundTrips() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);
        byte[] message = "a message whose origin and integrity matter".getBytes("UTF-8");
        byte[] signature = Sign.sign(signingKey, message);
        assertTrue(Sign.verify(verifyingKey, message, signature));
    }

    /** D-46: the ephemeral nonce is derived deterministically, not from an RNG. */
    @Test
    void signingIsDeterministic() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] message = "same message every time".getBytes("UTF-8");
        assertArrayEquals(Sign.sign(signingKey, message), Sign.sign(signingKey, message));
    }

    @Test
    void wrongMessageIsRejected() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);
        byte[] signature = Sign.sign(signingKey, "original message".getBytes("UTF-8"));
        assertFalse(Sign.verify(verifyingKey, "a different message".getBytes("UTF-8"), signature));
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] otherVerifyingKey = Sign.verifyingKey(Sign.keygen());
        byte[] message = "message".getBytes("UTF-8");
        byte[] signature = Sign.sign(signingKey, message);
        assertFalse(Sign.verify(otherVerifyingKey, message, signature));
    }

    @Test
    void zeroSigningKeyIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> Sign.verifyingKey(new byte[21]));
    }

    @Test
    void wrongLengthSigningKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign.sign(tooShort, "message".getBytes()));
    }

    @Test
    void wrongLengthVerifyingKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign.verify(tooShort, "message".getBytes(), new byte[42]));
    }

    @Test
    void wrongLengthSignatureIsRejected() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign.verify(verifyingKey, "message".getBytes(), tooShort));
    }
}
