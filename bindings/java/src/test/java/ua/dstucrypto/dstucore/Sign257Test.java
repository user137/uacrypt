package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code crypto_sign257} (DSTU 4145 {@code m=257}) - {@code m=257} sibling of {@code crypto_sign}
 * (T-199/T-204). Correctness (round trip, determinism of the nonce derivation), rejection (wrong
 * message/wrong key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying
 * key/signature).
 */
class Sign257Test {
    @Test
    void signVerifyRoundTrips() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] verifyingKey = Sign257.verifyingKey(signingKey);
        byte[] message = "a message whose origin and integrity matter".getBytes("UTF-8");
        byte[] signature = Sign257.sign(signingKey, message);
        assertTrue(Sign257.verify(verifyingKey, message, signature));
    }

    @Test
    void signingIsDeterministic() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] message = "same message every time".getBytes("UTF-8");
        assertArrayEquals(Sign257.sign(signingKey, message), Sign257.sign(signingKey, message));
    }

    @Test
    void wrongMessageIsRejected() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] verifyingKey = Sign257.verifyingKey(signingKey);
        byte[] signature = Sign257.sign(signingKey, "original message".getBytes("UTF-8"));
        assertFalse(Sign257.verify(verifyingKey, "a different message".getBytes("UTF-8"), signature));
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] otherVerifyingKey = Sign257.verifyingKey(Sign257.keygen());
        byte[] message = "message".getBytes("UTF-8");
        byte[] signature = Sign257.sign(signingKey, message);
        assertFalse(Sign257.verify(otherVerifyingKey, message, signature));
    }

    @Test
    void zeroSigningKeyIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> Sign257.verifyingKey(new byte[33]));
    }

    @Test
    void wrongLengthSigningKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign257.sign(tooShort, "message".getBytes()));
    }

    @Test
    void wrongLengthVerifyingKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign257.verify(tooShort, "message".getBytes(), new byte[66]));
    }

    @Test
    void wrongLengthSignatureIsRejected() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] verifyingKey = Sign257.verifyingKey(signingKey);
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Sign257.verify(verifyingKey, "message".getBytes(), tooShort));
    }
}
