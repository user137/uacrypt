package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code crypto_pwhash} (Argon2id, the one deliberately non-DSTU component, D-49/D-50).
 * Correctness: round trip. Rejection: wrong password, malformed hash string. {@code strength}'s
 * misuse category ("invalid strength value") is foreclosed by the type system here - it takes a
 * {@link PwhashStrength} enum, not a raw int, unlike Python's `PWHASH_*` int constants - so there
 * is nothing invalid to construct through the public API (see D-153's own note on this).
 * {@link PwhashStrength#INTERACTIVE} is used throughout (not the moderate default) so this class's
 * own tests stay fast.
 */
class PwhashTest {
    @Test
    void hashVerifyRoundTrips() throws Exception {
        String stored = Pwhash.hashPassword("correct horse battery staple".getBytes("UTF-8"), PwhashStrength.INTERACTIVE);
        assertTrue(Pwhash.verifyPassword("correct horse battery staple".getBytes("UTF-8"), stored));
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        String stored = Pwhash.hashPassword("correct horse battery staple".getBytes("UTF-8"), PwhashStrength.INTERACTIVE);
        assertFalse(Pwhash.verifyPassword("wrong guess".getBytes("UTF-8"), stored));
    }

    @Test
    void malformedHashStringIsRejected() throws Exception {
        assertFalse(Pwhash.verifyPassword("anything".getBytes("UTF-8"), "not a real PHC string"));
    }
}
