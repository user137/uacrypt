package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * {@code randombytes} - no rejection/misuse category (a single {@code int size} parameter, no
 * key/tag to tamper with or malform beyond what the type system already forecloses). Correctness:
 * returns the requested length, and two calls are not identical.
 */
class RandomBytesTest {
    @Test
    void returnsRequestedLength() {
        assertEquals(32, RandomBytes.buf(32).length);
    }

    @Test
    void zeroLengthReturnsEmpty() {
        assertEquals(0, RandomBytes.buf(0).length);
    }

    @Test
    void twoCallsAreNotIdentical() {
        assertFalse(java.util.Arrays.equals(RandomBytes.buf(32), RandomBytes.buf(32)));
    }
}
