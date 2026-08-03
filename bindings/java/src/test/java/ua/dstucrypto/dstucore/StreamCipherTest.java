package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_stream} (Strumok-256 keystream) - <strong>no authentication</strong>: no
 * rejection category, since there is no tag to tamper with - {@link StreamCipher#decrypt} never
 * fails on tampered input, it silently returns different, wrong plaintext instead. Correctness:
 * round trip. Misuse: wrong-length key, truncated input.
 */
class StreamCipherTest {
    @Test
    void encryptDecryptRoundTrips() throws Exception {
        byte[] key = StreamCipher.keygen();
        byte[] sealed = StreamCipher.encrypt(key, "message".getBytes("UTF-8"));
        assertArrayEquals("message".getBytes("UTF-8"), StreamCipher.decrypt(key, sealed));
    }

    /**
     * Documents the no-integrity property explicitly, per this project's own precedent
     * ({@code hazmat::kalyna_xts}'s tampered-ciphertext test) - a deliberate design property, not
     * a missing rejection test.
     */
    @Test
    void tamperingIsNotDetectedButProducesWrongPlaintext() throws Exception {
        byte[] key = StreamCipher.keygen();
        byte[] sealed = StreamCipher.encrypt(key, "message".getBytes("UTF-8"));
        sealed[sealed.length - 1] ^= 1;
        byte[] garbage = StreamCipher.decrypt(key, sealed);
        assertFalse(java.util.Arrays.equals(garbage, "message".getBytes("UTF-8")));
    }

    @Test
    void wrongLengthKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> StreamCipher.encrypt(tooShort, "message".getBytes()));
    }

    @Test
    void truncatedSealedInputIsRejected() {
        byte[] key = StreamCipher.keygen();
        assertThrows(DstuException.class, () -> StreamCipher.decrypt(key, "short".getBytes()));
    }
}
