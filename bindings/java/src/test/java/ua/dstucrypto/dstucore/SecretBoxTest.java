package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_secretbox} - three test categories per D-64/D-65: correctness (round trip, no
 * official vector exists for this construction, D-51), rejection (tamper/wrong key), misuse
 * (wrong-length key, truncated input).
 */
class SecretBoxTest {
    @Test
    void sealOpenRoundTrips() throws Exception {
        byte[] key = SecretBox.keygen();
        byte[] sealed = SecretBox.seal(key, "a message worth protecting".getBytes("UTF-8"));
        assertArrayEquals("a message worth protecting".getBytes("UTF-8"), SecretBox.open(key, sealed));
    }

    @Test
    void sealHandlesEmptyMessage() {
        byte[] key = SecretBox.keygen();
        byte[] sealed = SecretBox.seal(key, new byte[0]);
        assertArrayEquals(new byte[0], SecretBox.open(key, sealed));
    }

    @Test
    void tamperedCiphertextIsRejected() throws Exception {
        byte[] key = SecretBox.keygen();
        byte[] sealed = SecretBox.seal(key, "message".getBytes("UTF-8"));
        sealed[sealed.length - 1] ^= 1;
        assertThrows(DstuException.class, () -> SecretBox.open(key, sealed));
    }

    @Test
    void tamperedNonceIsRejected() throws Exception {
        byte[] key = SecretBox.keygen();
        byte[] sealed = SecretBox.seal(key, "message".getBytes("UTF-8"));
        sealed[0] ^= 1; // first byte of the nonce
        assertThrows(DstuException.class, () -> SecretBox.open(key, sealed));
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        byte[] key = SecretBox.keygen();
        byte[] otherKey = SecretBox.keygen();
        byte[] sealed = SecretBox.seal(key, "message".getBytes("UTF-8"));
        assertThrows(DstuException.class, () -> SecretBox.open(otherKey, sealed));
    }

    @Test
    void wrongLengthKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> SecretBox.seal(tooShort, "message".getBytes()));
    }

    @Test
    void truncatedSealedInputIsRejected() {
        byte[] key = SecretBox.keygen();
        assertThrows(DstuException.class, () -> SecretBox.open(key, "short".getBytes()));
    }
}
