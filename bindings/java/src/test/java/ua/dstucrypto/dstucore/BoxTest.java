package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_box} - no official vector exists for this composite construction (same posture as
 * {@code crypto_secretbox}, D-51/D-169's own "Provenance" section) - correctness (round trip,
 * including a message larger than the 25-byte KEM payload), rejection (tampered wire segments,
 * wrong key), misuse (wrong-length/invalid key encodings, truncated input).
 */
class BoxTest {
    @Test
    void sealOpenRoundTrips() throws UnsupportedEncodingException {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box.seal(publicKey, message);
        assertArrayEquals(message, Box.open(secretKey, sealed));
    }

    @Test
    void sealHandlesEmptyMessage() {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] sealed = Box.seal(publicKey, new byte[0]);
        assertArrayEquals(new byte[0], Box.open(secretKey, sealed));
    }

    @Test
    void sealHandlesMessageLargerThanTheKemPayload() {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] message = new byte[10_000];
        Arrays.fill(message, (byte) 'x');
        byte[] sealed = Box.seal(publicKey, message);
        assertArrayEquals(message, Box.open(secretKey, sealed));
    }

    @Test
    void twoSealsUseDifferentEphemeralMaterial() throws UnsupportedEncodingException {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] message = "same message twice".getBytes("UTF-8");
        assertFalse(Arrays.equals(Box.seal(publicKey, message), Box.seal(publicKey, message)));
    }

    @Test
    void tamperedKemPrefixIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] sealed = Box.seal(publicKey, "message".getBytes("UTF-8"));
        sealed[0] ^= 1;
        assertThrows(DstuException.class, () -> Box.open(secretKey, sealed));
    }

    @Test
    void tamperedCiphertextIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] sealed = Box.seal(publicKey, "message".getBytes("UTF-8"));
        sealed[sealed.length - 1] ^= 1;
        assertThrows(DstuException.class, () -> Box.open(secretKey, sealed));
    }

    @Test
    void wrongSecretKeyIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey);
        byte[] otherSecretKey = Box.keygen();
        byte[] sealed = Box.seal(publicKey, "message".getBytes("UTF-8"));
        assertThrows(DstuException.class, () -> Box.open(otherSecretKey, sealed));
    }

    @Test
    void wrongLengthSecretKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box.publicKey(tooShort));
    }

    @Test
    void zeroSecretKeyIsRejected() {
        byte[] zero = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> Box.publicKey(zero));
    }

    @Test
    void wrongLengthPublicKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box.seal(tooShort, "message".getBytes()));
    }

    @Test
    void degeneratePublicKeyXIsRejected() {
        byte[] zero = new byte[32]; // x = 0
        assertThrows(IllegalArgumentException.class, () -> Box.seal(zero, "message".getBytes()));
    }

    @Test
    void truncatedSealedInputIsRejected() {
        byte[] secretKey = Box.keygen();
        assertThrows(DstuException.class, () -> Box.open(secretKey, "short".getBytes()));
    }
}
