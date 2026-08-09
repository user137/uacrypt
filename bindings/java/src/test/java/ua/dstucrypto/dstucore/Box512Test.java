package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_box512} - {@code l(p)=512} sibling of {@code crypto_box} (T-193/T-204). No
 * official vector exists for this composite construction (same posture as {@code crypto_box}) -
 * correctness (round trip), rejection (tampered wire segments, wrong key), misuse
 * (wrong-length/invalid key encodings, truncated input).
 */
class Box512Test {
    @Test
    void sealOpenRoundTrips() throws UnsupportedEncodingException {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey);
        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box512.seal(publicKey, message);
        assertArrayEquals(message, Box512.open(secretKey, sealed));
    }

    @Test
    void sealHandlesEmptyMessage() {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey);
        byte[] sealed = Box512.seal(publicKey, new byte[0]);
        assertArrayEquals(new byte[0], Box512.open(secretKey, sealed));
    }

    @Test
    void twoSealsUseDifferentEphemeralMaterial() throws UnsupportedEncodingException {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey);
        byte[] message = "same message twice".getBytes("UTF-8");
        assertFalse(Arrays.equals(Box512.seal(publicKey, message), Box512.seal(publicKey, message)));
    }

    @Test
    void tamperedCiphertextIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey);
        byte[] sealed = Box512.seal(publicKey, "message".getBytes("UTF-8"));
        sealed[sealed.length - 1] ^= 1;
        assertThrows(DstuException.class, () -> Box512.open(secretKey, sealed));
    }

    @Test
    void wrongSecretKeyIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey);
        byte[] otherSecretKey = Box512.keygen();
        byte[] sealed = Box512.seal(publicKey, "message".getBytes("UTF-8"));
        assertThrows(DstuException.class, () -> Box512.open(otherSecretKey, sealed));
    }

    @Test
    void wrongLengthSecretKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box512.publicKey(tooShort));
    }

    @Test
    void zeroSecretKeyIsRejected() {
        byte[] zero = new byte[64];
        assertThrows(IllegalArgumentException.class, () -> Box512.publicKey(zero));
    }

    @Test
    void wrongLengthPublicKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box512.seal(tooShort, "message".getBytes()));
    }

    @Test
    void degeneratePublicKeyXIsRejected() {
        byte[] zero = new byte[64]; // x = 0
        assertThrows(IllegalArgumentException.class, () -> Box512.seal(zero, "message".getBytes()));
    }

    @Test
    void truncatedSealedInputIsRejected() {
        byte[] secretKey = Box512.keygen();
        assertThrows(DstuException.class, () -> Box512.open(secretKey, "short".getBytes()));
    }
}
