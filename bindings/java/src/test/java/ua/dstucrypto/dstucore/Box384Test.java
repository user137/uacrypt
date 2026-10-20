package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_box384} - {@code l(p)=384} sibling of {@code crypto_box} (T-297). No
 * official vector exists for this composite construction (same posture as {@code crypto_box}) -
 * correctness (round trip), rejection (tampered wire segments, wrong key), misuse
 * (wrong-length/invalid key encodings, truncated input).
 */
class Box384Test {
    @Test
    void sealOpenRoundTrips() throws UnsupportedEncodingException {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey);
        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box384.seal(publicKey, message);
        assertArrayEquals(message, Box384.open(secretKey, sealed));
    }

    @Test
    void sealHandlesEmptyMessage() {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey);
        byte[] sealed = Box384.seal(publicKey, new byte[0]);
        assertArrayEquals(new byte[0], Box384.open(secretKey, sealed));
    }

    @Test
    void twoSealsUseDifferentEphemeralMaterial() throws UnsupportedEncodingException {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey);
        byte[] message = "same message twice".getBytes("UTF-8");
        assertFalse(Arrays.equals(Box384.seal(publicKey, message), Box384.seal(publicKey, message)));
    }

    @Test
    void tamperedCiphertextIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey);
        byte[] sealed = Box384.seal(publicKey, "message".getBytes("UTF-8"));
        sealed[sealed.length - 1] ^= 1;
        assertThrows(DstuException.class, () -> Box384.open(secretKey, sealed));
    }

    @Test
    void wrongSecretKeyIsRejected() throws UnsupportedEncodingException {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey);
        byte[] otherSecretKey = Box384.keygen();
        byte[] sealed = Box384.seal(publicKey, "message".getBytes("UTF-8"));
        assertThrows(DstuException.class, () -> Box384.open(otherSecretKey, sealed));
    }

    @Test
    void wrongLengthSecretKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box384.publicKey(tooShort));
    }

    @Test
    void zeroSecretKeyIsRejected() {
        byte[] zero = new byte[48];
        assertThrows(IllegalArgumentException.class, () -> Box384.publicKey(zero));
    }

    @Test
    void wrongLengthPublicKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Box384.seal(tooShort, "message".getBytes()));
    }

    @Test
    void degeneratePublicKeyXIsRejected() {
        byte[] zero = new byte[48]; // x = 0
        assertThrows(IllegalArgumentException.class, () -> Box384.seal(zero, "message".getBytes()));
    }

    @Test
    void truncatedSealedInputIsRejected() {
        byte[] secretKey = Box384.keygen();
        assertThrows(DstuException.class, () -> Box384.open(secretKey, "short".getBytes()));
    }
}
