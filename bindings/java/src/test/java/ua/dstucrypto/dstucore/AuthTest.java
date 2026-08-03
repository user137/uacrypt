package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_auth} - three categories per D-64/D-65: correctness (round trip), rejection
 * (tampered message, wrong key), misuse (wrong-length key/tag).
 */
class AuthTest {
    private static byte[] bytes(String s) throws UnsupportedEncodingException {
        return s.getBytes("UTF-8");
    }

    @Test
    void authVerifyRoundTrips() throws Exception {
        byte[] key = Auth.keygen();
        byte[] tag = Auth.auth(key, bytes("a message both parties want to confirm is unmodified"));
        Auth.verify(key, bytes("a message both parties want to confirm is unmodified"), tag);
    }

    @Test
    void tamperedMessageIsRejected() throws Exception {
        byte[] key = Auth.keygen();
        byte[] tag = Auth.auth(key, bytes("original message"));
        assertThrows(DstuException.class, () -> Auth.verify(key, bytes("a different message"), tag));
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        byte[] key = Auth.keygen();
        byte[] otherKey = Auth.keygen();
        byte[] tag = Auth.auth(key, bytes("message"));
        assertThrows(DstuException.class, () -> Auth.verify(otherKey, bytes("message"), tag));
    }

    @Test
    void wrongLengthKeyIsRejected() throws Exception {
        byte[] tooShort = bytes("too short");
        assertThrows(IllegalArgumentException.class, () -> Auth.auth(tooShort, bytes("message")));
    }

    @Test
    void wrongLengthTagIsRejected() throws Exception {
        byte[] key = Auth.keygen();
        byte[] tooShort = bytes("too short");
        assertThrows(IllegalArgumentException.class, () -> Auth.verify(key, bytes("message"), tooShort));
    }
}
