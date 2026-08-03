package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_kdf} - no official vector exists for this construction (D-45). Correctness here
 * means determinism/distinctness. Misuse: wrong-length master key/context.
 */
class KdfTest {
    @Test
    void deriveSubkeyIsDeterministic() {
        byte[] masterKey = Kdf.keygen();
        assertArrayEquals(
                Kdf.deriveSubkey(masterKey, 0, "encrypt_".getBytes()),
                Kdf.deriveSubkey(masterKey, 0, "encrypt_".getBytes()));
    }

    @Test
    void differentSubkeyIdGivesDifferentSubkey() {
        byte[] masterKey = Kdf.keygen();
        byte[] a = Kdf.deriveSubkey(masterKey, 0, "context1".getBytes());
        byte[] b = Kdf.deriveSubkey(masterKey, 1, "context1".getBytes());
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void differentContextGivesDifferentSubkey() {
        byte[] masterKey = Kdf.keygen();
        byte[] a = Kdf.deriveSubkey(masterKey, 0, "context1".getBytes());
        byte[] b = Kdf.deriveSubkey(masterKey, 0, "context2".getBytes());
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void wrongLengthMasterKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> Kdf.deriveSubkey(tooShort, 0, "context1".getBytes()));
    }

    @Test
    void wrongLengthContextIsRejected() {
        byte[] masterKey = Kdf.keygen();
        assertThrows(IllegalArgumentException.class, () -> Kdf.deriveSubkey(masterKey, 0, "short".getBytes()));
    }
}
