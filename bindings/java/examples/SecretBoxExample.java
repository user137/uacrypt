import ua.dstucrypto.dstucore.DstuException;
import ua.dstucrypto.dstucore.SecretBox;

import java.util.Arrays;

/** {@code crypto_secretbox}: seal/open a single message with a symmetric key. */
final class SecretBoxExample {
    private SecretBoxExample() {
    }

    static void run() throws Exception {
        byte[] key = SecretBox.keygen();
        byte[] plaintext = "a message worth protecting".getBytes("UTF-8");
        byte[] sealed = SecretBox.seal(key, plaintext);
        byte[] opened = SecretBox.open(key, sealed);
        if (!Arrays.equals(opened, plaintext)) {
            throw new IllegalStateException("round trip failed");
        }
        System.out.println("sealed " + opened.length + " bytes -> " + sealed.length + " bytes, round-tripped OK");

        sealed[sealed.length - 1] ^= 1;
        try {
            SecretBox.open(key, sealed);
        } catch (DstuException e) {
            System.out.println("tampered ciphertext correctly rejected");
        }
    }
}
