import ua.dstucrypto.dstucore.Box;
import ua.dstucrypto.dstucore.DstuException;

import java.util.Arrays;

/** {@code crypto_box}: generate a keypair, seal a message to the public key, open it with the
 * secret key. */
final class BoxExample {
    private BoxExample() {
    }

    static void run() throws Exception {
        byte[] secretKey = Box.keygen();
        byte[] publicKey = Box.publicKey(secretKey); // safe to share/publish

        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box.seal(publicKey, message);
        byte[] opened = Box.open(secretKey, sealed);
        if (!Arrays.equals(opened, message)) {
            throw new IllegalStateException("round trip failed");
        }
        System.out.println("sealed " + opened.length + " bytes -> " + sealed.length + " bytes, round-tripped OK");

        sealed[sealed.length - 1] ^= 1;
        try {
            Box.open(secretKey, sealed);
        } catch (DstuException e) {
            System.out.println("tampered ciphertext correctly rejected");
        }
    }
}
