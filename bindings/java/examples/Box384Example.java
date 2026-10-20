import ua.dstucrypto.dstucore.Box384;
import ua.dstucrypto.dstucore.DstuException;

import java.util.Arrays;

/** {@code crypto_box384} ({@code l(p)=384} sibling of {@code crypto_box}, T-297): generate
 * a keypair, seal a message to the public key, open it with the secret key. */
final class Box384Example {
    private Box384Example() {
    }

    static void run() throws Exception {
        byte[] secretKey = Box384.keygen();
        byte[] publicKey = Box384.publicKey(secretKey); // safe to share/publish

        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box384.seal(publicKey, message);
        byte[] opened = Box384.open(secretKey, sealed);
        if (!Arrays.equals(opened, message)) {
            throw new IllegalStateException("round trip failed");
        }
        System.out.println("sealed " + opened.length + " bytes -> " + sealed.length + " bytes, round-tripped OK");

        sealed[sealed.length - 1] ^= 1;
        try {
            Box384.open(secretKey, sealed);
        } catch (DstuException e) {
            System.out.println("tampered ciphertext correctly rejected");
        }
    }
}
