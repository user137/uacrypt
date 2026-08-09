import ua.dstucrypto.dstucore.Box512;
import ua.dstucrypto.dstucore.DstuException;

import java.util.Arrays;

/** {@code crypto_box512} ({@code l(p)=512} sibling of {@code crypto_box}, T-193/T-204): generate
 * a keypair, seal a message to the public key, open it with the secret key. */
final class Box512Example {
    private Box512Example() {
    }

    static void run() throws Exception {
        byte[] secretKey = Box512.keygen();
        byte[] publicKey = Box512.publicKey(secretKey); // safe to share/publish

        byte[] message = "a message for the public key's holder only".getBytes("UTF-8");
        byte[] sealed = Box512.seal(publicKey, message);
        byte[] opened = Box512.open(secretKey, sealed);
        if (!Arrays.equals(opened, message)) {
            throw new IllegalStateException("round trip failed");
        }
        System.out.println("sealed " + opened.length + " bytes -> " + sealed.length + " bytes, round-tripped OK");

        sealed[sealed.length - 1] ^= 1;
        try {
            Box512.open(secretKey, sealed);
        } catch (DstuException e) {
            System.out.println("tampered ciphertext correctly rejected");
        }
    }
}
