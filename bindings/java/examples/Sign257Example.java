import ua.dstucrypto.dstucore.Sign257;

/** {@code crypto_sign257} (DSTU 4145 {@code m=257}, T-199/T-204): generate a signing keypair,
 * sign a message, verify it. */
final class Sign257Example {
    private Sign257Example() {
    }

    static void run() throws Exception {
        byte[] signingKey = Sign257.keygen();
        byte[] verifyingKey = Sign257.verifyingKey(signingKey);

        byte[] message = "a message whose origin and integrity matter".getBytes("UTF-8");
        byte[] signature = Sign257.sign(signingKey, message);
        if (!Sign257.verify(verifyingKey, message, signature)) {
            throw new IllegalStateException("verification failed");
        }
        System.out.println("signed and verified a " + message.length + "-byte message");

        if (!Sign257.verify(verifyingKey, "a different message".getBytes("UTF-8"), signature)) {
            System.out.println("signature over a different message correctly rejected");
        }
    }
}
