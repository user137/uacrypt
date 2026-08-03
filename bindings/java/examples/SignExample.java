import ua.dstucrypto.dstucore.Sign;

/** {@code crypto_sign} (DSTU 4145): generate a signing keypair, sign a message, verify it. */
final class SignExample {
    private SignExample() {
    }

    static void run() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);

        byte[] message = "a message whose origin and integrity matter".getBytes("UTF-8");
        byte[] signature = Sign.sign(signingKey, message);
        if (!Sign.verify(verifyingKey, message, signature)) {
            throw new IllegalStateException("verification failed");
        }
        System.out.println("signed and verified a " + message.length + "-byte message");

        if (!Sign.verify(verifyingKey, "a different message".getBytes("UTF-8"), signature)) {
            System.out.println("signature over a different message correctly rejected");
        }
    }
}
