import ua.dstucrypto.dstucore.Pwhash;
import ua.dstucrypto.dstucore.PwhashStrength;

/**
 * {@code crypto_pwhash} (Argon2id): hash and verify a password.
 *
 * <p>{@link PwhashStrength#INTERACTIVE} is used here so the example runs fast -
 * {@link PwhashStrength#MODERATE} (the strength most applications should use) and
 * {@link PwhashStrength#SENSITIVE} both take real seconds by design.
 */
final class PasswordHashingExample {
    private PasswordHashingExample() {
    }

    static void run() throws Exception {
        byte[] password = "correct horse battery staple".getBytes("UTF-8");
        String stored = Pwhash.hashPassword(password, PwhashStrength.INTERACTIVE);
        System.out.println("stored hash: " + stored);

        if (!Pwhash.verifyPassword(password, stored)) {
            throw new IllegalStateException("correct password was rejected");
        }
        System.out.println("correct password accepted");

        if (!Pwhash.verifyPassword("wrong guess".getBytes("UTF-8"), stored)) {
            System.out.println("wrong password correctly rejected");
        }
    }
}
