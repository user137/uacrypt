import ua.dstucrypto.dstucore.Auth;
import ua.dstucrypto.dstucore.GenericHash;
import ua.dstucrypto.dstucore.Kdf;
import ua.dstucrypto.dstucore.Kupyna256Hasher;
import ua.dstucrypto.dstucore.RandomBytes;
import ua.dstucrypto.dstucore.StreamCipher;

import java.util.Arrays;

/**
 * The remaining {@code crypto_*} modules, each small enough to share one file: {@code crypto_auth}
 * (Kupyna-KMAC), {@code crypto_kdf}, {@code crypto_generichash} (Kupyna-256/512),
 * {@code crypto_stream} (Strumok-256, unauthenticated), {@code RandomBytes}.
 */
final class MiscExample {
    private MiscExample() {
    }

    static void run() throws Exception {
        authExample();
        kdfExample();
        genericHashExample();
        streamExample();
        randomBytesExample();
    }

    private static void authExample() throws Exception {
        byte[] key = Auth.keygen();
        byte[] message = "a message both parties want to confirm is unmodified".getBytes("UTF-8");
        byte[] tag = Auth.auth(key, message);
        Auth.verify(key, message, tag);
        System.out.println("auth: tag verified");
    }

    private static void kdfExample() throws Exception {
        byte[] masterKey = Kdf.keygen();
        byte[] context = "encrypt_".getBytes("UTF-8");
        byte[] subkeyA = Kdf.deriveSubkey(masterKey, 0, context);
        byte[] subkeyB = Kdf.deriveSubkey(masterKey, 1, context);
        if (Arrays.equals(subkeyA, subkeyB)) {
            throw new IllegalStateException("subkeys should differ");
        }
        System.out.println("kdf: subkey 0 and subkey 1 differ, as expected");
    }

    private static void genericHashExample() throws Exception {
        byte[] message = "hello world".getBytes("UTF-8");
        byte[] oneShot = GenericHash.hash256(message);
        try (Kupyna256Hasher hasher = new Kupyna256Hasher()) {
            hasher.update("hello ".getBytes("UTF-8"));
            hasher.update("world".getBytes("UTF-8"));
            if (!Arrays.equals(hasher.finish(), oneShot)) {
                throw new IllegalStateException("streaming/one-shot mismatch");
            }
        }
        System.out.println("generichash: kupyna256(\"hello world\") = " + toHex(oneShot));
    }

    private static void streamExample() throws Exception {
        byte[] key = StreamCipher.keygen();
        byte[] message = "a message".getBytes("UTF-8");
        byte[] sealed = StreamCipher.encrypt(key, message);
        if (!Arrays.equals(StreamCipher.decrypt(key, sealed), message)) {
            throw new IllegalStateException("round trip failed");
        }
        System.out.println("stream: round-tripped (note: unauthenticated, no tamper detection)");
    }

    private static void randomBytesExample() {
        byte[] a = RandomBytes.buf(16);
        byte[] b = RandomBytes.buf(16);
        if (Arrays.equals(a, b)) {
            throw new IllegalStateException("two independent draws should differ");
        }
        System.out.println("randombytes: two independent 16-byte draws, e.g. " + toHex(a));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
