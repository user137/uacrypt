package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code crypto_secretstream} - both the low-level {@link SecretStreamPushState}/
 * {@link SecretStreamPullState} (step 2) and the {@link SecretStreamEncryptor}/
 * {@link SecretStreamDecryptor} pipeline (step 3, D-118). Three categories per D-64/D-65:
 * correctness (round trip across chunk-boundary sizes, plus real byte-for-byte interop with
 * {@code uacrypt encrypt}/{@code decrypt}'s own wire format), rejection (tamper, oversized chunk,
 * trailing data), misuse (wrong-length key, write-after-close).
 */
class SecretStreamTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        RANDOM.nextBytes(out);
        return out;
    }

    private static Path findUacrypt() {
        Path root = RepoRoot.find();
        Path[] candidates = {
                root.resolve("target").resolve("debug").resolve("uacrypt.exe"),
                root.resolve("target").resolve("release").resolve("uacrypt.exe"),
                root.resolve("target").resolve("debug").resolve("uacrypt"),
                root.resolve("target").resolve("release").resolve("uacrypt"),
        };
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 100, 8 * 1024, 8 * 1024 + 1, 8 * 1024 * 3, 8 * 1024 * 3 + 777})
    void roundTripsAcrossChunkBoundaries(int size) throws Exception {
        byte[] key = SecretStream.keygen();
        byte[] plaintext = randomBytes(size);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            int step = 777;
            for (int i = 0; i < plaintext.length; i += step) {
                enc.write(plaintext, i, Math.min(step, plaintext.length - i));
            }
            enc.complete();
        }

        byte[] encrypted = out.toByteArray();
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(encrypted))) {
            assertArrayEquals(plaintext, dec.readAll());
        }
    }

    /**
     * A file this binding encrypts is decryptable by {@code uacrypt decrypt}, and vice versa -
     * the concrete claim {@code docs/bindings-strategy.md}'s per-binding template makes about the
     * wire format.
     */
    @Test
    void interopWithUacryptCli() throws Exception {
        Path uacrypt = findUacrypt();
        Assumptions.assumeTrue(uacrypt != null, "uacrypt binary not built (cargo build -p uacrypt)");

        Path tmpDir = Files.createTempDirectory("dstu-java-secretstream-interop");
        byte[] key = SecretStream.keygen();
        Path keyPath = tmpDir.resolve("key.bin");
        Files.write(keyPath, key);
        byte[] plaintext = randomBytes(8 * 1024 * 2 + 555);
        Path plainPath = tmpDir.resolve("plain.bin");
        Files.write(plainPath, plaintext);

        Path javaEncryptedPath = tmpDir.resolve("java_encrypted.bin");
        try (java.io.OutputStream fileOut = Files.newOutputStream(javaEncryptedPath);
                SecretStreamEncryptor enc = new SecretStreamEncryptor(key, fileOut)) {
            enc.write(plaintext);
            enc.complete();
        }

        Path uacryptDecryptedPath = tmpDir.resolve("uacrypt_decrypted.bin");
        runUacrypt(uacrypt, "decrypt", "--key", keyPath.toString(), "--in", javaEncryptedPath.toString(),
                "--out", uacryptDecryptedPath.toString());
        assertArrayEquals(plaintext, Files.readAllBytes(uacryptDecryptedPath));

        Path uacryptEncryptedPath = tmpDir.resolve("uacrypt_encrypted.bin");
        runUacrypt(uacrypt, "encrypt", "--key", keyPath.toString(), "--in", plainPath.toString(),
                "--out", uacryptEncryptedPath.toString());
        try (java.io.InputStream fileIn = Files.newInputStream(uacryptEncryptedPath);
                SecretStreamDecryptor dec = new SecretStreamDecryptor(key, fileIn)) {
            assertArrayEquals(plaintext, dec.readAll());
        }
    }

    private static void runUacrypt(Path uacrypt, String... args) throws IOException, InterruptedException {
        String[] cmd = new String[args.length + 1];
        cmd[0] = uacrypt.toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process process = new ProcessBuilder(cmd).inheritIO().start();
        int exit = process.waitFor();
        assertEquals(0, exit, "uacrypt " + String.join(" ", args) + " failed");
    }

    @Test
    void tamperedChunkIsRejected() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            enc.write("secret message".getBytes("UTF-8"));
            enc.complete();
        }
        byte[] data = out.toByteArray();
        data[data.length - 1] ^= 1; // last byte of the Final chunk's auth tag
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(data))) {
            assertThrows(DstuException.class, dec::readAll);
        }
    }

    @Test
    void truncatedStreamIsRejected() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            enc.write(new byte[20000]);
            enc.complete();
        }
        byte[] truncated = java.util.Arrays.copyOf(out.toByteArray(), 100);
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(truncated))) {
            assertThrows(DstuException.class, dec::readAll);
        }
    }

    @Test
    void oversizedDeclaredChunkLengthIsRejected() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream malicious = new ByteArrayOutputStream();
        malicious.write(new byte[32]); // header (unread past this - the chunk-length check fires first)
        malicious.write(0x03); // tag byte (Final)
        malicious.write(0xFF);
        malicious.write(0xFF);
        malicious.write(0xFF);
        malicious.write(0xFF); // chunk length 0xFFFFFFFF, little-endian
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(malicious.toByteArray()))) {
            DstuException e = assertThrows(DstuException.class, dec::readAll);
            assertTrue(e.getMessage().contains("too large"));
        }
    }

    @Test
    void trailingDataAfterFinalIsRejected() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            enc.write("msg".getBytes("UTF-8"));
            enc.complete();
        }
        out.write("unexpected trailing bytes".getBytes("UTF-8"));
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(out.toByteArray()))) {
            DstuException e = assertThrows(DstuException.class, dec::readAll);
            assertTrue(e.getMessage().contains("trailing"));
        }
    }

    /**
     * Unlike Python's {@code __exit__}-based test of the same name, {@link SecretStreamEncryptor}
     * never auto-finalizes on {@code close()} at all, regardless of whether an exception occurred
     * - a stronger, unconditional guarantee (see the class's own doc comment) rather than one that
     * depends on distinguishing the exception path.
     */
    @Test
    void closeWithoutCompleteLeavesStreamUnfinalized() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            enc.write("chunk one".getBytes("UTF-8"));
            // deliberately no complete() call
        }
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(out.toByteArray()))) {
            assertThrows(DstuException.class, dec::readAll);
        }
    }

    @Test
    void wrongLengthKeyIsRejected() {
        byte[] tooShort = "too short".getBytes();
        assertThrows(IllegalArgumentException.class, () -> new SecretStreamPushState(tooShort));
    }

    @Test
    void writeAfterCloseIsRejected() throws Exception {
        byte[] key = SecretStream.keygen();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out);
        enc.write("data".getBytes("UTF-8"));
        enc.close();
        assertThrows(IllegalStateException.class, () -> enc.write("more data".getBytes("UTF-8")));
    }
}
