package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        Path rawKeyPath = tmpDir.resolve("key.bin");
        Files.write(rawKeyPath, key);
        // uacrypt reads typed key files (D-212): convert the raw key once.
        Path keyPath = tmpDir.resolve("key.txt");
        runUacrypt(uacrypt, "key-import", "--kind", "symmetric", "--in", rawKeyPath.toString(), "--out",
                keyPath.toString());
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
        malicious.write(2); // format version (D-208)
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

    private static final Path SHARED_VECTORS = RepoRoot.find().resolve("crates").resolve("dstu-core")
            .resolve("tests").resolve("vectors").resolve("secretstream-file").resolve("v2.json");

    static final class SharedCase {
        final String name;
        final String expect;
        final byte[] file;
        final byte[] plaintext;

        SharedCase(String name, String expect, byte[] file, byte[] plaintext) {
            this.name = name;
            this.expect = expect;
            this.file = file;
            this.plaintext = plaintext;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static String sharedJson() throws IOException {
        return new String(Files.readAllBytes(SHARED_VECTORS), StandardCharsets.UTF_8);
    }

    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static List<SharedCase> sharedCases() throws IOException {
        Pattern line = Pattern.compile("\"name\": \"([^\"]+)\", \"expect\": \"([^\"]+)\", "
                + "\"file_hex\": \"([0-9a-f]*)\", \"plaintext_hex\": \"([0-9a-f]*)\"");
        Matcher m = line.matcher(sharedJson());
        List<SharedCase> cases = new ArrayList<>();
        while (m.find()) {
            cases.add(new SharedCase(m.group(1), m.group(2), unhex(m.group(3)), unhex(m.group(4))));
        }
        assertEquals(7, cases.size(), "shared vector file is incomplete");
        return cases;
    }

    /** D-208: the same files every reader (uacrypt and all 8 bindings) is tested against. */
    @ParameterizedTest
    @MethodSource("sharedCases")
    void sharedStreamFileVector(SharedCase c) throws Exception {
        Matcher keyMatch = Pattern.compile("\"key_hex\": \"([0-9a-f]+)\"").matcher(sharedJson());
        assertTrue(keyMatch.find());
        byte[] key = unhex(keyMatch.group(1));
        if (c.expect.equals("ok")) {
            try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(c.file))) {
                assertArrayEquals(c.plaintext, dec.readAll());
            }
            return;
        }
        String wanted;
        if (c.expect.equals("unsupported_version")) {
            wanted = "unsupported stream format version";
        } else if (c.expect.equals("bad_chunk_length")) {
            wanted = "non-final chunk";
        } else if (c.expect.equals("truncated")) {
            wanted = "truncated";
        } else {
            wanted = "";
        }
        DstuException e = assertThrows(DstuException.class, () -> {
            try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(c.file))) {
                dec.readAll();
            }
        });
        assertTrue(e.getMessage().contains(wanted), e.getMessage());
    }

    @Test
    void encryptorWritesTheFormatVersionFirst() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(SecretStream.keygen(), out)) {
            enc.write(new byte[] {'x'});
            enc.complete();
        }
        assertEquals(2, out.toByteArray()[0]);
    }

    /** T-238: an 8-byte prefix of a real tag used to verify through the core's 8..=32 range. */
    @Test
    void truncatedEightByteAuthTagIsRejected() {
        byte[] key = SecretStream.keygen();
        try (SecretStreamPushState push = new SecretStreamPushState(key)) {
            SecretStreamPushResult r = push.push(SecretStreamTag.FINAL, "secret".getBytes(StandardCharsets.UTF_8));
            try (SecretStreamPullState pull = new SecretStreamPullState(key, push.header())) {
                byte[] shortTag = Arrays.copyOf(r.authTag(), 8);
                // The core rejects a non-16-byte tag as a length error, which this binding maps to
                // IllegalArgumentException, not DstuException: a caller bug, not a forgery.
                assertThrows(IllegalArgumentException.class,
                        () -> pull.pull(SecretStreamTag.FINAL.ordinal(), r.ciphertext(), shortTag));
            }
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
