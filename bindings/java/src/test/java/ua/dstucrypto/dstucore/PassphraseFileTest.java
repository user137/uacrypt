package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Passphrase files (D-219, moved into the core by T-269/D-240):
 * {@link SecretStreamEncryptor#forPassphrase}/{@link SecretStreamDecryptor#forPassphrase}, the
 * same bytes {@code uacrypt encrypt --passphrase-file} writes. Argon2 is 256 MiB, t=3 per run, so
 * only the shared-vector test and the uacrypt interop run it; every header refusal stops before
 * Argon2. Mirrors {@code bindings/python/tests/test_passphrase_file.py}.
 */
class PassphraseFileTest {
    private static final Path VECTORS = RepoRoot.find().resolve("crates").resolve("dstu-core")
            .resolve("tests").resolve("vectors").resolve("pwhash").resolve("passphrase_file.json");

    private static final class Case {
        final String name;
        final String expect;
        final byte[] passphrase;
        final int plaintextLen;
        final byte[] sealed;

        Case(String name, String expect, byte[] passphrase, int plaintextLen, byte[] sealed) {
            this.name = name;
            this.expect = expect;
            this.passphrase = passphrase;
            this.plaintextLen = plaintextLen;
            this.sealed = sealed;
        }
    }

    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static byte[] pattern(int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) ((i * 31 + 7) % 256);
        }
        return out;
    }

    private static List<Case> cases(boolean argon2) throws IOException {
        String json = new String(Files.readAllBytes(VECTORS), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("\"name\": \"([^\"]+)\", \"expect\": \"([^\"]+)\", \"argon2\": (true|false), "
                + "\"passphrase_hex\": \"([0-9a-f]*)\", \"plaintext_len\": (\\d+), \"sealed_hex\": \"([0-9a-f]*)\"")
                .matcher(json);
        List<Case> out = new ArrayList<>();
        while (m.find()) {
            if (Boolean.parseBoolean(m.group(3)) == argon2) {
                out.add(new Case(m.group(1), m.group(2), unhex(m.group(4)), Integer.parseInt(m.group(5)),
                        unhex(m.group(6))));
            }
        }
        return out;
    }

    private static byte[] open(byte[] passphrase, byte[] data) throws IOException {
        try (SecretStreamDecryptor dec = SecretStreamDecryptor.forPassphrase(passphrase, new ByteArrayInputStream(data))) {
            return dec.readAll();
        }
    }

    @Test
    void headerVectorsAreRefusedBeforeArgon2() throws Exception {
        Map<String, String> messages = new HashMap<>();
        messages.put("not_passphrase_file", "not a passphrase file");
        messages.put("unsupported_format", "unsupported passphrase file format");
        messages.put("unsupported_params", "unsupported Argon2 parameters");
        messages.put("truncated", "too short");
        List<Case> refused = cases(false);
        assertEquals(6, refused.size());
        for (Case c : refused) {
            DstuException e = assertThrows(DstuException.class, () -> open(c.passphrase, c.sealed), c.name);
            assertTrue(e.getMessage().contains(messages.get(c.expect)), c.name + ": " + e.getMessage());
        }
    }

    @Test
    void filesWrittenByUacrypt060GiveTheirExpectedOutcome() throws Exception {
        List<Case> argon2 = cases(true);
        assertEquals(4, argon2.size());
        for (Case c : argon2) {
            if (c.expect.equals("ok")) {
                assertArrayEquals(pattern(c.plaintextLen), open(c.passphrase, c.sealed), c.name);
            } else {
                assertThrows(DstuException.class, () -> open(c.passphrase, c.sealed), c.name);
            }
        }
    }

    @Test
    void anEmptyPassphraseIsRefusedOnBothSides() throws Exception {
        DstuException seal = assertThrows(DstuException.class,
                () -> SecretStreamEncryptor.forPassphrase(new byte[0], new ByteArrayOutputStream()));
        assertTrue(seal.getMessage().contains("empty"), seal.getMessage());
        byte[] sealed = cases(true).get(0).sealed;
        DstuException read = assertThrows(DstuException.class, () -> open(new byte[0], sealed));
        assertTrue(read.getMessage().contains("empty"), read.getMessage());
    }

    @Test
    void aKeyEncryptedStreamIsNotAPassphraseFile() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(SecretStream.keygen(), out)) {
            enc.write('x');
            enc.complete();
        }
        DstuException e = assertThrows(DstuException.class,
                () -> open("pw".getBytes(StandardCharsets.UTF_8), out.toByteArray()));
        assertTrue(e.getMessage().contains("not a passphrase file"), e.getMessage());
    }

    private static Path findUacrypt() {
        Path root = RepoRoot.find();
        for (String profile : new String[] {"release", "debug"}) {
            for (String name : new String[] {"uacrypt.exe", "uacrypt"}) {
                Path p = root.resolve("target").resolve(profile).resolve(name);
                if (Files.isRegularFile(p)) {
                    return p;
                }
            }
        }
        return null;
    }

    private static void run(Path uacrypt, String... args) throws IOException, InterruptedException {
        String[] cmd = new String[args.length + 1];
        cmd[0] = uacrypt.toString();
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process process = new ProcessBuilder(cmd).inheritIO().start();
        assertEquals(0, process.waitFor(), "uacrypt " + String.join(" ", args) + " failed");
    }

    @Test
    void interoperatesWithUacryptInBothDirections() throws Exception {
        Path uacrypt = findUacrypt();
        Assumptions.assumeTrue(uacrypt != null, "uacrypt binary not built (cargo build -p uacrypt)");
        Path dir = Files.createTempDirectory("dstu-pf-");
        byte[] message = pattern(8 * 1024 + 9);
        byte[] passphrase = "спільний пароль".getBytes(StandardCharsets.UTF_8);
        Path pw = dir.resolve("pw.txt");
        Files.write(pw, passphrase);

        Path ours = dir.resolve("ours.uac");
        try (OutputStream file = Files.newOutputStream(ours);
                SecretStreamEncryptor enc = SecretStreamEncryptor.forPassphrase(passphrase, file)) {
            enc.write(message);
            enc.complete();
        }
        Path back = dir.resolve("ours.back");
        run(uacrypt, "decrypt", "--passphrase-file", pw.toString(), "--in", ours.toString(), "--out", back.toString());
        assertArrayEquals(message, Files.readAllBytes(back));

        Path plain = dir.resolve("plain.bin");
        Files.write(plain, message);
        Path theirs = dir.resolve("theirs.uac");
        run(uacrypt, "encrypt", "--passphrase-file", pw.toString(), "--in", plain.toString(), "--out", theirs.toString());
        try (InputStream file = Files.newInputStream(theirs);
                SecretStreamDecryptor dec = SecretStreamDecryptor.forPassphrase(passphrase, file)) {
            assertArrayEquals(message, dec.readAll());
        }
    }
}
