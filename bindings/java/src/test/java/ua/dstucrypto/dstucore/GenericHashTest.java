package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code crypto_generichash} (Kupyna-256/512) - three categories per D-64/D-65: correctness
 * against a real official Kupyna-256 vector (the same JSON the Rust crate's own tests and
 * {@link Selftest} use), misuse ({@code finalize()} called twice - there is no rejection category,
 * a hash has no key/tag to tamper with).
 */
class GenericHashTest {
    private static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    @Test
    void kupyna256MatchesOfficialVector() throws IOException {
        Path vectorPath = RepoRoot.find()
                .resolve("crates").resolve("dstu-core").resolve("tests").resolve("vectors")
                .resolve("kupyna").resolve("kupyna-256.json");
        String json = new String(Files.readAllBytes(vectorPath), StandardCharsets.UTF_8);
        Matcher messageMatcher = Pattern.compile("\"message_hex\":\\s*\"([0-9A-Fa-f]+)\"").matcher(json);
        Matcher hashMatcher = Pattern.compile("\"hash_hex\":\\s*\"([0-9A-Fa-f]+)\"").matcher(json);
        if (!messageMatcher.find() || !hashMatcher.find()) {
            throw new IllegalStateException("could not find a case in " + vectorPath);
        }
        byte[] message = fromHex(messageMatcher.group(1));
        byte[] expected = fromHex(hashMatcher.group(1));
        assertArrayEquals(expected, GenericHash.hash256(message));
    }

    @Test
    void streamingHasherMatchesOneShot() throws Exception {
        byte[] whole = GenericHash.hash256("hello world".getBytes("UTF-8"));
        try (Kupyna256Hasher hasher = new Kupyna256Hasher()) {
            hasher.update("hello ".getBytes("UTF-8"));
            hasher.update("world".getBytes("UTF-8"));
            assertArrayEquals(whole, hasher.finish());
        }
    }

    @Test
    void kupyna512StreamingHasherMatchesOneShot() throws Exception {
        byte[] whole = GenericHash.hash512("hello world".getBytes("UTF-8"));
        try (Kupyna512Hasher hasher = new Kupyna512Hasher()) {
            hasher.update("hello ".getBytes("UTF-8"));
            hasher.update("world".getBytes("UTF-8"));
            assertArrayEquals(whole, hasher.finish());
        }
    }

    @Test
    void finalizeTwiceIsRejected() throws Exception {
        try (Kupyna256Hasher hasher = new Kupyna256Hasher()) {
            hasher.update("data".getBytes("UTF-8"));
            hasher.finish();
            assertThrows(IllegalStateException.class, hasher::finish);
        }
    }

    @Test
    void updateAfterFinalizeIsRejected() throws Exception {
        try (Kupyna256Hasher hasher = new Kupyna256Hasher()) {
            hasher.finish();
            assertThrows(IllegalStateException.class, () -> hasher.update("more data".getBytes("UTF-8")));
        }
    }
}
