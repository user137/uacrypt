import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Cross-checks this project's extracted test vectors (crates/dstu-core/tests/vectors/) against
 * Bouncy Castle's own Kalyna (DSTU7624Engine) and Kupyna (DSTU7564Digest), via the published
 * bcprov-jdk18on Maven artifact - not the vendored partial clone under
 * oracles/bouncycastle-java/ (see TASKS.md "Infrastructure").
 *
 * Evidentiary value note (ORACLES.md / DECISIONS.md D-10): Bouncy Castle's Kalyna/Kupyna code is
 * itself a port of Roman Oliynykov's C reference, not an independent implementation - a pass
 * here mostly re-confirms this project's own PDF vector extraction, not a second independent
 * reading of the algorithm.
 *
 * No JSON library dependency: the vector files have a fixed, simple shape this project controls,
 * so a small regex-based extractor (same approach as crates/dstu-core/tests/kupyna.rs) is safer
 * than adding a dependency for a handful of string fields.
 */
public final class OracleHarness {

    private static int failures = 0;

    public static void main(String[] args) throws IOException {
        Path vectorsDir = findVectorsDir();
        runKalyna(vectorsDir.resolve("kalyna"));
        runKupyna(vectorsDir.resolve("kupyna"));

        if (failures == 0) {
            System.out.println("ALL PASSED");
        } else {
            System.out.println(failures + " FAILURE(S)");
        }
        System.exit(failures == 0 ? 0 : 1);
    }

    private static Path findVectorsDir() {
        // Run from tests/oracle-harness/java/ (Maven project root or plain javac invocation).
        return Paths.get("..", "..", "..", "crates", "dstu-core", "tests", "vectors").normalize();
    }

    private static void runKalyna(Path dir) throws IOException {
        for (Path file : sortedJsonFiles(dir)) {
            String json = readFile(file);
            int blockBits = extractInt(json, "block_bits");

            for (String caseJson : extractCases(json)) {
                String name = extractString(caseJson, "name");
                byte[] key = Hex.decode(extractString(caseJson, "key_hex"));
                byte[] plaintext = Hex.decode(extractString(caseJson, "plaintext_hex"));
                byte[] ciphertext = Hex.decode(extractString(caseJson, "ciphertext_hex"));

                boolean forEncryption = name.equals("encryption");
                DSTU7624Engine engine = new DSTU7624Engine(blockBits);
                engine.init(forEncryption, new KeyParameter(key));

                byte[] input = forEncryption ? plaintext : ciphertext;
                byte[] expected = forEncryption ? ciphertext : plaintext;
                byte[] output = new byte[input.length];
                engine.processBlock(input, 0, output, 0);

                report(file, "case=" + name, expected, output);
            }
        }
    }

    private static void runKupyna(Path dir) throws IOException {
        for (Path file : sortedJsonFiles(dir)) {
            String json = readFile(file);
            int hashBits = extractInt(json, "hash_bits");

            for (String caseJson : extractCases(json)) {
                String messageHex = extractString(caseJson, "message_hex");
                byte[] message = Hex.decode(messageHex == null ? "" : messageHex);
                byte[] expected = Hex.decode(extractString(caseJson, "hash_hex"));
                int messageBits = extractInt(caseJson, "message_bits");

                DSTU7564Digest digest = new DSTU7564Digest(hashBits);
                digest.update(message, 0, message.length);
                byte[] output = new byte[digest.getDigestSize()];
                digest.doFinal(output, 0);

                report(file, "message_bits=" + messageBits, expected, output);
            }
        }
    }

    private static void report(Path file, String label, byte[] expected, byte[] actual) {
        String fileName = file.getFileName().toString();
        if (java.util.Arrays.equals(expected, actual)) {
            System.out.println("[ok] " + fileName + " " + label);
        } else {
            failures++;
            System.out.println("[FAIL] " + fileName + " " + label
                + ": expected=" + Hex.toHexString(expected)
                + " actual=" + Hex.toHexString(actual));
        }
    }

    private static String readFile(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    private static List<Path> sortedJsonFiles(Path dir) throws IOException {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.json")) {
            for (Path p : stream) {
                files.add(p);
            }
        }
        Collections.sort(files);
        return files;
    }

    // --- minimal fixed-shape JSON extraction (no external dependency, see class doc) ---

    private static int extractInt(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("missing int field \"" + key + "\" in test vector JSON");
        }
        return Integer.parseInt(m.group(1));
    }

    private static String extractString(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    /** Splits the top-level "cases" array into one JSON-object substring per case. */
    private static List<String> extractCases(String json) {
        int casesStart = json.indexOf("\"cases\"");
        int arrayStart = json.indexOf('[', casesStart);
        List<String> cases = new ArrayList<>();
        int depth = 0;
        int objectStart = -1;
        for (int i = arrayStart; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') {
                if (depth == 0) {
                    objectStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    cases.add(json.substring(objectStart, i + 1));
                }
            } else if (c == ']' && depth == 0) {
                break;
            }
        }
        return cases;
    }
}
