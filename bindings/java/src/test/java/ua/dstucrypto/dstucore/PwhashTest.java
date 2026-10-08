package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code crypto_pwhash} (Argon2id, the one deliberately non-DSTU component, D-49/D-50).
 * Correctness: round trip. Rejection: wrong password, malformed hash string. {@code strength}'s
 * misuse category ("invalid strength value") is foreclosed by the type system here - it takes a
 * {@link PwhashStrength} enum, not a raw int, unlike Python's `PWHASH_*` int constants - so there
 * is nothing invalid to construct through the public API (see D-153's own note on this).
 * {@link PwhashStrength#INTERACTIVE} is used throughout (not the moderate default) so this class's
 * own tests stay fast.
 */
class PwhashTest {
    @Test
    void hashVerifyRoundTrips() throws Exception {
        String stored = Pwhash.hashPassword("correct horse battery staple".getBytes("UTF-8"), PwhashStrength.INTERACTIVE);
        assertTrue(Pwhash.verifyPassword("correct horse battery staple".getBytes("UTF-8"), stored));
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        String stored = Pwhash.hashPassword("correct horse battery staple".getBytes("UTF-8"), PwhashStrength.INTERACTIVE);
        assertFalse(Pwhash.verifyPassword("wrong guess".getBytes("UTF-8"), stored));
    }

    @Test
    void malformedHashStringIsRejected() throws Exception {
        assertFalse(Pwhash.verifyPassword("anything".getBytes("UTF-8"), "not a real PHC string"));
    }

    static List<Arguments> verifyCases() throws IOException {
        String json = new String(Files.readAllBytes(RepoRoot.find().resolve("crates").resolve("dstu-core")
                .resolve("tests").resolve("vectors").resolve("pwhash").resolve("verify.json")), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("\"name\": \"([^\"]*)\",\\s*\"source\": \"[^\"]*\",\\s*\"password\": \"([^\"]*)\","
                + "\\s*\"hash\": \"([^\"]*)\",\\s*\"expect\": \"([^\"]*)\"").matcher(json);
        List<Arguments> cases = new ArrayList<>();
        while (m.find()) {
            cases.add(Arguments.of(m.group(1), m.group(2), m.group(3), m.group(4)));
        }
        assertEquals(22, cases.size(), "shared vector file is incomplete");
        return cases;
    }

    /** T-272/D-222: a crafted hash string returns false instead of aborting the JVM. */
    @ParameterizedTest
    @MethodSource("verifyCases")
    void sharedVerifyVector(String name, String password, String hash, String expect) {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        assertEquals(expect.equals("accept"), Pwhash.verifyPassword(pw, hash), name);
        assertFalse(Pwhash.verifyPassword((password + "x").getBytes(StandardCharsets.UTF_8), hash), name);
    }
}
