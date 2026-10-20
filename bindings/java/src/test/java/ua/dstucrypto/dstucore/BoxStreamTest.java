package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Streaming {@code crypto_box}/{@code crypto_box384}/{@code crypto_box512} (T-265 format v3, T-269,
 * T-297): {@link SecretStreamEncryptor#forBox}/{@link SecretStreamDecryptor#forBox} and the 384/512 pairs over
 * the core's {@code seal_stream}/{@code open_stream}. Happy path: the shared v3 vectors (one-shot
 * {@code open} and the streaming reader), a round trip across record boundaries, one-shot/streaming
 * byte equivalence. Security: tampering, a wrong key, trailing data. Misuse: wrong-length keys, a
 * cut prefix, the 0.4-0.6 format. Error path: {@code close()} without {@code complete()} leaves no
 * {@code Final} record (D-118). Mirrors {@code bindings/python/tests/test_box_stream.py}.
 */
class BoxStreamTest {
    private static final Path VECTORS = RepoRoot.find().resolve("crates").resolve("dstu-core")
            .resolve("tests").resolve("vectors").resolve("box");

    private static String json(String name) throws IOException {
        return new String(Files.readAllBytes(VECTORS.resolve(name)), StandardCharsets.UTF_8);
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

    private static byte[] secretFrom(String json, int curve) {
        Matcher m = Pattern.compile("\"box" + curve + "_secret_key_hex\": \"([0-9a-f]+)\"").matcher(json);
        assertTrue(m.find());
        return unhex(m.group(1));
    }

    private static byte[] keygen(int curve) {
        return curve == 256 ? Box.keygen() : curve == 384 ? Box384.keygen() : Box512.keygen();
    }

    private static byte[] publicKey(int curve, byte[] secret) {
        return curve == 256 ? Box.publicKey(secret) : curve == 384 ? Box384.publicKey(secret) : Box512.publicKey(secret);
    }

    private static byte[] oneShotOpen(int curve, byte[] secret, byte[] sealed) {
        return curve == 256 ? Box.open(secret, sealed)
                : curve == 384 ? Box384.open(secret, sealed) : Box512.open(secret, sealed);
    }

    private static byte[] streamOpen(int curve, byte[] secret, byte[] sealed) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(sealed);
        try (SecretStreamDecryptor dec = curve == 256
                ? SecretStreamDecryptor.forBox(secret, in)
                : curve == 384
                ? SecretStreamDecryptor.forBox384(secret, in)
                : SecretStreamDecryptor.forBox512(secret, in)) {
            return dec.readAll();
        }
    }

    private static SecretStreamEncryptor writer(int curve, byte[] publicKey, ByteArrayOutputStream out)
            throws IOException {
        return curve == 256 ? SecretStreamEncryptor.forBox(publicKey, out)
                : curve == 384 ? SecretStreamEncryptor.forBox384(publicKey, out)
                : SecretStreamEncryptor.forBox512(publicKey, out);
    }

    private static byte[] streamSeal(int curve, byte[] publicKey, byte[] message) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = writer(curve, publicKey, out)) {
            int first = Math.min(7, message.length);
            enc.write(message, 0, first);
            enc.write(message, first, message.length - first);
            enc.complete();
        }
        return out.toByteArray();
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 384, 512})
    void sharedV3VectorsGiveTheirExpectedOutcome(int curve) throws Exception {
        String json = json("v3.json");
        byte[] secret = secretFrom(json, curve);
        Matcher m = Pattern.compile("\"curve\": " + curve + ", \"name\": \"([^\"]+)\", \"expect\": \"([^\"]+)\", "
                + "\"plaintext_len\": (\\d+), \"sealed_hex\": \"([0-9a-f]*)\"").matcher(json);
        int seen = 0;
        while (m.find()) {
            String name = m.group(1);
            byte[] sealed = unhex(m.group(4));
            if (m.group(2).equals("ok")) {
                byte[] expected = pattern(Integer.parseInt(m.group(3)));
                assertArrayEquals(expected, oneShotOpen(curve, secret, sealed), name);
                assertArrayEquals(expected, streamOpen(curve, secret, sealed), name);
            } else {
                assertThrows(DstuException.class, () -> oneShotOpen(curve, secret, sealed), name);
                assertThrows(DstuException.class, () -> streamOpen(curve, secret, sealed), name);
            }
            seen++;
        }
        assertTrue(seen > 0);
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 512}) // 0.4-0.6 had no l(p)=384
    void theZeroSixFormatIsRefusedAsUnsupported(int curve) throws Exception {
        String json = json("legacy_v2.json");
        byte[] secret = secretFrom(json, curve);
        Matcher m = Pattern.compile("\"curve\": " + curve + ", [^\\n]*\"sealed_hex\": \"([0-9a-f]+)\"").matcher(json);
        int seen = 0;
        while (m.find()) {
            byte[] sealed = unhex(m.group(1));
            DstuException one = assertThrows(DstuException.class, () -> oneShotOpen(curve, secret, sealed));
            assertTrue(one.getMessage().contains("version"), one.getMessage());
            DstuException streaming = assertThrows(DstuException.class, () -> streamOpen(curve, secret, sealed));
            assertTrue(streaming.getMessage().contains("version"), streaming.getMessage());
            seen++;
        }
        assertTrue(seen > 0);
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 384, 512})
    void streamRoundTripReadsBackStreamingAndOneShot(int curve) throws Exception {
        byte[] secret = keygen(curve);
        for (int size : new int[] {0, 1, 8 * 1024, 8 * 1024 + 1, 3 * 8 * 1024 + 5}) {
            byte[] message = pattern(size);
            byte[] sealed = streamSeal(curve, publicKey(curve, secret), message);
            assertArrayEquals(message, streamOpen(curve, secret, sealed));
            assertArrayEquals(message, oneShotOpen(curve, secret, sealed));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 384, 512})
    void tamperingAWrongKeyAndTrailingDataFailClosed(int curve) throws Exception {
        byte[] secret = keygen(curve);
        byte[] sealed = streamSeal(curve, publicKey(curve, secret), pattern(100));
        byte[] other = keygen(curve);
        assertThrows(DstuException.class, () -> streamOpen(curve, other, sealed));
        for (int index : new int[] {1, sealed.length / 2, sealed.length - 1}) {
            byte[] bad = sealed.clone();
            bad[index] ^= 0x01;
            assertThrows(DstuException.class, () -> streamOpen(curve, secret, bad));
        }
        byte[] trailing = Arrays.copyOf(sealed, sealed.length + 1);
        assertThrows(DstuException.class, () -> streamOpen(curve, secret, trailing));
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 384, 512})
    void misuseIsRefused(int curve) throws Exception {
        byte[] secret = keygen(curve);
        byte[] wrong = new byte[] {1, 1, 1};
        assertThrows(IllegalArgumentException.class, () -> writer(curve, wrong, new ByteArrayOutputStream()));
        byte[] filler = new byte[400];
        Arrays.fill(filler, (byte) 3);
        assertThrows(IllegalArgumentException.class, () -> streamOpen(curve, wrong, filler));
        byte[] sealed = streamSeal(curve, publicKey(curve, secret), pattern(10));
        for (int cut : new int[] {0, 1, 50}) {
            DstuException e = assertThrows(DstuException.class,
                    () -> streamOpen(curve, secret, Arrays.copyOf(sealed, cut)));
            assertTrue(e.getMessage().contains("too short"), e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {256, 384, 512})
    void closeWithoutCompleteLeavesNoFinalRecord(int curve) throws Exception {
        byte[] secret = keygen(curve);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = writer(curve, publicKey(curve, secret), out)) {
            enc.write(pattern(3 * 8 * 1024));
        }
        assertThrows(DstuException.class, () -> streamOpen(curve, secret, out.toByteArray()));
    }

    /** No 0.4-0.6 file exists at l(p)=384 (T-297): a version-2 byte stands in for one. */
    @Test
    void aVersion2BlobIsUnsupportedAt384() throws Exception {
        byte[] secret = Box384.keygen();
        byte[] sealed = new byte[241];
        sealed[0] = 2;
        DstuException one = assertThrows(DstuException.class, () -> oneShotOpen(384, secret, sealed));
        assertTrue(one.getMessage().contains("version"), one.getMessage());
        DstuException streaming = assertThrows(DstuException.class, () -> streamOpen(384, secret, sealed));
        assertTrue(streaming.getMessage().contains("version"), streaming.getMessage());
    }
}
