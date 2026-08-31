package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * T-218: {@code crypto_secretstream} push/pull with a forced {@link System#gc()} between every
 * caller-level call. Unlike the .NET binding's {@code SafeHandle}, {@link SecretStreamPushState}/
 * {@link SecretStreamPullState} hold their native pointer in a plain {@code long} field with no
 * finalizer/{@link java.lang.ref.Cleaner} (T-213's own finding: native memory here is released only
 * by an explicit {@link SecretStreamPushState#close}/{@link SecretStreamPullState#close}, never by
 * GC) - so a collection mid-loop cannot itself free memory still in use. What this test actually
 * exercises is the JIT-reachability edge case a finalizer-based design would be exposed to (an
 * object proven unreachable, and thus eligible for collection/finalization, before its last
 * apparent use finishes): confirms the loop below still round-trips correctly under maximum GC
 * pressure, i.e. this binding's explicit-close design is safe here by construction, not by luck.
 */
class GcStressTest {
    @Test
    void secretstreamPushPullSurvivesForcedGcBetweenEveryCall() throws Exception {
        int chunkCount = 40;
        byte[][] chunks = new byte[chunkCount][];
        for (int i = 0; i < chunkCount; i++) {
            char[] padding = new char[500];
            Arrays.fill(padding, 'x');
            chunks[i] = ("gc-stress chunk #" + i + " " + new String(padding)).getBytes(StandardCharsets.US_ASCII);
        }

        byte[] key = SecretStream.keygen();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
            for (byte[] chunk : chunks) {
                enc.write(chunk);
                forceFullCollection();
            }
            enc.complete();
            forceFullCollection();
        }

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(out.toByteArray()))) {
            byte[] buffer = new byte[64];
            int read;
            while ((read = dec.read(buffer)) != -1) {
                decrypted.write(buffer, 0, read);
                forceFullCollection();
            }
        }

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        for (byte[] chunk : chunks) {
            expected.write(chunk);
        }

        assertArrayEquals(expected.toByteArray(), decrypted.toByteArray());
    }

    private static void forceFullCollection() {
        System.gc();
        System.runFinalization();
        System.gc();
    }
}
