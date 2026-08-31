package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
 * than assumed. Two shapes:
 * <ul>
 * <li><b>{@link Sign}'s static methods are safe to call concurrently on the same key bytes.</b>
 * Unlike .NET/C++, this binding's {@code Sign} holds no native handle at all - every key is a
 * plain Java {@code byte[]} copied into the native call each time (see {@code Sign.java}'s own
 * doc), so there is no shared mutable native state to race on in the first place. Verified below
 * by real concurrent JNI calls, not assumed from the API shape alone.</li>
 * <li><b>{@link SecretStreamPushState}/{@link SecretStreamPullState} are NOT safe to share across
 * threads</b> - each holds one native handle whose pointed-to state (nonce/counter) advances with
 * every {@code push}/{@code pull} call, with no lock anywhere in this wrapper. The supported
 * concurrency model is one stream per thread. Verified below: many threads, each driving its own
 * encrypt/decrypt pair concurrently, all round-trip correctly - deliberately not tested by racing
 * a single shared instance, since that would just induce undefined behavior on the native side
 * rather than test a contract.</li>
 * </ul>
 */
class ThreadSafetyTest {
    @Test
    void concurrentVerifyOnSharedKeyIsSafe() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);
        byte[] message = "shared-key concurrent verify".getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Sign.sign(signingKey, message);

        int threadCount = 16;
        int perThread = 200;
        runConcurrently(threadCount, () -> {
            for (int i = 0; i < perThread; i++) {
                if (!Sign.verify(verifyingKey, message, signature)) {
                    fail("Sign.verify returned false on a valid signature");
                }
            }
            return null;
        });
    }

    @Test
    void concurrentSignOnSharedKeyIsSafe() throws Exception {
        byte[] signingKey = Sign.keygen();
        byte[] verifyingKey = Sign.verifyingKey(signingKey);
        byte[] message = "shared-key concurrent sign".getBytes(StandardCharsets.US_ASCII);

        int threadCount = 16;
        int perThread = 50;
        runConcurrently(threadCount, () -> {
            for (int i = 0; i < perThread; i++) {
                byte[] sig = Sign.sign(signingKey, message);
                if (!Sign.verify(verifyingKey, message, sig)) {
                    fail("a concurrently-produced signature failed to verify");
                }
            }
            return null;
        });
    }

    @Test
    void concurrentIndependentSecretstreamLoopsAreSafe() throws Exception {
        int threadCount = 8;
        int perThreadChunks = 20;

        runConcurrently(threadCount, threadIndex -> {
            byte[] key = SecretStream.keygen();
            byte[][] chunks = new byte[perThreadChunks][];
            for (int i = 0; i < perThreadChunks; i++) {
                chunks[i] = ("thread " + threadIndex + " chunk " + i).getBytes(StandardCharsets.US_ASCII);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (SecretStreamEncryptor enc = new SecretStreamEncryptor(key, out)) {
                for (byte[] chunk : chunks) {
                    enc.write(chunk);
                }
                enc.complete();
            }

            ByteArrayOutputStream expected = new ByteArrayOutputStream();
            for (byte[] chunk : chunks) {
                expected.write(chunk);
            }

            try (SecretStreamDecryptor dec = new SecretStreamDecryptor(key, new ByteArrayInputStream(out.toByteArray()))) {
                assertArrayEquals(expected.toByteArray(), dec.readAll());
            }
            return null;
        });
    }

    /**
     * Runs {@code task} concurrently on {@code threadCount} real OS threads (a fixed thread pool,
     * not just async tasks that might serialize onto one carrier thread), each passed its own
     * index, and re-throws the first exception/assertion failure any of them hit.
     */
    private interface IndexedTask {
        Void call(int threadIndex) throws Exception;
    }

    private static void runConcurrently(int threadCount, Callable<Void> task) throws Exception {
        runConcurrently(threadCount, threadIndex -> task.call());
    }

    private static void runConcurrently(int threadCount, IndexedTask task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        try {
            List<Future<Void>> futures = new ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                int threadIndex = i;
                futures.add(pool.submit(() -> task.call(threadIndex)));
            }
            for (Future<Void> future : futures) {
                try {
                    future.get(60, TimeUnit.SECONDS);
                } catch (ExecutionException e) {
                    if (e.getCause() instanceof Exception) {
                        throw (Exception) e.getCause();
                    }
                    throw e;
                }
            }
        } finally {
            pool.shutdown();
        }
    }
}
