package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T-213: FFI memory-leak smoke test. Unlike the other five direct-Rust bindings (Python/Node.js/
 * Ruby/PHP), this binding's {@link SecretStreamPushState}/{@link SecretStreamPullState} hold a raw
 * {@code long handle} (a boxed Rust pointer via JNI) with no {@code finalize()}/{@code Cleaner}
 * registered - freeing it is entirely {@link AutoCloseable#close}'s job. That makes a JVM-heap-based
 * measurement structurally blind to this leak class: confirmed empirically before writing this test
 * - {@code Runtime.totalMemory() - freeMemory()} showed no positive correlation at all between a
 * properly-closed loop and a deliberately-never-closed one (both noise, one even negative). A
 * process-RSS measurement via repeated {@code Get-Process -Id <pid>).WorkingSet64} sampling on this
 * project's own Windows dev machine was tried next and was too noisy to trust even with a warmup
 * pass and N=20000 (JIT/GC churn swamped the actual leak signal, which showed *smaller* growth for
 * the deliberately-leaked case than the properly-closed one in one run). Two failed local-measurement
 * attempts on Windows - per this project's three-attempts rule, this stops chasing a Windows-local
 * signal and uses the one mechanism that's actually low-noise: reading {@code /proc/self/status}'s
 * {@code VmRSS} line directly (no subprocess spawn, well-established stable kernel text convention -
 * same source this project's own {@code uacrypt_with_peak_rss} CLI test helper already trusts for
 * its Linux path). Linux-only; skipped elsewhere via {@link Assumptions#assumeTrue} rather than
 * asserting something this test can't reliably observe there - not verified on this project's own
 * Windows dev machine (matches the precedent {@code uacrypt_with_peak_rss}'s own doc comment already
 * sets: its Linux/macOS paths were reviewed, not run, before their first CI confirmation).
 */
class MemoryLeakTest {
    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("linux");
    }

    private static long currentVmRssBytes() throws IOException {
        List<String> lines = Files.readAllLines(Paths.get("/proc/self/status"));
        for (String line : lines) {
            if (line.startsWith("VmRSS:")) {
                String[] parts = line.trim().split("\\s+");
                // "VmRSS:", "<kB value>", "kB"
                return Long.parseLong(parts[1]) * 1024;
            }
        }
        throw new IOException("VmRSS line not found in /proc/self/status");
    }

    @Test
    void secretstreamAndBoxLoopDoesNotLeak() throws Exception {
        Assumptions.assumeTrue(isLinux(), "VmRSS-based leak check only runs on Linux - see class doc");

        int warmup = 2000;
        int n = 20000;
        // Comfortable margin above normal JVM/JIT/GC churn but far below what N leaked handles
        // (each holding at least a few dozen bytes of native Rust state) would show at this scale.
        long maxAcceptableGrowthBytes = 8L * 1024 * 1024;

        byte[] key = SecretStream.keygen();
        byte[] boxSecret = Box.keygen();
        byte[] boxPublic = Box.publicKey(boxSecret);

        runLoop(key, boxSecret, boxPublic, warmup); // trigger class-loading/JIT noise before measuring
        System.gc();
        Thread.sleep(200);
        long before = currentVmRssBytes();

        runLoop(key, boxSecret, boxPublic, n);

        System.gc();
        Thread.sleep(200);
        long after = currentVmRssBytes();
        long growth = after - before;
        assertTrue(
                growth < maxAcceptableGrowthBytes,
                "VmRSS grew by " + growth + " bytes over " + n + " iterations "
                        + "(threshold " + maxAcceptableGrowthBytes + ") - possible native handle leak");
    }

    private static void runLoop(byte[] key, byte[] boxSecret, byte[] boxPublic, int n) throws Exception {
        for (int i = 0; i < n; i++) {
            try (SecretStreamPushState push = new SecretStreamPushState(key)) {
                byte[] header = push.header();
                SecretStreamPushResult r = push.push(SecretStreamTag.MESSAGE, "leak-check chunk".getBytes());
                try (SecretStreamPullState pull = new SecretStreamPullState(key, header)) {
                    pull.pull(SecretStreamTag.MESSAGE.ordinal(), r.ciphertext(), r.authTag());
                }
            }

            byte[] sealed = Box.seal(boxPublic, "leak-check message".getBytes());
            byte[] opened = Box.open(boxSecret, sealed);
            assertArrayEquals("leak-check message".getBytes(), opened);
        }
    }
}
