package ua.dstucrypto.dstucore;

import org.junit.jupiter.api.Test;

/**
 * Correctness gate: {@link Selftest#run} re-verifies one official vector per primitive (Kalyna,
 * Kupyna, Strumok, DSTU 4145) against this exact compiled native build - {@code docs/TASKS.md}
 * T-161. Every other test class in this suite adds its own correctness/rejection/misuse coverage
 * on top of this baseline (D-64/D-65).
 */
class SelftestTest {
    @Test
    void selftestPasses() {
        Selftest.run();
    }
}
