<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Correctness gate: `dstu_core_self_test()` re-verifies one official vector per primitive
 * (Kalyna, Kupyna, Strumok, DSTU 4145) against this exact compiled extension - docs/TASKS.md
 * T-161. Every other test file in this suite adds its own correctness/rejection/misuse coverage
 * on top of this baseline (D-64/D-65).
 */
final class SelfTestTest extends TestCase
{
    public function testPasses(): void
    {
        $this->expectNotToPerformAssertions();
        dstu_core_self_test();
    }
}
