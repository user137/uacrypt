<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * randombytes - no rejection/misuse category (a single `size` parameter, no key/tag to tamper
 * with or malform). Correctness: returns the requested length, and two calls are not identical.
 */
final class RandombytesTest extends TestCase
{
    public function testReturnsTheRequestedLength(): void
    {
        $this->assertSame(32, strlen(dstu_core_randombytes_buf(32)));
    }

    public function testReturnsEmptyForAZeroLength(): void
    {
        $this->assertSame('', dstu_core_randombytes_buf(0));
    }

    public function testDoesNotReturnTheSameBytesTwice(): void
    {
        $this->assertNotSame(dstu_core_randombytes_buf(32), dstu_core_randombytes_buf(32));
    }
}
