<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_generichash (Kupyna-256/512) - three categories per D-64/D-65: correctness against a
 * real official Kupyna-256 vector (loaded directly from the same JSON the Rust crate's own tests
 * and self_test use - crates/dstu-core/tests/vectors/kupyna/kupyna-256.json, not just round-trip
 * self-consistency, D-124) plus one-shot/streaming agreement, misuse (calling finalize() twice -
 * there is no rejection category, a hash has no key/tag to tamper with).
 */
final class GenerichashTest extends TestCase
{
    private function vectorPath(): string
    {
        return __DIR__ . '/../../../crates/dstu-core/tests/vectors/kupyna/kupyna-256.json';
    }

    public function testMatchesTheOfficialKupyna256Vector(): void
    {
        $vectors = json_decode(file_get_contents($this->vectorPath()), true);
        $case = $vectors['cases'][0];
        $message = hex2bin($case['message_hex']);
        $expected = hex2bin($case['hash_hex']);
        $this->assertSame($expected, dstu_core_generichash_kupyna256($message));
    }

    public function testMatchesOneShotWithAStreamingKupyna256Hasher(): void
    {
        $whole = dstu_core_generichash_kupyna256('hello world');
        $hasher = new DstuCoreKupyna256Hasher();
        $hasher->update('hello ');
        $hasher->update('world');
        $this->assertSame($whole, $hasher->finalize());
    }

    public function testMatchesOneShotWithAStreamingKupyna512Hasher(): void
    {
        $whole = dstu_core_generichash_kupyna512('hello world');
        $hasher = new DstuCoreKupyna512Hasher();
        $hasher->update('hello ');
        $hasher->update('world');
        $this->assertSame($whole, $hasher->finalize());
    }

    public function testRejectsCallingFinalizeTwice(): void
    {
        $hasher = new DstuCoreKupyna256Hasher();
        $hasher->update('data');
        $hasher->finalize();
        $this->expectException(DstuCoreException::class);
        $hasher->finalize();
    }

    public function testRejectsUpdateAfterFinalize(): void
    {
        $hasher = new DstuCoreKupyna256Hasher();
        $hasher->finalize();
        $this->expectException(DstuCoreException::class);
        $hasher->update('more data');
    }
}
