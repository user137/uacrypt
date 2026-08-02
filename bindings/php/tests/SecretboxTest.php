<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_secretbox - three test categories per D-64/D-65: correctness (round trip - no official
 * vector exists for this construction, same posture as the Rust crate's own tests, D-51),
 * rejection (tamper/wrong key), misuse (wrong-length key, truncated input).
 */
final class SecretboxTest extends TestCase
{
    public function testRoundTripsSealOpen(): void
    {
        $key = dstu_core_secretbox_keygen();
        $sealed = dstu_core_secretbox_seal($key, 'a message worth protecting');
        $this->assertSame('a message worth protecting', dstu_core_secretbox_open($key, $sealed));
    }

    public function testHandlesAnEmptyMessage(): void
    {
        $key = dstu_core_secretbox_keygen();
        $sealed = dstu_core_secretbox_seal($key, '');
        $this->assertSame('', dstu_core_secretbox_open($key, $sealed));
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $key = dstu_core_secretbox_keygen();
        $sealed = dstu_core_secretbox_seal($key, 'message');
        $sealed[strlen($sealed) - 1] = chr(ord($sealed[-1]) ^ 1);
        $this->expectException(DstuCoreException::class);
        dstu_core_secretbox_open($key, $sealed);
    }

    public function testRejectsTamperedNonce(): void
    {
        $key = dstu_core_secretbox_keygen();
        $sealed = dstu_core_secretbox_seal($key, 'message');
        $sealed[0] = chr(ord($sealed[0]) ^ 1);
        $this->expectException(DstuCoreException::class);
        dstu_core_secretbox_open($key, $sealed);
    }

    public function testRejectsWrongKey(): void
    {
        $key = dstu_core_secretbox_keygen();
        $otherKey = dstu_core_secretbox_keygen();
        $sealed = dstu_core_secretbox_seal($key, 'message');
        $this->expectException(DstuCoreException::class);
        dstu_core_secretbox_open($otherKey, $sealed);
    }

    public function testRejectsWrongLengthKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_secretbox_seal('too short', 'message');
    }

    public function testRejectsTruncatedSealedInput(): void
    {
        $key = dstu_core_secretbox_keygen();
        $this->expectException(DstuCoreException::class);
        dstu_core_secretbox_open($key, 'short');
    }
}
