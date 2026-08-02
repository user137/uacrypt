<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_auth - three categories per D-64/D-65: correctness (round trip), rejection (tampered
 * message, wrong key), misuse (wrong-length key/tag - foreclosed at the Rust layer by fixed-size
 * arrays, D-66, so `auth` itself is infallible; only the boundary length checks are testable
 * here).
 */
final class AuthTest extends TestCase
{
    public function testRoundTripsAuthAuthVerify(): void
    {
        $key = dstu_core_auth_keygen();
        $message = 'a message both parties want to confirm is unmodified';
        $tag = dstu_core_auth($key, $message);
        dstu_core_auth_verify($key, $message, $tag);
        $this->expectNotToPerformAssertions();
    }

    public function testRejectsTamperedMessage(): void
    {
        $key = dstu_core_auth_keygen();
        $tag = dstu_core_auth($key, 'original message');
        $this->expectException(DstuCoreException::class);
        dstu_core_auth_verify($key, 'a different message', $tag);
    }

    public function testRejectsWrongKey(): void
    {
        $key = dstu_core_auth_keygen();
        $otherKey = dstu_core_auth_keygen();
        $tag = dstu_core_auth($key, 'message');
        $this->expectException(DstuCoreException::class);
        dstu_core_auth_verify($otherKey, 'message', $tag);
    }

    public function testRejectsWrongLengthKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_auth('too short', 'message');
    }

    public function testRejectsWrongLengthTag(): void
    {
        $key = dstu_core_auth_keygen();
        $this->expectException(\ValueError::class);
        dstu_core_auth_verify($key, 'message', 'too short');
    }
}
