<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_sign257 (DSTU 4145 m=257) - m=257 sibling of crypto_sign (T-199/T-204). Correctness
 * (round trip, determinism of the nonce derivation), rejection (wrong message/wrong key), misuse
 * (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
 */
final class Sign257Test extends TestCase
{
    public function testRoundTripsSignVerify(): void
    {
        $signingKey = dstu_core_sign257_keygen();
        $verifyingKey = dstu_core_sign257_verifying_key($signingKey);
        $message = 'a message whose origin and integrity matter';
        $signature = dstu_core_sign257_message($signingKey, $message);
        $this->assertTrue(dstu_core_sign257_verify($verifyingKey, $message, $signature));
    }

    public function testIsDeterministic(): void
    {
        $signingKey = dstu_core_sign257_keygen();
        $message = 'same message every time';
        $this->assertSame(
            dstu_core_sign257_message($signingKey, $message),
            dstu_core_sign257_message($signingKey, $message)
        );
    }

    public function testRejectsWrongMessage(): void
    {
        $signingKey = dstu_core_sign257_keygen();
        $verifyingKey = dstu_core_sign257_verifying_key($signingKey);
        $signature = dstu_core_sign257_message($signingKey, 'original message');
        $this->assertFalse(dstu_core_sign257_verify($verifyingKey, 'a different message', $signature));
    }

    public function testRejectsWrongKey(): void
    {
        $signingKey = dstu_core_sign257_keygen();
        $otherVerifyingKey = dstu_core_sign257_verifying_key(dstu_core_sign257_keygen());
        $message = 'message';
        $signature = dstu_core_sign257_message($signingKey, $message);
        $this->assertFalse(dstu_core_sign257_verify($otherVerifyingKey, $message, $signature));
    }

    public function testRejectsAllZeroSigningKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign257_verifying_key(str_repeat("\x00", 33));
    }

    public function testRejectsWrongLengthSigningKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign257_message('too short', 'message');
    }

    public function testRejectsWrongLengthVerifyingKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign257_verify('too short', 'message', str_repeat("\x00", 66));
    }

    public function testRejectsWrongLengthSignature(): void
    {
        $signingKey = dstu_core_sign257_keygen();
        $verifyingKey = dstu_core_sign257_verifying_key($signingKey);
        $this->expectException(\ValueError::class);
        dstu_core_sign257_verify($verifyingKey, 'message', 'too short');
    }
}
