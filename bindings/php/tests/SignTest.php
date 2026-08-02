<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_sign (DSTU 4145) - the official Annex B.1 verify vector is already covered by
 * dstu_core_self_test() (SelfTestTest.php); this file covers what that single vector doesn't
 * reach: correctness (round trip, determinism of the nonce derivation), rejection (wrong
 * message/wrong key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying
 * key/signature).
 */
final class SignTest extends TestCase
{
    public function testRoundTripsSignVerify(): void
    {
        $signingKey = dstu_core_sign_keygen();
        $verifyingKey = dstu_core_sign_verifying_key($signingKey);
        $message = 'a message whose origin and integrity matter';
        $signature = dstu_core_sign_message($signingKey, $message);
        $this->assertTrue(dstu_core_sign_verify($verifyingKey, $message, $signature));
    }

    public function testIsDeterministic(): void
    {
        // D-46: the ephemeral nonce is derived deterministically, not from an RNG - the same
        // (key, message) pair always produces the same signature.
        $signingKey = dstu_core_sign_keygen();
        $message = 'same message every time';
        $this->assertSame(
            dstu_core_sign_message($signingKey, $message),
            dstu_core_sign_message($signingKey, $message)
        );
    }

    public function testRejectsWrongMessage(): void
    {
        $signingKey = dstu_core_sign_keygen();
        $verifyingKey = dstu_core_sign_verifying_key($signingKey);
        $signature = dstu_core_sign_message($signingKey, 'original message');
        $this->assertFalse(dstu_core_sign_verify($verifyingKey, 'a different message', $signature));
    }

    public function testRejectsWrongKey(): void
    {
        $signingKey = dstu_core_sign_keygen();
        $otherVerifyingKey = dstu_core_sign_verifying_key(dstu_core_sign_keygen());
        $message = 'message';
        $signature = dstu_core_sign_message($signingKey, $message);
        $this->assertFalse(dstu_core_sign_verify($otherVerifyingKey, $message, $signature));
    }

    public function testRejectsAllZeroSigningKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign_verifying_key(str_repeat("\x00", 21));
    }

    public function testRejectsWrongLengthSigningKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign_message('too short', 'message');
    }

    public function testRejectsWrongLengthVerifyingKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_sign_verify('too short', 'message', str_repeat("\x00", 42));
    }

    public function testRejectsWrongLengthSignature(): void
    {
        $signingKey = dstu_core_sign_keygen();
        $verifyingKey = dstu_core_sign_verifying_key($signingKey);
        $this->expectException(\ValueError::class);
        dstu_core_sign_verify($verifyingKey, 'message', 'too short');
    }
}
