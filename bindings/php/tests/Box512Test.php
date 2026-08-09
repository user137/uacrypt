<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_box512 - l(p)=512 sibling of crypto_box (T-193/T-204). No official vector exists for
 * this composite construction (same posture as crypto_box) - correctness (round trip), rejection
 * (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings, truncated
 * input).
 */
final class Box512Test extends TestCase
{
    public function testRoundTripsSealOpen(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $publicKey = dstu_core_box512_public_key($secretKey);
        $message = "a message for the public key's holder only";
        $sealed = dstu_core_box512_seal($publicKey, $message);
        $this->assertSame($message, dstu_core_box512_open($secretKey, $sealed));
    }

    public function testHandlesAnEmptyMessage(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $publicKey = dstu_core_box512_public_key($secretKey);
        $sealed = dstu_core_box512_seal($publicKey, '');
        $this->assertSame('', dstu_core_box512_open($secretKey, $sealed));
    }

    public function testTwoSealsUseDifferentEphemeralMaterial(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $publicKey = dstu_core_box512_public_key($secretKey);
        $message = 'same message twice';
        $this->assertNotSame(
            dstu_core_box512_seal($publicKey, $message),
            dstu_core_box512_seal($publicKey, $message)
        );
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $publicKey = dstu_core_box512_public_key($secretKey);
        $sealed = dstu_core_box512_seal($publicKey, 'message');
        $sealed[strlen($sealed) - 1] = chr(ord($sealed[-1]) ^ 1);
        $this->expectException(DstuCoreException::class);
        dstu_core_box512_open($secretKey, $sealed);
    }

    public function testRejectsWrongSecretKey(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $publicKey = dstu_core_box512_public_key($secretKey);
        $otherSecretKey = dstu_core_box512_keygen();
        $sealed = dstu_core_box512_seal($publicKey, 'message');
        $this->expectException(DstuCoreException::class);
        dstu_core_box512_open($otherSecretKey, $sealed);
    }

    public function testRejectsWrongLengthSecretKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box512_public_key('too short');
    }

    public function testRejectsZeroSecretKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box512_public_key(str_repeat("\x00", 64));
    }

    public function testRejectsWrongLengthPublicKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box512_seal('too short', 'message');
    }

    public function testRejectsDegeneratePublicKeyX(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box512_seal(str_repeat("\x00", 64), 'message'); // x = 0
    }

    public function testRejectsTruncatedSealedInput(): void
    {
        $secretKey = dstu_core_box512_keygen();
        $this->expectException(DstuCoreException::class);
        dstu_core_box512_open($secretKey, 'short');
    }
}
