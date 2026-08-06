<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_box - no official vector exists for this composite construction (same posture as
 * crypto_secretbox, D-51/D-169's own "Provenance" section) - correctness (round trip, including a
 * message larger than the 25-byte KEM payload), rejection (tampered wire segments, wrong key),
 * misuse (wrong-length/invalid key encodings, truncated input).
 */
final class BoxTest extends TestCase
{
    public function testRoundTripsSealOpen(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $message = "a message for the public key's holder only";
        $sealed = dstu_core_box_seal($publicKey, $message);
        $this->assertSame($message, dstu_core_box_open($secretKey, $sealed));
    }

    public function testHandlesAnEmptyMessage(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $sealed = dstu_core_box_seal($publicKey, '');
        $this->assertSame('', dstu_core_box_open($secretKey, $sealed));
    }

    public function testHandlesMessageLargerThanTheKemPayload(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $message = str_repeat('x', 10_000);
        $sealed = dstu_core_box_seal($publicKey, $message);
        $this->assertSame($message, dstu_core_box_open($secretKey, $sealed));
    }

    public function testTwoSealsUseDifferentEphemeralMaterial(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $message = 'same message twice';
        $this->assertNotSame(
            dstu_core_box_seal($publicKey, $message),
            dstu_core_box_seal($publicKey, $message)
        );
    }

    public function testRejectsTamperedKemPrefix(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $sealed = dstu_core_box_seal($publicKey, 'message');
        $sealed[0] = chr(ord($sealed[0]) ^ 1);
        $this->expectException(DstuCoreException::class);
        dstu_core_box_open($secretKey, $sealed);
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $sealed = dstu_core_box_seal($publicKey, 'message');
        $sealed[strlen($sealed) - 1] = chr(ord($sealed[-1]) ^ 1);
        $this->expectException(DstuCoreException::class);
        dstu_core_box_open($secretKey, $sealed);
    }

    public function testRejectsWrongSecretKey(): void
    {
        $secretKey = dstu_core_box_keygen();
        $publicKey = dstu_core_box_public_key($secretKey);
        $otherSecretKey = dstu_core_box_keygen();
        $sealed = dstu_core_box_seal($publicKey, 'message');
        $this->expectException(DstuCoreException::class);
        dstu_core_box_open($otherSecretKey, $sealed);
    }

    public function testRejectsWrongLengthSecretKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box_public_key('too short');
    }

    public function testRejectsZeroSecretKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box_public_key(str_repeat("\x00", 32));
    }

    public function testRejectsWrongLengthPublicKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box_seal('too short', 'message');
    }

    public function testRejectsDegeneratePublicKeyX(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_box_seal(str_repeat("\x00", 32), 'message'); // x = 0
    }

    public function testRejectsTruncatedSealedInput(): void
    {
        $secretKey = dstu_core_box_keygen();
        $this->expectException(DstuCoreException::class);
        dstu_core_box_open($secretKey, 'short');
    }
}
