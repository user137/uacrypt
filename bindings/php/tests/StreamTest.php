<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_stream (Strumok-256 keystream) - **no authentication** (see dstu_core::crypto_stream's
 * own module doc): no rejection category, since there is no tag to tamper with -
 * dstu_core_stream_decrypt() never fails on tampered input, it silently returns different, wrong
 * plaintext instead. Correctness: round trip. Misuse: wrong-length key, truncated input.
 */
final class StreamTest extends TestCase
{
    public function testRoundTripsEncryptDecrypt(): void
    {
        $key = dstu_core_stream_keygen();
        $sealed = dstu_core_stream_encrypt($key, 'message');
        $this->assertSame('message', dstu_core_stream_decrypt($key, $sealed));
    }

    public function testDoesNotDetectTamperingButProducesWrongPlaintext(): void
    {
        // Documents the no-integrity property explicitly, per this project's own precedent
        // (hazmat::kalyna_xts's tampered_ciphertext_does_not_error_but_produces_garbage) - a
        // deliberate design property, not a missing rejection test.
        $key = dstu_core_stream_keygen();
        $sealed = dstu_core_stream_encrypt($key, 'message');
        $sealed[strlen($sealed) - 1] = chr(ord($sealed[-1]) ^ 1);
        $garbage = dstu_core_stream_decrypt($key, $sealed);
        $this->assertNotSame('message', $garbage);
    }

    public function testRejectsWrongLengthKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_stream_encrypt('too short', 'message');
    }

    public function testRejectsTruncatedSealedInput(): void
    {
        $key = dstu_core_stream_keygen();
        $this->expectException(DstuCoreException::class);
        dstu_core_stream_decrypt($key, 'short');
    }
}
