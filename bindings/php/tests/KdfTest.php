<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * crypto_kdf - no official vector exists for this construction (D-45: no DSTU KDF standard or
 * reference implementation exists at all). Correctness here means determinism/distinctness,
 * matching the Rust crate's own property-test posture. Misuse: wrong-length master key/context
 * (infallible otherwise, D-66 - no rejection category, there is no tag to tamper with).
 */
final class KdfTest extends TestCase
{
    public function testDerivesADeterministicSubkey(): void
    {
        $masterKey = dstu_core_kdf_keygen();
        $a = dstu_core_kdf_derive_subkey($masterKey, 0, 'encrypt_');
        $b = dstu_core_kdf_derive_subkey($masterKey, 0, 'encrypt_');
        $this->assertSame($a, $b);
    }

    public function testDifferentSubkeyIdGivesADifferentSubkey(): void
    {
        $masterKey = dstu_core_kdf_keygen();
        $a = dstu_core_kdf_derive_subkey($masterKey, 0, 'context1');
        $b = dstu_core_kdf_derive_subkey($masterKey, 1, 'context1');
        $this->assertNotSame($a, $b);
    }

    public function testDifferentContextGivesADifferentSubkey(): void
    {
        $masterKey = dstu_core_kdf_keygen();
        $a = dstu_core_kdf_derive_subkey($masterKey, 0, 'context1');
        $b = dstu_core_kdf_derive_subkey($masterKey, 0, 'context2');
        $this->assertNotSame($a, $b);
    }

    public function testRejectsWrongLengthMasterKey(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_kdf_derive_subkey('too short', 0, 'context1');
    }

    public function testRejectsWrongLengthContext(): void
    {
        $masterKey = dstu_core_kdf_keygen();
        $this->expectException(\ValueError::class);
        dstu_core_kdf_derive_subkey($masterKey, 0, 'short');
    }

    public function testRejectsNegativeSubkeyId(): void
    {
        $masterKey = dstu_core_kdf_keygen();
        $this->expectException(\ValueError::class);
        dstu_core_kdf_derive_subkey($masterKey, -1, 'context1');
    }
}
