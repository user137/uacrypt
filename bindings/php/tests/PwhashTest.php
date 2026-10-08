<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * crypto_pwhash (Argon2id, the one deliberately non-DSTU component, D-49/D-50). Correctness:
 * round trip. Rejection: wrong password, malformed hash string. Misuse: invalid strength value.
 * DSTU_CORE_PWHASH_INTERACTIVE is used throughout (not the default Moderate) so this file's own
 * tests stay fast - Sensitive alone takes real seconds, per the Rust crate's own test comments.
 */
final class PwhashTest extends TestCase
{
    public function testRoundTripsHashPasswordVerifyPassword(): void
    {
        $stored = dstu_core_pwhash_hash_password('correct horse battery staple', DSTU_CORE_PWHASH_INTERACTIVE);
        $this->assertTrue(dstu_core_pwhash_verify_password('correct horse battery staple', $stored));
    }

    public function testRejectsTheWrongPassword(): void
    {
        $stored = dstu_core_pwhash_hash_password('correct horse battery staple', DSTU_CORE_PWHASH_INTERACTIVE);
        $this->assertFalse(dstu_core_pwhash_verify_password('wrong guess', $stored));
    }

    public function testRejectsAMalformedHashString(): void
    {
        $this->assertFalse(dstu_core_pwhash_verify_password('anything', 'not a real PHC string'));
    }

    public function testRejectsAnInvalidStrengthValue(): void
    {
        $this->expectException(\ValueError::class);
        dstu_core_pwhash_hash_password('password', 255);
    }

    /** T-272/D-222: a crafted hash string returns false instead of aborting the PHP process. */
    public static function sharedVerifyVectors(): array
    {
        $path = dirname(__DIR__, 3) . '/crates/dstu-core/tests/vectors/pwhash/verify.json';
        $vectors = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        $cases = [];
        foreach ($vectors['cases'] as $case) {
            $cases[$case['name']] = [$case['password'], $case['hash'], $case['expect']];
        }

        return $cases;
    }

    #[DataProvider('sharedVerifyVectors')]
    public function testSharedVerifyVector(string $password, string $hash, string $expect): void
    {
        $this->assertSame($expect === 'accept', dstu_core_pwhash_verify_password($password, $hash));
        $this->assertFalse(dstu_core_pwhash_verify_password($password . 'x', $hash));
    }
}
