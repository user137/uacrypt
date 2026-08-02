<?php

declare(strict_types=1);

/**
 * crypto_pwhash (Argon2id): hash and verify a password.
 *
 * DSTU_CORE_PWHASH_INTERACTIVE is used here so the example runs fast -
 * DSTU_CORE_PWHASH_MODERATE (the default strength most applications should use) and
 * DSTU_CORE_PWHASH_SENSITIVE both take real seconds by design.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/password-hashing.php
 */

$password = 'correct horse battery staple';
$stored = dstu_core_pwhash_hash_password($password, DSTU_CORE_PWHASH_INTERACTIVE);
echo "stored hash: {$stored}\n";

if (!dstu_core_pwhash_verify_password($password, $stored)) {
    throw new RuntimeException('correct password rejected');
}
echo "correct password accepted\n";

if (dstu_core_pwhash_verify_password('wrong guess', $stored)) {
    throw new RuntimeException('wrong password accepted');
}
echo "wrong password correctly rejected\n";
