<?php

declare(strict_types=1);

/**
 * crypto_sign (DSTU 4145): generate a signing keypair, sign a message, verify it.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/sign.php
 */

$signingKey = dstu_core_sign_keygen();
$verifyingKey = dstu_core_sign_verifying_key($signingKey);

$message = 'a message whose origin and integrity matter';
$signature = dstu_core_sign_message($signingKey, $message);
if (!dstu_core_sign_verify($verifyingKey, $message, $signature)) {
    throw new RuntimeException('verification failed');
}

printf("signed and verified a %d-byte message\n", strlen($message));

if (!dstu_core_sign_verify($verifyingKey, 'a different message', $signature)) {
    echo "signature over a different message correctly rejected\n";
}
