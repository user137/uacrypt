<?php

declare(strict_types=1);

/**
 * crypto_secretbox: seal/open a single message with a symmetric key.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/secretbox.php
 */

$key = dstu_core_secretbox_keygen();
$sealed = dstu_core_secretbox_seal($key, 'a message worth protecting');
$plaintext = dstu_core_secretbox_open($key, $sealed);
if ($plaintext !== 'a message worth protecting') {
    throw new RuntimeException('round trip failed');
}

printf("sealed %d bytes -> %d bytes, round-tripped OK\n", strlen($plaintext), strlen($sealed));

$tampered = $sealed;
$tampered[strlen($tampered) - 1] = chr(ord($tampered[-1]) ^ 1);
try {
    dstu_core_secretbox_open($key, $tampered);
} catch (DstuCoreException $e) {
    echo "tampered ciphertext correctly rejected\n";
}
