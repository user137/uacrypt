<?php

declare(strict_types=1);

/**
 * crypto_box: generate a keypair, seal a message to the public key, open it with the secret key.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/box.php
 */

$secretKey = dstu_core_box_keygen();
$publicKey = dstu_core_box_public_key($secretKey); // safe to share/publish

$message = "a message for the public key's holder only";
$sealed = dstu_core_box_seal($publicKey, $message);
$opened = dstu_core_box_open($secretKey, $sealed);
if ($opened !== $message) {
    throw new RuntimeException('round trip failed');
}

printf("sealed %d bytes -> %d bytes, round-tripped OK\n", strlen($opened), strlen($sealed));

$tampered = $sealed;
$tampered[strlen($tampered) - 1] = chr(ord($tampered[-1]) ^ 1);
try {
    dstu_core_box_open($secretKey, $tampered);
} catch (DstuCoreException $e) {
    echo "tampered ciphertext correctly rejected\n";
}
