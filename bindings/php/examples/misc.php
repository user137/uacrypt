<?php

declare(strict_types=1);

/**
 * The remaining crypto_* modules, each small enough to share one file:
 *
 * - crypto_auth (Kupyna-KMAC): keyed message authentication.
 * - crypto_kdf: deterministic subkey derivation from a master key.
 * - crypto_generichash (Kupyna-256/512): one-shot and streaming hashing.
 * - crypto_stream (Strumok-256): unauthenticated keystream cipher - no integrity, wrong
 *   key/tampered ciphertext silently decrypts to different, wrong plaintext instead of throwing.
 * - randombytes: CSPRNG-backed random bytes.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/misc.php
 */

function authExample(): void
{
    $key = dstu_core_auth_keygen();
    $message = 'a message both parties want to confirm is unmodified';
    $tag = dstu_core_auth($key, $message);
    dstu_core_auth_verify($key, $message, $tag);
    echo "auth: tag verified\n";
}

function kdfExample(): void
{
    $masterKey = dstu_core_kdf_keygen();
    $subkeyA = dstu_core_kdf_derive_subkey($masterKey, 0, 'encrypt_');
    $subkeyB = dstu_core_kdf_derive_subkey($masterKey, 1, 'encrypt_');
    if ($subkeyA === $subkeyB) {
        throw new RuntimeException('subkeys should differ');
    }
    echo "kdf: subkey 0 and subkey 1 differ, as expected\n";
}

function generichashExample(): void
{
    $oneShot = dstu_core_generichash_kupyna256('hello world');
    $hasher = new DstuCoreKupyna256Hasher();
    $hasher->update('hello ');
    $hasher->update('world');
    if ($hasher->finalize() !== $oneShot) {
        throw new RuntimeException('streaming mismatch');
    }
    printf("generichash: kupyna256('hello world') = %s\n", bin2hex($oneShot));
}

function streamExample(): void
{
    $key = dstu_core_stream_keygen();
    $sealed = dstu_core_stream_encrypt($key, 'a message');
    if (dstu_core_stream_decrypt($key, $sealed) !== 'a message') {
        throw new RuntimeException('round trip failed');
    }
    echo "stream: round-tripped (note: unauthenticated, no tamper detection)\n";
}

function randombytesExample(): void
{
    $a = dstu_core_randombytes_buf(16);
    $b = dstu_core_randombytes_buf(16);
    if ($a === $b) {
        throw new RuntimeException('draws should differ');
    }
    printf("randombytes: two independent 16-byte draws, e.g. %s\n", bin2hex($a));
}

authExample();
kdfExample();
generichashExample();
streamExample();
randombytesExample();
