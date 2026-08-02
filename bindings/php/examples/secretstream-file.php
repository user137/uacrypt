<?php

declare(strict_types=1);

/**
 * crypto_secretstream: encrypt/decrypt a file incrementally, chunk by chunk, via the idiomatic
 * DstuCoreSecretStreamWriter/Reader wrapper (docs/DECISIONS.md D-118/D-143). The wire format
 * matches `uacrypt encrypt`/`decrypt` exactly - a file this writes is decryptable by the
 * `uacrypt` CLI and vice versa.
 *
 * Run: php -d extension=<path to dstu_core_php.dll/.so> examples/secretstream-file.php
 */

require __DIR__ . '/../lib/DstuCoreSecretStream.php';

$key = dstu_core_secretstream_keygen();
$plaintext = str_repeat("a message spread across more than one 8 KiB chunk\n", 1000);

$tmpDir = sys_get_temp_dir() . '/dstu_core_php_example_' . bin2hex(random_bytes(8));
mkdir($tmpDir);

try {
    $encryptedPath = "{$tmpDir}/message.enc";
    $decryptedPath = "{$tmpDir}/message.dec";

    $out = fopen($encryptedPath, 'wb');
    DstuCoreSecretStreamWriter::withStream($key, $out, function ($w) use ($plaintext) {
        $w->write($plaintext);
    });
    fclose($out);

    $in = fopen($encryptedPath, 'rb');
    $recovered = DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
    fclose($in);

    if ($recovered !== $plaintext) {
        throw new RuntimeException('round trip failed');
    }

    printf(
        "%d bytes -> %d bytes on disk, round-tripped OK\n",
        strlen($plaintext),
        filesize($encryptedPath)
    );
    file_put_contents($decryptedPath, $recovered);
} finally {
    array_map('unlink', glob("{$tmpDir}/*"));
    rmdir($tmpDir);
}
