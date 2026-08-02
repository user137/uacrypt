<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * crypto_secretstream - both the low-level DstuCoreSecretStreamPushState/PullState (step 2) and
 * the idiomatic DstuCoreSecretStreamWriter/Reader pipeline (step 3, D-118/D-143). Three
 * categories per D-64/D-65: correctness (round trip across chunk-boundary sizes, plus real
 * byte-for-byte interop with `uacrypt encrypt`/`decrypt`'s own wire format), rejection (tamper,
 * oversized chunk, trailing data), misuse (wrong-length key, write-after-close).
 */
final class SecretstreamTest extends TestCase
{
    private static function findUacrypt(): ?string
    {
        $repoRoot = dirname(__DIR__, 3);
        foreach (['release', 'debug'] as $profile) {
            foreach (['uacrypt.exe', 'uacrypt'] as $name) {
                $path = "{$repoRoot}/target/{$profile}/{$name}";
                if (is_file($path)) {
                    return $path;
                }
            }
        }

        return null;
    }

    /** @return resource */
    private static function memoryStream(string $initial = ''): mixed
    {
        $s = fopen('php://memory', 'w+b');
        if ($initial !== '') {
            fwrite($s, $initial);
            rewind($s);
        }

        return $s;
    }

    public static function chunkBoundarySizes(): array
    {
        return [
            [0], [1], [100], [8 * 1024], [8 * 1024 + 1], [8 * 1024 * 3], [8 * 1024 * 3 + 777],
        ];
    }

    #[DataProvider('chunkBoundarySizes')]
    public function testRoundTripsAcrossChunkBoundaries(int $size): void
    {
        $key = dstu_core_secretstream_keygen();
        // PHP's own random_bytes() rejects a zero length (ValueError), unlike Ruby's
        // Random.bytes(0)/Python's os.urandom(0) - special-case it rather than skipping the
        // size-0 boundary case entirely.
        $plaintext = $size === 0 ? '' : random_bytes($size);

        $out = self::memoryStream();
        DstuCoreSecretStreamWriter::withStream($key, $out, function ($w) use ($plaintext) {
            $step = 777;
            for ($i = 0; $i < strlen($plaintext); $i += $step) {
                $w->write(substr($plaintext, $i, $step));
            }
        });

        rewind($out);
        $result = DstuCoreSecretStreamReader::withStream($key, $out, fn ($r) => $r->readAll());
        fclose($out);
        $this->assertSame($plaintext, $result);
    }

    public function testInteroperatesWithTheRealUacryptCliInBothDirections(): void
    {
        $uacrypt = self::findUacrypt();
        if ($uacrypt === null) {
            $this->markTestSkipped('uacrypt binary not built (cargo build -p uacrypt --release)');
        }

        $key = dstu_core_secretstream_keygen();
        $plaintext = random_bytes(8 * 1024 * 2 + 555);

        $tmpDir = sys_get_temp_dir() . '/dstu_core_php_test_' . bin2hex(random_bytes(8));
        mkdir($tmpDir);

        try {
            $keyFile = "{$tmpDir}/key.bin";
            file_put_contents($keyFile, $key);

            $plainFile = "{$tmpDir}/plain.bin";
            file_put_contents($plainFile, $plaintext);

            $phpEncrypted = "{$tmpDir}/php_encrypted.bin";
            $out = fopen($phpEncrypted, 'wb');
            DstuCoreSecretStreamWriter::withStream($key, $out, function ($w) use ($plaintext) {
                $w->write($plaintext);
            });
            fclose($out);

            $uacryptDecrypted = "{$tmpDir}/uacrypt_decrypted.bin";
            $this->runUacrypt($uacrypt, ['decrypt', '--key', $keyFile, '--in', $phpEncrypted, '--out', $uacryptDecrypted]);
            $this->assertSame($plaintext, file_get_contents($uacryptDecrypted));

            $uacryptEncrypted = "{$tmpDir}/uacrypt_encrypted.bin";
            $this->runUacrypt($uacrypt, ['encrypt', '--key', $keyFile, '--in', $plainFile, '--out', $uacryptEncrypted]);
            $in = fopen($uacryptEncrypted, 'rb');
            $result = DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
            fclose($in);
            $this->assertSame($plaintext, $result);
        } finally {
            array_map('unlink', glob("{$tmpDir}/*"));
            rmdir($tmpDir);
        }
    }

    private function runUacrypt(string $uacrypt, array $args): void
    {
        $cmd = array_merge([$uacrypt], $args);
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($cmd, $descriptors, $pipes);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        $this->assertSame(0, $exitCode, "uacrypt failed: {$stderr}");
    }

    public function testRejectsATamperedChunk(): void
    {
        $key = dstu_core_secretstream_keygen();
        $out = self::memoryStream();
        DstuCoreSecretStreamWriter::withStream($key, $out, fn ($w) => $w->write('secret message'));
        rewind($out);
        $data = stream_get_contents($out);
        fclose($out);
        $data[strlen($data) - 1] = chr(ord($data[-1]) ^ 1);

        $in = self::memoryStream($data);
        $this->expectException(DstuCoreException::class);
        DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
    }

    public function testRejectsATruncatedStream(): void
    {
        $key = dstu_core_secretstream_keygen();
        $out = self::memoryStream();
        DstuCoreSecretStreamWriter::withStream($key, $out, fn ($w) => $w->write(str_repeat('x', 20000)));
        rewind($out);
        $truncated = substr(stream_get_contents($out), 0, 100);
        fclose($out);

        $in = self::memoryStream($truncated);
        $this->expectException(DstuCoreException::class);
        DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
    }

    public function testRejectsAnOversizedDeclaredChunkLength(): void
    {
        $key = dstu_core_secretstream_keygen();
        $push = new DstuCoreSecretStreamPushState($key);
        $malicious = $push->header() . pack('C', DSTU_CORE_SECRETSTREAM_TAG_FINAL) . pack('V', 0xFFFFFFFF);

        $in = self::memoryStream($malicious);
        $this->expectException(DstuCoreException::class);
        $this->expectExceptionMessageMatches('/too large/');
        DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
    }

    public function testRejectsTrailingDataAfterFinal(): void
    {
        $key = dstu_core_secretstream_keygen();
        $out = self::memoryStream();
        DstuCoreSecretStreamWriter::withStream($key, $out, fn ($w) => $w->write('msg'));
        rewind($out);
        $data = stream_get_contents($out) . 'unexpected trailing bytes';
        fclose($out);

        $in = self::memoryStream($data);
        $this->expectException(DstuCoreException::class);
        $this->expectExceptionMessageMatches('/trailing/');
        DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
    }

    public function testLeavesTheStreamUnfinalizedWhenTheCallbackThrowsMidWrite(): void
    {
        $key = dstu_core_secretstream_keygen();
        $out = self::memoryStream();
        try {
            DstuCoreSecretStreamWriter::withStream($key, $out, function ($w) {
                $w->write('chunk one');
                throw new RuntimeException('simulated failure mid-stream');
            });
            $this->fail('expected RuntimeException');
        } catch (RuntimeException $e) {
            $this->assertSame('simulated failure mid-stream', $e->getMessage());
        }

        rewind($out);
        $this->expectException(DstuCoreException::class);
        DstuCoreSecretStreamReader::withStream($key, $out, fn ($r) => $r->readAll());
    }

    public function testRejectsAWrongLengthKey(): void
    {
        $this->expectException(\ValueError::class);
        new DstuCoreSecretStreamPushState('too short');
    }

    public function testRejectsWriteAfterClose(): void
    {
        $key = dstu_core_secretstream_keygen();
        $out = self::memoryStream();
        $writer = new DstuCoreSecretStreamWriter($key, $out);
        $writer->write('data');
        $writer->close();
        $this->expectException(DstuCoreException::class);
        $writer->write('more data');
    }
}
